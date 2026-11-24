"""Production knowledge-base wiring regression tests (Phase One audit).

The Phase One audit found the *code* path (get_knowledge_store attaching the
embedder) correct, but the *deployment* path omitted NEON_DATABASE_URL /
NVIDIA_API_KEY, so production audits silently ran the small shipped JSONL KB
(lexical-only). These tests lock both halves:

  1. The production run paths (both GitHub workflows + docker-compose) pass
     the Neon DSN and the embedder config to the audit process.
  2. get_knowledge_store logs a visible WARNING on both silent degradations:
     the JSONL fallback and the missing-embedder lexical-only path.
"""

from __future__ import annotations

import logging
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _settings(*, dsn: str, storage: str):
    return types.SimpleNamespace(
        NEON_DATABASE_URL=dsn, KB_VECTOR_DIM=2048, resolved_kb_storage=storage)


class _FakeStore:
    def __init__(self, dsn, vector_dim, embedding_model=None):
        self.embedding_model = embedding_model

    def migrate(self):
        return None

    def count(self):
        return 1

    def source_status(self, name):
        return "done"


class TestProductionDeployPathsPassKbEnv:
    @pytest.mark.parametrize("wf", ["audit.yml", "docker-audit.yml"])
    def test_workflow_passes_kb_and_embedder_env(self, wf):
        text = (ROOT / ".github" / "workflows" / wf).read_text(encoding="utf-8")
        assert "NEON_DATABASE_URL" in text
        assert "NVIDIA_API_KEY" in text

    def test_compose_passes_kb_env(self):
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        assert "NEON_DATABASE_URL" in text
        assert "NVIDIA_API_KEY" in text

    def test_env_example_documents_kb(self):
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        assert "NEON_DATABASE_URL=" in text
        assert "NVIDIA_API_KEY=" in text


class TestSilentDegradationIsVisible:
    def test_jsonl_fallback_logs_warning(self, caplog):
        from agentsafe.knowledge.db import get_knowledge_store

        with caplog.at_level(logging.WARNING, logger="agentSAFE.knowledge.db"):
            kb = get_knowledge_store(_settings(dsn="", storage="jsonl"))
        assert kb is not None
        assert any("shipped JSONL KB" in r.message for r in caplog.records)

    def test_missing_embedder_logs_lexical_only_warning(self, caplog, monkeypatch):
        import agentsafe.knowledge.embeddings as emb
        from agentsafe.knowledge import db as kb_db

        monkeypatch.setattr(kb_db, "NeonKnowledgeStore", _FakeStore)
        monkeypatch.setattr(emb, "get_embedder", lambda: None)
        with caplog.at_level(logging.WARNING, logger="agentSAFE.knowledge.db"):
            store = kb_db.get_knowledge_store(
                _settings(dsn="postgres://x/y", storage="neon"))
        assert store is not None
        assert any("no embedder" in r.message for r in caplog.records)
