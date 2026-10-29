"""Embedding providers — AgentSafe G+ Stage 3.

Verified provider (2025-10, live-tested):
  NVIDIA NIM  https://integrate.api.nvidia.com/v1/embeddings
              model nvidia/nemotron-3.5-embed-1b -> 2048-dim vectors
              OpenAI-compatible request shape, extra `input_type` field
              (query vs passage) per NIM contract.

Configured via environment variables (no OpenAI key required):
  EMBED_PROVIDER   = nvidia            (default; only provider wired)
  NVIDIA_API_KEY   = nvapi-...
  NVIDIA_BASE_URL  = https://integrate.api.nvidia.com/v1
  NVIDIA_EMBED_MODEL = nvidia/nemotron-3.5-embed-1b
  EMBED_DIM        = 2048

Guarantees (per G+ Stage 3 spec):
- Batch requests; bounded retries with exponential backoff (default 3).
- Rate-limit aware (429 -> backoff; still bounded).
- Content-hash reuse: callers skip embedding when content_hash matches the
  stored one (see NeonKnowledgeStore upsert path).
- NEVER fabricates vectors: on final failure it raises; callers store NULL
  and the record simply stays lexical-only.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Iterable, Sequence

logger = logging.getLogger("agentSAFE.knowledge.embeddings")

DEFAULT_MODEL = "nvidia/nemotron-3.5-embed-1b"
DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_DIM = 2048
BATCH_LIMIT = 32          # NIM batch cap (documented max inputs per request)
MAX_RETRIES = 3
RETRY_BACKOFF_S = 2.0


class EmbeddingError(RuntimeError):
    """Raised when a real embedding cannot be obtained. Never faked."""


class NVIDIAEmbedder:
    """OpenAI-compatible /embeddings client for NVIDIA NIM (live-verified)."""

    name = "nvidia/nemotron-3.5-embed-1b"

    def __init__(self, api_key: str, base_url: str = DEFAULT_BASE_URL,
                 model: str = DEFAULT_MODEL, dim: int = DEFAULT_DIM,
                 timeout: float = 30.0, max_retries: int = MAX_RETRIES):
        if not api_key:
            raise EmbeddingError("NVIDIA_API_KEY is required for NVIDIAEmbedder")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.dim = dim
        self.timeout = timeout
        self.max_retries = max_retries

    # -- public API ---------------------------------------------------------
    def embed(self, texts: Sequence[str], *, input_type: str = "passage"
              ) -> list[list[float]]:
        """Embed a batch. Returns list of vectors aligned to `texts`.
        Raises EmbeddingError after bounded retries — never returns fakes."""
        if not texts:
            return []
        out: list[list[float]] = []
        for i in range(0, len(texts), BATCH_LIMIT):
            out.extend(self._embed_batch(texts[i:i + BATCH_LIMIT],
                                         input_type=input_type))
        return out

    def embed_query(self, text: str) -> list[float]:
        return self.embed([text], input_type="query")[0]

    # -- internals -----------------------------------------------------------
    def _embed_batch(self, batch: Sequence[str], *, input_type: str
                     ) -> list[list[float]]:
        import json
        import urllib.error
        import urllib.request

        payload = json.dumps({
            "model": self.model,
            "input": list(batch),
            "input_type": input_type,
            "truncate": "END",
        }).encode("utf-8")
        last_err: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(
                f"{self.base_url}/embeddings", data=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                vecs = self._parse_response(data, expect=len(batch))
                return vecs
            except urllib.error.HTTPError as exc:
                last_err = exc
                if exc.code == 429 or 500 <= exc.code < 600:
                    wait = RETRY_BACKOFF_S * (2 ** (attempt - 1))
                    logger.warning("embeddings HTTP %s; backoff %.1fs (try %d/%d)",
                                   exc.code, wait, attempt, self.max_retries)
                    time.sleep(wait)
                    continue
                raise EmbeddingError(
                    f"embeddings HTTP {exc.code}: {exc.reason}") from exc
            except Exception as exc:  # network / ssl / parse
                last_err = exc
                wait = RETRY_BACKOFF_S * (2 ** (attempt - 1))
                logger.warning("embeddings %s; backoff %.1fs (try %d/%d)",
                               exc, wait, attempt, self.max_retries)
                time.sleep(wait)
        raise EmbeddingError(
            f"embeddings failed after {self.max_retries} retries: {last_err}")

    def _parse_response(self, data: dict[str, Any], *, expect: int
                        ) -> list[list[float]]:
        items = data.get("data") or []
        if len(items) != expect:
            raise EmbeddingError(
                f"embeddings returned {len(items)} vectors, expected {expect}")
        vecs = []
        for it in items:
            v = it.get("embedding")
            if not isinstance(v, list) or not v:
                raise EmbeddingError("embeddings response missing vector")
            vecs.append([float(x) for x in v])
        return vecs


def get_embedder(settings: Any = None) -> NVIDIAEmbedder | None:
    """Build the embedder from env/config; returns None when unconfigured so
    callers degrade to lexical-only retrieval (never fake vectors)."""
    env = os.environ
    if settings is not None:
        for k in ("NVIDIA_API_KEY", "NVIDIA_BASE_URL", "NVIDIA_EMBED_MODEL",
                  "EMBED_DIM"):
            v = getattr(settings, k, None)
            if v and not env.get(k):
                env = dict(env); env[k] = v  # type: ignore[assignment]
                break
    api_key = env.get("NVIDIA_API_KEY", "").strip()
    if not api_key:
        return None
    model = env.get("NVIDIA_EMBED_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    base = env.get("NVIDIA_BASE_URL", DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
    try:
        dim = int(env.get("EMBED_DIM", DEFAULT_DIM))
    except ValueError:
        dim = DEFAULT_DIM
    return NVIDIAEmbedder(api_key=api_key, base_url=base, model=model, dim=dim)
