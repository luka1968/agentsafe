"""Security knowledge base (versioned dataset + retrieval + import pipeline).

Storage backends: Neon PostgreSQL (persistent, normalized 4-table schema,
hybrid retrieval) or the shipped JSONL dataset (in-memory lexical).
`get_knowledge_store` picks the best available backend and never lets a Neon
outage block an audit. `importers` provides resumable, provenance-preserving
dataset ingestion into Neon.
"""

from .db import (
    NeonKnowledgeStore,
    content_hash_of,
    get_knowledge_store,
)
from .enrich_llm import enrich_group_a_llm
from .falsepositives import render_counterexamples, retrieve_counterexamples
from .importers import (
    ImportSummary,
    import_jsonl_dataset,
    normalize_record,
    run_import,
    run_import_resumable,
)
from .integrity import backfill_missing_embeddings, embedding_integrity
from .interface import (
    KnowledgeRequest,
    KnowledgeResponse,
)
from .interface import (
    describe as describe_retrieval_interface,
)
from .kb import DATASET_VERSION, KnowledgeBase
from .maintenance import (
    backfill_provenance,
    propagate_parent_intelligence,
    refresh_embeddings,
)

__all__ = [
    "KnowledgeBase",
    "NeonKnowledgeStore",
    "ImportSummary",
    "DATASET_VERSION",
    "KnowledgeRequest",
    "KnowledgeResponse",
    "backfill_missing_embeddings",
    "describe_retrieval_interface",
    "backfill_provenance",
    "content_hash_of",
    "embedding_integrity",
    "enrich_group_a_llm",
    "get_knowledge_store",
    "import_jsonl_dataset",
    "normalize_record",
    "propagate_parent_intelligence",
    "render_counterexamples",
    "retrieve_counterexamples",
    "refresh_embeddings",
    "run_import",
    "run_import_resumable",
]
