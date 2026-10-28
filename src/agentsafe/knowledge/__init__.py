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
from .importers import (
    ImportSummary,
    import_jsonl_dataset,
    normalize_record,
    run_import,
    run_import_resumable,
)
from .kb import DATASET_VERSION, KnowledgeBase

__all__ = [
    "KnowledgeBase",
    "NeonKnowledgeStore",
    "ImportSummary",
    "DATASET_VERSION",
    "content_hash_of",
    "get_knowledge_store",
    "import_jsonl_dataset",
    "normalize_record",
    "run_import",
    "run_import_resumable",
]
