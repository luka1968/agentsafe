"""Security knowledge base (versioned dataset + retrieval).

Storage backends: Neon PostgreSQL (persistent, hybrid retrieval) or the
shipped JSONL dataset (in-memory lexical). `get_knowledge_store` picks the
best available backend for the configured runtime and never lets a Neon
outage block an audit.
"""

from .db import NeonKnowledgeStore, get_knowledge_store
from .kb import DATASET_VERSION, KnowledgeBase

__all__ = [
    "KnowledgeBase",
    "NeonKnowledgeStore",
    "DATASET_VERSION",
    "get_knowledge_store",
]
