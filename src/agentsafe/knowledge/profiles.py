"""Retrieval profiles — Task: Retrieval Integration.

Maps each specialist agent to the knowledge categories it should see FIRST.
Profiles PRIORITIZE (boost) without excluding: an accounting agent still
receives cross-signal records, but accounting/attack-path cases rank above
everything else. Explicit filters (kb_groups/categories/tags) remain available
for hard filtering when a caller wants a strict subset.

Guarantees:
  * small result sets: MAX_SEARCH_LIMIT caps every search (never hundreds of
    records to an LLM)
  * profiles never fabricate relevance: they only reweight matched records
  * lexical fallback is unaffected (profiles apply on top of either leg)
"""

from __future__ import annotations

from typing import Any

# Hard cap on any single retrieval call: a small, relevant, high-quality set
# with concise evidence (renderer budgets apply downstream as well).
MAX_SEARCH_LIMIT = 10

RETRIEVAL_PROFILES: dict[str, dict[str, Any]] = {
    # Accounting Agent: accounting knowledge + relevant attack-path cases.
    "accounting": {
        "kb_groups": ("C", "B"),
        "categories": ("accounting", "rounding", "oracle", "token-transfer"),
        "boost": 2.0,
    },
    # Cross-function Agent: attack-path + cross-contract cases.
    "cross_function": {
        "kb_groups": ("B", "A"),
        "categories": ("reentrancy", "access-control", "proxy", "bridge",
                       "governance", "approval"),
        "boost": 2.0,
    },
    # Oracle Agent: oracle cases.
    "oracle": {
        "kb_groups": ("D",),
        "categories": ("oracle",),
        "boost": 2.0,
    },
    # Reentrancy Agent: BOTH vulnerable (A/B) and secure (E) reentrancy
    # examples — the secure patterns anchor false-positive rejection.
    "reentrancy": {
        "kb_groups": ("A", "B", "E"),
        "categories": ("reentrancy", "access-control"),
        "boost": 2.0,
    },
    # Validation Agent: PoC / exploit-validation + false-positive evidence.
    "validation": {
        "kb_groups": ("F", "E"),
        "categories": ("reentrancy", "access-control", "oracle", "proxy",
                       "rounding", "approval", "accounting"),
        "boost": 2.0,
    },
    "access_control": {
        "kb_groups": ("E", "A", "B"),
        "categories": ("access-control", "initialization", "proxy", "approval"),
        "boost": 1.8,
    },
    "arithmetic": {
        "kb_groups": ("C",),
        "categories": ("rounding", "accounting", "oracle"),
        "boost": 1.8,
    },
    "proxy_upgrade": {
        "kb_groups": ("E", "B"),
        "categories": ("proxy", "initialization", "access-control"),
        "boost": 1.8,
    },
    # general_discovery: no profile (broad retrieval across all groups).
}


def resolve_profile(name: str | None) -> dict[str, Any] | None:
    """Return the profile for `name`, or None when unset/unknown (broad)."""
    if not name:
        return None
    return RETRIEVAL_PROFILES.get(str(name).strip().lower())
