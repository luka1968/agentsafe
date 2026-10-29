"""Contract intelligence layer: deterministic extraction + graphs + rendering."""

from .extract import (
    ContractEntry,
    ContractIntel,
    FunctionIntel,
    enrich_from_slither_json,
    extract_contract_intel,
)
from .graph import (
    ProxyPattern,
    StateChange,
    call_graph,
    classify_proxy_pattern,
    sink_inventory,
    state_change_evidence,
    state_dependency_graph,
)

__all__ = [
    "ContractEntry",
    "ContractIntel",
    "FunctionIntel",
    "extract_contract_intel",
    "enrich_from_slither_json",
    "render_intel_brief",
    "render_kb_snippets",
    "ProxyPattern",
    "StateChange",
    "call_graph",
    "classify_proxy_pattern",
    "sink_inventory",
    "state_change_evidence",
    "state_dependency_graph",
]

from .render import render_intel_brief, render_kb_snippets  # noqa: E402
