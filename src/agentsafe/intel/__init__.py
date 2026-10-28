"""Contract intelligence layer: deterministic extraction + rendering."""

from .extract import (
    ContractEntry,
    ContractIntel,
    FunctionIntel,
    enrich_from_slither_json,
    extract_contract_intel,
)

__all__ = [
    "ContractEntry",
    "ContractIntel",
    "FunctionIntel",
    "extract_contract_intel",
    "enrich_from_slither_json",
    "render_intel_brief",
    "render_kb_snippets",
]

from .render import render_intel_brief, render_kb_snippets  # noqa: E402
