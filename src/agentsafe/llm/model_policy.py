"""Section 16 — model policy for complex security reasoning.

Uses stronger reasoning models for the complex domains (financial/accounting
logic, attack-path discovery, cross-contract composability, independent
validation) when such a model is configured, and NEVER selects a weaker model
to reduce calls. This module is a pure policy: it decides a tier and resolves a
model; the router keeps doing provider rotation, structured-output validation
and repair, bounded retries and budget accounting.

Policy is deterministic so it can be recorded in the reproducible audit
metadata (`model_policy_snapshot`).
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "COMPLEX_DOMAINS",
    "reasoning_tier_for",
    "select_model",
    "model_policy_snapshot",
]

# Domains where deeper reasoning materially changes the outcome.
COMPLEX_DOMAINS = frozenset({
    "accounting", "oracle", "cross_function", "cross_contract",
    "defi_logic", "validation", "adversarial",
})


def reasoning_tier_for(name: str | None) -> str:
    """'complex' for financial / attack-path / composability / validation work,
    else 'standard'. Unknown names default to standard (never over-claim)."""
    return "complex" if str(name or "").strip().lower() in COMPLEX_DOMAINS else "standard"


def select_model(
    tier: str,
    *,
    default: str,
    complex_model: str | None = None,
) -> str:
    """Resolve the model for a tier from the CONFIGURED models only.

    A complex-tier task uses ``complex_model`` when one is configured; otherwise
    it falls back to ``default``. There is intentionally NO path that selects a
    weaker model to save calls — the only choice is "stronger if available"."""
    if tier == "complex" and complex_model:
        return complex_model
    return default


def model_policy_snapshot(
    *, default_model: str, complex_model: str | None = None
) -> dict[str, Any]:
    """Reproducible record of the model policy + resolved per-tier models."""
    return {
        "default_model": default_model,
        "complex_model": complex_model,
        "complex_domains": sorted(COMPLEX_DOMAINS),
        "resolved": {
            "standard": select_model("standard", default=default_model,
                                     complex_model=complex_model),
            "complex": select_model("complex", default=default_model,
                                    complex_model=complex_model),
        },
        "weakens_to_reduce_calls": False,
    }
