"""Stage C — attacker-reachability annotation for attack paths.

An attack-path hypothesis is only actionable if an actual unprivileged caller
can reach its entry point. ``enumerate_attack_paths`` derives paths from static
structure; this module answers the complementary question for each path:

    can an attacker actually reach the required state?

It reuses the deterministic reachability model (``agents.reachability``), which
distinguishes "reachable" from "attacker-reachable" (a path that never ENTERS an
authorization-gated function). A path whose every external entry is gated is
marked ``attacker_reachable="no"`` so downstream stages never treat an
unreachable sequence as a live vulnerability. Ambiguity stays ``"unknown"``;
nothing is inferred without evidence.
"""

from __future__ import annotations

from typing import Any

from agentsafe.agents.reachability import build_reachability

__all__ = ["annotate_attack_paths"]


def annotate_attack_paths(
    paths: list[Any],
    segments: dict[str, str] | None,
    *,
    intel: Any | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Return (enriched path dicts, counts). Each dict gains an
    ``attacker_reachable`` field: ``yes`` when some entry is attacker-reachable,
    ``no`` when every entry is reachable only through an authorization gate,
    ``unknown`` when it cannot be determined from the analyzed source."""
    model = None
    try:
        model = build_reachability(segments, intel=intel)
    except Exception:  # an annotation aid must never break the audit
        model = None

    counts = {"attacker_reachable": 0, "gated": 0, "unknown": 0,
              "cross_contract": 0, "multi_tx": 0}
    out: list[dict[str, Any]] = []
    for p in paths:
        d = dict(p) if isinstance(p, dict) else p.to_dict()
        entries = d.get("entry_points") or []
        if model is None or not entries:
            d["attacker_reachable"] = "unknown"
            counts["unknown"] += 1
        else:
            verdicts = [model.key_attacker_reachable(str(e)) for e in entries]
            if "yes" in verdicts:
                d["attacker_reachable"] = "yes"
                counts["attacker_reachable"] += 1
            elif all(v == "no" for v in verdicts):
                d["attacker_reachable"] = "no"
                counts["gated"] += 1
            else:
                d["attacker_reachable"] = "unknown"
                counts["unknown"] += 1
        if d.get("cross_contract"):
            counts["cross_contract"] += 1
        if (d.get("transaction_count") or 1) > 1:
            counts["multi_tx"] += 1
        out.append(d)
    return out, counts
