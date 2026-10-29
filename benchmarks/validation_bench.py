"""Stage 10 — validation benchmark + regression evaluation.

Measures how the ValidationAgent's state machine classifies a labeled set of
candidate findings, plus regression guards: a fixing of the class of reentrancy
claims (CEI) and overflow claims (theoretical) that historically caused
false-positive headlines.

Ground truth labels use the same vocabulary as ValidationAgent outputs:
  confirmed | potential | informational | rejected | needs_manual_review

Metrics:
  - accuracy (exact match of final status)
  - per-class precision/recall
  - false-positive rate (label informational/rejected but predicted
    confirmed/potential)
  - regression checks must PASS (no confirmed on CEI-compliant / theoretical)

Output JSON to benchmarks/results/validation_bench.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agentsafe.agents.validation import ValidationAgent
from agentsafe.schemas import Finding, FindingStatus, Severity

OUT_DIR = Path(__file__).parent / "results"
OUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# labeled cases (deterministic, from real-ish source)
# ---------------------------------------------------------------------------

CEI_SRC = """\
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

NON_CEI_SRC = """\
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
}
"""

# unvalidated address parameter (no zero-address check) — real class of
# findings, not arithmetic so it does not trip the overflow heuristic
LOGIC_SRC = """\
contract Registry {
    address public admin;
    function setAdmin(address a) external {
        admin = a;  // no zero-address validation
    }
}
"""

# classic ERC-20 transfer -> transferFrom(msg.sender) delegation
ERC20_SRC = """\
contract Token {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function transfer(address to, uint256 v) external returns (bool) {
        return transferFrom(msg.sender, to, v);
    }
    function transferFrom(address f, address t, uint256 v) public returns (bool) {
        require(balanceOf[f] >= v, "b");
        balanceOf[f] -= v;
        balanceOf[t] += v;
        allowance[f][msg.sender] -= v;
        return true;
    }
}
"""


def _mk(title, severity, evidence, src_path, line_start,
        status=FindingStatus.LLM_SUGGESTED, **kw) -> Finding:
    return Finding(
        title=title, severity=severity, status=status,
        source=kw.pop("source", ["agent"]),
        description=kw.pop("description", title),
        evidence=evidence, file_path=src_path, line_start=line_start, **kw)


@dataclass
class Case:
    finding: Finding
    segments: dict[str, str]
    tools: list[Finding]
    label: str  # expected final status


CASES: list[Case] = [
    Case(_mk("Reentrancy in withdraw", Severity.HIGH,
             "payable(msg.sender).transfer(amount);", "Vault.sol", 3),
         {"Vault.sol": CEI_SRC}, [], "rejected"),
    Case(_mk("Reentrancy: external call before state update", Severity.HIGH,
             "payable(msg.sender).transfer(amount);", "Vault.sol", 2),
         {"Vault.sol": NON_CEI_SRC},
         [_mk("reentrancy-eth", Severity.HIGH, "call", "Vault.sol", 2,
              status=FindingStatus.TOOL_DETECTED, source=["slither"],
              detector_id="reentrancy-eth")],
         "confirmed"),
    Case(_mk("transfer delegates to transferFrom(msg.sender)", Severity.INFO,
             "return transferFrom(msg.sender, to, v);", "Token.sol", 3),
         {"Token.sol": ERC20_SRC}, [], "informational"),
    Case(_mk("Integer overflow in addition", Severity.HIGH,
             "balances[a] += x;", "Vault.sol", 5),
         {"Vault.sol": CEI_SRC},
         [_mk("unused-return", Severity.MEDIUM, "x", "Vault.sol", 5,
              status=FindingStatus.TOOL_DETECTED, source=["slither"],
              detector_id="unused-return")],
         "informational"),
    Case(_mk("Claim with no evidence", Severity.HIGH, "", "Vault.sol", 5),
         {"Vault.sol": CEI_SRC}, [], "rejected"),
    Case(_mk("Missing zero-address validation in setAdmin", Severity.MEDIUM,
             "admin = a;", "Registry.sol", 2),
         {"Registry.sol": LOGIC_SRC}, [], "potential"),
]


def run_bench() -> dict:
    v = ValidationAgent()
    rows: list[dict] = []
    correct = 0
    total = 0
    per_class = {k: {"tp": 0, "fp": 0, "fn": 0, "total": 0}
                 for k in ("confirmed", "potential", "informational",
                           "rejected", "needs_manual_review")}
    regression: dict = {"pass": True, "guards": []}

    for case in CASES:
        out = v.validate([case.finding], case.tools, case.segments,
                         is_pseudo_source=False)
        pred = out.findings[0].status.value
        label = case.label
        total += 1
        is_correct = pred == label
        if is_correct:
            correct += 1
        pc = per_class[label]
        pc["total"] += 1
        if is_correct:
            pc["tp"] += 1
        else:
            pc["fn"] += 1
            per_class.setdefault(pred, {"tp": 0, "fp": 0, "fn": 0, "total": 0})[
                "fp"] += 1
        # regression guards (hard expectations, independent of label matching)
        if label in ("informational", "rejected") and pred in (
                "confirmed", "potential"):
            regression["pass"] = False
            regression["guards"].append(
                f"FALSE-POSITIVE: label={label} predicted={pred} "
                f"for '{case.finding.title}'")
        rows.append({"title": case.finding.title,
                     "label": label, "predicted": pred,
                     "correct": is_correct,
                     "rule": (out.findings[0].metadata.get("validation", {}) or {}).get("rule")})

    accuracy = round(correct / total, 4) if total else 0.0
    # per-class precision/recall
    cls_metrics = {}
    for k, m in per_class.items():
        prec = round(m["tp"] / (m["tp"] + m["fp"]), 4) if (m["tp"] + m["fp"]) else None
        rec = round(m["tp"] / m["total"], 4) if m["total"] else None
        cls_metrics[k] = {"precision": prec, "recall": rec, "total": m["total"]}
    fp_total = sum(1 for r in rows
                   if r["label"] in ("informational", "rejected")
                   and r["predicted"] in ("confirmed", "potential"))
    result = {
        "dataset": "validation_bench",
        "n_cases": total,
        "accuracy": accuracy,
        "per_class": cls_metrics,
        "false_positive_count": fp_total,
        "false_positive_rate": round(fp_total / total, 4) if total else 0.0,
        "regression": regression,
        "rows": rows,
        "generated": __file__,
    }
    out = OUT_DIR / "validation_bench.json"
    out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result


def main() -> None:
    res = run_bench()
    print(json.dumps({k: res[k] for k in ("accuracy", "per_class",
                                          "false_positive_rate", "regression")},
                     indent=2, default=str))


if __name__ == "__main__":
    main()
