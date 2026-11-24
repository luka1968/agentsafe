"""Section 7 — deterministic EVM/Solidity execution semantics.

Basic execution semantics must never be decided by LLM reasoning alone. This
module encodes them once, deterministically, and uses them to REFUTE findings
whose claimed behaviour contradicts the EVM:

- ``transfer()`` (ETH): reverts on failure; all earlier state changes in the
  transaction roll back. A claim that a state change "persists" after a failed
  ``transfer()`` is wrong.
- ``send()`` (ETH): returns ``bool`` and does NOT revert on failure; state is
  not rolled back. A claim that a failed ``send()`` reverts the transaction is
  wrong.
- low-level ``call`` / ``delegatecall`` / ``staticcall``: return
  ``(bool, bytes)`` and do NOT revert the caller on failure.
- ``revert`` / ``require`` / ``assert``: atomic — every state change in the
  transaction is rolled back, so partial state cannot persist.
- ``try``/``catch``: a caught exception does not revert the whole transaction;
  state changes made before the failing call in the SAME call frame are rolled
  back to the ``try`` boundary.

Distinguishing ETH ``transfer``/``send`` from ERC20 ``transfer`` (two args,
returns bool) is done by argument shape: the ETH forms take a single argument.
Detection here is conservative — it never invents a construction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = ["EVMCallAnalysis", "EVMRefutation", "analyze_evm_calls", "refute_evm_claim"]

# ETH address.transfer(amount) / address.send(amount): a SINGLE argument.
# ERC20 token.transfer(to, amount) has a comma and is deliberately excluded.
_ETH_TRANSFER = re.compile(r"\.transfer\s*\(\s*[^,()]+\s*\)")
_ETH_SEND = re.compile(r"\.send\s*\(\s*[^,()]+\s*\)")
_LOW_CALL = re.compile(r"\.(?:call|delegatecall|staticcall)\s*[\({]")
_TRY_CATCH = re.compile(r"\btry\b[\s\S]{0,400}?\bcatch\b")
_REVERT_CTRL = re.compile(r"\brevert\s*[\(;]|\brequire\s*\(|\bassert\s*\(")

# Return-value handling (evidence, never a verdict).
_SEND_CHECKED = re.compile(
    r"(?:require\s*\(|if\s*\(|assert\s*\(|(?:\bbool\b\s+\w+\s*=)|!\s*)[^;\n]{0,80}"
    r"\.send\s*[\(]"
)
_CALL_CHECKED = re.compile(
    r"(?:require\s*\(|if\s*\(|(?:\bbool\b\s+\w+\s*[=,])|\(\s*bool\s+\w+)[^;\n]{0,80}"
    r"\.(?:call|delegatecall|staticcall)\s*[\({]"
)


@dataclass
class EVMCallAnalysis:
    eth_transfer: bool = False
    eth_send: bool = False
    low_level_call: bool = False
    try_catch: bool = False
    reverts_control: bool = False
    send_return_checked: bool = False
    call_return_checked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "eth_transfer": self.eth_transfer,
            "eth_send": self.eth_send,
            "low_level_call": self.low_level_call,
            "try_catch": self.try_catch,
            "reverts_control": self.reverts_control,
            "send_return_checked": self.send_return_checked,
            "call_return_checked": self.call_return_checked,
        }


@dataclass
class EVMRefutation:
    rule: str
    reason: str
    counterexamples: list[str] = field(default_factory=list)


def analyze_evm_calls(body: str) -> EVMCallAnalysis:
    b = body or ""
    return EVMCallAnalysis(
        eth_transfer=bool(_ETH_TRANSFER.search(b)),
        eth_send=bool(_ETH_SEND.search(b)),
        low_level_call=bool(_LOW_CALL.search(b)),
        try_catch=bool(_TRY_CATCH.search(b)),
        reverts_control=bool(_REVERT_CTRL.search(b)),
        send_return_checked=bool(_SEND_CHECKED.search(b)),
        call_return_checked=bool(_CALL_CHECKED.search(b)),
    )


# -- claim patterns asserting the WRONG semantics ------------------------------
_RE_STATE_PERSISTS = re.compile(
    r"\bpersist|\bremains?\b|\bnot\s+rolled\s+back\b|\bsurvives?\b|"
    r"\bis\s+not\s+reverted\b|\bstays?\b|\bpermanent",
    re.IGNORECASE,
)
_RE_TRANSFER_MENTION = re.compile(r"\btransfer\b|\beth\b|ether", re.IGNORECASE)
_RE_SEND_REVERTS = re.compile(
    r"\bsend\b[^.]{0,60}(?:revert|roll\s*back|rollback|reversal)|"
    r"(?:revert|roll\s*back)[^.]{0,40}\bsend\b",
    re.IGNORECASE,
)
_RE_CALL_REVERTS = re.compile(
    r"\bcall\b[^.]{0,70}(?:failure|fails?|failed)[^.]{0,40}(?:revert|roll\s*back)|"
    r"\bcall\s*\(\)[^.]{0,50}revert|"
    r"(?:low-?level\s+)?call[^.]{0,50}reverts?\s+the\s+(?:whole\s+)?transaction",
    re.IGNORECASE,
)
_RE_REVERT_PARTIAL = re.compile(
    r"(?:revert|require|assert)[^.]{0,80}(?:partial|state|balance|storage)"
    r"[^.]{0,60}(?:persist|remains?|survives?|not\s+rolled\s+back)|"
    r"partial\s+(?:state|write|update)[^.]{0,60}(?:persist|remains?|survives?)|"
    r"state\s+partially\s+(?:updated|applied)",
    re.IGNORECASE,
)


def refute_evm_claim(body: str, claim: str) -> EVMRefutation | None:
    """Return a refutation when ``claim`` contradicts EVM execution semantics
    given the code ``body``; None when it does not (no invention)."""
    a = analyze_evm_calls(body)
    text = claim or ""

    if a.eth_transfer and _RE_STATE_PERSISTS.search(text) and _RE_TRANSFER_MENTION.search(text):
        return EVMRefutation(
            rule="evm0_transfer_reverts_rollback",
            reason=(
                "ETH transfer() reverts on failure and the whole transaction is "
                "rolled back, so an earlier state change cannot persist after a "
                "failed transfer(); the claim contradicts EVM semantics"
            ),
            counterexamples=["solidity: address.transfer() reverts on failure"],
        )

    if a.eth_send and _RE_SEND_REVERTS.search(text):
        detail = (
            "the return value is NOT checked in this function"
            if not a.send_return_checked
            else "the return value is checked in this function"
        )
        return EVMRefutation(
            rule="evm1_send_does_not_revert",
            reason=(
                "send() returns a bool and does NOT revert on failure, so a "
                f"failed send() does not roll back the transaction ({detail}); "
                "the claim contradicts EVM semantics"
            ),
            counterexamples=[
                "solidity: address.send() returns bool and does not revert"
            ],
        )

    if a.low_level_call and _RE_CALL_REVERTS.search(text):
        return EVMRefutation(
            rule="evm2_call_does_not_revert",
            reason=(
                "a low-level call() returns (bool, bytes) and does NOT revert "
                "the caller on failure; only an explicit require/revert on the "
                "result reverts the transaction — the claim contradicts EVM "
                "semantics"
            ),
            counterexamples=["solidity: low-level call() does not auto-revert"],
        )

    if a.reverts_control and _RE_REVERT_PARTIAL.search(text):
        return EVMRefutation(
            rule="evm3_revert_is_atomic",
            reason=(
                "revert/require/assert are atomic: every state change in the "
                "transaction is rolled back, so partial state cannot persist "
                "after a revert; the claim contradicts EVM semantics"
            ),
            counterexamples=["solidity: revert rolls back all state changes"],
        )
    return None
