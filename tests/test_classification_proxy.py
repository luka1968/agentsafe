"""Classification fix: inheritance is NOT a proxy.

`contract_classes` used to append `:<name>:proxy` for any contract that had a
base contract, which produced the false fact `WETH9:proxy` (WETH9 inherits
nothing and has no proxy mechanism). Proxy-ness now requires EVIDENCE.
"""

from __future__ import annotations

from agentsafe.agents.classification import classify_contract
from agentsafe.intel.extract import extract_contract_intel

IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def test_inheritance_is_not_a_proxy():
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract Base { uint256 x; }\n"
        "contract Child is Base { function f() external { x = 1; } }"
    )
    intel = extract_contract_intel({"C.sol": src})
    p = classify_contract(intel, src)
    assert not any(":proxy" in c for c in p.contract_classes), p.contract_classes


def test_real_proxy_is_tagged_from_evidence():
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract PProxy {\n"
        f"    bytes32 private constant IMPLEMENTATION_SLOT = {IMPL_SLOT};\n"
        "    function upgradeToAndCall(address impl) external { }\n"
        "}"
    )
    intel = extract_contract_intel({"P.sol": src})
    p = classify_contract(intel, src)
    assert any(":proxy" in c for c in p.contract_classes), p.contract_classes
