"""Cross-contract scope disclosure.

External interactions that target a contract whose source is NOT in the
analyzed set are recorded by the intel extractor but cannot be analyzed. The
pipeline must say so explicitly, so that the absence of a finding for those
contracts is never mistaken for a clean result.
"""

from __future__ import annotations

from agentsafe.intel.extract import extract_contract_intel
from agentsafe.orchestrator import _cross_contract_scope_limitation

UNRESOLVED_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract A {",
        "    address private token;",
        "    function pay(address to, uint256 amt) external {",
        "        token.transfer(to, amt);",
        "    }",
        "}",
    ]
)

RESOLVED_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract A {",
        "    uint256 private x;",
        "    function f() external {",
        "        x = 1;",
        "    }",
        "}",
    ]
)


def test_scope_limitation_names_unanalyzed_external_targets():
    intel = extract_contract_intel({"A.sol": UNRESOLVED_SRC})
    lim = _cross_contract_scope_limitation(intel)
    assert lim is not None
    assert "not in the analyzed set" in lim
    assert "token.transfer" in lim


def test_no_scope_limitation_when_everything_is_resolved():
    intel = extract_contract_intel({"A.sol": RESOLVED_SRC})
    assert _cross_contract_scope_limitation(intel) is None
