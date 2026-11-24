"""Section 10 — explicit, evidence-based proxy classification.

Pins:
- the four explicit states (CONFIRMED_PROXY / PROBABLE_PROXY / REGULAR_CONTRACT
  / UNKNOWN);
- EIP-1967 implementation / beacon / admin slot and delegatecalling-fallback
  evidence drive the verdict;
- a proxy-looking NAME alone is NOT evidence -> REGULAR_CONTRACT;
- insufficient source -> UNKNOWN;
- evidence is always recorded; implementation addresses are never invented;
- the classification reaches the intel brief (and therefore the agents).
"""

from __future__ import annotations

from agentsafe.intel.extract import extract_contract_intel
from agentsafe.intel.graph import classify_proxy_pattern
from agentsafe.intel.proxy import ProxyClass, classify_contracts
from agentsafe.intel.render import render_intel_brief

IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

TRANSPARENT_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract TP {",
    f"    bytes32 private constant ADMIN_SLOT = {ADMIN};",
    f"    bytes32 private constant IMPLEMENTATION_SLOT = {IMPL};",
    "    address private _admin;",
    "    function upgradeToAndCall(address impl, bytes memory d) external { _setImpl(impl); }",
    "    function _setImpl(address impl) internal { }",
    "    function _fallback() internal { _delegate(); }",
    "    function _delegate() internal {",
    "        assembly { delegatecall(gas(), sload(IMPLEMENTATION_SLOT), 0, 0, 0, 0) }",
    "    }",
    "}",
])
UUPS_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract U {",
    f"    bytes32 private constant IMPLEMENTATION_SLOT = {IMPL};",
    "    modifier initializer() { _; }",
    "    function upgradeToAndCall(address impl) external { _authorizeUpgrade(impl); }",
    "    function _authorizeUpgrade(address impl) internal { }",
    "}",
])
BEACON_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract B {",
    f"    bytes32 private constant BEACON_SLOT = {BEACON};",
    "    function _fallback() internal { _delegate(); }",
    "    function _delegate() internal { assembly { delegatecall(gas(), 0, 0, 0, 0, 0) } }",
    "}",
])
PROBABLE_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract P {",
    "    modifier initializer() { _; }",
    "    function upgradeToAndCall(address impl) external { }",
    "    function _delegate() internal { assembly { delegatecall(gas(), 0, 0, 0, 0, 0) } }",
    "}",
])
NAME_ONLY_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract MyUpgradeableProxy {",
    "    uint256 private x;",
    "    function f() external { x = 1; }",
    "}",
])
REGULAR_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract Token {",
    "    mapping(address => uint256) private b;",
    "    function transfer(address to, uint256 a) external { b[msg.sender] -= a; b[to] += a; }",
    "}",
])
WITH_ADDR_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract WithAddr {",
    f"    bytes32 private constant IMPLEMENTATION_SLOT = {IMPL};",
    "    function setImpl() external {",
    "        assembly { sstore(IMPLEMENTATION_SLOT, 0x1111111111111111111111111111111111111111) }",
    "    }",
    "}",
])


def _cls(src, name):
    intel = extract_contract_intel({"X.sol": src})
    return next(c for c in classify_contracts(intel) if c.contract == name)


class TestClassification:
    def test_transparent_confirmed_from_admin_slot(self):
        c = _cls(TRANSPARENT_SRC, "TP")
        assert c.classification == ProxyClass.CONFIRMED
        assert c.pattern == "transparent"
        assert any("admin storage slot" in e for e in c.evidence)
        assert c.signals["fallback_delegatecall"] is True

    def test_uups_confirmed_from_impl_slot(self):
        c = _cls(UUPS_SRC, "U")
        assert c.classification == ProxyClass.CONFIRMED
        assert c.pattern == "uups"

    def test_beacon_confirmed_from_beacon_slot(self):
        c = _cls(BEACON_SRC, "B")
        assert c.classification == ProxyClass.CONFIRMED
        assert c.pattern == "beacon"

    def test_probable_without_slot(self):
        c = _cls(PROBABLE_SRC, "P")
        assert c.classification == ProxyClass.PROBABLE
        assert c.signals["delegatecall"] and c.signals["upgrade_mechanism"]

    def test_name_alone_is_not_evidence(self):
        c = _cls(NAME_ONLY_SRC, "MyUpgradeableProxy")
        assert c.classification == ProxyClass.REGULAR
        assert any("NO structural evidence" in e for e in c.evidence)

    def test_regular_contract(self):
        c = _cls(REGULAR_SRC, "Token")
        assert c.classification == ProxyClass.REGULAR

    def test_insufficient_source_is_unknown(self):
        c = _cls("pragma solidity ^0.8.0;\ncontract Empty {}", "Empty")
        assert c.classification == ProxyClass.UNKNOWN


class TestImplementationAddress:
    def test_no_literal_means_none(self):
        assert _cls(UUPS_SRC, "U").implementation_address is None

    def test_unambiguous_literal_is_recorded(self):
        c = _cls(WITH_ADDR_SRC, "WithAddr")
        assert c.implementation_address == "0x" + "1" * 40


class TestGraphAndBriefIntegration:
    def test_classify_proxy_pattern_uses_evidence(self):
        intel = extract_contract_intel({"X.sol": PROBABLE_SRC})
        p = classify_proxy_pattern(intel)[0]
        assert p.kind == "uups" and p.evidence

    def test_classification_reaches_the_intel_brief(self):
        intel = extract_contract_intel({"X.sol": TRANSPARENT_SRC})
        brief = render_intel_brief(intel, "proxy_upgrade")
        assert "PROXY CLASSIFICATION" in brief
        assert "CONFIRMED_PROXY" in brief
