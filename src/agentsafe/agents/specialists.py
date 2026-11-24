"""Stage 6 — specialist analyst agents (A–H).

Each specialist is a focused BaseAgent subclass with its own mandate and
keywords. Keywords only gate deep-vs-basic prompting; absence proves
nothing. Specialists are SELECTED by the scheduler from classification
evidence; they never self-decide scope.
"""

from __future__ import annotations

from agentsafe.agents.base import BaseAgent
from agentsafe.llm.prompts import (
    ACCESS_CONTROL_FOCUS,
    ACCOUNTING_FOCUS,
    ARITHMETIC_FOCUS,
    BUSINESS_LOGIC_FOCUS,
    CROSS_CONTRACT_FOCUS,
    CROSS_FUNCTION_FOCUS,
    DEFI_LOGIC_FOCUS,
    FUND_FLOW_FOCUS,
    GENERAL_DISCOVERY_FOCUS,
    ORACLE_FOCUS,
    PROXY_UPGRADE_FOCUS,
    REENTRANCY_FOCUS,
)


class AccessControlAgent(BaseAgent):
    """A. Missing authorization, privilege escalation, role checks,
    initialization, privileged config, proxy administration."""

    name = "access_control"
    focus = ACCESS_CONTROL_FOCUS
    profile = "access_control"
    keywords = (
        "onlyowner", "onlyrole", "hasrole", "grantrole", "renounceownership",
        "transferownership", "initializer", "upgrade", "admin", "authorizer",
        "msg.sender ==", "require(msg.sender",
    )


class ReentrancyAgent(BaseAgent):
    """B. Single/cross-function reentrancy, callbacks, token hooks,
    cross-contract state consistency. External call alone is not proof."""

    name = "reentrancy"
    focus = REENTRANCY_FOCUS
    profile = "reentrancy"
    keywords = (
        ".call{value", ".call(", "delegatecall", "staticcall", ".transfer(",
        ".send(", "receive(", "fallback(", "erc777", "erc1155", "onERC1155",
        "tokensReceived", "msg.sender.call",
    )


class AccountingAgent(BaseAgent):
    """C. Deposit/withdrawal accounting, share-to-asset conversions, fees,
    rounding, precision, balance discrepancies, loss/locking of funds."""

    name = "accounting"
    focus = ACCOUNTING_FOCUS
    profile = "accounting"
    keywords = (
        "totalSupply", "totalAssets", "balanceOf", "shares", "assets",
        "previewRedeem", "convertToShares", "convertToAssets", "deposit(",
        "withdraw(", "redeem(", "mint(", "burn(", "rounding", "fee",
        "feeOnTransfer", "donate",
    )


class CrossFunctionAgent(BaseAgent):
    """D. Interactions among functions sharing state; targeted multi-call
    sequences that bypass restrictions or violate properties."""

    name = "cross_function"
    focus = CROSS_FUNCTION_FOCUS
    profile = "cross_function"
    keywords = (
        "function ", "internal", "state", "flag", "lock", "bool",
        "lastInteraction", "deadline", "nonReentrant", "modifier",
    )


class DefiLogicAgent(BaseAgent):
    """E. Oracle assumptions, collateral/solvency, liquidations,
    interest/debt, flash-loan paths, share-price manipulation."""

    name = "defi_logic"
    focus = DEFI_LOGIC_FOCUS
    profile = "oracle"
    keywords = (
        "oracle", "latestAnswer", "latestRoundData", "getPrice", "priceFeed",
        "peek", "poke", "collateral", "liquidat", "healthFactor", "debt",
        "loan", "flashLoan", "uniswap", "pool", "reserve", "spot",
    )


class OracleAgent(BaseAgent):
    """E2. Oracle and price manipulation: spot-price dependence, stale feeds,
    decimal/scaling errors, TWAP assumptions, flash-loan manipulation."""

    name = "oracle"
    focus = ORACLE_FOCUS
    profile = "oracle"
    keywords = (
        "oracle", "latestanswer", "latestrounddata", "getprice", "pricefeed",
        "peek", "twap", "spot", "getreserves", "slot0", "chainlink",
        "aggregator", "decimals", "consult",
    )


class CrossContractAgent(BaseAgent):
    """I. External protocol dependencies, token behavior assumptions, callback
    interactions, trust boundaries, interface mismatches, composability."""

    name = "cross_contract"
    focus = CROSS_CONTRACT_FOCUS
    profile = "cross_contract"
    keywords = (
        ".call(", "delegatecall", "staticcall", ".transfer(", ".transferfrom(",
        "interface ", "external", "callback", "onerc", "erc777", "tokensreceived",
        "flashloan", "uniswap", "return", "approve(", "safetransfer",
    )


class ArithmeticAgent(BaseAgent):
    """F. Overflow/underflow, rounding, unit/decimal mismatches, boundaries,
    unsafe conversions, compiler-specific behavior."""

    name = "arithmetic"
    focus = ARITHMETIC_FOCUS
    profile = "arithmetic"
    keywords = (
        "uint8", "uint16", "uint32", "int8", "int16", "int32", "unchecked",
        "pragma", "0.7", "0.6", "0.5", "0.4", "decimals", "wei", "gwei",
        "/ ", "* ", "+=", "-=", "*=", "/=", "SafeMath",
    )


class ProxyUpgradeAgent(BaseAgent):
    """G. Storage layout, init/reinit, upgrade authorization, delegatecall,
    upgrade validation."""

    name = "proxy_upgrade"
    focus = PROXY_UPGRADE_FOCUS
    profile = "proxy_upgrade"
    keywords = (
        "upgradeTo", "upgradeToAndCall", "delegatecall", "__gap", "initialize(",
        "reinitializer", "initializer", "admin", "implementation", "proxy",
        "0x360894", "0xb531276",
    )


class GeneralDiscoveryAgent(BaseAgent):
    """H. Business logic beyond specialist categories, without repeating
    their findings."""

    name = "general_discovery"
    focus = GENERAL_DISCOVERY_FOCUS
    keywords = (
        "function", "modifier", "require", "if", "else", "emit", "enum",
        "struct", "mapping", "address", "bool",
    )


# Stable name -> factory map for the scheduler.
SPECIALIST_REGISTRY: dict[str, type[BaseAgent]] = {
    "access_control": AccessControlAgent,
    "reentrancy": ReentrancyAgent,
    "accounting": AccountingAgent,
    "cross_function": CrossFunctionAgent,
    "defi_logic": DefiLogicAgent,
    "oracle": OracleAgent,
    "cross_contract": CrossContractAgent,
    "arithmetic": ArithmeticAgent,
    "proxy_upgrade": ProxyUpgradeAgent,
    "general_discovery": GeneralDiscoveryAgent,
}

# Backwards-compatible aliases (legacy orchestrator wiring).
FundFlowAgent = AccountingAgent
BusinessLogicAgent = DefiLogicAgent
