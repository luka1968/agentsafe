"""AgentSafe MCP - AI-Powered Smart Contract Security Intelligence.

EVM smart contract audit MCP server. E-version scope: Ethereum Mainnet only.
AI-assisted security assessments, NOT a formal security audit. Results are
informational and require independent verification. Absence of findings
never means "safe".
"""

from typing import Final

__version__ = "0.1.0"

CHAIN_ID: Final = "ethereum-mainnet"

REPORT_DISCLAIMER = (
    "This report is an AI-assisted security assessment by AgentSafe, not a formal security audit. "
    "Absence of findings does not mean the contract is safe. "
    "All findings marked tool_detected/llm_suggested require verification before action."
)
