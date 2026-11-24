"""Phase 5 — context-aware knowledge retrieval.

Derives the TARGET CONTRACT's technical context (from deterministic intel +
source text) and uses it to (a) build a retrieval query that carries the
contract's own vocabulary, and (b) match/boost historical records that share
that context. Everything is derived from the contract — nothing is invented,
and a match is SUPPORTING INTELLIGENCE, never proof of exploitability (the
renderer keeps the "never automatic proof" duty).

Context signals: Solidity version, contract kinds, function names, state
variables, external calls, token standards, protocol characteristics, attack
surface, vulnerability categories, code patterns, known exploit conditions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentsafe.knowledge.rerank import context_factor

_TOKEN_STANDARDS = {
    "erc20": ("erc20", "ierc20"),
    "erc721": ("erc721", "ierc721", "nft"),
    "erc1155": ("erc1155", "ierc1155"),
    "erc4626": ("erc4626", "ierc4626", "vault"),
}
_TRAIT_HINTS = {
    "vault": ("vault", "deposit", "withdraw", "shares", "share", "redeem"),
    "lending": ("lend", "borrow", "loan", "collateral", "liquidat", "debt"),
    "dex": ("swap", "amm", "liquidity", "pool", "router", "pair"),
    "oracle": ("oracle", "price", "chainlink", "twap", "latestrounddata",
               "latestanswer", "getprice"),
    "governance": ("governance", "vote", "proposal", "quorum", "timelock",
                   "governor"),
    "proxy": ("proxy", "upgrade", "initialize", "delegatecall", "initializer",
              "uupl", "uups", "erc1967"),
    "bridge": ("bridge", "relay", "crosschain", "cross-chain", "message"),
    "staking": ("staking", "stake", "reward", "unstake"),
    "nft": ("erc721", "erc1155", "tokenuri", "nft"),
}
# Trait -> KB vulnerability categories an agent should consider.
_CATEGORY_BY_TRAIT = {
    "vault": ("accounting", "rounding", "token-transfer"),
    "lending": ("accounting", "oracle", "rounding"),
    "dex": ("oracle", "accounting"),
    "oracle": ("oracle", "accounting"),
    "governance": ("governance", "access-control"),
    "proxy": ("proxy", "initialization", "access-control"),
    "bridge": ("bridge", "access-control"),
    "staking": ("accounting", "rounding"),
    "nft": ("token-transfer", "accounting", "approval"),
}
_SOLC_MM = re.compile(r"(\d+)\.(\d+)")
_MAX_NAMES = 20


def _names(seq: Any, cap: int = _MAX_NAMES) -> list[str]:
    out: list[str] = []
    for x in seq or []:
        s = str(x).strip()
        if s and s not in out:
            out.append(s)
        if len(out) >= cap:
            break
    return out


@dataclass
class ContractContext:
    solc: str | None = None                 # "major.minor" from pragma
    pragma: list[str] = field(default_factory=list)
    contracts: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    state_vars: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    token_standards: list[str] = field(default_factory=list)
    protocol_traits: list[str] = field(default_factory=list)
    attack_surface: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)

    def to_match_dict(self) -> dict[str, Any]:
        return {
            "solc": self.solc,
            "functions": self.functions,
            "state_vars": self.state_vars,
            "external_calls": self.external_calls,
            "token_standards": self.token_standards,
            "traits": self.protocol_traits,
            "categories": self.categories,
        }


def derive_context(intel: Any, text: str = "") -> ContractContext:
    """Build the contract context from ContractIntel + raw source text."""
    ctx = ContractContext()
    low = (text or "").lower()
    if intel is not None:
        ctx.pragma = _names(getattr(intel, "pragma", []) or [])
        ctx.contracts = _names([c.name for c in getattr(intel, "contracts", [])])
        fns: list[str] = []
        svars: list[str] = []
        extcalls: list[str] = []
        for c in getattr(intel, "contracts", []):
            for f in getattr(c, "functions", []):
                fns.append(f.name)
                extcalls.extend(getattr(f, "external_calls", []) or [])
                if getattr(f, "delegatecalls", 0):
                    ctx.attack_surface.append(f"delegatecall in {f.name}")
                if getattr(f, "unchecked", 0):
                    ctx.attack_surface.append(f"unchecked block in {f.name}")
                if getattr(f, "ether_calls", 0):
                    ctx.attack_surface.append(f"ether transfer in {f.name}")
            svars.extend(k for k in getattr(c, "state_vars", {})
                         if not k.startswith("modifier:"))
        ctx.functions = _names(fns)
        ctx.state_vars = _names(svars)
        ctx.external_calls = _names(extcalls)
        ctx.attack_surface.extend(
            f"privileged:{p.split(' ')[0]}"
            for p in _names(getattr(intel, "privileged_functions", []) or [], 10))
        ctx.attack_surface.extend(
            f"initializer:{i}" for i in
            _names(getattr(intel, "initializer_functions", []) or [], 10))
        for slot in _names(getattr(intel, "proxy_hints", []) or [], 5):
            ctx.attack_surface.append(f"proxy:{slot.split(':')[-1]}")
    for m in _SOLC_MM.finditer(" ".join(ctx.pragma)):
        ctx.solc = f"{m.group(1)}.{m.group(2)}"
        break
    blob = f"{low} {' '.join(ctx.functions).lower()} {' '.join(ctx.state_vars).lower()}"
    for std, hints in _TOKEN_STANDARDS.items():
        if any(h in blob for h in hints):
            ctx.token_standards.append(std)
    for trait, hints in _TRAIT_HINTS.items():
        if any(h in blob for h in hints):
            ctx.protocol_traits.append(trait)
    cats: list[str] = []
    for trait in ctx.protocol_traits:
        for c in _CATEGORY_BY_TRAIT.get(trait, ()):
            if c not in cats:
                cats.append(c)
    ctx.categories = cats
    ctx.attack_surface = _names(ctx.attack_surface, 24)
    return ctx


def context_query(ctx: ContractContext, chunk: str, keywords: Any = (),
                  focus: str = "") -> str:
    """Query text = the code chunk + agent keywords + the contract's own
    bounded technical vocabulary (so function/state/token names are searchable).
    Bounded so the lexical leg is not diluted by noise."""
    parts = [str(chunk or "")[:4000], " ".join(str(k) for k in (keywords or ())),
             str(focus or ""), " ".join(ctx.token_standards),
             " ".join(ctx.protocol_traits), " ".join(ctx.functions[:10]),
             " ".join(ctx.state_vars[:10]), " ".join(ctx.external_calls[:8])]
    return " ".join(p for p in parts if p)


def retrieve_for_agents(kb: Any, ctx: ContractContext, *, chunk: str,
                        keywords: Any = (), focus: str = "",
                        profile: str | None = None, limit: int = 2
                        ) -> list[dict[str, Any]]:
    """Context-aware retrieval for a specialist. Compatible with both the Neon
    hybrid store (uses solc + context matching) and the JSONL fallback KB
    (which ignores the extra kwargs). Records are annotated with the context
    signals they matched. A retrieval failure is the caller's to surface — this
    never fabricates records."""
    query = context_query(ctx, chunk, keywords, focus)
    match = ctx.to_match_dict()
    try:
        records = kb.search(query, focus=focus, limit=limit, profile=profile,
                            solc=ctx.solc, context=match)
    except TypeError:
        # Fallback KB (or an older store) without context-aware retrieval.
        records = kb.search(query, focus=focus, limit=limit, profile=profile)
    for r in records:
        signals = context_factor(r, match)[1]
        ri = r.setdefault("_retrieval", {})
        if signals:
            ri["context_signals"] = signals
        else:
            # Always state a retrieval basis so no record is presented without a
            # reason (never append an unexplained description to a report).
            ri.setdefault(
                "reason",
                "lexical relevance to the contract's vocabulary + keywords",
            )
    return records
