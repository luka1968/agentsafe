"""Section 11 — historical / deployed-contract context.

Findings mean different things depending on WHAT is being audited and HOW it is
deployed. This module makes that explicit and deterministic:

- source kind: verified source of a deployed contract vs unverified bytecode;
- immutability: an immutable deployed contract vs an upgradeable one (from the
  evidence-based proxy classification);
- compiler era: the actual solc version, and the pre-0.8 rule that unchecked
  arithmetic is NOT automatically exploitable without a reachable attack path;
- disposition: whether a finding is an EXISTING EXPOSURE, an INFORMATIONAL
  OBSERVATION, or a RECOMMENDATION THAT CANNOT BE APPLIED to the deployed
  bytecode.

Compiler warnings and code-quality observations are never promoted to
actionable vulnerabilities: they are classified informational.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "DeploymentContext",
    "build_deployment_context",
    "finding_disposition",
    "is_code_quality",
    "SOURCE_DEPLOYED_VERIFIED",
    "SOURCE_DEPLOYED_UNVERIFIED",
    "DISPOSITION_EXISTING_EXPOSURE",
    "DISPOSITION_INFORMATIONAL",
    "DISPOSITION_RECOMMENDATION",
]

SOURCE_DEPLOYED_VERIFIED = "deployed_verified_source"
SOURCE_DEPLOYED_UNVERIFIED = "deployed_unverified_bytecode"
SOURCE_UNKNOWN = "unknown"

IMMUTABLE = "immutable"
UPGRADEABLE = "upgradeable"
IMMUTABILITY_UNKNOWN = "unknown"

DISPOSITION_EXISTING_EXPOSURE = "existing_exposure"
DISPOSITION_INFORMATIONAL = "informational_observation"
DISPOSITION_RECOMMENDATION = "recommendation_not_applicable_to_deployed_bytecode"

# Detector ids that are code-quality / compiler-warning classes, never a vuln.
_QUALITY_DETECTORS = frozenset({
    "naming-convention", "solc-version", "optimization", "constable-states",
    "too-many-digits", "cyclomatic-complexity", "dead-code", "assembly",
    "low-level-calls", "external-function", "immutable-states",
    "missing-inheritance", "style-guide", "compiler-version",
})
_QUALITY_TEXT = re.compile(
    r"naming\s+convention|solc\s+version|compiler\s+version|\bcode\s+quality\b|"
    r"gas\s+optim|constable|too\s+many\s+digits|dead\s+code|redundant|"
    r"unused\s+(?:variable|import|function|state|local)|shadow(?:ing|ed)?\s+variable",
    re.IGNORECASE,
)
_RECOMMENDATION_TEXT = re.compile(
    r"\brecommend|consider|best\s+practice|should\s+(?:add|use|consider|emit|"
    r"check)|\bmissing\s+(?:event|zero-address|check)|\bzero-address\b|"
    r"emit\s+an?\s+event|add\s+a\s+check|\bnaming\b|\bgas\b",
    re.IGNORECASE,
)
_SECURITY_CATEGORIES = frozenset({
    "reentrancy", "access_control", "oracle", "arithmetic", "accounting",
    "proxy", "unhandled_exception",
})
_SOLC_MM = re.compile(r"(\d+)\.(\d+)")


@dataclass
class DeploymentContext:
    address: str = ""
    chain: int | None = None
    source_kind: str = SOURCE_UNKNOWN
    immutability: str = IMMUTABILITY_UNKNOWN
    compiler_version: str = ""
    solc_mm: str | None = None
    pre_0_8: bool = False
    upgradeable: bool = False
    remediation_applicable_to_bytecode: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "chain": self.chain,
            "source_kind": self.source_kind,
            "immutability": self.immutability,
            "compiler_version": self.compiler_version,
            "solc_mm": self.solc_mm,
            "pre_0_8": self.pre_0_8,
            "upgradeable": self.upgradeable,
            "remediation_applicable_to_bytecode": (
                self.remediation_applicable_to_bytecode
            ),
            "notes": list(self.notes),
        }


def _solc_mm(version: str | None) -> str | None:
    if not version:
        return None
    m = _SOLC_MM.search(str(version))
    return f"{m.group(1)}.{m.group(2)}" if m else None


def _is_pre_0_8(solc_mm: str | None) -> bool:
    if not solc_mm:
        return False
    try:
        major, minor = solc_mm.split(".")
        return int(major) == 0 and int(minor) < 8
    except (ValueError, AttributeError):
        return False


def _immutability(intel: Any, verified: bool) -> tuple[str, bool]:
    if intel is None or not verified:
        return IMMUTABILITY_UNKNOWN, False
    try:
        from agentsafe.intel.proxy import ProxyClass, classify_contracts

        pcs = classify_contracts(intel)
    except Exception:
        return IMMUTABILITY_UNKNOWN, False
    if not pcs:
        return IMMUTABILITY_UNKNOWN, False
    if any(p.classification in (ProxyClass.CONFIRMED, ProxyClass.PROBABLE) for p in pcs):
        return UPGRADEABLE, True
    if all(p.classification == ProxyClass.REGULAR for p in pcs):
        return IMMUTABLE, False
    return IMMUTABILITY_UNKNOWN, False


def build_deployment_context(
    *,
    address: str = "",
    is_verified_source: bool,
    compiler_version: str = "",
    intel: Any | None = None,
    chain: int | None = None,
) -> DeploymentContext:
    src_kind = (
        SOURCE_DEPLOYED_VERIFIED if is_verified_source else SOURCE_DEPLOYED_UNVERIFIED
    )
    imm, upgradeable = _immutability(intel, is_verified_source)
    solc_mm = _solc_mm(compiler_version)
    if solc_mm is None and intel is not None:
        solc_mm = _solc_mm(" ".join(getattr(intel, "pragma", ()) or ()))
    pre08 = _is_pre_0_8(solc_mm)
    remediable = upgradeable and is_verified_source

    notes: list[str] = []
    if imm == IMMUTABLE:
        notes.append(
            "immutable deployed contract: source-level recommendations cannot be "
            "applied to the deployed bytecode"
        )
    if imm == UPGRADEABLE:
        notes.append(
            "upgradeable contract: remediation can be applied via an upgrade; "
            "the currently deployed implementation carries the live risk"
        )
    if src_kind == SOURCE_DEPLOYED_UNVERIFIED:
        notes.append(
            "unverified bytecode: no source-level remediation can be derived"
        )
    if pre08:
        notes.append(
            f"pre-0.8 compiler ({solc_mm}): unchecked arithmetic is NOT "
            "automatically exploitable — a concrete, reachable attack path is "
            "required; version-only claims are informational"
        )

    return DeploymentContext(
        address=address,
        chain=chain,
        source_kind=src_kind,
        immutability=imm,
        compiler_version=compiler_version or "",
        solc_mm=solc_mm,
        pre_0_8=pre08,
        upgradeable=upgradeable,
        remediation_applicable_to_bytecode=remediable,
        notes=notes,
    )


def is_code_quality(finding: Any) -> bool:
    """Compiler-warning / code-quality class — NEVER an actionable vulnerability."""
    det = str(getattr(finding, "detector_id", "") or "").lower()
    if det in _QUALITY_DETECTORS:
        return True
    text = f"{getattr(finding, 'title', '')} {getattr(finding, 'description', '')}"
    return bool(_QUALITY_TEXT.search(text))


def _is_security_category(finding: Any) -> bool:
    cat = getattr(getattr(finding, "category", None), "value", "")
    return cat in _SECURITY_CATEGORIES


def _is_recommendation(finding: Any) -> bool:
    text = " ".join(
        str(getattr(finding, k, "") or "")
        for k in ("title", "description", "recommendation", "impact")
    )
    return bool(_RECOMMENDATION_TEXT.search(text))


def finding_disposition(finding: Any, ctx: DeploymentContext) -> str:
    """EXISTING EXPOSURE | INFORMATIONAL OBSERVATION | RECOMMENDATION that
    cannot be applied to the deployed bytecode."""
    if is_code_quality(finding):
        return DISPOSITION_INFORMATIONAL
    if (
        not ctx.remediation_applicable_to_bytecode
        and not _is_security_category(finding)
        and _is_recommendation(finding)
    ):
        return DISPOSITION_RECOMMENDATION
    return DISPOSITION_EXISTING_EXPOSURE
