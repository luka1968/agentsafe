"""Independent adversarial verification — "try to disprove every candidate".

A finding is a *hypothesis* until something outside the discovering agents
actively tries to refute it. This stage is deliberately separate from both the
LLM specialists (which propose) and the ValidationAgent state machine (which
classifies): it re-examines every surviving candidate against the verified
source and downgrades the ones the code contradicts or that are not externally
actionable.

It can ONLY reduce — never raise — a finding's standing:

- ``ro0_readonly_contradiction``  a state-mutation / privileged-action claim
  whose located function is declared ``view``/``pure`` cannot happen (a view
  function cannot mutate state) — REJECTED.
- ``ra0_internal_unreachable``    an exploit claim located in an
  internal/private function that no external entry point reaches — the
  attacker cannot invoke it — INFORMATIONAL.
- ``ac0_authz_gated_path``        a "missing access control" claim where every
  external path to the function passes an authorization gate — INFORMATIONAL.
- ``vnd0_vendored_standard``      a standard-semantics claim about vendored
  third-party library code (out of the audited contract's surface) —
  INFORMATIONAL, with an explicit scope limitation.

Honesty is structural: every downgrade records the rule, the reason and the
contradicting source evidence, and a finding the engine cannot assess is left
untouched (never silently cleared). The engine never claims a contract is safe.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from agentsafe.agents.attacker import build_attacker_model
from agentsafe.agents.evm_semantics import analyze_evm_calls, refute_evm_claim
from agentsafe.agents.reachability import ReachabilityModel, build_reachability
from agentsafe.schemas import Finding, FindingStatus
from agentsafe.severity import assess, enrich_swc

logger = logging.getLogger("agentSAFE.adversarial")

__all__ = ["Challenge", "AdversarialVerifier", "ChallengeResult"]

# -- claim classifiers --------------------------------------------------------

# "missing access control / anyone can call" family.
_RE_MISSING_AUTHZ = re.compile(
    r"missing\s+(?:access\s+)?(?:control|authorization|authorisation|auth|"
    r"permission|owner\s+check)|"
    r"no\s+(?:access\s+)?(?:control|authorization|authorisation|auth|permission)|"
    r"unprotected|unauthori[sz]ed|"
    r"without\s+(?:an?\s+)?(?:access\s+)?(?:control|owner\s+check|authorization|"
    r"authorisation|auth)|"
    r"anyone\s+can\s+call|callable\s+by\s+anyone|permissionless|"
    r"lacks?\s+(?:an?\s+)?(?:access\s+)?(?:control|owner\s+check|authorization)|"
    r"publicly\s+callable",
    re.IGNORECASE,
)

# "mutates / performs a privileged action" family (used to catch a claim
# pinned on a view/pure function).
_RE_MUTATING_CLAIM = re.compile(
    r"\ballows?\s+(?:an?\s+)?upgrad|"
    r"\bcan\s+(?:upgrade|change|set|overwrite|modify|alter|drain|mint|burn|"
    r"withdraw|transfer|seize|freeze|pause|unpause|sweep|rescue)\b|"
    r"\bdrains?\b|\bsteals?\b|\bmints?\b|\bburns?\b|\boverwrit|\bseizes?\b|"
    r"\bmodif(?:y|ies)\s+(?:the\s+)?state\b|\bstate\s+(?:is\s+)?(?:changed|"
    r"modified|overwritten|updated)\b|\bchanges?\s+the\s+\w+|"
    r"\bsets?\s+the\s+\w+|\bassigns?\s+the\s+\w+|\bupdates?\s+the\s+\w+",
    re.IGNORECASE,
)

# Standard-semantics markers about vendored library code.
_RE_STANDARD_BEHAVIOR = re.compile(
    r"allowance\s+race|approve\s*/\s*transferfrom|standard\s+erc-?20|"
    r"canonical\s+erc-?20|standard\s+implementation|standard\s+semantics|"
    r"approve\s+front|reset\s+of\s+allowance|immutable\s+admin|proxy\s+admin|"
    r"transparent\s+proxy",
    re.IGNORECASE,
)

_VENDORED_PATH = re.compile(
    r"(?:^|/)(?:@openzeppelin|openzeppelin-contracts|openzeppelin|node_modules|lib|"
    r"solmate|solady|forge-std|@uniswap|@chainlink|@gnosis|@aave|@balancer)(?:/|$)",
    re.IGNORECASE,
)

# Upgrade / proxy-admin claims (used with the proxy-posture rule).
_RE_UPGRADE_ADMIN_CLAIM = re.compile(
    r"upgrad|changeadmin|setadmin|_implementation|\bproxy\s+admin\b|"
    r"admin\s+(?:change|control|key|function)|implementation\s+slot",
    re.IGNORECASE,
)

# A pure Solidity *declaration* (interface / abstract signature, no body). A
# finding whose only evidence is a declaration cannot be verified as an
# executable exploit: there is no implementation to reason about.
_RE_DECL_ONLY = re.compile(
    r"\bfunction\s+[A-Za-z_]\w*\s*\([^)]*\)[^;{]*;", re.DOTALL
)

_MIN_FRAGMENT = 20

# Existing-protection check for reentrancy claims: a guard modifier already
# protects the function (state-rollback / reversion semantics).
_RE_REENTRANCY_CLAIM = re.compile(r"re-?entran", re.IGNORECASE)
_GUARD_MODIFIERS = frozenset(
    {
        "nonreentrant", "noreentrant", "noreentrancy", "reentrancyguard",
        "mutex", "lock", "locked", "notentered",
    }
)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _longest_line(evidence: str) -> str:
    best = ""
    for ln in (evidence or "").splitlines():
        ln = ln.strip()
        if len(ln) > len(best):
            best = ln
    return best


def _declaration_only(evidence: str) -> bool:
    """True when the evidence is a bare Solidity declaration (no body). A
    signature cannot support an exploit claim, so the finding is neither
    confirmable nor refutable on the code shown."""
    ev = (evidence or "").strip()
    if not ev or "{" in ev:
        return False
    return bool(_RE_DECL_ONLY.search(ev))


@dataclass
class Challenge:
    """One refutation attempt that fired, with its evidence and verdict."""

    rule: str
    verdict: FindingStatus
    reason: str
    counterexamples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "counterexamples": list(self.counterexamples),
        }


@dataclass
class ChallengeResult:
    tool_findings: list[Finding] = field(default_factory=list)
    llm_findings: list[Finding] = field(default_factory=list)
    challenged: int = 0
    downgraded: int = 0
    rejected: int = 0
    needs_review: int = 0
    unverified: int = 0
    by_rule: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "challenged": self.challenged,
            "downgraded_to_informational": self.downgraded,
            "needs_manual_review": self.needs_review,
            "unverified": self.unverified,
            "refuted": self.rejected,
            "by_rule": dict(self.by_rule),
            "notes": list(self.notes),
        }


class AdversarialVerifier:
    """Deterministic refutation pass. Downgrades only; never raises a claim."""

    name = "adversarial_review"

    def review(
        self,
        tool_findings: list[Finding],
        llm_findings: list[Finding],
        source_segments: dict[str, str] | None,
        is_pseudo_source: bool = False,
        *,
        intel: Any | None = None,
        paths: list[dict[str, Any]] | None = None,
    ) -> ChallengeResult:
        result = ChallengeResult()
        # Pseudo-source has no reliable structure: reachability is unknown, so
        # only the path-based (vendored) rule may fire. Never fabricate
        # structure to manufacture a refutation.
        model = None
        if not is_pseudo_source:
            try:
                model = build_reachability(source_segments, intel=intel)
            except Exception as exc:  # a refutation aid must never break a report
                logger.warning("reachability model build failed: %s", exc)
                result.notes.append(
                    "reachability could not be modelled; reachability-based "
                    "refutation was skipped"
                )

        result.tool_findings = [
            self._review_one(f, model, is_pseudo_source, result, intel, paths)
            for f in tool_findings
        ]
        result.llm_findings = [
            self._review_one(f, model, is_pseudo_source, result, intel, paths)
            for f in llm_findings
        ]
        return result

    # -- one finding --------------------------------------------------------
    def _review_one(
        self,
        f: Finding,
        model: ReachabilityModel | None,
        is_pseudo: bool,
        result: ChallengeResult,
        intel: Any | None = None,
        paths: list[dict[str, Any]] | None = None,
    ) -> Finding:
        if f.status not in (
            FindingStatus.CONFIRMED,
            FindingStatus.POTENTIAL,
            FindingStatus.NEEDS_MANUAL_REVIEW,
        ):
            return f
        # Attacker model is built for every actionable candidate (transparency)
        # and gates confirmation: an infeasible attacker model (unreachable
        # code, unavailable permissions, or dependence on an external contract
        # whose source is absent) must never remain CONFIRMED.
        am = build_attacker_model(f, model, intel=intel, paths=paths)
        challenge = self._challenge(f, model, is_pseudo)
        if (
            challenge is None
            and f.status is FindingStatus.CONFIRMED
            and am.feasible == "no"
        ):
            challenge = Challenge(
                rule="att0_infeasible_attacker_model",
                verdict=FindingStatus.NEEDS_MANUAL_REVIEW,
                reason=(
                    "attacker model infeasible as stated: "
                    + "; ".join(am.blockers)
                    + "; a confirmed vulnerability requires a reachable attacker "
                    "path with available permissions on evidenced assumptions"
                ),
                counterexamples=list(am.blockers),
            )
        if challenge is None:
            out = f.model_copy(deep=True)
        else:
            result.challenged += 1
            result.by_rule[challenge.rule] = result.by_rule.get(challenge.rule, 0) + 1
            if challenge.verdict is FindingStatus.REJECTED:
                result.rejected += 1
            elif challenge.verdict is FindingStatus.NEEDS_MANUAL_REVIEW:
                result.needs_review += 1
            elif challenge.verdict is FindingStatus.UNVERIFIED:
                result.unverified += 1
            else:
                result.downgraded += 1
            out = self._apply(f, challenge)
        out.metadata = {**out.metadata, "attacker_model": am.to_dict()}
        if model is not None:
            _loc = model.function_at(f.file_path, f.line_start)
            if _loc is not None:
                out.metadata = {
                    **out.metadata,
                    "evm_semantics": analyze_evm_calls(_loc.fn.body or "").to_dict(),
                }
        return out

    # -- rule engine --------------------------------------------------------
    def _challenge(
        self,
        f: Finding,
        model: ReachabilityModel | None,
        is_pseudo: bool,
    ) -> Challenge | None:
        loc = None
        if model is not None:
            loc = model.function_at(f.file_path, f.line_start)

        # 0. declaration-only evidence: a signature with no implementation body
        #    cannot be verified as an executable exploit.
        if _declaration_only(f.evidence):
            first = (f.evidence or "").strip().splitlines()[0][:160]
            return Challenge(
                rule="iface0_declaration_only_evidence",
                verdict=FindingStatus.UNVERIFIED,
                reason=(
                    "the finding's evidence is a function declaration "
                    "(interface/abstract signature) with no implementation body; "
                    "there is insufficient evidence to verify exploitability — "
                    "the conclusion is unverified"
                ),
                counterexamples=[first] if first else [],
            )

        # 1. read-only contradiction: a mutation claim pinned on a view/pure
        #    function. Decisive — a view function cannot mutate state.
        claim = f"{f.title} {f.description} {f.impact} {f.attack_scenario}"

        # 0b. EVM execution semantics: a claim that contradicts how transfer()/
        #     send()/low-level call()/revert actually behave is refuted
        #     deterministically (never left to LLM reasoning alone).
        if loc is not None:
            evm_ref = refute_evm_claim(loc.fn.body or "", claim)
            if evm_ref is not None:
                return Challenge(
                    rule=evm_ref.rule,
                    verdict=FindingStatus.REJECTED,
                    reason=evm_ref.reason,
                    counterexamples=evm_ref.counterexamples,
                )
        if (
            loc is not None
            and model is not None
            and model.is_view(loc)
            and _RE_MUTATING_CLAIM.search(claim)
            and self._evidence_in_function(f, loc)
        ):
            header = loc.header.strip()[:200]
            return Challenge(
                rule="ro0_readonly_contradiction",
                verdict=FindingStatus.REJECTED,
                reason=(
                    f"the located function `{loc.fn.name}` is declared "
                    f"{loc.fn.mutability} and cannot mutate state or perform the "
                    "claimed privileged action; the claim contradicts the source"
                ),
                counterexamples=[header] if header else [],
            )

        # 2. internal / unreachable: the exploit cannot be invoked externally.
        if loc is not None and model is not None:
            verdict = model.reachability(loc)
            if verdict == "not_reachable":
                header = loc.header.strip()[:200]
                return Challenge(
                    rule="ra0_internal_unreachable",
                    verdict=FindingStatus.INFORMATIONAL,
                    reason=(
                        f"the flagged function `{loc.fn.name}` is "
                        f"{loc.fn.visibility} and is not reachable from any "
                        "external entry point in the analyzed source; an "
                        "attacker cannot invoke it directly, so the claim of "
                        "external exploitability is unsupported"
                    ),
                    counterexamples=[header] if header else [],
                )

        # 3. authorization-gated: every external path to the function passes an
        #    authorization check -> "missing access control" is contradicted.
        if (
            loc is not None
            and model is not None
            and _RE_MISSING_AUTHZ.search(claim)
            and model.attacker_can_reach(loc) is False
        ):
            gates = model.gating_guards(loc.key)
            guard = "; ".join(gates) if gates else "an authorization check"
            return Challenge(
                rule="ac0_authz_gated_path",
                verdict=FindingStatus.INFORMATIONAL,
                reason=(
                    "every external path to the flagged function passes an "
                    f"authorization gate (`{guard}`); an unprivileged caller "
                    "cannot reach it without authorization, so the 'missing "
                    "access control' claim is unsupported"
                ),
                counterexamples=gates or ["an authorization check on the call path"],
            )

        # 3b. existing protection: a reentrancy claim on a function that is
        #     already guarded against reentrancy is contradicted by the guard
        #     (existing protection / state-rollback semantics).
        if loc is not None and _RE_REENTRANCY_CLAIM.search(claim):
            guards = [
                m
                for m in (loc.fn.modifiers or ())
                if str(m).strip().lower() in _GUARD_MODIFIERS
            ]
            if guards:
                return Challenge(
                    rule="pr0_existing_guard",
                    verdict=FindingStatus.INFORMATIONAL,
                    reason=(
                        f"the flagged function `{loc.fn.name}` is protected by an "
                        f"existing reentrancy guard ({', '.join(guards)}); the "
                        "reentrancy claim is contradicted by that protection"
                    ),
                    counterexamples=[f"modifier {g}" for g in guards],
                )

        # 4. proxy posture: the contract is a recognized proxy (UUPS /
        #    transparent / beacon) AND upgrade/admin authorization is enforced
        #    by design (a guarded _authorizeUpgrade override, or a transparent
        #    proxy admin gate). The "missing access control" claim reflects the
        #    standard proxy pattern, not a defect. Requires positive evidence of
        #    an authorization mechanism - an UNGUARDED _authorizeUpgrade or a
        #    proxy with no admin gate is left untouched.
        if (
            loc is not None
            and model is not None
            and model.is_proxy()
            and (_RE_MISSING_AUTHZ.search(claim) or _RE_UPGRADE_ADMIN_CLAIM.search(claim))
        ):
            evidence = model.upgrade_authorization_evidence()
            if evidence:
                return Challenge(
                    rule="pxy0_proxy_admin_by_design",
                    verdict=FindingStatus.INFORMATIONAL,
                    reason=(
                        "the contract is a recognized proxy pattern and upgrade/"
                        "admin authorization is enforced by design "
                        f"(`{evidence}`); the reported control reflects the "
                        "standard proxy design rather than a missing-control defect"
                    ),
                    counterexamples=[evidence],
                )

        # 5. vendored third-party library, standard semantics: out of the
        #    audited contract's surface.
        if (
            f.file_path
            and _VENDORED_PATH.search(f.file_path.replace("\\", "/"))
            and f.category is not None
            and f.category.value in ("token", "access_control", "proxy")
            and _RE_STANDARD_BEHAVIOR.search(claim)
        ):
            return Challenge(
                rule="vnd0_vendored_standard",
                verdict=FindingStatus.INFORMATIONAL,
                reason=(
                    f"the flagged code is vendored third-party library code "
                    f"({f.file_path}); the reported pattern is standard library "
                    "semantics, not a defect introduced by the audited contract"
                ),
                counterexamples=[f.file_path],
            )
        return None

    @staticmethod
    def _evidence_in_function(f: Finding, loc: Any) -> bool:
        """Guard the read-only rule against a mis-located finding: the evidence
        fragment must actually sit inside the located function body, otherwise
        the claim is probably about a different function and must not be
        refuted on this basis."""
        frag = _longest_line(f.evidence or "")
        if len(frag) < _MIN_FRAGMENT:
            return True  # too short to locate; fall back to the line range
        return _norm(frag) in _norm(loc.fn.body or "")

    # -- state transition ---------------------------------------------------
    def _apply(self, f: Finding, ch: Challenge) -> Finding:
        nf = f.model_copy(deep=True)
        nf.proposed_severity = f.severity
        nf.status = ch.verdict
        for c in ch.counterexamples:
            if c and c not in nf.contradicting_evidence:
                nf.contradicting_evidence.append(c)
        nf.metadata = {**nf.metadata}
        nf.metadata["challenge"] = {
            **ch.to_dict(),
            "original_status": f.status.value,
            "original_severity": f.severity.value,
        }
        # Step 3 reconciliation: preserve BOTH arguments (the discovering
        # agent's claim and the independent challenge) and record that the
        # disagreement was resolved by source evidence, not by vote.
        nf.metadata["reconciliation"] = {
            "discovery": {
                "status": f.status.value,
                "severity": f.severity.value,
                "title": f.title,
                "impact": f.impact,
                "preconditions": f.preconditions,
                "attack_sequence": f.attack_scenario,
                "sources": list(f.source),
            },
            "challenge": {
                "rule": ch.rule,
                "verdict": ch.verdict.value,
                "reason": ch.reason,
                "counterexamples": list(ch.counterexamples),
            },
            "resolved_by": (
                "deterministic source analysis (independent adversarial review); "
                "no majority vote"
            ),
            "final_status": nf.status.value,
        }
        sev, basis = assess(nf)
        nf.severity = sev
        nf.metadata["challenge"]["severity_basis"] = basis
        swc = enrich_swc(nf)
        if swc:
            nf.swc_id = swc
        nf.validation_method = "adversarial_review"
        nf.validation_result = nf.status.value
        nf.limitations = [
            *nf.limitations,
            f"adversarial review: {ch.reason}",
        ]
        return nf
