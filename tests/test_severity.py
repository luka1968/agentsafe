"""Evidence-based severity rubric acceptance (documented, deterministic).

Section 4: severity is assessed from exploit prerequisites, attack
complexity, privileges, affected assets, financial impact, scope and
mitigating controls - NEVER from LLM confidence or LLM repetition.
"""

import pytest

from agentsafe.severity import assess, enrich_swc
from agentsafe.schemas import Finding, FindingStatus, Severity


def _f(**kw) -> Finding:
    base = dict(
        title="Unprotected drain()",
        severity="critical",
        status=FindingStatus.CONFIRMED,
        source=["slither"],
        detector_id="arbitrary-send-eth",
        description="Anyone can call drain() and take all funds",
        evidence="function drain() external { }",
        file_path="Vault.sol",
        line_start=42,
    )
    base.update(kw)
    return Finding(**base)


class TestSeverityRubric:
    def test_confirmed_permissionless_critical_stays_critical(self):
        sev, basis = assess(_f())
        assert sev is Severity.CRITICAL
        assert basis == "rubric:confirmed"

    def test_confirmed_privilege_gate_downgrades_one_level(self):
        f = _f(description="onlyOwner can drain; requires the owner key")
        sev, basis = assess(f)
        assert sev is Severity.HIGH
        assert "privilege_gate" in basis

    def test_confirmed_mitigation_downgrades_one_level(self):
        f = _f(severity="high", description="reentrancy claim; nonReentrant guard present on entry")
        sev, basis = assess(f)
        assert sev is Severity.MEDIUM
        assert "mitigating_controls" in basis

    def test_reductions_compound(self):
        f = _f(description="onlyOwner, pausable; requires owner to trigger")
        sev, _ = assess(f)
        assert sev is Severity.MEDIUM

    def test_floor_is_low_never_below(self):
        f = _f(severity="low", description="onlyOwner pausable hygiene issue")
        sev, _ = assess(f)
        assert sev is Severity.LOW

    def test_unvalidated_critical_capped_at_medium(self):
        f = _f(status=FindingStatus.POTENTIAL, severity="critical")
        sev, basis = assess(f)
        assert sev is Severity.MEDIUM
        assert basis == "rubric:unvalidated_capped_at_medium"

    def test_unvalidated_within_cap_unchanged(self):
        f = _f(status=FindingStatus.POTENTIAL, severity="medium")
        sev, basis = assess(f)
        assert sev is Severity.MEDIUM
        assert basis == "rubric:unvalidated_within_cap"

    def test_needs_manual_review_capped(self):
        f = _f(status=FindingStatus.NEEDS_MANUAL_REVIEW, severity="high")
        assert assess(f)[0] is Severity.MEDIUM

    def test_informational_is_info_regardless_of_claim(self):
        f = _f(status=FindingStatus.INFORMATIONAL, severity="critical")
        assert assess(f)[0] is Severity.INFO

    def test_rejected_keeps_claimed_severity(self):
        f = _f(status=FindingStatus.REJECTED, severity="high")
        sev, basis = assess(f)
        assert sev is Severity.HIGH
        assert basis == "rubric:rejected_keeps_claim"

    def test_llm_confidence_never_affects_severity(self):
        high_conf = _f(confidence=0.99)
        low_conf = _f(confidence=0.05)
        assert assess(high_conf)[0] is assess(low_conf)[0] is Severity.CRITICAL


class TestSwcEnrichment:
    def test_known_detector_maps_to_swc(self):
        assert enrich_swc(_f(detector_id="reentrancy-eth")) == "SWC-107"
        assert enrich_swc(_f(detector_id="integer-overflow")) == "SWC-101"

    def test_swc_prefixed_detector_passthrough(self):
        assert enrich_swc(_f(detector_id="SWC-101")) == "SWC-101"

    def test_unknown_detector_returns_none(self):
        assert enrich_swc(_f(detector_id="totally-custom-check")) is None

    def test_explicit_swc_id_wins(self):
        assert enrich_swc(_f(detector_id="reentrancy-eth", swc_id="SWC-999")) == "SWC-999"
