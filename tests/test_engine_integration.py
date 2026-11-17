"""Priority 4: static-engine integration contract.

Pins what must survive parsing and merging, independently of any LLM:

- original detector identifiers (slither check names, mythril SWC ids);
- the engine's own severity/confidence words (mapped severity + raw strings);
- source mappings (file, line range) and function/contract names;
- the raw engine record per finding and the raw payload per run (bounded,
  with a sha256 of the full payload);
- engine execution status and duration in ToolExecution;
- cross-engine duplicates describing ONE root cause collapse into a single
  vulnerability whose `source` lists every engine (and whose metadata keeps
  every detector id) - while distinct weaknesses never merge.
"""

from __future__ import annotations

import hashlib
import json

from agentsafe.agents.validation import ValidationAgent
from agentsafe.analyzers.bytecode import _parse_mythril
from agentsafe.analyzers.proc import ProcResult
from agentsafe.analyzers.source import _capture_raw, _parse_slither
from agentsafe.report import merge_findings, root_cause_class
from agentsafe.schemas import (
    Severity,
    ToolExecution,
)

SLITHER_JSON = {
    "success": True,
    "results": {
        "detectors": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "description": "Reentrancy in WETH9.withdraw (WETH9.sol#8-11): "
                               "external call before state update",
                "elements": [
                    {
                        "type": "function",
                        "name": "withdraw",
                        "source_mapping": {
                            "filename": {"short": "WETH9.sol"},
                            "lines": [10, 11],
                        },
                    },
                    {"type": "contract", "name": "WETH9"},
                ],
            }
        ]
    },
}

MYTHRIL_JSON = {
    "success": True,
    "error": None,
    "issues": [
        {
            "title": "External Call To User-Supplied Address",
            "swc-id": "107",
            "severity": "High",
            "address": 1234,
            "code": "CALL",
            "description": "Reentrancy: state write after external call",
            "function": "withdraw",
        }
    ],
}


def _slither_findings():
    payload = json.dumps(SLITHER_JSON).encode()
    return _parse_slither(ProcResult(exit_code=0, stdout=payload, stderr=b""))[0]


def _mythril_findings():
    payload = json.dumps(MYTHRIL_JSON).encode()
    return _parse_mythril(ProcResult(exit_code=0, stdout=payload, stderr=b""))[0]


class TestParsersPreserveEngineFacts:
    def test_slither_detector_identity_severity_confidence(self):
        (f,) = _slither_findings()
        assert f.detector_id == "reentrancy-eth"
        assert f.source == ["slither"]
        assert f.severity is Severity.HIGH
        # the engine's own words, never overwritten by a mapping
        assert f.metadata["tool_impact"] == "high"
        assert f.metadata["tool_severity_raw"] == "high"
        assert f.metadata["tool_confidence"] == "Medium"

    def test_slither_source_mapping_and_names(self):
        (f,) = _slither_findings()
        assert f.file_path == "WETH9.sol"
        assert (f.line_start, f.line_end) == (10, 11)
        assert f.affected_functions == ["withdraw"]
        assert f.metadata["function"] == "withdraw"
        assert f.metadata["contract"] == "WETH9"

    def test_slither_raw_record_kept_verbatim(self):
        (f,) = _slither_findings()
        raw = json.loads(f.metadata["tool_raw"])
        assert raw["check"] == "reentrancy-eth"
        assert raw["impact"] == "High"
        assert raw["confidence"] == "Medium"

    def test_mythril_detector_identity_and_raw_record(self):
        (f,) = _mythril_findings()
        assert f.detector_id == "SWC-107"
        assert f.source == ["mythril"]
        assert f.severity is Severity.HIGH
        assert f.metadata["swc_id"] == "107"
        assert f.metadata["bytecode_offset"] == 1234
        assert f.metadata["tool_severity_raw"] == "High"
        assert f.metadata["function"] == "withdraw"
        assert json.loads(f.metadata["tool_raw"])["swc-id"] == "107"
        # bytecode findings honestly carry no source mapping
        assert f.file_path is None and f.line_start is None

    def test_raw_payload_capture_digest_covers_full_payload(self):
        payload = json.dumps(SLITHER_JSON).encode()
        text, digest, size = _capture_raw(payload)
        assert text == payload.decode()
        assert digest == hashlib.sha256(payload).hexdigest()
        assert size == len(payload)

    def test_tool_execution_carries_status_duration_and_raw(self):
        te = ToolExecution(
            tool="slither",
            kind="source",
            executed=True,
            exit_code=0,
            duration_seconds=1.25,
            tool_version="0.10.4",
            raw_output="{}",
            raw_output_sha256="ab" * 32,
            raw_output_bytes=2,
            findings_count=1,
        )
        blob = json.loads(te.model_dump_json())
        assert blob["duration_seconds"] == 1.25
        assert blob["raw_output"] == "{}"
        assert blob["raw_output_sha256"] == "ab" * 32


class TestCrossEngineDeduplication:
    def _validated(self, slither=(), mythril=()):
        v = ValidationAgent()
        out = v.validate_tools(
            [*slither, *mythril], [], {"WETH9.sol": "contract WETH9 {}"}
        )
        return out.findings

    def test_same_root_cause_from_two_engines_is_one_vulnerability(self):
        sl, my = _slither_findings()[0], _mythril_findings()[0]
        merged = merge_findings(self._validated([sl], [my]), [])
        reent = [f for f in merged if root_cause_class(f) == "reentrancy"]
        assert len(reent) == 1, [(f.title, f.source) for f in reent]
        host = reent[0]
        # one vulnerability, both engines credited, both detector ids kept
        assert set(host.source) == {"slither", "mythril"}
        dets = {m.get("detector_id") for m in host.metadata["merged_from"]}
        assert dets == {"SWC-107"}
        assert host.detector_id == "reentrancy-eth"  # primary keeps its id
        # the located record's source mapping wins (data over absence)
        assert host.file_path == "WETH9.sol"
        assert host.line_start == 10

    def test_different_root_causes_do_not_merge(self):
        sl = _slither_findings()[0]
        my = _mythril_findings()[0]
        my.detector_id = "SWC-101"  # arithmetic
        my.title = "[mythril] Integer Overflow"
        my.swc_id = "SWC-101"
        merged = merge_findings([sl, my], [])
        assert len(merged) == 2

    def test_same_class_in_different_files_does_not_merge(self):
        a = _slither_findings()[0]
        b = _slither_findings()[0].model_copy(deep=True)
        b.source = ["mythril"]
        b.detector_id = "SWC-107"
        b.file_path = "Other.sol"
        merged = merge_findings([a, b], [])
        assert len(merged) == 2

    def test_two_distinct_bytecode_issues_of_one_class_stay_separate(self):
        """Unique-per-engine rule: two genuine mythril reentrancies must never
        collapse into one just because they share an SWC class."""
        m1 = _mythril_findings()[0]
        m2 = _mythril_findings()[0].model_copy(deep=True)
        m2.metadata = {**m2.metadata, "bytecode_offset": 9999}
        m2.title = "[mythril] Reentrancy in claim()"
        m2.evidence = "bytecode offset 9999: CALL"
        merged = merge_findings([m1, m2], [])
        assert len(merged) == 2

    def test_unknown_detector_class_never_merges(self):
        """An unknown detector/category is never collapsed on class alone -
        even at the same location the engines stay separate findings."""
        a = _slither_findings()[0].model_copy(deep=True)
        b = _slither_findings()[0].model_copy(deep=True)
        a.detector_id, a.swc_id = "mystery-check-a", None
        b.source = ["mythril"]
        b.detector_id, b.swc_id = "mythril-mystery", None
        from agentsafe.schemas import FindingCategory

        a.category = FindingCategory.UNKNOWN
        b.category = FindingCategory.UNKNOWN
        assert root_cause_class(a) is None
        assert root_cause_class(b) is None
        merged = merge_findings([a, b], [])
        assert len(merged) == 2

    def test_validation_preserves_tool_identity_and_raw_record(self):
        sl = _slither_findings()[0]
        v = ValidationAgent()
        out = v.validate_tools([sl], [], {"WETH9.sol": "contract WETH9 {}"})
        f = out.findings[0]
        assert f.detector_id == "reentrancy-eth"
        assert f.swc_id == "SWC-107"
        assert f.metadata["tool_raw"]
        assert f.metadata["tool_confidence"] == "Medium"
        # tool source mapping is reported as verified (AST-derived)
        assert f.location_status == "verified"
