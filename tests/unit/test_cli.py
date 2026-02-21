"""
Unit tests — cli.py

Covers:
- main() exit code 0 on valid model
- main() exit code 1 on missing file
- main() --json flag produces valid JSON with expected keys
- _report_to_dict() produces all expected keys with correct types
- _print_rich_report() renders without crashing (rich available)
- _print_rich_report() fallback when rich is not installed
"""
from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

import secure_torch as st
from secure_torch.cli import _report_to_dict, _print_rich_report, main
from secure_torch.models import (
    ModelFormat, ThreatLevel, ValidationReport, ProvenanceRecord, SBOMRecord
)


def make_safetensors_file() -> Path:
    header = {"__metadata__": {"model": "test"}}
    header_bytes = json.dumps(header).encode("utf-8")
    content = struct.pack("<Q", len(header_bytes)) + header_bytes
    f = tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def make_dummy_report(provenance=None, sbom=None) -> ValidationReport:
    return ValidationReport(
        path="/tmp/model.safetensors",
        format=ModelFormat.SAFETENSORS,
        threat_level=ThreatLevel.MEDIUM,
        threat_score=40,
        score_breakdown={"unsigned_model": 40},
        findings=[],
        warnings=["No signature bundle found - model is unsigned"],
        sha256="abc123" * 8,
        size_bytes=1024,
        load_allowed=True,
        sandbox_active=False,
        provenance=provenance or ProvenanceRecord(verified=False, error="No bundle"),
        sbom=sbom,
    )


# ── main() tests ──────────────────────────────────────────────────────────────

class TestCliMain:

    def test_audit_valid_file_exits_zero(self):
        path = make_safetensors_file()
        try:
            # audit_only is always True in main(), so this should succeed
            exit_code = main(["audit", str(path)])
            assert exit_code == 0
        finally:
            os.unlink(path)

    def test_audit_missing_file_exits_one(self):
        exit_code = main(["audit", "/nonexistent/path/model.pt"])
        assert exit_code == 1

    def test_audit_json_flag_produces_valid_json(self, capsys):
        path = make_safetensors_file()
        try:
            exit_code = main(["audit", str(path), "--json"])
            captured = capsys.readouterr()
            assert exit_code == 0
            parsed = json.loads(captured.out)
            assert "threat_score" in parsed
            assert "threat_level" in parsed
            assert "sha256" in parsed
        finally:
            os.unlink(path)

    def test_audit_json_flag_has_path_key(self, capsys):
        path = make_safetensors_file()
        try:
            main(["audit", str(path), "--json"])
            captured = capsys.readouterr()
            parsed = json.loads(captured.out)
            assert "path" in parsed
            assert "score_breakdown" in parsed
        finally:
            os.unlink(path)


# ── _report_to_dict() tests ────────────────────────────────────────────────────

class TestReportToDict:

    def test_all_base_keys_present(self):
        report = make_dummy_report()
        d = _report_to_dict(report)
        for key in ["path", "format", "threat_level", "threat_score",
                    "score_breakdown", "findings", "warnings", "sha256",
                    "size_bytes", "load_allowed", "sandbox_active"]:
            assert key in d, f"Missing key: {key}"

    def test_threat_level_is_string(self):
        report = make_dummy_report()
        d = _report_to_dict(report)
        assert isinstance(d["threat_level"], str)

    def test_format_is_string(self):
        report = make_dummy_report()
        d = _report_to_dict(report)
        assert isinstance(d["format"], str)

    def test_provenance_included_when_present(self):
        prov = ProvenanceRecord(verified=True, signer="org@example.com",
                                issuer="https://accounts.google.com",
                                bundle_path="/tmp/model.sig", mode="pubkey")
        report = make_dummy_report(provenance=prov)
        d = _report_to_dict(report)
        assert "provenance" in d
        assert d["provenance"]["verified"] is True
        assert d["provenance"]["signer"] == "org@example.com"

    def test_sbom_included_when_present(self):
        sbom = SBOMRecord(spdx_version="SPDX-2.3", name="my-model",
                          supplied_by="Acme", model_type="LLM",
                          sensitive_pii="no", training_info="wiki")
        report = make_dummy_report(sbom=sbom)
        d = _report_to_dict(report)
        assert "sbom" in d
        assert d["sbom"]["name"] == "my-model"

    def test_no_provenance_key_when_none(self):
        report = make_dummy_report(provenance=None)
        # Override to set provenance to None directly
        report.provenance = None
        d = _report_to_dict(report)
        assert "provenance" not in d

    def test_no_sbom_key_when_none(self):
        report = make_dummy_report()
        d = _report_to_dict(report)
        assert "sbom" not in d


# ── _print_rich_report() tests ─────────────────────────────────────────────────

class TestPrintRichReport:

    def test_rich_report_does_not_crash(self, capsys):
        """_print_rich_report must render without raising under any condition."""
        report = make_dummy_report()
        _print_rich_report(report)  # must not raise

    def test_rich_report_with_sbom_and_provenance_no_crash(self):
        """Full report with all optional fields must not crash."""
        prov = ProvenanceRecord(verified=True, signer="signer@test.com",
                                issuer="https://issuer.example.com",
                                bundle_path="/tmp/model.sigstore", mode="sigstore")
        sbom = SBOMRecord(name="my-model", supplied_by="Acme",
                          sensitive_pii="no", training_info="wiki")
        report = make_dummy_report(provenance=prov, sbom=sbom)
        _print_rich_report(report)  # must not raise

    def test_rich_fallback_when_not_installed(self, monkeypatch, capsys):
        """When rich is not installed, must fall back to report.summary()."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name.startswith("rich"):
                raise ImportError("rich not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        report = make_dummy_report()
        _print_rich_report(report)
        captured = capsys.readouterr()
        # summary() should have been called
        assert "Threat Level" in captured.out or "Model:" in captured.out
