"""
Unit tests — sbom/spdx_parser.py

Direct unit tests for parse_sbom():
- Valid full SPDX JSON
- Missing fields handled gracefully
- Malformed JSON returns None
- aiProfile.trainingDatasets parsed
- sensitivePersonalInformation mapped
"""

from __future__ import annotations

import json
import os
import tempfile


from secure_torch.sbom.spdx_parser import parse_sbom


def write_spdx(data: dict) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".spdx.json", delete=False, encoding="utf-8")
    json.dump(data, f)
    f.close()
    return f.name


class TestSpdxParser:
    def test_full_spdx_parsed_correctly(self):
        """All standard SPDX fields must map to SBOMRecord."""
        path = write_spdx(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "my-model",
                "packages": [
                    {
                        "suppliedBy": "ai-labs.example.com",
                        "typeOfModel": "LLM",
                        "sensitivePersonalInformation": "no",
                        "informationAboutTraining": "Wikipedia, CC0 datasets",
                    }
                ],
            }
        )
        try:
            record = parse_sbom(path)
            assert record is not None
            assert record.spdx_version == "SPDX-2.3"
            assert record.name == "my-model"
            assert record.supplied_by == "ai-labs.example.com"
            assert record.model_type == "LLM"
            assert record.sensitive_pii == "no"
            assert record.training_info == "Wikipedia, CC0 datasets"
        finally:
            os.unlink(path)

    def test_missing_spdx_version_is_none(self):
        path = write_spdx({"name": "model", "packages": []})
        try:
            record = parse_sbom(path)
            assert record is not None
            assert record.spdx_version is None
        finally:
            os.unlink(path)

    def test_missing_packages_no_crash(self):
        """SBOM without packages must return a valid (partial) record."""
        path = write_spdx({"spdxVersion": "SPDX-2.3", "name": "model"})
        try:
            record = parse_sbom(path)
            assert record is not None
            assert record.supplied_by is None
        finally:
            os.unlink(path)

    def test_malformed_json_returns_none(self):
        """Malformed JSON must return None, not raise."""
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".spdx.json", delete=False, encoding="utf-8"
        )
        f.write("{ this is not: valid json }")
        f.close()
        try:
            record = parse_sbom(f.name)
            assert record is None
        finally:
            os.unlink(f.name)

    def test_nonexistent_file_returns_none(self):
        """Missing file must return None, not raise."""
        record = parse_sbom("/nonexistent/path/model.spdx.json")
        assert record is None

    def test_sensitive_pii_yes_parsed(self):
        path = write_spdx(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "pii-model",
                "packages": [{"sensitivePersonalInformation": "yes"}],
            }
        )
        try:
            record = parse_sbom(path)
            assert record.sensitive_pii == "yes"
        finally:
            os.unlink(path)

    def test_ai_profile_training_datasets_parsed(self):
        """SPDX 3.0 aiProfile.trainingDatasets must be captured in training_info."""
        path = write_spdx(
            {
                "spdxVersion": "SPDX-3.0",
                "name": "model",
                "packages": [],
                "aiProfile": {
                    "modelType": "NLP",
                    "trainingDatasets": [
                        {"name": "Wikipedia", "license": "CC0"},
                        {"name": "Books3", "license": "Unknown"},
                    ],
                },
            }
        )
        try:
            record = parse_sbom(path)
            assert record is not None
            assert record.model_type == "NLP"
            assert record.training_info is not None
            assert "Wikipedia" in record.training_info
        finally:
            os.unlink(path)

    def test_originator_fallback_for_supplied_by(self):
        """If suppliedBy is missing, originator should be used as supplied_by."""
        path = write_spdx(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "model",
                "packages": [{"originator": "Organization: Acme Inc"}],
            }
        )
        try:
            record = parse_sbom(path)
            assert record.supplied_by == "Organization: Acme Inc"
        finally:
            os.unlink(path)

    def test_raw_data_preserved(self):
        """The full raw dict must be preserved in SBOMRecord.raw."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "name": "model",
            "packages": [{"custom_field": "custom_value"}],
        }
        path = write_spdx(data)
        try:
            record = parse_sbom(path)
            assert record.raw == data
        finally:
            os.unlink(path)
