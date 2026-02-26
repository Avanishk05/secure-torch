"""
OPA (Open Policy Agent) Rego policy runner — Phase 3 (Experimental).

Evaluates user-supplied .rego policy files against parsed SBOM data.
Uses the opa binary if available, falls back to a pure-Python subset evaluator
for simple deny rules.

Note: Full OPA Rego support requires the opa binary.
The pure-Python fallback handles the most common patterns.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Optional, Any

from secure_torch.models import SBOMRecord


class OPAPolicyRunner:
    def __init__(self, policy_path: str) -> None:

        self.policy_path: str = policy_path
        self._opa_binary: Optional[str] = shutil.which("opa")

    def evaluate(
        self,
        sbom: SBOMRecord,
        context: Optional[dict[str, Any]] = None,
    ) -> list[str]:

        input_data = self._build_input(sbom, context or {})

        if self._opa_binary:
            return self._evaluate_with_opa(input_data)

        return self._evaluate_python_fallback(input_data)

    def _build_input(
        self,
        sbom: SBOMRecord,
        context: dict[str, Any],
    ) -> dict[str, Any]:

        return {
            "spdxVersion": sbom.spdx_version,
            "name": sbom.name,
            "suppliedBy": sbom.supplied_by,
            "typeOfModel": sbom.model_type,
            "sensitivePersonalInformation": sbom.sensitive_pii,
            "informationAboutTraining": sbom.training_info,
            "aiProfile": sbom.raw.get("aiProfile", {}),
            **context,
        }

    def _evaluate_with_opa(self, input_data: dict[str, Any]) -> list[str]:

        if self._opa_binary is None:
            return []

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            json.dump(input_data, f)
            input_file = f.name

        opa_binary: str = self._opa_binary  # narrowed from Optional[str]

        try:
            result = subprocess.run(
                [
                    opa_binary,
                    "eval",
                    "--data",
                    self.policy_path,
                    "--input",
                    input_file,
                    "--format",
                    "json",
                    "data.secure_torch.policy.deny",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return [result.stderr]

            parsed = json.loads(result.stdout)

            if not parsed.get("result"):
                return []

            return parsed["result"][0]["expressions"][0]["value"]

        finally:
            os.unlink(input_file)

    def _evaluate_python_fallback(
        self,
        input_data: dict[str, Any],
    ) -> list[str]:
        """Pure-Python subset evaluator for simple deny rules."""
        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                policy_text = f.read()
        except Exception as e:
            return [f"Cannot read policy file: {e}"]

        denials = []

        # Pattern: block models with sensitive PII
        if "sensitivePersonalInformation" in policy_text:
            pii = input_data.get("sensitivePersonalInformation", "")
            if isinstance(pii, str) and pii.lower() in ("yes", "true", "1"):
                denials.append("Model contains sensitive personal information")

        # Pattern: require suppliedBy field
        if "suppliedBy" in policy_text and "not input.suppliedBy" in policy_text:
            if not input_data.get("suppliedBy"):
                denials.append("Model SBOM missing required suppliedBy field")

        # Pattern: block GPL-licensed datasets in production
        if "GPL" in policy_text and input_data.get("environment") == "production":
            ai_profile = input_data.get("aiProfile", {})
            datasets = ai_profile.get("trainingDatasets", [])
            for ds in datasets:
                license_ = ds.get("license", "")
                if license_.startswith("GPL"):
                    denials.append(
                        f"GPL dataset '{ds.get('name', 'unknown')}' blocked in production"
                    )

        return denials
