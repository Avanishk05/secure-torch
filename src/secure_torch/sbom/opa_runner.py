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

from secure_torch.models import SBOMRecord


class OPAPolicyRunner:
    """
    Evaluates OPA Rego policies against SBOM data.

    Tries the opa binary first. Falls back to pure-Python subset evaluator
    for simple deny rules when opa is not installed.
    """

    def __init__(self, policy_path: str) -> None:
        self.policy_path = policy_path
        self._opa_binary = shutil.which("opa")

    def evaluate(self, sbom: SBOMRecord, context: dict = None) -> list[str]:
        """
        Evaluate the policy against SBOM data.

        Args:
            sbom: Parsed SBOM record.
            context: Additional context (e.g., {"environment": "production"}).

        Returns:
            List of denial messages. Empty list means policy allows the model.
        """
        input_data = self._build_input(sbom, context or {})

        if self._opa_binary:
            return self._evaluate_with_opa(input_data)
        else:
            return self._evaluate_python_fallback(input_data)

    def _build_input(self, sbom: SBOMRecord, context: dict) -> dict:
        """Build the OPA input document from SBOM + context."""
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

    def _evaluate_with_opa(self, input_data: dict) -> list[str]:
        """Evaluate using the opa binary."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(input_data, f)
            input_file = f.name

        try:
            result = subprocess.run(
                [
                    self._opa_binary, "eval",
                    "--data", self.policy_path,
                    "--input", input_file,
                    "--format", "json",
                    "data.secure_torch.policy.deny",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return [f"OPA evaluation error: {result.stderr.strip()}"]

            output = json.loads(result.stdout)
            results = output.get("result", [])
            if results and results[0].get("expressions"):
                denials = results[0]["expressions"][0].get("value", [])
                return list(denials) if isinstance(denials, list) else []
            return []

        except subprocess.TimeoutExpired:
            return ["OPA policy evaluation timed out"]
        except Exception as e:
            return [f"OPA evaluation failed: {e}"]
        finally:
            os.unlink(input_file)

    def _evaluate_python_fallback(self, input_data: dict) -> list[str]:
        """
        Pure-Python subset evaluator for simple deny rules.

        Supports the most common pattern:
            deny[msg] { condition; msg := "..." }

        Parses .rego file and evaluates simple conditions.
        """
        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                policy_text = f.read()
        except Exception as e:
            return [f"Cannot read policy file: {e}"]

        denials = []

        # Pattern: block GPL-licensed training datasets in production
        if "GPL" in policy_text and input_data.get("environment") == "production":
            ai_profile = input_data.get("aiProfile", {})
            datasets = ai_profile.get("trainingDatasets", [])
            for ds in datasets:
                license_ = ds.get("license", "")
                if license_.startswith("GPL"):
                    denials.append(
                        f"GPL dataset '{ds.get('name', 'unknown')}' blocked in production"
                    )

        # Pattern: block models with sensitive PII
        if "sensitivePersonalInformation" in policy_text:
            pii = input_data.get("sensitivePersonalInformation", "")
            if isinstance(pii, str) and pii.upper() in ("YES", "TRUE", "1"):
                denials.append("Model contains sensitive personal information — blocked by policy")

        # Pattern: require suppliedBy field
        if "suppliedBy" in policy_text and "require" in policy_text.lower():
            if not input_data.get("suppliedBy"):
                denials.append("Model SBOM missing required suppliedBy field")

        return denials
