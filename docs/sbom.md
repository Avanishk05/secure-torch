# SBOM Policy (Experimental)

```{warning}
SPDX AI Profile is not yet widely adopted (early 2026). This feature is forward-looking. secure-torch is helping establish the standard. Use it for evaluation, not production enforcement.
```

## Overview

secure-torch can parse SPDX 2.3/3.0 AI Profile SBOM files and evaluate them against OPA Rego policies.

## Parse an SBOM

```python
from secure_torch.sbom.spdx_parser import parse_sbom

sbom = parse_sbom("model.spdx.json")

print(sbom.spdx_version)    # "SPDX-2.3"
print(sbom.name)             # "bert-base-uncased"
print(sbom.supplied_by)      # "Organization: huggingface.co"
print(sbom.model_type)       # "transformer"
print(sbom.sensitive_pii)    # "no"
```

## Evaluate a Rego policy

```python
from secure_torch.sbom.opa_runner import OPAPolicyRunner

runner = OPAPolicyRunner("policy/production.rego")
denials = runner.evaluate(sbom, context={"environment": "production"})

if denials:
    raise RuntimeError(f"Policy violations: {denials}")
```

## Example policy

```rego
package secure_torch.policy

# Block models with sensitive PII
deny[msg] {
    input.sensitivePersonalInformation == "yes"
    msg := "Model contains sensitive personal information"
}

# Block GPL datasets in production
deny[msg] {
    ds := input.aiProfile.trainingDatasets[_]
    startswith(ds.license, "GPL")
    input.environment == "production"
    msg := sprintf("GPL dataset '%v' blocked in production", [ds.name])
}
```

## OPA binary vs Python fallback

The runner uses the `opa` binary if available. If not installed, a pure-Python fallback evaluates common deny patterns.

Install OPA for full Rego support:

```bash
# Linux/macOS
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa && mv opa /usr/local/bin/

# Windows
winget install OpenPolicyAgent.OPA
```

## SPDX AI Profile fields supported

| Field | SPDX 2.3 path | SPDX 3.0 path |
|---|---|---|
| `supplied_by` | `packages[0].suppliedBy` | `packages[0].originator` |
| `model_type` | `packages[0].typeOfModel` | `aiProfile.modelType` |
| `sensitive_pii` | `packages[0].sensitivePersonalInformation` | — |
| `training_info` | `packages[0].informationAboutTraining` | `aiProfile.trainingDatasets` |
