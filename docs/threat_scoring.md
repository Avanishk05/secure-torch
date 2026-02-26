# Threat Scoring

## Overview

Every model load produces an **explainable threat score** — a named breakdown of risk factors, not a magic number.

```python
model, report = torch.load("model.pt", audit_only=True)

print(report.threat_score)       # 90
print(report.threat_level)       # ThreatLevel.CRITICAL
print(report.score_breakdown)
# {
#   'unsigned_model': 40,
#   'custom_ops_detected': 30,
#   'unknown_publisher': 20,
# }
```

## Score Contributors

| Key | Score | Trigger |
|---|---|---|
| `unsigned_model` | 40 | No Sigstore bundle found |
| `pickle_global_unknown_module:X` | 10 | Unknown module reference in pickle |
| `pickle_reduce_opcode:X` | 25 | REDUCE opcode with non-safe callable |
| `pickle_inst_opcode` | 10 | INST opcode (older RCE vector) |
| `safetensors_code_in_metadata:X` | 50 | Code-like string in safetensors metadata |
| `safetensors_unsafe_dtype:X` | 35 | Unsafe dtype (object, python_object) |
| `safetensors_header_too_large` | 15 | Header exceeds 100MB |
| `onnx_custom_op_domain:X` | 30 | Custom operator domain |
| `onnx_suspicious_external_data_path:X` | 30 | Suspicious external data references |
| `onnx_nested_graph:X` | 10 | Nested subgraph |
| `unknown_publisher` | 20 | Signer not in trusted_publishers |
| `untrusted_publisher` | 20 | Signer verified but not in allowlist |
| `sbom_missing` | 20 | No accompanying SBOM found |
| `provenance_unverifiable` | 25 | Signature exists but verification failed |
| `sbom_policy_denial:X` | 30 | Rego policy denied model |
| `onnx_code_in_metadata:X` | 50 | Code-like string in ONNX metadata |

## Threat Levels

| Score | Level |
|---|---|
| 0 | `SAFE` |
| 1–19 | `LOW` |
| 20–49 | `MEDIUM` |
| 50–79 | `HIGH` |
| 80+ | `CRITICAL` |

## Configuring the threshold

```python
# Default: block if score > 20 (MEDIUM)
model = torch.load("model.pt")

# Strict: block if score > 0
model = torch.load("model.pt", max_threat_score=0)

# Permissive: block only CRITICAL
model = torch.load("model.pt", max_threat_score=79)

# Never block (audit only)
model, report = torch.load("model.pt", audit_only=True)
```

## Accessing the full report

```python
model, report = torch.load("model.pt", audit_only=True)

report.path             # str — model file path
report.format           # ModelFormat.SAFETENSORS / PICKLE / ONNX
report.threat_score     # int — total score
report.threat_level     # ThreatLevel enum
report.score_breakdown  # dict[str, int] — named contributors
report.findings         # list[str] — blocking findings
report.warnings         # list[str] — non-blocking warnings
report.sha256           # str — SHA-256 of model file
report.size_bytes       # int
report.load_allowed     # bool
report.sandbox_active   # bool
report.provenance       # ProvenanceRecord
```
