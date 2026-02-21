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
| `pickle_global_unknown_module:X` | 15 | Unknown module reference in pickle |
| `pickle_reduce_opcode:X` | 20 | REDUCE opcode with non-safe callable |
| `pickle_inst_opcode` | 25 | INST opcode (older RCE vector) |
| `safetensors_code_in_metadata` | 50 | Code-like string in safetensors metadata |
| `safetensors_unsafe_dtype:X` | 30 | Unsafe dtype (object, python_object) |
| `safetensors_header_too_large` | 20 | Header exceeds 100MB |
| `onnx_custom_op_domain:X` | 30 | Custom operator domain |
| `onnx_external_data` | 20 | External data references |
| `onnx_nested_graph` | 10 | Nested subgraph |
| `unknown_publisher` | 20 | Signer not in trusted_publishers |
| `untrusted_publisher` | 20 | Signer verified but not in allowlist |

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
