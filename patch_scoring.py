import os

file_path = "docs/threat_scoring.md"
with open(file_path, "r", encoding="utf-8") as f:
    text = f.read()

old_table = """| Key | Score | Trigger |
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
| `untrusted_publisher` | 20 | Signer verified but not in allowlist |"""

new_table = """| Key | Score | Trigger |
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
| `onnx_code_in_metadata:X` | 50 | Code-like string in ONNX metadata |"""

if old_table in text:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(text.replace(old_table, new_table))
    print("success")
else:
    print("failure")
