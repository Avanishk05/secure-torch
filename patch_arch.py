import os

file_path = "docs/architecture_and_usage.md"

with open(file_path, "r", encoding="utf-8") as f:
    text = f.read()

old_format = """        -   Safetensors: Detected via valid header length (8 bytes little-endian) and JSON header structure.
        -   Pickle-based PyTorch models: Detected via pickle protocol opcodes or PyTorch archive ZIP format.
        -   ONNX: Detected via valid protobuf structure and ONNX graph schema validation."""
new_format = """        -   Safetensors: Detected via valid header length (8 bytes little-endian) and JSON header structure.
        -   Pickle-based PyTorch models: Detected via pickle protocol opcodes (`\\x80\\x02` to `\\x80\\x05`) or PyTorch archive ZIP format.
        -   ONNX: Detected via valid protobuf structure magic bytes (`\\x08`)."""
text = text.replace(old_format, new_format)

old_sandbox = """    -   **Environment**: Strips `HTTP_PROXY`, `HTTPS_PROXY`, `AWS_ACCESS_KEY_ID`, etc., to prevent network access or credential exfiltration.
    -   **Communication**: Passes model path via args, returns tensors via pickle serialization over `multiprocessing.Pipe`. Because deserialization occurs only in the trusted parent process and the sandbox restricts arbitrary execution, this does not introduce additional code execution risk."""
new_sandbox = """    -   **Environment**: Strips `HTTP_PROXY`, `HTTPS_PROXY`, `FTP_PROXY`, etc., to provide best-effort isolation from network access.
    -   **Communication**: Passes model path via JSON payload over stdin. Returns tensors via a temporary `safetensors` or `onnx` payload file, rather than generic pickle over a pipe, to ensure the parent process never unpickles child-controlled bytes."""
text = text.replace(old_sandbox, new_sandbox)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(text)

print("success")
