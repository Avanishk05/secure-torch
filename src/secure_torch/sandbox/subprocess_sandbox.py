"""
Subprocess sandbox.

Loads models in a subprocess and returns results through a JSON protocol.
The parent process never unpickles child-controlled bytes.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from secure_torch.exceptions import SandboxError
from secure_torch.models import ModelFormat

logger = logging.getLogger(__name__)

_WORKER_SCRIPT = """
import json
import sys
from pathlib import Path

def _emit(payload):
    sys.stdout.write(json.dumps(payload) + "\\n")
    sys.stdout.flush()

def _extract_tensor_dict(result):
    import torch

    if isinstance(result, dict):
        if all(isinstance(k, str) for k in result.keys()) and all(
            isinstance(v, torch.Tensor) for v in result.values()
        ):
            return result
    if hasattr(result, "state_dict"):
        state = result.state_dict()
        if isinstance(state, dict) and all(isinstance(k, str) for k in state.keys()) and all(
            isinstance(v, torch.Tensor) for v in state.values()
        ):
            return state
    return None

def _persist_tensor_dict(tensors, output_path):
    import struct
    import safetensors.torch as st

    if tensors:
        st.save_file(tensors, output_path)
    else:
        # Minimal valid empty safetensors file.
        with open(output_path, "wb") as fh:
            fh.write(struct.pack("<Q", 2))
            fh.write(b"{}")

def main():
    line = sys.stdin.readline()
    if not line:
        _emit({"ok": False, "error": "No task payload received"})
        return

    task = json.loads(line)
    model_path = task["model_path"]
    fmt = task["fmt"]
    output_path = task["output_path"]
    weights_only = task.get("weights_only", True)

    if sys.platform == "linux":
        try:
            from secure_torch.sandbox.seccomp_sandbox import apply_seccomp
            apply_seccomp()
        except Exception:
            pass

    try:
        if fmt == "safetensors":
            import safetensors.torch as st

            tensors = st.load_file(model_path)
            _persist_tensor_dict(tensors, output_path)
            _emit({"ok": True, "transfer": "safetensors", "path": output_path})
            return

        if fmt == "pickle":
            import torch

            result = torch.load(model_path, map_location="cpu", weights_only=weights_only)
            tensors = _extract_tensor_dict(result)
            if tensors is None:
                _emit(
                    {
                        "ok": False,
                        "error": (
                            "Sandbox transfer supports tensor-dict payloads only for pickle. "
                            "Load without sandbox if full object reconstruction is required."
                        ),
                    }
                )
                return
            _persist_tensor_dict(tensors, output_path)
            _emit({"ok": True, "transfer": "safetensors", "path": output_path})
            return

        if fmt == "onnx":
            import onnx

            model = onnx.load(model_path)
            with open(output_path, "wb") as fh:
                fh.write(model.SerializeToString())
            _emit({"ok": True, "transfer": "onnx", "path": output_path})
            return

        _emit({"ok": False, "error": f"Unknown format: {fmt}"})
    except Exception as exc:
        _emit({"ok": False, "error": str(exc)})

main()
"""


class SubprocessSandbox:
    """
    Load models in a restricted subprocess.

    For pickle sources, sandbox mode returns tensor dictionaries only.
    """

    def load(
        self,
        path: Path,
        fmt: ModelFormat,
        map_location=None,
        weights_only: bool = True,
    ) -> Any:
        del map_location  # sandbox always loads to CPU inside the subprocess

        transfer_suffix = ".onnx" if fmt == ModelFormat.ONNX else ".safetensors"
        transfer_file = tempfile.NamedTemporaryFile(suffix=transfer_suffix, delete=False)
        transfer_file.close()
        output_path = Path(transfer_file.name)

        task = json.dumps(
            {
                "model_path": str(path),
                "fmt": fmt.value,
                "weights_only": weights_only,
                "output_path": str(output_path),
            }
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as worker_file:
            worker_file.write(_WORKER_SCRIPT)
            worker_path = Path(worker_file.name)

        try:
            proc = subprocess.Popen(
                [sys.executable, str(worker_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._restricted_env(),
            )

            stdout, stderr = proc.communicate(
                input=(task + "\n").encode("utf-8"),
                timeout=120,
            )

            if proc.returncode != 0:
                raise SandboxError(
                    f"Sandbox subprocess exited with code {proc.returncode}.\n"
                    f"stderr: {stderr.decode('utf-8', errors='replace')}"
                )

            result = self._parse_json_result(stdout)
            if not result.get("ok"):
                raise SandboxError(f"Sandbox load failed: {result.get('error')}")

            transfer_path = Path(result.get("path", ""))
            if transfer_path.resolve() != output_path.resolve():
                raise SandboxError("Sandbox returned an unexpected transfer path")

            return self._load_transfer_artifact(output_path, result.get("transfer", ""))

        except subprocess.TimeoutExpired:
            proc.kill()
            raise SandboxError("Sandbox subprocess timed out after 120 seconds")
        finally:
            try:
                worker_path.unlink(missing_ok=True)
            except Exception:
                pass
            try:
                output_path.unlink(missing_ok=True)
            except Exception:
                pass

    def _parse_json_result(self, stdout: bytes) -> dict[str, Any]:
        lines = stdout.decode("utf-8", errors="replace").splitlines()
        payload = next((line for line in reversed(lines) if line.strip()), "")
        if not payload:
            raise SandboxError("Sandbox produced no result payload")
        try:
            result = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"Sandbox returned invalid JSON payload: {exc}")
        if not isinstance(result, dict):
            raise SandboxError("Sandbox payload must be a JSON object")
        return result

    def _load_transfer_artifact(self, artifact_path: Path, transfer: str) -> Any:
        if transfer == "safetensors":
            try:
                import safetensors.torch as st
            except ImportError:
                raise SandboxError("safetensors is required to deserialize sandbox payloads")
            return st.load_file(str(artifact_path))

        if transfer == "onnx":
            try:
                import onnx
            except ImportError:
                raise SandboxError("onnx is required to deserialize sandbox payloads")
            return onnx.load(str(artifact_path))

        raise SandboxError(f"Unknown sandbox transfer format: {transfer}")

    def _restricted_env(self) -> dict[str, str]:
        # Env-var patterns stripped via substring match (case-insensitive)
        _DANGEROUS_PATTERNS = ("PROXY", "HTTP", "HTTPS", "FTP", "SOCKS")
        # Exact env-var keys to strip (case-sensitive)
        _DANGEROUS_KEYS = {
            "PYTHONSTARTUP",
            "PYTHONHOME",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
        }

        env = dict(os.environ)
        for key in list(env.keys()):
            upper_key = key.upper()
            if any(token in upper_key for token in _DANGEROUS_PATTERNS):
                del env[key]
            elif key in _DANGEROUS_KEYS:
                del env[key]

        src_path = str(Path(__file__).parent.parent.parent)
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{src_path}{os.pathsep}{existing}" if existing else src_path
        return env
