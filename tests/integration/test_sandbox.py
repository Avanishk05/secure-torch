"""
Integration tests — Phase 4: Sandbox Isolation.

Tests the subprocess sandbox (cross-platform primary sandbox).
seccomp tests are Linux-only and skipped on Windows.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


def make_safetensors_file(metadata: dict = None) -> bytes:
    """Create a minimal valid safetensors file with a single empty tensor."""
    import safetensors.torch as st

    # Create an empty dict (no tensors) with metadata
    # safetensors requires the save_file to actually create the file
    # So we'll create a simple tensor dict
    tensor_dict = {}

    # If we need to create an actual file, we use safetensors to do it properly
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as tmp:
        st.save_file(tensor_dict, tmp.name, metadata=metadata or {"model": "test"})
        tmp_path = Path(tmp.name)
        content = tmp_path.read_bytes()
        tmp_path.unlink()

    return content


class TestSubprocessSandbox:
    def test_sandbox_loads_safetensors(self):
        """Subprocess sandbox must successfully load a safetensors file."""
        from secure_torch.sandbox.subprocess_sandbox import SubprocessSandbox
        from secure_torch.models import ModelFormat

        content = make_safetensors_file({"model": "bert-base"})
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            sandbox = SubprocessSandbox()
            result = sandbox.load(tmp_path, ModelFormat.SAFETENSORS)
            # safetensors returns a dict of tensors (empty for our test file, but no error)
            assert result is not None
        finally:
            os.unlink(tmp_path)

    def test_sandbox_via_secure_load(self):
        """secure_load with sandbox=True must return a result."""
        import secure_torch as st

        content = make_safetensors_file({"model": "test"})
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = f.name

        try:
            # max_threat_score=100 so unsigned test model isn't blocked before reaching sandbox
            model = st.load(tmp_path, sandbox=True, max_threat_score=100)
            assert model is not None
        finally:
            os.unlink(tmp_path)

    def test_sandbox_env_strips_proxy_vars(self):
        """Subprocess sandbox must strip HTTP proxy env vars."""
        from secure_torch.sandbox.subprocess_sandbox import SubprocessSandbox
        import os

        os.environ["HTTP_PROXY"] = "http://evil.proxy:8080"
        os.environ["HTTPS_PROXY"] = "http://evil.proxy:8080"

        try:
            sandbox = SubprocessSandbox()
            env = sandbox._restricted_env()
            assert "HTTP_PROXY" not in env
            assert "HTTPS_PROXY" not in env
        finally:
            del os.environ["HTTP_PROXY"]
            del os.environ["HTTPS_PROXY"]

    @pytest.mark.skipif(os.name != "posix", reason="seccomp is Linux-only")
    def test_seccomp_apply_returns_bool(self):
        """apply_seccomp() must return True on Linux or False gracefully."""
        from secure_torch.sandbox.seccomp_sandbox import apply_seccomp

        result = apply_seccomp()
        assert isinstance(result, bool)
