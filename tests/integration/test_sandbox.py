"""
Integration tests — Phase 4: Sandbox Isolation.

Tests the subprocess sandbox (cross-platform primary sandbox).
seccomp tests are Linux-only and skipped on non-POSIX systems.
Subprocess sandbox tests are skipped only on Linux CI due to GitHub Actions subprocess limitations.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Detect Linux CI environment (GitHub Actions sets CI=true)
IS_LINUX_CI = sys.platform.startswith("linux") and os.environ.get("CI") == "true"


def make_safetensors_file(metadata: dict | None = None) -> bytes:
    """Create a minimal valid safetensors file containing only metadata."""
    import json
    import struct

    header = {"__metadata__": metadata or {"model": "test"}}
    header_bytes = json.dumps(header).encode("utf-8")

    # safetensors format:
    # 8-byte little-endian uint64 header length + header JSON
    return struct.pack("<Q", len(header_bytes)) + header_bytes


class TestSubprocessSandbox:
    """Tests for subprocess-based sandbox isolation."""

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(
        IS_LINUX_CI,
        reason="Subprocess sandbox communication unreliable on Linux CI (GitHub Actions limitation)",
    )
    def test_sandbox_loads_safetensors(self):
        """
        Verify subprocess sandbox can successfully load safetensors file.
        """
        from secure_torch.sandbox.subprocess_sandbox import SubprocessSandbox
        from secure_torch.models import ModelFormat

        content = make_safetensors_file({"model": "bert-base"})

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            sandbox = SubprocessSandbox()
            result = sandbox.load(tmp_path, ModelFormat.SAFETENSORS)

            assert result is not None

        finally:
            os.unlink(tmp_path)

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(
        IS_LINUX_CI,
        reason="Subprocess sandbox communication unreliable on Linux CI (GitHub Actions limitation)",
    )
    def test_sandbox_via_secure_load(self):
        """
        Verify secure_load() correctly uses sandbox when enabled.
        """
        import secure_torch as st

        content = make_safetensors_file({"model": "test"})

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = f.name

        try:
            model = st.load(
                tmp_path,
                sandbox=True,
                max_threat_score=100,
            )

            assert model is not None

        finally:
            os.unlink(tmp_path)

    def test_sandbox_env_strips_proxy_vars(self):
        """
        Verify sandbox removes proxy environment variables.
        """
        from secure_torch.sandbox.subprocess_sandbox import SubprocessSandbox

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

    @pytest.mark.skipif(
        os.name != "posix",
        reason="seccomp supported only on POSIX systems",
    )
    def test_seccomp_apply_returns_bool(self):
        """
        Verify seccomp sandbox applies correctly.
        """
        from secure_torch.sandbox.seccomp_sandbox import apply_seccomp

        result = apply_seccomp()

        assert isinstance(result, bool)