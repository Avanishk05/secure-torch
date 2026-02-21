"""
Unit tests — sandbox/subprocess_sandbox.py (extra coverage)

Covers:
- _restricted_env() strips proxy env vars
- _restricted_env() adds PYTHONPATH correctly
- _parse_json_result edge cases (empty, non-JSON, non-dict)
- _load_transfer_artifact with unknown format
- Sandbox with a non-tensor-dict pickle (dict-only policy)
- Subprocess timeout scenario (mocked)
- Path mismatch in sandbox response (mocked)
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from secure_torch.sandbox.subprocess_sandbox import SubprocessSandbox
from secure_torch.exceptions import SandboxError
from secure_torch.models import ModelFormat


class TestRestrictedEnv:

    def test_http_proxy_stripped(self, monkeypatch):
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.evil.com:3128")
        sandbox = SubprocessSandbox()
        env = sandbox._restricted_env()
        assert "HTTP_PROXY" not in env

    def test_https_proxy_stripped(self, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "https://proxy.evil.com:3128")
        sandbox = SubprocessSandbox()
        env = sandbox._restricted_env()
        assert "HTTPS_PROXY" not in env

    def test_lowercase_http_proxy_stripped(self, monkeypatch):
        monkeypatch.setenv("http_proxy", "http://proxy.internal:3000")
        sandbox = SubprocessSandbox()
        env = sandbox._restricted_env()
        assert "http_proxy" not in env

    def test_ftp_proxy_stripped(self, monkeypatch):
        monkeypatch.setenv("FTP_PROXY", "ftp://ftp.example.com")
        sandbox = SubprocessSandbox()
        env = sandbox._restricted_env()
        assert "FTP_PROXY" not in env

    def test_python_path_set(self):
        """PYTHONPATH must be set to the src directory."""
        sandbox = SubprocessSandbox()
        env = sandbox._restricted_env()
        assert "PYTHONPATH" in env
        # The src directory should be in the path
        assert "secure_torch" in env["PYTHONPATH"] or "src" in env["PYTHONPATH"]

    def test_non_proxy_vars_preserved(self, monkeypatch):
        """Regular env vars must NOT be stripped."""
        monkeypatch.setenv("MY_CUSTOM_VAR", "should_remain")
        sandbox = SubprocessSandbox()
        env = sandbox._restricted_env()
        assert env.get("MY_CUSTOM_VAR") == "should_remain"


class TestParseJsonResult:

    def test_empty_stdout_raises(self):
        sandbox = SubprocessSandbox()
        with pytest.raises(SandboxError, match="no result"):
            sandbox._parse_json_result(b"")

    def test_whitespace_only_raises(self):
        sandbox = SubprocessSandbox()
        with pytest.raises(SandboxError, match="no result"):
            sandbox._parse_json_result(b"   \n   \n")

    def test_non_json_raises(self):
        sandbox = SubprocessSandbox()
        with pytest.raises(SandboxError, match="invalid JSON"):
            sandbox._parse_json_result(b"this is not json at all\n")

    def test_json_array_raises(self):
        """JSON response must be an object, not array."""
        sandbox = SubprocessSandbox()
        with pytest.raises(SandboxError, match="JSON object"):
            sandbox._parse_json_result(b'[1, 2, 3]\n')

    def test_valid_json_parsed(self):
        sandbox = SubprocessSandbox()
        result = sandbox._parse_json_result(b'{"ok": true, "path": "/tmp/out.safetensors"}\n')
        assert result["ok"] is True
        assert result["path"] == "/tmp/out.safetensors"

    def test_last_line_used(self):
        """When there are multiple lines, last non-empty line is used."""
        sandbox = SubprocessSandbox()
        output = b"debug output\n" + b'{"ok": true, "transfer": "safetensors", "path": "/tmp/x"}\n'
        result = sandbox._parse_json_result(output)
        assert result["ok"] is True


class TestLoadTransferArtifact:

    def test_unknown_transfer_format_raises(self):
        sandbox = SubprocessSandbox()
        with pytest.raises(SandboxError, match="Unknown sandbox transfer format"):
            sandbox._load_transfer_artifact(Path("/tmp/x"), "unknown_format")


class TestSandboxLoadMocked:
    """Tests that mock subprocess to avoid spawning real processes."""

    def _make_safetensors_file(self, tmp_dir: Path) -> Path:
        """Create a minimal valid safetensors file."""
        header = {"__metadata__": {}}
        header_bytes = json.dumps(header).encode("utf-8")
        content = struct.pack("<Q", len(header_bytes)) + header_bytes
        p = tmp_dir / "model.safetensors"
        p.write_bytes(content)
        return p

    def test_sandbox_timeout_raises_sandbox_error(self, tmp_path):
        """A subprocess.TimeoutExpired must be caught and re-raised as SandboxError."""
        import subprocess
        model_path = self._make_safetensors_file(tmp_path)
        sandbox = SubprocessSandbox()

        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="python", timeout=120)
        mock_proc.kill = MagicMock()

        with patch("subprocess.Popen", return_value=mock_proc):
            with pytest.raises(SandboxError, match="timed out"):
                sandbox.load(model_path, ModelFormat.SAFETENSORS)

    def test_sandbox_nonzero_exit_raises(self, tmp_path):
        """A subprocess that exits with non-zero code raises SandboxError."""
        model_path = self._make_safetensors_file(tmp_path)
        sandbox = SubprocessSandbox()

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"some error")

        with patch("subprocess.Popen", return_value=mock_proc):
            with pytest.raises(SandboxError, match="exit"):
                sandbox.load(model_path, ModelFormat.SAFETENSORS)

    def test_sandbox_path_mismatch_raises(self, tmp_path):
        """Sandbox returning an unexpected path must raise SandboxError."""
        model_path = self._make_safetensors_file(tmp_path)
        sandbox = SubprocessSandbox()

        # Return ok=True but a different path than what we created
        payload = json.dumps({"ok": True, "transfer": "safetensors",
                               "path": "/completely/different/path.safetensors"}).encode()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (payload + b"\n", b"")

        with patch("subprocess.Popen", return_value=mock_proc):
            with pytest.raises(SandboxError, match="unexpected transfer path"):
                sandbox.load(model_path, ModelFormat.SAFETENSORS)
