"""
Unit tests for HuggingFace integration and Seccomp sandbox stubs.
"""

from __future__ import annotations

from unittest.mock import patch


from secure_torch.huggingface import patch_huggingface, unpatch_huggingface, _is_model_file
from secure_torch.sandbox.seccomp_sandbox import apply_seccomp


class TestHuggingFacePatch:
    """Tests for Hugging Face monkey-patching."""

    def setup_method(self):
        unpatch_huggingface()

    def teardown_method(self):
        unpatch_huggingface()

    def test_is_model_file(self):
        assert _is_model_file("model.pt") is True
        assert _is_model_file("weights.safetensors") is True
        assert _is_model_file("config.json") is False
        assert _is_model_file("README.md") is False
        assert _is_model_file("MODEL.KERAS") is True

    @patch("huggingface_hub.file_download.hf_hub_download")
    def test_patch_intercepts_download(self, mock_download, tmp_path):
        # Create a dummy model file
        model_file = tmp_path / "model.pt"
        model_file.write_bytes(b"dummy")
        mock_download.return_value = str(model_file)

        # Patch HF
        with patch("secure_torch.loader._run_validators") as mock_val:
            patch_huggingface(audit_only=True)

            from huggingface_hub.file_download import hf_hub_download

            res = hf_hub_download("repo", "model.pt")

            assert res == str(model_file)
            assert mock_val.called

    def test_unpatch_restores_original(self):
        import huggingface_hub.file_download

        original = huggingface_hub.file_download.hf_hub_download

        patch_huggingface()
        assert huggingface_hub.file_download.hf_hub_download != original

        unpatch_huggingface()
        assert huggingface_hub.file_download.hf_hub_download == original


class TestSeccompSandbox:
    """Tests for seccomp sandbox stubs."""

    def test_apply_seccomp_on_non_linux(self):
        with patch("sys.platform", "win32"):
            assert apply_seccomp() is False

        with patch("sys.platform", "darwin"):
            assert apply_seccomp() is False

    @patch("sys.platform", "linux")
    def test_apply_seccomp_linux_missing_prctl_and_libseccomp(self):
        # Only mock prctl import failing
        import builtins

        original_import = builtins.__import__

        def restricted_import(name, *args, **kwargs):
            if name == "prctl":
                raise ImportError
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=restricted_import):
            with patch("ctypes.CDLL", side_effect=OSError):
                assert apply_seccomp() is False
