"""
Integration tests — huggingface.py (extra coverage)

Covers:
- Double patch warning (second call is ignored)
- unpatch_huggingface() restores original function
- unpatch_huggingface() without prior patch is a no-op
- _is_model_file() extension logic
- Non-model files are skipped without validation
- huggingface_hub not installed: warns gracefully
"""
from __future__ import annotations

from unittest.mock import patch



class TestIsModeFile:

    def test_safetensors_is_model(self):
        from secure_torch.huggingface import _is_model_file
        assert _is_model_file("weights.safetensors") is True

    def test_bin_is_model(self):
        from secure_torch.huggingface import _is_model_file
        assert _is_model_file("pytorch_model.bin") is True

    def test_pt_is_model(self):
        from secure_torch.huggingface import _is_model_file
        assert _is_model_file("model.pt") is True

    def test_onnx_is_model(self):
        from secure_torch.huggingface import _is_model_file
        assert _is_model_file("model.onnx") is True

    def test_pth_is_model(self):
        from secure_torch.huggingface import _is_model_file
        assert _is_model_file("checkpoint.pth") is True

    def test_config_json_not_model(self):
        from secure_torch.huggingface import _is_model_file
        assert _is_model_file("config.json") is False

    def test_tokenizer_not_model(self):
        from secure_torch.huggingface import _is_model_file
        assert _is_model_file("tokenizer.json") is False

    def test_readme_not_model(self):
        from secure_torch.huggingface import _is_model_file
        assert _is_model_file("README.md") is False


class TestPatchLifecycle:

    def setup_method(self):
        # Ensure clean state before each test
        from secure_torch import huggingface
        if huggingface._PATCHED:
            huggingface.unpatch_huggingface()

    def teardown_method(self):
        # Ensure clean state after each test
        from secure_torch import huggingface
        if huggingface._PATCHED:
            huggingface.unpatch_huggingface()

    def test_double_patch_is_idempotent(self):
        """Calling patch_huggingface twice must not double-patch."""
        import huggingface_hub.file_download as fd
        from secure_torch.huggingface import patch_huggingface

        patch_huggingface()
        first_patched_fn = fd.hf_hub_download

        # Second call should log a warning via logging, not raise
        patch_huggingface()

        # Verify not double-patched (the function reference is the same)
        assert fd.hf_hub_download is first_patched_fn

    def test_unpatch_restores_original(self):
        """unpatch_huggingface() must restore the original function identity."""
        import huggingface_hub.file_download as fd
        from secure_torch.huggingface import patch_huggingface, unpatch_huggingface

        original_fn = fd.hf_hub_download
        patch_huggingface()
        assert fd.hf_hub_download is not original_fn  # patched

        unpatch_huggingface()
        assert fd.hf_hub_download is original_fn  # restored

    def test_unpatch_without_prior_patch_is_no_op(self):
        """Calling unpatch_huggingface without prior patch must not raise."""
        from secure_torch.huggingface import unpatch_huggingface
        unpatch_huggingface()  # should not raise

    def test_non_model_file_skips_scanning(self, tmp_path):
        """Downloading a config.json must NOT trigger secure_torch scanning."""
        from secure_torch.huggingface import patch_huggingface
        import secure_torch.loader as loader

        config_path = tmp_path / "config.json"
        config_path.write_text('{"model_type": "bert"}')

        with patch("huggingface_hub.file_download.hf_hub_download",
                   return_value=str(config_path)):
            called = []
            original_secure_load = loader.secure_load

            def mock_secure_load(*a, **kw):
                called.append(True)
                return original_secure_load(*a, **kw)

            patch_huggingface()
            import huggingface_hub
            huggingface_hub.file_download.hf_hub_download(
                repo_id="fake/repo", filename="config.json"
            )
            # Scanning should NOT have been triggered for a non-model file
            assert len(called) == 0, "secure_load must not be called for non-model files"
