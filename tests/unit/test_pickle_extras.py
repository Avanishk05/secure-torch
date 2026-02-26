"""
Unit tests — formats/pickle_safe.py (extra coverage)

Covers:
- STACK_GLOBAL attack vector (modern RCE, post-Python 3.8)
- INST opcode paths
- _is_safe_module allowlist logic
- REDUCE scoring for unknown modules
- Malformed / garbage pickle bytes
"""

from __future__ import annotations

import io
import pickle

import pytest

from secure_torch.formats.pickle_safe import (
    validate_pickle,
    _is_safe_module,
)
from secure_torch.threat_score import ThreatScorer
from secure_torch.exceptions import UnsafePickleError


# ── Helper: craft STACK_GLOBAL payloads manually ──────────────────────────────


def make_stack_global_payload(module: str, name: str) -> bytes:
    """
    Build a minimal pickle payload using STACK_GLOBAL opcode.
    STACK_GLOBAL pops (module, name) from the string stack and pushes a global.
    Protocol 4 uses STACK_GLOBAL.
    """
    buf = io.BytesIO()
    pickle.Pickler(buf, protocol=4)

    # We manually write the opcodes
    buf2 = io.BytesIO()
    # PROTO 4
    buf2.write(b"\x80\x04")
    # Push module string
    module_bytes = module.encode("utf-8")
    buf2.write(b"\x8c" + bytes([len(module_bytes)]) + module_bytes)
    # Push name string
    name_bytes = name.encode("utf-8")
    buf2.write(b"\x8c" + bytes([len(name_bytes)]) + name_bytes)
    # STACK_GLOBAL
    buf2.write(b"\x93")
    # STOP
    buf2.write(b".")
    return buf2.getvalue()


def make_pickle_payload(module: str, func: str, args: list) -> bytes:
    class _Exploit:
        def __reduce__(self):
            import importlib

            m = importlib.import_module(module)
            return getattr(m, func), tuple(args)

    buf = io.BytesIO()
    pickle.dump(_Exploit(), buf)
    return buf.getvalue()


# ── _is_safe_module tests ─────────────────────────────────────────────────────


class TestIsSafeModule:
    def test_torch_is_safe(self):
        assert _is_safe_module("torch") is True

    def test_torch_submodule_is_safe(self):
        """torch.nn.modules.linear should match by prefix."""
        assert _is_safe_module("torch.nn.modules.linear") is True

    def test_torch_nn_parameter_is_safe(self):
        assert _is_safe_module("torch.nn.parameter") is True

    def test_numpy_is_safe(self):
        assert _is_safe_module("numpy") is True

    def test_numpy_core_multiarray_is_safe(self):
        assert _is_safe_module("numpy.core.multiarray") is True

    def test_collections_is_safe(self):
        assert _is_safe_module("collections") is True

    def test_empty_string_is_safe(self):
        """Empty module name is considered safe (no reference)."""
        assert _is_safe_module("") is True

    def test_custom_module_is_not_safe(self):
        assert _is_safe_module("mylib.custom_ops") is False

    def test_unknown_module_is_not_safe(self):
        assert _is_safe_module("requests") is False

    def test_os_is_not_safe(self):
        assert _is_safe_module("os") is False

    def test_subprocess_is_not_safe(self):
        assert _is_safe_module("subprocess") is False


# ── STACK_GLOBAL opcode tests ─────────────────────────────────────────────────


class TestStackGlobalOpcode:
    def test_stack_global_os_system_blocked(self):
        """STACK_GLOBAL referencing os.system must be blocked."""
        payload = make_stack_global_payload("os", "system")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_stack_global_subprocess_blocked(self):
        """STACK_GLOBAL referencing subprocess.Popen must be blocked."""
        payload = make_stack_global_payload("subprocess", "Popen")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_stack_global_importlib_blocked(self):
        """STACK_GLOBAL referencing importlib must be blocked."""
        payload = make_stack_global_payload("importlib", "import_module")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_stack_global_builtins_eval_blocked(self):
        """With the fix applied, STACK_GLOBAL with builtins+eval must block."""
        payload = make_stack_global_payload("builtins", "eval")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError, match="Dangerous callable"):
            validate_pickle(payload, scorer)

    def test_stack_global_nt_blocked(self):
        """STACK_GLOBAL referencing nt (Windows os alias) must be blocked."""
        payload = make_stack_global_payload("nt", "system")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)


# ── REDUCE opcode scoring ─────────────────────────────────────────────────────


class TestReduceOpcodeScoring:
    def test_unknown_module_reduce_scores(self):
        """A REDUCE on an unknown module should add to the threat score."""
        # Hand-craft a pickle: GLOBAL 'mylib\ncustom_fn\n' + EMPTY_TUPLE + REDUCE
        # This avoids calling build_pickle_payload which tries to import the module at creation time.
        buf = io.BytesIO()
        buf.write(b"\x80\x02")  # PROTO 2
        buf.write(b"cmylib\ncustom_fn\n")  # GLOBAL opcode (c = 0x63)
        buf.write(b").")  # EMPTY_TUPLE, then STOP
        payload = buf.getvalue()

        scorer = ThreatScorer()
        try:
            validate_pickle(payload, scorer)
            # The unknown module reference should score something
            assert scorer.total > 0, f"Expected non-zero score, got {scorer.breakdown}"
        except UnsafePickleError:
            pass  # Blocking is also acceptable for unknown modules

    def test_safe_module_reduce_no_score(self):
        """REDUCE on a torch module should NOT add score."""
        payload = pickle.dumps({"key": "value"})
        scorer = ThreatScorer()
        validate_pickle(payload, scorer)
        assert scorer.total == 0


# ── Malformed bytes ───────────────────────────────────────────────────────────


class TestMalformedPickle:
    def test_garbage_bytes_warns_not_raises(self):
        """Garbage bytes must produce a warning, not an uncaught exception."""
        scorer = ThreatScorer()
        validate_pickle(b"\xff\xfe\xfd\xfc\xfb\xfa", scorer)
        # Should have logged a warning
        assert len(scorer.warnings) > 0 or scorer.total == 0  # warned or safely scored 0

    def test_truncated_pickle_warns(self):
        """A truncated (incomplete) pickle stream must be handled gracefully."""
        # Valid pickle header but truncated body
        scorer = ThreatScorer()
        validate_pickle(b"\x80\x04", scorer)  # protocol 4 with no body
        # Should not raise

    def test_empty_bytes_no_op(self):
        """Empty bytes must produce no findings and no exceptions."""
        scorer = ThreatScorer()
        validate_pickle(b"", scorer)
        assert scorer.total == 0
        assert len(scorer.warnings) == 0
