"""
Unit tests — CVE regressions (extras)

Additional attack vectors not covered in the main CVE suite:
- importlib.import_module as a pickle attack vector
- builtins.eval and builtins.exec in a pickle stream
- gc module as a memory manipulation vector
- ctypes hazard in pickle stream
- socket in pickle stream (exfiltration)
"""
from __future__ import annotations

import io

import pytest

from secure_torch.formats.pickle_safe import validate_pickle
from secure_torch.threat_score import ThreatScorer
from secure_torch.exceptions import UnsafePickleError


def make_stack_global_payload(module: str, name: str) -> bytes:
    """Build minimal STACK_GLOBAL pickle payload."""
    buf = io.BytesIO()
    buf.write(b'\x80\x04')
    module_b = module.encode('utf-8')
    buf.write(b'\x8c' + bytes([len(module_b)]) + module_b)
    name_b = name.encode('utf-8')
    buf.write(b'\x8c' + bytes([len(name_b)]) + name_b)
    buf.write(b'\x93')  # STACK_GLOBAL
    buf.write(b'.')     # STOP
    return buf.getvalue()


class TestNewCVEVectors:

    def test_importlib_import_module_blocked(self):
        """
        importlib.import_module is a powerful dynamic import vector.
        Any pickle referencing importlib must be blocked.
        """
        payload = make_stack_global_payload("importlib", "import_module")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_builtins_eval_blocked_via_global_opcode(self):
        """
        GLOBAL opcode with 'builtins eval' must now raise UnsafePickleError.
        The fix parses the space-separated arg and checks 'builtins.eval'
        against DANGEROUS_MODULES.
        """
        import io
        buf = io.BytesIO()
        buf.write(b'\x80\x02')
        buf.write(b'cbuiltins\neval\n')  # GLOBAL opcode: 'c' (0x63), arg = 'builtins eval'
        buf.write(b'.')
        payload = buf.getvalue()
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError, match="Dangerous callable"):
            validate_pickle(payload, scorer)

    def test_builtins_eval_blocked_via_stack_global(self):
        """STACK_GLOBAL with builtins + eval must now raise UnsafePickleError."""
        payload = make_stack_global_payload("builtins", "eval")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError, match="Dangerous callable"):
            validate_pickle(payload, scorer)

    def test_builtins_exec_blocked(self):
        """builtins.exec via GLOBAL opcode must be blocked."""
        import io
        buf = io.BytesIO()
        buf.write(b'\x80\x02')
        buf.write(b'cbuiltins\nexec\n')  # GLOBAL opcode
        buf.write(b'.')
        payload = buf.getvalue()
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError, match="Dangerous callable"):
            validate_pickle(payload, scorer)

    def test_builtins_compile_blocked(self):
        """builtins.compile via GLOBAL opcode must be blocked."""
        import io
        buf = io.BytesIO()
        buf.write(b'\x80\x02')
        buf.write(b'cbuiltins\ncompile\n')  # GLOBAL opcode
        buf.write(b'.')
        payload = buf.getvalue()
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError, match="Dangerous callable"):
            validate_pickle(payload, scorer)

    def test_builtins_dunder_import_blocked(self):
        """builtins.__import__ via GLOBAL opcode must be blocked."""
        import io
        buf = io.BytesIO()
        buf.write(b'\x80\x02')
        buf.write(b'cbuiltins\n__import__\n')  # GLOBAL opcode
        buf.write(b'.')
        payload = buf.getvalue()
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError, match="Dangerous callable"):
            validate_pickle(payload, scorer)

    def test_gc_module_blocked(self):
        """
        gc (garbage collector) allows memory manipulation.
        A sophisticated attacker can use gc.get_objects() to walk interpreter state.
        """
        payload = make_stack_global_payload("gc", "get_objects")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_ctypes_blocked(self):
        """
        ctypes.cdll allows loading arbitrary shared libraries.
        Classic RCE vector for advanced attackers.
        """
        payload = make_stack_global_payload("ctypes", "cdll")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_socket_blocked(self):
        """
        socket module enables data exfiltration to remote servers.
        Must be blocked.
        """
        payload = make_stack_global_payload("socket", "socket")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_posix_alias_blocked(self):
        """
        posix is the Unix alias for the os module.
        posix.system('id') is equivalent to os.system('id').
        """
        payload = make_stack_global_payload("posix", "system")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_shutil_blocked(self):
        """shutil.rmtree can destroy the filesystem."""
        payload = make_stack_global_payload("shutil", "rmtree")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_sys_blocked(self):
        """sys module exposes the interpreter state."""
        payload = make_stack_global_payload("sys", "exit")
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)
