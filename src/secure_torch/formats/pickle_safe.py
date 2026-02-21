"""
Pickle opcode validator — Phase 1.

Uses pickletools.genops() to walk the opcode stream WITHOUT executing pickle.
Never calls pickle.loads(). Only inspects opcodes.

Correct terminology: "opcode validator", not "AST walker"
(pickle has no AST — it has a stack-based opcode stream).
"""

from __future__ import annotations

import io
import pickletools
from typing import Optional

from secure_torch.exceptions import UnsafePickleError
from secure_torch.threat_score import (
    ThreatScorer,
    SCORE_PICKLE_GLOBAL_UNKNOWN,
    SCORE_PICKLE_REDUCE_OPCODE,
    SCORE_PICKLE_INST_OPCODE,
)

# Modules that are safe to reference in pickle streams
SAFE_MODULES: frozenset[str] = frozenset({
    "torch",
    "torch.storage",
    "torch._utils",
    "torch.nn.modules",
    "torch.nn.parameter",
    "collections",
    "collections.OrderedDict",
    "_codecs",
    "numpy",
    "numpy.core.multiarray",
    "__builtin__",
    "builtins",
})

# Modules that are always dangerous — immediate block
# Rationale: These modules enable filesystem access, process execution, 
# dynamic code loading, or memory manipulation and are common targets 
# in pickle deserialization exploits.
DANGEROUS_MODULES: frozenset[str] = frozenset({
    "os",
    "nt",           # Windows alias for os module
    "posix",        # Unix alias for os module
    "subprocess",
    "sys",
    "importlib",
    "importlib.import_module",
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "builtins.__import__",
    "socket",
    "shutil",
    "pathlib",
    "ctypes",
    "cffi",
    "multiprocessing",
    "threading",
    "pty",
    "signal",
    "gc",
    "weakref",
})

# Opcodes that can execute arbitrary callables
EXECUTION_OPCODES: frozenset[str] = frozenset({
    "REDUCE",
    "BUILD",
    "INST",
    "OBJ",
    "NEWOBJ",
    "NEWOBJ_EX",
    "STACK_GLOBAL",
})


def validate_pickle(data: bytes, scorer: ThreatScorer) -> None:
    """
    Walk the pickle opcode stream and score threats.

    Args:
        data: Raw pickle bytes.
        scorer: ThreatScorer to accumulate findings.

    Raises:
        UnsafePickleError: If a definitely dangerous opcode is found.
    """
    if not data:
        return

    try:
        _walk_opcodes(data, scorer)
    except UnsafePickleError:
        raise
    except Exception as e:
        scorer.warn(f"Pickle opcode walk failed (malformed?): {e}")


def _walk_opcodes(data: bytes, scorer: ThreatScorer) -> None:
    """Internal opcode walker."""
    stream = io.BytesIO(data)
    last_global: Optional[str] = None

    # Track last two string values pushed onto the stack
    # STACK_GLOBAL pops (module, name) from stack — they arrive as separate SHORT_BINUNICODE/BINUNICODE pushes
    string_stack: list[str] = []

    for opcode, arg, pos in pickletools.genops(stream):
        name = opcode.name

        # Track string pushes for STACK_GLOBAL reconstruction
        if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "STRING", "BINSTRING"):
            string_stack.append(str(arg) if arg is not None else "")
            if len(string_stack) > 4:
                string_stack.pop(0)

        # GLOBAL opcode: arg is "module name" as a SPACE-SEPARATED string
        # e.g. "builtins eval" or "os system"
        elif name == "GLOBAL":
            raw = str(arg) if arg else ""
            parts = raw.split(" ", 1)
            module_name = parts[0] if parts else ""
            func_name   = parts[1] if len(parts) > 1 else ""
            dotted      = f"{module_name}.{func_name}" if func_name else module_name
            last_global = module_name
            _check_module_ref(module_name, pos, scorer)
            # Also block the exact dotted form e.g. "builtins.eval" in DANGEROUS_MODULES
            if func_name and dotted in DANGEROUS_MODULES:
                raise UnsafePickleError(
                    f"Dangerous callable at byte {pos}: '{dotted}'. "
                    f"This pickle can execute arbitrary code."
                )
            string_stack.clear()

        # STACK_GLOBAL: pops (module, name) from stack — no arg
        elif name == "STACK_GLOBAL":
            # Last two string pushes are (module, name) in that order
            if len(string_stack) >= 2:
                module_name = string_stack[-2]
                func_name   = string_stack[-1]
            elif len(string_stack) == 1:
                module_name = string_stack[-1]
                func_name   = ""
            else:
                module_name, func_name = "", ""

            dotted = f"{module_name}.{func_name}" if func_name else module_name
            last_global = module_name
            _check_module_ref(module_name, pos, scorer)
            # Also block the exact dotted sub-function e.g. "builtins.eval"
            if func_name and dotted in DANGEROUS_MODULES:
                raise UnsafePickleError(
                    f"Dangerous callable at byte {pos}: '{dotted}'. "
                    f"This pickle can execute arbitrary code."
                )
            string_stack.clear()

        # REDUCE applies the last GLOBAL as a callable — high risk
        elif name == "REDUCE":
            if last_global and not _is_safe_module(last_global):
                scorer.add(
                    f"pickle_reduce_opcode:{last_global}",
                    SCORE_PICKLE_REDUCE_OPCODE,
                )

        # INST is an older form of GLOBAL+REDUCE combined
        elif name == "INST":
            module_name = str(arg) if arg else ""
            module_root = module_name.split(".")[0] if module_name else ""
            if module_root in DANGEROUS_MODULES or module_name in DANGEROUS_MODULES:
                raise UnsafePickleError(
                    f"Dangerous INST opcode at byte {pos}: '{module_name}'"
                )
            scorer.add("pickle_inst_opcode", SCORE_PICKLE_INST_OPCODE)


def _check_module_ref(module_name: str, pos: int, scorer: ThreatScorer) -> None:
    """Check a module reference and raise or score accordingly."""
    module_root = module_name.split(".")[0] if module_name else ""
    if module_root in DANGEROUS_MODULES or module_name in DANGEROUS_MODULES:
        raise UnsafePickleError(
            f"Dangerous module reference at byte {pos}: '{module_name}'. "
            f"This pickle can execute arbitrary code."
        )
    if not _is_safe_module(module_name):
        scorer.add(
            f"pickle_global_unknown_module:{module_name}",
            SCORE_PICKLE_GLOBAL_UNKNOWN,
        )



def _is_safe_module(module_name: str) -> bool:
    """Check if a module reference is in the safe allowlist."""
    if not module_name:
        return True
    # Exact match
    if module_name in SAFE_MODULES:
        return True
    # Prefix match (e.g. "torch.nn.modules.linear" matches "torch")
    root = module_name.split(".")[0]
    return root in {m.split(".")[0] for m in SAFE_MODULES}


def build_pickle_payload(module: str, func: str, args: list) -> bytes:
    """
    Build a malicious pickle payload for testing.
    Only for use in CVE regression tests.
    """
    import pickle
    import io

    class _Exploit:
        def __reduce__(self):
            import importlib
            m = importlib.import_module(module)
            return getattr(m, func), tuple(args)

    buf = io.BytesIO()
    pickle.dump(_Exploit(), buf)
    return buf.getvalue()
