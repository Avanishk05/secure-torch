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

SAFE_MODULES: frozenset[str] = frozenset(
    {
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
    }
)

DANGEROUS_MODULES: frozenset[str] = frozenset(
    {
        "os",
        "nt",
        "posix",
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
    }
)


def validate_pickle(data: bytes, scorer: ThreatScorer) -> None:
    if not data:
        return
    try:
        _walk_opcodes(data, scorer)
    except UnsafePickleError:
        raise
    except Exception as e:
        scorer.warn(f"Pickle opcode walk failed: {e}")


def _walk_opcodes(data: bytes, scorer: ThreatScorer) -> None:

    stream = io.BytesIO(data)
    last_global: Optional[str] = None
    string_stack: list[str] = []

    for opcode, arg, pos in pickletools.genops(stream):
        name = opcode.name

        if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE"):
            if arg is not None:
                string_stack.append(str(arg))

        elif name == "GLOBAL":
            raw = str(arg) if arg else ""
            parts = raw.split(" ", 1)

            module = parts[0] if parts else ""
            func = parts[1] if len(parts) > 1 else ""

            last_global = module

            _check_module_ref(module, pos, scorer)

            if func and f"{module}.{func}" in DANGEROUS_MODULES:
                raise UnsafePickleError(f"Dangerous callable at {pos}")

        elif name == "STACK_GLOBAL":
            if len(string_stack) >= 2:
                module = string_stack[-2]
                func = string_stack[-1]
            else:
                module = ""
                func = ""

            last_global = module

            _check_module_ref(module, pos, scorer)

            if func and f"{module}.{func}" in DANGEROUS_MODULES:
                raise UnsafePickleError(f"Dangerous callable at {pos}")

        elif name == "REDUCE":
            if last_global and not _is_safe_module(last_global):
                scorer.add(
                    f"pickle_reduce_opcode:{last_global}",
                    SCORE_PICKLE_REDUCE_OPCODE,
                )

        elif name == "INST":
            module = str(arg) if arg else ""

            if module in DANGEROUS_MODULES:
                raise UnsafePickleError("Dangerous INST opcode")

            scorer.add("pickle_inst_opcode", SCORE_PICKLE_INST_OPCODE)


def _check_module_ref(module: str, pos: Optional[int], scorer: ThreatScorer) -> None:

    if module in DANGEROUS_MODULES:
        raise UnsafePickleError(f"Dangerous module {module}")

    if not _is_safe_module(module):
        scorer.add(
            f"pickle_global_unknown_module:{module}",
            SCORE_PICKLE_GLOBAL_UNKNOWN,
        )


def _is_safe_module(module: str) -> bool:

    # FIX: empty module is safe (required by pickle protocol)
    if module == "":
        return True

    if module in SAFE_MODULES:
        return True

    root = module.split(".")[0]

    return root in {m.split(".")[0] for m in SAFE_MODULES}
