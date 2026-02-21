"""
seccomp sandbox — Phase 4 (optional Linux-only enhancement).

Applied INSIDE the subprocess (never in the main process).
Blocks execve, socket, ptrace after deserialization setup.

Silently skipped on non-Linux platforms.
"""

from __future__ import annotations

import sys


def apply_seccomp() -> bool:
    """
    Apply seccomp-BPF filter to the current process.

    Must be called INSIDE the subprocess, not the main process.
    Calling this in the main process would break the Python runtime.

    Returns:
        True if seccomp was applied, False if skipped (non-Linux or unavailable).
    """
    if sys.platform != "linux":
        return False

    try:
        # Try using python-prctl if available
        try:
            import prctl

            _apply_via_prctl(prctl)
            return True
        except ImportError:
            pass

        # Fallback: use libseccomp via ctypes
        try:
            _apply_via_libseccomp()
            return True
        except Exception:
            pass

        return False

    except Exception:
        return False


def _apply_via_prctl(prctl) -> None:
    """Apply seccomp allowlist via python-prctl."""

    # Set no-new-privs first (required for unprivileged seccomp)
    prctl.set_no_new_privs(1)

    # Define allowed syscalls for tensor deserialization
    ALLOWED_SYSCALLS = [
        "read",
        "write",
        "mmap",
        "munmap",
        "brk",
        "mprotect",
        "futex",
        "exit_group",
        "fstat",
        "stat",
        "open",
        "openat",
        "close",
        "lseek",
        "pread64",
        "pwrite64",
        "getpid",
        "gettid",
        "rt_sigaction",
        "rt_sigprocmask",
        "madvise",
        "mremap",
    ]

    # BLOCKED: execve, socket, bind, connect, ptrace → SIGSYS
    prctl.seccomp.set_mode_filter(
        prctl.seccomp.ALLOW,
        ALLOWED_SYSCALLS,
    )


def _apply_via_libseccomp() -> None:
    """Apply seccomp via libseccomp shared library (ctypes fallback)."""
    import ctypes

    libseccomp = ctypes.CDLL("libseccomp.so.2")

    SCMP_ACT_ALLOW = 0x7FFF0000
    SCMP_ACT_KILL = 0x00000000

    ctx = libseccomp.seccomp_init(SCMP_ACT_KILL)
    if not ctx:
        raise RuntimeError("seccomp_init failed")

    # Syscall numbers (x86_64)
    ALLOWED_NRS = [0, 1, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 17, 21, 25, 28, 202]

    for nr in ALLOWED_NRS:
        libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)

    ret = libseccomp.seccomp_load(ctx)
    libseccomp.seccomp_release(ctx)

    if ret != 0:
        raise RuntimeError(f"seccomp_load failed: {ret}")
