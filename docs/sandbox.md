# Sandbox Isolation

## Overview

secure-torch loads models in a **restricted subprocess** by default when `sandbox=True`. This provides basic process isolation and strips network-related environment variables cross-platform, while enforcing strict syscall blocking (no network, no execing) via seccomp on Linux.

## Architecture

```
main process
  └─ spawn subprocess
       ├─ apply seccomp (Linux only, optional)
       ├─ load model
       └─ return tensors via pipe
```

The subprocess is the **primary sandbox** — cross-platform (Linux, macOS, Windows). seccomp is an optional enhancement applied *inside* the subprocess on Linux.

```{important}
seccomp is NEVER applied in the main process. Doing so would break the Python runtime.
```

## Usage

```python
import secure_torch as torch

model = torch.load("model.pt", sandbox=True, max_threat_score=100)
```

## What the sandbox restricts

| Restriction | How |
|---|---|
| No network access | Proxy env vars stripped from subprocess environment |
| No process spawning | seccomp blocks `execve` on Linux |
| No socket creation | seccomp blocks `socket` on Linux |
| Timeout | 120 second hard limit |

## Platform support

| Platform | Subprocess sandbox | seccomp |
|---|---|---|
| Linux | ✅ | ✅ (optional) |
| macOS | ✅ | ❌ (not applicable) |
| Windows | ✅ | ❌ (not applicable) |

## seccomp syscall allowlist (Linux)

When seccomp is available, only these syscall categories are permitted inside the subprocess:

- File I/O (`read`, `write`, `open`, `close`, `fstat`)
- Memory (`mmap`, `munmap`, `brk`, `mprotect`)
- Threading (`futex`, `gettid`)
- Process exit (`exit_group`)

**Blocked:** `execve`, `socket`, `bind`, `connect`, `ptrace`
