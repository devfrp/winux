# winux — Windows PE executor for Linux

Native, transparent execution of Windows PE32+ (x86_64) executables
on Linux, without Wine, without VMs, without containers.

```
                          ┌─────────────────────────┐
                          │     Windows PE .exe      │
                          │  (mmap'd in-place with   │
                          │   MAP_FIXED at VA base)  │
                          └───────────┬─────────────┘
                                      │ calls
                          ┌───────────▼─────────────┐
                          │     pe_loader.c          │
                          │  Parse PE, map sections, │
                          │  relocations, IAT build  │
                          └───────────┬─────────────┘
                                      │ resolves
                          ┌───────────▼─────────────┐
                          │    win32_bridge.c        │
                          │  Static import LUT:      │
                          │  kernel32 → our stubs    │
                          │  ntdll    → NT stubs     │
                          └───────────┬─────────────┘
                          ┌───────┐  │  ┌───────────┐
                          │kernel32│◄─┴─►│ ntdll     │
                          │ stubs  │     │ stubs     │
                          └───┬───┘     └─────┬─────┘
                              │    ┌──────────▼──────┐
                              │    │  memory_manager  │
                              │    │  (VirtualAlloc,  │
                              │    │   heap, regions) │
                              │    └────────┬────────┘
                              │    ┌────────▼────────┐
                              │    │  thread_model    │
                              │    │  (TEB/PEB/GS,    │
                              │    │   TLS, pthread)  │
                              │    └────────┬────────┘
                              │    ┌────────▼────────┐
                              └───►│  io_transparent  │
                                   │  (handle table,  │
                                   │   path translate, │
                                   │   console)       │
                                   └────────┬────────┘
                                            │
                          ┌─────────────────▼─────────┐
                          │   seccomp BPF filter       │
                          │   ~50 syscalls whitelisted  │
                          └─────────────────┬─────────┘
                                            │
                          ┌─────────────────▼─────────┐
                          │       Linux kernel         │
                          │  (open,read,write,mmap,    │
                          │   clone,futex,exit...)     │
                          └───────────────────────────┘
```

## Architecture

The project is organized into 11 source components, each responsible
for one layer of the Windows→Linux translation:

| Layer | File | LOC | Role |
|-------|------|-----|------|
| PE Loader | `src/pe_loader.c` | 698 | Parse PE32+ headers, mmap sections at VA, apply relocations |
| I/O Transparency | `src/io_transparent.c` | 539 | Handle→fd table, Windows→Linux path translation, pipes |
| Win32 Bridge | `src/win32_bridge.c` | 1137 | Static IAT resolver, kernel32.dll exports (~45 functions) |
| NT Stubs | `src/nt_stubs.c` | 1244 | ntdll.dll stubs: NtCreateFile, NtAllocateVirtualMemory, NtCreateThread, etc. (17 functions) |
| Memory Manager | `src/memory_manager.c` | 748 | VirtualAlloc/VirtualFree, heap (free-list + mutex), region tracking |
| Thread Model | `src/thread_model.c` | 329 | TEB/PEB synthesis, GS segment via arch_prctl, per-thread TEB |
| Signal Passthrough | `src/signal_passthrough.c` | 256 | SIGSEGV crash dump (VA+registers), SIGTERM→ExitProcess(0) |
| Seccomp Filter | `src/seccomp_filter.c` | 237 | BPF syscall whitelist via libseccomp, ioctl restricted |
| /proc Compat | `src/proc_compat.c` | 173 | PR_SET_VMA_ANON_NAME, fd cleanup, /proc/self/cmdline |
| Launcher | `src/winexec.c` | 269 | Main entry, 9-step init, process naming |
| Globals | `src/globals.c` | 33 | Shared state: TEB-based LastError, import resolver pointer |

**Total: ~5600 lines of C11, 11 headers (~1700 lines), 3 test programs (~800 lines).**

## Dependencies

### Build
- `gcc` or `clang` (C11)
- `make`
- `libseccomp-dev` (for seccomp BPF filter)
- `python3` (for test .exe generation only)

### Test (optional)
- `x86_64-w64-mingw32-gcc` (to compile PE test programs from Linux)

### Runtime
- Linux kernel ≥ 4.17 (MAP_FIXED_NOREPLACE)
- Linux kernel ≥ 5.17 (PR_SET_VMA_ANON_NAME, for /proc/maps labels)
- x86_64 architecture

## Build & Install

```bash
# Build
make

# Build with debug logging and sanitizers
make debug

# Install to /usr/local/bin
sudo make install

# Clean
make clean
```

## Usage

```
winexec [--debug] [--no-seccomp] [--paths <file>] <prog.exe> [args...]
```

| Flag | Description |
|------|-------------|
| `--debug` | Verbose logging of PE load, entry point, exit code |
| `--no-seccomp` | Disable seccomp BPF syscall filter (for debugging) |
| `--paths <file>` | Custom Windows→Linux path mapping file |

## Path Mapping

Windows paths are translated to Linux paths at runtime. Rules are loaded
from `.winexec_paths` in the current directory, or configured with `--paths`.

### Format (one rule per line)

```
# .winexec_paths
C:\Users\bob  →  /home/bob
C:\tmp        →  /tmp
D:\           →  /mnt/d
```

### Built-in defaults (if no .winexec_paths found)

| Windows prefix | Linux path |
|----------------|-----------|
| `C:\Users\<user>` | `/home/<user>` |
| `C:\tmp` | `/tmp` (if exists) |
| `C:\Users` | `/home` |
| `C:\` | current working directory |
| `D:\` | `/mnt/d` (if exists) |

## What Is Transparent

- **`ps aux`, `htop`** — process name shows the .exe name (via `prctl(PR_SET_NAME)`)
- **`/proc/pid/maps`** — PE sections labeled `PE:.text`, `PE:.data`, etc. (via `PR_SET_VMA_ANON_NAME`)
- **`/proc/pid/cmdline`** — shows the .exe path + its arguments (argv overwritten in-place)
- **`/proc/pid/fd`** — no stray file descriptors (cleaned up during init)
- **`strace`, `lsof`** — native Linux syscalls visible
- **Linux signals** — `SIGTERM` triggers `ExitProcess(0)`, `SIGSEGV` shows a crash dump
- **Exit codes** — Windows `ExitProcess(code)` → Linux `exit(code)` propagated to `$?`
- **I/O pipes** — stdin/stdout/stderr map to fd 0/1/2, pipe via `|` works

## Testing

```bash
# Full test suite (build + run)
make test

# Compile PE test programs
make hello    # test_hello.exe  —  basic functionality test
make stress   # test_stress.exe — stress/load test

# Run stress test manually
./build/bin/winexec build/test_stress.exe

# Stress test + SIGTERM validation
./build/bin/winexec build/test_stress.exe & sleep 0.2; kill -TERM $!

# Stress orchestration script
./tests/run_stress.sh
```

## Known Limitations

| Feature | Status |
|---------|--------|
| **GUI (USER32/GDI32)** | Not implemented — GUI apps will crash on first USER32 import |
| **COM/DirectX** | Not implemented |
| **Registry** | Not implemented — `RegOpenKeyEx`/`RegQueryValueEx` return `ERROR_FILE_NOT_FOUND` |
| **SEH exceptions** | Partial — `__try`/`__except` not emulated. SIGSEGV caught with crash dump only |
| **TLS callbacks** | Not implemented — code in `.tls` directory executed before entry point is ignored |
| **WoW64 (32-bit)** | Not implemented — only PE32+ (x86_64) supported |
| **Imports by ordinal** | Not implemented — only name-based imports resolved |
| **Third-party DLLs** | Not implemented — `msvcrt.dll`, `vcruntime140.dll`, etc. are not bundled |
| **DLL loading** | Not implemented — `LoadLibrary`/`GetProcAddress` are stubs |
| **Overlapped I/O** | Not implemented — `ReadFile`/`WriteFile` with `OVERLAPPED` return an error |
| **Console cursor/color** | Not implemented — raw console output only |
| **Networking (Winsock)** | Not implemented |

## License

MIT
