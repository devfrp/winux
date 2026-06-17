# Contributing to winux

## Prerequisites

```bash
# Ubuntu / Debian
sudo apt install gcc make libseccomp-dev gcc-mingw-w64-x86-64

# Arch / Manjaro
sudo pacman -S gcc make libseccomp mingw-w64-gcc
```

Optional but recommended:
```bash
sudo apt install valgrind cppcheck clang-tidy  # static analysis + memory
```

## Code Conventions

- **C standard:** C11 (`-std=c11`)
- **Naming:**
  - Public symbols: `winux_` prefix (`winux_set_last_error`)
  - Macros: `WINUX_` prefix (`WINUX_ALIGN_UP`, `WINUX_MAX_HANDLES`)
  - Internal/static functions: `snake_case` (`pe_map_section`)
  - Types: `WINUX_` prefix for structs (`WINUX_TEB`, `WINUX_HEAP`)
- **Formatting:** Kernel-style brackets, 4-space indent, no tabs
- **Comments:** English preferred (legacy files use French — both accepted)
- **No warnings:** `-Wall -Wextra -Werror` enforced in Makefile

## Adding a New NT Stub

1. **Declare** in `include/nt_stubs.h`:
   ```c
   WINAPI NTSTATUS NtNewFunction(PARAM1 arg1, PARAM2 arg2);
   ```
   The `WINAPI` macro expands to `__attribute__((ms_abi))` on x86_64
   so PE code compiled with Microsoft ABI can call it directly.

2. **Implement** in `src/nt_stubs.c`:
   ```c
   WINAPI NTSTATUS NtNewFunction(PARAM1 arg1, PARAM2 arg2)
   {
       // Translate Windows semantics to Linux syscall
       // Use io_get_handle() for HANDLE → fd lookup
       // Call winux_set_last_error() to set thread-local error
   }
   ```

3. **Register** in the IAT table in `src/win32_bridge.c`:
   ```c
   IMPORT_NT(NtNewFunction),
   ```

4. **Add a test** in `tests/test_hello.c` (basic) or `tests/test_stress.c` (load).

## Adding a New kernel32 Function

Same workflow, but declare in `include/win32_bridge.h`, implement in
`src/win32_bridge.c` with `kernel32_` prefix, and register with:
```c
IMPORT("kernel32.dll", NewFunction),
```

## Running Tests

```bash
# Quick smoke test
make && ./build/bin/winexec build/test_hello.exe

# Full test suite
make clean && make hello stress
./build/bin/winexec --no-seccomp build/test_stress.exe
bash tests/run_stress.sh

# Debug mode
make debug
./build/bin/winexec --debug build/test_hello.exe
```

## Pull Request Checklist

Before opening a PR, verify:

- [ ] `make clean && make` succeeds with **zero warnings**
- [ ] `make hello stress` compiles all PE test programs
- [ ] `bash tests/run_stress.sh` — all 5 tests **PASS**
- [ ] `valgrind --leak-check=full --error-exitcode=1 ./build/bin/winexec --no-seccomp build/test_hello.exe` — **zero definitely lost** bytes
- [ ] `strace -c ./build/bin/winexec --no-seccomp build/test_hello.exe 2>&1 | tail -20` — no syscall outside the seccomp whitelist
- [ ] New code follows naming conventions (`winux_` / `WINUX_`)
- [ ] `README.md` updated if adding user-visible features
