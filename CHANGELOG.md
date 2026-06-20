# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2025-06-20

### Added
- **Registry stubs (HKCU)** — JSON-backed per-user registry in `$HOME/.winux/registry.json`
  - `RegOpenKeyExA`, `RegQueryValueExA`, `RegSetValueExA`, `RegCloseKey`, `RegCreateKeyExA`
  - Supports REG_SZ and REG_DWORD types
  - Auto-creates missing keys on write
  - Non-HKCU hives return `ERROR_FILE_NOT_FOUND`
- **TLS callbacks** — execute PE Thread Local Storage callbacks before entry point
  - Parse `IMAGE_DIRECTORY_ENTRY_TLS` data directory in `pe_loader.c`
  - Call `DLL_PROCESS_ATTACH` callbacks after PE load, before entry
  - Call `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` from thread create/terminate
- **Imports by ordinal** — resolve ntdll/kernel32 ordinals via mapping table
  - ~50 ordinal-to-name mappings for ntdll.dll and kernel32.dll
  - Fallback to name-based lookup after ordinal resolution
- **Third-party DLL resolution** — `dlopen()`-based fallback for non-system DLLs
  - Search paths: `.`, `/usr/local/lib/winux`, `$HOME/.winux/lib`
  - Configurable via `$WINUX_LIB_PATH` environment variable
  - `LoadLibraryA`/`GetProcAddress`/`FreeLibrary` now functional via `dlopen`/`dlsym`
- **SEH (Structured Exception Handling)** — crash recovery with TEB ExceptionList walk
  - Walk `TEB->NtTib.ExceptionList` chain on SIGSEGV
  - Call `EXCEPTION_REGISTRATION_RECORD` handlers with `EXCEPTION_RECORD` + `CONTEXT`
  - Support recovery via `EXCEPTION_EXECUTE_HANDLER` with register restoration
  - Enhanced crash dump now shows SEH walk status

## [1.0.0] — 2025-06-17

### Added
- **PE32+ loader** (`pe_loader.c`): mmap sections at target VA, apply base relocations, build synthetic IAT
- **17 NT API stubs** (`nt_stubs.c`): NtCreateFile→open(), NtAllocateVirtualMemory→mmap(), NtCreateThread→pthread_create(), NtTerminateProcess→exit()
- **~45 kernel32 functions** (`win32_bridge.c`): GetStdHandle, CreateFile, ReadFile/WriteFile, ExitProcess, VirtualAlloc/Free, HeapAlloc/Free, CreateThread, WaitForSingleObject, GetLastError/SetLastError
- **I/O transparency layer** (`io_transparent.c`): handle→fd table, Windows→Linux path translation, pipe creation, CONIN$/CONOUT$→/dev/tty
- **Memory manager** (`memory_manager.c`): VirtualAlloc with region tracking, concurrent heap (free-list + mutex), VirtualQuery
- **Thread model** (`thread_model.c`): synthetic TEB/PEB structures, GS segment setup via arch_prctl, pthread_key per-thread TEB lookup
- **Signal passthrough** (`signal_passthrough.c`): SIGSEGV→PE crash dump (VA + 16 GPRs), SIGTERM→ExitProcess(0)
- **Seccomp BPF filter** (`seccomp_filter.c`): ~50 syscall whitelist, ioctl restricted to TIOCGWINSZ/FIONREAD, libseccomp-based
- **/proc transparency** (`proc_compat.c`): PR_SET_VMA_ANON_NAME labels, fd cleanup, /proc/self/cmdline overwrite
- **Launcher** (`winexec.c`): 9-step init sequence, --debug/--no-seccomp/--paths flags, prctl(PR_SET_NAME)
- **Test suite**: test_hello.exe (5 functional tests), test_stress.exe (4 stress tests), run_stress.sh (SIGTERM orchestration)

### Design Principles
- No Wine, no QEMU, no kernel module required — pure userspace
- Static IAT resolution (no dlopen for system DLLs)
- Microsoft x86_64 ABI via `__attribute__((ms_abi))` on all exported stubs
- PE sections mapped at original VA with MAP_FIXED for transparent execution
