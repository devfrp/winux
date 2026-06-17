# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- SEH (Structured Exception Handling) — crash recovery with TEB ExceptionList walk
- Registry stubs (HKCU) — JSON-backed per-user registry in `$HOME/.winux/`
- TLS callbacks — execute PE Thread Local Storage callbacks before entry point
- Imports by ordinal — resolve ntdll/kernel32 ordinals via mapping table
- Third-party DLL resolution — `dlopen()`-based fallback for non-system DLLs

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
