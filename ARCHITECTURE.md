# ARCHITECTURE.md — Winux Technical Reference

## 1. Annotated Call Stack

From `argv[1]` to the first byte of PE code executed.

```
winexec.c:main(argc, argv)
│   Parse --debug, --no-seccomp, --paths, extract <file.exe>
│
├─► proc_compat.c:proc_compat_init()
│       close stray fds > 1000 via /proc/self/fd scan
│
├─► io_transparent.c:io_init()
│       dup stdin/stdout/stderr → handles 0/1/2, load path rules from .winexec_paths
│
├─► memory_manager.c:mem_init()
│       mmap(MAP_ANONYMOUS, 64 MB) → process heap, init free-list
│
├─► win32_bridge.c:win32_bridge_init()
│       assign global winux_import_resolver = win32_bridge_resolve
│
├─► pe_loader.c:pe_load("prog.exe")
│   │   open + mmap PE file, validate MZ/PE signatures
│   │
│   ├─► pe_loader.c:pe_validate_headers()
│   │       check DOS magic, PE signature, AMD64 machine type
│   │
│   ├─► pe_loader.c:pe_map_section() × N sections
│   │       mmap(MAP_FIXED_NOREPLACE) each section at VA = ImageBase + RVA
│   │       copy raw data from file, mprotect() to final perms
│   │
│   ├─► proc_compat.c:proc_label_vma(addr, size, "PE:.text")
│   │       prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME) per section
│   │
│   ├─► pe_loader.c:pe_apply_relocations()
│   │       walk .reloc directory, add delta to each IMAGE_REL_BASED_DIR64
│   │
│   ├─► pe_loader.c:pe_resolve_imports()
│   │   │   walk IMAGE_IMPORT_DESCRIPTOR entries
│   │   │
│   │   └─► win32_bridge.c:win32_bridge_resolve("kernel32.dll", "WriteFile")
│   │           linear scan of static import_table[], return function pointer
│   │           write resolved address into IAT (IMAGE_THUNK_DATA64->Function)
│   │
│   └─► return PE_IMAGE* with mapped_base, entry_point, sections
│
├─► signal_passthrough.c:signal_passthrough_init(pe_base, pe_size)
│       sigaction(SIGSEGV → sigsegv_handler)  catch PE crashes with reg dump
│       sigaction(SIGTERM → sigterm_handler)  _exit(0) on SIGTERM
│       sigaction(SIGCHLD → SIG_IGN)
│
├─► thread_model.c:thread_model_init(pe_base, pe_size, stack_base, stack_limit)
│   │
│   ├─► memory_manager.c:mem_virtual_alloc() → PEB (PAGE_READWRITE, 4 KB)
│   │       set PEB->ImageBaseAddress = pe_base
│   │       set PEB->ProcessHeap = mem_get_process_heap()
│   │
│   ├─► memory_manager.c:mem_virtual_alloc() → main TEB (PAGE_READWRITE, 4 KB)
│   │       TEB->NtTib.StackBase = stack_base
│   │       TEB->NtTib.StackLimit = stack_limit
│   │       TEB->NtTib.Self = &TEB      (read by PE code via gs:[0x30])
│   │       TEB->Peb   = &PEB            (read by PE code via gs:[0x60])
│   │       TEB->LastErrorValue = 0    (read by GetLastError via gs:[0x68])
│   │
│   └─► syscall(__NR_arch_prctl, ARCH_SET_GS, &TEB)
│           set GS segment base → TEB for mov rax, gs:[0x30] etc.
│
├─► seccomp_filter.c:seccomp_filter_install(true)
│       libseccomp: init(SCMP_ACT_KILL_PROCESS), add ~50 SCMP_SYS rules, seccomp_load()
│
├─► winexec.c:set_process_name(exe_path)
│       prctl(PR_SET_NAME, "prog") + overwrite argv[0] in-place
│
├─► proc_compat.c:proc_set_cmdline(argv, exe_path, pe_argc, pe_argv)
│       overwrite argv[0..N] in-place for /proc/self/cmdline
│
└─► winexec.c:entry_fn()  [typedef int (WINAPI *pe_entry_fn)(void)]
        jump to pe->entry_point (VA = mapped_base + AddressOfEntryPoint)
        ┌──────────────────────────────────────────┐
        │  PE CODE EXECUTES HERE                    │
        │  push rbp; push rdi; push rsi; ...       │
        │  call GetStdHandle → kernel32_GetStdHandle│
        │  call WriteFile     → kernel32_WriteFile  │
        │  call HeapAlloc     → mem_heap_alloc      │
        │  call CreateThread  → NtCreateThread      │
        │  call ExitProcess   → io_shutdown + exit  │
        └──────────────────────────────────────────┘
```

---

## 2. Windows → Linux Correspondence Table

| Windows Concept | Winux Implementation | Linux Primitive |
|:--|:--|:--|
| **HANDLE** (file) | `io_handles[index]`, index cast to `HANDLE` | `fd` via `io_register_handle(fd, ...)` |
| **HANDLE** (stdin/out/err) | Index 0/1/2 in `io_handles[]` | `dup(STDIN_FILENO)` etc. |
| **HANDLE** (thread) | `pthread_t` cast to `HANDLE` | `pthread_create()` / `pthread_timedjoin_np()` |
| **INVALID_HANDLE_VALUE** | `(HANDLE)(uintptr_t)-1` | — |
| **VirtualAlloc** | `mem_virtual_alloc()` → `mmap(MAP_ANONYMOUS)` | `mmap()` / `mprotect()` |
| **VirtualFree** | `mem_virtual_free()` → `munmap()` or `mmap(PROT_NONE)` | `munmap()` |
| **VirtualProtect** | `mem_virtual_protect()` → `mprotect()` | `mprotect()` |
| **VirtualQuery** | `mem_virtual_query()` → scan `mem_regions[]` table | — |
| **HeapAlloc** | `mem_heap_alloc()` → free-list allocator + `pthread_mutex_lock` | `mmap(MAP_ANONYMOUS)` for expansion |
| **HeapFree** | `mem_heap_free()` → mark free + coalesce + mutex | — |
| **GetProcessHeap** | Returns `process_heap` pointer cast to `HANDLE` | — |
| **Thread** | `kernel32_CreateThread()` → `NtCreateThread()` | `pthread_create()` with ms_abi wrapper |
| **WaitForSingleObject** | `pthread_timedjoin_np()` for threads, instant for I/O | `pthread_timedjoin_np()` |
| **TEB** | `WINUX_TEB` struct in `thread_model.c` | `syscall(SYS_arch_prctl, ARCH_SET_GS, &teb)` |
| **PEB** | `WINUX_PEB` struct allocated via `mem_virtual_alloc()` | `mmap(MAP_ANONYMOUS)` |
| **TEB at gs:[0x30]** | `teb_get_current()` → `movq %%gs:0x30, %0` | GS segment base register |
| **TEB at gs:[0x60]** | `peb_get_current()` → `movq %%gs:0x60, %0` | GS segment base register |
| **GetLastError** | `winux_teb_get_last_error()` → `teb->LastErrorValue` (gs:[0x68]) | GS segment + fallback `__thread` |
| **SetLastError** | `winux_teb_set_last_error(err)` → `teb->LastErrorValue = err` | GS segment + fallback `__thread` |
| **CreateFile** | `kernel32_CreateFileA()` → translate path, call `open()` | `open()` / `openat()` |
| **ReadFile** | `kernel32_ReadFile()` → `read()` on `entry->linux_fd` | `read()` |
| **WriteFile** | `kernel32_WriteFile()` → `write()` on `entry->linux_fd` | `write()` |
| **CreatePipe** | `io_create_pipe()` → `pipe()` + register both fds | `pipe()` |
| **CreateProcess** | not implemented | — |
| **LoadLibrary / GetProcAddress** | stub — returns NULL | — |
| **Path translation** | `io_translate_path("C:\\Users\\...")` → `/home/...` | `strncasecmp()` prefix matching |
| **CONIN$ / CONOUT$** | Redirected to `/dev/tty` | `open("/dev/tty")` |
| **NUL** | Redirected to `/dev/null` | `open("/dev/null")` |
| **Signal (SIGSEGV)** | `sigsegv_handler()` → crash dump VA + 16 GPRs | `sigaction()` + `ucontext_t` |
| **Signal (SIGTERM)** | `sigterm_handler()` → `_exit(0)` | `sigaction()` + `_exit()` |
| **ExitProcess(code)** | `io_shutdown()` + `exit(code)` | `exit()` |
| **Process name in ps** | `prctl(PR_SET_NAME, "prog")` + argv[0] overwrite | `prctl()` |
| **PE sections in maps** | `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, "PE:.text")` | `prctl()` |
| **Seccomp syscall filter** | `seccomp_filter_install()` → BPF program | libseccomp → `seccomp()` syscall |
| **Stack canary** | `TEB->Tib.ArbitraryUserPointer` = `fs:[0x28]` (copied) | FS segment base read |
| **PE relocations** | `pe_apply_relocations()` → add delta to `IMAGE_REL_BASED_DIR64` | — |
| **PE imports (IAT)** | `pe_resolve_imports()` → `win32_bridge_resolve()` | — |

---

## 3. Security Boundaries

### What a malicious .exe CAN do (despite seccomp)

| Capability | Mechanism | Severity |
|:--|:--|:--|
| Read any user-readable file | `open()` + `read()` via `CreateFile`/`ReadFile` | High |
| Write to any user-writable file | `open(O_CREAT)` + `write()` via `CreateFile`/`WriteFile` | High |
| Delete any user-owned file | `unlink()` (if in seccomp whitelist) | High |
| Exhaust all RAM | `VirtualAlloc()` loops → `mmap()` until OOM | High |
| Fork-bomb via threads | `CreateThread()` → `clone()` loops | High |
| Leak data via stdout/stderr | `WriteFile()` to fd 1/2 | Medium |
| Network access via file paths | `/proc/net/tcp`, `/dev/tcp` (if enabled) | Medium |
| Access /proc/self/* | `open()` on procfs paths | Low |
| Execute any whitelisted syscall | ~50 syscalls available with arbitrary args | Low |
| CPU DoS (busy loops) | No CPU limit enforcement | Low |

### What a malicious .exe CANNOT do

| Restriction | Mechanism |
|:--|:--|
| Call non-whitelisted syscalls | seccomp BPF kills process with SIGSYS |
| Call `ptrace()` / attach to other processes | not in seccomp whitelist |
| Call `kexec_load()`, `bpf()`, `kvm()` | not in seccomp whitelist |
| Load kernel modules | not in seccomp whitelist |
| Change UID/GID / gain root | `setuid`/`setgid` not whitelisted |
| Create device nodes | `mknod` not whitelisted |
| Mount/unmount filesystems | `mount`/`umount2` not whitelisted |
| Reboot / shutdown | `reboot` not whitelisted |
| Modify seccomp filter | `seccomp()` called once at init, `PR_SET_SECCOMP` blocked |
| Access raw sockets | `socket()` not whitelisted |
| Send signals to other processes | `kill()`/`tgkill()` whitelisted but restricted to own thread group |
| Escape the process namespace | no `unshare()`, no `clone(NEWNS)`, etc. |

### Hardening recommendations for production

```bash
# Limit address space (prevents VirtualAlloc OOM)
ulimit -v 4194304  # 4 GB max virtual memory

# Limit CPU time (prevents infinite loops)
ulimit -t 300      # 5 minutes max

# Limit file size (prevents disk fill)
ulimit -f 1048576  # 1 GB max file size

# Run under a dedicated user
sudo -u winuxbox winexec prog.exe
```

---

## 4. Quick Debug Commands

```bash
# ── PE sections in /proc/maps ──────────────────────────────
grep "PE:" /proc/$(pgrep winexec)/maps
# Output example:
# 140000000-140001000 r-xp PE:.text
# 140002000-140003000 rw-p PE:.data

# ── Trace real syscalls emitted by the PE ──────────────────
strace -f -e trace=openat,read,write,mmap,mprotect,clone \
    ./build/bin/winexec prog.exe 2>&1 | tail -50

# ── Verify process name in ps ─────────────────────────────
ps -p $(pgrep winexec) -o pid,comm,args
# PID  COMMAND         COMMAND
# 1234 prog            /home/user/prog.exe

# ── Test path mapping with debug ──────────────────────────
cat > /tmp/test.paths << 'EOF'
C:\tmp  →  /tmp
C:\data →  /var/data
EOF
./build/bin/winexec --debug --paths /tmp/test.paths prog.exe

# ── Dump all active I/O handles ───────────────────────────
# (from test_main or add --io-dump flag)
./build/bin/winexec --io-dump prog.exe

# ── Run without seccomp (for strace/gdb) ──────────────────
./build/bin/winexec --no-seccomp prog.exe

# ── Inspect PE imports before execution ───────────────────
objdump -p prog.exe | grep -A2 'DLL Name'

# ── Check if seccomp is active ────────────────────────────
cat /proc/$(pgrep winexec)/status | grep -i seccomp
# Seccomp: 2  (2 = SECCOMP_MODE_FILTER)
# Seccomp_filters: 1

# ── Memory usage of the PE process ────────────────────────
cat /proc/$(pgrep winexec)/status | grep -E 'Vm|Rss|Threads'

# ── Find which syscall was blocked (seccomp violation) ────
# Run without seccomp, capture syscalls, diff with whitelist:
strace -c ./build/bin/winexec --no-seccomp prog.exe 2>&1 | head -40

# ── Verify exit code propagation ──────────────────────────
./build/bin/winexec prog.exe; echo "shell \$? = $?"

# ── Build with debug logging ──────────────────────────────
make clean && make debug
./build/bin/winexec --debug prog.exe 2>&1 | head -30

# ── Dump TEB/PEB state (add to winexec or use gdb) ────────
gdb -batch -ex "run" -ex "x/40gx \$gs_base" \
    --args ./build/bin/winexec prog.exe
```
