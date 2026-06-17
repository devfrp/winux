# Roadmap v0.2

Prioritized by impact/effort ratio. Each item includes the motivation, the
concrete approach, and the estimated complexity.

---

## 1. SEH — Structured Exception Handling

**Why:** PE executables compiled with MSVC use `__try`/`__except` blocks
extensively. Currently, any exception in PE code produces a raw crash dump
via our SIGSEGV handler. Proper SEH emulation would allow PE programs to
recover from access violations, division by zero, etc., as they do on
Windows.

**Approach:**
- Walk the `TEB->NtTib.ExceptionList` chain (linked list of
  `EXCEPTION_REGISTRATION_RECORD` on the stack) when SIGSEGV fires.
- If a handler is found that accepts the exception (`EXCEPTION_EXECUTE_HANDLER`),
  unwind the stack by restoring `RSP`/`RIP` from the registration record and
  jump to the handler.
- If no handler accepts (`EXCEPTION_CONTINUE_SEARCH`), pass to the next
  registration record or terminate.
- Need to define `EXCEPTION_RECORD`, `CONTEXT`, and
  `EXCEPTION_REGISTRATION_RECORD` structures matching the PE ABI.

**Complexity:** Medium (signal handler logic + stack unwinding on x86_64).

---

## 2. Registry Stubs — HKCU only

**Why:** Many Windows programs read their configuration from `HKEY_CURRENT_USER`.
Without registry support, programs that check for first-run flags, license keys,
or user preferences fail silently. HKCU is the highest-impact subset.

**Approach:**
- Store HKCU data in `$HOME/.winux/registry.json` (simple JSON key-value tree).
- Implement `RegOpenKeyExA`, `RegQueryValueExA`, `RegSetValueExA`, `RegCloseKey`.
- Map registry paths to JSON paths: `HKCU\Software\MyApp\Settings` →
  `$HOME/.winux/registry.json → ["Software"]["MyApp"]["Settings"]`.
- Stub `RegCreateKeyExA` to auto-create missing keys.
- All other hives (`HKLM`, `HKU`, etc.) return `ERROR_FILE_NOT_FOUND`.

**Complexity:** Low (file I/O + JSON parsing, could use a minimal embedded parser).

---

## 3. TLS Callbacks

**Why:** Some PE executables (especially packed/copy-protected ones) run
initialization code *before* the entry point via the Thread Local Storage
directory. If TLS callbacks are defined in the PE but not called, the program
may crash or behave incorrectly because critical initialization (e.g.,
unpacking, license checks) never happened.

**Approach:**
- Parse the `IMAGE_DIRECTORY_ENTRY_TLS` data directory in `pe_loader.c`.
- Extract `AddressOfCallBacks` (array of function pointers terminated by NULL).
- Call each callback **after** loading the PE and building the TEB/PEB, but
  **before** jumping to the entry point.
- Callbacks receive `(PVOID ImageBase, DWORD Reason, PVOID Reserved)` with
  `Reason = DLL_PROCESS_ATTACH` (1).
- TLS callbacks for thread attach/detach (`DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH`)
  should be called from `NtCreateThread`/`NtTerminateThread`.

**Complexity:** Low (parse TLS directory, iterate callback array, call).

---

## 4. Imports by Ordinal

**Why:** Some Windows DLLs (especially `ntdll.dll`, `kernel32.dll`, and
`user32.dll`) export functions only by ordinal number, not by name. Our current
IAT resolver in `win32_bridge.c` only handles name-based imports. Programs that
rely on ordinal imports (e.g., `GetProcAddress` by ordinal, or `Delay-Load`
thunks) crash silently.

**Approach:**
- Add an ordinal→name mapping table for the ~30 most commonly imported
  ordinals from `ntdll.dll`, `kernel32.dll`, and `user32.dll`:
  ```
  { "ntdll.dll", 1,  "NtMapViewOfSection" },
  { "ntdll.dll", 8,  "NtCreateSection" },
  { "kernel32.dll", 1, "GetModuleHandleA" },
  ...
  ```
- Extend `win32_bridge_resolve()` to accept ordinals: when the PE import
  thunk has the ordinal bit set, look up the ordinal→name mapping, then
  resolve by name as usual.

**Complexity:** Low (table + fallback lookup in existing resolver).

---

## 5. Third-Party DLL Resolution

**Why:** Nearly all real-world PE executables import from third-party DLLs
like `msvcrt.dll`, `vcruntime140.dll`, `msvcp140.dll`, and the MinGW runtime.
Currently, if a PE imports from a DLL we don't provide, the IAT entry stays
NULL and the program crashes silently without any useful error message.

**Approach:**
- Add a search path `$WINUX_LIB_PATH` (default: `/usr/local/lib/winux`,
  `$HOME/.winux/lib`) where users can place `.so` Linux-native shared
  libraries that export the same function signatures as Windows DLLs.
- Option A (transparent): if `win32_bridge_resolve()` doesn't find a function
  in the static table, attempt `dlopen("libmsvcrt.so")` followed by
  `dlsym("printf")`. This provides a "soft fallback" for any DLL.
- Option B (explicit): require users to compile or provide `.so` wrappers.
  This is safer but less automatic.
- Improve error messages: log `[winexec] UNRESOLVED: msvcrt.dll!printf` when
  an import cannot be resolved, so users know exactly what's missing.

**Complexity:** Medium (dlopen/dlsym infrastructure, ABI translation layer).

---

## v0.3 and Beyond (Tentative)

| Feature | Why |
|---------|-----|
| **Console PTY integration** | Proper `WriteConsole` with ANSI escapes, cursor movement, colors |
| **Networking (Winsock)** | `socket`/`connect`/`recv` via Linux sockets, mapped to fd handles |
| **File system watcher** | `ReadDirectoryChangesW` → `inotify` |
| **Process creation** | `CreateProcess` → `fork+execve` of nested winexec |
| **GUI subset (IME, message boxes)** | `MessageBoxA` via `zenity`/`notify-send` |
| **Time functions** | `GetSystemTime`, `QueryPerformanceCounter` |
| **Locale/encoding** | `MultiByteToWideChar`/`WideCharToMultiByte` with UTF-8 |
