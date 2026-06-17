/*
 * === FICHIER : win32_bridge.c ===
 * Description : Pont Win32 — résolution d'import et implémentation
 *               des fonctions exportées de kernel32.dll.
 *
 * Architecture :
 *   - Table de lookup statique (dll, func) → pointeur de fonction.
 *     Pas de dlopen() intermédiaire. La résolution est O(n) sur
 *     une table compilée en dur.
 *   - Chaque fonction exportée utilise __attribute__((ms_abi))
 *     pour que le code PE (compilé avec l'ABI Microsoft x64)
 *     puisse les appeler directement.
 *   - GetStdHandle() retourne les fd Linux 0/1/2 castés en HANDLE.
 *   - CreateFile sur "CONIN$"/"CONOUT$" redirige vers /dev/tty.
 *   - GetLastError/SetLastError utilisent le TEB synthétique
 *     via winux_get_last_error / winux_set_last_error (composant 5).
 *
 * Dépendances : include/winux.h, include/nt_stubs.h,
 *               include/io_transparent.h, include/memory_manager.h,
 *               include/thread_model.h
 */

#include "include/winux.h"
#include "include/win32_bridge.h"
#include "include/nt_stubs.h"
#include "include/io_transparent.h"
#include "include/memory_manager.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <sched.h>

/* ==========================================================================
   Table d'import statique
   ========================================================================== */

/*
 * Chaque entrée mappe (nom_de_dll, nom_de_fonction) → pointeur de fonction.
 * La table est parcourue linéairement par win32_bridge_resolve().
 * L'ordre n'importe pas, mais les fonctions les plus fréquentes
 * sont placées en tête pour accélérer la recherche.
 */

typedef struct {
    const char *dll;
    const char *name;
    void       *fn;
} IMPORT_ENTRY;

#define IMPORT(dll_name, func_name) \
    { dll_name, #func_name, (void *)(uintptr_t)kernel32_##func_name }

#define IMPORT_NT(func_name) \
    { "ntdll.dll", #func_name, (void *)(uintptr_t)func_name }

static IMPORT_ENTRY import_table[] = {
    /* ===========================================================
       ntdll.dll — Stubs NT natifs
       =========================================================== */
    IMPORT_NT(NtCreateFile),
    IMPORT_NT(NtReadFile),
    IMPORT_NT(NtWriteFile),
    IMPORT_NT(NtClose),
    IMPORT_NT(NtAllocateVirtualMemory),
    IMPORT_NT(NtFreeVirtualMemory),
    IMPORT_NT(NtProtectVirtualMemory),
    IMPORT_NT(NtCreateThread),
    IMPORT_NT(NtTerminateProcess),
    IMPORT_NT(NtTerminateThread),
    IMPORT_NT(NtWaitForSingleObject),
    IMPORT_NT(NtDelayExecution),
    IMPORT_NT(NtQueryInformationFile),
    IMPORT_NT(NtSetInformationFile),
    IMPORT_NT(NtDeviceIoControlFile),
    IMPORT_NT(NtQueryDirectoryFile),
    IMPORT_NT(NtFlushBuffersFile),

    /* Alias sans décorations (certains linkers omettent le @@) */
    { "ntdll.dll", "RtlAllocateHeap",      NULL },
    { "ntdll.dll", "RtlFreeHeap",          NULL },
    { "ntdll.dll", "RtlZeroMemory",        NULL },
    { "ntdll.dll", "RtlFillMemory",        NULL },
    { "ntdll.dll", "RtlMoveMemory",        NULL },
    { "ntdll.dll", "RtlCompareMemory",     NULL },

    /* ===========================================================
       kernel32.dll — Win32 API
       =========================================================== */
    IMPORT(     "kernel32.dll", GetStdHandle),
    IMPORT(     "kernel32.dll", CloseHandle),
    IMPORT(     "kernel32.dll", CreateFileA),
    IMPORT(     "kernel32.dll", ReadFile),
    IMPORT(     "kernel32.dll", WriteFile),
    IMPORT(     "kernel32.dll", ExitProcess),
    IMPORT(     "kernel32.dll", VirtualAlloc),
    IMPORT(     "kernel32.dll", VirtualFree),
    IMPORT(     "kernel32.dll", GetProcessHeap),
    IMPORT(     "kernel32.dll", HeapAlloc),
    IMPORT(     "kernel32.dll", HeapFree),
    IMPORT(     "kernel32.dll", GetModuleFileNameA),
    IMPORT(     "kernel32.dll", GetModuleHandleA),
    IMPORT(     "kernel32.dll", GetLastError),
    IMPORT(     "kernel32.dll", SetLastError),
    IMPORT(     "kernel32.dll", GetFileSize),
    IMPORT(     "kernel32.dll", SetFilePointer),
    IMPORT(     "kernel32.dll", SetEndOfFile),
    IMPORT(     "kernel32.dll", FlushFileBuffers),
    IMPORT(     "kernel32.dll", CreatePipe),
    IMPORT(     "kernel32.dll", WaitForSingleObject),
    IMPORT(     "kernel32.dll", GetConsoleMode),
    IMPORT(     "kernel32.dll", SetConsoleMode),
    IMPORT(     "kernel32.dll", WriteConsoleA),
    IMPORT(     "kernel32.dll", ReadConsoleA),
    IMPORT(     "kernel32.dll", Sleep),

    /* kernel32.dll — fonctions souvent importées, stubs minimales */
    { "kernel32.dll", "GetCommandLineA",       NULL },
    { "kernel32.dll", "GetEnvironmentVariableA", NULL },
    { "kernel32.dll", "SetEnvironmentVariableA", NULL },
    { "kernel32.dll", "GetCurrentDirectoryA",  NULL },
    { "kernel32.dll", "SetCurrentDirectoryA",  NULL },
    { "kernel32.dll", "GetCurrentProcess",     NULL },
    { "kernel32.dll", "GetCurrentThread",      NULL },
    { "kernel32.dll", "GetCurrentProcessId",   NULL },
    { "kernel32.dll", "GetCurrentThreadId",    NULL },
    { "kernel32.dll", "GetTickCount",          NULL },
    { "kernel32.dll", "GetSystemTimeAsFileTime", NULL },
    { "kernel32.dll", "QueryPerformanceCounter", NULL },
    { "kernel32.dll", "QueryPerformanceFrequency", NULL },
    { "kernel32.dll", "InitializeCriticalSection", NULL },
    { "kernel32.dll", "EnterCriticalSection",  NULL },
    { "kernel32.dll", "LeaveCriticalSection",  NULL },
    { "kernel32.dll", "DeleteCriticalSection", NULL },
    { "kernel32.dll", "TlsAlloc",              NULL },
    { "kernel32.dll", "TlsGetValue",           NULL },
    { "kernel32.dll", "TlsSetValue",           NULL },
    { "kernel32.dll", "TlsFree",               NULL },
    { "kernel32.dll", "MultiByteToWideChar",   NULL },
    { "kernel32.dll", "WideCharToMultiByte",   NULL },
    { "kernel32.dll", "LoadLibraryA",          NULL },
    { "kernel32.dll", "GetProcAddress",        NULL },
    { "kernel32.dll", "FreeLibrary",           NULL },
    IMPORT(     "kernel32.dll", CreateThread),
    { "kernel32.dll", "GetSystemInfo",         NULL },
    { "kernel32.dll", "IsDebuggerPresent",     NULL },
    { "kernel32.dll", "SetUnhandledExceptionFilter", NULL },
    { "kernel32.dll", "UnhandledExceptionFilter", NULL },
    { "kernel32.dll", "RaiseException",        NULL },
    { "kernel32.dll", "RtlUnwind",             NULL },
    { "kernel32.dll", "DebugBreak",            NULL },
    { "kernel32.dll", "OutputDebugStringA",    NULL },
    { "kernel32.dll", "DeleteFileA",           NULL },
    { "kernel32.dll", "MoveFileA",             NULL },
    { "kernel32.dll", "CopyFileA",             NULL },
    { "kernel32.dll", "CreateDirectoryA",      NULL },
    { "kernel32.dll", "RemoveDirectoryA",      NULL },
    { "kernel32.dll", "FindFirstFileA",        NULL },
    { "kernel32.dll", "FindNextFileA",         NULL },
    { "kernel32.dll", "FindClose",             NULL },
    { "kernel32.dll", "GetFileAttributesA",    NULL },
    { "kernel32.dll", "SetFileAttributesA",    NULL },
    { "kernel32.dll", "GetFileTime",           NULL },
    { "kernel32.dll", "SetFileTime",           NULL },
    { "kernel32.dll", "LocalAlloc",            NULL },
    { "kernel32.dll", "LocalFree",             NULL },
    { "kernel32.dll", "GlobalAlloc",           NULL },
    { "kernel32.dll", "GlobalFree",            NULL },
    { "kernel32.dll", "GetVersionExA",         NULL },
    { "kernel32.dll", "GetVersion",            NULL },
    { "kernel32.dll", "FormatMessageA",        NULL },
    { "kernel32.dll", "CreateEventA",          NULL },
    { "kernel32.dll", "SetEvent",              NULL },
    { "kernel32.dll", "ResetEvent",            NULL },
    /* CloseHandle already resolved above via IMPORT macro */
    { "kernel32.dll", "WaitForMultipleObjects", NULL },
    { "kernel32.dll", "lstrlenA",              NULL },
    { "kernel32.dll", "lstrcpyA",              NULL },
    { "kernel32.dll", "lstrcmpA",              NULL },

    /* kernel32.dll — Heap* déjà listées, aliases fréquentes */
    { "kernel32.dll", "HeapCreate",            NULL },
    { "kernel32.dll", "HeapDestroy",           NULL },
    { "kernel32.dll", "HeapReAlloc",           NULL },
    { "kernel32.dll", "HeapSize",              NULL },

    /* Terminaison (sentinel) */
    { NULL, NULL, NULL }
};

/* ==========================================================================
   Résolveur d'import
   ========================================================================== */

/*
 * win32_bridge_resolve : cherche (dll, func) dans la table statique.
 * Appelé par pe_loader.c pour chaque entrée IAT.
 *
 * Stratégie : parcours linéaire O(n). La table fait ~100 entrées,
 * ce qui est négligeable au chargement.
 *
 * Si le nom de fonction n'est pas trouvé, retourne NULL.
 * Le PE loader laissera alors l'entrée IAT à zéro, ce qui causera
 * un segfault si le programme tente d'appeler cette fonction.
 */
void *win32_bridge_resolve(const char *dll, const char *func)
{
    if (!dll || !func) return NULL;

    for (IMPORT_ENTRY *e = import_table; e->dll != NULL; e++) {
        if (strcasecmp(e->dll, dll) == 0 &&
            strcmp(e->name, func) == 0) {
            return e->fn;
        }
    }

    return NULL;
}

/* ==========================================================================
   Initialisation du pont
   ========================================================================== */

/*
 * win32_bridge_init : assigne le pointeur global winux_import_resolver
 * à notre fonction de lookup, et initialise la couche I/O.
 *
 * Doit être appelé AVANT tout pe_load().
 */
void win32_bridge_init(void)
{
    /* Enregistrer notre résolveur d'import */
    winux_import_resolver = win32_bridge_resolve;

    /* Initialiser la couche I/O (table de handles, traduction de chemins) */
    io_init();

    WINUX_LOG("Win32 bridge initialized, import resolver registered");
}

/* ==========================================================================
   kernel32.dll — Implémentations
   ========================================================================== */

/*
 * GetStdHandle : retourne les handles standard.
 *
 * STD_INPUT_HANDLE  (-10) → fd Linux 0 casté en HANDLE (index 0)
 * STD_OUTPUT_HANDLE (-11) → fd Linux 1 casté en HANDLE (index 1)
 * STD_ERROR_HANDLE  (-12) → fd Linux 2 casté en HANDLE (index 2)
 *
 * Ces handles sont pré-alloués par io_init() dans io_transparent.c.
 */
WINAPI HANDLE kernel32_GetStdHandle(DWORD nStdHandle)
{
    switch (nStdHandle) {
    case (DWORD)-10: /* STD_INPUT_HANDLE  */
        return (HANDLE)(uintptr_t)0;
    case (DWORD)-11: /* STD_OUTPUT_HANDLE */
        return (HANDLE)(uintptr_t)1;
    case (DWORD)-12: /* STD_ERROR_HANDLE  */
        return (HANDLE)(uintptr_t)2;
    default:
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
}

/*
 * CloseHandle : ferme un handle via io_close_handle().
 * Supporte fichiers, pipes, et consoles.
 */
WINAPI BOOL kernel32_CloseHandle(HANDLE hObject)
{
    int handle_idx = (int)(intptr_t)hObject;

    if (io_close_handle(handle_idx) != 0) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

/*
 * CreateFileA : crée ou ouvre un fichier Windows.
 *
 * Cas spéciaux :
 *   - "CONIN$"  → /dev/tty en lecture seule
 *   - "CONOUT$" → /dev/tty en écriture seule
 *   - "CON"     → /dev/tty en lecture/écriture
 *   - "NUL"     → /dev/null
 *
 * Chemins normaux : traduits via io_translate_path().
 */
WINAPI HANDLE kernel32_CreateFileA(
    LPCSTR lpFileName,
    DWORD  dwDesiredAccess,
    DWORD  dwShareMode,
    PVOID  lpSecurityAttributes,
    DWORD  dwCreationDisposition,
    DWORD  dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    char linux_path[4096];
    int oflags, fd, handle_idx;
    int is_console = 0;
    mode_t mode = 0666;
    const char *target_path;

    (void)dwShareMode;
    (void)lpSecurityAttributes;
    (void)hTemplateFile;

    if (!lpFileName) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    /* Détection des périphériques console */
    if (strcasecmp(lpFileName, "CONIN$") == 0) {
        target_path = "/dev/tty";
        is_console = 1;
    } else if (strcasecmp(lpFileName, "CONOUT$") == 0 ||
               strcasecmp(lpFileName, "CON") == 0) {
        target_path = "/dev/tty";
        is_console = 1;
    } else if (strcasecmp(lpFileName, "NUL") == 0) {
        target_path = "/dev/null";
    } else {
        /*
         * Chemin normal : traduire Windows → Linux.
         * On utilise io_translate_path pour la conversion.
         */
        if (!io_translate_path(lpFileName, linux_path, sizeof(linux_path))) {
            winux_set_last_error(ERROR_PATH_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
        target_path = linux_path;
    }

    /*
     * Construire les flags open(2) :
     *   GENERIC_READ  → O_RDONLY
     *   GENERIC_WRITE → O_WRONLY
     *   les deux      → O_RDWR
     */
    if ((dwDesiredAccess & GENERIC_READ) && (dwDesiredAccess & GENERIC_WRITE))
        oflags = O_RDWR;
    else if (dwDesiredAccess & GENERIC_WRITE)
        oflags = O_WRONLY;
    else if (dwDesiredAccess & GENERIC_READ)
        oflags = O_RDONLY;
    else
        oflags = O_RDONLY;

    /*
     * Traduire la disposition de création :
     *   CREATE_NEW    → O_CREAT | O_EXCL
     *   CREATE_ALWAYS → O_CREAT | O_TRUNC
     *   OPEN_EXISTING → 0
     *   OPEN_ALWAYS   → O_CREAT
     *   TRUNCATE_EXISTING → O_TRUNC
     */
    switch (dwCreationDisposition) {
    case CREATE_NEW:        oflags |= O_CREAT | O_EXCL;  break;
    case CREATE_ALWAYS:     oflags |= O_CREAT | O_TRUNC; break;
    case OPEN_EXISTING:     /* rien de plus */            break;
    case OPEN_ALWAYS:       oflags |= O_CREAT;           break;
    case TRUNCATE_EXISTING: oflags |= O_TRUNC;           break;
    default:                                              break;
    }

    fd = open(target_path, oflags, mode);
    if (fd < 0) {
        winux_set_last_error(ERROR_FILE_NOT_FOUND);
        if (errno == EACCES) winux_set_last_error(ERROR_ACCESS_DENIED);
        if (errno == EEXIST) winux_set_last_error(ERROR_FILE_EXISTS);
        return INVALID_HANDLE_VALUE;
    }

    /* Enregistrer le handle dans la table I/O */
    WINUX_HANDLE_TYPE htype = is_console ? HANDLE_TYPE_CONSOLE : HANDLE_TYPE_FILE;
    handle_idx = io_register_handle(fd, htype, lpFileName);
    if (handle_idx < 0) {
        close(fd);
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }

    winux_set_last_error(ERROR_SUCCESS);
    WINUX_LOG("CreateFileA: '%s' → '%s' fd=%d handle=%d",
              lpFileName, target_path, fd, handle_idx);
    return (HANDLE)(uintptr_t)(intptr_t)handle_idx;
}

/*
 * ReadFile : lit depuis un handle (fichier, pipe, console).
 * Délégue à read(2) sur le fd Linux sous-jacent.
 */
WINAPI BOOL kernel32_ReadFile(
    HANDLE hFile,
    PVOID  lpBuffer,
    DWORD  nNumberOfBytesToRead,
    DWORD *lpNumberOfBytesRead,
    PVOID  lpOverlapped
)
{
    int handle_idx;
    WINUX_HANDLE_ENTRY *entry;
    ssize_t bytes_read;

    if (!lpBuffer || nNumberOfBytesToRead == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* I/O asynchrone non supportée */
    if (lpOverlapped) {
        WINUX_LOG("ReadFile: overlapped I/O not supported");
        winux_set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    handle_idx = (int)(intptr_t)hFile;
    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    bytes_read = read(entry->linux_fd, lpBuffer, (size_t)nNumberOfBytesToRead);

    if (bytes_read < 0) {
        winux_set_last_error(ERROR_READ_FAULT);
        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
        return FALSE;
    }

    if (lpNumberOfBytesRead)
        *lpNumberOfBytesRead = (DWORD)bytes_read;

    if (bytes_read == 0) {
        winux_set_last_error(ERROR_HANDLE_EOF);
        return TRUE; /* EOF n'est pas une erreur pour ReadFile */
    }

    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

/*
 * WriteFile : écrit vers un handle (fichier, pipe, console).
 * Délégue à write(2) sur le fd Linux sous-jacent.
 */
WINAPI BOOL kernel32_WriteFile(
    HANDLE   hFile,
    PVOID    lpBuffer,
    DWORD    nNumberOfBytesToWrite,
    DWORD   *lpNumberOfBytesWritten,
    PVOID    lpOverlapped
)
{
    int handle_idx;
    WINUX_HANDLE_ENTRY *entry;
    ssize_t bytes_written;

    if (!lpBuffer || nNumberOfBytesToWrite == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (lpOverlapped) {
        WINUX_LOG("WriteFile: overlapped I/O not supported");
        winux_set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    handle_idx = (int)(intptr_t)hFile;
    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    bytes_written = write(entry->linux_fd, lpBuffer, (size_t)nNumberOfBytesToWrite);

    if (bytes_written < 0) {
        winux_set_last_error(ERROR_WRITE_FAULT);
        if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0;
        return FALSE;
    }

    if (lpNumberOfBytesWritten)
        *lpNumberOfBytesWritten = (DWORD)bytes_written;

    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

/*
 * ExitProcess : termine le processus avec le code de sortie Windows.
 * Propager le code via exit().
 */
WINAPI void kernel32_ExitProcess(UINT uExitCode)
{
    WINUX_LOG("ExitProcess(%u)", uExitCode);

    /* Nettoyer la couche I/O */
    io_shutdown();

    exit((int)uExitCode);
}

/*
 * VirtualAlloc : alloue de la mémoire virtuelle.
 * Délégue au memory_manager.
 */
WINAPI PVOID kernel32_VirtualAlloc(
    PVOID   lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
)
{
    PVOID   base = lpAddress;
    SIZE_T  size = dwSize;
    NTSTATUS status;

    status = mem_virtual_alloc(&base, &size, flAllocationType, flProtect);

    if (status != STATUS_SUCCESS) {
        return NULL;
    }

    return base;
}

/*
 * VirtualFree : libère de la mémoire virtuelle.
 * Délégue au memory_manager.
 */
WINAPI BOOL kernel32_VirtualFree(
    PVOID  lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
)
{
    PVOID  base = lpAddress;
    SIZE_T size = dwSize;
    NTSTATUS status;

    status = mem_virtual_free(&base, &size, dwFreeType);

    return (status == STATUS_SUCCESS) ? TRUE : FALSE;
}

/*
 * GetProcessHeap : retourne le heap de processus géré par memory_manager.
 */
WINAPI HANDLE kernel32_GetProcessHeap(void)
{
    return (HANDLE)(uintptr_t)mem_get_process_heap();
}

/*
 * HeapAlloc : alloue depuis un heap (processus ou privé).
 */
WINAPI PVOID kernel32_HeapAlloc(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
)
{
    WINUX_HEAP *heap;

    if (dwBytes == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    heap = (WINUX_HEAP *)(uintptr_t)hHeap;
    PVOID ptr = mem_heap_alloc(heap, dwBytes);
    if (!ptr) {
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    if (dwFlags & HEAP_ZERO_MEMORY)
        memset(ptr, 0, dwBytes);

    winux_set_last_error(ERROR_SUCCESS);
    return ptr;
}

/*
 * HeapFree : libère depuis un heap.
 */
WINAPI BOOL kernel32_HeapFree(
    HANDLE hHeap,
    DWORD  dwFlags,
    PVOID  lpMem
)
{
    (void)dwFlags;

    if (!lpMem) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    WINUX_HEAP *heap = (WINUX_HEAP *)(uintptr_t)hHeap;
    BOOL result = mem_heap_free(heap, lpMem);

    winux_set_last_error(result ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER);
    return result;
}

/*
 * CreateThread : crée un thread Windows.
 * Délégue à NtCreateThread avec un contexte simplifié.
 */
WINAPI HANDLE kernel32_CreateThread(
    PVOID   lpThreadAttributes,
    SIZE_T  dwStackSize,
    PVOID   lpStartAddress,
    PVOID   lpParameter,
    DWORD   dwCreationFlags,
    DWORD  *lpThreadId
)
{
    HANDLE  hThread = INVALID_HANDLE_VALUE;
    NTSTATUS status;

    (void)lpThreadAttributes;
    (void)dwCreationFlags;
    (void)dwStackSize; /* pthread gère sa propre stack */

    if (!lpStartAddress) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /*
     * Construire un contexte simplifié pour le thread.
     * Le thread wrapper dans nt_stubs.c lit ctx[16] (Rip) et ctx[1] (RDX).
     */
    uint64_t thread_ctx[32];
    memset(thread_ctx, 0, sizeof(thread_ctx));
    thread_ctx[16] = (uint64_t)(uintptr_t)lpStartAddress; /* Rip */
    thread_ctx[1]  = (uint64_t)(uintptr_t)lpParameter;    /* RDX */

    status = NtCreateThread(
        &hThread,
        GENERIC_ALL,
        NULL,
        (HANDLE)(uintptr_t)-1,
        NULL,
        thread_ctx,
        NULL,
        FALSE
    );

    if (status != STATUS_SUCCESS) {
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    if (lpThreadId) {
        *lpThreadId = (DWORD)(uintptr_t)hThread;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return hThread;
}

/*
 * GetModuleFileNameA : retourne le chemin de l'exécutable PE chargé.
 * Le chemin est stocké par winexec.c dans g_loaded_exe_path.
 */
WINAPI DWORD kernel32_GetModuleFileNameA(
    HANDLE hModule,
    LPSTR  lpFilename,
    DWORD  nSize
)
{
    (void)hModule;

    if (!lpFilename || nSize == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    size_t len = strlen(g_loaded_exe_path);
    if (len >= nSize) {
        winux_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return (DWORD)nSize;
    }

    memcpy(lpFilename, g_loaded_exe_path, len + 1);
    winux_set_last_error(ERROR_SUCCESS);
    return (DWORD)len;
}

/*
 * GetModuleHandleA : stub qui retourne NULL.
 * Le code PE utilise souvent GetModuleHandleA(NULL) pour obtenir
 * le HINSTANCE du module courant.
 */
WINAPI HANDLE kernel32_GetModuleHandleA(LPCSTR lpModuleName)
{
    (void)lpModuleName;

    /*
     * Retourne un pseudo-handle non nul pour le module courant.
     * La valeur exacte n'a pas d'importance tant qu'elle est non nulle
     * et utilisable comme base pour GetProcAddress.
     */
    return (HANDLE)(uintptr_t)0x400000;
}

/*
 * GetLastError / SetLastError : lecture/écriture dans le TEB synthétique
 * via winux_get_last_error / winux_set_last_error.
 *
 * [COMPOSANT 5] : le TEB (Thread Environment Block) est actif via GS.
 * winux_get_last_error() lit gs:[0x68] (teb->LastErrorValue).
 * En fallback (pendant l'init), le __thread _last_error prend le relais.
 */
WINAPI DWORD kernel32_GetLastError(void)
{
    return winux_get_last_error();
}

WINAPI void kernel32_SetLastError(DWORD dwErrCode)
{
    winux_set_last_error(dwErrCode);
}

/*
 * GetFileSize : retourne la taille d'un fichier.
 */
WINAPI DWORD kernel32_GetFileSize(
    HANDLE hFile,
    DWORD *lpFileSizeHigh
)
{
    int handle_idx = (int)(intptr_t)hFile;
    WINUX_HANDLE_ENTRY *entry;
    struct stat st;

    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return (DWORD)-1; /* INVALID_FILE_SIZE */
    }

    if (fstat(entry->linux_fd, &st) != 0) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return (DWORD)-1;
    }

    if (lpFileSizeHigh) {
        *lpFileSizeHigh = (DWORD)((uint64_t)st.st_size >> 32);
    }

    winux_set_last_error(ERROR_SUCCESS);
    return (DWORD)(st.st_size & 0xFFFFFFFF);
}

/*
 * SetFilePointer : déplace le curseur de fichier.
 */
WINAPI DWORD kernel32_SetFilePointer(
    HANDLE hFile,
    LONG   lDistanceToMove,
    LONG  *lpDistanceToMoveHigh,
    DWORD  dwMoveMethod
)
{
    int handle_idx = (int)(intptr_t)hFile;
    WINUX_HANDLE_ENTRY *entry;
    off_t offset;
    int whence;

    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return (DWORD)-1;
    }

    offset = (off_t)lDistanceToMove;
    if (lpDistanceToMoveHigh) {
        offset |= ((off_t)(*lpDistanceToMoveHigh)) << 32;
    }

    switch (dwMoveMethod) {
    case 0: /* FILE_BEGIN   */ whence = SEEK_SET; break;
    case 1: /* FILE_CURRENT */ whence = SEEK_CUR; break;
    case 2: /* FILE_END     */ whence = SEEK_END; break;
    default:
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return (DWORD)-1;
    }

    off_t new_pos = lseek(entry->linux_fd, offset, whence);
    if (new_pos < 0) {
        winux_set_last_error(ERROR_SEEK_ON_DEVICE);
        return (DWORD)-1;
    }

    if (lpDistanceToMoveHigh) {
        *lpDistanceToMoveHigh = (LONG)((uint64_t)new_pos >> 32);
    }

    winux_set_last_error(ERROR_SUCCESS);
    return (DWORD)(new_pos & 0xFFFFFFFF);
}

/*
 * SetEndOfFile : tronque le fichier à la position courante.
 */
WINAPI BOOL kernel32_SetEndOfFile(HANDLE hFile)
{
    int handle_idx = (int)(intptr_t)hFile;
    WINUX_HANDLE_ENTRY *entry;
    off_t current_pos;

    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    current_pos = lseek(entry->linux_fd, 0, SEEK_CUR);
    if (current_pos < 0) {
        winux_set_last_error(ERROR_SEEK_ON_DEVICE);
        return FALSE;
    }

    if (ftruncate(entry->linux_fd, current_pos) != 0) {
        winux_set_last_error(ERROR_WRITE_FAULT);
        return FALSE;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

/*
 * FlushFileBuffers : force l'écriture sur disque (fsync).
 */
WINAPI BOOL kernel32_FlushFileBuffers(HANDLE hFile)
{
    int handle_idx = (int)(intptr_t)hFile;
    WINUX_HANDLE_ENTRY *entry;

    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (fsync(entry->linux_fd) != 0) {
        winux_set_last_error(ERROR_WRITE_FAULT);
        return FALSE;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

/*
 * CreatePipe : crée un pipe anonyme.
 * Délégue à io_create_pipe().
 */
WINAPI HANDLE kernel32_CreatePipe(
    HANDLE *hReadPipe,
    HANDLE *hWritePipe,
    PVOID   lpPipeAttributes,
    DWORD   nSize
)
{
    (void)lpPipeAttributes;

    if (io_create_pipe(hReadPipe, hWritePipe, nSize) != 0) {
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE; /* échec */
    }

    winux_set_last_error(ERROR_SUCCESS);
    return (HANDLE)(uintptr_t)1; /* succès → TRUE casté en HANDLE */
}

/*
 * WaitForSingleObject : attente sur un handle (thread ou I/O).
 * Pour les threads : pthread_timedjoin_np avec timeout.
 * Pour l'I/O : pas de support epoll pour l'instant (retour immédiat).
 */
WINAPI DWORD kernel32_WaitForSingleObject(
    HANDLE hHandle,
    DWORD  dwMilliseconds
)
{
    WINUX_HANDLE_ENTRY *entry;
    int handle_idx = (int)(intptr_t)hHandle;

    /* Vérifier si c'est un handle I/O valide */
    entry = io_get_handle(handle_idx);

    if (entry) {
        /*
         * Handle I/O : pas de support epoll/poll pour l'instant.
         * Retour immédiat.
         */
        winux_set_last_error(ERROR_SUCCESS);
        return WAIT_OBJECT_0;
    }

    /*
     * Ce n'est pas un handle I/O → probablement un handle de thread.
     * Le handle de thread est le pthread_t casté en HANDLE.
     * On essaie de faire un pthread_timedjoin_np.
     */
    pthread_t tid = (pthread_t)(uintptr_t)hHandle;
    if (tid == 0) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    }

    if (dwMilliseconds == 0) {
        /* Retour immédiat — on ne peut pas tester un thread sans join */
        winux_set_last_error(ERROR_SUCCESS);
        return WAIT_TIMEOUT;
    }

    /*
     * pthread_timedjoin_np : attente avec timeout.
     * Convertir le timeout Windows en temps absolu.
     */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    uint64_t timeout_ns = (uint64_t)dwMilliseconds * 1000000ULL;
    if (dwMilliseconds == INFINITE)
        timeout_ns = 30000000000ULL; /* 30 secondes max */

    ts.tv_sec  += (time_t)(timeout_ns / 1000000000ULL);
    ts.tv_nsec += (long)(timeout_ns % 1000000000ULL);
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec  += 1;
        ts.tv_nsec -= 1000000000L;
    }

    int rc = pthread_timedjoin_np(tid, NULL, &ts);
    if (rc == 0) {
        winux_set_last_error(ERROR_SUCCESS);
        return WAIT_OBJECT_0;
    }

    if (rc == ETIMEDOUT) {
        winux_set_last_error(ERROR_SUCCESS);
        return WAIT_TIMEOUT;
    }

    winux_set_last_error(ERROR_INVALID_HANDLE);
    return WAIT_FAILED;
}

/*
 * GetConsoleMode / SetConsoleMode : stubs console.
 * Retourne toujours TRUE (mode console standard).
 */
WINAPI BOOL kernel32_GetConsoleMode(
    HANDLE hConsoleHandle,
    DWORD *lpMode
)
{
    (void)hConsoleHandle;

    if (lpMode) {
        /*
         * Flags console standard :
         *   ENABLE_PROCESSED_INPUT  = 0x0001
         *   ENABLE_LINE_INPUT       = 0x0002
         *   ENABLE_ECHO_INPUT       = 0x0004
         *   ENABLE_PROCESSED_OUTPUT = 0x0001
         *   ENABLE_WRAP_AT_EOL_OUTPUT = 0x0002
         */
        *lpMode = 0x0001 | 0x0002; /* ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT */
    }

    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

WINAPI BOOL kernel32_SetConsoleMode(
    HANDLE hConsoleHandle,
    DWORD  dwMode
)
{
    (void)hConsoleHandle;
    (void)dwMode;

    /* Stub : on accepte tous les modes */
    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

/*
 * WriteConsoleA : écrit sur la console.
 * Redirige vers write() sur le fd sous-jacent.
 */
WINAPI BOOL kernel32_WriteConsoleA(
    HANDLE  hConsoleOutput,
    PVOID   lpBuffer,
    DWORD   nNumberOfCharsToWrite,
    DWORD  *lpNumberOfCharsWritten,
    PVOID   lpReserved
)
{
    int handle_idx;
    WINUX_HANDLE_ENTRY *entry;
    ssize_t bytes_written;

    (void)lpReserved;

    if (!lpBuffer || nNumberOfCharsToWrite == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    handle_idx = (int)(intptr_t)hConsoleOutput;
    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    bytes_written = write(entry->linux_fd, lpBuffer, (size_t)nNumberOfCharsToWrite);

    if (bytes_written < 0) {
        winux_set_last_error(ERROR_WRITE_FAULT);
        if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = 0;
        return FALSE;
    }

    if (lpNumberOfCharsWritten)
        *lpNumberOfCharsWritten = (DWORD)bytes_written;

    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

/*
 * ReadConsoleA : lit depuis la console.
 * Redirige vers read() sur le fd sous-jacent.
 */
WINAPI BOOL kernel32_ReadConsoleA(
    HANDLE  hConsoleInput,
    PVOID   lpBuffer,
    DWORD   nNumberOfCharsToRead,
    DWORD  *lpNumberOfCharsRead,
    PVOID   lpReserved
)
{
    int handle_idx;
    WINUX_HANDLE_ENTRY *entry;
    ssize_t bytes_read;

    (void)lpReserved;

    if (!lpBuffer || nNumberOfCharsToRead == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    handle_idx = (int)(intptr_t)hConsoleInput;
    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    bytes_read = read(entry->linux_fd, lpBuffer, (size_t)nNumberOfCharsToRead);

    if (bytes_read < 0) {
        winux_set_last_error(ERROR_READ_FAULT);
        if (lpNumberOfCharsRead) *lpNumberOfCharsRead = 0;
        return FALSE;
    }

    if (lpNumberOfCharsRead)
        *lpNumberOfCharsRead = (DWORD)bytes_read;

    winux_set_last_error(ERROR_SUCCESS);
    return TRUE;
}

/*
 * Sleep : suspension du thread courant.
 */
WINAPI void kernel32_Sleep(DWORD dwMilliseconds)
{
    if (dwMilliseconds == 0) {
        /* Yield le CPU */
        sched_yield();
        return;
    }

    if (dwMilliseconds > 60000) {
        /* Limiter à 60 secondes max */
        dwMilliseconds = 60000;
    }

    usleep(dwMilliseconds * 1000);
}
