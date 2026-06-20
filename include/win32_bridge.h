/*
 * === FICHIER : include/win32_bridge.h ===
 * Description : API publique du pont Win32.
 *               Fournit la table de résolution d'import (IAT)
 *               et les fonctions exportées de kernel32.dll / user32.dll.
 *
 * Architecture :
 *   - win32_bridge_init() doit être appelé AVANT pe_load().
 *     Elle assigne le pointeur global winux_import_resolver.
 *   - La résolution est statique : table de lookup compilée en dur,
 *     pas de dlopen() intermédiaire.
 *   - Chaque fonction exportée utilise __attribute__((ms_abi))
 *     pour correspondre à l'ABI Microsoft x64 attendue par le code PE.
 *
 * Dépendances : include/winux.h, include/nt_stubs.h
 */

#ifndef WIN32_BRIDGE_H
#define WIN32_BRIDGE_H

#include "winux.h"

/* ==========================================================================
   Initialisation
   ========================================================================== */

/*
 * Initialise le pont Win32 :
 * - Enregistre le résolveur d'import global
 * - Initialise le heap de processus par défaut
 * - Prépare les handles standard (stdin/stdout/stderr)
 *
 * Doit être appelé avant tout pe_load().
 */
void win32_bridge_init(void);

void win32_bridge_shutdown(void);

/*
 * Fonction de résolution d'import.
 * Appelée par pe_loader.c pour chaque entrée IAT.
 * Cherche dans la table statique (dll, func) → pointeur de fonction.
 */
void *win32_bridge_resolve(const char *dll, const char *func);

/* ==========================================================================
   kernel32.dll — Fonctions exportées
   ========================================================================== */

WINAPI HANDLE kernel32_GetStdHandle(DWORD nStdHandle);
WINAPI BOOL   kernel32_CloseHandle(HANDLE hObject);
WINAPI HANDLE kernel32_CreateFileA(
    LPCSTR lpFileName,
    DWORD  dwDesiredAccess,
    DWORD  dwShareMode,
    PVOID  lpSecurityAttributes,
    DWORD  dwCreationDisposition,
    DWORD  dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
WINAPI BOOL kernel32_ReadFile(
    HANDLE hFile,
    PVOID  lpBuffer,
    DWORD  nNumberOfBytesToRead,
    DWORD *lpNumberOfBytesRead,
    PVOID  lpOverlapped
);
WINAPI BOOL kernel32_WriteFile(
    HANDLE   hFile,
    PVOID    lpBuffer,
    DWORD    nNumberOfBytesToWrite,
    DWORD   *lpNumberOfBytesWritten,
    PVOID    lpOverlapped
);
WINAPI void kernel32_ExitProcess(UINT uExitCode);
WINAPI PVOID kernel32_VirtualAlloc(
    PVOID   lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);
WINAPI BOOL kernel32_VirtualFree(
    PVOID  lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
);
WINAPI HANDLE kernel32_GetProcessHeap(void);
WINAPI PVOID  kernel32_HeapAlloc(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
);
WINAPI BOOL kernel32_HeapFree(
    HANDLE hHeap,
    DWORD  dwFlags,
    PVOID  lpMem
);
WINAPI DWORD kernel32_GetModuleFileNameA(
    HANDLE hModule,
    LPSTR  lpFilename,
    DWORD  nSize
);
WINAPI HANDLE kernel32_GetModuleHandleA(LPCSTR lpModuleName);
WINAPI DWORD  kernel32_GetLastError(void);
WINAPI void   kernel32_SetLastError(DWORD dwErrCode);
WINAPI DWORD  kernel32_GetFileSize(
    HANDLE hFile,
    DWORD *lpFileSizeHigh
);
WINAPI DWORD kernel32_SetFilePointer(
    HANDLE hFile,
    LONG   lDistanceToMove,
    LONG  *lpDistanceToMoveHigh,
    DWORD  dwMoveMethod
);
WINAPI BOOL kernel32_SetEndOfFile(HANDLE hFile);
WINAPI BOOL kernel32_FlushFileBuffers(HANDLE hFile);
WINAPI HANDLE kernel32_CreateThread(
    PVOID  lpThreadAttributes,
    SIZE_T dwStackSize,
    PVOID  lpStartAddress,
    PVOID  lpParameter,
    DWORD  dwCreationFlags,
    DWORD *lpThreadId
);
WINAPI BOOL   kernel32_TerminateThread(HANDLE hThread, DWORD dwExitCode);
WINAPI DWORD  kernel32_ResumeThread(HANDLE hThread);
WINAPI HANDLE kernel32_CreatePipe(
    HANDLE *hReadPipe,
    HANDLE *hWritePipe,
    PVOID   lpPipeAttributes,
    DWORD   nSize
);
WINAPI DWORD kernel32_WaitForSingleObject(
    HANDLE hHandle,
    DWORD  dwMilliseconds
);
WINAPI BOOL kernel32_GetConsoleMode(
    HANDLE hConsoleHandle,
    DWORD *lpMode
);
WINAPI BOOL kernel32_SetConsoleMode(
    HANDLE hConsoleHandle,
    DWORD  dwMode
);
WINAPI BOOL kernel32_WriteConsoleA(
    HANDLE  hConsoleOutput,
    PVOID   lpBuffer,
    DWORD   nNumberOfCharsToWrite,
    DWORD  *lpNumberOfCharsWritten,
    PVOID   lpReserved
);
WINAPI BOOL kernel32_ReadConsoleA(
    HANDLE  hConsoleInput,
    PVOID   lpBuffer,
    DWORD   nNumberOfCharsToRead,
    DWORD  *lpNumberOfCharsRead,
    PVOID   lpReserved
);
WINAPI void kernel32_Sleep(DWORD dwMilliseconds);

/* kernel32.dll — Registry functions */
WINAPI LONG kernel32_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
                                    DWORD samDesired, HKEY *phkResult);
WINAPI LONG kernel32_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName,
                                       DWORD *lpReserved, DWORD *lpType,
                                       BYTE *lpData, DWORD *lpcbData);
WINAPI LONG kernel32_RegSetValueExA(HKEY hKey, LPCSTR lpValueName,
                                     DWORD Reserved, DWORD dwType,
                                     const BYTE *lpData, DWORD cbData);
WINAPI LONG kernel32_RegCloseKey(HKEY hKey);
WINAPI LONG kernel32_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved,
                                      LPSTR lpClass, DWORD dwOptions,
                                      DWORD samDesired, void *lpSecurityAttributes,
                                      HKEY *phkResult, DWORD *lpdwDisposition);

/* kernel32.dll — Third-party DLL resolution */
WINAPI HANDLE kernel32_LoadLibraryA(LPCSTR lpLibFileName);
WINAPI void  *kernel32_GetProcAddress(HANDLE hModule, LPCSTR lpProcName);
WINAPI BOOL   kernel32_FreeLibrary(HANDLE hLibModule);

/* kernel32.dll — SEH support */
WINAPI LONG kernel32_UnhandledExceptionFilter(PVOID ExceptionInfo);
WINAPI PVOID kernel32_SetUnhandledExceptionFilter(PVOID lpTopLevelExceptionFilter);
WINAPI void   kernel32_FatalAppExitA(UINT uAction, LPCSTR lpMessageText);

#endif /* WIN32_BRIDGE_H */
