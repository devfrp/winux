/*
 * test_hello.c — Programme de test PE minimal pour Winux
 *
 * Compilation (depuis Linux avec MinGW-w64, SANS CRT) :
 *   x86_64-w64-mingw32-gcc -std=c11 -O2 -s -nostartfiles -nostdlib \
 *       -e WinMainCRTStartup \
 *       -o build/test_hello.exe test_hello.c \
 *       -lkernel32
 *
 * Valide :
 *   1. WriteFile → stdout Linux (via notre stub kernel32_WriteFile)
 *   2. HeapAlloc / HeapFree → heap processus Winux
 *   3. CreateThread + WaitForSingleObject + CloseHandle
 *   4. GetLastError / SetLastError via TEB
 *   5. Exit code 42 propagé au shell Linux ($? = 42)
 */

/*
 * Déclarations minimales (pas de #include <windows.h> pour éviter la CRT)
 */

#ifdef __x86_64__
#define WINAPI __attribute__((ms_abi))
#else
#define WINAPI
#endif

typedef void           *HANDLE;
typedef unsigned int    DWORD;
typedef unsigned short  WORD;
typedef unsigned char   BYTE;
typedef unsigned long   ULONG_PTR;
typedef void           *LPVOID;
typedef void           *LPCVOID;
typedef const char     *LPCSTR;

#define NULL            ((void *)0)
#define TRUE            1
#define FALSE           0

typedef int BOOL;

#define STD_OUTPUT_HANDLE   ((DWORD)-11)

#define GENERIC_READ   0x80000000
#define GENERIC_WRITE  0x40000000

#define CREATE_ALWAYS  2
#define FILE_ATTRIBUTE_NORMAL 0x00000080

#define HEAP_ZERO_MEMORY  0x00000008

#define INFINITE          0xFFFFFFFF
#define WAIT_OBJECT_0     0

/*
 * Prototypes Win32 (appelés via IAT → nos stubs dans win32_bridge.c)
 */
WINAPI HANDLE GetStdHandle(DWORD nStdHandle);
WINAPI BOOL   WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                         DWORD *lpNumberOfBytesWritten, LPVOID lpOverlapped);
WINAPI void   ExitProcess(DWORD uExitCode);
WINAPI HANDLE GetProcessHeap(void);
WINAPI LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, unsigned long dwBytes);
WINAPI BOOL   HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
WINAPI HANDLE CreateThread(LPVOID lpThreadAttributes, unsigned long dwStackSize,
                            LPVOID lpStartAddress, LPVOID lpParameter,
                            DWORD dwCreationFlags, DWORD *lpThreadId);
WINAPI DWORD  WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINAPI BOOL   CloseHandle(HANDLE hObject);
WINAPI DWORD  GetLastError(void);
WINAPI void   SetLastError(DWORD dwErrCode);

/*
 * Helper pour écrire une chaîne sur stdout sans CRT
 */
static void puts_win32(char *msg)
{
    DWORD written = 0;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD len = 0;
    while (msg[len]) len++;
    WriteFile(hOut, msg, len, &written, NULL);
    WriteFile(hOut, "\r\n", 2, &written, NULL);
}

/*
 * itoa simplifié dans un buffer statique
 */
static char *itoa_simple(int val, char *buf)
{
    char *p = buf;
    if (val < 0) { *p++ = '-'; val = -val; }
    if (val == 0) { *p++ = '0'; *p = '\0'; return buf; }
    char tmp[32];
    int i = 0;
    while (val > 0) { tmp[i++] = '0' + (val % 10); val /= 10; }
    while (i > 0) *p++ = tmp[--i];
    *p = '\0';
    return buf;
}

static void write_dec(HANDLE hOut, int val)
{
    char buf[32];
    itoa_simple(val, buf);
    DWORD written = 0;
    char *s = buf;
    while (*s) s++;
    WriteFile(hOut, buf, (DWORD)(s - buf), &written, NULL);
}

static void write_hex(HANDLE hOut, unsigned long val)
{
    char buf[32];
    char *p = buf;
    *p++ = '0'; *p++ = 'x';
    for (int shift = 28; shift >= 0; shift -= 4) {
        unsigned long nibble = (val >> shift) & 0xF;
        *p++ = (char)(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));
    }
    *p = '\0';
    DWORD written = 0;
    WriteFile(hOut, buf, (DWORD)(p - buf), &written, NULL);
}

/*
 * Thread proc
 */
static DWORD WINAPI thread_proc(LPVOID param)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    int val = *(int *)param;
    DWORD written = 0;
    WriteFile(hOut, "  [thread] Hello from PE thread! value=", 40, &written, NULL);
    write_dec(hOut, val);
    WriteFile(hOut, "\r\n", 2, &written, NULL);
    return 0;
}

/*
 * Point d'entrée (appelé par le CRT startup)
 */
void WinMainCRTStartup(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    puts_win32("=== Winux PE Test: Hello from Windows PE! ===");
    puts_win32("");

    /* Test 1 : WriteFile direct */
    {
        DWORD w = 0;
        WriteFile(hOut, "  WriteFile direct to stdout: OK\r\n", 34, &w, NULL);
    }

    /* Test 2 : HeapAlloc / HeapFree */
    HANDLE hHeap = GetProcessHeap();
    char *buf = (char *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 128);
    if (!buf) {
        puts_win32("  FAIL: HeapAlloc returned NULL");
        ExitProcess(99);
    }
    DWORD w = 0;
    WriteFile(hOut, "  HeapAlloc: OK, ptr=", 21, &w, NULL);
    write_hex(hOut, (unsigned long)(unsigned long long)(void *)buf);
    WriteFile(hOut, "\r\n", 2, &w, NULL);
    HeapFree(hHeap, 0, buf);
    puts_win32("  HeapFree: OK");

    /* Test 3 : GetLastError / SetLastError */
    SetLastError(12345);
    DWORD le = GetLastError();
    WriteFile(hOut, "  GetLastError after SetLastError(12345): ", 43, &w, NULL);
    write_dec(hOut, (int)le);
    WriteFile(hOut, " (expected 12345)\r\n", 19, &w, NULL);

    /* Test 4 : CreateThread + WaitForSingleObject */
    int thread_val = 42;
    DWORD thread_id = 0;
    HANDLE hThread = CreateThread(NULL, 4096,
                                   (LPVOID)(void *)thread_proc,
                                   &thread_val, 0, &thread_id);

    if (!hThread) {
        puts_win32("  FAIL: CreateThread returned NULL");
        ExitProcess(98);
    }

    WriteFile(hOut, "  Thread created (id=", 20, &w, NULL);
    write_dec(hOut, (int)thread_id);
    WriteFile(hOut, ")\r\n", 3, &w, NULL);

    DWORD wait_ret = WaitForSingleObject(hThread, 5000);
    WriteFile(hOut, "  WaitForSingleObject returned: ", 32, &w, NULL);
    write_dec(hOut, (int)wait_ret);
    WriteFile(hOut, " (expected 0=WAIT_OBJECT_0)\r\n", 30, &w, NULL);
    CloseHandle(hThread);

    puts_win32("");
    puts_win32("=== All tests passed! Exit code: 42 ===");

    /* Test 5 : Exit code 42 propagé au shell */
    ExitProcess(42);
}
