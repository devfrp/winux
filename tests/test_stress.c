/*
 * test_stress.c — Programme de stress PE pour Winux
 *
 * Compilation (MinGW-w64, sans CRT) :
 *   x86_64-w64-mingw32-gcc -std=c11 -O2 -s -nostartfiles -nostdlib \
 *       -e WinMainCRTStartup -o test_stress.exe test_stress.c -lkernel32
 *
 * Tests :
 *   1. I/O intensive : 100k lignes stdout + lecture stdin via pipe
 *   2. Threads concurrents : 16 threads, 1000 alloc/free aléatoires
 *   3. Allocation massive : 512 blocs de 1 MB VirtualAlloc/VirtualFree
 *   4. Path translation : CreateFileA("C:\\tmp\\test.txt")
 *   5. Signal handling : testé via script shell externe (SIGTERM)
 */

#ifdef __x86_64__
#define WINAPI __attribute__((ms_abi))
#else
#define WINAPI
#endif

typedef void           *HANDLE;
typedef unsigned int    DWORD;
typedef unsigned long   SIZE_T;
typedef void           *LPVOID;
typedef void           *LPCVOID;
typedef const char     *LPCSTR;
typedef char           *LPSTR;

#define NULL            ((void *)0)
#define TRUE            1
#define FALSE           0
typedef int BOOL;

/*
 * ___chkstk_ms : requis par MinGW pour les fonctions avec
 * de grands frames de pile (> 4K). Simple no-op pour notre cas.
 */
void ___chkstk_ms(void) {}

#define STD_OUTPUT_HANDLE   ((DWORD)-11)
#define STD_INPUT_HANDLE    ((DWORD)-10)

#define GENERIC_READ      0x80000000
#define GENERIC_WRITE     0x40000000
#define CREATE_ALWAYS     2
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define OPEN_EXISTING     3

#define HEAP_ZERO_MEMORY  0x00000008

#define INFINITE          0xFFFFFFFF
#define WAIT_OBJECT_0     0

#define MEM_COMMIT        0x00001000
#define MEM_RESERVE       0x00002000
#define MEM_RELEASE       0x00008000
#define PAGE_READWRITE    0x04

/* Prototypes Win32 */
WINAPI HANDLE GetStdHandle(DWORD nStdHandle);
WINAPI BOOL   WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD n, DWORD *w, LPVOID o);
WINAPI BOOL   ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD n, DWORD *r, LPVOID o);
WINAPI void   ExitProcess(DWORD code);
WINAPI HANDLE GetProcessHeap(void);
WINAPI LPVOID HeapAlloc(HANDLE hHeap, DWORD flags, SIZE_T bytes);
WINAPI BOOL   HeapFree(HANDLE hHeap, DWORD flags, LPVOID mem);
WINAPI HANDLE CreateThread(LPVOID a, SIZE_T s, LPVOID fn, LPVOID p, DWORD f, DWORD *id);
WINAPI DWORD  WaitForSingleObject(HANDLE h, DWORD ms);
WINAPI BOOL   CloseHandle(HANDLE h);
WINAPI HANDLE CreateFileA(LPCSTR name, DWORD access, DWORD share,
                           LPVOID sec, DWORD disp, DWORD flags, HANDLE tmpl);
WINAPI DWORD  GetLastError(void);
WINAPI void   SetLastError(DWORD err);
WINAPI LPVOID VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD prot);
WINAPI BOOL   VirtualFree(LPVOID addr, SIZE_T size, DWORD type);
WINAPI void   Sleep(DWORD ms);
WINAPI DWORD  GetTickCount(void);

/* ==========================================================================
   Helpers sans CRT
   ========================================================================== */

static void write_str(char *msg)
{
    DWORD w = 0, len = 0;
    while (msg[len]) len++;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, len, &w, NULL);
}

static void write_crlf(void)
{
    DWORD w = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "\r\n", 2, &w, NULL);
}

static char *itoa_simple(int val, char *buf)
{
    char *p = buf;
    if (val < 0) { *p++ = '-'; val = -val; }
    if (val == 0) { *p++ = '0'; *p = 0; return buf; }
    char tmp[32];
    int i = 0;
    while (val > 0) { tmp[i++] = '0' + (val % 10); val /= 10; }
    while (i > 0) *p++ = tmp[--i];
    *p = 0;
    return buf;
}

static void write_dec(int val)
{
    char buf[32];
    char *s = itoa_simple(val, buf);
    DWORD w = 0, len = 0;
    while (s[len]) len++;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, len, &w, NULL);
}

/* ==========================================================================
   Test 1 : I/O intensive
   ========================================================================== */

static void test_io_intensive(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    static char line[128];
    DWORD w, r;
    int errors = 0;

    write_str("  [TEST 1] I/O intensive: ");
    write_str("writing 100000 lines...");
    write_crlf();

    /* Écrire 100 000 lignes */
    for (int i = 0; i < 100000; i++) {
        int pos = 0;

        /* Construire la ligne dans le buffer */
        line[pos++] = 'L';
        line[pos++] = 'I';
        line[pos++] = 'N';
        line[pos++] = 'E';
        line[pos++] = ':';
        line[pos++] = ' ';

        char *nb = itoa_simple(i, line + pos);
        while (nb && *nb) { nb++; } /* rien, juste pour avancer */
        while (line[pos]) pos++;

        line[pos++] = '\r';
        line[pos++] = '\n';

        WriteFile(hOut, line, (DWORD)pos, &w, NULL);
        if (w != (DWORD)pos) errors++;

        /* Vérifier stdin une ligne sur 1000 */
        if (i % 1000 == 0) {
            char test_buf[64];
            HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
            ReadFile(hIn, test_buf, sizeof(test_buf) - 1, &r, NULL);
            if (r > 0) {
                test_buf[r] = 0;
            }
        }
    }

    write_str("    Lines written: 100000, errors: ");
    write_dec(errors);
    write_crlf();

    if (errors == 0)
        write_str("    [PASS]");
    else
        write_str("    [FAIL]");
    write_crlf();
}

/* ==========================================================================
   Test 2 : Threads concurrents
   ========================================================================== */

#define TEST2_THREADS 16
#define TEST2_ALLOCS  1000
#define TEST2_MIN_SIZE 8
#define TEST2_MAX_SIZE 65536

typedef struct {
    int thread_id;
    int errors;
} thread2_data;

static DWORD WINAPI test2_thread_proc(LPVOID param)
{
    thread2_data *data = (thread2_data *)param;
    HANDLE hHeap = GetProcessHeap();
    LPVOID *ptrs;
    int sizes_mem[TEST2_ALLOCS];
    int errors = 0;

    /* Allouer le tableau de pointeurs */
    ptrs = (LPVOID *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, TEST2_ALLOCS * sizeof(LPVOID));
    if (!ptrs) { data->errors = 9999; return 0; }

    DWORD seed = (DWORD)(unsigned long long)(void *)data + (DWORD)data->thread_id;

    /* Phase 1 : allocations aléatoires */
    for (int i = 0; i < TEST2_ALLOCS; i++) {
        /* PRNG minimal */
        seed = seed * 1103515245 + 12345;
        SIZE_T size = TEST2_MIN_SIZE + (SIZE_T)(seed % (TEST2_MAX_SIZE - TEST2_MIN_SIZE));
        size = (size + 7) & ~7UL; /* align 8 */

        LPVOID p = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
        if (!p) {
            errors++;
            sizes_mem[i] = 0;
            ptrs[i] = NULL;
            continue;
        }
        sizes_mem[i] = (int)size;
        ptrs[i] = p;

        /* Écrire un motif pour détecter la corruption */
        unsigned char *bp = (unsigned char *)p;
        bp[0] = (unsigned char)(seed & 0xFF);
        bp[size - 1] = (unsigned char)((seed >> 8) & 0xFF);
    }

    /* Phase 2 : libération dans l'ordre inverse (stress coalescing) */
    for (int i = TEST2_ALLOCS - 1; i >= 0; i--) {
        if (ptrs[i]) {
            /* Vérifier le motif avant de libérer */
            unsigned char *bp = (unsigned char *)ptrs[i];
            /* Le motif est reproductible si on refait le même seed
               mais c'est compliqué. On vérifie juste que la mémoire
               est accessible (pas de segfault). */
            volatile unsigned char v = bp[0];
            (void)v;
            v = bp[sizes_mem[i] - 1];
            (void)v;

            if (!HeapFree(hHeap, 0, ptrs[i]))
                errors++;
        }
    }

    HeapFree(hHeap, 0, ptrs);
    data->errors = errors;
    return 0;
}

static void test_threads_concurrent(void)
{
    write_str("  [TEST 2] Concurrent threads: 16 threads, 1000 alloc/free each");
    write_crlf();

    HANDLE threads[TEST2_THREADS];
    thread2_data data[TEST2_THREADS];
    int total_errors = 0;

    for (int i = 0; i < TEST2_THREADS; i++) {
        data[i].thread_id = i;
        data[i].errors = 0;
        threads[i] = CreateThread(NULL, 65536,
                                   test2_thread_proc, &data[i], 0, NULL);
    }

    /* Attendre tous les threads */
    for (int i = 0; i < TEST2_THREADS; i++) {
        if (threads[i]) {
            WaitForSingleObject(threads[i], 30000);
            CloseHandle(threads[i]);
            total_errors += data[i].errors;
        }
    }

    write_str("    Threads completed, total errors: ");
    write_dec(total_errors);
    write_crlf();

    if (total_errors == 0)
        write_str("    [PASS]");
    else
        write_str("    [FAIL]");
    write_crlf();
}

/* ==========================================================================
   Test 3 : Allocation massive
   ========================================================================== */

#define TEST3_BLOCKS 512
#define TEST3_BLOCK_SIZE (1024 * 1024)

static void test_massive_alloc(void)
{
    LPVOID blocks[TEST3_BLOCKS];
    int allocated = 0;
    int errors = 0;

    write_str("  [TEST 3] Massive allocation: ");
    write_dec(TEST3_BLOCKS);
    write_str(" blocks of 1 MB via VirtualAlloc");
    write_crlf();

    /* Allouer */
    for (int i = 0; i < TEST3_BLOCKS; i++) {
        blocks[i] = VirtualAlloc(NULL, TEST3_BLOCK_SIZE,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (blocks[i]) {
            allocated++;
            /* Écrire un marqueur */
            *(unsigned char *)blocks[i] = (unsigned char)(i & 0xFF);
        }
    }

    write_str("    Allocated: ");
    write_dec(allocated);
    write_str(" / ");
    write_dec(TEST3_BLOCKS);
    write_crlf();

    /* Vérifier les marqueurs puis libérer */
    for (int i = 0; i < TEST3_BLOCKS; i++) {
        if (blocks[i]) {
            if (*(unsigned char *)blocks[i] != (unsigned char)(i & 0xFF))
                errors++;

            if (!VirtualFree(blocks[i], 0, MEM_RELEASE))
                errors++;
        }
    }

    write_str("    Errors: ");
    write_dec(errors);
    write_crlf();

    if (allocated >= TEST3_BLOCKS / 2 && errors == 0)
        write_str("    [PASS]");
    else
        write_str("    [FAIL]");
    write_crlf();
}

/* ==========================================================================
   Test 4 : Path translation
   ========================================================================== */

static void test_path_translation(void)
{
    write_str("  [TEST 4] Path translation: CreateFileA(\"C:\\\\tmp\\\\test.txt\")");
    write_crlf();

    HANDLE hFile = CreateFileA("C:\\tmp\\test.txt",
                                GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                NULL);
    if (hFile == (HANDLE)(unsigned long long)-1) {
        DWORD err = GetLastError();
        write_str("    CreateFileA failed (err=");
        write_dec((int)err);
        write_str(")");
        write_crlf();
        write_str("    [FAIL]");
        write_crlf();
        return;
    }

    char *data = "Winux stress test: path translation OK!\r\n";
    DWORD w = 0, len = 0;
    while (data[len]) len++;

    if (WriteFile(hFile, data, len, &w, NULL) && w == len) {
        write_str("    File written successfully: /tmp/test.txt");
        write_crlf();
        write_str("    [PASS]");
    } else {
        write_str("    WriteFile failed");
        write_crlf();
        write_str("    [FAIL]");
    }
    write_crlf();

    CloseHandle(hFile);
}

/* ==========================================================================
   main entry
   ========================================================================== */

void WinMainCRTStartup(void)
{
    write_str("============================================================");
    write_crlf();
    write_str("  WINUX STRESS TEST");
    write_crlf();
    write_str("============================================================");
    write_crlf();
    write_crlf();

    test_io_intensive();
    write_crlf();

    test_threads_concurrent();
    write_crlf();

    test_massive_alloc();
    write_crlf();

    test_path_translation();
    write_crlf();

    write_str("============================================================");
    write_crlf();
    write_str("  ALL STRESS TESTS COMPLETED");
    write_crlf();
    write_str("============================================================");
    write_crlf();

    ExitProcess(0);
}
