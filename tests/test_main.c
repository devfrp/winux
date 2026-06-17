/*
 * === FICHIER : test_main.c ===
 * Description : Programme de test minimal pour vérifier la compilation
 *               et l'interaction des composants PE Loader + I/O Transparency.
 *               Sera remplacé par winexec.c (composant 8) dans la version finale.
 *
 * Usage : ./build/bin/test_main <fichier.exe>
 *         ./build/bin/test_main --io-test  (teste uniquement la couche I/O)
 */

#include "include/winux.h"
#include "include/pe_loader.h"
#include "include/io_transparent.h"

#include <sys/wait.h>

static void test_io_transparency(void)
{
    printf("\n=== I/O Transparency Test ===\n\n");

    if (io_init() != 0) {
        fprintf(stderr, "FAIL: io_init() failed\n");
        return;
    }

    /* Vérifier les handles 0/1/2 */
    WINUX_HANDLE_ENTRY *h;

    h = io_get_handle(0);
    printf("Handle 0 (stdin):  fd=%d type=%d path=%s  %s\n",
           h ? h->linux_fd : -1, h ? (int)h->type : -1,
           h ? h->win_path : "NULL",
           h ? "OK" : "FAIL");

    h = io_get_handle(1);
    printf("Handle 1 (stdout): fd=%d type=%d path=%s  %s\n",
           h ? h->linux_fd : -1, h ? (int)h->type : -1,
           h ? h->win_path : "NULL",
           h ? "OK" : "FAIL");

    h = io_get_handle(2);
    printf("Handle 2 (stderr): fd=%d type=%d path=%s  %s\n",
           h ? h->linux_fd : -1, h ? (int)h->type : -1,
           h ? h->win_path : "NULL",
           h ? "OK" : "FAIL");

    /* Test de traduction de chemins */
    char out[4096];

    const char *tests[] = {
        "C:\\Users\\bob\\Documents\\file.txt",
        "C:\\Windows\\System32\\notepad.exe",
        "D:\\data\\project\\readme.md",
        "C:\\Users\\bob\\AppData\\Local\\Temp\\tmp123.tmp",
        "/home/bob/file.txt",  /* déjà Linux */
        NULL
    };

    printf("\nPath translations:\n");
    for (int i = 0; tests[i]; i++) {
        const char *result = io_translate_path(tests[i], out, sizeof(out));
        printf("  %-45s → %s\n", tests[i], result ? result : "ERROR");
    }

    /* Test CreatePipe */
    HANDLE h_read = INVALID_HANDLE_VALUE;
    HANDLE h_write = INVALID_HANDLE_VALUE;
    if (io_create_pipe(&h_read, &h_write, 4096) == 0) {
        printf("\nPipe created: read=%p write=%p\n",
               (void *)h_read, (void *)h_write);

        /* Écrire dans le pipe et lire */
        const char *msg = "Hello from pipe!";
        int hw_idx = (int)(intptr_t)h_write;
        int hr_idx = (int)(intptr_t)h_read;
        WINUX_HANDLE_ENTRY *hw = io_get_handle(hw_idx);
        WINUX_HANDLE_ENTRY *hr = io_get_handle(hr_idx);

        if (hw && hr) {
            ssize_t written = write(hw->linux_fd, msg, strlen(msg));
            printf("Written %zd bytes to pipe\n", written);

            char buf[128] = {0};
            ssize_t nread = read(hr->linux_fd, buf, sizeof(buf) - 1);
            printf("Read %zd bytes from pipe: '%s'\n", nread, buf);
        }

        io_close_handle(hw_idx);
        io_close_handle(hr_idx);
    }

    /* Dump des handles */
    io_dump_handles();

    io_shutdown();
    printf("\n=== I/O Test Complete ===\n\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable.exe>\n", argv[0]);
        fprintf(stderr, "       %s --io-test\n", argv[0]);
        return 1;
    }

    /* Test I/O uniquement */
    if (strcmp(argv[1], "--io-test") == 0) {
        test_io_transparency();
        return 0;
    }

    /* Test PE Loader */
    printf("\n=== PE Loader Test ===\n");
    printf("Loading: %s\n\n", argv[1]);

    PE_IMAGE *pe = pe_load(argv[1]);
    if (!pe) {
        fprintf(stderr, "FAIL: pe_load() returned NULL\n");
        return 1;
    }

    printf("  Image Base:       0x%016lx\n", pe->mapped_base);
    printf("  Preferred Base:   0x%016lx\n", pe->preferred_base);
    printf("  Delta:            0x%016lx\n", pe->delta);
    printf("  Entry Point:      0x%016lx\n", pe->entry_point);
    printf("  Sections:         %u\n", pe->section_count);
    printf("  Stack Size:       %zu\n", pe->stack_size);

    for (uint16_t i = 0; i < pe->section_count; i++) {
        char name[9] = {0};
        memcpy(name, pe->sections[i].Name, 8);
        printf("  Section [%u] %-8s  VA=0x%08x  VS=0x%08x  RS=0x%08x  flags=0x%08x\n",
               i, name,
               pe->sections[i].VirtualAddress,
               pe->sections[i].Misc.VirtualSize,
               pe->sections[i].SizeOfRawData,
               pe->sections[i].Characteristics);
    }

    printf("\n  PE loaded successfully!\n");

    /*
     * Si le point d'entrée est valide, on pourrait tenter de l'appeler :
     *
     *   typedef int (*entry_fn)(void);
     *   entry_fn entry = (entry_fn)pe_entry_point(pe);
     *   int ret = entry();
     *   printf("  Entry returned: %d\n", ret);
     *
     * Mais sans les stubs NT/Win32, cela segfaultera probablement.
     * On se contente de décharger le PE proprement.
     */

    pe_unload(pe);
    printf("  PE unloaded cleanly.\n\n");

    return 0;
}
