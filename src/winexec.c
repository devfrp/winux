/*
 * === FICHIER : winexec.c ===
 * Description : Launcher principal de Winux.
 *               Initialise tous les composants, charge le PE,
 *               et saute au point d'entrée du programme Windows.
 *
 * Usage :
 *   ./winexec <file.exe> [args...]
 *   ./winexec --debug <file.exe> [args...]
 *   ./winexec --no-seccomp <file.exe> [args...]
 *   ./winexec --paths <mapping_file> <file.exe> [args...]
 *
 * Ordre d'init :
 *   0. proc_compat_init()        — nettoyage fd, transparence /proc
 *   1. io_init()                — couche I/O transparente
 *   2. mem_init()               — gestionnaire de mémoire
 *   3. win32_bridge_init()      — pont Win32 (import resolver)
 *   4. pe_load()                — chargement du PE (+ labels VMA)
 *   5. signal_passthrough_init()— handlers de signaux
 *   6. thread_model_init()      — TEB/PEB synthétiques
 *   7. seccomp_filter_install() — filtre BPF
 *   8. proc_set_cmdline()       — /proc/self/cmdline
 *   9. Saut vers l'entry point PE
 *
 * Dépendances : tous les composants Winux.
 */

#include "include/winux.h"
#include "include/pe_loader.h"
#include "include/io_transparent.h"
#include "include/nt_stubs.h"
#include "include/win32_bridge.h"
#include "include/memory_manager.h"
#include "include/thread_model.h"
#include "include/signal_passthrough.h"
#include "include/seccomp_filter.h"
#include "include/proc_compat.h"

#include <sys/prctl.h>
#include <string.h>
#include <signal.h>

/* ==========================================================================
   Helpers — gestion du nom de processus
   ========================================================================== */

static void set_process_name(const char *exe_path)
{
    const char *basename = strrchr(exe_path, '/');
    if (basename)
        basename++;
    else
        basename = exe_path;

    /*
     * prctl(PR_SET_NAME) pour le nom court (15 octets max + \0).
     * Visible dans /proc/pid/comm, ps, htop.
     */
    char short_name[16];
    /* Sans extension .exe pour la propreté */
    const char *dot = strrchr(basename, '.');
    size_t name_len = dot ? (size_t)(dot - basename) : strlen(basename);
    if (name_len > 14) name_len = 14;

    memcpy(short_name, basename, name_len);
    short_name[name_len] = '\0';
    prctl(PR_SET_NAME, short_name, 0, 0, 0);
}

/* ==========================================================================
   main
   ========================================================================== */

int main(int argc, char **argv)
{
    const char *exe_path = NULL;
    const char *paths_file = NULL;
    bool debug_mode = false;
    bool no_seccomp = false;
    int entry_ret = 0;

    /* =============================================================
       Parsing des arguments
       ============================================================= */

    int arg_idx = 1;
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "--debug") == 0) {
            debug_mode = true;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "--no-seccomp") == 0) {
            no_seccomp = true;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "--paths") == 0 && arg_idx + 1 < argc) {
            paths_file = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (argv[arg_idx][0] == '-') {
            fprintf(stderr, "Usage: %s [--debug] [--no-seccomp] [--paths <file>] "
                    "<file.exe> [args...]\n", argv[0]);
            return 1;
        } else {
            exe_path = argv[arg_idx];
            arg_idx++;
            break;
        }
    }

    if (!exe_path) {
        fprintf(stderr, "Usage: %s [--debug] [--no-seccomp] [--paths <file>] "
                "<file.exe> [args...]\n", argv[0]);
        return 1;
    }

    /*
     * Sauvegarder les arguments PE restants pour /proc/self/cmdline.
     * pe_argc = nombre d'arguments après le .exe
     * pe_argv = pointeurs dans argv[] à partir de arg_idx
     */
    int   pe_argc = argc - arg_idx;
    char **pe_argv = &argv[arg_idx];

    /* =============================================================
       Étape 0 : Transparence /proc (nettoyage fd)
       ============================================================= */

    proc_compat_init();

    /* =============================================================
       Étape 1 : Couche I/O transparente
       ============================================================= */

    if (paths_file) {
        setenv("WINUX_PATHS_FILE", paths_file, 1);
        WINUX_LOG("Using custom path mapping: %s", paths_file);
    }

    if (io_init() != 0) {
        fprintf(stderr, "[winexec] FATAL: io_init() failed\n");
        return 1;
    }

    /* =============================================================
       Étape 2 : Gestionnaire de mémoire
       ============================================================= */

    if (mem_init() != 0) {
        fprintf(stderr, "[winexec] FATAL: mem_init() failed\n");
        return 1;
    }

    /* =============================================================
       Étape 3 : Pont Win32 (import resolver)
       ============================================================= */

    win32_bridge_init();

    /* =============================================================
       Étape 4 : Chargement du PE
       ============================================================= */

    PE_IMAGE *pe = pe_load(exe_path);
    if (!pe) {
        fprintf(stderr, "[winexec] FATAL: Cannot load PE '%s'\n", exe_path);
        return 1;
    }

    /* Stocker le chemin pour GetModuleFileNameA */
    strncpy(g_loaded_exe_path, exe_path, sizeof(g_loaded_exe_path) - 1);
    g_loaded_exe_path[sizeof(g_loaded_exe_path) - 1] = '\0';

    if (debug_mode) {
        printf("\n[winexec] PE loaded: %s\n", exe_path);
        printf("  Mapped Base:  0x%016lx\n", pe->mapped_base);
        printf("  Entry Point:  0x%016lx\n", pe->entry_point);
        printf("  Sections:     %u\n", pe->section_count);
        printf("  Image Size:   0x%08x\n", pe->nt->OptionalHeader.SizeOfImage);
        printf("\n");
    }

    /* =============================================================
       Étape 5 : Handlers de signaux
       ============================================================= */

    if (signal_passthrough_init(pe->mapped_base,
                                 pe->nt->OptionalHeader.SizeOfImage) != 0) {
        fprintf(stderr, "[winexec] WARNING: signal_passthrough_init() failed\n");
    }

    /* =============================================================
       Étape 6 : Modèle de threads (TEB/PEB synthétiques)
       ============================================================= */

    uint64_t stack_base = (uint64_t)(uintptr_t)pe->stack_base + pe->stack_size;
    uint64_t stack_limit = (uint64_t)(uintptr_t)pe->stack_base;

    if (thread_model_init(pe->mapped_base,
                           pe->nt->OptionalHeader.SizeOfImage,
                           stack_base,
                           stack_limit) != 0) {
        fprintf(stderr, "[winexec] FATAL: thread_model_init() failed\n");
        pe_unload(pe);
        return 1;
    }

    /* =============================================================
       Étape 7 : Seccomp BPF filter (sauf si --no-seccomp)
       ============================================================= */

    if (!no_seccomp) {
        if (seccomp_filter_install(true) != 0) {
            fprintf(stderr, "[winexec] WARNING: seccomp_filter_install() failed\n"
                    "  Use --no-seccomp to run without syscall filtering.\n");
        }
    } else {
        WINUX_LOG("Seccomp disabled via --no-seccomp flag");
    }

    /* =============================================================
       Étape 8 : Transparence /proc (cmdline)
       ============================================================= */

    set_process_name(exe_path);
    proc_set_cmdline(argv, exe_path, pe_argc, pe_argv);

    /* =============================================================
       Étape 9 : Saut vers l'entry point PE
       ============================================================= */

    void *entry = pe_entry_point(pe);
    if (!entry) {
        fprintf(stderr, "[winexec] FATAL: No entry point in PE\n");
        thread_model_shutdown();
        signal_passthrough_shutdown();
        pe_unload(pe);
        return 1;
    }

    WINUX_LOG("Jumping to PE entry point: %p (VA 0x%lx)",
              entry, pe->entry_point);

    if (debug_mode) {
        printf("[winexec] Executing PE entry point at %p...\n\n", entry);
    }

    typedef int (WINAPI *pe_entry_fn)(void);
    pe_entry_fn entry_fn = (pe_entry_fn)entry;

    if (winux_terminate_requested) {
        fprintf(stderr, "\n[winexec] Terminate requested before entry, "
                "calling ExitProcess(0)\n");
        kernel32_ExitProcess(0);
    }

    entry_ret = entry_fn();

    WINUX_LOG("PE entry point returned %d (0x%x)", entry_ret, entry_ret);

    /* =============================================================
       Nettoyage
       ============================================================= */

    thread_model_shutdown();
    signal_passthrough_shutdown();
    pe_unload(pe);
    io_shutdown();
    mem_shutdown();

    if (debug_mode) {
        printf("\n[winexec] PE exit code: %d\n", entry_ret);
    }

    return entry_ret;
}
