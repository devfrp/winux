/*
 * === FICHIER : signal_passthrough.c ===
 * Description : Gestionnaire de signaux pour l'exécution de code PE.
 *               Intercepte SIGSEGV (crash PE) et SIGTERM (arrêt propre).
 *
 * Dépendances Linux : sigaction(2), ucontext.h, signal.h
 *
 * Architecture :
 *   - SIGTERM : positionne un flag atomique winux_terminate_requested.
 *     Pas de longjmp() — la boucle principale vérifie le flag et
 *     appelle ExitProcess(0) dans le contexte du thread PE.
 *   - SIGSEGV dans [pe_base, pe_base+pe_size) : dump le crash
 *     (offset PE, VA, registres GPR) puis exit(128+SIGSEGV).
 *   - SIGSEGV hors plage PE : laisse le handler par défaut
 *     (bug dans winexec lui-même, pas dans le PE).
 *   - SIGCHLD : ignoré (pas de fork, threads via pthread).
 */

#include "include/winux.h"
#include "include/signal_passthrough.h"
#include "include/thread_model.h"

#include <ucontext.h>
#include <stdlib.h>
#include <unistd.h>
#include <setjmp.h>

/* ==========================================================================
   État global
   ========================================================================== */

static uint64_t   g_pe_base  = 0;
static uint64_t   g_pe_size  = 0;
static bool       g_initialized = false;

/* Flag atomique pour SIGTERM → terminaison propre */
atomic_bool winux_terminate_requested = false;

/* Anciens handlers (restaurés au shutdown) */
static struct sigaction g_old_segv;
static struct sigaction g_old_term;
static struct sigaction g_old_chld;
static bool g_saved_segv = false;
static bool g_saved_term = false;
static bool g_saved_chld = false;

/* ==========================================================================
   Handlers
   ========================================================================== */

/*
 * SIGTERM handler : positionne le flag atomique.
 * La boucle principale du launcher vérifie ce flag périodiquement
 * et appelle ExitProcess(0) dans le contexte du thread PE.
 */
static void sigterm_handler(int sig)
{
    (void)sig;
    winux_terminate_requested = true;

    const char msg[] = "\n[winexec] SIGTERM received, terminating...\n";
    if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0) {}

    /*
     * Terminaison immédiate avec exit code 0.
     * _exit() est async-signal-safe. On ne peut pas appeler
     * ExitProcess() ici car il n'est pas async-signal-safe
     * (utilise io_shutdown, fprintf, etc.).
     */
    _exit(0);
}

/*
 * SIGSEGV handler : intercepte les crashes dans le code PE.
 *
 * Si l'adresse fautive est dans la plage PE :
 *   1. Tente de dérouler le SEH (walk TEB->ExceptionList)
 *      - Boucle sur la chaîne EXCEPTION_REGISTRATION_RECORD
 *      - Appelle chaque handler (sa)
 *      - Si EXCEPTION_EXECUTE_HANDLER : unwinding (restore RSP/RIP)
 *      - Si EXCEPTION_CONTINUE_SEARCH : continue
 *   2. Si aucun handler n'a pris l'exception → crash dump + exit
 *
 * Si l'adresse est hors plage PE :
 *   - Restaure le handler par défaut et relance le signal.
 */
static void sigsegv_handler(int sig, siginfo_t *info, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
    uintptr_t fault_addr = (uintptr_t)info->si_addr;

    if (fault_addr >= g_pe_base && fault_addr < g_pe_base + g_pe_size) {
        EXCEPTION_RECORD except_rec;
        CONTEXT64 seh_context;
        memset(&except_rec, 0, sizeof(except_rec));
        memset(&seh_context, 0, sizeof(seh_context));

        except_rec.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        except_rec.ExceptionAddress = (PVOID)fault_addr;
        except_rec.NumberParameters = 2;
        except_rec.ExceptionInformation[0] = (info->si_code == SEGV_MAPERR) ? 0 : 1;
        except_rec.ExceptionInformation[1] = (ULONG_PTR)fault_addr;

#ifdef __x86_64__
        seh_context.Rax = uc->uc_mcontext.gregs[REG_RAX];
        seh_context.Rcx = uc->uc_mcontext.gregs[REG_RCX];
        seh_context.Rdx = uc->uc_mcontext.gregs[REG_RDX];
        seh_context.Rbx = uc->uc_mcontext.gregs[REG_RBX];
        seh_context.Rsp = uc->uc_mcontext.gregs[REG_RSP];
        seh_context.Rbp = uc->uc_mcontext.gregs[REG_RBP];
        seh_context.Rsi = uc->uc_mcontext.gregs[REG_RSI];
        seh_context.Rdi = uc->uc_mcontext.gregs[REG_RDI];
        seh_context.R8  = uc->uc_mcontext.gregs[REG_R8];
        seh_context.R9  = uc->uc_mcontext.gregs[REG_R9];
        seh_context.R10 = uc->uc_mcontext.gregs[REG_R10];
        seh_context.R11 = uc->uc_mcontext.gregs[REG_R11];
        seh_context.R12 = uc->uc_mcontext.gregs[REG_R12];
        seh_context.R13 = uc->uc_mcontext.gregs[REG_R13];
        seh_context.R14 = uc->uc_mcontext.gregs[REG_R14];
        seh_context.R15 = uc->uc_mcontext.gregs[REG_R15];
        seh_context.Rip = uc->uc_mcontext.gregs[REG_RIP];
#endif

        WINUX_TEB *teb = teb_get_current();
        EXCEPTION_REGISTRATION_RECORD *rec = NULL;
        bool handled = false;

        if (teb && teb->Tib.ExceptionList != (uint64_t)-1) {
            rec = (EXCEPTION_REGISTRATION_RECORD *)(uintptr_t)teb->Tib.ExceptionList;
        }

        if (rec) {
            while (rec && rec->Handler && rec != (void *)-1) {
                EXCEPTION_REGISTRATION_RECORD *next =
                    (EXCEPTION_REGISTRATION_RECORD *)rec->Next;

                PVECTORED_EXCEPTION_HANDLER handler_fn =
                    (PVECTORED_EXCEPTION_HANDLER)rec->Handler;

                LONG disposition = handler_fn(&except_rec);

                if (disposition == EXCEPTION_EXECUTE_HANDLER) {
#ifdef __x86_64__
                    uc->uc_mcontext.gregs[REG_RAX] = seh_context.Rax;
                    uc->uc_mcontext.gregs[REG_RCX] = seh_context.Rcx;
                    uc->uc_mcontext.gregs[REG_RDX] = seh_context.Rdx;
                    uc->uc_mcontext.gregs[REG_RBX] = seh_context.Rbx;
                    uc->uc_mcontext.gregs[REG_RSP] = seh_context.Rsp;
                    uc->uc_mcontext.gregs[REG_RBP] = seh_context.Rbp;
                    uc->uc_mcontext.gregs[REG_RSI] = seh_context.Rsi;
                    uc->uc_mcontext.gregs[REG_RDI] = seh_context.Rdi;
                    uc->uc_mcontext.gregs[REG_R8]  = seh_context.R8;
                    uc->uc_mcontext.gregs[REG_R9]  = seh_context.R9;
                    uc->uc_mcontext.gregs[REG_R10] = seh_context.R10;
                    uc->uc_mcontext.gregs[REG_R11] = seh_context.R11;
                    uc->uc_mcontext.gregs[REG_R12] = seh_context.R12;
                    uc->uc_mcontext.gregs[REG_R13] = seh_context.R13;
                    uc->uc_mcontext.gregs[REG_R14] = seh_context.R14;
                    uc->uc_mcontext.gregs[REG_R15] = seh_context.R15;
                    uc->uc_mcontext.gregs[REG_RIP] = seh_context.Rip;
#endif
                    handled = true;
                    break;
                }

                if (disposition == EXCEPTION_CONTINUE_EXECUTION) {
                    return;
                }

                rec = next;
                if (rec == (void *)-1) break;
            }
        }

        if (handled) return;

        /* Crash dump (handler non trouvé) */
        char buf[1024];
        int len;

        len = snprintf(buf, sizeof(buf),
                 "\n"
                 "╔══════════════════════════════════════════════════╗\n"
                 "║          [winexec] PE CRASH DETECTED            ║\n"
                 "╠══════════════════════════════════════════════════╣\n"
                 "║  Fault VA:      0x%016llx                       ║\n"
                 "║  PE Base:       0x%016llx                       ║\n"
                 "║  PE Offset:     0x%08lx                         ║\n"
                 "║  ExceptionList: %s                           ║\n"
                 "╠══════════════════════════════════════════════════╣\n",
                 (unsigned long long)fault_addr,
                 (unsigned long long)g_pe_base,
                 fault_addr - g_pe_base,
                 rec ? "SEH walked" : "empty");
        if (len > 0 && len < (int)sizeof(buf))
            if (write(STDERR_FILENO, buf, (size_t)len) < 0) {}

#ifdef __x86_64__
        len = snprintf(buf, sizeof(buf),
                 "║  Registers:                                       ║\n"
                 "║    RAX=0x%016llx  RBX=0x%016llx                 ║\n"
                 "║    RCX=0x%016llx  RDX=0x%016llx                 ║\n"
                 "║    RSI=0x%016llx  RDI=0x%016llx                 ║\n"
                 "║    R8 =0x%016llx  R9 =0x%016llx                 ║\n"
                 "║    R10=0x%016llx  R11=0x%016llx                 ║\n"
                 "║    R12=0x%016llx  R13=0x%016llx                 ║\n"
                 "║    R14=0x%016llx  R15=0x%016llx                 ║\n"
                 "║    RSP=0x%016llx  RBP=0x%016llx                 ║\n"
                 "║    RIP=0x%016llx                                ║\n",
                 (unsigned long long)uc->uc_mcontext.gregs[REG_RAX],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_RBX],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_RCX],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_RDX],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_RSI],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_RDI],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_R8],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_R9],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_R10],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_R11],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_R12],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_R13],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_R14],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_R15],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_RSP],
                 (unsigned long long)uc->uc_mcontext.gregs[REG_RBP],
                  (unsigned long long)uc->uc_mcontext.gregs[REG_RIP]);
        if (len > 0 && len < (int)sizeof(buf))
            if (write(STDERR_FILENO, buf, (size_t)len) < 0) {}
#endif

        len = snprintf(buf, sizeof(buf),
                 "╚══════════════════════════════════════════════════╝\n"
                 "\n");
        if (len > 0 && len < (int)sizeof(buf))
            if (write(STDERR_FILENO, buf, (size_t)len) < 0) {}

        _exit(128 + SIGSEGV);
    }

    /*
     * Crash hors plage PE → bug interne winexec.
     * Restaurer le handler par défaut et relancer le signal.
     */
    if (g_saved_segv) {
        sigaction(SIGSEGV, &g_old_segv, NULL);
    } else {
        signal(SIGSEGV, SIG_DFL);
    }

    /*
     * Si le signal a été envoyé par kill() (si_code <= 0),
     * le re-lever. Sinon (si_code > 0, faute matérielle),
     * on ne peut pas facilement le reproduire. On exit().
     */
    if (info->si_code <= 0) {
        raise(SIGSEGV);
    } else {
        const char msg[] = "\n[winexec] Internal SIGSEGV outside PE range\n";
        if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0) {}
        _exit(128 + SIGSEGV);
    }
}

/* ==========================================================================
   Init / Shutdown
   ========================================================================== */

int signal_passthrough_init(uint64_t pe_base, uint64_t pe_size)
{
    struct sigaction sa;

    if (g_initialized) return 0;

    g_pe_base = pe_base;
    g_pe_size = pe_size;

    /*
     * 1. SIGSEGV — intercepte les crashes PE.
     */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &g_old_segv) != 0) {
        WINUX_ERR("sigaction(SIGSEGV) failed");
        return -1;
    }
    g_saved_segv = true;

    /*
     * 2. SIGTERM — arrêt propre.
     */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigterm_handler;
    sa.sa_flags   = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTERM, &sa, &g_old_term) != 0) {
        WINUX_ERR("sigaction(SIGTERM) failed");
        /* Non fatal */
    } else {
        g_saved_term = true;
    }

    /*
     * 3. SIGCHLD — ignoré (pas de fork).
     */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags   = SA_NOCLDWAIT;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGCHLD, &sa, &g_old_chld) != 0) {
        WINUX_ERR("sigaction(SIGCHLD) failed");
    } else {
        g_saved_chld = true;
    }

    g_initialized = true;

    WINUX_LOG("Signal handlers installed: PE range [0x%lx - 0x%lx]",
              pe_base, pe_base + pe_size);

    return 0;
}

void signal_passthrough_shutdown(void)
{
    if (!g_initialized) return;

    /* Restaurer les handlers originaux */
    if (g_saved_segv) sigaction(SIGSEGV, &g_old_segv, NULL);
    if (g_saved_term) sigaction(SIGTERM, &g_old_term, NULL);
    if (g_saved_chld) sigaction(SIGCHLD, &g_old_chld, NULL);

    g_initialized = false;
    g_saved_segv  = false;
    g_saved_term  = false;
    g_saved_chld  = false;

    WINUX_LOG("Signal handlers restored to defaults");
}
