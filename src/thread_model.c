/*
 * === FICHIER : thread_model.c ===
 * Description : Implémentation du modèle de threads Winux.
 *               Crée les TEB/PEB synthétiques, configure le segment
 *               GS pour l'accès TEB par le code PE.
 *
 * Dépendances Linux : arch_prctl(2), mmap(2), pthread_key_create(3),
 *                      pthread_setspecific(3)
 *
 * Architecture :
 *   - PEB alloué via mem_virtual_alloc() (PAGE_READWRITE, MEM_COMMIT)
 *   - TEB alloué via mem_virtual_alloc() (PAGE_READWRITE, MEM_COMMIT)
 *   - Chaque TEB a son propre mapping pour l'isolation entre threads
 *   - GS segment → TEB via do_arch_prctl(ARCH_SET_GS)
 *   - Le stack canary Linux est copié depuis fs:[0x28] dans le TEB
 *     pour que le code PE MinGW qui ferait mov rax, fs:[0x28] fonctionne
 *   - pthread_key pour stocker/récupérer le pointeur TEB par thread
 */

#include "include/winux.h"
#include "include/thread_model.h"
#include "include/memory_manager.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/*
 * Polymorphisme arch_prctl selon la glibc.
 * Sur certaines distributions, arch_prctl est dans <asm/prctl.h>,
 * sur d'autres <sys/prctl.h>. On utilise syscall(SYS_arch_prctl, ...)
 * pour la portabilité.
 */
#ifndef SYS_arch_prctl
#define SYS_arch_prctl 158  /* x86_64 */
#endif

static inline int do_arch_prctl(int code, unsigned long addr)
{
    return (int)syscall(SYS_arch_prctl, code, addr);
}

/* ==========================================================================
   État global
   ========================================================================== */

static WINUX_PEB  *g_peb = NULL;        /* PEB unique du processus */
static bool        g_initialized = false;
static pthread_key_t g_teb_key;         /* clé TLS pour TEB par thread */
static bool        g_teb_active = false; /* TEB initialisé pour le thread courant ? */

/*
 * Fallback : __thread pour l'init (avant que le TEB ne soit prêt).
 * Défini dans globals.c, on l'utilise ici comme référence.
 */
extern __thread DWORD _last_error;

/* ==========================================================================
   Helpers
   ========================================================================== */

/*
 * Lit le stack canary Linux depuis fs:[0x28].
 * Cette valeur doit être préservée dans le TEB au même offset
 * pour que le code compilé avec -fstack-protector continue
 * de fonctionner même après qu'on ait changé FS/GS.
 */
static uint64_t read_stack_canary(void)
{
    uint64_t canary;
    __asm__ __volatile__("movq %%fs:0x28, %0" : "=r"(canary));
    return canary;
}

/* ==========================================================================
   PEB
   ========================================================================== */

/*
 * Alloue et initialise le PEB.
 * Appelé une seule fois au début du processus.
 * Utilise mem_virtual_alloc() — PAS malloc() — pour que le PEB
 * soit dans une région trackée par le memory manager.
 */
static WINUX_PEB *peb_create(uint64_t image_base, uint64_t image_size,
                              HANDLE process_heap)
{
    SIZE_T peb_size = WINUX_ALIGN_UP(sizeof(WINUX_PEB), 0x1000);
    PVOID  peb_addr = NULL;

    NTSTATUS st = mem_virtual_alloc(&peb_addr, &peb_size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (st != STATUS_SUCCESS) {
        WINUX_ERR("Failed to allocate PEB (mem_virtual_alloc returned 0x%x)", st);
        return NULL;
    }

    WINUX_PEB *peb = (WINUX_PEB *)peb_addr;
    memset(peb, 0, peb_size);

    peb->InheritedAddressSpace    = 0;
    peb->BeingDebugged            = 0;
    peb->ImageBaseAddress         = image_base;
    peb->ProcessHeap              = (uint64_t)(uintptr_t)process_heap;
    peb->NumberOfProcessors       = (uint64_t)sysconf(_SC_NPROCESSORS_ONLN);
    peb->NtGlobalFlag             = 0;

    WINUX_LOG("PEB created at %p (ImageBase=0x%lx, Heap=%p)",
              (void *)peb, image_base, (void *)(uintptr_t)process_heap);

    return peb;
}

/* ==========================================================================
   TEB
   ========================================================================== */

/*
 * Alloue et initialise un TEB.
 * Le TEB est alloué via mem_virtual_alloc(), dans une page dédiée
 * pour garantir l'alignement et l'isolation.
 */
WINUX_TEB *teb_create_for_thread(uint64_t stack_base, uint64_t stack_limit)
{
    SIZE_T teb_size = WINUX_ALIGN_UP(sizeof(WINUX_TEB), 0x1000);
    PVOID  teb_addr = NULL;

    NTSTATUS st = mem_virtual_alloc(&teb_addr, &teb_size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (st != STATUS_SUCCESS) {
        WINUX_ERR("Failed to allocate TEB (mem_virtual_alloc returned 0x%x)", st);
        return NULL;
    }

    WINUX_TEB *teb = (WINUX_TEB *)teb_addr;
    memset(teb, 0, sizeof(*teb));

    /* NT_TIB */
    teb->Tib.ExceptionList        = (uint64_t)-1;  /* 0xFFFFFFFFFFFFFFFF = fin de chaîne */
    teb->Tib.StackBase            = stack_base;
    teb->Tib.StackLimit           = stack_limit;
    teb->Tib.Self                 = (uint64_t)(uintptr_t)teb;
    teb->Tib.ArbitraryUserPointer = read_stack_canary();  /* copie du canary Linux */

    /* TEB fields */
    teb->Peb             = (uint64_t)(uintptr_t)g_peb;
    teb->LastErrorValue  = ERROR_SUCCESS;
    teb->linux_tid       = pthread_self();
    teb->teb_id          = 0;

    return teb;
}

/*
 * Active le TEB pour le thread courant :
 * configure ARCH_SET_GS sur l'adresse du TEB.
 *
 * Sur x86_64, le code PE Windows utilise GS pour accéder au TEB.
 * On configure le GS base register pour pointer sur notre TEB synthétique.
 *
 * IMPORTANT : on ne touche PAS au FS (utilisé par Linux pour TLS/errno).
 */
int teb_activate(WINUX_TEB *teb)
{
    if (!teb) return -1;

    /*
     * do_arch_prctl(ARCH_SET_GS, addr) configure le segment GS
     * pour pointer sur le TEB. Le code PE qui fait gs:[0x30]
     * (Self) ou gs:[0x60] (PEB) lira les bonnes valeurs.
     */
    if (do_arch_prctl(ARCH_SET_GS, (unsigned long)(uintptr_t)teb) != 0) {
        WINUX_ERR("do_arch_prctl(ARCH_SET_GS) failed");
        return -1;
    }

    /* Stocker le pointeur TEB dans la TLS pthread */
    pthread_setspecific(g_teb_key, teb);

    WINUX_LOG("TEB activated: %p, GS=teb, Self=0x%lx, PEB=0x%lx",
              (void *)teb, teb->Tib.Self, teb->Peb);
    return 0;
}

/*
 * Détruit le TEB et libère la mémoire.
 * Restaure GS à 0 pour éviter de pointer sur de la mémoire libérée.
 */
void teb_destroy_for_thread(WINUX_TEB *teb)
{
    if (!teb) return;

    /* Remettre GS à 0 (sécurité) */
    do_arch_prctl(ARCH_SET_GS, 0UL);

    /* Libérer la page TEB */
    PVOID  base = (PVOID)teb;
    SIZE_T size = WINUX_ALIGN_UP(sizeof(WINUX_TEB), 0x1000);
    mem_virtual_free(&base, &size, MEM_RELEASE);

    WINUX_LOG("TEB destroyed: %p", (void *)teb);
}

/* ==========================================================================
   GetLastError / SetLastError via TEB
   ========================================================================== */

DWORD winux_teb_get_last_error(void)
{
    if (!g_teb_active) {
        /* Fallback : le TEB n'est pas encore initialisé */
        return _last_error;
    }

    WINUX_TEB *teb;
    __asm__ __volatile__("movq %%gs:0x30, %0" : "=r"(teb));
    if (!teb) return ERROR_SUCCESS;

    return teb->LastErrorValue;
}

void winux_teb_set_last_error(DWORD err)
{
    if (!g_teb_active) {
        /* Fallback : le TEB n'est pas encore initialisé */
        _last_error = err;
        return;
    }

    WINUX_TEB *teb;
    __asm__ __volatile__("movq %%gs:0x30, %0" : "=r"(teb));
    if (!teb) return;

    teb->LastErrorValue = err;
}

/* ==========================================================================
   Init / Shutdown
   ========================================================================== */

int thread_model_init(uint64_t pe_base, uint64_t pe_size,
                       uint64_t stack_base, uint64_t stack_limit)
{
    if (g_initialized) return 0;

    /*
     * 1. Créer la clé pthread pour le lookup TEB par thread.
     */
    if (pthread_key_create(&g_teb_key, NULL) != 0) {
        WINUX_ERR("pthread_key_create failed");
        return -1;
    }

    /*
     * 2. Allouer le PEB (unique pour le processus).
     *    Utilise mem_virtual_alloc() pour que le PEB soit dans
     *    une région trackée, pas malloc().
     */
    HANDLE proc_heap = mem_get_process_heap();
    g_peb = peb_create(pe_base, pe_size, proc_heap);
    if (!g_peb) {
        pthread_key_delete(g_teb_key);
        return -1;
    }

    /*
     * 3. Créer le TEB pour le thread principal.
     */
    WINUX_TEB *main_teb = teb_create_for_thread(stack_base, stack_limit);
    if (!main_teb) {
        pthread_key_delete(g_teb_key);
        PVOID base = (PVOID)g_peb;
        SIZE_T sz  = WINUX_ALIGN_UP(sizeof(WINUX_PEB), 0x1000);
        mem_virtual_free(&base, &sz, MEM_RELEASE);
        g_peb = NULL;
        return -1;
    }

    /*
     * 4. Activer le TEB (configure GS, stocke dans TLS pthread).
     */
    if (teb_activate(main_teb) != 0) {
        teb_destroy_for_thread(main_teb);
        pthread_key_delete(g_teb_key);
        PVOID base = (PVOID)g_peb;
        SIZE_T sz  = WINUX_ALIGN_UP(sizeof(WINUX_PEB), 0x1000);
        mem_virtual_free(&base, &sz, MEM_RELEASE);
        g_peb = NULL;
        return -1;
    }

    g_teb_active = true;
    g_initialized = true;

    WINUX_LOG("Thread model initialized: PEB=%p, main TEB=%p, "
              "PE base=0x%lx size=0x%lx",
              (void *)g_peb, (void *)main_teb, pe_base, pe_size);

    return 0;
}

void thread_model_shutdown(void)
{
    if (!g_initialized) return;

    g_teb_active = false;

    /*
     * Détruire le TEB du thread principal.
     * On récupère le TEB via GS avant de le nettoyer.
     */
    WINUX_TEB *teb;
    __asm__ __volatile__("movq %%gs:0x30, %0" : "=r"(teb));
    if (teb) {
        teb_destroy_for_thread(teb);
    }

    /*
     * Libérer le PEB.
     */
    if (g_peb) {
        PVOID  base = (PVOID)g_peb;
        SIZE_T size = WINUX_ALIGN_UP(sizeof(WINUX_PEB), 0x1000);
        mem_virtual_free(&base, &size, MEM_RELEASE);
        g_peb = NULL;
    }

    pthread_key_delete(g_teb_key);
    g_initialized = false;

    WINUX_LOG("Thread model shut down");
}
