/*
 * === FICHIER : include/thread_model.h ===
 * Description : API publique du modèle de threads Winux.
 *               Gère le TEB (Thread Environment Block) et le PEB
 *               (Process Environment Block) synthétiques.
 *
 * Architecture :
 *   - PEB unique par processus, alloué via mem_virtual_alloc()
 *   - TEB par thread, avec GS segment register pointant dessus
 *     pour que le code PE accède à gs:[0x30] (Self), gs:[0x60] (PEB)
 *   - Le stack canary Linux (fs:[0x28]) est préservé dans le TEB
 *     au cas où un PE MinGW accèderait à fs:[0x28]
 *   - GetLastError/SetLastError lisent/écrivent teb->LastErrorValue
 *     (remplace le __thread _last_error placeholder)
 *
 * Dépendances : include/winux.h, include/memory_manager.h,
 *               <pthread.h>, <asm/prctl.h>, <sys/prctl.h>
 */

#ifndef THREAD_MODEL_H
#define THREAD_MODEL_H

#include "winux.h"
#include <pthread.h>
#include <sys/prctl.h>

/* ==========================================================================
    Constantes pour arch_prctl (x86_64)
    ========================================================================== */
#ifndef ARCH_SET_GS
#define ARCH_SET_GS 0x1001
#endif
#ifndef ARCH_SET_FS
#define ARCH_SET_FS 0x1002
#endif

/* ==========================================================================
    TEB — Thread Environment Block (synthétique)
    ========================================================================== */

/*
 * Layout simplifié du TEB pour x86_64.
 * Les offsets respectent la disposition Windows réelle
 * pour la compatibilité binaire avec le code PE.
 *
 * Structure alignée sur 8 octets.
 */
#pragma pack(push, 8)

typedef struct _WINUX_NT_TIB {
    uint64_t ExceptionList;         /* +0x00 : pointeur vers EXCEPTION_REGISTRATION */
    uint64_t StackBase;             /* +0x08 : haut de la pile */
    uint64_t StackLimit;            /* +0x10 : bas de la pile */
    uint64_t SubSystemTib;          /* +0x18 : réservé */
    uint64_t FiberData;             /* +0x20 : données fibre / version */
    uint64_t ArbitraryUserPointer;  /* +0x28 : pointeur arbitraire (stack canary) */
    uint64_t Self;                  /* +0x30 : pointeur vers le TEB lui-même */
} WINUX_NT_TIB;

/*
 * TEB complet (version Winux).
 *
 * Après le NT_TIB (0x38 octets) :
 *   +0x38 : EnvironmentPointer
 *   +0x40 : ClientId.UniqueProcess
 *   +0x48 : ClientId.UniqueThread
 *   +0x50 : ActiveRpcHandle
 *   +0x58 : ThreadLocalStoragePointer
 *   +0x60 : ProcessEnvironmentBlock (pointeur vers PEB)
 *   +0x68 : LastErrorValue        (DWORD, 4 octets)
 *
 * On garde aussi une copie locale de certaines valeurs
 * pour le debug.
 */
#define WINUX_TEB_SIZE  4096   /* 4K, aligné page */

typedef struct _WINUX_TEB {
    /* NT_TIB (0x00 → 0x37) */
    WINUX_NT_TIB Tib;

    /* Padding après NT_TIB pour atteindre les bons offsets */
    uint64_t     Reserved0;              /* +0x38 : EnvironmentPointer */
    uint8_t      Reserved1[16];          /* +0x40 : ClientId (16 bytes) */
    uint64_t     Reserved2;              /* +0x50 : ActiveRpcHandle    */
    uint64_t     Reserved3;              /* +0x58 : TLS pointer        */
    uint64_t     Peb;                    /* +0x60 : ProcessEnvironmentBlock */
    DWORD        LastErrorValue;         /* +0x68 : LastErrorValue (4 bytes) */
    DWORD        Reserved4;              /* +0x6C : padding            */

    /*
     * Champs Winux internes (au-delà des offsets Windows standard)
     */
    pthread_t    linux_tid;              /* tid pthread sous-jacent */
    int          teb_id;                 /* identifiant local du TEB */
} WINUX_TEB;

/*
 * PEB — Process Environment Block (synthétique)
 */
#define WINUX_PEB_SIZE  4096

typedef struct _WINUX_PEB {
    uint8_t      InheritedAddressSpace;   /* +0x00 */
    uint8_t      ReadImageFileExecOptions;/* +0x01 */
    uint8_t      BeingDebugged;           /* +0x02 */
    uint8_t      BitField;                /* +0x03 */
    uint8_t      __pad1[4];               /* align to 8 bytes */
    uint64_t     Mutant;                  /* +0x08 */
    uint64_t     ImageBaseAddress;        /* +0x10 : base de l'image PE */
    uint64_t     Ldr;                     /* +0x18 : PEB_LDR_DATA (stub) */
    uint64_t     ProcessParameters;       /* +0x20 */
    uint64_t     SubSystemData;           /* +0x28 : réservé (offset réel Windows) */
    uint64_t     ProcessHeap;             /* +0x30 : heap processus */
    uint64_t     NumberOfProcessors;      /* +0x38 */
    uint64_t     NtGlobalFlag;            /* +0x40 */
} WINUX_PEB;

#pragma pack(pop)

/* ==========================================================================
   API
   ========================================================================== */

/*
 * Initialise le modèle de threads :
 * - Alloue le PEB (unique par processus)
 * - Crée le TEB pour le thread principal
 * - Configure GS segment → TEB via arch_prctl(ARCH_SET_GS)
 * - Enregistre la clé pthread_key pour le lookup TEB
 *
 * Doit être appelé APRÈS pe_load() (pour avoir pe->mapped_base à
 * mettre dans PEB->ImageBaseAddress).
 */
int thread_model_init(uint64_t pe_base, uint64_t pe_size,
                       uint64_t stack_base, uint64_t stack_limit);

/*
 * Libère les ressources du modèle de threads.
 */
void thread_model_shutdown(void);

/*
 * Retourne le TEB du thread courant.
 * Utilise GS segment register (gs:[0x30] = Self).
 */
static inline WINUX_TEB *teb_get_current(void)
{
    WINUX_TEB *teb;
    __asm__ __volatile__("movq %%gs:0x30, %0" : "=r"(teb));
    return teb;
}

/*
 * Retourne le PEB du processus courant.
 * Utilise GS:[0x60] → PEB.
 */
static inline WINUX_PEB *peb_get_current(void)
{
    WINUX_PEB *peb;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

/*
 * GetLastError/SetLastError via TEB.
 * Remplace l'implémentation __thread _last_error de globals.c.
 * Si le TEB n'est pas encore initialisé (pendant l'init), fallback
 * sur le __thread _last_error.
 */
DWORD winux_teb_get_last_error(void);
void  winux_teb_set_last_error(DWORD err);

/*
 * Crée un TEB pour un nouveau thread (appelé depuis NtCreateThread).
 * Retourne le pointeur TEB ou NULL.
 */
WINUX_TEB *teb_create_for_thread(uint64_t stack_base, uint64_t stack_limit);

/*
 * Détruit le TEB d'un thread et restaure le FS/GS.
 */
void teb_destroy_for_thread(WINUX_TEB *teb);

/*
 * Active le TEB pour le thread courant (appelé depuis un nouveau thread PE).
 * Configure ARCH_SET_GS sur ce TEB.
 */
int teb_activate(WINUX_TEB *teb);

#endif /* THREAD_MODEL_H */
