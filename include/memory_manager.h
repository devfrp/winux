/*
 * === FICHIER : include/memory_manager.h ===
 * Description : API publique du gestionnaire de mémoire.
 *               Gère les allocations virtuelles (VirtualAlloc),
 *               les heaps (HeapAlloc/HeapFree), et le tracking
 *               des régions mémoire pour VirtualQuery.
 *
 * Architecture :
 *   - Table de régions virtuelles (addresses, tailles, protections)
 *   - Heap processus : simple free-list allocator au-dessus de mmap
 *   - VirtualQuery interroge la table de régions
 *
 * Dépendances : include/winux.h, <stdint.h>
 */

#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include "winux.h"
#include <pthread.h>

/* ==========================================================================
   Types
   ========================================================================== */

/*
 * État d'une page mémoire (pour VirtualQuery).
 * Préfixés WINUX_ pour éviter le conflit avec les #define MEM_* de winux.h.
 */
typedef enum _WINUX_MEM_STATE {
    WINUX_MEM_FREE    = 0x00010000,
    WINUX_MEM_RESERVE = 0x00002000,
    WINUX_MEM_COMMIT  = 0x00001000,
} WINUX_MEM_STATE;

/*
 * Type de mémoire.
 */
typedef enum _MEM_TYPE {
    MEM_PRIVATE = 0x00020000,
    MEM_MAPPED  = 0x00040000,
    MEM_IMAGE   = 0x01000000,
} MEM_TYPE;

/*
 * Structure MEMORY_BASIC_INFORMATION retournée par VirtualQuery.
 */
#pragma pack(push, 1)
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID     BaseAddress;
    PVOID     AllocationBase;
    DWORD     AllocationProtect;
    SIZE_T    RegionSize;
    DWORD     State;
    DWORD     Protect;
    DWORD     Type;
} MEMORY_BASIC_INFORMATION;
#pragma pack(pop)

/*
 * Structure de gestion d'un heap.
 */
typedef struct _WINUX_HEAP {
    PVOID   base;            /* adresse de base de la région mmap */
    SIZE_T  total_size;      /* taille totale réservée */
    SIZE_T  used;            /* octets utilisés */
    void   *free_list;       /* tête de la liste libre (first-fit) */
    void   *first_block;     /* premier bloc allouable */
    DWORD   flags;           /* HEAP_* flags */
    pthread_mutex_t lock;    /* mutex pour accès concurrent */
} WINUX_HEAP;

/* ==========================================================================
   API Mémoire Virtuelle
   ========================================================================== */

/*
 * Initialise le gestionnaire de mémoire :
 * - Crée la table de tracking des régions virtuelles
 * - Initialise le heap de processus par défaut
 *
 * Doit être appelé avant toute allocation.
 */
int mem_init(void);

/*
 * Arrête le gestionnaire de mémoire :
 * - Libère toutes les régions virtuelles
 * - Détruit le heap de processus
 */
void mem_shutdown(void);

/*
 * Alloue une région de mémoire virtuelle.
 * Équivalent de NtAllocateVirtualMemory.
 *
 * Retourne STATUS_SUCCESS ou code d'erreur NT.
 */
NTSTATUS mem_virtual_alloc(
    PVOID   *BaseAddress,
    SIZE_T  *RegionSize,
    ULONG    AllocationType,
    ULONG    Protect
);

/*
 * Libère une région de mémoire virtuelle.
 * Équivalent de NtFreeVirtualMemory.
 */
NTSTATUS mem_virtual_free(
    PVOID  *BaseAddress,
    SIZE_T *RegionSize,
    ULONG   FreeType
);

/*
 * Change la protection d'une région mémoire.
 * Équivalent de NtProtectVirtualMemory.
 */
NTSTATUS mem_virtual_protect(
    PVOID  *BaseAddress,
    SIZE_T *RegionSize,
    ULONG   NewProtect,
    ULONG  *OldProtect
);

/*
 * Interroge les informations d'une adresse mémoire.
 * Équivalent de VirtualQuery.
 *
 * Remplit une structure MEMORY_BASIC_INFORMATION.
 * Retourne le nombre d'octets écrits, ou 0 si échec.
 */
SIZE_T mem_virtual_query(
    PVOID                         Address,
    MEMORY_BASIC_INFORMATION     *Buffer,
    SIZE_T                        Length
);

/* ==========================================================================
   API Heap
   ========================================================================== */

/*
 * Crée un nouveau heap privé.
 * Retourne le handle du heap ou NULL si échec.
 */
WINUX_HEAP *mem_heap_create(SIZE_T initial_size, DWORD flags);

/*
 * Détruit un heap privé.
 */
void mem_heap_destroy(WINUX_HEAP *heap);

/*
 * Alloue depuis un heap.
 * Retourne le pointeur alloué ou NULL si échec.
 */
PVOID mem_heap_alloc(WINUX_HEAP *heap, SIZE_T size);

/*
 * Libère un bloc alloué depuis un heap.
 * Retourne TRUE si succès, FALSE si échec.
 */
BOOL mem_heap_free(WINUX_HEAP *heap, PVOID ptr);

/*
 * Réalloue un bloc (changement de taille).
 * Retourne le nouveau pointeur ou NULL si échec.
 */
PVOID mem_heap_realloc(WINUX_HEAP *heap, PVOID ptr, SIZE_T new_size);

/*
 * Retourne la taille d'un bloc alloué.
 */
SIZE_T mem_heap_size(WINUX_HEAP *heap, PVOID ptr);

/*
 * Réinitialise le heap de processus (libère tous les blocs).
 */
void mem_heap_reset(void);

/*
 * Récupère le heap de processus par défaut.
 */
WINUX_HEAP *mem_get_process_heap(void);

#endif /* MEMORY_MANAGER_H */
