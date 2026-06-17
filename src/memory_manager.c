/*
 * === FICHIER : memory_manager.c ===
 * Description : Gestionnaire de mémoire Winux.
 *               Gère les allocations virtuelles (mmap),
 *               le tracking des régions, et le heap processus.
 *
 * Dépendances Linux : mmap(2), munmap(2), mprotect(2)
 *
 * Architecture :
 *   - Table de régions : liste chaînée des allocations VirtualAlloc
 *     pour supporter VirtualQuery.
 *   - Heap processus : free-list allocator au-dessus d'une région
 *     mmap(MAP_ANONYMOUS) de 64 MB avec expansion automatique.
 *   - Les blocs du heap ont un en-tête de 32 octets contenant
 *     la taille, les flags, et les pointeurs next/prev.
 */

#include "include/winux.h"
#include "include/memory_manager.h"

#include <sys/mman.h>

/* ==========================================================================
   Constantes internes
   ========================================================================== */

#define MEM_INITIAL_HEAP_SIZE   (64ULL * 1024 * 1024)  /* 64 MB */
#define MEM_MAX_REGIONS          2048
#define MEM_BLOCK_ALIGN          16    /* alignement des blocs heap */
#define MEM_BLOCK_HEADER_SIZE    32    /* taille de l'en-tête de bloc */

#define MEM_MAGIC_ALLOCATED  0xDEADBEEF
#define MEM_MAGIC_FREE       0xCAFEBABE

/* ==========================================================================
   Tracking des régions virtuelles
   ========================================================================== */

typedef struct _MEM_REGION {
    PVOID    base;
    SIZE_T   size;
    ULONG    state;    /* MEM_FREE, MEM_RESERVE, MEM_COMMIT */
    ULONG    protect;
    ULONG    type;     /* MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE */
    bool     in_use;
} MEM_REGION;

static MEM_REGION  mem_regions[MEM_MAX_REGIONS];
static int         mem_region_count = 0;
static bool        mem_initialized = false;
static pthread_mutex_t mem_regions_lock = PTHREAD_MUTEX_INITIALIZER;

/* ==========================================================================
   Bloc de heap (free-list)
   ========================================================================== */

typedef struct _HEAP_BLOCK {
    uint64_t magic;          /* MEM_MAGIC_ALLOCATED ou MEM_MAGIC_FREE */
    SIZE_T   size;           /* taille utile (sans l'en-tête) */
    struct _HEAP_BLOCK *prev; /* bloc précédent dans la liste */
    struct _HEAP_BLOCK *next; /* bloc suivant dans la liste */
} HEAP_BLOCK;

/* ==========================================================================
   Heap de processus global
   ========================================================================== */

static WINUX_HEAP *process_heap = NULL;

/* ==========================================================================
   Helpers — regions
   ========================================================================== */

static void mem_region_add(PVOID base, SIZE_T size, ULONG state,
                            ULONG protect, ULONG type)
{
    pthread_mutex_lock(&mem_regions_lock);
    for (int i = 0; i < MEM_MAX_REGIONS; i++) {
        if (!mem_regions[i].in_use) {
            mem_regions[i].base    = base;
            mem_regions[i].size    = size;
            mem_regions[i].state   = state;
            mem_regions[i].protect = protect;
            mem_regions[i].type    = type;
            mem_regions[i].in_use  = true;
            mem_region_count++;
            pthread_mutex_unlock(&mem_regions_lock);
            return;
        }
    }
    pthread_mutex_unlock(&mem_regions_lock);
    WINUX_ERR("Region tracking table full (%d entries)", MEM_MAX_REGIONS);
}

static void mem_region_remove(PVOID base)
{
    pthread_mutex_lock(&mem_regions_lock);
    for (int i = 0; i < MEM_MAX_REGIONS; i++) {
        if (mem_regions[i].in_use && mem_regions[i].base == base) {
            mem_regions[i].in_use = false;
            mem_region_count--;
            pthread_mutex_unlock(&mem_regions_lock);
            return;
        }
    }
    pthread_mutex_unlock(&mem_regions_lock);
}

static int mem_region_find_index(PVOID address)
{
    for (int i = 0; i < MEM_MAX_REGIONS; i++) {
        if (!mem_regions[i].in_use) continue;
        uintptr_t base_u = (uintptr_t)mem_regions[i].base;
        uintptr_t addr_u = (uintptr_t)address;
        if (addr_u >= base_u && addr_u < base_u + mem_regions[i].size)
            return i;
    }
    return -1;
}

/* ==========================================================================
   Helpers — heap
   ========================================================================== */

/*
 * Crée un nouveau bloc libre à une adresse donnée.
 */
static HEAP_BLOCK *heap_make_free_block(void *addr, SIZE_T size)
{
    HEAP_BLOCK *blk = (HEAP_BLOCK *)addr;
    blk->magic = MEM_MAGIC_FREE;
    blk->size  = size;
    blk->prev  = NULL;
    blk->next  = NULL;
    return blk;
}

/*
 * Étend le heap en allouant une nouvelle région via mmap.
 * Retourne le nouveau bloc libre ainsi créé, ou NULL.
 */
static HEAP_BLOCK *heap_extend(WINUX_HEAP *heap, SIZE_T min_size)
{
    SIZE_T extend_size = WINUX_MAX(min_size + MEM_BLOCK_HEADER_SIZE, MEM_INITIAL_HEAP_SIZE);
    extend_size = WINUX_ALIGN_UP(extend_size, 0x10000); /* 64K align */

    void *region = mmap(NULL, extend_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);
    if (region == MAP_FAILED) {
        WINUX_ERR("Heap extension failed (mmap %zu bytes)", extend_size);
        return NULL;
    }

    heap->total_size += extend_size;

    /*
     * Si c'est la première extension, initialiser first_block.
     */
    if (!heap->first_block)
        heap->first_block = region;

    HEAP_BLOCK *blk = heap_make_free_block(region,
        extend_size - MEM_BLOCK_HEADER_SIZE);
    return blk;
}

/*
 * Ajoute un bloc à la liste libre (trié par adresse pour coalescing).
 */
static void heap_free_list_insert(WINUX_HEAP *heap, HEAP_BLOCK *blk)
{
    HEAP_BLOCK *cur = (HEAP_BLOCK *)heap->free_list;

    /* Insertion en tête si liste vide ou avant le premier */
    if (!cur || (uintptr_t)blk < (uintptr_t)cur) {
        blk->next = cur;
        blk->prev = NULL;
        if (cur) cur->prev = blk;
        heap->free_list = blk;
        return;
    }

    /* Chercher la position d'insertion */
    while (cur->next && (uintptr_t)cur->next < (uintptr_t)blk)
        cur = cur->next;

    blk->next = cur->next;
    blk->prev = cur;
    if (cur->next) cur->next->prev = blk;
    cur->next = blk;
}

/*
 * Retire un bloc de la liste libre.
 */
static void heap_free_list_remove(WINUX_HEAP *heap, HEAP_BLOCK *blk)
{
    if (blk->prev)
        blk->prev->next = blk->next;
    else
        heap->free_list = blk->next;

    if (blk->next)
        blk->next->prev = blk->prev;
}

/*
 * Coalesce (fusionne) un bloc libre avec ses voisins.
 * Suppose que le bloc est déjà dans la free_list.
 */
static void heap_coalesce(WINUX_HEAP *heap, HEAP_BLOCK *blk)
{
    uintptr_t blk_end = (uintptr_t)blk + MEM_BLOCK_HEADER_SIZE + blk->size;

    /* Coalescer avec le bloc suivant */
    if (blk->next) {
        uintptr_t next_start = (uintptr_t)blk->next;
        if (next_start == blk_end) {
            blk->size += MEM_BLOCK_HEADER_SIZE + blk->next->size;
            heap_free_list_remove(heap, blk->next);
        }
    }

    /* Coalescer avec le bloc précédent */
    if (blk->prev) {
        uintptr_t prev_end = (uintptr_t)blk->prev + MEM_BLOCK_HEADER_SIZE + blk->prev->size;
        if (prev_end == (uintptr_t)blk) {
            blk->prev->size += MEM_BLOCK_HEADER_SIZE + blk->size;
            heap_free_list_remove(heap, blk);
        }
    }
}

/* ==========================================================================
   API Initialisation / Arrêt
   ========================================================================== */

int mem_init(void)
{
    if (mem_initialized) return 0;

    memset(mem_regions, 0, sizeof(mem_regions));
    mem_region_count = 0;

    /* Créer le heap de processus par défaut */
    process_heap = mem_heap_create(MEM_INITIAL_HEAP_SIZE, 0);
    if (!process_heap) {
        WINUX_ERR("Failed to create process heap");
        return -1;
    }

    mem_initialized = true;
    WINUX_LOG("Memory manager initialized (heap: %llu MB at %p)",
              MEM_INITIAL_HEAP_SIZE / (1024 * 1024), process_heap->base);
    return 0;
}

void mem_shutdown(void)
{
    if (!mem_initialized) return;

    /* Détruire le heap de processus */
    if (process_heap) {
        mem_heap_destroy(process_heap);
        process_heap = NULL;
    }

    /* Libérer les régions virtuelles restantes */
    for (int i = 0; i < MEM_MAX_REGIONS; i++) {
        if (mem_regions[i].in_use) {
            /* Ne pas libérer les régions MEM_IMAGE (gérées par pe_loader) */
            if (mem_regions[i].type != MEM_IMAGE) {
                munmap(mem_regions[i].base, mem_regions[i].size);
            }
            mem_regions[i].in_use = false;
        }
    }

    mem_region_count = 0;
    mem_initialized  = false;
    WINUX_LOG("Memory manager shut down");
}

/* ==========================================================================
   API Mémoire Virtuelle
   ========================================================================== */

NTSTATUS mem_virtual_alloc(
    PVOID   *BaseAddress,
    SIZE_T  *RegionSize,
    ULONG    AllocationType,
    ULONG    Protect
)
{
    void *addr;
    SIZE_T size;
    int prot, flags = MAP_PRIVATE | MAP_ANONYMOUS;
    NTSTATUS status = STATUS_SUCCESS;

    if (!mem_initialized) {
        if (mem_init() != 0) return STATUS_NO_MEMORY;
    }

    if (!BaseAddress || !RegionSize || *RegionSize == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    size = WINUX_ALIGN_UP(*RegionSize, 0x1000);

    /* Traduire les flags de protection */
    switch (Protect & 0xFF) {
    case PAGE_NOACCESS:          prot = PROT_NONE;   break;
    case PAGE_READONLY:          prot = PROT_READ;   break;
    case PAGE_READWRITE:         prot = PROT_READ | PROT_WRITE; break;
    case PAGE_WRITECOPY:         prot = PROT_READ | PROT_WRITE; break;
    case PAGE_EXECUTE:           prot = PROT_EXEC;   break;
    case PAGE_EXECUTE_READ:      prot = PROT_READ | PROT_EXEC;  break;
    case PAGE_EXECUTE_READWRITE: prot = PROT_READ | PROT_WRITE | PROT_EXEC; break;
    default:                     prot = PROT_READ | PROT_WRITE; break;
    }

    /*
     * MEM_RESERVE seul → réserver l'espace d'adressage sans commiter.
     * Sous Linux, on fait mmap avec PROT_NONE pour simuler.
     * MEM_COMMIT → rendre accessible.
     */
    if ((AllocationType & MEM_RESERVE) && !(AllocationType & MEM_COMMIT))
        prot = PROT_NONE;

    addr = *BaseAddress;
    if (addr) {
        void *requested = (void *)((uintptr_t)addr & ~0xFFFULL);
        flags |= MAP_FIXED_NOREPLACE;
        addr = mmap(requested, size, prot, flags, -1, 0);
        if (addr == MAP_FAILED && errno == EEXIST) {
            flags &= ~MAP_FIXED_NOREPLACE;
            flags |= MAP_FIXED;
            addr = mmap(requested, size, prot, flags, -1, 0);
        }
    } else {
        addr = mmap(NULL, size, prot, flags, -1, 0);
    }

    if (addr == MAP_FAILED) {
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return STATUS_NO_MEMORY;
    }

    /* Tracking */
    ULONG state = (AllocationType & MEM_COMMIT) ? MEM_COMMIT : MEM_RESERVE;
    ULONG type  = MEM_PRIVATE;

    /*
     * Si l'adresse tombe dans une région déjà trackée (MEM_RESERVE
     * suivie de MEM_COMMIT), on met à jour au lieu d'ajouter.
     */
    pthread_mutex_lock(&mem_regions_lock);
    int existing_idx = mem_region_find_index(addr);
    if (existing_idx >= 0 && mem_regions[existing_idx].state == MEM_RESERVE && (AllocationType & MEM_COMMIT)) {
        mem_regions[existing_idx].state   = MEM_COMMIT;
        mem_regions[existing_idx].protect = Protect;
        pthread_mutex_unlock(&mem_regions_lock);
    } else {
        pthread_mutex_unlock(&mem_regions_lock);
        if (existing_idx < 0)
            mem_region_add(addr, size, state, Protect, type);
    }

    *BaseAddress = addr;
    *RegionSize  = size;

    winux_set_last_error(ERROR_SUCCESS);
    WINUX_LOG("VirtualAlloc: %zu bytes at %p (state=0x%x prot=0x%x)",
              size, addr, state, Protect);
    return status;
}

NTSTATUS mem_virtual_free(
    PVOID  *BaseAddress,
    SIZE_T *RegionSize,
    ULONG   FreeType
)
{
    void *addr;
    SIZE_T size;

    if (!mem_initialized) return STATUS_INVALID_PARAMETER;
    if (!BaseAddress || !*BaseAddress) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    addr = *BaseAddress;
    size = RegionSize ? *RegionSize : 0;

    if (FreeType & MEM_RELEASE) {
        if (size == 0) {
            /* Trouver la taille depuis la table de régions */
            pthread_mutex_lock(&mem_regions_lock);
            int region_idx = mem_region_find_index(addr);
            if (region_idx >= 0)
                size = mem_regions[region_idx].size;
            else
                size = 0x1000;
            pthread_mutex_unlock(&mem_regions_lock);
        }

        if (munmap(addr, size) != 0) {
            winux_set_last_error(ERROR_INVALID_PARAMETER);
            return STATUS_UNSUCCESSFUL;
        }

        mem_region_remove(addr);
        *BaseAddress = NULL;
        if (RegionSize) *RegionSize = 0;
    } else {
        /* MEM_DECOMMIT : remplacer par PROT_NONE */
        if (size == 0) size = 0x1000;
        void *ret = mmap(addr, size, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (ret == MAP_FAILED) {
            winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return STATUS_NO_MEMORY;
        }

        /* Mettre à jour l'état dans la table */
        pthread_mutex_lock(&mem_regions_lock);
        int region_idx = mem_region_find_index(addr);
        if (region_idx >= 0)
            mem_regions[region_idx].state = MEM_RESERVE;
        pthread_mutex_unlock(&mem_regions_lock);
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

NTSTATUS mem_virtual_protect(
    PVOID  *BaseAddress,
    SIZE_T *RegionSize,
    ULONG   NewProtect,
    ULONG  *OldProtect
)
{
    void *addr;
    SIZE_T size;
    int new_prot;

    if (!mem_initialized) return STATUS_INVALID_PARAMETER;
    if (!BaseAddress || !*BaseAddress || !RegionSize || *RegionSize == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    addr = *BaseAddress;
    size = WINUX_ALIGN_UP(*RegionSize, 0x1000);

    switch (NewProtect & 0xFF) {
    case PAGE_NOACCESS:          new_prot = PROT_NONE;   break;
    case PAGE_READONLY:          new_prot = PROT_READ;   break;
    case PAGE_READWRITE:         new_prot = PROT_READ | PROT_WRITE; break;
    case PAGE_EXECUTE:           new_prot = PROT_EXEC;   break;
    case PAGE_EXECUTE_READ:      new_prot = PROT_READ | PROT_EXEC;  break;
    case PAGE_EXECUTE_READWRITE: new_prot = PROT_READ | PROT_WRITE | PROT_EXEC; break;
    default:                     new_prot = PROT_READ | PROT_WRITE; break;
    }

    /* Récupérer l'ancienne protection depuis la table de régions */
    if (OldProtect) {
        pthread_mutex_lock(&mem_regions_lock);
        int region_idx = mem_region_find_index(addr);
        *OldProtect = (region_idx >= 0) ? mem_regions[region_idx].protect : PAGE_READWRITE;
        pthread_mutex_unlock(&mem_regions_lock);
    }

    if (mprotect(addr, size, new_prot) != 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_UNSUCCESSFUL;
    }

    /* Mettre à jour la table */
    pthread_mutex_lock(&mem_regions_lock);
    int region_idx = mem_region_find_index(addr);
    if (region_idx >= 0)
        mem_regions[region_idx].protect = NewProtect;
    pthread_mutex_unlock(&mem_regions_lock);

    *RegionSize = size;
    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

SIZE_T mem_virtual_query(
    PVOID                         Address,
    MEMORY_BASIC_INFORMATION     *Buffer,
    SIZE_T                        Length
)
{
    if (!mem_initialized || !Buffer || Length < sizeof(MEMORY_BASIC_INFORMATION))
        return 0;

    memset(Buffer, 0, sizeof(*Buffer));

    pthread_mutex_lock(&mem_regions_lock);
    int region_idx = mem_region_find_index(Address);
    if (region_idx >= 0) {
        Buffer->BaseAddress       = mem_regions[region_idx].base;
        Buffer->AllocationBase    = mem_regions[region_idx].base;
        Buffer->AllocationProtect = mem_regions[region_idx].protect;
        Buffer->RegionSize        = mem_regions[region_idx].size;
        Buffer->State             = mem_regions[region_idx].state;
        Buffer->Protect           = mem_regions[region_idx].protect;
        Buffer->Type              = mem_regions[region_idx].type;
    }
    pthread_mutex_unlock(&mem_regions_lock);

    if (region_idx < 0) {
        /*
         * Adresse non trackée : on remplit comme MEM_FREE.
         * On arrondit au début de page et on met une taille
         * arbitraire de 64K (pour que l'appelant puisse itérer).
         */
        uintptr_t page_base = (uintptr_t)Address & ~0xFFFULL;
        Buffer->BaseAddress    = (PVOID)page_base;
        Buffer->AllocationBase = (PVOID)page_base;
        Buffer->RegionSize     = 0x10000; /* 64K */
        Buffer->State          = MEM_FREE;
        Buffer->Protect        = PAGE_NOACCESS;
        Buffer->Type           = 0;
    }

    return sizeof(MEMORY_BASIC_INFORMATION);
}

/* ==========================================================================
   API Heap
   ========================================================================== */

WINUX_HEAP *mem_heap_create(SIZE_T initial_size, DWORD flags)
{
    WINUX_HEAP *heap;

    if (initial_size == 0)
        initial_size = MEM_INITIAL_HEAP_SIZE;
    initial_size = WINUX_ALIGN_UP(initial_size, 0x10000);

    /* Allouer la structure du heap */
    heap = calloc(1, sizeof(WINUX_HEAP));
    if (!heap) return NULL;

    /* Allouer la région mémoire initiale */
    heap->base = mmap(NULL, initial_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1, 0);
    if (heap->base == MAP_FAILED) {
        free(heap);
        return NULL;
    }

    heap->total_size  = initial_size;
    heap->used        = 0;
    heap->flags       = flags;
    heap->first_block = heap->base;
    if (pthread_mutex_init(&heap->lock, NULL) != 0) {
        WINUX_ERR("pthread_mutex_init failed");
        munmap(heap->base, initial_size);
        free(heap);
        return NULL;
    }

    /* Créer le premier bloc libre occupant toute la région */
    HEAP_BLOCK *first = heap_make_free_block(heap->base,
        initial_size - MEM_BLOCK_HEADER_SIZE);
    heap->free_list = first;

    WINUX_LOG("Heap created: base=%p size=%llu MB",
              heap->base, initial_size / (1024 * 1024));
    return heap;
}

void mem_heap_destroy(WINUX_HEAP *heap)
{
    if (!heap) return;
    pthread_mutex_destroy(&heap->lock);
    if (heap->base)
        munmap(heap->base, heap->total_size);
    free(heap);
}

PVOID mem_heap_alloc(WINUX_HEAP *heap, SIZE_T size)
{
    HEAP_BLOCK *blk, *best;

    if (!heap || size == 0) return NULL;

    /* Aligner la taille */
    size = WINUX_ALIGN_UP(size, MEM_BLOCK_ALIGN);

    /* Verrouiller (sauf HEAP_NO_SERIALIZE) */
    if (!(heap->flags & HEAP_NO_SERIALIZE))
        pthread_mutex_lock(&heap->lock);

    /* First-fit dans la free list */
    best = NULL;
    for (blk = (HEAP_BLOCK *)heap->free_list; blk != NULL; blk = blk->next) {
        if (blk->magic == MEM_MAGIC_FREE &&
            blk->size >= size) {
            best = blk;
            break;
        }
    }

    /* Pas de bloc assez grand → étendre le heap */
    if (!best) {
        best = heap_extend(heap, size);
        if (!best) {
            if (!(heap->flags & HEAP_NO_SERIALIZE))
                pthread_mutex_unlock(&heap->lock);
            return NULL;
        }
        heap_free_list_insert(heap, best);
        /*
         * Après extension, le nouveau bloc est le dernier.
         * On le reprend directement ci-dessous.
         */
    }

    /* Retirer le bloc de la free list */
    heap_free_list_remove(heap, best);

    /*
     * Si le bloc est significativement plus grand que nécessaire,
     * on le split (on garde la partie non utilisée comme nouveau
     * bloc libre).
     */
    SIZE_T remaining = best->size - size;
    if (remaining >= MEM_BLOCK_HEADER_SIZE + MEM_BLOCK_ALIGN) {
        /* Split */
        HEAP_BLOCK *new_free = (HEAP_BLOCK *)(
            (uint8_t *)best + MEM_BLOCK_HEADER_SIZE + size);
        new_free->magic = MEM_MAGIC_FREE;
        new_free->size  = remaining - MEM_BLOCK_HEADER_SIZE;
        new_free->prev  = NULL;
        new_free->next  = NULL;
        heap_free_list_insert(heap, new_free);

        best->size = size;
    }

    /* Marquer comme alloué */
    best->magic = MEM_MAGIC_ALLOCATED;
    heap->used += best->size + MEM_BLOCK_HEADER_SIZE;

    if (!(heap->flags & HEAP_NO_SERIALIZE))
        pthread_mutex_unlock(&heap->lock);

    /* Retourner l'adresse juste après l'en-tête */
    return (PVOID)((uint8_t *)best + MEM_BLOCK_HEADER_SIZE);
}

BOOL mem_heap_free(WINUX_HEAP *heap, PVOID ptr)
{
    if (!heap || !ptr) return FALSE;

    if (!(heap->flags & HEAP_NO_SERIALIZE))
        pthread_mutex_lock(&heap->lock);

    /* Retrouver l'en-tête du bloc */
    HEAP_BLOCK *blk = (HEAP_BLOCK *)((uint8_t *)ptr - MEM_BLOCK_HEADER_SIZE);

    if (blk->magic != MEM_MAGIC_ALLOCATED) {
        WINUX_ERR("Heap corruption: invalid magic in free (ptr=%p)", ptr);
        if (!(heap->flags & HEAP_NO_SERIALIZE))
            pthread_mutex_unlock(&heap->lock);
        return FALSE;
    }

    heap->used -= blk->size + MEM_BLOCK_HEADER_SIZE;

    /* Marquer comme libre et insérer dans la free list */
    blk->magic = MEM_MAGIC_FREE;
    blk->prev  = NULL;
    blk->next  = NULL;
    heap_free_list_insert(heap, blk);

    /* Coalescer avec les voisins */
    heap_coalesce(heap, blk);

    if (!(heap->flags & HEAP_NO_SERIALIZE))
        pthread_mutex_unlock(&heap->lock);

    return TRUE;
}

PVOID mem_heap_realloc(WINUX_HEAP *heap, PVOID ptr, SIZE_T new_size)
{
    if (!heap || !ptr) return NULL;
    if (new_size == 0) {
        mem_heap_free(heap, ptr);
        return NULL;
    }

    HEAP_BLOCK *blk = (HEAP_BLOCK *)((uint8_t *)ptr - MEM_BLOCK_HEADER_SIZE);
    if (blk->magic != MEM_MAGIC_ALLOCATED) return NULL;

    new_size = WINUX_ALIGN_UP(new_size, MEM_BLOCK_ALIGN);

    /* Si la nouvelle taille est plus petite ou égale, on garde le bloc */
    if (new_size <= blk->size) {
        /*
         * Si la différence est assez grande, on peut split.
         */
        SIZE_T diff = blk->size - new_size;
        if (diff >= MEM_BLOCK_HEADER_SIZE + MEM_BLOCK_ALIGN) {
            HEAP_BLOCK *new_free = (HEAP_BLOCK *)(
                (uint8_t *)blk + MEM_BLOCK_HEADER_SIZE + new_size);
            new_free->magic = MEM_MAGIC_FREE;
            new_free->size  = diff - MEM_BLOCK_HEADER_SIZE;
            new_free->prev  = NULL;
            new_free->next  = NULL;
            heap_free_list_insert(heap, new_free);
            heap_coalesce(heap, new_free);

            blk->size = new_size;
        }
        return ptr;
    }

    /* Nouvelle taille plus grande → alloc + copy + free */
    PVOID new_ptr = mem_heap_alloc(heap, new_size);
    if (!new_ptr) return NULL;

    memcpy(new_ptr, ptr, blk->size);
    mem_heap_free(heap, ptr);

    return new_ptr;
}

SIZE_T mem_heap_size(WINUX_HEAP *heap, PVOID ptr)
{
    if (!heap || !ptr) return 0;

    HEAP_BLOCK *blk = (HEAP_BLOCK *)((uint8_t *)ptr - MEM_BLOCK_HEADER_SIZE);
    if (blk->magic != MEM_MAGIC_ALLOCATED) return 0;

    return blk->size;
}

void mem_heap_reset(void)
{
    if (!process_heap) return;

    /*
     * Réinitialiser le heap : on recrée le premier bloc libre
     * qui englobe toute la région mmapée.
     */
    HEAP_BLOCK *first = (HEAP_BLOCK *)process_heap->base;
    first->magic = MEM_MAGIC_FREE;
    first->size  = process_heap->total_size - MEM_BLOCK_HEADER_SIZE;
    first->prev  = NULL;
    first->next  = NULL;

    process_heap->free_list = first;
    process_heap->used      = 0;

    WINUX_LOG("Process heap reset");
}

WINUX_HEAP *mem_get_process_heap(void)
{
    if (!process_heap)
        mem_init();
    return process_heap;
}
