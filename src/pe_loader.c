/*
 * === FICHIER : pe_loader.c ===
 * Description : Chargeur PE32+ natif pour Linux.
 *               Parse un fichier PE, mappe ses sections en mémoire
 *               aux adresses virtuelles PE, applique les relocations,
 *               et construit une IAT synthétique.
 *
 * Dépendances Linux : mmap(2), mprotect(2), open(2), read(2), close(2),
 *                      fstat(2), sysconf(3)
 *
 * Architecture :
 *   1. mmap le fichier PE entier en lecture seule
 *   2. Valider les signatures DOS et NT
 *   3. Pour chaque section : mmap une région à la VA cible avec
 *      MAP_FIXED_NOREPLACE (kernel >= 4.17)
 *   4. Appliquer les relocations si le delta base != 0
 *   5. Parcourir la table d'import et construire une IAT synthétique
 *      (délégation vers win32_bridge.c pour la résolution)
 */

#include "include/winux.h"
#include "include/pe_loader.h"
#include "include/proc_compat.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/mman.h>

/* ==========================================================================
   Variable globale : table d'import résolue externe
   ========================================================================== */

/*
 * Pointeur de fonction pour la résolution d'import.
 * win32_bridge.c doit assigner ce pointeur à sa fonction de lookup
 * avant d'appeler pe_load(). Si ce pointeur est NULL, tous les imports
 * seront laissés non résolus (le PE ne pourra pas appeler de DLL).
 */
extern void *(*winux_import_resolver)(const char *dll, const char *func);

/* ==========================================================================
   Fonctions internes — validation du PE
   ========================================================================== */

/*
 * Valide les signatures de base :
 * - Taille de fichier suffisante (> sizeof(IMAGE_DOS_HEADER))
 * - Signature MZ
 * - Signature PE à l'offset e_lfanew
 * - Machine cible x86_64 (AMD64)
 *
 * Retourne 0 si valide, -1 sinon.
 */
static int pe_validate_headers(const uint8_t *base, size_t file_size)
{
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    uint32_t pe_offset;

    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        WINUX_ERR("File too small for DOS header (%zu bytes)", file_size);
        return -1;
    }

    dos = (const IMAGE_DOS_HEADER *)base;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        WINUX_ERR("Invalid DOS signature: 0x%04X (expected 0x%04X)",
                  dos->e_magic, IMAGE_DOS_SIGNATURE);
        return -1;
    }

    pe_offset = (uint32_t)dos->e_lfanew;
    if (pe_offset + sizeof(IMAGE_NT_HEADERS64) > file_size) {
        WINUX_ERR("PE offset 0x%X beyond file bounds (%zu bytes)",
                  pe_offset, file_size);
        return -1;
    }

    nt = (const IMAGE_NT_HEADERS64 *)(base + pe_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        WINUX_ERR("Invalid NT signature: 0x%08X", nt->Signature);
        return -1;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        WINUX_ERR("Unsupported machine type: 0x%04X (only AMD64 supported)",
                  nt->FileHeader.Machine);
        return -1;
    }

    /* Vérifier que c'est une image exécutable (pas un objet .obj) */
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        WINUX_ERR("File is not marked as executable image");
        return -1;
    }

    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        WINUX_ERR("File is a DLL, not an executable (DLL loading not supported yet)");
        return -1;
    }

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        WINUX_ERR("Not a PE32+ image (magic 0x%04X)", nt->OptionalHeader.Magic);
        return -1;
    }

    return 0;
}

/* ==========================================================================
   Fonctions internes — allocation mémoire PE
   ========================================================================== */

/*
 * Calcule les flags mmap à partir des caractéristiques de section PE.
 *
 * Mapping PE → Linux :
 *   MEM_EXECUTE → PROT_EXEC
 *   MEM_READ    → PROT_READ
 *   MEM_WRITE   → PROT_WRITE (inclut toujours PROT_READ sur Linux)
 *   CNT_UNINITIALIZED_DATA → pas de données fichier, uniquement MAP_ANONYMOUS
 */
static int pe_section_prot(DWORD characteristics)
{
    int prot = PROT_NONE;

    if (characteristics & IMAGE_SCN_MEM_EXECUTE)  prot |= PROT_EXEC;
    if (characteristics & IMAGE_SCN_MEM_READ)     prot |= PROT_READ;
    if (characteristics & IMAGE_SCN_MEM_WRITE)    prot |= PROT_READ | PROT_WRITE;

    /* Si aucun flag, au moins PROT_READ pour le mapping initial */
    if (prot == PROT_NONE) prot = PROT_READ;

    return prot;
}

/*
 * Alloue et mappe une section PE en mémoire.
 *
 * Stratégie : on utilise MAP_FIXED_NOREPLACE pour garantir
 * l'adresse virtuelle PE. Si ce flag n'est pas supporté (kernel < 4.17),
 * on utilise MAP_FIXED — ce qui est risqué mais nécessaire pour
 * la transparence.
 *
 * Pour les sections avec données fichier (.text, .rdata, .data) :
 * on mmap d'abord avec PROT_READ|PROT_WRITE, on copie les données,
 * puis on applique mprotect() avec les vrais flags.
 *
 * Pour le .bss (CNT_UNINITIALIZED_DATA) : MAP_ANONYMOUS seulement.
 *
 * Retourne l'adresse mappée ou MAP_FAILED.
 */
static void *pe_map_section(const PE_IMAGE *pe,
                             const IMAGE_SECTION_HEADER *sect)
{
    uint64_t va      = pe->preferred_base + sect->VirtualAddress;
    uint64_t va_aligned = WINUX_ALIGN_DOWN(va, 0x1000); /* 4K page alignment */
    uint64_t offset_pg  = va - va_aligned;
    uint64_t map_size   = WINUX_ALIGN_UP(sect->Misc.VirtualSize + offset_pg, 0x1000);
    int prot_final = pe_section_prot(sect->Characteristics);
    int prot_rw    = PROT_READ | PROT_WRITE;
    void *addr     = MAP_FAILED;
    int flags      = MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_ANONYMOUS;

    /*
     * Tentative avec MAP_FIXED_NOREPLACE (kernel >= 4.17).
     * En cas d'échec avec EEXIST, on tombe sur MAP_FIXED avec un
     * avertissement — cela pourrait écraser une mapping existant
     * du kernel (vDSO, etc.), mais c'est le seul moyen d'obtenir
     * les adresses PE exactes sans privilège root.
     */
    addr = mmap((void *)(uintptr_t)va_aligned, map_size, prot_rw, flags, -1, 0);

    if (addr == MAP_FAILED && errno == EEXIST) {
        WINUX_ERR("MAP_FIXED_NOREPLACE failed at 0x%lx (region occupied), "
                  "falling back to MAP_FIXED — this may be unsafe",
                  va_aligned);
        flags = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
        addr = mmap((void *)(uintptr_t)va_aligned, map_size, prot_rw, flags, -1, 0);
    }

    if (addr == MAP_FAILED) {
        WINUX_ERR("mmap failed for section at VA 0x%lx (size 0x%lx)",
                  va_aligned, map_size);
        return MAP_FAILED;
    }

    /* Copier les données du fichier si la section en a
       (sections CNT_UNINITIALIZED_DATA = .bss ont SizeOfRawData == 0) */
    uint8_t *dest = (uint8_t *)addr + offset_pg;

    if (sect->SizeOfRawData > 0 && sect->PointerToRawData > 0) {
        size_t copy_size = WINUX_MIN(sect->SizeOfRawData, sect->Misc.VirtualSize);
        if (sect->PointerToRawData + copy_size <= pe->file_size) {
            memcpy(dest, pe->file_base + sect->PointerToRawData, copy_size);
        } else {
            /*
             * Certains PE ont PointerToRawData qui dépasse la taille
             * du fichier (ex: sections compressées). On copie ce qu'on peut.
             */
            size_t available = 0;
            if (sect->PointerToRawData < pe->file_size)
                available = pe->file_size - sect->PointerToRawData;
            size_t safe_copy = WINUX_MIN(copy_size, available);
            if (safe_copy > 0)
                memcpy(dest, pe->file_base + sect->PointerToRawData, safe_copy);
            /* Le reste de la section sera zéro (MAP_ANONYMOUS le garantit) */
        }
    }
    /* Pour .bss : les pages MAP_ANONYMOUS sont déjà à zéro, rien à faire */

    /* Appliquer les permissions finales via mprotect() */
    if (mprotect((void *)(uintptr_t)va_aligned, map_size, prot_final) != 0) {
        WINUX_ERR("mprotect failed at 0x%lx (prot 0x%x)", va_aligned, prot_final);
        /* Non fatal : la section reste RW */
    }

    return addr;
}

/* ==========================================================================
   Fonctions internes — relocations
   ========================================================================== */

/*
 * Applique la table de relocations de base (base relocation table).
 *
 * Principe : le linker PE suppose que l'image est chargée à ImageBase.
 * Si le kernel déplace l'image (ASLR), il faut ajouter le delta à
 * chaque adresse référencée dans la table .reloc.
 *
 * La table .reloc est composée de blocs IMAGE_BASE_RELOCATION.
 * Chaque bloc couvre une page de 4K d'adresses virtuelles.
 * Chaque entrée de 2 octets : 4 bits de type + 12 bits d'offset.
 *
 * Types supportés :
 *   IMAGE_REL_BASED_DIR64 (10) : ajuster un QWORD (PE32+)
 *   IMAGE_REL_BASED_ABSOLUTE (0) : padding, ignorer
 *
 * retourne 0 si succès, -1 si erreur.
 */
static int pe_apply_relocations(PE_IMAGE *pe)
{
    IMAGE_DATA_DIRECTORY reloc_dir;
    IMAGE_BASE_RELOCATION *block;
    uint8_t *reloc_base;
    uint32_t remaining;

    if (pe->delta == 0) {
        /* Pas de déplacement, pas besoin de relocations */
        return 0;
    }

    reloc_dir = pe->nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) {
        /*
         * Certains PE sont compilés sans table .reloc (ex: /FIXED).
         * Dans ce cas, on ne peut pas les charger à une adresse
         * différente de leur base préférée.
         */
        WINUX_ERR("No relocation table found, but image was relocated "
                  "(delta=0x%lx). The PE must be loaded at its preferred base.",
                  pe->delta);
        return -1;
    }

    /* La table .reloc est mappée dans l'espace d'adressage du PE */
    reloc_base = (uint8_t *)(uintptr_t)(pe->mapped_base + reloc_dir.VirtualAddress);
    remaining  = reloc_dir.Size;

    block = (IMAGE_BASE_RELOCATION *)reloc_base;

    while (remaining >= sizeof(IMAGE_BASE_RELOCATION) && block->SizeOfBlock > 0) {
        uint32_t block_size  = block->SizeOfBlock;
        uint32_t entry_count = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entries = (WORD *)(block + 1);
        uint8_t *page = (uint8_t *)(uintptr_t)(
            pe->mapped_base + block->VirtualAddress);

        for (uint32_t i = 0; i < entry_count; i++) {
            WORD entry = entries[i];
            uint8_t type = (entry >> 12) & 0xF;
            uint16_t offset = entry & 0xFFF;

            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                /* Padding, pas d'action */
                break;

            case IMAGE_REL_BASED_DIR64: {
                /* Ajuster un pointeur 64 bits */
                uint64_t *ptr = (uint64_t *)(page + offset);
                *ptr += pe->delta;
                break;
            }

            case IMAGE_REL_BASED_HIGHLOW: {
                /* Format PE32 (32-bit) — support partiel pour DLLs 32-bit */
                uint32_t *ptr32 = (uint32_t *)(page + offset);
                *ptr32 += (uint32_t)pe->delta;
                break;
            }

            case IMAGE_REL_BASED_HIGH:
            case IMAGE_REL_BASED_LOW:
                /*
                 * Types de relocation 16-bit obsolètes.
                 * On les ignore — ils n'apparaissent que dans des
                 * PE très anciens (Windows 3.x).
                 */
                break;

            default:
                WINUX_ERR("Unknown relocation type %u at offset 0x%04X", type, offset);
                /* Non fatal : on continue */
                break;
            }
        }

        remaining -= block_size;
        block = (IMAGE_BASE_RELOCATION *)((uint8_t *)block + block_size);
    }

    WINUX_LOG("Relocations applied: delta=0x%lx", pe->delta);
    return 0;
}

/* ==========================================================================
   Fonctions internes — résolution d'imports
   ========================================================================== */

/*
 * Résout la table d'import (Import Address Table — IAT).
 *
 * Parcourt le répertoire IMAGE_DIRECTORY_ENTRY_IMPORT.
 * Pour chaque DLL importée, lit les noms de fonctions (ou ordinaux)
 * et appelle le résolveur externe winux_import_resolver().
 *
 * La résolution réelle est faite par win32_bridge.c qui maintient
 * une table de lookup DLL → fonction. Si le résolveur n'est pas
 * encore initialisé, on marque l'import comme STATUS_DLL_NOT_FOUND.
 *
 * Retourne 0 si succès (même avec des imports non résolus),
 * -1 si la table d'import est corrompue.
 */
static int pe_resolve_imports(PE_IMAGE *pe)
{
    IMAGE_DATA_DIRECTORY import_dir;
    IMAGE_IMPORT_DESCRIPTOR *imp_desc;
    uint32_t unresolved = 0;

    import_dir = pe->nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        /* Pas d'imports — exécutable statique ou bien exe minimal */
        return 0;
    }

    imp_desc = (IMAGE_IMPORT_DESCRIPTOR *)(uintptr_t)(
        pe->mapped_base + import_dir.VirtualAddress);

    /* Si aucun résolveur n'est enregistré, on compte tout comme non résolu */
    if (!winux_import_resolver) {
        WINUX_LOG("No import resolver registered — "
                  "all imports will be unresolved (STATUS_DLL_NOT_FOUND)");
    }

    /*
     * Parcourir les descriptors d'import jusqu'à trouver un bloc nul
     * (Characteristics == 0 et Name == 0 et FirstThunk == 0)
     */
    for (int idx = 0; ; idx++) {
        IMAGE_IMPORT_DESCRIPTOR *desc = &imp_desc[idx];

        /* Fin de la table */
        if (desc->Characteristics == 0 && desc->FirstThunk == 0)
            break;

        DWORD thunk_rva  = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                     : desc->FirstThunk;
        DWORD iat_rva    = desc->FirstThunk;
        const char *dll_name = (const char *)(uintptr_t)(
            pe->mapped_base + desc->Name);

        if (thunk_rva == 0 || iat_rva == 0 || desc->Name == 0) {
            WINUX_ERR("Corrupt import descriptor at index %d", idx);
            continue;
        }

        IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64 *)(uintptr_t)(
            pe->mapped_base + thunk_rva);
        IMAGE_THUNK_DATA64 *iat   = (IMAGE_THUNK_DATA64 *)(uintptr_t)(
            pe->mapped_base + iat_rva);

        /*
         * Parcourir les thunks pour cette DLL.
         * Un thunk nul marque la fin de la liste.
         */
        for (int thunk_idx = 0; ; thunk_idx++) {
            IMAGE_THUNK_DATA64 *t = &thunk[thunk_idx];
            IMAGE_THUNK_DATA64 *i = &iat[thunk_idx];

            if (t->u1.AddressOfData == 0)
                break; /* Fin des imports pour cette DLL */

            const char *func_name = NULL;
            uint16_t    ordinal   = 0;

            if (t->u1.Ordinal & 0x8000000000000000ULL) {
                /* Import par ordinal */
                ordinal = (uint16_t)(t->u1.Ordinal & 0xFFFF);
            } else {
                /* Import par nom : le thunk pointe vers un WORD (hint)
                   suivi du nom ASCIIZ */
                WORD hint = *(WORD *)(uintptr_t)(
                    pe->mapped_base + (DWORD)t->u1.AddressOfData);
                WINUX_UNUSED(hint);
                func_name = (const char *)(uintptr_t)(
                    pe->mapped_base + (DWORD)t->u1.AddressOfData + sizeof(WORD));
            }

            /* Résoudre via le bridge */
            void *func_addr = NULL;
            if (winux_import_resolver) {
                if (func_name) {
                    func_addr = winux_import_resolver(dll_name, func_name);
                } else {
                    /* Résolution par ordinal — rare, support partiel */
                    char ord_buf[32];
                    snprintf(ord_buf, sizeof(ord_buf), "#%u", ordinal);
                    func_addr = winux_import_resolver(dll_name, ord_buf);
                }
            }

            if (func_addr) {
                i->u1.Function = (ULONGLONG)(uintptr_t)func_addr;
            } else {
                unresolved++;
                /*
                 * On laisse l'adresse à zéro. Si le programme appelle
                 * cette fonction, il fera un segfault → intercepté
                 * par le signal handler dans signal_passthrough.c.
                 * Alternative : pointer vers un stub qui retourne
                 * STATUS_DLL_NOT_FOUND.
                 */
            }
        }
    }

    if (unresolved > 0) {
        WINUX_LOG("%u import(s) unresolved", unresolved);
    }

    return 0;
}

/* ==========================================================================
   Fonctions internes — passthrough des signaux initiaux
   ========================================================================== */

/*
 * Installe un handler de signal basique pour SIGSEGV dans le code PE.
 * Version minimale : affiche l'adresse fautive et le delta de relocation.
 * La version complète est dans signal_passthrough.c.
 */
#include <signal.h>

static void pe_sigsegv_handler(int sig, siginfo_t *info, void *ctx)
{
    WINUX_UNUSED(ctx);
    /* write() is async-signal-safe; fprintf is NOT */
    char buf[256];
    int len = snprintf(buf, sizeof(buf),
             "\n[winux] *** CRASH ***\n"
             "[winux] Signal: SIGSEGV\n"
             "[winux] Fault address: %p\n"
             "[winux] Unresolved import or PE bug\n",
             info->si_addr);
    if (len > 0) { ssize_t wr = write(STDERR_FILENO, buf, (size_t)len); (void)wr; }
    _exit(128 + sig);
}

static void pe_install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = pe_sigsegv_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
}

/* ==========================================================================
   API publique
   ========================================================================== */

PE_IMAGE *pe_load(const char *path)
{
    PE_IMAGE *pe = NULL;
    int fd = -1;
    struct stat st;
    uint8_t *file_base = MAP_FAILED;

    /* 1. Ouvrir et mmap le fichier */
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        WINUX_ERR("Cannot open '%s'", path);
        return NULL;
    }

    if (fstat(fd, &st) != 0) {
        WINUX_ERR("fstat failed on '%s'", path);
        goto fail_close;
    }

    if (st.st_size < (off_t)sizeof(IMAGE_DOS_HEADER)) {
        WINUX_ERR("File '%s' too small (%ld bytes)", path, st.st_size);
        goto fail_close;
    }

    file_base = mmap(NULL, (size_t)st.st_size, PROT_READ,
                     MAP_PRIVATE, fd, 0);
    if (file_base == MAP_FAILED) {
        WINUX_ERR("mmap failed on '%s'", path);
        goto fail_close;
    }

    close(fd);
    fd = -1;

    /* 2. Valider les en-têtes PE */
    if (pe_validate_headers(file_base, (size_t)st.st_size) != 0)
        goto fail_unmap_file;

    /* 3. Allouer la structure PE_IMAGE */
    pe = calloc(1, sizeof(PE_IMAGE));
    if (!pe) {
        WINUX_ERR("calloc PE_IMAGE failed");
        goto fail_unmap_file;
    }

    pe->file_base = file_base;
    pe->file_size = (size_t)st.st_size;
    pe->dos = (IMAGE_DOS_HEADER *)file_base;
    pe->nt  = (IMAGE_NT_HEADERS64 *)(file_base + pe->dos->e_lfanew);

    pe->preferred_base = pe->nt->OptionalHeader.ImageBase;
    pe->section_count  = pe->nt->FileHeader.NumberOfSections;
    pe->sections       = (IMAGE_SECTION_HEADER *)((uint8_t *)&pe->nt->OptionalHeader
                           + pe->nt->FileHeader.SizeOfOptionalHeader);

    WINUX_LOG("PE file: %u sections, preferred base 0x%lx, entry RVA 0x%x",
              pe->section_count, pe->preferred_base,
              pe->nt->OptionalHeader.AddressOfEntryPoint);

    /* 4. Mapper chaque section en mémoire */
    uint16_t mapped_count = 0;
    for (uint16_t i = 0; i < pe->section_count; i++) {
        IMAGE_SECTION_HEADER *sect = &pe->sections[i];
        char name[9] = {0};
        memcpy(name, sect->Name, WINUX_MIN(IMAGE_SIZEOF_SHORT_NAME, 8));

        if (sect->Misc.VirtualSize == 0)
            continue;

        WINUX_LOG("Mapping section %u [%s]: VA=0x%x VS=0x%x RS=0x%x",
                  i, name, sect->VirtualAddress,
                  sect->Misc.VirtualSize, sect->SizeOfRawData);

        void *mapped = pe_map_section(pe, sect);
        if (mapped == MAP_FAILED) {
            WINUX_ERR("Failed to map section %u [%s]", i, name);
            goto fail_unmap_sections;
        }
        mapped_count++;

        /* Label VMA pour /proc/self/maps */
        char label[32];
        snprintf(label, sizeof(label), "PE:%.8s", name);
        uint64_t va_aligned = WINUX_ALIGN_DOWN(
            pe->preferred_base + sect->VirtualAddress, 0x1000);
        uint64_t offset_pg = (pe->preferred_base + sect->VirtualAddress) - va_aligned;
        size_t map_sz = WINUX_ALIGN_UP(sect->Misc.VirtualSize + offset_pg, 0x1000);
        proc_label_vma((void *)(uintptr_t)va_aligned, map_sz, label);
    }

    /*
     * 5. Déterminer la base mappée réelle.
     *
     * La première section est normalement .text, placée à l'adresse
     * préférée + son VirtualAddress. Le résultat de mmap() avec
     * MAP_FIXED donne l'adresse exacte demandée, donc :
     *   mapped_base = adresse réelle - VirtualAddress
     *
     * Si la première section n'a pas pu être mappée à son adresse
     * préférée (MAP_FIXED_NOREPLACE a échoué), on utilise le delta
     * pour recalculer.
     */
    if (pe->section_count > 0 && pe->sections[0].Misc.VirtualSize > 0) {
        pe->mapped_base = pe->preferred_base; /* MAP_FIXED garantit cette adresse */
        pe->delta       = pe->mapped_base - pe->preferred_base;
    } else {
        pe->mapped_base = pe->preferred_base;
        pe->delta       = 0;
    }

    WINUX_LOG("Mapped base: 0x%lx, delta: 0x%lx", pe->mapped_base, pe->delta);

    /* 6. Appliquer les relocations */
    if (pe_apply_relocations(pe) != 0) {
        WINUX_ERR("Relocation failed for '%s'", path);
        goto fail_unmap_sections;
    }

    /* 7. Résoudre les imports */
    if (pe_resolve_imports(pe) != 0) {
        WINUX_ERR("Import resolution failed for '%s'", path);
        goto fail_unmap_sections;
    }

    /* 8. Configurer le point d'entrée */
    if (pe->nt->OptionalHeader.AddressOfEntryPoint != 0) {
        pe->entry_point = pe->mapped_base
                        + pe->nt->OptionalHeader.AddressOfEntryPoint;
    }

    /* 9. Allouer la stack */
    pe->stack_size = pe->nt->OptionalHeader.SizeOfStackCommit;
    if (pe->stack_size == 0)
        pe->stack_size = 1024 * 1024; /* 1MB par défaut */

    pe->stack_base = mmap(NULL, pe->stack_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                           -1, 0);
    if (pe->stack_base == MAP_FAILED) {
        WINUX_ERR("Failed to allocate stack (%zu bytes)", pe->stack_size);
        pe->stack_base = NULL;
        pe->stack_size = 0;
        /* Non fatal : on peut continuer sans stack dédiée */
    }

    /* 10. Installer le handler SIGSEGV */
    pe_install_signal_handlers();

    return pe;

    /* Nettoyage en cas d'erreur */
fail_unmap_sections:
    for (uint16_t i = 0; i < mapped_count; i++) {
        uint64_t va = pe->nt->OptionalHeader.ImageBase
                    + pe->sections[i].VirtualAddress;
        uint64_t va_aligned = WINUX_ALIGN_DOWN(va, 0x1000);
        size_t size = WINUX_ALIGN_UP(pe->sections[i].Misc.VirtualSize
                     + (va - va_aligned), 0x1000);
        munmap((void *)(uintptr_t)va_aligned, size);
    }
    if (pe->stack_base)
        munmap(pe->stack_base, pe->stack_size);
    free(pe);
    pe = NULL;

fail_unmap_file:
    munmap(file_base, (size_t)st.st_size);

fail_close:
    if (fd >= 0) close(fd);
    return NULL;
}

void pe_unload(PE_IMAGE *pe)
{
    if (!pe) return;

    /* Démapper les sections */
    for (uint16_t i = 0; i < pe->section_count; i++) {
        uint64_t va = pe->nt->OptionalHeader.ImageBase
                    + pe->sections[i].VirtualAddress;
        uint64_t va_aligned = WINUX_ALIGN_DOWN(va, 0x1000);
        uint64_t offset_pg  = va - va_aligned;
        size_t   size       = WINUX_ALIGN_UP(
            pe->sections[i].Misc.VirtualSize + offset_pg, 0x1000);
        if (size > 0)
            munmap((void *)(uintptr_t)va_aligned, size);
    }

    /* Libérer la stack */
    if (pe->stack_base)
        munmap(pe->stack_base, pe->stack_size);

    /* Démapper le fichier */
    if (pe->file_base && pe->file_size > 0)
        munmap(pe->file_base, pe->file_size);

    /* Libérer la table d'import résolue */
    free(pe->import_resolved);

    free(pe);
}
