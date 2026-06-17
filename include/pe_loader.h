/*
 * === FICHIER : include/pe_loader.h ===
 * Description : API publique du chargeur PE32+.
 *               Parse, mappe et charge une image PE dans l'espace
 *               d'adressage du processus Linux, résout les relocations
 *               et construit une IAT synthétique.
 * Dépendances : include/winux.h, <sys/mman.h>
 */

#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "winux.h"

/*
 * Charge un fichier PE depuis le disque.
 * - Mappe le fichier en lecture seule avec mmap
 * - Parse les en-têtes DOS, NT, sections
 * - Mappe les sections en mémoire aux adresses PE virtuelles
 * - Applique les relocations si le delta != 0
 * - Résout les imports via la table IAT synthétique
 *
 * Retourne un pointeur sur PE_IMAGE alloué dynamiquement, ou NULL.
 * En cas d'échec, l'erreur est loggée et errno est positionné.
 */
PE_IMAGE *pe_load(const char *path);

/*
 * Libère toutes les ressources associées à une image PE :
 * - Démappe les sections
 * - Démappe le fichier
 * - Libère la stack
 * - Libère la table d'import
 * - Libère la structure PE_IMAGE
 */
void pe_unload(PE_IMAGE *pe);

/*
 * Récupère l'adresse de l'entrée du PE (entry point VA absolue).
 * Cette fonction est le pointeur de fonction que le launcher
 * appellera pour démarrer le processus Windows.
 */
static inline void *pe_entry_point(const PE_IMAGE *pe)
{
    if (!pe || !pe->entry_point) return NULL;
    return (void *)(uintptr_t)pe->entry_point;
}

/*
 * Récupère le pointeur sur le PEB synthétique (mis en place
 * par le thread model plus tard). Pour l'instant, retourne NULL.
 */
static inline void *pe_get_peb(const PE_IMAGE *pe)
{
    WINUX_UNUSED(pe);
    return NULL; /* Sera implémenté dans thread_model.c */
}

#endif /* PE_LOADER_H */
