/*
 * === FICHIER : include/proc_compat.h ===
 * Description : API publique de la couche de transparence /proc.
 *               Rend le processus winexec invisiblement natif
 *               pour les outils Linux (ps, top, strace, lsof).
 *
 * 4 fonctionnalités :
 *   1. Nom de processus (PR_SET_NAME) — déjà fait dans winexec.c
 *   2. Labels mémoire (/proc/self/maps) — PR_SET_VMA_ANON_NAME
 *   3. Nettoyage des file descriptors parasites
 *   4. /proc/self/cmdline — écrasement de argv[]
 *
 * Dépendances : <sys/prctl.h>, <linux/prctl.h>
 */

#ifndef PROC_COMPAT_H
#define PROC_COMPAT_H

#include "winux.h"

/*
 * PR_SET_VMA_ANON_NAME — kernel >= 5.17
 * Défini manuellement au cas où <linux/prctl.h> ne le déclare pas.
 */
#ifndef PR_SET_VMA
#define PR_SET_VMA              0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME    0
#endif

/* ==========================================================================
   API
   ========================================================================== */

/*
 * Étape 2 : applique un label lisible à une région mémoire anonyme
 * pour /proc/self/maps.
 *
 * Après chaque pe_map_section(), appeler :
 *   proc_label_vma(addr, size, "PE:.text")
 *
 * Kernel minimum : 5.17. Si non supporté, log un avertissement.
 */
void proc_label_vma(void *addr, size_t size, const char *label);

/*
 * Étape 3 : nettoie les file descriptors parasites.
 * Ferme tout fd > 2 qui n'est pas utilisé par le PE loader
 * ou la couche I/O. Appelé après io_init().
 */
void proc_cleanup_stray_fds(void);

/*
 * Étape 4 : écrase argv[] in-place pour que /proc/self/cmdline
 * affiche le chemin Windows et ses arguments.
 *
 * argv        : tableau original (depuis main)
 * exe_path    : chemin du .exe PE
 * pe_argc     : nombre d'arguments PE (depuis la ligne de commande)
 * pe_argv     : arguments PE
 */
void proc_set_cmdline(char **argv, const char *exe_path,
                       int pe_argc, char **pe_argv);

/*
 * Applique toutes les étapes de transparence /proc.
 * Appelé pendant l'initialisation de winexec.
 */
void proc_compat_init(void);

#endif /* PROC_COMPAT_H */
