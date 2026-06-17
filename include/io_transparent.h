/*
 * === FICHIER : include/io_transparent.h ===
 * Description : API publique de la couche de transparence I/O.
 *               Gère la table de handles, la traduction de chemins
 *               Windows → Linux, et la création de pipes.
 * Dépendances : include/winux.h
 */

#ifndef IO_TRANSPARENT_H
#define IO_TRANSPARENT_H

#include "winux.h"

/*
 * Initialise la couche I/O :
 * - Alloue la table de handles globale
 * - Associe stdin/stdout/stderr aux handles 0/1/2
 * - Charge la table de traduction de chemins depuis .winexec_paths
 *
 * Retourne 0 en cas de succès, -1 en cas d'erreur.
 */
int io_init(void);

/*
 * Libère les ressources de la couche I/O :
 * - Ferme tous les handles encore ouverts
 * - Libère la table de traduction
 */
void io_shutdown(void);

/*
 * Traduit un chemin Windows (C:\Users\...) en chemin Linux (/home/...)
 * en utilisant la table de traduction configurable.
 *
 * Si aucune règle ne correspond, applique la règle par défaut :
 *   C:\Users\<user>  → /home/<user>
 *   C:\              → chemin courant
 *   D:\              → /mnt/d (si existe)
 *
 * La chaîne out doit faire au moins PATH_MAX (4096) octets.
 * Retourne l'adresse de out, ou NULL si la traduction échoue.
 */
char *io_translate_path(const char *win_path, char *out, size_t out_size);

/*
 * Enregistre un handle dans la table globale.
 * Retourne l'index du handle (>= 0) ou -1 si la table est pleine.
 * Le handle 0 est réservé pour stdin, 1 pour stdout, 2 pour stderr.
 */
int io_register_handle(int linux_fd, WINUX_HANDLE_TYPE type, const char *win_path);

/*
 * Libère un handle de la table globale et ferme le fd associé.
 * Retourne 0 en cas de succès, -1 si le handle n'existe pas.
 */
int io_close_handle(int handle_index);

/*
 * Récupère l'entrée de la table de handles pour un index donné.
 * Retourne NULL si le handle n'existe pas ou est invalide.
 */
WINUX_HANDLE_ENTRY *io_get_handle(int handle_index);

/*
 * Crée un pipe Windows (anonyme) en utilisant pipe(2) Linux.
 * Les handles lecture/écriture sont enregistrés dans la table.
 * Retourne 0 en cas de succès, -1 en cas d'erreur.
 */
int io_create_pipe(HANDLE *h_read, HANDLE *h_write, uint32_t pipe_size);

/*
 * Affiche tous les handles actifs (debug).
 */
void io_dump_handles(void);

#endif /* IO_TRANSPARENT_H */
