/*
 * === FICHIER : include/seccomp_filter.h ===
 * Description : API publique du filtre seccomp BPF.
 *               Restreint les appels système disponibles après
 *               le chargement du PE, pour limiter la surface
 *               d'attaque du code Windows exécuté.
 *
 * Dépendances : <seccomp.h> (libseccomp, lien -lseccomp)
 */

#ifndef SECCOMP_FILTER_H
#define SECCOMP_FILTER_H

#include "winux.h"
#include <seccomp.h>

/*
 * Installe un filtre seccomp BPF qui restreint les syscalls
 * à la whitelist dérivée de l'implémentation actuelle.
 *
 * Toute syscall non whitelistée → SIGSYS → log + kill.
 * ioctl est restreint à TIOCGWINSZ et FIONREAD uniquement.
 *
 * Paramètre :
 *   pe_loaded : si false, le filtre est moins restrictif (debug).
 *
 * Retourne 0 en cas de succès, -1 en cas d'échec.
 */
int seccomp_filter_install(bool pe_loaded);

/*
 * Vérifie si le filtre seccomp est actif.
 */
bool seccomp_filter_is_active(void);

#endif /* SECCOMP_FILTER_H */
