/*
 * === FICHIER : include/signal_passthrough.h ===
 * Description : API publique de la couche de gestion des signaux.
 *               Intercepte SIGSEGV/SIGTERM dans le contexte du code PE
 *               pour fournir un diagnostic ou une terminaison propre.
 *
 * Architecture :
 *   - SIGSEGV dans la plage PE → crash dump (VA, offset, registres)
 *   - SIGSEGV hors plage PE → laisse le handler par défaut
 *     (bug interne winexec)
 *   - SIGTERM → positionne un flag atomique lu par la boucle
 *     principale (pas de longjmp)
 *   - SIGCHLD → ignoré (threads via pthread, pas fork)
 *
 * Dépendances : include/winux.h, <signal.h>, <ucontext.h>
 */

#ifndef SIGNAL_PASSTHROUGH_H
#define SIGNAL_PASSTHROUGH_H

#include "winux.h"
#include <signal.h>
#include <stdatomic.h>

/* ==========================================================================
   Flag atomique pour terminaison propre
   ========================================================================== */

/*
 * Positionné par le handler SIGTERM, lu par la boucle principale
 * du launcher pour appeler ExitProcess(0) dans le contexte PE.
 */
extern atomic_bool winux_terminate_requested;

/* ==========================================================================
   API
   ========================================================================== */

/*
 * Initialise les handlers de signaux.
 * Doit être appelé APRÈS pe_load() pour connaître la plage d'adresses PE.
 *
 * Paramètres :
 *   pe_base  : adresse de base mappée du PE
 *   pe_size  : taille totale de l'image PE (SizeOfImage)
 */
int signal_passthrough_init(uint64_t pe_base, uint64_t pe_size);

/*
 * Restaure les handlers de signaux par défaut.
 */
void signal_passthrough_shutdown(void);

#endif /* SIGNAL_PASSTHROUGH_H */
