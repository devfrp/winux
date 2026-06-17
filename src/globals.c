/*
 * === FICHIER : globals.c ===
 * Description : Variables globales partagées par tous les composants Winux.
 *               _last_error (fallback __thread) pour GetLastError/SetLastError,
 *               et le pointeur de résolution d'import utilisé par pe_loader.c
 * Dépendances : include/winux.h, include/thread_model.h
 */

#include "include/winux.h"
#include "include/thread_model.h"

/*
 * Fallback __thread pour GetLastError / SetLastError.
 *
 * [COMPOSANT 5] : ce __thread sert UNIQUEMENT de fallback pendant
 * l'initialisation (avant thread_model_init). Une fois le TEB
 * synthétique actif, winux_set_last_error / winux_get_last_error
 * lisent/écrivent dans teb->LastErrorValue via GS segment.
 */
__thread DWORD _last_error = ERROR_SUCCESS;

/* Pointeur de résolution d'import — assigné par win32_bridge.c */
void *(*winux_import_resolver)(const char *dll, const char *func) = NULL;

/* Chemin de l'exécutable PE chargé — stocké par winexec.c, lu par GetModuleFileNameA */
char g_loaded_exe_path[4096] = {0};

void winux_set_last_error(DWORD err)
{
    winux_teb_set_last_error(err);  /* délègue au TEB (avec fallback __thread) */
}

DWORD winux_get_last_error(void)
{
    return winux_teb_get_last_error();  /* délègue au TEB (avec fallback __thread) */
}
