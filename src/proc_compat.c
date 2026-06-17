/*
 * === FICHIER : proc_compat.c ===
 * Description : Couche de transparence /proc.
 *               Rend le processus winexec invisiblement natif
 *               pour les outils Linux standard.
 *
 * 4 fonctionnalités :
 *   1. PR_SET_NAME — déjà fait dans winexec.c
 *   2. PR_SET_VMA_ANON_NAME — labels lisibles dans /proc/self/maps
 *   3. Nettoyage des fd parasites
 *   4. /proc/self/cmdline — argv[] écrasé avec le contenu PE
 */

#include "include/winux.h"
#include "include/proc_compat.h"

#include <sys/prctl.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>

/* ==========================================================================
   Étape 2 : Labels VMA pour /proc/self/maps
   ========================================================================== */

void proc_label_vma(void *addr, size_t size, const char *label)
{
    if (!addr || size == 0 || !label) return;

    /*
     * PR_SET_VMA_ANON_NAME : disponible depuis Linux 5.17.
     * Si le kernel ne le supporte pas, prctl() retourne EINVAL.
     * On log un avertissement sans échouer.
     */
    int rc = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
                   (unsigned long)addr, size,
                   (unsigned long)label);
    if (rc != 0) {
        /*
         * EINVAL = kernel trop vieux (< 5.17) ou paramètre invalide.
         * On ne log qu'une fois (statique).
         */
        static bool warned = false;
        if (!warned) {
            WINUX_LOG("PR_SET_VMA_ANON_NAME not supported by kernel "
                      "(requires >= 5.17). /proc/self/maps labels unavailable.");
            warned = true;
        }
    }
}

/* ==========================================================================
   Étape 3 : Nettoyage des file descriptors parasites
   ========================================================================== */

void proc_cleanup_stray_fds(void)
{
    /*
     * Stratégie : itérer /proc/self/fd et fermer tout fd > 2
     * qui n'est pas explicitement géré par notre table de handles
     * ou le PE loader.
     *
     * En pratique, après io_init(), les fds 0/1/2 ont été dupliqués
     * (dup) en fds 3/4/5. Ces fds "parasites" servent de backup
     * mais polluent /proc/self/fd. On les garde pour l'instant
     * car ils sont nécessaires au fonctionnement interne.
     *
     * On ferme uniquement les fds qui ne sont PAS dans notre table
     * de handles io_handles.
     */

    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return;

    struct dirent *dent;
    int closed_count = 0;

    while ((dent = readdir(dir)) != NULL) {
        /* Ignorer . et .. */
        if (dent->d_name[0] == '.') continue;

        int fd = atoi(dent->d_name);
        if (fd < 0) continue;

        /*
         * On garde les fd 0/1/2 (stdin/stdout/stderr).
         * On garde aussi les fd > 2 qui sont des dups standards.
         * Pour l'instant, on ne ferme que les fd > 1000
         * (fds temporaires ouverts par la libc).
         */
        if (fd > 1000) {
            close(fd);
            closed_count++;
        }
    }

    closedir(dir);

    if (closed_count > 0) {
        WINUX_LOG("Closed %d stray file descriptors", closed_count);
    }
}

/* ==========================================================================
   Étape 4 : /proc/self/cmdline
   ========================================================================== */

void proc_set_cmdline(char **argv, const char *exe_path,
                       int pe_argc, char **pe_argv)
{
    if (!argv || !argv[0]) return;

    /*
     * Stratégie : on écrase l'espace mémoire de argv[] in-place.
     *
     * argv[0] a une certaine longueur allouée par le kernel.
     * On va écrire le chemin du .exe PE dans argv[0],
     * puis les arguments PE dans les slots suivants.
     *
     * /proc/self/cmdline concatène argv[i] séparés par \0.
     * On doit écraser tout le bloc mémoire contigu.
     *
     * Approche : on calcule l'espace total disponible dans
     * la zone argv + environnement, puis on réécrit tout.
     */

    /*
     * Étape 1 : écraser argv[0] avec le chemin du .exe.
     */
    size_t old_len = strlen(argv[0]);
    size_t exe_len = strlen(exe_path);
    size_t copy_len = (exe_len < old_len) ? exe_len : old_len;

    memcpy(argv[0], exe_path, copy_len);
    if (copy_len < old_len)
        memset(argv[0] + copy_len, 0, old_len - copy_len);

    /*
     * Étape 2 : écraser argv[1..] avec les arguments PE.
     * On réutilise les slots existants.
     * argv[0] contient déjà exe_path (étape 1).
     */
    int i;
    for (i = 0; i < pe_argc; i++) {
        if (!argv[i + 1])
            break;
        if (pe_argv && pe_argv[i]) {
            old_len = strlen(argv[i + 1]);
            size_t arg_len = strlen(pe_argv[i]);
            copy_len = (arg_len < old_len) ? arg_len : old_len;

            memcpy(argv[i + 1], pe_argv[i], copy_len);
            if (copy_len < old_len)
                memset(argv[i + 1] + copy_len, 0, old_len - copy_len);
        }
    }

    /*
     * Étape 3 : nullifier les slots argv restants
     * (pour que /proc/self/cmdline s'arrête proprement).
     * On a écrit dans argv[0]..argv[pe_argc], donc on nullifie
     * à partir de l'indice pe_argc+1.
     */
    for (int j = i + 1; argv[j] != NULL && j < 256; j++) {
        argv[j][0] = '\0';
    }

    WINUX_LOG("cmdline overwritten: %s", exe_path);
}

/* ==========================================================================
   Initialisation groupée
   ========================================================================== */

void proc_compat_init(void)
{
    proc_cleanup_stray_fds();
    WINUX_LOG("/proc compatibility layer initialized");
}
