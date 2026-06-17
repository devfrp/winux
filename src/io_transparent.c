/*
 * === FICHIER : io_transparent.c ===
 * Description : Couche de transparence I/O.
 *               Gère la table de handles Windows → fd Linux,
 *               la traduction de chemins (C:\Users → /home),
 *               et la création de pipes anonymes.
 *
 * Dépendances Linux : open(2), close(2), read(2), write(2), pipe(2),
 *                      fcntl(2), unistd(2), <linux/limits.h>
 *
 * Architecture :
 *   - Table de handles statique de 4096 entrées
 *   - Les handles 0/1/2 sont pré-alloués pour stdin/stdout/stderr
 *   - La traduction de chemins utilise un fichier de config .winexec_paths
 *     dans le répertoire courant, avec une règle par ligne au format :
 *       C:\Users  → /home
 *       D:\       → /mnt/d
 *   - Si aucun fichier .winexec_paths n'existe, règles par défaut :
 *     C:\Users\<username> → /home/<username>
 *     C:\                 → répertoire courant
 */

#include "include/winux.h"
#include "include/io_transparent.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>

/* ==========================================================================
   État global de la couche I/O
   ========================================================================== */

/*
 * Table de handles Windows → fd Linux.
 * Index 0 = stdin, 1 = stdout, 2 = stderr (handles standard Windows).
 * Les handles 3..4095 sont disponibles pour les fichiers/pipes.
 */
static WINUX_HANDLE_ENTRY  io_handles[WINUX_MAX_HANDLES];
static bool                io_initialized = false;

/*
 * Table de traduction de chemins.
 * Chaque entrée : préfixe Windows → préfixe Linux.
 * Chargée depuis .winexec_paths au démarrage.
 */
#define MAX_PATH_RULES  64

typedef struct {
    char win_prefix[256];
    char linux_prefix[256];
} PATH_RULE;

static PATH_RULE  path_rules[MAX_PATH_RULES];
static int        path_rule_count = 0;

/* ==========================================================================
   Gestion des handles
   ========================================================================== */

/*
 * Initialise la table de handles et associe stdin/stdout/stderr.
 *
 * Stratégie : on duplique les fd 0/1/2 pour que les processus Windows
 * puissent les fermer sans affecter notre propre stdin/stdout/stderr.
 * Les handles résultants pointent vers les mêmes fichiers sous-jacents
 * mais sont indépendants.
 */
int io_init(void)
{
    if (io_initialized) return 0;

    memset(io_handles, 0, sizeof(io_handles));
    io_initialized = true;

    /* Handle 0 = STD_INPUT_HANDLE */
    io_handles[0].linux_fd = dup(STDIN_FILENO);
    io_handles[0].type     = HANDLE_TYPE_CONSOLE;
    io_handles[0].in_use   = true;
    snprintf(io_handles[0].win_path, sizeof(io_handles[0].win_path), "CONIN$");

    /* Handle 1 = STD_OUTPUT_HANDLE */
    io_handles[1].linux_fd = dup(STDOUT_FILENO);
    io_handles[1].type     = HANDLE_TYPE_CONSOLE;
    io_handles[1].in_use   = true;
    snprintf(io_handles[1].win_path, sizeof(io_handles[1].win_path), "CONOUT$");

    /* Handle 2 = STD_ERROR_HANDLE */
    io_handles[2].linux_fd = dup(STDERR_FILENO);
    io_handles[2].type     = HANDLE_TYPE_CONSOLE;
    io_handles[2].in_use   = true;
    snprintf(io_handles[2].win_path, sizeof(io_handles[2].win_path), "CONERR$");

    /* Charger les règles de traduction de chemins */
    io_translate_path("", NULL, 0); /* Force le chargement de .winexec_paths */

    WINUX_LOG("I/O layer initialized: stdin=%d stdout=%d stderr=%d, %d path rules loaded",
              io_handles[0].linux_fd, io_handles[1].linux_fd,
              io_handles[2].linux_fd, path_rule_count);

    return 0;
}

void io_shutdown(void)
{
    if (!io_initialized) return;

    /* Fermer tous les handles encore ouverts */
    for (int i = 0; i < WINUX_MAX_HANDLES; i++) {
        if (io_handles[i].in_use && io_handles[i].linux_fd >= 0) {
            close(io_handles[i].linux_fd);
        }
        io_handles[i].in_use = false;
    }

    io_initialized = false;
    WINUX_LOG("I/O layer shut down");
}

int io_register_handle(int linux_fd, WINUX_HANDLE_TYPE type,
                        const char *win_path)
{
    if (!io_initialized) {
        if (io_init() != 0) return -1;
    }

    /* Chercher un slot libre (commence après les handles standard) */
    for (int i = 0; i < WINUX_MAX_HANDLES; i++) {
        if (!io_handles[i].in_use) {
            io_handles[i].linux_fd = linux_fd;
            io_handles[i].type     = type;
            io_handles[i].in_use   = true;
            if (win_path) {
                size_t max = sizeof(io_handles[i].win_path) - 1;
                strncpy(io_handles[i].win_path, win_path, max);
                io_handles[i].win_path[max] = '\0';
            } else {
                io_handles[i].win_path[0] = '\0';
            }
            return i;
        }
    }

    WINUX_ERR("Handle table full (%d handles)", WINUX_MAX_HANDLES);
    return -1;
}

int io_close_handle(int handle_index)
{
    if (!io_initialized) return -1;
    if (handle_index < 0 || handle_index >= WINUX_MAX_HANDLES) return -1;
    if (!io_handles[handle_index].in_use) return -1;

    if (io_handles[handle_index].linux_fd >= 0) {
        close(io_handles[handle_index].linux_fd);
    }

    io_handles[handle_index].linux_fd = -1;
    io_handles[handle_index].in_use   = false;
    io_handles[handle_index].win_path[0] = '\0';

    return 0;
}

WINUX_HANDLE_ENTRY *io_get_handle(int handle_index)
{
    if (!io_initialized) {
        if (io_init() != 0) return NULL;
    }
    if (handle_index < 0 || handle_index >= WINUX_MAX_HANDLES) return NULL;
    if (!io_handles[handle_index].in_use) return NULL;

    return &io_handles[handle_index];
}

/* ==========================================================================
   Traduction de chemins Windows → Linux
   ========================================================================== */

/*
 * Charge les règles de traduction depuis .winexec_paths.
 *
 * Format du fichier : une règle par ligne
 *   # commentaire
 *   C:\Users  → /home
 *   D:\       → /mnt/d
 *
 * Le fichier doit être dans le répertoire courant (ou défini par
 * WINUX_PATHS_FILE dans l'environnement).
 *
 * Retourne le nombre de règles chargées.
 */
static int io_load_path_rules(void)
{
    const char *config_file;
    char default_path[PATH_MAX];
    FILE *fp;
    char line[512];
    int count = 0;

    /* Déterminer le fichier de config */
    config_file = getenv("WINUX_PATHS_FILE");
    if (!config_file) {
        if (getcwd(default_path, sizeof(default_path) - 32)) {
            snprintf(default_path + strlen(default_path),
                     sizeof(default_path) - strlen(default_path),
                     "/.winexec_paths");
        } else {
            snprintf(default_path, sizeof(default_path), ".winexec_paths");
        }
        config_file = default_path;
    }

    fp = fopen(config_file, "r");
    if (!fp) {
        /* Pas de fichier de config, utiliser les règles par défaut */
        goto load_defaults;
    }

    while (count < MAX_PATH_RULES && fgets(line, sizeof(line), fp)) {
        char *arrow;
        size_t len;

        /* Supprimer le newline final */
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        if (len > 0 && line[len - 1] == '\r')
            line[--len] = '\0';

        /* Ignorer les lignes vides et commentaires */
        if (len == 0 || line[0] == '#')
            continue;

        /* Chercher la flèche de mapping */
        arrow = strstr(line, "->");
        if (!arrow) {
            /* Essayer le format avec espace */
            arrow = strstr(line, " → ");
        }
        if (!arrow)
            continue;

        /* Extraire le préfixe Windows */
        size_t win_len = (size_t)(arrow - line);
        while (win_len > 0 && line[win_len - 1] == ' ')
            win_len--;
        if (win_len >= sizeof(path_rules[count].win_prefix))
            win_len = sizeof(path_rules[count].win_prefix) - 1;
        memcpy(path_rules[count].win_prefix, line, win_len);
        path_rules[count].win_prefix[win_len] = '\0';

        /* Extraire le préfixe Linux (après la flèche) */
        const char *linux_start = arrow + 2;
        while (*linux_start == ' ' || *linux_start == '\xE2')
            linux_start++;
        if ((unsigned char)*linux_start == 0x86)
            linux_start += 2; /* Sauter les bytes UTF-8 restants de → */
        while (*linux_start == ' ')
            linux_start++;

        size_t lmax = sizeof(path_rules[count].linux_prefix) - 1;
        strncpy(path_rules[count].linux_prefix, linux_start, lmax);
        path_rules[count].linux_prefix[lmax] = '\0';

        WINUX_LOG("Path rule: '%s' -> '%s'",
                  path_rules[count].win_prefix,
                  path_rules[count].linux_prefix);
        count++;
    }

    fclose(fp);
    path_rule_count = count;
    return count;

load_defaults:
    /*
     * Règles par défaut si aucun fichier .winexec_paths n'existe :
     *
     * C:\Users\<user> → /home/<user>
     * C:\             → répertoire courant si rien ne correspond
     */
    {
        const char *home = getenv("HOME");
        const char *user = getenv("USER");
        if (!user) user = "user";
        if (!home) home = "/home/user";

        count = 0;

        /* Règle 1 : C:\Users\<user>  → /home/<user> */
        snprintf(path_rules[count].win_prefix,
                 sizeof(path_rules[count].win_prefix),
                 "C:\\Users\\%s", user);
        snprintf(path_rules[count].linux_prefix,
                 sizeof(path_rules[count].linux_prefix),
                 "/home/%s", user);
        count++;

        /* Règle 2 : C:\tmp  → /tmp (si /tmp existe) */
        {
            struct stat st;
            if (stat("/tmp", &st) == 0 && S_ISDIR(st.st_mode)) {
                strncpy(path_rules[count].win_prefix, "C:\\tmp",
                        sizeof(path_rules[count].win_prefix) - 1);
                strncpy(path_rules[count].linux_prefix, "/tmp",
                        sizeof(path_rules[count].linux_prefix) - 1);
                count++;
            }
        }

        /* Règle 3 : C:\Users  → /home */
        strncpy(path_rules[count].win_prefix, "C:\\Users",
                sizeof(path_rules[count].win_prefix) - 1);
        strncpy(path_rules[count].linux_prefix, "/home",
                sizeof(path_rules[count].linux_prefix) - 1);
        count++;

        /* Règle 3 : C:\  → répertoire courant */
        if (getcwd(path_rules[count].linux_prefix,
                   sizeof(path_rules[count].linux_prefix))) {
            strncpy(path_rules[count].win_prefix, "C:\\",
                    sizeof(path_rules[count].win_prefix) - 1);
            count++;
        }

        /* Règle 4 : D:\  → /mnt/d (si le répertoire existe) */
        {
            struct stat st;
            if (stat("/mnt/d", &st) == 0) {
                strncpy(path_rules[count].win_prefix, "D:\\",
                        sizeof(path_rules[count].win_prefix) - 1);
                strncpy(path_rules[count].linux_prefix, "/mnt/d",
                        sizeof(path_rules[count].linux_prefix) - 1);
                count++;
            }
        }

        path_rule_count = count;
        return count;
    }
}

char *io_translate_path(const char *win_path, char *out, size_t out_size)
{
    /* Chargement lazy des règles */
    if (path_rule_count == 0 && !io_initialized) {
        io_load_path_rules();
    }
    if (path_rule_count == 0 && io_initialized) {
        io_load_path_rules();
    }

    if (!out || out_size == 0)
        return NULL;

    if (!win_path || win_path[0] == '\0') {
        out[0] = '\0';
        return out;
    }

    /*
     * Normaliser le chemin Windows : remplacer \ par / et
     * ignorer la casse pour la comparaison de préfixe.
     */
    char norm_win[PATH_MAX];
    size_t win_len = strlen(win_path);
    if (win_len >= sizeof(norm_win))
        win_len = sizeof(norm_win) - 1;

    memcpy(norm_win, win_path, win_len);
    norm_win[win_len] = '\0';

    /* Remplacer \ par / */
    for (size_t i = 0; i < win_len; i++) {
        if (norm_win[i] == '\\')
            norm_win[i] = '/';
    }

    /*
     * Chercher une règle de traduction qui correspond au préfixe.
     * On compare en ignorant la casse (insensible à la casse).
     */
    for (int i = 0; i < path_rule_count; i++) {
        /* Normaliser aussi le préfixe de la règle */
        char rule_prefix[256];
        size_t rule_len = strlen(path_rules[i].win_prefix);
        if (rule_len >= sizeof(rule_prefix))
            rule_len = sizeof(rule_prefix) - 1;
        memcpy(rule_prefix, path_rules[i].win_prefix, rule_len);
        rule_prefix[rule_len] = '\0';

        for (size_t j = 0; j < rule_len; j++) {
            if (rule_prefix[j] == '\\')
                rule_prefix[j] = '/';
        }

        if (strncasecmp(norm_win, rule_prefix, rule_len) == 0) {
            /*
             * Le préfixe correspond. Construire le chemin Linux :
             * linux_prefix + partie restante du chemin Windows.
             *
             * Exemple :
             *   win:  C:\Users\bob\Documents\file.txt
             *   rule: C:\Users\bob  → /home/bob
             *   rest: /Documents/file.txt
             *   out:  /home/bob/Documents/file.txt
             */
            const char *rest = norm_win + rule_len;

            /* Consommer un éventuel '/' ou '\' au début du reste */
            while (*rest == '/' || *rest == '\\') rest++;

            size_t linux_len = strlen(path_rules[i].linux_prefix);
            size_t rest_len  = strlen(rest);

            if (linux_len + 1 + rest_len >= out_size) {
                WINUX_ERR("Path too long after translation");
                return NULL;
            }

            memcpy(out, path_rules[i].linux_prefix, linux_len);
            if (rest_len > 0 && out[linux_len - 1] != '/' && rest[0] != '/') {
                out[linux_len] = '/';
                linux_len++;
            }
            memcpy(out + linux_len, rest, rest_len + 1); /* +1 pour \0 */

            return out;
        }
    }

    /*
     * Aucune règle trouvée. Stratégie par défaut :
     * Si le chemin commence par une lettre de lecteur (C:\, D:\, etc.),
     * on remplace le préfixe par le répertoire courant.
     */
    if (win_len >= 2 && norm_win[1] == ':') {
        const char *rest = norm_win + 2;
        while (*rest == '/' || *rest == '\\') rest++;

        if (getcwd(out, out_size)) {
            size_t cwd_len = strlen(out);
            size_t rest_len = strlen(rest);

            if (cwd_len + 1 + rest_len < out_size) {
                out[cwd_len] = '/';
                memcpy(out + cwd_len + 1, rest, rest_len + 1);
                return out;
            }
        }
    }

    /*
     * Dernier recours : retourner le chemin tel quel
     * (le fichier n'existe probablement pas, mais l'appelant
     * recevra une erreur ENOENT appropriée).
     */
    if (win_len < out_size) {
        memcpy(out, norm_win, win_len + 1);
        return out;
    }

    errno = ENAMETOOLONG;
    return NULL;
}

/* ==========================================================================
   Création de pipe Windows → pipe(2) Linux
   ========================================================================== */

int io_create_pipe(HANDLE *h_read, HANDLE *h_write, uint32_t pipe_size)
{
    int fds[2];
    int read_handle, write_handle;

    WINUX_UNUSED(pipe_size); /* pipe(2) n'a pas de taille configurable */

    if (!h_read || !h_write) {
        errno = EINVAL;
        return -1;
    }

    /* pipe(2) Linux : fds[0] = lecture, fds[1] = écriture */
    if (pipe(fds) != 0) {
        WINUX_ERR("pipe() failed");
        return -1;
    }

    /* Mettre les deux extrémités en non-blocking optionnel */
    int flags = fcntl(fds[0], F_GETFL, 0);
    if (flags >= 0)
        fcntl(fds[0], F_SETFL, flags & ~O_NONBLOCK); /* blocking par défaut */

    flags = fcntl(fds[1], F_GETFL, 0);
    if (flags >= 0)
        fcntl(fds[1], F_SETFL, flags & ~O_NONBLOCK);

    read_handle  = io_register_handle(fds[0], HANDLE_TYPE_PIPE, "\\\\.\\pipe\\anon");
    write_handle = io_register_handle(fds[1], HANDLE_TYPE_PIPE, "\\\\.\\pipe\\anon");

    if (read_handle < 0 || write_handle < 0) {
        close(fds[0]);
        close(fds[1]);
        if (read_handle >= 0) io_close_handle(read_handle);
        return -1;
    }

    *h_read  = (HANDLE)(uintptr_t)(intptr_t)read_handle;
    *h_write = (HANDLE)(uintptr_t)(intptr_t)write_handle;

    WINUX_LOG("Pipe created: read=%d fd=%d, write=%d fd=%d",
              read_handle, fds[0], write_handle, fds[1]);

    return 0;
}

/* ==========================================================================
   Debug
   ========================================================================== */

void io_dump_handles(void)
{
    fprintf(stderr, "\n[winux] === Handle Table Dump ===\n");
    fprintf(stderr, "[winux] %d path rules loaded\n", path_rule_count);
    for (int i = 0; i < WINUX_MAX_HANDLES; i++) {
        if (io_handles[i].in_use) {
            const char *type_str = "UNKNOWN";
            switch (io_handles[i].type) {
            case HANDLE_TYPE_FILE:    type_str = "FILE";    break;
            case HANDLE_TYPE_PIPE:    type_str = "PIPE";    break;
            case HANDLE_TYPE_CONSOLE: type_str = "CONSOLE"; break;
            case HANDLE_TYPE_NULL:    type_str = "NULL";    break;
            case HANDLE_TYPE_SOCKET:  type_str = "SOCKET";  break;
            }
            fprintf(stderr, "  [%3d] fd=%-4d type=%-7s path=%s\n",
                    i, io_handles[i].linux_fd, type_str, io_handles[i].win_path);
        }
    }
    fprintf(stderr, "[winux] === End Handle Dump ===\n\n");
}
