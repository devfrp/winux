/*
 * === FICHIER : registry.c ===
 * Description : Implémentation du registre Windows HKCU.
 *               Stockage JSON arborescent dans $HOME/.winux/registry.json.
 *               Parser JSON minimaliste intégré (sans dépendances externes).
 */

#include "include/winux.h"
#include "include/registry.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

static REGISTRY_NODE *g_root = NULL;
static bool g_dirty = false;

static char *reg_dir_path(void)
{
    static char path[4096];
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(path, sizeof(path), "%.4000s/.winux", home);
    mkdir(path, 0755);
    return path;
}

static char *reg_file_path(void)
{
    static char path[4128];
    int n = snprintf(path, sizeof(path), "%s/registry.json", reg_dir_path());
    (void)n;
    return path;
}

/* ==========================================================================
   Parser JSON minimaliste
   ========================================================================== */

static char *json_skip_ws(char *p)
{
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static char *json_parse_string(char *p, char *out, size_t out_size)
{
    if (*p != '"') return NULL;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_size) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
            case '"': out[i++] = '"'; break;
            case '\\': out[i++] = '\\'; break;
            case 'n': out[i++] = '\n'; break;
            case 't': out[i++] = '\t'; break;
            case 'r': out[i++] = '\r'; break;
            default: out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    if (*p == '"') p++;
    return p;
}

static REGISTRY_NODE *reg_node_create(const char *name)
{
    REGISTRY_NODE *n = calloc(1, sizeof(REGISTRY_NODE));
    if (!n) return NULL;
    n->name = name ? strdup(name) : NULL;
    n->value = NULL;
    n->children = NULL;
    n->child_count = 0;
    n->child_capacity = 0;
    n->next = NULL;
    return n;
}

static void reg_node_free(REGISTRY_NODE *n)
{
    if (!n) return;
    free(n->name);
    free(n->value);
    for (int i = 0; i < n->child_count; i++)
        reg_node_free(&n->children[i]);
    free(n->children);
    free(n);
}

static REGISTRY_NODE *reg_node_find_child(REGISTRY_NODE *parent, const char *name)
{
    for (int i = 0; i < parent->child_count; i++)
        if (strcasecmp(parent->children[i].name, name) == 0)
            return &parent->children[i];
    return NULL;
}

static REGISTRY_NODE *reg_node_get_path(REGISTRY_NODE *root, const char *path, int create)
{
    if (!path || !*path) return root;
    char buf[4096];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    REGISTRY_NODE *cur = root;
    char *saveptr;
    char *token = strtok_r(buf, "\\", &saveptr);
    while (token) {
        REGISTRY_NODE *child = reg_node_find_child(cur, token);
        if (!child) {
            if (!create) return NULL;
            if (cur->child_count >= cur->child_capacity) {
                int new_cap = cur->child_capacity ? cur->child_capacity * 2 : 4;
                REGISTRY_NODE *arr = realloc(cur->children, (size_t)new_cap * sizeof(REGISTRY_NODE));
                if (!arr) return NULL;
                cur->children = arr;
                cur->child_capacity = new_cap;
            }
            child = &cur->children[cur->child_count++];
            memset(child, 0, sizeof(REGISTRY_NODE));
            child->name = strdup(token);
        }
        cur = child;
        token = strtok_r(NULL, "\\", &saveptr);
    }
    return cur;
}

static char *json_parse_node(char *p, REGISTRY_NODE *parent)
{
    p = json_skip_ws(p);
    if (!p || *p != '{') return p ? p : NULL;
    p++;
    while (1) {
        p = json_skip_ws(p);
        if (!p) return NULL;
        if (*p == '}') { p++; return p; }
        if (*p == ',') { p++; continue; }

        char key[4096];
        p = json_parse_string(p, key, sizeof(key));
        if (!p) return NULL;

        p = json_skip_ws(p);
        if (!p || *p != ':') return NULL;
        p++;
        p = json_skip_ws(p);
        if (!p) return NULL;

        if (*p == '{') {
            REGISTRY_NODE *child = reg_node_get_path(parent, key, 1);
            p = json_parse_node(p, child);
            if (!p) return NULL;
        } else if (*p == '"') {
            char val[4096];
            p = json_parse_string(p, val, sizeof(val));
            if (!p) return NULL;
            REGISTRY_NODE *child = reg_node_get_path(parent, key, 1);
            if (child) {
                free(child->value);
                child->value = strdup(val);
            }
        } else {
            while (*p && *p != ',' && *p != '}' && *p != ']') p++;
        }
    }
}

static void json_serialize_node(FILE *f, REGISTRY_NODE *node, int indent)
{
    if (!node) return;
    bool has_children = (node->child_count > 0);
    bool has_value = (node->value && node->value[0]);

    if (!has_children && !has_value) return;

    fprintf(f, "{\n");
    bool first = true;

    if (has_value) {
        for (int j = 0; j < indent + 2; j++) fputc(' ', f);
        fprintf(f, "\"@\": \"");
        for (const char *c = node->value; *c; c++) {
            if (*c == '"' || *c == '\\') fputc('\\', f);
            fputc(*c, f);
        }
        fprintf(f, "\"");
        first = false;
    }

    for (int i = 0; i < node->child_count; i++) {
        REGISTRY_NODE *c = &node->children[i];
        if (!c->name) continue;
        if (!first) fprintf(f, ",\n");
        for (int j = 0; j < indent + 2; j++) fputc(' ', f);
        fprintf(f, "\"%s\": ", c->name);
        json_serialize_node(f, c, indent + 2);
        first = false;
    }

    if (!first) fprintf(f, "\n");
    for (int j = 0; j < indent; j++) fputc(' ', f);
    fprintf(f, "}");
}

static int reg_load(void)
{
    struct stat st;
    const char *path = reg_file_path();
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    if (st.st_size <= 0) { close(fd); return -1; }

    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return -1; }
    ssize_t nr = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (nr <= 0) { free(buf); return -1; }
    buf[nr] = '\0';

    char *p = buf;
    p = json_skip_ws(p);
    if (p && *p == '{') {
        json_parse_node(p, g_root);
    }
    free(buf);
    return 0;
}

/* ==========================================================================
   API publique
   ========================================================================== */

int reg_init(void)
{
    if (g_root) return 0;
    g_root = reg_node_create("HKCU");
    if (!g_root) return -1;
    reg_load();
    g_dirty = false;
    return 0;
}

void reg_shutdown(void)
{
    reg_save();
    reg_node_free(g_root);
    g_root = NULL;
}

REGISTRY_NODE *reg_open_key(const char *path, DWORD access, int create)
{
    (void)access;
    if (!g_root) return NULL;
    return reg_node_get_path(g_root, path, create);
}

void reg_close_key(REGISTRY_NODE *node)
{
    (void)node;
}

int reg_query_value(REGISTRY_NODE *node, const char *value_name,
                    DWORD *type, void *data, DWORD *data_size)
{
    if (!node) return ERROR_BADKEY;

    const char *val = NULL;
    if (!value_name || !*value_name) {
        val = node->value;
    } else {
        REGISTRY_NODE *child = reg_node_find_child(node, value_name);
        if (child) val = child->value;
    }

    if (!val) return ERROR_FILE_NOT_FOUND;

    DWORD len = (DWORD)strlen(val) + 1;
    if (type) *type = REG_SZ;

    if (!data || !data_size || *data_size < len) {
        if (data_size) *data_size = len;
        return ERROR_MORE_DATA;
    }

    memcpy(data, val, len);
    if (data_size) *data_size = len;
    return ERROR_SUCCESS;
}

int reg_set_value(REGISTRY_NODE *node, const char *value_name,
                  DWORD type, const void *data, DWORD data_size)
{
    char num_buf[64];
    const char *str;
    if (!node) return ERROR_BADKEY;
    if (!data || data_size == 0) return ERROR_INVALID_PARAMETER;

    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        str = (const char *)data;
    } else if (type == REG_DWORD && data_size >= 4) {
        snprintf(num_buf, sizeof(num_buf), "%u", *(const DWORD *)data);
        str = num_buf;
    } else {
        return ERROR_INVALID_PARAMETER;
    }

    if (!value_name || !*value_name) {
        free(node->value);
        node->value = strdup(str);
    } else {
        REGISTRY_NODE *child = reg_node_find_child(node, value_name);
        if (!child) {
            child = reg_node_get_path(node, value_name, 1);
        }
        if (child) {
            free(child->value);
            child->value = strdup(str);
        } else {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    g_dirty = true;
    reg_save();
    return ERROR_SUCCESS;
}

int reg_save(void)
{
    if (!g_root || !g_dirty) return 0;
    FILE *f = fopen(reg_file_path(), "w");
    if (!f) return -1;
    json_serialize_node(f, g_root, 0);
    fprintf(f, "\n");
    fclose(f);
    g_dirty = false;
    return 0;
}

/* ==========================================================================
   kernel32.dll — RegOpenKeyExA
   ========================================================================== */

WINAPI LONG kernel32_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
                                    DWORD samDesired, HKEY *phkResult)
{
    (void)ulOptions;

    if (!phkResult) return ERROR_INVALID_PARAMETER;
    *phkResult = NULL;

    if (hKey != HKEY_CURRENT_USER && hKey != HKEY_LOCAL_MACHINE)
        return ERROR_FILE_NOT_FOUND;

    REGISTRY_NODE *node = reg_open_key(lpSubKey ? lpSubKey : "", samDesired, 0);
    if (!node) return ERROR_FILE_NOT_FOUND;

    *phkResult = (HKEY)node;
    return ERROR_SUCCESS;
}

WINAPI LONG kernel32_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName,
                                       DWORD *lpReserved, DWORD *lpType,
                                       BYTE *lpData, DWORD *lpcbData)
{
    (void)lpReserved;
    REGISTRY_NODE *node = (REGISTRY_NODE *)hKey;
    return reg_query_value(node, lpValueName, lpType, lpData, lpcbData);
}

WINAPI LONG kernel32_RegSetValueExA(HKEY hKey, LPCSTR lpValueName,
                                     DWORD Reserved, DWORD dwType,
                                     const BYTE *lpData, DWORD cbData)
{
    (void)Reserved;
    REGISTRY_NODE *node = (REGISTRY_NODE *)hKey;
    return reg_set_value(node, lpValueName, dwType, lpData, cbData);
}

WINAPI LONG kernel32_RegCloseKey(HKEY hKey)
{
    reg_close_key((REGISTRY_NODE *)hKey);
    return ERROR_SUCCESS;
}

WINAPI LONG kernel32_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved,
                                      LPSTR lpClass, DWORD dwOptions,
                                      DWORD samDesired, void *lpSecurityAttributes,
                                      HKEY *phkResult, DWORD *lpdwDisposition)
{
    (void)Reserved;
    (void)lpClass;
    (void)dwOptions;
    (void)lpSecurityAttributes;

    if (!phkResult) return ERROR_INVALID_PARAMETER;
    *phkResult = NULL;

    if (hKey != HKEY_CURRENT_USER) return ERROR_FILE_NOT_FOUND;

    REGISTRY_NODE *node = reg_open_key(lpSubKey ? lpSubKey : "", samDesired, 1);
    if (!node) return ERROR_NOT_ENOUGH_MEMORY;

    *phkResult = (HKEY)node;
    if (lpdwDisposition) *lpdwDisposition = 1; /* REG_CREATED_NEW_KEY */
    return ERROR_SUCCESS;
}
