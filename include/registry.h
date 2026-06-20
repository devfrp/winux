/*
 * === FICHIER : include/registry.h ===
 * Description : API du registre Windows (HKCU).
 *               Stocke le registre HKEY_CURRENT_USER dans
 *               $HOME/.winux/registry.json (JSON arborescent).
 */

#ifndef REGISTRY_H
#define REGISTRY_H

#include "winux.h"
#include <stddef.h>

typedef HANDLE HKEY;

#define HKEY_CLASSES_ROOT     ((HKEY)(uintptr_t)0x80000000)
#define HKEY_CURRENT_USER     ((HKEY)(uintptr_t)0x80000001)
#define HKEY_LOCAL_MACHINE    ((HKEY)(uintptr_t)0x80000002)
#define HKEY_USERS            ((HKEY)(uintptr_t)0x80000003)

#define REG_NONE                       0
#define REG_SZ                         1
#define REG_EXPAND_SZ                  2
#define REG_BINARY                     3
#define REG_DWORD                      4
#define REG_DWORD_LITTLE_ENDIAN        4
#define REG_DWORD_BIG_ENDIAN           5
#define REG_LINK                       6
#define REG_MULTI_SZ                   7
#define REG_QWORD                      11
#define REG_QWORD_LITTLE_ENDIAN        11

#define ERROR_MORE_DATA               234
#define ERROR_BADDB                   1009
#define ERROR_BADKEY                  1010
#define ERROR_CANTOPEN                1011
#define ERROR_CANTREAD                1012
#define ERROR_CANTWRITE               1013
#define ERROR_REGISTRY_RECOVERED      1014
#define ERROR_REGISTRY_CORRUPT        1015
#define ERROR_REGISTRY_IO_FAILED      1016
#define ERROR_NOT_REGISTRY_FILE       1017
#define ERROR_KEY_DELETED             1018

#define KEY_QUERY_VALUE        0x0001
#define KEY_SET_VALUE          0x0002
#define KEY_CREATE_SUB_KEY     0x0004
#define KEY_ENUMERATE_SUB_KEYS 0x0008
#define KEY_READ               0x20019
#define KEY_WRITE              0x20006
#define KEY_ALL_ACCESS         0xF003F

#define REG_OPTION_NON_VOLATILE 0

typedef struct _REGISTRY_NODE {
    char    *name;
    char    *value;
    struct _REGISTRY_NODE *children;
    int      child_count;
    int      child_capacity;
    struct _REGISTRY_NODE *next;
} REGISTRY_NODE;

int reg_init(void);
void reg_shutdown(void);
REGISTRY_NODE *reg_open_key(const char *path, DWORD access, int create);
void reg_close_key(REGISTRY_NODE *node);
int reg_query_value(REGISTRY_NODE *node, const char *value_name,
                    DWORD *type, void *data, DWORD *data_size);
int reg_set_value(REGISTRY_NODE *node, const char *value_name,
                  DWORD type, const void *data, DWORD data_size);
int reg_save(void);

/* kernel32.dll stubs avec ms_abi */
WINAPI LONG kernel32_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
                                    DWORD samDesired, HKEY *phkResult);
WINAPI LONG kernel32_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName,
                                       DWORD *lpReserved, DWORD *lpType,
                                       BYTE *lpData, DWORD *lpcbData);
WINAPI LONG kernel32_RegSetValueExA(HKEY hKey, LPCSTR lpValueName,
                                     DWORD Reserved, DWORD dwType,
                                     const BYTE *lpData, DWORD cbData);
WINAPI LONG kernel32_RegCloseKey(HKEY hKey);
WINAPI LONG kernel32_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved,
                                      LPSTR lpClass, DWORD dwOptions,
                                      DWORD samDesired, void *lpSecurityAttributes,
                                      HKEY *phkResult, DWORD *lpdwDisposition);

#endif /* REGISTRY_H */
