/*
 * === FICHIER : include/winux.h ===
 * Description : Types communs, structures PE, codes d'erreur et constantes
 *                pour le projet Winux — exécuteur Windows natif sur Linux.
 * Dépendances Linux : <stdint.h> <stddef.h> <stdbool.h>
 */

#ifndef WINUX_H
#define WINUX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

/* ==========================================================================
   Types Windows de base
   ========================================================================== */

typedef uint8_t     BYTE;
typedef uint16_t    WORD;
typedef uint32_t    DWORD;
typedef uint64_t    QWORD;
typedef int32_t     LONG;
typedef uint32_t    ULONG;
typedef uint64_t    ULONGLONG;
typedef void       *PVOID;
typedef void       *LPVOID;
typedef const void *LPCVOID;
typedef char       *LPSTR;
typedef const char *LPCSTR;
typedef uint16_t   *LPWSTR;
typedef const uint16_t *LPCWSTR;
typedef void       *HANDLE;
typedef uint64_t    ULONG_PTR;
typedef int64_t     LONG_PTR;
typedef uint32_t    NTSTATUS;
typedef uint32_t    HRESULT;
typedef size_t      SIZE_T;
typedef uint32_t    BOOL;
typedef unsigned int UINT;

#define FALSE 0
#define TRUE  1

/* ==========================================================================
   Codes NTSTATUS — statuts de retour de l'API NT native
   ========================================================================== */

#define STATUS_SUCCESS                    0x00000000
#define STATUS_NOT_IMPLEMENTED            0xC0000002
#define STATUS_INVALID_PARAMETER          0xC000000D
#define STATUS_ACCESS_DENIED              0xC0000022
#define STATUS_UNSUCCESSFUL               0xC0000001
#define STATUS_NO_MEMORY                  0xC0000017
#define STATUS_INVALID_HANDLE             0xC0000008
#define STATUS_OBJECT_NAME_NOT_FOUND      0xC0000034
#define STATUS_OBJECT_NAME_COLLISION      0xC0000035
#define STATUS_END_OF_FILE                0xC0000011
#define STATUS_FILE_CLOSED                0xC0000128
#define STATUS_NOT_SUPPORTED              0xC00000BB
#define STATUS_DLL_NOT_FOUND              0xC0000135
#define STATUS_ORDINAL_NOT_FOUND          0xC0000138
#define STATUS_ENTRYPOINT_NOT_FOUND       0xC0000139
#define STATUS_INVALID_IMAGE_FORMAT       0xC000007B

/* ==========================================================================
   Constantes magiques PE
   ========================================================================== */

#define IMAGE_DOS_SIGNATURE              0x5A4D      /* "MZ" */
#define IMAGE_NT_SIGNATURE               0x00004550  /* "PE\0\0" */
#define IMAGE_SIZEOF_SHORT_NAME          8

/* Machine types */
#define IMAGE_FILE_MACHINE_AMD64         0x8664
#define IMAGE_FILE_MACHINE_I386          0x014C

/* PE characteristics */
#define IMAGE_FILE_RELOCS_STRIPPED       0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE      0x0002
#define IMAGE_FILE_LARGE_ADDRESS_AWARE   0x0020
#define IMAGE_FILE_32BIT_MACHINE         0x0100
#define IMAGE_FILE_DLL                   0x2000

/* Optional header magic */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC    0x010B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC    0x020B

/* Section characteristics */
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0xC0000000
#define IMAGE_SCN_MEM_DISCARDABLE        0x02000000

/* Directory entry indices */
#define IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define IMAGE_DIRECTORY_ENTRY_IMPORT      1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE    2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION   3
#define IMAGE_DIRECTORY_ENTRY_BASERELOC   5
#define IMAGE_DIRECTORY_ENTRY_TLS         9
#define IMAGE_DIRECTORY_ENTRY_IAT        12

/* Base relocation types */
#define IMAGE_REL_BASED_ABSOLUTE          0
#define IMAGE_REL_BASED_HIGH              1
#define IMAGE_REL_BASED_LOW               2
#define IMAGE_REL_BASED_HIGHLOW           3
#define IMAGE_REL_BASED_DIR64            10

/* ==========================================================================
   Structures du format PE32+
   ========================================================================== */

#pragma pack(push, 1)

typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    ULONGLONG            ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                    Signature;
    IMAGE_FILE_HEADER        FileHeader;
    IMAGE_OPTIONAL_HEADER64  OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER;

/* Import descriptor */
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

/* Import thunk (IAT entry) for PE32+ */
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64;

/* Base relocation block */
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
    /* Suivi de (SizeOfBlock - 8) / 2 entrées WORD */
} IMAGE_BASE_RELOCATION;

#pragma pack(pop)

/* ==========================================================================
   Représentation interne d'une image PE chargée
   ========================================================================== */

typedef struct _PE_IMAGE {
    /* Pointeurs dans le fichier mmapé */
    uint8_t              *file_base;
    size_t                file_size;
    IMAGE_DOS_HEADER     *dos;
    IMAGE_NT_HEADERS64   *nt;

    /* Adresse de base réelle après mapping */
    uint64_t              mapped_base;
    uint64_t              preferred_base;
    uint64_t              delta;            /* mapped_base - preferred_base */

    /* Entrée */
    uint64_t              entry_point;      /* VA absolue */

    /* Sections */
    IMAGE_SECTION_HEADER *sections;
    uint16_t              section_count;

    /* Stack */
    void                 *stack_base;
    size_t                stack_size;

    /* Table d'import résolue (IAT synthétique) */
    void                **import_resolved;
    size_t                import_count;
} PE_IMAGE;

/* ==========================================================================
   Représentation interne d'un handle de fichier
   ========================================================================== */

typedef enum _WINUX_HANDLE_TYPE {
    HANDLE_TYPE_FILE      = 0,
    HANDLE_TYPE_PIPE      = 1,
    HANDLE_TYPE_CONSOLE   = 2,
    HANDLE_TYPE_NULL      = 3,
    HANDLE_TYPE_SOCKET    = 4,
} WINUX_HANDLE_TYPE;

#define WINUX_MAX_HANDLES  4096

typedef struct _WINUX_HANDLE_ENTRY {
    int                linux_fd;
    WINUX_HANDLE_TYPE  type;
    bool               in_use;
    char               win_path[4096];  /* Chemin Windows original */
} WINUX_HANDLE_ENTRY;

/* ==========================================================================
   Codes d'erreur Win32 pour GetLastError/SetLastError
   ========================================================================== */

#define ERROR_SUCCESS              0
#define ERROR_FILE_NOT_FOUND       2
#define ERROR_PATH_NOT_FOUND       3
#define ERROR_ACCESS_DENIED        5
#define ERROR_INVALID_HANDLE       6
#define ERROR_NOT_ENOUGH_MEMORY    8
#define ERROR_INVALID_PARAMETER   87
#define ERROR_PIPE_BUSY          231
#define ERROR_NO_MORE_FILES      259

/* ==========================================================================
   Définitions Win32 courantes
   ========================================================================== */

#define INVALID_HANDLE_VALUE  ((HANDLE)(uintptr_t)-1)

#define GENERIC_READ   0x80000000
#define GENERIC_WRITE  0x40000000

#define FILE_SHARE_READ    0x00000001
#define FILE_SHARE_WRITE   0x00000002
#define FILE_SHARE_DELETE  0x00000004

#define CREATE_NEW         1
#define CREATE_ALWAYS      2
#define OPEN_EXISTING      3
#define OPEN_ALWAYS        4
#define TRUNCATE_EXISTING  5

#define FILE_ATTRIBUTE_NORMAL    0x00000080
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#define FILE_FLAG_OVERLAPPED     0x40000000

#define STD_INPUT_HANDLE   ((DWORD)-10)
#define STD_OUTPUT_HANDLE  ((DWORD)-11)
#define STD_ERROR_HANDLE   ((DWORD)-12)

#define INFINITE          0xFFFFFFFF

#define WAIT_OBJECT_0     0
#define WAIT_TIMEOUT      0x00000102
#define WAIT_FAILED       0xFFFFFFFF

/* ==========================================================================
   Calling convention Microsoft x64 → Linux
   ========================================================================== */

#ifdef __x86_64__
  #define WINAPI  __attribute__((ms_abi))
#else
  #define WINAPI
#endif

/* ==========================================================================
   Structure commune NT : UNICODE_STRING
   ========================================================================== */

typedef struct _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    uint16_t *Buffer;
} UNICODE_STRING;

/* ==========================================================================
   Statuts NT additionnels
   ========================================================================== */

#define STATUS_BUFFER_OVERFLOW           0x80000005
#define STATUS_BUFFER_TOO_SMALL          0xC0000023
#define STATUS_OBJECT_TYPE_MISMATCH      0xC0000024
#define STATUS_PORT_NOT_SET              0xC0000029
#define STATUS_INFO_LENGTH_MISMATCH      0xC0000004
#define STATUS_OBJECT_PATH_NOT_FOUND     0xC000003A
#define STATUS_OBJECT_PATH_INVALID       0xC0000039
#define STATUS_FILE_IS_A_DIRECTORY       0xC00000BA
#define STATUS_NOT_A_DIRECTORY           0xC0000103
#define STATUS_SHARING_VIOLATION         0xC0000043
#define STATUS_PIPE_NOT_AVAILABLE        0xC00000AC
#define STATUS_PIPE_BUSY                 0xC00000AE
#define STATUS_PIPE_DISCONNECTED         0xC00000B0
#define STATUS_PIPE_CLOSING              0xC00000B1
#define STATUS_PIPE_EMPTY                0xC00000B6
#define STATUS_THREAD_IS_TERMINATING     0xC000004B
#define STATUS_NO_SUCH_FILE              0xC000000F

/* ==========================================================================
   Constantes mémoire NT
   ========================================================================== */

#define MEM_COMMIT            0x00001000
#define MEM_RESERVE           0x00002000
#define MEM_RELEASE           0x00008000
#define MEM_RESET             0x00080000
#define MEM_TOP_DOWN          0x00100000
#define MEM_LARGE_PAGES       0x20000000
#define MEM_FREE              0x00010000

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_GUARD             0x100
#define PAGE_NOCACHE           0x200

/* ==========================================================================
   Constantes IO NT (pour NtCreateFile)
   ========================================================================== */

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005

#define FILE_DIRECTORY_FILE             0x00000001
#define FILE_WRITE_THROUGH              0x00000002
#define FILE_SEQUENTIAL_ONLY            0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING  0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT       0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#define FILE_NON_DIRECTORY_FILE         0x00000040
#define FILE_CREATE_TREE_CONNECTION     0x00000080

#define FILE_OPENED              0x00000001
#define FILE_CREATED             0x00000002
#define FILE_OVERWRITTEN         0x00000003
#define FILE_EXISTS              0x00000004
#define FILE_DOES_NOT_EXIST      0x00000005

#define OBJ_INHERIT             0x00000002
#define OBJ_PERMANENT           0x00000010
#define OBJ_EXCLUSIVE           0x00000020
#define OBJ_CASE_INSENSITIVE    0x00000040
#define OBJ_OPENIF              0x00000080
#define OBJ_OPENLINK            0x00000100
#define OBJ_KERNEL_HANDLE       0x00000200

#define FILE_SHARE_READ          0x00000001
#define FILE_SHARE_WRITE         0x00000002
#define FILE_SHARE_DELETE        0x00000004

#define SYNCHRONIZE              0x00100000
#define DELETE                   0x00010000
#define READ_CONTROL             0x00020000
#define WRITE_DAC                0x00040000
#define WRITE_OWNER              0x00080000
#define GENERIC_ALL              0x10000000
#define GENERIC_EXECUTE          0x20000000
#define MAXIMUM_ALLOWED          0x02000000

/* ==========================================================================
   Codes d'erreur Win32 additionnels
   ========================================================================== */

#define ERROR_BROKEN_PIPE        109
#define ERROR_HANDLE_EOF         38
#define ERROR_PIPE_CONNECTED     535
#define ERROR_NO_DATA            232
#define ERROR_MORE_DATA          234
#define ERROR_IO_PENDING         997
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_MOD_NOT_FOUND      126
#define ERROR_PROC_NOT_FOUND     127
#define ERROR_NOT_READY          21
#define ERROR_READ_FAULT         30
#define ERROR_WRITE_FAULT        29
#define ERROR_NEGATIVE_SEEK      131
#define ERROR_SEEK_ON_DEVICE     132
#define ERROR_ALREADY_EXISTS     183
#define ERROR_FILE_EXISTS        80
#define ERROR_INVALID_NAME       123
#define ERROR_DIRECTORY          267
#define ERROR_CALL_NOT_IMPLEMENTED 120
#define ERROR_INVALID_FLAGS      1004
#define ERROR_NO_UNICODE_TRANSLATION 1113

/* ==========================================================================
   Constantes Heap
   ========================================================================== */

#define HEAP_NO_SERIALIZE        0x00000001
#define HEAP_GENERATE_EXCEPTIONS 0x00000004
#define HEAP_ZERO_MEMORY         0x00000008
#define HEAP_CREATE_ENABLE_EXECUTE 0x00040000

/* ==========================================================================
   Constantes Console
   ========================================================================== */

#define CTRL_C_EVENT         0
#define CTRL_BREAK_EVENT     1
#define CTRL_CLOSE_EVENT     2
#define CTRL_LOGOFF_EVENT    5
#define CTRL_SHUTDOWN_EVENT  6

/* ==========================================================================
   Divers
   ========================================================================== */

#define MAX_PATH_W  260
#define STRING_MAX_LENGTH  4096

/* ==========================================================================
   Macros utilitaires
   ========================================================================== */

#define WINUX_UNUSED(x)        ((void)(x))
#define WINUX_ARRAY_SIZE(a)    (sizeof(a) / sizeof((a)[0]))
#define WINUX_MIN(a, b)        ((a) < (b) ? (a) : (b))
#define WINUX_MAX(a, b)        ((a) > (b) ? (a) : (b))
#define WINUX_ALIGN_UP(x, a)   (((x) + ((a) - 1)) & ~((a) - 1))
#define WINUX_ALIGN_DOWN(x, a) ((x) & ~((a) - 1))

#define WINUX_RVA(pe, va)      ((uint64_t)(pe)->file_base + (uint64_t)(va))
#define WINUX_VA(pe, rva)      ((uint64_t)(pe)->mapped_base + (uint64_t)(rva))

/* Logging conditionnel */
#ifdef WINUX_DEBUG
  #define WINUX_LOG(fmt, ...) \
    fprintf(stderr, "[winux] %s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#else
  #define WINUX_LOG(fmt, ...) ((void)0)
#endif

#define WINUX_ERR(fmt, ...) \
  fprintf(stderr, "[winux] ERROR %s:%d: " fmt ": %s\n", \
          __func__, __LINE__, ##__VA_ARGS__, strerror(errno))

/* ==========================================================================
   Variables globales partagées
   ========================================================================== */

/*
 * Placeholder __thread pour GetLastError/SetLastError.
 * [COMPOSANT 5] : sera remplacé par une lecture/écriture dans le TEB.
 */
extern __thread DWORD _last_error;

/*
 * Pointeur de résolution d'import — assigné par win32_bridge.c
 * et utilisé par pe_loader.c pour résoudre les entrées IAT.
 */
extern void *(*winux_import_resolver)(const char *dll, const char *func);

/* Chemin de l'exécutable PE chargé (pour GetModuleFileNameA) */
extern char g_loaded_exe_path[4096];

extern HANDLE  winux_handles[WINUX_MAX_HANDLES];
extern HANDLE  winux_process_heap;

/* ==========================================================================
   Prototypes globaux
   ========================================================================== */

void winux_set_last_error(DWORD err);
DWORD winux_get_last_error(void);

#endif /* WINUX_H */
