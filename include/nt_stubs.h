/*
 * === FICHIER : include/nt_stubs.h ===
 * Description : Prototypes des stubs NT (ntdll.dll).
 *               Chaque fonction est compilée avec l'ABI Microsoft x64
 *               (__attribute__((ms_abi))) pour que le code PE puisse
 *               les appeler directement.
 * Dépendances : include/winux.h
 */

#ifndef NT_STUBS_H
#define NT_STUBS_H

#include "winux.h"
#include <pthread.h>

/* ==========================================================================
   Structures NT spécifiques
   ========================================================================== */

#pragma pack(push, 1)

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING *ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _USER_STACK {
    PVOID   FixedStackBase;
    PVOID   FixedStackLimit;
    PVOID   ExpandableStackBase;
    PVOID   ExpandableStackLimit;
    PVOID   ExpandableStackBottom;
} USER_STACK;

typedef struct _INITIAL_TEB {
    PVOID       OldInitialTebOpaque;
    PVOID       StackBase;
    PVOID       StackLimit;
    PVOID       StackAllocationBase;
    /* Le reste est opaque / non utilisé pour l'instant */
} INITIAL_TEB;

#pragma pack(pop)

typedef IO_STATUS_BLOCK  *PIO_STATUS_BLOCK;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CLIENT_ID         *PCLIENT_ID;
typedef INITIAL_TEB       *PINITIAL_TEB;

/* ==========================================================================
   Stubs NT principaux
   ========================================================================== */

/*
 * NtCreateFile : ouvre/crée un fichier.
 * Traduit le chemin Windows → Linux via io_translate_path(),
 * convertit les flags GENERIC_READ/WRITE → O_RDONLY/O_WRONLY/O_RDWR,
 * et enregistre le fd Linux dans la table io_handles.
 */
WINAPI NTSTATUS NtCreateFile(
    HANDLE            *FileHandle,
    ULONG              DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    int64_t           *AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);

/*
 * NtReadFile : lit depuis un handle fichier/pipe/console.
 */
WINAPI NTSTATUS NtReadFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    int64_t         *ByteOffset,
    ULONG           *Key
);

/*
 * NtWriteFile : écrit vers un handle fichier/pipe/console.
 */
WINAPI NTSTATUS NtWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    int64_t         *ByteOffset,
    ULONG           *Key
);

/*
 * NtClose : ferme un handle (fichier, pipe, thread, etc.).
 */
WINAPI NTSTATUS NtClose(HANDLE Handle);

/*
 * NtAllocateVirtualMemory : équivalent de mmap(MAP_ANONYMOUS).
 */
WINAPI NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID    *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T   *RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

/*
 * NtFreeVirtualMemory : équivalent de munmap().
 */
WINAPI NTSTATUS NtFreeVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    SIZE_T *RegionSize,
    ULONG   FreeType
);

/*
 * NtProtectVirtualMemory : équivalent de mprotect().
 */
WINAPI NTSTATUS NtProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    SIZE_T *RegionSize,
    ULONG   NewProtect,
    ULONG  *OldProtect
);

/*
 * NtCreateThread : crée un thread via pthread_create().
 */
WINAPI NTSTATUS NtCreateThread(
    HANDLE           *ThreadHandle,
    ULONG             DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE             ProcessHandle,
    PCLIENT_ID        ClientId,
    PVOID             ThreadContext,
    PINITIAL_TEB      InitialTeb,
    BOOL              CreateSuspended
);

/*
 * NtTerminateProcess : termine le processus via exit().
 */
WINAPI NTSTATUS NtTerminateProcess(
    HANDLE   ProcessHandle,
    NTSTATUS ExitStatus
);

/*
 * NtTerminateThread : termine le thread courant.
 */
WINAPI NTSTATUS NtTerminateThread(
    HANDLE   ThreadHandle,
    NTSTATUS ExitStatus
);

/*
 * NtWaitForSingleObject : attente sur un handle (simplifié : sleep/usleep).
 */
WINAPI NTSTATUS NtWaitForSingleObject(
    HANDLE   Handle,
    BOOL     Alertable,
    int64_t *Timeout
);

/*
 * NtDelayExecution : met le thread en attente (usleep).
 */
WINAPI NTSTATUS NtDelayExecution(
    BOOL    Alertable,
    int64_t *Interval
);

/*
 * NtQueryInformationFile : récupère des infos sur un fichier.
 */
WINAPI NTSTATUS NtQueryInformationFile(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass
);

/*
 * NtSetInformationFile : modifie des attributs de fichier.
 */
WINAPI NTSTATUS NtSetInformationFile(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass
);

/*
 * NtDeviceIoControlFile : ioctl générique (stub partiel).
 */
WINAPI NTSTATUS NtDeviceIoControlFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
);

/*
 * NtQueryDirectoryFile : énumère le contenu d'un répertoire.
 */
WINAPI NTSTATUS NtQueryDirectoryFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass,
    BOOL             ReturnSingleEntry,
    UNICODE_STRING  *FileName,
    BOOL             RestartScan
);

/*
 * NtFlushBuffersFile : fsync() le fd associé.
 */
WINAPI NTSTATUS NtFlushBuffersFile(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
);

#endif /* NT_STUBS_H */
