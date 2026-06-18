/*
 * === FICHIER : nt_stubs.c ===
 * Description : Implémentation des stubs NT (ntdll.dll).
 *               Chaque fonction traduit un appel API NT natif
 *               en appel système Linux équivalent.
 *
 * Dépendances Linux : open(2), read(2), write(2), close(2), mmap(2),
 *                      munmap(2), mprotect(2), fsync(2), pthread_create(3),
 *                      usleep(3), exit(3), fstat(2), lseek(2), getdents(2)
 *
 * Architecture :
 *   - Tous les handles utilisent la table io_handles
 *     (io_register_handle, io_close_handle, io_get_handle)
 *   - Les chemins Windows sont traduits via io_translate_path()
 *   - La variable __thread _last_error (globals.c) sert de placeholder
 *     pour GetLastError/SetLastError jusqu'au TEB synthétique (composant 5)
 *   - Chaque fonction est compilée avec __attribute__((ms_abi))
 *     pour respecter l'ABI Microsoft x64 appelée par le code PE
 */

#include "include/winux.h"
#include "include/nt_stubs.h"
#include "include/io_transparent.h"
#include "include/memory_manager.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

/* ==========================================================================
   Helpers internes — conversion d'erreurs
   ========================================================================== */

/*
 * Convertit errno Linux en NTSTATUS Windows.
 * Mapping approximatif mais suffisant pour la plupart des cas.
 */
static NTSTATUS errno_to_ntstatus(int err)
{
    switch (err) {
    case 0:           return STATUS_SUCCESS;
    case EACCES:      return STATUS_ACCESS_DENIED;
    case EPERM:       return STATUS_ACCESS_DENIED;
    case ENOENT:      return STATUS_OBJECT_NAME_NOT_FOUND;
    case EEXIST:      return STATUS_OBJECT_NAME_COLLISION;
    case EINVAL:      return STATUS_INVALID_PARAMETER;
    case ENOMEM:      return STATUS_NO_MEMORY;
    case EBADF:       return STATUS_INVALID_HANDLE;
    case ENOSPC:      return STATUS_NO_MEMORY;
    case EISDIR:      return STATUS_FILE_IS_A_DIRECTORY;
    case ENOTDIR:     return STATUS_NOT_A_DIRECTORY;
    case ENAMETOOLONG:return STATUS_OBJECT_PATH_INVALID;
    case ENFILE:
    case EMFILE:      return STATUS_NO_MEMORY; /* plus de fd */
    case ENOTTY:      return STATUS_NOT_SUPPORTED;
    case EROFS:       return STATUS_ACCESS_DENIED;
    case ENOSYS:      return STATUS_NOT_IMPLEMENTED;
    case ESPIPE:      return STATUS_NOT_SUPPORTED;
    default:          return STATUS_UNSUCCESSFUL;
    }
}

/*
 * Convertit errno Linux en code d'erreur Win32 (pour SetLastError).
 */
static DWORD errno_to_win32_error(int err)
{
    switch (err) {
    case 0:           return ERROR_SUCCESS;
    case EACCES:      return ERROR_ACCESS_DENIED;
    case EPERM:       return ERROR_ACCESS_DENIED;
    case ENOENT:      return ERROR_FILE_NOT_FOUND;
    case EEXIST:      return ERROR_FILE_EXISTS;
    case EINVAL:      return ERROR_INVALID_PARAMETER;
    case ENOMEM:      return ERROR_NOT_ENOUGH_MEMORY;
    case EBADF:       return ERROR_INVALID_HANDLE;
    case ENOSPC:      return ERROR_NOT_ENOUGH_MEMORY;
    case EISDIR:      return ERROR_DIRECTORY;
    case ENOTDIR:     return ERROR_DIRECTORY;
    case ENAMETOOLONG:return ERROR_INVALID_NAME;
    case ENFILE:
    case EMFILE:      return ERROR_NOT_ENOUGH_MEMORY;
    case ENOSYS:      return ERROR_CALL_NOT_IMPLEMENTED;
    case ESPIPE:      return ERROR_SEEK_ON_DEVICE;
    case EPIPE:       return ERROR_BROKEN_PIPE;
    default:          return ERROR_INVALID_PARAMETER;
    }
}

/* ==========================================================================
   Helpers internes — traduction de flags
   ========================================================================== */

/*
 * Traduit les flags DesiredAccess Windows (GENERIC_READ, GENERIC_WRITE)
 * en flags open(2) Linux (O_RDONLY, O_WRONLY, O_RDWR).
 */
static int access_to_oflags(ULONG DesiredAccess)
{
    int flags = 0;

    if ((DesiredAccess & GENERIC_READ)  && (DesiredAccess & GENERIC_WRITE))
        flags = O_RDWR;
    else if (DesiredAccess & GENERIC_WRITE)
        flags = O_WRONLY;
    else if (DesiredAccess & GENERIC_READ)
        flags = O_RDONLY;
    else
        flags = O_RDONLY; /* fallback */

    return flags;
}

/*
 * Traduit CreateDisposition Windows en flags open(2) Linux.
 */
static int disposition_to_oflags(ULONG CreateDisposition)
{
    switch (CreateDisposition) {
    case FILE_CREATE:        return O_CREAT | O_EXCL;
    case FILE_OPEN:          return 0;
    case FILE_OPEN_IF:       return O_CREAT;
    case FILE_OVERWRITE:     return O_TRUNC;
    case FILE_OVERWRITE_IF:  return O_CREAT | O_TRUNC;
    case FILE_SUPERSEDE:     return O_CREAT | O_TRUNC;
    default:                 return 0;
    }
}

/*
 * Extrait une chaîne C (char*) depuis une UNICODE_STRING (UTF-16LE simplifié).
 * On suppose que les caractères sont en ASCII étendu (0-255) et on
 * ignore proprement le byte haut de chaque uint16_t.
 *
 * Retourne le nombre d'octets écrits dans out (sans le \0 final),
 * ou -1 si out est trop petit.
 */
static int unicode_to_ascii(const UNICODE_STRING *ustr, char *out, size_t out_size)
{
    if (!ustr || !ustr->Buffer || ustr->Length == 0) {
        if (out && out_size > 0) out[0] = '\0';
        return 0;
    }

    uint16_t char_count = ustr->Length / sizeof(uint16_t);
    if (char_count >= out_size)
        char_count = (uint16_t)(out_size - 1);

    for (uint16_t i = 0; i < char_count; i++) {
        uint16_t wc = ustr->Buffer[i];
        out[i] = (char)(wc & 0xFF); /* ASCII étendu : on prend le byte bas */
    }
    out[char_count] = '\0';
    return (int)char_count;
}

/* ==========================================================================
   NtCreateFile
   ========================================================================== */

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
)
{
    char win_path[4096] = {0};
    char linux_path[4096] = {0};
    int oflags, fd, handle_idx;
    mode_t mode = 0666;
    NTSTATUS status;

    (void)AllocationSize;
    (void)ShareAccess;
    (void)FileAttributes;
    (void)EaBuffer;
    (void)EaLength;

    if (!FileHandle) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    *FileHandle = INVALID_HANDLE_VALUE;

    /* Extraire le chemin depuis ObjectAttributes->ObjectName */
    if (!ObjectAttributes || !ObjectAttributes->ObjectName) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_OBJECT_PATH_INVALID;
    }

    if (unicode_to_ascii(ObjectAttributes->ObjectName,
                          win_path, sizeof(win_path)) <= 0) {
        winux_set_last_error(ERROR_INVALID_NAME);
        return STATUS_OBJECT_PATH_INVALID;
    }

    /* Traduire le chemin Windows → Linux */
    if (!io_translate_path(win_path, linux_path, sizeof(linux_path))) {
        winux_set_last_error(ERROR_PATH_NOT_FOUND);
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    /* Construire les flags open() */
    oflags  = access_to_oflags(DesiredAccess);
    oflags |= disposition_to_oflags(CreateDisposition);

    /* Si on demande un répertoire, forcer O_RDONLY */
    if (CreateOptions & FILE_DIRECTORY_FILE) {
        oflags &= ~(O_WRONLY | O_RDWR);
        oflags |= O_RDONLY;
    }

    fd = open(linux_path, oflags, mode);
    if (fd < 0) {
        int saved_errno = errno;
        winux_set_last_error(errno_to_win32_error(saved_errno));
        if (IoStatusBlock)
            IoStatusBlock->Status = errno_to_ntstatus(saved_errno);
        return errno_to_ntstatus(saved_errno);
    }

    /* Enregistrer le handle dans la table io_handles */
    handle_idx = io_register_handle(fd, HANDLE_TYPE_FILE, win_path);
    if (handle_idx < 0) {
        close(fd);
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return STATUS_NO_MEMORY;
    }

    *FileHandle = (HANDLE)(uintptr_t)(intptr_t)handle_idx;

    /* Remplir IO_STATUS_BLOCK */
    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;

        /*
         * Déterminer Information (FILE_CREATED / FILE_OPENED / etc.)
         * Simplifié : si O_CREAT a été utilisé, c'est FILE_CREATED,
         * sinon FILE_OPENED.
         */
        if (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_SUPERSEDE)
            IoStatusBlock->Information = FILE_CREATED;
        else if (CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE_IF) {
            /* On ne sait pas facilement si le fichier existait déjà.
             * On utilise une heuristique : si O_EXCL n'était pas dans les flags
             * et qu'on a réussi, c'est que le fichier existait peut-être. */
            IoStatusBlock->Information = (oflags & O_CREAT) ? FILE_CREATED : FILE_OPENED;
        } else
            IoStatusBlock->Information = FILE_OPENED;
    }

    status = STATUS_SUCCESS;
    winux_set_last_error(ERROR_SUCCESS);
    WINUX_LOG("NtCreateFile: '%s' → '%s' fd=%d handle=%d",
              win_path, linux_path, fd, handle_idx);
    return status;
}

/* ==========================================================================
   NtReadFile
   ========================================================================== */

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
)
{
    int handle_idx;
    WINUX_HANDLE_ENTRY *entry;
    ssize_t bytes_read;

    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;

    if (!Buffer || Length == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    handle_idx = (int)(intptr_t)FileHandle;
    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    /* Seek si un offset explicite est fourni */
    if (ByteOffset) {
        if (lseek(entry->linux_fd, (off_t)*ByteOffset, SEEK_SET) < 0) {
            int saved_errno = errno;
            winux_set_last_error(errno_to_win32_error(saved_errno));
            if (IoStatusBlock) IoStatusBlock->Status = errno_to_ntstatus(saved_errno);
            return errno_to_ntstatus(saved_errno);
        }
    }

    bytes_read = read(entry->linux_fd, Buffer, (size_t)Length);

    if (bytes_read < 0) {
        int saved_errno = errno;
        winux_set_last_error(errno_to_win32_error(saved_errno));
        if (IoStatusBlock) {
            IoStatusBlock->Status = errno_to_ntstatus(saved_errno);
            IoStatusBlock->Information = 0;
        }
        return errno_to_ntstatus(saved_errno);
    }

    if (IoStatusBlock) {
        IoStatusBlock->Status      = STATUS_SUCCESS;
        IoStatusBlock->Information = (ULONG_PTR)bytes_read;
    }

    if (bytes_read == 0) {
        winux_set_last_error(ERROR_HANDLE_EOF);
        return STATUS_END_OF_FILE;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtWriteFile
   ========================================================================== */

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
)
{
    int handle_idx;
    WINUX_HANDLE_ENTRY *entry;
    ssize_t bytes_written;

    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;

    if (!Buffer || Length == 0) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    handle_idx = (int)(intptr_t)FileHandle;
    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    if (ByteOffset) {
        if (lseek(entry->linux_fd, (off_t)*ByteOffset, SEEK_SET) < 0) {
            int saved_errno = errno;
            winux_set_last_error(errno_to_win32_error(saved_errno));
            if (IoStatusBlock) IoStatusBlock->Status = errno_to_ntstatus(saved_errno);
            return errno_to_ntstatus(saved_errno);
        }
    }

    bytes_written = write(entry->linux_fd, Buffer, (size_t)Length);

    if (bytes_written < 0) {
        int saved_errno = errno;
        winux_set_last_error(errno_to_win32_error(saved_errno));
        if (IoStatusBlock) {
            IoStatusBlock->Status = errno_to_ntstatus(saved_errno);
            IoStatusBlock->Information = 0;
        }
        return errno_to_ntstatus(saved_errno);
    }

    if (IoStatusBlock) {
        IoStatusBlock->Status      = STATUS_SUCCESS;
        IoStatusBlock->Information = (ULONG_PTR)bytes_written;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtClose
   ========================================================================== */

WINAPI NTSTATUS NtClose(HANDLE Handle)
{
    int handle_idx = (int)(intptr_t)Handle;

    if (io_close_handle(handle_idx) != 0) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtAllocateVirtualMemory
   ========================================================================== */

WINAPI NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID    *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T   *RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
)
{
    (void)ProcessHandle;
    (void)ZeroBits;

    return mem_virtual_alloc(BaseAddress, RegionSize, AllocationType, Protect);
}

/* ==========================================================================
   NtFreeVirtualMemory
   ========================================================================== */

WINAPI NTSTATUS NtFreeVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    SIZE_T *RegionSize,
    ULONG   FreeType
)
{
    (void)ProcessHandle;

    return mem_virtual_free(BaseAddress, RegionSize, FreeType);
}

/* ==========================================================================
   NtProtectVirtualMemory
   ========================================================================== */

WINAPI NTSTATUS NtProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    SIZE_T *RegionSize,
    ULONG   NewProtect,
    ULONG  *OldProtect
)
{
    (void)ProcessHandle;

    return mem_virtual_protect(BaseAddress, RegionSize, NewProtect, OldProtect);
}

/* ==========================================================================
   NtCreateThread
   ========================================================================== */

/*
 * Structure simplifiée pour le contexte du thread.
 * On utilise la convention d'appel Microsoft x64 :
 * le premier argument est dans RCX (registre RDI en SysV = param 1).
 * Mais comme le code PE utilise l'ABI MS, le thread démarre avec
 * l'adresse de la fonction dans RCX.
 *
 * Pour appeler le point d'entrée du thread PE depuis un thread
 * Linux, on utilise une fonction wrapper.
 */

typedef struct _THREAD_START_PARAM {
    void *start_address;  /* adresse de la fonction dans le code PE */
    void *parameter;      /* paramètre à passer */
} THREAD_START_PARAM;

static void *nt_thread_wrapper(void *arg)
{
    THREAD_START_PARAM *param = (THREAD_START_PARAM *)arg;
    void *start_addr = param->start_address;
    void *thread_param = param->parameter;

    free(param);

    /*
     * Appeler le point d'entrée du thread avec l'ABI Microsoft x64.
     * On utilise un cast de pointeur de fonction avec ms_abi.
     * Signature typique : DWORD WINAPI ThreadProc(LPVOID lpParameter);
     */
    typedef DWORD (WINAPI *thread_entry_fn)(void *);
    thread_entry_fn entry = (thread_entry_fn)start_addr;

    DWORD ret = entry(thread_param);

    WINUX_LOG("Thread exited with code %u", (unsigned)ret);

    return (void *)(uintptr_t)ret;
}

WINAPI NTSTATUS NtCreateThread(
    HANDLE           *ThreadHandle,
    ULONG             DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE             ProcessHandle,
    PCLIENT_ID        ClientId,
    PVOID             ThreadContext,
    PINITIAL_TEB      InitialTeb,
    BOOL              CreateSuspended
)
{
    THREAD_START_PARAM *param;
    pthread_t tid;
    pthread_attr_t attr;
    int rc;

    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)ProcessHandle;
    (void)ClientId;
    (void)InitialTeb;

    if (!ThreadHandle) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    *ThreadHandle = INVALID_HANDLE_VALUE;

    /*
     * Récupérer l'adresse de début depuis le contexte (Rip).
     * Sur x64, le contexte passé aux threads Windows contient
     * l'adresse de début dans RCX (premier argument MS ABI).
     * Comme on reçoit un pointeur opaque, on lit le premier QWORD
     * si ThreadContext n'est pas NULL.
     */
    void *start_addr = NULL;
    void *start_param = NULL;

    if (ThreadContext) {
        uint64_t *ctx = (uint64_t *)ThreadContext;
        /*
         * La structure CONTEXT x64 est complexe. On suppose que
         * l'appelant a placé l'adresse de début dans les premiers
         * champs. Pour l'instant, on lit :
         *   ctx[0] = P1Home (RCX shadow)
         *   ctx[1] = P2Home (RDX shadow)
         * Mais la réalité dépend du layout exact.
         *
         * Approche pragmatique : on lit le 16ème QWORD (Rip dans
         * un CONTEXT typique). Si ça ressemble à un pointeur valide
         * (> 0x10000), on l'utilise. Sinon, on prend ctx[0].
         */
        if (ctx[16] > 0x10000)
            start_addr = (void *)(uintptr_t)ctx[16];  /* Rip */
        else if (ctx[0] > 0x10000)
            start_addr = (void *)(uintptr_t)ctx[0];   /* RCX */
        else
            start_addr = (void *)(uintptr_t)ctx[0];
        start_param = (void *)(uintptr_t)ctx[1];       /* RDX */
    }

    if (!start_addr) {
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    param = malloc(sizeof(THREAD_START_PARAM));
    if (!param) {
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return STATUS_NO_MEMORY;
    }

    param->start_address = start_addr;
    param->parameter      = start_param;

    pthread_attr_init(&attr);
    /* Threads créés joinable pour que WaitForSingleObject puisse les joindre */
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    rc = pthread_create(&tid, &attr, nt_thread_wrapper, param);
    pthread_attr_destroy(&attr);

    if (rc != 0) {
        free(param);
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        WINUX_ERR("NtCreateThread: pthread_create failed (rc=%d)", rc);
        return STATUS_NO_MEMORY;
    }

    if (CreateSuspended) {
        /*
         * Les threads suspendus ne sont pas facilement implémentables
         * avec pthread_create seul. On log un avertissement : le thread
         * démarre immédiatement.
         */
        WINUX_LOG("NtCreateThread: CreateSuspended not fully supported, "
                  "thread started immediately");
    }

    /* On n'a pas de table de handles pour les threads pour l'instant,
       on retourne le tid casté en HANDLE */
    *ThreadHandle = (HANDLE)(uintptr_t)tid;

    WINUX_LOG("NtCreateThread: created thread tid=%lu entry=%p param=%p",
              (unsigned long)tid, start_addr, start_param);

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtTerminateProcess / NtTerminateThread
   ========================================================================== */

WINAPI NTSTATUS NtTerminateProcess(
    HANDLE   ProcessHandle,
    NTSTATUS ExitStatus
)
{
    (void)ProcessHandle;

    WINUX_LOG("NtTerminateProcess: exit code 0x%08X", ExitStatus);

    /* Propager le code de sortie Windows */
    exit((int)ExitStatus);

    /* never reached */
    return STATUS_SUCCESS;
}

WINAPI NTSTATUS NtTerminateThread(
    HANDLE   ThreadHandle,
    NTSTATUS ExitStatus
)
{
    (void)ThreadHandle;

    WINUX_LOG("NtTerminateThread: exit code 0x%08X", ExitStatus);

    /*
     * On ne peut pas vraiment terminer un thread POSIX proprement
     * depuis l'extérieur sans pthread_cancel + pthread_join.
     * On fait un exit() du thread courant (pthread_exit).
     */
    pthread_exit((void *)(uintptr_t)ExitStatus);

    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtWaitForSingleObject
   ========================================================================== */

WINAPI NTSTATUS NtWaitForSingleObject(
    HANDLE   Handle,
    BOOL     Alertable,
    int64_t *Timeout
)
{
    WINUX_HANDLE_ENTRY *entry;
    int handle_idx = (int)(intptr_t)Handle;

    (void)Alertable;

    entry = io_get_handle(handle_idx);

    if (!entry) {
        /*
         * Si ce n'est pas un handle I/O, c'est peut-être un thread.
         * On ne peut pas faire grand-chose pour attendre un thread
         * sans infrastructure de synchronisation. On retourne immédiatement.
         */
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    /*
     * Pour les handles I/O, on ne peut pas vraiment "attendre"
     * sans poll/epoll. On fait un usleep si Timeout est positif.
     * Version simplifiée : retour immédiat.
     */
    /*
     * Le Timeout est en centaines de nanosecondes (unités NT).
     * Valeurs positives = absolu, négatives = relatif.
     * Conversion en microsecondes : diviser par 10.
     */
    int64_t wait_us;
    if (!Timeout || *Timeout == 0) {
        wait_us = 0;
    } else if (*Timeout < 0) {
        wait_us = (-*Timeout) / 10;
    } else {
        wait_us = *Timeout / 10;
    }
    if (wait_us > 0) {
        if (wait_us > 10000000)
            wait_us = 10000000;
        usleep((useconds_t)wait_us);
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS; /* WAIT_OBJECT_0 */
}

/* ==========================================================================
   NtDelayExecution
   ========================================================================== */

WINAPI NTSTATUS NtDelayExecution(
    BOOL    Alertable,
    int64_t *Interval
)
{
    (void)Alertable;

    if (!Interval || *Interval <= 0) {
        /* Pas d'attente */
        winux_set_last_error(ERROR_SUCCESS);
        return STATUS_SUCCESS;
    }

    /*
     * L'intervalle est en centaines de nanosecondes (unités de 100ns).
     * Convertir en microsecondes : diviser par 10.
     */
    int64_t delay_us = *Interval / 10;
    if (delay_us < 0)
        delay_us = 0;

    /*
     * Limiter à 10 secondes max pour éviter des attentes infinies
     * non intentionnelles.
     */
    if (delay_us > 10000000)
        delay_us = 10000000;

    usleep((useconds_t)delay_us);

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtQueryInformationFile
   ========================================================================== */

WINAPI NTSTATUS NtQueryInformationFile(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass
)
{
    int handle_idx = (int)(intptr_t)FileHandle;
    WINUX_HANDLE_ENTRY *entry;
    struct stat st;

    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    if (fstat(entry->linux_fd, &st) != 0) {
        int saved_errno = errno;
        winux_set_last_error(errno_to_win32_error(saved_errno));
        if (IoStatusBlock) IoStatusBlock->Status = errno_to_ntstatus(saved_errno);
        return errno_to_ntstatus(saved_errno);
    }

    /*
     * FileInformationClass détermine ce qu'on retourne.
     * Les plus courants :
     *   FileBasicInformation (4)    → FILE_BASIC_INFORMATION
     *   FileStandardInformation (5) → FILE_STANDARD_INFORMATION
     *   FilePositionInformation (14)→ FILE_POSITION_INFORMATION
     *
     * Pour l'instant, on supporte seulement FileStandardInformation.
     */

    switch (FileInformationClass) {
    case 5: /* FileStandardInformation */
        if (Length >= 24 && FileInformation) {
            /* FILE_STANDARD_INFORMATION layout :
               int64_t AllocationSize;
               int64_t EndOfFile;
               uint32_t NumberOfLinks;
               uint8_t  DeletePending;
               uint8_t  Directory;
            */
            int64_t *info = (int64_t *)FileInformation;
            info[0] = (int64_t)st.st_blocks * 512; /* AllocationSize */
            info[1] = (int64_t)st.st_size;          /* EndOfFile */
            ((uint32_t *)info)[4] = (uint32_t)st.st_nlink; /* NumberOfLinks */
            ((uint8_t *)info)[20] = 0;               /* DeletePending */
            ((uint8_t *)info)[21] = S_ISDIR(st.st_mode) ? 1 : 0; /* Directory */

            if (IoStatusBlock) {
                IoStatusBlock->Status      = STATUS_SUCCESS;
                IoStatusBlock->Information = 24;
            }
        } else {
            winux_set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case 14: /* FilePositionInformation */
        if (Length >= 8 && FileInformation) {
            off_t pos = lseek(entry->linux_fd, 0, SEEK_CUR);
            if (pos < 0) {
                int saved_errno = errno;
                winux_set_last_error(errno_to_win32_error(saved_errno));
                return errno_to_ntstatus(saved_errno);
            }
            *(int64_t *)FileInformation = (int64_t)pos;
            if (IoStatusBlock) {
                IoStatusBlock->Status      = STATUS_SUCCESS;
                IoStatusBlock->Information = 8;
            }
        } else {
            winux_set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        WINUX_LOG("NtQueryInformationFile: unsupported class %u", FileInformationClass);
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_NOT_SUPPORTED;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtSetInformationFile
   ========================================================================== */

WINAPI NTSTATUS NtSetInformationFile(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass
)
{
    int handle_idx = (int)(intptr_t)FileHandle;
    WINUX_HANDLE_ENTRY *entry;

    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    switch (FileInformationClass) {
    case 10: { /* FileEndOfFileInformation — SetEndOfFile */
        if (Length >= 8 && FileInformation) {
            int64_t new_size = *(int64_t *)FileInformation;
            if (ftruncate(entry->linux_fd, (off_t)new_size) != 0) {
                int saved_errno = errno;
                winux_set_last_error(errno_to_win32_error(saved_errno));
                return errno_to_ntstatus(saved_errno);
            }
            if (IoStatusBlock) {
                IoStatusBlock->Status = STATUS_SUCCESS;
                IoStatusBlock->Information = 0;
            }
        }
        break;
    }

    case 20: { /* FileDispositionInformation — delete on close */
        /* Simplifié : on ne supporte pas le delete-on-close pour l'instant */
        WINUX_LOG("NtSetInformationFile: FileDispositionInformation ignored");
        break;
    }

    default:
        WINUX_LOG("NtSetInformationFile: unsupported class %u", FileInformationClass);
        winux_set_last_error(ERROR_INVALID_PARAMETER);
        return STATUS_NOT_SUPPORTED;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtDeviceIoControlFile
   ========================================================================== */

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
)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)IoControlCode;
    (void)InputBuffer;
    (void)InputBufferLength;
    (void)OutputBuffer;
    (void)OutputBufferLength;

    WINUX_LOG("NtDeviceIoControlFile: ioctl 0x%08X (stub)", IoControlCode);

    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_NOT_SUPPORTED;
        IoStatusBlock->Information = 0;
    }

    winux_set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
    return STATUS_NOT_SUPPORTED;
}

/* ==========================================================================
   NtQueryDirectoryFile
   ========================================================================== */

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
)
{
    int handle_idx = (int)(intptr_t)FileHandle;
    WINUX_HANDLE_ENTRY *entry;
    DIR *dirp;
    struct dirent *dent;
    int dir_fd;

    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)FileName;
    (void)RestartScan;

    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    /*
     * NtQueryDirectoryFile nécessite un fd de répertoire.
     * On duplique le fd pour ne pas perturber la position
     * du fd original, puis on utilise fdopendir().
     */
    dir_fd = dup(entry->linux_fd);
    if (dir_fd < 0) {
        winux_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return STATUS_NO_MEMORY;
    }

    dirp = fdopendir(dir_fd);
    if (!dirp) {
        close(dir_fd);
        winux_set_last_error(ERROR_DIRECTORY);
        return STATUS_NOT_A_DIRECTORY;
    }

    /*
     * Implémentation simplifiée : on lit une entrée et on remplit
     * une structure FILE_DIRECTORY_INFORMATION basique :
     *   ULONG  NextEntryOffset;
     *   ULONG  FileIndex;
     *   LARGE_INTEGER CreationTime;
     *   LARGE_INTEGER LastAccessTime;
     *   LARGE_INTEGER LastWriteTime;
     *   LARGE_INTEGER ChangeTime;
     *   LARGE_INTEGER EndOfFile;
     *   LARGE_INTEGER AllocationSize;
     *   ULONG  FileAttributes;
     *   ULONG  FileNameLength;
     *   WCHAR  FileName[1];
     */

    ULONG written = 0;

    while ((dent = readdir(dirp)) != NULL) {
        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
            continue;

        size_t name_len = strlen(dent->d_name);
        ULONG entry_size = (ULONG)(64 + name_len * sizeof(uint16_t));
        entry_size = WINUX_ALIGN_UP(entry_size, 8);

        if (written + entry_size > Length)
            break; /* Plus de place dans le buffer */

        uint8_t *entry_buf = (uint8_t *)FileInformation + written;
        memset(entry_buf, 0, entry_size);

        /* NextEntryOffset : 0 si dernière entrée, sinon entry_size */
        *(ULONG *)(entry_buf + 0) = 0; /* Mis à jour après */

        /* FileAttributes */
        ULONG attrs = FILE_ATTRIBUTE_NORMAL;
        if (dent->d_type == DT_DIR) attrs |= FILE_ATTRIBUTE_DIRECTORY;
        *(ULONG *)(entry_buf + 56) = attrs;

        /* FileNameLength */
        ULONG fname_bytes = (ULONG)(name_len * sizeof(uint16_t));
        *(ULONG *)(entry_buf + 60) = fname_bytes;

        /* FileName (WCHAR) */
        uint16_t *wbuf = (uint16_t *)(entry_buf + 64);
        for (size_t i = 0; i < name_len; i++)
            wbuf[i] = (uint16_t)(uint8_t)dent->d_name[i];

        written += entry_size;

        if (ReturnSingleEntry)
            break;
    }

    closedir(dirp); /* ferme aussi dir_fd */

    if (IoStatusBlock) {
        IoStatusBlock->Status      = STATUS_SUCCESS;
        IoStatusBlock->Information = written;
    }

    if (written == 0) {
        winux_set_last_error(ERROR_NO_MORE_FILES);
        return STATUS_NO_SUCH_FILE;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}

/* ==========================================================================
   NtFlushBuffersFile
   ========================================================================== */

WINAPI NTSTATUS NtFlushBuffersFile(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
)
{
    int handle_idx = (int)(intptr_t)FileHandle;
    WINUX_HANDLE_ENTRY *entry;

    entry = io_get_handle(handle_idx);
    if (!entry) {
        winux_set_last_error(ERROR_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    if (fsync(entry->linux_fd) != 0) {
        int saved_errno = errno;
        winux_set_last_error(errno_to_win32_error(saved_errno));
        if (IoStatusBlock) IoStatusBlock->Status = errno_to_ntstatus(saved_errno);
        return errno_to_ntstatus(saved_errno);
    }

    if (IoStatusBlock) {
        IoStatusBlock->Status      = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
    }

    winux_set_last_error(ERROR_SUCCESS);
    return STATUS_SUCCESS;
}
