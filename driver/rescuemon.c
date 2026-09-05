/*
 * rescuemon.c - RescueMon, the Rescue kernel minifilter (roadmap Phase 6).
 *
 * This is the "un-killable" real-time tier. Everything the user-mode Ransom
 * Guard does is a heuristic because Windows will not tell a user-mode watcher
 * WHICH process wrote a file. A file-system minifilter runs in the I/O path in
 * kernel mode and gets exactly that: FltGetRequestorProcessId in the pre-write
 * callback is the definitive answer to "who is encrypting my files?".
 *
 * What it does:
 *   - registers pre-operation callbacks on WRITE, SET_INFORMATION (rename/
 *     delete);
 *   - for each, captures the requestor PID + target path and pushes an RM_EVENT
 *     to the user-mode Rescue service over a filter communication port;
 *   - the service correlates the rate/pattern and, when it identifies the
 *     culprit, sends an RM_CMD_BLOCK_PID back; from then on the driver REFUSES
 *     that PID's WRITE/RENAME/DELETE in the pre-operation callback with
 *     STATUS_ACCESS_DENIED - vetting each write in the I/O path and denying it
 *     BEFORE it lands. This is the "inspect every write, then allow or deny"
 *     tier: it can only exist in kernel mode, because user mode is not in the
 *     write path (which is exactly why this needs a signed driver).
 *
 * BUILD: this is WDK/MSVC code. It CANNOT be built with MinGW. See
 * driver/README.md - you need the Windows Driver Kit, and to LOAD it you need a
 * signed driver (test-signing for development, an EV cert + Microsoft
 * attestation signing for release). It is provided as correct, reviewable
 * source for the Phase 6 tier; it is not compiled by the top-level Makefile.
 */
#include <fltKernel.h>
#include <dontuse.h>
#include "rescuemon.h"

PFLT_FILTER   gFilter = NULL;
PFLT_PORT     gServerPort = NULL;   // listening port
PFLT_PORT     gClientPort = NULL;   // the connected user-mode service

/* ---- enforcement: PID blocklist --------------------------------------- */
/* The service names malicious PIDs; the pre-op callbacks deny their writes.
 * A small fixed array under a fast mutex is plenty - a handful of culprits at
 * once, checked on a hot path, so keep it simple and lock-cheap. */
/* A KSPIN_LOCK (not FAST_MUTEX) because a WRITE pre-op callback can run as high
 * as DISPATCH_LEVEL (paging I/O), where a fast mutex is illegal; a spin lock is
 * valid at <= DISPATCH_LEVEL and the critical section is a tiny array scan. */
#define RM_MAX_BLOCKED 256
static KSPIN_LOCK gBlockLock;
static ULONG      gBlocked[RM_MAX_BLOCKED];
static ULONG      gBlockedCount = 0;

static BOOLEAN RmIsBlocked(ULONG pid) {
    KIRQL irql;
    ULONG i;
    BOOLEAN hit = FALSE;
    KeAcquireSpinLock(&gBlockLock, &irql);
    for (i = 0; i < gBlockedCount; ++i) {
        if (gBlocked[i] == pid) { hit = TRUE; break; }
    }
    KeReleaseSpinLock(&gBlockLock, irql);
    return hit;
}

static VOID RmBlockPid(ULONG pid) {
    KIRQL irql;
    ULONG i;
    BOOLEAN present = FALSE;
    KeAcquireSpinLock(&gBlockLock, &irql);
    for (i = 0; i < gBlockedCount; ++i) if (gBlocked[i] == pid) { present = TRUE; break; }
    if (!present && gBlockedCount < RM_MAX_BLOCKED) gBlocked[gBlockedCount++] = pid;
    KeReleaseSpinLock(&gBlockLock, irql);
}

static VOID RmUnblockPid(ULONG pid) {
    KIRQL irql;
    ULONG i;
    KeAcquireSpinLock(&gBlockLock, &irql);
    for (i = 0; i < gBlockedCount; ++i) {
        if (gBlocked[i] == pid) {
            gBlocked[i] = gBlocked[--gBlockedCount];   /* swap-remove */
            break;
        }
    }
    KeReleaseSpinLock(&gBlockLock, irql);
}

static VOID RmUnblockAll(VOID) {
    KIRQL irql;
    KeAcquireSpinLock(&gBlockLock, &irql);
    gBlockedCount = 0;
    KeReleaseSpinLock(&gBlockLock, irql);
}

/* ---- communication port callbacks ------------------------------------- */

NTSTATUS RmPortConnect(PFLT_PORT ClientPort, PVOID ServerCookie,
                       PVOID Context, ULONG Size, PVOID* ConnectionCookie) {
    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    gClientPort = ClientPort;   // only the Rescue service connects (ACL-guarded)
    return STATUS_SUCCESS;
}

VOID RmPortDisconnect(PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gFilter, &gClientPort);
    gClientPort = NULL;
}

/* Push one event to user mode (best-effort, short timeout - never block I/O). */
static VOID RmReport(ULONG pid, ULONG op, PCUNICODE_STRING path) {
    RM_EVENT ev;
    LARGE_INTEGER timeout;

    if (gClientPort == NULL) return;

    RtlZeroMemory(&ev, sizeof(ev));
    ev.ProcessId = pid;
    ev.Operation = op;
    if (path != NULL && path->Buffer != NULL) {
        USHORT chars = path->Length / sizeof(WCHAR);
        if (chars > 259) chars = 259;
        RtlCopyMemory(ev.Path, path->Buffer, chars * sizeof(WCHAR));
        ev.PathChars = chars;
    }
    timeout.QuadPart = -10 * 1000 * 50;   /* 5 ms, relative */
    FltSendMessage(gFilter, &gClientPort, &ev, sizeof(ev), NULL, NULL, &timeout);
}

/* ---- commands from user mode (FilterSendMessage) ---------------------- */
/* The input buffer is user memory: probe and copy inside a guarded region. */
NTSTATUS RmMessageNotify(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
                         PVOID OutputBuffer, ULONG OutputBufferLength,
                         PULONG ReturnOutputBufferLength) {
    RM_COMMAND cmd;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    if (InputBuffer == NULL || InputBufferLength < sizeof(RM_COMMAND))
        return STATUS_INVALID_PARAMETER;

    __try {
        ProbeForRead(InputBuffer, sizeof(RM_COMMAND), sizeof(ULONG));
        RtlCopyMemory(&cmd, InputBuffer, sizeof(RM_COMMAND));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    switch (cmd.Command) {
        case RM_CMD_BLOCK_PID:   RmBlockPid(cmd.ProcessId);   break;
        case RM_CMD_UNBLOCK_PID: RmUnblockPid(cmd.ProcessId); break;
        case RM_CMD_UNBLOCK_ALL: RmUnblockAll();              break;
        default: return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

/* ---- pre-operation callbacks ------------------------------------------ */

/* Deny this operation in-kernel, before it touches the file. */
static FLT_PREOP_CALLBACK_STATUS RmDeny(PFLT_CALLBACK_DATA Data) {
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static VOID RmReportForData(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, ULONG op) {
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG pid = FltGetRequestorProcessId(Data);

    UNREFERENCED_PARAMETER(FltObjects);

    /* FltGetFileNameInformation and FltSendMessage require <= APC_LEVEL. A write
     * pre-op can arrive at DISPATCH_LEVEL (paging I/O); reporting is skipped
     * there rather than crashing. Enforcement (the spin-locked block check in
     * the caller) is unaffected and still runs at any IRQL. */
    if (KeGetCurrentIrql() > APC_LEVEL) return;

    if (NT_SUCCESS(FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        RmReport(pid, op, &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
    } else {
        RmReport(pid, op, NULL);
    }
}

FLT_PREOP_CALLBACK_STATUS RmPreWrite(PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    ULONG pid = FltGetRequestorProcessId(Data);
    UNREFERENCED_PARAMETER(CompletionContext);
    RmReportForData(Data, FltObjects, RM_OP_WRITE);
    if (RmIsBlocked(pid)) return RmDeny(Data);   /* refuse the write before it lands */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS RmPreSetInfo(PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    ULONG pid = FltGetRequestorProcessId(Data);
    BOOLEAN relevant = FALSE;
    UNREFERENCED_PARAMETER(CompletionContext);
    if (cls == FileRenameInformation || cls == FileRenameInformationEx) {
        RmReportForData(Data, FltObjects, RM_OP_RENAME); relevant = TRUE;
    } else if (cls == FileDispositionInformation || cls == FileDispositionInformationEx) {
        RmReportForData(Data, FltObjects, RM_OP_DELETE); relevant = TRUE;
    }
    if (relevant && RmIsBlocked(pid)) return RmDeny(Data);   /* refuse rename/delete */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ---- registration ----------------------------------------------------- */

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_WRITE,           0, RmPreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION, 0, RmPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

NTSTATUS RmUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    if (gServerPort) FltCloseCommunicationPort(gServerPort);
    if (gFilter)     FltUnregisterFilter(gFilter);
    return STATUS_SUCCESS;
}

NTSTATUS RmInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
        FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType,
        FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;   /* attach to every volume */
}

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    RmUnload,
    RmInstanceSetup,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&gBlockLock);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilter);
    if (!NT_SUCCESS(status)) return status;

    /* communication port - only SYSTEM/Administrators may connect */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&portName, RESCUEMON_PORT_NAME);
        InitializeObjectAttributes(&oa, &portName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
        status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
            RmPortConnect, RmPortDisconnect, RmMessageNotify, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(gFilter); return status; }

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        FltUnregisterFilter(gFilter);
    }
    return status;
}
