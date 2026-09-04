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
 *   - the service correlates the rate/pattern and tells the driver (or uses its
 *     own SYSTEM privileges) to stop the offending process - with certainty,
 *     not a guess.
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

/* ---- pre-operation callbacks ------------------------------------------ */

static VOID RmReportForData(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, ULONG op) {
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG pid = FltGetRequestorProcessId(Data);

    UNREFERENCED_PARAMETER(FltObjects);

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
    UNREFERENCED_PARAMETER(CompletionContext);
    RmReportForData(Data, FltObjects, RM_OP_WRITE);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS RmPreSetInfo(PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    UNREFERENCED_PARAMETER(CompletionContext);
    if (cls == FileRenameInformation || cls == FileRenameInformationEx)
        RmReportForData(Data, FltObjects, RM_OP_RENAME);
    else if (cls == FileDispositionInformation || cls == FileDispositionInformationEx)
        RmReportForData(Data, FltObjects, RM_OP_DELETE);
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

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilter);
    if (!NT_SUCCESS(status)) return status;

    /* communication port - only SYSTEM/Administrators may connect */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&portName, RESCUEMON_PORT_NAME);
        InitializeObjectAttributes(&oa, &portName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
        status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
            RmPortConnect, RmPortDisconnect, NULL, 1);
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
