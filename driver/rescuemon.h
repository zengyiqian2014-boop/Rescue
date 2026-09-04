// rescuemon.h - shared definitions between the RescueMon minifilter driver and
// the user-mode Rescue service that consumes its events.
#pragma once

// Communication port the user-mode service connects to.
#define RESCUEMON_PORT_NAME  L"\\RescueMonPort"

// Operation classes the driver reports.
typedef enum _RM_OP {
    RM_OP_WRITE  = 1,   // file contents modified
    RM_OP_RENAME = 2,   // file renamed (classic ".locked" extension swap)
    RM_OP_DELETE = 3,   // file deleted
} RM_OP;

// One event, pushed from kernel to user mode. This carries the thing user mode
// cannot get on its own: the PID that actually performed the write.
#pragma pack(push, 1)
typedef struct _RM_EVENT {
    unsigned long ProcessId;    // the requestor - reliable per-write attribution
    unsigned long Operation;    // RM_OP
    unsigned short PathChars;   // number of WCHARs in Path (no NUL)
    wchar_t Path[260];          // target file path (truncated to fit)
} RM_EVENT;
#pragma pack(pop)
