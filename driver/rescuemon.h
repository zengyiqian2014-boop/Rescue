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

// Commands sent user-mode -> kernel over the same port (FilterSendMessage).
// This is what turns the driver from an observer into an enforcer: the service
// watches the RM_EVENT stream, decides (with its signatures + heuristics) who is
// malicious, and tells the driver to REFUSE that PID's writes in-kernel, before
// they land. The policy lives in user mode; the enforcement lives in the I/O
// path - which is the only place a write can be vetted and then allowed/denied.
typedef enum _RM_CMD {
    RM_CMD_BLOCK_PID   = 1,   // deny all future WRITE/RENAME/DELETE from this PID
    RM_CMD_UNBLOCK_PID = 2,   // stop denying (e.g. a false positive was cleared)
    RM_CMD_UNBLOCK_ALL = 3,   // clear the whole blocklist
} RM_CMD;

#pragma pack(push, 1)
typedef struct _RM_COMMAND {
    unsigned long Command;      // RM_CMD
    unsigned long ProcessId;    // target PID for BLOCK/UNBLOCK_PID
} RM_COMMAND;
#pragma pack(pop)
