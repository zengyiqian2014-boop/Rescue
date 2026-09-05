# RescueMon — kernel minifilter (Phase 6)

The **un-killable real-time tier**. Everything the user-mode
[`ransom_guard`](../src/ransom_guard.cpp) does is a *heuristic*, because Windows
will not tell a user-mode watcher **which process** wrote a file. A file-system
**minifilter** runs inside the kernel I/O path and gets exactly that — so it
turns "the busiest writer is *probably* the culprit" into **certain per-write
attribution**, and, running as a boot-start driver, it is far harder for malware
to kill than a user-mode process.

> **What still needs this driver, after the ETW work in Module 3:** only
> *blocking a write before it lands*. Deterministic **attribution** — knowing
> which process performed each write/rename/delete — is now done from user mode
> via a real-time ETW session on `Microsoft-Windows-Kernel-File`
> ([`../src/etw_filemon.h`](../src/etw_filemon.h)), with Secure Boot and HVCI
> left on and no signing required. The minifilter's remaining unique capability
> is the **pre-operation callback** that can return `STATUS_ACCESS_DENIED` and
> stop a malicious write in the I/O path — something ETW, which reports events
> after the fact, structurally cannot do.

## Why it's separate from the Makefile

This is **WDK / MSVC code — it cannot be built with MinGW.** Kernel drivers use
the Windows Driver Kit headers, a kernel runtime, and the MSVC compiler; the GCC
/ Clang MinGW toolchain that builds the rest of Rescue does not target kernel
mode. It's kept here as **correct, reviewable source** for the Phase 6 tier and
is intentionally excluded from the top-level `make`.

## What it does

- `DriverEntry` registers the filter and a **filter communication port**
  (`\RescueMonPort`, ACL'd to SYSTEM/Administrators).
- Pre-operation callbacks on **`IRP_MJ_WRITE`** and **`IRP_MJ_SET_INFORMATION`**
  (rename / delete) capture, for every file change: the **requestor PID**
  (`FltGetRequestorProcessId`) and the **normalized target path**.
- Each event is pushed to the user-mode Rescue service as an `RM_EVENT`
  (see [`rescuemon.h`](rescuemon.h)) with a 5 ms non-blocking send, so it never
  stalls file I/O.
- The service correlates rate/pattern across PIDs and stops the real culprit
  **with certainty** — no more "top writer" guessing.

**Enforcement is now implemented in source, not just observation.** The driver
reports every attributed WRITE/RENAME/DELETE *and* enforces a PID blocklist: the
user-mode service watches the event stream, decides who is malicious (its
signatures + heuristics), and sends `RM_CMD_BLOCK_PID` back over the same port;
from then on the driver refuses that PID's writes in the pre-operation callback
with `FLT_PREOP_COMPLETE` + `STATUS_ACCESS_DENIED` — vetting each write in the
I/O path and denying it **before it lands**. This is the "inspect every write,
then allow or deny" tier, and it can *only* live in the kernel: user mode is not
in the write path, so no amount of user-mode aggressiveness can do it (API
hooking is per-process and bypassable via direct syscalls / raw handles — not a
security boundary). Policy stays in user mode (so a false positive is a cleared
`RM_CMD_UNBLOCK_PID`, not a bricked machine); enforcement lives where writes
actually pass. The blocklist is guarded by a `KSPIN_LOCK` because a write pre-op
can run at `DISPATCH_LEVEL`. Still needs signing to load — that gate is the whole
reason this tier isn't already shipping.

## Building (Windows, WDK)

1. Install **Visual Studio** + the **Windows Driver Kit (WDK)** matching it (or
   the standalone **EWDK**).
2. Create a *Kernel Mode Driver, Empty (KMDF/WDM)* → *Filter* project, add
   `rescuemon.c`, `rescuemon.h`, `rescuemon.inf`, or build with the EWDK:
   ```
   msbuild rescuemon.vcxproj /p:Configuration=Release /p:Platform=x64
   ```
   Output: `rescuemon.sys`.

## Loading it (signing is mandatory, and self-signing is not enough)

64-bit Windows will not load an unsigned kernel driver — and, importantly, it
will not load a **self-signed** one either, no matter what the user agrees to.

Kernel Code Integrity **does not consult the machine's certificate stores**.
That is the part that surprises people: in user mode, trusting a root makes code
signed by it validate; in kernel mode the loader makes a stricter, separate
check before any user context exists. Since **Windows 10 1607** a new kernel
driver loads only when **Microsoft** signed it, and the **April 2026 Windows
update** removed default trust for the old cross-signed program as well. So
there is no "install our certificate during setup" flow that makes this driver
load. See [`../installer/README.md`](../installer/README.md) for the full
reasoning and the two paths that do work:

- **Release / other people's machines — the only real path:** an **EV
  code-signing certificate** plus **Microsoft Partner Center attestation
  signing** (or full WHCP). The driver comes back signed by Microsoft and loads
  with Secure Boot on, with nothing for the user to accept.
- **Development / your own machine:** test-signing mode, which requires
  **Secure Boot off** and lowers the bar for every driver on that machine, not
  just this one. `installer/Install-RescueDriver.ps1 -LabMode` does this with
  itemised, typed consent and a precise revert:
  ```powershell
  .\Install-RescueDriver.ps1 -LabMode     # preflight, consent, sign, trust, load
  .\Uninstall-RescueDriver.ps1            # undoes exactly what it changed
  ```

Also worth knowing before the first load attempt: **Memory Integrity (HVCI)** is
on by default on much current hardware and will block a driver that is not
HVCI-compatible *even when it is correctly signed*. The installer reports its
state up front so a silent failure has an explanation.

## Altitude

`rescuemon.inf` uses a **development placeholder altitude** (`329100`, in the
Anti-Virus range 320000–329998). A shipped filter must **request its own unique
altitude from Microsoft** so it loads in a defined order relative to other AV
filters.

## Honest status

This is the scaffold of the un-killable tier: registration, the communication
port, and attributed WRITE/RENAME/DELETE reporting are all real and correct.
It is not yet a signed, shipping driver — that requires the WDK build and the
signing gate above, neither of which can happen in the MinGW cross-build that
produces the rest of Rescue. The installer scripts in
[`../installer/`](../installer/) are written and parse-checked but have not been
run on Windows; the first run on a real test machine is what validates them.
