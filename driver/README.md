# RescueMon — kernel minifilter (Phase 6)

The **un-killable real-time tier**. Everything the user-mode
[`ransom_guard`](../src/ransom_guard.cpp) does is a *heuristic*, because Windows
will not tell a user-mode watcher **which process** wrote a file. A file-system
**minifilter** runs inside the kernel I/O path and gets exactly that — so it
turns "the busiest writer is *probably* the culprit" into **certain per-write
attribution**, and, running as a boot-start driver, it is far harder for malware
to kill than a user-mode process.

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

This first version *observes and reports*. Blocking a write in-kernel
(`FLT_PREOP_COMPLETE` with `STATUS_ACCESS_DENIED` once a PID is confirmed
malicious) is a deliberate next step, gated behind the service's decision so a
false positive can't brick the machine.

## Building (Windows, WDK)

1. Install **Visual Studio** + the **Windows Driver Kit (WDK)** matching it (or
   the standalone **EWDK**).
2. Create a *Kernel Mode Driver, Empty (KMDF/WDM)* → *Filter* project, add
   `rescuemon.c`, `rescuemon.h`, `rescuemon.inf`, or build with the EWDK:
   ```
   msbuild rescuemon.vcxproj /p:Configuration=Release /p:Platform=x64
   ```
   Output: `rescuemon.sys`.

## Loading it (signing is mandatory)

64-bit Windows will not load an unsigned kernel driver.

- **Development / your own machine:** enable test-signing, make a test cert,
  sign the `.sys`, then load with the Filter Manager:
  ```
  bcdedit /set testsigning on              :: then reboot
  makecert / signtool sign /v /s PrivateCertStore /n RescueTest rescuemon.sys
  copy rescuemon.sys %windir%\System32\drivers\
  sc create RescueMon type= filesys binPath= System32\drivers\rescuemon.sys start= demand
  fltmc load RescueMon
  ```
  (Or right-click `rescuemon.inf` → Install, then `fltmc load RescueMon`.)
- **Release / other people's machines:** you need an **EV code-signing
  certificate** and to submit the driver to the **Microsoft Partner Center**
  for **attestation signing** (or full WHQL). There is no way around this — it's
  the same gate that made the ExecTI SmartScreen story what it was, and for
  kernel code it is absolute.

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
produces the rest of Rescue.
