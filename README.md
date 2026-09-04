# Rescue

An **active-defense** ransomware rescue & anti-malware toolkit for Windows —
built to *unlock*, *clean*, and *guard* a machine that malware has taken over.
Cross-compiled with **MinGW** for both **x86_64** and **ARM64** Windows.

> **Status: early, honest work-in-progress.** Module 1 (Lockdown Breaker) is
> real and working. The rest is on the roadmap below. Read the
> [Honest scope](#honest-scope) section before expecting a "full antivirus" —
> some of that goal has hard technical limits, and this README is straight with
> you about them.

---

## Why this exists

Modern ransomware / lockers don't just encrypt files. They **lock you out of
your own machine** so you can't fight back: they disable Task Manager and
regedit, hijack the login shell, freeze the keyboard and mouse, throw a
full-screen "you are locked" overlay on top of everything, and — the newest
trick — **drop a Microsoft-signed Code-Integrity (WDAC/S-mode) policy** into
`System32\CodeIntegrity` so the system refuses to launch *any* `.exe`, including
every antivirus you'd try to run.

Rescue attacks that lockdown **actively**: it walks each lever the malware
pulled and puts it back, so you can get control of the machine and then clean it.

## Honest scope

Being straight about what is and isn't achievable, so you can trust the parts
that work:

- **Encrypted files:** a *correctly implemented* ransomware (AES + RSA/ECC,
  attacker holds the key) **cannot be decrypted without the key** — not by
  Rescue, not by Kaspersky, not by anyone. That's mathematics, not a missing
  feature. Rescue focuses on the *winnable* fights: **prevention / early kill**,
  **recovery from Volume Shadow Copies & undelete**, **known-family decryptors**
  (via the No More Ransom ecosystem), and **breaking the lockdown**.
- **A truly un-killable real-time guard** ultimately needs a **signed kernel
  driver** (a file-system minifilter + process/registry callbacks). Everything
  Rescue can do from user mode + a borrowed SYSTEM/TrustedInstaller token is
  built first; the kernel driver is the last phase, and it's called out as such.
- Everything here uses **documented Win32 APIs** and requires you to approve a
  **UAC prompt**. It is a defensive tool for machines **you own or are
  authorized to administer**.

## Roadmap

| Phase | Module | What it does | State |
| --- | --- | --- | --- |
| **1** | **Lockdown Breaker** | Undo restriction policies, shell hijack, frozen input, lock overlays, dropped WDAC policy — on the live system | ✅ **working** |
| **1b** | **Offline WinPE rescue** | Same cleanup from a boot USB, where the malware isn't running (beats signed/enforced policies) | ✅ **working** |
| **2** | **ASEP Cleaner** | Enumerate *all* autostart points (Run, services, tasks, IFEO, Winlogon, startup) and flag/quarantine unsigned entries — Authenticode-verified, generic, not per-virus | ✅ **working** |
| **3** | **Anti-ransomware guard** | Honeypot canary files + directory watcher + mass-change detection → suspend/kill the busiest writer's process tree | ✅ **working** |
| 4 | Scanner | Integrate the **ClamAV** engine + scheduled scans; downloaded files (Mark-of-the-Web) get top-priority deep scan | planned |
| **5** | **Watchdog** | Windows service that keeps the guard alive + a paired companion; kill either and the other restarts it | ✅ **working** |
| **6** | **Kernel minifilter** | The "can't be killed" tier — per-write attribution in kernel. Source complete; needs WDK build + signing | 🧩 **source** |

## Module 1 — Lockdown Breaker

Undo the finite set of levers malware uses to lock you out. **Dry-run by
default** — it changes nothing until you pass `--fix`.

```
lockdown_breaker                     scan and REPORT only (changes nothing)
lockdown_breaker --fix               clear restriction policies, restore the
                                     login shell, release frozen input
lockdown_breaker --fix --kill-overlays        also close full-screen lock overlays
lockdown_breaker --fix --remove-ci-policy     also back up & attempt WDAC removal
```

What it walks:

- **Restriction policies** (per-user across every loaded hive, and machine-wide):
  `DisableTaskMgr`, `DisableRegistryTools`, `DisableCMD`, `NoRun`, `NoDesktop`,
  `NoControlPanel`, `NoViewContextMenu`, `NoFind`, `NoClose`, `NoFolderOptions`,
  `NoDrives`, `RestrictRun`, `DisallowRun`, lock/change-password blocks.
- **Login shell hijack** — restores `Winlogon\Shell` to `explorer.exe` and
  `Userinit` to its default if malware repointed them.
- **Frozen input** — issues `BlockInput(FALSE)` to release a `BlockInput` lock.
- **Full-screen lock overlays** — lists suspicious top-most, full-screen windows
  (never the real shell) and, with `--kill-overlays`, closes them.
- **Dropped WDAC / Code-Integrity policy** — finds `SiPolicy.p7b` and
  `CiPolicies\Active\*.cip`, backs them up, and with `--remove-ci-policy`
  attempts removal. **If the policy is being enforced (Microsoft-signed /
  boot-anchored), online removal will fail** and Rescue tells you to clear it
  **offline** from WinPE — that's Phase 1b.

To acquire the authority to touch `HKLM` policy keys and OS-protected files,
Rescue enables `SeDebugPrivilege`, borrows a **SYSTEM** token from `winlogon.exe`,
and enables the full privilege set — the same documented token flow as ExecTI.

### Recommended use

1. Run a plain scan first, read the findings.
2. Re-run with `--fix` (add `--kill-overlays` / `--remove-ci-policy` if needed).
3. **Reboot** so the shell reloads cleanly.
4. If Rescue reported a WDAC policy it couldn't remove, use the offline WinPE
   rescue (Phase 1b) to delete it, then reboot.

## Module 3 — Anti-Ransomware Guard

A resident guard that reacts *while the attack is running*: it plants **canary**
files, watches your folders in real time, and the instant something mass-modifies
files (or touches a canary) it finds the busiest writer process and **suspends**
its whole process tree — freezing the attack so you lose a handful of files
instead of all of them.

```
ransom_guard                       watch Desktop/Documents/Pictures, SUSPEND on attack
ransom_guard --watch D:\Work       watch a specific folder (repeatable)
ransom_guard --threshold 25        files-changed-per-second that counts as an attack
ransom_guard --kill                KILL the culprit instead of suspending (irreversible)
```

**Honest limitation:** from user mode Windows tells a watcher *that* files
changed, not *which process* changed each one. Reliable per-write attribution
needs a kernel minifilter driver (Phase 6). Until then the guard attributes the
attack by ranking processes on write-I/O rate at the moment of the trip — a
strong heuristic, not a certainty — so it **suspends** (reversible) by default
and logs exactly what it acted on. Confirm in Task Manager before you `--kill`.
It never touches OS-critical processes (a built-in whitelist).

## Module 2 — ASEP Cleaner

Malware can be anything, but to survive a reboot it has to anchor itself to one
of a finite set of **Auto-Start Extensibility Points**. This walks all of them,
**verifies each program's Authenticode signature — embedded *and* catalog** — and
flags whatever is unsigned, untrusted, or points at a missing file. That catches
brand-new malware nobody has a signature for yet, **without a virus database**.

```
asep_cleaner                 scan & REPORT flagged autostarts (changes nothing)
asep_cleaner --quarantine    neutralize flagged entries (backs up first)
```

It covers **Run/RunOnce** (HKLM, HKCU, every loaded user hive, WOW64),
**Winlogon** Shell/Userinit, **Image File Execution Options** debugger hijacks,
**startup folders**, **auto-start services**, and **scheduled tasks**. Bare names
(e.g. `Shell = explorer.exe`) are resolved via the OS search path before
verifying, so legitimate system entries aren't falsely flagged. Catalog
verification is why it doesn't scream "unsigned!" at half of System32 — most
Windows binaries are catalog-signed, and it checks the catalogs.

`--quarantine` backs up registry values to `HKLM\SOFTWARE\RescueQuarantine`
before removing them, renames flagged startup files (never deletes), and sets
flagged services to *Disabled*. Scheduled tasks are reported, not touched. A
flag means *unsigned*, not *definitely malicious* — review before quarantining.

## Module 5 — Watchdog

A protection tool a malicious process can just kill is no protection. This is a
Windows service (`RescueWatchdog`) that keeps **Ransom Guard** running and runs a
**paired companion** process: the service watches the companion, the companion
watches the service, and killing either one makes the other bring it back. The
service is also set to auto-restart on crash.

```
watchdog --install     install + start the service (run elevated)
watchdog --uninstall   stop + remove the service
watchdog --status      show service + guard state
```

**Honest ceiling:** two cooperating user-mode processes raise the bar — an
attacker has to kill both in the same instant, repeatedly — but a
privileged attacker can still win the race. Truly tamper-proof protection needs
a Protected-Process-Light service or the kernel filter below. The tool says so.

## Module 6 — Kernel minifilter (source)

The **un-killable real-time tier**. Everything in user mode is a heuristic
because Windows won't tell a user-mode watcher *which* process wrote a file — a
kernel **minifilter** in the I/O path gets exactly that (`FltGetRequestorProcessId`
in a pre-write callback), turning "probably the culprit" into **certain per-write
attribution**. It reports attributed WRITE/RENAME/DELETE events to the Rescue
service over a filter communication port.

The full, reviewable driver source, its INF, and a build/signing guide are in
[`driver/`](driver/). **It is WDK/MSVC code — it can't be built with MinGW and is
excluded from `make`.** Loading it requires a signed driver (test-signing for
dev; an EV cert + Microsoft attestation for release). This is the one tier that
can't be a cross-compiled `.exe`, and the README is explicit about why.

## Phase 1b — Offline WinPE rescue

When the machine is locked so hard that even the live tools can't run — a
Microsoft-signed / enforced WDAC policy blocking every `.exe`, a re-dropping
dropper, a full-screen locker — clean it **offline** from a WinPE/WinRE boot USB,
where the malware isn't running. See [`offline/`](offline/) for the scripts
(`Rescue-Offline.ps1` and a bare-batch `rescue-offline.cmd`) and a full guide to
building the USB and running them. Offline, a policy file is just a file — the
signature can't stop you deleting it.

## Building

```bash
make          # both tools, both architectures
make x64      # -> build/x86_64/{lockdown_breaker,ransom_guard,asep_cleaner,watchdog}.exe
make arm64    # -> build/arm64/{...}.exe    (llvm-mingw Clang)
```

The offline rescue (`offline/`) is scripts — nothing to build.

| Target | Toolchain |
| --- | --- |
| x86_64 | [mingw-w64](https://www.mingw-w64.org/) GCC (`x86_64-w64-mingw32-g++`) |
| ARM64  | [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) Clang (`aarch64-w64-mingw32-clang++`) |

Both build statically (`-static-libgcc -static-libstdc++`) and depend only on
system DLLs. The embedded manifest is `requireAdministrator`, so Windows shows a
UAC prompt on launch.

## Safety & ethics

Rescue is a **defensive** tool: it removes malware's hold on a machine and helps
recover data. It uses only documented APIs, is gated behind UAC, and defaults to
read-only reporting. Use it only on systems you own or are authorized to
administer. Because Lockdown Breaker can also *change* policy and delete policy
files, always review a scan before running `--fix`, and keep backups.

## License

Provided as-is for defensive, educational, and administrative use. No warranty.
