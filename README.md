# Rescue

An **active-defense** ransomware rescue & anti-malware toolkit for Windows —
built to *unlock*, *clean*, and *guard* a machine that malware has taken over.
Cross-compiled with **MinGW** for both **x86_64** and **ARM64** Windows.

> **Status: work-in-progress, honestly labelled.** Modules 1–5 build and run;
> Module 6 is reviewable source that needs a WDK build and a signing cert. Read the
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
| **3** | **Anti-ransomware guard** | Canary files + watcher + mass-change detection → freeze the culprit's process tree; **ETW gives deterministic per-process attribution** (no driver), heuristic fallback | ✅ **working** |
| **4** | **Scanner** | Heuristic + hash on-demand scanner: Authenticode triage, Mark-of-the-Web, PE structure analysis, script markers, quarantine, scheduled scans, optional ClamAV hand-off | ✅ **working** |
| **5** | **Watchdog** | Windows service that keeps the guard alive + a paired companion; kill either and the other restarts it | ✅ **working** |
| **6** | **Kernel minifilter** | The "can't be killed" tier — per-write attribution in kernel. Source complete + install/revert scripts; needs WDK build + Microsoft attestation signing | 🧩 **source** |

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

**Attribution — deterministic, without a driver.** `ReadDirectoryChangesW`
tells a watcher *that* files changed, not *which process* changed them. Rescue
gets the missing half from a real-time **ETW** session on the
`Microsoft-Windows-Kernel-File` provider, whose WRITE / RENAME / DELETE events
each carry the requesting **process id**. So when the guard trips it counts the
actual file-modifying operations per process over a short window and freezes the
one that did them — the *exact* culprit, not a guess — with **Secure Boot and
Memory Integrity left fully on** and no kernel driver. It needs elevation (a
real-time ETW session does); if the session can't start it falls back to ranking
processes by write-I/O rate (the previous heuristic), and the banner says which
tier is live.

The one thing ETW still cannot do is **block** a write before it lands — only an
in-kernel pre-write callback (Phase 6, signed driver) can. Attribution does not
need the kernel, and this is it. The guard **suspends** (reversible) by default,
logs exactly what it acted on, and never touches OS-critical processes (a
built-in whitelist).

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

## Module 4 — Scanner

An on-demand file scanner. Being straight about the hard part first: **a real
signature database is an operational product**, not something a source tree can
ship — millions of samples and daily updates. So this scanner is built on the
three things that work *without* a virus database, and it delegates to a real
engine when one is installed.

```
scanner                        quick scan: Downloads, Desktop, Documents, Temp,
                               Roaming, Public, startup folders
scanner --full                 every fixed drive (skips WinSxS/servicing)
scanner --path DIR|FILE        scan a specific path (repeatable)
scanner --db HASHES.txt        SHA-256 blocklist (paste IOC hashes straight in)
scanner --min-score N          report threshold (default 4; >= 8 prints HIGH)
scanner --clam                 run a local ClamAV over the detections
scanner --quarantine           move detections aside (reversible)
scanner --list-quarantine      show what has been quarantined
scanner --restore ID           put a quarantined file back
scanner --schedule-daily 03:00 register a daily scheduled scan
```

**What it actually reasons about**

1. **Authenticode trust first** (`signature.h`, embedded *and* catalog). A file
   vouched for by a trusted signer is the overwhelming majority of a clean disk;
   clearing it up front is what makes scanning the rest affordable.
2. **Mark-of-the-Web.** Windows records download provenance in the
   `:Zone.Identifier` alternate data stream. *Downloaded + unsigned + executable*
   is the highest-yield triage signal on a real infection, so those files get
   priority and the report prints the originating URL when it's recorded.
3. **PE structure.** Packer-grade entropy in the code section, a section that is
   both writable and executable, packer section names (`UPX0`, `.vmp0`, …), an
   empty import table (APIs resolved at runtime), TLS callbacks, a mostly-overlay
   file, a name that impersonates a system binary from the wrong directory, a
   double extension (`invoice.pdf.exe`).
4. **Script markers** for `.ps1/.vbs/.js/.hta/.bat/.lnk` droppers — encoded
   commands, `FromBase64String` + `IEX`, hidden-window execution policy bypass,
   `certutil` as a decoder, and the destructive tells (`vssadmin delete shadows`,
   `bcdedit /set recoveryenabled no`, Defender exclusions).

**Scores are a ranking for a human, not a verdict.** Every point printed carries
its reason, so you can see exactly why a file ranked where it did. Only a hash
blocklist hit is reported as a fact (`KNOWN-BAD`); everything else is a weighted
heuristic. Unsigned *alone* scores 1 — far below the threshold — which is why a
sweep of 700 unsigned binaries produces zero findings.

**Quarantine is reversible by construction:** the file is *moved* (never
deleted) into `%ProgramData%\Rescue\Quarantine` and an append-only manifest
records the original path, hash, score, and reasons, so `--restore` puts it back.

**Why not ClamAV built in?** `libclamav` is MSVC/autotools C that does not
cross-compile with MinGW; vendoring a broken half-port would be worse than being
honest. If you have a real ClamAV install, `--clam` hands the flagged files to
`clamdscan`/`clamscan` — its engine and daily signatures beat anything here.

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
[`driver/`](driver/); the install/revert scripts are in
[`installer/`](installer/). **It is WDK/MSVC code — it can't be built with MinGW and is
excluded from `make`.** Loading it requires a signed driver, and **self-signing does not help**:
kernel Code Integrity does not consult the machine's certificate stores, so no
"accept our certificate during setup" flow will make it load. The only path to
other people's machines is an **EV certificate + Microsoft attestation
signing**; test-signing mode is a developer-only facility that requires Secure
Boot off. [`installer/`](installer/) implements both paths — the production one
changes nothing about the machine, and the lab one takes itemised typed consent
and reverts exactly what it changed. This is the one tier that can't be a
cross-compiled `.exe`, and the docs are explicit about why.

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
make x64      # -> build/x86_64/{lockdown_breaker,ransom_guard,asep_cleaner,watchdog,scanner}.exe
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
