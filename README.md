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
| **1** | **Lockdown Breaker** | Undo restriction policies, shell hijack, frozen input, lock overlays, dropped WDAC policy, **screen-takeover effects (MEMZ-style rotation/flip + effect process)** — live | ✅ **working** |
| **1b** | **Offline WinPE rescue** | Same cleanup from a boot USB, where the malware isn't running (beats signed/enforced policies) | ✅ **working** |
| **2** | **ASEP Cleaner** | Enumerate *all* autostart points (Run, services, tasks, IFEO, Winlogon, startup) and flag/quarantine unsigned entries — Authenticode-verified, generic, not per-virus | ✅ **working** |
| **3** | **Anti-ransomware guard** | Canary files + watcher + mass-change detection → freeze the culprit's tree; **ETW deterministic attribution** + **multi-factor wiper detection** (rate + sustain + trust) + **critical-sector tripwire** (MBR/GPT/VBR tamper) + raw-disk **write shield**, heuristic fallback | ✅ **working** |
| **4** | **Scanner** | Heuristic + hash on-demand scanner: Authenticode triage, Mark-of-the-Web, PE structure analysis, script markers, quarantine, scheduled scans, optional ClamAV hand-off | ✅ **working** |
| **5** | **Watchdog** | Windows service that keeps the guard alive + a paired companion; kill either and the other restarts it | ✅ **working** |
| **6** | **Kernel minifilter** | The "can't be killed" tier — per-write attribution **and in-kernel write veto** (inspect each write, allow/deny before it lands). Source complete + install/revert scripts; needs WDK build + Microsoft attestation signing | 🧩 **source** |
| **7** | **Backup & Restore** | Ransomware-resilient `.rbk` backup of user data + settings + HKCU; **scheduled versioned snapshots to a chosen disk (Time Machine-style)**, retention, and recovery-disk builder | ✅ **working** |

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
- **Screen-takeover effects (MEMZ / rainbow-cat and imitators)** — resets a
  flipped/rotated display back to default, and with `--kill-effects` terminates
  the process tree behind a full-screen effect overlay (the ones that ignore a
  polite `WM_CLOSE`), so the mouse-jitter/tunnel/rotation stops and you can work.
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

**Wiper defense (raw-disk writes).** A ransomware encrypts *files*, which the
directory watcher sees. A **wiper** often skips the filesystem entirely, opening
the raw disk (`\\.\PhysicalDrive0`) and streaming zeros to sectors — producing
no file-change events at all. So a second monitor watches each process's raw
write-**byte** rate — but no single factor is enough, and each has an evasion:

- **rate alone** — a legitimate disk imager (Rufus, Win32DiskImager, `dd`, a USB
  writer) writes to a raw disk at the *same* rate as a wiper;
- **signature alone** — malware can be signed (stolen/abused certs), so a
  signature is **not a free pass**, only a raised bar;
- **one burst** — says little; a wiper runs **sustained** (blindly continuous or
  paced/bursty, but for a long time, because it must cover the whole disk).

So it *scores*: a process over the byte-rate budget (`--wiper-mbps`, default
150 MB/s) accrues "sustain" seconds that persist across brief dips (catching a
*paced* wiper, not just a dumb one). An **unsigned** writer trips after a short
sustain; a **signed** one is not exempt but must sustain far longer before it
trips — evidence proportional to trust. The response **suspends** the culprit,
which is itself the user-mode "stop": a frozen process issues no more writes.

**Prevention, not just detection — the disk write shield (`--shield`).** A
raw-disk attacker (an MBR overwriter like MEMZ, a zero-fill wiper) must open
`\\.\PhysicalDriveN` for *write*. If the guard opens the same device **first**
with write-sharing denied (`FILE_SHARE_READ` only) and holds the handle, every
later attempt to open it for write fails with a sharing violation — so the
attacker never gets its write handle. That stops the overwrite *before* it
happens, from user mode, no signing. The shield covers **both** the physical drives *and* each fixed volume device
(`\\.\C:` …), which closes a second trick: `FSCTL_DISMOUNT_VOLUME` can force a
mounted volume off even with files open, and its purpose is to make the volume's
sectors raw-writable afterwards. We can't stop the dismount call itself from
user mode (that needs the kernel filter), but holding the volume device with
write-sharing denied means the attacker still can't get a write handle to those
sectors *after* dismounting — so the dismount buys them nothing. Holding the
volume handle does not block normal file I/O (that goes through the mounted
filesystem, not the raw volume handle), so it's safe on the live system volume.

It is best-effort and has real costs: if another component already holds a
device with write access the restrictive open fails, and while the shield is up
a *legitimate* disk tool is blocked too (stop the guard to use one). The live
system volume still can't be `FSCTL_LOCK_VOLUME`'d outright (the registry/
pagefile keep handles open) — but the raw-device shields cover the MBR/GPT and
raw-sector vectors a volume lock wouldn't anyway.

**Critical-sector tripwire.** A *surgical* attack — MEMZ overwriting the MBR, a
tool zeroing the GPT header or a volume boot record — writes only a few hundred
bytes, far below the byte-**rate** monitor's radar. But those bytes land in a
tiny, fixed set of high-value sectors that shouldn't change outside a deliberate
partition operation. So the guard snapshots them at startup (MBR + GPT header of
each physical drive, and each fixed volume's boot record) and **polls them
read-only**; if one changes, it alarms and responds. It watches the *real*
structures rather than writing decoy bytes — writing decoys would risk
corrupting data and wouldn't slow an attacker anyway; the value is detecting the
change. This is detection with a short poll-window race, complementing the shield
(prevention) and the rate monitor (bulk wipes): rate catches the batch wiper,
the tripwire catches the boot/partition surgeon, the shield blocks both.

**What still needs the kernel (Module 6):** telling *which sectors* a write
targets (to allow a legit write to a data region but block one to the MBR-GPT
region) and per-write pre-blocking with a policy decision — that is the
minifilter's pre-operation callback. The shield is coarse (all-or-nothing on a
device); the kernel filter is surgical. Data already overwritten is gone
regardless — only the offline backup (Module 7) survives that.

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

## Module 7 — Backup & Restore

Every other module tries to *stop* damage. This one *undoes* it. A correctly
encrypted file cannot be decrypted (that is mathematics, stated up top) — so the
only real recovery is a copy made **before** the attack, kept somewhere the
malware could not reach. Module 7 makes that copy, and restores it.

```
backup --out FILE.rbk               back up user data, settings, HKCU, program list
backup --list FILE.rbk              show what a container holds
backup --restore FILE.rbk --to DIR extract everything under DIR
```

**What it backs up — and pointedly what it does not.** The OS is *excluded on
purpose*: you reinstall Windows from clean media, not from a backup that might
carry the infection forward. What matters, and what it captures, is the layer a
user can actually change and cannot get back:

- profile document folders (Desktop, Documents, Pictures, Videos, Music,
  Downloads, Favorites, …, and OneDrive if present);
- application settings in Roaming and Local AppData, **minus caches/temp**
  (Temp, INetCache, thumbcache, browser Cache/GPUCache/Code Cache, UWP package
  caches) — those are churn, not settings, and would bloat the backup;
- the **HKCU** registry hive (personalization, environment variables, file
  associations);
- a reference list of installed programs, so you know what to reinstall.

**The container.** One self-describing `.rbk` file. Each member is stored
compressed (Windows' built-in XPRESS_HUFF) *only when that is actually smaller* —
already-compressed files (jpg, mp4, zip) are kept raw rather than wastefully
re-packed. Restore needs no external index and reconstructs paths, timestamps,
and attributes. Restore refuses `..` path components, so a crafted container
can't write outside the target directory. The registry export is restored **as a
file** for you to review and import, never merged silently.

**Two things this module deliberately does not pretend to do**, because being
straight about the limits is the point of this project:

- **It does not bundle a Windows ISO** into rescue media. Redistributing Windows
  violates Microsoft's licence — use the official Media Creation Tool for clean
  media, and let this restore the user layer on top of it.
- **It is not a "leaves no trace" reboot.** A reboot that truly discards every
  disk change needs write-redirection in a filesystem filter driver — the same
  signed-kernel tier as Phase 6 (think Deep Freeze). A user-mode tool cannot do
  that honestly, so it doesn't claim to.

Run it elevated (it borrows SYSTEM to read ACL-locked profile files), and
**keep the `.rbk` on external or offline media** — a backup the ransomware can
encrypt along with everything else is not a backup.

### Scheduled snapshots (Time Machine for Windows)

A backup you have to remember to run is a backup you won't have. Module 7 can
run itself on a schedule, keeping a **versioned history** on a disk you choose —
the Windows equivalent of Apple's Time Machine.

```
backup --snapshot E:                 one timestamped snapshot to E:\RescueBackups
backup --list-snapshots E:           the history on that disk
backup --schedule daily --disk E: --keep 14      automate it (keep last 14)
backup --schedule custom --every 6 --unit hour --disk E:
backup --schedule-status | --unschedule
```

Pick the cadence by how much you'd hate to lose:

| Data importance | Suggested schedule |
| --- | --- |
| Low — you could recreate it | `--schedule monthly` |
| Important | `--schedule every5days` or `--schedule daily` |
| Critical — can't lose a day | `--schedule hourly` |

`--keep N` prunes the oldest so the disk doesn't fill. **Per-second backups are
refused on purpose**: a backup takes far longer than a second and the scheduler's
floor is one minute — the tool says so rather than pretending. Point `--disk` at
an **external** drive and, ideally, unplug it between runs: a schedule that keeps
the backup disk permanently mounted is convenient but reachable by the very
ransomware you're guarding against.

### Making the backup disk a recovery disk

`offline/Make-RescueDisk.ps1` turns a USB into a recovery stick, at three honest
levels:

- **`-Mode data`** — copies the Rescue tools, the offline cleanup scripts, and
  your newest `.rbk` onto the stick. Needs nothing from Microsoft. Boot any
  Windows/WinPE media, then clean and restore from the stick.
- **`-Mode bootable`** — a stick that boots on its own into WinPE with the tools
  ready. WinPE is Microsoft's and **can't be redistributed**, so the script uses
  your free **Windows ADK + WinPE add-on** (it prints the one `winget` command if
  they're missing) to build the boot media, then lays the Rescue payload on top.
- **`-Mode system-image`** — a full, block-level image of the whole OS via
  Windows' built-in **`wbadmin`** (free, no signing), so recovery restores the
  machine to its previous state, **bootable and ready to use**. Recover it from
  Windows install media → *System Image Recovery*.
- **`-Mode oneclick`** — combines an **official Windows ISO** (your machine
  downloads it from Microsoft — Windows is never bundled or redistributed here)
  with your newest `.rbk` and a Microsoft-supported **`autounattend.xml`** answer
  file, so booting the stick runs Windows Setup, skips the OOBE nag screens, and
  **auto-restores your data, settings and personalization on first logon**. It is
  *near*-one-click on purpose: you still confirm which disk and edition in Setup,
  because an answer file that silently wipes a disk is dangerous. **Applications
  are not restored** (licensed separately — the backup keeps a program list to
  reinstall from), and **activation is not handled**: no key is written unless you
  pass your own `-ProductKey`, and the script contains no activation logic of any
  kind. If you don't pass `-Iso`, it points you at Microsoft's official download
  and fetches the official Media Creation Tool rather than shipping Windows.

Which to use: the `.rbk` snapshots restore *your files and settings* onto a
clean or existing Windows (apps must be reinstalled — that's why the backup
includes a program list); the `wbadmin` system image restores *the entire OS
exactly*. The first is smaller and malware-version-proof; the second is
"one-click back to how it was". Keep both if the data is critical.

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
make x64      # -> build/x86_64/{lockdown_breaker,ransom_guard,asep_cleaner,watchdog,scanner,backup}.exe
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
