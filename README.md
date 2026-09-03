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
| 1b | Offline WinPE rescue | Same cleanup from a boot USB, where the malware isn't running (beats signed/enforced policies) | planned |
| 2 | ASEP cleaner | Enumerate *all* autostart points (Run, services, drivers, tasks, WMI, IFEO, Winlogon) and quarantine unknown/unsigned entries — generic, not per-virus | planned |
| 3 | Anti-ransomware guard | Honeypot canary files + directory watcher + entropy spike detection → suspend/kill the offending process tree; protect Shadow Copies from deletion | planned |
| 4 | Scanner | Integrate the **ClamAV** engine + scheduled scans; downloaded files (Mark-of-the-Web) get top-priority deep scan | planned |
| 5 | Watchdog service | Paired self-protecting services that restart each other and the guard | planned |
| 6 | Kernel minifilter driver | The "can't be killed" real-time tier (requires code-signing) | research |

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

## Building

```bash
make          # both architectures
make x64      # -> build/x86_64/lockdown_breaker.exe   (mingw-w64 GCC)
make arm64    # -> build/arm64/lockdown_breaker.exe     (llvm-mingw Clang)
```

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
