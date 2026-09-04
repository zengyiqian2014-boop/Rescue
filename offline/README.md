# Rescue — Offline WinPE Rescue (Phase 1b)

The **only reliable** way to clear a Microsoft-signed / enforced WDAC
(Code-Integrity / S-mode) policy, re-dropping persistence, and full-screen
lockers is to fight them **while the malware isn't running** — from a WinPE /
WinRE boot environment that boots *its own* Windows and doesn't enforce the
infected disk's policy.

Two scripts, same job, pick by what your boot media has:

| File | Needs | Use it when |
| --- | --- | --- |
| `Rescue-Offline.ps1` | WinPE **with PowerShell** (Hiren's BootCD PE, Medicat, Sergei Strelec, ADK+PS) | default — richer detection, per-user hives, autostart report |
| `rescue-offline.cmd` | **any** WinPE (bare `reg.exe`/`del`) | your boot USB has no PowerShell |

Both are **dry-run by default** and **back up every file** before deleting.

## What they remove

- **Dropped WDAC / Code-Integrity policy** — `SiPolicy.p7b` and
  `CiPolicies\Active\*.cip` under `System32\CodeIntegrity`, **and the EFI copy**
  at `\EFI\Microsoft\Boot\CiPolicies\Active\*.cip`. Offline, the file is just a
  file — the Microsoft signature can't stop you deleting it, and with no file to
  load at next boot the lock is gone.
- **Machine-wide restriction policies** + **Winlogon shell/Userinit hijack**
  (from the offline `SOFTWARE` hive).
- **Per-user restriction policies** (PowerShell version, from each user's
  `NTUSER.DAT`) and a **report of Run/RunOnce autostart entries** so you can
  spot and delete the dropper that would otherwise re-infect on reboot.

## How to build the boot USB

Easiest (already includes PowerShell + tools): **Hiren's BootCD PE**.

1. On a *clean* PC, download Hiren's BootCD PE (free) and **Rufus**.
2. Rufus → select the Hiren's ISO → write to an 8 GB+ USB.
3. Copy this whole `offline/` folder onto the USB (so the scripts ride along).

Or roll your own with the **Windows ADK**: `copype amd64 C:\WinPE`, add the
`WinPE-PowerShell` optional component, `MakeWinPEMedia /UFD C:\WinPE U:`.

## How to run it

1. Boot the target PC from the USB (F12 / boot menu; disable Secure Boot only if
   a signed policy resists removal — see below).
2. Open the command prompt / terminal in WinPE.
3. Find your USB and the infected Windows volume — letters differ in WinPE:
   ```
   diskpart
   list vol            ← note the Windows volume, and the FAT32 "System" = EFI
   exit
   ```
4. **Scan first** (change nothing):
   ```
   :: PowerShell media
   powershell -ExecutionPolicy Bypass -File X:\offline\Rescue-Offline.ps1

   :: bare WinPE
   X:\offline\rescue-offline.cmd
   ```
5. Review the findings, then **apply**:
   ```
   powershell -ExecutionPolicy Bypass -File X:\offline\Rescue-Offline.ps1 -Fix
   :: or
   X:\offline\rescue-offline.cmd /FIX
   ```
6. **Reboot** into Windows normally (remove the USB).

### If a signed policy is also anchored in EFI

The scripts auto-scan lettered volumes for the EFI copy. If the EFI System
Partition isn't lettered, assign one and point the script at it:

```
diskpart
list vol
select vol <the FAT32 System volume>
assign letter=S
exit

powershell -ExecutionPolicy Bypass -File X:\offline\Rescue-Offline.ps1 -EfiDrive S -Fix
:: or
X:\offline\rescue-offline.cmd D: S: /FIX
```

If it *still* won't clear (rare, firmware-anchored), enter UEFI setup, **turn
Secure Boot off temporarily**, delete the EFI copy, boot once, then turn Secure
Boot back on.

## After the rescue

- The dropped policy and the shell hijack are gone, so `.exe` runs again and the
  desktop is back.
- **Delete the dropper** you saw in the `[autostart]` report, or it re-infects.
  When the machine boots, run the live tools to finish: `lockdown_breaker --fix`
  and leave `ransom_guard` running.
- Keep the `RescueBackup` folder until you're sure everything works — it holds
  the removed policy files (also useful as forensic evidence).
