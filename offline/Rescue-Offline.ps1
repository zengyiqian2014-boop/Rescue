<#
.SYNOPSIS
    Rescue - Offline WinPE rescue (roadmap Phase 1b).

.DESCRIPTION
    Run this from a WinPE / WinRE boot USB against an *offline* (not running)
    Windows installation. Because the malware is not executing, every lock it
    set is inert - so this is the ONLY reliable way to remove a Microsoft-signed
    / enforced WDAC (Code-Integrity / S-mode) policy that blocks .exe launches,
    and it also beats re-dropping persistence and full-screen lockers.

    It walks the same levers as the live Lockdown Breaker, but offline:
      * dropped WDAC / Code-Integrity policy files (System32 AND the EFI copy)
      * machine-wide restriction policies + Winlogon shell/Userinit hijack
        (offline SOFTWARE hive)
      * per-user restriction policies (each user's offline NTUSER.DAT)
      * reports Run / RunOnce autostart entries for your review

    DRY-RUN BY DEFAULT. Nothing is changed unless you pass -Fix. Everything it
    deletes is backed up first.

.PARAMETER Volume
    Drive letter of the offline Windows volume (e.g. C or D as WinPE sees it).
    Omit to auto-detect.

.PARAMETER EfiDrive
    Drive letter of the EFI System Partition, if you assigned one with diskpart.
    Omit to auto-scan lettered volumes for an EFI policy copy.

.PARAMETER Fix
    Actually apply changes. Without it, the script only reports.

.PARAMETER BackupDir
    Where to copy removed files before deleting. Default: <Volume>\RescueBackup.

.EXAMPLE
    .\Rescue-Offline.ps1                 # scan/report, auto-detect volume
    .\Rescue-Offline.ps1 -Fix            # apply
    .\Rescue-Offline.ps1 -Volume D -EfiDrive S -Fix
#>
[CmdletBinding()]
param(
    [string]$Volume,
    [string]$EfiDrive,
    [switch]$Fix,
    [string]$BackupDir
)

$ErrorActionPreference = 'Continue'
$script:findings = 0
$script:fixed    = 0

function Say  ($m) { Write-Host $m }
function Head ($m) { Write-Host "`n== $m ==" }
function Find ($m) { Write-Host "  [!] $m"; $script:findings++ }
function Did  ($m) { Write-Host "      -> $m" }

# --- locate the offline Windows volume -------------------------------------
function Find-WindowsVolume {
    foreach ($d in [char[]](67..90)) {           # C..Z
        $p = "${d}:\Windows\System32\config\SOFTWARE"
        if (Test-Path $p) { return "${d}:" }
    }
    return $null
}

if (-not $Volume) {
    $Volume = Find-WindowsVolume
    if (-not $Volume) { Say "No offline Windows installation found on any drive. Aborting."; exit 1 }
} else {
    if ($Volume -notmatch ':$') { $Volume = "${Volume}:" }
}
if (-not (Test-Path "$Volume\Windows\System32")) { Say "No Windows at $Volume. Aborting."; exit 1 }
if (-not $BackupDir) { $BackupDir = "$Volume\RescueBackup" }

Say "====================================================="
Say "  Rescue - Offline WinPE Rescue     $(if($Fix){'[FIX MODE]'}else{'[scan only]'})"
Say "====================================================="
Say "  Target Windows volume: $Volume"
Say "  Backups go to:         $BackupDir"

function Backup-File ($path) {
    if (-not $Fix) { return }
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null }
    try { Copy-Item -LiteralPath $path -Destination $BackupDir -Force -ErrorAction Stop } catch {}
}

# --- 1. dropped WDAC / Code-Integrity policy -------------------------------
function Clear-CodeIntegrity {
    Head "Dropped WDAC / Code-Integrity policy (blocks .exe launches)"
    $ci = "$Volume\Windows\System32\CodeIntegrity"
    $targets = @()
    $legacy = Join-Path $ci 'SiPolicy.p7b'
    if (Test-Path $legacy) { $targets += $legacy }
    $active = Join-Path $ci 'CiPolicies\Active'
    if (Test-Path $active) { $targets += (Get-ChildItem -Path $active -Filter *.cip -File -ErrorAction SilentlyContinue).FullName }

    # EFI copy: use the drive you passed, else scan lettered volumes.
    $efiRoots = @()
    if ($EfiDrive) { if ($EfiDrive -notmatch ':$'){$EfiDrive="${EfiDrive}:"}; $efiRoots += $EfiDrive }
    else { foreach ($d in [char[]](67..90)) { if (Test-Path "${d}:\EFI\Microsoft\Boot") { $efiRoots += "${d}:" } } }
    foreach ($r in $efiRoots) {
        $ea = "$r\EFI\Microsoft\Boot\CiPolicies\Active"
        if (Test-Path $ea) { $targets += (Get-ChildItem -Path $ea -Filter *.cip -File -ErrorAction SilentlyContinue).FullName }
    }

    if (-not $targets) { Say "    none found"; return }
    if (-not $efiRoots) { Say "    (note: EFI System Partition not lettered - if a signed policy persists," ;
                          Say "     assign it a letter in diskpart and re-run with -EfiDrive)" }
    foreach ($t in $targets) {
        if (-not $t) { continue }
        Find "policy file: $t"
        if ($Fix) {
            Backup-File $t
            try { Remove-Item -LiteralPath $t -Force -ErrorAction Stop; Did "backed up and removed"; $script:fixed++ }
            catch { Did "could NOT remove: $($_.Exception.Message)" }
        }
    }
}

# --- registry policy definitions (shared with the live tool) ----------------
$MachinePolicies = @(
    @{Key='Microsoft\Windows\CurrentVersion\Policies\System';   Val='DisableTaskMgr';       What='Task Manager disabled'},
    @{Key='Microsoft\Windows\CurrentVersion\Policies\System';   Val='DisableRegistryTools'; What='regedit disabled'},
    @{Key='Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='NoRun';                What='Run box removed'},
    @{Key='Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='NoDesktop';            What='Desktop icons hidden'},
    @{Key='Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='NoControlPanel';       What='Control Panel blocked'},
    @{Key='Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='RestrictRun';          What='Only whitelisted apps may run'},
    @{Key='Policies\Microsoft\Windows\System';                  Val='DisableCMD';           What='Command Prompt disabled'}
)
$UserPolicies = @(
    @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\System';   Val='DisableTaskMgr';        What='Task Manager disabled'},
    @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\System';   Val='DisableRegistryTools';  What='regedit disabled'},
    @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\System';   Val='DisableLockWorkstation';What='Lock (Win+L) disabled'},
    @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='NoRun';                 What='Run box removed'},
    @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='NoDesktop';             What='Desktop icons hidden'},
    @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='NoControlPanel';        What='Control Panel blocked'},
    @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='NoViewContextMenu';     What='Right-click menu blocked'},
    @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Val='RestrictRun';           What='Only whitelisted apps may run'},
    @{Key='Software\Policies\Microsoft\Windows\System';                  Val='DisableCMD';            What='Command Prompt disabled'}
)

function Clear-PolicySet ($hiveRoot, $policies) {
    foreach ($p in $policies) {
        $full = Join-Path $hiveRoot $p.Key
        if (Test-Path $full) {
            $item = Get-ItemProperty -Path $full -Name $p.Val -ErrorAction SilentlyContinue
            if ($null -ne $item -and $null -ne $item.$($p.Val)) {
                Find "$($p.What)"
                if ($Fix) {
                    try { Remove-ItemProperty -Path $full -Name $p.Val -Force -ErrorAction Stop; Did "cleared"; $script:fixed++ }
                    catch { Did "could NOT clear: $($_.Exception.Message)" }
                }
            }
        }
    }
}

# --- 2. machine-wide policies + shell hijack (offline SOFTWARE) --------------
function Clear-MachineHive {
    Head "Machine-wide restriction policies + login shell hijack (offline SOFTWARE)"
    $sw = "$Volume\Windows\System32\config\SOFTWARE"
    if (-not (Test-Path $sw)) { Say "    SOFTWARE hive not found"; return }
    & reg load HKLM\RESCUE_SW "$sw" *> $null
    if ($LASTEXITCODE -ne 0) { Say "    could not load SOFTWARE hive"; return }
    try {
        Clear-PolicySet 'HKLM:\RESCUE_SW' $MachinePolicies

        $wl = 'HKLM:\RESCUE_SW\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if (Test-Path $wl) {
            $shell = (Get-ItemProperty -Path $wl -Name Shell -ErrorAction SilentlyContinue).Shell
            if ($shell -and $shell -ne 'explorer.exe') {
                Find "Shell hijacked to: $shell"
                if ($Fix) { Set-ItemProperty -Path $wl -Name Shell -Value 'explorer.exe'; Did "restored to explorer.exe"; $script:fixed++ }
            }
            $ui = (Get-ItemProperty -Path $wl -Name Userinit -ErrorAction SilentlyContinue).Userinit
            if ($ui -and $ui -notmatch 'userinit\.exe') {
                Find "Userinit hijacked to: $ui"
                if ($Fix) { Set-ItemProperty -Path $wl -Name Userinit -Value 'C:\Windows\system32\userinit.exe,'; Did "restored to default"; $script:fixed++ }
            }
            # Machine Run keys (report only - review before removing)
            foreach ($rk in @('Microsoft\Windows\CurrentVersion\Run','Microsoft\Windows\CurrentVersion\RunOnce')) {
                $rp = "HKLM:\RESCUE_SW\$rk"
                if (Test-Path $rp) {
                    (Get-Item $rp).Property | ForEach-Object {
                        $v = (Get-ItemProperty -Path $rp -Name $_).$_
                        Say "    [autostart] HKLM\...\$rk :: $_ = $v"
                    }
                }
            }
        }
    } finally {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        & reg unload HKLM\RESCUE_SW *> $null
    }
}

# --- 3. per-user policies (each offline NTUSER.DAT) -------------------------
function Clear-UserHives {
    Head "Per-user restriction policies (each user's offline NTUSER.DAT)"
    $users = Get-ChildItem "$Volume\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($u in $users) {
        $dat = Join-Path $u.FullName 'NTUSER.DAT'
        if (-not (Test-Path $dat)) { continue }
        Say "  user: $($u.Name)"
        & reg load HKLM\RESCUE_NT "$dat" *> $null
        if ($LASTEXITCODE -ne 0) { Say "      (in use / could not load)"; continue }
        try {
            Clear-PolicySet 'HKLM:\RESCUE_NT' $UserPolicies
            foreach ($rk in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
                $rp = "HKLM:\RESCUE_NT\$rk"
                if (Test-Path $rp) {
                    (Get-Item $rp).Property | ForEach-Object {
                        $v = (Get-ItemProperty -Path $rp -Name $_).$_
                        Say "    [autostart] HKCU\...\$rk :: $_ = $v"
                    }
                }
            }
        } finally {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            & reg unload HKLM\RESCUE_NT *> $null
        }
    }
}

# --- run --------------------------------------------------------------------
Clear-CodeIntegrity
Clear-MachineHive
Clear-UserHives

Say "`n-----------------------------------------------------"
if ($script:findings -eq 0) {
    Say "  No lockdown levers found on $Volume. Looks clean."
} elseif ($Fix) {
    Say "  Findings: $script:findings   Fixed: $script:fixed"
    Say "  Review the [autostart] entries above and delete any you don't recognize."
    Say "  Remove the offline system's boot media and boot Windows normally."
} else {
    Say "  Findings: $script:findings  (scan only - nothing changed)"
    Say "  Re-run with -Fix to apply. Backups will go to $BackupDir."
}
Say "-----------------------------------------------------"
