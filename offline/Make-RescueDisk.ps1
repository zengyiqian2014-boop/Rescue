<#
.SYNOPSIS
    Turn a USB drive into a Rescue recovery disk: the offline cleanup tools, the
    Rescue binaries, and (optionally) your latest backup snapshot, all on one
    stick you can boot when the system itself is dead.

.DESCRIPTION
    There are two honestly different "recovery disk" ambitions, and this script
    supports both, because they need different things:

    (A) A DATA + TOOLS stick (no special base required).
        Copies the Rescue tools, the offline cleanup scripts, and your newest
        .rbk snapshot onto the USB. You boot any Windows install media or WinPE,
        then run the tools from this stick to clean the machine and restore your
        files. This part needs nothing from Microsoft and is what --data does.

    (B) A BOOTABLE WinPE recovery stick.
        A stick that boots on its own into a mini-Windows (WinPE) with the
        Rescue tools ready. WinPE itself is Microsoft's, shipped in the free
        Windows ADK + "WinPE add-on". We CANNOT redistribute WinPE (licence), so
        this script does not bundle it - it detects your ADK install and uses
        copype/MakeWinPEMedia to build the boot stick, then lays the Rescue
        payload on top. If the ADK isn't present it tells you the one command to
        get it and stops. This is what --bootable does.

    (C) A full "boot and you're back exactly" system image.
        That is a block-level image of the whole OS, which Windows already makes
        with wbadmin (built in, free, no signing). --system-image wraps it and
        writes the image to the USB; recovery is done from Windows install
        media's "System Image Recovery". See the note it prints.

.PARAMETER Drive
    Target USB drive letter, e.g. F:. Its contents are used as-is for --data;
    --bootable REFORMATS it (it will confirm first).

.PARAMETER Snapshot
    Path to a .rbk to include. Default: the newest snapshot on --BackupDisk.

.PARAMETER BackupDisk
    Where to look for the newest snapshot (a drive holding RescueBackups\).

    (D) A ONE-CLICK RESTORE stick (official Windows ISO + your .rbk).
        Combines an official Windows ISO (which YOUR machine downloads from
        Microsoft - we never bundle or redistribute Windows) with your newest
        .rbk and a Microsoft-supported answer file (autounattend.xml), so the
        stick installs a clean Windows unattended and then automatically
        restores your data, settings and personalization on first boot. This is
        what --oneclick does. Applications are NOT reinstalled (they are
        licensed separately - the backup keeps a program list so you know what
        to reinstall). ACTIVATION IS NOT HANDLED and not guaranteed: no product
        key is injected unless you supply your own with -ProductKey, and this
        script contains no activation logic of any kind.

.PARAMETER Mode
    data | bootable | system-image | oneclick  (default: data)

.PARAMETER Iso
    (oneclick) Path to an official Windows ISO you obtained from Microsoft. If
    omitted, the script points you at Microsoft's official download and, where
    possible, launches the official Media Creation Tool - it never ships Windows.

.PARAMETER ProductKey
    (oneclick, optional) YOUR OWN Windows product key, to place in the answer
    file. Omit it and no key is written; Setup may then prompt, and activation
    remains your responsibility. This script does not activate anything.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Drive,
    [string]$Snapshot,
    [string]$BackupDisk,
    [ValidateSet('data','bootable','system-image','oneclick')][string]$Mode = 'data',
    [string]$Iso,
    [string]$ProductKey
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Say($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
function Head($m){ Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }

$Drive = $Drive.TrimEnd('\')
if ($Drive -notmatch '^[A-Za-z]:$') { throw "Drive must look like F:" }
if (-not (Test-Path "$Drive\")) { throw "Drive $Drive not found - is the USB plugged in?" }

# Rescue binaries live next to this script's parent (build\<arch>) or are named on PATH.
$root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
function FindTool($name){
    foreach ($p in @("$root\build\x86_64\$name","$root\build\arm64\$name",".\$name")) {
        if (Test-Path $p) { return (Resolve-Path $p).Path }
    }
    return $null
}

function NewestSnapshot([string]$disk){
    if (-not $disk) { return $null }
    $dir = Join-Path $disk.TrimEnd('\') 'RescueBackups'
    if (-not (Test-Path $dir)) { return $null }
    Get-ChildItem $dir -Filter 'rescue-*.rbk' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName
}

function LayPayload([string]$dest){
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Head "Copying Rescue payload -> $dest"
    foreach ($t in 'lockdown_breaker.exe','asep_cleaner.exe','scanner.exe','backup.exe') {
        $src = FindTool $t
        if ($src) { Copy-Item $src (Join-Path $dest $t) -Force; Say "  tool: $t" Green }
        else      { Say "  [!] missing $t - build it first (make x64)" Yellow }
    }
    foreach ($s in 'Rescue-Offline.ps1','rescue-offline.cmd') {
        $src = Join-Path (Split-Path $PSCommandPath -Parent) $s
        if (Test-Path $src) { Copy-Item $src (Join-Path $dest $s) -Force; Say "  script: $s" Green }
    }
    if (-not $Snapshot) { $Snapshot = NewestSnapshot $BackupDisk }
    if ($Snapshot -and (Test-Path $Snapshot)) {
        Copy-Item $Snapshot (Join-Path $dest (Split-Path $Snapshot -Leaf)) -Force
        Say "  snapshot: $(Split-Path $Snapshot -Leaf)" Green
    } else {
        Say "  [i] no snapshot included (pass -Snapshot or -BackupDisk)" Yellow
    }
    # a one-liner the operator runs from WinPE
    $readme = @"
Rescue recovery disk
--------------------
1. Clean the offline system:   powershell -ExecutionPolicy Bypass -File Rescue-Offline.ps1
   (or the bare-batch rescue-offline.cmd)
2. Scan the offline drive:     scanner.exe --full   (point at the offline OS drive)
3. Restore your files:         backup.exe --restore rescue-YYYYMMDD-HHMMSS.rbk --to D:\Restored
   (D: = wherever you want them; do NOT restore onto a disk you are still recovering)
Boot code / partition repair is documented in offline\README.md (bootrec /fixmbr, etc.).
"@
    Set-Content -Path (Join-Path $dest 'RESCUE-README.txt') -Value $readme -Encoding UTF8
    Say "  RESCUE-README.txt written" Green
}

switch ($Mode) {
'data' {
    LayPayload (Join-Path "$Drive\" 'Rescue')
    Head 'Done (data + tools)'
    Say "Boot Windows install media or WinPE, then run the tools from $Drive\Rescue." Green
}
'bootable' {
    Head 'Bootable WinPE recovery stick'
    # Locate the ADK WinPE environment (copype).
    $copype = @(
        "$env:ProgramFiles(x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\copype.cmd",
        "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\copype.cmd"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $copype) {
        Say "[!] Windows ADK + WinPE add-on not found." Yellow
        Say "    WinPE is Microsoft's and cannot be bundled here. Install it (free):" Yellow
        Say "    winget install Microsoft.WindowsADK ; winget install Microsoft.ADKPEAddon" Cyan
        Say "    Then re-run with -Mode bootable." Yellow
        exit 1
    }
    Say "[!] -Mode bootable REFORMATS $Drive. Ctrl+C now to abort." Yellow
    $c = Read-Host "Type the drive letter again to confirm reformat of $Drive"
    if ("$c".TrimEnd('\').ToUpper() -ne $Drive.ToUpper()) { Say 'Not confirmed.' Green; exit 1 }
    $work = Join-Path $env:TEMP 'RescueWinPE'
    if (Test-Path $work) { Remove-Item $work -Recurse -Force }
    Say "building WinPE workspace ..." 
    & cmd /c "`"$copype`" amd64 `"$work`""
    LayPayload (Join-Path "$work\media" 'Rescue')
    $makemedia = Join-Path (Split-Path $copype -Parent) '..\..\Deployment Tools\amd64\Oscdimg' 'MakeWinPEMedia.cmd'
    $makemedia = Join-Path (Split-Path $copype) 'MakeWinPEMedia.cmd'
    Say "writing bootable media to $Drive ..."
    & cmd /c "`"$makemedia`" /UFD `"$work`" $Drive"
    Head 'Done (bootable WinPE + Rescue)'
    Say "This stick now boots into WinPE. Run \Rescue\RESCUE-README.txt's steps." Green
}
'system-image' {
    Head 'Full system image (Windows wbadmin, block-level)'
    Say "This makes a bootable, exact image of the whole OS so recovery restores"
    Say "the machine to its previous state, ready to use. It is Windows' own,"
    Say "built-in, free, and needs no signing. Writing the image to $Drive ..."
    Say ""
    Say "  wbadmin start backup -backupTarget:$Drive -include:C: -allCritical -quiet" Cyan
    & wbadmin start backup -backupTarget:$Drive -include:C: -allCritical -quiet
    Head 'Recovery instructions'
    Say "Boot Windows install media -> Repair your computer -> Troubleshoot ->"
    Say "System Image Recovery, and point it at $Drive. It restores C: exactly,"
    Say "bootable and ready. (Restores the WHOLE OS; use the .rbk data backup"
    Say "instead when you only want your files and settings back.)"
}
'oneclick' {
    Head 'One-click restore stick (official Windows ISO + your .rbk)'

    # --- 1. get an official Windows ISO (from Microsoft, never bundled) -------
    if (-not $Iso -or -not (Test-Path $Iso)) {
        Say "[i] No -Iso given. Windows is Microsoft's and is not shipped here;" Yellow
        Say "    your machine downloads it from Microsoft's official page:" Yellow
        Say "      https://www.microsoft.com/software-download/windows11" Cyan
        $mct = Join-Path $env:TEMP 'MediaCreationTool.exe'
        try {
            Say "    attempting the official Media Creation Tool ..."
            # Official Microsoft fwlink for the Windows 11 MCT.
            Invoke-WebRequest -UseBasicParsing `
                -Uri 'https://go.microsoft.com/fwlink/?linkid=2156295' `
                -OutFile $mct
            Say "    downloaded the official tool -> $mct" Green
            Say "    Run it to create an ISO, then re-run this script with -Iso <that ISO>." Yellow
        } catch {
            Say "    could not fetch the tool automatically; download the ISO from the" Yellow
            Say "    page above, then re-run with -Iso <path to the ISO>." Yellow
        }
        exit 1
    }
    $Iso = (Resolve-Path $Iso).Path
    Say "official ISO: $Iso" Green

    # --- 2. reformat the USB as a UEFI-bootable Windows installer -------------
    Say "[!] -Mode oneclick REFORMATS $Drive and ERASES it. Ctrl+C now to abort." Yellow
    $c = Read-Host "Type the drive letter again to confirm reformat of $Drive"
    if ("$c".TrimEnd('\').ToUpper() -ne $Drive.ToUpper()) { Say 'Not confirmed.' Green; exit 1 }

    $mount = Mount-DiskImage -ImagePath $Iso -PassThru
    $isoDrive = ($mount | Get-Volume).DriveLetter + ':'
    try {
        # FAT32 is required for the widest UEFI boot support, but install.wim
        # often exceeds FAT32's 4 GB file limit - so split it into .swm parts,
        # which Windows Setup reassembles. Everything else is copied verbatim.
        Say "copying Windows setup files to $Drive (this takes a while) ..."
        $installWim = Join-Path "$isoDrive\sources" 'install.wim'
        Get-ChildItem "$isoDrive\" -Recurse | ForEach-Object {
            $rel = $_.FullName.Substring($isoDrive.Length)
            $dst = Join-Path "$Drive\" $rel
            if ($_.PSIsContainer) { New-Item -ItemType Directory -Path $dst -Force | Out-Null }
            elseif ($_.Name -ne 'install.wim') { Copy-Item $_.FullName $dst -Force }
        }
        if (Test-Path $installWim) {
            if ((Get-Item $installWim).Length -gt 4GB) {
                Say "install.wim > 4 GB: splitting into .swm for FAT32 ..."
                & dism /Split-Image /ImageFile:"$installWim" `
                       /SWMFile:"$Drive\sources\install.swm" /FileSize:3800 | Out-Null
            } else {
                Copy-Item $installWim "$Drive\sources\install.wim" -Force
            }
        }
    } finally {
        Dismount-DiskImage -ImagePath $Iso | Out-Null
    }

    # --- 3. the answer file: unattended install + auto-restore ---------------
    # autounattend.xml at the USB root is a Microsoft-supported mechanism; Setup
    # reads it automatically. The FirstLogon step launches our restore, which
    # scans drives for the Rescue payload marker and applies the .rbk.
    $keyBlock = ''
    if ($ProductKey) {
        # The user's OWN key, if they chose to supply one. No activation logic.
        $keyBlock = "<ProductKey><Key>$ProductKey</Key></ProductKey>"
    }
    $unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="amd64"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State/v3"
               language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <ProtectYourPC>3</ProtectYourPC>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
      </OOBE>
      $keyBlock
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>cmd /c for %d in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist %d:\Rescue\Restore-AfterInstall.cmd call %d:\Rescue\Restore-AfterInstall.cmd</CommandLine>
          <Description>Rescue: restore user data and settings</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"@
    Set-Content -Path (Join-Path "$Drive\" 'autounattend.xml') -Value $unattend -Encoding UTF8
    Say "autounattend.xml written (unattended install + first-logon restore)" Green

    # --- 4. lay the Rescue payload (backup.exe + newest .rbk + restore hook) --
    $pay = Join-Path "$Drive\" 'Rescue'
    LayPayload $pay
    $restoreCmd = @"
@echo off
rem Rescue post-install restore. Runs at first logon from the USB.
setlocal
set HERE=%~dp0
for %%f in ("%HERE%rescue-*.rbk") do set RBK=%%f
if not defined RBK (echo No .rbk found next to this script & exit /b 1)
echo Restoring your files and settings from %RBK% ...
"%HERE%backup.exe" --restore "%RBK%" --to "%USERPROFILE%\RescueRestored"
echo.
echo Your data was restored to "%USERPROFILE%\RescueRestored".
echo Registry\HKCU.reg is there too - review, then double-click to import settings.
echo Reinstall applications using Reference\installed-programs.reg as a checklist.
echo (Windows activation is not handled by Rescue.)
pause
"@
    Set-Content -Path (Join-Path $pay 'Restore-AfterInstall.cmd') -Value $restoreCmd -Encoding ASCII
    Say "Restore-AfterInstall.cmd written" Green

    Head 'Done (one-click restore stick)'
    Say "Boot this USB. It runs Windows Setup; you confirm WHICH DISK to install" Green
    Say "to (left to you on purpose - an answer file that auto-wipes a disk is"    Green
    Say "dangerous), Setup skips the OOBE nag screens, and on first logon it"      Green
    Say "restores your data/settings from the .rbk automatically."                 Green
    Say ""
    Say "Honest boundaries:"                                                       Yellow
    Say "  - It is near-one-click, not fully headless: you pick the target disk"   Yellow
    Say "    and edition in Setup (a couple of screens), by design/safety."        Yellow
    Say "  - autounattend.xml is a reviewable template - adapt it to your"         Yellow
    Say "    edition/architecture before relying on it."                           Yellow
    Say "  - Applications are NOT restored (licensed separately; see the program" Yellow
    Say "    list in the backup). Reinstall them."                                 Yellow
    Say "  - Activation is NOT handled. No key was injected unless you passed"     Yellow
    Say "    -ProductKey. Setup may prompt; activation is your responsibility."    Yellow
    Say "  - A clean install ERASES the target disk. This is recovery from a"      Yellow
    Say "    dead/compromised system, not an in-place upgrade."                    Yellow
}
}
