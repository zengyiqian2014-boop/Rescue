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

.PARAMETER Mode
    data | bootable | system-image  (default: data)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Drive,
    [string]$Snapshot,
    [string]$BackupDisk,
    [ValidateSet('data','bootable','system-image')][string]$Mode = 'data'
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
}
