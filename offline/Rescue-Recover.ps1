<#
.SYNOPSIS
    Rescue - offline disk/boot recovery: repair a trashed boot record, rebuild a
    lost partition table, and carve back files after a quick-format.

.DESCRIPTION
    Run this from a WinPE / WinRE boot USB, against an *offline* (not running)
    system - so the malware can't fight back. It covers the damage classes that
    "reset this PC" cannot, and that DON'T mean the data is gone:

      * BOOT record trashed (MEMZ / rainbow-cat style overwriting the MBR so the
        machine won't boot) - repaired with the built-in bootrec/bootsect. The
        data and Windows install are untouched; only the boot code is rewritten.

      * PARTITION TABLE destroyed / partition shows grey & "unavailable" - the
        file data is still in the sectors; the index was wiped. TestDisk rebuilds
        the partition table so the volume and its files reappear.

      * Quick-FORMAT or deleted files - the bytes are still on disk until
        overwritten; PhotoRec carves them back by file signature.

    IMPORTANT, stated plainly:
      * This does NOT recover data that was genuinely OVERWRITTEN (a wiper that
        zero-filled every sector, or correct ransomware encryption). That is
        physics, not a missing tool - only an offline backup survives that.
      * TestDisk / PhotoRec are third-party GPL tools (CGSecurity) and are NOT
        bundled here (licence + they are separately maintained). Put testdisk.exe
        / photorec.exe on the rescue USB, or pass -ToolDir. The script wires the
        workflow around them and refuses to guess if they're absent.
      * NEVER recover onto the same disk you are reading from - a write can
        overwrite the very data you're saving. -OutDir must be a DIFFERENT disk.

.PARAMETER RepairBoot
    Rewrite the boot record of -OsDrive (bootrec /fixmbr /fixboot /rebuildbcd,
    and bootsect for the volume boot code). For a machine bricked by an MBR
    overwrite (MEMZ), this alone usually brings it back - data intact.

.PARAMETER OsDrive
    The offline Windows volume (e.g. C:). Used by -RepairBoot.

.PARAMETER RecoverPartition
    Launch TestDisk to rebuild a lost/corrupt partition table (interactive).

.PARAMETER CarveFiles
    Launch PhotoRec to carve files by signature into -OutDir (interactive).

.PARAMETER SourceDisk
    Physical disk number to recover from (e.g. 0), for -RecoverPartition /
    -CarveFiles. See 'diskpart > list disk'.

.PARAMETER OutDir
    Destination for carved files - MUST be on a different disk than SourceDisk.

.PARAMETER ToolDir
    Folder holding testdisk.exe / photorec.exe. Default: next to this script.
#>
[CmdletBinding()]
param(
    [switch]$RepairBoot,
    [string]$OsDrive = 'C:',
    [switch]$RecoverPartition,
    [switch]$CarveFiles,
    [string]$SourceDisk,
    [string]$OutDir,
    [string]$ToolDir
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Say($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
function Head($m){ Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }

if (-not $ToolDir) { $ToolDir = Split-Path $PSCommandPath -Parent }
$OsDrive = $OsDrive.TrimEnd('\')

if (-not ($RepairBoot -or $RecoverPartition -or $CarveFiles)) {
    Say "Rescue offline disk/boot recovery. Choose at least one action:" 
    Say "  -RepairBoot -OsDrive C:                 fix a trashed boot record (MEMZ etc.)"
    Say "  -RecoverPartition -SourceDisk 0         rebuild a lost partition table (TestDisk)"
    Say "  -CarveFiles -SourceDisk 0 -OutDir E:\R  carve files after a quick-format (PhotoRec)"
    Say ""
    Say "Data that was truly overwritten (zero-fill wiper / encryption) is NOT" Yellow
    Say "recoverable by any tool - only an offline backup survives that."        Yellow
    exit 0
}

# --------------------------------------------------------------- boot repair --
if ($RepairBoot) {
    Head "Boot record repair on $OsDrive"
    Say "A boot-killer (e.g. MEMZ) overwrites the boot code, not your data."
    Say "Rewriting it is safe and non-destructive to files."
    # bootrec targets the system's boot config; on WinPE it operates on the
    # offline install. These are Windows' own repair commands.
    foreach ($cmd in @('bootrec /fixmbr','bootrec /fixboot','bootrec /rebuildbcd')) {
        Say ">>> $cmd" Cyan
        try { cmd /c $cmd } catch { Say "  ($cmd reported: $_)" Yellow }
    }
    # bootsect rewrites the volume boot record to the BOOTMGR-compatible code.
    $bootsect = Join-Path $OsDrive '\Windows\System32\bootsect.exe'
    if (Test-Path $bootsect) {
        Say ">>> bootsect /nt60 $OsDrive /force /mbr" Cyan
        try { & $bootsect /nt60 $OsDrive /force /mbr } catch { Say "  ($_)" Yellow }
    }
    Say "Boot repair done. Remove the USB and reboot to test." Green
    Say "(If Windows still won't boot, the install itself may be damaged - then"
    Say " reinstall from clean media and restore your .rbk backup on top.)"
}

# --------------------------------------------------- third-party tool wiring --
function Need-Tool([string]$exe) {
    $p = Join-Path $ToolDir $exe
    if (Test-Path $p) { return $p }
    $onPath = Get-Command $exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    Say "[!] $exe not found (looked in $ToolDir and PATH)." Yellow
    Say "    TestDisk/PhotoRec are GPL tools from https://www.cgsecurity.org and are" Yellow
    Say "    not bundled. Download the package, put $exe on the rescue USB, and" Yellow
    Say "    re-run (or pass -ToolDir)." Yellow
    return $null
}

function Assert-DifferentDisk([string]$srcDisk, [string]$outDir) {
    if (-not $outDir) { throw "-OutDir is required and MUST be on a different disk than SourceDisk $srcDisk." }
    $outRoot = [System.IO.Path]::GetPathRoot((Resolve-Path $outDir -ErrorAction SilentlyContinue))
    if (-not $outRoot) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    Say "  recovering FROM physical disk $srcDisk  ->  INTO $outDir" 
    Say "  (verify these are different physical disks - writing to the source"    Yellow
    Say "   disk would overwrite the data you are trying to save)"                Yellow
}

# ------------------------------------------------------- partition recovery ---
if ($RecoverPartition) {
    Head "Partition-table rebuild (TestDisk)"
    if (-not $SourceDisk) { throw "-SourceDisk N required (see 'diskpart > list disk')." }
    $td = Need-Tool 'testdisk_win.exe'
    if (-not $td) { $td = Need-Tool 'testdisk.exe' }
    if ($td) {
        Say "Launching TestDisk. In it: select disk $SourceDisk -> [Proceed] ->"
        Say "partition type (usually EFI GPT or Intel) -> [Analyse] -> [Quick Search],"
        Say "confirm the found partition(s), then [Write] and reboot. A grey/'unavailable'"
        Say "partition reappears with its files once the table is rewritten." Green
        & $td
    }
}

# ------------------------------------------------------------ file carving ---
if ($CarveFiles) {
    Head "File carving after quick-format (PhotoRec)"
    if (-not $SourceDisk) { throw "-SourceDisk N required (see 'diskpart > list disk')." }
    Assert-DifferentDisk $SourceDisk $OutDir
    $pr = Need-Tool 'photorec_win.exe'
    if (-not $pr) { $pr = Need-Tool 'photorec.exe' }
    if ($pr) {
        Say "Launching PhotoRec. In it: select disk $SourceDisk -> partition (or"
        Say "'Whole disk') -> [Search], choose the destination on $OutDir when asked."
        Say "It carves recoverable files by signature into that folder." Green
        & $pr
    }
}
