<#
.SYNOPSIS
    Restore the original Code Integrity configuration: remove the custom RescueMon
    WDAC policy and undo everything Enable-KernelCI.ps1 changed. The machine's
    own CI policies are never deleted - only the one we added is removed, and any
    file we touched is restored from its .bak.

.DESCRIPTION
    Reads the state file written by Enable-KernelCI.ps1 and reverses, in order:
      1. Unloads and removes the RescueMon minifilter service + driver file.
      2. Removes our WDAC policy (CiTool --remove-policy, or deletes our .cip
         from CiPolicies\Active).
      3. Restores any existing policy files we had copied to .bak.
      4. Removes the self-signed certificate from LocalMachine\My, \Root and
         \TrustedPublisher.
    Safe to run more than once; missing pieces are skipped.

.PARAMETER KeepDriver
    Leave the RescueMon service/driver in place; only revert the CI policy + cert.
#>
[CmdletBinding()]
param([switch]$KeepDriver)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$StateFile = Join-Path $env:ProgramData 'Rescue\kernel-ci-state.json'
$CiDir     = Join-Path $env:SystemRoot 'System32\CodeIntegrity'
$ActiveDir = Join-Path $CiDir 'CiPolicies\Active'

function Write-Head($t) { Write-Host ''; Write-Host "== $t ==" -ForegroundColor Cyan }
function Write-Item($l, $v, $c = 'Gray') { Write-Host ("  {0,-28} {1}" -f $l, $v) -ForegroundColor $c }
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run elevated (Run as Administrator)."
    }
}

Assert-Admin
Write-Head 'Restore original Code Integrity'

if (-not (Test-Path $StateFile)) {
    Write-Host '  No kernel-ci-state.json found - nothing recorded to restore.' -ForegroundColor Yellow
    Write-Host '  (If you deployed the policy manually, remove it with:' -ForegroundColor Gray
    Write-Host '   CiTool --list-policies  then  CiTool --remove-policy {ID} )' -ForegroundColor Gray
    return
}
$state = Get-Content $StateFile -Raw | ConvertFrom-Json

# ---- 1. driver / minifilter --------------------------------------------------
if (-not $KeepDriver) {
    Write-Head 'Driver'
    $svc = if ($state.PSObject.Properties.Name -contains 'ServiceName') { $state.ServiceName } else { 'RescueMon' }
    & fltmc.exe unload $svc 2>&1 | Out-Null
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        & sc.exe stop $svc   2>&1 | Out-Null
        & sc.exe delete $svc 2>&1 | Out-Null
        Write-Item 'service removed' $svc 'Green'
    }
    $sys = Join-Path $env:SystemRoot 'System32\drivers\rescuemon.sys'
    if (Test-Path $sys) { Remove-Item $sys -Force -ErrorAction SilentlyContinue; Write-Item 'driver file removed' $sys 'Green' }
} else {
    Write-Item 'driver' 'left in place (-KeepDriver)' 'Yellow'
}

# ---- 2. remove our WDAC policy ----------------------------------------------
Write-Head 'Code Integrity policy'
$pid = $state.PolicyId
if ((Get-Command CiTool -ErrorAction SilentlyContinue) -and $state.DeployMethod -eq 'CiTool') {
    & CiTool --remove-policy $pid 2>&1 | Out-Null
    Write-Item 'policy removed' $pid 'Green'
} else {
    $cip = Join-Path $ActiveDir ("{0}.cip" -f $pid)
    if (Test-Path $cip) { Remove-Item $cip -Force -ErrorAction SilentlyContinue; Write-Item 'policy file removed' $cip 'Green' }
    else { Write-Item 'policy file' 'already absent' 'Gray' }
    Write-Item 'note' 'reboot to fully clear the enforced policy' 'Yellow'
}

# ---- 3. restore any backups we made -----------------------------------------
if ($state.PSObject.Properties.Name -contains 'BackupsCreated' -and $state.BackupsCreated) {
    Write-Head 'Restoring backed-up policies'
    foreach ($bak in $state.BackupsCreated) {
        if (Test-Path $bak) {
            $orig = $bak.Substring(0, $bak.Length - 4)   # strip .bak
            Copy-Item $bak $orig -Force
            Remove-Item $bak -Force -ErrorAction SilentlyContinue
            Write-Item 'restored' (Split-Path $orig -Leaf) 'Green'
        }
    }
}

# ---- 4. remove the self-signed cert -----------------------------------------
Write-Head 'Certificate'
$thumb = $state.CertThumbprint
if ($thumb) {
    foreach ($store in @('My', 'Root', 'TrustedPublisher')) {
        $p = "Cert:\LocalMachine\$store\$thumb"
        if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue; Write-Item 'removed from' "LocalMachine\$store" 'Green' }
    }
}

Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host 'Original Code Integrity configuration restored.' -ForegroundColor Green
if ($state.DeployMethod -ne 'CiTool') { Write-Host 'Reboot to finish clearing the policy.' -ForegroundColor Yellow }
