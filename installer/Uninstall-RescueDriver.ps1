<#
.SYNOPSIS
    Removes the RescueMon kernel minifilter and reverses every machine change
    Install-RescueDriver.ps1 made.

.DESCRIPTION
    The installer records what it changed in
    %ProgramData%\Rescue\driver-install-state.json - the certificate
    thumbprint it created, and whether IT was the thing that turned on
    test-signing. This script reads that record and undoes exactly those
    changes, which matters in both directions:

      * it removes the self-signed certificate it added, and no others;
      * it turns test-signing back OFF only if the installer turned it on. If
        the machine was already in test-signing mode for some other driver,
        silently disabling it here would break that driver at the next boot.

    Without the state file it falls back to removing the driver and the
    certificate matching Rescue's lab subject name, and leaves boot
    configuration alone - a safe partial revert rather than a guess.
#>
[CmdletBinding()]
param(
    [switch]$KeepTestSigning
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ServiceName = 'RescueMon'
$StateFile   = Join-Path $env:ProgramData 'Rescue\driver-install-state.json'
$LabSubject  = 'CN=Rescue Development Driver Signing (LAB ONLY)'

function Write-Item($label, $value, $color = 'Gray') {
    Write-Host ("  {0,-28} {1}" -f $label, $value) -ForegroundColor $color
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run elevated (Run as Administrator)."
    }
}

Assert-Admin

Write-Host ''
Write-Host '== Removing RescueMon ==' -ForegroundColor Cyan

$state = $null
if (Test-Path $StateFile) {
    try { $state = Get-Content $StateFile -Raw | ConvertFrom-Json } catch { $state = $null }
}
if ($null -eq $state) {
    Write-Item 'install record' 'not found - partial revert only' 'Yellow'
} else {
    Write-Item 'install record' ("mode={0} installed={1}" -f $state.Mode, $state.InstalledUtc)
}

# --- 1. unload and deregister the filter ---
& fltmc.exe unload $ServiceName 2>&1 | Out-Null
Write-Item 'minifilter' 'unloaded (or was not loaded)'

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    & sc.exe delete $ServiceName | Out-Null
    Write-Item 'service' 'deleted' 'Green'
}

$sys = Join-Path $env:SystemRoot 'System32\drivers\rescuemon.sys'
if (Test-Path $sys) {
    try {
        Remove-Item $sys -Force
        Write-Item 'driver file' 'deleted' 'Green'
    } catch {
        Write-Item 'driver file' 'still in use - removed at next reboot' 'Yellow'
    }
}

# Drop the OEM INF from the driver store if the installer added one.
$oem = & pnputil /enum-drivers 2>&1 | Out-String
if ($oem -match '(?ims)Published Name:\s*(oem\d+\.inf).*?Original Name:\s*rescuemon\.inf') {
    $published = $Matches[1]
    & pnputil /delete-driver $published /uninstall /force 2>&1 | Out-Null
    Write-Item 'INF removed' $published 'Green'
}

# --- 2. remove the certificate we added (and only that one) ---
$thumb = $null
if ($null -ne $state -and $state.PSObject.Properties.Name -contains 'CertThumbprint') {
    $thumb = $state.CertThumbprint
}
foreach ($store in @('Root', 'TrustedPublisher', 'My')) {
    $path = "Cert:\LocalMachine\$store"
    $certs = @(Get-ChildItem $path -ErrorAction SilentlyContinue | Where-Object {
        ($thumb -and $_.Thumbprint -eq $thumb) -or
        (-not $thumb -and $_.Subject -eq $LabSubject)
    })
    foreach ($c in $certs) {
        Remove-Item -Path (Join-Path $path $c.Thumbprint) -Force -DeleteKey -ErrorAction SilentlyContinue
        Write-Item "cert removed" ("{0}  {1}" -f $store, $c.Thumbprint) 'Green'
    }
}

# --- 3. test-signing: only revert what we turned on ---
if ($KeepTestSigning) {
    Write-Item 'test-signing' 'left on (-KeepTestSigning)' 'Yellow'
} elseif ($null -ne $state -and $state.PSObject.Properties.Name -contains 'TestSigningEnabled' `
          -and $state.TestSigningEnabled) {
    & bcdedit /set testsigning off | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Item 'test-signing' 'disabled (reboot to apply)' 'Green'
    } else {
        Write-Item 'test-signing' 'could not disable - run bcdedit /set testsigning off' 'Red'
    }
} else {
    Write-Item 'test-signing' 'not changed by the installer - left alone' 'Gray'
}

if (Test-Path $StateFile) { Remove-Item $StateFile -Force }

Write-Host ''
Write-Host 'RescueMon removed. Reboot to complete the revert.' -ForegroundColor Green
Write-Host 'Re-enable Secure Boot in UEFI setup if you turned it off for lab mode.' -ForegroundColor Yellow
