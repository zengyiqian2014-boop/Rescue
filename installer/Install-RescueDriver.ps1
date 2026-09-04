<#
.SYNOPSIS
    Installs the RescueMon kernel minifilter (Phase 6), on whichever of the two
    signing paths the driver actually qualifies for.

.DESCRIPTION
    There are exactly two ways a kernel driver loads on a current Windows
    system, and this script detects which one applies rather than guessing:

    PRODUCTION PATH - the .sys carries a Microsoft signature (WHCP, or
      attestation signing via Partner Center). It installs normally, alongside
      Secure Boot and Memory Integrity, and touches no machine security
      settings. This is the only path that works on a machine you do not own.

    LAB PATH - the .sys is self-signed or unsigned. Windows kernel Code
      Integrity does NOT consult the user's certificate stores, so importing a
      self-signed root does not make it load; the machine must additionally be
      put into test-signing mode, which requires Secure Boot to be OFF. That is
      a real reduction in the machine's security posture, so this path is
      opt-in (-LabMode), requires typed consent, records every change it makes,
      and is fully reversible with Uninstall-RescueDriver.ps1.

    The lab path is for a developer's own test machine. Shipping it to end
    users would mean asking them to disable Secure Boot and trust a private
    signing key - do not do that.

.PARAMETER LabMode
    Opt in to the self-signed / test-signing path. Ignored when the driver is
    already Microsoft-signed.

.PARAMETER SysPath
    Path to rescuemon.sys. Defaults to .\rescuemon.sys.

.PARAMETER InfPath
    Path to rescuemon.inf. Defaults to .\rescuemon.inf.

.PARAMETER Force
    Skip the interactive consent prompt. Only honoured together with -LabMode,
    and intended for an unattended lab reimage where the operator has already
    accepted the consequences. It does not bypass the Secure Boot check.
#>
[CmdletBinding()]
param(
    [switch]$LabMode,
    [string]$SysPath = ".\rescuemon.sys",
    [string]$InfPath = ".\rescuemon.inf",
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ServiceName = 'RescueMon'
$StateFile   = Join-Path $env:ProgramData 'Rescue\driver-install-state.json'

# ----------------------------------------------------------------- helpers --
function Write-Head($text) {
    Write-Host ''
    Write-Host "== $text ==" -ForegroundColor Cyan
}

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

# Secure Boot state. Confirm-SecureBootUEFI throws on legacy BIOS machines,
# where Secure Boot is simply not a concept - that is 'Off', not an error.
function Get-SecureBootState {
    try { if (Confirm-SecureBootUEFI) { return 'On' } else { return 'Off' } }
    catch { return 'Unsupported (legacy BIOS)' }
}

# HVCI / Memory Integrity. A driver that is not HVCI-compatible will not load
# while this is on, even when it is correctly Microsoft-signed - so it is worth
# reporting before the install rather than after the failure.
function Get-HvciState {
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
              -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if ($dg.SecurityServicesRunning -contains 2) { return 'On' }
        return 'Off'
    } catch { return 'Unknown' }
}

function Get-TestSigningState {
    $out = & bcdedit /enum '{current}' 2>&1 | Out-String
    if ($out -match '(?im)^\s*testsigning\s+Yes\s*$') { return 'On' }
    return 'Off'
}

# Is this .sys signed by a chain rooted in Microsoft? That - not the presence
# of *a* signature - is what kernel Code Integrity actually requires.
function Get-DriverSigningStatus([string]$path) {
    $result = [pscustomobject]@{
        Valid           = $false
        MicrosoftSigned = $false
        Status          = 'NotSigned'
        Subject         = ''
        Issuer          = ''
        RootSubject     = ''
    }
    $sig = Get-AuthenticodeSignature -FilePath $path
    $result.Status = [string]$sig.Status
    if ($null -eq $sig.SignerCertificate) { return $result }

    $result.Subject = $sig.SignerCertificate.Subject
    $result.Issuer  = $sig.SignerCertificate.Issuer
    $result.Valid   = ($sig.Status -eq 'Valid')

    # Walk to the root of the chain and look for a Microsoft root. A driver
    # attestation-signed by Partner Center chains to 'Microsoft Windows Third
    # Party Component Root'; a WHCP one chains to a Microsoft root as well.
    try {
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        [void]$chain.Build($sig.SignerCertificate)
        if ($chain.ChainElements.Count -gt 0) {
            $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
            $result.RootSubject = $root.Subject
            if ($root.Subject -match 'CN=Microsoft.*Root') { $result.MicrosoftSigned = $true }
        }
    } catch { }
    return $result
}

function Save-State($state) {
    $dir = Split-Path $StateFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $state | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile -Encoding UTF8
}

# ------------------------------------------------------------- the consent --
# Deliberately NOT a line buried in a T&C blob. Every consequence is itemised
# on screen, in plain language, and the operator has to type the sentence. A
# consent that the person did not read is not consent - and for a change that
# turns off Secure Boot enforcement and trusts a private signing key, "they
# clicked Agree on a 40-page EULA" is not a defensible record.
function Request-LabConsent {
    Write-Host ''
    Write-Host '  ############################################################' -ForegroundColor Yellow
    Write-Host '  #  LAB MODE - THIS WEAKENS THIS MACHINE. READ ALL OF IT.   #' -ForegroundColor Yellow
    Write-Host '  ############################################################' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  The RescueMon driver is not Microsoft-signed, so Windows will'
    Write-Host '  not load it as-is. To load it on THIS machine, this script'
    Write-Host '  will make the following changes:'
    Write-Host ''
    Write-Host '   1. Turn on kernel TEST-SIGNING MODE (bcdedit /set testsigning on).'   -ForegroundColor White
    Write-Host '      From then on this machine will load ANY test-signed kernel'
    Write-Host '      driver, not just this one. This is the actual security cost:'
    Write-Host '      it lowers the bar for every driver, not only ours.'          -ForegroundColor Yellow
    Write-Host ''
    Write-Host '   2. Generate a self-signed CODE SIGNING certificate and import it' -ForegroundColor White
    Write-Host '      into LocalMachine\Root and LocalMachine\TrustedPublisher.'
    Write-Host '      The private key stays on this machine. The certificate is'
    Write-Host '      restricted to the Code Signing EKU, so it cannot be used to'
    Write-Host '      intercept TLS - but while it is trusted, anything signed with'
    Write-Host '      that key is treated as trusted publisher code.'              -ForegroundColor Yellow
    Write-Host ''
    Write-Host '   3. Install a filesystem filter driver that sees every file write' -ForegroundColor White
    Write-Host '      on this machine. A bug in kernel code bugchecks (BSODs) the'
    Write-Host '      whole system, not just the application.'                     -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Also true:'
    Write-Host '   - Secure Boot must be OFF for test-signing to take effect.'
    Write-Host '   - Windows will show a desktop watermark while in test-signing mode.'
    Write-Host '   - Some DRM-protected content and some anti-cheat systems refuse'
    Write-Host '     to run on a test-signing machine.'
    Write-Host '   - Uninstall-RescueDriver.ps1 reverses every one of these changes.'
    Write-Host ''
    Write-Host '  Do this on a development or test machine you own. Do NOT ask an'  -ForegroundColor Yellow
    Write-Host '  end user to do it: the correct path for other people''s machines' -ForegroundColor Yellow
    Write-Host '  is Microsoft attestation signing (see installer/README.md).'      -ForegroundColor Yellow
    Write-Host ''
    $phrase = 'I ACCEPT LAB MODE'
    Write-Host ("  To proceed, type exactly:  {0}" -f $phrase) -ForegroundColor Cyan
    $typed = Read-Host '  >'
    if ($typed -ne $phrase) {
        Write-Host ''
        Write-Host '  Not confirmed - nothing was changed.' -ForegroundColor Green
        return $false
    }
    return $true
}

# ------------------------------------------------------------ install steps --
function Install-DriverFiles([string]$sys, [string]$inf) {
    $dest = Join-Path $env:SystemRoot 'System32\drivers\rescuemon.sys'
    Copy-Item -Path $sys -Destination $dest -Force
    Write-Item 'driver file' $dest 'Green'

    if (Test-Path $inf) {
        & pnputil /add-driver $inf /install | Out-Null
        Write-Item 'INF registered' $inf 'Green'
    }

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        # A minifilter is a filesystem-type service; the Instances/Altitude keys
        # come from the INF, so register the service and let Filter Manager
        # pick it up.
        & sc.exe create $ServiceName type= filesys start= demand `
            binPath= 'System32\drivers\rescuemon.sys' | Out-Null
        Write-Item 'service created' $ServiceName 'Green'
    } else {
        Write-Item 'service' 'already present' 'Gray'
    }
}

function Start-Minifilter {
    $out = & fltmc.exe load $ServiceName 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        Write-Item 'minifilter' 'loaded' 'Green'
        return $true
    }
    Write-Item 'minifilter' "load failed: $($out.Trim())" 'Red'
    return $false
}

# ------------------------------------------------------------------- main ----
Assert-Admin

Write-Head 'RescueMon driver installer'

if (-not (Test-Path $SysPath)) {
    throw "Driver not found: $SysPath`nBuild it first with the WDK - see driver/README.md."
}
$SysPath = (Resolve-Path $SysPath).Path

$secureBoot  = Get-SecureBootState
$hvci        = Get-HvciState
$testSigning = Get-TestSigningState
$signing     = Get-DriverSigningStatus $SysPath

Write-Head 'Preflight'
Write-Item 'Windows'            ((Get-CimInstance Win32_OperatingSystem).Caption + ' build ' + [Environment]::OSVersion.Version.Build)
Write-Item 'Secure Boot'        $secureBoot
Write-Item 'Memory Integrity'   $hvci
Write-Item 'Test-signing mode'  $testSigning
Write-Item 'Driver signature'   $signing.Status
if ($signing.Subject)     { Write-Item '  signer' $signing.Subject }
if ($signing.RootSubject) { Write-Item '  chains to' $signing.RootSubject }
Write-Item 'Microsoft-signed'   $(if ($signing.MicrosoftSigned) { 'yes' } else { 'NO' }) `
                                $(if ($signing.MicrosoftSigned) { 'Green' } else { 'Yellow' })

if ($hvci -eq 'On') {
    Write-Host ''
    Write-Host '  [!] Memory Integrity (HVCI) is on. A driver that is not HVCI-compatible' -ForegroundColor Yellow
    Write-Host '      will be blocked even when correctly signed. If the load fails with'  -ForegroundColor Yellow
    Write-Host '      no other explanation, that is the reason.'                           -ForegroundColor Yellow
}

# ---- Path 1: properly signed. Nothing about the machine needs to change. ----
if ($signing.MicrosoftSigned -and $signing.Valid) {
    Write-Head 'Production path (Microsoft-signed driver)'
    Install-DriverFiles $SysPath $InfPath
    $loaded = Start-Minifilter
    Save-State ([pscustomobject]@{
        Mode              = 'Production'
        InstalledUtc      = (Get-Date).ToUniversalTime().ToString('o')
        ServiceName       = $ServiceName
        CertThumbprint    = $null
        TestSigningEnabled = $false
    })
    Write-Host ''
    if ($loaded) { Write-Host 'RescueMon is installed and running.' -ForegroundColor Green }
    else { Write-Host 'Installed, but the filter did not load - see the message above.' -ForegroundColor Yellow }
    return
}

# ---- Path 2: not Microsoft-signed. Lab mode only, with explicit consent. ----
Write-Head 'This driver is not Microsoft-signed'
Write-Host '  Windows kernel Code Integrity does not consult the local certificate'
Write-Host '  stores. Importing a self-signed root - however the user was asked -'
Write-Host '  will NOT make this driver load. There is no consent flow that changes'
Write-Host '  that; it is enforced below the level a user can agree to.'
Write-Host ''
Write-Host '  Two real options:'
Write-Host '    * Ship it: get an EV code-signing certificate and submit the driver'
Write-Host '      for Microsoft attestation signing (Partner Center). Then it loads'
Write-Host '      everywhere, with Secure Boot on. See installer/README.md.'
Write-Host '    * Test it here: lab mode, below - your own machine, Secure Boot off.'

if (-not $LabMode) {
    Write-Host ''
    Write-Host '  Re-run with -LabMode to install on this machine for development.' -ForegroundColor Cyan
    Write-Host '  Nothing was changed.' -ForegroundColor Green
    return
}

if ($secureBoot -eq 'On') {
    Write-Host ''
    Write-Host '  [X] Secure Boot is ON, so test-signing cannot be enabled.' -ForegroundColor Red
    Write-Host '      bcdedit will refuse the change ("protected by Secure Boot policy").'
    Write-Host '      Turn Secure Boot off in UEFI firmware setup first - deliberately,'
    Write-Host '      on a machine where that is acceptable - or use the signed path.'
    Write-Host '  Nothing was changed.' -ForegroundColor Green
    exit 1
}

if (-not $Force) {
    if (-not (Request-LabConsent)) { exit 1 }
} else {
    Write-Host '  -Force: consent prompt skipped by operator.' -ForegroundColor Yellow
}

Write-Head 'Lab mode: signing and trusting'

# The certificate is deliberately narrow: Code Signing EKU only, so even while
# it sits in the root store it cannot be used to forge a TLS certificate.
$cert = New-SelfSignedCertificate `
            -Subject 'CN=Rescue Development Driver Signing (LAB ONLY)' `
            -Type CodeSigningCert `
            -KeyUsage DigitalSignature `
            -KeyLength 3072 `
            -KeyAlgorithm RSA `
            -HashAlgorithm SHA256 `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -NotAfter (Get-Date).AddYears(2) `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
Write-Item 'certificate' $cert.Thumbprint 'Green'

$sig = Set-AuthenticodeSignature -FilePath $SysPath -Certificate $cert `
        -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.digicert.com'
if ($sig.Status -ne 'Valid' -and $sig.Status -ne 'UnknownError') {
    Write-Item 'signing' "failed: $($sig.Status) $($sig.StatusMessage)" 'Red'
    throw 'Could not sign the driver.'
}
Write-Item 'driver signed' $sig.Status 'Green'

# Public certificate only into the machine stores - the private key stays in
# LocalMachine\My and is never exported.
$tmp = Join-Path $env:TEMP 'rescue-lab-signing.cer'
Export-Certificate -Cert $cert -FilePath $tmp -Force | Out-Null
foreach ($store in @('Root', 'TrustedPublisher')) {
    Import-Certificate -FilePath $tmp -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
    Write-Item "trusted in" "LocalMachine\$store" 'Yellow'
}
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

$weEnabledTestSigning = $false
if ($testSigning -ne 'On') {
    & bcdedit /set testsigning on | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'bcdedit /set testsigning on failed.' }
    $weEnabledTestSigning = $true
    Write-Item 'test-signing' 'enabled (reboot required)' 'Yellow'
} else {
    Write-Item 'test-signing' 'already on (left as-is)' 'Gray'
}

Install-DriverFiles $SysPath $InfPath

Save-State ([pscustomobject]@{
    Mode               = 'Lab'
    InstalledUtc       = (Get-Date).ToUniversalTime().ToString('o')
    ServiceName        = $ServiceName
    CertThumbprint     = $cert.Thumbprint
    TestSigningEnabled = $weEnabledTestSigning
})

Write-Host ''
if ($weEnabledTestSigning) {
    Write-Host 'REBOOT REQUIRED. Test-signing takes effect at the next boot; after' -ForegroundColor Yellow
    Write-Host 'rebooting, run:  fltmc load RescueMon' -ForegroundColor Yellow
} else {
    [void](Start-Minifilter)
}
Write-Host ''
Write-Host ("Everything this script changed is recorded in {0}." -f $StateFile)
Write-Host 'Uninstall-RescueDriver.ps1 reverses all of it.'
