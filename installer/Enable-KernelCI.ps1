<#
.SYNOPSIS
    Enable RescueMon's kernel tier by deploying a custom WDAC (App Control /
    Code Integrity) policy that allows *this one driver* while leaving every
    other rule at the Microsoft default. Opt-in and fully reversible.

.DESCRIPTION
    Windows kernel Code Integrity will not load an unsigned/self-signed driver.
    One supported way to authorize a specific driver without buying an EV
    certificate and going through Microsoft attestation signing is a custom WDAC
    policy that allow-lists the driver by file hash. This script builds such a
    policy on top of the shipped AllowMicrosoft base ("everything Microsoft
    would allow, plus our one hash"), and deploys it.

    IMPORTANT - read before enforcing:

    * Multiple WDAC *base* policies are ANDed. On a machine with no existing
      WDAC policy, introducing an enforced base means kernel CI now governs
      EVERY driver, not just ours. A third-party driver that is not
      Microsoft-signed could then be blocked - in the worst case a boot-critical
      one. That is why this script deploys in AUDIT mode by default: audit blocks
      nothing, it only logs what an enforced policy *would* block, to the
      CodeIntegrity operational event log. Review that log, and only then re-run
      with -Enforce.

    * This authorizes the driver by hash. Whether kernel CI then actually loads
      the unsigned image depends on the machine: with Memory Integrity (HVCI)
      ON, the hypervisor still requires a Microsoft-rooted signature and a
      WDAC hash rule does not satisfy it - the driver will not load and the only
      remaining path is Microsoft attestation signing. This script REPORTS HVCI
      and Secure Boot state; it never changes them. It also self-signs the driver
      and trusts that certificate locally, which helps on the signature path and
      is harmless on the hash path.

    Everything it changes is written to a state file and reversed exactly by
    Restore-KernelCI.ps1. Existing Code Integrity policy files are never deleted;
    if one is touched it is copied to <name>.bak first.

.PARAMETER Enforce
    Deploy the policy in ENFORCED mode (actually gates driver loading, and lets
    our driver load). Without this, the policy is deployed in AUDIT mode.

.PARAMETER SysPath
    Path to rescuemon.sys. Defaults to .\rescuemon.sys.

.PARAMETER InfPath
    Path to rescuemon.inf. Defaults to .\rescuemon.inf.

.PARAMETER Force
    Skip the typed consent prompt (unattended lab reimage only).
#>
[CmdletBinding()]
param(
    [switch]$Enforce,
    [switch]$DisableHVCI,   # opt-in: also turn OFF Memory Integrity (needed for an
                            # unsigned driver when HVCI is on). Reversible; a real
                            # security downgrade; never done without this flag.
    [string]$SysPath = ".\rescuemon.sys",
    [string]$InfPath = ".\rescuemon.inf",
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ServiceName = 'RescueMon'
$PolicyName  = 'Rescue Kernel CI'
$StateFile   = Join-Path $env:ProgramData 'Rescue\kernel-ci-state.json'
$WorkDir     = Join-Path $env:ProgramData 'Rescue\ci'
$CiDir       = Join-Path $env:SystemRoot 'System32\CodeIntegrity'
$ActiveDir   = Join-Path $CiDir 'CiPolicies\Active'

# ----------------------------------------------------------------- helpers --
function Write-Head($text) { Write-Host ''; Write-Host "== $text ==" -ForegroundColor Cyan }
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
function Get-SecureBootState {
    try { if (Confirm-SecureBootUEFI) { return 'On' } else { return 'Off' } }
    catch { return 'Unsupported (legacy BIOS)' }
}
function Get-HvciState {
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
              -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if ($dg.SecurityServicesRunning -contains 2) { return 'On' }
        return 'Off'
    } catch { return 'Unknown' }
}
function Save-State($state) {
    $dir = Split-Path $StateFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $state | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8
}

function Request-Consent([string]$mode) {
    Write-Host ''
    Write-Host '  ############################################################' -ForegroundColor Yellow
    Write-Host '  #  CUSTOM KERNEL CODE-INTEGRITY POLICY - READ ALL OF IT.   #' -ForegroundColor Yellow
    Write-Host '  ############################################################' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "  This deploys a WDAC kernel policy in $mode mode. It will:"
    Write-Host ''
    Write-Host '   1. Build a policy = "AllowMicrosoft" base + this driver''s hash,' -ForegroundColor White
    Write-Host '      then deploy it. AUDIT logs only; ENFORCE actually gates which'
    Write-Host '      kernel drivers may load on this machine.'                     -ForegroundColor White
    if ($mode -eq 'ENFORCE') {
        Write-Host ''
        Write-Host '      In ENFORCE mode, any kernel driver NOT allowed by this policy'  -ForegroundColor Yellow
        Write-Host '      (i.e. not Microsoft-signed and not our hash) will be BLOCKED.'  -ForegroundColor Yellow
        Write-Host '      If a boot-critical third-party driver is not Microsoft-signed,' -ForegroundColor Yellow
        Write-Host '      that can stop the machine booting. Run AUDIT first and review'  -ForegroundColor Yellow
        Write-Host '      the CodeIntegrity event log before you do this.'                -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '   2. Generate a self-signed CODE SIGNING certificate, sign the driver' -ForegroundColor White
    Write-Host '      with it, and trust it in LocalMachine\Root + TrustedPublisher.'
    Write-Host '   3. Register + (in ENFORCE mode) load the RescueMon minifilter.'      -ForegroundColor White
    if ($DisableHVCI) {
        Write-Host ''
        Write-Host '   4. TURN OFF Memory Integrity (HVCI).'                              -ForegroundColor Red
        Write-Host '      HVCI otherwise requires a Microsoft-rooted signature for kernel' -ForegroundColor Yellow
        Write-Host '      code and a WDAC hash rule does not satisfy it. Turning it off'   -ForegroundColor Yellow
        Write-Host '      lowers this machine''s kernel-memory protection for EVERY driver,'-ForegroundColor Yellow
        Write-Host '      not just ours, and takes effect after a reboot. Restore-KernelCI'-ForegroundColor Yellow
        Write-Host '      turns it back on.'                                               -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '  It does NOT change Secure Boot or Memory Integrity, and does NOT'
    Write-Host '  delete any existing policy (touched files are copied to .bak).'
    Write-Host '  Restore-KernelCI.ps1 reverses everything.'
    Write-Host ''
    $phrase = "I ACCEPT KERNEL CI $mode"
    Write-Host ("  To proceed, type exactly:  {0}" -f $phrase) -ForegroundColor Cyan
    $typed = Read-Host '  >'
    if ($typed -ne $phrase) { Write-Host ''; Write-Host '  Not confirmed - nothing was changed.' -ForegroundColor Green; return $false }
    return $true
}

# ------------------------------------------------------------------- main ----
Assert-Admin
Write-Head 'RescueMon kernel Code-Integrity enablement'

if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) {
    throw "The ConfigCI module (New-CIPolicy/Merge-CIPolicy) is not available on this edition of Windows. WDAC policy authoring needs Windows 10/11 Enterprise/Pro or the RSAT ConfigCI feature."
}
if (-not (Test-Path $SysPath)) {
    throw "Driver not found: $SysPath`nBuild rescuemon.sys first with the WDK - see driver/README.md."
}
$SysPath = (Resolve-Path $SysPath).Path

$mode = if ($Enforce) { 'ENFORCE' } else { 'AUDIT' }
$secureBoot = Get-SecureBootState
$hvci       = Get-HvciState

Write-Head 'Preflight'
Write-Item 'Windows'          ((Get-CimInstance Win32_OperatingSystem).Caption + ' build ' + [Environment]::OSVersion.Version.Build)
Write-Item 'Secure Boot'      $secureBoot
Write-Item 'Memory Integrity' $hvci
Write-Item 'Requested mode'   $mode $(if ($Enforce) { 'Yellow' } else { 'Gray' })
if ($hvci -eq 'On') {
    Write-Host ''
    Write-Host '  [!] Memory Integrity (HVCI) is ON. A WDAC hash rule does NOT satisfy'   -ForegroundColor Yellow
    Write-Host '      HVCI: the hypervisor still requires a Microsoft-rooted signature,'  -ForegroundColor Yellow
    Write-Host '      so this unsigned driver will still not load. Options: sign the'     -ForegroundColor Yellow
    Write-Host '      driver via Microsoft attestation, or re-run this with -DisableHVCI'  -ForegroundColor Yellow
    Write-Host '      to turn Memory Integrity off (opt-in, reversible, security cost).'   -ForegroundColor Yellow
}

if (-not $Force) { if (-not (Request-Consent $mode)) { exit 1 } }
else { Write-Host '  -Force: consent prompt skipped by operator.' -ForegroundColor Yellow }

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

# ---- 0. optionally turn off Memory Integrity (HVCI), opt-in only --------------
$hvciDisabled=$false
if ($DisableHVCI -and $hvci -eq 'On') {
    Write-Head 'Memory Integrity (HVCI)'
    $key='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null
    $hvciDisabled=$true
    Write-Item 'HVCI' 'turned OFF - reboot required to take effect' 'Red'
    Write-Item 'reverse with' 'Restore-KernelCI.ps1' 'Gray'
} elseif ($DisableHVCI) {
    Write-Item 'HVCI' 'already off - nothing to change' 'Gray'
}

# ---- 1. self-sign the driver (Code Signing EKU only) --------------------------
Write-Head 'Signing the driver'
$cert = New-SelfSignedCertificate `
            -Subject 'CN=Rescue Kernel Protection (self-signed)' `
            -Type CodeSigningCert -KeyUsage DigitalSignature `
            -KeyLength 3072 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -NotAfter (Get-Date).AddYears(3) `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
Write-Item 'certificate' $cert.Thumbprint 'Green'
$sig = Set-AuthenticodeSignature -FilePath $SysPath -Certificate $cert -HashAlgorithm SHA256
Write-Item 'driver signed' $sig.Status $(if ($sig.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
$cerTmp = Join-Path $WorkDir 'rescue-kernel-signing.cer'
Export-Certificate -Cert $cert -FilePath $cerTmp -Force | Out-Null
foreach ($store in @('Root', 'TrustedPublisher')) {
    Import-Certificate -FilePath $cerTmp -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
    Write-Item 'trusted in' "LocalMachine\$store" 'Yellow'
}

# ---- 2. build the WDAC policy: AllowMicrosoft base + our driver hash ----------
Write-Head 'Building the Code Integrity policy'
$allowMs = Join-Path $env:SystemRoot 'schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml'
if (-not (Test-Path $allowMs)) {
    throw "AllowMicrosoft.xml example policy not found at $allowMs (needed as the 'everything Microsoft' base)."
}
$drvXml    = Join-Path $WorkDir 'rescue-driver.xml'
$mergedXml = Join-Path $WorkDir 'rescue-kernel-ci.xml'
$cipFile   = Join-Path $WorkDir 'rescue-kernel-ci.cip'

# Scan only our driver, by hash, kernel PEs only.
New-CIPolicy -FilePath $drvXml -Level Hash -Fallback Hash `
    -DriverFiles (Get-Item $SysPath) -UserPEs:$false -MultiplePolicyFormat 3>$null 4>$null
Write-Item 'driver hash rule' (Split-Path $drvXml -Leaf) 'Green'

Merge-CIPolicy -PolicyPaths $allowMs, $drvXml -OutputFilePath $mergedXml | Out-Null
Write-Item 'merged with' 'AllowMicrosoft base' 'Green'

# Make it a fresh base multi-policy with its own GUID + friendly name.
$idInfo   = Set-CIPolicyIdInfo -FilePath $mergedXml -PolicyName $PolicyName -ResetPolicyID
$policyId  = ([regex]::Match([string]$idInfo, '\{[0-9A-Fa-f-]+\}')).Value
if (-not $policyId) {
    # Set-CIPolicyIdInfo output form varies; fall back to reading the XML.
    [xml]$xml = Get-Content $mergedXml
    $policyId = $xml.SiPolicy.PolicyID
}
Write-Item 'policy id' $policyId 'Green'

# Rule options:
#   6  Unsigned System Integrity Policy - allow our UNSIGNED .cip to be honored
#   16 Enabled:Update Policy No Reboot  - so CiTool can apply without reboot
#   3  Audit Mode                       - present = audit, deleted = enforce
#   0  UMCI (user-mode)                 - REMOVE: we only want to gate drivers
Set-RuleOption -FilePath $mergedXml -Option 6            # unsigned policy allowed
Set-RuleOption -FilePath $mergedXml -Option 16           # update without reboot
Set-RuleOption -FilePath $mergedXml -Option 0 -Delete    # kernel mode only, no UMCI
if ($Enforce) {
    Set-RuleOption -FilePath $mergedXml -Option 3 -Delete # enforce
} else {
    Set-RuleOption -FilePath $mergedXml -Option 3         # audit
}

ConvertFrom-CIPolicy -XmlFilePath $mergedXml -BinaryFilePath $cipFile | Out-Null
Write-Item 'compiled policy' (Split-Path $cipFile -Leaf) 'Green'

# ---- 3. back up any existing active policies, then deploy ours ----------------
Write-Head 'Deploying'
$backups = @()
if (Test-Path $ActiveDir) {
    foreach ($f in Get-ChildItem -Path $ActiveDir -Filter *.cip -ErrorAction SilentlyContinue) {
        $bak = "$($f.FullName).bak"
        if (-not (Test-Path $bak)) { Copy-Item $f.FullName $bak -Force; $backups += $bak }
    }
}
$legacy = Join-Path $CiDir 'SIPolicy.p7b'
if (Test-Path $legacy) {
    $bak = "$legacy.bak"
    if (-not (Test-Path $bak)) { Copy-Item $legacy $bak -Force; $backups += $bak }
}
if ($backups.Count) { Write-Item 'backed up (.bak)' ("{0} existing policy file(s)" -f $backups.Count) 'Green' }
else { Write-Item 'existing CI policies' 'none found (clean add)' 'Gray' }

$deployMethod = 'none'
if (Get-Command CiTool -ErrorAction SilentlyContinue) {
    & CiTool --update-policy $cipFile | Out-Null
    $deployMethod = 'CiTool'
    Write-Item 'deployed via' 'CiTool --update-policy' 'Green'
} else {
    if (-not (Test-Path $ActiveDir)) { New-Item -ItemType Directory -Path $ActiveDir -Force | Out-Null }
    $dest = Join-Path $ActiveDir ("{0}.cip" -f $policyId)
    Copy-Item $cipFile $dest -Force
    $deployMethod = 'CiPolicies\Active (reboot)'
    Write-Item 'deployed to' $dest 'Green'
    Write-Item 'note' 'reboot required to apply' 'Yellow'
}

# ---- 4. register / load the minifilter ---------------------------------------
Write-Head 'Driver service'
$dest = Join-Path $env:SystemRoot 'System32\drivers\rescuemon.sys'
Copy-Item -Path $SysPath -Destination $dest -Force
Write-Item 'driver file' $dest 'Green'
if (Test-Path $InfPath) { & pnputil /add-driver $InfPath /install | Out-Null; Write-Item 'INF registered' $InfPath 'Green' }
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    & sc.exe create $ServiceName type= filesys start= demand binPath= 'System32\drivers\rescuemon.sys' | Out-Null
    Write-Item 'service created' $ServiceName 'Green'
}
if ($Enforce -and $deployMethod -eq 'CiTool') {
    $out = & fltmc.exe load $ServiceName 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Item 'minifilter' 'loaded' 'Green' }
    else { Write-Item 'minifilter' "not loaded yet: $($out.Trim())" 'Yellow' }
} else {
    Write-Item 'minifilter' 'load after reboot / after -Enforce' 'Gray'
}

# ---- 5. record everything for exact reversal ---------------------------------
Save-State ([pscustomobject]@{
    EnabledUtc     = (Get-Date).ToUniversalTime().ToString('o')
    Mode           = $mode
    PolicyName     = $PolicyName
    PolicyId       = $policyId
    DeployMethod   = $deployMethod
    CipFile        = $cipFile
    CertThumbprint = $cert.Thumbprint
    ServiceName    = $ServiceName
    BackupsCreated = $backups
    SecureBoot     = $secureBoot
    Hvci           = $hvci
    HvciDisabledByUs = $hvciDisabled
})

Write-Host ''
Write-Host ("Recorded in {0}. Restore-KernelCI.ps1 reverses all of it." -f $StateFile)
if (-not $Enforce) {
    Write-Host ''
    Write-Host 'AUDIT mode is active: nothing is blocked. Reproduce your normal work,' -ForegroundColor Cyan
    Write-Host 'reboot, then check Event Viewer > Applications and Services Logs >'      -ForegroundColor Cyan
    Write-Host 'Microsoft > Windows > CodeIntegrity > Operational for "would block"'     -ForegroundColor Cyan
    Write-Host 'events (id 3076/3077). If none matter to you, re-run with -Enforce.'     -ForegroundColor Cyan
}
