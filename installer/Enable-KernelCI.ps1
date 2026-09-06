<#
.SYNOPSIS
    Turn on RescueMon's kernel tier with the fewest steps that still keep every
    safety check. A custom WDAC / Code-Integrity policy allow-lists THIS driver's
    hash on top of the Microsoft default ("only our sys, everything else
    Microsoft"). Opt-in, fully reversible by Restore-KernelCI.ps1.

.DESCRIPTION
    Two-step guided flow (one reboot in between is unavoidable - it is how a
    kernel WDAC policy is verified safely, and skipping it would remove a check,
    not a step):

      STEP 1  (default run)  Enable-KernelCI.ps1
              Preflight + ONE typed consent, then it does everything at once:
              self-signs the driver, installs the service, deploys the policy in
              AUDIT mode (blocks nothing, only logs what enforce WOULD block),
              and - if Memory Integrity (HVCI) is on, since an unsigned driver
              cannot load under it - turns HVCI off (reversible; -KeepHVCI opts
              out). Then reboot and use the machine normally.

      STEP 2  Enable-KernelCI.ps1 -CheckEnforce
              Reads the CodeIntegrity AUDIT log FOR YOU (no Event Viewer), lists
              any kernel driver that enforce would block, and only if that list
              is empty flips the SAME policy (same GUID) to ENFORCE and loads the
              minifilter. If something would be blocked it refuses and names it.

    -Enforce still exists for a one-shot direct enforce (skips the audit pass -
    advanced, less safe).

    Nothing is deleted; a touched policy file is copied to <name>.bak first, and
    everything done is recorded for exact reversal.

.PARAMETER CheckEnforce  Step 2: verify the audit log, then enforce if clean.
.PARAMETER Enforce       One-shot direct enforce (skip the audit pass).
.PARAMETER KeepHVCI      Do NOT turn Memory Integrity off, even if it is on.
.PARAMETER SysPath       Path to rescuemon.sys (default .\rescuemon.sys).
.PARAMETER InfPath       Path to rescuemon.inf (default .\rescuemon.inf).
.PARAMETER Force         Skip the typed consent (unattended lab use).
#>
[CmdletBinding()]
param(
    [switch]$CheckEnforce,
    [switch]$Enforce,
    [switch]$KeepHVCI,
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
function Write-Item($label, $value, $color = 'Gray') { Write-Host ("  {0,-28} {1}" -f $label, $value) -ForegroundColor $color }
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "This script must run elevated (Run as Administrator)." }
}
function Get-SecureBootState { try { if (Confirm-SecureBootUEFI) { 'On' } else { 'Off' } } catch { 'Unsupported (legacy BIOS)' } }
function Get-HvciState {
    try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
          if ($dg.SecurityServicesRunning -contains 2) { 'On' } else { 'Off' } } catch { 'Unknown' }
}
function Save-State($state) {
    $dir = Split-Path $StateFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $state | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8
}
function Set-Hvci([int]$on) {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Enabled' -Value $on -PropertyType DWord -Force | Out-Null
}
function Deploy-Cip([string]$cip, [string]$policyId) {
    if (Get-Command CiTool -ErrorAction SilentlyContinue) {
        & CiTool --update-policy $cip | Out-Null; return 'CiTool'
    }
    if (-not (Test-Path $ActiveDir)) { New-Item -ItemType Directory -Path $ActiveDir -Force | Out-Null }
    Copy-Item $cip (Join-Path $ActiveDir ("{0}.cip" -f $policyId)) -Force   # name MUST equal the PolicyID
    return 'CiPolicies\Active (reboot)'
}
# Read the CodeIntegrity audit log and return the distinct kernel files that an
# ENFORCED policy would have blocked (event 3076 = audit-mode block) since $since.
function Get-CiAuditBlocks([datetime]$since) {
    $files = @()
    try { $evs = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3076 } -ErrorAction Stop }
    catch { return @() }
    foreach ($e in $evs) {
        if ($e.TimeCreated.ToUniversalTime() -lt $since) { continue }
        $path = $null
        try { $x = [xml]$e.ToXml()
              $d = $x.Event.EventData.Data | Where-Object { $_.Name -eq 'File Name' } | Select-Object -First 1
              if ($d) { $path = [string]$d.'#text' } } catch {}
        if (-not $path) { $path = ($e.Message -split "`n" | Select-Object -First 1) }
        if ($path) { $files += $path.Trim() }
    }
    $files | Where-Object { $_ } | Sort-Object -Unique
}

# =====================================================================
#  STEP 2 : -CheckEnforce  (verify audit log, then enforce if clean)
# =====================================================================
if ($CheckEnforce) {
    Assert-Admin
    Write-Head 'Verify audit log, then enforce'
    if (-not (Test-Path $StateFile)) { throw "No kernel-ci-state.json - run Enable-KernelCI.ps1 (step 1) first." }
    $st = Get-Content $StateFile -Raw | ConvertFrom-Json
    $mergedXml = Join-Path $WorkDir 'rescue-kernel-ci.xml'
    $cipFile   = Join-Path $WorkDir 'rescue-kernel-ci.cip'
    if (-not (Test-Path $mergedXml)) { throw "Built policy $mergedXml is missing - re-run step 1." }
    if ($st.Mode -eq 'ENFORCE') { Write-Item 'already' 'in enforce mode' 'Green'; return }

    $since = [datetime]::Parse($st.EnabledUtc).ToUniversalTime()
    $blocks = Get-CiAuditBlocks $since
    if ($blocks.Count -gt 0) {
        Write-Head 'Enforce would BLOCK these kernel files'
        $blocks | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        Write-Host ''
        Write-Host '  These are drivers the policy does not allow (not Microsoft-signed,' -ForegroundColor Yellow
        Write-Host '  not our hash). Enforcing now could destabilise the machine. Get them' -ForegroundColor Yellow
        Write-Host '  signed / uninstalled first, or stay in audit. NOT enforcing.'         -ForegroundColor Yellow
        exit 2
    }
    Write-Item 'audit log' 'clean - nothing would be blocked' 'Green'

    Set-RuleOption -FilePath $mergedXml -Option 3 -Delete            # audit -> enforce
    ConvertFrom-CIPolicy -XmlFilePath $mergedXml -BinaryFilePath $cipFile | Out-Null
    $method = Deploy-Cip $cipFile $st.PolicyId                        # same PolicyID / same name
    Write-Item 'policy' "enforced via $method" 'Green'

    $out = & fltmc.exe load $ServiceName 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Item 'minifilter' 'loaded' 'Green' }
    else { Write-Item 'minifilter' "not loaded yet (reboot may be needed): $($out.Trim())" 'Yellow' }

    $st.Mode = 'ENFORCE'; Save-State $st
    Write-Host ''; Write-Host 'Kernel protection is now ENFORCED. Restore-KernelCI.ps1 reverses it.' -ForegroundColor Green
    return
}

# =====================================================================
#  STEP 1 : default (audit enable) or -Enforce (one-shot)
# =====================================================================
Assert-Admin
Write-Head 'RescueMon kernel Code-Integrity enablement'
if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) {
    throw "The ConfigCI module (New-CIPolicy/Merge-CIPolicy) is unavailable on this edition of Windows. WDAC authoring needs Win10/11 Pro/Enterprise or the RSAT ConfigCI feature."
}
if (-not (Test-Path $SysPath)) { throw "Driver not found: $SysPath`nBuild rescuemon.sys first (tools/build-driver.sh, or the WDK - see driver/README.md)." }
$SysPath = (Resolve-Path $SysPath).Path

$mode       = if ($Enforce) { 'ENFORCE' } else { 'AUDIT' }
$secureBoot = Get-SecureBootState
$hvci       = Get-HvciState
$willDisableHvci = ($hvci -eq 'On') -and (-not $KeepHVCI)

Write-Head 'Preflight'
Write-Item 'Windows'          ((Get-CimInstance Win32_OperatingSystem).Caption + ' build ' + [Environment]::OSVersion.Version.Build)
Write-Item 'Secure Boot'      $secureBoot
Write-Item 'Memory Integrity' $hvci
Write-Item 'Deploy mode'      $mode $(if ($Enforce) { 'Yellow' } else { 'Gray' })
if ($willDisableHvci) { Write-Item 'Memory Integrity' 'will be turned OFF (reversible)' 'Red' }
elseif ($hvci -eq 'On') { Write-Item 'Memory Integrity' 'kept ON (-KeepHVCI) - unsigned driver will NOT load' 'Yellow' }

# ---- one consolidated typed consent -----------------------------------------
if (-not $Force) {
    Write-Host ''
    Write-Host '  ############################################################' -ForegroundColor Yellow
    Write-Host '  #  TURN ON KERNEL PROTECTION - READ ALL OF IT.            #' -ForegroundColor Yellow
    Write-Host '  ############################################################' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  This will, in one go:'
    Write-Host '   1. Self-sign rescuemon.sys and trust that cert (Root/TrustedPublisher).' -ForegroundColor White
    Write-Host '   2. Deploy a WDAC kernel policy = AllowMicrosoft + this driver''s hash'    -ForegroundColor White
    Write-Host ("      in {0} mode (audit blocks nothing; enforce gates every driver)." -f $mode) -ForegroundColor White
    Write-Host '   3. Install the RescueMon minifilter service.'                             -ForegroundColor White
    if ($willDisableHvci) {
        Write-Host '   4. TURN OFF Memory Integrity (HVCI) - required for an unsigned driver' -ForegroundColor Red
        Write-Host '      to load; lowers kernel-memory protection for ALL drivers; reboot'  -ForegroundColor Yellow
        Write-Host '      to take effect; Restore-KernelCI.ps1 turns it back on.'            -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '  Nothing is deleted (existing policy copied to .bak). Secure Boot is not touched.'
    if (-not $Enforce) { Write-Host '  After reboot, run  Enable-KernelCI.ps1 -CheckEnforce  to finish.' -ForegroundColor Cyan }
    Write-Host ''
    $phrase = 'I ACCEPT KERNEL PROTECTION'
    Write-Host ("  To proceed, type exactly:  {0}" -f $phrase) -ForegroundColor Cyan
    if ((Read-Host '  >') -ne $phrase) { Write-Host ''; Write-Host '  Not confirmed - nothing was changed.' -ForegroundColor Green; exit 1 }
} else { Write-Host '  -Force: consent prompt skipped.' -ForegroundColor Yellow }

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

# ---- 0. HVCI off (only if on, and not -KeepHVCI) ----------------------------
$hvciDisabled = $false
if ($willDisableHvci) { Write-Head 'Memory Integrity'; Set-Hvci 0; $hvciDisabled = $true; Write-Item 'HVCI' 'turned OFF - reboot required' 'Red' }

# ---- 1. self-sign the driver ------------------------------------------------
Write-Head 'Signing the driver'
$cert = New-SelfSignedCertificate -Subject 'CN=Rescue Kernel Protection (self-signed)' `
            -Type CodeSigningCert -KeyUsage DigitalSignature -KeyLength 3072 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
            -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddYears(3) `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
Write-Item 'certificate' $cert.Thumbprint 'Green'
$sig = Set-AuthenticodeSignature -FilePath $SysPath -Certificate $cert -HashAlgorithm SHA256
Write-Item 'driver signed' $sig.Status $(if ($sig.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
$cerTmp = Join-Path $WorkDir 'rescue-kernel-signing.cer'
Export-Certificate -Cert $cert -FilePath $cerTmp -Force | Out-Null
foreach ($store in @('Root', 'TrustedPublisher')) { Import-Certificate -FilePath $cerTmp -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null }

# ---- 2. build the policy: AllowMicrosoft base + our driver hash --------------
Write-Head 'Building the Code Integrity policy'
$allowMs = Join-Path $env:SystemRoot 'schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml'
if (-not (Test-Path $allowMs)) { throw "AllowMicrosoft.xml example policy not found at $allowMs." }
$drvXml    = Join-Path $WorkDir 'rescue-driver.xml'
$mergedXml = Join-Path $WorkDir 'rescue-kernel-ci.xml'
$cipFile   = Join-Path $WorkDir 'rescue-kernel-ci.cip'
New-CIPolicy -FilePath $drvXml -Level Hash -Fallback Hash -DriverFiles (Get-Item $SysPath) -UserPEs:$false -MultiplePolicyFormat 3>$null 4>$null
Merge-CIPolicy -PolicyPaths $allowMs, $drvXml -OutputFilePath $mergedXml | Out-Null
$idInfo = Set-CIPolicyIdInfo -FilePath $mergedXml -PolicyName $PolicyName -ResetPolicyID
$policyId = ([regex]::Match([string]$idInfo, '\{[0-9A-Fa-f-]+\}')).Value
if (-not $policyId) { [xml]$xml = Get-Content $mergedXml; $policyId = $xml.SiPolicy.PolicyID }
Write-Item 'policy id' $policyId 'Green'
Set-RuleOption -FilePath $mergedXml -Option 6             # allow unsigned policy
Set-RuleOption -FilePath $mergedXml -Option 16            # update without reboot
Set-RuleOption -FilePath $mergedXml -Option 0 -Delete     # kernel only (no UMCI)
if ($Enforce) { Set-RuleOption -FilePath $mergedXml -Option 3 -Delete } else { Set-RuleOption -FilePath $mergedXml -Option 3 }
ConvertFrom-CIPolicy -XmlFilePath $mergedXml -BinaryFilePath $cipFile | Out-Null

# ---- 3. back up existing policies, deploy ours ------------------------------
Write-Head 'Deploying'
$backups = @()
if (Test-Path $ActiveDir) { foreach ($f in Get-ChildItem $ActiveDir -Filter *.cip -ErrorAction SilentlyContinue) {
    $bak = "$($f.FullName).bak"; if (-not (Test-Path $bak)) { Copy-Item $f.FullName $bak -Force; $backups += $bak } } }
$legacy = Join-Path $CiDir 'SIPolicy.p7b'
if (Test-Path $legacy) { $bak = "$legacy.bak"; if (-not (Test-Path $bak)) { Copy-Item $legacy $bak -Force; $backups += $bak } }
$deployMethod = Deploy-Cip $cipFile $policyId
Write-Item 'deployed via' $deployMethod 'Green'

# ---- 4. install the minifilter service --------------------------------------
Write-Head 'Driver service'
$dest = Join-Path $env:SystemRoot 'System32\drivers\rescuemon.sys'
Copy-Item -Path $SysPath -Destination $dest -Force
if (Test-Path $InfPath) { & pnputil /add-driver $InfPath /install | Out-Null }
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    & sc.exe create $ServiceName type= filesys start= demand binPath= 'System32\drivers\rescuemon.sys' | Out-Null
    Write-Item 'service created' $ServiceName 'Green'
}
if ($Enforce -and $deployMethod -eq 'CiTool' -and -not $hvciDisabled) {
    $out = & fltmc.exe load $ServiceName 2>&1 | Out-String
    Write-Item 'minifilter' $(if ($LASTEXITCODE -eq 0) { 'loaded' } else { "load after reboot: $($out.Trim())" }) 'Gray'
}

Save-State ([pscustomobject]@{
    EnabledUtc = (Get-Date).ToUniversalTime().ToString('o'); Mode = $mode
    PolicyName = $PolicyName; PolicyId = $policyId; DeployMethod = $deployMethod
    CipFile = $cipFile; MergedXml = $mergedXml; CertThumbprint = $cert.Thumbprint
    ServiceName = $ServiceName; BackupsCreated = $backups
    SecureBoot = $secureBoot; Hvci = $hvci; HvciDisabledByUs = $hvciDisabled
})

Write-Host ''
if ($Enforce) {
    Write-Host 'Kernel protection deployed in ENFORCE mode.' -ForegroundColor Green
    if ($hvciDisabled) { Write-Host 'REBOOT to apply (HVCI off), then: fltmc load RescueMon' -ForegroundColor Yellow }
} else {
    Write-Host 'STEP 1 done (AUDIT mode - nothing blocked).' -ForegroundColor Green
    Write-Host 'Next: REBOOT, use the machine normally for a bit, then run:' -ForegroundColor Cyan
    Write-Host '      Enable-KernelCI.ps1 -CheckEnforce' -ForegroundColor Cyan
    Write-Host '(it reads the audit log for you and enforces only if clean).' -ForegroundColor Cyan
}
