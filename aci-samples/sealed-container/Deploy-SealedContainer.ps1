<#
.SYNOPSIS
    Deploy the sealed-app container group to ACI Confidential SKU using the
    artifacts produced by Build-SealedArtifacts.ps1.

.DESCRIPTION
    Reads acr-config.json (written by Build-SealedArtifacts.ps1) plus the
    confcom-generated CCE policy under artifacts/cce-policy.rego, then
    submits an ARM deployment of deployment-template.json with the right
    parameters.

    The container is exposed on a PUBLIC IP because Confidential ACI does
    not support VNet integration without a NAT gateway. Ingress is locked
    down at L7 by the app (see app.py before_request) using the signed
    artifacts/firewall-policy.json baked into the image.

    There is intentionally NO Standard-SKU variant of this deployment: the
    SKR release policy refuses to release the wrapping key off SEV-SNP, so a
    Standard deploy would crash-loop forever and is more confusing than
    educational.

.PARAMETER Deploy
    Submit the ARM deployment. Default action.

.PARAMETER Cleanup
    Delete the container group (NOT the AKV / ACR — use the full RG cleanup
    in Build-SealedArtifacts.ps1 for that).

.PARAMETER SkipBrowser
    Don't open the FQDN after a successful deploy.

.PARAMETER Verify
    Re-check artifacts/checksums.sha256 against the files on disk; warn if
    anything has drifted since the last build.
#>
[CmdletBinding(DefaultParameterSetName='Deploy')]
param(
    [Parameter(ParameterSetName='Deploy')]  [switch]$Deploy,
    [Parameter(ParameterSetName='Cleanup')] [switch]$Cleanup,
    [Parameter(ParameterSetName='Verify')]  [switch]$Verify,
    [Parameter(ParameterSetName='Deploy')]  [switch]$SkipBrowser
)

$ErrorActionPreference = 'Stop'
$ScriptDir   = $PSScriptRoot
$ArtifactDir = Join-Path $ScriptDir 'artifacts'
$ConfigPath  = Join-Path $ScriptDir 'acr-config.json'

function Write-Header { param($m) Write-Host ""; Write-Host ("=" * 72) -ForegroundColor Cyan; Write-Host $m -ForegroundColor Cyan; Write-Host ("=" * 72) -ForegroundColor Cyan }
function Write-Step   { param($m) Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-Success { param($m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn2  { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }

function Get-Cfg {
    if (-not (Test-Path $ConfigPath)) {
        throw "acr-config.json not found. Run ./Build-SealedArtifacts.ps1 -Build first."
    }
    return Get-Content $ConfigPath -Raw | ConvertFrom-Json
}

function Get-Sha256 { param($Path) (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower() }

# ----------------------------------------------------------------------------
# Verify
# ----------------------------------------------------------------------------
function Invoke-Verify {
    Write-Header "Verifying artifacts/checksums.sha256"
    $checksumPath = Join-Path $ArtifactDir 'checksums.sha256'
    if (-not (Test-Path $checksumPath)) { throw "$checksumPath not found." }
    $bad = 0; $good = 0
    foreach ($line in Get-Content $checksumPath) {
        if (-not $line.Trim()) { continue }
        $parts = $line -split '\s+', 2
        $expected = $parts[0]
        $name     = $parts[1].TrimStart('*')
        $path     = Join-Path $ArtifactDir $name
        if (-not (Test-Path $path)) { Write-Warn2 "MISSING : $name"; $bad++; continue }
        $actual = Get-Sha256 $path
        if ($actual -eq $expected) {
            Write-Host "  OK      $name" -ForegroundColor Green
            $good++
        } else {
            Write-Host "  MISMATCH $name" -ForegroundColor Red
            Write-Host "     expected: $expected" -ForegroundColor DarkGray
            Write-Host "     actual:   $actual"   -ForegroundColor DarkGray
            $bad++
        }
    }
    Write-Host ""
    if ($bad -eq 0) { Write-Success "All $good artifacts match their recorded SHA-256." ; return 0 }
    Write-Warn2 "$bad artifacts failed verification."
    return 1
}

# ----------------------------------------------------------------------------
# Cleanup (container group only)
# ----------------------------------------------------------------------------
function Invoke-Cleanup {
    Write-Header "Cleanup — deleting container group"
    $cfg = Get-Cfg
    $cgName = "$($cfg.basename)-cg"
    Write-Host "Deleting container group(s) matching: $cgName*"
    $cgList = az container list --resource-group $cfg.resourceGroup --query "[?starts_with(name, '$cgName')].name" -o tsv
    foreach ($n in ($cgList -split "`n" | Where-Object { $_ })) {
        Write-Host "  - $n"
        az container delete --resource-group $cfg.resourceGroup --name $n --yes | Out-Null
    }
    Write-Success "Cleanup done."
}

# ----------------------------------------------------------------------------
# Deploy
# ----------------------------------------------------------------------------
function Invoke-Deploy {
    Write-Header "Deploying sealed-app to ACI Confidential SKU (public IP, L7 firewall)"
    $cfg = Get-Cfg

    if (-not $cfg.ccePolicyBase64 -or -not $cfg.imageRef) {
        throw "acr-config.json is incomplete — re-run ./Build-SealedArtifacts.ps1 -Build."
    }
    if (-not $cfg.trustedSourceCidr) {
        throw "acr-config.json is missing trustedSourceCidr — re-run ./Build-SealedArtifacts.ps1 -Build."
    }

    # Re-verify checksums before deploying; refuse if anything drifted.
    if ((Invoke-Verify) -ne 0) {
        throw "Artifact verification failed. Refusing to deploy."
    }

    # Pull ACR creds
    $u = az acr credential show --name $cfg.registry --query username -o tsv
    $p = az acr credential show --name $cfg.registry --query "passwords[0].value" -o tsv
    if (-not $u -or -not $p) { throw "Failed to read ACR admin credentials" }

    $stamp = Get-Date -Format 'MMddHHmm'
    $cgName       = "$($cfg.basename)-cg-$stamp"
    $dnsNameLabel = "$($cfg.basename)-$stamp".ToLower() -replace '[^a-z0-9-]', ''
    if ($dnsNameLabel.Length -gt 63) { $dnsNameLabel = $dnsNameLabel.Substring(0, 63) }

    $paramsObj = @{
        '$schema'         = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
        contentVersion    = "1.0.0.0"
        parameters        = @{
            containerGroupName   = @{ value = $cgName }
            location             = @{ value = $cfg.location }
            dnsNameLabel         = @{ value = $dnsNameLabel }
            appImage             = @{ value = $cfg.imageRef }
            registryServer       = @{ value = $cfg.loginServer }
            registryUsername     = @{ value = $u }
            registryPassword     = @{ value = $p }
            managedIdentityId    = @{ value = $cfg.identityId }
            maaEndpoint          = @{ value = $cfg.maaEndpoint }
            akvEndpoint          = @{ value = $cfg.akvEndpoint }
            skrKeyName           = @{ value = $cfg.keyName }
            releasePolicySha256  = @{ value = $cfg.releasePolicySha256 }
            firewallPolicySha256 = @{ value = $cfg.firewallPolicySha256 }
            trustedSourceCidr    = @{ value = $cfg.trustedSourceCidr }
            ccePolicyBase64      = @{ value = $cfg.ccePolicyBase64 }
        }
    }
    $tmpParams = Join-Path ([IO.Path]::GetTempPath()) "sealed-deploy-$([guid]::NewGuid().ToString('N')).json"
    $paramsObj | ConvertTo-Json -Depth 10 | Set-Content $tmpParams -Encoding UTF8
    try {
        Write-Step "Submitting ARM deployment ($cgName)"
        $deployJson = az deployment group create `
            --resource-group $cfg.resourceGroup `
            --name $cgName `
            --template-file (Join-Path $ScriptDir 'deployment-template.json') `
            --parameters "@$tmpParams" -o json
        if ($LASTEXITCODE -ne 0) { throw "az deployment group create failed" }
    } finally {
        Remove-Item $tmpParams -Force -ErrorAction SilentlyContinue
    }

    $outputs = ($deployJson | ConvertFrom-Json).properties.outputs
    $publicIp = $outputs.publicIp.value
    $fqdn     = $outputs.fqdn.value
    $url      = $outputs.url.value

    Write-Success "Deployed."
    Write-Host "  Container group: $cgName"
    Write-Host "  Public IP:       $publicIp"
    Write-Host "  FQDN:            $fqdn"
    Write-Host "  URL:             $url"
    Write-Host ""
    Write-Host "  L7 firewall (enforced by app.py) only accepts requests from:"
    Write-Host "    $($cfg.trustedSourceCidr)"
    Write-Host "  Anything else gets a 403 before any route runs."
    Write-Host "  /healthz bypasses the firewall (so the platform probe works)."
    Write-Host ""
    Write-Host "View logs:    az container logs -g $($cfg.resourceGroup) -n $cgName --container-name sealed-app"
    Write-Host "Try exec:     az container exec -g $($cfg.resourceGroup) -n $cgName --exec-command /bin/sh"
    Write-Host "              ^ will FAIL by design — confcom-generated CCE policy denies exec_processes"
    Write-Host "Cleanup:      ./Deploy-SealedContainer.ps1 -Cleanup"
    Write-Host ""

    if (-not $SkipBrowser -and $url) {
        Start-Process $url -ErrorAction SilentlyContinue
    }
}

# ----------------------------------------------------------------------------
# Dispatch
# ----------------------------------------------------------------------------
switch ($PSCmdlet.ParameterSetName) {
    'Cleanup' { Invoke-Cleanup }
    'Verify'  { Invoke-Verify | Out-Null }
    default   { Invoke-Deploy }
}
