<#
.SYNOPSIS
    Build, sign and attest the sealed-app container image and produce a complete
    set of signed artifacts under artifacts/.

.DESCRIPTION
    Steps performed (in order):

      1. Validate prerequisites (az with the confcom extension, docker OR
         az acr build, optionally: cosign, syft, trivy).
      2. Create resource group + ACR if missing (or reuse an existing one
         pinned in acr-config.json).
      3. Generate a fresh 32-byte AES-256 data-encryption key (DEK) and
         produce the sealed data bundle at artifacts/sealed-data.enc using
         a freshly-generated RSA-4096 keypair as the wrapping key. The
         RSA PRIVATE key is then uploaded into Azure Key Vault Premium
         (HSM-backed) with the SKR release policy from
         policies/skr-release-policy.json.
      4. Render policies/firewall-policy.json with the deployer's /32
         substituted, write it to artifacts/, and compute its SHA-256.
      5. Build the container image (`az acr build` server-side, no local
         Docker required) and capture the image digest. The rendered
         firewall-policy.json is baked into the image.
      6. Run `az confcom acipolicygen` against deployment-template.json
         to produce artifacts/cce-policy.rego (the only form of CCE
         policy the Confidential ACI platform accepts), then compute
         sha256(cce-policy) and base64-encode it.
      7. Render policies/skr-release-policy.json with that SHA-256
         (closing the chain) and import the wrap key into AKV with the
         release policy attached.
      8. Generate an SBOM with syft (SPDX + CycloneDX). Fall back to a
         minimal hand-rolled SBOM if syft is not installed.
      9. Run a vulnerability scan with trivy. Fall back to a stub report.
     10. Sign every artifact with cosign (if installed) and compute SHA-256
         checksums.
     11. Assemble artifacts/MANIFEST.json + MANIFEST.json.sig pointing at
         every file with its digest, and refresh artifacts/checksums.sha256.

    No interactive prompts — fully scriptable.

.PARAMETER Build
    Build the image and produce all artifacts. Default action.

.PARAMETER Refresh
    Re-render the policies, SBOM, scan and signatures against the
    already-built image. Skips the docker build.

.PARAMETER Prefix
    Resource naming prefix (default: sgall). Random 5-char suffix appended.

.PARAMETER Location
    Azure region (default: eastus). Must support Confidential ACI + Premium AKV.

.PARAMETER SubscriptionId
    Azure subscription to use. Defaults to current az context.

.EXAMPLE
    ./Build-SealedArtifacts.ps1 -Build
#>
[CmdletBinding(DefaultParameterSetName='Build')]
param(
    [Parameter(ParameterSetName='Build')]   [switch]$Build,
    [Parameter(ParameterSetName='Refresh')] [switch]$Refresh,
    [string]$Prefix = 'sgall',
    [string]$Location = 'eastus',
    [string]$SubscriptionId,
    [string]$TrustedSourceCidr
)

$ErrorActionPreference = 'Stop'
$OutputEncoding        = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir   = $PSScriptRoot
$ArtifactDir = Join-Path $ScriptDir 'artifacts'
$PolicyDir   = Join-Path $ScriptDir 'policies'
$ConfigPath  = Join-Path $ScriptDir 'acr-config.json'
$ImageName   = 'sealed-app'
$ImageTag    = '1.0.0'

if (-not (Test-Path $ArtifactDir)) { New-Item -ItemType Directory -Path $ArtifactDir -Force | Out-Null }

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Write-Header  { param($m) Write-Host ""; Write-Host ("=" * 72) -ForegroundColor Cyan; Write-Host $m -ForegroundColor Cyan; Write-Host ("=" * 72) -ForegroundColor Cyan }
function Write-Step    { param($m) Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-Success { param($m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn2   { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }

function Test-Tool {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { Write-Host "  $Name found: $($cmd.Source)"; return $true }
    Write-Warn2 "$Name not installed — falling back to placeholder output."
    return $false
}

function Get-Sha256 {
    param([Parameter(Mandatory)] [string]$Path)
    (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
}

function Save-Config { param($cfg) $cfg | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath -Encoding UTF8 }
function Get-Config  { if (Test-Path $ConfigPath) { Get-Content $ConfigPath -Raw | ConvertFrom-Json } }

function Invoke-Az {
    az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed (exit $LASTEXITCODE)" }
}

function Test-AzCli {
    az version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Azure CLI not found. Install from https://aka.ms/azcli" }
    $acct = az account show 2>$null | ConvertFrom-Json
    if (-not $acct) { throw "Not logged in. Run: az login" }
    if ($SubscriptionId -and $acct.id -ne $SubscriptionId) {
        Invoke-Az account set --subscription $SubscriptionId
        $acct = az account show | ConvertFrom-Json
    }
    Write-Host "Subscription: $($acct.name) ($($acct.id))"
    return $acct
}

# ----------------------------------------------------------------------------
# Sealed data bundle producer
# ----------------------------------------------------------------------------
function New-SealedBundle {
    <#
        Produces:
          artifacts/sealed-data.enc                  — encrypted on-disk bundle.
          artifacts/wrap-key.pem (TEMP, deleted)     — RSA-4096 priv key (uploaded to AKV then wiped).
          artifacts/wrap-key.public.pem              — public half (recorded for traceability).
        Returns:
          @{ DekHex, WrapPrivPem (string), WrapPubPem (string), CiphertextSha256 }
    #>
    Add-Type -AssemblyName System.Security
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $dek = New-Object byte[] 32 ; $rng.GetBytes($dek)
    $nonce = New-Object byte[] 12 ; $rng.GetBytes($nonce)

    # Plaintext sealed bundle — application secrets, sample data, splash text.
    $plain = [ordered]@{
        sealed_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        meta = @{
            description = "Demo sealed data bundle for sealed-app on ACI Confidential Containers."
            owner       = "Azure Confidential Computing samples"
        }
        files = @{
            'welcome.txt'   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
                "Hello from inside the TEE. This file was never on disk in plaintext on the host."))
            'api-token.txt' = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
                "demo-api-token-" + ([guid]::NewGuid().ToString('N'))))
            'config.json'   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
                (@{ tenant='demo'; tier='confidential'; rotation_days=30 } | ConvertTo-Json -Compress)))
        }
    } | ConvertTo-Json -Depth 10 -Compress
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($plain)

    # AES-256-GCM via .NET (PowerShell 7+)
    $aes = [System.Security.Cryptography.AesGcm]::new($dek)
    $ct  = New-Object byte[] $plainBytes.Length
    $tag = New-Object byte[] 16
    $aad = [Text.Encoding]::ASCII.GetBytes("sealed-app/v1")
    $aes.Encrypt($nonce, $plainBytes, $ct, $tag, $aad)
    $aes.Dispose()
    # The cryptography library expects the auth tag appended to the ciphertext.
    $ctTag = New-Object byte[] ($ct.Length + 16)
    [Array]::Copy($ct, 0, $ctTag, 0, $ct.Length)
    [Array]::Copy($tag, 0, $ctTag, $ct.Length, 16)

    # RSA-4096 wrapping key
    $rsa = [System.Security.Cryptography.RSA]::Create(4096)
    $wrapped = $rsa.Encrypt($dek, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $privPem = $rsa.ExportRSAPrivateKeyPem()
    $pubPem  = $rsa.ExportRSAPublicKeyPem()
    $rsa.Dispose()

    # Assemble the bundle: SEAL magic, version, [u32+wrapped][u32+nonce][u32+ct+tag]
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter $ms
    $bw.Write([byte[]]([Text.Encoding]::ASCII.GetBytes("SEAL")))
    $bw.Write([uint32]1)
    $bw.Write([uint32]$wrapped.Length); $bw.Write($wrapped)
    $bw.Write([uint32]$nonce.Length);   $bw.Write($nonce)
    $bw.Write([uint32]$ctTag.Length);   $bw.Write($ctTag)
    $bw.Flush()
    $bundlePath = Join-Path $ArtifactDir 'sealed-data.enc'
    [System.IO.File]::WriteAllBytes($bundlePath, $ms.ToArray())
    $bw.Dispose() ; $ms.Dispose()

    $ctSha = Get-Sha256 $bundlePath
    $pubPath = Join-Path $ArtifactDir 'wrap-key.public.pem'
    $pubPem | Set-Content $pubPath -Encoding ASCII

    Write-Success "Sealed bundle written: $bundlePath ($ctSha)"
    return @{
        DekHex           = ($dek | ForEach-Object { '{0:x2}' -f $_ }) -join ''
        WrapPrivPem      = $privPem
        WrapPubPem       = $pubPem
        CiphertextSha256 = $ctSha
    }
}

# ----------------------------------------------------------------------------
# SBOM (syft)
# ----------------------------------------------------------------------------
function New-Sbom {
    param([string]$ImageRef)
    $spdx   = Join-Path $ArtifactDir 'sealed-app.sbom.spdx.json'
    $cdx    = Join-Path $ArtifactDir 'sealed-app.sbom.cyclonedx.json'
    if (Test-Tool 'syft') {
        Write-Step "Generating SBOM with syft"
        syft "$ImageRef" -o "spdx-json=$spdx" -o "cyclonedx-json=$cdx" --quiet
        if ($LASTEXITCODE -ne 0) { throw "syft failed" }
    } else {
        Write-Step "Writing placeholder SBOM (syft not installed)"
        $requirements = Get-Content (Join-Path $ScriptDir 'requirements.txt')
        $packages = $requirements | Where-Object { $_ -and ($_ -notmatch '^\s*#') } |
            ForEach-Object {
                $name, $rest = $_ -split '[><=!]', 2
                @{ name = $name.Trim(); versionRange = $_.Trim(); SPDXID = "SPDXRef-Package-$($name.Trim())" }
            }
        $obj = [ordered]@{
            spdxVersion       = "SPDX-2.3"
            dataLicense       = "CC0-1.0"
            SPDXID            = "SPDXRef-DOCUMENT"
            name              = "sealed-app-placeholder"
            documentNamespace = "https://example.invalid/spdxdocs/sealed-app/" + [guid]::NewGuid()
            creationInfo      = @{ created = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); creators = @("Tool: Build-SealedArtifacts.ps1 (placeholder; install syft for real SBOM)") }
            packages          = $packages
            _placeholder      = $true
        }
        $obj | ConvertTo-Json -Depth 10 | Set-Content $spdx -Encoding UTF8
        # CycloneDX placeholder
        $cdxObj = [ordered]@{
            bomFormat = "CycloneDX" ; specVersion = "1.5" ; version = 1
            metadata = @{ timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); tools = @(@{ vendor = "Build-SealedArtifacts.ps1"; name = "placeholder" }) }
            components = $packages | ForEach-Object { @{ type = "library"; name = $_.name; version = $_.versionRange } }
            _placeholder = $true
        }
        $cdxObj | ConvertTo-Json -Depth 10 | Set-Content $cdx -Encoding UTF8
    }
    Write-Success "SBOM: $spdx + $cdx"
    return @{ Spdx = $spdx; Cdx = $cdx }
}

# ----------------------------------------------------------------------------
# Vulnerability scan (trivy)
# ----------------------------------------------------------------------------
function Invoke-Scan {
    param([string]$ImageRef)
    $jsonPath = Join-Path $ArtifactDir 'trivy-report.json'
    $mdPath   = Join-Path $ArtifactDir 'trivy-report.summary.md'
    if (Test-Tool 'trivy') {
        Write-Step "Scanning image with trivy"
        trivy image --quiet --format json --output $jsonPath $ImageRef
        if ($LASTEXITCODE -ne 0) { throw "trivy failed" }
        trivy image --quiet --format table --severity CRITICAL,HIGH,MEDIUM --output $mdPath $ImageRef
    } else {
        Write-Step "Writing placeholder vulnerability report (trivy not installed)"
        $stub = [ordered]@{
            ArtifactName = $ImageRef
            ArtifactType = "container_image"
            Metadata     = @{ ScannedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); Scanner = "placeholder" }
            Results      = @()
            _placeholder = $true
            _instructions = "Install trivy (https://aquasecurity.github.io/trivy/) and re-run with -Refresh."
        }
        $stub | ConvertTo-Json -Depth 10 | Set-Content $jsonPath -Encoding UTF8
        @"
# Vulnerability scan summary (placeholder)

trivy is not installed in this environment. Run:

```powershell
choco install trivy   # or: scoop install trivy
./Build-SealedArtifacts.ps1 -Refresh
```

After a real scan this file will list every CVE in the image grouped by
severity, with fixed-version columns and a signed JSON report alongside.
"@ | Set-Content $mdPath -Encoding UTF8
    }
    Write-Success "Scan report: $jsonPath + $mdPath"
    return @{ Json = $jsonPath; Md = $mdPath }
}

# ----------------------------------------------------------------------------
# Signing (cosign)
# ----------------------------------------------------------------------------
function Sign-Artifact {
    param(
        [string]$Path,
        [string]$KeyRef  # cosign key path or KMS ref. If null, ephemeral keyless OIDC.
    )
    $sigPath = "$Path.sig"
    if (Test-Tool 'cosign') {
        # Use sign-blob for detached signatures over arbitrary files.
        $cmd = @('sign-blob', '--yes', '--output-signature', $sigPath, $Path)
        if ($KeyRef) { $cmd = @('sign-blob', '--yes', '--key', $KeyRef, '--output-signature', $sigPath, $Path) }
        cosign @cmd 2>&1 | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0) { throw "cosign sign-blob failed for $Path" }
    } else {
        # Stub signature: a JSON document recording the hash + a clear note.
        @{
            _placeholder = $true
            note         = "cosign is not installed — install it and re-run -Refresh for a real signature."
            algorithm    = "sha256"
            digest       = Get-Sha256 $Path
            signed_at    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            file         = (Split-Path -Leaf $Path)
        } | ConvertTo-Json -Depth 10 | Set-Content $sigPath -Encoding UTF8
    }
    return $sigPath
}

# ----------------------------------------------------------------------------
# Policy rendering
# ----------------------------------------------------------------------------
function Render-SkrPolicy {
    <#
        Renders policies/skr-release-policy.json (source of truth) with the
        target MAA endpoint and the CCE policy SHA-256, then writes the
        inner `.policy` object to artifacts/skr-release-policy.json (the
        AKV-acceptable form). Returns the path + sha256.
    #>
    param(
        [string]$MaaEndpoint,
        [string]$CcePolicySha256
    )
    $releasePath = Join-Path $ArtifactDir 'skr-release-policy.json'
    $releaseSrcRaw = Get-Content (Join-Path $PolicyDir 'skr-release-policy.json') -Raw
    $releaseSrcRaw = $releaseSrcRaw `
        -replace '__MAA_ENDPOINT__',         $MaaEndpoint `
        -replace '__CCE_POLICY_SHA256_HEX__', $CcePolicySha256
    $releaseObj = $releaseSrcRaw | ConvertFrom-Json
    $releaseAkvJson = $releaseObj.policy | ConvertTo-Json -Depth 20
    Set-Content $releasePath $releaseAkvJson -Encoding UTF8
    $releaseSha = Get-Sha256 $releasePath
    Write-Success "skr-release-policy.json  sha256 = $releaseSha"
    return @{ Path = $releasePath; Sha256 = $releaseSha }
}

function Invoke-Confcom {
    <#
        Renders a temporary, fully-concrete ARM parameters file for the
        deployment template (every value confcom needs to compute the
        policy is filled in), then runs `az confcom acipolicygen` to
        produce artifacts/cce-policy.rego. Returns the path, the raw
        bytes' sha256, and the base64-encoded form that goes into
        deployment-template.json's ccePolicyBase64 parameter at deploy
        time.

        confcom-generated policies are the ONLY form the ACI control
        plane accepts — hand-authored Rego is silently rejected at
        SNP_LAUNCH_FINISH and the container never reaches the image-pull
        stage. See the Unsupported Scenarios section of
        https://learn.microsoft.com/azure/container-instances/container-instances-confidential-overview
    #>
    param(
        [hashtable]$Params,
        [string]$RegistryName,
        [string]$SubscriptionId
    )
    $cceRawPath = Join-Path $ArtifactDir 'cce-policy.rego'
    $tmpParams  = Join-Path ([IO.Path]::GetTempPath()) ("sealed-confcom-" + [guid]::NewGuid().ToString('N') + '.json')

    $paramsDoc = @{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        contentVersion = '1.0.0.0'
        parameters     = @{}
    }
    foreach ($k in $Params.Keys) { $paramsDoc.parameters[$k] = @{ value = $Params[$k] } }
    $paramsDoc | ConvertTo-Json -Depth 10 | Set-Content $tmpParams -Encoding UTF8

    Write-Step "Generating CCE policy with az confcom acipolicygen"
    try {
        # confcom shells out to the local docker daemon to pull the image
        # and hash its layers, so the daemon needs an ACR token. `az acr
        # login` writes one into the docker credential store for us.
        $loginArgs = @('acr', 'login', '--name', $RegistryName)
        if ($SubscriptionId) { $loginArgs += @('--subscription', $SubscriptionId) }
        az @loginArgs 2>&1 | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0) { throw "az acr login failed (exit $LASTEXITCODE)" }

        # --outraw       → write raw (un-base64'd) policy text to the file
        # --save-to-file → write the policy to disk
        # -y             → auto-approve wildcards prompt (we don't use any,
        #                   but the tool prompts in some cases anyway)
        $deployTemplate = Join-Path $ScriptDir 'deployment-template.json'
        az confcom acipolicygen --template-file $deployTemplate --parameters $tmpParams `
            --save-to-file $cceRawPath --outraw -y 2>&1 | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0) { throw "az confcom acipolicygen failed (exit $LASTEXITCODE)" }
        if (-not (Test-Path $cceRawPath)) { throw "confcom did not produce $cceRawPath" }
    } finally {
        Remove-Item $tmpParams -Force -ErrorAction SilentlyContinue
    }

    $cceBytes = [System.IO.File]::ReadAllBytes($cceRawPath)
    $cceSha   = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($cceBytes))).Replace('-', '').ToLower()
    $cceB64   = [Convert]::ToBase64String($cceBytes)
    Write-Success "cce-policy.rego          sha256 = $cceSha ($($cceBytes.Length) bytes)"
    return @{
        Path    = $cceRawPath
        Sha256  = $cceSha
        Base64  = $cceB64
    }
}

# ----------------------------------------------------------------------------
# Firewall policy rendering
# ----------------------------------------------------------------------------
function Get-DeployerCidr {
    if ($TrustedSourceCidr) { return $TrustedSourceCidr }
    try {
        $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 8).Trim()
        if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { return "$ip/32" }
    } catch { }
    Write-Warn2 "Could not detect deployer public IP; defaulting trustedSourceCidr to 0.0.0.0/0 (NOT recommended). Override with -TrustedSourceCidr."
    return '0.0.0.0/0'
}

function Render-Firewall {
    <#
        Renders policies/firewall-policy.json (the SOURCE OF TRUTH) by
        substituting __TRUSTED_SOURCE_CIDR__ with the detected/overridden
        CIDR, writes it to artifacts/, and returns its sha256 + the CIDR
        used. Because Confidential ACI does not allow VNet integration
        without a NAT gateway, this policy is enforced AT THE APP
        (app.py before_request hook) instead of by an NSG. The CCE
        policy bakes the resulting sha256 + CIDR into the container's
        env vars so a tampered firewall file fails the in-process
        verification at startup.
    #>
    param([string]$Cidr)
    $srcPolicy   = Join-Path $PolicyDir   'firewall-policy.json'
    $dstPolicy   = Join-Path $ArtifactDir 'firewall-policy.json'
    $raw = Get-Content $srcPolicy -Raw
    $raw = $raw -replace '__TRUSTED_SOURCE_CIDR__', $Cidr
    Set-Content $dstPolicy $raw -Encoding UTF8
    $sha = Get-Sha256 $dstPolicy
    Write-Success "firewall-policy.json     sha256 = $sha"
    Write-Host    "  trusted source CIDR: $Cidr"
    return @{
        PolicyPath        = $dstPolicy
        PolicySha256      = $sha
        TrustedSourceCidr = $Cidr
    }
}

# ----------------------------------------------------------------------------
# Top-level orchestration
# ----------------------------------------------------------------------------
function Invoke-Build {
    Write-Header "sealed-app — build, attest and sign"
    Test-AzCli | Out-Null

    $cfg = Get-Config
    if (-not $cfg) {
        $rand = -join ((97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $cfg = [pscustomobject]@{
            basename      = "$Prefix-sealed-$rand"
            resourceGroup = "$Prefix-sealed-$rand-rg"
            registry      = "acr$Prefix$rand"
            keyVault      = "kv$Prefix$rand"
            identity      = "id$Prefix$rand"
            location      = $Location
            keyName       = 'sealed-app-wrap-key'
            maaEndpoint   = "sharedeus.eus.attest.azure.net"
        }
    }
    Write-Host "Resource group: $($cfg.resourceGroup)"
    Write-Host "ACR           : $($cfg.registry)"
    Write-Host "Key Vault     : $($cfg.keyVault)"
    Write-Host "Identity      : $($cfg.identity)"
    Write-Host "Location      : $($cfg.location)"

    Write-Step "Ensuring Azure resources (group, ACR, identity, KV, SKR key)"
    Invoke-Az group create --name $cfg.resourceGroup --location $cfg.location --output none

    # ACR — create only if missing (az acr create errors on already-exists).
    $acrExists = az acr show --name $cfg.registry --resource-group $cfg.resourceGroup 2>$null
    if (-not $acrExists) {
        Invoke-Az acr create --resource-group $cfg.resourceGroup --name $cfg.registry --sku Basic --admin-enabled true --output none
    }
    $loginServer = az acr show --name $cfg.registry --query loginServer -o tsv
    $cfg | Add-Member -NotePropertyName loginServer -NotePropertyValue $loginServer -Force

    # User-assigned managed identity — idempotent on `create` but other CLI
    # versions complain, so guard the same way.
    $idExists = az identity show --resource-group $cfg.resourceGroup --name $cfg.identity 2>$null
    if (-not $idExists) {
        Invoke-Az identity create --resource-group $cfg.resourceGroup --name $cfg.identity --location $cfg.location --output none
    }
    $identityJson = az identity show --resource-group $cfg.resourceGroup --name $cfg.identity | ConvertFrom-Json
    $cfg | Add-Member -NotePropertyName identityId       -NotePropertyValue $identityJson.id          -Force
    $cfg | Add-Member -NotePropertyName identityClientId -NotePropertyValue $identityJson.clientId    -Force
    $cfg | Add-Member -NotePropertyName identityPrincipalId -NotePropertyValue $identityJson.principalId -Force

    # Premium AKV with purge protection (required for HSM-backed exportable keys).
    # `az keyvault create` errors hard when the vault already exists in any
    # subscription on the tenant — guard with a show first.
    $kvExists = az keyvault show --name $cfg.keyVault --resource-group $cfg.resourceGroup 2>$null
    if (-not $kvExists) {
        Invoke-Az keyvault create --resource-group $cfg.resourceGroup --name $cfg.keyVault --location $cfg.location `
            --sku Premium --enable-purge-protection true --enable-rbac-authorization false --output none
    }

    Invoke-Az keyvault set-policy --name $cfg.keyVault --object-id $cfg.identityPrincipalId `
        --key-permissions get release wrapKey unwrapKey --output none

    Write-Step "Creating sealed data bundle and RSA-4096 wrap key"
    $sealed = New-SealedBundle
    $akvEndpoint = "$($cfg.keyVault).vault.azure.net"

    Save-Config $cfg

    # The actual AKV import + release-policy attach happens AFTER policy
    # rendering below so we have the final policy hash to bind to the key.

    # Render the firewall policy BEFORE building the image, because the
    # image bakes artifacts/firewall-policy.json so the app can verify its
    # SHA-256 against the FIREWALL_POLICY_SHA256 env var at startup.
    $cidr = Get-DeployerCidr
    Write-Step "Rendering firewall policy (trusted CIDR = $cidr)"
    $fw = Render-Firewall -Cidr $cidr

    if (-not $Refresh) {
        Write-Step "Building image server-side with az acr build"
        # NB: at this point sealed-data.enc AND firewall-policy.json both
        # exist under artifacts/, so the Dockerfile COPYs succeed.
        Invoke-Az acr build --registry $cfg.registry --image "${ImageName}:${ImageTag}" --file Dockerfile --no-logs $ScriptDir
    }

    $manifest = az acr repository show-manifests --name $cfg.registry --repository $ImageName --query "[?tags && contains(tags,'${ImageTag}')] | [0]" -o json | ConvertFrom-Json
    if (-not $manifest) { throw "Image ${ImageName}:${ImageTag} not found in $($cfg.registry) — build failed?" }
    $imageDigest = $manifest.digest
    $imageRef    = "$loginServer/${ImageName}@$imageDigest"
    # Layer dm-verity hashes are produced by `az acr manifest show` for ORAS-compliant images.
    $layerInfo = az acr manifest show --registry $cfg.registry --name "$ImageName@$imageDigest" -o json | ConvertFrom-Json
    $layerDigests = @($layerInfo.layers | ForEach-Object { $_.digest })
    Write-Success "Image: $imageRef ($($layerDigests.Count) layer(s))"

    # Pull ACR creds NOW so confcom can authenticate when it inspects the
    # private image to enumerate layers.
    $acrUser = az acr credential show --name $cfg.registry --query username -o tsv
    $acrPass = az acr credential show --name $cfg.registry --query "passwords[0].value" -o tsv
    if (-not $acrUser -or -not $acrPass) { throw "Failed to read ACR admin credentials for confcom" }

    # Generate the CCE policy with az confcom acipolicygen against the
    # actual deployment template + concrete parameters. The platform
    # ONLY accepts confcom-generated policies; hand-authored Rego is
    # silently rejected at SNP_LAUNCH_FINISH and the deployment then
    # hits the 30-minute provisioning timeout with zero events.
    $confcomParams = @{
        containerGroupName   = "sealed-app-cg"
        location             = $cfg.location
        dnsNameLabel         = "sealed-app"
        appImage             = $imageRef
        registryServer       = $loginServer
        registryUsername     = $acrUser
        registryPassword     = $acrPass
        managedIdentityId    = $cfg.identityId
        maaEndpoint          = $cfg.maaEndpoint
        akvEndpoint          = $akvEndpoint
        skrKeyName           = $cfg.keyName
        releasePolicySha256  = ('0' * 64)   # tag-only; not in container env
        firewallPolicySha256 = $fw.PolicySha256
        trustedSourceCidr    = $fw.TrustedSourceCidr
        ccePolicyBase64      = 'placeholder'  # confcom replaces this on injection paths; we ignore the in-template value
    }
    $cce = Invoke-Confcom -Params $confcomParams -RegistryName $cfg.registry

    Write-Step "Rendering SKR release policy (binds to CCE SHA-256)"
    $skr = Render-SkrPolicy -MaaEndpoint $cfg.maaEndpoint -CcePolicySha256 $cce.Sha256

    Write-Step "Importing wrap key into Azure Key Vault with SKR release policy"
    $tmpPem = Join-Path ([IO.Path]::GetTempPath()) ("wrap-key-$([guid]::NewGuid().ToString('N')).pem")
    Set-Content $tmpPem $sealed.WrapPrivPem -Encoding ASCII
    try {
        Invoke-Az keyvault key import --vault-name $cfg.keyVault --name $cfg.keyName `
            --pem-file $tmpPem --protection hsm --ops decrypt unwrapKey --exportable true `
            --policy (Resolve-Path $skr.Path).Path --output none
    } finally {
        Remove-Item $tmpPem -Force -ErrorAction SilentlyContinue
    }
    Write-Success "Wrap key $($cfg.keyName) imported into $($cfg.keyVault) and bound to SKR release policy"

    $sbom = New-Sbom -ImageRef $imageRef
    $scan = Invoke-Scan -ImageRef $imageRef

    Write-Step "Signing artifacts"
    $signed = @()
    foreach ($p in @(
        $cce.Path, $skr.Path,
        $fw.PolicyPath,
        $sbom.Spdx, $sbom.Cdx,
        $scan.Json, $scan.Md,
        (Join-Path $ArtifactDir 'sealed-data.enc'),
        (Join-Path $ScriptDir 'deployment-template.json')
    )) {
        $sig = Sign-Artifact -Path $p
        $signed += [pscustomobject]@{ file = (Split-Path -Leaf $p); sig = (Split-Path -Leaf $sig); sha256 = (Get-Sha256 $p) }
    }

    Write-Step "Writing MANIFEST.json + checksums.sha256"
    $manifestObj = [ordered]@{
        schema                = "https://github.com/Azure-Samples/confidential-computing/sealed-container/manifest-v1"
        produced_at           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        image = @{
            reference     = $imageRef
            digest        = $imageDigest
            layers        = $layerDigests
            registry      = $cfg.registry
        }
        policies = @{
            cce_policy_sha256     = $cce.Sha256
            release_policy_sha256 = $skr.Sha256
        }
        firewall = @{
            policy_sha256        = $fw.PolicySha256
            trusted_source_cidr  = $fw.TrustedSourceCidr
            allowed_ingress_port = 8443
            enforcement          = "L7 (app.py before_request) — Confidential ACI does not support NSG without NAT gateway"
            default_action       = "deny"
        }
        akv = @{
            endpoint  = $akvEndpoint
            key_name  = $cfg.keyName
        }
        managed_identity = @{
            name        = $cfg.identity
            client_id   = $cfg.identityClientId
            resource_id = $cfg.identityId
        }
        sealed_data = @{
            file              = "sealed-data.enc"
            ciphertext_sha256 = $sealed.CiphertextSha256
            wrap_algorithm    = "RSA-OAEP-SHA256 + AES-256-GCM"
            wrap_key_public   = "wrap-key.public.pem"
        }
        files = $signed
    }
    $manifestPath = Join-Path $ArtifactDir 'MANIFEST.json'
    $manifestObj | ConvertTo-Json -Depth 10 | Set-Content $manifestPath -Encoding UTF8
    Sign-Artifact -Path $manifestPath | Out-Null

    $checksumPath = Join-Path $ArtifactDir 'checksums.sha256'
    Get-ChildItem $ArtifactDir -File | Where-Object { $_.Name -notin @('checksums.sha256') } |
        Sort-Object Name | ForEach-Object {
            "$(Get-Sha256 $_.FullName)  $($_.Name)"
        } | Set-Content $checksumPath -Encoding ASCII
    Write-Success "Checksums written: $checksumPath"

    # Update acr-config so Deploy-SealedContainer.ps1 can pick up everything.
    $cfg | Add-Member -NotePropertyName imageRef           -NotePropertyValue $imageRef -Force
    $cfg | Add-Member -NotePropertyName imageDigest        -NotePropertyValue $imageDigest -Force
    $cfg | Add-Member -NotePropertyName ccePolicyBase64    -NotePropertyValue $cce.Base64 -Force
    $cfg | Add-Member -NotePropertyName ccePolicySha256    -NotePropertyValue $cce.Sha256 -Force
    $cfg | Add-Member -NotePropertyName releasePolicySha256 -NotePropertyValue $skr.Sha256 -Force
    $cfg | Add-Member -NotePropertyName firewallPolicySha256 -NotePropertyValue $fw.PolicySha256 -Force
    $cfg | Add-Member -NotePropertyName trustedSourceCidr  -NotePropertyValue $fw.TrustedSourceCidr -Force
    $cfg | Add-Member -NotePropertyName akvEndpoint        -NotePropertyValue $akvEndpoint -Force
    Save-Config $cfg

    Write-Header "Build complete"
    Write-Host "Artifacts directory: $ArtifactDir"
    Write-Host "Image:               $imageRef"
    Write-Host ""
    Write-Host "Next step:"
    Write-Host "  ./Deploy-SealedContainer.ps1 -Deploy"
}

# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------
if ($Refresh -or $Build -or $PSCmdlet.ParameterSetName -eq 'Build') {
    Invoke-Build
} else {
    Get-Help $MyInvocation.MyCommand.Path -Full
}
