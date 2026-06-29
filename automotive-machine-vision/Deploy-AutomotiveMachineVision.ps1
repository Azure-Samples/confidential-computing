param(
    [switch]$Build,
    [switch]$Deploy,
    [switch]$Cleanup,
    [switch]$DeployAFD,
    [string]$RegistryName,
    [string]$ImageTag = "latest",
    [ValidateRange(1, 30)][int]$CpuCores = 4,
    [ValidateRange(2, 128)][int]$MemoryInGB = 6,
    [ValidateRange(0, 30)][int]$ProcessingWorkers = 0,
    [ValidateRange(1, 12)][int]$DetectEveryNFrames = 1,
    [string]$TlsCertPath = "",
    [string]$TlsKeyPath = ""
)

$ErrorActionPreference = "Stop"
$Location = "eastus"
$ImageName = "automotive-machine-vision"

function Invoke-Az {
    param(
        [string]$Description,
        [scriptblock]$Command
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed (exit code $LASTEXITCODE)."
    }
}

function Invoke-AzValue {
    param(
        [string]$Description,
        [scriptblock]$Command
    )

    $result = & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed (exit code $LASTEXITCODE)."
    }

    return $result
}

function Get-Config {
    if (Test-Path "acr-config.json") { return Get-Content "acr-config.json" | ConvertFrom-Json }
    return $null
}

function Save-Config($Config) {
    $Config | ConvertTo-Json | Out-File -FilePath "acr-config.json" -Encoding UTF8
}

if ($Build) {
    if (-not $RegistryName) {
        $random = -join ((97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
        $RegistryName = "acr$random"
    }

    $ResourceGroup = "amv-$RegistryName-rg"
    Invoke-Az "Create resource group" { az group create --name $ResourceGroup --location $Location | Out-Null }

    Invoke-Az "Create Azure Container Registry" { az acr create --resource-group $ResourceGroup --name $RegistryName --sku Basic --admin-enabled true | Out-Null }
    Invoke-Az "Build container image in ACR" { az acr build --registry $RegistryName --image "$ImageName`:$ImageTag" --file Dockerfile . }

    $acrUsername = Invoke-AzValue "Fetch ACR username" { az acr credential show --name $RegistryName --query username -o tsv }
    $acrPassword = Invoke-AzValue "Fetch ACR password" { az acr credential show --name $RegistryName --query "passwords[0].value" -o tsv }
    $loginServer = Invoke-AzValue "Fetch ACR login server" { az acr show --name $RegistryName --query loginServer -o tsv }

    Save-Config @{
        registryName = $RegistryName
        resourceGroup = $ResourceGroup
        loginServer = $loginServer
        imageName = $ImageName
        imageTag = $ImageTag
        fullImage = "$loginServer/$ImageName`:$ImageTag"
        acrUsername = $acrUsername
        acrPassword = $acrPassword
    }

    Write-Host "Build complete: $loginServer/$ImageName`:$ImageTag" -ForegroundColor Green
}

if ($Deploy) {
    $config = Get-Config
    if (-not $config) {
        throw "Run -Build first (acr-config.json is missing)."
    }

    if ($ImageTag -and $ImageTag -ne "latest") {
        $config.imageTag = $ImageTag
        $config.fullImage = "$($config.loginServer)/$($config.imageName):$ImageTag"
    }

    $suffix = -join ((97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    $dnsLabel = "amv-$suffix"
    $containerName = "amv-container-$suffix"
    $secret = [guid]::NewGuid().ToString()
    $effectiveWorkers = if ($ProcessingWorkers -gt 0) { $ProcessingWorkers } else { [Math]::Max(6, [Math]::Min(24, $CpuCores)) }
    $tlsCertPem = ""
    $tlsKeyPem = ""

    if (($TlsCertPath -and -not $TlsKeyPath) -or (-not $TlsCertPath -and $TlsKeyPath)) {
        throw "To use a real TLS certificate, provide both -TlsCertPath and -TlsKeyPath."
    }

    if ($TlsCertPath -and $TlsKeyPath) {
        if (-not (Test-Path $TlsCertPath)) {
            throw "TLS certificate file not found: $TlsCertPath"
        }
        if (-not (Test-Path $TlsKeyPath)) {
            throw "TLS private key file not found: $TlsKeyPath"
        }

        $tlsCertPem = Get-Content -Path $TlsCertPath -Raw
        $tlsKeyPem = Get-Content -Path $TlsKeyPath -Raw

        if ([string]::IsNullOrWhiteSpace($tlsCertPem) -or [string]::IsNullOrWhiteSpace($tlsKeyPem)) {
            throw "TLS certificate and key files must not be empty."
        }

        Write-Host "Using provided CA-issued TLS certificate for deployment." -ForegroundColor Green
    } else {
        Write-Host "No TLS certificate files provided; deployment will fall back to self-signed certificate." -ForegroundColor Yellow
    }

    $params = @{
        containerGroupName = @{ value = $containerName }
        location = @{ value = $Location }
        appImage = @{ value = $config.fullImage }
        registryServer = @{ value = $config.loginServer }
        registryUsername = @{ value = $config.acrUsername }
        registryPassword = @{ value = $config.acrPassword }
        dnsNameLabel = @{ value = $dnsLabel }
        flaskSecretKey = @{ value = $secret }
        tlsCertificatePem = @{ value = $tlsCertPem }
        tlsPrivateKeyPem = @{ value = $tlsKeyPem }
        cpuCores = @{ value = $CpuCores }
        memoryInGB = @{ value = $MemoryInGB }
        processingWorkers = @{ value = [string]$effectiveWorkers }
        detectEveryNFrames = @{ value = [string]$DetectEveryNFrames }
    }

    $armParameterFile = @{
        '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
        contentVersion = "1.0.0.0"
        parameters = $params
    }

    $armParameterFile | ConvertTo-Json -Depth 12 | Out-File -FilePath "deployment-params.json" -Encoding UTF8
    Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template.json" -Force

    # az confcom pulls images via local Docker to compute measurements.
    Invoke-Az "Authenticate Docker to ACR" { az acr login --name $config.registryName | Out-Null }
    Invoke-Az "Pull latest image for policy generation" { docker pull $config.fullImage | Out-Null }

    # CCE policy generation: binds policy to approved image and disables interactive access
    Invoke-Az "Generate CCE policy" { az confcom acipolicygen -a deployment-template.json --parameters deployment-params.json --disable-stdio }

    Invoke-Az "Deploy confidential container group $containerName" {
        az deployment group create --resource-group $config.resourceGroup --template-file deployment-template.json --parameters '@deployment-params.json' containerGroupName=$containerName dnsNameLabel=$dnsLabel instanceName=$containerName | Out-Null
    }

    $fqdn = Invoke-AzValue "Get deployed container FQDN for $containerName" { az container show --resource-group $config.resourceGroup --name $containerName --query ipAddress.fqdn -o tsv }
    if ([string]::IsNullOrWhiteSpace($fqdn)) {
        throw "Deployment finished but no container FQDN was returned for $containerName."
    }

    if ($DeployAFD) {
        Write-Host "Deploying Azure Front Door for HTTPS access..." -ForegroundColor Cyan
        $afdDeploymentName = "deployment-afd-$(Get-Date -Format 'yyyyMMddHHmmss')"
        Invoke-Az "Deploy Azure Front Door" {
            az deployment group create `
                --resource-group $config.resourceGroup `
                --name $afdDeploymentName `
                --template-file deployment-afd.bicep `
                --parameters aciOriginFqdn=$fqdn `
                | Out-Null
        }
        
        $afdEndpoint = Invoke-AzValue "Get AFD endpoint" {
            az deployment group show `
                --resource-group $config.resourceGroup `
                --name $afdDeploymentName `
                --query "properties.outputs.frontDoorEndpoint.value" -o tsv
        }

        Write-Host "Azure Front Door deployment complete!" -ForegroundColor Green
        Write-Host "Endpoint (Azure-managed HTTPS):" -ForegroundColor Green
        Write-Host " - https://$afdEndpoint" -ForegroundColor Green
        Write-Host "" -ForegroundColor Green
        Write-Host "Direct ACI endpoint (self-signed or provided cert):" -ForegroundColor Yellow
        Write-Host " - https://$fqdn" -ForegroundColor Yellow
    } else {
        Write-Host "Deployment complete. Endpoint:" -ForegroundColor Green
        Write-Host " - https://$fqdn" -ForegroundColor Green
        if ($TlsCertPath -and $TlsKeyPath) {
            Write-Host "TLS mode: using provided certificate and key." -ForegroundColor Green
        } else {
            Write-Host "TLS mode: self-signed fallback (demo only)." -ForegroundColor Yellow
        }
    }
}

if ($Cleanup) {
    $config = Get-Config
    if ($config -and $config.resourceGroup) {
        Invoke-Az "Start cleanup of resource group" { az group delete --name $config.resourceGroup --yes --no-wait }
        Write-Host "Cleanup started for resource group $($config.resourceGroup)" -ForegroundColor Green
    } else {
        Write-Host "No acr-config.json found with resource group info." -ForegroundColor Yellow
    }
}

if (-not ($Build -or $Deploy -or $Cleanup)) {
    Write-Host "Usage: .\Deploy-AutomotiveMachineVision.ps1 -Build [-ImageTag amv-20260602] | -Deploy [-ImageTag amv-20260602 -CpuCores 30 -MemoryInGB 120 -ProcessingWorkers 24 -DetectEveryNFrames 1 -TlsCertPath .\certs\fullchain.pem -TlsKeyPath .\certs\privkey.pem] [-DeployAFD] | -Cleanup"
}
