param(
    [switch]$Build,
    [switch]$Deploy,
    [switch]$Cleanup,
    [string]$RegistryName,
    [ValidateRange(1, 16)][int]$CpuCores = 2,
    [ValidateRange(2, 128)][int]$MemoryInGB = 6,
    [ValidateRange(1, 16)][int]$ProcessingWorkers = 3,
    [ValidateRange(1, 12)][int]$DetectEveryNFrames = 1
)

$ErrorActionPreference = "Stop"
$Location = "eastus"
$ImageName = "automotive-machine-vision"
$ImageTag = "latest"

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

    $suffix = -join ((97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    $dnsLabel = "amv-$suffix"
    $containerName = "amv-container-$suffix"
    $secret = [guid]::NewGuid().ToString()

    $params = @{
        containerGroupName = @{ value = $containerName }
        location = @{ value = $Location }
        appImage = @{ value = $config.fullImage }
        registryServer = @{ value = $config.loginServer }
        registryUsername = @{ value = $config.acrUsername }
        registryPassword = @{ value = $config.acrPassword }
        dnsNameLabel = @{ value = $dnsLabel }
        flaskSecretKey = @{ value = $secret }
        cpuCores = @{ value = $CpuCores }
        memoryInGB = @{ value = $MemoryInGB }
        processingWorkers = @{ value = $ProcessingWorkers }
        detectEveryNFrames = @{ value = $DetectEveryNFrames }
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

    Write-Host "Deployment complete. Endpoint:" -ForegroundColor Green
    Write-Host " - https://$fqdn" -ForegroundColor Green
    Write-Host "Note: certificate is self-signed for demo purposes." -ForegroundColor Yellow
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
    Write-Host "Usage: .\Deploy-AutomotiveMachineVision.ps1 -Build | -Deploy [-CpuCores 16 -MemoryInGB 128 -ProcessingWorkers 16 -DetectEveryNFrames 1] | -Cleanup"
}
