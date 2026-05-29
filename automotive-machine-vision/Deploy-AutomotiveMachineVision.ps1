param(
    [switch]$Build,
    [switch]$Deploy,
    [switch]$Cleanup,
    [string]$RegistryName
)

$ErrorActionPreference = "Stop"
$Location = "eastus"
$ImageName = "automotive-machine-vision"
$ImageTag = "latest"

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
    az group create --name $ResourceGroup --location $Location | Out-Null

    az acr create --resource-group $ResourceGroup --name $RegistryName --sku Basic --admin-enabled true | Out-Null
    az acr build --registry $RegistryName --image "$ImageName`:$ImageTag" --file Dockerfile .

    $acrUsername = az acr credential show --name $RegistryName --query username -o tsv
    $acrPassword = az acr credential show --name $RegistryName --query "passwords[0].value" -o tsv
    $loginServer = az acr show --name $RegistryName --query loginServer -o tsv

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

    $dnsLabel = "amv-" + (-join ((97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}))
    $containerName = "amv-container"
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
    }

    $params | ConvertTo-Json -Depth 10 | Out-File -FilePath "deployment-params.json" -Encoding UTF8
    Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template.json" -Force

    # CCE policy generation: binds policy to approved image and disables interactive access
    az confcom acipolicygen -a deployment-template.json --parameters deployment-params.json --disable-stdio

    az deployment group create --resource-group $config.resourceGroup --template-file deployment-template.json --parameters '@deployment-params.json' | Out-Null

    $fqdn = az container show --resource-group $config.resourceGroup --name $containerName --query ipAddress.fqdn -o tsv
    Write-Host "Deployment complete. Open: https://$fqdn" -ForegroundColor Green
    Write-Host "Note: certificate is self-signed for demo purposes." -ForegroundColor Yellow
}

if ($Cleanup) {
    $config = Get-Config
    if ($config -and $config.resourceGroup) {
        az group delete --name $config.resourceGroup --yes --no-wait
        Write-Host "Cleanup started for resource group $($config.resourceGroup)" -ForegroundColor Green
    } else {
        Write-Host "No acr-config.json found with resource group info." -ForegroundColor Yellow
    }
}

if (-not ($Build -or $Deploy -or $Cleanup)) {
    Write-Host "Usage: .\Deploy-AutomotiveMachineVision.ps1 -Build | -Deploy | -Cleanup"
}
