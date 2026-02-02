<#
.SYNOPSIS
    Build, deploy, and manage Azure Container Instances with confidential computing.

.DESCRIPTION
    A unified script for the Azure Confidential Container Attestation Demo.
    Supports building container images, deploying to ACI with optional confidential 
    computing (AMD SEV-SNP with attestation sidecar), and cleanup.

.PARAMETER Build
    Build and push the container image to Azure Container Registry.
    Creates ACR and Key Vault if they don't exist.

.PARAMETER Deploy
    Deploy the container to Azure Container Instances.
    Requires a previous build (acr-config.json must exist).

.PARAMETER Compare
    Deploy TWO containers side by side - one Confidential SKU and one Standard SKU.
    Opens Edge with split tabs showing both containers for comparison.

.PARAMETER Cleanup
    Delete all Azure resources created by this script.

.PARAMETER NoAcc
    Deploy with Standard SKU instead of Confidential SKU.
    Skips Docker and security policy generation requirements.
    Sidecar is still deployed but attestation will fail (no TEE).

.PARAMETER SkipBrowser
    Skip opening the browser after deployment.

.PARAMETER RegistryName
    Custom name for the Azure Container Registry.
    If not provided, a random name will be generated.

.EXAMPLE
    .\Deploy-AttestationDemo.ps1 -Build
    Build and push the container image

.EXAMPLE
    .\Deploy-AttestationDemo.ps1 -Deploy
    Deploy with confidential computing (default)

.EXAMPLE
    .\Deploy-AttestationDemo.ps1 -Build -Deploy
    Build and deploy in one command

.EXAMPLE
    .\Deploy-AttestationDemo.ps1 -Deploy -NoAcc
    Deploy with standard SKU (attestation will fail)

.EXAMPLE
    .\Deploy-AttestationDemo.ps1 -Compare
    Deploy both Confidential and Standard containers side by side

.EXAMPLE
    .\Deploy-AttestationDemo.ps1 -Cleanup
    Delete all Azure resources
#>

param(
    [switch]$Build,
    [switch]$Deploy,
    [switch]$Compare,
    [switch]$Cleanup,
    [switch]$NoAcc,
    [switch]$SkipBrowser,
    [string]$RegistryName
)

$ErrorActionPreference = "Stop"
$Location = "eastus"
$ImageName = "aci-attestation-demo"
$ImageTag = "latest"

# Set UTF-8 encoding to handle Unicode characters in Azure CLI output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

function Get-Config {
    if (Test-Path "acr-config.json") {
        return Get-Content "acr-config.json" | ConvertFrom-Json
    }
    return $null
}

function Save-Config {
    param($Config)
    $Config | ConvertTo-Json | Out-File -FilePath "acr-config.json" -Encoding UTF8
}

# ============================================================================
# Build Phase
# ============================================================================

function Invoke-Build {
    param([string]$RegistryName)
    
    Write-Header "Building Container Image"
    
    # Generate registry name if not provided
    if (-not $RegistryName) {
        $random = -join ((97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
        $RegistryName = "acr$random"
        Write-Warning "No registry name provided. Using: $RegistryName"
    }
    
    $ResourceGroup = "sgall$RegistryName-rg"
    $KeyVaultName = "kv$RegistryName"
    
    Write-Host "Registry Name: $RegistryName"
    Write-Host "Resource Group: $ResourceGroup"
    Write-Host "Location: $Location"
    Write-Host "Image: ${ImageName}:${ImageTag}"
    Write-Host ""
    
    # Create resource group
    Write-Host "Creating resource group..." -ForegroundColor Green
    az group create --name $ResourceGroup --location $Location | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create resource group"
    }
    
    # Create Azure Container Registry
    Write-Host "Creating Azure Container Registry..." -ForegroundColor Green
    az acr create `
        --resource-group $ResourceGroup `
        --name $RegistryName `
        --sku Basic `
        --admin-enabled true | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create ACR"
    }
    
    # Create Azure Key Vault
    Write-Host "Creating Azure Key Vault: $KeyVaultName..." -ForegroundColor Green
    az keyvault create `
        --resource-group $ResourceGroup `
        --name $KeyVaultName `
        --location $Location `
        --enable-rbac-authorization false | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to create Key Vault, continuing..."
    }
    
    # Build and push image
    Write-Host "Building and pushing container image..." -ForegroundColor Green
    Write-Host "This may take a few minutes..."
    
    # Use --no-logs to avoid Unicode encoding issues with progress bars on Windows
    # Then query the build status separately
    $buildResult = az acr build `
        --registry $RegistryName `
        --image "${ImageName}:${ImageTag}" `
        --file Dockerfile `
        --no-logs `
        . 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        # Check if build actually succeeded by listing the image
        $imageExists = az acr repository show --name $RegistryName --image "${ImageName}:${ImageTag}" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host $buildResult
            throw "Failed to build and push image"
        }
    }
    
    Write-Success "Container image built and pushed successfully"
    
    # Get ACR credentials
    Write-Host "Retrieving ACR credentials..." -ForegroundColor Green
    $acrUsername = az acr credential show --name $RegistryName --query username -o tsv
    $acrPassword = az acr credential show --name $RegistryName --query "passwords[0].value" -o tsv
    $loginServer = az acr show --name $RegistryName --query loginServer -o tsv
    
    # Store credentials in Key Vault
    Write-Host "Storing credentials in Key Vault..." -ForegroundColor Green
    az keyvault secret set --vault-name $KeyVaultName --name "acr-username" --value $acrUsername --only-show-errors | Out-Null
    az keyvault secret set --vault-name $KeyVaultName --name "acr-password" --value $acrPassword --only-show-errors | Out-Null
    
    # Save configuration
    $config = @{
        registryName = $RegistryName
        resourceGroup = $ResourceGroup
        loginServer = $loginServer
        imageName = $ImageName
        imageTag = $ImageTag
        fullImage = "$loginServer/${ImageName}:${ImageTag}"
        keyVaultName = $KeyVaultName
    }
    Save-Config $config
    
    Write-Header "Build Complete"
    Write-Host "Registry: $loginServer"
    Write-Host "Image: $loginServer/${ImageName}:${ImageTag}"
    Write-Host "Key Vault: $KeyVaultName"
    Write-Host ""
    Write-Success "Credentials stored securely in Azure Key Vault"
    Write-Host "Configuration saved to acr-config.json"
    
    return $config
}

# ============================================================================
# Deploy Phase
# ============================================================================

function Invoke-Deploy {
    param(
        [switch]$NoAcc,
        [switch]$SkipBrowser
    )
    
    Write-Header "Deploying Container"
    
    # Check for config
    $config = Get-Config
    if (-not $config) {
        throw "acr-config.json not found. Run with -Build first."
    }
    
    $resource_group = $config.resourceGroup
    $FULL_IMAGE = $config.fullImage
    $ACR_LOGIN_SERVER = $config.loginServer
    $KEY_VAULT_NAME = $config.keyVaultName
    
    if ($NoAcc) {
        Write-Warning "*** NON-CONFIDENTIAL MODE ***"
        Write-Host "Deploying with Standard SKU (attestation will fail)"
        Write-Host ""
    }
    
    Write-Host "Image: $FULL_IMAGE"
    Write-Host "Resource Group: $resource_group"
    Write-Host ""
    
    # Retrieve credentials from Key Vault
    Write-Host "Retrieving credentials from Azure Key Vault..."
    $ACR_USERNAME = az keyvault secret show --vault-name $KEY_VAULT_NAME --name acr-username --query value -o tsv
    $ACR_PASSWORD = az keyvault secret show --vault-name $KEY_VAULT_NAME --name acr-password --query value -o tsv
    
    if ([string]::IsNullOrEmpty($ACR_USERNAME)) {
        throw "Failed to retrieve credentials from Key Vault: $KEY_VAULT_NAME"
    }
    Write-Success "Credentials retrieved successfully"
    Write-Host ""
    
    # Generate unique container name and DNS label
    $random_string = -join ((97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    $container_name = "attestation-demo-$random_string"
    $dns_label = "attest-$random_string"
    
    Write-Host "Container group name: $container_name"
    Write-Host "DNS label: $dns_label"
    Write-Host ""
    
    # Create parameters file
    Write-Host "Creating ARM template parameters..."
    $params = @{
        '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $container_name }
            'location' = @{ 'value' = $Location }
            'appImage' = @{ 'value' = $FULL_IMAGE }
            'registryServer' = @{ 'value' = $ACR_LOGIN_SERVER }
            'registryUsername' = @{ 'value' = $ACR_USERNAME }
            'registryPassword' = @{ 'value' = $ACR_PASSWORD }
            'dnsNameLabel' = @{ 'value' = $dns_label }
        }
    }
    $params | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params.json'
    
    # Set template based on mode
    if ($NoAcc) {
        Write-Host "Using Standard SKU template..."
        Copy-Item -Path "deployment-template-standard.json" -Destination "deployment-template.json" -Force
    } else {
        # Check Docker
        Write-Host "Checking if Docker is running..."
        $dockerInfo = docker info 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Docker is not running. Required for security policy generation. Start Docker Desktop or use -NoAcc."
        }
        Write-Success "Docker is running"
        Write-Host ""
        
        # Login to ACR
        Write-Host "Logging into Azure Container Registry..."
        az acr login --name $ACR_LOGIN_SERVER --username $ACR_USERNAME --password $ACR_PASSWORD 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            docker login $ACR_LOGIN_SERVER -u $ACR_USERNAME -p $ACR_PASSWORD 2>&1 | Out-Null
        }
        Write-Success "ACR login complete"
        Write-Host ""
        
        # Copy template and generate policy
        Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template.json" -Force
        
        Write-Host "Generating security policy for confidential container group..."
        Write-Host "This may take a few minutes..."
        Write-Host ""
        
        # --disable-stdio blocks interactive shell/exec access to containers
        az confcom acipolicygen -a deployment-template.json --parameters deployment-params.json --disable-stdio
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to generate security policy"
        }
        Write-Success "Security policy generated"
        Write-Host ""
    }
    
    # Deploy
    Write-Host "Deploying container group to Azure..."
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template.json `
        --parameters '@deployment-params.json'
    
    if ($LASTEXITCODE -ne 0) {
        az container delete --resource-group $resource_group --name $container_name --yes 2>&1 | Out-Null
        throw "Failed to create container group"
    }
    
    Write-Success "Container deployed successfully!"
    az container show --resource-group $resource_group --name $container_name --query "{FQDN:ipAddress.fqdn,ProvisioningState:provisioningState}" --output table
    
    # Get FQDN
    $fqdn = az container show --resource-group $resource_group --name $container_name --query "ipAddress.fqdn" --output tsv
    
    # Wait for container
    Write-Host ""
    Write-Host "Waiting for container to respond at http://$fqdn"
    $timeout_seconds = 180
    $elapsed_seconds = 0
    
    while ($elapsed_seconds -lt $timeout_seconds) {
        try {
            $response = Invoke-WebRequest -Uri "http://$fqdn" -Method Head -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) { break }
        } catch { }
        
        Write-Host "Waiting... ($elapsed_seconds/$timeout_seconds seconds)"
        Start-Sleep -Seconds 5
        $elapsed_seconds += 5
    }
    
    if ($elapsed_seconds -ge $timeout_seconds) {
        az container delete --resource-group $resource_group --name $container_name --yes
        throw "Container did not respond within 3 minutes"
    }
    
    Write-Host ""
    Write-Success "Container is responding!"
    
    # In NoAcc mode, show diagnostics
    if ($NoAcc) {
        Write-Host ""
        Write-Header "Attestation Diagnostics (NoAcc Mode)"
        Write-Warning "Running in Standard SKU - Attestation WILL fail (no TEE hardware)"
        Write-Host ""
        
        Write-Host "Fetching container logs..."
        Write-Host "" 
        $container_logs = az container logs --resource-group $resource_group --name $container_name --container-name attestation-demo 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $container_logs) {
            Write-Host "=== Container Logs ===" -ForegroundColor Yellow
            # Show last 30 lines of logs
            $container_logs | Select-Object -Last 30 | ForEach-Object { Write-Host $_ }
            Write-Host "=== End Container Logs ===" -ForegroundColor Yellow
        } else {
            Write-Host "No logs available yet (container may still be starting)"
        }
        
        Write-Host ""
        Write-Host "Checking /info endpoint for live attestation status..."
        try {
            $info_response = Invoke-RestMethod -Uri "http://$fqdn/info" -Method Get -TimeoutSec 10
            Write-Host ""
            Write-Host "=== Live Attestation Status ===" -ForegroundColor Yellow
            Write-Host "Platform Status: $($info_response.status.platform_status)"
            Write-Host "SKR Available: $($info_response.status.sidecar_available)"
            Write-Host "Attestation Works: $($info_response.status.attestation_works)"
            
            if ($info_response.status.attestation_error) {
                Write-Host ""
                Write-Host "Attestation Error Details:" -ForegroundColor Red
                Write-Host $info_response.status.attestation_error
            }
            
            if ($info_response.status.sidecar_error) {
                Write-Host ""
                Write-Host "SKR Error:" -ForegroundColor Red  
                Write-Host $info_response.status.sidecar_error
            }
            
            Write-Host ""
            Write-Host "Recommendation: $($info_response.diagnostics.recommendation)" -ForegroundColor Cyan
            Write-Host "=== End Attestation Status ===" -ForegroundColor Yellow
        } catch {
            Write-Host "Could not fetch /info endpoint: $_"
        }
        
        Write-Host ""
        Write-Host "To view full container logs anytime:"
        Write-Host "  az container logs -g $resource_group -n $container_name --container-name attestation-demo"
        Write-Host ""
    }
    
    # Open browser
    if (-not $SkipBrowser) {
        Write-Host "Opening web browser..."
        if ($NoAcc) {
            Write-Host "Running in Standard mode - attestation will fail (no TEE)."
        } else {
            Write-Host "The container includes the SKR attestation service for remote attestation."
        }
        Write-Host "Close the browser window when done."
        Write-Host ""
        Start-Process "msedge" -ArgumentList "http://$fqdn" -Wait
    }
    
    # Cleanup prompt
    Write-Host ""
    Write-Host "Cleanup options:" -ForegroundColor Cyan
    Write-Host "  d = Delete container only (keep ACR and Key Vault)"
    Write-Host "  a = Delete ALL resources (entire resource group)"
    Write-Host "  k = Keep everything"
    Write-Host ""
    $choice = Read-Host "Choose option (d/a/k)"
    
    switch ($choice) {
        'k' {
            Write-Host ""
            Write-Success "Resources preserved."
            Write-Host "Resource Group: $resource_group"
            Write-Host "Container: $container_name"
            Write-Host "FQDN: http://$fqdn"
            Write-Host ""
            Write-Host "To delete later: az container delete --resource-group $resource_group --name $container_name --yes"
        }
        'a' {
            Invoke-Cleanup -Confirm
        }
        default {
            Write-Host ""
            Write-Host "Deleting container: $container_name"
            az container delete --resource-group $resource_group --name $container_name --yes
            Write-Success "Container deleted. ACR and Key Vault preserved."
        }
    }
}

# ============================================================================
# Compare Phase - Deploy Both Confidential and Standard Side by Side
# ============================================================================

function Invoke-Compare {
    Write-Header "Deploying Comparison: Confidential vs Standard"
    
    $config = Get-Config
    if (-not $config) {
        throw "acr-config.json not found. Run with -Build first."
    }
    
    $resource_group = $config.resourceGroup
    $ACR_LOGIN_SERVER = $config.loginServer
    $FULL_IMAGE = $config.fullImage
    $KeyVaultName = $config.keyVaultName
    
    # Get ACR credentials from Key Vault
    Write-Host "Retrieving ACR credentials from Key Vault..."
    $ACR_USERNAME = az keyvault secret show --vault-name $KeyVaultName --name "acr-username" --query "value" -o tsv
    $ACR_PASSWORD = az keyvault secret show --vault-name $KeyVaultName --name "acr-password" --query "value" -o tsv
    
    if (-not $ACR_USERNAME -or -not $ACR_PASSWORD) {
        throw "Failed to retrieve ACR credentials from Key Vault"
    }
    
    # Generate unique names for both containers
    $timestamp = Get-Date -Format "MMddHHmm"
    $container_conf = "aci-attest-conf-$timestamp"
    $container_std = "aci-attest-std-$timestamp"
    $dns_conf = "attest-conf-$timestamp"
    $dns_std = "attest-std-$timestamp"
    
    Write-Host "Confidential Container: $container_conf"
    Write-Host "Standard Container: $container_std"
    Write-Host ""
    
    # Check Docker for confidential deployment
    Write-Host "Checking if Docker is running (required for Confidential SKU)..."
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running. Required for security policy generation. Start Docker Desktop."
    }
    Write-Success "Docker is running"
    Write-Host ""
    
    # Login to ACR
    Write-Host "Logging into Azure Container Registry..."
    az acr login --name $ACR_LOGIN_SERVER --username $ACR_USERNAME --password $ACR_PASSWORD 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        docker login $ACR_LOGIN_SERVER -u $ACR_USERNAME -p $ACR_PASSWORD 2>&1 | Out-Null
    }
    Write-Success "ACR login complete"
    Write-Host ""
    
    # ========== Deploy Confidential Container ==========
    Write-Header "Deploying Confidential Container (with AMD SEV-SNP)"
    
    # Create parameters for confidential
    $params_conf = @{
        '`$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $container_conf }
            'location' = @{ 'value' = $Location }
            'appImage' = @{ 'value' = $FULL_IMAGE }
            'registryServer' = @{ 'value' = $ACR_LOGIN_SERVER }
            'registryUsername' = @{ 'value' = $ACR_USERNAME }
            'registryPassword' = @{ 'value' = $ACR_PASSWORD }
            'dnsNameLabel' = @{ 'value' = $dns_conf }
        }
    }
    $params_conf | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-conf.json'
    
    # Copy template and generate policy for confidential
    Copy-Item -Path "deployment-template-original.json" -Destination "deployment-template-conf.json" -Force
    
    Write-Host "Generating security policy for confidential container..."
    az confcom acipolicygen -a deployment-template-conf.json --parameters deployment-params-conf.json --disable-stdio
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to generate security policy for confidential container"
    }
    Write-Success "Security policy generated"
    
    Write-Host "Deploying confidential container..."
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template-conf.json `
        --parameters '@deployment-params-conf.json' | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to deploy confidential container"
    }
    Write-Success "Confidential container deployed!"
    
    # ========== Deploy Standard Container ==========
    Write-Header "Deploying Standard Container (no TEE)"
    
    # Create parameters for standard
    $params_std = @{
        '`$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'containerGroupName' = @{ 'value' = $container_std }
            'location' = @{ 'value' = $Location }
            'appImage' = @{ 'value' = $FULL_IMAGE }
            'registryServer' = @{ 'value' = $ACR_LOGIN_SERVER }
            'registryUsername' = @{ 'value' = $ACR_USERNAME }
            'registryPassword' = @{ 'value' = $ACR_PASSWORD }
            'dnsNameLabel' = @{ 'value' = $dns_std }
        }
    }
    $params_std | ConvertTo-Json -Depth 10 | Set-Content 'deployment-params-std.json'
    
    # Use standard template (no policy)
    Copy-Item -Path "deployment-template-standard.json" -Destination "deployment-template-std.json" -Force
    
    Write-Host "Deploying standard container..."
    az deployment group create `
        --resource-group $resource_group `
        --template-file deployment-template-std.json `
        --parameters '@deployment-params-std.json' | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to deploy standard container"
    }
    Write-Success "Standard container deployed!"
    
    # ========== Wait for Both Containers ==========
    Write-Header "Waiting for Containers to Start"
    
    $fqdn_conf = az container show --resource-group $resource_group --name $container_conf --query "ipAddress.fqdn" --output tsv
    $fqdn_std = az container show --resource-group $resource_group --name $container_std --query "ipAddress.fqdn" --output tsv
    
    Write-Host "Confidential FQDN: http://$fqdn_conf"
    Write-Host "Standard FQDN: http://$fqdn_std"
    Write-Host ""
    
    $timeout_seconds = 180
    $elapsed_seconds = 0
    $conf_ready = $false
    $std_ready = $false
    
    while ($elapsed_seconds -lt $timeout_seconds -and (-not $conf_ready -or -not $std_ready)) {
        if (-not $conf_ready) {
            try {
                $response = Invoke-WebRequest -Uri "http://$fqdn_conf" -Method Head -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { 
                    $conf_ready = $true
                    Write-Success "Confidential container is ready!"
                }
            } catch { }
        }
        
        if (-not $std_ready) {
            try {
                $response = Invoke-WebRequest -Uri "http://$fqdn_std" -Method Head -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) { 
                    $std_ready = $true
                    Write-Success "Standard container is ready!"
                }
            } catch { }
        }
        
        if (-not $conf_ready -or -not $std_ready) {
            $status = "Waiting... ($elapsed_seconds/$timeout_seconds sec) - "
            $status += "Confidential: $(if ($conf_ready) { 'Ready' } else { 'Starting...' }), "
            $status += "Standard: $(if ($std_ready) { 'Ready' } else { 'Starting...' })"
            Write-Host $status
            Start-Sleep -Seconds 5
            $elapsed_seconds += 5
        }
    }
    
    if (-not $conf_ready -or -not $std_ready) {
        Write-Warning "Some containers did not start in time"
        if (-not $conf_ready) { Write-Warning "  - Confidential container not ready" }
        if (-not $std_ready) { Write-Warning "  - Standard container not ready" }
    }
    
    # ========== Open Edge with Split View ==========
    Write-Header "Opening Side-by-Side Comparison"
    
    Write-Host "Creating split-screen comparison view..."
    Write-Host "  Left:  Confidential (AMD SEV-SNP) - http://$fqdn_conf"
    Write-Host "  Right: Standard (No TEE)         - http://$fqdn_std"
    Write-Host ""
    
    # Create a local HTML file with iframes for split view
    $splitHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Attestation Comparison: Confidential vs Standard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { display: flex; flex-direction: column; height: 100vh; font-family: 'Segoe UI', sans-serif; }
        .header { 
            display: flex; 
            background: #1a1a2e; 
            color: white; 
            padding: 4px 15px;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 14px; font-weight: 500; }
        .labels { display: flex; gap: 0; }
        .label { 
            flex: 1; 
            text-align: center; 
            padding: 4px; 
            font-weight: bold;
            font-size: 12px;
        }
        .label.confidential { background: #28a745; color: white; }
        .label.standard { background: #dc3545; color: white; }
        .container { display: flex; flex: 1; }
        .pane { flex: 1; border: none; }
        .divider { width: 3px; background: #1a1a2e; }
        iframe { width: 100%; height: 100%; border: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Azure Confidential Container Attestation Demo - Comparison View</h1>
    </div>
    <div class="labels">
        <div class="label confidential">✅ CONFIDENTIAL (AMD SEV-SNP TEE)</div>
        <div class="label standard">❌ STANDARD (No Hardware Protection)</div>
    </div>
    <div class="container">
        <div class="pane">
            <iframe src="http://$fqdn_conf" title="Confidential Container"></iframe>
        </div>
        <div class="divider"></div>
        <div class="pane">
            <iframe src="http://$fqdn_std" title="Standard Container"></iframe>
        </div>
    </div>
</body>
</html>
"@
    
    $splitHtmlPath = Join-Path $PSScriptRoot "comparison-view.html"
    $splitHtml | Out-File -FilePath $splitHtmlPath -Encoding UTF8
    
    # Open the split view HTML in Edge
    Start-Process "msedge" -ArgumentList "--new-window `"file:///$($splitHtmlPath.Replace('\', '/'))`"" -Wait
    
    # Cleanup prompt
    Write-Host "Press Enter when done viewing to cleanup containers..." -ForegroundColor Yellow
    Read-Host
    
    Write-Header "Cleanup Comparison Containers"
    
    Write-Host "Deleting comparison containers..."
    az container delete --resource-group $resource_group --name $container_conf --yes 2>&1 | Out-Null
    az container delete --resource-group $resource_group --name $container_std --yes 2>&1 | Out-Null
    
    # Cleanup temp files
    Remove-Item -Path "deployment-params-conf.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-params-std.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-conf.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "deployment-template-std.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "comparison-view.html" -Force -ErrorAction SilentlyContinue
    
    Write-Success "Comparison containers deleted. ACR and Key Vault preserved."
    Write-Host "Run -Cleanup to delete all resources including ACR and Key Vault."
}

# ============================================================================
# Cleanup Phase
# ============================================================================

function Invoke-Cleanup {
    param([switch]$Confirm)
    
    $config = Get-Config
    if (-not $config) {
        Write-Warning "No acr-config.json found. Nothing to clean up."
        return
    }
    
    $resource_group = $config.resourceGroup
    
    Write-Header "Cleanup Resources"
    Write-Warning "This will delete the ENTIRE resource group: $resource_group"
    Write-Host "Including:"
    Write-Host "  - Azure Container Registry: $($config.registryName)"
    Write-Host "  - Azure Key Vault: $($config.keyVaultName)"
    Write-Host "  - All container instances"
    Write-Host ""
    
    if (-not $Confirm) {
        $response = Read-Host "Type 'yes' to confirm deletion"
        if ($response -ne 'yes') {
            Write-Warning "Cleanup cancelled."
            return
        }
    }
    
    Write-Host ""
    Write-Host "Deleting resource group: $resource_group"
    Write-Host "This may take a few minutes..."
    az group delete --name $resource_group --yes --no-wait
    
    # Remove local config
    if (Test-Path "acr-config.json") {
        Remove-Item "acr-config.json" -Force
        Write-Host "Removed acr-config.json"
    }
    
    Write-Host ""
    Write-Success "Resource group deletion initiated."
    Write-Host "Deletion is running in the background."
    Write-Host "Run 'az group show --name $resource_group' to check status."
}

# ============================================================================
# Main Entry Point
# ============================================================================

# Show help if no action specified
if (-not $Build -and -not $Deploy -and -not $Compare -and -not $Cleanup) {
    Write-Host ""
    Write-Host "Azure Confidential Container Attestation Demo" -ForegroundColor Cyan
    Write-Host "=============================================="
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\Deploy-AttestationDemo.ps1 -Build              # Build container image"
    Write-Host "  .\Deploy-AttestationDemo.ps1 -Deploy             # Deploy to ACI (confidential)"
    Write-Host "  .\Deploy-AttestationDemo.ps1 -Deploy -NoAcc      # Deploy to ACI (standard)"
    Write-Host "  .\Deploy-AttestationDemo.ps1 -Compare            # Deploy BOTH side by side"
    Write-Host "  .\Deploy-AttestationDemo.ps1 -Build -Deploy      # Build and deploy"
    Write-Host "  .\Deploy-AttestationDemo.ps1 -Cleanup            # Delete all resources"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -NoAcc          Use Standard SKU (no confidential computing)"
    Write-Host "  -SkipBrowser    Don't open browser after deployment"
    Write-Host "  -RegistryName   Custom ACR name (default: random)"
    Write-Host ""
    
    $config = Get-Config
    if ($config) {
        Write-Host "Current configuration (from acr-config.json):" -ForegroundColor Green
        Write-Host "  Resource Group: $($config.resourceGroup)"
        Write-Host "  Registry: $($config.loginServer)"
        Write-Host "  Image: $($config.fullImage)"
    } else {
        Write-Host "No existing configuration. Run with -Build to get started." -ForegroundColor Yellow
    }
    Write-Host ""
    exit 0
}

# Execute requested actions
try {
    if ($Build) {
        $config = Invoke-Build -RegistryName $RegistryName
    }
    
    if ($Compare) {
        Invoke-Compare
    }
    elseif ($Deploy) {
        Invoke-Deploy -NoAcc:$NoAcc -SkipBrowser:$SkipBrowser
    }
    
    if ($Cleanup) {
        Invoke-Cleanup
    }
} catch {
    Write-Error "Error: $_"
    exit 1
}
