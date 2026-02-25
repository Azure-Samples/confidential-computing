<#
.SYNOPSIS
    Create an Azure Storage Account with a blob container.
    Run this in a seperate Azure subscription to the one used by the demo app, ideally in a seperate EntraID tenant

.DESCRIPTION
    Creates a storage account called 'orangeappstorage' in UK South region
    with a blob container called 'privateappdata' accessible over the internet.

.PARAMETER ResourceGroup
    The resource group to create the storage account in.
    If not specified, creates 'orangeapp-rg'.

.EXAMPLE
    .\Create-StorageAccount.ps1
    Creates storage account in a new resource group

.EXAMPLE
    .\Create-StorageAccount.ps1 -ResourceGroup "my-existing-rg"
    Creates storage account in an existing resource group
#>

param(
    [string]$ResourceGroup = "orangeapp-rg"
)

$ErrorActionPreference = "Stop"

# Configuration
$StorageAccountName = "orangeappstorezspo861" # name must be globally unique
$Location = "uksouth"
$ContainerName = "privateappdata"

Write-Host ""
Write-Host "=== Creating Azure Storage Account ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Storage Account: $StorageAccountName"
Write-Host "Location: $Location"
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Container: $ContainerName"
Write-Host ""

# Create resource group if it doesn't exist
Write-Host "Creating resource group..." -ForegroundColor Green
az group create --name $ResourceGroup --location $Location | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create resource group"
}
Write-Host "Resource group ready: $ResourceGroup" -ForegroundColor Green

# Create storage account
Write-Host ""
Write-Host "Creating storage account..." -ForegroundColor Green
az storage account create `
    --name $StorageAccountName `
    --resource-group $ResourceGroup `
    --location $Location `
    --sku Standard_LRS `
    --kind StorageV2 `
    --access-tier Hot `
    --allow-blob-public-access true `
    --public-network-access Enabled `
    --min-tls-version TLS1_2

if ($LASTEXITCODE -ne 0) {
    throw "Failed to create storage account"
}
Write-Host "Storage account created: $StorageAccountName" -ForegroundColor Green

# Get storage account key
Write-Host ""
Write-Host "Retrieving storage account key..." -ForegroundColor Green
$StorageKey = az storage account keys list `
    --account-name $StorageAccountName `
    --resource-group $ResourceGroup `
    --query "[0].value" -o tsv

if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($StorageKey)) {
    throw "Failed to retrieve storage account key"
}

# Create blob container
Write-Host ""
Write-Host "Creating blob container: $ContainerName..." -ForegroundColor Green
az storage container create `
    --name $ContainerName `
    --account-name $StorageAccountName `
    --account-key $StorageKey `
    --public-access blob

if ($LASTEXITCODE -ne 0) {
    throw "Failed to create blob container"
}
Write-Host "Blob container created: $ContainerName" -ForegroundColor Green

# Get connection string
$ConnectionString = az storage account show-connection-string `
    --name $StorageAccountName `
    --resource-group $ResourceGroup `
    --query connectionString -o tsv

# Display summary
Write-Host ""
Write-Host "=== Storage Account Created Successfully ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Storage Account: $StorageAccountName"
Write-Host "Location: $Location"
Write-Host "Container: $ContainerName"
Write-Host "Public Access: Enabled (blob-level)"
Write-Host ""
Write-Host "Blob Endpoint:" -ForegroundColor Yellow
Write-Host "  https://$StorageAccountName.blob.core.windows.net/$ContainerName"
Write-Host ""
Write-Host "Connection String:" -ForegroundColor Yellow
Write-Host "  $ConnectionString"
Write-Host ""
Write-Host "To upload a file:" -ForegroundColor Cyan
Write-Host "  az storage blob upload --account-name $StorageAccountName --container-name $ContainerName --file <local-file> --name <blob-name>"
Write-Host ""
Write-Host "To delete resources:" -ForegroundColor Cyan
Write-Host "  az group delete --name $ResourceGroup --yes"
Write-Host ""
