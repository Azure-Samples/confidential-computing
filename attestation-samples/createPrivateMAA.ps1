<#
.SYNOPSIS
    Creates a private Microsoft Azure Attestation (MAA) provider with command line parameters

.DESCRIPTION
    This script creates a new Azure Attestation provider in a specified location and resource group.
    If the resource group doesn't exist, it will be created.

.PARAMETER Location
    The Azure region where the attestation provider should be created (e.g., "westeurope", "eastus")

.PARAMETER AttestationResourceGroup
    The name of the resource group to contain the attestation provider

.PARAMETER AttestationProviderName
    The name for the new attestation provider (must be globally unique)

.PARAMETER SubscriptionId
    The Azure subscription ID to use

.EXAMPLE
    .\createPrivateMAA.ps1 -Location "westeurope" -AttestationResourceGroup "myAttestationRG" -AttestationProviderName "myAttestationProvider" -SubscriptionId "12345678-1234-1234-1234-123456789abc"
#>

param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure region (e.g., westeurope, eastus)")]
    [string]$Location,

    [Parameter(Mandatory = $true, HelpMessage = "Resource group name for the attestation provider")]
    [string]$AttestationResourceGroup,

    [Parameter(Mandatory = $true, HelpMessage = "Name for the attestation provider (globally unique)")]
    [string]$AttestationProviderName,

    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID")]
    [string]$SubscriptionId
)

# Set the subscription context
Write-Host "Setting Azure subscription context to: $SubscriptionId"
try {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    Write-Host "Successfully set subscription context" -ForegroundColor Green
} catch {
    Write-Error "Failed to set subscription context: $_"
    exit 1
}

# Check if resource group exists, create if it doesn't
Write-Host "Checking if resource group '$AttestationResourceGroup' exists in location '$Location'..."
$existingRG = Get-AzResourceGroup -Name $AttestationResourceGroup -ErrorAction SilentlyContinue

if (-not $existingRG) {
    Write-Host "Resource group '$AttestationResourceGroup' does not exist. Creating..." -ForegroundColor Yellow
    try {
        $newRG = New-AzResourceGroup -Name $AttestationResourceGroup -Location $Location -ErrorAction Stop
        Write-Host "Successfully created resource group '$AttestationResourceGroup'" -ForegroundColor Green
    } catch {
        Write-Error "Failed to create resource group: $_"
        exit 1
    }
} else {
    Write-Host "Resource group '$AttestationResourceGroup' already exists" -ForegroundColor Green
}

# Check if attestation provider already exists
Write-Host "Checking if attestation provider '$AttestationProviderName' already exists..."
$existingProvider = Get-AzAttestation -Name $AttestationProviderName -ResourceGroupName $AttestationResourceGroup -ErrorAction SilentlyContinue

if ($existingProvider) {
    Write-Warning "Attestation provider '$AttestationProviderName' already exists in resource group '$AttestationResourceGroup'"
    Write-Host "Existing provider details:"
    $existingProvider | Format-List Name, Location, AttestUri, Status
    exit 0
}

# Create the attestation provider
Write-Host "Creating attestation provider '$AttestationProviderName' in resource group '$AttestationResourceGroup'..." -ForegroundColor Yellow
try {
    $attestationProvider = New-AzAttestation -Name $AttestationProviderName -ResourceGroupName $AttestationResourceGroup -Location $Location -ErrorAction Stop
    Write-Host "Successfully created attestation provider!" -ForegroundColor Green
    
    Write-Host "`nAttestation Provider Details:" -ForegroundColor Cyan
    $attestationProvider | Format-List Name, Location, AttestUri, Status, ResourceGroupName
    
    Write-Host "`nAttestation URI: $($attestationProvider.AttestUri)" -ForegroundColor Yellow
    
} catch {
    Write-Error "Failed to create attestation provider: $_"
    exit 1
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green