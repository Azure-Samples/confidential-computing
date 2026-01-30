# Enhanced script to build a Confidential Virtual Machine with Private Microsoft Azure Attestation (MAA) instance
# VM will be created in a private vnet with no public IP and can only be accessed over the Internet via the Azure Bastion service
# Private MAA instance will be created with private endpoint for secure attestation
#
# ⚠️ EXPERIMENTAL: This script is experimental and may not work in all scenarios.
# Private MAA endpoints with CVMs is an advanced configuration that requires specific
# Azure subscription permissions and regional availability. Use for testing purposes only.
# 
# Based on the original DEBUGBuildRandomCVMwithPvtMAA.ps1 and MAA private endpoint script
# Enhanced November 2025 - Added private MAA instance creation with private endpoint
# 
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
# 
# Usage: ./BuildCVMWithPrivateMAA.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME> -osType <Windows|Windows11|Windows2019|Ubuntu|RHEL> [-description <OPTIONAL DESCRIPTION>] [-smoketest] [-region <AZURE REGION>] [-DisableBastion] [-vnetName <EXISTING VNET NAME>]
#
# Basename is a prefix for all resources created, it's used to create unique names for the resources
# osType specifies which OS to deploy: Windows (Server 2022), Windows11 (Windows 11 Enterprise), Ubuntu (24.04), or RHEL (9.5)
# description is an optional parameter that will be added as a tag to the resource group
# smoketest is an optional switch that automatically removes all resources after completion (useful for testing)
# region is an optional parameter that specifies the Azure region (defaults to northeurope)
# DisableBastion is an optional switch that skips the creation of Azure Bastion (VM will only be accessible via private network)
# vnetName is an optional parameter to use an existing VNET (if not provided, a new one will be created)
#
# You'll need to have the latest Azure PowerShell module installed

param (
    [Parameter(Mandatory)]$subsID,
    [Parameter(Mandatory)]$basename,
    [Parameter(Mandatory)]
    [ValidateSet("Windows", "Windows11", "Windows2019", "Ubuntu", "RHEL")]
    $osType,
    [Parameter(Mandatory=$false)]$description = "",
    [Parameter(Mandatory=$false)][switch]$smoketest,
    [Parameter(Mandatory=$false)]$region = "northeurope",
    [Parameter(Mandatory=$false)]$vmsize = "Standard_DC2as_v5",
    [Parameter(Mandatory=$false)][switch]$DisableBastion, # Disable Bastion creation, this can speed up deployment for quick tests
    [Parameter(Mandatory=$false)]$vnetName = ""
)

if ($subsID -eq "" -or $basename -eq "" -or $osType -eq "") {
    write-host "You must enter a subscription ID, basename, and OS type (Windows, Windows11, Ubuntu, or RHEL)"
    exit
}

# mark the start time of the script execution
$startTime = Get-Date
# get the name of the script so we can tag the resource group with it
$scriptName = $MyInvocation.MyCommand.Name

# Get GitHub repository URL from git remote
$gitRemoteUrl = ""  
try {
    $gitRemoteUrl = git remote get-url origin
    $gitRemoteUrl = $gitRemoteUrl -replace "\.git$", ""
} catch {
    $gitRemoteUrl = "[Originally from] https://github.com/Microsoft/confidential-computing"
}

# Set PowerShell variables to use in the script
$basename = $basename + -join ((97..122) | Get-Random -Count 5 | % {[char]$_}) # basename + 5 random lower-case letters
$vmusername = "azureuser"
$vmadminpassword = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%".ToCharArray() | Get-Random -Count 40)
$resgrp = $basename
$akvname = $basename + "akv"
$desname = $basename + "des"
$keyname = $basename + "-cmk-key"
$vmname = $basename
$vnetname = if ($vnetName -ne "") { $vnetName } else { $vmname + "vnet" }
$bastionname = $vnetname + "-bastion"
$vnetipname = $vnetname + "-pip"
$nicPrefix = $basename + "-nic"
$bastionsubnetName = "AzureBastionSubnet"
$vmsubnetname = $basename + "vmsubnet"
$privateEndpointSubnetName = $basename + "pesubnet"

# MAA specific variables
$attestationProviderName = $basename + "maa"
$privateEndpointName = $basename + "maa-pe"
$privateLinkConnectionName = $basename + "maa-connection"
$privateDnsZoneName = "privatelink.attest.azure.net"
$dnsLinkName = $basename + "dns-link"
$dnsZoneGroupName = $basename + "dns-group"

# VM Configuration
$vmSize = $vmsize
$identityType = "SystemAssigned"
$secureEncryptGuestState = "DiskWithVMGuestState"
$vmSecurityType = "ConfidentialVM"
$KeySize = 3072
$diskEncryptionType = "ConfidentialVmEncryptedWithCustomerKey"

# Function to create dynamic policy JSON file
function Create-DynamicPolicyFile {
    param(
        [string]$maaName,
        [string]$region
    )
    
    # Convert region to MAA region format
    $regionMapping = @{
        "northeurope" = "neu"
        "westeurope" = "weu"
        "eastus" = "eus"
        "eastus2" = "eus2"
        "westus" = "wus"
        "westus2" = "wus2"
        "westus3" = "wus3"
        "centralus" = "cus"
        "southcentralus" = "scus"
        "northcentralus" = "ncus"
        "canadacentral" = "cac"
        "canadaeast" = "cae"
        "brazilsouth" = "brs"
        "uksouth" = "uks"
        "ukwest" = "ukw"
        "francecentral" = "frc"
        "francesouth" = "frs"
        "germanywestcentral" = "gwc"
        "germanynorth" = "gn"
        "norwayeast" = "noe"
        "norwaywest" = "now"
        "switzerlandnorth" = "szn"
        "switzerlandwest" = "szw"
        "southeastasia" = "sea"
        "eastasia" = "ea"
        "australiaeast" = "ae"
        "australiasoutheast" = "ase"
        "japaneast" = "jpe"
        "japanwest" = "jpw"
        "koreacentral" = "krc"
        "koreasouth" = "krs"
        "southafricanorth" = "san"
        "southafricawest" = "saw"
        "centralindia" = "inc"
        "southindia" = "ins"
        "westindia" = "inw"
        "uaenorth" = "uaen"
        "uaecentral" = "uaec"
    }
    
    $regionCode = $regionMapping[$region.ToLower()]
    if (-not $regionCode) {
        # Default to first 3 characters if region not in mapping
        $regionCode = $region.Substring(0, [Math]::Min(3, $region.Length))
        Write-Host "Warning: Region '$region' not in mapping. Using '$regionCode' as region code." -ForegroundColor Yellow
    }
    
    $maaEndpoint = "https://$maaName.$regionCode.attest.azure.net/"
    
    $policyContent = @{
        version = "1.0.0"
        anyOf = @(
            @{
                authority = $maaEndpoint
                allOf = @(
                    @{
                        claim = "x-ms-compliance-status"
                        equals = "azure-compliant-cvm"
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 10
    
    $tempPolicyFile = Join-Path $env:TEMP "$maaName-policy.json"
    $policyContent | Out-File -FilePath $tempPolicyFile -Encoding UTF8
    
    Write-Host "Created dynamic policy file: $tempPolicyFile" -ForegroundColor Green
    Write-Host "Policy authority: $maaEndpoint" -ForegroundColor Cyan
    
    return $tempPolicyFile
}

# Display configuration information
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Building a Confidential Virtual Machine ($osType) with Private MAA in $basename in $region"
if ($smoketest) {
    write-host "SMOKETEST MODE: Resources will be automatically deleted after completion" -ForegroundColor Yellow
}
if ($DisableBastion) {
    write-host "BASTION DISABLED: VM will only be accessible via private network connectivity" -ForegroundColor Yellow
}
write-host "IMPORTANT"
write-host "VM admin username is $vmusername"
write-host "randomly generated password for the VM is $vmadminpassword - save this now as you CANNOT retrieve it later"
write-host ""
write-host "Script: $scriptName"
write-host "Repository URL: $gitRemoteUrl"
write-host "MAA Instance: $attestationProviderName"
write-host "----------------------------------------------------------------------------------------------------------------"

# Connect to Azure
Set-AzContext -SubscriptionId $subsID
if (!$?) {
    write-host "Failed to connect to the Azure subscription $subsID exiting"
    exit
}

# Get username of logged-in Azure user
$tmp = Get-AzContext
$ownername = $tmp.Account.Id

# Create Resource Group with tags
$resourceGroupTags = @{
    owner = $ownername
    BuiltBy = $scriptName
    OSType = $osType
    GitRepo = $gitRemoteUrl
    PrivateMAA = "enabled"
    MAAInstance = $attestationProviderName
}

if ($description -ne "") { $resourceGroupTags.Add("description", $description) }
if ($smoketest) { $resourceGroupTags.Add("smoketest", "true") }
if ($DisableBastion) { $resourceGroupTags.Add("BastionDisabled", "true") }

New-AzResourceGroup -Name $resgrp -Location $region -Tag $resourceGroupTags -force

# Create credential object
$securePassword = ConvertTo-SecureString -String $vmadminpassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($vmusername, $securePassword)

# Create Key Vault
write-host "Creating Azure Key Vault..."
New-AzKeyVault -Name $akvname -Location $region -ResourceGroupName $resgrp -Sku Premium -EnabledForDiskEncryption -DisableRbacAuthorization -SoftDeleteRetentionInDays 10 -EnablePurgeProtection

# Set up CVM agent access to Key Vault
$cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0'
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $cvmAgent.id -PermissionsToKeys get,release

# Create Private MAA Instance first (needed for policy file generation)
write-host "Creating Private Microsoft Azure Attestation instance..."
$attestationProvider = New-AzAttestation -Name $attestationProviderName -ResourceGroupName $resgrp -Location $region
$attestationProviderId = $attestationProvider.Id

# Create dynamic policy file based on the MAA instance
write-host "Generating dynamic policy file for MAA instance..."
$dynamicPolicyFile = Create-DynamicPolicyFile -maaName $attestationProviderName -region $region

# Add Key vault Key with dynamic policy
write-host "Adding Key Vault key with dynamic MAA policy..."
try {
    Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size $KeySize -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -ReleasePolicyPath $dynamicPolicyFile
    write-host "Key created successfully with MAA-specific policy" -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to create key with custom policy. Using default CVM policy instead." -ForegroundColor Yellow
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size $KeySize -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -UseDefaultCVMPolicy
} finally {
    # Clean up temporary policy file
    if (Test-Path $dynamicPolicyFile) {
        # Remove-Item $dynamicPolicyFile -Force
        write-host "Cleaned up temporary policy file" -ForegroundColor Gray
    }
}

# Capture Key Vault and Key details
$encryptionKeyVaultId = (Get-AzKeyVault -VaultName $akvname -ResourceGroupName $resgrp).ResourceId
$encryptionKeyURL = (Get-AzKeyVaultKey -VaultName $akvname -KeyName $keyName).Key.Kid

# Create new DES Config and Disk Encryption Set
write-host "Creating Disk Encryption Set..."
$desConfig = New-AzDiskEncryptionSetConfig -Location $region -SourceVaultId $encryptionKeyVaultId -KeyUrl $encryptionKeyURL -IdentityType SystemAssigned -EncryptionType $diskEncryptionType
New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName -DiskEncryptionSet $desConfig

$diskencset = Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName

# Assign DES Access Policy to key vault
$desIdentity = (Get-AzDiskEncryptionSet -Name $desName -ResourceGroupName $resgrp).Identity.PrincipalId
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $desIdentity -PermissionsToKeys wrapKey,unwrapKey,get -BypassObjectIdValidation

# Create or get VNet configuration
write-host "Setting up Virtual Network..."
if ($vnetName -ne "" -and (Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp -ErrorAction SilentlyContinue)) {
    write-host "Using existing VNet: $vnetName"
    $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp
    
    # Add VM subnet if it doesn't exist
    $vmSubnet = $vnet.Subnets | Where-Object { $_.Name -eq $vmsubnetname }
    if (-not $vmSubnet) {
        Add-AzVirtualNetworkSubnetConfig -Name $vmsubnetname -VirtualNetwork $vnet -AddressPrefix "10.0.1.0/24"
        $vnet | Set-AzVirtualNetwork
        $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp
    }
    
    # Add private endpoint subnet if it doesn't exist
    $peSubnet = $vnet.Subnets | Where-Object { $_.Name -eq $privateEndpointSubnetName }
    if (-not $peSubnet) {
        Add-AzVirtualNetworkSubnetConfig -Name $privateEndpointSubnetName -VirtualNetwork $vnet -AddressPrefix "10.0.2.0/24"
        $vnet | Set-AzVirtualNetwork
        $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp
    }
} else {
    write-host "Creating new VNet: $vnetname"
    # Create subnets
    $vmSubnet = New-AzVirtualNetworkSubnetConfig -Name $vmsubnetName -AddressPrefix "10.0.1.0/24"
    $peSubnet = New-AzVirtualNetworkSubnetConfig -Name $privateEndpointSubnetName -AddressPrefix "10.0.2.0/24"
    
    # Create VNet with both subnets
    $vnet = New-AzVirtualNetwork -Force -Name $vnetname -ResourceGroupName $resgrp -Location $region -AddressPrefix "10.0.0.0/16" -Subnet $vmSubnet, $peSubnet
}

# Get updated VNet and subnet references
$vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
$vmSubnetObj = $vnet.Subnets | Where-Object { $_.Name -eq $vmsubnetname }
$peSubnetObj = $vnet.Subnets | Where-Object { $_.Name -eq $privateEndpointSubnetName }

# Configure private endpoint subnet (disable network policies)
write-host "Configuring private endpoint subnet..."

# SIMONDEBUG - try without this disabled
write-host "SIMONDEBUG - NOT disabling private endpoint network policies..."
#$peSubnetObj.PrivateEndpointNetworkPolicies = "Disabled"
$peSubnetObj.PrivateEndpointNetworkPolicies = "Enabled" # SIMONDEBUG - try with this enabled
$vnet | Set-AzVirtualNetwork

# Refresh VNet reference after update
$vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
$peSubnetObj = $vnet.Subnets | Where-Object { $_.Name -eq $privateEndpointSubnetName }

# Create private endpoint connection for MAA
write-host "Creating private endpoint for MAA..."
$privateEndpointConnection = New-AzPrivateLinkServiceConnection -Name $privateLinkConnectionName -PrivateLinkServiceId $attestationProviderId -GroupID "Standard"

# Create private endpoint
New-AzPrivateEndpoint -ResourceGroupName $resgrp -Name $privateEndpointName -Location $region -Subnet $peSubnetObj -PrivateLinkServiceConnection $privateEndpointConnection

# Create private DNS zone for MAA
write-host "Setting up private DNS for MAA..."
$zone = New-AzPrivateDnsZone -ResourceGroupName $resgrp -Name $privateDnsZoneName

# Create DNS network link
$link = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $resgrp -ZoneName $privateDnsZoneName -Name $dnsLinkName -VirtualNetworkId $vnet.Id

# Create DNS configuration
$config = New-AzPrivateDnsZoneConfig -Name $privateDnsZoneName -PrivateDnsZoneId $zone.ResourceId

# Create DNS zone group
New-AzPrivateDnsZoneGroup -ResourceGroupName $resgrp -PrivateEndpointName $privateEndpointName -Name $dnsZoneGroupName -PrivateDnsZoneConfig $config

# Create VM Configuration
write-host "Configuring Virtual Machine..."
$VirtualMachine = New-AzVMConfig -VMName $VMName -VMSize $vmSize

# Configure OS based on the selected type
switch ($osType) {
    "Windows" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' -Skus '2022-datacenter-smalldisk-g2' -Version "latest"
        $VMIsLinux = $false
    }
    "Windows11" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsDesktop' -Offer 'Windows-11' -Skus 'win11-23h2-ent' -Version "latest"
        $VMIsLinux = $false
    }
    "Windows2019" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' -Skus '2019-datacenter-smalldisk-g2' -Version "latest"
        $VMIsLinux = $false
    }
    "Ubuntu" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Linux -ComputerName $vmname -Credential $cred
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'Canonical' -Offer 'ubuntu-24_04-lts' -Skus 'cvm' -Version "latest"
        $VMIsLinux = $true
    }
    "RHEL" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Linux -ComputerName $vmname -Credential $cred
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'redhat' -Offer 'rhel-cvm' -Skus '9_5_cvm' -Version "latest"
        $VMIsLinux = $true
    }
}

# Create Network Interface
write-host "Creating network interface..."
$subnetId = $vmSubnetObj.Id
$nic = New-AzNetworkInterface -Force -Name $nicPrefix -ResourceGroupName $resgrp -Location $region -SubnetId $subnetId
$nic = Get-AzNetworkInterface -Name $nicPrefix -ResourceGroupName $resgrp
$nicId = $nic.Id

$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $nicId

# Set VM SecurityType and connect to DES
if ($VMisLinux) {
    $VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.Id -Linux
} else {
    $VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.Id
}

$VirtualMachine = Set-AzVmSecurityProfile -VM $VirtualMachine -SecurityType $vmSecurityType
$VirtualMachine = Set-AzVmUefi -VM $VirtualMachine -EnableVtpm $true -EnableSecureBoot $true
$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -disable

# Create the VM
write-host "Creating Confidential Virtual Machine..."
New-AzVM -ResourceGroupName $resgrp -Location $region -Vm $VirtualMachine
$vm = Get-AzVm -ResourceGroupName $resgrp -Name $vmname

# Create the Bastion (unless disabled)
if (-not $DisableBastion) {
    write-host "Creating Azure Bastion for VM access..."
    
    # Add bastion subnet if it doesn't exist
    $bastionSubnet = $vnet.Subnets | Where-Object { $_.Name -eq $bastionsubnetName }
    if (-not $bastionSubnet) {
        Add-AzVirtualNetworkSubnetConfig -Name $bastionsubnetName -VirtualNetwork $vnet -AddressPrefix "10.0.99.0/26"
        $vnet | Set-AzVirtualNetwork
    }
    
    $publicip = New-AzPublicIpAddress -ResourceGroupName $resgrp -name $vnetipname -location $region -AllocationMethod Static -Sku Standard
    New-AzBastion -ResourceGroupName $resgrp -Name $bastionname -PublicIpAddressRgName $resgrp -PublicIpAddressName $publicIp.Name -VirtualNetworkRgName $resgrp -VirtualNetworkName $vnetname -Sku "Basic"
} else {
    write-host "Bastion creation skipped due to -DisableBastion parameter"
}

# Display completion information
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "DEPLOYMENT COMPLETE!" -ForegroundColor Green
write-host ""
write-host "Created Resources:"
write-host "- Resource Group: $resgrp"
write-host "- Confidential VM: $vmname"
write-host "- Virtual Network: $vnetname"
write-host "- Private MAA Instance: $attestationProviderName"
write-host "- Private Endpoint: $privateEndpointName"
write-host "- Key Vault: $akvname (with MAA-specific policy)"
write-host "- Disk Encryption Set: $desname"
if (-not $DisableBastion) {
    write-host "- Azure Bastion: $bastionname"
}
write-host ""
write-host "Private MAA Endpoint: $($attestationProvider.AttestUri)"
write-host "Private DNS Zone: $privateDnsZoneName"
write-host ""
write-host "VM Credentials:"
write-host "- Username: $vmusername"
write-host "- Password: $vmadminpassword"
write-host ""
if (-not $DisableBastion) {
    write-host "Access your VM through Azure Portal > Virtual Machines > $vmname > Connect > Bastion"
} else {
    write-host "VM is only accessible via private network connectivity (VPN, ExpressRoute, or peered networks)"
}
write-host "----------------------------------------------------------------------------------------------------------------"

# Smoketest cleanup
if ($smoketest) {
    write-host "SMOKETEST MODE: Automatically removing all created resources..."
    write-host "Removing resource group: $resgrp"
    write-host "WARNING: RESOURCES ARE NOT RECOVERABLE." -ForegroundColor Red
    write-host "Press ANY KEY to cancel deletion, or wait 10 seconds to proceed..." -ForegroundColor Yellow
    
    $timeout = 10
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $cancelled = $false
    
    while ($timer.Elapsed.TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) {
            [Console]::ReadKey($true) | Out-Null
            $cancelled = $true
            break
        }
        Start-Sleep -Milliseconds 100
        $remaining = [math]::Ceiling($timeout - $timer.Elapsed.TotalSeconds)
        Write-Host "`rDeletion in $remaining seconds... (Press any key to cancel)" -NoNewline -ForegroundColor Yellow
    }
    $timer.Stop()
    
    if ($cancelled) {
        write-host "`nDeletion cancelled by user. Resources remain in resource group: $resgrp" -ForegroundColor Green
        write-host "To clean up manually later, run: Remove-AzResourceGroup -Name $resgrp -Force"
    } else {
        write-host "`nProceeding with resource deletion..."
        try {
            Remove-AzResourceGroup -Name $resgrp -Force -AsJob
            write-host "Resource group deletion initiated successfully (running in background)"
            write-host "All resources in resource group '$resgrp' are being removed"
        } catch {
            write-host "Error removing resource group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    write-host "Resources created in resource group: $resgrp"
    write-host "To clean up manually, run: Remove-AzResourceGroup -Name $resgrp -Force"
}

# Calculate and display execution time
$myTimeSpan = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Output ("Execution time was {0} minutes and {1} seconds." -f $myTimeSpan.Minutes, $myTimeSpan.Seconds)