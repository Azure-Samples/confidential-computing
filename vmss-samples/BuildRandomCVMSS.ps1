# Hands-off script to build a Confidential Virtual Machine Scale Set (VMSS) running a small web app,
# fronted by an Application Gateway, with CPU-based autoscale so you can watch the scale set grow and shrink.
#
# The scale set instances have NO public IP. Inbound app traffic arrives only via the Application Gateway,
# and outbound internet (if enabled) leaves via a NAT Gateway. Optional Azure Bastion gives you SSH access.
#
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
# based on https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview
#
# Clone this repo to a folder (relies on cloud-init-webapp.yaml being in the same folder as this script)
#
# Usage: ./BuildRandomCVMSS.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME> [-region <AZURE REGION>]
#        [-vmsize <CVM SKU>] [-instanceCount 2] [-minInstances 2] [-maxInstances 5] [-description <TEXT>]
#        [-EnableBastion] [-NoInternetAccess] [-SkipSkuPreflight] [-smoketest]
#
# basename       prefix for all resources; 5 random lower-case letters are appended to keep names unique
# instanceCount  starting number of instances (also the autoscale default capacity)
# minInstances   autoscale floor
# maxInstances   autoscale ceiling (kept small on purpose - this is a demo, not a capacity test)
# EnableBastion  also deploy Azure Bastion so you can SSH into individual instances (adds cost)
# NoInternetAccess  do not attach a NAT Gateway; the scale set subnet gets no outbound internet
# smoketest      delete the whole resource group once the build finishes (useful for CI/testing)
#
# You'll need the latest Azure PowerShell module installed (update-module -force)

param (
    [Parameter(Mandatory)]$subsID,
    [Parameter(Mandatory)]$basename,
    [Parameter(Mandatory=$false)]$region = "northeurope",
    [Parameter(Mandatory=$false)]$vmsize = "Standard_DC2as_v5",
    [Parameter(Mandatory=$false)][int]$instanceCount = 2,
    [Parameter(Mandatory=$false)][int]$minInstances = 2,
    [Parameter(Mandatory=$false)][int]$maxInstances = 5,
    [Parameter(Mandatory=$false)]$description = "",
    [Parameter(Mandatory=$false)][switch]$EnableBastion,
    [Parameter(Mandatory=$false)][switch]$NoInternetAccess,
    [Parameter(Mandatory=$false)][switch]$SkipSkuPreflight,
    [Parameter(Mandatory=$false)][switch]$smoketest
)

if ($subsID -eq "" -or $basename -eq "") {
    write-host "You must enter a subscription ID and a basename"
    exit
}

if ($minInstances -lt 1 -or $maxInstances -lt $minInstances -or $instanceCount -lt $minInstances -or $instanceCount -gt $maxInstances) {
    write-host "Invalid scale settings: require 1 <= minInstances <= instanceCount <= maxInstances" -ForegroundColor Red
    exit 1
}

#---------Prerequisite Checks: PowerShell version and required Az modules-----------------------------------------------
function Test-PrerequisitesInstalled {
    $missingPrereqs = @()

    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 7) {
        $missingPrereqs += "PowerShell 7.0+ (currently running: $($psVersion.Major).$($psVersion.Minor).$($psVersion.Patch))"
    }

    $requiredModules = @("Az.Accounts", "Az.Compute", "Az.Network", "Az.Resources")
    foreach ($moduleName in $requiredModules) {
        if (-not (Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue)) {
            $missingPrereqs += "$moduleName (required)"
        }
    }

    write-host ""
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "Prerequisite Check" -ForegroundColor Cyan
    write-host "----------------------------------------------------------------------------------------------------------------"

    if ($psVersion.Major -ge 7) {
        write-host "✓ PowerShell $($psVersion.Major).$($psVersion.Minor).$($psVersion.Patch)" -ForegroundColor Green
    }
    foreach ($moduleName in $requiredModules) {
        $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue
        if ($module) {
            $version = $module.Version | Sort-Object -Descending | Select-Object -First 1
            write-host "✓ $moduleName (v$version)" -ForegroundColor Green
        }
    }

    if ($missingPrereqs.Count -gt 0) {
        write-host ""
        write-host "MISSING PREREQUISITES:" -ForegroundColor Red
        foreach ($prereq in $missingPrereqs) { write-host "✗ $prereq" -ForegroundColor Red }
        write-host ""
        write-host "  PowerShell 7+: https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Gray
        write-host "  Azure PowerShell: Update-Module -Name Az -Force" -ForegroundColor Gray
        write-host "----------------------------------------------------------------------------------------------------------------"
        exit 1
    }

    write-host "✓ All required prerequisites are installed" -ForegroundColor Green
    write-host "----------------------------------------------------------------------------------------------------------------"
}

Test-PrerequisitesInstalled

$startTime = Get-Date
$scriptName = $MyInvocation.MyCommand.Name

# Tag the resource group with the repo it came from, for traceability
$gitRemoteUrl = git remote get-url origin 2>$null
$gitRemoteUrl = $gitRemoteUrl -replace "\.git$", ""
if (-not $gitRemoteUrl) {
    $gitRemoteUrl = "[Originally from] https://github.com/Azure-Samples/confidential-computing"
}

# The cloud-init file that installs the demo web app on every instance
$cloudInitPath = Join-Path $PSScriptRoot "cloud-init-webapp.yaml"
if (-not (Test-Path $cloudInitPath)) {
    write-host "ERROR: cannot find cloud-init-webapp.yaml next to this script ($cloudInitPath)" -ForegroundColor Red
    exit 1
}

# Names for everything we create
$basename        = $basename + -join ((97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
$resgrp          = $basename
$vmssname        = $basename + "vmss"
$vnetname        = $basename + "vnet"
$vmsssubnetname  = "vmss-subnet"
$appgwsubnetname = "appgw-subnet"
$vmssnsgname     = $basename + "-vmss-nsg"
$appgwnsgname    = $basename + "-appgw-nsg"
$natGatewayName  = $vnetname + "-nat"
$natPublicIpName = $vnetname + "-nat-pip"
$appgwname       = $basename + "-appgw"
$appgwPipName    = $appgwname + "-pip"
$bastionname     = $vnetname + "-bastion"
$bastionPipName  = $bastionname + "-pip"
$autoscaleName   = $vmssname + "-autoscale"

$vmusername      = "azureuser"
$vmadminpassword = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%".ToCharArray() | Get-Random -Count 40)
$appPort         = 8080

write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Building a Confidential VM Scale Set in resource group '$resgrp' in '$region'"
write-host "SKU: $vmsize   start: $instanceCount instances   autoscale range: $minInstances-$maxInstances"
if ($smoketest)        { write-host "SMOKETEST MODE: resources will be deleted automatically at the end" -ForegroundColor Yellow }
if ($EnableBastion)    { write-host "BASTION ENABLED: Azure Bastion will be deployed for SSH access" -ForegroundColor Cyan }
if ($NoInternetAccess) { write-host "INTERNET DISABLED: scale set subnet gets no outbound internet" -ForegroundColor Yellow }
else                   { write-host "INTERNET ENABLED: scale set subnet uses a NAT Gateway for outbound" -ForegroundColor Cyan }
write-host "IMPORTANT"
write-host "VM admin username is $vmusername"
write-host "randomly generated password is $vmadminpassword - save this now as you CANNOT retrieve it later"
write-host "Script: $scriptName"
write-host "Repository URL: $gitRemoteUrl"
write-host "----------------------------------------------------------------------------------------------------------------"

Set-AzContext -SubscriptionId $subsID | Out-Null
if (!$?) {
    write-host "Failed to connect to the Azure subscription $subsID - exiting"
    exit
}

$ownername = (Get-AzContext).Account.Id

#---------Pre-flight: SKU availability and quota check---------------------------------------------------------------
# Confirm the SKU is a Confidential VM SKU (AMD SEV-SNP or Intel TDX - not Intel SGX, which is a different
# isolation model), is offered and unrestricted in this region, and that there is enough vCPU quota to reach
# maxInstances. Get-AzComputeResourceSku / Get-AzVMUsage occasionally misreport; use -SkipSkuPreflight to bypass.
if ($SkipSkuPreflight) {
    write-host "Pre-flight check SKIPPED (-SkipSkuPreflight). ARM will validate '$vmsize' in '$region' at deploy time." -ForegroundColor Yellow
}
else {
    write-host "Pre-flight check: confirming '$vmsize' is available in '$region' with quota for $maxInstances instances..." -ForegroundColor Cyan

    if ($vmsize -match '^Standard_DC\d+s_v[23]$') {
        write-host "ERROR: '$vmsize' is an Intel SGX SKU (application-enclave isolation), which is NOT supported by this script." -ForegroundColor Red
        write-host "Use a Confidential VM SKU instead: AMD SEV-SNP (DCa*/ECa*, e.g. Standard_DC2as_v5) or Intel TDX (DCe*/ECe*, e.g. Standard_DC2es_v5)." -ForegroundColor Yellow
        exit 1
    }

    $skuInfo = $null
    try {
        $skuInfo = Get-AzComputeResourceSku -Location $region -ErrorAction Stop |
            Where-Object { $_.ResourceType -eq 'virtualMachines' -and $_.Name -eq $vmsize } |
            Select-Object -First 1
    } catch {
        write-host "Warning: could not query Get-AzComputeResourceSku for '$region': $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($null -eq $skuInfo) {
        write-host "ERROR: VM SKU '$vmsize' is not offered in region '$region'." -ForegroundColor Red
        write-host "List the Confidential VM SKUs offered there with:" -ForegroundColor Yellow
        write-host "  Get-AzComputeResourceSku -Location '$region' | Where-Object { `$_.ResourceType -eq 'virtualMachines' -and `$_.Name -match '_(DC|EC)\d+(a|e)' } | Select-Object Name" -ForegroundColor Gray
        exit 1
    }

    $subRestriction = $skuInfo.Restrictions | Where-Object {
        $_.ReasonCode -eq 'NotAvailableForSubscription' -or
        ($_.RestrictionInfo -and $_.RestrictionInfo.Locations -contains $region) -or
        ($_.Values -contains $region)
    }
    if ($subRestriction) {
        $reason = ($skuInfo.Restrictions | ForEach-Object { $_.ReasonCode }) -join ', '
        write-host "ERROR: VM SKU '$vmsize' is restricted for this subscription in '$region' (reason: $reason)." -ForegroundColor Red
        write-host "Request a quota increase: https://learn.microsoft.com/azure/quotas/quickstart-increase-quota-portal" -ForegroundColor Yellow
        exit 1
    }

    $skuVCpus = ($skuInfo.Capabilities | Where-Object { $_.Name -eq 'vCPUs' } | Select-Object -First 1).Value -as [int]
    if (-not $skuVCpus) { $skuVCpus = 2 }
    $neededVCpus = $skuVCpus * $maxInstances
    $skuFamily = $skuInfo.Family

    try {
        $usage = Get-AzVMUsage -Location $region -ErrorAction Stop | Where-Object { $_.Name.Value -eq $skuFamily } | Select-Object -First 1
        if ($usage) {
            $available = [int]$usage.Limit - [int]$usage.CurrentValue
            write-host ("Quota for {0} in {1}: {2}/{3} used, {4} vCPUs available, scaling to {5} instances needs {6}." -f `
                $skuFamily, $region, $usage.CurrentValue, $usage.Limit, $available, $maxInstances, $neededVCpus) -ForegroundColor Cyan
            if ($available -lt $neededVCpus) {
                write-host "ERROR: insufficient vCPU quota in family '$skuFamily' in '$region' to scale to $maxInstances instances." -ForegroundColor Red
                write-host "Lower -maxInstances, pick another region, or request a quota increase." -ForegroundColor Yellow
                exit 1
            }
        }
    } catch {
        write-host "Warning: Get-AzVMUsage failed for '$region': $($_.Exception.Message). Proceeding without quota check." -ForegroundColor Yellow
    }

    write-host "Pre-flight check passed." -ForegroundColor Green
}

#---------Resource group-----------------------------------------------------------------------------------------------
$resourceGroupTags = @{
    owner   = $ownername
    BuiltBy = $scriptName
    OSType  = "Ubuntu2404CVM"
    GitRepo = $gitRemoteUrl
}
if ($description -ne "")  { $resourceGroupTags.Add("description", $description) }
if ($smoketest)           { $resourceGroupTags.Add("smoketest", "true") }
if ($NoInternetAccess)    { $resourceGroupTags.Add("NoInternetAccess", "true") }

New-AzResourceGroup -Name $resgrp -Location $region -Tag $resourceGroupTags -Force | Out-Null
write-host "Resource group '$resgrp' created." -ForegroundColor Green

#---------Network security groups--------------------------------------------------------------------------------------
# Scale set instances only accept the app port, and only from the Application Gateway subnet.
$vmssNsgRules = @(
    New-AzNetworkSecurityRuleConfig -Name "allow-appgw-to-app" -Description "App traffic from the Application Gateway subnet only" `
        -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 `
        -SourceAddressPrefix "10.0.1.0/24" -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $appPort
)
$vmssNsg = New-AzNetworkSecurityGroup -ResourceGroupName $resgrp -Location $region -Name $vmssnsgname -SecurityRules $vmssNsgRules -Force

# Application Gateway v2 requires inbound 65200-65535 from the GatewayManager service tag for control plane health.
$appgwNsgRules = @(
    New-AzNetworkSecurityRuleConfig -Name "allow-gatewaymanager" -Description "Required by Application Gateway v2 control plane" `
        -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 `
        -SourceAddressPrefix GatewayManager -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 65200-65535
    New-AzNetworkSecurityRuleConfig -Name "allow-http-inbound" -Description "Public HTTP to the gateway frontend" `
        -Access Allow -Protocol Tcp -Direction Inbound -Priority 110 `
        -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80
)
$appgwNsg = New-AzNetworkSecurityGroup -ResourceGroupName $resgrp -Location $region -Name $appgwnsgname -SecurityRules $appgwNsgRules -Force
write-host "Network security groups created." -ForegroundColor Green

#---------Virtual network----------------------------------------------------------------------------------------------
$subnets = @(
    New-AzVirtualNetworkSubnetConfig -Name $vmsssubnetname -AddressPrefix "10.0.0.0/24" -NetworkSecurityGroup $vmssNsg -DefaultOutboundAccess $false
    New-AzVirtualNetworkSubnetConfig -Name $appgwsubnetname -AddressPrefix "10.0.1.0/24" -NetworkSecurityGroup $appgwNsg
)
if ($EnableBastion) {
    $subnets += New-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -AddressPrefix "10.0.99.0/26"
}

New-AzVirtualNetwork -Force -Name $vnetname -ResourceGroupName $resgrp -Location $region -AddressPrefix "10.0.0.0/16" -Subnet $subnets | Out-Null
$vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
write-host "Virtual network '$vnetname' created." -ForegroundColor Green

#---------Outbound internet via NAT Gateway (no public IP on the instances)--------------------------------------------
if ($NoInternetAccess) {
    write-host "No NAT Gateway attached to the scale set subnet due to -NoInternetAccess." -ForegroundColor Yellow
}
else {
    write-host "Configuring NAT Gateway egress so instances reach the internet without a public IP..." -ForegroundColor Cyan
    $natPublicIp = New-AzPublicIpAddress -ResourceGroupName $resgrp -Name $natPublicIpName -Location $region -AllocationMethod Static -Sku Standard
    $natGateway = New-AzNatGateway -ResourceGroupName $resgrp -Name $natGatewayName -Location $region -IdleTimeoutInMinutes 10 -Sku Standard -PublicIpAddress $natPublicIp

    # Some Az.Network versions do not persist the NAT association through Set-AzVirtualNetworkSubnetConfig,
    # so verify afterwards and fall back to Azure CLI if needed.
    Set-AzVirtualNetworkSubnetConfig -Name $vmsssubnetname -VirtualNetwork $vnet -AddressPrefix "10.0.0.0/24" `
        -NetworkSecurityGroup $vmssNsg -DefaultOutboundAccess $false -InputObject $natGateway | Set-AzVirtualNetwork | Out-Null
    $vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
    $vmssSubnet = $vnet.Subnets | Where-Object { $_.Name -eq $vmsssubnetname } | Select-Object -First 1

    if (-not $vmssSubnet.NatGateway -or -not $vmssSubnet.NatGateway.Id) {
        $azCli = Get-Command az -ErrorAction SilentlyContinue
        if ($azCli) {
            write-host "Az.Network did not persist the NAT association; falling back to Azure CLI..." -ForegroundColor Yellow
            & $azCli.Source network vnet subnet update --resource-group $resgrp --vnet-name $vnetname --name $vmsssubnetname --nat-gateway $natGatewayName --only-show-errors -o none
            if ($LASTEXITCODE -ne 0) { throw "Failed to attach NAT Gateway '$natGatewayName' to subnet '$vmsssubnetname' via Azure CLI." }
            $vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
            $vmssSubnet = $vnet.Subnets | Where-Object { $_.Name -eq $vmsssubnetname } | Select-Object -First 1
        }
    }
    if (-not $vmssSubnet.NatGateway -or -not $vmssSubnet.NatGateway.Id) {
        throw "NAT Gateway '$natGatewayName' is not associated with subnet '$vmsssubnetname'."
    }
    write-host "NAT Gateway '$natGatewayName' attached to subnet '$vmsssubnetname'." -ForegroundColor Green
}

$vmssSubnetId  = ($vnet.Subnets | Where-Object { $_.Name -eq $vmsssubnetname }  | Select-Object -First 1).Id
$appgwSubnetId = ($vnet.Subnets | Where-Object { $_.Name -eq $appgwsubnetname } | Select-Object -First 1).Id

#---------Application Gateway (the only public entry point to the app)-------------------------------------------------
write-host "Creating Application Gateway '$appgwname' (this typically takes several minutes)..." -ForegroundColor Cyan
$appgwPip = New-AzPublicIpAddress -ResourceGroupName $resgrp -Name $appgwPipName -Location $region -AllocationMethod Static -Sku Standard

$agIpConfig  = New-AzApplicationGatewayIPConfiguration -Name "appgw-ipcfg" -SubnetId $appgwSubnetId
$agFrontIp   = New-AzApplicationGatewayFrontendIPConfig -Name "appgw-feip" -PublicIPAddressId $appgwPip.Id
$agFrontPort = New-AzApplicationGatewayFrontendPort -Name "port80" -Port 80
$agPool      = New-AzApplicationGatewayBackendAddressPool -Name "vmss-pool"
$agProbe     = New-AzApplicationGatewayProbeConfig -Name "app-health" -Protocol Http -Path "/health" `
                    -Interval 15 -Timeout 10 -UnhealthyThreshold 3 -PickHostNameFromBackendHttpSettings
# RequestTimeout is generous because /burn deliberately holds a request open while it consumes CPU.
$agSettings  = New-AzApplicationGatewayBackendHttpSetting -Name "app-http" -Port $appPort -Protocol Http `
                    -CookieBasedAffinity Disabled -RequestTimeout 180 -Probe $agProbe -PickHostNameFromBackendAddress
$agListener  = New-AzApplicationGatewayHttpListener -Name "http-listener" -Protocol Http `
                    -FrontendIPConfiguration $agFrontIp -FrontendPort $agFrontPort
$agRule      = New-AzApplicationGatewayRequestRoutingRule -Name "http-rule" -RuleType Basic -Priority 100 `
                    -HttpListener $agListener -BackendAddressPool $agPool -BackendHttpSettings $agSettings
$agSku       = New-AzApplicationGatewaySku -Name Standard_v2 -Tier Standard_v2 -Capacity 2

$appgw = New-AzApplicationGateway -Name $appgwname -ResourceGroupName $resgrp -Location $region `
    -Sku $agSku -GatewayIPConfigurations $agIpConfig -FrontendIPConfigurations $agFrontIp `
    -FrontendPorts $agFrontPort -BackendAddressPools $agPool -BackendHttpSettingsCollection $agSettings `
    -HttpListeners $agListener -RequestRoutingRules $agRule -Probes $agProbe

$agPoolId = ($appgw.BackendAddressPools | Where-Object { $_.Name -eq "vmss-pool" }).Id
write-host "Application Gateway created." -ForegroundColor Green

#---------Confidential VM Scale Set------------------------------------------------------------------------------------
# cloud-init has to be passed as base64 in the OS profile custom data
$cloudInit = Get-Content -Path $cloudInitPath -Raw
$customData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cloudInit))

write-host "Creating Confidential VM Scale Set '$vmssname'..." -ForegroundColor Cyan

# Uniform orchestration keeps the autoscale + Application Gateway backend wiring simple for this demo.
$vmssConfig = New-AzVmssConfig -Location $region -SkuCapacity $instanceCount -SkuName $vmsize `
    -UpgradePolicyMode "Automatic" -Overprovision $false -OrchestrationMode "Uniform"

# securityEncryptionType VMGuestStateOnly encrypts the VM guest state with a platform-managed key and
# needs no Key Vault or disk encryption set. For Confidential OS disk encryption bound to a customer
# managed key, see ../vm-samples/BuildRandomCVM.ps1.
$vmssConfig = Set-AzVmssStorageProfile -VirtualMachineScaleSet $vmssConfig `
    -OsDiskCreateOption "FromImage" -OsDiskCaching "ReadOnly" -ManagedDisk "StandardSSD_LRS" `
    -SecurityEncryptionType "VMGuestStateOnly" `
    -ImageReferencePublisher "Canonical" -ImageReferenceOffer "ubuntu-24_04-lts" `
    -ImageReferenceSku "cvm" -ImageReferenceVersion "latest"

$vmssConfig = Set-AzVmssOsProfile -VirtualMachineScaleSet $vmssConfig `
    -ComputerNamePrefix ($basename.Substring(0, [Math]::Min(9, $basename.Length))) `
    -AdminUsername $vmusername -AdminPassword $vmadminpassword `
    -CustomData $customData -LinuxConfigurationDisablePasswordAuthentication $false

$vmssConfig = Set-AzVmssSecurityProfile -VirtualMachineScaleSet $vmssConfig -SecurityType "ConfidentialVM"
$vmssConfig = Set-AzVmssUefi -VirtualMachineScaleSet $vmssConfig -EnableVtpm $true -EnableSecureBoot $true

# No PublicIPAddressConfiguration here, so instances are reachable only from inside the VNet.
$ipConfig = New-AzVmssIpConfig -Name "vmss-ipcfg" -SubnetId $vmssSubnetId -Primary $true `
    -ApplicationGatewayBackendAddressPoolsId $agPoolId
$vmssConfig = Add-AzVmssNetworkInterfaceConfiguration -VirtualMachineScaleSet $vmssConfig `
    -Name "vmss-nic" -Primary $true -IPConfiguration $ipConfig -NetworkSecurityGroupId $vmssNsg.Id

try {
    New-AzVmss -ResourceGroupName $resgrp -VMScaleSetName $vmssname -VirtualMachineScaleSet $vmssConfig -ErrorAction Stop | Out-Null
} catch {
    throw "Scale set deployment failed for '$vmssname' in '$region': $($_.Exception.Message)"
}
$vmss = Get-AzVmss -ResourceGroupName $resgrp -VMScaleSetName $vmssname
write-host "Scale set '$vmssname' created with $instanceCount instances." -ForegroundColor Green

#---------Autoscale rules----------------------------------------------------------------------------------------------
# Created through the raw ARM resource type rather than the Az.Monitor autoscale cmdlets, whose names and
# parameters changed between module versions.
write-host "Configuring CPU autoscale ($minInstances-$maxInstances instances)..." -ForegroundColor Cyan

# Autoscale settings live in Microsoft.Insights, which is not registered on every subscription.
$insightsProvider = Get-AzResourceProvider -ProviderNamespace Microsoft.Insights -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $insightsProvider -or $insightsProvider.RegistrationState -ne 'Registered') {
    write-host "Registering the Microsoft.Insights resource provider (required for autoscale)..." -ForegroundColor Yellow
    Register-AzResourceProvider -ProviderNamespace Microsoft.Insights | Out-Null
    for ($i = 1; $i -le 30; $i++) {
        Start-Sleep -Seconds 10
        $state = (Get-AzResourceProvider -ProviderNamespace Microsoft.Insights -ErrorAction SilentlyContinue | Select-Object -First 1).RegistrationState
        if ($state -eq 'Registered') { break }
        write-host "  waiting for Microsoft.Insights registration ($i/30, currently '$state')..." -ForegroundColor DarkGray
    }
    if ($state -ne 'Registered') {
        throw "Microsoft.Insights did not reach 'Registered' state; autoscale cannot be configured."
    }
    write-host "Microsoft.Insights registered." -ForegroundColor Green
}

$autoscaleProperties = @{
    name              = $autoscaleName
    targetResourceUri = $vmss.Id
    enabled           = $true
    profiles          = @(
        @{
            name     = "cpu-based-scaling"
            capacity = @{
                minimum = "$minInstances"
                maximum = "$maxInstances"
                default = "$instanceCount"
            }
            rules    = @(
                @{
                    metricTrigger = @{
                        metricName        = "Percentage CPU"
                        metricResourceUri = $vmss.Id
                        timeGrain         = "PT1M"
                        statistic         = "Average"
                        timeWindow        = "PT5M"
                        timeAggregation   = "Average"
                        operator          = "GreaterThan"
                        threshold         = 60
                    }
                    scaleAction   = @{ direction = "Increase"; type = "ChangeCount"; value = "1"; cooldown = "PT5M" }
                },
                @{
                    metricTrigger = @{
                        metricName        = "Percentage CPU"
                        metricResourceUri = $vmss.Id
                        timeGrain         = "PT1M"
                        statistic         = "Average"
                        timeWindow        = "PT5M"
                        timeAggregation   = "Average"
                        operator          = "LessThan"
                        threshold         = 30
                    }
                    scaleAction   = @{ direction = "Decrease"; type = "ChangeCount"; value = "1"; cooldown = "PT5M" }
                }
            )
        }
    )
}

try {
    New-AzResource -ResourceType "Microsoft.Insights/autoscalesettings" -ResourceGroupName $resgrp `
        -ResourceName $autoscaleName -Location $region -Properties $autoscaleProperties -Force -ErrorAction Stop | Out-Null
} catch {
    throw "Failed to create autoscale setting '$autoscaleName': $($_.Exception.Message)"
}
write-host "Autoscale configured: out at >60% CPU, in at <30% CPU (5 minute windows, 5 minute cooldown)." -ForegroundColor Green

#---------Optional Azure Bastion---------------------------------------------------------------------------------------
if ($EnableBastion) {
    write-host "Creating Azure Bastion (this takes several minutes)..." -ForegroundColor Cyan
    $bastionPip = New-AzPublicIpAddress -ResourceGroupName $resgrp -Name $bastionPipName -Location $region -AllocationMethod Static -Sku Standard
    New-AzBastion -ResourceGroupName $resgrp -Name $bastionname -PublicIpAddressRgName $resgrp -PublicIpAddressName $bastionPip.Name `
        -VirtualNetworkRgName $resgrp -VirtualNetworkName $vnetname -Sku "Basic" | Out-Null
    write-host "Azure Bastion '$bastionname' created." -ForegroundColor Green
}

#---------Wait for the app to come up behind the gateway---------------------------------------------------------------
$appgwIp = (Get-AzPublicIpAddress -ResourceGroupName $resgrp -Name $appgwPipName).IpAddress
$appUrl = "http://$appgwIp"

write-host "Waiting for the backend instances to report healthy through the Application Gateway..." -ForegroundColor Cyan
$healthy = $false
for ($i = 1; $i -le 30; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "$appUrl/health" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        if ($resp.StatusCode -eq 200) { $healthy = $true; break }
    } catch {
        # cloud-init still running, or the gateway has not finished probing the pool yet
    }
    write-host "  attempt $i/30: app not answering yet, waiting 20s..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 20
}

$elapsed = (Get-Date) - $startTime
write-host ""
write-host "----------------------------------------------------------------------------------------------------------------"
if ($healthy) {
    write-host "BUILD COMPLETE - the app is live" -ForegroundColor Green
} else {
    write-host "BUILD COMPLETE - but the app did not answer within the wait window" -ForegroundColor Yellow
    write-host "Check backend health with: Get-AzApplicationGatewayBackendHealth -ResourceGroupName $resgrp -Name $appgwname" -ForegroundColor Gray
}
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Resource group : $resgrp ($region)"
write-host "Scale set      : $vmssname   SKU $vmsize   autoscale $minInstances-$maxInstances"
write-host "App URL        : $appUrl"
write-host "Admin user     : $vmusername"
write-host "Admin password : $vmadminpassword"
write-host "Build time     : $([Math]::Round($elapsed.TotalMinutes, 1)) minutes"
write-host ""
write-host "Drive load until the scale set grows:" -ForegroundColor Cyan
write-host "  ./Start-VmssLoad.ps1 -Target $appUrl -subsID $subsID -ResourceGroup $resgrp -VmssName $vmssname" -ForegroundColor Gray
write-host ""
write-host "Delete everything when you are done:" -ForegroundColor Cyan
write-host "  Remove-AzResourceGroup -Name $resgrp -Force" -ForegroundColor Gray
write-host "----------------------------------------------------------------------------------------------------------------"

if ($smoketest) {
    write-host ""
    write-host "SMOKETEST MODE: removing resource group '$resgrp'..." -ForegroundColor Yellow
    Remove-AzResourceGroup -Name $resgrp -Force | Out-Null
    write-host "Resource group '$resgrp' deleted." -ForegroundColor Green
}
