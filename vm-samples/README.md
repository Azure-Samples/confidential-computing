# Confidential Virtual Machines

**Last Updated:** February 2026

## Overview

Deploy Confidential Virtual Machines (CVMs) with AMD SEV-SNP hardware protection, Customer Managed Keys (CMK), and automated attestation.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Confidential VM Architecture                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Confidential VM (DCasv5)                       │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │                  Guest OS (Windows/Linux)                   │  │   │
│  │  │  ┌─────────────────┐    ┌─────────────────────────────┐   │  │   │
│  │  │  │  Application    │    │  Attestation Agent          │   │  │   │
│  │  │  │  Workload       │    │  (Proves TEE Integrity)     │   │  │   │
│  │  │  └─────────────────┘    └──────────────┬──────────────┘   │  │   │
│  │  └────────────────────────────────────────┼───────────────────┘  │   │
│  │                                           │                       │   │
│  │              AMD SEV-SNP TEE              │                       │   │
│  │         (Memory Encrypted at CPU)         │                       │   │
│  └───────────────────────────────────────────┼───────────────────────┘   │
│                                              │                           │
│                                              ▼                           │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                     Azure Infrastructure                          │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │  │
│  │  │  Key Vault      │  │  Azure          │  │  Azure Bastion  │   │  │
│  │  │  (Premium HSM)  │  │  Attestation    │  │  (Secure RDP/   │   │  │
│  │  │                 │  │  (MAA)          │  │  SSH Access)    │   │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Available Scripts

| Script | Description | Status |
|--------|-------------|--------|
| `BuildRandomCVM.ps1` | Deploy CVM with CMK, Confidential Disk Encryption, and Bastion | **Stable** |
| `BuildCVMWithPrivateMAA.ps1` | CVM with private Azure Attestation provider | **Experimental** |
| `BuildRandomSQLCVM.ps1` | SQL Server 2022 on Confidential VM | **Stable** |

---

## BuildRandomCVM.ps1

Builds a CVM with Customer Managed Key, Confidential Disk Encryption, a private VNet (no public IP) and deploy Azure Bastion for remote access over the Internet. It supports Windows Server 2022, Windows 11 Enterprise, Ubuntu 24.04 LTS, and RHEL 9.5 CVM images. The script automatically detects the GitHub repository URL from the local git configuration and includes it in resource tagging. It will then kick off an attestation inside the CVM and present back the output via Invoke-AzVMRunCommand.

Use at your own risk, no warranties implied.

## Usage

Clone this repo locally (Windows deployments depend on WindowsAttest.ps1).  
Basename is a prefix assigned to all resources created by the script and will be given a 5 char suffix - for example: myCVM-sdfrw.  
The script will generate a random complex password and output it to the terminal once; make sure you copy it if you want to login to the CVM.

```powershell
./BuildRandomCVM.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME> -osType <Windows|Windows11|Ubuntu|RHEL> [-description <OPTIONAL DESCRIPTION>] [-smoketest] [-region <AZURE REGION>] [-vmsize <VM SIZE SKU>]
```

## Parameters:
- **subsID**: Your Azure subscription ID (required)
- **basename**: A prefix for all resources created by the script (required)
- **osType**: The operating system to deploy (required)
- **description**: Optional description that will be added as a tag to the resource group
- **smoketest**: Optional switch that automatically removes all resources after completion (useful for testing)
- **region**: Optional Azure region to deploy resources (defaults to "northeurope")
- **vmsize**: Optional VM size SKU (defaults to "Standard_DC2as_v5"). Use this to select a different Confidential VM SKU, e.g. "Standard_DC4as_v5".

## OS Type Options:
- **Windows**: Windows Server 2022 Datacenter (supports RDP via Bastion)
- **Windows11**: Windows 11 Enterprise 24H2 (supports RDP via Bastion)
- **Ubuntu**: Ubuntu 24.04 LTS CVM (supports SSH via Bastion)  
- **RHEL**: Red Hat Enterprise Linux 9.5 CVM (supports SSH via Bastion)

## Example:
```powershell
# Deploy Ubuntu CVM with a larger VM size
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myubuntu" -osType "Ubuntu" -vmsize "Standard_DC4as_v5"
```

## Examples:
```powershell
# Deploy Windows Server CVM (resources remain)
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myvm" -osType "Windows"

# Deploy Windows 11 Enterprise CVM
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "mywin11" -osType "Windows11"

# Deploy Ubuntu CVM with description
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myvm" -osType "Ubuntu" -description "Development testing environment"

# Deploy RHEL CVM for testing (automatically cleaned up)
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "test" -osType "RHEL" -smoketest

# Deploy Windows 11 CVM in a specific region
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myvm" -osType "Windows11" -region "eastus"

# Smoketest with Windows 11 for CI/CD pipeline
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "ci" -osType "Windows11" -description "Automated testing pipeline" -smoketest
```

The script automatically tags the resource group with:
- **owner**: Your Azure user principal name
- **BuiltBy**: The script name that created the resources
- **OSType**: The operating system type deployed
- **GitRepo**: The GitHub repository URL where the script was cloned from
- **description**: Optional description if provided
- **smoketest**: Set to "true" when running in smoketest mode

## Smoketest Mode:
The `-smoketest` parameter is perfect for:
- **Automated testing**: CI/CD pipelines that need to validate deployments
- **Quick validation**: Testing that the script works without leaving resources behind
- **Demonstrations**: Show functionality without manual cleanup
- **Cost management**: Ensures test resources are automatically removed

### Interactive Safety Features:
- **Real-time countdown**: Shows exactly how many seconds remain before deletion
- **Easy cancellation**: Press any key during the 10-second countdown to cancel deletion
- **Clear warnings**: Bold red warnings that resources cannot be recovered
- **Flexible operation**: Works in both interactive and automated environments

When using `-smoketest`, the script will:
1. Deploy and configure the CVM as normal
2. Run attestation checks
3. Display a 10-second interactive countdown with real-time timer
4. Allow cancellation by pressing any key during the countdown
5. Automatically remove all created resources (VM, Key Vault, Bastion, VNet, etc.) if not cancelled
6. Provide confirmation of successful cleanup or cancellation status

## Key Release Policy Template

The [`releasePolicyTemplate.json`](releasePolicyTemplate.json) file is a template for configuring a key release policy that can be assigned to a CVM. This policy defines the conditions under which a key can be released from Azure Key Vault to a Confidential VM.

### Key Features:
- **Attestation validation**: Ensures the VM is running in a compliant confidential computing environment
- **Custom MAA endpoint support**: Can be configured to point to a custom Microsoft Azure Attestation (MAA) endpoint
- **SEV-SNP validation**: Validates that the VM is running on AMD SEV-SNP hardware

### Default Behavior:
If the `-policyFilePath` parameter is not specified when running `BuildRandomCVM.ps1`, the script will automatically use the default CVM policy that points to the shared attestation endpoint serving the region where your CVM has been created. This provides out-of-the-box attestation functionality without requiring custom configuration.

### Usage with Custom MAA:
The template can be customized to work with a private MAA endpoint created using the [`createPrivateMAA.ps1`](../attestation-samples/createPrivateMAA.ps1) script from the attestation-samples directory:

1. Create a private MAA endpoint using the attestation samples
2. Update the `authority` field in `releasePolicyTemplate.json` with your MAA endpoint URL
3. Use the `-policyFilePath` parameter with `BuildRandomCVM.ps1` to apply the custom policy

```powershell
# Deploy CVM with default shared attestation endpoint (regional)
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myvm" -osType "Windows"

# Deploy CVM with custom key release policy
./BuildRandomCVM.ps1 -subsID "your-subscription-id" -basename "myvm" -osType "Windows" -policyFilePath "./releasePolicyTemplate.json"
```

This ensures that the CVM's customer-managed key can only be released when the attestation validation passes through your specified MAA endpoint (custom) or the regional shared endpoint (default).

## Important Notes:
Note this will deploy an Azure Keyvault *Premium* SKU [pricing](https://azure.microsoft.com/en-gb/pricing/details/key-vault/#pricing) & enables purge protection for 10 days (you can adjust the purge protection period but AKV Premium is required for CVMs with confidential disk encryption

By default the script will create resources in North Europe - you can specify a different region using the `-region` parameter. Make sure to check availability of CVMs in your chosen region first.

There is a similar concept to build an AKS cluster with CMK enabled on the worker nodes.


# SQL Server on Confidential Computing

The BuildRandomSQLCVM.ps1 script builds on the CVM script but deploys the specific SQL image to give you a SQL 2022 build running on Windows Server 2022 [official docs](https://learn.microsoft.com/en-gb/azure/azure-sql/virtual-machines/windows/sql-vm-create-confidential-vm-how-to?view=azuresql)


# ARM Template (currently a work-in-progress)
Create a simple CVM with CMK enabled using an Azure Resource Manager (ARM) template

You'll need to pre-create a disk encryption set and encryption key (use Azure Keyvault Premium) and replace the relevant values in the parameter file, see 'snippet-createDES.ps1' for an automated way to do this in an existing Azure Key Vault _Premium_ instance - in future will try to do this in the ARM template itself, seems complex to get the resource ID for the DES and pass it in the same ARM template (or, at-least I haven't figured out how to do it yet)

To deploy from the command line:

New-AzResourceGroupDeployment -Name DeployLocalTemplate -ResourceGroupName "<YOUR_RESOURCE_GROUP>" -TemplateFile ./cvm-cmk.json  -TemplateParameterFile ./cvm-cmk-params.json -Verbose


# Automated Attestation

[Attestation](https://learn.microsoft.com/en-us/azure/confidential-computing/attestation-solutions) is how you prove you are running on a confidential computing VM based on evidence provided and signed by the CPU and validated by an attestation service.

## Windows CVMs
Once you've deployed a Windows CVM (Windows Server 2022 or Windows 11 Enterprise), you can install the [simple attestation client](https://github.com/Azure/confidential-computing-cvm-guest-attestation/blob/main/cvm-platform-checker-exe/README.md) install the VC runtime 1st!to see true/false if your VM is protected by Azure Confidential Computing

The WindowsAttest.ps1 script can manually be invoked inside a Windows CVM to do an automated attestation check against the West Europe shared attestation endpoint. This script works with both Windows Server 2022 and Windows 11 Enterprise CVMs.

Expected output for Windows CVMs:

Running on a CVM (DCa / ECa Series SKU using AMD SEV-SNP hardware)
>    This  Windows  OS is running on  sevsnpvm VM hardware
>    This VM is an Azure compliant CVM attested by  https://sharedweu.weu.attest.azure.net

NOT running on a CVM (any other Azure SKU)
>    This VM is NOT an Azure compliant CVM

![Screenshot of output from attestation script](./AttestationClientScreenshot.png)

## Linux CVMs
For Ubuntu and RHEL CVMs, the script performs a basic attestation check by looking for TPM devices and CVM indicators. For production use, you should implement proper Linux attestation tools 
and libraries.

You can download the script to a CVM or execute directly from GitHub >inside< your CVM by pasting the following single line Command in a PowerShell session that is running with Administrative permissions (review the script 1st to ensure you are happy with the binaries and packages it installs or download & customize)

```powershell
$ScriptFromGitHub = Invoke-WebRequest -uri https://raw.githubusercontent.com/vinfnet/simple-cvm-cmk-demo/refs/heads/main/WindowsAttest.ps1 ; Invoke-Expression $($ScriptFromGitHub.Content)
```

If you want to run this command against your CVM >from< your own workstation over the Internet you can use the following 1-line command, edit the <VARIABLES> to match the VM you're targetting and paste it into a PowerShell session that is authenticated to your Azure subscription (in this case output will not be colour-coded)

```powershell
$ScriptContent = Invoke-WebRequest -Uri https://raw.githubusercontent.com/vinfnet/simple-cvm-cmk-demo/main/WindowsAttest.ps1 -UseBasicParsing | Select-Object -ExpandProperty Content ; Invoke-AzVMRunCommand -ResourceGroupName <YOUR_RESOURCE_GROUP> -VMName <YOUR_VM_NAME> -CommandId "RunPowerShellScript" -ScriptString $ScriptContent
```

For more information on Azure confidential Computing see the [public docs](https//aka.ms/accdocs)


# TURBO Charged Versions

These scripts are useful for step by step learning or exploring, but one of our colleagues has a turbo-charged version of this script with detailed error handing, Managed HSM support and much more - check it out - [GitHub Link](https://github.com/RZomermanMS/CVM)
