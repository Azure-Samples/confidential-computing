---
page_type: sample
languages:
- yaml
- python
- shell
- C++
- PowerShell
- AzureCLI
products:
- azure-confidential-computing
- azure-kubernetes-service
- azure-attestation-service
- azure-container-instances
- azure-virtual-machines
description: "Azure Confidential Computing Samples"
urlFragment: confidential-computing-samples
---

# Confidential Computing Samples

![MIT license badge](https://img.shields.io/badge/license-MIT-green.svg)

**Last Updated:** January 2026

Security is a key driver accelerating the adoption of cloud computing, but it’s also a major concern when you’re moving extremely sensitive IP and data scenarios to the cloud.

Confidential computing is the protection of data-in-use through isolating computations to a hardware-based trusted execution environment (TEE). While data is traditionally encrypted at rest and in transit, confidential computing protects your data while it’s being processed. A TEE provides a protected container by securing a portion of the hardware’s processor and memory. You can run software on top of the protected environment to shield portions of your code and data from view or modification from outside of the TEE. [read more](https://azure.microsoft.com/en-us/solutions/confidential-compute/)

## Prerequisites

- [Azure subscription](https://azure.microsoft.com/free/)
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest) (v2.50+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell?view=azps-latest)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (for confidential container policy generation)

## Sample Categories

This repository is organized by Azure service type and deployment method:

### [ACI Samples](/aci-samples/README.md)
Azure Container Instances with AMD SEV-SNP confidential computing:
- **BuildRandomACI.ps1** - Create confidential ACI with hello-world container
- **Visual Attestation Demo** - Interactive web demo with remote attestation via Microsoft Azure Attestation (MAA)

### [VM Samples](/vm-samples/README.md)
Confidential Virtual Machine (CVM) deployment scripts:
- **BuildRandomCVM.ps1** - Deploy CVMs with Customer Managed Keys, Confidential Disk Encryption, and attestation (Windows Server, Windows 11, Ubuntu, RHEL)
- **BuildCVMWithPrivateMAA.ps1** - CVM with private Azure Attestation provider
- **BuildRandomSQLCVM.ps1** - SQL Server on Confidential VM

### [AKS Samples](/aks-samples/README.md)
Azure Kubernetes Service with AMD SEV-SNP confidential computing:
- **BuildRandomAKS.ps1** - AKS cluster with Customer Managed Keys and confidential node pools

### [Attestation Samples](/attestation-samples/README.md)
Microsoft Azure Attestation (MAA) provider management:
- **createPrivateMAA.ps1** - Create private Azure Attestation provider for custom attestation policies

### Utility Snippets
Reusable PowerShell snippets for common confidential computing tasks:
- `snippet-createDES.ps1` - Create Disk Encryption Set for Confidential VMs
- `snippet-remoteCallAttest.ps1` - Remote attestation call examples

### [Container Samples](/containersamples/README.md) *(Intel SGX)*
Enclave-aware container samples for AKS with Intel SGX:
- **HelloWorld** - Simple enclave creation and function calls
- **Attested-TLS** - Secure communication channel between enclaves
 
## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit <https://cla.opensource.microsoft.com.>

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
