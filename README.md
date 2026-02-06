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

**Last Updated:** February 2026

Security is a key driver accelerating the adoption of cloud computing, but it's also a major concern when you're moving extremely sensitive IP and data scenarios to the cloud.

Confidential computing is the protection of data-in-use through isolating computations to a hardware-based trusted execution environment (TEE). While data is traditionally encrypted at rest and in transit, confidential computing protects your data while it's being processed. A TEE provides a protected container by securing a portion of the hardware's processor and memory. You can run software on top of the protected environment to shield portions of your code and data from view or modification from outside of the TEE. [read more](https://azure.microsoft.com/en-us/solutions/confidential-compute/)

## ⚠️ Disclaimer

**IMPORTANT:** This repository contains sample code for educational and demonstration purposes only. 

- **No Warranty:** This code is provided "AS IS" without warranty of any kind, express or implied
- **Not Production-Ready:** These samples are not intended for production use without thorough review and modification
- **User Responsibility:** Users are solely responsible for:
  - Reviewing and testing all code before deployment
  - Ensuring compliance with their organization's security policies
  - Validating cryptographic implementations meet their security requirements
  - Proper key management and secret handling
  - Any data processed using these samples
- **AI-Generated Content:** The multi-party demonstration samples were created with assistance from AI (GitHub Copilot with Claude) to showcase modern AI-assisted development capabilities. While functional, AI-generated code should always be reviewed by qualified security professionals before use in sensitive scenarios.

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
- **Visual Attestation Demo** - Interactive web demo with remote attestation via Microsoft Azure Attestation (MAA), includes side-by-side comparison mode

### [Multi-Party Samples](/multi-party-samples/README.md) ⭐ FEATURED
Secure multi-party computation demonstrations with Azure Confidential Containers. Two versions available:

#### [Advanced App](/multi-party-samples/advanced-app/README.md) - Full-Featured Demo
Comprehensive 4-container demonstration with partner analytics:

![Multi-Party Topology](/multi-party-samples/advanced-app/MultiPartyTopology.svg)

- **Contoso Corporation** - Enterprise data provider with encrypted employee records
- **Fabrikam Fashion** - Online retailer with encrypted customer records
- **Woodgrove Bank** - Trusted analytics partner with cross-company key access
- **Snooper** - Attacker view showing encrypted-only data

**Key Features:**
- 🔐 **Hardware-based isolation** - AMD SEV-SNP TEE protects data in memory
- 🛡️ **Remote attestation** - Cryptographic proof of TEE environment via MAA
- 🔑 **Secure Key Release (SKR)** - HSM keys only released to attested containers
- 🏦 **Partner Analytics** - Woodgrove Bank analyzes encrypted partner data inside TEE
- 📊 **Real-time Progress** - SSE streaming with progress bars and time estimates
- 🌍 **Demographics Analysis** - Top countries, cities, generations, salaries, eye colors
- 👁️ **Attacker visualization** - Snooper container shows what attackers see
- 🔓 **TEE-only decryption** - Data decrypted only inside hardware-protected memory

![Multi-Party Architecture](/multi-party-samples/advanced-app/MultiPartyArchitecture.svg)

**Encrypted Data Flow:** Data remains encrypted in storage and transit; decryption only occurs inside the TEE.

![Data Flow Diagram](/multi-party-samples/advanced-app/DataFlowDiagram.svg)

#### [Demo App](/multi-party-samples/demo-app/README-MultiParty.md) - Basic Demo
Simpler 3-container demonstration (Contoso, Fabrikam Fashion, Snooper) without partner analytics.

### [VM Samples](/vm-samples/README.md)
Confidential Virtual Machine (CVM) deployment scripts:
- **BuildRandomCVM.ps1** - Deploy CVMs with Customer Managed Keys, Confidential Disk Encryption, and attestation (Windows Server, Windows 11, Ubuntu, RHEL)
- **BuildCVMWithPrivateMAA.ps1** - CVM with private Azure Attestation provider *(experimental)*
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

## 🤖 AI-Assisted Development Note

The **multi-party-samples** in this repository were entirely created using AI-assisted development with **GitHub Copilot** powered by **Claude**. This demonstrates the capabilities of modern AI models for:

- Complex infrastructure-as-code (ARM templates, PowerShell)
- Cryptographic implementations (AES-256-GCM encryption/decryption)
- Web application development (Flask, HTML/CSS/JavaScript)
- Security-focused architecture design
- Documentation and diagram generation

While these samples are functional and demonstrate real Azure Confidential Computing capabilities, **they should be reviewed by qualified security professionals** before use in production scenarios.
 
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

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

**By using this code, you acknowledge that:**
- You have read and understood the disclaimer above
- You accept full responsibility for any use of this code
- You will conduct appropriate security reviews before any production deployment
