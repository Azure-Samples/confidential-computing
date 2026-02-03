# Multi-Party Samples

This folder contains demonstrations of secure multi-party computation using Azure Confidential Containers.

## Available Samples

### [Demo App](demo-app/README-MultiParty.md)

A comprehensive demonstration of multi-party confidential computing that deploys three containers:

| Container | Type | Purpose |
|-----------|------|---------|
| **Contoso** | Confidential (AMD SEV-SNP) | Trusted party with access to own encryption key |
| **Fabrikam** | Confidential (AMD SEV-SNP) | Trusted party with access to own encryption key |
| **Snooper** | Standard (No TEE) | Attacker view - cannot access any keys |

#### Key Features

- **Hardware-Based Security**: AMD SEV-SNP memory encryption
- **Remote Attestation**: Cryptographic proof via Microsoft Azure Attestation
- **Secure Key Release**: Azure Key Vault HSM keys only released to TEE
- **Company Isolation**: Each party's data protected from others
- **Attacker Visualization**: See what a malicious actor would observe
- **TEE-Only Decryption**: Data encrypted at rest, decrypted only inside hardware TEE

#### Architecture

![Architecture Diagram](demo-app/MultiPartyArchitecture.svg)

#### Encrypted Data Flow

![Data Flow Diagram](demo-app/DataFlowDiagram.svg)

**Key Insight:** Data remains encrypted in storage and transit. Decryption **only** occurs inside the AMD SEV-SNP TEE, where memory is hardware-encrypted. Even infrastructure operators cannot access plaintext.

#### Quick Start

```powershell
cd demo-app
.\Deploy-MultiParty.ps1 -Build -Deploy
```

See the [full documentation](demo-app/README-MultiParty.md) for detailed instructions.

## Prerequisites

- Azure CLI with `confcom` extension
- Docker Desktop
- Azure subscription with Confidential Container support
- PowerShell 5.1+

## Related Resources

- [Azure Confidential Computing](https://azure.microsoft.com/solutions/confidential-compute/)
- [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
- [Azure Container Instances Confidential Containers](https://docs.microsoft.com/azure/container-instances/container-instances-confidential-overview)
