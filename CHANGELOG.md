## Azure Confidential Computing Samples Changelog

<a name="2.1.0"></a>
# 2.1.0 (2026-02-07)

*Documentation*
* **Comprehensive README refresh** - All sample documentation updated with current architectures
* **ASCII Architecture Diagrams** - Added visual flow diagrams to all major README files
* **Updated Prerequisites** - Azure CLI 2.60+, PowerShell 7.0+, Python 3.11+
* **Windows 11 24H2** - Updated CVM samples to support latest Windows 11 Enterprise
* **Enhanced AKS Documentation** - Complete rewrite with architecture diagrams and deployment guide
* **Attestation Flow Diagrams** - Visual representation of MAA attestation process
* **Multi-Party Architecture** - Detailed diagrams showing container isolation and key access patterns

*Improvements*
* Standardized documentation format across all sample folders
* Added Quick Setup section to main README
* Enhanced troubleshooting sections with common error scenarios
* Updated all Azure service references to current API versions

<a name="2.0.0"></a>
# 2.0.0 (2026-02-03)

*Features*
* **Visual Attestation Demo** - New interactive web UI for attestation demonstration
* **Secure Key Release (SKR)** - Azure Key Vault integration with release policies
* **Real-time Encryption** - Encrypt text using SKR-released keys with RSA-OAEP-SHA256
* **Side-by-Side Comparison** - Deploy Confidential and Standard containers simultaneously
* **Live Diagnostics** - Service logs and `/dev/sev-guest` device detection in UI
* **Updated SKR Sidecar** - Using `mcr.microsoft.com/aci/skr:2.13`
* **Python 3.13** - Updated base container to latest Python slim-bookworm
* **Latest Dependencies** - Flask 3.1.2, Requests 2.32.5, Cryptography 44.0.0

*Improvements*
* Single combined container architecture (Flask + SKR via supervisord)
* Multi-stage Docker build for smaller image size
* Comprehensive error diagnostics with failure reasons
* Interactive cleanup prompts after deployment
* Better ARM template organization (separate confidential/standard templates)

*Security*
* No hardcoded credentials - all secrets stored in Azure Key Vault
* CCE policy enforcement with layer hash validation
* Release policy requiring `x-ms-attestation-type: sevsnpvm`
* Disabled container shell access via `--disable-stdio` in policy

<a name="1.0.0"></a>
# 1.0.0 (2024-01-01)

*Initial Release*
* BuildRandomACI.ps1 - Basic confidential ACI creation
* BuildRandomCVM.ps1 - Confidential VM deployment with multiple OS options
* BuildRandomSQLCVM.ps1 - SQL Server on Confidential VM
* BuildCVMWithPrivateMAA.ps1 - CVM with private attestation provider
* AKS samples with confidential node pools
* Intel SGX container samples (HelloWorld, Attested-TLS)
