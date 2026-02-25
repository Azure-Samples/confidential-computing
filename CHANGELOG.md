## Azure Confidential Computing Samples Changelog

<a name="2.3.0"></a>
# 2.3.0 (2025-06-19)

*Documentation*
* **Repo-wide documentation refresh** - Fixed broken URLs, removed references to non-existent scripts, updated GitHub repository URLs from legacy forks to Azure-Samples
* **SKR version alignment** - Updated SKR sidecar references from `2.7` to `2.13` in all ATTESTATION.md files to match Dockerfiles
* **CONTRIBUTING.md** - Replaced placeholder project name and repository URLs with actual values
* **GitHub templates** - Updated PR template with correct clone instructions, modernised OS examples in issue template
* **SKR Examples** - Added new section in root README for the SKR Examples project

<a name="2.2.0"></a>
# 2.2.0 (2026-02-17)

*Features*
* **AKS Virtual Node deployment** - Full end-to-end AKS deployment with confidential virtual nodes (VN2), private VNet networking, and nginx reverse proxy for external access
* **Multi-port nginx proxy** - LoadBalancer exposes all three containers: `:80` Woodgrove, `:8081` Contoso, `:8082` Fabrikam
* **Partner auto-initialization** - `_ensure_partner_data_ready()` automatically triggers key release and CSV encryption on partner containers when data is missing
* **Debug endpoints** - `/debug/partner-keys` to inspect stored partner key structure and `/debug/test-partner-decrypt` for step-by-step decryption diagnostics
* **Streaming partner analysis** - SSE endpoint `/partner/analyze-stream` with real-time progress, time estimates, and full demographic analytics
* **Kubernetes Service YAML** - Added `svc-contoso.yaml` for ClusterIP service routing

*Improvements*
* **SKR retry logic** - Secure Key Release now retries up to 3 times with 5-second delays for sidecar timing issues
* **MAA attestation resilience** - Attestation step is now informational; failures no longer block key release (which performs its own attestation)
* **Parallel decryption** - Thread pool-based RSA decryption with cached private key objects for 3-5x speedup
* **Partner data fetching** - Uses `_ensure_partner_data_ready()` helper in both streaming and non-streaming analysis endpoints
* **runtime_data encoding** - Fixed MAA attestation payload to use base64-encoded JSON as required by the sidecar

*Documentation*
* **AKS architecture diagram** - Updated ASCII diagram with multi-port nginx proxy routing
* **Architecture SVG** - Added nginx reverse proxy box with port-to-container mapping
* **AKS browser access section** - New section documenting `kubectl get svc` and per-container URLs
* **Nginx proxy key concept** - Expanded with port/container table and access instructions

*Bug Fixes*
* **Partner key nesting** - Fixed double-nesting issue where `_build_private_key()` failed to unwrap JWK keys stored as `{key: {key: {...}}}`
* **Key mismatch detection** - Added diagnostics to identify when KV keys are recreated after data encryption, causing silent decryption failures

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
