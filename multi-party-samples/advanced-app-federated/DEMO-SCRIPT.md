# Federated Confidential Computing Demo Script

> **Duration:** ~3 minutes  
> **Focus:** Federated privacy-preserving analysis where each company processes its own data locally inside a TEE and only shares aggregate insights — never raw PII.

---

## Setup (Before Demo)

1. Deploy all four containers:
   ```powershell
   .\Deploy-MultiParty.ps1 -Prefix sgall -RegistryName acrhjlxsrnc -Build -Deploy
   ```
2. Verify all four are healthy:
   - **Woodgrove Bank** (orchestrator) — port 80
   - **Contoso** (data provider) — port 8081
   - **Fabrikam** (data provider) — port 8082
   - **Wingtip Toys** (data provider) — port 8083
3. Open **Woodgrove Bank** in a browser. Optionally open a data provider (e.g. Contoso) in a second tab.

---

## [0:00 – 0:30] Architecture & How It Works

*Woodgrove Bank container*

**Action:** The page loads with the **🏗️ Federated Multi-Party Architecture** diagram expanded at the top.

> "This is a federated multi-party confidential computing demo. Four companies — Contoso, Fabrikam, Wingtip Toys, and Woodgrove Bank — each run their workloads inside AMD SEV-SNP Trusted Execution Environments on Azure. Each company's data is encrypted at rest and only decrypted inside its own TEE — not even the cloud provider can see the plaintext. Woodgrove Bank acts as the analytics partner. It requests aggregate statistics from each company's container but never receives any raw personal data. Before accepting results, Woodgrove cryptographically verifies each partner's identity through remote attestation and policy hash matching, ensuring the code running in each TEE hasn't been tampered with. The result: multiple organizations collaborate on shared analytics without ever exposing their sensitive data to each other or to the infrastructure."

---

## [0:30 – 0:50] Security & Attestation

**Action:** The **🛡️ Security Features** section shows six properties with ○ pending indicators. Expand **🔍 Remote Attestation** and click **"Request Attestation Token"** — all six flip to ✓ green. Then expand **🔑 Secure Key Release** and click **"🔐 Test Secure Key Release"**.

> "The attestation token from Microsoft Azure Attestation confirms this container is running inside a genuine AMD SEV-SNP TEE. Now Azure Key Vault releases the decryption key — but only because attestation proved this is the approved container."

---

## [0:50 – 1:05] TEE Is Locked Down

**Action:** Expand **"🖥️ Try to Access Container OS"** and click **"🔓 Attempt to Connect"**. All three access methods fail.

> "Can an operator shell in? No. SSH — blocked, no daemon and the policy prevents adding one. `az container exec` — disabled at the policy level. Shell spawn — blocked even if malware got in. This is hardware-enforced isolation, not just configuration."

**Action:** Optionally expand **"📦 Container Image Information"** to show hostname, SEV-SNP device status, and SHA-256 checksums of application files.

---

## [1:05 – 1:20] Live Encryption & Cross-Company Isolation

**Action:** Expand **"🔐 Encrypt Data Using [Company] Key"**. Type a message — ciphertext appears in real-time (RSA-OAEP-SHA256). Then on a data provider tab, expand **"🚫 Attempt to Use Key from Other Company"** and click **"🚫 Attempt to Access Other Company's Key"** — it fails.

> "With the key released we can encrypt in real-time. But each company can only access its own key — Contoso trying to use Fabrikam's key is denied. Shared infrastructure, cryptographic isolation."

---

## [1:20 – 2:00] Federated Analysis

*Woodgrove Bank container*

**Action:** Expand **"📊 Federated Partner Analysis"** and click **"📊 Start Federated Analysis"**. A progress bar tracks the phases.

> "Instead of gathering data centrally, each company's container decrypts its own data locally inside its TEE, computes aggregate statistics, and sends back only the aggregates — no names, no IDs, no PII. Watch the status cards: Contoso… done. Fabrikam… done. Wingtip… done."

---

## [2:00 – 2:20] Attestation Verification & Explain This

**Action:** Point to the **Container Attestation Verification** panel (three cards). Click **"ℹ️ Explain This"** to open the flyout.

> "Each card shows TEE type, SKR key released, image verified, policy hash, and file integrity hashes. The flyout explains: AMD SEV-SNP generates a policy hash for the running code; MAA confirms it before Key Vault releases any key; Woodgrove cross-verifies each partner's hash. Modify one line of code and the key is never released."

**Action:** Close the flyout.

---

## [2:20 – 2:45] Combined Results

**Action:** Scroll through the demographics summary: 750 total staff cards, per-company salary comparison, generation breakdown bars, blood type distribution, medical condition counts, world map with salary-by-country colouring, top countries with city breakdowns.

> "Every insight was computed inside each company's TEE. Woodgrove received only counts, averages, and percentages. Zero PII crossed any network boundary."

---

## [2:45 – 3:00] Proof of Privacy

**Action:** Scroll to **"🔍 Raw Partner Responses (Privacy Proof)"** showing formatted JSON per partner.

> "This is the exact data Woodgrove received — record counts, salary averages, generation percentages, blood type counts. No names, no SSNs, no credit cards. Full collaboration, zero data exposure."

---

## Key Takeaways

| Principle | How It's Demonstrated |
|-----------|----------------------|
| **Data sovereignty** | Each company's PII never leaves its TEE |
| **Hardware attestation** | AMD SEV-SNP verifies code integrity before key release |
| **Operator lockout** | No SSH, no exec, no shell — policy-enforced |
| **Federated analytics** | Local processing, aggregate-only sharing |
| **Key isolation** | Cross-company key access fails even between TEEs |
| **Cryptographic proof** | Results include attestation_evidence with policy hash and file integrity |
| **Zero trust** | Even the orchestrator (Woodgrove) cannot decrypt raw data |

---

## UI Features Reference

| Feature | Location | Visibility |
|---------|----------|------------|
| 🏗️ Architecture diagram (SVG) | Top of page, collapsible `<details>` | Woodgrove only |
| 🔊 Explain It (TTS narration) | Button next to diagram | Woodgrove only |
| Narration controls (⏪ 5s, ▶️/⏸, 5s ⏩, ⏹, volume, progress scrub) | Expands below diagram | Woodgrove only |
| 🛡️ Security Features | Six checkable properties | All containers |
| 🔍 Remote Attestation | Request Attestation Token / Get Raw Report | All containers |
| 🔑 Secure Key Release | 🔐 Test Secure Key Release button | All containers |
| 🚫 Attempt to Use Key from Other Company | Cross-company key access test | Contoso, Fabrikam, Wingtip only |
| 📊 Company Demographics | Per-company local TEE analysis with progress bar | Contoso, Fabrikam, Wingtip only |
| 📊 Federated Partner Analysis | Multi-company orchestrated analysis | Woodgrove only |
| ℹ️ Explain This (attestation flyout) | Attestation panel header | Woodgrove only |
| Demographics summary (cards, charts, map) | Below federated analysis results | Woodgrove only |
| 🔍 Raw Partner Responses (JSON) | Bottom of federated results | Woodgrove only |
| 🔐 Encrypt Data Using [Company] Key | Live RSA-OAEP-SHA256 encryption (after SKR) | All containers |
| 🖥️ Try to Access Container OS | 🔓 Attempt to Connect button | All containers |
| 📦 Container Image Information | Hostname, OS, SEV-SNP status, SHA-256 checksums | All containers |

---

## Sensitive Fields in Each Company's Dataset (18 fields)

| Field | Classification | Shared? |
|-------|---------------|---------|
| name | PII | ❌ Never |
| email | PII | ❌ Never |
| phone | PII | ❌ Never |
| date_of_birth | PII | ❌ Never |
| national_id (SSN) | PII - Critical | ❌ Never |
| salary | PII - Financial | ❌ Never (only avg/min/max) |
| credit_card | PII - Critical | ❌ Never |
| bank_account | PII - Financial | ❌ Never |
| passport_number | PII - Critical | ❌ Never |
| medical_condition | PHI | ❌ Never (only condition counts) |
| blood_type | PHI | ❌ Never (only type distribution) |
| address | PII | ❌ Never |
| postal_code | PII | ❌ Never |
| city | PII - Location | ❌ Never (only city counts) |
| country | PII - Location | ❌ Never (only country counts) |
| age | PII | ❌ Never (only generation buckets) |
| eye_color | Personal | ❌ Never (only color distribution) |
| favorite_color | Personal | ❌ Never (only color distribution) |
