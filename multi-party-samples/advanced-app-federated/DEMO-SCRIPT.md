# Federated Confidential Computing Demo Script

> **Duration:** ~4 minutes  
> **Focus:** Federated privacy-preserving analysis where each company processes its own data locally inside a TEE and only shares aggregate insights — never raw PII.

---

## Setup (Before Demo)

1. Deploy all four containers using the deploy script:
   ```powershell
   .\Deploy-MultiParty.ps1 -Prefix sgall -RegistryName acrhjlxsrnc -Build -Deploy
   ```
2. Verify all four are healthy:
   - **Woodgrove Bank** (orchestrator) — port 80
   - **Contoso** (data provider) — port 8081
   - **Fabrikam** (data provider) — port 8082
   - **Wingtip Toys** (data provider) — port 8083
3. Open **Woodgrove Bank's URL** in a browser (e.g. `http://woodgrove-MMDDTTTT.eastus.azurecontainer.io`).

---

## [0:00 – 0:40] Architecture Overview & Audio Narration

**Action:** The page loads with the **🏗️ Federated Multi-Party Architecture** section expanded at the top, showing the architecture diagram SVG.

**Talk track:**

> "Let me start by showing you the architecture of what we've built. This diagram shows four companies — Contoso, Fabrikam, Wingtip Toys, and Woodgrove Bank — each running inside their own AMD SEV-SNP Trusted Execution Environment on Azure."

**Action:** Click the **"🔊 Explain It"** button next to the diagram. The narration controls panel appears with play/pause, ±5s seek, stop, volume slider, and a progress scrub bar. Click **▶️ Play** to start the ~50-second audio narration (English woman's voice).

> *(Let the TTS narration play while you point to the relevant parts of the diagram. The narration script covers: four companies in TEEs, data encrypted at rest, Woodgrove as analytics partner requesting aggregates only, remote attestation and policy hash matching, hardware-enforced trust.)*

**Action:** When the narration finishes (or stop it early with ⏹), click **"🔇 Hide Narration"** to collapse the controls.

---

## [0:40 – 1:15] Show the Data & Encryption

**Talk track:**

> "Let me show you what's actually in each company's data. Each has 250 employee records with 18 highly sensitive fields — names, emails, phone numbers, dates of birth, national IDs, salary, credit card numbers, bank accounts, passport numbers, medical conditions, and blood types."

**Action:** Click **"List Saved Data"** on the Woodgrove container. Show the encrypted view.

> "Notice that even Woodgrove — the orchestrator — can only see encrypted ciphertext. The data was encrypted at rest with each company's own key, released only via AMD SEV-SNP attestation. No one — not even Microsoft or the cloud provider — can read this data outside the TEE."

**Action:** Point out the encrypted columns and the "Unable to Decrypt Contents" rows for other companies' records.

---

## [1:15 – 2:15] Run Federated Analysis

**Talk track:**

> "Now here's the key innovation. Instead of gathering all data centrally, we use a **federated model**. Watch what happens when I start the analysis."

**Action:** Scroll to the **"Federated Partner Analysis"** section and click **"Start Federated Analysis"**. A progress bar appears showing the current phase.

> "Each company's container is now:
> 1. Receiving the analysis request
> 2. Decrypting its own data **locally inside its own TEE**
> 3. Computing aggregate statistics — averages, counts, distributions
> 4. Signing the results with a hardware-attested key
> 5. Sending back **only the aggregates** — no names, no IDs, no PII
>
> Watch the status cards — Contoso... done. Fabrikam... done. Wingtip... done."

**Action:** As results stream in, point to the green status indicators and the progress bar completing.

---

## [2:15 – 2:45] Attestation Verification & "Explain This"

**Talk track:**

> "Notice the **Container Attestation Verification** panel that appeared. This proves each company is running the exact approved container image — verified by hardware."

**Action:** Point to the attestation panel showing three cards (Contoso, Fabrikam, Wingtip Toys).

> "For each partner you can see:
> - The **TEE type** — AMD SEV-SNP — the hardware enclave protecting their data
> - **SKR Key Released: Yes** — Azure Key Vault confirmed, through Microsoft Azure Attestation, that this is the genuine approved container before releasing the decryption key
> - **Image Verified: Yes** — the container image hash matches what was approved
> - The **Policy Hash** — a cryptographic fingerprint that binds the exact container code, environment variables, and mount points
> - **File Integrity hashes** — SHA-256 of key application files proving no tampering"

**Action:** Click the **"ℹ️ Explain This"** button in the attestation header. A flyout panel expands explaining the two-phase trust chain:

> "This flyout describes the three verification steps:
> 1. **Hardware attestation** — AMD SEV-SNP generates a unique security policy hash for the exact code running in the enclave
> 2. **Key release gate** — MAA confirms the container's `x-ms-sevsnpvm-hostdata` claim matches the approved hash before Key Vault releases any key
> 3. **Cross-verification** — Woodgrove compares each partner's self-reported hash against the expected value baked into its own confcom policy
>
> If *anyone* — including the cloud provider — modified even one line of code, the policy hash would change, attestation would fail, and the key would **never** be released. This is hardware-enforced trust."

**Action:** Click the **✕** or the button again to close the flyout.

---

## [2:45 – 3:30] Explore the Combined Results

**Talk track:**

> "Now Woodgrove combines the aggregate statistics from all three companies into a unified view. Look at what we can see:"

**Action:** Scroll through the demographics summary showing:
- **750 total staff** across all companies (four colour-coded cards)
- **Average salaries** compared side-by-side per company
- **Generation breakdown** (Gen Z / Millennial / Gen X / Baby Boomer) with per-company percentage bars
- **Blood type distribution** — aggregated counts, not individual records
- **Medical conditions** — only "X people have hypertension", not "John Smith has hypertension"
- **World map** showing salary distribution by country (coloured by salary level)
- **Top countries** with city breakdowns

> "Every single insight here was computed **inside** each company's TEE. Woodgrove received only the numbers — the counts, averages, and percentages you see. **Zero PII crossed any network boundary.**"

---

## [3:30 – 4:00] Proof of Privacy

**Talk track:**

> "But don't take my word for it. Scroll down to the Privacy Proof section."

**Action:** Scroll to the **"🔍 Raw Partner Responses (Privacy Proof)"** section. This shows the raw JSON that Woodgrove received from each partner in a scrollable table.

> "This table shows the **exact data** Woodgrove received from each partner. Every cell is an aggregate — record counts, salary averages, generation percentages, blood type counts. There are no names, no social security numbers, no credit card numbers, no addresses.
>
> This is the power of confidential computing with federated analytics: **full collaboration, zero data exposure**. Each company retains sovereignty over its data while everyone benefits from the combined insights."

---

## Key Takeaways

| Principle | How It's Demonstrated |
|-----------|----------------------|
| **Data sovereignty** | Each company's PII never leaves its TEE |
| **Hardware attestation** | AMD SEV-SNP verifies code integrity before key release |
| **Federated analytics** | Local processing, aggregate-only sharing |
| **Cryptographic proof** | Results signed with TEE-attested keys |
| **Zero trust** | Even the orchestrator (Woodgrove) cannot decrypt raw data |

---

## UI Features Reference

| Feature | Location | Visibility |
|---------|----------|------------|
| Architecture diagram (SVG) | Top of page, collapsible `<details>` | Woodgrove only |
| 🔊 Explain It (TTS narration) | Button next to diagram | Woodgrove only |
| Narration controls (play/pause, seek, stop, volume, scrub) | Expands below diagram | Woodgrove only |
| ℹ️ Explain This (attestation flyout) | Attestation panel header | Woodgrove only |
| Progress bar | Below "Start Federated Analysis" | Woodgrove only |
| Demographics summary (cards, charts, map) | Below progress bar | Woodgrove only |
| Raw Partner Responses (JSON table) | Bottom of results | Woodgrove only |
| List Saved Data / Save Data / Retrieve Key | Main section | All containers |

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
