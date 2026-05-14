# Federated Confidential Computing Demo Script

> **Duration:** ~3 minutes  
> **Focus:** Federated privacy-preserving analysis where each company processes its own data locally inside a TEE and only shares aggregate insights — never raw PII.

---

## Setup (Before Demo)

Ensure all four containers are deployed and healthy:
- **Woodgrove Bank** (orchestrator) — port 80
- **Contoso** (data provider) — port 8081
- **Fabrikam** (data provider) — port 8082
- **Wingtip Toys** (data provider) — port 8083

---

## [0:00 – 0:30] Introduction & Context

**Talk track:**

> "Today I'm going to show you how multiple companies can collaborate on workforce analytics without ever sharing sensitive employee data.
>
> We have three companies — Contoso, Fabrikam, and Wingtip Toys — each holding highly sensitive employee records: names, national IDs, credit card numbers, medical conditions, passport numbers, and more.
>
> The problem? They want combined insights — salary benchmarks, generational workforce trends, geographic distribution — but regulatory and privacy constraints mean **no company can send PII outside its own boundary**.
>
> Our solution uses Azure Confidential Computing with AMD SEV-SNP hardware to run each company's data inside a Trusted Execution Environment (TEE). A fourth container — Woodgrove Bank — orchestrates the analysis but **never sees any raw data**."

**Action:** Open Woodgrove Bank's web interface in the browser.

---

## [0:30 – 1:15] Show the Data & Encryption

**Talk track:**

> "Let me first show you what's actually in each company's data. Each has 250 employee records with 18 highly sensitive fields — names, emails, phone numbers, dates of birth, national IDs, salary, credit card numbers, bank accounts, passport numbers, medical conditions, and blood types."

**Action:** Click **"List Saved Data"** on the Woodgrove container. Show the encrypted view.

> "Notice that even Woodgrove — the orchestrator — can only see encrypted ciphertext. The data was encrypted at rest with each company's own key, released only via AMD SEV-SNP attestation. No one, not even Microsoft or the cloud provider, can read this data outside the TEE."

**Action:** Point out the encrypted columns and the "Unable to Decrypt Contents" rows for other companies' records.

---

## [1:15 – 2:15] Run Federated Analysis

**Talk track:**

> "Now here's the key innovation. Instead of gathering all data centrally, we use a **federated model**. Watch what happens when I start the analysis."

**Action:** Scroll to the **"Federated Partner Analysis"** section and click **"Start Federated Analysis"**.

> "Each company's container is now:
> 1. Receiving the analysis request
> 2. Decrypting its own data **locally inside its own TEE**
> 3. Computing aggregate statistics — averages, counts, distributions
> 4. Signing the results with a hardware-attested key
> 5. Sending back **only the aggregates** — no names, no IDs, no PII
>
> Watch the status cards — Contoso... done. Fabrikam... done. Wingtip... done."

**Action:** As results stream in, point to the green status indicators showing each partner completing.

---

## [2:00 – 2:15] Attestation Verification Evidence

**Talk track:**

> "Notice the **Container Attestation Verification** panel that appeared. This proves each company is running the exact approved container image — verified by hardware."

**Action:** Point to the attestation panel showing three cards (Contoso, Fabrikam, Wingtip Toys).

> "For each partner you can see:
> - The **TEE type** — AMD SEV-SNP — the hardware enclave protecting their data
> - **SKR Key Released: Yes** — Azure Key Vault confirmed, through Microsoft Azure Attestation, that this is the genuine approved container before releasing the decryption key
> - **Image Verified: Yes** — the container image hash matches what was approved
> - The **Policy Hash** — a cryptographic fingerprint that binds the exact container code, environment variables, and mount points
> - **File Integrity hashes** — SHA-256 of key application files proving no tampering
>
> If *anyone* — including the cloud provider — modified even one line of code, the policy hash would change, attestation would fail, and the key would **never** be released. This is hardware-enforced trust."

---

## [2:15 – 2:45] Explore the Combined Results

**Talk track:**

> "Now Woodgrove combines the aggregate statistics from all three companies into a unified view. Look at what we can see:"

**Action:** Scroll through the demographics summary showing:
- **750 total staff** across all companies
- **Average salaries** compared side-by-side
- **Generation breakdown** with per-company percentage bars
- **Blood type distribution** — aggregated counts, not individual records
- **Medical conditions** — only "X people have hypertension" not "John Smith has hypertension"
- **World map** showing salary distribution by country
- **Top countries** with city breakdowns

> "Every single insight here was computed **inside** each company's TEE. Woodgrove received only the numbers — the counts, averages, and percentages you see. **Zero PII crossed any network boundary.**"

---

## [2:45 – 3:00] Proof of Privacy

**Talk track:**

> "But don't take my word for it. Scroll down to the Privacy Proof section."

**Action:** Scroll to the **"Raw Partner Responses"** scrollable table.

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
