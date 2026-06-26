# CVM Validation Workflow

This repository uses a two-tier validation system to ensure code quality and security before deployment.

## Local Validation (Before Push)

Run validation checks on your machine before pushing to catch issues early:

```powershell
# From repository root
.\scripts\validate-cvm.ps1
```

### What it checks:
- ✓ PowerShell syntax on all scripts
- ✓ No hardcoded Azure subscription IDs
- ✓ Parameter files are valid JSON
- ✓ ARM templates are valid (optional, use `-SkipTemplateValidation` to skip)
- ✓ Common mistakes and TODOs

**Exit codes:**
- `0` = All checks passed, safe to push
- `1` = Validation failed, fix issues first

## Automated CI/CD Validation (On PR)

When you create or update a pull request, GitHub Actions automatically runs:

### 1. **Secret Scan** (1-2 min)
   - Blocks PRs with hardcoded credentials
   - Scans for Azure subscription IDs, keys, tokens, passwords
   - Uses patterns in `scripts/pre-commit.ps1`

### 2. **Syntax & Parameter Validation** (1-2 min)
   - PowerShell syntax check
   - Parameter file validation
   - Template dry-runs

### 3. **Full CVM Matrix Validation** (12-15 min)
   - Deploys and attests 4 combinations:
     - AMD SEV-SNP v6 Windows
     - AMD SEV-SNP v6 Linux
     - Intel TDX v6 Windows
     - Intel TDX v6 Linux
   - Auto-cleans up test resources
   - Blocks merge if any test fails

## Local Git Hooks (One-Time Setup)

To automatically run secret scanning on every commit:

```powershell
.\scripts\Install-PreCommitHook.ps1
```

This installs both local hooks:
- `pre-commit` → runs `scripts/pre-commit.ps1` (secret/credential scan)
- `pre-push` → runs `scripts/validate-cvm.ps1` (lightweight CVM validation)

Emergency bypass options:
- `git commit --no-verify`
- `git push --no-verify`

## GitHub Secrets Setup

For CI/CD to work, configure these repository secrets in GitHub:

1. **AZURE_CREDENTIALS** — Service Principal credentials (JSON)
   ```json
   {
     "clientId": "...",
     "clientSecret": "...",
     "subscriptionId": "...",
     "tenantId": "..."
   }
   ```
   
2. **AZURE_SUBSCRIPTION_ID** — Target subscription for test deployments

See [Azure/login](https://github.com/azure/login) for setup instructions.

## Troubleshooting

### Local validation fails with "Not inside a git repository"
Ensure you're running the script from within the repo:
```powershell
cd /path/to/confidential-computing
.\scripts\validate-cvm.ps1
```

### CI/CD tests hang or timeout
- VM provisioning takes 5-10 min per test
- GitHub Actions default timeout is 360 min (6 hours)
- If tests exceed timeout, they'll auto-cleanup and fail

### Secret scan blocks a legitimate value
Add it to the `Exclude` pattern in `scripts/pre-commit.ps1` for that check, or use placeholder values in examples (e.g., `YOUR_SUBSCRIPTION_ID`, `example.vault.azure.net`).

### Manual CI/CD trigger
Dispatch the workflow manually from GitHub:
```
Actions > CVM Validation on PR > Run workflow
```

Optional inputs:
- `skipCleanup` — Set to `true` to keep test resources for debugging (manual cleanup required)
