# Validation Automation

## Current Behavior

Validation results are posted as comments on the active GitHub pull request.
Commit-message annotation is no longer used.

## Local Hooks

Run once per clone:

```powershell
.\scripts\Install-PreCommitHook.ps1
```

This installs:
- `pre-commit`: secret scan (`scripts/pre-commit.ps1`)
- `pre-push`: validation (`scripts/validate-cvm.ps1`) and PR comment posting

## Pre-Push PR Comment Posting

On `git push`:
1. `scripts/validate-cvm.ps1` runs
2. Push is blocked if validation fails
3. A best-effort PR comment is posted with validation output when:
   - `gh` CLI is installed
   - current branch has an active PR

If PR comment posting fails, push behavior is unchanged (non-blocking).

## Manual 4-Way Validation Comment

For full AMD/TDX x Windows/Linux smoke validation and PR comment:

```powershell
.\scripts\post-validation-comment.ps1 -subsID "68432aaa-6eba-435c-bc7c-1d998d835e80"
```

## GitHub Actions (Temporary Reduced Mode)

Until service principal secrets are available, CI runs only:
- Secret scan
- Syntax and parameter validation

Cloud deployment matrix checks are disabled in `.github/workflows/cvm-validation.yml`.

## Re-Enable Full CI Matrix Later

When ready, restore matrix job and add:
- `AZURE_CREDENTIALS`
- `AZURE_SUBSCRIPTION_ID`

## Troubleshooting

Check GitHub CLI:

```bash
gh --version
gh auth status
```

Emergency bypass:

```bash
git commit --no-verify
git push --no-verify
```
