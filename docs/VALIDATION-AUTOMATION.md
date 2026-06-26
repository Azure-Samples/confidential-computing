# Validation Output Automation — Complete Setup

## Overview

Validation results are now automatically captured in two places:

1. **GitHub PR Comments** — Validation results posted automatically after push (post-push hook)
2. **Commit Messages** — Validation status appended to commit messages (manual or automatic)

---

## Feature 1: GitHub PR Comment Posting (Automatic)

### What It Does
After you `git push`, the post-push hook automatically:
- Runs CVM 4-way validation (if on a PR branch)
- Collects attestation results
- Posts results as a comment on your active GitHub PR
- Does NOT block the push (purely informational)

### Setup
```powershell
# One-time setup for teammates:
.\scripts\Install-PreCommitHook.ps1

# This installs:
# - pre-commit hook (secret scanning)
# - pre-push hook (CVM validation)
# - post-push hook (validation → PR comment)
```

### Usage
```bash
# Normal workflow:
git add <files>
git commit -m "feature: add something"
git push

# ← post-push hook runs automatically
# ← Results posted to GitHub PR (if on PR branch)
```

### Manual Validation + Comment
If you want to run validation and post to PR without waiting:
```powershell
.\scripts\post-validation-comment.ps1 -subsID "68432aaa-6eba-435c-bc7c-1d998d835e80"
```

---

## Feature 2: Commit Message Annotation (Manual)

### What It Does
Appends validation results directly to the commit message for history tracking.

### Usage

**After committing, add validation results to the commit message:**
```powershell
.\scripts\add-validation-to-commit.ps1 -Amend
```

This will:
- Run quick validation (syntax, config checks)
- Append results to the last commit message
- Update the commit (requires force-push if already pushed)

**Just view the results without amending:**
```powershell
.\scripts\add-validation-to-commit.ps1
```

### Example Output
```
feat: add new feature

═══════════════════════════════════════════════════
Validation Results
═══════════════════════════════════════════════════
2026-06-26T14:30:00Z

Branch: exp-ado-vm-svr
Status: ✅ All checks passed

Details:
- ✅ PowerShell syntax valid
```

---

## Git Hook Reference

### Hook Execution Flow

```
┌─────────────────────────────────────────────────────┐
│ git commit <files>                                  │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
         [PRE-COMMIT HOOK]
         scans for secrets
         │
         ├─ Secrets detected? → BLOCK commit
         └─ OK? → Continue

┌────────────────────────────────────────────────────┐
│ git push                                           │
└────────────┬─────────────────────────────────────┘
             │
             ▼
      [PRE-PUSH HOOK]
      validates CVM scripts
      │
      ├─ Errors found? → BLOCK push
      └─ OK? → Continue

             │
             ▼
      [Push to GitHub]
             │
             ▼
      [POST-PUSH HOOK]
      runs validation & posts PR comment
      │
      └─ Errors? → Log silently (doesn't block)
```

### Individual Hook Details

| Hook | Timing | Blocks? | Purpose |
|------|--------|---------|---------|
| **pre-commit** | Before commit | Yes | Scan for hardcoded secrets, API keys, credentials |
| **pre-push** | Before push | Yes | Validate PowerShell syntax, ARM templates, parameter files |
| **post-push** | After successful push | No | Run 4-way CVM validation, post results to GitHub PR |

---

## Emergency Bypass

If a hook is blocking you and you need to push urgently:

```bash
# Skip pre-commit hook (allow any secrets):
git commit --no-verify -m "emergency: skip secret scan"

# Skip pre-push hook (allow validation errors):
git push --no-verify

# Note: post-push hook runs after successful push
#       and doesn't block anything, so no bypass needed
```

⚠️ **Use sparingly!** Hooks exist to prevent secrets and broken code from reaching the repository.

---

## GitHub CLI Requirement

### For PR Comments to Work
The post-push hook requires GitHub CLI (`gh`) to be installed:

**Check if installed:**
```bash
gh --version
```

**Install:**
- Windows: `choco install gh` or download from https://cli.github.com
- macOS: `brew install gh`
- Linux: See https://github.com/cli/cli/blob/trunk/docs/install_linux.md

**Verify authentication:**
```bash
gh auth status
```

### Fallback Behavior
If GitHub CLI is not installed:
- Pre-commit and pre-push hooks work normally
- Post-push hook gracefully skips PR comment posting
- Validation still runs but results don't get posted

---

## Latest Changes

**Commit:** `edfac0d`

```
feat: add validation output to PR comments and commit messages

- add-validation-to-commit.ps1: Appends CVM validation results to commit messages
- post-validation-comment.ps1: Runs 4-way validation and posts results as GitHub PR comment
- post-push.ps1: Git post-push hook to trigger validation comment posting after push
- Install-PreCommitHook.ps1: Updated to install pre-commit, pre-push, and post-push hooks
```

---

## Next Steps for Teammates

1. **Install hooks** (one-time):
   ```powershell
   .\scripts\Install-PreCommitHook.ps1
   ```

2. **Check GitHub CLI is available:**
   ```bash
   gh --version
   ```

3. **Use normally:**
   ```bash
   git commit -m "..."   # ← pre-commit scans for secrets
   git push              # ← pre-push validates scripts
                         # ← post-push posts results to PR
   ```

4. **Optional: Add validation to commit message:**
   ```powershell
   .\scripts\add-validation-to-commit.ps1 -Amend
   ```

---

## Troubleshooting

### "PowerShell not found" error in hooks
**Solution:** Ensure PowerShell 7+ (`pwsh`) or PowerShell 5.1 (`powershell`) is in PATH

### Post-push hook not posting comments
**Causes:**
- GitHub CLI not installed → install via https://cli.github.com
- Not authenticated → run `gh auth login`
- Not on a PR branch → hook silently skips
- Custom branch naming → hook works with any branch, detects PR automatically

### Commit message amendment failed
**Cause:** Already pushed the commit
**Solution:** Use `git push --force-with-lease` to update the remote

---

## Files

- [scripts/add-validation-to-commit.ps1](../../scripts/add-validation-to-commit.ps1)
- [scripts/post-validation-comment.ps1](../../scripts/post-validation-comment.ps1)
- [scripts/post-push.ps1](../../scripts/post-push.ps1)
- [scripts/Install-PreCommitHook.ps1](../../scripts/Install-PreCommitHook.ps1)
