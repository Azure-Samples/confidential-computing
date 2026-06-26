<#
.SYNOPSIS
    Pre-push hook: run CVM validation before pushing.

.DESCRIPTION
    Runs scripts/validate-cvm.ps1 and blocks the push when checks fail.

.NOTES
    Exit 0 = allow push, Exit 1 = block push.
    Use "git push --no-verify" to bypass in emergencies.
#>

$ErrorActionPreference = "Stop"
$repoRoot = git rev-parse --show-toplevel 2>$null

if (-not $repoRoot) {
    Write-Host "ERROR: Not inside a git repository." -ForegroundColor Red
    exit 1
}

Set-Location $repoRoot

if (-not (Test-Path "./scripts/validate-cvm.ps1")) {
    Write-Host "ERROR: Missing ./scripts/validate-cvm.ps1 - blocking push." -ForegroundColor Red
    exit 1
}

$validationOutput = & ./scripts/validate-cvm.ps1 2>&1 | Out-String
$validationExitCode = $LASTEXITCODE

Write-Host $validationOutput

# Best-effort PR comment: do not block push if GitHub comment fails.
if (Get-Command gh -ErrorAction SilentlyContinue) {
    $prNumber = & gh pr view --json number -q .number 2>$null
    if ($LASTEXITCODE -eq 0 -and $prNumber) {
        $branch = git rev-parse --abbrev-ref HEAD
        $statusLabel = if ($validationExitCode -eq 0) { "PASS" } else { "FAIL" }
        $statusIcon = if ($validationExitCode -eq 0) { "✅" } else { "❌" }

        $lines = $validationOutput -split "`r?`n"
        $maxLines = 200
        if ($lines.Count -gt $maxLines) {
            $lines = $lines[($lines.Count - $maxLines)..($lines.Count - 1)]
            $lines = @("[truncated to last $maxLines lines]") + $lines
        }
        $trimmedOutput = ($lines -join "`n").Trim()

        $commentBody = @"
## $statusIcon Local Pre-Push CVM Validation: $statusLabel

- Branch: $branch
- Timestamp (UTC): $(Get-Date -Format "u")

```text
$trimmedOutput
```
"@

        & gh pr comment $prNumber --body $commentBody 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Posted validation results to PR #$prNumber" -ForegroundColor Green
        } else {
            Write-Host "WARNING: Failed to post validation comment to PR #$prNumber" -ForegroundColor Yellow
        }
    }
}

exit $validationExitCode
