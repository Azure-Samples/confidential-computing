#!/usr/bin/env pwsh
<#
.SYNOPSIS
Post-push hook that runs CVM validation and posts results as GitHub PR comment.

.DESCRIPTION
This hook is triggered after a successful push to run CVM validation and automatically
post the results as a comment on the associated pull request.
#>

param()

# Only run if GitHub CLI is available
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    exit 0
}

# Check if we're on a PR branch
$prNumber = & gh pr view --json number -q .number 2>$null
if ($LASTEXITCODE -ne 0) {
    exit 0  # Not on a PR, skip
}

Write-Host "▶ Running CVM validation and posting results to PR #$prNumber..." -ForegroundColor Cyan

$repoRoot = git rev-parse --show-toplevel
$validationScript = Join-Path $repoRoot "scripts" "post-validation-comment.ps1"

if (Test-Path $validationScript) {
    & $validationScript -subsID "68432aaa-6eba-435c-bc7c-1d998d835e80" | Out-Null
} else {
    Write-Host "⚠ Validation script not found: $validationScript" -ForegroundColor Yellow
}

exit 0
