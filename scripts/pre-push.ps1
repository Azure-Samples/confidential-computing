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

& ./scripts/validate-cvm.ps1
exit $LASTEXITCODE
