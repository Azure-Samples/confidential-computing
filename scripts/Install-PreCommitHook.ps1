<#
.SYNOPSIS
    Installs the pre-commit secret-scanning hook for this repository.

.DESCRIPTION
    Copies the PowerShell pre-commit hook into .git/hooks/ and creates
    a shell wrapper so git can invoke it on any platform.

.EXAMPLE
    .\scripts\Install-PreCommitHook.ps1
#>

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    Write-Host "ERROR: Not inside a git repository." -ForegroundColor Red
    exit 1
}

$hooksDir = Join-Path $repoRoot ".git" "hooks"
$sourceScript = Join-Path $repoRoot "scripts" "pre-commit.ps1"
$targetHook = Join-Path $hooksDir "pre-commit"

if (-not (Test-Path $sourceScript)) {
    Write-Host "ERROR: Source script not found at: $sourceScript" -ForegroundColor Red
    exit 1
}

# Copy the PowerShell script into .git/hooks/
Copy-Item $sourceScript (Join-Path $hooksDir "pre-commit.ps1") -Force

# Create a shell wrapper that calls PowerShell (works on Windows Git Bash and *nix)
$hookContent = @'
#!/bin/sh
# Auto-generated wrapper - calls the PowerShell pre-commit hook
# To update, re-run: .\scripts\Install-PreCommitHook.ps1

# Try pwsh (PowerShell 7+) first, fall back to powershell
if command -v pwsh >/dev/null 2>&1; then
    pwsh -NoProfile -ExecutionPolicy Bypass -File "$(dirname "$0")/pre-commit.ps1"
elif command -v powershell >/dev/null 2>&1; then
    powershell -NoProfile -ExecutionPolicy Bypass -File "$(dirname "$0")/pre-commit.ps1"
else
    echo "WARNING: PowerShell not found - running shell-based pre-commit hook"
    # Fall back to the shell version if present
    SHELL_HOOK="$(cd "$(git rev-parse --show-toplevel)" && pwd)/.git/hooks/pre-commit-shell"
    if [ -f "$SHELL_HOOK" ]; then
        exec "$SHELL_HOOK"
    else
        echo "No fallback hook found. Allowing commit."
        exit 0
    fi
fi
'@

Set-Content -Path $targetHook -Value $hookContent -Encoding UTF8 -NoNewline

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host " Pre-commit hook installed successfully!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Hook location : $targetHook" -ForegroundColor Gray
Write-Host "  Script source : $sourceScript" -ForegroundColor Gray
Write-Host ""
Write-Host "  The hook will scan every commit for:" -ForegroundColor White
Write-Host "    • Azure subscription IDs in resource paths"
Write-Host "    • Storage account keys & connection strings"
Write-Host "    • SAS tokens, client secrets, API keys"
Write-Host "    • Private keys (PEM), JWT tokens"
Write-Host "    • Specific Key Vault & ACR endpoint names"
Write-Host "    • Database connection strings"
Write-Host "    • Certificate/key/env files"
Write-Host ""
Write-Host "  To bypass in emergencies: git commit --no-verify" -ForegroundColor Yellow
Write-Host ""
