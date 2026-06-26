<#
.SYNOPSIS
    Installs local git hooks for this repository.

.DESCRIPTION
    Copies the PowerShell pre-commit and pre-push hooks into .git/hooks/
    and creates shell wrappers so git can invoke them on any platform.

.EXAMPLE
    .\scripts\Install-PreCommitHook.ps1
#>

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    Write-Host "ERROR: Not inside a git repository." -ForegroundColor Red
    exit 1
}

$hooksDir = Join-Path $repoRoot ".git" "hooks"
$sourcePreCommitScript = Join-Path $repoRoot "scripts" "pre-commit.ps1"
$sourcePrePushScript = Join-Path $repoRoot "scripts" "pre-push.ps1"
$targetPreCommitHook = Join-Path $hooksDir "pre-commit"
$targetPrePushHook = Join-Path $hooksDir "pre-push"

if (-not (Test-Path $sourcePreCommitScript)) {
    Write-Host "ERROR: Source script not found at: $sourcePreCommitScript" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $sourcePrePushScript)) {
    Write-Host "ERROR: Source script not found at: $sourcePrePushScript" -ForegroundColor Red
    exit 1
}

# Copy the PowerShell scripts into .git/hooks/
Copy-Item $sourcePreCommitScript (Join-Path $hooksDir "pre-commit.ps1") -Force
Copy-Item $sourcePrePushScript (Join-Path $hooksDir "pre-push.ps1") -Force

# Create shell wrappers that call PowerShell (works on Windows Git Bash and *nix)
$preCommitHookContent = @'
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

$prePushHookContent = @'
#!/bin/sh
# Auto-generated wrapper - calls the PowerShell pre-push hook
# To update, re-run: .\scripts\Install-PreCommitHook.ps1

# Try pwsh (PowerShell 7+) first, fall back to powershell
if command -v pwsh >/dev/null 2>&1; then
    pwsh -NoProfile -ExecutionPolicy Bypass -File "$(dirname "$0")/pre-push.ps1"
elif command -v powershell >/dev/null 2>&1; then
    powershell -NoProfile -ExecutionPolicy Bypass -File "$(dirname "$0")/pre-push.ps1"
else
    echo "ERROR: PowerShell not found. Blocking push."
    exit 1
fi
'@

Set-Content -Path $targetPreCommitHook -Value $preCommitHookContent -Encoding UTF8 -NoNewline
Set-Content -Path $targetPrePushHook -Value $prePushHookContent -Encoding UTF8 -NoNewline

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host " Git hooks installed successfully!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  pre-commit hook: $targetPreCommitHook" -ForegroundColor Gray
Write-Host "  pre-push hook  : $targetPrePushHook" -ForegroundColor Gray
Write-Host ""
Write-Host "  pre-commit scans every commit for:" -ForegroundColor White
Write-Host "    • Azure subscription IDs in resource paths"
Write-Host "    • Storage account keys & connection strings"
Write-Host "    • SAS tokens, client secrets, API keys"
Write-Host "    • Private keys (PEM), JWT tokens"
Write-Host "    • Generated parameters files like confcom-params.json"
Write-Host "    • Multiline JSON parameter values containing passwords/secrets"
Write-Host "    • Specific Key Vault & ACR endpoint names"
Write-Host "    • Database connection strings"
Write-Host "    • Certificate/key/env files"
Write-Host ""
Write-Host "  pre-push runs: .\scripts\validate-cvm.ps1" -ForegroundColor White
Write-Host "    • PowerShell syntax checks"
Write-Host "    • ARM template validation (dry-run)"
Write-Host "    • Parameter file validation"
Write-Host "    • Does not post GitHub PR comments automatically"
Write-Host ""
Write-Host "  Emergency bypass:" -ForegroundColor Yellow
Write-Host "    git commit --no-verify          (skip pre-commit hook)" -ForegroundColor Gray
Write-Host "    git push --no-verify             (skip pre-push hook)" -ForegroundColor Gray
Write-Host ""
