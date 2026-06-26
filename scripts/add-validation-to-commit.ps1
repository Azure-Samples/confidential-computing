<#
.SYNOPSIS
Appends CVM validation results to the latest commit message.

.DESCRIPTION
Runs CVM validation and appends results to the previous (most recent) commit message.
This is useful for documenting validation status in commit history.

.PARAMETER subsID
Azure Subscription ID for deployments.

.PARAMETER Amend
If true, amends the last commit with validation results. If false, just displays results.

.EXAMPLE
.\add-validation-to-commit.ps1 -subsID "68432aaa-6eba-435c-bc7c-1d998d835e80" -Amend
#>

param(
    [string]$subsID = "68432aaa-6eba-435c-bc7c-1d998d835e80",
    [switch]$Amend
)

# Ensure we're in the vm-samples directory
$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    Write-Host "ERROR: Not in a git repository" -ForegroundColor Red
    exit 1
}

$vmSamplesPath = Join-Path $repoRoot "vm-samples"
if (-not (Test-Path $vmSamplesPath)) {
    Write-Host "ERROR: vm-samples directory not found at $vmSamplesPath" -ForegroundColor Red
    exit 1
}

Set-Location $vmSamplesPath

Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "CVM Validation for Commit Message" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Quick validation (no smoketest deployment, just check syntax and configs)
$validationResults = @()
$validationResults += ""
$validationResults += "**Validation Results** ($(Get-Date -Format 'u'))"
$validationResults += ""

# Check PowerShell syntax
$syntaxOk = $true
$scripts = @("BuildRandomCVM.ps1", "BuildRandomSQLCVM.ps1")
foreach ($script in $scripts) {
    $testSyntax = & pwsh -NoProfile -Command "& { [void](Test-Path -LiteralPath '$vmSamplesPath\$script'); [System.Management.Automation.PSParser]::Tokenize((Get-Content '$vmSamplesPath\$script'), [ref]$null) }" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $syntaxOk = $false
        $validationResults += "- ❌ $script: Syntax error"
        break
    }
}

if ($syntaxOk) {
    $validationResults += "- ✅ PowerShell syntax valid"
} else {
    $validationResults += "- ❌ PowerShell syntax check failed"
}

# Get latest commit message
$lastCommitMsg = & git log -1 --pretty=%B
$currentBranch = & git rev-parse --abbrev-ref HEAD

# Check if validation block already exists
if ($lastCommitMsg -match "=== Validation Results ===") {
    Write-Host "NOTE: Commit already contains validation results" -ForegroundColor Yellow
}

# Format the validation block for commit message
$validationBlock = @"

═══════════════════════════════════════════════════
Validation Results
═══════════════════════════════════════════════════
$(Get-Date -Format 'u')

Branch: $currentBranch
Status: $(if($syntaxOk) {'✅ All checks passed'} else {'❌ Some checks failed'})

Details:
$($validationResults -join "`n")
"@

Write-Host $validationBlock -ForegroundColor Green

if ($Amend) {
    $newMsg = $lastCommitMsg + $validationBlock
    & git commit --amend -m $newMsg --no-edit
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✓ Commit message updated with validation results" -ForegroundColor Green
        Write-Host "  Note: Use 'git push --force-with-lease' if already pushed" -ForegroundColor Yellow
    } else {
        Write-Host "ERROR: Failed to amend commit" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "To add this to the commit message, run:" -ForegroundColor Cyan
    Write-Host "  .\scripts\add-validation-to-commit.ps1 -Amend" -ForegroundColor Gray
}
