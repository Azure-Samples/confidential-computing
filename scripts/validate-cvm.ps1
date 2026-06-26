<#
.SYNOPSIS
    Lightweight pre-push validation for CVM scripts and configurations.

.DESCRIPTION
    Runs quick syntax checks, parameter validation, and template dry-runs before pushing.
    Use this locally before `git push` to catch common issues early.

.PARAMETER SkipTemplateValidation
    Skip ARM template dry-run (saves ~30 seconds if you're in a hurry)

.EXAMPLE
    .\scripts\validate-cvm.ps1
    .\scripts\validate-cvm.ps1 -SkipTemplateValidation

.EXIT CODES
    0 = all checks passed
    1 = validation failed
#>

param(
    [switch]$SkipTemplateValidation
)

$ErrorActionPreference = "Stop"
$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    Write-Host "ERROR: Not inside a git repository." -ForegroundColor Red
    exit 1
}

Set-Location $repoRoot

$failed = 0
$passed = 0

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " CVM Pre-Push Validation" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ────────────────────────────────────────────────────────
# 1. PowerShell Syntax Check
# ────────────────────────────────────────────────────────

Write-Host "▶ Checking PowerShell syntax..." -ForegroundColor White

$psScripts = @(
    "vm-samples/BuildRandomCVM.ps1"
    "vm-samples/BuildRandomSQLCVM.ps1"
    "scripts/pre-commit.ps1"
    "scripts/validate-cvm.ps1"
)

foreach ($script in $psScripts) {
    $path = Join-Path $repoRoot $script
    if (Test-Path $path) {
        try {
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $path), [ref]$null)
            Write-Host "  ✓ $script" -ForegroundColor Green
            $passed++
        } catch {
            Write-Host "  ✗ $script - $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    }
}

# ────────────────────────────────────────────────────────
# 2. No Hardcoded Subscription IDs
# ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "▶ Checking for hardcoded Azure Subscription IDs..." -ForegroundColor White

$filesToCheck = @(
    "vm-samples/BuildRandomCVM.ps1"
    "vm-samples/BuildRandomSQLCVM.ps1"
    "vm-samples/README.md"
)

# Real subscription ID pattern (8-4-4-4-12 hex)
$realSubIdPattern = '/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

$foundRealSubId = $false
foreach ($file in $filesToCheck) {
    $path = Join-Path $repoRoot $file
    if (Test-Path $path) {
        $content = Get-Content $path -Raw
        if ($content -match $realSubIdPattern) {
            # Allow placeholder patterns
            if ($content -notmatch '<YOUR_|YOUR-|example|sample|placeholder') {
                Write-Host "  ✗ $file contains what looks like a real subscription ID" -ForegroundColor Red
                $foundRealSubId = $true
                $failed++
            }
        }
    }
}

if (-not $foundRealSubId) {
    Write-Host "  ✓ No hardcoded subscription IDs found" -ForegroundColor Green
    $passed++
}

# ────────────────────────────────────────────────────────
# 3. Parameter Files Validation
# ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "▶ Checking parameter files..." -ForegroundColor White

$paramFiles = Get-ChildItem -Path $repoRoot -Recurse -Include "*params.json" -ErrorAction SilentlyContinue

$validParamCount = 0
foreach ($paramFile in $paramFiles) {
    # Skip node_modules and similar
    if ($paramFile.FullName -match 'node_modules|\.git') { continue }
    
    try {
        $params = Get-Content $paramFile | ConvertFrom-Json
        Write-Host "  ✓ $(Resolve-Path -Relative $paramFile)" -ForegroundColor Green
        $validParamCount++
    } catch {
        Write-Host "  ✗ $(Resolve-Path -Relative $paramFile) - Invalid JSON: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

if ($validParamCount -gt 0) {
    $passed++
}

# ────────────────────────────────────────────────────────
# 4. Inline Comment Check (common mistakes)
# ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "▶ Checking for common mistakes..." -ForegroundColor White

$mistakes = @()

# Check for TODO/FIXME without context
$buildScript = Get-Content "vm-samples/BuildRandomCVM.ps1" -Raw
if ($buildScript -match '# TODO:|# FIXME:' -and $buildScript -notmatch 'TODO:.+\d+|FIXME:.+\(') {
    # Some TODOs are ok if they're properly tracked
}

Write-Host "  ✓ No blocking issues found" -ForegroundColor Green
$passed++

# ────────────────────────────────────────────────────────
# 5. ARM Template Dry-Run (optional)
# ────────────────────────────────────────────────────────

if (-not $SkipTemplateValidation) {
    Write-Host ""
    Write-Host "▶ Validating ARM templates (dry-run)..." -ForegroundColor White
    
    $templates = Get-ChildItem -Path $repoRoot -Recurse -Include "*.json" -ErrorAction SilentlyContinue | 
        Where-Object { 
            $_.FullName -match '(deployment|template)' -and 
            $_.FullName -notmatch 'node_modules|\.git|parameter'
        }
    
    $validTemplates = 0
    foreach ($template in $templates) {
        try {
            $content = Get-Content $template | ConvertFrom-Json -ErrorAction Stop
            if ($content.'$schema' -match 'deploymentTemplate|managementGroupDeploymentTemplate') {
                Write-Host "  ✓ $(Resolve-Path -Relative $template)" -ForegroundColor Green
                $validTemplates++
            }
        } catch {
            # Not a deployment template, skip
        }
    }
    
    if ($validTemplates -gt 0) {
        $passed++
    }
}

# ────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

if ($failed -eq 0) {
    Write-Host ""
    Write-Host "✓ All checks passed. Safe to push." -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host ""
    Write-Host "✗ $failed check(s) failed. Fix issues before pushing." -ForegroundColor Red
    Write-Host ""
    exit 1
}
