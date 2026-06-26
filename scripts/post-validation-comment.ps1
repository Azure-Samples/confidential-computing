<#
.SYNOPSIS
Captures CVM 4-way validation output and posts it as a GitHub PR comment.

.DESCRIPTION
Runs the 4-way CVM validation matrix, captures results, and posts them as a comment
on the active pull request using the GitHub CLI.

.PARAMETER subsID
Azure Subscription ID for deployments.

.PARAMETER OutputFile
Path to save validation output before posting.

.EXAMPLE
.\post-validation-comment.ps1 -subsID "68432aaa-6eba-435c-bc7c-1d998d835e80"
#>

param(
    [string]$subsID = "68432aaa-6eba-435c-bc7c-1d998d835e80",
    [string]$OutputFile = "./cvm-validation-results.txt"
)

# Ensure we're in the vm-samples directory
$vmSamplesPath = Split-Path -Parent -Path $PSScriptRoot
$vmSamplesPath = Join-Path $vmSamplesPath "vm-samples"
Set-Location $vmSamplesPath

Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "CVM 4-Way Validation Matrix with GitHub PR Comment" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Capture validation output
$outputLines = @()
$outputLines += "# CVM 4-Way Validation Results"
$outputLines += ""
$outputLines += "**Date:** $(Get-Date -Format 'u')"
$outputLines += ""
$outputLines += "| Scenario | Status | Attestation |"
$outputLines += "|----------|--------|-------------|"

$scenarios = @(
    @{name="AMD SEV-SNP v6 Windows"; os="Windows"; region="koreacentral"; vmsize="Standard_DC2as_v6"; basename="amdw"}
    @{name="AMD SEV-SNP v6 Linux"; os="Ubuntu"; region="koreacentral"; vmsize="Standard_DC2as_v6"; basename="amdl"}
    @{name="Intel TDX v6 Windows"; os="Windows"; region="westeurope"; vmsize="Standard_DC2es_v6"; basename="tdxw"}
    @{name="Intel TDX v6 Linux"; os="Ubuntu"; region="westeurope"; vmsize="Standard_DC2es_v6"; basename="tdxl"}
)

$passed = 0
$failed = 0

foreach($scenario in $scenarios) {
    Write-Host "▶ Testing: $($scenario.name)" -ForegroundColor White
    
    try {
        $output = & ./BuildRandomCVM.ps1 -subsID $subsID -basename $scenario.basename -osType $scenario.os -region $scenario.region -vmsize $scenario.vmsize -smoketest -DisableBastion -ErrorAction Stop 2>&1
        
        # Extract attestation info
        $attestationMatch = $output | Select-String -Pattern "(x-ms-attestation-type|x-ms-compliance-status|ATTEST_TYPE|COMPLIANCE|SECURE_BOOT|TPM_ENABLED)" | Select-Object -First 3
        $attestationStr = if ($attestationMatch) { ($attestationMatch | ForEach-Object {$_.Line.Trim()}) -join " / " } else { "N/A" }
        
        Write-Host "  ✓ $($scenario.name) PASSED" -ForegroundColor Green
        $outputLines += "| $($scenario.name) | ✅ PASS | $attestationStr |"
        $passed++
    } 
    catch {
        Write-Host "  ✗ $($scenario.name) FAILED: $_" -ForegroundColor Red
        $outputLines += "| $($scenario.name) | ❌ FAIL | Error: $_ |"
        $failed++
    }
    
    Write-Host ""
}

$outputLines += ""
$outputLines += "## Summary"
$outputLines += ""
$outputLines += "- **Passed:** $passed"
$outputLines += "- **Failed:** $failed"
$outputLines += "- **Result:** $(if ($failed -eq 0) {'✅ All tests passed'} else {'❌ Some tests failed'})"
$outputLines += ""

# Save to file
$outputLines | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "Validation output saved to: $OutputFile" -ForegroundColor Yellow

# Try to post as GitHub PR comment
try {
    # Check if GitHub CLI is available
    $ghVersion = & gh --version 2>$null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Posting comment to active pull request..." -ForegroundColor Cyan
        
        # Get the current PR number (if on a PR branch)
        $prNumber = & gh pr view --json number -q .number 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $prNumber) {
            $commentBody = $outputLines -join "`n"
            & gh pr comment $prNumber --body $commentBody
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✓ Comment posted to PR #$prNumber" -ForegroundColor Green
            } else {
                Write-Host "⚠ Failed to post comment (error: $LASTEXITCODE)" -ForegroundColor Yellow
                Write-Host "Run manually: gh pr comment <PR_NUMBER> --body-file $OutputFile" -ForegroundColor Yellow
            }
        } else {
            Write-Host "⚠ No active PR found on this branch" -ForegroundColor Yellow
            Write-Host "To post manually, run:" -ForegroundColor Yellow
            Write-Host "  gh pr comment <PR_NUMBER> --body-file '$OutputFile'" -ForegroundColor Cyan
        }
    } else {
        Write-Host "⚠ GitHub CLI (gh) not found. Install from: https://cli.github.com/" -ForegroundColor Yellow
        Write-Host "Validation output saved to: $OutputFile" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "⚠ Error posting comment: $_" -ForegroundColor Yellow
    Write-Host "Output saved to: $OutputFile" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Validation Complete" -ForegroundColor $(if($failed -eq 0) { "Green" } else { "Red" })
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
