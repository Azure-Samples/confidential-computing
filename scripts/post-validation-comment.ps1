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
    [string]$OutputFile = "./cvm-validation-results.txt",
    [switch]$Sequential
)

# Ensure we're in the vm-samples directory
$vmSamplesPath = Split-Path -Parent -Path $PSScriptRoot
$vmSamplesPath = Join-Path $vmSamplesPath "vm-samples"
Set-Location $vmSamplesPath

Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "CVM 4-Way Validation Matrix with GitHub PR Comment" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

function Get-AttestationSummary {
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    function Get-FirstMatch {
        param(
            [string]$Source,
            [string[]]$Patterns
        )

        foreach ($pattern in $Patterns) {
            $m = [regex]::Match($Source, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($m.Success) {
                return $m.Groups[1].Value
            }
        }
        return $null
    }

    $attestationType = Get-FirstMatch -Source $Text -Patterns @(
        'x-ms-attestation-type\s*[":=]\s*"?([A-Za-z0-9\-]+)"?',
        '"x-ms-attestation-type"\s*:\s*"([A-Za-z0-9\-]+)"'
    )

    $compliance = Get-FirstMatch -Source $Text -Patterns @(
        'x-ms-compliance-status\s*[":=]\s*"?([A-Za-z0-9\-]+)"?',
        '"x-ms-compliance-status"\s*:\s*"([A-Za-z0-9\-]+)"'
    )

    $secureBoot = Get-FirstMatch -Source $Text -Patterns @(
        'secure-boot\s*[":=]\s*(true|false|True|False)',
        '"secure-boot"\s*:\s*(true|false)',
        'x-ms-runtime-vm-configuration-secure-boot\s*[":=]\s*(true|false|True|False)',
        '"x-ms-runtime-vm-configuration-secure-boot"\s*:\s*(true|false)'
    )
    if ($secureBoot) { $secureBoot = $secureBoot.ToLower() }

    $tpmEnabled = Get-FirstMatch -Source $Text -Patterns @(
        'tpm-enabled\s*[":=]\s*(true|false|True|False)',
        '"tpm-enabled"\s*:\s*(true|false)',
        'x-ms-runtime-vm-configuration-tpm-enabled\s*[":=]\s*(true|false|True|False)',
        '"x-ms-runtime-vm-configuration-tpm-enabled"\s*:\s*(true|false)'
    )
    if ($tpmEnabled) { $tpmEnabled = $tpmEnabled.ToLower() }

    $parts = @()
    if ($attestationType) { $parts += "type=$attestationType" }
    if ($compliance) { $parts += "compliance=$compliance" }
    if ($secureBoot) { $parts += "secureBoot=$secureBoot" }
    if ($tpmEnabled) { $parts += "tpm=$tpmEnabled" }

    if ($parts.Count -eq 0) {
        return "attestation-details-unavailable"
    }

    return ($parts -join ", ")
}

# Capture validation output
$outputLines = @()
$outputLines += "# CVM 4-Way Validation Results"
$outputLines += ""
$outputLines += "**Date:** $(Get-Date -Format 'u')"
$outputLines += ""
$outputLines += "**Execution mode:** $(if ($Sequential) { 'sequential' } else { 'parallel' })"
$outputLines += ""
$outputLines += "| Scenario | Status | Attestation |"
$outputLines += "|----------|--------|-------------|"

$scenarios = @(
    @{name="AMD SEV-SNP v6 Windows"; os="Windows"; region="koreacentral"; vmsize="Standard_DC2as_v6"; basename="amdw"; skipPreflight=$true}
    @{name="AMD SEV-SNP v6 Linux"; os="Ubuntu"; region="koreacentral"; vmsize="Standard_DC2as_v6"; basename="amdl"; skipPreflight=$true}
    @{name="Intel TDX v6 Windows"; os="Windows"; region="westeurope"; vmsize="Standard_DC2es_v6"; basename="tdxw"}
    @{name="Intel TDX v6 Linux"; os="Ubuntu"; region="westeurope"; vmsize="Standard_DC2es_v6"; basename="tdxl"}
)

$passed = 0
$failed = 0

$jobScript = {
    param($scenario, $subscriptionId, $samplesPath)

    Set-Location $samplesPath
    $args = @(
        '-subsID', $subscriptionId,
        '-basename', $scenario.basename,
        '-osType', $scenario.os,
        '-region', $scenario.region,
        '-vmsize', $scenario.vmsize,
        '-smoketest',
        '-DisableBastion'
    )

    if ($scenario.skipPreflight) {
        $args += '-SkipSkuPreflight'
    }

    $output = & ./BuildRandomCVM.ps1 @args *>&1
    $outputText = ($output | Out-String)
    $exitCode = $LASTEXITCODE

    [PSCustomObject]@{
        name = $scenario.name
        outputText = $outputText
        exitCode = $exitCode
    }
}

$results = @()
if ($Sequential) {
    foreach ($scenario in $scenarios) {
        Write-Host "▶ Testing: $($scenario.name)" -ForegroundColor White
        $results += & $jobScript $scenario $subsID $vmSamplesPath
        Write-Host ""
    }
} else {
    Write-Host "Starting all 4 scenarios in parallel..." -ForegroundColor Cyan
    $jobs = @()
    foreach ($scenario in $scenarios) {
        $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $scenario, $subsID, $vmSamplesPath
    }

    Wait-Job -Job $jobs | Out-Null
    $results = $jobs | Receive-Job
    $jobs | Remove-Job -Force | Out-Null
}

foreach ($scenario in $scenarios) {
    $result = $results | Where-Object { $_.name -eq $scenario.name } | Select-Object -First 1
    if (-not $result) {
        Write-Host "  ✗ $($scenario.name) FAILED: no result" -ForegroundColor Red
        $outputLines += "| $($scenario.name) | ❌ FAIL | result-unavailable |"
        $failed++
        continue
    }

    $attestationStr = Get-AttestationSummary -Text $result.outputText

    $sawCompletion = $result.outputText -match 'Build and attestation complete'
    $sawFatalError = $result.outputText -match 'ERROR:\s|FAILED:\s|VM deployment failed'
    $isPass = ($result.exitCode -eq 0 -or $null -eq $result.exitCode) -and $sawCompletion -and (-not $sawFatalError)

    if ($isPass) {
        Write-Host "  ✓ $($scenario.name) PASSED" -ForegroundColor Green
        $outputLines += "| $($scenario.name) | ✅ PASS | $attestationStr |"
        $passed++
    } else {
        Write-Host "  ✗ $($scenario.name) FAILED" -ForegroundColor Red
        $errorHint = if ($result.outputText -match 'NotAvailableForSubscription') { 'sku-not-available-for-subscription' } elseif ($result.outputText -match 'Run-command extension busy') { 'run-command-timeout-or-busy' } else { 'deployment-or-attestation-failure' }
        $outputLines += "| $($scenario.name) | ❌ FAIL | $attestationStr ($errorHint) |"
        $failed++
    }
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
