$logFile = Join-Path $PSScriptRoot "deploy-output.log"
"" | Set-Content $logFile -Force

Push-Location (Join-Path $PSScriptRoot "multi-party-samples\advanced-app")
try {
    & .\Deploy-MultiParty.ps1 -Prefix sgall -Deploy -AKS -Location eastus -SkipBrowser *>&1 | ForEach-Object {
        $_ | Out-File $logFile -Append
        $_
    }
} finally {
    Pop-Location
}
