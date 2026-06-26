param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [Parameter(Mandatory = $true)]
    [string]$Email,

    [ValidateSet("dns-manual", "http-standalone")]
    [string]$Challenge = "dns-manual",

    [switch]$UseStaging
)

$ErrorActionPreference = "Stop"

function Ensure-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

Ensure-Command -Name "docker"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$certRoot = Join-Path $scriptDir "certs"
$liveRoot = Join-Path $certRoot "live"
$workRoot = Join-Path $certRoot "work"
$logsRoot = Join-Path $certRoot "logs"

New-Item -ItemType Directory -Force -Path $liveRoot, $workRoot, $logsRoot | Out-Null

$challengeArgs = @()
switch ($Challenge) {
    "dns-manual" {
        $challengeArgs = @("--manual", "--preferred-challenges", "dns", "--manual-public-ip-logging-ok")
    }
    "http-standalone" {
        $challengeArgs = @("--standalone", "--preferred-challenges", "http")
        Write-Host "HTTP challenge requires inbound port 80 to this machine during validation." -ForegroundColor Yellow
    }
}

$serverArgs = @()
if ($UseStaging) {
    $serverArgs = @("--staging")
    Write-Host "Using Let's Encrypt staging endpoint." -ForegroundColor Yellow
}

$dockerArgs = @(
    "run", "--rm", "-it",
    "-p", "80:80",
    "-v", "$($liveRoot):/etc/letsencrypt",
    "-v", "$($workRoot):/var/lib/letsencrypt",
    "-v", "$($logsRoot):/var/log/letsencrypt",
    "certbot/certbot",
    "certonly",
    "--agree-tos",
    "--no-eff-email",
    "-m", $Email,
    "-d", $Domain
) + $challengeArgs + $serverArgs

Write-Host "Requesting Let's Encrypt certificate for $Domain ..." -ForegroundColor Cyan
& docker @dockerArgs
if ($LASTEXITCODE -ne 0) {
    throw "Certbot failed with exit code $LASTEXITCODE."
}

$fullchainPath = Join-Path $liveRoot "$Domain/fullchain.pem"
$privkeyPath = Join-Path $liveRoot "$Domain/privkey.pem"

if (-not (Test-Path $fullchainPath) -or -not (Test-Path $privkeyPath)) {
    throw "Certificate request completed but expected files were not found."
}

Write-Host "Certificate artifacts created:" -ForegroundColor Green
Write-Host " - Certificate: $fullchainPath" -ForegroundColor Green
Write-Host " - Private key: $privkeyPath" -ForegroundColor Green
Write-Host "" 
Write-Host "Deploy with:" -ForegroundColor Cyan
Write-Host ".\Deploy-AutomotiveMachineVision.ps1 -Deploy -TlsCertPath \"$fullchainPath\" -TlsKeyPath \"$privkeyPath\""
