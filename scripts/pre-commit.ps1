<#
.SYNOPSIS
    Pre-commit hook: Block secrets, keys, credentials, and Azure resource identifiers.

.DESCRIPTION
    Scans staged files for sensitive patterns before allowing a git commit.
    Place this file (or a copy) at .git/hooks/pre-commit.ps1 and configure
    git to use PowerShell hooks, OR use the companion shell script on *nix/WSL.

    To install automatically, run:
        .\scripts\Install-PreCommitHook.ps1

.NOTES
    Exit 0 = allow commit, Exit 1 = block commit.
    Use "git commit --no-verify" to bypass in emergencies.
#>

$ErrorActionPreference = "Continue"

# Colors
function Write-Blocked($desc, $file, $matches) {
    Write-Host ""
    Write-Host "  ✗ BLOCKED " -ForegroundColor Red -NoNewline
    Write-Host "[$desc]"
    Write-Host "    File: $file" -ForegroundColor Gray
    $shown = 0
    foreach ($m in $matches) {
        if ($shown -ge 5) {
            $remaining = $matches.Count - 5
            Write-Host "    ... and $remaining more matches" -ForegroundColor Gray
            break
        }
        $text = $m.ToString()
        if ($text.Length -gt 120) { $text = $text.Substring(0, 120) + "..." }
        Write-Host "    $text" -ForegroundColor DarkRed
        $shown++
    }
    return 1
}

function Write-Warning-Match($desc, $file, $matches) {
    Write-Host ""
    Write-Host "  ⚠ WARNING " -ForegroundColor Yellow -NoNewline
    Write-Host "[$desc]"
    Write-Host "    File: $file" -ForegroundColor Gray
    $shown = 0
    foreach ($m in $matches) {
        if ($shown -ge 3) { break }
        $text = $m.ToString()
        if ($text.Length -gt 120) { $text = $text.Substring(0, 120) + "..." }
        Write-Host "    $text" -ForegroundColor DarkYellow
        $shown++
    }
    return 1
}

Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Pre-commit secret & credential scan" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

# Get staged files (added or modified, not deleted)
$stagedFiles = git diff --cached --name-only --diff-filter=ACM 2>$null
if (-not $stagedFiles) {
    Write-Host "No staged files to scan." -ForegroundColor Green
    exit 0
}

$blocked = 0
$warnings = 0

# ──────────────────────────────────────────────────────
# Define patterns
# ──────────────────────────────────────────────────────

# BLOCKED patterns: real secrets and specific resource identifiers
$blockedPatterns = @(
    @{
        Pattern     = '/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        Description = "Azure Subscription ID in resource path"
        Exclude     = '<YOUR_|example|sample|placeholder'
    },
    @{
        Pattern     = 'AccountKey=[A-Za-z0-9+/=]{44,}'
        Description = "Azure Storage Account Key"
        Exclude     = $null
    },
    @{
        Pattern     = 'DefaultEndpointsProtocol=https?;AccountName=[^<][^;]+;AccountKey=[A-Za-z0-9+/=]{20,}'
        Description = "Azure Storage connection string with embedded key"
        Exclude     = $null
    },
    @{
        Pattern     = 'SharedAccessSignature=sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&s[a-z]=[a-z]&'
        Description = "Azure SAS token"
        Exclude     = $null
    },
    @{
        Pattern     = '(?i)(client_secret|clientSecret)\s*[:=]\s*["''][A-Za-z0-9~._-]{30,}["'']'
        Description = "Azure AD/Entra ID client secret"
        Exclude     = $null
    },
    @{
        Pattern     = '(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["''][A-Za-z0-9+/=_-]{20,}["'']'
        Description = "API key"
        Exclude     = $null
    },
    @{
        Pattern     = '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
        Description = "Private key (PEM format)"
        Exclude     = $null
    },
    @{
        Pattern     = 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'
        Description = "JWT token"
        Exclude     = $null
    },
    @{
        Pattern     = '(?i)(password|passwd|pwd)\s*[:=]\s*["''][^"<'']{8,}["'']'
        Description = "Hardcoded password"
        Exclude     = 'placeholder|example|YOUR_|<|notmatch|format|Expected'
    },
    @{
        Pattern     = '(?<!\$[\w{}]*)[a-z0-9]{6,}\.vault\.azure\.net'
        Description = "Azure Key Vault endpoint (specific resource name)"
        Exclude     = 'mykeyvault|example|placeholder|kv\*\*\*|\$\{|\$[A-Z]'
    },
    @{
        Pattern     = '(?<!\$[\w{}]*)(?<!<\w*)[a-z0-9]{6,}\.azurecr\.io'
        Description = "Azure Container Registry endpoint (specific resource name)"
        Exclude     = 'myacr|example|placeholder|<registry>|\$\{|\$[A-Z]'
    },
    @{
        Pattern     = '(?i)Server=tcp:[a-z0-9-]+\.(database\.windows\.net|documents\.azure\.com|mongo\.cosmos\.azure\.com)'
        Description = "Azure database connection string"
        Exclude     = $null
    }
)

# WARNING patterns: may be legitimate but worth reviewing
$warningPatterns = @(
    @{
        Pattern     = 'Microsoft\.ManagedIdentity/userAssignedIdentities/'
        Description = "Managed Identity resource ID"
        Exclude     = $null
    },
    @{
        Pattern     = '(?i)resourcegroups/[a-z0-9]+-rg'
        Description = "Specific resource group name"
        Exclude     = '<YOUR_|example|placeholder'
    },
    @{
        Pattern     = '(?i)(proxy_pass|url|endpoint|host)\s*[:=]?\s*(https?://)?((10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})'
        Description = "Private/internal IP address in configuration"
        Exclude     = '^\s*#|^\s*//'
    }
)

# Risky file extensions
$riskyExtensions = @('.pfx', '.p12', '.key', '.pem', '.env')

# ──────────────────────────────────────────────────────
# Scan each staged file
# ──────────────────────────────────────────────────────
foreach ($file in $stagedFiles) {
    # Check risky file extensions
    $ext = [System.IO.Path]::GetExtension($file)
    $basename = [System.IO.Path]::GetFileName($file)

    if ($ext -in $riskyExtensions -or $basename -match '^\.env(\.|$)') {
        Write-Host ""
        Write-Host "  ✗ BLOCKED " -ForegroundColor Red -NoNewline
        Write-Host "[Certificate/key/env file]"
        Write-Host "    File: $file" -ForegroundColor Gray
        $blocked++
        continue
    }

    # Get the staged content of the file
    $content = git show ":$file" 2>$null
    if (-not $content) { continue }

    # Skip binary detection (if content has null bytes, skip)
    if ($content -match '\x00') { continue }

    $lines = $content -split "`n"

    # Check blocked patterns
    foreach ($bp in $blockedPatterns) {
        $matchingLines = @()
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            if ($line -match $bp.Pattern) {
                # Apply exclusion filter
                if ($bp.Exclude -and $line -match $bp.Exclude) { continue }
                $matchingLines += "${lineNum}: $line"
            }
        }
        if ($matchingLines.Count -gt 0) {
            $blocked += Write-Blocked $bp.Description $file $matchingLines
        }
    }

    # Check warning patterns
    foreach ($wp in $warningPatterns) {
        $matchingLines = @()
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            if ($line -match $wp.Pattern) {
                if ($wp.Exclude -and $line -match $wp.Exclude) { continue }
                $matchingLines += "${lineNum}: $line"
            }
        }
        if ($matchingLines.Count -gt 0) {
            $warnings += Write-Warning-Match $wp.Description $file $matchingLines
        }
    }
}

# ──────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "───────────────────────────────────────────────────" -ForegroundColor Cyan

if ($blocked -gt 0) {
    Write-Host "COMMIT BLOCKED: $blocked secret/credential issue(s) found." -ForegroundColor Red
    Write-Host ""
    Write-Host "To fix:" -ForegroundColor White
    Write-Host "  1. Remove the sensitive data from the staged files"
    Write-Host "  2. Add generated files to .gitignore"
    Write-Host "  3. Use 'git rm --cached <file>' for already-tracked files"
    Write-Host ""
    Write-Host "To bypass (emergency only):" -ForegroundColor Yellow
    Write-Host "  git commit --no-verify"
    Write-Host "───────────────────────────────────────────────────" -ForegroundColor Cyan
    exit 1
}
elseif ($warnings -gt 0) {
    Write-Host "COMMIT ALLOWED with $warnings warning(s). Please review above." -ForegroundColor Yellow
    Write-Host "───────────────────────────────────────────────────" -ForegroundColor Cyan
    exit 0
}
else {
    Write-Host "✓ No secrets or credentials detected. Commit OK." -ForegroundColor Green
    Write-Host "───────────────────────────────────────────────────" -ForegroundColor Cyan
    exit 0
}
