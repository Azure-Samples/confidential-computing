<#
.SYNOPSIS
    Deploy Norland Citizen Registry on Confidential ACI with Azure SQL confidential computing.

.DESCRIPTION
    Deploys a confidential container (AMD SEV-SNP) running the Republic of Norland
    citizen registry app, connected to Azure SQL Database using DC-series hardware.
    Uses user-assigned managed identity for database authentication. No static database
    credentials are stored in files or passed to the application.

.PARAMETER Prefix
    REQUIRED. Short unique identifier (3-12 chars) to prefix Azure resources.

.PARAMETER Build
    Build and push the container image to ACR.

.PARAMETER Deploy
    Deploy SQL + managed identity, seed data, generate ccepolicy, deploy Confidential ACI.

.PARAMETER Cleanup
    Delete all Azure resources.

.PARAMETER Location
    Azure region for ACI. Defaults to "uaenorth".

.PARAMETER DbLocation
    Azure region for Azure SQL. Defaults to "eastus".

.EXAMPLE
    .\Deploy-CitizenRegistry.ps1 -Prefix "sgall" -Build -Deploy

.EXAMPLE
    .\Deploy-CitizenRegistry.ps1 -Prefix "sgall" -Cleanup
#>
param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-z0-9]{3,12}$')]
    [string]$Prefix,
    [switch]$Build,
    [switch]$Deploy,
    [switch]$Cleanup,
    [string]$Location = "uaenorth",
    [string]$DbLocation = "eastus"
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not ($Build -or $Deploy -or $Cleanup)) {
    throw "Specify one of: -Build, -Deploy, -Cleanup"
}
if (($Build -or $Deploy) -and -not $Prefix) {
    throw "-Prefix is required for Build/Deploy"
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptRoot
$configPath = Join-Path $ScriptRoot "citizen-registry-config.json"
$appDir = Join-Path $ScriptRoot "citizen-registry-app"

$pythonExe = "python"
$venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    $pythonExe = $venvPython
}

function Write-Step([string]$msg) {
    Write-Host "`n=== $msg ===`n" -ForegroundColor Cyan
}

function Write-Success([string]$msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Save-Config($obj) {
    $obj | ConvertTo-Json -Depth 8 | Set-Content -Path $configPath -Encoding UTF8
}

function Load-Config {
    if (-not (Test-Path $configPath)) {
        throw "Missing config file: $configPath. Run -Build first."
    }
    Get-Content $configPath -Raw | ConvertFrom-Json
}

function Get-OwnerUpn {
    $upn = az ad signed-in-user show --only-show-errors --query userPrincipalName -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $upn) {
        $upn = az account show --only-show-errors --query user.name -o tsv 2>$null
    }
    if ($LASTEXITCODE -ne 0 -or -not $upn) {
        throw "Unable to determine signed-in user UPN for owner tag."
    }
    return $upn
}

function Ensure-Docker {
    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $dockerCmd) {
        throw "Docker is not installed. It is required for ccepolicy generation."
    }

    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Docker is running"
        return
    }

    Write-Host "Docker is not running. Attempting to start Docker Desktop..." -ForegroundColor Yellow

    $dockerDesktopPaths = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
    )

    $dockerDesktopPath = $null
    foreach ($path in $dockerDesktopPaths) {
        if (Test-Path $path) {
            $dockerDesktopPath = $path
            break
        }
    }

    if (-not $dockerDesktopPath) {
        throw "Could not find Docker Desktop executable. Start Docker manually and retry."
    }

    Start-Process -FilePath $dockerDesktopPath

    $maxWaitSeconds = 120
    $elapsed = 0
    while ($elapsed -lt $maxWaitSeconds) {
        Start-Sleep -Seconds 5
        $elapsed += 5
        docker info 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker started after ${elapsed}s"
            return
        }
    }

    throw "Docker failed to start within ${maxWaitSeconds}s."
}

function Get-PolicyHashFromConfcom {
    param(
        [string]$TemplatePath,
        [string]$ParamsPath
    )

    $output = "y" | az confcom acipolicygen -a $TemplatePath --parameters $ParamsPath --disable-stdio --approve-wildcards 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to generate ccepolicy: $output"
    }

    $hashLine = $null
    foreach ($line in $output) {
        if ($line -match '([a-f0-9]{64})') {
            $hashLine = $Matches[1]
        }
    }

    if (-not $hashLine) {
        throw "No policy hash found in confcom output."
    }

    return $hashLine.Trim()
}

if ($Cleanup) {
    if (Test-Path $configPath) {
        $cfg = Load-Config
        Write-Step "Cleaning up all resources"

        if ($cfg.containerGroupName) {
            az container delete --resource-group $cfg.resourceGroup --name $cfg.containerGroupName --yes 2>&1 | Out-Null
        }

        if ($cfg.sqlServerName) {
            az sql server delete --resource-group $cfg.resourceGroup --name $cfg.sqlServerName --yes 2>&1 | Out-Null
        }

        if ($cfg.identityName) {
            az identity delete --resource-group $cfg.resourceGroup --name $cfg.identityName 2>&1 | Out-Null
        }

        az group delete --name $cfg.resourceGroup --yes --no-wait
        Remove-Item -Path $configPath -ErrorAction SilentlyContinue
        Write-Success "Cleanup requested for resource group $($cfg.resourceGroup)"
    }
    else {
        throw "Cleanup requested but config file was not found: $configPath"
    }
    return
}

if ($Build) {
    $ownerUpn = Get-OwnerUpn
    $rg = "rg-$Prefix-norland"
    $acr = "${Prefix}noracr"
    $imageName = "norland-citizen-cce"
    $imageTag = "latest"

    Write-Step "Create Resource Group"
    az group create --name $rg --location $Location --tags "owner=$ownerUpn" | Out-Null
    Write-Success "Resource group: $rg"

    Write-Step "Create ACR"
    az acr create --resource-group $rg --name $acr --sku Standard --admin-enabled true --tags "owner=$ownerUpn" | Out-Null
    $acrLogin = az acr show --resource-group $rg --name $acr --query loginServer -o tsv
    Write-Success "ACR: $acrLogin"

    Write-Step "Build and Push Container"
    az acr build --registry $acr --image "${imageName}:${imageTag}" $appDir --no-logs
    if ($LASTEXITCODE -ne 0) {
        throw "Container build failed"
    }

    $cfg = [pscustomobject]@{
        prefix         = $Prefix
        location       = $Location
        dbLocation     = $DbLocation
        resourceGroup  = $rg
        acrName        = $acr
        acrLoginServer = $acrLogin
        image          = "$acrLogin/${imageName}:${imageTag}"
        ownerUpn       = $ownerUpn
    }
    Save-Config $cfg
    Write-Success "Build complete"
}

if ($Deploy) {
    $cfg = Load-Config
    $ownerUpn = Get-OwnerUpn

    Write-Step "Ensure prerequisites"
    az extension add --name confcom --upgrade 2>&1 | Out-Null
    Ensure-Docker

    Write-Step "Create User-Assigned Managed Identity"
    $identityName = "$($cfg.prefix)-nor-citizen-id"
    $null = az identity show --only-show-errors --name $identityName --resource-group $cfg.resourceGroup --query id -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        $subscriptionId = az account show --only-show-errors --query id -o tsv
        $identityPayload = @{ 
            location = $cfg.location
            tags = @{ owner = $ownerUpn }
            properties = @{ isolationScope = "Regional" }
        } | ConvertTo-Json -Depth 6 -Compress

        $identityUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$($cfg.resourceGroup)/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$identityName?api-version=2023-01-31"
        $createOutput = az rest --method put --url $identityUrl --body $identityPayload --only-show-errors 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create managed identity: $createOutput"
        }
        Start-Sleep -Seconds 5
    }
    
    $identityClientId = az identity show --only-show-errors --name $identityName --resource-group $cfg.resourceGroup --query clientId -o tsv 2>&1
    $identityResourceId = az identity show --only-show-errors --name $identityName --resource-group $cfg.resourceGroup --query id -o tsv 2>&1
    
    if (-not $identityClientId -or -not $identityResourceId) {
        throw "Failed to retrieve managed identity details"
    }
    Write-Success "Managed identity ready: $identityName (ID: $identityClientId)"

    Write-Step "Create Azure SQL Server (Entra-only)"
    $sqlServerName = "$($cfg.prefix)-nor-citizen-sql"
    $sqlDbName = "citizendb"

    $deployerUpn = $ownerUpn
    $deployerObjectId = az ad signed-in-user show --only-show-errors --query id -o tsv 2>&1
    if (-not $deployerObjectId -or $deployerObjectId -match "ERROR|error") {
        throw "Failed to retrieve deployer object ID: $deployerObjectId"
    }

    $serverState = az sql server show --only-show-errors --resource-group $cfg.resourceGroup --name $sqlServerName --query state -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        $sqlCreateOutput = az sql server create `
            --name $sqlServerName `
            --resource-group $cfg.resourceGroup `
            --location $cfg.dbLocation `
            --enable-ad-only-auth `
            --external-admin-principal-type User `
            --external-admin-name $deployerUpn `
            --external-admin-sid $deployerObjectId 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Azure SQL server: $sqlCreateOutput"
        }

        $sqlServerId = az sql server show --only-show-errors --resource-group $cfg.resourceGroup --name $sqlServerName --query id -o tsv 2>$null
        if ($sqlServerId) {
            az resource tag --ids $sqlServerId --tags "owner=$ownerUpn" --only-show-errors 1>$null 2>$null
        }
    }
    $sqlFqdn = az sql server show --only-show-errors --resource-group $cfg.resourceGroup --name $sqlServerName --query fullyQualifiedDomainName -o tsv 2>&1
    Write-Success "SQL server: $sqlFqdn"

    Write-Step "Create SQL Database (DC-series)"
    $dbStatus = az sql db show --only-show-errors --resource-group $cfg.resourceGroup --server $sqlServerName --name $sqlDbName --query status -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        az sql db create `
            --resource-group $cfg.resourceGroup `
            --server $sqlServerName `
            --name $sqlDbName `
            --compute-model Provisioned `
            --edition GeneralPurpose `
            --family DC `
            --capacity 2 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create SQL database with DC-series SKU"
        }

        $sqlDbId = az sql db show --only-show-errors --resource-group $cfg.resourceGroup --server $sqlServerName --name $sqlDbName --query id -o tsv 2>$null
        if ($sqlDbId) {
            az resource tag --ids $sqlDbId --tags "owner=$ownerUpn" --only-show-errors 1>$null 2>$null
        }
    }
    Write-Success "SQL database ready: $sqlDbName"

    az sql server firewall-rule create --resource-group $cfg.resourceGroup --server $sqlServerName --name AllowAzureServices --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0 2>&1 | Out-Null

    try {
        $deployerIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
        az sql server firewall-rule create --resource-group $cfg.resourceGroup --server $sqlServerName --name AllowDeployer --start-ip-address $deployerIp --end-ip-address $deployerIp 2>&1 | Out-Null
    }
    catch {
        Write-Warning "Could not detect deployer IP."
    }

    Write-Step "Seed data and grant managed identity DB access"
    $generatorPath = Join-Path $appDir "generate_citizen_data.py"
    $seedPath = Join-Path $appDir "seed-data.sql"
    & $pythonExe $generatorPath --count 100 --output $seedPath
    if ($LASTEXITCODE -ne 0) {
        throw "Seed data generation failed"
    }

    Write-Host "Waiting 30s for identity propagation..." -ForegroundColor Gray
    Start-Sleep -Seconds 30

    & $pythonExe -c @"
import struct
import pyodbc
from azure.identity import DefaultAzureCredential

SQL_COPT_SS_ACCESS_TOKEN = 1256

drivers = set(pyodbc.drivers())
if 'ODBC Driver 18 for SQL Server' in drivers:
    driver = 'ODBC Driver 18 for SQL Server'
elif 'ODBC Driver 17 for SQL Server' in drivers:
    driver = 'ODBC Driver 17 for SQL Server'
else:
    raise RuntimeError(f'No SQL Server ODBC driver found. Installed drivers: {sorted(drivers)}')

credential = DefaultAzureCredential()
token = credential.get_token('https://database.windows.net/.default')
token_bytes = token.token.encode('UTF-16-LE')
token_struct = struct.pack(f'<I{len(token_bytes)}s', len(token_bytes), token_bytes)

conn = pyodbc.connect(
    f'Driver={{{driver}}};'
    'Server=tcp:$sqlFqdn,1433;'
    'Database=$sqlDbName;'
    'Encrypt=yes;TrustServerCertificate=no;',
    attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_struct}
)
cur = conn.cursor()
cur.execute('''
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'citizen_registry')
BEGIN
    CREATE TABLE citizen_registry (
        id INT IDENTITY(1,1) PRIMARY KEY,
        national_id NVARCHAR(20) NOT NULL UNIQUE,
        first_name NVARCHAR(100) NOT NULL,
        last_name NVARCHAR(100) NOT NULL,
        date_of_birth DATE NOT NULL,
        sex NVARCHAR(10) NOT NULL,
        region NVARCHAR(100) NOT NULL,
        municipality NVARCHAR(100) NOT NULL,
        address_line NVARCHAR(200),
        postal_code NVARCHAR(10),
        household_size INT DEFAULT 1,
        marital_status NVARCHAR(20) DEFAULT N'Single',
        employment_status NVARCHAR(30) DEFAULT N'Employed',
        tax_bracket NVARCHAR(10) DEFAULT N'B',
        registered_voter BIT DEFAULT 1
    )
END
''')
conn.commit()

cur.execute("DELETE FROM citizen_registry")
conn.commit()

with open(r'$seedPath', 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if line and line.upper().startswith('INSERT'):
            cur.execute(line.rstrip(';'))
conn.commit()

if not any(row[0] == '$identityName' for row in cur.execute("SELECT name FROM sys.database_principals WHERE type_desc='EXTERNAL_USER'").fetchall()):
    cur.execute("CREATE USER [$identityName] FROM EXTERNAL PROVIDER")
    conn.commit()

for role_sql in [
    "IF NOT EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON m.role_principal_id=r.principal_id JOIN sys.database_principals u ON m.member_principal_id=u.principal_id WHERE r.name='db_datareader' AND u.name='$identityName') ALTER ROLE db_datareader ADD MEMBER [$identityName]",
    "IF NOT EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON m.role_principal_id=r.principal_id JOIN sys.database_principals u ON m.member_principal_id=u.principal_id WHERE r.name='db_datawriter' AND u.name='$identityName') ALTER ROLE db_datawriter ADD MEMBER [$identityName]"
]:
    cur.execute(role_sql)
conn.commit()
conn.close()
print('Database seeded and managed identity grants applied')
"@
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to seed SQL database"
    }

    Write-Success "Database seeded and managed identity grants applied"

    Write-Step "Generate ccepolicy"
    $templateFile = Join-Path $appDir "deployment-template.json"
    $paramsFile = Join-Path $appDir "confcom-params.json"

    $acrUser = az acr credential show --name $cfg.acrName --query username -o tsv
    $acrPass = az acr credential show --name $cfg.acrName --query "passwords[0].value" -o tsv
    $dnsLabel = "norland-$($cfg.prefix)-$(Get-Random -Minimum 1000 -Maximum 9999)"
    $cgName = "$($cfg.prefix)-nor-citizen-cg"

    az acr login --name $cfg.acrName 2>&1 | Out-Null

    $imageRepoTag = $cfg.image.Substring($cfg.acrLoginServer.Length + 1)
    $imageRepo = $imageRepoTag.Split(':')[0]
    $imageTag = $imageRepoTag.Split(':')[1]
    $imageDigest = az acr repository show --name $cfg.acrName --image "$imageRepo`:$imageTag" --query digest -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $imageDigest) {
        throw "Failed to resolve image digest for $($cfg.image)"
    }
    $deployImage = "$($cfg.acrLoginServer)/$imageRepo@$imageDigest"

    $paramObj = @{
        '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
        contentVersion = "1.0.0.0"
        parameters     = @{
            containerGroupName     = @{ value = $cgName }
            dnsNameLabel           = @{ value = $dnsLabel }
            appImage               = @{ value = $deployImage }
            registryServer         = @{ value = $cfg.acrLoginServer }
            registryUsername       = @{ value = $acrUser }
            registryPassword       = @{ value = $acrPass }
            dbHost                 = @{ value = $sqlFqdn }
            dbName                 = @{ value = $sqlDbName }
            managedIdentityClientId = @{ value = $identityClientId }
            identityResourceId     = @{ value = $identityResourceId }
            securityPolicyHash     = @{ value = "" }
            ownerUpn               = @{ value = $ownerUpn }
        }
    }
    $paramObj | ConvertTo-Json -Depth 20 | Set-Content -Path $paramsFile -Encoding UTF8

    $policyHash = Get-PolicyHashFromConfcom -TemplatePath $templateFile -ParamsPath $paramsFile
    $paramsJson = Get-Content $paramsFile -Raw | ConvertFrom-Json
    $paramsJson.parameters.securityPolicyHash.value = $policyHash
    $paramsJson | ConvertTo-Json -Depth 20 | Set-Content -Path $paramsFile -Encoding UTF8

    Write-Step "Deploy Confidential ACI"
    az deployment group create --resource-group $cfg.resourceGroup --template-file $templateFile --parameters @$paramsFile 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "ARM deployment failed"
    }

    $fqdn = az container show --resource-group $cfg.resourceGroup --name $cgName --query ipAddress.fqdn -o tsv

    $cfg | Add-Member -NotePropertyName containerGroupName -NotePropertyValue $cgName -Force
    $cfg | Add-Member -NotePropertyName sqlServerName -NotePropertyValue $sqlServerName -Force
    $cfg | Add-Member -NotePropertyName sqlFqdn -NotePropertyValue $sqlFqdn -Force
    $cfg | Add-Member -NotePropertyName sqlDbName -NotePropertyValue $sqlDbName -Force
    $cfg | Add-Member -NotePropertyName identityName -NotePropertyValue $identityName -Force
    $cfg | Add-Member -NotePropertyName identityClientId -NotePropertyValue $identityClientId -Force
    $cfg | Add-Member -NotePropertyName dnsLabel -NotePropertyValue $dnsLabel -Force
    $cfg | Add-Member -NotePropertyName fqdn -NotePropertyValue $fqdn -Force
    $cfg | Add-Member -NotePropertyName ccePolicyHash -NotePropertyValue $policyHash -Force
    $cfg | Add-Member -NotePropertyName ownerUpn -NotePropertyValue $ownerUpn -Force
    Save-Config $cfg

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "  DEPLOYMENT COMPLETE" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "  Owner:            $ownerUpn"
    Write-Host "  Resource Group:   $($cfg.resourceGroup)"
    Write-Host "  Container Group:  $cgName"
    Write-Host "  SKU:              Confidential (AMD SEV-SNP)"
    Write-Host "  DB:               Azure SQL DC-series"
    Write-Host "  Auth:             Managed Identity (no DB password)"
    Write-Host "  Policy Hash:      $policyHash"
    Write-Host "  App URL:          http://$fqdn"
    Write-Host "  SQL Server:       $sqlFqdn"
    Write-Host "===============================================" -ForegroundColor Green
}
