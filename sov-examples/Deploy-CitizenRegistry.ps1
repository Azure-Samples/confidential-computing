<#
.SYNOPSIS
    Deploy Norland Citizen Registry on Confidential ACI with SQL Server on AMD CVM.

.DESCRIPTION
    Deploys a confidential container (AMD SEV-SNP) running the Republic of Norland
    citizen registry app, connected to SQL Server hosted on an AMD-based Confidential VM
    (DCadsv6 family). Backend connectivity uses private VNet networking.

.PARAMETER Prefix
    REQUIRED. Short unique identifier (3-12 chars) to prefix Azure resources.

.PARAMETER Build
    Build and push the container image to ACR.

.PARAMETER Deploy
    Deploy SQL Server on AMD CVM, seed data, generate ccepolicy, deploy Confidential ACI.

.PARAMETER Cleanup
    Delete all Azure resources.

.PARAMETER Location
    Azure region for ACI. Defaults to "koreacentral".

.PARAMETER DbLocation
    Azure region for SQL CVM. Defaults to Location when omitted.
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
    [string]$Location = "koreacentral",
    [string]$DbLocation = ""
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

function New-RandomPassword([int]$Length = 24) {
    # Use shell-safe characters to avoid quoting/expansion edge cases across cloud-init, bash, sqlcmd, and connection strings.
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789_-"
    -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
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

    $effectiveDbLocation = if ([string]::IsNullOrWhiteSpace($DbLocation)) { $Location } else { $DbLocation }

    $cfg = [pscustomobject]@{
        prefix         = $Prefix
        location       = $Location
        dbLocation     = $effectiveDbLocation
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

    if ($cfg.dbLocation -ne $cfg.location) {
        Write-Host "Database region $($cfg.dbLocation) overridden to $($cfg.location) for private VNet backend connectivity." -ForegroundColor Yellow
        $cfg.dbLocation = $cfg.location
        Save-Config $cfg
    }

    Write-Step "Ensure prerequisites"
    az extension add --name confcom --upgrade 2>&1 | Out-Null
    Ensure-Docker

    Write-Step "Prepare private VNet networking"
    $vnetName = "$($cfg.prefix)-nor-vnet"
    $aciSubnetName = "aci-subnet"
    $sqlSubnetName = "sql-subnet"
    $appGwSubnetName = "appgw-subnet"
    $vnetCidr = "10.90.0.0/16"
    $aciSubnetCidr = "10.90.1.0/24"
    $sqlSubnetCidr = "10.90.2.0/24"
    $appGwSubnetCidr = "10.90.3.0/24"
    $sqlNsgName = "$($cfg.prefix)-nor-sql-nsg"

    $vnetState = az network vnet show --only-show-errors --resource-group $cfg.resourceGroup --name $vnetName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $vnetState) {
        az network vnet create --only-show-errors --resource-group $cfg.resourceGroup --location $cfg.location --name $vnetName --address-prefixes $vnetCidr --subnet-name $aciSubnetName --subnet-prefixes $aciSubnetCidr | Out-Null
    }

    $aciSubnetState = az network vnet subnet show --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $aciSubnetName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $aciSubnetState) {
        az network vnet subnet create --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $aciSubnetName --address-prefixes $aciSubnetCidr | Out-Null
    }
    az network vnet subnet update --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $aciSubnetName --delegations Microsoft.ContainerInstance/containerGroups | Out-Null

    $sqlSubnetState = az network vnet subnet show --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $sqlSubnetName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $sqlSubnetState) {
        az network vnet subnet create --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $sqlSubnetName --address-prefixes $sqlSubnetCidr | Out-Null
    }

    $appGwSubnetState = az network vnet subnet show --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $appGwSubnetName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $appGwSubnetState) {
        az network vnet subnet create --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $appGwSubnetName --address-prefixes $appGwSubnetCidr | Out-Null
    }

    $sqlNsgState = az network nsg show --only-show-errors --resource-group $cfg.resourceGroup --name $sqlNsgName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $sqlNsgState) {
        az network nsg create --only-show-errors --resource-group $cfg.resourceGroup --location $cfg.location --name $sqlNsgName --tags "owner=$ownerUpn" | Out-Null
    }

    $sqlRuleState = az network nsg rule show --only-show-errors --resource-group $cfg.resourceGroup --nsg-name $sqlNsgName --name allow-sql-from-aci --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $sqlRuleState) {
        az network nsg rule create --only-show-errors --resource-group $cfg.resourceGroup --nsg-name $sqlNsgName --name allow-sql-from-aci --priority 100 --direction Inbound --access Allow --protocol Tcp --source-address-prefixes $aciSubnetCidr --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 1433 | Out-Null
    }

    az network vnet subnet update --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $sqlSubnetName --network-security-group $sqlNsgName | Out-Null

    $aciSubnetId = az network vnet subnet show --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $aciSubnetName --query id -o tsv
    Write-Success "Private networking ready: $vnetName"

    Write-Step "Provision SQL Server on AMD Confidential VM"
    $sqlVmName = "$($cfg.prefix)-nor-sql-cvm"
    # v6-only confidential VM SKUs, in order of preference
    $allowedSqlVmSizes = @(
        "Standard_DC2as_v6",
        "Standard_DC4as_v6",
        "Standard_DC8as_v6",
        "Standard_DC2ads_v6",
        "Standard_DC4ads_v6",
        "Standard_DC8ads_v6",
        "Standard_DC2es_v6",
        "Standard_DC4es_v6",
        "Standard_EC2ads_v6",
        "Standard_EC4ads_v6"
    )
    # Use first available v6 SKU; if none listed as available, try first one anyway (user may have quota)
    $sqlVmSize = $allowedSqlVmSizes[0]
    Write-Host "  Using confidential VM SKU: $sqlVmSize (v6-only enforcement active)"
    $sqlVmImage = "Canonical:ubuntu-22_04-lts:cvm:22.04.202510140"
    $sqlDbName = "citizendb"
    $sqlAppUser = "citizenapp"
    # Generate per-run SQL credentials; do not persist them in repo files.
    $sqlAppPassword = New-RandomPassword 32
    $sqlSaPassword = New-RandomPassword 32
    Write-Host "  Generated ephemeral SQL credentials for this deployment run"
    $vmAdminUser = "azureuser"
    $vmAdminPassword = New-RandomPassword 24

    $vmState = az vm show --only-show-errors --resource-group $cfg.resourceGroup --name $sqlVmName --query provisioningState -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        $cloudInitPath = Join-Path $env:TEMP ("sql-cvm-" + $sqlVmName + ".yaml")
        $cloudInit = @"
#cloud-config
runcmd:
    - export DEBIAN_FRONTEND=noninteractive
    - systemd-run --property="After=apt-daily.service apt-daily-upgrade.service" --wait /bin/true
    - apt-get -o DPkg::Lock::Timeout=120 update
    - apt-get -o DPkg::Lock::Timeout=120 install -y curl gnupg
    - curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
    - echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/mssql-server-2022 jammy main" > /etc/apt/sources.list.d/mssql-server.list
    - echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" > /etc/apt/sources.list.d/msprod.list
    - apt-get -o DPkg::Lock::Timeout=120 update
    - ACCEPT_EULA=Y apt-get -o DPkg::Lock::Timeout=120 install -y mssql-server
    - ACCEPT_EULA=Y apt-get -o DPkg::Lock::Timeout=120 install -y mssql-tools18 unixodbc-dev
    - MSSQL_SA_PASSWORD='$sqlSaPassword' MSSQL_PID=Developer /opt/mssql/bin/mssql-conf -n setup accept-eula
    - systemctl enable mssql-server
    - systemctl start mssql-server
"@
        Set-Content -Path $cloudInitPath -Value $cloudInit -Encoding UTF8

        $vmCreateOutput = az vm create `
            --resource-group $cfg.resourceGroup `
            --name $sqlVmName `
            --location $cfg.dbLocation `
            --image $sqlVmImage `
            --size $sqlVmSize `
            --security-type ConfidentialVM `
            --os-disk-security-encryption-type VMGuestStateOnly `
            --enable-vtpm true `
            --enable-secure-boot true `
            --vnet-name $vnetName `
            --subnet $sqlSubnetName `
            --nsg $sqlNsgName `
            --authentication-type password `
            --admin-username $vmAdminUser `
            --admin-password $vmAdminPassword `
            --custom-data $cloudInitPath `
            --tags "owner=$ownerUpn" --only-show-errors 2>&1
        Remove-Item -Path $cloudInitPath -ErrorAction SilentlyContinue
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create SQL CVM: $vmCreateOutput"
        }
    }

    $sqlPrivateHost = az vm show -d --resource-group $cfg.resourceGroup --name $sqlVmName --query privateIps -o tsv 2>&1
    if (-not $sqlPrivateHost -or $sqlPrivateHost -match "ERROR|error") {
        throw "Failed to retrieve SQL CVM private IP: $sqlPrivateHost"
    }

    $privateZoneName = "norland.internal"
    $sqlRecordName = "sql"
    $sqlPrivateDnsName = "$sqlRecordName.$privateZoneName"
    $dnsZoneState = az network private-dns zone show --only-show-errors --resource-group $cfg.resourceGroup --name $privateZoneName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $dnsZoneState) {
        az network private-dns zone create --only-show-errors --resource-group $cfg.resourceGroup --name $privateZoneName | Out-Null
    }
    $dnsLinkName = "$vnetName-link"
    $dnsLinkState = az network private-dns link vnet show --only-show-errors --resource-group $cfg.resourceGroup --zone-name $privateZoneName --name $dnsLinkName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $dnsLinkState) {
        az network private-dns link vnet create --only-show-errors --resource-group $cfg.resourceGroup --zone-name $privateZoneName --name $dnsLinkName --virtual-network $vnetName --registration-enabled false | Out-Null
    }
    $dnsRecordSetState = az network private-dns record-set a show --only-show-errors --resource-group $cfg.resourceGroup --zone-name $privateZoneName --name $sqlRecordName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $dnsRecordSetState) {
        az network private-dns record-set a create --only-show-errors --resource-group $cfg.resourceGroup --zone-name $privateZoneName --name $sqlRecordName | Out-Null
    }
    $existingDnsIps = az network private-dns record-set a show --only-show-errors --resource-group $cfg.resourceGroup --zone-name $privateZoneName --name $sqlRecordName --query "arecords[].ipv4Address" -o tsv 2>$null
    foreach ($existingIp in $existingDnsIps) {
        if ($existingIp) {
            az network private-dns record-set a remove-record --only-show-errors --resource-group $cfg.resourceGroup --zone-name $privateZoneName --record-set-name $sqlRecordName --ipv4-address $existingIp 2>$null | Out-Null
        }
    }
    az network private-dns record-set a add-record --only-show-errors --resource-group $cfg.resourceGroup --zone-name $privateZoneName --record-set-name $sqlRecordName --ipv4-address $sqlPrivateHost | Out-Null

    Write-Success "SQL CVM ready: $sqlVmName (private $sqlPrivateHost)"

    Write-Step "Initialize SQL schema and application login on CVM"
    $initSqlPath = Join-Path $env:TEMP ("sql-init-" + $sqlVmName + ".sql")
    # Escape single quotes in password for SQL syntax ('' represents one quote in SQL)
    $sqlAppPasswordEscaped = $sqlAppPassword -replace "'", "''"
    $initSql = @"
IF DB_ID(N'$sqlDbName') IS NULL
BEGIN
    CREATE DATABASE [$sqlDbName];
END
GO

IF EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = N'$sqlAppUser')
BEGIN
    ALTER LOGIN [$sqlAppUser] WITH PASSWORD = '$sqlAppPasswordEscaped';
END
ELSE
BEGIN
    CREATE LOGIN [$sqlAppUser] WITH PASSWORD = '$sqlAppPasswordEscaped';
END
GO

-- Keep login default DB aligned with app connection string to avoid 4060.
ALTER LOGIN [$sqlAppUser] WITH DEFAULT_DATABASE = [$sqlDbName];
GO

USE [$sqlDbName];
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$sqlAppUser')
BEGIN
    CREATE USER [$sqlAppUser] FOR LOGIN [$sqlAppUser];
END
GO

-- Rebind user to login in case orphaned principal state exists.
ALTER USER [$sqlAppUser] WITH LOGIN = [$sqlAppUser];
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.database_role_members m
    JOIN sys.database_principals r ON m.role_principal_id = r.principal_id
    JOIN sys.database_principals u ON m.member_principal_id = u.principal_id
    WHERE r.name = 'db_datareader' AND u.name = '$sqlAppUser'
)
BEGIN
    ALTER ROLE db_datareader ADD MEMBER [$sqlAppUser];
END
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.database_role_members m
    JOIN sys.database_principals r ON m.role_principal_id = r.principal_id
    JOIN sys.database_principals u ON m.member_principal_id = u.principal_id
    WHERE r.name = 'db_datawriter' AND u.name = '$sqlAppUser'
)
BEGIN
    ALTER ROLE db_datawriter ADD MEMBER [$sqlAppUser];
END
GO

IF OBJECT_ID(N'dbo.citizen_registry', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.citizen_registry (
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
    );
END
GO
"@
    Set-Content -Path $initSqlPath -Value $initSql -Encoding UTF8

    $initSqlEscaped = (Get-Content -Path $initSqlPath -Raw) -replace "`r", ""
    Remove-Item -Path $initSqlPath -ErrorAction SilentlyContinue

    # Base64-encode the SQL script so multi-line content survives command-line transport
    $initSqlBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($initSqlEscaped))

    # Escape SA password for shell: replace single quotes with '\'' (end quote, escaped quote, start quote)
    $sqlSaPasswordEscaped = $sqlSaPassword -replace "'", "'\\''"
    
    $initOutput = az vm run-command invoke `
        --resource-group $cfg.resourceGroup `
        --name $sqlVmName `
        --command-id RunShellScript `
        --scripts "set -e; export DEBIAN_FRONTEND=noninteractive" `
              "if [ ! -f /lib/systemd/system/mssql-server.service ] || [ ! -x /opt/mssql/bin/mssql-conf ]; then sudo apt-get -o DPkg::Lock::Timeout=120 update; sudo apt-get -o DPkg::Lock::Timeout=120 install -y curl gnupg; curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /tmp/microsoft-prod.gpg; sudo install -o root -g root -m 644 /tmp/microsoft-prod.gpg /usr/share/keyrings/microsoft-prod.gpg; echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/mssql-server-2022 jammy main' | sudo tee /etc/apt/sources.list.d/mssql-server.list >/dev/null; echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main' | sudo tee /etc/apt/sources.list.d/msprod.list >/dev/null; sudo apt-get -o DPkg::Lock::Timeout=120 update; sudo ACCEPT_EULA=Y apt-get -o DPkg::Lock::Timeout=120 install -y mssql-server; fi" `
              "if [ ! -x /opt/mssql-tools18/bin/sqlcmd ]; then sudo ACCEPT_EULA=Y apt-get -o DPkg::Lock::Timeout=120 install -y mssql-tools18 unixodbc-dev; fi" `
              "if [ ! -f /var/opt/mssql/data/master.mdf ]; then sudo env MSSQL_SA_PASSWORD='$sqlSaPasswordEscaped' MSSQL_PID=Developer /opt/mssql/bin/mssql-conf -n setup accept-eula; fi" `
                  "sudo systemctl enable mssql-server" `
                  "sudo systemctl restart mssql-server || sudo systemctl start mssql-server" `
                  "sleep 5" `
                  "echo '$initSqlBase64' | base64 -d > /tmp/init.sql" `
                  "sudo /opt/mssql-tools18/bin/sqlcmd -b -S localhost -U sa -P '$sqlSaPasswordEscaped' -C -i /tmp/init.sql" `
                  "echo 'INIT_COMPLETE'" `
        --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to initialize SQL schema on CVM: $initOutput"
    }
    $initMessage = ($initOutput | ConvertFrom-Json).value[0].message
    if ($initMessage -notmatch 'INIT_COMPLETE') {
        throw "SQL init script did not complete successfully on CVM:`n$initMessage"
    }

    Write-Success "SQL schema and login initialized on CVM"

    Write-Step "Verify SQL app login on CVM"
    $sqlAppPasswordShellEscaped = $sqlAppPassword -replace "'", "'\\''"
    $verifyOutput = az vm run-command invoke `
        --resource-group $cfg.resourceGroup `
        --name $sqlVmName `
        --command-id RunShellScript `
        --scripts "set -e" `
                  "echo 'SET NOCOUNT ON; SELECT DB_NAME() AS db_name, SUSER_SNAME() AS login_name;' > /tmp/verify.sql" `
                  "sudo /opt/mssql-tools18/bin/sqlcmd -b -S localhost -U '$sqlAppUser' -P '$sqlAppPasswordShellEscaped' -d '$sqlDbName' -C -i /tmp/verify.sql" `
                  "echo 'VERIFY_COMPLETE'" `
        --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SQL app login verification failed: $verifyOutput"
    }
    $verifyMessage = ($verifyOutput | ConvertFrom-Json).value[0].message
    if ($verifyMessage -notmatch 'VERIFY_COMPLETE') {
        throw "SQL app login verification did not complete on CVM:`n$verifyMessage"
    }

    Write-Success "SQL app login verified on CVM"

    Write-Step "Generate ccepolicy"
    $legacyParamsFile = Join-Path $appDir "confcom-params.json"
    if (Test-Path $legacyParamsFile) {
        Remove-Item -Path $legacyParamsFile -Force -ErrorAction SilentlyContinue
    }
    $templateSourceFile = Join-Path $appDir "deployment-template.json"
    $runId = [Guid]::NewGuid().ToString("N")
    $templateFile = Join-Path $env:TEMP ("citizen-registry-template-" + $runId + ".json")
    $paramsFile = Join-Path $env:TEMP ("citizen-registry-params-" + $runId + ".json")

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
    Copy-Item -Path $templateSourceFile -Destination $templateFile -Force
    $utf8NoBOM = New-Object System.Text.UTF8Encoding($false)

    try {
        $paramsJson = @{
            '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
            contentVersion = "1.0.0.0"
            parameters     = @{
                containerGroupName  = @{ value = $cgName }
                dnsNameLabel        = @{ value = $dnsLabel }
                appImage            = @{ value = $deployImage }
                registryServer      = @{ value = $cfg.acrLoginServer }
                registryUsername    = @{ value = $acrUser }
                registryPassword    = @{ value = $acrPass }
                aciSubnetResourceId = @{ value = $aciSubnetId }
                dbHost              = @{ value = $sqlPrivateHost }
                dbName              = @{ value = $sqlDbName }
                dbUser              = @{ value = $sqlAppUser }
                dbPassword          = @{ value = $sqlAppPassword }
                dbSaPassword        = @{ value = $sqlSaPassword }
                securityPolicyHash  = @{ value = "" }
                ownerUpn            = @{ value = $ownerUpn }
            }
        }

        [System.IO.File]::WriteAllText($paramsFile, ($paramsJson | ConvertTo-Json -Depth 20), $utf8NoBOM)

        $policyHash = Get-PolicyHashFromConfcom -TemplatePath $templateFile -ParamsPath $paramsFile
        $paramsJson.parameters.securityPolicyHash.value = $policyHash
        [System.IO.File]::WriteAllText($paramsFile, ($paramsJson | ConvertTo-Json -Depth 20), $utf8NoBOM)

        Write-Step "Deploy Confidential ACI"
        $existingCg = az container show --resource-group $cfg.resourceGroup --name $cgName --query name -o tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and $existingCg) {
            Write-Host "  Existing container group found; recreating to apply fresh ephemeral credentials"
            az container delete --resource-group $cfg.resourceGroup --name $cgName --yes 2>&1 | Out-Null
            az container wait --resource-group $cfg.resourceGroup --name $cgName --deleted 2>&1 | Out-Null
        }

        az deployment group create --resource-group $cfg.resourceGroup --template-file $templateFile --parameters "@$paramsFile" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "ARM deployment failed"
        }
    }
    finally {
        Remove-Item -Path $paramsFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $templateFile -Force -ErrorAction SilentlyContinue
    }

    $aciPrivateIp = az container show --resource-group $cfg.resourceGroup --name $cgName --query ipAddress.ip -o tsv
    if (-not $aciPrivateIp) {
        throw "Failed to retrieve ACI private IP after deployment"
    }

    Write-Step "Provision public frontend gateway"
    $appGwName = "$($cfg.prefix)-nor-appgw"
    $appGwPipName = "$($cfg.prefix)-nor-appgw-pip"

    # Application Gateway v2 requires its subnet to allow inbound ephemeral ports 65200-65535.
    # Clear subnet NSG association to avoid blocked gateway management traffic.
    az network vnet subnet update --only-show-errors --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $appGwSubnetName --remove networkSecurityGroup | Out-Null

    $appGwState = az network application-gateway show --only-show-errors --resource-group $cfg.resourceGroup --name $appGwName --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $appGwState) {
        $appGwPipCreate = az network public-ip create --only-show-errors --resource-group $cfg.resourceGroup --location $cfg.location --name $appGwPipName --sku Standard --allocation-method Static --tags "owner=$ownerUpn" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Application Gateway public IP: $appGwPipCreate"
        }
        $appGwCreate = az network application-gateway create --only-show-errors --resource-group $cfg.resourceGroup --location $cfg.location --name $appGwName --sku Standard_v2 --capacity 1 --public-ip-address $appGwPipName --vnet-name $vnetName --subnet $appGwSubnetName --servers $aciPrivateIp --frontend-port 80 --http-settings-port 80 --http-settings-protocol Http --priority 100 --tags "owner=$ownerUpn" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Application Gateway: $appGwCreate"
        }
    }
    else {
        $updated = $false
        $lastUpdateError = $null
        # App Gateway updates can race with platform-side operations; retry transient cancel/supersede responses.
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            $appGwUpdate = az network application-gateway address-pool update --only-show-errors --resource-group $cfg.resourceGroup --gateway-name $appGwName --name appGatewayBackendPool --servers $aciPrivateIp 2>&1
            if ($LASTEXITCODE -eq 0) {
                $updated = $true
                break
            }

            $lastUpdateError = $appGwUpdate
            if ($appGwUpdate -match "CanceledAndSupersededDueToAnotherOperation|Operation was canceled") {
                Start-Sleep -Seconds (5 * $attempt)
                continue
            }

            throw "Failed to update Application Gateway backend pool: $appGwUpdate"
        }

        if (-not $updated) {
            throw "Failed to update Application Gateway backend pool after retries: $lastUpdateError"
        }
    }

    # Create health probe to check Flask app /health endpoint
    $probeState = az network application-gateway probe show --only-show-errors --resource-group $cfg.resourceGroup --gateway-name $appGwName --name "health-probe" --query name -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $probeState) {
        $probeCreate = az network application-gateway probe create --only-show-errors --resource-group $cfg.resourceGroup --gateway-name $appGwName --name "health-probe" --protocol Http --path "/health" --host $aciPrivateIp --port 80 --interval 30 --timeout 30 --threshold 3 --match-status-codes "200" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Warning: Failed to create health probe: $probeCreate"
        }
    }

    # Update HTTP settings to reference the health probe
    $settingsUpdate = az network application-gateway http-settings update --only-show-errors --resource-group $cfg.resourceGroup --gateway-name $appGwName --name appGatewayBackendHttpSettings --probe health-probe 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Warning: Failed to update HTTP settings with probe: $settingsUpdate"
    }

    $frontendPublicIp = az network public-ip show --only-show-errors --resource-group $cfg.resourceGroup --name $appGwPipName --query ipAddress -o tsv

    $cfg | Add-Member -NotePropertyName containerGroupName -NotePropertyValue $cgName -Force
    $cfg | Add-Member -NotePropertyName sqlVmName -NotePropertyValue $sqlVmName -Force
    $cfg | Add-Member -NotePropertyName sqlHost -NotePropertyValue $sqlPrivateDnsName -Force
    $cfg | Add-Member -NotePropertyName sqlPrivateIp -NotePropertyValue $sqlPrivateHost -Force
    $cfg | Add-Member -NotePropertyName sqlDbName -NotePropertyValue $sqlDbName -Force
    $cfg | Add-Member -NotePropertyName sqlDbUser -NotePropertyValue $sqlAppUser -Force
    $cfg | Add-Member -NotePropertyName dnsLabel -NotePropertyValue $dnsLabel -Force
    $cfg | Add-Member -NotePropertyName fqdn -NotePropertyValue $frontendPublicIp -Force
    $cfg | Add-Member -NotePropertyName aciPrivateIp -NotePropertyValue $aciPrivateIp -Force
    $cfg | Add-Member -NotePropertyName appGatewayName -NotePropertyValue $appGwName -Force
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
    Write-Host "  App SKU:          Confidential ACI (AMD SEV-SNP)"
    Write-Host "  DB SKU:           SQL Server on AMD CVM ($sqlVmSize)"
    Write-Host "  DB Host:          $sqlPrivateDnsName ($sqlPrivateHost)"
    Write-Host "  ACI IP:           $aciPrivateIp (private)"
    Write-Host "  Frontend:         Application Gateway public IP"
    Write-Host "  Auth:             SQL login (randomly generated per deployment; not written to repo files)"
    Write-Host "  Policy Hash:      $policyHash"
    Write-Host "  App URL:          http://$frontendPublicIp"
    Write-Host "  SQL VM:           $sqlVmName"
    Write-Host "  App Gateway:      $appGwName"
    Write-Host "===============================================" -ForegroundColor Green
}
