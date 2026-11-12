#Requires -Version 7.2
function Test-SamplePreflight {
    param(
        [string]$Az,
        [string]$Subscription,
        [string]$Location,
        [string]$KubernetesVersion,
        [string]$OutputDirectory
    )
    $scope = @('--subscription', $Subscription, '--only-show-errors')
    $account = Invoke-CheckedCommand $Az (@('account', 'show', '-o', 'json') + $scope) | ConvertFrom-Json
    if ($account.state -ne 'Enabled') { throw 'The target subscription is not enabled.' }
    $cliVersion = (Invoke-CheckedCommand $Az @('version', '-o', 'json') | ConvertFrom-Json).'azure-cli'
    Write-Host "Using built-in Azure CLI $cliVersion AKS commands in $Location (extensions isolated)."
    $versions = Invoke-CheckedCommand $Az (@('aks', 'get-versions', '--location', $Location, '-o', 'json') + $scope) | ConvertFrom-Json
    $patches = @($versions.values | ForEach-Object { $_.patchVersions.PSObject.Properties.Name })
    if ($KubernetesVersion -notin $patches) { throw "Kubernetes $KubernetesVersion is not offered in $Location." }

    $skus = @(Invoke-CheckedCommand $Az (@('vm', 'list-skus', '--location', $Location,
        '--resource-type', 'virtualMachines', '--all', '-o', 'json') + $scope) | ConvertFrom-Json)
    $usage = @(Invoke-CheckedCommand $Az (@('vm', 'list-usage', '--location', $Location, '-o', 'json') + $scope) | ConvertFrom-Json)
    $required = @{}
    $skuEvidence = @(foreach ($size in @('Standard_D4ds_v6', 'Standard_NCC40ads_H100_v5')) {
        $sku = @($skus | Where-Object name -EQ $size)
        if ($sku.Count -ne 1) { throw "SKU $size was not found in $Location." }
        $sku = $sku[0]
        $regionBlocks = @($sku.restrictions | Where-Object type -EQ 'Location')
        if ($regionBlocks.Count) {
            throw "SKU $size has a regional subscription restriction: $($regionBlocks | ConvertTo-Json -Depth 10 -Compress)"
        }
        $cores = [int]($sku.capabilities | Where-Object name -EQ 'vCPUs').value
        if (-not $required.ContainsKey($sku.family)) { $required[$sku.family] = 0 }
        $required[$sku.family] += $cores
        $sku
    })
    $total = 0
    foreach ($family in $required.Keys) {
        $quota = @($usage | Where-Object { $_.name.value -eq $family })
        if ($quota.Count -ne 1 -or ([int]$quota[0].limit - [int]$quota[0].currentValue) -lt $required[$family]) {
            throw "Insufficient $family quota for $($required[$family]) new vCPUs."
        }
        $total += $required[$family]
    }
    $regional = $usage | Where-Object { $_.name.value -eq 'cores' }
    if (([int]$regional.limit - [int]$regional.currentValue) -lt $total) {
        throw "Insufficient regional vCPU quota for $total cores."
    }
    $feature = Invoke-CheckedCommand $Az (@('feature', 'show', '--namespace', 'Microsoft.ContainerService',
        '--name', 'Ubuntu2404Preview', '--query', 'properties.state', '-o', 'tsv') + $scope)
    $preflight = [ordered]@{
        CheckedAtUtc = [DateTime]::UtcNow.ToString('o')
        Location = $Location
        KubernetesVersion = $KubernetesVersion
        PreviewState = "$feature"
        Skus = $skuEvidence
        Quota = @($usage | Where-Object { $_.name.value -in @($required.Keys) + @('cores') })
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $preflight | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $OutputDirectory 'preflight.json')
    if ($feature -ne 'Registered') { throw "Ubuntu2404Preview is $feature. Arrange subscription registration before deploying." }
    Write-Host 'Preflight passed; no Azure resources were changed.'
}
