#Requires -Version 7.2
. (Join-Path $PSScriptRoot '..\Common.ps1')
$script:passed = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:passed++
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Pattern)
    $caught = $false
    try { & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        $caught = $true
    }
    Assert-True $caught "Expected error matching $Pattern."
}

foreach ($kernel in @('6.8.0-1071-azure-fde', '6.8.0-1072-azure-fde', '6.8.0-11000-azure-fde', '6.11.0-1-azure-fde', '7.0.0-1-azure-fde')) {
    Assert-MinimumKernel $kernel
    $script:passed++
}
foreach ($kernel in @('6.8.0-1070-azure-fde', '6.8.0-999-azure-fde', '6.7.0-9999-azure-fde')) {
    Assert-Throws { Assert-MinimumKernel $kernel } 'older'
}
foreach ($kernel in @('6.8.0-1071-azure', '6.8.0-1071-generic', 'garbage')) {
    Assert-Throws { Assert-MinimumKernel $kernel } 'Not an Azure FDE'
}
Assert-Throws { Assert-MinimumKernel '6.8.0-1071-azure-fde' 'garbage' } 'Invalid minimum'
$versions = @'
{"values":[
  {"isPreview":false,"patchVersions":{"1.36.9":{},"1.36.10":{}}},
  {"isPreview":true,"patchVersions":{"1.99.0":{}}},
  {"isPreview":null,"patchVersions":{"1.35.11":{}}}
]}
'@ | ConvertFrom-Json
Assert-True ((Get-LatestKubernetesPatch $versions) -eq '1.36.10') 'Patch selection must be numerical and exclude preview.'
Assert-Throws { Get-LatestKubernetesPatch ([pscustomobject]@{ values = @() }) } 'No stable'

$keyDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "aks-gpu-key-test-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $keyDirectory | Out-Null
$keyPath = Join-Path $keyDirectory 'ssh-key'
try {
    New-SampleSshKey -Path $keyPath
    Assert-True ((Get-Content "$keyPath.pub" -Raw) -match '^ssh-rsa ') 'Expected a real RSA public key.'
    Assert-Throws { New-SampleSshKey -Path (Join-Path $keyDirectory 'missing\ssh-key') } 'ssh-keygen failed'
}
finally {
    foreach ($path in @($keyPath, "$keyPath.pub")) {
        if (Test-Path $path) { Remove-Item -LiteralPath $path -Force }
    }
    Remove-Item -LiteralPath $keyDirectory
}

function Invoke-RestMethod { param($Uri) return @{ token = 'unit-test-token' } }
function Invoke-WebRequest {
    param($Uri, $Headers, [switch]$SkipHttpErrorCheck)
    Assert-True ($Headers.Authorization -eq 'Bearer unit-test-token') 'Registry authentication was not passed.'
    Assert-True ($Uri -like '*/580-6.8.0-1071-azure-fde-ubuntu24.04') 'Driver tag differs from the guide.'
    return $script:response
}
$script:response = @{
    StatusCode = 404
    Content = '{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}'
}
$image = Get-ExactDriverImages '6.8.0-1071-azure-fde' @('580')
Assert-True (-not $image.Available -and $image.HttpStatus -eq 404 -and -not $image.Digest) 'Missing-image evidence was incorrect.'
foreach ($status in @(401, 403, 429, 500)) {
    $script:response = @{ StatusCode = $status }
    Assert-Throws { Get-ExactDriverImages '6.8.0-1071-azure-fde' @('580') } "HTTP $status"
}
$script:response = @{ StatusCode = 404; Content = '{"errors":[{"code":"NAME_UNKNOWN","message":"repository unknown"}]}' }
Assert-Throws { Get-ExactDriverImages '6.8.0-1071-azure-fde' @('580') } 'Unexpected registry 404'
$script:response = @{ StatusCode = 200; Headers = @{ 'Docker-Content-Digest' = @('sha256:' + ('a' * 64)) } }
$image = Get-ExactDriverImages '6.8.0-1071-azure-fde' @('580')
Assert-True ($image.Available -and $image.Digest -eq ('sha256:' + ('a' * 64))) 'Available-image evidence was incorrect.'
$script:response = @{ StatusCode = 200; Headers = @{ 'Docker-Content-Digest' = @('not-a-digest') } }
Assert-Throws { Get-ExactDriverImages '6.8.0-1071-azure-fde' @('580') } 'Missing registry digest'
Remove-Item Function:\Invoke-RestMethod
Remove-Item Function:\Invoke-WebRequest

$workload = @'
apiVersion: batch/v1
kind: Job
metadata:
  name: tf-matmul-demo
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: tf-matmul-demo
        image: tensorflow/tensorflow:2.15.0-gpu
        args:
        - |
          c = tf.matmul(a, b)
'@
$guardedWorkload = Get-GuideWorkloadManifest $workload
Assert-True ($guardedWorkload.Contains('activeDeadlineSeconds: 900')) 'Workload deadline missing.'
Assert-True ($guardedWorkload.Contains('restartPolicy: Never')) 'Workload should not retry indefinitely.'
Assert-True ($guardedWorkload.Contains('runtimeClassName: nvidia')) 'NVIDIA runtime missing.'
Assert-True ($guardedWorkload.Contains('agentpool: gpunp')) 'Workload must target GPU pool.'
Assert-True ($guardedWorkload.Contains('tf.config.set_soft_device_placement(False)')) 'CPU fallback must be disabled.'
Assert-True ($guardedWorkload.Contains("with tf.device('/GPU:0'):")) 'Matmul must explicitly target GPU.'
Assert-True ($guardedWorkload.Contains("assert 'GPU:0' in c.device")) 'Actual tensor device must be checked.'
Assert-True ($guardedWorkload.Contains('image: tensorflow/tensorflow:2.15.0-gpu')) 'Guide workload image changed.'
Assert-Throws { Get-GuideWorkloadManifest ($workload.Replace('c = tf.matmul(a, b)', 'unexpected')) } 'Upstream workload manifest changed'

$script:commands = [System.Collections.Generic.List[string]]::new()
function Invoke-CheckedCommand {
    param([string]$Command, [string[]]$ArgumentList)
    $call = $ArgumentList -join ' '
    $script:commands.Add($call)
    if ($call -like 'aks list *') { return '[]' }
    if ($call -like 'vmss list *') { return '[]' }
    if ($call -like 'vm list *') {
        return '[{"name":"ncc","location":"westeurope","powerState":"VM running","id":"/vm/ncc","hardwareProfile":{"vmSize":"Standard_NCC40ads_H100_v5"}},{"name":"untouched","location":"westeurope","powerState":"VM running","hardwareProfile":{"vmSize":"Standard_D2s_v5"}}]'
    }
    if ($call -like 'vm deallocate *') { return }
    if ($call -like 'vm get-instance-view *') { return $script:power }
    throw "Unexpected test command: $call"
}
Assert-Throws { Stop-ExistingNccCompute -Az az -Subscription test -Location westeurope } 'needs -StopExistingNcc'
Assert-True (-not @($script:commands | Where-Object { $_ -like '* deallocate *' }).Count) 'Read-only inventory modified compute.'
$script:commands.Clear()
$script:power = 'PowerState/deallocated'
Stop-ExistingNccCompute -Az az -Subscription test -Location westeurope -Stop
Assert-True (@($script:commands | Where-Object { $_ -like 'vm deallocate *' }).Count -eq 1) 'Expected exactly one NCC shutdown.'
Assert-True (-not @($script:commands | Where-Object { $_ -like '*untouched*' }).Count) 'Non-NCC VM was modified.'
Assert-True (-not @($script:commands | Where-Object { $_ -notlike '*--subscription test*' }).Count) 'Missing subscription scope.'
$script:power = 'PowerState/running'
Assert-Throws { Stop-ExistingNccCompute -Az az -Subscription test -Location westeurope -Stop } 'did not deallocate'
Remove-Item Function:\Invoke-CheckedCommand

$script:readCount = 0
$script:readyStates = @('Updating', 'Succeeded')
function Invoke-CheckedCommand {
    param([string]$Command, [string[]]$ArgumentList)
    Assert-True ('--subscription' -in $ArgumentList -and 'test' -in $ArgumentList) 'Readiness lookup lost subscription scope.'
    $state = $script:readyStates[[Math]::Min($script:readCount, $script:readyStates.Count - 1)]
    if ($ArgumentList[1] -eq 'show') {
        return (@{ provisioningState = $state } | ConvertTo-Json)
    }
    $script:readCount++
    return "[{`"name`":`"sysnp`",`"provisioningState`":`"$state`"}]"
}
Wait-SampleAksReady az test group cluster -PollSeconds 0
Assert-True ($script:readCount -eq 2) 'Readiness must wait for background AKS operations.'
$script:readyStates = @('Failed')
Assert-Throws { Wait-SampleAksReady az test group cluster -PollSeconds 0 } 'provisioning failed'
$script:readyStates = @('Updating')
Assert-Throws { Wait-SampleAksReady az test group cluster -TimeoutSeconds 0 -PollSeconds 0 } 'did not settle'
Remove-Item Function:\Invoke-CheckedCommand

$script:stopCalls = 0
$script:stopFailures = 1
$script:stopError = '(OperationNotAllowed) There is an in-progress PutExtensionAddonHandler.PUT operation.'
function Invoke-TestAksStop {
    Assert-True (($args -join ' ') -eq 'aks stop -g group -n cluster -o none --subscription test --only-show-errors') 'Shutdown lost explicit target/subscription scope.'
    $script:stopCalls++
    $global:LASTEXITCODE = 0
    if ($script:stopCalls -le $script:stopFailures) {
        $global:LASTEXITCODE = 1
        $script:stopError
    }
}
Stop-SampleAks Invoke-TestAksStop test group cluster -PollSeconds 0
Assert-True ($script:stopCalls -eq 2) 'In-progress operation must be retried.'
foreach ($errorMessage in @('(AuthorizationFailed) Denied',
        '(OperationNotAllowed) Unsupported cluster configuration',
        'There is an in-progress operation, but a different error code')) {
    $script:stopCalls = 0
    $script:stopError = $errorMessage
    Assert-Throws { Stop-SampleAks Invoke-TestAksStop test group cluster -PollSeconds 0 } 'AKS stop failed'
    Assert-True ($script:stopCalls -eq 1) 'Nonretryable shutdown failure was retried.'
}
$script:stopCalls = 0
$script:stopError = '(OperationNotAllowed) There is an in-progress PutExtensionAddonHandler.PUT operation.'
Assert-Throws { Stop-SampleAks Invoke-TestAksStop test group cluster -TimeoutSeconds 0 -PollSeconds 0 } 'remained blocked'
Assert-True ($script:stopCalls -eq 1) 'Expired shutdown deadline must stop retrying.'
Remove-Item Function:\Invoke-TestAksStop
$global:LASTEXITCODE = 0

$script:preflightCommands = [System.Collections.Generic.List[string]]::new()
$script:accountState = 'Enabled'
$script:featureState = 'Registered'
$script:familyLimit = 40
$script:regionalLimit = 44
$script:restricted = $false
function Invoke-CheckedCommand {
    param([string]$Command, [string[]]$ArgumentList)
    $call = $ArgumentList -join ' '
    $script:preflightCommands.Add($call)
    if ($call -eq 'version -o json') { return '{"azure-cli":"2.92.0"}' }
    if ($call -notlike '*--subscription test*') { throw 'Preflight lost subscription scope.' }
    if ($call -like 'account show *') { return "{`"state`":`"$script:accountState`"}" }
    if ($call -like 'aks get-versions *') {
        return '{"values":[{"patchVersions":{"1.36.5":{}}}]}'
    }
    if ($call -like 'vm list-skus *') {
        $restrictions = @(if ($script:restricted) { @{ type = 'Location' } })
        return (ConvertTo-Json -Depth 10 -InputObject @(
            @{ name = 'Standard_D4ds_v6'; family = 'system'; restrictions = @(); capabilities = @(@{ name = 'vCPUs'; value = '4' }) }
            @{ name = 'Standard_NCC40ads_H100_v5'; family = 'ncc'; restrictions = $restrictions; capabilities = @(@{ name = 'vCPUs'; value = '40' }) }
        ))
    }
    if ($call -like 'vm list-usage *') {
        return (ConvertTo-Json -Depth 10 -InputObject @(
            @{ name = @{ value = 'system' }; currentValue = 0; limit = 4 }
            @{ name = @{ value = 'ncc' }; currentValue = 0; limit = $script:familyLimit }
            @{ name = @{ value = 'cores' }; currentValue = 0; limit = $script:regionalLimit }
        ))
    }
    if ($call -like 'feature show *') { return $script:featureState }
    throw "Unexpected preflight command: $call"
}
$preflightDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "aks-gpu-preflight-test-$([guid]::NewGuid())"
try {
    Test-SamplePreflight az test westeurope '1.36.5' $preflightDirectory
    $evidencePath = Join-Path $preflightDirectory 'preflight.json'
    $evidence = Get-Content $evidencePath -Raw | ConvertFrom-Json
    Assert-True ($evidence.Skus.Count -eq 2 -and $evidence.Quota.Count -eq 3) 'Preflight evidence must include both SKUs and all quotas.'
    Assert-True ($evidence.Location -eq 'westeurope' -and $evidence.PreviewState -eq 'Registered') 'Preflight evidence lost location or registration.'
    Assert-True (-not @($script:preflightCommands | Where-Object { $_ -notmatch '^(account show|version|aks get-versions|vm list-skus|vm list-usage|feature show) ' }).Count) 'Preflight modified Azure resources.'
    Assert-Throws { Test-SamplePreflight az test westeurope '1.99.0' $preflightDirectory } 'not offered'
    $script:accountState = 'Disabled'
    Assert-Throws { Test-SamplePreflight az test westeurope '1.36.5' $preflightDirectory } 'not enabled'
    $script:accountState = 'Enabled'
    $script:familyLimit = 39
    Assert-Throws { Test-SamplePreflight az test westeurope '1.36.5' $preflightDirectory } 'Insufficient ncc quota'
    $script:familyLimit = 40
    $script:regionalLimit = 43
    Assert-Throws { Test-SamplePreflight az test westeurope '1.36.5' $preflightDirectory } 'Insufficient regional'
    $script:regionalLimit = 44
    $script:restricted = $true
    Assert-Throws { Test-SamplePreflight az test westeurope '1.36.5' $preflightDirectory } 'regional subscription restriction'
    $script:restricted = $false
    $script:featureState = 'NotRegistered'
    Assert-Throws { Test-SamplePreflight az test westeurope '1.36.5' $preflightDirectory } 'Arrange subscription registration'
}
finally {
    if (Test-Path $preflightDirectory) {
        Remove-Item -LiteralPath (Join-Path $preflightDirectory 'preflight.json') -Force
        Remove-Item -LiteralPath $preflightDirectory
    }
    Remove-Item Function:\Invoke-CheckedCommand
}

$root = Split-Path $PSScriptRoot
foreach ($file in Get-ChildItem $root -Filter '*.ps1' -Recurse | Where-Object FullName -NotMatch '[\\/]\.local[\\/]') {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    Assert-True ($errors.Count -eq 0) "Syntax error in $($file.Name): $errors"
    if ($file.DirectoryName -eq $root) {
        Assert-True ((Get-Content $file.FullName -Raw) -notmatch 'aks-gpu-worker-temp|\.\.\\aks-gpu-worker\\') "Stale sibling dependency in $($file.Name)."
    }
}
$source = Get-Content (Join-Path $root 'Deploy.ps1') -Raw
Assert-True ($source.IndexOf('BlockedMissingGuideDriver') -lt $source.IndexOf("helm @('install'")) 'Missing-driver gate must precede Helm installation.'
Assert-True ($source -match "-Branches @\('580'\)") 'Only the guide driver branch is allowed.'
Assert-True ($source -notmatch 'Install-SignedDriver|driver.enabled=false|apt-get.*linux') 'An alternative host-driver installation was introduced.'
$readme = Get-Content (Join-Path $root 'README.md') -Raw
Assert-True ($readme -notmatch 'GPU-[0-9a-f]{8}-|aks-gpu-worker-temp|aks-gpunp-\d+|aks-sysnp-\d+') 'README contains deployment identifiers or stale names.'
Assert-True ($readme.Contains('Version numbers and exact output may change')) 'Attestation version caveat missing.'
Assert-True ($readme.Contains('GPU Attestation is Successful.') -and $readme.Contains('[Attestation token omitted]')) 'Redacted attestation example missing.'
Write-Host "Passed $script:passed assertions."
