#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$ResourceGroup = "rg-aks-gpu-worker-$(Get-Date -Format yyyyMMddHHmmss)",
    [ValidatePattern('^[a-zA-Z0-9-]+$')][string]$ClusterName = "aks-gpu-worker-$(Get-Date -Format yyyyMMddHHmmss)",
    [string]$Location = 'westeurope',
    [string]$KubernetesVersion,
    [string]$MinimumKernel = '6.8.0-1071-azure-fde',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '.local'),
    [switch]$StopExistingNcc,
    [switch]$PreflightOnly,
    [switch]$KeepRunning
)
. (Join-Path $PSScriptRoot 'Common.ps1')
$oldExtensions = $env:AZURE_EXTENSION_DIR
$oldDynamicInstall = $env:AZURE_EXTENSION_USE_DYNAMIC_INSTALL
$created = $false
$result = [ordered]@{
    StartedAtUtc = [DateTime]::UtcNow.ToString('o')
    SubscriptionId = $SubscriptionId.ToString()
    ResourceGroup = $ResourceGroup
    ClusterName = $ClusterName
    Location = $Location
    Status = 'Preparing'
    VendorSupportValidated = $false
    DriverPath = 'Guide GPU Operator v25.3.1, NVIDIA branch 580 only'
}

function Invoke-Az {
    param([string[]]$Arguments)
    Invoke-CheckedCommand $az ($Arguments + $scope)
}

function Invoke-Kube {
    param([string[]]$Arguments)
    Invoke-CheckedCommand kubectl (@('--kubeconfig', $kubeConfig) + $Arguments)
}

function Wait-GpuJob {
    param([string]$Name, [string]$Namespace, [int]$TimeoutSeconds = 600)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $job = Invoke-Kube @('get', 'job', $Name, '-n', $Namespace, '-o', 'json') | ConvertFrom-Json
        $property = $job.status.PSObject.Properties['conditions']
        $conditions = @(if ($property) { $property.Value })
        if (@($conditions | Where-Object { $_ -and $_.type -eq 'Failed' -and $_.status -eq 'True' }).Count) {
            Save-GpuJobDiagnostics $Name $Namespace
            throw "Job $Namespace/$Name failed. Inspect its pods using the dedicated kubeconfig."
        }
        if (@($conditions | Where-Object { $_ -and $_.type -eq 'Complete' -and $_.status -eq 'True' }).Count) { return }
        Start-Sleep 10
    } while ([DateTime]::UtcNow -lt $deadline)
    Save-GpuJobDiagnostics $Name $Namespace
    throw "Job $Namespace/$Name did not complete within $TimeoutSeconds seconds."
}

function Save-GpuJobDiagnostics {
    param([string]$Name, [string]$Namespace)
    try {
        $pods = Invoke-Kube @('get', 'pods', '-n', $Namespace, '-l', "job-name=$Name", '-o', 'json')
        $pods | Set-Content (Join-Path $runDirectory "$Name-failed-pods.json")
        $log = Invoke-Kube @('logs', '-n', $Namespace, "job/$Name", '--tail=200')
        (($log -join "`n") -replace '(?s)Entity Attestation Token:.*', '[Attestation token omitted]') |
            Set-Content (Join-Path $runDirectory "$Name-failed-log.txt")
    }
    catch { Write-Warning "Unable to capture complete diagnostics for ${Namespace}/${Name}: $($_.Exception.Message)" }
}

try {
    Assert-MinimumKernel $MinimumKernel
    $az = Resolve-AzureCli
    foreach ($tool in @('kubectl', 'helm', 'ssh-keygen')) { Get-Command $tool -CommandType Application -ErrorAction Stop | Out-Null }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $OutputDirectory = (Resolve-Path $OutputDirectory).Path
    $runDirectory = Join-Path $OutputDirectory "$ClusterName-$(Get-Date -Format yyyyMMddHHmmssfff)"
    New-Item -ItemType Directory -Path $runDirectory | Out-Null
    $kubeConfig = Join-Path $runDirectory 'kubeconfig'
    $scope = @('--subscription', $SubscriptionId.ToString(), '--only-show-errors')
    $env:AZURE_EXTENSION_DIR = Join-Path $runDirectory 'cli-extensions-core'
    $env:AZURE_EXTENSION_USE_DYNAMIC_INSTALL = 'no'
    New-Item -ItemType Directory -Path $env:AZURE_EXTENSION_DIR | Out-Null
    $result.EvidenceDirectory = $runDirectory

    $versions = Invoke-Az @('aks', 'get-versions', '-l', $Location, '-o', 'json') | ConvertFrom-Json
    if (-not $KubernetesVersion) {
        $default = @($versions.values | Where-Object { $_.isDefault -eq $true -and $_.isPreview -ne $true })
        if ($default.Count -ne 1) { throw 'Expected exactly one non-preview default AKS minor version.' }
        $KubernetesVersion = Get-LatestKubernetesPatch ([pscustomobject]@{ values = $default })
    }
    $stable = @($versions.values | Where-Object { $_.isPreview -ne $true } |
        ForEach-Object { $_.patchVersions.PSObject.Properties.Name })
    if ($KubernetesVersion -notin $stable) { throw "Non-preview Kubernetes $KubernetesVersion is not offered." }
    $result.KubernetesVersion = $KubernetesVersion
    $exists = Invoke-Az @('group', 'exists', '-n', $ResourceGroup, '-o', 'tsv')
    if ($exists -ne 'false') { throw 'Use a new resource group; this script never adopts or overwrites existing resources.' }

    if (-not $PreflightOnly) {
        Stop-ExistingNccCompute -Az $az -Subscription $SubscriptionId -Location $Location -Stop:$StopExistingNcc
    }
    Test-SamplePreflight -Az $az -Subscription $SubscriptionId -Location $Location `
        -KubernetesVersion $KubernetesVersion -OutputDirectory (Join-Path $runDirectory 'preflight')
    Invoke-CheckedCommand helm @('pull', 'gpu-operator', '--repo', 'https://helm.ngc.nvidia.com/nvidia',
        '--version', 'v25.3.1', '--destination', $runDirectory)
    $chartPath = Join-Path $runDirectory 'gpu-operator-v25.3.1.tgz'
    $result.ChartSha256 = (Get-FileHash $chartPath -Algorithm SHA256).Hash
    if ($PreflightOnly) {
        $result.Status = 'PreflightPassed'
        return
    }

    $sshKey = Join-Path $runDirectory 'ssh-key'
    New-SampleSshKey -Path $sshKey
    Invoke-Az @('group', 'create', '-n', $ResourceGroup, '-l', $Location, '--tags', 'sample=aks-gpu-worker', '-o', 'none')
    $created = $true
    Invoke-Az @('aks', 'create', '-g', $ResourceGroup, '-n', $ClusterName, '-l', $Location,
        '--kubernetes-version', $KubernetesVersion, '--nodepool-name', 'sysnp', '--node-count', '1',
        '--node-vm-size', 'Standard_D4ds_v6', '--os-sku', 'Ubuntu2404', '--ssh-key-value', "$sshKey.pub",
        '--enable-managed-identity', '--network-plugin', 'azure', '--network-plugin-mode', 'overlay',
        '--auto-upgrade-channel', 'none', '--node-os-upgrade-channel', 'None',
        '--tags', 'sample=aks-gpu-worker', '-o', 'none')
    Wait-SampleAksReady $az $SubscriptionId $ResourceGroup $ClusterName
    Invoke-Az @('aks', 'nodepool', 'add', '-g', $ResourceGroup, '--cluster-name', $ClusterName,
        '-n', 'gpunp', '--node-count', '1', '--node-vm-size', 'Standard_NCC40ads_H100_v5',
        '--os-sku', 'Ubuntu2404', '--gpu-driver', 'None', '--node-taints', 'sku=gpu:NoSchedule', '-o', 'none')
    Wait-SampleAksReady $az $SubscriptionId $ResourceGroup $ClusterName

    foreach ($poolName in @('sysnp', 'gpunp')) {
        $pool = Invoke-Az @('aks', 'nodepool', 'show', '-g', $ResourceGroup, '--cluster-name', $ClusterName,
            '-n', $poolName, '-o', 'json') | ConvertFrom-Json
        $upgrades = Invoke-Az @('aks', 'nodepool', 'get-upgrades', '-g', $ResourceGroup,
            '--cluster-name', $ClusterName, '-n', $poolName, '-o', 'json') | ConvertFrom-Json
        if (-not $upgrades.latestNodeImageVersion) { throw "AKS did not report the latest image for $poolName." }
        if ($pool.nodeImageVersion -ne $upgrades.latestNodeImageVersion) {
            Invoke-Az @('aks', 'nodepool', 'upgrade', '-g', $ResourceGroup, '--cluster-name', $ClusterName,
                '-n', $poolName, '--node-image-only', '--yes', '-o', 'none')
            $pool = Invoke-Az @('aks', 'nodepool', 'show', '-g', $ResourceGroup, '--cluster-name', $ClusterName,
                '-n', $poolName, '-o', 'json') | ConvertFrom-Json
        }
        if ($pool.nodeImageVersion -ne $upgrades.latestNodeImageVersion) { throw "$poolName is not on the latest offered image." }
        $result["${poolName}Image"] = $pool.nodeImageVersion
    }
    $pools = @(Invoke-Az @('aks', 'nodepool', 'list', '-g', $ResourceGroup,
        '--cluster-name', $ClusterName, '-o', 'json') | ConvertFrom-Json)
    Assert-SamplePools -Pools $pools -SystemVmSize Standard_D4ds_v6
    $cluster = Invoke-Az @('aks', 'show', '-g', $ResourceGroup, '-n', $ClusterName, '-o', 'json') | ConvertFrom-Json
    $sets = @(Invoke-Az @('vmss', 'list', '-g', $cluster.nodeResourceGroup, '-o', 'json') | ConvertFrom-Json)
    Assert-ConfidentialGpuScaleSet $sets
    $sets | ConvertTo-Json -Depth 40 | Set-Content (Join-Path $runDirectory 'scale-sets.json')
    Invoke-Az @('aks', 'get-credentials', '-g', $ResourceGroup, '-n', $ClusterName, '--file', $kubeConfig, '-o', 'none')
    Invoke-Kube @('wait', 'node', '-l', 'agentpool=gpunp', '--for=condition=Ready', '--timeout=900s')
    $node = Get-GpuNode -KubeConfig $kubeConfig
    $result.Kernel = $node.status.nodeInfo.kernelVersion
    $result.OsImage = $node.status.nodeInfo.osImage
    if ($result.OsImage -notlike 'Ubuntu 24.04*') { throw "Unexpected GPU OS: $($result.OsImage)." }
    Assert-MinimumKernel $result.Kernel $MinimumKernel
    $node | ConvertTo-Json -Depth 30 | Set-Content (Join-Path $runDirectory 'gpu-node.json')

    $images = @(Get-ExactDriverImages -Kernel $result.Kernel -Branches @('580'))
    $images | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $runDirectory 'driver-images.json')
    $image = @($images | Where-Object Available)
    if ($image.Count -ne 1) {
        $result.Status = 'BlockedMissingGuideDriver'
        throw "The guide's image nvcr.io/nvidia/driver:580-$($result.Kernel)-ubuntu24.04 is absent (MANIFEST_UNKNOWN). No alternative driver or kernel will be installed."
    }
    $result.DriverImage = "nvcr.io/nvidia/driver:$($image[0].Tag)"
    $result.DriverDigest = $image[0].Digest
    $values = Get-GuideOperatorValues $result.Kernel
    $valuesPath = Join-Path $runDirectory 'operator-values.yaml'
    $values | Set-Content $valuesPath
    Invoke-CheckedCommand helm @('install', 'gpu-operator', $chartPath, '--kubeconfig', $kubeConfig,
        '--namespace', 'gpu-operator', '--create-namespace', '-f', $valuesPath, '--wait', '--timeout', '20m')
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        $node = Get-GpuNode -KubeConfig $kubeConfig
        $gpu = $node.status.allocatable.PSObject.Properties['nvidia.com/gpu']
        if ($gpu -and $gpu.Value -eq '1') { break }
        Start-Sleep 10
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $gpu -or $gpu.Value -ne '1') { throw 'The worker did not expose exactly one allocatable GPU.' }
    $driverPods = (Invoke-Kube @('get', 'pods', '-n', 'gpu-operator', '-l', 'app=nvidia-driver-daemonset', '-o', 'json') |
        ConvertFrom-Json).items
    $driver = @($driverPods | Where-Object { $_.spec.nodeName -eq $node.metadata.name })
    if ($driver.Count -ne 1) { throw 'Expected one GPU driver pod on the confidential worker.' }
    $driverName = $driver[0].metadata.name
    foreach ($operation in @('-f', '-e', '-srs', '-q')) {
        $command = @('exec', '-n', 'gpu-operator', $driverName, '-c', 'nvidia-driver-ctr', '--', 'nvidia-smi', 'conf-compute', $operation)
        if ($operation -eq '-srs') { $command += '1' }
        $output = Invoke-Kube $command
        $output | Set-Content (Join-Path $runDirectory "cc-$($operation.TrimStart('-')).txt")
        if ($operation -eq '-f' -and "$output" -notmatch 'CC status: ON') { throw 'GPU confidential mode is not ON.' }
        if ($operation -eq '-e' -and "$output" -notmatch 'CC Environment: PRODUCTION') { throw 'GPU is not in PRODUCTION mode.' }
        if ($operation -eq '-q' -and "$output" -notmatch 'CC GPUs Ready State\s*: Ready') { throw 'GPU is not Ready.' }
    }

    $guideCommit = '136262ef00ad75b8e0bc789563f043006fb68f4c'
    $manifestUrl = "https://raw.githubusercontent.com/Azure/az-cgpu-onboarding/$guideCommit/docs/cgpu-aks-attestation.yaml"
    $attestation = (Invoke-WebRequest $manifestUrl).Content
    if ($attestation -notmatch 'python3 -m verifier.cc_admin') { throw 'Upstream attestation manifest changed; review it before continuing.' }
    $identity = Invoke-Kube @('exec', '-n', 'gpu-operator', $driverName, '-c', 'nvidia-driver-ctr',
        '--', 'nvidia-smi', '--query-gpu=uuid', '--format=csv,noheader')
    $uuid = ("$identity").Trim()
    if ($uuid -notmatch '^GPU-[0-9a-fA-F-]+$') { throw 'Expected exactly one GPU UUID.' }
    $result.GpuUuid = $uuid
    $attestation = $attestation.Replace('./prodtest/bin/python3 -m verifier.cc_admin',
        './prodtest/bin/python3 -m verifier.cc_admin --ocsp_attestation_settings strict')
    # Pin scheduling and deadline while preserving the guide's verifier installation.
    $attestation = $attestation.Replace('  backoffLimit: 0', "  backoffLimit: 0`n  activeDeadlineSeconds: 900")
    $attestation = $attestation.Replace('      restartPolicy: Never', @"
      restartPolicy: Never
      nodeSelector:
        agentpool: gpunp
      tolerations:
        - key: sku
          operator: Equal
          value: gpu
          effect: NoSchedule
"@)
    $attestationPath = Join-Path $runDirectory 'attestation.yaml'
    $attestation | Set-Content $attestationPath
    foreach ($phase in @('before', 'after')) {
        Invoke-Kube @('apply', '-f', $attestationPath)
        Wait-GpuJob -Name local-gpu-attestation -Namespace attest -TimeoutSeconds 950
        $log = Invoke-Kube @('logs', '-n', 'attest', 'job/local-gpu-attestation')
        $text = $log -join "`n"
        $redacted = $text -replace '(?s)Entity Attestation Token:.*', '[Attestation token omitted]'
        $redacted | Set-Content (Join-Path $runDirectory "attestation-$phase.txt")
        if ($text -notmatch 'GPU Attestation is Successful\.') { throw "GPU attestation $phase did not report success." }
        if ($text -notmatch "(?i)$([regex]::Escape($uuid))") { throw "Attestation $phase did not identify this worker's GPU." }
        $result["Attestation${phase}Passed"] = $true
        Invoke-Kube @('delete', 'job', 'local-gpu-attestation', '-n', 'attest', '--wait=true')
        if ($phase -eq 'before') {
            $workloadUrl = "https://raw.githubusercontent.com/Azure/az-cgpu-onboarding/$guideCommit/docs/samples-tf-matmul-demo.yaml"
            $smoke = Get-GuideWorkloadManifest (Invoke-WebRequest $workloadUrl).Content
            $smokePath = Join-Path $runDirectory 'gpu-smoke-test.yaml'
            $smoke | Set-Content $smokePath
            Invoke-Kube @('apply', '-f', $smokePath)
            Wait-GpuJob -Name tf-matmul-demo -Namespace default -TimeoutSeconds 950
            $log = Invoke-Kube @('logs', 'job/tf-matmul-demo')
            $log | Set-Content (Join-Path $runDirectory 'gpu-smoke-test.txt')
            if (($log -join "`n") -notmatch 'GPU matmul device:.*GPU:0') { throw 'Guide TensorFlow workload did not report GPU execution.' }
            $result.GpuWorkloadPassed = $true
        }
    }
    $result.Status = 'Succeeded'
}
catch {
    $result.Error = $_.Exception.Message
    if ($result.Status -notlike 'Blocked*') { $result.Status = 'Failed' }
    throw
}
finally {
    try {
        if ($created -and -not $KeepRunning) {
            $clusters = @(Invoke-Az @('aks', 'list', '-g', $ResourceGroup, '-o', 'json') | ConvertFrom-Json)
            if ($clusters.Count -eq 1) {
                Wait-SampleAksReady $az $SubscriptionId $ResourceGroup $ClusterName
                Stop-SampleAks $az $SubscriptionId $ResourceGroup $ClusterName
                $state = Invoke-Az @('aks', 'show', '-g', $ResourceGroup, '-n', $ClusterName,
                    '--query', 'powerState.code', '-o', 'tsv')
                $result.FinalPowerState = "$state"
                if ($state -ne 'Stopped') { throw 'Disposable AKS did not stop; inspect it immediately for ongoing NCC charges.' }
                $nodeGroup = $clusters[0].nodeResourceGroup
                $sets = @(Invoke-Az @('vmss', 'list', '-g', $nodeGroup, '-o', 'json') | ConvertFrom-Json)
                foreach ($set in $sets) {
                    $instances = @(Invoke-Az @('vmss', 'list-instances', '-g', $nodeGroup, '-n', $set.name,
                        '--expand', 'instanceView', '-o', 'json') | ConvertFrom-Json)
                    if (@($instances | Where-Object { 'PowerState/deallocated' -notin @($_.instanceView.statuses.code) }).Count) {
                        throw "Scale set $($set.name) still has allocated instances after AKS stop."
                    }
                }
                $result.ComputeDeallocated = $true
            }
        }
        elseif ($created) { $result.FinalPowerState = 'KeptRunningByRequest' }
    }
    catch {
        $result.CleanupError = $_.Exception.Message
        $result.Status = 'CleanupFailed'
        throw
    }
    finally {
        $result.FinishedAtUtc = [DateTime]::UtcNow.ToString('o')
        if ($result.Contains('EvidenceDirectory')) {
            $result | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $runDirectory 'result.json')
            Write-Host "Evidence: $runDirectory"
        }
        $env:AZURE_EXTENSION_DIR = $oldExtensions
        $env:AZURE_EXTENSION_USE_DYNAMIC_INSTALL = $oldDynamicInstall
    }
}
