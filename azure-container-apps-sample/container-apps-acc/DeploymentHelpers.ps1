function Get-ArmJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $response = Invoke-AzRestMethod -Method GET -Path $Path -ErrorAction Stop
    if ($response.StatusCode -ne 200) {
        throw "ARM GET failed for ${Path}: HTTP $($response.StatusCode): $($response.Content)"
    }
    $response.Content | ConvertFrom-Json -ErrorAction Stop
}

function Assert-ConfidentialContainerApp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$App,
        [Parameter(Mandatory)][object]$Environment,
        [ValidateSet('uaenorth', 'westeurope')][string]$Location = 'uaenorth'
    )

    if ($App.properties.provisioningState -ne 'Succeeded' -or
        $Environment.properties.provisioningState -ne 'Succeeded') {
        throw 'App and environment must both report provisioningState Succeeded.'
    }
    if ($App.properties.environmentId -ne $Environment.id) {
        throw 'The app is not bound to the expected environment.'
    }
    $profileName = $App.properties.workloadProfileName
    $profiles = @($Environment.properties.workloadProfiles | Where-Object name -eq $profileName)
    if ($profileName -ne 'confidential' -or $profiles.Count -ne 1 -or
        $profiles[0].workloadProfileType -ne 'DC4' -or
        $profiles[0].minimumCount -ne 1 -or $profiles[0].maximumCount -ne 1) {
        throw 'Expected explicit binding to the confidential DC4 profile with exactly one node; refusing ordinary-compute fallback.'
    }
    if (($App.location -replace '\s', '') -ne $Location -or
        ($Environment.location -replace '\s', '') -ne $Location) {
        throw "Expected the app and environment in $Location."
    }
    $ingress = $App.properties.configuration.ingress
    if ($ingress.external -ne $true -or $ingress.allowInsecure -ne $false -or
        $ingress.targetPort -ne 80 -or [string]::IsNullOrWhiteSpace($ingress.fqdn)) {
        throw 'Expected public HTTPS-only ingress, target port 80, and a nonempty FQDN.'
    }
    if ([string]::IsNullOrWhiteSpace($App.properties.latestRevisionName) -or
        $App.properties.latestReadyRevisionName -ne $App.properties.latestRevisionName) {
        throw 'The latest app revision is not ready.'
    }
    $uri = [uri]"https://$($ingress.fqdn)"
    if ($uri.Host -ne $ingress.fqdn -or $uri.AbsolutePath -ne '/' -or $uri.Query -or
        $uri.Fragment -or $uri.UserInfo -or -not $uri.IsDefaultPort) {
        throw 'ARM returned an invalid application FQDN.'
    }
    $uri.AbsoluteUri.TrimEnd('/')
}

function Test-HelloWorldEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [ValidateRange(1, 30)][int]$Attempts = 12,
        [ValidateRange(0, 60)][int]$DelaySeconds = 10
    )

    if ($Uri.Scheme -ne 'https') {
        throw 'Endpoint verification requires HTTPS.'
    }
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $response = Invoke-WebRequest -Uri $Uri -TimeoutSec 30 -MaximumRedirection 0 `
            -SkipHttpErrorCheck -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            if ($response.Content -notmatch 'Azure Container Apps') {
                throw 'HTTP 200 received, but the Microsoft hello-world page signature is missing.'
            }
            return
        }
        if ($response.StatusCode -notin @(404, 408, 429, 500, 502, 503, 504) -or $attempt -eq $Attempts) {
            throw "Hello-world verification failed: HTTP $($response.StatusCode) after $attempt attempt(s)."
        }
        Write-Warning "Endpoint returned HTTP $($response.StatusCode); retrying ($attempt/$Attempts)."
        Start-Sleep -Seconds $DelaySeconds
    }
}
