function Test-RegionalAvailabilityError {
    param([Parameter(Mandatory)][string]$Message)

    if ($Message -match 'AuthorizationFailed|Authorization failed|RequestDisallowedByPolicy|InvalidAuthenticationToken|RoleAssignment') {
        return $false
    }
    if ($Message -match 'SkuNotAvailable|RegionNotSupported|LocationNotAvailableForResourceType|InsufficientCapacity') {
        return $true
    }
    return ($Message -match '(?i)confidential|platformCapabilities') -and
        ($Message -match '(?i)region|location') -and
        ($Message -match '(?i)not supported|not available|unsupported|unavailable')
}
