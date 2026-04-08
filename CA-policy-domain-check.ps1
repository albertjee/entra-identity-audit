<#
.SYNOPSIS
    CA-policy-domain-check.ps1
.VERSION
    v1.0-CriticalHighFixes-Rev0.03
.DATE
    2026-04-07
.AUTHOR
    Albert Jee
.PURPOSE
    Evaluates a single Microsoft Entra Conditional Access policy against an
    identity-domain alignment model and outputs console, HTML, and JSON results.
.REQUIRED MODULES
    Microsoft.Graph.Authentication
    Microsoft.Graph.Identity.SignIns
    Microsoft.Graph.Groups
.REQUIRED SCOPES
    Policy.Read.All
    Group.Read.All
    Directory.Read.All (requires admin consent; restricted in some delegated auth scenarios)
.EXAMPLE
    .\CA-policy-domain-check.ps1 -PolicyName "CA - Workforce - All Apps"
.EXAMPLE
    .\CA-policy-domain-check.ps1 -PolicyId "11111111-2222-3333-4444-555555555555"
#>

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
    [string]$PolicyName,

    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [string]$PolicyId,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ([string]::IsNullOrWhiteSpace($_)) { return $true }
        # Accept GUID format
        if ([System.Guid]::TryParse($_, [ref]([System.Guid]::Empty))) { return $true }
        # Accept domain format (e.g., contoso.onmicrosoft.com)
        if ($_ -match '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.onmicrosoft\.com$') { return $true }
        throw "TenantId must be empty, a GUID, or valid domain (e.g., contoso.onmicrosoft.com)"
    })]
    [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Groups'
)

$Script:RequiredScopes = @(
    'Policy.Read.All',
    'Group.Read.All',
    'Directory.Read.All'
)

function Write-Section {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor $Color
    Write-Host ('=' * 78) -ForegroundColor DarkGray
}

function Get-SafePropertyValue {
    param(
        [object]$Object,
        [string[]]$Path
    )

    $current = $Object
    foreach ($segment in $Path) {
        if ($null -eq $current) {
            return $null
        }

        if ($current -is [System.Collections.IDictionary]) {
            if ($current.Contains($segment)) {
                $current = $current[$segment]
                continue
            }
            return $null
        }

        $property = $current.PSObject.Properties[$segment]
        if ($null -eq $property) {
            return $null
        }

        $current = $property.Value
    }

    return $current
}

function ConvertTo-ArraySafe {
    param([object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Array]) {
        return @($Value)
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value)
    }

    return @($Value)
}

function Test-IsGuid {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return [System.Guid]::TryParse($Value, [ref]([System.Guid]::Empty))
}

function Sanitize-FileName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return 'UnknownPolicy'
    }

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $sanitized = -join ($Name.ToCharArray() | ForEach-Object {
        if ($invalid -contains $_) { '_' } else { $_ }
    })

    return ($sanitized -replace '\s+', '_').Trim('_')
}

function Ensure-ReportsDirectory {
    $reportsPath = Join-Path -Path $PSScriptRoot -ChildPath 'Reports'
    if (-not (Test-Path -LiteralPath $reportsPath)) {
        New-Item -Path $reportsPath -ItemType Directory -Force | Out-Null
    }
    return $reportsPath
}

function Ensure-GraphModules {
    foreach ($moduleName in $Script:RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Host "Required module '$moduleName' is not installed." -ForegroundColor Yellow
            Write-Host "Install from PSGallery: Install-Module -Name '$moduleName' -Scope CurrentUser -Force" -ForegroundColor Cyan
            throw "Cannot continue without module '$moduleName'. Install from PSGallery and retry."
        }

        Import-Module $moduleName -ErrorAction Stop | Out-Null
    }
}

function Ensure-GraphConnection {
    param([string]$RequestedTenantId)

    $context = $null
    try {
        $context = Get-MgContext
    } catch {
        $context = $null
    }

    $needsConnect = $false
    if ($null -eq $context) {
        $needsConnect = $true
    } elseif ([string]::IsNullOrWhiteSpace($context.TenantId)) {
        $needsConnect = $true
    } elseif ($RequestedTenantId -and $context.TenantId -ne $RequestedTenantId) {
        $needsConnect = $true
    } else {
        # Normalize granted scopes to lowercase for comparison
        $grantedScopes = @($context.Scopes) | ForEach-Object { $_.ToLower() }
        foreach ($scope in $Script:RequiredScopes) {
            if ($grantedScopes -notcontains $scope.ToLower()) {
                $needsConnect = $true
                break
            }
        }
    }

    if ($needsConnect) {
        Write-Section -Message 'Connecting to Microsoft Graph' -Color Cyan
        $connectParams = @{
            Scopes    = $Script:RequiredScopes
            NoWelcome = $true
        }
        if ($RequestedTenantId) {
            $connectParams.TenantId = $RequestedTenantId
        }
        Connect-MgGraph @connectParams | Out-Null
        $context = Get-MgContext
    }

    return $context
}

function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 4
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        } catch {
            $message = $_.Exception.Message
            $statusCode = $null
            $retryAfter = $null

            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
            } catch {
                $statusCode = $null
            }

            try {
                if ($_.Exception.Response -and $_.Exception.Response.Headers['Retry-After']) {
                    $retryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                }
            } catch {
                $retryAfter = $null
            }

            # Retry on 429 (Too Many Requests), 503 (Service Unavailable), 504 (Gateway Timeout)
            if (($message -match '429|Too Many Requests' -or $statusCode -in @(429, 503, 504)) -and $attempt -lt $MaxAttempts) {
                $sleepSeconds = if ($retryAfter) { $retryAfter } else { [math]::Pow(2, $attempt) }
                Write-Information "Graph throttling detected (attempt $attempt/$MaxAttempts). Waiting $sleepSeconds second(s)..." -InformationAction Continue
                Start-Sleep -Seconds $sleepSeconds
                continue
            }

            throw
        }
    }
}

function Get-ConditionalAccessPolicy {
    param(
        [string]$Id,
        [string]$Name
    )

    if ($Id) {
        try {
            return Invoke-WithRetry -ScriptBlock {
                Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Id -ErrorAction Stop
            }
        } catch {
            if ($_.Exception.Message -match '404|Request_ResourceNotFound|Not found') {
                throw "Policy not found: $Id"
            }
            throw
        }
    }

    $allPolicies = Invoke-WithRetry -ScriptBlock {
        Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    }

    $matches = @($allPolicies | Where-Object { $_.DisplayName -eq $Name })
    if ($matches.Count -gt 1) {
        Write-Warning "Multiple policies found with name '$Name'. Using first match. Consider using -PolicyId instead for unambiguous selection."
    }
    
    $match = $matches | Select-Object -First 1
    if (-not $match) {
        throw "Policy not found: $Name"
    }

    return $match
}

function Get-GroupNameMap {
    param([string[]]$GroupIds)

    $map = @{}
    $uniqueIds = @($GroupIds | Where-Object { Test-IsGuid $_ } | Sort-Object -Unique)

    if ($uniqueIds.Count -eq 0) {
        return @{}
    }

    # Batch in chunks of 20 per Graph API limits
    for ($i = 0; $i -lt $uniqueIds.Count; $i += 20) {
        $endIndex = [math]::Min($i + 19, $uniqueIds.Count - 1)
        $batch = @($uniqueIds[$i..$endIndex])
        $filterString = "id in ('$($batch -join "','")')"

        try {
            $groups = Invoke-WithRetry -ScriptBlock {
                Get-MgGroup -Filter $filterString -Property Id,DisplayName -All -ErrorAction Stop
            }

            foreach ($group in $groups) {
                $map[$group.Id] = $group.DisplayName
            }

            foreach ($gid in $batch) {
                if (-not $map.ContainsKey($gid)) {
                    $map[$gid] = $gid
                }
            }
        } catch {
            foreach ($gid in $batch) {
                $map[$gid] = $gid
            }
        }
    }

    return $map
}

function Get-DomainHint {
    param(
        [string]$PolicyName,
        [string[]]$IncludedGroupNames
    )

    $haystack = @($PolicyName) + $IncludedGroupNames
    $text = ($haystack -join ' | ')

    if ($text -match '(?i)\b(tier0|tier 0|privileged|admin|administrator)\b') {
        return 'Privileged'
    }
    if ($text -match '(?i)\b(guest|external|b2b|collaborator)\b') {
        return 'Guest'
    }
    if ($text -match '(?i)\b(workforce|employee|staff|standard)\b') {
        return 'Workforce'
    }
    if ($text -match '(?i)\b(service principal|workload|application identity)\b') {
        return 'Workload'
    }

    return 'Unknown'
}

function Get-CriterionResult {
    param(
        [ValidateSet('PASS','REVIEW','FAIL')]
        [string]$Result,
        [string]$CriterionName,
        [string]$Explanation
    )

    [pscustomobject]@{
        CriterionName = $CriterionName
        Result        = $Result
        Explanation   = $Explanation
    }
}


function Test-HasEffectiveAuthStrength {
    param([object]$AuthenticationStrength)

    if ($null -eq $AuthenticationStrength) {
        return $false
    }

    if ($AuthenticationStrength.PSObject.Properties.Name -contains 'Id' -and $AuthenticationStrength.Id) {
        return $true
    }

    if ($AuthenticationStrength.AdditionalProperties) {
        if ($AuthenticationStrength.AdditionalProperties.ContainsKey('id') -and $AuthenticationStrength.AdditionalProperties['id']) {
            return $true
        }

        if ($AuthenticationStrength.AdditionalProperties.ContainsKey('displayName') -and $AuthenticationStrength.AdditionalProperties['displayName']) {
            return $true
        }
    }

    return $false
}

function Get-AuthStrengthName {
    param([object]$AuthenticationStrength)

    if ($null -eq $AuthenticationStrength) {
        return $null
    }

    if ($AuthenticationStrength.PSObject.Properties.Name -contains 'DisplayName' -and $AuthenticationStrength.DisplayName) {
        return $AuthenticationStrength.DisplayName
    }

    if ($AuthenticationStrength.AdditionalProperties -and $AuthenticationStrength.AdditionalProperties.ContainsKey('displayName')) {
        return $AuthenticationStrength.AdditionalProperties['displayName']
    }

    if ($AuthenticationStrength.PSObject.Properties.Name -contains 'Id' -and $AuthenticationStrength.Id) {
        return "Authentication strength ID: $($AuthenticationStrength.Id)"
    }

    if ($AuthenticationStrength.AdditionalProperties -and $AuthenticationStrength.AdditionalProperties.ContainsKey('id')) {
        return "Authentication strength ID: $($AuthenticationStrength.AdditionalProperties['id'])"
    }

    return 'Authentication strength present'
}

function Resolve-DirectoryObject {
    param(
        [string]$ObjectId,
        [hashtable]$ObjectCache
    )

    if (-not (Test-IsGuid $ObjectId)) {
        return $null
    }

    if ($ObjectCache.ContainsKey($ObjectId)) {
        return $ObjectCache[$ObjectId]
    }

    $result = $null

    try {
        $obj = Invoke-WithRetry -ScriptBlock {
            Get-MgDirectoryObjectById -Ids @($ObjectId) -ErrorAction Stop
        } | Select-Object -First 1

        if ($obj) {
            $odataType = $null
            $displayName = $null
            $upn = $null

            if ($obj.AdditionalProperties) {
                if ($obj.AdditionalProperties.ContainsKey('@odata.type')) {
                    $odataType = $obj.AdditionalProperties['@odata.type']
                }
                if ($obj.AdditionalProperties.ContainsKey('displayName')) {
                    $displayName = $obj.AdditionalProperties['displayName']
                }
                if ($obj.AdditionalProperties.ContainsKey('userPrincipalName')) {
                    $upn = $obj.AdditionalProperties['userPrincipalName']
                }
            }

            if ($odataType -eq '#microsoft.graph.user') {
                try {
                    $user = Invoke-WithRetry -ScriptBlock {
                        Get-MgUser -UserId $ObjectId -Property Id,DisplayName,UserPrincipalName -ErrorAction Stop
                    }

                    if ($user) {
                        $displayName = $user.DisplayName
                        $upn = $user.UserPrincipalName
                    }
                } catch {
                    # Keep partial object from directory lookup
                }
            }

            $result = [pscustomobject]@{
                Id                = $ObjectId
                ODataType         = $odataType
                DisplayName       = if ($displayName) { $displayName } else { $ObjectId }
                UserPrincipalName = $upn
            }
        }
    } catch {
        $result = [pscustomobject]@{
            Id                = $ObjectId
            ODataType         = $null
            DisplayName       = $ObjectId
            UserPrincipalName = $null
        }
    }

    $ObjectCache[$ObjectId] = $result
    return $result
}

function Test-HasBreakGlassEvidence {
    param(
        [string[]]$IncludeGroupIds,
        [string[]]$IncludeGroupNames,
        [string[]]$ExcludeUserIds,
        [string[]]$ExcludeGroupIds,
        [hashtable]$GroupNameMap,
        [hashtable]$ObjectCache
    )

    $pattern = '(?i)break.?glass|emergency.?access'

    foreach ($name in @($IncludeGroupNames)) {
        if ($name -and $name -match $pattern) {
            return $true
        }
    }

    foreach ($groupId in @($ExcludeGroupIds | Where-Object { Test-IsGuid $_ })) {
        if ($GroupNameMap.ContainsKey($groupId) -and $GroupNameMap[$groupId] -match $pattern) {
            return $true
        }

        try {
            $memberships = Invoke-WithRetry -ScriptBlock {
                Get-MgGroupTransitiveMember -GroupId $groupId -All -ErrorAction Stop
            }

            foreach ($member in $memberships) {
                $displayName = $null
                $upn = $null

                if ($member.AdditionalProperties) {
                    if ($member.AdditionalProperties.ContainsKey('displayName')) {
                        $displayName = $member.AdditionalProperties['displayName']
                    }
                    if ($member.AdditionalProperties.ContainsKey('userPrincipalName')) {
                        $upn = $member.AdditionalProperties['userPrincipalName']
                    }
                }

                if (($displayName -and $displayName -match $pattern) -or ($upn -and $upn -match $pattern)) {
                    return $true
                }
            }
        } catch {
            # Best effort only
        }
    }

    foreach ($userId in @($ExcludeUserIds | Where-Object { Test-IsGuid $_ })) {
        $resolved = Resolve-DirectoryObject -ObjectId $userId -ObjectCache $ObjectCache
        if ($resolved) {
            if (($resolved.DisplayName -and $resolved.DisplayName -match $pattern) -or
                ($resolved.UserPrincipalName -and $resolved.UserPrincipalName -match $pattern)) {
                return $true
            }
        }
    }

    foreach ($groupId in @($IncludeGroupIds | Where-Object { Test-IsGuid $_ })) {
        try {
            $memberships = Invoke-WithRetry -ScriptBlock {
                Get-MgGroupTransitiveMember -GroupId $groupId -All -ErrorAction Stop
            }

            foreach ($member in $memberships) {
                $displayName = $null
                $upn = $null

                if ($member.AdditionalProperties) {
                    if ($member.AdditionalProperties.ContainsKey('displayName')) {
                        $displayName = $member.AdditionalProperties['displayName']
                    }
                    if ($member.AdditionalProperties.ContainsKey('userPrincipalName')) {
                        $upn = $member.AdditionalProperties['userPrincipalName']
                    }
                }

                if (($displayName -and $displayName -match $pattern) -or ($upn -and $upn -match $pattern)) {
                    return $true
                }
            }
        } catch {
            # Best effort only
        }
    }

    return $false
}


function Get-PolicyEvaluation {
    param(
        [object]$Policy,
        [hashtable]$GroupNameMap,
        [object]$GraphContext
    )

    $includeUsers       = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','IncludeUsers'))
    $excludeUsers       = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','ExcludeUsers'))
    $includeGroups      = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','IncludeGroups'))
    $excludeGroups      = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','ExcludeGroups'))
    $includeRoles       = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','IncludeRoles'))
    $includeApps        = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Applications','IncludeApplications'))
    $excludeApps        = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Applications','ExcludeApplications'))
    $sessionControls    = Get-SafePropertyValue -Object $Policy -Path @('SessionControls')
    $builtInControls    = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('GrantControls','BuiltInControls'))
    $authStrength       = Get-SafePropertyValue -Object $Policy -Path @('GrantControls','AuthenticationStrength')
    $clientAppTypes     = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','ClientAppTypes'))

    $isAllApps = ($null -eq $includeApps -or $includeApps.Count -eq 0 -or $includeApps -contains 'All')

    $includedGroupNames = @()
    foreach ($groupId in $includeGroups) {
        if ($GroupNameMap.ContainsKey($groupId)) {
            $includedGroupNames += $GroupNameMap[$groupId]
        } else {
            $includedGroupNames += $groupId
        }
    }

    $excludedGroupNames = @()
    foreach ($groupId in $excludeGroups) {
        if ($GroupNameMap.ContainsKey($groupId)) {
            $excludedGroupNames += $GroupNameMap[$groupId]
        } else {
            $excludedGroupNames += $groupId
        }
    }

    $domainHint = Get-DomainHint -PolicyName $Policy.DisplayName -IncludedGroupNames $includedGroupNames
    $criteria = New-Object System.Collections.Generic.List[object]

    $includeUserGuids = @($includeUsers | Where-Object { Test-IsGuid $_ })
    $excludeUserGuids = @($excludeUsers | Where-Object { Test-IsGuid $_ })
    $objectCache = @{}

    # Criterion 1: User scope
    if ($includeGroups.Count -gt 0 -and $includeUserGuids.Count -eq 0) {
        $criteria.Add((Get-CriterionResult -Result 'PASS' -CriterionName 'USER SCOPE' -Explanation "Policy targets group scope ($($includedGroupNames -join ', ')) rather than individual user assignments."))
    } elseif ($includeUsers -contains 'All') {
        $guestSetting = Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','IncludeGuestsOrExternalUsers')
        if ($guestSetting) {
            $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'USER SCOPE' -Explanation 'Policy targets All Users including guests (B2B). Validate guest inclusion scope is intentional.'))
        } else {
            $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'USER SCOPE' -Explanation 'Policy targets All Users (workforce only, external guests excluded).'))
        }
    } elseif ($includeUserGuids.Count -gt 0) {
        $criteria.Add((Get-CriterionResult -Result 'FAIL' -CriterionName 'USER SCOPE' -Explanation "Policy includes individual user GUID assignment(s): $($includeUserGuids -join ', ')."))
    } elseif ($includeRoles.Count -gt 0 -and $includeGroups.Count -eq 0) {
        $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'USER SCOPE' -Explanation 'Policy is role-scoped without governed group targeting. Validate whether this is acceptable for the intended architecture.'))
    } else {
        $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'USER SCOPE' -Explanation 'Policy user targeting could not be confidently mapped to a governed domain group.'))
    }

    # Criterion 2: Application scope
    if ($isAllApps) {
        $criteria.Add((Get-CriterionResult -Result 'PASS' -CriterionName 'APPLICATION SCOPE' -Explanation 'Policy is scoped to All Cloud Apps.'))
    } elseif ($includeApps.Count -gt 0) {
        $criteria.Add((Get-CriterionResult -Result 'FAIL' -CriterionName 'APPLICATION SCOPE' -Explanation "Policy is scoped to specific application ID(s): $($includeApps -join ', ')."))
    } else {
        $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'APPLICATION SCOPE' -Explanation 'Policy application targeting is empty or could not be resolved.'))
    }

    # Criterion 3: Exclusion hygiene
    $namedExclusions = New-Object System.Collections.Generic.List[string]

    foreach ($userId in $excludeUserGuids) {
        $resolved = Resolve-DirectoryObject -ObjectId $userId -ObjectCache $objectCache
        if ($resolved -and $resolved.ODataType -eq '#microsoft.graph.user') {
            if ($resolved.UserPrincipalName) {
                $namedExclusions.Add("$($resolved.DisplayName) <$($resolved.UserPrincipalName)>")
            } else {
                $namedExclusions.Add($resolved.DisplayName)
            }
        } else {
            $namedExclusions.Add($userId)
        }
    }

    foreach ($groupName in $excludedGroupNames) {
        $namedExclusions.Add("Excluded group: $groupName")
    }

    if ($namedExclusions.Count -eq 0) {
        $criteria.Add((Get-CriterionResult -Result 'PASS' -CriterionName 'EXCLUSION HYGIENE' -Explanation 'No individual user or excluded group exceptions were found.'))
    } else {
        $hasBreakGlassEvidence = Test-HasBreakGlassEvidence `
            -IncludeGroupIds $includeGroups `
            -IncludeGroupNames $includedGroupNames `
            -ExcludeUserIds $excludeUserGuids `
            -ExcludeGroupIds $excludeGroups `
            -GroupNameMap $GroupNameMap `
            -ObjectCache $objectCache

        if ($hasBreakGlassEvidence) {
            $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'EXCLUSION HYGIENE' -Explanation "Exclusions found ($($namedExclusions -join '; ')). Break-glass evidence exists, but documentation and approval trail should be verified."))
        } else {
            $criteria.Add((Get-CriterionResult -Result 'FAIL' -CriterionName 'EXCLUSION HYGIENE' -Explanation "Exclusions found without clear break-glass evidence: $($namedExclusions -join '; ')."))
        }
    }

    # Criterion 4: Grant controls
    $hasBuiltIn = $builtInControls.Count -gt 0
    $hasAuthStrength = Test-HasEffectiveAuthStrength -AuthenticationStrength $authStrength
    $authStrengthName = Get-AuthStrengthName -AuthenticationStrength $authStrength
    $hasSessionControls = $false

    if ($null -ne $sessionControls) {
        foreach ($prop in $sessionControls.PSObject.Properties) {
            if ($null -ne $prop.Value) {
                $hasSessionControls = $true
                break
            }
        }
    }

    switch ($domainHint) {
        'Privileged' {
            if ($hasAuthStrength -and ($builtInControls -contains 'compliantDevice' -or $builtInControls -contains 'domainJoinedDevice')) {
                $criteria.Add((Get-CriterionResult -Result 'PASS' -CriterionName 'GRANT CONTROLS' -Explanation "Privileged policy has authentication strength ('$authStrengthName') and device trust controls."))
            } elseif ($hasAuthStrength) {
                $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'GRANT CONTROLS' -Explanation "Privileged policy has authentication strength ('$authStrengthName') but no compliantDevice or domainJoinedDevice control."))
            } else {
                $criteria.Add((Get-CriterionResult -Result 'FAIL' -CriterionName 'GRANT CONTROLS' -Explanation 'Privileged policy does not include effective authentication strength enforcement.'))
            }
        }
        'Workforce' {
            if ($builtInControls -contains 'mfa' -or $builtInControls -contains 'compliantDevice') {
                $criteria.Add((Get-CriterionResult -Result 'PASS' -CriterionName 'GRANT CONTROLS' -Explanation 'Workforce policy includes MFA and/or compliant device requirements.'))
            } elseif ($hasBuiltIn -or $hasAuthStrength) {
                $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'GRANT CONTROLS' -Explanation 'Workforce policy has grant controls, but not the expected MFA/compliant-device baseline.'))
            } else {
                $criteria.Add((Get-CriterionResult -Result 'FAIL' -CriterionName 'GRANT CONTROLS' -Explanation 'Workforce policy has no usable grant controls.'))
            }
        }
        'Guest' {
            if (($builtInControls -contains 'mfa') -and $hasSessionControls) {
                $criteria.Add((Get-CriterionResult -Result 'PASS' -CriterionName 'GRANT CONTROLS' -Explanation 'Guest policy includes MFA and session control coverage.'))
            } elseif ($builtInControls -contains 'mfa') {
                $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'GRANT CONTROLS' -Explanation 'Guest policy includes MFA but no session controls were detected.'))
            } else {
                $criteria.Add((Get-CriterionResult -Result 'FAIL' -CriterionName 'GRANT CONTROLS' -Explanation 'Guest policy lacks the expected MFA-plus-session control pattern.'))
            }
        }
        default {
            if ($hasBuiltIn -or $hasAuthStrength -or $hasSessionControls) {
                $criteria.Add((Get-CriterionResult -Result 'REVIEW' -CriterionName 'GRANT CONTROLS' -Explanation 'Grant controls exist, but the target domain could not be inferred confidently.'))
            } else {
                $criteria.Add((Get-CriterionResult -Result 'FAIL' -CriterionName 'GRANT CONTROLS' -Explanation 'No grant or session controls were detected.'))
            }
        }
    }

    # Criterion 5: Domain classification
    $failCount = @($criteria | Where-Object Result -eq 'FAIL').Count
    $reviewCount = @($criteria | Where-Object Result -eq 'REVIEW').Count

    $overallVerdict = if ((-not $isAllApps -and $includeApps.Count -gt 0) -or $failCount -ge 2) {
        'APPLICATION-CENTRIC'
    } elseif ($failCount -eq 0 -and $reviewCount -le 1) {
        'DOMAIN-ALIGNED'
    } else {
        'NEEDS-REVIEW'
    }

    $verdictExplanation = switch ($overallVerdict) {
        'DOMAIN-ALIGNED'       { 'Policy largely conforms to group-based, all-apps domain architecture.' }
        'NEEDS-REVIEW'         { 'Policy shows partial domain alignment but has review items that should be resolved before production reliance.' }
        'APPLICATION-CENTRIC'  { 'Policy materially follows an application-centric or exception-heavy pattern.' }
    }

    $criteria.Add((Get-CriterionResult -Result (
        if ($overallVerdict -eq 'DOMAIN-ALIGNED') { 'PASS' }
        elseif ($overallVerdict -eq 'NEEDS-REVIEW') { 'REVIEW' }
        else { 'FAIL' }
    ) -CriterionName 'DOMAIN CLASSIFICATION' -Explanation $verdictExplanation))

    return [pscustomobject]@{
        PolicyId            = $Policy.Id
        PolicyName          = $Policy.DisplayName
        PolicyState         = $Policy.State
        TenantId            = $GraphContext.TenantId
        Timestamp           = (Get-Date).ToString('s')
        DomainHint          = $domainHint
        IncludeUsers        = $includeUsers
        ExcludeUsers        = $excludeUsers
        IncludeGroups       = $includeGroups
        ExcludeGroups       = $excludeGroups
        IncludeApplications = $includeApps
        ExcludeApplications = $excludeApps
        ClientAppTypes      = $clientAppTypes
        Criteria            = @($criteria)
        OverallVerdict      = $overallVerdict
        CreatedDateTime     = (Get-SafePropertyValue -Object $Policy -Path @('CreatedDateTime'))
        ModifiedDateTime    = (Get-SafePropertyValue -Object $Policy -Path @('ModifiedDateTime'))
    }
}

function Write-ConsoleSummary {
    param([object]$Evaluation)
    Write-Section -Message 'Conditional Access Policy Domain Check' -Color Cyan
    Write-Host "Policy Name : $($Evaluation.PolicyName)" -ForegroundColor White
    Write-Host "Policy ID : $($Evaluation.PolicyId)" -ForegroundColor White
    Write-Host "State : $($Evaluation.PolicyState)" -ForegroundColor White
    Write-Host "Tenant ID : $($Evaluation.TenantId)" -ForegroundColor White
    Write-Host "Domain Hint : $($Evaluation.DomainHint)" -ForegroundColor White
    Write-Host ''
    foreach ($criterion in $Evaluation.Criteria) {
        $color = switch ($criterion.Result) {
            'PASS' { 'Green' }
            'REVIEW' { 'Yellow' }
            'FAIL' { 'Red' }
        }
        Write-Host ("[{0}] {1}" -f $criterion.Result.PadRight(6), $criterion.CriterionName) -ForegroundColor $color
        Write-Host (" {0}" -f $criterion.Explanation) -ForegroundColor Gray
    }
    Write-Host ''
    $verdictColor = switch ($Evaluation.OverallVerdict) {
        'DOMAIN-ALIGNED' { 'Green' }
        'NEEDS-REVIEW' { 'Yellow' }
        'APPLICATION-CENTRIC' { 'Red' }
    }
    Write-Host ('#' * 78) -ForegroundColor DarkGray
    Write-Host ("FINAL VERDICT: {0}" -f $Evaluation.OverallVerdict) -ForegroundColor $verdictColor
    Write-Host ('#' * 78) -ForegroundColor DarkGray
}

function New-PolicyHtmlReport {
    param(
        [object]$Evaluation,
        [string]$OutputPath
    )

    $rows = foreach ($criterion in $Evaluation.Criteria) {
        $badgeClass = switch ($criterion.Result) {
            'PASS'   { 'badge-pass' }
            'REVIEW' { 'badge-review' }
            'FAIL'   { 'badge-fail' }
        }

        @"
<tr>
    <td>$([System.Net.WebUtility]::HtmlEncode($criterion.CriterionName))</td>
    <td><span class="$badgeClass">$([System.Net.WebUtility]::HtmlEncode($criterion.Result))</span></td>
    <td>$([System.Net.WebUtility]::HtmlEncode($criterion.Explanation))</td>
</tr>
"@
    }

    $verdictClass = switch ($Evaluation.OverallVerdict) {
        'DOMAIN-ALIGNED' { 'badge-pass' }
        'NEEDS-REVIEW' { 'badge-review' }
        default { 'badge-fail' }
    }

    $created = if ($Evaluation.CreatedDateTime) { $Evaluation.CreatedDateTime } else { 'Not returned by current Graph response' }
    $modified = if ($Evaluation.ModifiedDateTime) { $Evaluation.ModifiedDateTime } else { 'Not returned by current Graph response' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Conditional Access Policy Domain Check</title>
<style>
body { background: #1a1a2e; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; margin: 24px; }
h1, h2 { color: #C8A96A; border-bottom: 1px solid #C8A96A; padding-bottom: 4px; }
.badge-pass { background: #2d6a4f; color: #fff; padding: 2px 8px; border-radius: 4px; }
.badge-review { background: #b5700a; color: #fff; padding: 2px 8px; border-radius: 4px; }
.badge-fail { background: #7b2d2d; color: #fff; padding: 2px 8px; border-radius: 4px; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; }
th { background: #C8A96A; color: #1a1a2e; padding: 8px; text-align: left; }
td { padding: 8px; border-bottom: 1px solid #2a2a3e; vertical-align: top; }
tr:hover { background: #2a2a3e; }
.panel { background: #22243a; border: 1px solid #313552; padding: 16px; margin-bottom: 18px; border-radius: 8px; }
footer { margin-top: 32px; color: #666; font-size: 0.85em; border-top: 1px solid #333; padding-top: 8px; }
.small { color: #999; }
</style>
</head>
<body>
    <h1>Conditional Access Policy Domain Check</h1>

    <div class="panel">
        <h2>Policy Metadata</h2>
        <p><strong>Display Name:</strong> $([System.Net.WebUtility]::HtmlEncode($Evaluation.PolicyName))</p>
        <p><strong>Policy ID:</strong> $([System.Net.WebUtility]::HtmlEncode($Evaluation.PolicyId))</p>
        <p><strong>State:</strong> $([System.Net.WebUtility]::HtmlEncode($Evaluation.PolicyState))</p>
        <p><strong>Created:</strong> $([System.Net.WebUtility]::HtmlEncode($created))</p>
        <p><strong>Last Modified:</strong> $([System.Net.WebUtility]::HtmlEncode($modified))</p>
        <p><strong>Domain Hint:</strong> $([System.Net.WebUtility]::HtmlEncode($Evaluation.DomainHint))</p>
        <p><strong>Overall Verdict:</strong> <span class="$verdictClass">$([System.Net.WebUtility]::HtmlEncode($Evaluation.OverallVerdict))</span></p>
    </div>

    <div class="panel">
        <h2>Criterion Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Criterion</th>
                    <th>Result</th>
                    <th>Explanation</th>
                </tr>
            </thead>
            <tbody>
                $($rows -join [Environment]::NewLine)
            </tbody>
        </table>
    </div>

    <footer>
        Tenant ID: $([System.Net.WebUtility]::HtmlEncode([string]$Evaluation.TenantId)) |
        Generated: $([System.Net.WebUtility]::HtmlEncode([string]$Evaluation.Timestamp))
    </footer>
</body>
</html>
"@

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
}

try {
    Ensure-GraphModules
    $script:GraphContext = Ensure-GraphConnection -RequestedTenantId $TenantId
    $reportsPath = Ensure-ReportsDirectory

    $policy = Get-ConditionalAccessPolicy -Id $PolicyId -Name $PolicyName
    
    if (-not $policy) {
        throw "Policy could not be resolved. Verify PolicyName or PolicyId and retry."
    }

    $groupIds = @()
    $groupIds += ConvertTo-ArraySafe (Get-SafePropertyValue -Object $policy -Path @('Conditions','Users','IncludeGroups'))
    $groupIds += ConvertTo-ArraySafe (Get-SafePropertyValue -Object $policy -Path @('Conditions','Users','ExcludeGroups'))
    $groupNameMap = Get-GroupNameMap -GroupIds $groupIds

    $evaluation = Get-PolicyEvaluation -Policy $policy -GroupNameMap $groupNameMap -GraphContext $script:GraphContext

    Write-ConsoleSummary -Evaluation $evaluation

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeName = Sanitize-FileName -Name $evaluation.PolicyName

    $htmlPath = Join-Path -Path $reportsPath -ChildPath ("CA-PolicyCheck-{0}-{1}.html" -f $safeName, $timestamp)
    $jsonPath = Join-Path -Path $reportsPath -ChildPath ("CA-PolicyCheck-{0}-{1}.json" -f $safeName, $timestamp)

    New-PolicyHtmlReport -Evaluation $evaluation -OutputPath $htmlPath
    $evaluation | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    Write-Host ''
    Write-Host "HTML report : $htmlPath" -ForegroundColor Cyan
    Write-Host "JSON export : $jsonPath" -ForegroundColor Cyan
}
catch {
    Write-Error "Fatal error during audit: $($_.Exception.Message)"
    if ($_.Exception.InnerException) {
        Write-Error "Inner exception: $($_.Exception.InnerException.Message)"
    }
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
