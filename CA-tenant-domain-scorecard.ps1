<#
.SYNOPSIS
    CA-tenant-domain-scorecard.ps1
.VERSION
    v1.0-CriticalHighFixes-Rev0.03
.DATE
    2026-04-05
.AUTHOR
    Albert Jee
.PURPOSE
    Evaluates Conditional Access policies in a tenant against an identity-domain
    architecture model and outputs console, HTML, JSON, and CSV scorecard results.
.REQUIRED MODULES
    Microsoft.Graph.Authentication
    Microsoft.Graph.Identity.SignIns
    Microsoft.Graph.Groups
    Microsoft.Graph.Users
    Microsoft.Graph.DirectoryObjects
.REQUIRED SCOPES
    Policy.Read.All
    Group.Read.All
    Directory.Read.All (requires admin consent; restricted in some delegated auth scenarios)
    User.Read.All
.EXAMPLE
    .\CA-tenant-domain-scorecard.ps1
.EXAMPLE
    .\CA-tenant-domain-scorecard.ps1 -IncludeReportOnly
.EXAMPLE
    .\CA-tenant-domain-scorecard.ps1 -TenantId "contoso.onmicrosoft.com" -ExportPath ".\Outputs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ([string]::IsNullOrWhiteSpace($_)) { return $true }
        # Accept GUID format
        if ([System.Guid]::TryParse($_, [ref]([System.Guid]::Empty))) { return $true }
        # Accept domain format (e.g., contoso.onmicrosoft.com)
        if ($_ -match '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.onmicrosoft\.com$') { return $true }
        throw "TenantId must be empty, a GUID, or valid domain (e.g., contoso.onmicrosoft.com)"
    })]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeReportOnly,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.DirectoryObjects'
)

$Script:RequiredScopes = @(
    'Policy.Read.All',
    'Group.Read.All',
    'Directory.Read.All',
    'User.Read.All'
)

function Write-Section {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )
    Write-Host ''
    Write-Host ('=' * 98) -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor $Color
    Write-Host ('=' * 98) -ForegroundColor DarkGray
}

function ConvertTo-ArraySafe {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return @($Value) }
    return @($Value)
}

function Get-SafePropertyValue {
    param(
        [object]$Object,
        [string[]]$Path
    )

    $current = $Object
    foreach ($segment in $Path) {
        if ($null -eq $current) { return $null }

        if ($current -is [System.Collections.IDictionary]) {
            if ($current.Contains($segment)) {
                $current = $current[$segment]
                continue
            }
            return $null
        }

        $property = $current.PSObject.Properties[$segment]
        if ($null -eq $property) { return $null }
        $current = $property.Value
    }

    return $current
}

function Test-IsGuid {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return [System.Guid]::TryParse($Value, [ref]([System.Guid]::Empty))
}

function Sanitize-FileName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return 'Tenant' }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $sanitized = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    return ($sanitized -replace '\s+', '_').Trim('_')
}

function Ensure-OutputDirectory {
    param([string]$PreferredPath)

    if ($PreferredPath) {
        $fullPath = [System.IO.Path]::GetFullPath($PreferredPath)
    } else {
        $fullPath = Join-Path -Path $PSScriptRoot -ChildPath 'Reports'
    }

    if (-not (Test-Path -LiteralPath $fullPath)) {
        New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
    }

    return $fullPath
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
    try { $context = Get-MgContext } catch { $context = $null }

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
        if ($RequestedTenantId) { $connectParams.TenantId = $RequestedTenantId }
        Connect-MgGraph @connectParams | Out-Null
        $context = Get-MgContext
    }

    return $context
}

function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 5
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

            if ($obj.AdditionalProperties.ContainsKey('@odata.type')) {
                $odataType = $obj.AdditionalProperties['@odata.type']
            }

            if ($obj.AdditionalProperties.ContainsKey('displayName')) {
                $displayName = $obj.AdditionalProperties['displayName']
            }

            if ($obj.AdditionalProperties.ContainsKey('userPrincipalName')) {
                $upn = $obj.AdditionalProperties['userPrincipalName']
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
                    # keep the partial response
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

function Get-DomainHint {
    param(
        [string]$PolicyName,
        [string[]]$IncludedGroupNames
    )

    $text = (@($PolicyName) + $IncludedGroupNames) -join ' | '

    if ($text -match '(?i)\b(tier0|tier 0|privileged|admin|administrator)\b') { return 'Privileged' }
    if ($text -match '(?i)\b(guest|external|b2b|collaborator)\b') { return 'Guest' }
    if ($text -match '(?i)\b(workforce|employee|staff|standard)\b') { return 'Workforce' }
    if ($text -match '(?i)\b(service principal|workload|application identity)\b') { return 'Workload' }

    return 'Unknown'
}

function Test-HasSessionControls {
    param([object]$SessionControls)

    if ($null -eq $SessionControls) { return $false }
    foreach ($prop in $SessionControls.PSObject.Properties) {
        if ($null -ne $prop.Value) { return $true }
    }
    return $false
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

function Test-IsWorkloadPolicyDomainAligned {
    param(
        [string]$State,
        [string[]]$ServicePrincipalTargets,
        [string[]]$IncludeApplications,
        [string[]]$IndividualIncludeIds,
        [string[]]$BuiltInControls,
        [bool]$HasSessionControls,
        [string[]]$WorkloadExclusions
    )

    if ($State -ne 'enabled') {
        return $false
    }

    if (@($ServicePrincipalTargets).Count -eq 0) {
        return $false
    }

    $hasAllApps = ($IncludeApplications.Count -eq 0 -or $IncludeApplications -contains 'All')
    if (-not $hasAllApps) {
        return $false
    }

    if (@($IndividualIncludeIds).Count -gt 0) {
        return $false
    }

    if (@($WorkloadExclusions).Count -gt 0) {
        return $false
    }

    $hasUsableControls = (@($BuiltInControls).Count -gt 0) -or $HasSessionControls
    if (-not $hasUsableControls) {
        return $false
    }

    return $true
}

function Test-PolicyHasBreakGlassTripwireEvidence {
    param(
        [pscustomobject]$PolicyResult,
        [hashtable]$BreakGlassCache
    )

    $pattern = '(?i)break.?glass|emergency.?access'

    foreach ($name in @($PolicyResult.IncludedGroupNames)) {
        if ($name -and $name -match $pattern) {
            return $true
        }
    }

    foreach ($groupId in @($PolicyResult.IncludeGroupIds | Where-Object { Test-IsGuid $_ })) {
        if ($BreakGlassCache.ContainsKey($groupId) -and $BreakGlassCache[$groupId]) {
            return $true
        }
    }

    return $false
}


function Get-PolicyClassification {
    param(
        [object]$Policy,
        [hashtable]$GroupNameMap,
        [object]$GraphContext
    )

    $state                = $Policy.State
    $includeUsers         = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','IncludeUsers'))
    $excludeUsers         = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','ExcludeUsers'))
    $includeGroups        = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','IncludeGroups'))
    $includeRoles         = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Users','IncludeRoles'))
    $includeApplications  = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','Applications','IncludeApplications'))
    $clientAppTypes       = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','ClientAppTypes'))
    $grantControls        = Get-SafePropertyValue -Object $Policy -Path @('GrantControls')
    $sessionControls      = Get-SafePropertyValue -Object $Policy -Path @('SessionControls')
    $builtInControls      = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('GrantControls','BuiltInControls'))
    $authStrength         = Get-SafePropertyValue -Object $Policy -Path @('GrantControls','AuthenticationStrength')
    $hasAuthStrengthEffective = Test-HasEffectiveAuthStrength -AuthenticationStrength $authStrength

    $clientApplicationsSP = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','ClientApplications','IncludeServicePrincipals'))
    $clientApplicationsEx = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $Policy -Path @('Conditions','ClientApplications','ExcludeServicePrincipals'))

    $includedGroupNames = @()
    foreach ($groupId in $includeGroups) {
        if ($GroupNameMap.ContainsKey($groupId)) { $includedGroupNames += $GroupNameMap[$groupId] } else { $includedGroupNames += $groupId }
    }

    $domainHint = Get-DomainHint -PolicyName $Policy.DisplayName -IncludedGroupNames $includedGroupNames
    $individualIncludeIds = @($includeUsers | Where-Object { Test-IsGuid $_ })
    $hasAllApps = ($includeApplications.Count -eq 1 -and $includeApplications[0] -eq 'All')
    $isReportOnly = ($state -eq 'enabledForReportingButNotEnforced')
    $isDisabled = ($state -eq 'disabled')
    $hasSessionControls = Test-HasSessionControls -SessionControls $sessionControls

    $isGlobalBaseline = (
        ($includeUsers -contains 'All') -and
        $hasAllApps -and
        ($builtInControls -contains 'block') -and
        (@($clientAppTypes | ForEach-Object { $_.ToString() }) -contains 'exchangeActiveSync' -or
         @($clientAppTypes | ForEach-Object { $_.ToString() }) -contains 'other')
    )

    if ($isDisabled) {
        return [pscustomobject]@{
            Classification = 'DISABLED'
            ScoreImpact = 0
            DomainHint = $domainHint
            HasAllApps = $hasAllApps
            IndividualIncludeIds = $individualIncludeIds
            ExcludeUsers = $excludeUsers
            IncludedGroupNames = $includedGroupNames
            WorkloadTargets = @($clientApplicationsSP)
            WorkloadExclusions = @($clientApplicationsEx)
            HasAuthStrength = $hasAuthStrengthEffective
            BuiltInControls = $builtInControls
            HasSessionControls = $hasSessionControls
        }
    }

    if ($isReportOnly) {
        return [pscustomobject]@{
            Classification = 'REPORT-ONLY'
            ScoreImpact = 0
            DomainHint = $domainHint
            HasAllApps = $hasAllApps
            IndividualIncludeIds = $individualIncludeIds
            ExcludeUsers = $excludeUsers
            IncludedGroupNames = $includedGroupNames
            WorkloadTargets = @($clientApplicationsSP)
            WorkloadExclusions = @($clientApplicationsEx)
            HasAuthStrength = $hasAuthStrengthEffective
            BuiltInControls = $builtInControls
            HasSessionControls = $hasSessionControls
        }
    }

    if ($isGlobalBaseline) {
        return [pscustomobject]@{
            Classification = 'GLOBAL-BASELINE'
            ScoreImpact = 2
            DomainHint = $domainHint
            HasAllApps = $hasAllApps
            IndividualIncludeIds = $individualIncludeIds
            ExcludeUsers = $excludeUsers
            IncludedGroupNames = $includedGroupNames
            WorkloadTargets = @($clientApplicationsSP)
            WorkloadExclusions = @($clientApplicationsEx)
            HasAuthStrength = $hasAuthStrengthEffective
            BuiltInControls = $builtInControls
            HasSessionControls = $hasSessionControls
        }
    }

    if ($clientApplicationsSP.Count -gt 0) {
        $isWorkloadDomainAligned = Test-IsWorkloadPolicyDomainAligned `
            -State $state `
            -ServicePrincipalTargets $clientApplicationsSP `
            -IncludeApplications $includeApplications `
            -IndividualIncludeIds $individualIncludeIds `
            -BuiltInControls $builtInControls `
            -HasSessionControls $hasSessionControls `
            -WorkloadExclusions $clientApplicationsEx
        if ($isWorkloadDomainAligned) {
            return [pscustomobject]@{
                Classification      = 'DOMAIN-ALIGNED'
                ScoreImpact          = 2
                DomainHint           = 'Workload'
                HasAllApps           = $hasAllApps
                IndividualIncludeIds = $individualIncludeIds
                ExcludeUsers         = $excludeUsers
                IncludedGroupNames   = $includedGroupNames
                WorkloadTargets      = @($clientApplicationsSP)
                WorkloadExclusions   = @($clientApplicationsEx)
                HasAuthStrength      = $hasAuthStrengthEffective
                BuiltInControls      = $builtInControls
                HasSessionControls   = $hasSessionControls
            }
        }
        return [pscustomobject]@{
            Classification      = 'PARTIALLY-ALIGNED'
            ScoreImpact          = 1
            DomainHint           = 'Workload'
            HasAllApps           = $hasAllApps
            IndividualIncludeIds = $individualIncludeIds
            ExcludeUsers         = $excludeUsers
            IncludedGroupNames   = $includedGroupNames
            WorkloadTargets      = @($clientApplicationsSP)
            WorkloadExclusions   = @($clientApplicationsEx)
            HasAuthStrength      = $hasAuthStrengthEffective
            BuiltInControls      = $builtInControls
            HasSessionControls   = $hasSessionControls
        }
    }

    $isPrivilegedTarget = ($domainHint -eq 'Privileged') -or ($includeRoles.Count -gt 0)

    if ($isPrivilegedTarget -and ((-not $hasAllApps) -or ($null -eq $authStrength))) {
        return [pscustomobject]@{
            Classification = 'PRIVILEGED-UNGOVERNED'
            ScoreImpact = -1
            DomainHint = $domainHint
            HasAllApps = $hasAllApps
            IndividualIncludeIds = $individualIncludeIds
            ExcludeUsers = $excludeUsers
            IncludedGroupNames = $includedGroupNames
            WorkloadTargets = @($clientApplicationsSP)
            WorkloadExclusions = @($clientApplicationsEx)
            HasAuthStrength = $hasAuthStrengthEffective
            BuiltInControls = $builtInControls
            HasSessionControls = $hasSessionControls
        }
    }

    $hasExpectedDomainPattern = $false
    switch ($domainHint) {
        'Privileged' {
            $hasExpectedDomainPattern = $hasAllApps -and ($null -ne $authStrength) -and (($builtInControls -contains 'compliantDevice') -or ($builtInControls -contains 'domainJoinedDevice'))
        }
        'Workforce' {
            $hasExpectedDomainPattern = $hasAllApps -and $includeGroups.Count -gt 0 -and (($builtInControls -contains 'mfa') -or ($builtInControls -contains 'compliantDevice'))
        }
        'Guest' {
            $hasExpectedDomainPattern = $hasAllApps -and $includeGroups.Count -gt 0 -and ($builtInControls -contains 'mfa') -and $hasSessionControls
        }
        default {
            $hasExpectedDomainPattern = $hasAllApps -and $includeGroups.Count -gt 0 -and $individualIncludeIds.Count -eq 0
        }
    }

    if ($hasExpectedDomainPattern -and $individualIncludeIds.Count -eq 0) {
        return [pscustomobject]@{
            Classification = 'DOMAIN-ALIGNED'
            ScoreImpact = 2
            DomainHint = $domainHint
            HasAllApps = $hasAllApps
            IndividualIncludeIds = $individualIncludeIds
            ExcludeUsers = $excludeUsers
            IncludedGroupNames = $includedGroupNames
            WorkloadTargets = @($clientApplicationsSP)
            WorkloadExclusions = @($clientApplicationsEx)
            HasAuthStrength = $hasAuthStrengthEffective
            BuiltInControls = $builtInControls
            HasSessionControls = $hasSessionControls
        }
    }

    if ($hasAllApps -or $includeGroups.Count -gt 0) {
        return [pscustomobject]@{
            Classification = 'PARTIALLY-ALIGNED'
            ScoreImpact = 1
            DomainHint = $domainHint
            HasAllApps = $hasAllApps
            IndividualIncludeIds = $individualIncludeIds
            ExcludeUsers = $excludeUsers
            IncludedGroupNames = $includedGroupNames
            WorkloadTargets = @($clientApplicationsSP)
            WorkloadExclusions = @($clientApplicationsEx)
            HasAuthStrength = $hasAuthStrengthEffective
            BuiltInControls = $builtInControls
            HasSessionControls = $hasSessionControls
        }
    }

    return [pscustomobject]@{
        Classification = 'APPLICATION-CENTRIC'
        ScoreImpact = 0
        DomainHint = $domainHint
        HasAllApps = $hasAllApps
        IndividualIncludeIds = $individualIncludeIds
        ExcludeUsers = $excludeUsers
        IncludedGroupNames = $includedGroupNames
        WorkloadTargets = @($clientApplicationsSP)
        WorkloadExclusions = @($clientApplicationsEx)
        HasAuthStrength = $hasAuthStrengthEffective
        BuiltInControls = $builtInControls
        HasSessionControls = $hasSessionControls
    }
}

function Get-BreakGlassEvidence {
    param(
        [string[]]$IncludeGroupIds,
        [string[]]$IncludeGroupNames
    )

    $pattern = '(?i)break.?glass|emergency.?access'

    if (@($IncludeGroupNames | Where-Object { $_ -match $pattern }).Count -gt 0) {
        return $true
    }

    foreach ($groupId in ($IncludeGroupIds | Where-Object { Test-IsGuid $_ })) {
        try {
            $memberships = Invoke-WithRetry -ScriptBlock {
                Get-MgGroupTransitiveMember -GroupId $groupId -All -ErrorAction Stop
            }

            foreach ($member in $memberships) {
                $displayName = $null
                if ($member.AdditionalProperties.ContainsKey('displayName')) {
                    $displayName = $member.AdditionalProperties['displayName']
                }

                if ($displayName -and $displayName -match $pattern) {
                    return $true
                }
            }
        } catch {
            # best effort only
        }
    }

    return $false
}

function New-ScorecardHtmlReport {
    param(
        [object]$Scorecard,
        [string]$OutputPath
    )

    $policyRows = foreach ($policy in $Scorecard.Policies) {
        $badgeClass = switch ($policy.Classification) {
            'DOMAIN-ALIGNED'       { 'badge-pass' }
            'GLOBAL-BASELINE'      { 'badge-pass' }
            'PARTIALLY-ALIGNED'    { 'badge-review' }
            'REPORT-ONLY'          { 'badge-review' }
            default                { 'badge-fail' }
        }

        @"
<tr>
    <td>$([System.Net.WebUtility]::HtmlEncode([string]$policy.PolicyName))</td>
    <td>$([System.Net.WebUtility]::HtmlEncode([string]$policy.State))</td>
    <td><span class="$badgeClass">$([System.Net.WebUtility]::HtmlEncode([string]$policy.Classification))</span></td>
    <td>$([System.Net.WebUtility]::HtmlEncode([string]$policy.IndividualNameCount))</td>
    <td>$([System.Net.WebUtility]::HtmlEncode([string]$policy.ExclusionGapCount))</td>
    <td>$([System.Net.WebUtility]::HtmlEncode([string]$policy.ScoreImpact))</td>
</tr>
"@
    }

    $assignmentDetails = if ($Scorecard.IndividualAssignments.Count -gt 0) {
        ($Scorecard.IndividualAssignments | ForEach-Object {
            "<tr><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.PolicyName))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.DisplayName))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.UserPrincipalName))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.UserId))</td></tr>"
        }) -join [Environment]::NewLine
    } else {
        '<tr><td colspan="4">No individual name assignments detected.</td></tr>'
    }

    $exclusionDetails = if ($Scorecard.ExclusionGaps.Count -gt 0) {
        ($Scorecard.ExclusionGaps | ForEach-Object {
            "<tr><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.PolicyName))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.DisplayName))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.UserPrincipalName))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$_.UserId))</td></tr>"
        }) -join [Environment]::NewLine
    } else {
        '<tr><td colspan="4">No non-break-glass individual exclusions detected.</td></tr>'
    }

    $gapTemplate = {
        param($Title, $Present)
        $safeTitle = [System.Net.WebUtility]::HtmlEncode([string]$Title)
        if ($Present) {
            return "<div class='gap-alert'><strong>$safeTitle</strong></div>"
        }
        return "<div class='gap-clear'><strong>$safeTitle</strong></div>"
    }

    $verdictClass = switch ($Scorecard.Verdict) {
        'DOMAIN-ALIGNED' { 'badge-pass' }
        'IN TRANSITION' { 'badge-review' }
        default { 'badge-fail' }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Conditional Access Tenant Domain Scorecard</title>
<style>
body { background: #1a1a2e; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; margin: 24px; }
h1, h2 { color: #C8A96A; border-bottom: 1px solid #C8A96A; padding-bottom: 4px; }
.badge-pass { background: #2d6a4f; color: #fff; padding: 2px 8px; border-radius: 4px; }
.badge-review { background: #b5700a; color: #fff; padding: 2px 8px; border-radius: 4px; }
.badge-fail { background: #7b2d2d; color: #fff; padding: 2px 8px; border-radius: 4px; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; }
th { background: #C8A96A; color: #1a1a2e; padding: 8px; text-align: left; position: sticky; top: 0; }
td { padding: 8px; border-bottom: 1px solid #2a2a3e; vertical-align: top; }
tr:hover { background: #2a2a3e; }
.gap-alert { background: #7b2d2d; border-left: 4px solid #ff4444; padding: 12px; margin: 8px 0; }
.gap-clear { background: #2d6a4f; border-left: 4px solid #44ff88; padding: 12px; margin: 8px 0; }
.panel { background: #22243a; border: 1px solid #313552; padding: 16px; margin-bottom: 18px; border-radius: 8px; }
footer { margin-top: 32px; color: #666; font-size: 0.85em; border-top: 1px solid #333; padding-top: 8px; }
</style>
</head>
<body>
    <h1>Conditional Access Tenant Domain Scorecard</h1>

    <div class="panel">
        <h2>Executive Summary</h2>
        <p><strong>Tenant ID:</strong> $([System.Net.WebUtility]::HtmlEncode([string]$Scorecard.TenantId))</p>
        <p><strong>Timestamp:</strong> $([System.Net.WebUtility]::HtmlEncode([string]$Scorecard.Timestamp))</p>
        <p><strong>Policy Count:</strong> $([System.Net.WebUtility]::HtmlEncode([string]$Scorecard.PolicyCount))</p>
        <p><strong>Overall Score:</strong> $([System.Net.WebUtility]::HtmlEncode([string]$Scorecard.OverallScore)) / $([System.Net.WebUtility]::HtmlEncode([string]$Scorecard.MaxPossibleScore))</p>
        <p><strong>Score Percent:</strong> $([System.Net.WebUtility]::HtmlEncode([string]$Scorecard.ScorePercent))%</p>
        <p><strong>Verdict:</strong> <span class="$verdictClass">$([System.Net.WebUtility]::HtmlEncode([string]$Scorecard.Verdict))</span></p>
    </div>

    <div class="panel">
        <h2>Gap Findings</h2>
        $(& $gapTemplate 'Privileged Boundary Gap — no phishing-resistant All Cloud Apps policy for Tier 0' $Scorecard.GapFindings.PrivilegedBoundaryGap)
        $(& $gapTemplate 'Workload Identity Gap — service principals ungoverned by Conditional Access' $Scorecard.GapFindings.WorkloadIdentityGap)
        $(& $gapTemplate 'Break-Glass Tripwire Missing — emergency access unmonitored' $Scorecard.GapFindings.BreakGlassTripwireMissing)
    </div>

    <div class="panel">
        <h2>Per-Policy Detail</h2>
        <table>
            <thead>
                <tr>
                    <th>Policy Name</th>
                    <th>State</th>
                    <th>Classification</th>
                    <th>Individual Names</th>
                    <th>Exclusion Gaps</th>
                    <th>Score Impact</th>
                </tr>
            </thead>
            <tbody>
                $($policyRows -join [Environment]::NewLine)
            </tbody>
        </table>
    </div>

    <div class="panel">
        <h2>Individual Name Assignment Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>Display Name</th>
                    <th>User Principal Name</th>
                    <th>User ID</th>
                </tr>
            </thead>
            <tbody>
                $assignmentDetails
            </tbody>
        </table>
    </div>

    <div class="panel">
        <h2>Exclusion Gap Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>Display Name</th>
                    <th>User Principal Name</th>
                    <th>User ID</th>
                </tr>
            </thead>
            <tbody>
                $exclusionDetails
            </tbody>
        </table>
    </div>

    <footer>
        github.com/albertjee | linkedin.com/in/albertjee | generated $([System.Net.WebUtility]::HtmlEncode([string]$Scorecard.Timestamp))
    </footer>
</body>
</html>
"@

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
}

function Write-ConsoleSummary {
    param([object]$Scorecard)
    $verdictColor = switch ($Scorecard.Verdict) {
        'DOMAIN-ALIGNED' { 'Green' }
        'IN TRANSITION' { 'Yellow' }
        default { 'Red' }
    }
    Write-Section -Message 'Conditional Access Tenant Domain Scorecard' -Color Cyan
    Write-Host ("OVERALL SCORE: {0} / {1} ({2}%)" -f $Scorecard.OverallScore, $Scorecard.MaxPossibleScore, $Scorecard.ScorePercent) -ForegroundColor White
    Write-Host ("VERDICT : {0}" -f $Scorecard.Verdict) -ForegroundColor $verdictColor
    Write-Host ("TENANT ID : {0}" -f $Scorecard.TenantId) -ForegroundColor White
    Write-Host ("POLICY COUNT : {0}" -f $Scorecard.PolicyCount) -ForegroundColor White
    Write-Host ''
    $header = '{0,-48} {1,-22} {2,8} {3,8} {4,10}'
    Write-Host ($header -f 'Policy Name', 'Classification', 'Names', 'Excl', 'Score') -ForegroundColor DarkCyan
    Write-Host ('-' * 98) -ForegroundColor DarkGray
    foreach ($policy in $Scorecard.Policies) {
        $color = switch ($policy.Classification) {
            'DOMAIN-ALIGNED' { 'Green' }
            'GLOBAL-BASELINE' { 'Green' }
            'PARTIALLY-ALIGNED' { 'Yellow' }
            'REPORT-ONLY' { 'Yellow' }
            default { 'Red' }
        }
        $name = $policy.PolicyName
        if ($name.Length -gt 48) { $name = $name.Substring(0,45) + '...' }
        Write-Host ($header -f $name, $policy.Classification, $policy.IndividualNameCount, $policy.ExclusionGapCount, $policy.ScoreImpact) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host 'Summary' -ForegroundColor Cyan
    Write-Host " Domain-Aligned : $($Scorecard.Counts.'DOMAIN-ALIGNED')" -ForegroundColor Green
    Write-Host " Global Baseline : $($Scorecard.Counts.'GLOBAL-BASELINE')" -ForegroundColor Green
    Write-Host " Partially Aligned : $($Scorecard.Counts.'PARTIALLY-ALIGNED')" -ForegroundColor Yellow
    Write-Host " Application-Centric : $($Scorecard.Counts.'APPLICATION-CENTRIC')" -ForegroundColor Red
    Write-Host " Privileged-Ungoverned : $($Scorecard.Counts.'PRIVILEGED-UNGOVERNED')" -ForegroundColor Red
    Write-Host " Report-Only : $($Scorecard.Counts.'REPORT-ONLY')" -ForegroundColor Yellow
    Write-Host " Disabled : $($Scorecard.Counts.'DISABLED')" -ForegroundColor DarkGray
    Write-Host " Individual Assignments: $($Scorecard.IndividualAssignments.Count)" -ForegroundColor White
    Write-Host " Exclusion Gaps : $($Scorecard.ExclusionGaps.Count)" -ForegroundColor White
    Write-Host ''
    foreach ($gap in @(
        @{ Name = 'Privileged Boundary Gap'; Present = $Scorecard.GapFindings.PrivilegedBoundaryGap },
        @{ Name = 'Workload Identity Gap'; Present = $Scorecard.GapFindings.WorkloadIdentityGap },
        @{ Name = 'Break-Glass Tripwire Missing'; Present = $Scorecard.GapFindings.BreakGlassTripwireMissing }
    )) {
        $color = if ($gap.Present) { 'Red' } else { 'Green' }
        $status = if ($gap.Present) { 'GAP PRESENT' } else { 'CLOSED' }
        Write-Host (" {0}: {1}" -f $gap.Name, $status) -ForegroundColor $color
    }
}

try {
    Ensure-GraphModules
    $script:GraphContext = Ensure-GraphConnection -RequestedTenantId $TenantId
    $script:DirectoryObjectCache = @{}
    $exportRoot = Ensure-OutputDirectory -PreferredPath $ExportPath

    Write-Section -Message 'Enumerating Conditional Access policies' -Color Cyan
    $policies = Invoke-WithRetry -ScriptBlock {
        Get-MgIdentityConditionalAccessPolicy -All -PageSize 100 -ErrorAction Stop
    }

    if (-not $policies) {
        throw 'No Conditional Access policies were returned from Microsoft Graph.'
    }

    $allGroupIds = New-Object System.Collections.Generic.List[string]
    foreach ($policy in $policies) {
        foreach ($groupId in (ConvertTo-ArraySafe (Get-SafePropertyValue -Object $policy -Path @('Conditions','Users','IncludeGroups')))) {
            if (Test-IsGuid $groupId) { $allGroupIds.Add($groupId) }
        }
        foreach ($groupId in (ConvertTo-ArraySafe (Get-SafePropertyValue -Object $policy -Path @('Conditions','Users','ExcludeGroups')))) {
            if (Test-IsGuid $groupId) { $allGroupIds.Add($groupId) }
        }
    }

    $groupNameMap = Get-GroupNameMap -GroupIds $allGroupIds.ToArray()

    $policyResults = New-Object System.Collections.Generic.List[object]
    $individualAssignments = New-Object System.Collections.Generic.List[object]
    $exclusionGaps = New-Object System.Collections.Generic.List[object]

    $policyCount = @($policies).Count
    $currentIndex = 0
    $directoryObjectCache = @{}
    # Build break-glass cache ONCE before policy loop to avoid transitive member calls in hot path
    $breakGlassCache = @{}
    $breakGlassPattern = '(?i)break.?glass|emergency.?access'
    $allIncludeGroupIds = @()

    foreach ($policy in $policies) {
        $includeGroupIds = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $policy -Path @('Conditions','Users','IncludeGroups'))
        $allIncludeGroupIds += @($includeGroupIds | Where-Object { Test-IsGuid $_ })
    }

    $allIncludeGroupIds = @($allIncludeGroupIds | Sort-Object -Unique)

    foreach ($groupId in $allIncludeGroupIds) {
        try {
            $transMembers = Invoke-WithRetry -ScriptBlock {
                Get-MgGroupTransitiveMember -GroupId $groupId -All -ErrorAction Stop
            }

            $hasBreakGlassMember = $false
            foreach ($member in $transMembers) {
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

                if (($displayName -and $displayName -match $breakGlassPattern) -or
                    ($upn -and $upn -match $breakGlassPattern)) {
                    $hasBreakGlassMember = $true
                    break
                }
            }

            $breakGlassCache[$groupId] = $hasBreakGlassMember
        } catch {
            $breakGlassCache[$groupId] = $false
        }
    }

    foreach ($policy in $policies) {
        $includeGroupIds = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $policy -Path @('Conditions','Users','IncludeGroups'))
        $allIncludeGroupIds += @($includeGroupIds | Where-Object { Test-IsGuid $_ })
    }
    $allIncludeGroupIds = $allIncludeGroupIds | Sort-Object -Unique

    foreach ($groupId in $allIncludeGroupIds) {
        try {
            $transMembers = Invoke-WithRetry -ScriptBlock {
                Get-MgGroupTransitiveMember -GroupId $groupId -All -ErrorAction Stop
            }
            $breakGlassUsers = @($transMembers | Where-Object { 
                $_.AdditionalProperties.displayName -match '(?i)break.?glass|emergency.?access|breakglass' 
            })
            $breakGlassCache[$groupId] = $breakGlassUsers.Count -gt 0
        } catch {
            # best effort only
            $breakGlassCache[$groupId] = $false
        }
    }

    foreach ($policy in $policies) {
        $currentIndex++
        $percent = [int](($currentIndex / [double]$policyCount) * 100)

        Write-Progress -Activity 'Evaluating Conditional Access policies' `
                       -Status ("{0}/{1}: {2}" -f $currentIndex, $policyCount, $policy.DisplayName) `
                       -PercentComplete $percent

        $classification = Get-PolicyClassification -Policy $policy -GroupNameMap $groupNameMap -GraphContext $script:GraphContext
        $includeGroupIds = ConvertTo-ArraySafe (Get-SafePropertyValue -Object $policy -Path @('Conditions','Users','IncludeGroups'))

        $policyIndividualAssignments = New-Object System.Collections.Generic.List[object]
        foreach ($userId in $classification.IndividualIncludeIds) {
            $resolved = Resolve-DirectoryObject -ObjectId $userId -ObjectCache $directoryObjectCache
            if ($resolved -and $resolved.ODataType -eq '#microsoft.graph.user') {
                $record = [pscustomobject]@{
                    PolicyName        = $policy.DisplayName
                    UserId            = $userId
                    DisplayName       = $resolved.DisplayName
                    UserPrincipalName = $resolved.UserPrincipalName
                }
                $policyIndividualAssignments.Add($record)
                $individualAssignments.Add($record)
            }
        }

        $policyExclusionGaps = New-Object System.Collections.Generic.List[object]

        $breakGlassEvidence = Test-PolicyHasBreakGlassTripwireEvidence -PolicyResult $classification -BreakGlassCache $breakGlassCache

        foreach ($excludeUserId in ($classification.ExcludeUsers | Where-Object { Test-IsGuid $_ })) {
            $resolved = Resolve-DirectoryObject -ObjectId $excludeUserId -ObjectCache $directoryObjectCache
            if ($resolved -and $resolved.ODataType -eq '#microsoft.graph.user') {
                $isBreakGlass = $false

                if ($resolved.DisplayName -and $resolved.DisplayName -match $breakGlassPattern) {
                    $isBreakGlass = $true
                }
                if ($resolved.UserPrincipalName -and $resolved.UserPrincipalName -match $breakGlassPattern) {
                    $isBreakGlass = $true
                }
                if ($breakGlassEvidence) {
                    $isBreakGlass = $true
                }

                if (-not $isBreakGlass) {
                    $record = [pscustomobject]@{
                        PolicyName        = $policy.DisplayName
                        UserId            = $excludeUserId
                        DisplayName       = $resolved.DisplayName
                        UserPrincipalName = $resolved.UserPrincipalName
                    }
                    $policyExclusionGaps.Add($record)
                    $exclusionGaps.Add($record)
                }
            }
        }

        $scoreImpact = $classification.ScoreImpact - $policyIndividualAssignments.Count - $policyExclusionGaps.Count

        $policyResults.Add([pscustomobject]@{
            PolicyId                = $policy.Id
            PolicyName              = $policy.DisplayName
            State                   = $policy.State
            Classification          = $classification.Classification
            DomainHint              = $classification.DomainHint
            IndividualNameCount     = $policyIndividualAssignments.Count
            ExclusionGapCount       = $policyExclusionGaps.Count
            ScoreImpact             = $scoreImpact
            IncludeGroupIds         = @($classification.IncludeGroupIds)
            IncludedGroupNames      = @($classification.IncludedGroupNames)
            WorkloadTargetCount     = @($classification.WorkloadTargets).Count
            WorkloadTargets         = @($classification.WorkloadTargets)
            WorkloadExclusions      = @($classification.WorkloadExclusions)
            HasAllApps              = $classification.HasAllApps
            HasAuthStrength         = $classification.HasAuthStrength
            BuiltInControls         = @($classification.BuiltInControls)
            BuiltInControlsDisplay  = ($classification.BuiltInControls -join ', ')
            HasSessionControls      = $classification.HasSessionControls
        })
    }

    Write-Progress -Activity 'Evaluating Conditional Access policies' -Completed

    $reportablePolicies = @($policyResults | Where-Object {
        $_.State -ne 'disabled' -and ($IncludeReportOnly -or $_.State -ne 'enabledForReportingButNotEnforced')
    })

    $counts = @{
        'DOMAIN-ALIGNED'       = @($policyResults | Where-Object Classification -eq 'DOMAIN-ALIGNED').Count
        'PARTIALLY-ALIGNED'    = @($policyResults | Where-Object Classification -eq 'PARTIALLY-ALIGNED').Count
        'APPLICATION-CENTRIC'  = @($policyResults | Where-Object Classification -eq 'APPLICATION-CENTRIC').Count
        'PRIVILEGED-UNGOVERNED'= @($policyResults | Where-Object Classification -eq 'PRIVILEGED-UNGOVERNED').Count
        'GLOBAL-BASELINE'      = @($policyResults | Where-Object Classification -eq 'GLOBAL-BASELINE').Count
        'REPORT-ONLY'          = @($policyResults | Where-Object Classification -eq 'REPORT-ONLY').Count
        'DISABLED'             = @($policyResults | Where-Object Classification -eq 'DISABLED').Count
    }

        $privilegedBoundaryGap = (@($policyResults | Where-Object {
        $_.State -eq 'enabled' -and
        $_.Classification -in @('DOMAIN-ALIGNED','PARTIALLY-ALIGNED') -and
        $_.DomainHint -eq 'Privileged' -and
        $_.HasAllApps -eq $true -and
        $_.HasAuthStrength -eq $true -and
        (
            $_.BuiltInControls -contains 'compliantDevice' -or
            $_.BuiltInControls -contains 'domainJoinedDevice'
        )
    }).Count -eq 0)

    $workloadIdentityGap = (@($policyResults | Where-Object {
        $_.State -eq 'enabled' -and
        $_.WorkloadTargetCount -gt 0 -and
        $_.Classification -eq 'DOMAIN-ALIGNED'
    }).Count -eq 0)

    $breakGlassTripwireMissing = (@($policyResults | Where-Object {
        $_.State -eq 'enabled' -and
        (Test-PolicyHasBreakGlassTripwireEvidence -PolicyResult $_ -BreakGlassCache $breakGlassCache)
    }).Count -eq 0)

    $baseScore = ($reportablePolicies | Measure-Object -Property ScoreImpact -Sum).Sum
    if ($null -eq $baseScore) { $baseScore = 0 }

    $gapPenalty = 0
    if ($privilegedBoundaryGap) { $gapPenalty -= 5 }
    if ($workloadIdentityGap) { $gapPenalty -= 3 }
    if ($breakGlassTripwireMissing) { $gapPenalty -= 3 }

    $overallScore = $baseScore + $gapPenalty
    if ($overallScore -lt 0) { $overallScore = 0 }

    $enabledScopeCount = @($policyResults | Where-Object { $_.State -eq 'enabled' }).Count
    $maxPossibleScore = [math]::Max(($enabledScopeCount * 2), 2)
    $scorePercent = [math]::Round(($overallScore / [double]$maxPossibleScore) * 100, 1)

    $verdict = if ($scorePercent -ge 80) {
        'DOMAIN-ALIGNED'
    } elseif ($scorePercent -ge 50) {
        'IN TRANSITION'
    } else {
        'APPLICATION-CENTRIC'
    }

    $scorecard = [pscustomobject]@{
        TenantId              = $script:GraphContext.TenantId
        Timestamp             = (Get-Date).ToString('s')
        OverallScore          = $overallScore
        MaxPossibleScore      = $maxPossibleScore
        ScorePercent          = $scorePercent
        Verdict               = $verdict
        PolicyCount           = $policyResults.Count
        Counts                = $counts
        GapFindings           = [pscustomobject]@{
            PrivilegedBoundaryGap     = $privilegedBoundaryGap
            WorkloadIdentityGap       = $workloadIdentityGap
            BreakGlassTripwireMissing = $breakGlassTripwireMissing
        }
        Policies              = @($policyResults | Sort-Object PolicyName)
        IndividualAssignments = @($individualAssignments)
        ExclusionGaps         = @($exclusionGaps)
    }

    Write-ConsoleSummary -Scorecard $scorecard

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeTenant = Sanitize-FileName -Name $scorecard.TenantId

    $htmlPath = Join-Path -Path $exportRoot -ChildPath ("CA-TenantScorecard-{0}-{1}.html" -f $safeTenant, $timestamp)
    $jsonPath = Join-Path -Path $exportRoot -ChildPath ("CA-TenantScorecard-{0}-{1}.json" -f $safeTenant, $timestamp)
    $csvPath  = Join-Path -Path $exportRoot -ChildPath ("CA-TenantScorecard-{0}-{1}.csv" -f $safeTenant, $timestamp)

    New-ScorecardHtmlReport -Scorecard $scorecard -OutputPath $htmlPath
    $scorecard | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        $scorecard.Policies |
        Select-Object PolicyId,PolicyName,State,Classification,DomainHint,IndividualNameCount,ExclusionGapCount,ScoreImpact,HasAllApps,HasAuthStrength,BuiltInControlsDisplay,HasSessionControls,WorkloadTargetCount |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host ''
    Write-Host "HTML report : $htmlPath" -ForegroundColor Cyan
    Write-Host "JSON export : $jsonPath" -ForegroundColor Cyan
    Write-Host "CSV export  : $csvPath" -ForegroundColor Cyan
}
catch {
    Write-Error "Fatal error during audit: $($_.Exception.Message)"
    if ($_.Exception.InnerException) {
        Write-Error "Inner exception: $($_.Exception.InnerException.Message)"
    }
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
