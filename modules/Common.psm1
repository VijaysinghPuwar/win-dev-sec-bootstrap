#Requires -Version 5.1
<#
    Shared helpers: console output, platform checks, JSON file I/O and
    redaction of user-identifying strings in report evidence.

    All PowerShell files in this repository are kept ASCII-only so that
    Windows PowerShell 5.1 (which reads BOM-less files as ANSI) parses and
    displays them the same way PowerShell 7 does.
#>
Set-StrictMode -Version 2.0

$script:ToolName = 'win-dev-sec-bootstrap'
$script:ToolVersion = '2.0.0'

function Get-ToolInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()
    [pscustomobject]@{ Name = $script:ToolName; Version = $script:ToolVersion }
}

function Write-Status {
    <#
    .SYNOPSIS
        Writes a prefixed, colored status line to the console (and transcript).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification = 'Interactive console status output; Write-Host feeds the information stream and the transcript in PS 5+.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Info', 'Ok', 'Warn', 'Error', 'Plan', 'Detail')][string]$Level,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message
    )
    $style = @{
        Info   = @('[*]', 'Cyan')
        Ok     = @('[+]', 'Green')
        Warn   = @('[!]', 'Yellow')
        Error  = @('[x]', 'Red')
        Plan   = @('[~]', 'Magenta')
        Detail = @('   ', 'Gray')
    }[$Level]
    Write-Host ('{0} {1}' -f $style[0], $Message) -ForegroundColor $style[1]
}

function Test-IsWindowsPlatform {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    # $IsWindows does not exist in Windows PowerShell 5.1, so use the runtime API.
    [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Test-IsAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (-not (Test-IsWindowsPlatform)) { return $false }
    $principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-OptionalProperty {
    <#
    .SYNOPSIS
        Returns a property value or a default when the property is absent.
        Needed because strict mode throws on missing properties, and optional
        JSON fields / edition-dependent cmdlet output are expected here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    $property.Value
}

function Read-JsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "JSON file not found: $Path"
    }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    try {
        $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Invalid JSON in ${Path}: $($_.Exception.Message)"
    }
}

function Write-Utf8File {
    <#
    .SYNOPSIS
        Writes text as UTF-8. BOM-less by default (JSON/HTML consumers);
        -WithBom for PowerShell scripts that Windows PowerShell 5.1 must read.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [switch]$WithBom
    )
    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force -WhatIf:$false | Out-Null
    }
    if ($PSCmdlet.ShouldProcess($Path, 'Write file')) {
        $encoding = New-Object System.Text.UTF8Encoding ([bool]$WithBom)
        # .NET resolves relative paths against the process directory, not $PWD.
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        [System.IO.File]::WriteAllText($fullPath, $Content, $encoding)
    }
}

function Write-JsonFile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$InputObject
    )
    $json = ConvertTo-Json -InputObject $InputObject -Depth 12
    Write-Utf8File -Path $Path -Content $json -WhatIf:$WhatIfPreference
}

function Protect-SensitiveText {
    <#
    .SYNOPSIS
        Replaces the current user's profile path and user name in free text,
        so reports and backups can be shared without identifying the user.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Text,
        [string]$UserProfile = $env:USERPROFILE,
        [string]$UserName = $env:USERNAME
    )
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $result = $Text
    if ($UserProfile) {
        $result = [regex]::Replace($result, [regex]::Escape($UserProfile), '%USERPROFILE%', 'IgnoreCase')
    }
    # Only whole path segments, to avoid mangling unrelated words that happen
    # to contain a short user name.
    if ($UserName -and $UserName.Length -ge 3) {
        $pattern = '(?<=[\\/])' + [regex]::Escape($UserName) + '(?=[\\/]|$)'
        $result = [regex]::Replace($result, $pattern, '<user>', 'IgnoreCase')
    }
    $result
}

Export-ModuleMember -Function Get-ToolInfo, Write-Status, Test-IsWindowsPlatform, Test-IsAdministrator,
    Get-OptionalProperty, Read-JsonFile, Write-Utf8File, Write-JsonFile, Protect-SensitiveText
