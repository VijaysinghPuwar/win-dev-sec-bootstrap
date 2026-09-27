#Requires -Version 5.1
<#
    Session PATH refresh, the managed PowerShell profile block and the
    Windows features needed by WSL2.
#>
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

$script:BlockBegin = '# BEGIN win-dev-sec-bootstrap'
$script:BlockEnd = '# END win-dev-sec-bootstrap'

#region PATH

function Merge-PathEntry {
    <#
    .SYNOPSIS
        Splits one or more PATH strings, drops empty entries and removes
        duplicates while keeping the first occurrence. Entries compare
        case-insensitively and ignore a trailing backslash, which is how
        Windows resolves them.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][AllowEmptyString()][AllowEmptyCollection()][string[]]$Entry)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $merged = New-Object System.Collections.Generic.List[string]
    foreach ($value in @($Entry)) {
        if ([string]::IsNullOrEmpty($value)) { continue }
        foreach ($part in $value.Split(';')) {
            $trimmed = $part.Trim().Trim('"')
            if (-not $trimmed) { continue }
            $key = $trimmed
            if ($key.Length -gt 3) { $key = $key.TrimEnd('\') }
            if ($seen.Add($key)) { $merged.Add($trimmed) }
        }
    }
    $merged.ToArray()
}

function Get-PersistentPath {
    <#
    .SYNOPSIS
        Reads the stored Machine or User PATH. The .NET API expands
        REG_EXPAND_SZ values such as %SystemRoot%.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][ValidateSet('Machine', 'User')][string]$Scope)
    [Environment]::GetEnvironmentVariable('Path', $Scope)
}

function Update-SessionPath {
    <#
    .SYNOPSIS
        Rebuilds this process's PATH from the stored Machine and User values
        so executables installed during this run can be found without opening
        a new terminal. Entries that exist only in this session (for example
        an activated virtual environment) are kept at the end.
    .NOTES
        Only the current process is changed; the persistent PATH is never
        written here.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $merged = @(Merge-PathEntry -Entry @((Get-PersistentPath -Scope Machine), (Get-PersistentPath -Scope User), $env:Path))
    if ($PSCmdlet.ShouldProcess('current process PATH', 'Refresh from Machine and User scopes')) {
        $env:Path = $merged -join ';'
    }
}

function Add-SessionPathEntry {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    if ($PSCmdlet.ShouldProcess('current process PATH', "Add $Path")) {
        $env:Path = @(Merge-PathEntry -Entry @($env:Path, $Path)) -join ';'
    }
}

#endregion

#region PowerShell profile

function Get-ManagedProfileBlock {
    <#
    .SYNOPSIS
        Returns the static profile block. Every integration is guarded so a
        missing tool never produces an error when a shell starts.
    .NOTES
        Built-in aliases such as cat/ls are deliberately not overridden:
        replacing Get-Content with bat changes pipeline behaviour for scripts
        run from the interactive session.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $lines = @(
        $script:BlockBegin
        '# Managed by win-dev-sec-bootstrap. Changes inside this block are replaced on the next run.'
        'if (Get-Module -ListAvailable -Name PSReadLine) {'
        '    Import-Module PSReadLine -ErrorAction SilentlyContinue'
        '    # Predictive IntelliSense list view needs PSReadLine 2.2+ (Windows PowerShell 5.1 ships 2.0).'
        "    if ((Get-Module PSReadLine).Version -ge [version]'2.2.0') {"
        '        Set-PSReadLineOption -PredictionSource History -PredictionViewStyle ListView'
        '    }'
        '}'
        'if (Get-Command oh-my-posh -CommandType Application -ErrorAction SilentlyContinue) {'
        '    oh-my-posh init pwsh | Invoke-Expression'
        '}'
        'if (Get-Command rg -CommandType Application -ErrorAction SilentlyContinue) {'
        '    Set-Alias -Name grep -Value rg'
        '}'
        'Set-Alias -Name ll -Value Get-ChildItem'
        $script:BlockEnd
    )
    $lines -join "`r`n"
}

function Merge-ManagedBlock {
    <#
    .SYNOPSIS
        Returns profile text with the managed block inserted or replaced.
        Content outside the markers is preserved byte-for-byte. Throws when
        the markers are unbalanced or duplicated rather than guessing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()][AllowNull()][string]$Content,
        [Parameter(Mandatory)][string]$Block
    )
    if ($null -eq $Content) { $Content = '' }
    $newline = if ($Content -match "`r`n") { "`r`n" } elseif ($Content -match "`n") { "`n" } else { "`r`n" }
    $normalizedBlock = ($Block -split "`r?`n") -join $newline

    $beginPattern = '(?m)^[ \t]*' + [regex]::Escape($script:BlockBegin) + '[^\r\n]*'
    $endPattern = '(?m)^[ \t]*' + [regex]::Escape($script:BlockEnd) + '[^\r\n]*'
    $begins = [regex]::Matches($Content, $beginPattern)
    $ends = [regex]::Matches($Content, $endPattern)

    if ($begins.Count -eq 0 -and $ends.Count -eq 0) {
        if ($Content.Length -eq 0) { return $normalizedBlock + $newline }
        $separator = if ($Content.EndsWith("`n")) { $newline } else { $newline + $newline }
        return $Content + $separator + $normalizedBlock + $newline
    }
    if ($begins.Count -ne 1 -or $ends.Count -ne 1 -or $ends[0].Index -lt $begins[0].Index) {
        throw 'The profile contains unbalanced or duplicate win-dev-sec-bootstrap markers. Fix them manually; the profile was not changed.'
    }
    $start = $begins[0].Index
    $stop = $ends[0].Index + $ends[0].Length
    $Content.Substring(0, $start) + $normalizedBlock + $Content.Substring($stop)
}

function Get-ProfileTarget {
    <#
    .SYNOPSIS
        CurrentUserCurrentHost profile paths for PowerShell 7 and Windows
        PowerShell 5.1. Uses the real Documents folder, which may be
        redirected to OneDrive.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $documents = [Environment]::GetFolderPath('MyDocuments')
    Join-Path (Join-Path $documents 'PowerShell') 'Microsoft.PowerShell_profile.ps1'
    Join-Path (Join-Path $documents 'WindowsPowerShell') 'Microsoft.PowerShell_profile.ps1'
}

function Set-ManagedProfile {
    <#
    .SYNOPSIS
        Inserts or refreshes the managed block in one profile file. The
        existing file is backed up before the first change; an unchanged
        profile is not rewritten.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Block = (Get-ManagedProfileBlock)
    )
    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    $current = if ($exists) { Get-Content -LiteralPath $Path -Raw } else { '' }
    if ($null -eq $current) { $current = '' }

    try {
        $updated = Merge-ManagedBlock -Content $current -Block $Block
    } catch {
        return [pscustomobject]@{ Path = $Path; Status = 'Failed'; Detail = $_.Exception.Message; Backup = $null }
    }
    if ($exists -and $updated -ceq $current) {
        return [pscustomobject]@{ Path = $Path; Status = 'Current'; Detail = 'Managed block already up to date'; Backup = $null }
    }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Update managed profile block')) {
        return [pscustomobject]@{ Path = $Path; Status = 'Skipped'; Detail = 'Not confirmed'; Backup = $null }
    }

    $backup = $null
    if ($exists) {
        $backup = '{0}.bak-{1}' -f $Path, (Get-Date -Format 'yyyyMMdd-HHmmss')
        Copy-Item -LiteralPath $Path -Destination $backup -ErrorAction Stop
    }
    # BOM so Windows PowerShell 5.1 reads any non-ASCII user content correctly.
    Write-Utf8File -Path $Path -Content $updated -WithBom -WhatIf:$false
    $status = if ($exists) { 'Updated' } else { 'Created' }
    [pscustomobject]@{ Path = $Path; Status = $status; Detail = 'Managed block written'; Backup = $backup }
}

#endregion

#region WSL

function Enable-WslPrerequisite {
    <#
    .SYNOPSIS
        Enables the two optional features WSL2 needs. Already-enabled features
        are reported as Current and left alone.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $newResult = {
        param($Feature, $Status, $Detail, $Restart)
        [pscustomobject]@{
            Source = 'feature'; Category = 'WSL'; Name = $Feature; Id = $Feature
            Status = $Status; Detail = $Detail; ExitCode = $null; RestartRequired = [bool]$Restart
        }
    }
    foreach ($feature in @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')) {
        try {
            $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction Stop
            if ($state -and "$($state.State)" -eq 'Enabled') {
                & $newResult $feature 'Current' 'Already enabled' $false
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($feature, 'Enable Windows optional feature')) {
                & $newResult $feature 'Skipped' 'Not confirmed' $false
                continue
            }
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart -ErrorAction Stop
            & $newResult $feature 'Installed' 'Enabled' $result.RestartNeeded
        } catch {
            & $newResult $feature 'Failed' $_.Exception.Message $false
        }
    }
}

#endregion

Export-ModuleMember -Function Merge-PathEntry, Get-PersistentPath, Update-SessionPath, Add-SessionPathEntry,
    Get-ManagedProfileBlock, Merge-ManagedBlock, Get-ProfileTarget, Set-ManagedProfile, Enable-WslPrerequisite
