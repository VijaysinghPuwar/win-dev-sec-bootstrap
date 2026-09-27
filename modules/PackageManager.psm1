#Requires -Version 5.1
<#
    Package catalog loading/validation, category resolution and idempotent
    installation through winget, pipx and the VS Code CLI.

    Every install function returns a result object with a Status of:
      Installed | Upgraded | Current | Planned | Manual | Skipped | Failed
    so the caller can summarise the run and pick a process exit code.
#>
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

$script:ValidModes = @('Lite', 'Sec', 'Full')
$script:ValidSources = @('winget', 'pipx', 'vscode', 'manual')

# Identifier formats. These double as an injection guard: every id ends up as
# a native command argument, so anything outside these character sets is
# rejected during validation.
$script:IdPatterns = @{
    winget = '^[A-Za-z0-9][A-Za-z0-9.+_-]*$'
    pipx   = '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    vscode = '^[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$'
}

# winget exit codes that this module treats specially. Values and names come
# from winget-cli doc/windows/package-manager/winget/returnCodes.md.
$script:WingetCodes = @{
    NoApplicationsFound     = -1978335212 # 0x8A150014
    UpdateNotApplicable     = -1978335189 # 0x8A15002B
    UpgradeVersionUnknown   = -1978335152 # 0x8A150050
    PackageAlreadyInstalled = -1978335135 # 0x8A150061
    PackageIsPinned         = -1978335128 # 0x8A150068
    RebootRequiredToFinish  = -1978334967 # 0x8A150109
    InstallAlreadyInstalled = -1978334963 # 0x8A15010D
}
$script:WingetCodeNames = @{
    -1978335216 = 'No applicable installer for this system'
    -1978335212 = 'No packages found'
    -1978335210 = 'Multiple packages found'
    -1978335189 = 'No applicable update found'
    -1978335174 = 'Blocked by Group Policy'
    -1978335152 = 'Installed version is unknown to winget'
    -1978335135 = 'Package already installed'
    -1978335128 = 'Package is pinned'
    -1978334975 = 'Application is currently running'
    -1978334967 = 'Restart required to finish installation'
    -1978334966 = 'Restart required before installation'
    -1978334964 = 'Installation cancelled'
    -1978334963 = 'Another version is already installed'
    -1978334961 = 'Installation blocked by organization policy'
    -1978334959 = 'Application is in use by another application'
}

#region Catalog

function Test-PackageCatalog {
    <#
    .SYNOPSIS
        Validates a parsed packages.json object. Returns a list of error
        strings; an empty list means the catalog is valid.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)]$Catalog)

    $errors = New-Object System.Collections.Generic.List[string]
    if ((Get-OptionalProperty $Catalog 'schemaVersion') -ne 1) { $errors.Add('schemaVersion must be 1') }

    $categories = @(Get-OptionalProperty $Catalog 'categories' @())
    $packages = @(Get-OptionalProperty $Catalog 'packages' @())
    if ($categories.Count -eq 0) { $errors.Add('categories must be a non-empty array') }
    if ($packages.Count -eq 0) { $errors.Add('packages must be a non-empty array') }

    $categoryNames = @{}
    foreach ($category in $categories) {
        $name = Get-OptionalProperty $category 'name'
        if (-not ($name -is [string]) -or $name -notmatch '^[A-Za-z][A-Za-z0-9]*$') {
            $errors.Add("Invalid category name '$name'"); continue
        }
        if ($categoryNames.ContainsKey($name)) { $errors.Add("Duplicate category '$name'") }
        $categoryNames[$name] = $true
        foreach ($mode in @(Get-OptionalProperty $category 'modes' @())) {
            if ($script:ValidModes -notcontains $mode) { $errors.Add("Category '$name' references unknown mode '$mode'") }
        }
    }

    $seen = @{}
    $index = 0
    foreach ($package in $packages) {
        $index++
        $label = "packages[$index]"
        $source = Get-OptionalProperty $package 'source'
        $name = Get-OptionalProperty $package 'name'
        $category = Get-OptionalProperty $package 'category'
        if ([string]::IsNullOrWhiteSpace($name)) { $errors.Add("${label}: name is required") } else { $label = "$label ($name)" }
        if ($script:ValidSources -notcontains $source) { $errors.Add("${label}: unknown source '$source'"); continue }
        if (-not $categoryNames.ContainsKey([string]$category)) { $errors.Add("${label}: unknown category '$category'") }

        if ($source -eq 'manual') {
            $url = Get-OptionalProperty $package 'url'
            if ($url -notmatch '^https://') { $errors.Add("${label}: manual packages need an https url") }
            if ([string]::IsNullOrWhiteSpace((Get-OptionalProperty $package 'reason'))) { $errors.Add("${label}: manual packages need a reason") }
            continue
        }

        $id = Get-OptionalProperty $package 'id'
        if (-not ($id -is [string]) -or $id -notmatch $script:IdPatterns[$source]) {
            $errors.Add("${label}: invalid $source id '$id'"); continue
        }
        $key = "$source|$($id.ToLowerInvariant())"
        if ($seen.ContainsKey($key)) { $errors.Add("${label}: duplicate $source id '$id'") }
        $seen[$key] = $true
    }

    # A tool offered by two package managers ends up installed twice with two
    # different update paths (mitmproxy was installed by winget and pipx).
    $wingetNames = @($packages | Where-Object { (Get-OptionalProperty $_ 'source') -eq 'winget' } | ForEach-Object { $_.name.ToLowerInvariant() })
    foreach ($package in $packages | Where-Object { (Get-OptionalProperty $_ 'source') -eq 'pipx' }) {
        if ($wingetNames -contains $package.name.ToLowerInvariant()) {
            $errors.Add("Package '$($package.name)' is listed for both winget and pipx")
        }
    }
    $errors.ToArray()
}

function Import-PackageCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $catalog = Read-JsonFile -Path $Path
    $errors = @(Test-PackageCatalog -Catalog $catalog)
    if ($errors.Count -gt 0) {
        throw ("Package catalog '{0}' is invalid:`n  - {1}" -f $Path, ($errors -join "`n  - "))
    }
    $catalog
}

function Resolve-CategorySelection {
    <#
    .SYNOPSIS
        Turns -Mode/-Only/-Include/-Skip into the ordered list of categories
        to provision. Throws on unknown names or contradictory arguments.
    .NOTES
        -Only replaces the mode's category list entirely, so combining it with
        -Mode, -Include or -Skip is rejected rather than silently ignored.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]$Catalog,
        [ValidateSet('Lite', 'Sec', 'Full')][string]$Mode = 'Full',
        [string[]]$Only = @(),
        [string[]]$Include = @(),
        [string[]]$Skip = @(),
        [switch]$ModeSpecified
    )
    # `powershell -File script.ps1 -Only A,B` passes "A,B" as one string, so
    # accept comma-separated values as well as real arrays.
    $split = { param($Values) @($Values | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $Only = @(& $split $Only)
    $Include = @(& $split $Include)
    $Skip = @(& $split $Skip)

    $all = @($Catalog.categories | ForEach-Object { $_.name })
    foreach ($pair in @(@('Only', $Only), @('Include', $Include), @('Skip', $Skip))) {
        foreach ($name in @($pair[1])) {
            if ($all -notcontains $name) {
                throw "Unknown category '$name' in -$($pair[0]). Valid categories: $($all -join ', ')"
            }
        }
    }

    if (@($Only).Count -gt 0) {
        if ($ModeSpecified) { throw '-Only cannot be combined with -Mode.' }
        if (@($Include).Count -gt 0 -or @($Skip).Count -gt 0) { throw '-Only cannot be combined with -Include or -Skip.' }
        $selected = @($Only)
    } else {
        $overlap = @($Include | Where-Object { $Skip -contains $_ })
        if ($overlap.Count -gt 0) { throw "Categories listed in both -Include and -Skip: $($overlap -join ', ')" }
        $selected = @($Catalog.categories | Where-Object { @($_.modes) -contains $Mode } | ForEach-Object { $_.name }) + @($Include)
        $selected = @($selected | Where-Object { $Skip -notcontains $_ })
    }

    # Return in catalog order, de-duplicated (case-insensitive like PowerShell itself).
    $all | Where-Object { $selected -contains $_ }
}

function Get-ProvisioningPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Catalog,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Category
    )
    $Catalog.packages | Where-Object { $Category -contains $_.category }
}

#endregion

#region Result objects

function New-PackageResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Package,
        [Parameter(Mandatory)][ValidateSet('Installed', 'Upgraded', 'Current', 'Planned', 'Manual', 'Skipped', 'Failed')][string]$Status,
        [string]$Detail = '',
        [Nullable[int]]$ExitCode = $null,
        [switch]$RestartRequired
    )
    [pscustomobject]@{
        Source          = $Package.source
        Category        = $Package.category
        Name            = $Package.name
        Id              = Get-OptionalProperty $Package 'id' ''
        Status          = $Status
        Detail          = $Detail
        ExitCode        = $ExitCode
        RestartRequired = [bool]$RestartRequired
    }
}

function Get-WingetExitDescription {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][int]$ExitCode)
    $hex = '0x{0:X8}' -f $ExitCode
    if ($script:WingetCodeNames.ContainsKey($ExitCode)) { return "$hex ($($script:WingetCodeNames[$ExitCode]))" }
    $hex
}

function Get-LastOutputLine {
    # Native tools print progress bars and spinners; keep the last line that
    # carries words so failures stay readable in the summary.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][AllowNull()][string]$Output)
    if ([string]::IsNullOrWhiteSpace($Output)) { return '' }
    $lines = @($Output -split "`r?`n|`r" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '[A-Za-z]{3}' })
    if ($lines.Count -eq 0) { return '' }
    $lines[-1]
}

#endregion

#region Native command wrappers (mocked in tests)

function Invoke-NativeCommand {
    <#
    .SYNOPSIS
        Runs a native executable with an argument array (no string
        concatenation, no cmd /c) and returns its exit code and output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    if (-not (Get-Command -Name $FilePath -CommandType Application -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ExitCode = -1; Output = "Command not found: $FilePath" }
    }
    # With 'Stop', Windows PowerShell 5.1 turns any stderr line of a native
    # command into a terminating error. Exit codes are checked explicitly.
    $ErrorActionPreference = 'Continue'
    $output = & $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" } | Out-String
    [pscustomobject]@{ ExitCode = [int]$LASTEXITCODE; Output = $output }
}

function Invoke-Winget {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$ArgumentList)
    Invoke-NativeCommand -FilePath 'winget' -ArgumentList $ArgumentList
}

function Test-WingetAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    [bool](Get-Command winget -CommandType Application -ErrorAction SilentlyContinue)
}

#endregion

#region winget

function Install-WingetPackage {
    <#
    .SYNOPSIS
        Installs a winget package, or upgrades it when it is already present.
        Detection uses an exact id match against the winget source.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Package,
        [switch]$SkipUpgrade
    )
    $id = $Package.id
    $common = @('--id', $id, '--exact', '--source', 'winget', '--accept-source-agreements', '--disable-interactivity')

    $list = Invoke-Winget -ArgumentList (@('list') + $common)
    if ($list.ExitCode -eq 0) {
        if ($SkipUpgrade) { return New-PackageResult -Package $Package -Status Current -Detail 'Already installed (upgrade skipped)' }
        if (-not $PSCmdlet.ShouldProcess($id, 'winget upgrade')) { return New-PackageResult -Package $Package -Status Skipped -Detail 'Upgrade not confirmed' }
        $upgrade = Invoke-Winget -ArgumentList (@('upgrade') + $common + @('--silent', '--accept-package-agreements'))
        switch ($upgrade.ExitCode) {
            0 { return New-PackageResult -Package $Package -Status Upgraded -Detail 'Upgraded to the latest version' -ExitCode 0 }
            $script:WingetCodes.UpdateNotApplicable { return New-PackageResult -Package $Package -Status Current -Detail 'Already up to date' -ExitCode $upgrade.ExitCode }
            $script:WingetCodes.UpgradeVersionUnknown { return New-PackageResult -Package $Package -Status Current -Detail 'Installed; version unknown to winget so it was not upgraded' -ExitCode $upgrade.ExitCode }
            $script:WingetCodes.PackageIsPinned { return New-PackageResult -Package $Package -Status Current -Detail 'Installed; pinned in winget so it was not upgraded' -ExitCode $upgrade.ExitCode }
            $script:WingetCodes.RebootRequiredToFinish { return New-PackageResult -Package $Package -Status Upgraded -Detail 'Upgraded; restart required to finish' -ExitCode $upgrade.ExitCode -RestartRequired }
            default {
                $detail = "winget upgrade failed: $(Get-WingetExitDescription $upgrade.ExitCode) $(Get-LastOutputLine $upgrade.Output)".Trim()
                return New-PackageResult -Package $Package -Status Failed -Detail $detail -ExitCode $upgrade.ExitCode
            }
        }
    }

    if ($list.ExitCode -ne $script:WingetCodes.NoApplicationsFound) {
        $detail = "winget list failed: $(Get-WingetExitDescription $list.ExitCode) $(Get-LastOutputLine $list.Output)".Trim()
        return New-PackageResult -Package $Package -Status Failed -Detail $detail -ExitCode $list.ExitCode
    }

    if (-not $PSCmdlet.ShouldProcess($id, 'winget install')) { return New-PackageResult -Package $Package -Status Skipped -Detail 'Install not confirmed' }
    $install = Invoke-Winget -ArgumentList (@('install') + $common + @('--silent', '--accept-package-agreements'))
    switch ($install.ExitCode) {
        0 { return New-PackageResult -Package $Package -Status Installed -Detail 'Installed' -ExitCode 0 }
        $script:WingetCodes.PackageAlreadyInstalled { return New-PackageResult -Package $Package -Status Current -Detail 'Already installed' -ExitCode $install.ExitCode }
        $script:WingetCodes.InstallAlreadyInstalled { return New-PackageResult -Package $Package -Status Current -Detail 'Another version is already installed' -ExitCode $install.ExitCode }
        $script:WingetCodes.RebootRequiredToFinish { return New-PackageResult -Package $Package -Status Installed -Detail 'Installed; restart required to finish' -ExitCode $install.ExitCode -RestartRequired }
        default {
            $detail = "winget install failed: $(Get-WingetExitDescription $install.ExitCode) $(Get-LastOutputLine $install.Output)".Trim()
            return New-PackageResult -Package $Package -Status Failed -Detail $detail -ExitCode $install.ExitCode
        }
    }
}

#endregion

#region pipx

function Resolve-PythonCommand {
    <#
    .SYNOPSIS
        Returns the command (as an argument prefix array) that runs Python 3,
        or $null. Prefers the py launcher and ignores the Microsoft Store
        "App execution alias" stub in WindowsApps, which opens the Store
        instead of running Python.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()
    $launcher = Get-Command py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($launcher) { return , @($launcher.Source, '-3') }
    foreach ($candidate in @(Get-Command python -CommandType Application -All -ErrorAction SilentlyContinue)) {
        if ($candidate.Source -notmatch '\\WindowsApps\\') { return , @($candidate.Source) }
    }
    $null
}

function Invoke-Python {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$PythonCommand,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )
    $prefix = @($PythonCommand | Select-Object -Skip 1)
    Invoke-NativeCommand -FilePath $PythonCommand[0] -ArgumentList ($prefix + $ArgumentList)
}

function Initialize-Pipx {
    <#
    .SYNOPSIS
        Ensures pipx is importable by the given Python, runs `pipx ensurepath`
        (idempotent, handles the persistent user PATH itself) and returns the
        pipx bin directory so the caller can add it to this session's PATH.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string[]]$PythonCommand)

    $check = Invoke-Python -PythonCommand $PythonCommand -ArgumentList @('-m', 'pipx', '--version')
    if ($check.ExitCode -ne 0) {
        if (-not $PSCmdlet.ShouldProcess('pipx', 'pip install --user')) { throw 'pipx is not installed and installation was not confirmed.' }
        $install = Invoke-Python -PythonCommand $PythonCommand -ArgumentList @('-m', 'pip', 'install', '--user', '--upgrade', '--disable-pip-version-check', 'pipx')
        if ($install.ExitCode -ne 0) { throw "pip could not install pipx (exit $($install.ExitCode)): $(Get-LastOutputLine $install.Output)" }
    }
    $ensure = Invoke-Python -PythonCommand $PythonCommand -ArgumentList @('-m', 'pipx', 'ensurepath')
    if ($ensure.ExitCode -ne 0) { Write-Status Warn "pipx ensurepath returned $($ensure.ExitCode): $(Get-LastOutputLine $ensure.Output)" }

    $binDir = Invoke-Python -PythonCommand $PythonCommand -ArgumentList @('-m', 'pipx', 'environment', '--value', 'PIPX_BIN_DIR')
    if ($binDir.ExitCode -eq 0) { return $binDir.Output.Trim() }
    $null
}

function Get-PipxInstalledPackage {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string[]]$PythonCommand)
    $list = Invoke-Python -PythonCommand $PythonCommand -ArgumentList @('-m', 'pipx', 'list', '--short')
    if ($list.ExitCode -ne 0) { throw "pipx list failed (exit $($list.ExitCode)): $(Get-LastOutputLine $list.Output)" }
    # Each line is "<package> <version>".
    $list.Output -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { ($_.Trim() -split '\s+')[0].ToLowerInvariant() }
}

function Install-PipxPackage {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Package,
        [Parameter(Mandatory)][string[]]$PythonCommand,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$InstalledPackage,
        [switch]$SkipUpgrade
    )
    $id = $Package.id
    if ($InstalledPackage -contains $id.ToLowerInvariant()) {
        if ($SkipUpgrade) { return New-PackageResult -Package $Package -Status Current -Detail 'Already installed (upgrade skipped)' }
        if (-not $PSCmdlet.ShouldProcess($id, 'pipx upgrade')) { return New-PackageResult -Package $Package -Status Skipped -Detail 'Upgrade not confirmed' }
        $upgrade = Invoke-Python -PythonCommand $PythonCommand -ArgumentList @('-m', 'pipx', 'upgrade', $id)
        if ($upgrade.ExitCode -eq 0) { return New-PackageResult -Package $Package -Status Current -Detail 'Installed; pipx upgrade completed' -ExitCode 0 }
        return New-PackageResult -Package $Package -Status Failed -Detail "pipx upgrade failed (exit $($upgrade.ExitCode)): $(Get-LastOutputLine $upgrade.Output)" -ExitCode $upgrade.ExitCode
    }
    if (-not $PSCmdlet.ShouldProcess($id, 'pipx install')) { return New-PackageResult -Package $Package -Status Skipped -Detail 'Install not confirmed' }
    $install = Invoke-Python -PythonCommand $PythonCommand -ArgumentList @('-m', 'pipx', 'install', $id)
    if ($install.ExitCode -eq 0) { return New-PackageResult -Package $Package -Status Installed -Detail 'Installed in an isolated pipx environment' -ExitCode 0 }
    New-PackageResult -Package $Package -Status Failed -Detail "pipx install failed (exit $($install.ExitCode)): $(Get-LastOutputLine $install.Output)" -ExitCode $install.ExitCode
}

#endregion

#region VS Code

function Resolve-CodeCommand {
    [CmdletBinding()]
    param()
    $code = Get-Command code -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($code) { return $code.Source }
    $null
}

function Get-VSCodeInstalledExtension {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$CodeCommand)
    $list = Invoke-NativeCommand -FilePath $CodeCommand -ArgumentList @('--list-extensions')
    if ($list.ExitCode -ne 0) { throw "code --list-extensions failed (exit $($list.ExitCode))" }
    $list.Output -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim().ToLowerInvariant() }
}

function Install-VSCodeExtension {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Package,
        [Parameter(Mandatory)][string]$CodeCommand,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$InstalledExtension
    )
    # VS Code keeps installed extensions updated itself, so an installed
    # extension is reported as Current instead of being force-reinstalled.
    if ($InstalledExtension -contains $Package.id.ToLowerInvariant()) { return New-PackageResult -Package $Package -Status Current -Detail 'Already installed' }
    if (-not $PSCmdlet.ShouldProcess($Package.id, 'code --install-extension')) { return New-PackageResult -Package $Package -Status Skipped -Detail 'Install not confirmed' }
    $install = Invoke-NativeCommand -FilePath $CodeCommand -ArgumentList @('--install-extension', $Package.id)
    if ($install.ExitCode -eq 0) { return New-PackageResult -Package $Package -Status Installed -Detail 'Installed' -ExitCode 0 }
    New-PackageResult -Package $Package -Status Failed -Detail "Extension install failed (exit $($install.ExitCode)): $(Get-LastOutputLine $install.Output)" -ExitCode $install.ExitCode
}

#endregion

#region Orchestration

function Invoke-PackageProvisioning {
    <#
    .SYNOPSIS
        Installs a resolved plan in dependency order: winget packages first,
        then a PATH refresh, then pipx tools (need Python) and VS Code
        extensions (need the `code` CLI). With -DryRun nothing external is
        executed; every entry is reported as Planned or Manual.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Plan,
        [switch]$DryRun,
        [switch]$SkipUpgrade,
        # Invoked after the winget stage so newly installed tools are found.
        [scriptblock]$OnPathChanged = {}
    )
    $results = New-Object System.Collections.Generic.List[object]
    $bySource = @{}
    foreach ($source in $script:ValidSources) { $bySource[$source] = @($Plan | Where-Object { $_.source -eq $source }) }

    foreach ($package in $bySource['manual']) {
        $results.Add((New-PackageResult -Package $package -Status Manual -Detail "$($package.reason) Download: $($package.url)"))
    }

    if ($DryRun) {
        foreach ($source in @('winget', 'pipx', 'vscode')) {
            foreach ($package in $bySource[$source]) { $results.Add((New-PackageResult -Package $package -Status Planned -Detail "Would ensure via $source")) }
        }
        return $results.ToArray()
    }

    foreach ($package in $bySource['winget']) {
        Write-Status Info "winget: $($package.name) ($($package.id))"
        $results.Add((Install-WingetPackage -Package $package -SkipUpgrade:$SkipUpgrade))
    }
    & $OnPathChanged

    if ($bySource['pipx'].Count -gt 0) {
        $python = Resolve-PythonCommand
        $pipxError = $null
        $installed = @()
        if (-not $python) {
            $pipxError = 'Python 3 was not found on PATH (the Store alias stub is ignored). Include the Core category or install Python first.'
        } else {
            try {
                $binDir = Initialize-Pipx -PythonCommand $python
                if ($binDir) { & $OnPathChanged $binDir }
                $installed = @(Get-PipxInstalledPackage -PythonCommand $python)
            } catch { $pipxError = $_.Exception.Message }
        }
        foreach ($package in $bySource['pipx']) {
            if ($pipxError) { $results.Add((New-PackageResult -Package $package -Status Failed -Detail "Prerequisite missing: $pipxError")); continue }
            Write-Status Info "pipx: $($package.name) ($($package.id))"
            $results.Add((Install-PipxPackage -Package $package -PythonCommand $python -InstalledPackage $installed -SkipUpgrade:$SkipUpgrade))
        }
    }

    if ($bySource['vscode'].Count -gt 0) {
        $code = Resolve-CodeCommand
        $codeError = $null
        $installedExtensions = @()
        if (-not $code) {
            $codeError = "The VS Code 'code' CLI was not found on PATH. Include the Core category or install VS Code first."
        } else {
            try { $installedExtensions = @(Get-VSCodeInstalledExtension -CodeCommand $code) } catch { $codeError = $_.Exception.Message }
        }
        foreach ($package in $bySource['vscode']) {
            if ($codeError) { $results.Add((New-PackageResult -Package $package -Status Failed -Detail "Prerequisite missing: $codeError")); continue }
            Write-Status Info "VS Code: $($package.name) ($($package.id))"
            $results.Add((Install-VSCodeExtension -Package $package -CodeCommand $code -InstalledExtension $installedExtensions))
        }
    }
    $results.ToArray()
}

#endregion

Export-ModuleMember -Function Test-PackageCatalog, Import-PackageCatalog, Resolve-CategorySelection, Get-ProvisioningPlan,
    New-PackageResult, Get-WingetExitDescription, Get-LastOutputLine, Invoke-NativeCommand, Invoke-Winget, Test-WingetAvailable,
    Install-WingetPackage, Resolve-PythonCommand, Invoke-Python, Initialize-Pipx, Get-PipxInstalledPackage, Install-PipxPackage,
    Resolve-CodeCommand, Get-VSCodeInstalledExtension, Install-VSCodeExtension, Invoke-PackageProvisioning
