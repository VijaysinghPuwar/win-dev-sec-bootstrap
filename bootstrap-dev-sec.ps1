<#
.SYNOPSIS
    Windows developer and security workstation bootstrap and security assessment.

.DESCRIPTION
    Provisioning (default): installs a configurable tool catalog
    (config/packages.json) with winget, pipx and the VS Code CLI. Safe to
    re-run: installed packages are detected with exact ids and only upgraded,
    the session PATH is refreshed so tools installed earlier in the run are
    usable later in the same run, and the PowerShell profile is edited only
    inside a marked block.

    Assessment (-Assess): read-only evaluation of the Windows security
    controls in config/controls.json, written to JSON and HTML reports.

.PARAMETER Mode
    Lite: Core, NetDebug, QoL. Sec: adds SecTools. Full: adds DevLangs and Cloud.

.PARAMETER Only
    Provision exactly these categories. Cannot be combined with -Mode, -Include or -Skip.

.PARAMETER Include
    Add categories to the mode, for example the opt-in Containers or MalwareAnalysis.

.PARAMETER Skip
    Remove categories from the mode.

.PARAMETER WithWSL
    Enable the WSL and VirtualMachinePlatform optional features (restart required).

.PARAMETER WithDocker
    Shorthand for -Include Containers.

.PARAMETER SkipUpgrade
    Leave already-installed packages at their current version.

.PARAMETER SkipProfile
    Do not modify PowerShell profiles.

.PARAMETER DryRun
    Print the plan and exit without running winget, pipx, code or changing
    the system. Does not require Administrator. -WhatIf behaves the same way.

.PARAMETER Assess
    Run the read-only security assessment instead of provisioning.

.PARAMETER ReportDirectory
    Where assessment reports are written. Defaults to reports\ next to this script.

.PARAMETER LogPath
    Transcript path. Defaults to logs\bootstrap-<timestamp>.log next to this script.

.EXAMPLE
    .\bootstrap-dev-sec.ps1 -Mode Sec -DryRun

.EXAMPLE
    .\bootstrap-dev-sec.ps1 -Mode Full -Skip Cloud -WithWSL

.EXAMPLE
    .\bootstrap-dev-sec.ps1 -Assess

.NOTES
    Exit codes: 0 success, 1 fatal error (invalid arguments, missing
    prerequisite, not elevated), 2 completed with one or more failures.
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Provision')]
param(
    [Parameter(ParameterSetName = 'Provision')]
    [ValidateSet('Lite', 'Sec', 'Full')]
    [string]$Mode = 'Full',

    [Parameter(ParameterSetName = 'Provision')][string[]]$Only = @(),
    [Parameter(ParameterSetName = 'Provision')][string[]]$Include = @(),
    [Parameter(ParameterSetName = 'Provision')][string[]]$Skip = @(),
    [Parameter(ParameterSetName = 'Provision')][switch]$WithWSL,
    [Parameter(ParameterSetName = 'Provision')][switch]$WithDocker,
    [Parameter(ParameterSetName = 'Provision')][switch]$SkipUpgrade,
    [Parameter(ParameterSetName = 'Provision')][switch]$SkipProfile,
    [Parameter(ParameterSetName = 'Provision')][switch]$DryRun,

    [Parameter(ParameterSetName = 'Assess', Mandatory)][switch]$Assess,
    [Parameter(ParameterSetName = 'Assess')][string]$ReportDirectory,

    [string]$LogPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExitSuccess = 0
$ExitFatal = 1
$ExitPartial = 2

# Captured here because $PSBoundParameters inside a function refers to that function.
$ModeSpecified = $PSBoundParameters.ContainsKey('Mode')

foreach ($module in @('Common', 'PackageManager', 'Environment', 'SecurityAssessment', 'Reporting')) {
    Import-Module (Join-Path (Join-Path $PSScriptRoot 'modules') "$module.psm1") -Force
}

function Invoke-Provisioning {
    $catalog = Import-PackageCatalog -Path (Join-Path (Join-Path $PSScriptRoot 'config') 'packages.json')
    $includeList = @($Include)
    if ($WithDocker) { $includeList += 'Containers' }
    $categories = @(Resolve-CategorySelection -Catalog $catalog -Mode $Mode -Only $Only -Include $includeList -Skip $Skip `
        -ModeSpecified:$ModeSpecified)
    $plan = @(Get-ProvisioningPlan -Catalog $catalog -Category $categories)

    $isDryRun = $DryRun -or $WhatIfPreference
    Write-Status Info ("Categories: {0}" -f ($(if ($categories.Count) { $categories -join ', ' } else { '(none)' })))

    if (-not $isDryRun) {
        if (-not (Test-IsWindowsPlatform)) { Write-Status Error 'Provisioning requires Windows. Use -DryRun to preview the plan on other platforms.'; return $ExitFatal }
        if (-not (Test-IsAdministrator)) { Write-Status Error 'Run this script from an elevated (Administrator) PowerShell session, or use -DryRun.'; return $ExitFatal }
        if (@($plan | Where-Object { $_.source -eq 'winget' }).Count -gt 0 -and -not (Test-WingetAvailable)) {
            Write-Status Error "winget was not found. Install 'App Installer' from the Microsoft Store, then re-run."
            return $ExitFatal
        }
    }

    # Called by the package stage after winget installs and after pipx
    # reports its bin directory; never called during a dry run.
    $onPathChanged = {
        param($ExtraEntry)
        Update-SessionPath
        if ($ExtraEntry) { Add-SessionPathEntry -Path $ExtraEntry }
    }
    $results = @(Invoke-PackageProvisioning -Plan $plan -DryRun:$isDryRun -SkipUpgrade:$SkipUpgrade -OnPathChanged $onPathChanged -Confirm:$false)

    if ($WithWSL) {
        if ($isDryRun) {
            $results += [pscustomobject]@{ Source = 'feature'; Category = 'WSL'; Name = 'Microsoft-Windows-Subsystem-Linux, VirtualMachinePlatform'; Id = ''; Status = 'Planned'; Detail = 'Would enable'; ExitCode = $null; RestartRequired = $true }
        } else {
            Write-Status Info 'Enabling WSL2 prerequisites'
            $results += @(Enable-WslPrerequisite -Confirm:$false)
        }
    }

    if (-not $SkipProfile) {
        foreach ($profilePath in Get-ProfileTarget) {
            $target = Protect-SensitiveText $profilePath
            if ($isDryRun) {
                Write-Status Plan "Would add or refresh the managed block in $target"
                continue
            }
            $profileResult = Set-ManagedProfile -Path $profilePath -Confirm:$false
            $level = if ($profileResult.Status -eq 'Failed') { 'Error' } else { 'Ok' }
            Write-Status $level "Profile $($profileResult.Status): $target $(if ($profileResult.Backup) { "(backup: $(Protect-SensitiveText $profileResult.Backup))" })"
            if ($profileResult.Status -eq 'Failed') {
                $results += [pscustomobject]@{ Source = 'profile'; Category = 'Profile'; Name = $target; Id = ''; Status = 'Failed'; Detail = $profileResult.Detail; ExitCode = $null; RestartRequired = $false }
            }
        }
    }

    Write-ProvisioningSummary -Result $results
    if ($WithWSL -and -not $isDryRun) {
        Write-Status Info 'After restarting, install a distribution, for example: wsl --install -d Ubuntu'
    }
    if (@($results | Where-Object { $_.Status -eq 'Failed' }).Count -gt 0) { return $ExitPartial }
    $ExitSuccess
}

function Get-ReportDirectory {
    if ($ReportDirectory) { return $ReportDirectory }
    Join-Path $PSScriptRoot 'reports'
}

function Invoke-Assessment {
    if (-not (Test-IsWindowsPlatform)) { Write-Status Error 'The security assessment requires Windows.'; return $ExitFatal }
    if (-not (Test-IsAdministrator)) {
        Write-Status Warn 'Not elevated: controls that need Administrator rights (Defender exclusions, BitLocker, optional features) will report ERROR.'
    }
    $catalog = Import-ControlCatalog -Path (Join-Path (Join-Path $PSScriptRoot 'config') 'controls.json')
    $findings = @(Invoke-SecurityAssessment -Catalog $catalog)
    $report = New-AssessmentReport -Finding $findings
    Write-AssessmentSummary -Report $report
    $name = 'security-assessment-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
    $paths = Export-AssessmentReport -Report $report -Directory (Get-ReportDirectory) -BaseName $name -Confirm:$false -WhatIf:$false
    Write-Status Ok "Reports: $(Protect-SensitiveText $paths.Json), $(Protect-SensitiveText $paths.Html)"
    $ExitSuccess
}

if (-not $LogPath) {
    $LogPath = Join-Path (Join-Path $PSScriptRoot 'logs') ('bootstrap-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$transcriptStarted = $false
try {
    New-Item -ItemType Directory -Path (Split-Path $LogPath -Parent) -Force -WhatIf:$false | Out-Null
    Start-Transcript -Path $LogPath -WhatIf:$false | Out-Null
    $transcriptStarted = $true
} catch {
    Write-Status Warn "Could not start transcript: $($_.Exception.Message)"
}

$stopwatch = [Diagnostics.Stopwatch]::StartNew()
$exitCode = $ExitFatal
try {
    switch ($PSCmdlet.ParameterSetName) {
        'Assess' { $exitCode = Invoke-Assessment }
        default { $exitCode = Invoke-Provisioning }
    }
} catch {
    Write-Status Error $_.Exception.Message
    $exitCode = $ExitFatal
} finally {
    $stopwatch.Stop()
    Write-Status Info ('Finished in {0:hh\:mm\:ss} with exit code {1}' -f $stopwatch.Elapsed, $exitCode)
    if ($transcriptStarted) {
        Stop-Transcript -WhatIf:$false | Out-Null
        Write-Status Info "Log: $(Protect-SensitiveText $LogPath)"
    }
}
exit $exitCode
