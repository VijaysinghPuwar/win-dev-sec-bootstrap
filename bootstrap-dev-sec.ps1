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

    Remediation (-Remediate): assesses, then applies automated fixes for
    failing controls. Each change is confirmed individually (use -WhatIf to
    preview, -Confirm:$false for unattended runs), backed up first, and
    verified afterwards. -Rollback restores the values from a backup file.

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

.PARAMETER Remediate
    Assess, then remediate failing controls that support automated remediation.

.PARAMETER ControlId
    Limit remediation to these control ids (for example WIN-PS-001).

.PARAMETER Rollback
    Restore the settings recorded in a remediation backup file.

.PARAMETER BackupFile
    Backup file for -Rollback. Defaults to the newest file in backup\.

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

.EXAMPLE
    .\bootstrap-dev-sec.ps1 -Remediate -WhatIf

.EXAMPLE
    .\bootstrap-dev-sec.ps1 -Remediate -ControlId WIN-PS-001,WIN-NET-001

.EXAMPLE
    .\bootstrap-dev-sec.ps1 -Rollback

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

    [Parameter(ParameterSetName = 'Remediate', Mandatory)][switch]$Remediate,
    [Parameter(ParameterSetName = 'Remediate')][string[]]$ControlId = @(),

    [Parameter(ParameterSetName = 'Rollback', Mandatory)][switch]$Rollback,
    [Parameter(ParameterSetName = 'Rollback')][string]$BackupFile,

    [Parameter(ParameterSetName = 'Assess')]
    [Parameter(ParameterSetName = 'Remediate')]
    [string]$ReportDirectory,

    [string]$LogPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExitSuccess = 0
$ExitFatal = 1
$ExitPartial = 2

# Captured here because $PSBoundParameters inside a function refers to that function.
$ModeSpecified = $PSBoundParameters.ContainsKey('Mode')
# -WhatIf/-Confirm are forwarded explicitly: module functions do not inherit
# this script's preference variables.
$ShouldProcessArgs = @{ WhatIf = [bool]$WhatIfPreference }
if ($PSBoundParameters.ContainsKey('Confirm')) { $ShouldProcessArgs['Confirm'] = [bool]$PSBoundParameters['Confirm'] }

foreach ($module in @('Common', 'PackageManager', 'Environment', 'SecurityAssessment', 'Remediation', 'Reporting')) {
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

function Get-BackupDirectory { Join-Path $PSScriptRoot 'backup' }

function Test-RemediationPrerequisite {
    if (-not (Test-IsWindowsPlatform)) { Write-Status Error 'Remediation and rollback require Windows.'; return $false }
    if (-not (Test-IsAdministrator)) { Write-Status Error 'Remediation and rollback require an elevated (Administrator) PowerShell session.'; return $false }
    $true
}

function Invoke-Remediation {
    if (-not (Test-RemediationPrerequisite)) { return $ExitFatal }
    $catalog = Import-ControlCatalog -Path (Join-Path (Join-Path $PSScriptRoot 'config') 'controls.json')
    $coverage = @(Test-RemediationCoverage -Catalog $catalog)
    if ($coverage.Count -gt 0) { throw "Remediation handlers do not match controls.json: $($coverage -join '; ')" }

    $requested = @($ControlId | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $unknown = @($requested | Where-Object { @($catalog.controls.id) -notcontains $_ })
    if ($unknown.Count -gt 0) { Write-Status Error "Unknown control id(s): $($unknown -join ', ')"; return $ExitFatal }
    $notAutomated = @($requested | Where-Object { @(Get-RemediableControlId) -notcontains $_ })
    foreach ($id in $notAutomated) { Write-Status Warn "$id has no automated remediation; see its guidance in the report." }

    $findings = @(Invoke-SecurityAssessment -Catalog $catalog)
    $candidates = @($findings | Where-Object { $_.remediationAvailable -and ($requested.Count -eq 0 -or $requested -contains $_.id) })
    if ($candidates.Count -eq 0) {
        Write-Status Ok 'No failing control needs automated remediation.'
        return $ExitSuccess
    }
    Write-Status Plan "Controls eligible for automated remediation ($($candidates.Count)):"
    foreach ($f in $candidates) { Write-Status Detail "$($f.id) [$($f.status)] $($f.name) -> $($f.remediationGuidance)" }

    $backupPath = Join-Path (Get-BackupDirectory) ('security-backup-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $results = @(Invoke-SecurityRemediation -Finding $candidates -BackupPath $backupPath @ShouldProcessArgs)
    foreach ($r in $results) {
        $level = @{ Remediated = 'Ok'; Failed = 'Error'; Skipped = 'Warn' }[$r.status]
        Write-Status $level "$($r.status): $($r.controlId) - $($r.detail)"
    }
    if ($WhatIfPreference) { return $ExitSuccess }

    if (Test-Path -LiteralPath $backupPath) { Write-Status Info "Backup of previous values: $(Protect-SensitiveText $backupPath)" }
    $after = @(Invoke-SecurityAssessment -Catalog $catalog)
    $report = New-AssessmentReport -Finding $after -Remediation $results -Kind PostRemediation
    Write-AssessmentSummary -Report $report
    $paths = Export-AssessmentReport -Report $report -Directory (Get-ReportDirectory) -BaseName ('security-remediation-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')) -Confirm:$false -WhatIf:$false
    Write-Status Ok "Reports: $(Protect-SensitiveText $paths.Json), $(Protect-SensitiveText $paths.Html)"
    if (@($results | Where-Object { $_.status -eq 'Failed' }).Count -gt 0) { return $ExitPartial }
    $ExitSuccess
}

function Invoke-Rollback {
    if (-not (Test-RemediationPrerequisite)) { return $ExitFatal }
    $path = $BackupFile
    if (-not $path) {
        $latest = Get-ChildItem -Path (Get-BackupDirectory) -Filter 'security-backup-*.json' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^security-backup-\d{8}-\d{6}\.json$' } | Sort-Object Name -Descending | Select-Object -First 1
        if (-not $latest) { Write-Status Error 'No backup file found in backup\. Pass -BackupFile.'; return $ExitFatal }
        $path = $latest.FullName
    }
    Write-Status Info "Rolling back from $(Protect-SensitiveText $path)"
    $results = @(Invoke-SecurityRollback -BackupPath $path @ShouldProcessArgs)
    if ($results.Count -eq 0) { Write-Status Ok 'The backup contains no changes to restore.' }
    foreach ($r in $results) {
        $level = @{ Restored = 'Ok'; Failed = 'Error'; Skipped = 'Warn' }[$r.status]
        Write-Status $level "$($r.status): $($r.controlId) - $($r.detail)"
    }
    if (-not $WhatIfPreference -and $results.Count -gt 0) {
        $resultPath = [IO.Path]::ChangeExtension($path, ('rollback-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
        Write-JsonFile -Path $resultPath -InputObject @($results) -WhatIf:$false
        Write-Status Info "Rollback record: $(Protect-SensitiveText $resultPath)"
    }
    if (@($results | Where-Object { $_.status -eq 'Failed' }).Count -gt 0) { return $ExitPartial }
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
        'Remediate' { $exitCode = Invoke-Remediation }
        'Rollback' { $exitCode = Invoke-Rollback }
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
