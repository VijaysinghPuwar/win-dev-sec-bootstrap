<#
.SYNOPSIS
    Regenerates docs/examples/sample-assessment.{json,html} from the
    synthetic workstation fixture in tests/fixtures.

.DESCRIPTION
    The sample shows the report format without publishing data from a real
    machine. Host details are fixed placeholder values and the timestamp is
    fixed so the output is reproducible. Runs on any platform.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'docs') 'examples')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
foreach ($module in @('Common', 'SecurityAssessment', 'Reporting')) {
    Import-Module (Join-Path (Join-Path $repoRoot 'modules') "$module.psm1") -Force
}

$catalog = Import-ControlCatalog -Path (Join-Path (Join-Path $repoRoot 'config') 'controls.json')
$snapshot = Import-PowerShellDataFile -Path (Join-Path (Join-Path (Join-Path $repoRoot 'tests') 'fixtures') 'Snapshot.Workstation.psd1')
$systemInfo = [ordered]@{
    computerName      = 'EXAMPLE-WS01'
    operatingSystem   = 'Synthetic fixture (not a real machine)'
    powershellVersion = '7.5.0'
    powershellEdition = 'Core'
    elevated          = $true
}
$findings = @(Invoke-SecurityAssessment -Catalog $catalog -Snapshot $snapshot)
$report = New-AssessmentReport -Finding $findings -SystemInfo $systemInfo -Timestamp ([datetime]::SpecifyKind([datetime]'2026-01-15T10:00:00', 'Utc'))
Write-AssessmentSummary -Report $report
$paths = Export-AssessmentReport -Report $report -Directory $OutputDirectory -BaseName 'sample-assessment'
Write-Status Ok "Wrote $($paths.Json) and $($paths.Html)"
