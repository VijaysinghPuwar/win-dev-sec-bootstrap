<#
.SYNOPSIS
    Runs the Pester suite. Exits non-zero when any test fails.

.PARAMETER ResultPath
    Optional NUnit XML output path (used by CI to publish results).
#>
[CmdletBinding()]
param([string]$ResultPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The suite targets Pester 5 so the same tests run on Windows PowerShell 5.1.
if (-not (Get-Module Pester | Where-Object { $_.Version.Major -eq 5 })) {
    Import-Module Pester -MinimumVersion 5.5.0 -MaximumVersion 5.99.99
}
$configuration = New-PesterConfiguration
$configuration.Run.Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'tests'
$configuration.Run.Exit = $true
$configuration.Output.Verbosity = 'Detailed'
if ($ResultPath) {
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputFormat = 'NUnitXml'
    $configuration.TestResult.OutputPath = $ResultPath
}
Invoke-Pester -Configuration $configuration
