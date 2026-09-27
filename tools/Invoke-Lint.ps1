<#
.SYNOPSIS
    Runs PSScriptAnalyzer over the repository. Exits 1 when any Error or
    Warning finding exists; Information findings are listed but advisory.

.NOTES
    PSScriptAnalyzer 1.25 was observed to throw an intermittent
    NullReferenceException from inside the analyzer (not a finding) during
    local runs. Such an internal exception is retried once per file and
    reported; findings themselves are never retried or suppressed.
#>
[CmdletBinding()]
param([switch]$IncludeInformation)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module PSScriptAnalyzer

function Invoke-AnalyzerWithRetry([string]$Path, [string]$Settings) {
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            return @(Invoke-ScriptAnalyzer -Path $Path -Settings $Settings -ErrorAction Stop)
        } catch {
            if ($attempt -eq 2) { throw }
            Write-Warning "PSScriptAnalyzer threw internally on $Path ($($_.Exception.Message)); retrying once."
        }
    }
}

$productSettings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
$testSettings = Join-Path (Join-Path $repoRoot 'tests') 'PSScriptAnalyzerSettings.psd1'
$files = @(Get-ChildItem -Path $repoRoot -Recurse -Include '*.ps1', '*.psm1' -File |
    Where-Object { $_.FullName -notmatch '[\\/](\.git|logs|reports|backup)[\\/]' })

$findings = foreach ($file in $files) {
    $isTest = $file.FullName -match '[\\/]tests[\\/]'
    Invoke-AnalyzerWithRetry -Path $file.FullName -Settings $(if ($isTest) { $testSettings } else { $productSettings })
}
$findings = @($findings)
$blocking = @($findings | Where-Object { $_.Severity -in @('Error', 'Warning', 'ParseError') })
$information = @($findings | Where-Object { $_.Severity -eq 'Information' })

$show = @(if ($IncludeInformation) { $findings } else { $blocking })
if ($show.Count -gt 0) {
    $show | Sort-Object ScriptName, Line | Format-Table Severity, RuleName, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 220 | Write-Output
}
Write-Output ("PSScriptAnalyzer: {0} file(s), {1} error/warning finding(s), {2} information finding(s)" -f $files.Count, $blocking.Count, $information.Count)
if ($blocking.Count -gt 0) { exit 1 }
exit 0
