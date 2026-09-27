<#
.SYNOPSIS
    Generates docs/CONTROLS.md from config/controls.json.

.DESCRIPTION
    The control reference is generated rather than hand-written so it cannot
    drift from the catalog. tests/Repository.Tests.ps1 fails when the
    committed file is out of date. Pass -PassThru to get the text without
    writing the file.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'docs') 'CONTROLS.md'),
    [switch]$PassThru
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
foreach ($module in @('Common', 'SecurityAssessment')) {
    Import-Module (Join-Path (Join-Path $repoRoot 'modules') "$module.psm1") -Force
}
$catalog = Import-ControlCatalog -Path (Join-Path (Join-Path $repoRoot 'config') 'controls.json')

function Format-Cell([string]$Text) { ($Text -replace '\|', '\|' -replace '\r?\n', ' ').Trim() }

function Format-Reference($References) {
    $parts = @()
    $parts += @($References.nist80053 | Where-Object { $_ } | ForEach-Object { "NIST $_" })
    $parts += @($References.attack | Where-Object { $_ } | ForEach-Object {
            $path = if ($_ -like 'M*') { "mitigations/$_" } else { 'techniques/' + ($_ -replace '\.', '/') }
            "[ATT&CK $_](https://attack.mitre.org/$path/)"
        })
    $parts += @($References.microsoft | Where-Object { $_ } | ForEach-Object { "[Microsoft Learn]($_)" })
    if ($parts.Count -eq 0) { return 'None mapped' }
    $parts -join ', '
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# Security control reference')
$lines.Add('')
$lines.Add('Generated from `config/controls.json` by `tools/New-ControlDoc.ps1`. Do not edit by hand.')
$lines.Add('')
$lines.Add($catalog.referenceNote)
$lines.Add('')
$lines.Add('Statuses: `PASS` meets the expected state, `WARN` partially meets it or is a context-dependent recommendation, `FAIL` does not meet it, `NOT_APPLICABLE` the feature is not present on this system, `ERROR` the state could not be read (often because the session is not elevated).')
$lines.Add('')
foreach ($category in @($catalog.controls | ForEach-Object { $_.category } | Select-Object -Unique)) {
    $lines.Add("## $category")
    $lines.Add('')
    $lines.Add('| ID | Control | Severity | Expected | Remediation | References |')
    $lines.Add('|---|---|---|---|---|---|')
    foreach ($c in @($catalog.controls | Where-Object { $_.category -eq $category })) {
        $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $c.id, (Format-Cell $c.name), $c.severity, (Format-Cell $c.expected),
                $c.remediation.type, (Format-Reference $c.references)))
    }
    $lines.Add('')
    foreach ($c in @($catalog.controls | Where-Object { $_.category -eq $category })) {
        $lines.Add("- **$($c.id)**: $(Format-Cell $c.rationale) Remediation: $(Format-Cell $c.remediation.guidance)")
    }
    $lines.Add('')
}
$text = ($lines -join "`n").TrimEnd() + "`n"
if ($PassThru) { return $text }
Write-Utf8File -Path $OutputPath -Content $text
Write-Status Ok "Wrote $OutputPath"
