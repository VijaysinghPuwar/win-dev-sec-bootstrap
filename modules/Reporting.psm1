#Requires -Version 5.1
<#
    Console summaries for provisioning runs, and JSON / HTML reports for
    security assessments. HTML reports are self-contained (inline CSS, no
    scripts, no external requests) and every value is HTML-encoded, because
    evidence such as Defender exclusion paths is attacker-influenced text.
#>
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

$script:StatusOrder = @{ FAIL = 0; ERROR = 1; WARN = 2; PASS = 3; NOT_APPLICABLE = 4 }
$script:SeverityOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }

#region Provisioning

function Write-ProvisioningSummary {
    <#
    .SYNOPSIS
        Prints package results grouped by status, failures first.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result)

    $order = @('Failed', 'Manual', 'Installed', 'Upgraded', 'Current', 'Planned', 'Skipped')
    $level = @{ Failed = 'Error'; Manual = 'Warn'; Installed = 'Ok'; Upgraded = 'Ok'; Current = 'Ok'; Planned = 'Plan'; Skipped = 'Warn' }
    Write-Status Info 'Provisioning summary'
    foreach ($status in $order) {
        $items = @($Result | Where-Object { $_.Status -eq $status })
        if ($items.Count -eq 0) { continue }
        Write-Status $level[$status] ('{0} ({1})' -f $status, $items.Count)
        foreach ($item in $items) {
            $label = if ($item.Id) { '{0,-7} {1} [{2}]' -f $item.Source, $item.Name, $item.Id } else { '{0,-7} {1}' -f $item.Source, $item.Name }
            if ($status -in @('Failed', 'Manual', 'Skipped')) { $label = "$label - $($item.Detail)" }
            Write-Status Detail $label
        }
    }
    if (@($Result | Where-Object { $_.RestartRequired }).Count -gt 0) {
        Write-Status Warn 'At least one change needs a restart to finish.'
    }
}

#endregion

#region Assessment report model

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Minimal host context for a report: computer name, OS and PowerShell
        version, elevation. No user names, IP or MAC addresses, or serials.
    #>
    [CmdletBinding()]
    param()
    $os = [Environment]::OSVersion.VersionString
    if (Test-IsWindowsPlatform) {
        try {
            $cim = Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption, Version -ErrorAction Stop
            $os = '{0} ({1})' -f $cim.Caption, $cim.Version
        } catch {
            Write-Verbose "Win32_OperatingSystem unavailable: $($_.Exception.Message)"
        }
    }
    [ordered]@{
        computerName      = [Environment]::MachineName
        operatingSystem   = $os
        powershellVersion = $PSVersionTable.PSVersion.ToString()
        powershellEdition = [string](Get-OptionalProperty $PSVersionTable 'PSEdition' 'Desktop')
        elevated          = [bool](Test-IsAdministrator)
    }
}

function Get-AssessmentSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)
    $summary = [ordered]@{ total = @($Finding).Count }
    foreach ($status in @('PASS', 'WARN', 'FAIL', 'NOT_APPLICABLE', 'ERROR')) {
        $summary[$status] = @($Finding | Where-Object { $_.status -eq $status }).Count
    }
    $bySeverity = [ordered]@{}
    foreach ($severity in @('High', 'Medium', 'Low', 'Info')) {
        $bySeverity[$severity] = @($Finding | Where-Object { $_.status -eq 'FAIL' -and $_.severity -eq $severity }).Count
    }
    $summary['failBySeverity'] = $bySeverity
    $summary
}

function Get-SortedFinding {
    # Most urgent first: status, then severity, then id.
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Finding)
    $Finding | Sort-Object -Property @{ Expression = { $script:StatusOrder[$_.status] } },
    @{ Expression = { $script:SeverityOrder[$_.severity] } }, id
}

function New-AssessmentReport {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [System.Collections.IDictionary]$SystemInfo = (Get-SystemInfo),
        [AllowEmptyCollection()][object[]]$Remediation = @(),
        [ValidateSet('Assessment', 'PostRemediation')][string]$Kind = 'Assessment',
        [datetime]$Timestamp = (Get-Date)
    )
    $tool = Get-ToolInfo
    $assessment = [ordered]@{ tool = $tool.Name; toolVersion = $tool.Version; kind = $Kind; timestampUtc = $Timestamp.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    foreach ($key in $SystemInfo.Keys) { $assessment[$key] = $SystemInfo[$key] }
    [ordered]@{
        assessment  = $assessment
        summary     = Get-AssessmentSummary -Finding $Finding
        controls    = @(Get-SortedFinding -Finding $Finding)
        remediation = @($Remediation)
        disclaimer  = 'Framework references show related guidance only. This report is a point-in-time configuration assessment, not a compliance certification.'
    }
}

#endregion

#region HTML

function ConvertTo-HtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ReferenceHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param($References)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($id in @(Get-OptionalProperty $References 'nist80053' @())) {
        $parts.Add('NIST SP 800-53 ' + (ConvertTo-HtmlText $id))
    }
    foreach ($id in @(Get-OptionalProperty $References 'attack' @())) {
        # IDs are validated as T####[.###] or M#### by Test-ControlCatalog.
        $path = if ($id -like 'M*') { "mitigations/$id" } else { 'techniques/' + ($id -replace '\.', '/') }
        $parts.Add(('<a href="https://attack.mitre.org/{0}/">ATT&amp;CK {1}</a>' -f (ConvertTo-HtmlText $path), (ConvertTo-HtmlText $id)))
    }
    foreach ($url in @(Get-OptionalProperty $References 'microsoft' @())) {
        $parts.Add(('<a href="{0}">Microsoft Learn</a>' -f (ConvertTo-HtmlText $url)))
    }
    if ($parts.Count -eq 0) { return '<span class="muted">None mapped</span>' }
    $parts -join ' &middot; '
}

function ConvertTo-AssessmentHtml {
    <#
    .SYNOPSIS
        Renders a report as a standalone HTML page that works offline.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Report)
    $a = $Report.assessment
    $s = $Report.summary
    $e = { param($v) ConvertTo-HtmlText $v }

    $rows = New-Object System.Text.StringBuilder
    foreach ($f in $Report.controls) {
        $statusClass = ([string]$f.status).ToLowerInvariant() -replace '_', '-'
        $evidence = ''
        if (@($f.evidence).Count -gt 0) {
            $evidence = '<p><strong>Evidence</strong></p><ul>' + ((@($f.evidence) | ForEach-Object { '<li><code>' + (& $e $_) + '</code></li>' }) -join '') + '</ul>'
        }
        $remediation = if ($f.remediationType -eq 'Automated') { 'Automated (-Remediate)' } else { 'Manual' }
        [void]$rows.AppendFormat(
            '<tr class="{0}"><td><span class="status">{1}</span></td><td><span class="sev sev-{2}">{3}</span></td><td class="id">{4}</td><td><details><summary>{5}</summary>' +
            '<p>{6}</p><dl><dt>Expected</dt><dd>{7}</dd><dt>Detected</dt><dd>{8}</dd><dt>Remediation</dt><dd>{9}: {10}</dd><dt>References</dt><dd>{11}</dd></dl>{12}</details>' +
            '<div class="note">{13}</div></td></tr>',
            (& $e $statusClass), (& $e ($f.status -replace '_', ' ')), (& $e ([string]$f.severity).ToLowerInvariant()), (& $e $f.severity), (& $e $f.id), (& $e $f.name),
            (& $e $f.rationale), (& $e $f.expected), (& $e $f.detected), (& $e $remediation), (& $e $f.remediationGuidance), (Get-ReferenceHtml $f.references),
            $evidence, (& $e $(if ($f.message) { $f.message } else { $f.detected })))
    }

    $remediationHtml = ''
    if (@($Report.remediation).Count -gt 0) {
        $items = foreach ($r in $Report.remediation) {
            '<tr><td>{0}</td><td class="id">{1}</td><td>{2}</td></tr>' -f (& $e $r.status), (& $e $r.controlId), (& $e $r.detail)
        }
        $remediationHtml = '<h2>Remediation actions</h2><table><thead><tr><th>Result</th><th>Control</th><th>Detail</th></tr></thead><tbody>' + ($items -join '') + '</tbody></table>'
    }

    $tiles = foreach ($status in @('FAIL', 'WARN', 'ERROR', 'PASS', 'NOT_APPLICABLE')) {
        '<div class="tile {0}"><span class="num">{1}</span><span class="lbl">{2}</span></div>' -f (& $e ($status.ToLowerInvariant() -replace '_', '-')), (& $e $s[$status]), (& $e ($status -replace '_', ' '))
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Windows Security Assessment - $(& $e $a.computerName)</title>
<style>
:root { --bg:#f7f7f5; --fg:#1d1d1b; --muted:#6b6b66; --card:#fff; --line:#e3e2dd;
  --fail:#b42318; --warn:#9a6700; --pass:#1a7f37; --error:#8250df; --na:#6b6b66; }
@media (prefers-color-scheme: dark) { :root { --bg:#161615; --fg:#ecebe6; --muted:#9d9c95; --card:#1f1f1d; --line:#34332f;
  --fail:#ff7b72; --warn:#e3b341; --pass:#56d364; --error:#bc8cff; --na:#9d9c95; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:24px; margin:0 0 4px; } h2 { font-size:18px; margin:32px 0 12px; }
.meta { color:var(--muted); font-size:13px; margin:0 0 20px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:10px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 14px; border-top:3px solid var(--na); }
.tile.fail { border-top-color:var(--fail); } .tile.warn { border-top-color:var(--warn); } .tile.pass { border-top-color:var(--pass); } .tile.error { border-top-color:var(--error); }
.num { display:block; font-size:26px; font-weight:600; font-variant-numeric:tabular-nums; } .lbl { color:var(--muted); font-size:12px; letter-spacing:.04em; }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; }
th, td { text-align:left; vertical-align:top; padding:10px 12px; border-bottom:1px solid var(--line); }
th { font-size:12px; color:var(--muted); font-weight:600; letter-spacing:.04em; }
.status { font-weight:600; font-size:12px; white-space:nowrap; }
tr.fail .status { color:var(--fail); } tr.warn .status { color:var(--warn); } tr.pass .status { color:var(--pass); } tr.error .status { color:var(--error); } tr.not-applicable .status { color:var(--na); }
.sev { font-size:12px; white-space:nowrap; } .sev-high { font-weight:600; }
.id { font-family:ui-monospace,Consolas,monospace; font-size:13px; white-space:nowrap; }
summary { cursor:pointer; font-weight:500; } .note { color:var(--muted); font-size:13px; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:4px 12px; font-size:13px; } dt { color:var(--muted); } dd { margin:0; }
code { font-family:ui-monospace,Consolas,monospace; font-size:12px; word-break:break-all; }
a { color:inherit; } .muted { color:var(--muted); }
footer { margin-top:28px; color:var(--muted); font-size:12px; }
</style>
</head>
<body>
<main>
<h1>Windows Security Assessment</h1>
<p class="meta">$(& $e $a.computerName) &middot; $(& $e $a.operatingSystem) &middot; PowerShell $(& $e $a.powershellVersion) ($(& $e $a.powershellEdition)) &middot; elevated: $(& $e $a.elevated) &middot; $(& $e $a.timestampUtc) &middot; $(& $e $a.tool) $(& $e $a.toolVersion) &middot; $(& $e $a.kind)</p>
<div class="tiles">$($tiles -join '')</div>
<p class="meta">Failed by severity: High $(& $e $s.failBySeverity.High), Medium $(& $e $s.failBySeverity.Medium), Low $(& $e $s.failBySeverity.Low), Info $(& $e $s.failBySeverity.Info)</p>
<h2>Controls</h2>
<div class="table-wrap"><table>
<thead><tr><th>Status</th><th>Severity</th><th>ID</th><th>Control</th></tr></thead>
<tbody>$($rows.ToString())</tbody>
</table></div>
$remediationHtml
<footer>$(& $e $Report.disclaimer)</footer>
</main>
</body>
</html>
"@
}

#endregion

#region Output

function Export-AssessmentReport {
    <#
    .SYNOPSIS
        Writes <BaseName>.json and <BaseName>.html and returns both paths.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Report,
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$BaseName
    )
    $jsonPath = Join-Path $Directory "$BaseName.json"
    $htmlPath = Join-Path $Directory "$BaseName.html"
    if ($PSCmdlet.ShouldProcess($Directory, "Write $BaseName.json and $BaseName.html")) {
        Write-JsonFile -Path $jsonPath -InputObject $Report -Confirm:$false
        Write-Utf8File -Path $htmlPath -Content (ConvertTo-AssessmentHtml -Report $Report) -Confirm:$false
    }
    [pscustomobject]@{ Json = $jsonPath; Html = $htmlPath }
}

function Write-AssessmentSummary {
    <#
    .SYNOPSIS
        Prints one line per control, most severe first, and the totals.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Report)
    $level = @{ PASS = 'Ok'; WARN = 'Warn'; FAIL = 'Error'; ERROR = 'Error'; NOT_APPLICABLE = 'Detail' }
    Write-Status Info 'Windows security assessment'
    foreach ($f in $Report.controls) {
        $line = '{0,-5} {1,-11} {2,-6} {3}' -f ($f.status -replace 'NOT_APPLICABLE', 'N/A'), $f.id, $f.severity, $f.name
        if ($f.status -ne 'PASS' -and $f.detected) { $line = "$line ($($f.detected))" }
        Write-Status $level[$f.status] $line
    }
    $s = $Report.summary
    Write-Status Info ('PASS {0}  WARN {1}  FAIL {2}  N/A {3}  ERROR {4}  (FAIL by severity: High {5}, Medium {6}, Low {7})' -f `
            $s.PASS, $s.WARN, $s.FAIL, $s.NOT_APPLICABLE, $s.ERROR, $s.failBySeverity.High, $s.failBySeverity.Medium, $s.failBySeverity.Low)
}

#endregion

Export-ModuleMember -Function Write-ProvisioningSummary, Get-SystemInfo, Get-AssessmentSummary, New-AssessmentReport,
    ConvertTo-AssessmentHtml, Export-AssessmentReport, Write-AssessmentSummary
