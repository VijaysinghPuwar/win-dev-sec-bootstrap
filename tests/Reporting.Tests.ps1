#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'modules/Common.psm1') -Force
    Import-Module (Join-Path $repoRoot 'modules/SecurityAssessment.psm1') -Force
    Import-Module (Join-Path $repoRoot 'modules/Reporting.psm1') -Force
    $catalog = Import-ControlCatalog -Path (Join-Path $repoRoot 'config/controls.json')
    $snapshot = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'fixtures/Snapshot.Workstation.psd1')
    $systemInfo = [ordered]@{
        computerName = 'TEST-PC'; operatingSystem = 'Windows 11 Pro (10.0.26100)'
        powershellVersion = '7.5.0'; powershellEdition = 'Core'; elevated = $true
    }
    $findings = @(Invoke-SecurityAssessment -Catalog $catalog -Snapshot $snapshot)
    $report = New-AssessmentReport -Finding $findings -SystemInfo $systemInfo -Timestamp ([datetime]'2026-01-15T10:00:00Z')
}

Describe 'Get-AssessmentSummary' {
    It 'counts every status and adds up to the total' {
        $s = $report.summary
        $s.total | Should -Be @($catalog.controls).Count
        ($s.PASS + $s.WARN + $s.FAIL + $s.NOT_APPLICABLE + $s.ERROR) | Should -Be $s.total
    }

    It 'matches the known state of the workstation fixture' {
        $s = $report.summary
        $s.FAIL | Should -Be 4    # DEF-005 network protection, DEF-008 Downloads exclusion, NET-001 LLMNR, PS-001 script block logging
        $s.NOT_APPLICABLE | Should -Be 1   # BitLocker cmdlets unavailable
        $s.failBySeverity.High | Should -Be 1
    }
}

Describe 'New-AssessmentReport' {
    It 'orders controls by status then severity' {
        $report.controls[0].status | Should -Be 'FAIL'
        $report.controls[0].severity | Should -Be 'High'
        $report.controls[-1].status | Should -Be 'NOT_APPLICABLE'
    }

    It 'records host context without user identifiers' {
        $keys = @($report.assessment.Keys)
        $keys | Should -Contain 'computerName'
        $keys | Should -Not -Contain 'userName'
        $report.assessment.timestampUtc | Should -Be '2026-01-15T10:00:00Z'
    }

    It 'includes the non-certification disclaimer' {
        $report.disclaimer | Should -Match 'not a compliance certification'
    }
}

Describe 'ConvertTo-AssessmentHtml' {
    BeforeAll { $html = ConvertTo-AssessmentHtml -Report $report }

    It 'loads nothing from the network' {
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '<link\b'
        $html | Should -Not -Match '\bsrc\s*='
        $html | Should -Match "Content-Security-Policy"
    }

    It 'HTML-encodes attacker-influenced evidence' {
        $evil = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'fixtures/Snapshot.Workstation.psd1')
        $evil.DefenderPreference.Data.ExclusionPath = @('C:\x\<script>alert(1)</script>\"onmouseover=\"x')
        $evilReport = New-AssessmentReport -Finding @(Invoke-SecurityAssessment -Catalog $catalog -Snapshot $evil) -SystemInfo $systemInfo
        $evilHtml = ConvertTo-AssessmentHtml -Report $evilReport
        $evilHtml | Should -Not -Match '<script>alert'
        $evilHtml | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
    }

    It 'links ATT&CK techniques, sub-techniques and mitigations correctly' {
        $html | Should -Match 'https://attack.mitre.org/techniques/T1557/001/'
        $html | Should -Match 'https://attack.mitre.org/mitigations/M1040/'
    }

    It 'renders one row per control' {
        ([regex]::Matches($html, '<tr class="')).Count | Should -Be @($catalog.controls).Count
    }
}

Describe 'Export-AssessmentReport' {
    It 'writes BOM-less JSON that round-trips and an HTML file' {
        $paths = Export-AssessmentReport -Report $report -Directory $TestDrive -BaseName 'report-test'
        $bytes = [IO.File]::ReadAllBytes($paths.Json)
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB) | Should -BeFalse
        $parsed = Get-Content -LiteralPath $paths.Json -Raw | ConvertFrom-Json
        @($parsed.controls).Count | Should -Be @($catalog.controls).Count
        $parsed.summary.FAIL | Should -Be $report.summary.FAIL
        Test-Path -LiteralPath $paths.Html | Should -BeTrue
    }

    It 'rejects base names that could escape the report directory' {
        { Export-AssessmentReport -Report $report -Directory $TestDrive -BaseName '..\..\evil' } | Should -Throw
    }

    It 'writes nothing under -WhatIf' {
        $dir = Join-Path $TestDrive 'whatif'
        Export-AssessmentReport -Report $report -Directory $dir -BaseName 'r' -WhatIf | Out-Null
        Test-Path -LiteralPath (Join-Path $dir 'r.json') | Should -BeFalse
    }
}
