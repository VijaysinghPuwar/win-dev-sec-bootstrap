#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The system-facing functions (Get/Set/Test/Restore-RemediationState) are
# mocked against an in-memory "machine", so these tests never touch Windows
# security settings.

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'modules/Common.psm1') -Force
    Import-Module (Join-Path $repoRoot 'modules/SecurityAssessment.psm1') -Force
    Import-Module (Join-Path $repoRoot 'modules/Remediation.psm1') -Force
    $catalog = Import-ControlCatalog -Path (Join-Path $repoRoot 'config/controls.json')

    function New-Finding([string]$Id) {
        $control = $catalog.controls | Where-Object id -eq $Id
        [pscustomobject]@{ id = $Id; name = $control.name; status = 'FAIL'; remediationGuidance = $control.remediation.guidance }
    }

    function Initialize-FakeMachine {
        $script:machine = @{
            DisableRealtimeMonitoring = $true
            EnableNetworkProtection   = 0
            ScriptBlockLogging        = @{ KeyExists = $false; ValueExists = $false; Value = $null }
            SignatureAge              = 10
        }
        $script:setCalls = New-Object System.Collections.Generic.List[string]
        $script:blockChanges = @()

        Mock -ModuleName Remediation Get-RemediationState {
            switch ($Handler.Kind) {
                'MpPreference' { return $script:machine[$Handler.Property] }
                'RegistryPolicy' { return $script:machine.ScriptBlockLogging.Clone() }
                'SignatureUpdate' { return $script:machine.SignatureAge }
            }
        }
        Mock -ModuleName Remediation Set-RemediationState {
            $script:setCalls.Add($Handler.Kind)
            if ($script:blockChanges -contains $Handler.Kind) { return }  # simulates policy/tamper protection reverting it
            switch ($Handler.Kind) {
                'MpPreference' { $script:machine[$Handler.Property] = $Handler.Desired }
                'RegistryPolicy' { $script:machine.ScriptBlockLogging = @{ KeyExists = $true; ValueExists = $true; Value = $Handler.Desired } }
                'SignatureUpdate' { $script:machine.SignatureAge = 0 }
            }
        }
        Mock -ModuleName Remediation Test-RemediationState {
            switch ($Handler.Kind) {
                'MpPreference' { return $script:machine[$Handler.Property] -eq $Handler.Desired }
                'RegistryPolicy' { return $script:machine.ScriptBlockLogging.Value -eq $Handler.Desired }
                'SignatureUpdate' { return $script:machine.SignatureAge -le 3 }
            }
        }
        Mock -ModuleName Remediation Restore-RemediationState {
            switch ($Handler.Kind) {
                'MpPreference' { $script:machine[$Handler.Property] = $Before }
                'RegistryPolicy' { $script:machine.ScriptBlockLogging = @{ KeyExists = $Before.KeyExists; ValueExists = $Before.ValueExists; Value = $Before.Value } }
            }
        }
    }
}

Describe 'Remediation coverage' {
    It 'has a handler for exactly the controls marked Automated' {
        @(Test-RemediationCoverage -Catalog $catalog).Count | Should -Be 0
    }

    It 'never automates restart-dependent or data-risking controls' {
        foreach ($id in @('WIN-BL-001', 'WIN-SMB-002', 'WIN-PS-004', 'WIN-SYS-001', 'WIN-SYS-002', 'WIN-DEF-008', 'WIN-DEF-009', 'WIN-DEF-010', 'WIN-DEF-007')) {
            Get-RemediationHandler -ControlId $id | Should -BeNullOrEmpty -Because $id
        }
    }
}

Describe 'Invoke-SecurityRemediation' {
    BeforeEach {
        Initialize-FakeMachine
        $backupPath = Join-Path $TestDrive ("backup-{0}.json" -f [guid]::NewGuid())
    }

    It 'backs up, applies and verifies each change' {
        $results = @(Invoke-SecurityRemediation -Finding @((New-Finding 'WIN-DEF-001'), (New-Finding 'WIN-PS-001')) -BackupPath $backupPath -Confirm:$false)
        $results.status | Should -Be @('Remediated', 'Remediated')
        $script:machine.DisableRealtimeMonitoring | Should -BeFalse
        $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        @($backup.changes).Count | Should -Be 2
        $backup.changes[0].before | Should -BeTrue
        $backup.changes[0].status | Should -Be 'Applied'
        $backup.changes[1].before.KeyExists | Should -BeFalse
    }

    It 'writes the backup entry before applying the change' {
        # Capture what was on disk at the moment of the change; asserting inside
        # the mock would be swallowed by the function's own error handling.
        $script:seenAtApply = $null
        Mock -ModuleName Remediation Set-RemediationState {
            $script:seenAtApply = if (Test-Path -LiteralPath $backupPath) { Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json } else { 'missing' }
        }
        Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-001') -BackupPath $backupPath -Confirm:$false | Out-Null
        Should -Invoke -ModuleName Remediation Set-RemediationState -Times 1
        $script:seenAtApply | Should -Not -Be 'missing'
        $script:seenAtApply.changes[0].status | Should -Be 'Pending'
        $script:seenAtApply.changes[0].before | Should -BeTrue
    }

    It 'makes no change and writes no backup under -WhatIf' {
        $results = @(Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-001') -BackupPath $backupPath -WhatIf)
        $results[0].status | Should -Be 'Skipped'
        $script:setCalls.Count | Should -Be 0
        Test-Path -LiteralPath $backupPath | Should -BeFalse
    }

    It 'reports Failed when the setting does not persist (policy or tamper protection)' {
        $script:blockChanges = @('MpPreference')
        $result = @(Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-005') -BackupPath $backupPath -Confirm:$false)[0]
        $result.status | Should -Be 'Failed'
        $result.detail | Should -Match 'did not take effect'
        (Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json).changes[0].status | Should -Be 'Failed'
    }

    It 'changes nothing when the current value cannot be read' {
        Mock -ModuleName Remediation Get-RemediationState { throw 'Access denied' }
        $result = @(Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-001') -BackupPath $backupPath -Confirm:$false)[0]
        $result.status | Should -Be 'Failed'
        $result.detail | Should -Match 'nothing changed'
        $script:setCalls.Count | Should -Be 0
    }

    It 'skips controls without a handler' {
        (@(Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-BL-001') -BackupPath $backupPath -Confirm:$false)[0]).status | Should -Be 'Skipped'
    }

    It 'does not record a signature update in the rollback backup' {
        $result = @(Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-006') -BackupPath $backupPath -Confirm:$false)[0]
        $result.status | Should -Be 'Remediated'
        Test-Path -LiteralPath $backupPath | Should -BeFalse
    }
}

Describe 'Invoke-SecurityRollback' {
    BeforeEach {
        Initialize-FakeMachine
        $backupPath = Join-Path $TestDrive ("backup-{0}.json" -f [guid]::NewGuid())
    }

    It 'restores the original values after a remediation (round trip)' {
        Invoke-SecurityRemediation -Finding @((New-Finding 'WIN-DEF-001'), (New-Finding 'WIN-DEF-005'), (New-Finding 'WIN-PS-001')) -BackupPath $backupPath -Confirm:$false | Out-Null
        $results = @(Invoke-SecurityRollback -BackupPath $backupPath -Confirm:$false)
        $results.status | Should -Be @('Restored', 'Restored', 'Restored')
        $script:machine.DisableRealtimeMonitoring | Should -BeTrue
        $script:machine.EnableNetworkProtection | Should -Be 0
        $script:machine.ScriptBlockLogging.ValueExists | Should -BeFalse
    }

    It 'restores newest change first' {
        Invoke-SecurityRemediation -Finding @((New-Finding 'WIN-DEF-001'), (New-Finding 'WIN-PS-001')) -BackupPath $backupPath -Confirm:$false | Out-Null
        (@(Invoke-SecurityRollback -BackupPath $backupPath -Confirm:$false)).controlId | Should -Be @('WIN-PS-001', 'WIN-DEF-001')
    }

    It 'refuses to write tampered values from the backup file' {
        Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-005') -BackupPath $backupPath -Confirm:$false | Out-Null
        $json = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $json.changes[0].before = 'Set-MpPreference -DisableRealtimeMonitoring $true'
        $json | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath
        $result = @(Invoke-SecurityRollback -BackupPath $backupPath -Confirm:$false)[0]
        $result.status | Should -Be 'Failed'
        $result.detail | Should -Match 'not valid'
        Should -Invoke -ModuleName Remediation Restore-RemediationState -Times 0
    }

    It 'refuses unknown control ids in the backup file' {
        Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-001') -BackupPath $backupPath -Confirm:$false | Out-Null
        $json = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $json.changes[0].controlId = 'WIN-BL-001'
        $json | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath
        (@(Invoke-SecurityRollback -BackupPath $backupPath -Confirm:$false)[0]).detail | Should -Match 'unknown control id'
    }

    It 'refuses a backup from another computer' {
        Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-001') -BackupPath $backupPath -Confirm:$false | Out-Null
        $json = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $json.computerName = 'SOME-OTHER-PC'
        $json | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath
        { Invoke-SecurityRollback -BackupPath $backupPath -Confirm:$false } | Should -Throw '*another machine*'
    }

    It 'makes no change under -WhatIf' {
        Invoke-SecurityRemediation -Finding @(New-Finding 'WIN-DEF-001') -BackupPath $backupPath -Confirm:$false | Out-Null
        (@(Invoke-SecurityRollback -BackupPath $backupPath -WhatIf)[0]).status | Should -Be 'Skipped'
        $script:machine.DisableRealtimeMonitoring | Should -BeFalse
    }
}

Describe 'Test-BackupValue' {
    It 'accepts <Case>' -TestCases @(
        @{ Case = 'a boolean Defender flag'; Id = 'WIN-DEF-001'; Value = $true }
        @{ Case = 'an allowed Defender enum value'; Id = 'WIN-DEF-005'; Value = [int64]2 }
        @{ Case = 'a firewall profile state'; Id = 'WIN-FW-001'; Value = @{ Enabled = 'False'; DefaultInboundAction = 'NotConfigured' } }
        @{ Case = 'an absent registry value'; Id = 'WIN-PS-001'; Value = @{ KeyExists = $true; ValueExists = $false; Value = $null } }
    ) {
        Test-BackupValue -Handler (Get-RemediationHandler -ControlId $Id) -Value $Value | Should -BeTrue
    }

    It 'rejects <Case>' -TestCases @(
        @{ Case = 'an out-of-range Defender value'; Id = 'WIN-DEF-005'; Value = 7 }
        @{ Case = 'a string where a boolean belongs'; Id = 'WIN-DEF-001'; Value = 'true' }
        @{ Case = 'an unknown firewall action'; Id = 'WIN-FW-002'; Value = @{ Enabled = 'True'; DefaultInboundAction = 'Everything' } }
        @{ Case = 'a string registry value'; Id = 'WIN-NET-001'; Value = @{ KeyExists = $true; ValueExists = $true; Value = 'calc.exe' } }
        @{ Case = 'a negative registry value'; Id = 'WIN-NET-001'; Value = @{ KeyExists = $true; ValueExists = $true; Value = -1 } }
    ) {
        Test-BackupValue -Handler (Get-RemediationHandler -ControlId $Id) -Value $Value | Should -BeFalse
    }
}

Describe 'Protect-BackupDirectory' {
    # Set-Acl and DirectorySecurity exist only on Windows; CI runs this there.
    It 'creates the directory and applies a protected ACL on Windows' -Skip:([Environment]::OSVersion.Platform -ne 'Win32NT') {
        Mock -ModuleName Remediation Test-IsWindowsPlatform { $true }
        Mock -ModuleName Remediation Set-Acl { $script:appliedAcl = $AclObject }
        $dir = Join-Path $TestDrive 'protected-backup'
        Protect-BackupDirectory -Path $dir
        Test-Path -LiteralPath $dir | Should -BeTrue
        Should -Invoke -ModuleName Remediation Set-Acl -Times 1
        $script:appliedAcl.AreAccessRulesProtected | Should -BeTrue
        $sids = @($script:appliedAcl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
        @($sids | Sort-Object) | Should -Be @('S-1-5-18', 'S-1-5-32-544')
    }

    It 'leaves an existing directory untouched' {
        # Returns before any ACL work, so it must not throw on any platform.
        Mock -ModuleName Remediation New-Item { throw 'must not create' }
        { Protect-BackupDirectory -Path $TestDrive } | Should -Not -Throw
        Should -Invoke -ModuleName Remediation New-Item -Times 0
    }
}
