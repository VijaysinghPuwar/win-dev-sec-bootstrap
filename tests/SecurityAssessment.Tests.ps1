#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'modules/Common.psm1') -Force
    Import-Module (Join-Path $repoRoot 'modules/SecurityAssessment.psm1') -Force
    $catalog = Import-ControlCatalog -Path (Join-Path $repoRoot 'config/controls.json')
    $fixtureDir = Join-Path $PSScriptRoot 'fixtures'

    function Get-Snapshot([string]$Name = 'Hardened') {
        Import-PowerShellDataFile -Path (Join-Path $fixtureDir "Snapshot.$Name.psd1")
    }
    function Get-Finding([hashtable]$Snapshot, [string]$Id) {
        Invoke-SecurityAssessment -Catalog $catalog -Snapshot $Snapshot -ControlId $Id
    }
}

Describe 'Control catalog' {
    It 'is valid and matches the implemented evaluators' {
        @(Test-ControlCatalog -Catalog $catalog).Count | Should -Be 0
        @($catalog.controls.id | Sort-Object) | Should -Be @(Get-ImplementedControlId)
    }

    It 'reports a control without an evaluator' {
        $copy = $catalog | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $copy.controls[0].id = 'WIN-XYZ-999'
        $errors = @(Test-ControlCatalog -Catalog $copy) -join "`n"
        $errors | Should -Match 'WIN-XYZ-999: no evaluator'
        $errors | Should -Match "Evaluator $($catalog.controls[0].id) has no entry"
    }

    It 'rejects malformed framework references' {
        $copy = $catalog | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $copy.controls[0].references.nist80053 = @('SI3')
        $copy.controls[0].references.attack = @('T15620')
        $copy.controls[0].references.microsoft = @('https://example.com/defender')
        $errors = @(Test-ControlCatalog -Catalog $copy) -join "`n"
        $errors | Should -Match 'invalid NIST'
        $errors | Should -Match 'invalid ATT&CK'
        $errors | Should -Match 'learn.microsoft.com'
    }
}

Describe 'Invoke-SecurityAssessment on a hardened snapshot' {
    It 'passes every control' {
        $findings = @(Invoke-SecurityAssessment -Catalog $catalog -Snapshot (Get-Snapshot))
        $findings.Count | Should -Be @($catalog.controls).Count
        @($findings | Where-Object status -ne 'PASS' | ForEach-Object { "$($_.id)=$($_.status): $($_.message)" }) | Should -BeNullOrEmpty
    }

    It 'offers no remediation for passing controls' {
        @(Invoke-SecurityAssessment -Catalog $catalog -Snapshot (Get-Snapshot) | Where-Object remediationAvailable).Count | Should -Be 0
    }
}

Describe 'Control evaluators' {
    It '<Id> reports <Status> when <Case>' -TestCases @(
        @{ Id = 'WIN-DEF-001'; Status = 'FAIL'; Case = 'real-time protection is off'; Change = { param($s) $s.DefenderStatus.Data.RealTimeProtectionEnabled = $false } }
        @{ Id = 'WIN-DEF-003'; Status = 'FAIL'; Case = 'MAPS is disabled'; Change = { param($s) $s.DefenderPreference.Data.MAPSReporting = 0 } }
        @{ Id = 'WIN-DEF-004'; Status = 'WARN'; Case = 'PUA is audit only'; Change = { param($s) $s.DefenderPreference.Data.PUAProtection = 2 } }
        @{ Id = 'WIN-DEF-005'; Status = 'WARN'; Case = 'network protection is audit only'; Change = { param($s) $s.DefenderPreference.Data.EnableNetworkProtection = 2 } }
        @{ Id = 'WIN-DEF-005'; Status = 'FAIL'; Case = 'network protection is off'; Change = { param($s) $s.DefenderPreference.Data.EnableNetworkProtection = 0 } }
        @{ Id = 'WIN-DEF-006'; Status = 'WARN'; Case = 'signatures are 5 days old'; Change = { param($s) $s.DefenderStatus.Data.AntivirusSignatureAge = 5 } }
        @{ Id = 'WIN-DEF-006'; Status = 'FAIL'; Case = 'signatures are 30 days old'; Change = { param($s) $s.DefenderStatus.Data.AntivirusSignatureAge = 30 } }
        @{ Id = 'WIN-DEF-006'; Status = 'FAIL'; Case = 'signatures were never loaded'; Change = { param($s) $s.DefenderStatus.Data.AntivirusSignatureAge = 65535 } }
        @{ Id = 'WIN-DEF-007'; Status = 'FAIL'; Case = 'tamper protection is off'; Change = { param($s) $s.DefenderStatus.Data.IsTamperProtected = $false } }
        @{ Id = 'WIN-DEF-007'; Status = 'NOT_APPLICABLE'; Case = 'tamper state is not reported'; Change = { param($s) $s.DefenderStatus.Data.IsTamperProtected = $null } }
        @{ Id = 'WIN-DEF-009'; Status = 'WARN'; Case = 'ASR rules are audit only'; Change = { param($s) $s.DefenderPreference.Data.AttackSurfaceReductionRules_Actions = @(2, 2) } }
        @{ Id = 'WIN-DEF-009'; Status = 'WARN'; Case = 'no ASR rules exist'; Change = { param($s) $s.DefenderPreference.Data.AttackSurfaceReductionRules_Ids = @(); $s.DefenderPreference.Data.AttackSurfaceReductionRules_Actions = @() } }
        @{ Id = 'WIN-DEF-010'; Status = 'WARN'; Case = 'controlled folder access is off'; Change = { param($s) $s.DefenderPreference.Data.EnableControlledFolderAccess = 0 } }
        @{ Id = 'WIN-FW-003'; Status = 'FAIL'; Case = 'the Public profile is off'; Change = { param($s) $s.Firewall.Data[2].Enabled = 'False' } }
        @{ Id = 'WIN-FW-001'; Status = 'FAIL'; Case = 'the Domain profile allows inbound by default'; Change = { param($s) $s.Firewall.Data[0].DefaultInboundAction = 'Allow' } }
        @{ Id = 'WIN-FW-002'; Status = 'ERROR'; Case = 'the Private profile is missing'; Change = { param($s) $s.Firewall.Data = @($s.Firewall.Data[0], $s.Firewall.Data[2]) } }
        @{ Id = 'WIN-SMB-001'; Status = 'FAIL'; Case = 'the server accepts SMBv1'; Change = { param($s) $s.SmbServer.Data.EnableSMB1Protocol = $true } }
        @{ Id = 'WIN-SMB-002'; Status = 'FAIL'; Case = 'the SMBv1 feature is enabled'; Change = { param($s) $s.Smb1Feature.Data = 'Enabled' } }
        @{ Id = 'WIN-SMB-002'; Status = 'WARN'; Case = 'SMBv1 removal waits for a restart'; Change = { param($s) $s.Smb1Feature.Data = 'DisablePending' } }
        @{ Id = 'WIN-SMB-003'; Status = 'WARN'; Case = 'signing is not required'; Change = { param($s) $s.SmbServer.Data.RequireSecuritySignature = $false } }
        @{ Id = 'WIN-NET-001'; Status = 'FAIL'; Case = 'LLMNR policy is not configured'; Change = { param($s) $s.Registry.Data.LlmnrMulticast = @{ Exists = $false; Value = $null } } }
        @{ Id = 'WIN-PS-001'; Status = 'FAIL'; Case = 'script block logging is not configured'; Change = { param($s) $s.Registry.Data.ScriptBlockLogging = @{ Exists = $false; Value = $null } } }
        @{ Id = 'WIN-PS-001'; Status = 'FAIL'; Case = 'script block logging is set to 0'; Change = { param($s) $s.Registry.Data.ScriptBlockLogging = @{ Exists = $true; Value = 0 } } }
        @{ Id = 'WIN-PS-002'; Status = 'WARN'; Case = 'module logging is not configured'; Change = { param($s) $s.Registry.Data.ModuleLogging = @{ Exists = $false; Value = $null } } }
        @{ Id = 'WIN-PS-004'; Status = 'FAIL'; Case = 'the PowerShell 2.0 engine is enabled'; Change = { param($s) $s.PowerShellV2Feature.Data = 'Enabled' } }
        @{ Id = 'WIN-BL-001'; Status = 'FAIL'; Case = 'the OS drive is not encrypted'; Change = { param($s) $s.BitLocker.Data = @{ ProtectionStatus = 'Off'; VolumeStatus = 'FullyDecrypted'; EncryptionPercentage = 0 } } }
        @{ Id = 'WIN-BL-001'; Status = 'WARN'; Case = 'protection is suspended'; Change = { param($s) $s.BitLocker.Data.ProtectionStatus = 'Off' } }
        @{ Id = 'WIN-BL-001'; Status = 'NOT_APPLICABLE'; Case = 'the BitLocker module is absent'; Change = { param($s) $s.BitLocker = @{ Available = $false; Reason = 'NotSupported'; Error = 'missing'; Data = $null } } }
        @{ Id = 'WIN-SYS-001'; Status = 'FAIL'; Case = 'UAC is disabled'; Change = { param($s) $s.Registry.Data.EnableLUA = @{ Exists = $true; Value = 0 } } }
        @{ Id = 'WIN-SYS-001'; Status = 'PASS'; Case = 'EnableLUA is absent (Windows default)'; Change = { param($s) $s.Registry.Data.EnableLUA = @{ Exists = $false; Value = $null } } }
        @{ Id = 'WIN-SYS-002'; Status = 'WARN'; Case = 'RunAsPPL is not configured'; Change = { param($s) $s.Registry.Data.RunAsPPL = @{ Exists = $false; Value = $null } } }
        @{ Id = 'WIN-SYS-003'; Status = 'FAIL'; Case = 'Secure Boot is off'; Change = { param($s) $s.SecureBoot.Data = $false } }
        @{ Id = 'WIN-SYS-003'; Status = 'NOT_APPLICABLE'; Case = 'the firmware is legacy BIOS'; Change = { param($s) $s.SecureBoot = @{ Available = $false; Reason = 'NotSupported'; Error = 'Cmdlet not supported on this platform'; Data = $null } } }
        @{ Id = 'WIN-ACC-001'; Status = 'FAIL'; Case = 'Guest is enabled'; Change = { param($s) $s.GuestAccount.Data.Enabled = $true } }
        @{ Id = 'WIN-RDP-001'; Status = 'PASS'; Case = 'RDP is on with NLA'; Change = { param($s) $s.Registry.Data.DenyTSConnections.Value = 0 } }
        @{ Id = 'WIN-RDP-001'; Status = 'FAIL'; Case = 'RDP is on without NLA'; Change = { param($s) $s.Registry.Data.DenyTSConnections.Value = 0; $s.Registry.Data.RdpNla.Value = 0 } }
    ) {
        $snapshot = Get-Snapshot
        & $Change $snapshot
        (Get-Finding $snapshot $Id).status | Should -Be $Status
    }
}

Describe 'Unsupported and unreadable state' {
    It 'marks every Defender control NOT_APPLICABLE when another antivirus is primary' {
        $snapshot = Get-Snapshot
        $snapshot.DefenderStatus.Data.AMRunningMode = 'Passive Mode'
        $defender = @(Invoke-SecurityAssessment -Catalog $catalog -Snapshot $snapshot | Where-Object id -like 'WIN-DEF-*')
        $defender.Count | Should -Be 10
        @($defender | Where-Object status -ne 'NOT_APPLICABLE').Count | Should -Be 0
    }

    It 'reports ERROR, not PASS, when a probe needed elevation' {
        $snapshot = Get-Snapshot
        $snapshot.SmbServer = @{ Available = $false; Reason = 'AccessDenied'; Error = 'Access denied'; Data = $null }
        $finding = Get-Finding $snapshot 'WIN-SMB-001'
        $finding.status | Should -Be 'ERROR'
        $finding.message | Should -Match 'Administrator'
    }

    It 'reports ERROR when exclusions are hidden from a non-admin session' {
        $snapshot = Get-Snapshot
        $snapshot.DefenderPreference.Data.ExclusionPath = @('N/A: Must be an administrator to view exclusions')
        (Get-Finding $snapshot 'WIN-DEF-008').status | Should -Be 'ERROR'
    }

    It 'turns an evaluator exception into an ERROR finding instead of aborting' {
        $snapshot = Get-Snapshot
        $snapshot.Firewall.Data = 'not a list of profiles'
        $findings = @(Invoke-SecurityAssessment -Catalog $catalog -Snapshot $snapshot)
        $findings.Count | Should -Be @($catalog.controls).Count
        ($findings | Where-Object id -eq 'WIN-FW-001').status | Should -Be 'ERROR'
    }
}

Describe 'Get-ExclusionRisk' {
    It 'flags <Entry> as high risk' -TestCases @(
        @{ Kind = 'Path'; Entry = 'C:\' }
        @{ Kind = 'Path'; Entry = 'D:' }
        @{ Kind = 'Path'; Entry = 'C:\Users\alice\AppData\Local\Temp' }
        @{ Kind = 'Path'; Entry = '%TEMP%\build' }
        @{ Kind = 'Path'; Entry = 'C:\Users\alice\Downloads' }
        @{ Kind = 'Path'; Entry = 'C:\Users\alice' }
        @{ Kind = 'Path'; Entry = 'C:\Users\Public\Documents' }
        @{ Kind = 'Process'; Entry = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
        @{ Kind = 'Process'; Entry = 'mshta.exe' }
        @{ Kind = 'Extension'; Entry = '.ps1' }
        @{ Kind = 'Extension'; Entry = 'exe' }
    ) {
        $arguments = @{ $Kind = @($Entry) }
        (Get-ExclusionRisk @arguments).High.Count | Should -Be 1
    }

    It 'treats a scoped project folder as a normal exclusion' {
        $risk = Get-ExclusionRisk -Path @('C:\Users\alice\source\repos\app\node_modules') -Process @('node.exe') -Extension @('.log')
        $risk.High.Count | Should -Be 0
        $risk.Other.Count | Should -Be 3
    }
}

Describe 'Finding privacy' {
    It 'redacts the user profile path from evidence' {
        $snapshot = Get-Snapshot
        $snapshot.DefenderPreference.Data.ExclusionPath = @('C:\Users\alice\Downloads')
        Mock -ModuleName SecurityAssessment Protect-SensitiveText {
            if ($null -eq $Text) { return $Text }
            $Text -replace [regex]::Escape('C:\Users\alice'), '%USERPROFILE%'
        }
        $finding = Get-Finding $snapshot 'WIN-DEF-008'
        $finding.evidence | Should -Be @('HIGH RISK Path: %USERPROFILE%\Downloads')
    }
}

Describe 'Get-SecuritySnapshot' {
    It 'degrades to NotSupported probes instead of throwing when Windows cmdlets are missing' {
        Mock -ModuleName SecurityAssessment Get-Command { $null }
        Mock -ModuleName SecurityAssessment Test-IsWindowsPlatform { $false }
        $snapshot = Get-SecuritySnapshot
        foreach ($name in @('DefenderStatus', 'DefenderPreference', 'Firewall', 'SmbServer', 'BitLocker', 'SecureBoot', 'GuestAccount', 'Registry')) {
            $snapshot[$name].Available | Should -BeFalse -Because $name
            $snapshot[$name].Reason | Should -Be 'NotSupported' -Because $name
        }
    }
}

Describe 'Invoke-StateProbe' {
    It 'classifies <Case>' -TestCases @(
        @{ Case = 'access denied'; Exception = { throw (New-Object System.UnauthorizedAccessException 'Access is denied.') }; Reason = 'AccessDenied' }
        @{ Case = 'an elevation error'; Exception = { throw 'The requested operation requires elevation.' }; Reason = 'AccessDenied' }
        @{ Case = 'unsupported firmware'; Exception = { throw (New-Object System.PlatformNotSupportedException 'Cmdlet not supported on this platform') }; Reason = 'NotSupported' }
        @{ Case = 'other errors'; Exception = { throw 'RPC server unavailable' }; Reason = 'Error' }
    ) {
        $probe = Invoke-StateProbe -ScriptBlock $Exception
        $probe.Available | Should -BeFalse
        $probe.Reason | Should -Be $Reason
    }

    It 'returns data from a successful probe' {
        (Invoke-StateProbe -ScriptBlock { @{ Value = 42 } }).Data.Value | Should -Be 42
    }
}
