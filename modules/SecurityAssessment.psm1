#Requires -Version 5.1
<#
    Read-only Windows security assessment.

    The work is split in two so it can be tested without a Windows machine:

      1. Get-SecuritySnapshot runs read-only probes (Defender, firewall, SMB,
         optional features, registry policy values, BitLocker, Secure Boot,
         local accounts). Each probe records Available/Reason/Error instead of
         throwing, so a missing feature or a non-elevated session degrades to
         NOT_APPLICABLE or ERROR for the affected controls only.

      2. Invoke-SecurityAssessment evaluates control definitions from
         config/controls.json against a snapshot. Evaluators are pure
         functions of the snapshot, which is what the Pester tests exercise.

    Only the fields needed by the evaluators are copied into the snapshot.
#>
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

$script:Statuses = @('PASS', 'WARN', 'FAIL', 'NOT_APPLICABLE', 'ERROR')
$script:Severities = @('High', 'Medium', 'Low', 'Info')

# Registry values read by the assessment. Paths are fixed here, never taken
# from configuration.
$script:RegistryChecks = [ordered]@{
    ScriptBlockLogging = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging')
    ModuleLogging      = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging', 'EnableModuleLogging')
    Transcription      = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 'EnableTranscripting')
    LlmnrMulticast     = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'EnableMulticast')
    EnableLUA          = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA')
    RunAsPPL           = @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL')
    DenyTSConnections  = @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections')
    RdpNla             = @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', 'UserAuthentication')
}

#region Probes

function Get-RegistryValue {
    <#
    .SYNOPSIS
        Reads one registry value. Returns @{ Exists; Value } without throwing
        when the key or value is absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return @{ Exists = $false; Value = $null } }
    @{ Exists = $true; Value = $item.$Name }
}

function Invoke-StateProbe {
    <#
    .SYNOPSIS
        Runs one probe and classifies failures as NotSupported (feature or
        cmdlet missing on this edition), AccessDenied or Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$RequiredCommand
    )
    if ($RequiredCommand -and -not (Get-Command -Name $RequiredCommand -ErrorAction SilentlyContinue)) {
        return @{ Available = $false; Reason = 'NotSupported'; Error = "$RequiredCommand is not available on this system"; Data = $null }
    }
    try {
        @{ Available = $true; Reason = $null; Error = $null; Data = (& $ScriptBlock) }
    } catch {
        $exception = $_.Exception
        $message = $exception.Message
        $reason = 'Error'
        if ($exception -is [System.UnauthorizedAccessException] -or $message -match 'access (is |was )?denied|administrator|elevation|0x80070005|0x80041003') {
            $reason = 'AccessDenied'
        } elseif ($exception -is [System.PlatformNotSupportedException] -or $message -match 'not supported on this platform|Invalid class|Invalid namespace') {
            $reason = 'NotSupported'
        }
        @{ Available = $false; Reason = $reason; Error = $message; Data = $null }
    }
}

function Select-ProbeField {
    # Copies selected properties into a plain hashtable. Enums become
    # strings so snapshots serialise identically on 5.1 and 7.
    [CmdletBinding()]
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string[]]$Property
    )
    $result = @{}
    foreach ($name in $Property) {
        $value = Get-OptionalProperty $InputObject $name
        if ($value -is [enum]) { $value = $value.ToString() }
        $result[$name] = $value
    }
    $result
}

function Get-OptionalFeatureState {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$FeatureName)
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
    } catch {
        # Removed features (for example PowerShell 2.0 on Windows 11 24H2)
        # are reported as unknown rather than disabled.
        if ($_.Exception.Message -match 'unknown|not found|does not exist') { return 'NotPresent' }
        throw
    }
    if ($null -eq $feature) { return 'NotPresent' }
    "$($feature.State)"
}

function Get-SecuritySnapshot {
    <#
    .SYNOPSIS
        Collects the read-only system state used by every control.
    #>
    [CmdletBinding()]
    param()
    $snapshot = @{}

    $snapshot.DefenderStatus = Invoke-StateProbe -RequiredCommand 'Get-MpComputerStatus' -ScriptBlock {
        Select-ProbeField -InputObject (Get-MpComputerStatus -ErrorAction Stop) -Property @(
            'AMRunningMode', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled',
            'AntivirusSignatureAge', 'IsTamperProtected')
    }
    $snapshot.DefenderPreference = Invoke-StateProbe -RequiredCommand 'Get-MpPreference' -ScriptBlock {
        Select-ProbeField -InputObject (Get-MpPreference -ErrorAction Stop) -Property @(
            'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'MAPSReporting', 'PUAProtection',
            'EnableNetworkProtection', 'EnableControlledFolderAccess', 'ExclusionPath', 'ExclusionProcess',
            'ExclusionExtension', 'AttackSurfaceReductionRules_Ids', 'AttackSurfaceReductionRules_Actions')
    }
    # ActiveStore is the effective policy (local settings merged with GPO).
    $snapshot.Firewall = Invoke-StateProbe -RequiredCommand 'Get-NetFirewallProfile' -ScriptBlock {
        @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                Select-ProbeField -InputObject $_ -Property @('Name', 'Enabled', 'DefaultInboundAction')
            })
    }
    $snapshot.SmbServer = Invoke-StateProbe -RequiredCommand 'Get-SmbServerConfiguration' -ScriptBlock {
        Select-ProbeField -InputObject (Get-SmbServerConfiguration -ErrorAction Stop) -Property @('EnableSMB1Protocol', 'RequireSecuritySignature')
    }
    $snapshot.Smb1Feature = Invoke-StateProbe -RequiredCommand 'Get-WindowsOptionalFeature' -ScriptBlock {
        Get-OptionalFeatureState -FeatureName 'SMB1Protocol'
    }
    $snapshot.PowerShellV2Feature = Invoke-StateProbe -RequiredCommand 'Get-WindowsOptionalFeature' -ScriptBlock {
        Get-OptionalFeatureState -FeatureName 'MicrosoftWindowsPowerShellV2Root'
    }
    $snapshot.Registry = Invoke-StateProbe -ScriptBlock {
        if (-not (Test-IsWindowsPlatform)) { throw (New-Object System.PlatformNotSupportedException 'The Windows registry is not available on this platform') }
        $values = @{}
        foreach ($key in $script:RegistryChecks.Keys) {
            $values[$key] = Get-RegistryValue -Path $script:RegistryChecks[$key][0] -Name $script:RegistryChecks[$key][1]
        }
        $values
    }
    $snapshot.BitLocker = Invoke-StateProbe -RequiredCommand 'Get-BitLockerVolume' -ScriptBlock {
        Select-ProbeField -InputObject (Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop) -Property @(
            'ProtectionStatus', 'VolumeStatus', 'EncryptionPercentage')
    }
    $snapshot.SecureBoot = Invoke-StateProbe -RequiredCommand 'Confirm-SecureBootUEFI' -ScriptBlock {
        [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
    }
    $snapshot.GuestAccount = Invoke-StateProbe -RequiredCommand 'Get-LocalUser' -ScriptBlock {
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { "$($_.SID)" -match '^S-1-5-21-[\d-]+-501$' } | Select-Object -First 1
        if ($null -eq $guest) { @{ Present = $false; Enabled = $false } } else { @{ Present = $true; Enabled = [bool]$guest.Enabled } }
    }
    $snapshot
}

#endregion

#region Evaluation helpers

function New-Outcome {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'NOT_APPLICABLE', 'ERROR')][string]$Status,
        [AllowNull()][AllowEmptyString()][string]$Detected = '',
        [AllowNull()][AllowEmptyString()][string]$Message = '',
        [AllowEmptyCollection()][string[]]$Evidence = @()
    )
    @{ Status = $Status; Detected = $Detected; Message = $Message; Evidence = @($Evidence) }
}

function Get-UnavailableOutcome {
    # Maps a failed probe to NOT_APPLICABLE (feature absent on this system)
    # or ERROR (could not be read; the control is not known to pass).
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Probe, [Parameter(Mandatory)][string]$Subject)
    switch ($Probe.Reason) {
        'NotSupported' { return New-Outcome -Status NOT_APPLICABLE -Detected 'Unavailable' -Message "$Subject is not available on this system: $($Probe.Error)" }
        'AccessDenied' { return New-Outcome -Status ERROR -Detected 'Unknown' -Message "$Subject could not be read without Administrator rights: $($Probe.Error)" }
        default { return New-Outcome -Status ERROR -Detected 'Unknown' -Message "$Subject could not be read: $($Probe.Error)" }
    }
}

function Test-DefenderApplicable {
    <#
    .SYNOPSIS
        Returns $null when Defender Antivirus is the active antivirus,
        otherwise the outcome that every Defender control should report.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)][string]$ProbeName)
    $status = $Snapshot.DefenderStatus
    if (-not $status.Available) { return Get-UnavailableOutcome -Probe $status -Subject 'Microsoft Defender status' }
    $mode = [string]$status.Data.AMRunningMode
    if ($mode -and $mode -ne 'Normal') {
        return New-Outcome -Status NOT_APPLICABLE -Detected "AMRunningMode = $mode" `
            -Message 'Microsoft Defender Antivirus is not the primary antivirus on this system (passive or EDR block mode). Assess the active product instead.'
    }
    $probe = $Snapshot[$ProbeName]
    if (-not $probe.Available) { return Get-UnavailableOutcome -Probe $probe -Subject 'Microsoft Defender configuration' }
    $null
}

function Get-RegistryOutcomeValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)][string]$Key)
    $value = $Snapshot.Registry.Data[$Key]
    if ($null -eq $value -or -not $value.Exists) { return $null }
    $value.Value
}

function Get-ExclusionRisk {
    <#
    .SYNOPSIS
        Splits Defender exclusions into high-risk and other entries.
        High-risk means: a drive root or wildcard, a user-writable staging
        folder (Temp, Downloads, Public, a whole profile), a script host or
        LOLBin process, or an executable/script file extension.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][string[]]$Path = @(),
        [AllowNull()][AllowEmptyCollection()][string[]]$Process = @(),
        [AllowNull()][AllowEmptyCollection()][string[]]$Extension = @()
    )
    $riskyPath = @(
        '^[A-Za-z]:\\?\*?$', '^\*', '^%?(TEMP|TMP)%?(\\|$)', '\\Temp(\\|$)', '\\Downloads(\\|$)',
        '^[A-Za-z]:\\Users(\\Public)?\\?$', '^[A-Za-z]:\\Users\\[^\\]+\\?$', '^%USERPROFILE%\\?$', '\\Users\\Public(\\|$)'
    )
    $riskyProcess = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msbuild.exe', 'installutil.exe')
    $riskyExtension = @('exe', 'dll', 'ps1', 'psm1', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'hta', 'scr', 'msi', 'lnk', 'wsf')

    $high = New-Object System.Collections.Generic.List[string]
    $other = New-Object System.Collections.Generic.List[string]
    foreach ($entry in @($Path | Where-Object { $_ })) {
        $isRisky = $false
        foreach ($pattern in $riskyPath) { if ($entry -match $pattern) { $isRisky = $true; break } }
        if ($isRisky) { $high.Add("Path: $entry") } else { $other.Add("Path: $entry") }
    }
    foreach ($entry in @($Process | Where-Object { $_ })) {
        $leaf = ($entry -split '[\\/]')[-1].ToLowerInvariant()
        if ($riskyProcess -contains $leaf) { $high.Add("Process: $entry") } else { $other.Add("Process: $entry") }
    }
    foreach ($entry in @($Extension | Where-Object { $_ })) {
        if ($riskyExtension -contains $entry.TrimStart('.', '*').ToLowerInvariant()) { $high.Add("Extension: $entry") } else { $other.Add("Extension: $entry") }
    }
    @{ High = $high.ToArray(); Other = $other.ToArray() }
}

#endregion

#region Evaluators

$script:Evaluators = @{
    'WIN-DEF-001' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderStatus'; if ($na) { return $na }
        if ($Snapshot.DefenderStatus.Data.RealTimeProtectionEnabled -eq $true) { return New-Outcome PASS 'Enabled' }
        New-Outcome FAIL 'Disabled' 'Real-time protection is off.'
    }
    'WIN-DEF-002' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderStatus'; if ($na) { return $na }
        if ($Snapshot.DefenderStatus.Data.BehaviorMonitorEnabled -eq $true) { return New-Outcome PASS 'Enabled' }
        New-Outcome FAIL 'Disabled' 'Behavior monitoring is off.'
    }
    'WIN-DEF-003' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderPreference'; if ($na) { return $na }
        $maps = $Snapshot.DefenderPreference.Data.MAPSReporting
        $names = @{ 0 = 'Disabled'; 1 = 'Basic'; 2 = 'Advanced' }
        $label = if ($null -ne $maps -and $names.ContainsKey([int]$maps)) { $names[[int]$maps] } else { "$maps" }
        if ($null -ne $maps -and [int]$maps -ge 1) { return New-Outcome PASS "MAPSReporting = $label" }
        New-Outcome FAIL "MAPSReporting = $label" 'Cloud-delivered protection is off.'
    }
    'WIN-DEF-004' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderPreference'; if ($na) { return $na }
        switch ([int]$Snapshot.DefenderPreference.Data.PUAProtection) {
            1 { return New-Outcome PASS 'Enabled (block)' }
            2 { return New-Outcome WARN 'Audit mode' 'PUA detections are logged but not blocked.' }
            default { return New-Outcome WARN 'Disabled' 'PUA protection is off.' }
        }
    }
    'WIN-DEF-005' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderPreference'; if ($na) { return $na }
        switch ([int]$Snapshot.DefenderPreference.Data.EnableNetworkProtection) {
            1 { return New-Outcome PASS 'Enabled (block)' }
            2 { return New-Outcome WARN 'Audit mode' 'Network protection logs but does not block connections.' }
            default { return New-Outcome FAIL 'Disabled' 'Network protection is off.' }
        }
    }
    'WIN-DEF-006' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderStatus'; if ($na) { return $na }
        $age = $Snapshot.DefenderStatus.Data.AntivirusSignatureAge
        if ($null -eq $age) { return New-Outcome ERROR 'Unknown' 'Signature age was not reported.' }
        $age = [int64]$age
        # 65535 / uint32 max are reported when signatures were never loaded.
        if ($age -ge 65535) { return New-Outcome FAIL 'Never updated' 'No signature update has been recorded.' }
        if ($age -le 3) { return New-Outcome PASS "$age day(s) old" }
        if ($age -le 7) { return New-Outcome WARN "$age day(s) old" 'Signatures are older than 3 days.' }
        New-Outcome FAIL "$age day(s) old" 'Signatures are older than 7 days.'
    }
    'WIN-DEF-007' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderStatus'; if ($na) { return $na }
        $value = $Snapshot.DefenderStatus.Data.IsTamperProtected
        if ($null -eq $value) { return New-Outcome NOT_APPLICABLE 'Not reported' 'This Defender version does not report tamper protection state.' }
        if ($value -eq $true) { return New-Outcome PASS 'Enabled' }
        New-Outcome FAIL 'Disabled' 'Tamper protection is off; local administrators and malware can disable Defender features.'
    }
    'WIN-DEF-008' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderPreference'; if ($na) { return $na }
        $data = $Snapshot.DefenderPreference.Data
        $all = @(@($data.ExclusionPath) + @($data.ExclusionProcess) + @($data.ExclusionExtension) | Where-Object { $_ })
        if (@($all | Where-Object { "$_" -match '^N/A: Must be an administrator' }).Count -gt 0) {
            return New-Outcome ERROR 'Hidden' 'Defender only shows exclusions to administrators. Re-run elevated.'
        }
        $risk = Get-ExclusionRisk -Path $data.ExclusionPath -Process $data.ExclusionProcess -Extension $data.ExclusionExtension
        $evidence = @($risk.High | ForEach-Object { "HIGH RISK $_" }) + @($risk.Other)
        if ($risk.High.Count -gt 0) {
            return New-Outcome FAIL "$($risk.High.Count) high-risk of $($evidence.Count) exclusion(s)" 'High-risk exclusions found.' $evidence
        }
        if ($risk.Other.Count -gt 0) {
            return New-Outcome WARN "$($risk.Other.Count) exclusion(s)" 'Exclusions exist; confirm each one is still needed.' $evidence
        }
        New-Outcome PASS 'No exclusions'
    }
    'WIN-DEF-009' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderPreference'; if ($na) { return $na }
        $ids = @($Snapshot.DefenderPreference.Data.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
        $actions = @($Snapshot.DefenderPreference.Data.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
        $counts = @{ Block = 0; Audit = 0; Warn = 0; Off = 0 }
        foreach ($action in $actions) {
            switch ([int]$action) { 1 { $counts.Block++ } 2 { $counts.Audit++ } 6 { $counts.Warn++ } default { $counts.Off++ } }
        }
        $detected = 'Block {0}, Warn {1}, Audit {2}, Off {3}' -f $counts.Block, $counts.Warn, $counts.Audit, $counts.Off
        $evidence = @(for ($i = 0; $i -lt $ids.Count; $i++) { '{0} = {1}' -f $ids[$i], $(if ($i -lt $actions.Count) { $actions[$i] } else { '?' }) })
        if ($counts.Block + $counts.Warn -gt 0) { return New-Outcome PASS $detected '' $evidence }
        if ($counts.Audit -gt 0) { return New-Outcome WARN $detected 'ASR rules are in audit mode only.' $evidence }
        New-Outcome WARN 'No rules configured' 'No attack surface reduction rules are configured.'
    }
    'WIN-DEF-010' = {
        param($Snapshot)
        $na = Test-DefenderApplicable $Snapshot 'DefenderPreference'; if ($na) { return $na }
        switch ([int]$Snapshot.DefenderPreference.Data.EnableControlledFolderAccess) {
            1 { return New-Outcome PASS 'Enabled (block)' }
            2 { return New-Outcome WARN 'Audit mode' 'Controlled folder access is in audit mode.' }
            default { return New-Outcome WARN 'Disabled' 'Controlled folder access is off.' }
        }
    }
    'WIN-FW-001' = { param($Snapshot) Get-FirewallOutcome $Snapshot 'Domain' }
    'WIN-FW-002' = { param($Snapshot) Get-FirewallOutcome $Snapshot 'Private' }
    'WIN-FW-003' = { param($Snapshot) Get-FirewallOutcome $Snapshot 'Public' }
    'WIN-SMB-001' = {
        param($Snapshot)
        if (-not $Snapshot.SmbServer.Available) { return Get-UnavailableOutcome $Snapshot.SmbServer 'SMB server configuration' }
        if ($Snapshot.SmbServer.Data.EnableSMB1Protocol -eq $false) { return New-Outcome PASS 'Disabled' }
        New-Outcome FAIL 'Enabled' 'The SMB server accepts SMBv1 connections.'
    }
    'WIN-SMB-002' = {
        param($Snapshot)
        if (-not $Snapshot.Smb1Feature.Available) { return Get-UnavailableOutcome $Snapshot.Smb1Feature 'Windows optional features' }
        $state = [string]$Snapshot.Smb1Feature.Data
        if ($state -in @('Disabled', 'DisabledWithPayloadRemoved', 'NotPresent')) { return New-Outcome PASS $state }
        if ($state -eq 'DisablePending') { return New-Outcome WARN $state 'SMBv1 removal is waiting for a restart.' }
        New-Outcome FAIL $state 'The SMBv1 feature is installed.'
    }
    'WIN-SMB-003' = {
        param($Snapshot)
        if (-not $Snapshot.SmbServer.Available) { return Get-UnavailableOutcome $Snapshot.SmbServer 'SMB server configuration' }
        if ($Snapshot.SmbServer.Data.RequireSecuritySignature -eq $true) { return New-Outcome PASS 'Required' }
        New-Outcome WARN 'Not required' 'SMB signing is negotiated but not required.'
    }
    'WIN-NET-001' = {
        param($Snapshot)
        if (-not $Snapshot.Registry.Available) { return Get-UnavailableOutcome $Snapshot.Registry 'The registry' }
        $value = Get-RegistryOutcomeValue $Snapshot 'LlmnrMulticast'
        if ($null -ne $value -and [int]$value -eq 0) { return New-Outcome PASS 'Disabled by policy' }
        $detected = if ($null -eq $value) { 'Not configured (LLMNR on)' } else { "EnableMulticast = $value" }
        New-Outcome FAIL $detected 'LLMNR is active and can be poisoned on the local network.'
    }
    'WIN-PS-001' = { param($Snapshot) Get-PolicyFlagOutcome $Snapshot 'ScriptBlockLogging' 'FAIL' 'Script block logging is not enabled by policy.' }
    'WIN-PS-002' = { param($Snapshot) Get-PolicyFlagOutcome $Snapshot 'ModuleLogging' 'WARN' 'Module logging is not enabled by policy.' }
    'WIN-PS-003' = { param($Snapshot) Get-PolicyFlagOutcome $Snapshot 'Transcription' 'WARN' 'Transcription is not enabled by policy.' }
    'WIN-PS-004' = {
        param($Snapshot)
        if (-not $Snapshot.PowerShellV2Feature.Available) { return Get-UnavailableOutcome $Snapshot.PowerShellV2Feature 'Windows optional features' }
        $state = [string]$Snapshot.PowerShellV2Feature.Data
        if ($state -in @('Disabled', 'DisabledWithPayloadRemoved', 'NotPresent')) { return New-Outcome PASS $state }
        New-Outcome FAIL $state 'The PowerShell 2.0 engine can be started to bypass logging and AMSI.'
    }
    'WIN-BL-001' = {
        param($Snapshot)
        $probe = $Snapshot.BitLocker
        if (-not $probe.Available) {
            if ($probe.Reason -eq 'NotSupported') {
                return New-Outcome NOT_APPLICABLE 'Unavailable' 'BitLocker cmdlets are not available (for example on Windows Home). Check Device Encryption in Settings.'
            }
            return Get-UnavailableOutcome $probe 'BitLocker status'
        }
        $protection = [string]$probe.Data.ProtectionStatus
        $volume = [string]$probe.Data.VolumeStatus
        $detected = "ProtectionStatus = $protection, VolumeStatus = $volume"
        if ($protection -eq 'On') { return New-Outcome PASS $detected }
        if ($volume -eq 'FullyEncrypted') { return New-Outcome WARN $detected 'The drive is encrypted but protection is suspended.' }
        New-Outcome FAIL $detected 'The operating system drive is not protected by BitLocker.'
    }
    'WIN-SYS-001' = {
        param($Snapshot)
        if (-not $Snapshot.Registry.Available) { return Get-UnavailableOutcome $Snapshot.Registry 'The registry' }
        $value = Get-RegistryOutcomeValue $Snapshot 'EnableLUA'
        # Absent means the Windows default, which is enabled.
        if ($null -eq $value -or [int]$value -eq 1) { return New-Outcome PASS 'Enabled' }
        New-Outcome FAIL "EnableLUA = $value" 'User Account Control is disabled.'
    }
    'WIN-SYS-002' = {
        param($Snapshot)
        if (-not $Snapshot.Registry.Available) { return Get-UnavailableOutcome $Snapshot.Registry 'The registry' }
        $value = Get-RegistryOutcomeValue $Snapshot 'RunAsPPL'
        if ($null -ne $value -and [int]$value -in @(1, 2)) { return New-Outcome PASS "RunAsPPL = $value" }
        $detected = if ($null -eq $value) { 'Not configured' } else { "RunAsPPL = $value" }
        New-Outcome WARN $detected 'LSASS does not run as a protected process.'
    }
    'WIN-SYS-003' = {
        param($Snapshot)
        $probe = $Snapshot.SecureBoot
        if (-not $probe.Available) { return Get-UnavailableOutcome $probe 'Secure Boot state' }
        if ($probe.Data -eq $true) { return New-Outcome PASS 'Enabled' }
        New-Outcome FAIL 'Disabled' 'Secure Boot is supported but turned off.'
    }
    'WIN-ACC-001' = {
        param($Snapshot)
        $probe = $Snapshot.GuestAccount
        if (-not $probe.Available) { return Get-UnavailableOutcome $probe 'Local accounts' }
        if (-not $probe.Data.Present) { return New-Outcome PASS 'Not present' }
        if (-not $probe.Data.Enabled) { return New-Outcome PASS 'Disabled' }
        New-Outcome FAIL 'Enabled' 'The built-in Guest account is enabled.'
    }
    'WIN-RDP-001' = {
        param($Snapshot)
        if (-not $Snapshot.Registry.Available) { return Get-UnavailableOutcome $Snapshot.Registry 'The registry' }
        $deny = Get-RegistryOutcomeValue $Snapshot 'DenyTSConnections'
        if ($null -eq $deny -or [int]$deny -eq 1) { return New-Outcome PASS 'Remote Desktop disabled' }
        $nla = Get-RegistryOutcomeValue $Snapshot 'RdpNla'
        if ($null -ne $nla -and [int]$nla -eq 1) { return New-Outcome PASS 'Remote Desktop enabled with NLA' }
        $detected = if ($null -eq $nla) { 'Remote Desktop enabled, NLA setting not found' } else { 'Remote Desktop enabled without NLA' }
        New-Outcome FAIL $detected 'Remote Desktop accepts connections without Network Level Authentication.'
    }
}

function Get-FirewallOutcome {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)][string]$ProfileName)
    $probe = $Snapshot.Firewall
    if (-not $probe.Available) { return Get-UnavailableOutcome $probe 'Windows Firewall profiles' }
    $fwProfile = @($probe.Data | Where-Object { $_.Name -eq $ProfileName }) | Select-Object -First 1
    if ($null -eq $fwProfile) { return New-Outcome ERROR 'Missing' "The $ProfileName profile was not returned." }
    $enabled = [string]$fwProfile.Enabled
    $inbound = [string]$fwProfile.DefaultInboundAction
    $detected = "Enabled = $enabled, DefaultInboundAction = $inbound"
    if ($enabled -ne 'True') { return New-Outcome FAIL $detected "The $ProfileName firewall profile is off." }
    # NotConfigured on an enabled profile means the Windows default (Block).
    if ($inbound -eq 'Allow') { return New-Outcome FAIL $detected "The $ProfileName profile allows unsolicited inbound traffic by default." }
    New-Outcome PASS $detected
}

function Get-PolicyFlagOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][ValidateSet('FAIL', 'WARN')][string]$StatusWhenOff,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Snapshot.Registry.Available) { return Get-UnavailableOutcome $Snapshot.Registry 'The registry' }
    $value = Get-RegistryOutcomeValue $Snapshot $Key
    if ($null -ne $value -and [int]$value -eq 1) { return New-Outcome PASS 'Enabled by policy' }
    $detected = if ($null -eq $value) { 'Not configured' } else { "Value = $value" }
    New-Outcome $StatusWhenOff $detected $Message
}

#endregion

#region Catalog and assessment

function Get-ImplementedControlId {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    @($script:Evaluators.Keys | Sort-Object)
}

function Test-ControlCatalog {
    <#
    .SYNOPSIS
        Validates controls.json. Returns error strings (empty when valid).
        Also checks that every control has an evaluator and vice versa, so
        configuration and code cannot drift apart silently.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)]$Catalog)
    $errors = New-Object System.Collections.Generic.List[string]
    if ((Get-OptionalProperty $Catalog 'schemaVersion') -ne 1) { $errors.Add('schemaVersion must be 1') }
    $controls = @(Get-OptionalProperty $Catalog 'controls' @())
    if ($controls.Count -eq 0) { $errors.Add('controls must be a non-empty array') }

    $seen = @{}
    foreach ($control in $controls) {
        $id = [string](Get-OptionalProperty $control 'id')
        if ($id -notmatch '^WIN-[A-Z]{2,4}-\d{3}$') { $errors.Add("Invalid control id '$id'"); continue }
        if ($seen.ContainsKey($id)) { $errors.Add("Duplicate control id '$id'") }
        $seen[$id] = $true
        foreach ($field in @('name', 'category', 'expected', 'rationale')) {
            if ([string]::IsNullOrWhiteSpace((Get-OptionalProperty $control $field))) { $errors.Add("${id}: '$field' is required") }
        }
        if ($script:Severities -notcontains (Get-OptionalProperty $control 'severity')) { $errors.Add("${id}: severity must be one of $($script:Severities -join ', ')") }
        $remediation = Get-OptionalProperty $control 'remediation'
        if (@('Automated', 'Manual') -notcontains (Get-OptionalProperty $remediation 'type')) { $errors.Add("${id}: remediation.type must be Automated or Manual") }
        if ([string]::IsNullOrWhiteSpace((Get-OptionalProperty $remediation 'guidance'))) { $errors.Add("${id}: remediation.guidance is required") }

        $references = Get-OptionalProperty $control 'references'
        foreach ($ref in @(Get-OptionalProperty $references 'nist80053' @())) {
            if ($ref -notmatch '^[A-Z]{2}-\d{1,2}$') { $errors.Add("${id}: invalid NIST SP 800-53 reference '$ref'") }
        }
        foreach ($ref in @(Get-OptionalProperty $references 'attack' @())) {
            if ($ref -notmatch '^(T\d{4}(\.\d{3})?|M\d{4})$') { $errors.Add("${id}: invalid ATT&CK reference '$ref'") }
        }
        foreach ($ref in @(Get-OptionalProperty $references 'microsoft' @())) {
            if ($ref -notmatch '^https://learn\.microsoft\.com/') { $errors.Add("${id}: Microsoft references must be learn.microsoft.com URLs") }
        }
        if (-not $script:Evaluators.ContainsKey($id)) { $errors.Add("${id}: no evaluator is implemented") }
    }
    foreach ($implemented in $script:Evaluators.Keys) {
        if (-not $seen.ContainsKey($implemented)) { $errors.Add("Evaluator $implemented has no entry in controls.json") }
    }
    $errors.ToArray()
}

function Import-ControlCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $catalog = Read-JsonFile -Path $Path
    $errors = @(Test-ControlCatalog -Catalog $catalog)
    if ($errors.Count -gt 0) {
        throw ("Control catalog '{0}' is invalid:`n  - {1}" -f $Path, ($errors -join "`n  - "))
    }
    $catalog
}

function Invoke-SecurityAssessment {
    <#
    .SYNOPSIS
        Evaluates controls against a snapshot and returns one finding per
        control. Never changes system state.
    .PARAMETER Snapshot
        State from Get-SecuritySnapshot. Collected automatically when omitted;
        tests pass fixtures here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Catalog,
        [hashtable]$Snapshot,
        [string[]]$ControlId = @()
    )
    if (-not $Snapshot) { $Snapshot = Get-SecuritySnapshot }
    $controls = @($Catalog.controls)
    if (@($ControlId).Count -gt 0) { $controls = @($controls | Where-Object { $ControlId -contains $_.id }) }

    foreach ($control in $controls) {
        try {
            $outcome = & $script:Evaluators[$control.id] $Snapshot
        } catch {
            $outcome = New-Outcome -Status ERROR -Detected 'Unknown' -Message "Evaluation failed: $($_.Exception.Message)"
        }
        $remediationType = $control.remediation.type
        [pscustomobject][ordered]@{
            id                   = $control.id
            name                 = $control.name
            category             = $control.category
            severity             = $control.severity
            status               = $outcome.Status
            expected             = $control.expected
            detected             = Protect-SensitiveText $outcome.Detected
            message              = Protect-SensitiveText $outcome.Message
            evidence             = @($outcome.Evidence | ForEach-Object { Protect-SensitiveText $_ })
            rationale            = $control.rationale
            remediationType      = $remediationType
            remediationAvailable = ($remediationType -eq 'Automated' -and $outcome.Status -in @('FAIL', 'WARN'))
            remediationGuidance  = $control.remediation.guidance
            references           = $control.references
        }
    }
}

#endregion

Export-ModuleMember -Function Get-RegistryValue, Invoke-StateProbe, Get-OptionalFeatureState, Get-SecuritySnapshot, Get-ExclusionRisk,
    Get-ImplementedControlId, Test-ControlCatalog, Import-ControlCatalog, Invoke-SecurityAssessment
