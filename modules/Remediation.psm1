#Requires -Version 5.1
<#
    Opt-in remediation and rollback for the subset of controls whose setting
    takes effect immediately, can be read back to verify, and can be
    restored exactly.

    Sequence per control:
        ShouldProcess -> record the current value in the backup file ->
        apply -> read back and verify -> record the outcome

    The backup file is written before each change, so an interrupted run
    still leaves enough information to roll back what was touched.

    Controls that need a restart (optional features, UAC, LSA protection),
    could lock the user out of data (BitLocker), or often break developer
    tooling (ASR rules, controlled folder access, exclusions) are
    deliberately Manual and have no handler here.
#>
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

$script:BackupFormatVersion = 1

# Handler definitions are data; behaviour lives in the *-RemediationState
# functions below, dispatched on Kind. Nothing here comes from configuration.
$script:Handlers = @{
    'WIN-DEF-001' = @{ Kind = 'MpPreference'; Property = 'DisableRealtimeMonitoring'; Desired = $false; Allowed = @($true, $false) }
    'WIN-DEF-002' = @{ Kind = 'MpPreference'; Property = 'DisableBehaviorMonitoring'; Desired = $false; Allowed = @($true, $false) }
    'WIN-DEF-003' = @{ Kind = 'MpPreference'; Property = 'MAPSReporting'; Desired = 2; Allowed = @(0, 1, 2) }
    'WIN-DEF-004' = @{ Kind = 'MpPreference'; Property = 'PUAProtection'; Desired = 1; Allowed = @(0, 1, 2) }
    'WIN-DEF-005' = @{ Kind = 'MpPreference'; Property = 'EnableNetworkProtection'; Desired = 1; Allowed = @(0, 1, 2) }
    'WIN-DEF-006' = @{ Kind = 'SignatureUpdate' }
    'WIN-FW-001'  = @{ Kind = 'FirewallProfile'; Profile = 'Domain' }
    'WIN-FW-002'  = @{ Kind = 'FirewallProfile'; Profile = 'Private' }
    'WIN-FW-003'  = @{ Kind = 'FirewallProfile'; Profile = 'Public' }
    'WIN-SMB-001' = @{ Kind = 'SmbServer'; Property = 'EnableSMB1Protocol'; Desired = $false; Allowed = @($true, $false) }
    'WIN-NET-001' = @{ Kind = 'RegistryPolicy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Desired = 0 }
    'WIN-PS-001'  = @{ Kind = 'RegistryPolicy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Desired = 1 }
    'WIN-ACC-001' = @{ Kind = 'GuestAccount' }
}

#region Handler lookup

function Get-RemediableControlId {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    @($script:Handlers.Keys | Sort-Object)
}

function Get-RemediationHandler {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ControlId)
    if ($script:Handlers.ContainsKey($ControlId)) { return $script:Handlers[$ControlId] }
    $null
}

function Test-RemediationCoverage {
    <#
    .SYNOPSIS
        Returns errors when controls.json and the implemented handlers
        disagree about which controls have automated remediation.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)]$Catalog)
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($control in $Catalog.controls) {
        $automated = $control.remediation.type -eq 'Automated'
        $hasHandler = $script:Handlers.ContainsKey($control.id)
        if ($automated -and -not $hasHandler) { $errors.Add("$($control.id) is marked Automated but has no remediation handler") }
        if (-not $automated -and $hasHandler) { $errors.Add("$($control.id) has a remediation handler but is marked Manual") }
    }
    $errors.ToArray()
}

function Test-RollbackSupported {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][hashtable]$Handler)
    # A signature update cannot and should not be undone.
    $Handler.Kind -ne 'SignatureUpdate'
}

#endregion

#region State access (the only functions that touch the system)

function Get-GuestAccount {
    [CmdletBinding()]
    param()
    Get-LocalUser -ErrorAction Stop | Where-Object { "$($_.SID)" -match '^S-1-5-21-[\d-]+-501$' } | Select-Object -First 1
}

function Get-RemediationState {
    <#
    .SYNOPSIS
        Reads the current value of the setting a handler manages, in a form
        that can be stored in the backup file and passed to Restore.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Handler)
    switch ($Handler.Kind) {
        'MpPreference' { return (Get-MpPreference -ErrorAction Stop).($Handler.Property) }
        'SmbServer' { return (Get-SmbServerConfiguration -ErrorAction Stop).($Handler.Property) }
        'SignatureUpdate' { return [int64](Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureAge }
        'FirewallProfile' {
            # The local (persistent) store is what this tool can change and restore.
            $p = Get-NetFirewallProfile -Profile $Handler.Profile -PolicyStore PersistentStore -ErrorAction Stop
            return @{ Enabled = [string]$p.Enabled; DefaultInboundAction = [string]$p.DefaultInboundAction }
        }
        'RegistryPolicy' {
            $keyExists = Test-Path -LiteralPath $Handler.Path
            $value = $null
            $valueExists = $false
            if ($keyExists) {
                $item = Get-ItemProperty -LiteralPath $Handler.Path -Name $Handler.Name -ErrorAction SilentlyContinue
                if ($null -ne $item) { $valueExists = $true; $value = [int]$item.($Handler.Name) }
            }
            return @{ KeyExists = $keyExists; ValueExists = $valueExists; Value = $value }
        }
        'GuestAccount' {
            $guest = Get-GuestAccount
            if ($null -eq $guest) { return $null }
            return [bool]$guest.Enabled
        }
    }
    throw "Unknown remediation kind '$($Handler.Kind)'"
}

function Set-RemediationState {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][hashtable]$Handler)
    if (-not $PSCmdlet.ShouldProcess($Handler.Kind, 'Apply desired state')) { return }
    switch ($Handler.Kind) {
        'MpPreference' { $arguments = @{ $Handler.Property = $Handler.Desired }; Set-MpPreference @arguments -ErrorAction Stop; return }
        'SmbServer' { $arguments = @{ $Handler.Property = $Handler.Desired }; Set-SmbServerConfiguration @arguments -Force -ErrorAction Stop; return }
        'SignatureUpdate' { Update-MpSignature -ErrorAction Stop; return }
        'FirewallProfile' { Set-NetFirewallProfile -Profile $Handler.Profile -Enabled True -DefaultInboundAction Block -ErrorAction Stop; return }
        'RegistryPolicy' {
            if (-not (Test-Path -LiteralPath $Handler.Path)) { New-Item -Path $Handler.Path -Force -ErrorAction Stop | Out-Null }
            New-ItemProperty -LiteralPath $Handler.Path -Name $Handler.Name -PropertyType DWord -Value $Handler.Desired -Force -ErrorAction Stop | Out-Null
            return
        }
        'GuestAccount' {
            $guest = Get-GuestAccount
            if ($guest) { Disable-LocalUser -SID $guest.SID -ErrorAction Stop }
            return
        }
    }
    throw "Unknown remediation kind '$($Handler.Kind)'"
}

function Test-RemediationState {
    <#
    .SYNOPSIS
        Verifies the desired state after a change. Firewall verification
        reads the effective (ActiveStore) policy, so a Group Policy that
        overrides the local change is reported as a failed remediation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][hashtable]$Handler)
    switch ($Handler.Kind) {
        'MpPreference' { return (Get-RemediationState -Handler $Handler) -eq $Handler.Desired }
        'SmbServer' { return (Get-RemediationState -Handler $Handler) -eq $Handler.Desired }
        'SignatureUpdate' { return (Get-RemediationState -Handler $Handler) -le 3 }
        'FirewallProfile' {
            $p = Get-NetFirewallProfile -Profile $Handler.Profile -PolicyStore ActiveStore -ErrorAction Stop
            return ([string]$p.Enabled -eq 'True' -and [string]$p.DefaultInboundAction -ne 'Allow')
        }
        'RegistryPolicy' { $s = Get-RemediationState -Handler $Handler; return ($s.ValueExists -and $s.Value -eq $Handler.Desired) }
        'GuestAccount' { return (Get-RemediationState -Handler $Handler) -ne $true }
    }
    $false
}

function Test-BackupValue {
    <#
    .SYNOPSIS
        Validates a value read from a backup file before it is written back
        to the system. The backup file sits on disk between runs, so it is
        treated as untrusted input: only the value shapes this handler could
        have produced are accepted.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][hashtable]$Handler, [AllowNull()]$Value)
    $isInteger = { param($v) $v -is [int] -or $v -is [long] -or $v -is [int16] -or $v -is [byte] }
    switch ($Handler.Kind) {
        'MpPreference' {
            foreach ($allowed in $Handler.Allowed) {
                if (($allowed -is [bool]) -and ($Value -is [bool]) -and $Value -eq $allowed) { return $true }
                if (($allowed -is [int]) -and (& $isInteger $Value) -and [int64]$Value -eq $allowed) { return $true }
            }
            return $false
        }
        'SmbServer' { return $Value -is [bool] }
        'GuestAccount' { return $Value -is [bool] }
        'FirewallProfile' {
            return ((Get-OptionalProperty $Value 'Enabled') -in @('True', 'False', 'NotConfigured') -and
                (Get-OptionalProperty $Value 'DefaultInboundAction') -in @('Block', 'Allow', 'NotConfigured'))
        }
        'RegistryPolicy' {
            $keyExists = Get-OptionalProperty $Value 'KeyExists'
            $valueExists = Get-OptionalProperty $Value 'ValueExists'
            $raw = Get-OptionalProperty $Value 'Value'
            if (-not ($keyExists -is [bool]) -or -not ($valueExists -is [bool])) { return $false }
            if ($valueExists) { return ((& $isInteger $raw) -and [int64]$raw -ge 0 -and [int64]$raw -le [uint32]::MaxValue) }
            return $null -eq $raw
        }
    }
    $false
}

function Restore-RemediationState {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][hashtable]$Handler, [AllowNull()]$Before)
    if (-not $PSCmdlet.ShouldProcess($Handler.Kind, 'Restore previous state')) { return }
    switch ($Handler.Kind) {
        'MpPreference' {
            $value = if ($Before -is [bool]) { $Before } else { [int]$Before }
            $arguments = @{ $Handler.Property = $value }
            Set-MpPreference @arguments -ErrorAction Stop
            return
        }
        'SmbServer' { $arguments = @{ $Handler.Property = [bool]$Before }; Set-SmbServerConfiguration @arguments -Force -ErrorAction Stop; return }
        'FirewallProfile' {
            Set-NetFirewallProfile -Profile $Handler.Profile -Enabled $Before.Enabled -DefaultInboundAction $Before.DefaultInboundAction -ErrorAction Stop
            return
        }
        'RegistryPolicy' {
            if ($Before.ValueExists) {
                if (-not (Test-Path -LiteralPath $Handler.Path)) { New-Item -Path $Handler.Path -Force -ErrorAction Stop | Out-Null }
                New-ItemProperty -LiteralPath $Handler.Path -Name $Handler.Name -PropertyType DWord -Value ([int64]$Before.Value) -Force -ErrorAction Stop | Out-Null
                return
            }
            if (Test-Path -LiteralPath $Handler.Path) {
                Remove-ItemProperty -LiteralPath $Handler.Path -Name $Handler.Name -ErrorAction SilentlyContinue
                # Remove the key only if this tool created it and it is now empty.
                $key = Get-Item -LiteralPath $Handler.Path
                if (-not $Before.KeyExists -and $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) {
                    Remove-Item -LiteralPath $Handler.Path -ErrorAction Stop
                }
            }
            return
        }
        'GuestAccount' {
            $guest = Get-GuestAccount
            if ($guest -and $Before -eq $true) { Enable-LocalUser -SID $guest.SID -ErrorAction Stop }
            return
        }
    }
    throw "Rollback is not supported for '$($Handler.Kind)'"
}

#endregion

#region Backup file

function New-RemediationBackup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an in-memory object; Save-RemediationBackup writes it.')]
    [CmdletBinding()]
    param()
    $tool = Get-ToolInfo
    [ordered]@{
        tool          = $tool.Name
        toolVersion   = $tool.Version
        formatVersion = $script:BackupFormatVersion
        createdUtc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        computerName  = [Environment]::MachineName
        changes       = New-Object System.Collections.ArrayList
    }
}

function Protect-BackupDirectory {
    <#
    .SYNOPSIS
        Creates the backup directory with an ACL that only Administrators and
        SYSTEM can write, so a non-elevated process cannot plant values that
        a later elevated -Rollback would write to the system.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) { return }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create backup directory restricted to Administrators and SYSTEM')) { return }
    New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
    if (-not (Test-IsWindowsPlatform)) { return }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier $sid
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity, 'FullControl', $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Save-RemediationBackup {
    # No ShouldProcess on purpose: the backup is only written for a change
    # that was already confirmed, and must never be skipped by -WhatIf/-Confirm
    # preferences leaking in from the caller.
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Backup, [Parameter(Mandatory)][string]$Path)
    Protect-BackupDirectory -Path (Split-Path -Path $Path -Parent) -WhatIf:$false -Confirm:$false
    Write-JsonFile -Path $Path -InputObject $Backup -WhatIf:$false -Confirm:$false
}

function Read-RemediationBackup {
    <#
    .SYNOPSIS
        Loads and validates a backup file. Entries that fail validation are
        returned with an Error so rollback can report them instead of
        writing unvalidated values to the system.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $backup = Read-JsonFile -Path $Path
    if ((Get-OptionalProperty $backup 'tool') -ne (Get-ToolInfo).Name -or (Get-OptionalProperty $backup 'formatVersion') -ne $script:BackupFormatVersion) {
        throw "$Path is not a win-dev-sec-bootstrap backup (format version $script:BackupFormatVersion)."
    }
    if ((Get-OptionalProperty $backup 'computerName') -ne [Environment]::MachineName) {
        throw "$Path was created on '$($backup.computerName)', not on this computer. Refusing to restore settings from another machine."
    }
    foreach ($change in @(Get-OptionalProperty $backup 'changes' @())) {
        $id = [string](Get-OptionalProperty $change 'controlId')
        $handler = Get-RemediationHandler -ControlId $id
        $problem = $null
        if ($null -eq $handler) { $problem = "unknown control id '$id'" }
        elseif (-not (Test-RollbackSupported -Handler $handler)) { $problem = 'rollback is not applicable to this action' }
        elseif (-not (Test-BackupValue -Handler $handler -Value (Get-OptionalProperty $change 'before'))) { $problem = 'the stored previous value is not valid for this setting' }
        [pscustomobject]@{
            ControlId = $id
            Handler   = $handler
            Before    = Get-OptionalProperty $change 'before'
            Status    = [string](Get-OptionalProperty $change 'status')
            Error     = $problem
        }
    }
}

function ConvertTo-BackupValue {
    # JSON round-trips hashtables as PSCustomObject; restore expects hashtables.
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $table = @{}
        foreach ($p in $Value.PSObject.Properties) { $table[$p.Name] = $p.Value }
        return $table
    }
    $Value
}

#endregion

#region Orchestration

function New-RemediationResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][ValidateSet('Remediate', 'Rollback')][string]$Action,
        [Parameter(Mandatory)][ValidateSet('Remediated', 'Restored', 'Failed', 'Skipped')][string]$Status,
        [string]$Detail = '',
        $Before = $null,
        $After = $null
    )
    [pscustomobject][ordered]@{ controlId = $ControlId; action = $Action; status = $Status; detail = $Detail; before = $Before; after = $After }
}

function Invoke-SecurityRemediation {
    <#
    .SYNOPSIS
        Applies automated remediation to the given findings. Each control is
        confirmed individually (ConfirmImpact High), backed up, applied and
        verified. Supports -WhatIf and -Confirm.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)][string]$BackupPath
    )
    $backup = $null
    foreach ($f in $Finding) {
        $handler = Get-RemediationHandler -ControlId $f.id
        if ($null -eq $handler) {
            New-RemediationResult -ControlId $f.id -Action Remediate -Status Skipped -Detail 'No automated remediation for this control'
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("$($f.id) $($f.name)", "Apply: $($f.remediationGuidance)")) {
            New-RemediationResult -ControlId $f.id -Action Remediate -Status Skipped -Detail 'Not applied (WhatIf or declined)'
            continue
        }

        try { $before = Get-RemediationState -Handler $handler }
        catch {
            New-RemediationResult -ControlId $f.id -Action Remediate -Status Failed -Detail "Could not read the current value, nothing changed: $($_.Exception.Message)"
            continue
        }

        if (Test-RollbackSupported -Handler $handler) {
            if ($null -eq $backup) { $backup = New-RemediationBackup }
            $entry = [ordered]@{
                controlId = $f.id; kind = $handler.Kind; before = $before; status = 'Pending'
                timestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); detail = ''
            }
            [void]$backup.changes.Add($entry)
            Save-RemediationBackup -Backup $backup -Path $BackupPath
        } else {
            $entry = $null
        }

        $status = 'Failed'
        $detail = ''
        $after = $null
        try {
            Set-RemediationState -Handler $handler -Confirm:$false
            $after = Get-RemediationState -Handler $handler
            if (Test-RemediationState -Handler $handler) {
                $status = 'Remediated'; $detail = 'Applied and verified'
            } else {
                $detail = 'The change did not take effect. Group Policy, MDM or Defender tamper protection may control this setting.'
            }
        } catch {
            $detail = "Apply failed: $($_.Exception.Message)"
        }
        if ($entry) {
            $entry.status = if ($status -eq 'Remediated') { 'Applied' } else { 'Failed' }
            $entry.detail = $detail
            Save-RemediationBackup -Backup $backup -Path $BackupPath
        }
        New-RemediationResult -ControlId $f.id -Action Remediate -Status $status -Detail $detail -Before $before -After $after
    }
}

function Invoke-SecurityRollback {
    <#
    .SYNOPSIS
        Restores the settings recorded in a backup file, newest change first.
        Every entry is validated before anything is written.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$BackupPath)
    $entries = @(Read-RemediationBackup -Path $BackupPath)
    [array]::Reverse($entries)
    foreach ($entry in $entries) {
        if ($entry.Error) {
            New-RemediationResult -ControlId $entry.ControlId -Action Rollback -Status Failed -Detail "Not restored: $($entry.Error)"
            continue
        }
        $before = ConvertTo-BackupValue $entry.Before
        if (-not $PSCmdlet.ShouldProcess($entry.ControlId, "Restore previous value $(ConvertTo-Json -InputObject $before -Compress)")) {
            New-RemediationResult -ControlId $entry.ControlId -Action Rollback -Status Skipped -Detail 'Not restored (WhatIf or declined)'
            continue
        }
        try {
            Restore-RemediationState -Handler $entry.Handler -Before $before -Confirm:$false
            $after = Get-RemediationState -Handler $entry.Handler
            $isMatch = (ConvertTo-Json -InputObject $after -Compress -Depth 3) -eq (ConvertTo-Json -InputObject $before -Compress -Depth 3)
            if ($entry.Handler.Kind -eq 'FirewallProfile' -or $entry.Handler.Kind -eq 'RegistryPolicy') {
                # Compare the fields that matter; key ordering differs between hashtables.
                $isMatch = @($before.Keys | Where-Object { "$($before[$_])" -ne "$($after[$_])" }).Count -eq 0
            }
            if ($isMatch) {
                New-RemediationResult -ControlId $entry.ControlId -Action Rollback -Status Restored -Detail 'Previous value restored and verified' -Before $before -After $after
            } else {
                New-RemediationResult -ControlId $entry.ControlId -Action Rollback -Status Failed -Detail 'Restore ran but the value read back differs from the backup' -Before $before -After $after
            }
        } catch {
            New-RemediationResult -ControlId $entry.ControlId -Action Rollback -Status Failed -Detail "Restore failed: $($_.Exception.Message)" -Before $before
        }
    }
}

#endregion

Export-ModuleMember -Function Get-RemediableControlId, Get-RemediationHandler, Test-RemediationCoverage, Test-RollbackSupported,
    Get-RemediationState, Set-RemediationState, Test-RemediationState, Test-BackupValue, Restore-RemediationState,
    New-RemediationBackup, Protect-BackupDirectory, Save-RemediationBackup, Read-RemediationBackup, Invoke-SecurityRemediation, Invoke-SecurityRollback
