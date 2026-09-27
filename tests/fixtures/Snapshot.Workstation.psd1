# Synthetic snapshot of a typical unmanaged developer workstation: Defender
# mostly on, no hardening policies, one broad developer exclusion. Used by the
# reporting tests and to generate docs/examples. Not collected from a real
# machine; the user name in the exclusion path is a placeholder.
@{
    DefenderStatus      = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{
            AMRunningMode             = 'Normal'
            AntivirusEnabled          = $true
            RealTimeProtectionEnabled = $true
            BehaviorMonitorEnabled    = $true
            AntivirusSignatureAge     = 1
            IsTamperProtected         = $true
        }
    }
    DefenderPreference  = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{
            DisableRealtimeMonitoring           = $false
            DisableBehaviorMonitoring           = $false
            MAPSReporting                       = 2
            PUAProtection                       = 2
            EnableNetworkProtection             = 0
            EnableControlledFolderAccess        = 0
            ExclusionPath                       = @('C:\Users\exampleuser\source\repos', 'C:\Users\exampleuser\Downloads')
            ExclusionProcess                    = @()
            ExclusionExtension                  = @()
            AttackSurfaceReductionRules_Ids     = @()
            AttackSurfaceReductionRules_Actions = @()
        }
    }
    Firewall            = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @(
            @{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'NotConfigured' }
            @{ Name = 'Private'; Enabled = 'True'; DefaultInboundAction = 'NotConfigured' }
            @{ Name = 'Public'; Enabled = 'True'; DefaultInboundAction = 'NotConfigured' }
        )
    }
    SmbServer           = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{ EnableSMB1Protocol = $false; RequireSecuritySignature = $false }
    }
    Smb1Feature         = @{ Available = $true; Reason = $null; Error = $null; Data = 'Disabled' }
    PowerShellV2Feature = @{ Available = $true; Reason = $null; Error = $null; Data = 'NotPresent' }
    Registry            = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{
            ScriptBlockLogging = @{ Exists = $false; Value = $null }
            ModuleLogging      = @{ Exists = $false; Value = $null }
            Transcription      = @{ Exists = $false; Value = $null }
            LlmnrMulticast     = @{ Exists = $false; Value = $null }
            EnableLUA          = @{ Exists = $true; Value = 1 }
            RunAsPPL           = @{ Exists = $false; Value = $null }
            DenyTSConnections  = @{ Exists = $true; Value = 1 }
            RdpNla             = @{ Exists = $true; Value = 1 }
        }
    }
    BitLocker           = @{
        Available = $false; Reason = 'NotSupported'; Error = 'Get-BitLockerVolume is not available on this system'; Data = $null
    }
    SecureBoot          = @{ Available = $true; Reason = $null; Error = $null; Data = $true }
    GuestAccount        = @{ Available = $true; Reason = $null; Error = $null; Data = @{ Present = $true; Enabled = $false } }
}
