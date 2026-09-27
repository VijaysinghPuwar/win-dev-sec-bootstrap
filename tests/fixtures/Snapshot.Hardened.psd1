# Synthetic snapshot in which every control passes. Tests copy it and change
# single values to exercise each evaluator branch. Not collected from a real
# machine.
@{
    DefenderStatus      = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{
            AMRunningMode             = 'Normal'
            AntivirusEnabled          = $true
            RealTimeProtectionEnabled = $true
            BehaviorMonitorEnabled    = $true
            AntivirusSignatureAge     = 0
            IsTamperProtected         = $true
        }
    }
    DefenderPreference  = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{
            DisableRealtimeMonitoring           = $false
            DisableBehaviorMonitoring           = $false
            MAPSReporting                       = 2
            PUAProtection                       = 1
            EnableNetworkProtection             = 1
            EnableControlledFolderAccess        = 1
            ExclusionPath                       = @()
            ExclusionProcess                    = @()
            ExclusionExtension                  = @()
            AttackSurfaceReductionRules_Ids     = @('56a863a9-875e-4185-98a7-b882c64b5ce5', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a')
            AttackSurfaceReductionRules_Actions = @(1, 2)
        }
    }
    Firewall            = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @(
            @{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block' }
            @{ Name = 'Private'; Enabled = 'True'; DefaultInboundAction = 'NotConfigured' }
            @{ Name = 'Public'; Enabled = 'True'; DefaultInboundAction = 'Block' }
        )
    }
    SmbServer           = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{ EnableSMB1Protocol = $false; RequireSecuritySignature = $true }
    }
    Smb1Feature         = @{ Available = $true; Reason = $null; Error = $null; Data = 'Disabled' }
    PowerShellV2Feature = @{ Available = $true; Reason = $null; Error = $null; Data = 'NotPresent' }
    Registry            = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{
            ScriptBlockLogging = @{ Exists = $true; Value = 1 }
            ModuleLogging      = @{ Exists = $true; Value = 1 }
            Transcription      = @{ Exists = $true; Value = 1 }
            LlmnrMulticast     = @{ Exists = $true; Value = 0 }
            EnableLUA          = @{ Exists = $true; Value = 1 }
            RunAsPPL           = @{ Exists = $true; Value = 2 }
            DenyTSConnections  = @{ Exists = $true; Value = 1 }
            RdpNla             = @{ Exists = $true; Value = 1 }
        }
    }
    BitLocker           = @{
        Available = $true; Reason = $null; Error = $null
        Data      = @{ ProtectionStatus = 'On'; VolumeStatus = 'FullyEncrypted'; EncryptionPercentage = 100 }
    }
    SecureBoot          = @{ Available = $true; Reason = $null; Error = $null; Data = $true }
    GuestAccount        = @{ Available = $true; Reason = $null; Error = $null; Data = @{ Present = $true; Enabled = $false } }
}
