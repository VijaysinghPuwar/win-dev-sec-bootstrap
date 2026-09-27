# PSScriptAnalyzer settings for the product code (bootstrap script and modules).
# CI fails on Error and Warning findings; Information findings are printed but
# do not fail the build. tests/PSScriptAnalyzerSettings.psd1 relaxes two rules
# that misfire on Pester's scoping model.
@{
    Severity = @('Error', 'Warning', 'Information')
    Rules    = @{
        # Keep the syntax usable on Windows PowerShell 5.1 as well as PowerShell 7.
        PSUseCompatibleSyntax   = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        # Check cmdlets and their parameters against Windows PowerShell 5.1
        # (Windows 10 1809 profile) and PowerShell 7 on Windows. Added after
        # Stop-Transcript -WhatIf (valid only in 7) broke the 5.1 dry run.
        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @(
                'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'
            )
        }
    }
}
