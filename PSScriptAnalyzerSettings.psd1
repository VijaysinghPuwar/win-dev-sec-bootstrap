# PSScriptAnalyzer settings for the product code (bootstrap script and modules).
# CI fails on Error and Warning findings; Information findings are printed but
# do not fail the build. tests/PSScriptAnalyzerSettings.psd1 relaxes two rules
# that misfire on Pester's scoping model.
@{
    Severity = @('Error', 'Warning', 'Information')
    Rules    = @{
        # Keep the syntax usable on Windows PowerShell 5.1 as well as PowerShell 7.
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
