# PSScriptAnalyzer settings for Pester test files.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Variables assigned in BeforeAll/BeforeDiscovery are consumed inside It
        # blocks, which the analyzer cannot see across Pester's script blocks.
        'PSUseDeclaredVarsMoreThanAssignments'
        # Test helpers such as New-TestCatalog only build in-memory fixtures.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
