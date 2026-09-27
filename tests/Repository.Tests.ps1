#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Repository-wide checks: shipped configuration is valid, PowerShell files
# parse on this engine, and every script stays ASCII-only so Windows
# PowerShell 5.1 reads BOM-less files correctly.

BeforeDiscovery {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $powershellFiles = @(Get-ChildItem -Path $repoRoot -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File |
        Where-Object { $_.FullName -notmatch '[\\/](\.git|logs|reports|backup)[\\/]' } |
        ForEach-Object { @{ Path = $_.FullName; Name = $_.FullName.Substring($repoRoot.Length + 1) } })
}

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'modules/Common.psm1') -Force
    Import-Module (Join-Path $repoRoot 'modules/PackageManager.psm1') -Force
}

Describe 'Shipped package catalog' {
    It 'passes validation' {
        { Import-PackageCatalog -Path (Join-Path $repoRoot 'config/packages.json') } | Should -Not -Throw
    }

    It 'no longer contains the ids that were wrong or duplicated' {
        $ids = @((Import-PackageCatalog -Path (Join-Path $repoRoot 'config/packages.json')).packages |
            ForEach-Object { "$($_.source):$(Get-OptionalProperty $_ 'id')" })
        foreach ($bad in @('winget:OWASP.ZAP', 'winget:Microsoft.SysinternalsSuite', 'winget:Nmap.Nmap', 'winget:CMake.CMake',
                'winget:Progress.Fiddler.Classic', 'winget:NSA.Ghidra', 'winget:Hashcat.Hashcat', 'winget:BurntSushi.ripgrep',
                'pipx:yara-python', 'pipx:mitmproxy', 'vscode:VisualStudioExptTeam.vscodeintellicode', 'vscode:ms-vscode.vscode-node-azure-pack')) {
            $ids | Should -Not -Contain $bad
        }
    }
}

Describe 'PowerShell source files' {
    It '<Name> parses without errors' -TestCases $powershellFiles {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It '<Name> is ASCII-only' -TestCases $powershellFiles {
        $bytes = [IO.File]::ReadAllBytes($Path)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'Generated documentation' {
    It 'docs/CONTROLS.md matches config/controls.json (run tools/New-ControlDoc.ps1)' {
        $expected = & (Join-Path (Join-Path $repoRoot 'tools') 'New-ControlDoc.ps1') -PassThru
        $actual = [IO.File]::ReadAllText((Join-Path (Join-Path $repoRoot 'docs') 'CONTROLS.md'))
        ($actual -replace "`r`n", "`n") | Should -BeExactly $expected
    }
}
