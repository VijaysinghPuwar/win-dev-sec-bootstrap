#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'modules/Environment.psm1') -Force
}

Describe 'Merge-PathEntry' {
    It 'removes duplicates case-insensitively and ignores trailing backslashes' {
        Merge-PathEntry -Entry @('C:\Tools;C:\Windows\System32', 'c:\tools\;C:\Git\cmd') |
            Should -Be @('C:\Tools', 'C:\Windows\System32', 'C:\Git\cmd')
    }

    It 'drops empty entries and surrounding quotes' {
        Merge-PathEntry -Entry @(';;"C:\Program Files\App";', $null, '') | Should -Be @('C:\Program Files\App')
    }

    It 'keeps a drive root distinct from its trimmed form' {
        Merge-PathEntry -Entry @('C:\', 'C:\Tools') | Should -Be @('C:\', 'C:\Tools')
    }
}

Describe 'Update-SessionPath' {
    BeforeEach { $script:savedPath = $env:Path }
    AfterEach { $env:Path = $script:savedPath }

    It 'puts Machine then User entries first and keeps session-only entries' {
        Mock -ModuleName Environment Get-PersistentPath { 'C:\Windows;C:\NewTool' } -ParameterFilter { $Scope -eq 'Machine' }
        Mock -ModuleName Environment Get-PersistentPath { 'C:\Users\u\.local\bin' } -ParameterFilter { $Scope -eq 'User' }
        $env:Path = 'C:\Windows;C:\venv\Scripts'
        Update-SessionPath
        $env:Path | Should -Be 'C:\Windows;C:\NewTool;C:\Users\u\.local\bin;C:\venv\Scripts'
    }

    It 'is idempotent' {
        Mock -ModuleName Environment Get-PersistentPath { 'C:\A;C:\B' } -ParameterFilter { $Scope -eq 'Machine' }
        Mock -ModuleName Environment Get-PersistentPath { 'C:\C' } -ParameterFilter { $Scope -eq 'User' }
        $env:Path = 'C:\A'
        Update-SessionPath
        $first = $env:Path
        Update-SessionPath
        Add-SessionPathEntry -Path 'C:\C\'
        $env:Path | Should -Be $first
    }
}

Describe 'Merge-ManagedBlock' {
    BeforeAll {
        $block = Get-ManagedProfileBlock
        $newBlock = $block -replace 'Set-Alias -Name ll', 'Set-Alias -Name lla'
    }

    It 'creates the block in an empty profile' {
        $result = Merge-ManagedBlock -Content '' -Block $block
        $result | Should -Match '^# BEGIN win-dev-sec-bootstrap'
        $result | Should -Match '# END win-dev-sec-bootstrap\r\n$'
    }

    It 'appends after existing user content without modifying it' {
        $userContent = "Set-Location C:\work`r`n`$env:EDITOR = 'code'`r`n"
        $result = Merge-ManagedBlock -Content $userContent -Block $block
        $result.StartsWith($userContent) | Should -BeTrue
    }

    It 'replaces only the managed block and preserves content on both sides' {
        $before = "# user top`r`n"
        $after = "`r`n# user bottom`r`n"
        $existing = $before + $block + $after
        $result = Merge-ManagedBlock -Content $existing -Block $newBlock
        $result | Should -Be ($before + $newBlock + $after)
    }

    It 'never produces a second block when run repeatedly' {
        $once = Merge-ManagedBlock -Content "# mine`n" -Block $block
        $twice = Merge-ManagedBlock -Content $once -Block $block
        $twice | Should -BeExactly $once
        ([regex]::Matches($twice, '# BEGIN win-dev-sec-bootstrap')).Count | Should -Be 1
    }

    It 'keeps LF line endings in LF profiles' {
        $result = Merge-ManagedBlock -Content "# mine`n" -Block $block
        $result | Should -Not -Match "`r"
    }

    It 'refuses to edit a profile with <Case>' -TestCases @(
        @{ Case = 'a BEGIN marker without END'; Content = "# BEGIN win-dev-sec-bootstrap`r`nfoo`r`n" }
        @{ Case = 'duplicate blocks'; Content = "# BEGIN win-dev-sec-bootstrap`n# END win-dev-sec-bootstrap`n# BEGIN win-dev-sec-bootstrap`n# END win-dev-sec-bootstrap`n" }
        @{ Case = 'END before BEGIN'; Content = "# END win-dev-sec-bootstrap`n# BEGIN win-dev-sec-bootstrap`n" }
    ) {
        { Merge-ManagedBlock -Content $Content -Block $block } | Should -Throw '*unbalanced or duplicate*'
    }
}

Describe 'Get-ManagedProfileBlock' {
    BeforeAll { $block = Get-ManagedProfileBlock }

    It 'does not override built-in aliases such as cat or ls' {
        $block | Should -Not -Match 'Set-Alias\s+(-Name\s+)?(cat|ls)\b'
    }

    It 'guards every external tool with Get-Command' {
        foreach ($tool in @('oh-my-posh', 'rg')) {
            $block | Should -Match ("Get-Command $tool -CommandType Application")
        }
    }

    It 'only enables list prediction on PSReadLine 2.2 or newer' {
        $block | Should -Match "Version -ge \[version\]'2.2.0'"
    }

    It 'is valid PowerShell' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseInput($block, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }
}

Describe 'Set-ManagedProfile' {
    BeforeEach { $profilePath = Join-Path $TestDrive ('profile-{0}.ps1' -f [guid]::NewGuid()) }

    It 'creates a missing profile without a backup' {
        $result = Set-ManagedProfile -Path $profilePath
        $result.Status | Should -Be 'Created'
        $result.Backup | Should -BeNullOrEmpty
        Get-Content -LiteralPath $profilePath -Raw | Should -Match 'BEGIN win-dev-sec-bootstrap'
    }

    It 'backs up an existing profile before changing it and keeps user content' {
        Set-Content -LiteralPath $profilePath -Value 'Write-Output "mine"'
        $result = Set-ManagedProfile -Path $profilePath
        $result.Status | Should -Be 'Updated'
        Test-Path -LiteralPath $result.Backup | Should -BeTrue
        (Get-Content -LiteralPath $result.Backup -Raw).Trim() | Should -Be 'Write-Output "mine"'
        Get-Content -LiteralPath $profilePath -Raw | Should -Match 'Write-Output "mine"'
    }

    It 'does not rewrite or back up an up-to-date profile' {
        Set-ManagedProfile -Path $profilePath | Out-Null
        $stamp = (Get-Item -LiteralPath $profilePath).LastWriteTimeUtc
        $result = Set-ManagedProfile -Path $profilePath
        $result.Status | Should -Be 'Current'
        (Get-Item -LiteralPath $profilePath).LastWriteTimeUtc | Should -Be $stamp
        @(Get-ChildItem -Path $TestDrive -Filter '*.bak-*' | Where-Object Name -like "$(Split-Path $profilePath -Leaf)*").Count | Should -Be 0
    }

    It 'reports Failed and leaves a malformed profile untouched' {
        $content = "# BEGIN win-dev-sec-bootstrap`r`nkeep me`r`n"
        [IO.File]::WriteAllText($profilePath, $content)
        (Set-ManagedProfile -Path $profilePath).Status | Should -Be 'Failed'
        [IO.File]::ReadAllText($profilePath) | Should -BeExactly $content
    }

    It 'makes no change under -WhatIf' {
        (Set-ManagedProfile -Path $profilePath -WhatIf).Status | Should -Be 'Skipped'
        Test-Path -LiteralPath $profilePath | Should -BeFalse
    }
}
