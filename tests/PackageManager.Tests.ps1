#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'modules/PackageManager.psm1') -Force

    function New-TestCatalog {
        [pscustomobject]@{
            schemaVersion = 1
            categories    = @(
                [pscustomobject]@{ name = 'Core'; modes = @('Lite', 'Sec', 'Full') }
                [pscustomobject]@{ name = 'SecTools'; modes = @('Sec', 'Full') }
                [pscustomobject]@{ name = 'Cloud'; modes = @('Full') }
                [pscustomobject]@{ name = 'Containers'; modes = @() }
            )
            packages      = @(
                [pscustomobject]@{ source = 'winget'; category = 'Core'; name = 'Git'; id = 'Git.Git' }
                [pscustomobject]@{ source = 'pipx'; category = 'SecTools'; name = 'Bandit'; id = 'bandit' }
                [pscustomobject]@{ source = 'vscode'; category = 'Cloud'; name = 'Terraform'; id = 'hashicorp.terraform' }
                [pscustomobject]@{ source = 'manual'; category = 'SecTools'; name = 'Ghidra'; url = 'https://example.invalid/ghidra'; reason = 'Not in winget.' }
                [pscustomobject]@{ source = 'winget'; category = 'Containers'; name = 'Docker Desktop'; id = 'Docker.DockerDesktop' }
            )
        }
    }
    $script:WingetPackage = [pscustomobject]@{ source = 'winget'; category = 'Core'; name = 'Git'; id = 'Git.Git' }
}

Describe 'Test-PackageCatalog' {
    It 'accepts a valid catalog' {
        @(Test-PackageCatalog -Catalog (New-TestCatalog)).Count | Should -Be 0
    }

    It 'rejects ids that could smuggle extra command-line arguments' {
        $catalog = New-TestCatalog
        $catalog.packages[0].id = 'Git.Git --override "/S & calc"'
        @(Test-PackageCatalog -Catalog $catalog) -join "`n" | Should -Match "invalid winget id"
    }

    It 'rejects unknown sources, categories and modes' {
        $catalog = New-TestCatalog
        $catalog.packages[1].source = 'chocolatey'
        $catalog.packages[2].category = 'Nope'
        $catalog.categories[0].modes = @('Ultra')
        $errors = @(Test-PackageCatalog -Catalog $catalog) -join "`n"
        $errors | Should -Match "unknown source 'chocolatey'"
        $errors | Should -Match "unknown category 'Nope'"
        $errors | Should -Match "unknown mode 'Ultra'"
    }

    It 'rejects duplicate ids within a source' {
        $catalog = New-TestCatalog
        $catalog.packages += [pscustomobject]@{ source = 'winget'; category = 'Core'; name = 'Git again'; id = 'git.git' }
        @(Test-PackageCatalog -Catalog $catalog) -join "`n" | Should -Match 'duplicate winget id'
    }

    It 'rejects the same tool offered by winget and pipx' {
        $catalog = New-TestCatalog
        $catalog.packages += [pscustomobject]@{ source = 'pipx'; category = 'Core'; name = 'Git'; id = 'git' }
        @(Test-PackageCatalog -Catalog $catalog) -join "`n" | Should -Match 'both winget and pipx'
    }

    It 'requires manual packages to carry an https url and a reason' {
        $catalog = New-TestCatalog
        $catalog.packages[3].url = 'http://insecure.example'
        $catalog.packages[3].reason = ''
        $errors = @(Test-PackageCatalog -Catalog $catalog) -join "`n"
        $errors | Should -Match 'https url'
        $errors | Should -Match 'need a reason'
    }
}

Describe 'Resolve-CategorySelection' {
    BeforeAll { $catalog = New-TestCatalog }

    It 'maps <Mode> to its categories' -TestCases @(
        @{ Mode = 'Lite'; Expected = @('Core') }
        @{ Mode = 'Sec'; Expected = @('Core', 'SecTools') }
        @{ Mode = 'Full'; Expected = @('Core', 'SecTools', 'Cloud') }
    ) {
        Resolve-CategorySelection -Catalog $catalog -Mode $Mode | Should -Be $Expected
    }

    It 'never selects opt-in categories without -Include' {
        Resolve-CategorySelection -Catalog $catalog -Mode Full | Should -Not -Contain 'Containers'
    }

    It 'adds -Include and removes -Skip' {
        Resolve-CategorySelection -Catalog $catalog -Mode Full -Include Containers -Skip SecTools |
            Should -Be @('Core', 'Cloud', 'Containers')
    }

    It 'returns categories in catalog order regardless of argument order' {
        Resolve-CategorySelection -Catalog $catalog -Only Cloud, Core | Should -Be @('Core', 'Cloud')
    }

    It 'accepts comma-separated strings as passed by powershell -File' {
        Resolve-CategorySelection -Catalog $catalog -Only 'Cloud,Core' | Should -Be @('Core', 'Cloud')
    }

    It 'rejects unknown category names' {
        { Resolve-CategorySelection -Catalog $catalog -Skip Bogus } | Should -Throw "*Unknown category 'Bogus'*"
    }

    It 'rejects -Only combined with <Name>' -TestCases @(
        @{ Name = '-Skip'; Arguments = @{ Skip = @('Core') } }
        @{ Name = '-Include'; Arguments = @{ Include = @('Cloud') } }
        @{ Name = '-Mode'; Arguments = @{ ModeSpecified = $true } }
    ) {
        { Resolve-CategorySelection -Catalog $catalog -Only Core @Arguments } | Should -Throw '*-Only cannot be combined*'
    }

    It 'rejects a category that is both included and skipped' {
        { Resolve-CategorySelection -Catalog $catalog -Include Cloud -Skip Cloud } | Should -Throw '*both -Include and -Skip*'
    }
}

Describe 'Install-WingetPackage' {
    It 'installs a package that winget reports as absent' {
        Mock -ModuleName PackageManager Invoke-Winget {
            if ($ArgumentList[0] -eq 'list') { return [pscustomobject]@{ ExitCode = -1978335212; Output = 'No installed package found' } }
            [pscustomobject]@{ ExitCode = 0; Output = 'Successfully installed' }
        }
        $result = Install-WingetPackage -Package $script:WingetPackage
        $result.Status | Should -Be 'Installed'
        Should -Invoke -ModuleName PackageManager Invoke-Winget -Times 1 -ParameterFilter { $ArgumentList[0] -eq 'install' }
    }

    It 'uses exact id matching against the winget source' {
        Mock -ModuleName PackageManager Invoke-Winget { [pscustomobject]@{ ExitCode = -1978335189; Output = '' } }
        Install-WingetPackage -Package $script:WingetPackage | Out-Null
        Should -Invoke -ModuleName PackageManager Invoke-Winget -ParameterFilter {
            $ArgumentList[0] -eq 'list' -and $ArgumentList -contains '--exact' -and ($ArgumentList -join ' ') -match '--source winget'
        }
    }

    It 'reports Current when no upgrade is applicable' {
        Mock -ModuleName PackageManager Invoke-Winget {
            if ($ArgumentList[0] -eq 'list') { return [pscustomobject]@{ ExitCode = 0; Output = 'Git Git.Git 2.50' } }
            [pscustomobject]@{ ExitCode = -1978335189; Output = 'No applicable update found.' }
        }
        (Install-WingetPackage -Package $script:WingetPackage).Status | Should -Be 'Current'
    }

    It 'reports Upgraded when winget upgrades an installed package' {
        Mock -ModuleName PackageManager Invoke-Winget { [pscustomobject]@{ ExitCode = 0; Output = '' } }
        (Install-WingetPackage -Package $script:WingetPackage).Status | Should -Be 'Upgraded'
    }

    It 'does not call upgrade with -SkipUpgrade' {
        Mock -ModuleName PackageManager Invoke-Winget { [pscustomobject]@{ ExitCode = 0; Output = '' } }
        (Install-WingetPackage -Package $script:WingetPackage -SkipUpgrade).Status | Should -Be 'Current'
        Should -Invoke -ModuleName PackageManager Invoke-Winget -Times 0 -ParameterFilter { $ArgumentList[0] -eq 'upgrade' }
    }

    It 'flags restart-required installs as successful but pending restart' {
        Mock -ModuleName PackageManager Invoke-Winget {
            if ($ArgumentList[0] -eq 'list') { return [pscustomobject]@{ ExitCode = -1978335212; Output = '' } }
            [pscustomobject]@{ ExitCode = -1978334967; Output = '' }
        }
        $result = Install-WingetPackage -Package $script:WingetPackage
        $result.Status | Should -Be 'Installed'
        $result.RestartRequired | Should -BeTrue
    }

    It 'surfaces install failures with the decoded winget code and last output line' {
        Mock -ModuleName PackageManager Invoke-Winget {
            if ($ArgumentList[0] -eq 'list') { return [pscustomobject]@{ ExitCode = -1978335212; Output = '' } }
            [pscustomobject]@{ ExitCode = -1978334961; Output = "  -\\|/`r`nInstaller blocked by policy`r`n" }
        }
        $result = Install-WingetPackage -Package $script:WingetPackage
        $result.Status | Should -Be 'Failed'
        $result.ExitCode | Should -Be -1978334961
        $result.Detail | Should -Match '0x8A15010F'
        $result.Detail | Should -Match 'Installer blocked by policy'
    }

    It 'fails instead of installing when winget list itself errors' {
        Mock -ModuleName PackageManager Invoke-Winget { [pscustomobject]@{ ExitCode = -1978335174; Output = '' } }
        $result = Install-WingetPackage -Package $script:WingetPackage
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -Match 'winget list failed'
        Should -Invoke -ModuleName PackageManager Invoke-Winget -Times 0 -ParameterFilter { $ArgumentList[0] -eq 'install' }
    }

    It 'honours -WhatIf' {
        Mock -ModuleName PackageManager Invoke-Winget {
            if ($ArgumentList[0] -eq 'list') { return [pscustomobject]@{ ExitCode = -1978335212; Output = '' } }
            throw 'install must not run under -WhatIf'
        }
        (Install-WingetPackage -Package $script:WingetPackage -WhatIf).Status | Should -Be 'Skipped'
    }
}

Describe 'Resolve-PythonCommand' {
    It 'ignores the Microsoft Store python alias stub' {
        Mock -ModuleName PackageManager Get-Command { $null } -ParameterFilter { $Name -eq 'py' }
        Mock -ModuleName PackageManager Get-Command {
            [pscustomobject]@{ Source = 'C:\Users\u\AppData\Local\Microsoft\WindowsApps\python.exe' }
        } -ParameterFilter { $Name -eq 'python' }
        Resolve-PythonCommand | Should -BeNullOrEmpty
    }

    It 'prefers the py launcher' {
        Mock -ModuleName PackageManager Get-Command { [pscustomobject]@{ Source = 'C:\Windows\py.exe' } } -ParameterFilter { $Name -eq 'py' }
        $python = Resolve-PythonCommand
        $python | Should -Be @('C:\Windows\py.exe', '-3')
    }

    It 'returns a single-element array for a plain python.exe' {
        Mock -ModuleName PackageManager Get-Command { $null } -ParameterFilter { $Name -eq 'py' }
        Mock -ModuleName PackageManager Get-Command { [pscustomobject]@{ Source = 'C:\Python313\python.exe' } } -ParameterFilter { $Name -eq 'python' }
        $python = Resolve-PythonCommand
        , $python | Should -BeOfType [object[]]
        $python[0] | Should -Be 'C:\Python313\python.exe'
    }
}

Describe 'Invoke-PackageProvisioning' {
    BeforeAll {
        $plan = @((New-TestCatalog).packages | Where-Object { $_.category -ne 'Containers' })
    }

    It 'runs no external command during a dry run' {
        Mock -ModuleName PackageManager Invoke-NativeCommand { throw 'no native commands in dry run' }
        $results = @(Invoke-PackageProvisioning -Plan $plan -DryRun)
        ($results | Where-Object Source -eq 'manual').Status | Should -Be 'Manual'
        @($results | Where-Object Status -eq 'Planned').Count | Should -Be 3
    }

    It 'refreshes PATH after winget and before pipx and VS Code' {
        $script:calls = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName PackageManager Install-WingetPackage { $script:calls.Add('winget'); New-PackageResult $Package Installed }
        Mock -ModuleName PackageManager Resolve-PythonCommand { $script:calls.Add('python'); , @('py', '-3') }
        Mock -ModuleName PackageManager Initialize-Pipx { 'C:\pipx\bin' }
        Mock -ModuleName PackageManager Get-PipxInstalledPackage { @() }
        Mock -ModuleName PackageManager Install-PipxPackage { New-PackageResult $Package Installed }
        Mock -ModuleName PackageManager Resolve-CodeCommand { $script:calls.Add('code'); 'code.cmd' }
        Mock -ModuleName PackageManager Get-VSCodeInstalledExtension { @() }
        Mock -ModuleName PackageManager Install-VSCodeExtension { New-PackageResult $Package Installed }

        Invoke-PackageProvisioning -Plan $plan -OnPathChanged { param($Extra) $script:calls.Add("path:$Extra") } | Out-Null
        $script:calls | Should -Be @('winget', 'path:', 'python', 'path:C:\pipx\bin', 'code')
    }

    It 'fails dependent packages clearly when a prerequisite is missing' {
        Mock -ModuleName PackageManager Install-WingetPackage { New-PackageResult $Package Failed 'boom' }
        Mock -ModuleName PackageManager Resolve-PythonCommand { $null }
        Mock -ModuleName PackageManager Resolve-CodeCommand { $null }
        $results = @(Invoke-PackageProvisioning -Plan $plan)
        ($results | Where-Object Source -eq 'pipx').Detail | Should -Match 'Prerequisite missing: Python 3 was not found'
        ($results | Where-Object Source -eq 'vscode').Detail | Should -Match "Prerequisite missing: The VS Code 'code' CLI"
        @($results | Where-Object Status -eq 'Failed').Count | Should -Be 3
    }
}

Describe 'Install-PipxPackage and Install-VSCodeExtension' {
    It 'does not reinstall an installed VS Code extension (case-insensitive)' {
        Mock -ModuleName PackageManager Invoke-NativeCommand { throw 'should not install' }
        $package = [pscustomobject]@{ source = 'vscode'; category = 'Core'; name = 'PS'; id = 'ms-vscode.PowerShell' }
        (Install-VSCodeExtension -Package $package -CodeCommand 'code' -InstalledExtension @('ms-vscode.powershell')).Status | Should -Be 'Current'
    }

    It 'passes the pipx package name as a separate argument' {
        Mock -ModuleName PackageManager Invoke-NativeCommand { [pscustomobject]@{ ExitCode = 0; Output = '' } }
        $package = [pscustomobject]@{ source = 'pipx'; category = 'SecTools'; name = 'Bandit'; id = 'bandit' }
        (Install-PipxPackage -Package $package -PythonCommand @('py', '-3') -InstalledPackage @()).Status | Should -Be 'Installed'
        Should -Invoke -ModuleName PackageManager Invoke-NativeCommand -ParameterFilter {
            $FilePath -eq 'py' -and ($ArgumentList -join '|') -eq '-3|-m|pipx|install|bandit'
        }
    }
}
