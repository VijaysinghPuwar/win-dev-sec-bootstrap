#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Runs the real entry script in a child process to check argument handling
# and exit codes. Only paths that cannot change the system are exercised:
# dry runs and invalid arguments. Logs go to TestDrive.

BeforeAll {
    $script = Join-Path (Split-Path -Parent $PSScriptRoot) 'bootstrap-dev-sec.ps1'
    $engine = (Get-Process -Id $PID).Path

    function Invoke-Bootstrap([string[]]$Arguments) {
        $log = Join-Path $TestDrive ("cli-{0}.log" -f [guid]::NewGuid())
        $output = & $engine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script @Arguments -LogPath $log 2>&1 | Out-String
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
}

Describe 'bootstrap-dev-sec.ps1 command line' {
    It 'prints the plan for a dry run and exits 0 without Administrator rights' {
        $run = Invoke-Bootstrap @('-Mode', 'Sec', '-DryRun', '-SkipProfile')
        $run.ExitCode | Should -Be 0
        $run.Output | Should -Match 'Categories: Core, NetDebug, SecTools, QoL'
        $run.Output | Should -Match 'Planned \(\d+\)'
        $run.Output | Should -Match 'ZAP\.ZAP'
        $run.Output | Should -Match 'Manual \(\d+\).*'
    }

    It 'applies -Skip to the mode' {
        $run = Invoke-Bootstrap @('-Mode', 'Full', '-Skip', 'SecTools,Cloud', '-DryRun', '-SkipProfile')
        $run.ExitCode | Should -Be 0
        $run.Output | Should -Match 'Categories: Core, DevLangs, NetDebug, QoL\s'
        $run.Output | Should -Not -Match 'Burp'
    }

    It 'adds Docker with -WithDocker' {
        (Invoke-Bootstrap @('-Mode', 'Lite', '-WithDocker', '-DryRun', '-SkipProfile')).Output | Should -Match 'Docker\.DockerDesktop'
    }

    It 'exits 1 for an unknown category' {
        $run = Invoke-Bootstrap @('-Only', 'Bogus', '-DryRun')
        $run.ExitCode | Should -Be 1
        $run.Output | Should -Match "Unknown category 'Bogus'"
    }

    It 'exits 1 when -Only is combined with -Skip' {
        (Invoke-Bootstrap @('-Only', 'Core', '-Skip', 'QoL', '-DryRun')).ExitCode | Should -Be 1
    }

    It 'exits non-zero when parameters from different modes are mixed' {
        (Invoke-Bootstrap @('-Assess', '-Mode', 'Lite')).ExitCode | Should -Not -Be 0
    }

    It 'rejects an invalid -Mode value' {
        (Invoke-Bootstrap @('-Mode', 'Everything', '-DryRun')).ExitCode | Should -Not -Be 0
    }
}
