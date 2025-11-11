<#
.SYNOPSIS
  Windows Dev + Security Bootstrap (PS 5.1/7+). Idempotent, parameterized.

.EXAMPLE
  .\bootstrap-dev-sec.ps1 -Mode Full -WithWSL -WithDocker

.PARAMETER Mode
  Lite  : core tools only (fast)
  Full  : everything (languages, RE tools, QoL)
  Sec   : focus on cybersecurity tooling + essentials

.PARAMETER WithWSL
  Enable WSL2 + virtualization features (requires reboot to finalize).

.PARAMETER WithDocker
  Install Docker Desktop (large; optional).

.PARAMETER LogPath
  Where to write a transcript log (default: Desktop\bootstrap.log).
#>

[CmdletBinding()]
param(
  [ValidateSet('Lite','Full','Sec')]
  [string]$Mode = 'Full',
  [switch]$WithWSL,
  [switch]$WithDocker,
  [string]$LogPath = "$env:USERPROFILE\Desktop\bootstrap.log"
)

# --- Guard: Admin check ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
  Write-Host "[!] Please run this script in an ELEVATED (Administrator) PowerShell." -ForegroundColor Yellow
  break
}

# --- Safer execution ---
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force | Out-Null

# --- Logging ---
try {
  if (Test-Path $LogPath) { Remove-Item $LogPath -Force -ErrorAction SilentlyContinue }
  Start-Transcript -Path $LogPath -Append | Out-Null
} catch { Write-Host "[i] Could not start transcript log: $($_.Exception.Message)" -ForegroundColor Yellow }

# --- Stopwatch for final timing ---
$sw = [System.Diagnostics.Stopwatch]::StartNew()

function Info($msg)  { Write-Host "→ $msg" -ForegroundColor Cyan }
function Warn($msg)  { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Good($msg)  { Write-Host "✓ $msg" -ForegroundColor Green }

# --- Winget presence ---
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
  Warn "winget not found. Install 'App Installer' from Microsoft Store, then re-run."
  Stop-Transcript | Out-Null
  break
}

# --- Install helper: idempotent ---
function Install-App {
  param([Parameter(Mandatory=$true)][string]$Id)
  $pkg = winget list --id $Id --accept-source-agreements --disable-interactivity 2>$null
  if ($LASTEXITCODE -eq 0 -and $pkg) {
    Info "Upgrading $Id (if needed)..."
    winget upgrade --id $Id --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Null
  } else {
    Info "Installing $Id..."
    winget install --id $Id --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Null
  }
}

# --- Package sets ---
$Core = @(
  'Microsoft.PowerShell',          # PowerShell 7
  'Microsoft.WindowsTerminal',
  'Git.Git',
  'Microsoft.VisualStudioCode',
  '7zip.7zip',
  'Microsoft.SysinternalsSuite',
  'Sharkdp.Bat',
  'junegunn.FZF',
  'BurntSushi.ripgrep',
  'JanDeDobbeleer.OhMyPosh'
)

$DevLangs = @(
  'Python.Python.3.12',
  'OpenJS.NodeJS.LTS',
  'GoLang.Go',
  'Rustlang.Rustup',
  'EclipseAdoptium.Temurin.17.JDK',
  'Microsoft.DotNet.SDK.8',
  'RubyInstallerTeam.RubyWithDevKit',
  'MSYS2.MSYS2',
  'CMake.CMake'
)

$NetDebug = @(
  'WiresharkFoundation.Wireshark',
  'Nmap.Nmap',
  'Postman.Postman',
  'cURL.cURL'
)

$SecTools = @(
  'PortSwigger.BurpSuite.Community',
  'OWASP.ZAP',
  'mitmproxy.mitmproxy',
  'Progress.Fiddler.Classic',
  'NSA.Ghidra',
  'x64dbg.x64dbg',
  'Hashcat.Hashcat'
  # 'Rizin.Cutter' # optional
)

$QoL = @('Microsoft.PowerToys', 'GitHub.GitHubDesktop')

# --- Mode selection ---
$InstallQueue = @()
switch ($Mode) {
  'Lite' {
    $InstallQueue += $Core + @('Python.Python.3.12') + $NetDebug + @('Nmap.Nmap') + $QoL
  }
  'Sec' {
    $InstallQueue += $Core + $NetDebug + $SecTools + @('Python.Python.3.12') + $QoL
  }
  'Full' {
    $InstallQueue += $Core + $DevLangs + $NetDebug + $SecTools + $QoL
  }
}

if ($WithDocker) { $InstallQueue += 'Docker.DockerDesktop' }

# --- Deduplicate ---
$InstallQueue = $InstallQueue | Sort-Object -Unique

# --- Install packages ---
foreach ($id in $InstallQueue) { Install-App $id }

# --- Optional: Enable WSL2/Virtualization ---
if ($WithWSL) {
  Info "Enabling WSL2 & virtualization features (reboot required to finalize)..."
  dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart | Out-Null
  dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart | Out-Null
  dism.exe /online /enable-feature /featurename:HypervisorPlatform /all /norestart | Out-Null
}

# --- Python + pipx setup ---
function Ensure-PythonAndPipx {
  # Prefer Python launcher
  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  $pythonCmd  = Get-Command python -ErrorAction SilentlyContinue

  if ($pyLauncher) {
    Info "Using Python launcher (py -3.12)..."
    py -3.12 -m pip install --upgrade pip pipx
    py -3.12 -m pipx ensurepath | Out-Null
  } elseif ($pythonCmd) {
    Info "Using python on PATH..."
    python -m pip install --upgrade pip pipx
    python -m pipx ensurepath | Out-Null
  } else {
    Warn "Python not on PATH; installing Python 3.12..."
    Install-App 'Python.Python.3.12'
    if (Get-Command py -ErrorAction SilentlyContinue) {
      py -3.12 -m pip install --upgrade pip pipx
      py -3.12 -m pipx ensurepath | Out-Null
    } else {
      python -m pip install --upgrade pip pipx
      python -m pipx ensurepath | Out-Null
    }
  }

  # Ensure per-user .local\bin is visible now and next sessions
  $UserBin = "$env:USERPROFILE\.local\bin"
  if (!(Test-Path $UserBin)) { New-Item -ItemType Directory -Path $UserBin | Out-Null }
  if ($env:Path -notlike "*$UserBin*") { $env:Path = "$env:Path;$UserBin" }
  [Environment]::SetEnvironmentVariable("Path",
    [System.Environment]::GetEnvironmentVariable("Path","User") + ";$UserBin", "User")

  # Windows Store alias can hijack 'python'—recommend turning it off
  Warn "If 'python' opens Microsoft Store, disable the 'python.exe' alias in Settings → Apps → Advanced app settings → App execution aliases."
}

# --- Pipx toolsets (install via isolated venvs) ---
function Install-PipxTools {
  param([string[]]$Tools)
  foreach ($t in $Tools) {
    Info "pipx install $t"
    cmd /c "pipx install $t" | Out-Null
  }
}

# Always ensure pipx if Python was installed
Ensure-PythonAndPipx

# Pipx: base dev + security set depending on mode
$PipxBase = @('poetry','httpie')
$PipxSec  = @('bandit','mitmproxy','sqlmap','yara-python','volatility3')

switch ($Mode) {
  'Lite' { Install-PipxTools -Tools ($PipxBase + 'bandit') }
  'Sec'  { Install-PipxTools -Tools ($PipxBase + $PipxSec) }
  'Full' { Install-PipxTools -Tools ($PipxBase + $PipxSec) }
}

# Optional extra malware-analysis pack (comment in if you want by default)
# Install-PipxTools -Tools @('capa','floss','oletools','lief','speakeasy-emulator')

# --- VS Code extensions ---
function Install-CodeExtensions {
  $codeCmd = Get-Command code -ErrorAction SilentlyContinue
  if (-not $codeCmd) { Warn "VS Code 'code' CLI not found on PATH; skipping extensions."; return }

  $ext = @(
    'ms-python.python','ms-python.vscode-pylance','ms-vscode.powershell','ms-vscode.cpptools',
    'golang.go','rust-lang.rust-analyzer','redhat.java','ms-azuretools.vscode-docker',
    'GitHub.vscode-pull-request-github','ms-vscode.vscode-node-azure-pack',
    'Gruntfuggly.todo-tree','oderwat.indent-rainbow','eamodio.gitlens',
    'kevinrose.vsc-python-indent','sonarsource.sonarlint-vscode',
    'tamasfe.even-better-toml','VisualStudioExptTeam.vscodeintellicode'
  )
  foreach ($e in $ext) {
    Info "VS Code ext: $e"
    code --install-extension $e --force | Out-Null
  }
}
Install-CodeExtensions

# --- PowerShell profile (nicer prompt, history, aliases) ---
function Setup-PowerShellProfile {
  if ($PSVersionTable.PSEdition -eq 'Core') {
    $profilePath = $PROFILE
  } else {
    $profilePath = "$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
  }
  New-Item -ItemType Directory -Force (Split-Path $profilePath) | Out-Null
  if (-not (Test-Path $profilePath)) { New-Item $profilePath -ItemType File | Out-Null }

  @'
# ===== Developer-friendly PowerShell =====
try { Import-Module PSReadLine } catch {}
Set-PSReadLineOption -PredictionSource History -PredictionViewStyle ListView
Set-PSReadLineOption -EditMode Windows

# Prompt
oh-my-posh init pwsh --config "$(oh-my-posh print-shell -c)" | Invoke-Expression

# Aliases
Set-Alias ll Get-ChildItem
Set-Alias cat bat
Set-Alias grep rg
'@ | Out-File -FilePath $profilePath -Encoding utf8
  Good "PowerShell profile updated: $profilePath"
}
Setup-PowerShellProfile

# --- Final notes & timing ---
$sw.Stop()
Good "Bootstrap complete in $($sw.Elapsed.ToString())."
if ($WithWSL) {
  Warn "WSL/Virtualization changes require a REBOOT to finalize. After reboot, run:"
  Write-Host "   wsl --install -d Ubuntu"
  Write-Host "   wsl --install -d kali-linux"
}

try { Stop-Transcript | Out-Null } catch {}
Good "Log saved to: $LogPath"
