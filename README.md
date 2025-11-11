# win-dev-sec-bootstrap

Idempotent **PowerShell 5.1/7+** script to set up a fresh Windows machine for **software engineering + cybersecurity**.
Installs core shells, editors, languages (Python, Node, Go, Rust, .NET, Java), and tools (Wireshark, Nmap, Sysinternals, Burp, ZAP, Ghidra, x64dbg, Hashcat, etc.).
Optional **WSL2** and **Docker Desktop**, plus **pipx** security tooling and a friendly PowerShell profile.

> ✅ Safe to re-run (idempotent) • ⚡ Works on Windows 10/11 • 🛠️ Supports **Lite**, **Sec**, and **Full** modes

---

## Quick Start

1. **Clone or download** this repo.
2. Open **PowerShell as Administrator**.
3. Run one of the presets:

```powershell
# Full stack + WSL + Docker (most complete)
Set-ExecutionPolicy Bypass -Scope Process -Force; .\bootstrap-dev-sec.ps1 -Mode Full -WithWSL -WithDocker

# Security-focused tooling (faster) + WSL
Set-ExecutionPolicy Bypass -Scope Process -Force; .\bootstrap-dev-sec.ps1 -Mode Sec -WithWSL

# Core dev-only (quickest)
Set-ExecutionPolicy Bypass -Scope Process -Force; .\bootstrap-dev-sec.ps1 -Mode Lite
```

### Run directly from GitHub (optional)

Replace `<OWNER>` with your GitHub username and run **as Administrator**:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr https://raw.githubusercontent.com/<OWNER>/win-dev-sec-bootstrap/main/bootstrap-dev-sec.ps1 -UseBasicParsing -OutFile bootstrap-dev-sec.ps1
.\bootstrap-dev-sec.ps1 -Mode Full -WithWSL -WithDocker
```

---

## What Gets Installed

### Core

* PowerShell 7, Windows Terminal, Git, VS Code, Sysinternals, 7zip
* QoL CLI: `bat`, `fzf`, `ripgrep`, `oh-my-posh`

### Languages & SDKs (Full mode)

* Python 3.12, Node.js LTS, Go, Rust (rustup), Java 17 (Temurin), .NET 8, Ruby+DevKit, MSYS2, CMake

### Networking & Debug

* Wireshark, Nmap, Postman, curl

### AppSec / RE

* Burp Suite Community, OWASP ZAP, mitmproxy, Fiddler Classic
* Ghidra, x64dbg, Hashcat
* *(optional in script: Cutter/Rizin)*

### pipx Security Tooling

* `poetry`, `httpie`, `bandit`, `mitmproxy`, `sqlmap`, `yara-python`, `volatility3`
* *(commented pack available: `capa`, `floss`, `oletools`, `lief`, `speakeasy-emulator`)*

### Optional Platforms

* **WSL2** (Ubuntu/Kali ready after reboot)
* **Docker Desktop**

---

## Modes

| Mode   | Purpose                     | Includes                                                |
| ------ | --------------------------- | ------------------------------------------------------- |
| `Lite` | Fast bootstrap for dev only | Core + Python + basic Net/Debug + QoL                   |
| `Sec`  | Security tooling focus      | Core + Net/Debug + AppSec/RE + Python + pipx sec tools  |
| `Full` | Everything                  | Core + All Languages/SDKs + Net/Debug + AppSec/RE + QoL |

**Flags**

* `-WithWSL` → Enables WSL2 & virtualization features (requires reboot)
* `-WithDocker` → Installs Docker Desktop
* `-LogPath` → Transcript path (default: `Desktop\bootstrap.log`)

---

## After Running

If you included `-WithWSL`, **reboot** first, then:

```powershell
wsl --install -d Ubuntu
# optional
wsl --install -d kali-linux
```

**Python alias tip:** If running `python` opens the Microsoft Store, disable the Store alias:
**Settings → Apps → Advanced app settings → App execution aliases → Turn off** `python.exe` and `python3.exe`.

---

## Verify

Useful checks (run in a new PowerShell window):

```powershell
# Core tools
pwsh -v; winget --version; code -v; git --version

# Languages
python --version; py -V
node -v; npm -v
go version
rustc --version; cargo --version
java -version
dotnet --list-sdks

# Net & Sec
nmap --version
wireshark -v
zap.sh -version  # from ZAP install folder or start menu
hashcat --version

# pipx tooling
pipx --version
pipx list
```

---

## Troubleshooting

* **“`python` opens the Store”**
  Turn off the **App execution alias** for Python (see tip above). Reopen PowerShell.

* **`pipx` not found**
  Open a **new PowerShell** (PATH refresh) or add manually:

  ```powershell
  $UserBin = "$env:USERPROFILE\.local\bin"
  if ($env:Path -notlike "*$UserBin*") { [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path","User") + ";$UserBin", "User") }
  ```

* **Docker/WSL errors**
  Ensure virtualization is enabled in BIOS/UEFI (Intel VT-x/AMD-V). Re-run with `-WithWSL` and reboot.

* **Winget source update slow**
  First run on a fresh Windows install may take longer; reruns will be faster.

* **VirtualBox users**
  If you rely on VirtualBox, consider omitting `-WithWSL` and `-WithDocker` (Hyper-V can conflict).

---

## Logging

The script writes a transcript log (default: `Desktop\bootstrap.log`).
Change with `-LogPath`:

```powershell
.\bootstrap-dev-sec.ps1 -Mode Sec -WithWSL -LogPath C:\Temp\bootstrap.log
```

---

## Structure

```
.
├── bootstrap-dev-sec.ps1   # main script
├── README.md               # this file
├── .gitignore
└── LICENSE                 # MIT
```

---

## Security Notes

* Use a **throwaway VM** for malware analysis; keep host protections on.
* For dynamic analysis, avoid bridged networking; prefer **Host-Only** + **FakeNet-NG/INetSim**.
* Move samples via **password-protected zips** (`infected`) and verify SHA-256.

---

## License

MIT — see `LICENSE`.

---

## Contributing

PRs welcome for:

* Additional modes (e.g., Cloud CLIs pack: AWS/Azure/GCP)
* Optional **malware-analysis
