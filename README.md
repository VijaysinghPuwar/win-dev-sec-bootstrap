# win-dev-sec-bootstrap

[![CI](https://github.com/VijaysinghPuwar/win-dev-sec-bootstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/VijaysinghPuwar/win-dev-sec-bootstrap/actions/workflows/ci.yml)
[![Secret scan](https://github.com/VijaysinghPuwar/win-dev-sec-bootstrap/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/VijaysinghPuwar/win-dev-sec-bootstrap/actions/workflows/secret-scan.yml)
![PowerShell 5.1 | 7](https://img.shields.io/badge/PowerShell-5.1%20%7C%207-5391FE)
![Windows 10 | 11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

PowerShell tooling that sets up a Windows 10/11 workstation for development and security work, then checks how well that workstation is protected. It runs a read-only assessment of 27 Windows security controls, writes JSON and HTML evidence reports, and can fix a subset of findings with per-change confirmation, backups and rollback.

```powershell
.\bootstrap-dev-sec.ps1 -Mode Sec -DryRun     # preview what would be installed
.\bootstrap-dev-sec.ps1 -Mode Sec             # install it (elevated)
.\bootstrap-dev-sec.ps1 -Assess               # read-only security assessment + reports
.\bootstrap-dev-sec.ps1 -Remediate -WhatIf    # preview fixes without changing anything
```

## Why this project exists

Setting up a new Windows machine for security work by hand takes an afternoon and never comes out the same twice. It also says nothing about whether the machine is well protected: Defender features left off, SMBv1 still enabled, no PowerShell logging, a Defender exclusion someone added for a build that was never removed.

This project handles both halves. Provisioning is driven by a validated package catalog and is safe to re-run. The assessment reads the live security configuration and reports each control with its expected state, detected state, evidence and the guidance it relates to. Remediation is a separate, explicit step.

## Key capabilities

- **Idempotent provisioning** through winget, pipx and the VS Code CLI, driven by `config/packages.json`. Packages are detected by exact id, winget exit codes are decoded, and every package ends up Installed, Upgraded, Current, Manual or Failed.
- **Clean first-run behaviour**: the session PATH is rebuilt after installs, so pipx tools and VS Code extensions install in the same run as Python and VS Code.
- **Category selection** with `-Mode`, `-Only`, `-Include` and `-Skip`, plus `-DryRun` (or `-WhatIf`) to print the plan without touching the system.
- **Managed PowerShell profile**: changes are confined to a marked block, the previous profile is backed up, and every integration checks that its tool exists.
- **Read-only security assessment** of Microsoft Defender, Windows Firewall, SMB, LLMNR, PowerShell logging, BitLocker, UAC, LSA protection, Secure Boot, the Guest account and RDP.
- **PASS / WARN / FAIL / NOT_APPLICABLE / ERROR** results. Missing features and unreadable settings are reported as such rather than counted as passing.
- **Structured reports**: machine-readable JSON and a self-contained offline HTML page, with the user profile path redacted from evidence.
- **Opt-in remediation** for 13 controls using native `SupportsShouldProcess` (`-WhatIf`, `-Confirm`), with the previous value backed up before each change and verified afterwards.
- **Rollback** of recorded changes, with validation of every value read from the backup file.
- **Tests and CI**: 210 Pester tests, PSScriptAnalyzer, and GitHub Actions on Windows running both PowerShell 7 and Windows PowerShell 5.1.

## Quick start

Requirements: Windows 10 or 11, winget (App Installer), and an elevated PowerShell session for provisioning, remediation and rollback. `-DryRun` works without elevation and on any OS that has PowerShell.

```powershell
git clone https://github.com/VijaysinghPuwar/win-dev-sec-bootstrap.git
cd win-dev-sec-bootstrap

# The scripts are not code-signed. Allow them for this PowerShell session only.
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\bootstrap-dev-sec.ps1 -Mode Full -DryRun
```

If you downloaded a zip instead of cloning, run `Get-ChildItem -Recurse | Unblock-File` in the folder first. Read the scripts before running them as Administrator.

## Usage

### Provisioning

```powershell
.\bootstrap-dev-sec.ps1 -Mode Lite                       # Core, NetDebug, QoL
.\bootstrap-dev-sec.ps1 -Mode Sec                        # adds SecTools
.\bootstrap-dev-sec.ps1 -Mode Full                       # adds DevLangs and Cloud (default)
.\bootstrap-dev-sec.ps1 -Mode Full -DryRun               # print the plan only
.\bootstrap-dev-sec.ps1 -Mode Full -Skip SecTools        # remove categories
.\bootstrap-dev-sec.ps1 -Mode Sec -Include MalwareAnalysis
.\bootstrap-dev-sec.ps1 -Only Core,Cloud                 # exactly these categories
.\bootstrap-dev-sec.ps1 -Mode Sec -WithWSL -WithDocker   # WSL2 features + Docker Desktop
.\bootstrap-dev-sec.ps1 -Mode Sec -SkipUpgrade -SkipProfile
```

`-Only` cannot be combined with `-Mode`, `-Include` or `-Skip`, and unknown category names are rejected. Both are errors (exit code 1), not warnings.

### Security assessment and remediation

```powershell
.\bootstrap-dev-sec.ps1 -Assess                                  # read-only, writes reports\
.\bootstrap-dev-sec.ps1 -Assess -ReportDirectory C:\Evidence
.\bootstrap-dev-sec.ps1 -Remediate -WhatIf                       # show what would change
.\bootstrap-dev-sec.ps1 -Remediate                               # prompts before each change
.\bootstrap-dev-sec.ps1 -Remediate -ControlId WIN-PS-001,WIN-NET-001
.\bootstrap-dev-sec.ps1 -Remediate -Confirm:$false               # unattended
.\bootstrap-dev-sec.ps1 -Rollback                                # newest backup in backup\
.\bootstrap-dev-sec.ps1 -Rollback -BackupFile .\backup\security-backup-20260115-100000.json -WhatIf
```

Full parameter help: `Get-Help .\bootstrap-dev-sec.ps1 -Full`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed. For `-Assess` this means the assessment ran, whatever the findings. |
| 1 | Fatal: invalid arguments or configuration, not Windows, not elevated, winget missing. |
| 2 | Completed with failures: a package, remediation or rollback step failed. |

## Provisioning categories

| Category | Default in | Contents |
|---|---|---|
| Core | Lite, Sec, Full | PowerShell 7, Windows Terminal, Git, VS Code, 7-Zip, Sysinternals, Python 3.13, bat, fzf, ripgrep, Oh My Posh |
| DevLangs | Full | Node.js LTS, Go, Rustup, Temurin JDK 21, .NET SDK 10, Ruby, MSYS2, CMake, Poetry |
| NetDebug | Lite, Sec, Full | Wireshark, Postman, curl, HTTPie |
| SecTools | Sec, Full | Burp Suite Community, ZAP, mitmproxy, Fiddler Classic, x64dbg, Bandit, sqlmap, Volatility 3 |
| Cloud | Full | AWS CLI, Azure CLI, Terraform CLI, kubectl |
| QoL | Lite, Sec, Full | PowerToys, GitHub Desktop, editor extensions |
| Containers | opt-in | Docker Desktop (`-WithDocker` or `-Include Containers`) |
| MalwareAnalysis | opt-in | capa, FLOSS, oletools via pipx (`-Include MalwareAnalysis`) |

Each category also installs the VS Code extensions that go with it. Nmap, Npcap, Ghidra and Hashcat are listed as **manual** installs with download links, because they are either missing from the winget community repository or, in Nmap's case, stuck at a 2019 release there. The full catalog, with every id, is in [`config/packages.json`](config/packages.json).

## Security assessment

The assessment only reads configuration. It runs one probe per data source, and every probe records whether it succeeded, so a missing feature or a non-elevated session affects only the controls that depend on it.

| Area | Controls |
|---|---|
| Microsoft Defender | Real-time protection, behavior monitoring, cloud protection, PUA blocking, network protection, signature age, tamper protection, high-risk exclusions, ASR rules, controlled folder access |
| Windows Firewall | Domain, Private and Public profiles enabled with inbound blocked by default (effective policy, including GPO) |
| Network protocols | SMBv1 server setting, SMBv1 feature, SMB signing, LLMNR |
| PowerShell | Script block logging, module logging, transcription, PowerShell 2.0 engine removed |
| Data protection | BitLocker on the OS drive |
| System and accounts | UAC, LSA protection (RunAsPPL), Secure Boot, Guest account, RDP Network Level Authentication |

Every control is listed with its rationale, remediation guidance and references in [docs/CONTROLS.md](docs/CONTROLS.md), which is generated from [`config/controls.json`](config/controls.json).

**Result model.** Each finding records the control id, category, severity, status, expected state, detected state, an explanation, evidence where relevant, whether automated remediation exists, and references. The statuses mean:

- `PASS`: meets the expected state.
- `WARN`: partially meets it (for example audit mode), or the control is a context-dependent recommendation.
- `FAIL`: does not meet the expected state.
- `NOT_APPLICABLE`: the feature is not present, for example the BitLocker module on Windows Home, Secure Boot on legacy BIOS, or Defender controls when another antivirus is primary.
- `ERROR`: the state could not be read, usually because the session is not elevated.

There is no overall score. The summary gives counts per status and FAIL counts per severity.

**Framework references.** Controls cite NIST SP 800-53 Rev. 5 controls, MITRE ATT&CK techniques or mitigations, and Microsoft Learn pages only where the relationship was checked against the source. ATT&CK ids were checked against attack.mitre.org (including the renumbering of *Disable or Modify Tools* to T1685). CIS Benchmark item numbers are not included because they change between benchmark versions and could not be verified against a licensed copy. The references point to related guidance. They are not a compliance claim.

### Remediation and rollback

The sequence is **assess, confirm, back up, apply, verify, record**, and `-Rollback` reverses it.

- Only controls whose setting applies immediately and can be read back are automated: Defender preferences and signature update, firewall profiles, the SMBv1 server setting, the LLMNR and script block logging policy values, and the Guest account.
- Each change goes through `ShouldProcess` with `ConfirmImpact = High`, so PowerShell asks before every change unless you pass `-Confirm:$false`. `-WhatIf` lists the changes and writes nothing.
- The previous value is written to `backup\security-backup-<timestamp>.json` **before** the change. The backup folder is created with an ACL limited to Administrators and SYSTEM.
- After the change the value is read back. Firewall checks read the effective policy, so a Group Policy or MDM setting that overrides the local change shows up as a failed remediation rather than a false success. The same happens when Defender tamper protection blocks a change.
- Rollback restores entries newest-first. It refuses a backup made on a different computer, unknown control ids, and values that the setting could not have had.
- A signature update is not rolled back. Settings that need a restart (optional features, UAC, LSA protection), could cost data (BitLocker), or often break developer tools (ASR rules, controlled folder access, exclusions) are never changed automatically. The report gives manual guidance for them.

## Reports

`-Assess` writes `reports\security-assessment-<timestamp>.json` and `.html`, and `-Remediate` writes a post-remediation pair that includes the actions taken. A sample generated from a **synthetic fixture** (not a real machine) is in [docs/examples](docs/examples):

```text
[x] FAIL  WIN-DEF-008 High   No high-risk Microsoft Defender exclusions (1 high-risk of 2 exclusion(s))
[x] FAIL  WIN-DEF-005 Medium Microsoft Defender network protection is in block mode (Disabled)
[x] FAIL  WIN-NET-001 Medium LLMNR multicast name resolution is disabled (Not configured (LLMNR on))
[x] FAIL  WIN-PS-001  Medium PowerShell script block logging is on (Not configured)
[!] WARN  WIN-DEF-009 Medium Attack surface reduction rules are configured (No rules configured)
[!] WARN  WIN-SMB-003 Medium SMB server requires signing (Not required)
...
[+] PASS  WIN-FW-003  High   Windows Firewall Public profile is on and blocks unsolicited inbound traffic
[+] PASS  WIN-SMB-001 High   SMBv1 server protocol is disabled
    N/A   WIN-BL-001  High   BitLocker protects the operating system drive (Unavailable)
[*] PASS 15  WARN 7  FAIL 4  N/A 1  ERROR 0  (FAIL by severity: High 1, Medium 3, Low 0)
```

```json
{
  "id": "WIN-PS-001",
  "severity": "Medium",
  "status": "FAIL",
  "expected": "Policy EnableScriptBlockLogging = 1",
  "detected": "Not configured",
  "remediationType": "Automated",
  "references": { "nist80053": ["AU-2", "AU-12"], "attack": ["T1059.001"] }
}
```

**Privacy.** Reports include the computer name, OS version and PowerShell version. They do not include user names, IP or MAC addresses, or hardware serials. The current user's profile path is replaced with `%USERPROFILE%` in evidence. The HTML report makes no network requests, contains no scripts, sets a restrictive Content Security Policy, and HTML-encodes all values. `reports\`, `backup\` and `logs\` are git-ignored.

## Architecture

```text
win-dev-sec-bootstrap/
├── bootstrap-dev-sec.ps1          Entry point: parameter sets, admin checks, exit codes
├── config/
│   ├── packages.json              Package catalog (categories, sources, ids)
│   └── controls.json              Security control definitions and references
├── modules/
│   ├── Common.psm1                Console output, platform checks, JSON I/O, redaction
│   ├── PackageManager.psm1        Catalog validation, category resolution, winget/pipx/VS Code
│   ├── Environment.psm1           Session PATH refresh, managed profile block, WSL features
│   ├── SecurityAssessment.psm1    Read-only probes and control evaluators
│   ├── Remediation.psm1           Remediation handlers, backup, verification, rollback
│   └── Reporting.psm1             Console summaries, JSON and HTML reports
├── tests/                         Pester suites and synthetic snapshot fixtures
├── tools/                         Lint and test runners, doc and sample generators
├── docs/                          Control reference, sample reports, resume notes
└── .github/workflows/             CI (Windows, PS 7 and 5.1) and secret scanning
```

Configuration holds data and code holds behaviour. `packages.json` is validated before use: ids must match a strict pattern (which also stops them from carrying extra command-line arguments), and duplicates across winget and pipx are rejected. `controls.json` holds control metadata only. Registry paths and commands are fixed in code, and a test fails if any control lacks an evaluator or if the Automated/Manual flag disagrees with the implemented remediation handlers.

The assessment is split into **probes**, which read system state into a snapshot, and **evaluators**, which are pure functions of that snapshot. That split is what makes every control testable on any machine with synthetic fixtures.

## Security model

- **Assessment is read-only** and is the default security action. Remediation needs `-Remediate` and a confirmation for every change.
- **Administrator rights** are required for provisioning, remediation and rollback. `-Assess` runs without elevation, but controls that need it (Defender exclusions, BitLocker, optional features) report `ERROR`.
- **Native commands** receive argument arrays. The script never builds command strings or uses `cmd /c`.
- **winget** is called with `--accept-package-agreements` and `--accept-source-agreements`, so running provisioning accepts the licenses of the packages you selected. Run `-DryRun` first to see what they are.
- **The profile block** runs `oh-my-posh init` output at shell start, as the Oh My Posh documentation describes, and only if `oh-my-posh` is on PATH.
- **Transcripts** in `logs\` record console output, which includes local paths.
- **Unsupported scenarios**: machines where Defender is not the primary antivirus (Defender controls report NOT_APPLICABLE), Windows Server (not tested), and domain-joined machines where GPO manages these settings (remediation reports the override as a failure).

## Testing

```powershell
Install-Module Pester -RequiredVersion 5.9.1 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser

.\tools\Invoke-Tests.ps1     # Pester, exits non-zero on failure
.\tools\Invoke-Lint.ps1      # PSScriptAnalyzer, fails on Error/Warning findings
```

The suite covers catalog validation, mode and category resolution, winget exit-code handling, the order of the PATH refresh, managed profile edits (append, replace, idempotency, malformed markers, backups), every evaluator branch, unsupported and unreadable state, exclusion risk classification, report encoding and privacy, remediation ordering (backup before change), verification failures, rollback round trips, tampered backups, and CLI exit codes. Windows-only operations are mocked. The tests do not install software or change security settings.

`tools\New-ControlDoc.ps1` regenerates `docs/CONTROLS.md`, and a test fails if the committed file is stale. `tools\New-SampleReport.ps1` regenerates the sample reports.

## CI/CD

[`ci.yml`](.github/workflows/ci.yml) runs on `windows-latest` in two jobs, one for **PowerShell 7** and one for **Windows PowerShell 5.1**:

1. Validate `packages.json`, `controls.json` and remediation coverage.
2. Run PSScriptAnalyzer (PowerShell 7 job).
3. Run the Pester suite.
4. Run dry-run smoke tests across modes and categories.
5. Run a **read-only** `-Assess` against the runner and upload the reports as artifacts.
6. Run `-Remediate -WhatIf` and fail if any backup file was written (PowerShell 7 job).

The runner is never provisioned or hardened. [`secret-scan.yml`](.github/workflows/secret-scan.yml) runs gitleaks over the full history. Actions are pinned to commit SHAs and workflows use a read-only token.

## Skills demonstrated

**Security engineering.** Windows endpoint hardening assessment across Microsoft Defender, Windows Firewall, SMB, LLMNR, PowerShell logging, BitLocker, UAC, LSA protection, Secure Boot and RDP. Defender exclusion risk analysis. Remediation that verifies against effective policy and accounts for GPO, MDM and tamper protection.

**Security automation.** PowerShell modules with `SupportsShouldProcess`, idempotent desired-state checks, configuration as code with schema validation, backup and rollback with input validation, and structured JSON and HTML evidence reports.

**DevSecOps.** Pester unit and CLI tests with mocked system calls, PSScriptAnalyzer gating, GitHub Actions on Windows across two PowerShell engines, gitleaks secret scanning, and SHA-pinned actions with least-privilege tokens.

**Security frameworks.** Controls mapped to NIST SP 800-53 Rev. 5 and MITRE ATT&CK, with every reference checked against its source. Microsoft Learn guidance linked for each control.

**Tooling.** winget, pipx and VS Code CLI automation. Provisioning of the AWS CLI, Azure CLI, Terraform CLI and kubectl. This repository installs those CLIs; it does not contain infrastructure code.

## Design principles

- **Safe defaults**: dry run before install, assessment before remediation, confirmation before each change.
- **Visible failures**: every package, control and remediation ends in an explicit status, and failures set the exit code.
- **Idempotency**: re-running changes nothing that is already in the desired state (PATH entries, profile block, installed packages, compliant settings).
- **Configuration over hard-coded data**, with validation that keeps the configuration and the code in sync.
- **Testability**: system access sits behind small functions, so the logic can be tested without a live Windows machine.
- **Honest reporting**: unknown is ERROR, absent is NOT_APPLICABLE, and neither counts as PASS.

## Limitations

- Microsoft Defender features and cmdlets vary by Windows edition and version. The BitLocker module is not present on Windows Home.
- Several controls need Administrator rights to read. Without them the controls report ERROR.
- Group Policy, Intune or other MDM can override local settings. The assessment reports the effective state, but local remediation cannot win against a managed policy.
- Real installs and remediation run only on Windows. CI covers the logic with mocks, plus a read-only assessment and a `-WhatIf` remediation on GitHub's Windows Server runners. Remediation has not been exercised end-to-end on a Windows 10/11 client in CI.
- Signature age thresholds (3 and 7 days) and the exclusion risk patterns are project defaults, not vendor requirements.
- Framework references are related guidance. Passing every control does not make a machine compliant with CIS, NIST or any other standard.
- Rollback covers only changes made by `-Remediate` and recorded in a backup file.

## Roadmap

- Microsoft Graph based, read-only Entra ID checks (MFA registration, privileged role assignments, guest accounts, Conditional Access visibility) with documented least-privilege scopes. Not started. It will not store credentials.
- Additional Windows baseline controls, for example Credential Guard and audit policy subcategories.
- A Windows 11 client test lane for end-to-end remediation and rollback on a disposable VM.
- Signed releases.

## Contributing

Issues and pull requests are welcome. Please run `tools\Invoke-Tests.ps1` and `tools\Invoke-Lint.ps1` before opening a PR. New controls need an entry in `controls.json`, an evaluator, fixture-based tests and a regenerated `docs/CONTROLS.md`. New references must be checked against their source.

## License

[MIT](LICENSE)
