# Resume notes: win-dev-sec-bootstrap

Material for tailoring a resume or preparing for interviews. Everything here describes what the repository actually contains.

## Short project title

Windows Security Assessment and Provisioning Automation (PowerShell)

## Technology line

PowerShell 5.1/7 | Microsoft Defender | Windows Firewall | Pester | PSScriptAnalyzer | GitHub Actions | NIST SP 800-53 / MITRE ATT&CK mapping | JSON | winget

## Resume bullets

- Built a PowerShell tool that assesses 27 Windows 10/11 endpoint security controls (Microsoft Defender, firewall, SMBv1 and signing, LLMNR, PowerShell logging, BitLocker, UAC, LSA protection, RDP NLA) read-only, writes JSON and HTML evidence reports mapped to NIST SP 800-53 and MITRE ATT&CK, and remediates 13 controls only with per-change confirmation, pre-change backups, post-change verification and validated rollback.
- Rebuilt an unreliable workstation bootstrap into idempotent, configuration-driven provisioning (winget, pipx, VS Code CLI) with decoded installer exit codes, same-session PATH refresh and a managed PowerShell profile, covered by 200+ Pester tests with mocked system calls and Windows GitHub Actions CI on PowerShell 7 and 5.1 with PSScriptAnalyzer and gitleaks.

Shorter variants:

- Developed a read-only Windows endpoint security assessment in PowerShell with explicit PASS/WARN/FAIL/NOT_APPLICABLE/ERROR results, framework references checked against their sources, and opt-in remediation with backup and rollback.
- Added Pester and PSScriptAnalyzer quality gates and Windows CI for a security automation project, testing every control evaluator against synthetic system snapshots.

## 30-second explanation

I started with a script that installed security and developer tools on a new Windows machine, and it failed in ways nobody would notice: wrong package ids, errors swallowed, tools missing from PATH until a new terminal was opened. I rebuilt it so installs are reliable and safe to re-run, then added the part that matters more: a read-only check of how well the machine is protected, covering things like Defender settings, firewall profiles, SMBv1 and PowerShell logging. It produces JSON and HTML evidence and can fix some findings, but only after asking, backing up the old value and checking that the fix actually applied. It is tested with Pester on both PowerShell engines in GitHub Actions.

## Interview talking points

1. **Why assessment and remediation are separate.** Assessment only reads, so it is safe to run anywhere, including CI. Remediation needs `-Remediate` and a `ShouldProcess` confirmation for every change (`ConfirmImpact = High`), and `-WhatIf` works natively. Only settings that apply immediately and can be read back are automated. BitLocker, ASR rules and anything needing a restart stay manual because the failure modes are data loss or broken developer tooling.

2. **Verifying against effective policy.** After a firewall change the tool reads the ActiveStore (effective policy), not the local store it wrote to. If a GPO or MDM policy overrides the change, or Defender tamper protection silently ignores `Set-MpPreference`, the result is reported as a failed remediation instead of a false success.

3. **Treating the backup file as untrusted input.** Rollback writes values back as Administrator, so the backup is validated: the computer name must match, the control id must be known, and each value must be one the setting could have had (booleans, specific enums, non-negative DWORDs). The backup folder is created with an ACL that only Administrators and SYSTEM can write. Tests confirm that a tampered value is refused without calling the restore function.

4. **Making Windows security checks testable without Windows.** Probes read system state into a snapshot, and evaluators are pure functions of that snapshot. Synthetic `.psd1` fixtures (a fully hardened machine and a typical developer workstation) drive tests for every evaluator branch, including unsupported editions (NOT_APPLICABLE) and non-elevated sessions (ERROR, never PASS). CI adds a real read-only assessment on the Windows runner and a `-WhatIf` remediation that fails if any backup file is written.

5. **The PATH bug and idempotency.** winget updates the registry PATH, but the running process keeps its old copy, so pipx and VS Code extension installs failed on a clean first run. The fix rebuilds the session PATH from the Machine and User values after the winget stage, de-duplicating case-insensitively and keeping session-only entries. The old code also appended to the persistent user PATH on every run. That was removed, and `pipx ensurepath` now handles it idempotently.

6. **Honest framework mapping.** References were checked against their sources. One ATT&CK technique had been renumbered (Disable or Modify Tools is now T1685), and CIS item numbers were left out because they could not be verified against a licensed benchmark. Reports say the references are related guidance, not a compliance claim.

## What not to claim

- Not used in production or in an enterprise environment.
- Not a compliance tool, and it does not certify CIS or NIST compliance.
- Installs the Terraform, AWS, Azure and kubectl CLIs, but contains no infrastructure-as-code.
- No Microsoft Graph or Entra ID functionality yet (roadmap only).
- Remediation has not been run end-to-end on a Windows 10/11 client in CI. CI runs on Windows Server runners with `-WhatIf`.
