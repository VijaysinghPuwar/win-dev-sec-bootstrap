# Security control reference

Generated from `config/controls.json` by `tools/New-ControlDoc.ps1`. Do not edit by hand.

NIST SP 800-53 Rev. 5 control families and MITRE ATT&CK IDs are listed only where the relationship was checked against the source. CIS Benchmark item numbers are intentionally omitted because they change between benchmark versions and could not be verified against a licensed copy.

Statuses: `PASS` meets the expected state, `WARN` partially meets it or is a context-dependent recommendation, `FAIL` does not meet it, `NOT_APPLICABLE` the feature is not present on this system, `ERROR` the state could not be read (often because the session is not elevated).

## Microsoft Defender

| ID | Control | Severity | Expected | Remediation | References |
|---|---|---|---|---|---|
| WIN-DEF-001 | Microsoft Defender real-time protection is on | High | Real-time protection enabled | Automated | NIST SI-3, [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus) |
| WIN-DEF-002 | Microsoft Defender behavior monitoring is on | Medium | Behavior monitoring enabled | Automated | NIST SI-3, [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/behavior-monitor) |
| WIN-DEF-003 | Microsoft Defender cloud-delivered protection is on | Medium | MAPS reporting Basic or Advanced | Automated | NIST SI-3, [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-defender-antivirus) |
| WIN-DEF-004 | Potentially unwanted application (PUA) blocking is on | Low | PUAProtection = Enabled (1) | Automated | NIST SI-3, [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus) |
| WIN-DEF-005 | Microsoft Defender network protection is in block mode | Medium | EnableNetworkProtection = Enabled (1) | Automated | NIST SI-3, NIST SC-7, [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection) |
| WIN-DEF-006 | Microsoft Defender antivirus signatures are current | Medium | Signatures updated within 3 days (WARN up to 7 days) | Automated | NIST SI-3 |
| WIN-DEF-007 | Microsoft Defender tamper protection is on | Medium | IsTamperProtected = True | Manual | NIST SI-3, [ATT&CK T1685](https://attack.mitre.org/techniques/T1685/), [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection) |
| WIN-DEF-008 | No high-risk Microsoft Defender exclusions | High | No exclusions for drive roots, temp or download folders, script hosts or executable file types | Manual | NIST SI-3, [ATT&CK T1685](https://attack.mitre.org/techniques/T1685/), [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus), [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/common-exclusion-mistakes-microsoft-defender-antivirus) |
| WIN-DEF-009 | Attack surface reduction rules are configured | Medium | At least one ASR rule in Block or Warn mode | Manual | NIST SI-3, [ATT&CK M1040](https://attack.mitre.org/mitigations/M1040/), [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) |
| WIN-DEF-010 | Controlled folder access is on | Low | EnableControlledFolderAccess = Enabled (1) | Manual | NIST SI-3, [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders) |

- **WIN-DEF-001**: Real-time protection scans files and processes as they are accessed. Without it, Defender only detects malware during scheduled or manual scans. Remediation: Set-MpPreference -DisableRealtimeMonitoring $false
- **WIN-DEF-002**: Behavior monitoring detects suspicious process activity that signature scanning alone misses. Remediation: Set-MpPreference -DisableBehaviorMonitoring $false
- **WIN-DEF-003**: Cloud-delivered protection lets Defender query Microsoft's cloud service to block new threats before signatures are published. Remediation: Set-MpPreference -MAPSReporting Advanced
- **WIN-DEF-004**: PUA protection blocks adware, bundlers and similar software that is not classified as malware. Remediation: Set-MpPreference -PUAProtection Enabled
- **WIN-DEF-005**: Network protection blocks outbound connections to low-reputation and known-malicious domains from any process, not only the browser. Remediation: Set-MpPreference -EnableNetworkProtection Enabled
- **WIN-DEF-006**: Stale signatures miss recent malware families. The 3 and 7 day thresholds are project defaults, not a vendor requirement. Remediation: Update-MpSignature
- **WIN-DEF-007**: Tamper protection stops local processes, including malware running as administrator, from turning off Defender features. Remediation: Turn on Tamper Protection in Windows Security > Virus & threat protection settings, or through Intune. It cannot be changed with PowerShell by design.
- **WIN-DEF-008**: Broad exclusions create blind spots. Attackers add Defender exclusions to hide payloads, and overly wide developer exclusions have the same effect. Remediation: Review each exclusion and remove it with Remove-MpPreference -ExclusionPath/-ExclusionProcess/-ExclusionExtension. Exclusions are never removed automatically because they are often needed by build tools.
- **WIN-DEF-009**: ASR rules block common malware behaviors such as Office spawning child processes or credential theft from LSASS. Remediation: Deploy rules in Audit mode first and review events before switching to Block, because ASR rules can interfere with developer tools. See the ASR rules reference.
- **WIN-DEF-010**: Controlled folder access stops untrusted applications from modifying files in protected folders, which limits ransomware damage. Remediation: Enable in Windows Security > Ransomware protection after allow-listing the development tools you use; it frequently blocks compilers and package managers.

## Windows Firewall

| ID | Control | Severity | Expected | Remediation | References |
|---|---|---|---|---|---|
| WIN-FW-001 | Windows Firewall Domain profile is on and blocks unsolicited inbound traffic | High | Enabled = True, DefaultInboundAction = Block | Automated | NIST SC-7, [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/) |
| WIN-FW-002 | Windows Firewall Private profile is on and blocks unsolicited inbound traffic | High | Enabled = True, DefaultInboundAction = Block | Automated | NIST SC-7, [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/) |
| WIN-FW-003 | Windows Firewall Public profile is on and blocks unsolicited inbound traffic | High | Enabled = True, DefaultInboundAction = Block | Automated | NIST SC-7, [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/) |

- **WIN-FW-001**: The host firewall is the last network control on a device that roams between networks. Remediation: Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block
- **WIN-FW-002**: The host firewall is the last network control on a device that roams between networks. Remediation: Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block
- **WIN-FW-003**: The Public profile applies on untrusted networks such as hotel and airport Wi-Fi. Remediation: Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block

## Network Protocols

| ID | Control | Severity | Expected | Remediation | References |
|---|---|---|---|---|---|
| WIN-SMB-001 | SMBv1 server protocol is disabled | High | EnableSMB1Protocol = False | Automated | NIST CM-7, [ATT&CK T1210](https://attack.mitre.org/techniques/T1210/), [ATT&CK M1042](https://attack.mitre.org/mitigations/M1042/), [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3) |
| WIN-SMB-002 | SMBv1 optional feature is removed | High | SMB1Protocol feature Disabled or not present | Manual | NIST CM-7, [ATT&CK T1210](https://attack.mitre.org/techniques/T1210/), [ATT&CK M1042](https://attack.mitre.org/mitigations/M1042/), [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3) |
| WIN-SMB-003 | SMB server requires signing | Medium | RequireSecuritySignature = True | Manual | NIST SC-8, [ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/), [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview) |
| WIN-NET-001 | LLMNR multicast name resolution is disabled | Medium | Policy EnableMulticast = 0 | Automated | NIST CM-7, [ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/) |

- **WIN-SMB-001**: SMBv1 lacks modern integrity protections and was the transport for EternalBlue (MS17-010) exploitation. Remediation: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
- **WIN-SMB-002**: Removing the feature removes both the SMBv1 client and server components, not only the server setting. Remediation: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart, then restart. Not automated because it needs a restart before it can be verified.
- **WIN-SMB-003**: Required SMB signing prevents NTLM relay attacks against this host's file shares. Remediation: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force. Test first: very old SMB clients and some NAS devices cannot sign.
- **WIN-NET-001**: LLMNR answers can be spoofed by anyone on the local network to capture NTLM credentials (Responder-style poisoning). Remediation: Set HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient EnableMulticast (DWORD) to 0

## PowerShell Logging

| ID | Control | Severity | Expected | Remediation | References |
|---|---|---|---|---|---|
| WIN-PS-001 | PowerShell script block logging is on | Medium | Policy EnableScriptBlockLogging = 1 | Automated | NIST AU-2, NIST AU-12, [ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/), [Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) |
| WIN-PS-002 | PowerShell module logging is on | Low | Policy EnableModuleLogging = 1 | Manual | NIST AU-2, NIST AU-12, [ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/), [Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) |
| WIN-PS-003 | PowerShell transcription is on | Info | Policy EnableTranscripting = 1 | Manual | NIST AU-12, [ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/), [Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) |
| WIN-PS-004 | Windows PowerShell 2.0 engine is removed | Medium | MicrosoftWindowsPowerShellV2Root feature Disabled or not present | Manual | NIST CM-7, [ATT&CK M1042](https://attack.mitre.org/mitigations/M1042/) |

- **WIN-PS-001**: Script block logging records deobfuscated PowerShell code in event 4104, which is the main evidence source for PowerShell-based attacks. Logged code can include secrets typed into scripts, so restrict access to the PowerShell Operational log. Remediation: Set HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging EnableScriptBlockLogging (DWORD) to 1
- **WIN-PS-002**: Module logging records pipeline execution details (event 4103). It is noisy, so it is reported as a recommendation rather than a failure. Remediation: Enable 'Turn on Module Logging' in Group Policy and choose module names deliberately to control log volume.
- **WIN-PS-003**: Transcripts capture full session input and output, including any secrets displayed. Enable only with a protected output directory. Reported for visibility only. Remediation: Enable 'Turn on PowerShell Transcription' with an OutputDirectory that users cannot read or modify.
- **WIN-PS-004**: The 2.0 engine predates script block logging and AMSI, so launching it (powershell -Version 2) bypasses both. Remediation: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart. Not automated because feature changes need a restart before verification.

## Data Protection

| ID | Control | Severity | Expected | Remediation | References |
|---|---|---|---|---|---|
| WIN-BL-001 | BitLocker protects the operating system drive | High | ProtectionStatus = On | Manual | NIST SC-28, [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/) |

- **WIN-BL-001**: Without disk encryption, anyone with physical access to a lost or stolen device can read its data. Remediation: Enable BitLocker from Control Panel or manage-bde after saving the recovery key somewhere safe. Never enabled automatically: a lost recovery key means lost data.

## System Hardening

| ID | Control | Severity | Expected | Remediation | References |
|---|---|---|---|---|---|
| WIN-SYS-001 | User Account Control is on | High | EnableLUA = 1 | Manual | NIST AC-6, [ATT&CK T1548.002](https://attack.mitre.org/techniques/T1548/002/), [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/) |
| WIN-SYS-002 | LSA protection (RunAsPPL) is on | Medium | RunAsPPL = 1 or 2 | Manual | [ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/), [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) |
| WIN-SYS-003 | Secure Boot is on | Medium | Confirm-SecureBootUEFI = True | Manual | NIST SI-7, [Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot) |

- **WIN-SYS-001**: With UAC off, every administrator process runs with a full token and malware inherits it without a prompt. Remediation: Set EnableLUA to 1 under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System and restart.
- **WIN-SYS-002**: Running LSASS as a protected process blocks most user-mode credential dumping from LSASS memory. Remediation: Follow Microsoft's LSA protection guidance: audit incompatible drivers and plug-ins first, then enable and restart.
- **WIN-SYS-003**: Secure Boot only allows signed boot components to load, which blocks boot-level rootkits. Remediation: Enable Secure Boot in the UEFI firmware settings.

## Accounts

| ID | Control | Severity | Expected | Remediation | References |
|---|---|---|---|---|---|
| WIN-ACC-001 | Built-in Guest account is disabled | Medium | Guest (RID 501) Enabled = False | Automated | NIST AC-2, [ATT&CK T1078.001](https://attack.mitre.org/techniques/T1078/001/) |

- **WIN-ACC-001**: The Guest account allows unauthenticated-style local access and is a well-known default account. Remediation: Disable-LocalUser -SID <machine SID>-501

## Remote Access

| ID | Control | Severity | Expected | Remediation | References |
|---|---|---|---|---|---|
| WIN-RDP-001 | Remote Desktop is off or requires Network Level Authentication | High | fDenyTSConnections = 1, or UserAuthentication = 1 when RDP is enabled | Manual | NIST AC-17, [ATT&CK T1021.001](https://attack.mitre.org/techniques/T1021/001/), [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access) |

- **WIN-RDP-001**: Network Level Authentication requires credentials before a session is created, which reduces exposure to pre-authentication RDP vulnerabilities. Remediation: Turn off Remote Desktop if unused, or enable 'Require devices to use Network Level Authentication' in Settings > System > Remote Desktop.
