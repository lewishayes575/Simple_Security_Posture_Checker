from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SEVERITIES = {"PASS": 0, "INFO": 1, "WARN": 2, "FAIL": 3, "ERROR": 4}


@dataclass
class Finding:
    category: str
    title: str
    status: str
    severity: str
    summary: str
    evidence: Any = None
    remediation: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    host: str
    generated_at: str
    is_admin: bool
    findings: list[Finding] = field(default_factory=list)
    comparison: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        counts = {level: 0 for level in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {
            "scanner": "Windows Security Posture Scanner",
            "schema_version": "1.0",
            "host": self.host,
            "generated_at": self.generated_at,
            "is_admin": self.is_admin,
            "summary": counts,
            "findings": [finding.as_dict() for finding in self.findings],
            "comparison": self.comparison,
        }


def run_powershell(script: str) -> Any:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not powershell:
        raise RuntimeError("PowerShell was not found on PATH")
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=35,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "PowerShell command failed"
        raise RuntimeError(message)
    output = completed.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Unexpected PowerShell output: {output[:300]}") from exc


def ps_json(body: str) -> str:
    return f"$ErrorActionPreference='Stop'; {body} | ConvertTo-Json -Depth 8 -Compress"


def make_finding(category: str, title: str, status: str, summary: str, evidence: Any = None,
                 remediation: str = "", error: str = "") -> Finding:
    return Finding(category, title, status, status, summary, evidence, remediation, error)


def execute_check(category: str, title: str, body: str, evaluate: Callable[[Any], Finding]) -> Finding:
    try:
        return evaluate(run_powershell(ps_json(body)))
    except Exception as exc:
        return make_finding(category, title, "ERROR", "The check could not be completed.", error=str(exc),
                            remediation="Run the scanner in an elevated Windows PowerShell session and review the command error.")


def check_defender() -> Finding:
    def evaluate(data: Any) -> Finding:
        if not data:
            return make_finding("Defender", "Microsoft Defender", "WARN", "No Defender status was returned.")
        fields = {key: data.get(key) for key in ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "AntispywareEnabled")}
        missing = [key for key, value in fields.items() if value is not True]
        if missing:
            return make_finding("Defender", "Microsoft Defender", "FAIL", "One or more Defender protections are not enabled.", fields,
                                "Enable the affected Defender protection features and investigate tamper or policy settings.")
        return make_finding("Defender", "Microsoft Defender", "PASS", "Core Defender protections are enabled.", fields)

    return execute_check("Defender", "Microsoft Defender", "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled", evaluate)


def check_firewall() -> Finding:
    def evaluate(data: Any) -> Finding:
        profiles = data if isinstance(data, list) else [data]
        disabled = [profile.get("Name") for profile in profiles if profile and profile.get("Enabled") is not True]
        evidence = [{"Name": item.get("Name"), "Enabled": item.get("Enabled"), "DefaultInboundAction": item.get("DefaultInboundAction")} for item in profiles]
        if disabled:
            return make_finding("Firewall", "Windows Firewall", "FAIL", f"Firewall is disabled for: {', '.join(map(str, disabled))}.", evidence,
                                "Enable Windows Firewall on every network profile and keep inbound traffic restricted by default.")
        return make_finding("Firewall", "Windows Firewall", "PASS", "Windows Firewall is enabled on every returned profile.", evidence)

    return execute_check("Firewall", "Windows Firewall", "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction", evaluate)


def check_bitlocker() -> Finding:
    def evaluate(data: Any) -> Finding:
        volumes = data if isinstance(data, list) else [data]
        system = [volume for volume in volumes if volume and volume.get("MountPoint") == "C:"]
        if not system:
            return make_finding("BitLocker", "BitLocker", "WARN", "The system volume could not be identified.", volumes)
        volume = system[0]
        encrypted = volume.get("ProtectionStatus") in (1, "On") and volume.get("VolumeStatus") in ("FullyEncrypted", "EncryptionInProgress")
        evidence = {key: volume.get(key) for key in ("MountPoint", "VolumeStatus", "ProtectionStatus", "EncryptionMethod")}
        if not encrypted:
            return make_finding("BitLocker", "BitLocker", "FAIL", "The system volume is not fully encrypted and protected.", evidence,
                                "Enable BitLocker on the operating-system volume and escrow its recovery key according to policy.")
        return make_finding("BitLocker", "BitLocker", "PASS", "The system volume is encrypted and protection is on.", evidence)

    return execute_check("BitLocker", "BitLocker", "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod", evaluate)


def check_secure_boot() -> Finding:
    def evaluate(data: Any) -> Finding:
        enabled = data is True or data == "True"
        if enabled:
            return make_finding("Secure Boot", "Secure Boot", "PASS", "Secure Boot is enabled.", {"enabled": True})
        return make_finding("Secure Boot", "Secure Boot", "FAIL", "Secure Boot is not enabled or could not be confirmed.", {"enabled": data},
                            "Enable Secure Boot in UEFI firmware after confirming the device uses a compatible GPT/UEFI configuration.")

    return execute_check("Secure Boot", "Secure Boot", "Confirm-SecureBootUEFI", evaluate)


def check_local_admins() -> Finding:
    def evaluate(data: Any) -> Finding:
        members = data if isinstance(data, list) else ([data] if data else [])
        names = [member.get("Name", "unknown") if isinstance(member, dict) else str(member) for member in members]
        if len(names) > 3:
            return make_finding("Local Administrators", "Local administrator membership", "WARN", f"{len(names)} local administrator entries were found.", names,
                                "Remove stale or unnecessary administrator accounts and use least privilege; retain only approved break-glass access.")
        return make_finding("Local Administrators", "Local administrator membership", "PASS", f"{len(names)} local administrator entries were found.", names)

    body = "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass,PrincipalSource"
    return execute_check("Local Administrators", "Local administrator membership", body, evaluate)


def check_audit_policy() -> Finding:
    def evaluate(data: Any) -> Finding:
        text = str(data or "")
        categories = re.findall(r"(?m)^\s*([^:]+):\s*(Success and Failure|Success|Failure|No Auditing)\s*$", text)
        no_audit = [name.strip() for name, mode in categories if mode == "No Auditing"]
        evidence = {"no_auditing_categories": no_audit, "raw": text}
        if no_audit:
            return make_finding("Audit Policy", "Windows audit policy", "WARN", f"{len(no_audit)} audit categories have no auditing enabled.", evidence,
                                "Enable Success and Failure auditing for security-relevant categories, especially logon, account management, policy change, and system events.")
        return make_finding("Audit Policy", "Windows audit policy", "PASS", "No audit category was reported as completely disabled.", evidence)

    script = "auditpol /get /category:* /r | Out-String"
    return execute_check("Audit Policy", "Windows audit policy", script, evaluate)


def check_risky_services() -> Finding:
    risky = "RemoteRegistry,TermService,SSDPSRV,upnphost,Tcpip6,WebClient,WinRM"
    def evaluate(data: Any) -> Finding:
        services = data if isinstance(data, list) else ([data] if data else [])
        running = [item.get("Name") for item in services if item.get("Status") == "Running"]
        if running:
            return make_finding("Risky Services", "High-risk service exposure", "WARN", f"{len(running)} monitored service(s) are running.", services,
                                "Disable services that are not required, restrict their firewall exposure, and document approved remote administration paths.")
        return make_finding("Risky Services", "High-risk service exposure", "PASS", "No monitored high-risk service is running.", services)

    body = f"$names = '{risky}'.Split(','); Get-CimInstance Win32_Service | Where-Object {{ $names -contains $_.Name }} | Select-Object Name,DisplayName,State,StartMode,PathName"
    return execute_check("Risky Services", "High-risk service exposure", body, evaluate)


def check_updates() -> Finding:
    def evaluate(data: Any) -> Finding:
        updates = data if isinstance(data, list) else ([data] if data else [])
        if updates:
            return make_finding("Updates", "Missing Windows updates", "FAIL", f"{len(updates)} applicable update(s) are pending.", updates,
                                "Install pending security and quality updates, then restart when required.")
        return make_finding("Updates", "Missing Windows updates", "PASS", "Windows Update returned no pending applicable updates.", [])

    body = "$session = New-Object -ComObject Microsoft.Update.Session; $searcher = $session.CreateUpdateSearcher(); $result = $searcher.Search(\"IsInstalled=0 and IsHidden=0\"); $result.Updates | Select-Object Title,KBArticleIDs,Severity,IsDownloaded"
    return execute_check("Updates", "Missing Windows updates", body, evaluate)


def check_smb() -> Finding:
    def evaluate(data: Any) -> Finding:
        server = data.get("server") or {}
        client = data.get("client") or {}
        smb1 = server.get("EnableSMB1Protocol")
        signing = server.get("EnableSecuritySignature") is True and client.get("EnableSecuritySignature") is True
        evidence = {"server": server, "client": client}
        if smb1 is True or not signing:
            return make_finding("SMB", "SMB security settings", "FAIL", "SMB 1 or required SMB signing protection is not safely configured.", evidence,
                                "Disable SMBv1 and require SMB signing on client and server where supported; validate legacy dependencies before enforcing changes.")
        return make_finding("SMB", "SMB security settings", "PASS", "SMBv1 is disabled and SMB signing is enabled for both client and server.", evidence)

    body = "@{server=(Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSecuritySignature,RequireSecuritySignature); client=(Get-SmbClientConfiguration | Select-Object EnableSecuritySignature,RequireSecuritySignature)}"
    return execute_check("SMB", "SMB security settings", body, evaluate)


def check_password_policy() -> Finding:
    def evaluate(data: Any) -> Finding:
        text = str(data or "")
        values = dict(re.findall(r"(?im)^\s*([^\r\n]+?)\s{2,}(\d+|Never|Unlimited)\s*$", text))
        minimum = next((int(value) for key, value in values.items() if "Minimum password length" in key and value.isdigit()), 0)
        lockout = next((int(value) for key, value in values.items() if "Lockout threshold" in key and value.isdigit()), 0)
        evidence = {"minimum_password_length": minimum, "lockout_threshold": lockout, "raw": text}
        if minimum < 14 or lockout == 0:
            return make_finding("Password Policy", "Local password policy", "WARN", "Password length or account lockout settings are weaker than the scanner baseline.", evidence,
                                "Use a minimum password length of 14 characters and configure a non-zero account lockout threshold consistent with your organization policy.")
        return make_finding("Password Policy", "Local password policy", "PASS", "Password length and lockout settings meet the scanner baseline.", evidence)

    return execute_check("Password Policy", "Local password policy", "net accounts | Out-String", evaluate)


def check_rdp() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        enabled = data.get("RdpEnabled") is True
        nla = data.get("NlaEnabled") is True
        if not enabled:
            return make_finding("RDP", "Remote Desktop", "PASS", "Remote Desktop is disabled.", data)
        if not nla:
            return make_finding("RDP", "Remote Desktop", "FAIL", "Remote Desktop is enabled without Network Level Authentication.", data,
                                "Disable Remote Desktop if it is not required, or require Network Level Authentication and restrict access to approved administrators.")
        return make_finding("RDP", "Remote Desktop", "WARN", "Remote Desktop is enabled and protected by Network Level Authentication.", data,
                            "Restrict RDP to approved management networks, require MFA where available, and monitor remote logons.")

    body = "@{RdpEnabled=((Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections -eq 0); NlaEnabled=((Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication -eq 1)}"
    return execute_check("RDP", "Remote Desktop", body, evaluate)


def check_uac() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        enabled = data.get("EnableLUA") == 1
        prompt_level = data.get("ConsentPromptBehaviorAdmin")
        if not enabled:
            return make_finding("UAC", "User Account Control", "FAIL", "User Account Control is disabled.", data,
                                "Enable UAC and require consent for administrator actions.")
        if prompt_level is not None and prompt_level < 2:
            return make_finding("UAC", "User Account Control", "WARN", "UAC is enabled but administrator consent prompting is weak.", data,
                                "Use the secure desktop and require consent or credentials for administrator elevation.")
        return make_finding("UAC", "User Account Control", "PASS", "UAC is enabled with a standard administrator prompt level.", data)

    body = "@{EnableLUA=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA; ConsentPromptBehaviorAdmin=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').ConsentPromptBehaviorAdmin}"
    return execute_check("UAC", "User Account Control", body, evaluate)


def check_defender_exclusions() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        exclusions = {key: value for key, value in data.items() if value}
        if exclusions:
            return make_finding("Defender", "Defender exclusions", "WARN", "Defender exclusions are configured and should be reviewed.", exclusions,
                                "Remove unnecessary exclusions and document every approved path, process, extension, or IP exclusion.")
        return make_finding("Defender", "Defender exclusions", "PASS", "No Defender exclusions were returned.", data)

    body = "Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress"
    return execute_check("Defender", "Defender exclusions", body, evaluate)


def check_logging() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        logs = data.get("logs") or []
        disabled_logs = [item.get("LogName") for item in logs if item.get("IsEnabled") is not True or (item.get("MaximumKilobytes") or 0) < 20480]
        script_logging = data.get("script_block_logging") == 1
        evidence = {"logs": logs, "script_block_logging": data.get("script_block_logging"), "module_logging": data.get("module_logging")}
        if disabled_logs or not script_logging:
            return make_finding("Logging", "Security event logging", "WARN", "One or more important logs are disabled, undersized, or PowerShell script block logging is off.", evidence,
                                "Enable Security, System, and PowerShell logs with at least 20 MB retention and enable PowerShell script block logging under policy.")
        return make_finding("Logging", "Security event logging", "PASS", "Important event logs and PowerShell script block logging meet the scanner baseline.", evidence)

    body = "@{logs=(@('Security','System','Windows PowerShell') | ForEach-Object { $logName=$_; try { Get-WinEvent -ListLog $logName -ErrorAction Stop | Select-Object LogName,IsEnabled,@{N='MaximumKilobytes';E={[int]($_.MaximumSizeInBytes / 1KB)}} } catch { [pscustomobject]@{LogName=$logName;IsEnabled=$false;MaximumKilobytes=0;Error=$_.Exception.Message} } }); script_block_logging=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging; module_logging=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging}"
    return execute_check("Logging", "Security event logging", body, evaluate)


def check_insecure_protocols() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        enabled = [name for name, value in data.items() if isinstance(value, dict) and value.get("Enabled") == 1 and value.get("DisabledByDefault") != 1]
        if enabled:
            return make_finding("Protocols", "Insecure protocol exposure", "FAIL", f"Legacy protocol endpoints are enabled: {', '.join(enabled)}.", data,
                                "Disable TLS 1.0 and TLS 1.1 for client and server roles after validating legacy application compatibility.")
        return make_finding("Protocols", "Insecure protocol exposure", "PASS", "TLS 1.0 and TLS 1.1 are not explicitly enabled for client or server roles.", data)

    paths = [
        ("TLS10Client", "TLS 1.0", "Client"), ("TLS10Server", "TLS 1.0", "Server"),
        ("TLS11Client", "TLS 1.1", "Client"), ("TLS11Server", "TLS 1.1", "Server"),
    ]
    expressions = "; ".join(f"${name}=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\{protocol}\\{role}' -ErrorAction SilentlyContinue | Select-Object Enabled,DisabledByDefault)" for name, protocol, role in paths)
    body = f"{expressions}; @{{{'; '.join(f'{name}=${name}' for name, _, _ in paths)}}}"
    return execute_check("Protocols", "Insecure protocol exposure", body, evaluate)


def check_guest_account() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        if data.get("Enabled") is True:
            return make_finding("Accounts", "Guest account", "FAIL", "The built-in Guest account is enabled.", data,
                                "Disable the built-in Guest account unless a documented legacy dependency requires it.")
        return make_finding("Accounts", "Guest account", "PASS", "The built-in Guest account is disabled.", data)

    return execute_check("Accounts", "Guest account", "Get-LocalUser -Name Guest | Select-Object Name,Enabled,LastLogon", evaluate)


def check_open_shares() -> Finding:
    def evaluate(data: Any) -> Finding:
        shares = data if isinstance(data, list) else ([data] if data else [])
        custom = [share for share in shares if share.get("Name") not in {"ADMIN$", "C$", "IPC$"}]
        if custom:
            return make_finding("Shares", "Network shares", "WARN", f"{len(custom)} non-default network share(s) are exposed.", custom,
                                "Review each share and its ACLs; remove unused shares and avoid broad Everyone or anonymous access.")
        return make_finding("Shares", "Network shares", "PASS", "No non-default network shares were found.", shares)

    return execute_check("Shares", "Network shares", "Get-SmbShare | Where-Object { -not $_.Special } | Select-Object Name,Path,Description,EncryptData", evaluate)


def check_smb_guest() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        guest = data.get("EnableInsecureGuestLogons") is True
        unencrypted = data.get("RejectUnencryptedAccess") is not True
        if guest or unencrypted:
            return make_finding("SMB", "SMB guest and encryption policy", "FAIL", "SMB allows insecure guest logons or unencrypted access.", data,
                                "Disable insecure guest logons and reject unencrypted SMB access after validating legacy device compatibility.")
        return make_finding("SMB", "SMB guest and encryption policy", "PASS", "Insecure SMB guest logons are disabled and unencrypted access is rejected.", data)

    body = "Get-SmbServerConfiguration | Select-Object EnableInsecureGuestLogons,RejectUnencryptedAccess"
    return execute_check("SMB", "SMB guest and encryption policy", body, evaluate)


def check_virtualization_security() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        device_guard = data.get("SecurityServicesRunning") or []
        lsa = data.get("RunAsPPL") == 1
        credential_guard = 1 in device_guard or "Credential Guard" in device_guard
        evidence = {"device_guard": data, "lsa_protection": lsa, "credential_guard": credential_guard}
        if not lsa and not credential_guard:
            return make_finding("Credential Protection", "Credential Guard and LSA protection", "WARN", "Credential Guard and LSA protection were not detected as enabled.", evidence,
                                "Enable virtualization-based security, Credential Guard, and LSA protection where supported by the device and operating system.")
        return make_finding("Credential Protection", "Credential Guard and LSA protection", "PASS", "At least one credential-isolation protection is enabled.", evidence)

    body = "@{SecurityServicesRunning=((Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning); RunAsPPL=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue).RunAsPPL}"
    return execute_check("Credential Protection", "Credential Guard and LSA protection", body, evaluate)


def check_update_services() -> Finding:
    def evaluate(data: Any) -> Finding:
        services = data if isinstance(data, list) else ([data] if data else [])
        unhealthy = [service for service in services if service.get("Status") != "Running" or service.get("StartType") == "Disabled"]
        if unhealthy:
            return make_finding("Updates", "Windows Update services", "FAIL", "Windows Update or BITS is stopped or disabled.", services,
                                "Set Windows Update and Background Intelligent Transfer Service to an approved startup mode and ensure they can run during maintenance windows.")
        return make_finding("Updates", "Windows Update services", "PASS", "Windows Update and BITS are running and not disabled.", services)

    body = "Get-CimInstance Win32_Service -Filter \"Name='wuauserv' OR Name='BITS'\" | Select-Object Name,State,StartMode | ForEach-Object { [pscustomobject]@{Name=$_.Name;Status=$_.State;StartType=$_.StartMode} }"
    return execute_check("Updates", "Windows Update services", body, evaluate)


def check_autologon() -> Finding:
    def evaluate(data: Any) -> Finding:
        data = data or {}
        configured = bool(data.get("AutoAdminLogon") == "1" or data.get("DefaultUserName") or data.get("DefaultPassword"))
        evidence = {"AutoAdminLogon": data.get("AutoAdminLogon"), "DefaultUserNameConfigured": bool(data.get("DefaultUserName")), "DefaultPasswordConfigured": bool(data.get("DefaultPassword"))}
        if configured:
            return make_finding("Credentials", "Automatic logon", "FAIL", "Automatic logon settings are configured in the system policy.", evidence,
                                "Disable automatic logon and remove stored credentials from the Winlogon policy unless a tightly controlled kiosk exception is documented.")
        return make_finding("Credentials", "Automatic logon", "PASS", "No automatic logon configuration was detected.", evidence)

    body = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue | Select-Object AutoAdminLogon,DefaultUserName,DefaultPassword"
    return execute_check("Credentials", "Automatic logon", body, evaluate)


def check_llmnr() -> Finding:
    def evaluate(data: Any) -> Finding:
        enabled = data.get("EnableMulticast") != 0 if data else True
        if enabled:
            return make_finding("Network", "LLMNR name resolution", "WARN", "LLMNR is enabled or not explicitly disabled.", data,
                                "Disable LLMNR through Group Policy unless a documented compatibility requirement exists.")
        return make_finding("Network", "LLMNR name resolution", "PASS", "LLMNR is disabled by policy.", data)

    body = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -ErrorAction SilentlyContinue | Select-Object EnableMulticast"
    return execute_check("Network", "LLMNR name resolution", body, evaluate)


def check_netbios() -> Finding:
    def evaluate(data: Any) -> Finding:
        adapters = data if isinstance(data, list) else ([data] if data else [])
        enabled = [item for item in adapters if item.get("TcpipNetbiosOptions") != 2]
        if enabled:
            return make_finding("Network", "NetBIOS over TCP/IP", "WARN", f"{len(enabled)} adapter(s) allow NetBIOS over TCP/IP.", enabled,
                                "Disable NetBIOS over TCP/IP on networks that do not require legacy name resolution.")
        return make_finding("Network", "NetBIOS over TCP/IP", "PASS", "NetBIOS over TCP/IP is disabled on all returned adapters.", adapters)

    body = "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"IPEnabled=True\" | Select-Object Description,Index,TcpipNetbiosOptions"
    return execute_check("Network", "NetBIOS over TCP/IP", body, evaluate)


def check_broad_firewall_rules() -> Finding:
    def evaluate(data: Any) -> Finding:
        rules = data if isinstance(data, list) else ([data] if data else [])
        risky = [rule for rule in rules if rule.get("Action") == "Allow" and rule.get("Enabled") is True and rule.get("Direction") == "Inbound" and rule.get("Profile") == "Any"]
        if risky:
            return make_finding("Firewall", "Broad inbound firewall rules", "WARN", f"{len(risky)} enabled inbound allow rule(s) have broad scope.", risky,
                                "Review inbound allow rules with Any address, Any port, or Any profile scope; restrict them to required services and trusted networks.")
        return make_finding("Firewall", "Broad inbound firewall rules", "PASS", "No broad enabled inbound allow rules were returned.", rules)

    body = "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Select-Object -First 500 DisplayName,InstanceID,Direction,Action,Enabled,@{N='Profile';E={$_.Profile.ToString()}}"
    return execute_check("Firewall", "Broad inbound firewall rules", body, evaluate)


def check_tamper_protection() -> Finding:
    def evaluate(data: Any) -> Finding:
        enabled = data.get("IsTamperProtected") is True if data else False
        if enabled:
            return make_finding("Defender", "Tamper protection", "PASS", "Microsoft Defender tamper protection is enabled.", data)
        return make_finding("Defender", "Tamper protection", "WARN", "Microsoft Defender tamper protection is disabled or unavailable.", data,
                            "Enable Defender tamper protection and verify that security policy prevents unauthorized changes to Defender settings.")

    return execute_check("Defender", "Tamper protection", "Get-MpComputerStatus | Select-Object IsTamperProtected", evaluate)


def compare_reports(current: ScanReport, previous_path: Path) -> dict[str, Any]:
    previous_data = json.loads(previous_path.read_text(encoding="utf-8"))
    previous = {(item.get("category"), item.get("title")): item.get("status") for item in previous_data.get("findings", [])}
    current_status = {(item.category, item.title): item.status for item in current.findings}
    improved = [f"{category}: {title}" for (category, title), status in current_status.items() if previous.get((category, title)) in {"FAIL", "WARN", "ERROR"} and status == "PASS"]
    regressed = [f"{category}: {title}" for (category, title), status in current_status.items() if status in {"FAIL", "WARN", "ERROR"} and previous.get((category, title)) == "PASS"]
    changed = [f"{category}: {title} ({previous.get((category, title))} -> {status})" for (category, title), status in current_status.items() if (category, title) in previous and previous[(category, title)] != status and f"{category}: {title}" not in improved and f"{category}: {title}" not in regressed]
    return {"previous_report": str(previous_path), "improved": improved, "regressed": regressed, "changed": changed}


CHECKS = [check_defender, check_firewall, check_bitlocker, check_secure_boot, check_local_admins,
          check_audit_policy, check_risky_services, check_updates, check_smb, check_password_policy,
          check_rdp, check_uac, check_defender_exclusions, check_logging, check_insecure_protocols,
          check_guest_account, check_open_shares, check_smb_guest, check_virtualization_security,
          check_update_services, check_autologon, check_llmnr, check_netbios,
          check_broad_firewall_rules, check_tamper_protection]


def is_admin() -> bool:
    try:
        return bool(run_powershell("[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() -as [object] | ForEach-Object { $_.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }"))
    except Exception:
        return False


def scan() -> ScanReport:
    findings = [check() for check in CHECKS]
    return ScanReport(os.environ.get("COMPUTERNAME", "unknown"), datetime.now(timezone.utc).isoformat(), is_admin(), findings)


def write_json(report: ScanReport, path: Path) -> None:
    path.write_text(json.dumps(report.as_dict(), indent=2, default=str), encoding="utf-8")


def write_csv(report: ScanReport, path: Path) -> None:
    fields = ["category", "title", "status", "severity", "summary", "evidence", "remediation", "error"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in report.findings:
            row = finding.as_dict()
            row["evidence"] = json.dumps(row["evidence"], default=str)
            writer.writerow(row)


def write_html(report: ScanReport, path: Path) -> None:
    data = report.as_dict()
    rows = []
    for finding in report.findings:
        rows.append("<tr class='{}'><td>{}</td><td>{}</td><td><b>{}</b></td><td>{}</td><td><pre>{}</pre></td><td>{}</td></tr>".format(
            finding.severity.lower(), html.escape(finding.category), html.escape(finding.title), finding.severity,
            html.escape(finding.summary), html.escape(json.dumps(finding.evidence, indent=2, default=str)), html.escape(finding.remediation or finding.error)))
    summary = " ".join(f"<span class='badge'>{key}: {value}</span>" for key, value in data["summary"].items())
    comparison = data.get("comparison")
    comparison_html = ""
    if comparison:
        comparison_html = f"<h2>Comparison</h2><pre>{html.escape(json.dumps(comparison, indent=2))}</pre>"
    document = f"""<!doctype html><html><head><meta charset='utf-8'><title>Windows Security Posture - {html.escape(report.host)}</title>
<style>body{{font:15px Segoe UI,Arial,sans-serif;color:#202124;margin:32px;background:#f5f7fa}}main{{max-width:1400px;margin:auto;background:white;padding:28px;box-shadow:0 2px 12px #0001}}h1{{margin-top:0}}.badge{{display:inline-block;margin:0 8px 12px 0;padding:7px 10px;background:#edf1f5;border-radius:4px}}table{{border-collapse:collapse;width:100%}}th,td{{padding:10px;border:1px solid #dfe3e8;text-align:left;vertical-align:top}}th{{background:#25364a;color:white}}tr.fail{{background:#fff0f0}}tr.warn{{background:#fff9e6}}tr.error{{background:#f3e8ff}}pre{{white-space:pre-wrap;max-height:240px;overflow:auto;font-size:12px}}</style></head>
<body><main><h1>Windows Security Posture Scanner</h1><p><b>Host:</b> {html.escape(report.host)} &nbsp; <b>Generated:</b> {html.escape(report.generated_at)} &nbsp; <b>Elevated:</b> {report.is_admin}</p><p>{summary}</p>{comparison_html}
<table><thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Summary</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>{''.join(rows)}</tbody></table></main></body></html>"""
    path.write_text(document, encoding="utf-8")


def pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_pdf(report: ScanReport, path: Path) -> None:
    lines = ["Windows Security Posture Scanner", f"Host: {report.host}", f"Generated: {report.generated_at}", ""]
    for finding in report.findings:
        lines.extend([f"[{finding.severity}] {finding.category}: {finding.title}", finding.summary])
        if finding.remediation:
            lines.append("Remediation: " + finding.remediation)
        lines.append("")
    pages = [lines[index:index + 48] for index in range(0, len(lines), 48)] or [[]]
    objects: list[bytes] = [b"", b"<< /Type /Catalog /Pages 2 0 R >>", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    page_ids = []
    for page_lines in pages:
        content = "BT /F1 9 Tf 42 750 Td 0 -13 Td\n" + "\n".join(f"({pdf_escape(line[:150])}) Tj 0 -13 Td" for line in page_lines) + " ET"
        content_bytes = content.encode("latin-1", "replace")
        content_id = len(objects)
        objects.append(f"<< /Length {len(content_bytes)} >>\nstream\n".encode() + content_bytes + b"\nendstream")
        page_id = len(objects)
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents {content_id} 0 R >>".encode())
        page_ids.append(page_id)
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(f'{page_id} 0 R' for page_id in page_ids)}] /Count {len(page_ids)} >>".encode()
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects[1:], 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects)}\n0000000000 65535 f \n".encode())
    output.extend("".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:]).encode())
    output.extend(f"trailer\n<< /Size {len(objects)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    path.write_bytes(output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Windows security posture scanner")
    parser.add_argument("-o", "--output", type=Path, default=Path("security-posture-report"), help="Output file prefix")
    parser.add_argument("--compare", type=Path, help="Compare this scan with a previous JSON report")
    args = parser.parse_args()
    report = scan()
    if args.compare:
        try:
            report.comparison = compare_reports(report, args.compare)
        except Exception as exc:
            report.comparison = {"previous_report": str(args.compare), "error": str(exc)}
    prefix = args.output
    prefix.parent.mkdir(parents=True, exist_ok=True)
    write_json(report, prefix.with_suffix(".json"))
    write_csv(report, prefix.with_suffix(".csv"))
    write_html(report, prefix.with_suffix(".html"))
    write_pdf(report, prefix.with_suffix(".pdf"))
    print(f"Scanned {report.host}: {len(report.findings)} checks")
    for finding in report.findings:
        print(f"{finding.severity:5} {finding.category}: {finding.summary}")
    print(f"Reports written with prefix: {prefix}")
    return 0 if not any(finding.severity == "ERROR" for finding in report.findings) else 2


if __name__ == "__main__":
    sys.exit(main())