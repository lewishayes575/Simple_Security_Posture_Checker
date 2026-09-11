# Windows Security Posture Scanner

Read-only Windows posture checks for Defender, firewall, BitLocker, Secure Boot, local administrators, audit policy, risky services, pending updates, SMB settings, password policy, RDP/NLA, UAC, Defender exclusions, event logging, legacy TLS protocols, guest access, network shares, credential protections, update services, automatic logon, LLMNR, NetBIOS, broad firewall rules, and tamper protection.

## Run

Use an elevated Windows PowerShell or Command Prompt for the most complete results:

```powershell
python .\scanner.py --output .\reports\security-posture
```

Compare against a previous JSON report:

```powershell
python .\scanner.py --output .\reports\security-posture-new --compare .\reports\security-posture-old.json
```

The scanner creates:

- `security-posture.html` for a readable browser report
- `security-posture.json` for automation
- `security-posture.csv` for spreadsheets
- `security-posture.pdf` for sharing or archiving

The tool uses only the Python standard library. Some checks depend on Windows features and permissions; unavailable commands are reported as `ERROR` findings instead of stopping the scan.

The service list, password policy thresholds, logging baseline, protocol checks, and credential protection baseline are intentionally conservative starting points. Review them against your organization policy before treating a `PASS` or `WARN` as compliance evidence.