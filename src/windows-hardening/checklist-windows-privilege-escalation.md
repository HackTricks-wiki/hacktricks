# चेकलिस्ट - स्थानीय Windows विशेषाधिकार वृद्धि

{{#include ../banners/hacktricks-training.md}}

### **Windows स्थानीय विशेषाधिकार वृद्धि वेक्टर की खोज के लिए सबसे अच्छा उपकरण:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [सिस्टम जानकारी](windows-local-privilege-escalation/#system-info)

- [ ] [**सिस्टम जानकारी**](windows-local-privilege-escalation/#system-info) प्राप्त करें
- [ ] **कर्नेल** [**शोषणों के लिए स्क्रिप्ट का उपयोग करें**](windows-local-privilege-escalation/#version-exploits)
- [ ] कर्नेल **शोषणों के लिए Google का उपयोग करें**
- [ ] कर्नेल **शोषणों के लिए searchsploit का उपयोग करें**
- [ ] [**env vars**](windows-local-privilege-escalation/#environment) में दिलचस्प जानकारी?
- [ ] [**PowerShell इतिहास**](windows-local-privilege-escalation/#powershell-history) में पासवर्ड?
- [ ] [**इंटरनेट सेटिंग्स**](windows-local-privilege-escalation/#internet-settings) में दिलचस्प जानकारी?
- [ ] [**ड्राइव**](windows-local-privilege-escalation/#drives)?
- [ ] [**WSUS शोषण**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [लॉगिंग/AV एन्यूमरेशन](windows-local-privilege-escalation/#enumeration)

- [ ] [**ऑडिट** ](windows-local-privilege-escalation/#audit-settings) और [**WEF** ](windows-local-privilege-escalation/#wef) सेटिंग्स की जांच करें
- [ ] [**LAPS**](windows-local-privilege-escalation/#laps) की जांच करें
- [ ] जांचें कि [**WDigest** ](windows-local-privilege-escalation/#wdigest) सक्रिय है या नहीं
- [ ] [**LSA सुरक्षा**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**क्रेडेंशियल्स गार्ड**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**कैश किए गए क्रेडेंशियल्स**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] क्या कोई [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) है
- [ ] [**AppLocker नीति**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**उपयोगकर्ता विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups)
- [ ] [**वर्तमान** उपयोगकर्ता **विशेषाधिकार**](windows-local-privilege-escalation/#users-and-groups) की जांच करें
- [ ] क्या आप [**किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] क्या आपके पास [इनमें से कोई टोकन सक्षम है](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**उपयोगकर्ता सत्र**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] [**उपयोगकर्ताओं के घरों**](windows-local-privilege-escalation/#home-folders) की जांच करें (पहुँच?)
- [ ] [**पासवर्ड नीति**](windows-local-privilege-escalation/#password-policy) की जांच करें
- [ ] [**क्लिपबोर्ड के अंदर**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) क्या है?

### [नेटवर्क](windows-local-privilege-escalation/#network)

- [ ] **वर्तमान** [**नेटवर्क** **जानकारी**](windows-local-privilege-escalation/#network) की जांच करें
- [ ] **छिपी हुई स्थानीय सेवाओं** की जांच करें जो बाहर से प्रतिबंधित हैं

### [चल रहे प्रक्रियाएँ](windows-local-privilege-escalation/#running-processes)

- [ ] प्रक्रियाओं के बाइनरी [**फाइल और फ़ोल्डर अनुमतियाँ**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**मेमोरी पासवर्ड खनन**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**असुरक्षित GUI ऐप्स**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] क्या आप `ProcDump.exe` के माध्यम से **दिलचस्प प्रक्रियाओं** के साथ क्रेडेंशियल चुरा सकते हैं? (फायरफॉक्स, क्रोम, आदि ...)

### [सेवाएँ](windows-local-privilege-escalation/#services)

- [ ] [क्या आप **किसी सेवा को संशोधित कर सकते हैं**?](windows-local-privilege-escalation/#permissions)
- [ ] [क्या आप **किसी सेवा द्वारा** **निष्पादित** **बाइनरी** को **संशोधित** कर सकते हैं?](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [क्या आप किसी **सेवा** के **पंजीकरण** को **संशोधित** कर सकते हैं?](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [क्या आप किसी **अनकोटेड सेवा** बाइनरी **पथ** का लाभ उठा सकते हैं?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**ऐप्लिकेशन**](windows-local-privilege-escalation/#applications)

- [ ] [**स्थापित ऐप्लिकेशन**](windows-local-privilege-escalation/#write-permissions) पर **लिखने** की अनुमतियाँ
- [ ] [**स्टार्टअप ऐप्लिकेशन**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **कमजोर** [**ड्राइवर**](windows-local-privilege-escalation/#drivers)

### [DLL हाइजैकिंग](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] क्या आप **PATH के अंदर किसी फ़ोल्डर में लिख सकते हैं**?
- [ ] क्या कोई ज्ञात सेवा बाइनरी है जो **किसी गैर-मौजूद DLL को लोड करने की कोशिश करती है**?
- [ ] क्या आप **किसी बाइनरी फ़ोल्डर में लिख सकते हैं**?

### [नेटवर्क](windows-local-privilege-escalation/#network)

- [ ] नेटवर्क का एन्यूमरेशन करें (शेयर, इंटरफेस, मार्ग, पड़ोसी, ...)
- [ ] लोकलहोस्ट (127.0.0.1) पर सुनने वाली नेटवर्क सेवाओं पर विशेष ध्यान दें

### [Windows क्रेडेंशियल्स](windows-local-privilege-escalation/#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials) क्रेडेंशियल्स
- [ ] [**Windows वॉल्ट**](windows-local-privilege-escalation/#credentials-manager-windows-vault) क्रेडेंशियल्स जो आप उपयोग कर सकते हैं?
- [ ] दिलचस्प [**DPAPI क्रेडेंशियल्स**](windows-local-privilege-escalation/#dpapi)?
- [ ] [**Wifi नेटवर्क**](windows-local-privilege-escalation/#wifi) के पासवर्ड?
- [ ] [**सहेजे गए RDP कनेक्शन**](windows-local-privilege-escalation/#saved-rdp-connections) में दिलचस्प जानकारी?
- [ ] [**हाल ही में चलाए गए कमांड**](windows-local-privilege-escalation/#recently-run-commands) में पासवर्ड?
- [ ] [**रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**](windows-local-privilege-escalation/#remote-desktop-credential-manager) पासवर्ड?
- [ ] [**AppCmd.exe** मौजूद है](windows-local-privilege-escalation/#appcmd-exe)? क्रेडेंशियल्स?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL साइड लोडिंग?

### [फाइलें और रजिस्ट्र्री (क्रेडेंशियल्स)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**क्रेड्स**](windows-local-privilege-escalation/#putty-creds) **और** [**SSH होस्ट कुंजी**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**रजिस्ट्र्री में SSH कुंजी**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] [**अनटेंडेड फाइलों**](windows-local-privilege-escalation/#unattended-files) में पासवर्ड?
- [ ] कोई [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) बैकअप?
- [ ] [**क्लाउड क्रेडेंशियल्स**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) फ़ाइल?
- [ ] [**कैश किए गए GPP पासवर्ड**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] [**IIS वेब कॉन्फ़िग फ़ाइल**](windows-local-privilege-escalation/#iis-web-config) में पासवर्ड?
- [ ] [**वेब** **लॉग्स**](windows-local-privilege-escalation/#logs) में दिलचस्प जानकारी?
- [ ] क्या आप उपयोगकर्ता से [**क्रेडेंशियल्स**](windows-local-privilege-escalation/#ask-for-credentials) मांगना चाहते हैं?
- [ ] [**रीसाइक्ल बिन के अंदर दिलचस्प फाइलें**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] अन्य [**पंजीकरण जिसमें क्रेडेंशियल्स हैं**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] [**ब्राउज़र डेटा के अंदर**](windows-local-privilege-escalation/#browsers-history) (dbs, इतिहास, बुकमार्क, ...)?
- [ ] [**फाइलों और रजिस्ट्र्री में सामान्य पासवर्ड खोज**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
- [ ] पासवर्ड के लिए स्वचालित रूप से खोजने के लिए [**उपकरण**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [लीक हुए हैंडलर्स](windows-local-privilege-escalation/#leaked-handlers)

- [ ] क्या आपके पास किसी प्रक्रिया के हैंडलर तक पहुंच है जो व्यवस्थापक द्वारा चलायी जाती है?

### [पाइप क्लाइंट अनुकरण](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] जांचें कि क्या आप इसका दुरुपयोग कर सकते हैं

{{#include ../banners/hacktricks-training.md}}
