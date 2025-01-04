# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows स्थानीय विशेषाधिकार वृद्धि वेक्टर की खोज के लिए सबसे अच्छा उपकरण:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**सिस्टम जानकारी**](windows-local-privilege-escalation/index.html#system-info) प्राप्त करें
- [ ] **कर्नेल** [**एक्सप्लॉइट्स के लिए स्क्रिप्ट का उपयोग करें**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] कर्नेल **एक्सप्लॉइट्स** के लिए **गूगल से खोजें**
- [ ] कर्नेल **एक्सप्लॉइट्स** के लिए **searchsploit से खोजें**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) में दिलचस्प जानकारी?
- [ ] [**PowerShell इतिहास**](windows-local-privilege-escalation/index.html#powershell-history) में पासवर्ड?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) में दिलचस्प जानकारी?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) और [**WEF** ](windows-local-privilege-escalation/index.html#wef) सेटिंग्स की जांच करें
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) की जांच करें
- [ ] जांचें कि [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) सक्रिय है या नहीं
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] जांचें कि कोई [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) है या नहीं
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**वर्तमान** उपयोगकर्ता **विशेषाधिकार**](windows-local-privilege-escalation/index.html#users-and-groups) की जांच करें
- [ ] क्या आप [**किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] जांचें कि आपके पास [इनमें से कोई भी टोकन सक्षम है](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) की जांच करें (पहुँच?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) की जांच करें
- [ ] [**Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) के अंदर क्या है?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] **वर्तमान** [**नेटवर्क** **जानकारी**](windows-local-privilege-escalation/index.html#network) की जांच करें
- [ ] **छिपी हुई स्थानीय सेवाओं** की जांच करें जो बाहर के लिए प्रतिबंधित हैं

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] प्रक्रियाओं के बाइनरी [**फाइल और फ़ोल्डर अनुमतियाँ**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] क्या आप **दिलचस्प प्रक्रियाओं** के माध्यम से क्रेडेंशियल चुरा सकते हैं `ProcDump.exe` ? (फायरफॉक्स, क्रोम, आदि ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [क्या आप **किसी सेवा को संशोधित कर सकते हैं**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [क्या आप **किसी सेवा द्वारा ** निष्पादित **बाइनरी** को **संशोधित कर सकते हैं**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [क्या आप किसी **सेवा** के **रजिस्ट्री** को **संशोधित कर सकते हैं**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [क्या आप किसी **अनकोटेड सेवा** बाइनरी **पथ** का लाभ उठा सकते हैं?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **स्थापित अनुप्रयोगों पर** [**लिखने** की अनुमतियाँ](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **कमजोर** [**ड्राइवर**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] क्या आप **PATH के अंदर किसी फ़ोल्डर में लिख सकते हैं**?
- [ ] क्या कोई ज्ञात सेवा बाइनरी है जो **किसी गैर-मौजूद DLL को लोड करने की कोशिश करती है**?
- [ ] क्या आप **किसी बाइनरी फ़ोल्डर में लिख सकते हैं**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] नेटवर्क का एन्यूमरेट करें (शेयर, इंटरफेस, रूट, पड़ोसी, ...)
- [ ] लोकलहोस्ट (127.0.0.1) पर सुनने वाली नेटवर्क सेवाओं पर विशेष ध्यान दें

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) क्रेडेंशियल्स
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) क्रेडेंशियल्स जो आप उपयोग कर सकते हैं?
- [ ] दिलचस्प [**DPAPI क्रेडेंशियल्स**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) के पासवर्ड?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) में दिलचस्प जानकारी?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) में पासवर्ड?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) के पासवर्ड?
- [ ] [**AppCmd.exe** मौजूद है](windows-local-privilege-escalation/index.html#appcmd-exe)? क्रेडेंशियल्स?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL साइड लोडिंग?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **और** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) में पासवर्ड?
- [ ] कोई [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) बैकअप?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) फ़ाइल?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) में पासवर्ड?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) में दिलचस्प जानकारी?
- [ ] क्या आप [**credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) के लिए उपयोगकर्ता से पूछना चाहते हैं?
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) के अंदर दिलचस्प फ़ाइलें?
- [ ] अन्य [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) के अंदर (dbs, इतिहास, बुकमार्क, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) फ़ाइलों और रजिस्ट्री में
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) जो स्वचालित रूप से पासवर्ड खोजने के लिए हैं

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] क्या आपके पास किसी प्रक्रिया के हैंडलर तक पहुंच है जो व्यवस्थापक द्वारा चलायी जाती है?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] जांचें कि क्या आप इसका दुरुपयोग कर सकते हैं

{{#include ../banners/hacktricks-training.md}}
