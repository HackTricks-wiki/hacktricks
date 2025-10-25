# चेकलिस्ट - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors के लिए सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] प्राप्त करें [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] स्क्रिप्ट्स का उपयोग कर **kernel** [**exploits**](windows-local-privilege-escalation/index.html#version-exploits) खोजें
- [ ] **kernel exploits** खोजने के लिए **Google** का उपयोग करें
- [ ] **kernel exploits** खोजने के लिए **searchsploit** का उपयोग करें
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) में कोई दिलचस्प जानकारी?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) में पासवर्ड?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) में कोई दिलचस्प जानकारी?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) और [**WEF** ](windows-local-privilege-escalation/index.html#wef) सेटिंग्स जांचें
- [ ] जांचें [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] जांचें कि [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) सक्रिय है या नहीं
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] किसी भी [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) की जाँच करें
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) जांचें
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] वर्तमान उपयोगकर्ता के **privileges** जांचें (current)
- [ ] क्या आप किसी [**privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) के सदस्य हैं?
- [ ] जाँचें कि क्या आपके पास इन में से कोई टोकन सक्षम हैं: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] जाँचें[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) जांचें
- [ ] जानें कि क्लिपबोर्ड में क्या है: [ **inside the Clipboard** ](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] वर्तमान [**network information**](windows-local-privilege-escalation/index.html#network) जांचें
- [ ] बाहरी से प्रतिबंधित **hidden local services** की जाँच करें

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries के [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) जांचें
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` के जरिए रोचक processes से क्रेडेंशियल्स चुराएँ? (firefox, chrome, आदि ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] क्या आप किसी सर्विस को **modify** कर सकते हैं? (Can you **modify any service**?)
- [ ] क्या आप किसी सर्विस द्वारा execute किए जाने वाले **binary** को **modify** कर सकते हैं? (binary that is **executed** by any **service**?)
- [ ] क्या आप किसी सर्विस के **registry** को **modify** कर सकते हैं? (services registry modify permissions?)
- [ ] क्या आप किसी **unquoted service** binary **path** का फायदा उठा सकते हैं?
- [ ] Service Triggers: privileged services को enumerate और trigger करें (service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] इंस्टॉल किए गए applications पर **Write** [**permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] क्या आप PATH के किसी भी फोल्डर में **write** कर सकते हैं?
- [ ] क्या कोई ज्ञात सर्विस binary है जो किसी non-existant DLL को लोड करने की कोशिश करती है?
- [ ] क्या आप किसी **binaries folder** में **write** कर सकते हैं?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] नेटवर्क enumerate करें (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) पर सुनने वाली network services पर विशेष ध्यान दें

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] क्या उपयोग करने योग्य [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials हैं?
- [ ] दिलचस्प [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] सहेजे गए [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) के पासवर्ड?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) में कोई दिलचस्प जानकारी?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) में पासवर्ड?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) पासवर्ड?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] क्या registry में [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) हैं?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) में पासवर्ड?
- [ ] कोई [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) बैकअप?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) फाइल?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) में पासवर्ड?
- [ ] [**web logs**](windows-local-privilege-escalation/index.html#logs) में कोई दिलचस्प जानकारी?
- [ ] क्या आप user से क्रेडेंशियल्स माँगना चाहेंगे? ([**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials))
- [ ] [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) में कोई दिलचस्प चीज़?
- [ ] अन्य [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) के अंदर (dbs, history, bookmarks, ...)?
- [ ] फाइलों और रजिस्ट्री में [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] पासवर्ड अपने आप खोजने के लिए [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] क्या आपके पास किसी administrator द्वारा चलाए गए प्रोसेस का कोई handler access है?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] जाँचें कि क्या आप इसका दुरुपयोग कर सकते हैं

{{#include ../banners/hacktricks-training.md}}
