# चेकलिस्ट - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors को खोजने का सर्वश्रेष्ठ टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] प्राप्त करें [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] खोजें **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] उपयोग करें **Google to search** kernel **exploits** के लिए
- [ ] उपयोग करें **searchsploit to search** kernel **exploits** के लिए
- [ ] क्या दिलचस्प जानकारी है [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] क्या पासवर्ड हैं [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) में?
- [ ] क्या दिलचस्प जानकारी है [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] क्या [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] क्या [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] क्या [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] क्या [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] जाँच करें [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)और [**WEF** ](windows-local-privilege-escalation/index.html#wef)settings
- [ ] जाँच करें [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] जाँच करें कि [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)active है या नहीं
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] जाँच करें क्या कोई [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) है
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] जाँच करें [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] जाँच करें [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] जाँच करें [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] क्या आप [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] जाँच करें क्या आपके पास इनमें से कोई टोकन enabled हैं ( [**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**](windows-local-privilege-escalation/index.html#token-manipulation) ) ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] जाँच करें [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] जाँच करें [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] क्या है [ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] जाँच करें **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] जाँच करें बाहर की ओर restricted किसी भी hidden local services

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries के [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] चुराएँ credentials **interesting processes** से `ProcDump.exe` का उपयोग करके ? (firefox, chrome, आदि ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] क्या आप किसी service को **modify** कर सकते हैं? (Can you **modify any service**?)
- [ ] क्या आप किसी service द्वारा execute किए जाने वाले **binary** को **modify** कर सकते हैं? (Can you **modify** the **binary** that is **executed** by any **service**?)
- [ ] क्या आप किसी service के **registry** को **modify** कर सकते हैं? (Can you **modify** the **registry** of any **service**?)
- [ ] क्या आप किसी unquoted service binary **path** का फायदा उठा सकते हैं? (Can you take advantage of any **unquoted service** binary **path**?)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] इंस्टॉल की गई applications पर **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] जाँच करें [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] क्या आप PATH के किसी भी फ़ोल्डर में **write** कर सकते हैं?
- [ ] क्या कोई ज्ञात service binary है जो किसी non-existant DLL को load करने की कोशिश करता है?
- [ ] क्या आप किसी **binaries folder** में **write** कर सकते हैं?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] नेटवर्क enumerate करें (shares, interfaces, routes, neighbours, ...)
- [ ] खास ध्यान दें localhost (127.0.0.1) पर सुनने वाली network services पर

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] क्या उपयोगी हैं [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials?
- [ ] दिलचस्प [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] saved [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) के पासवर्ड?
- [ ] saved RDP Connections में दिलचस्प जानकारी? [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] क्या पासवर्ड हैं [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) में?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords?
- [ ] क्या [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] क्या [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] क्या हैं [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] क्या पासवर्ड हैं [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] क्या कोई [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup है?
- [ ] क्या [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] क्या मौजूद है [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] क्या [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] क्या पासवर्ड है [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] क्या दिलचस्प जानकारी है [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] क्या आप उपयोगकर्ता से [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) चाहेंगे?
- [ ] क्या दिलचस्प फ़ाइलें हैं [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] अन्य [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] ब्राउज़र डेटा के अंदर (dbs, history, bookmarks, ...) ? [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history)
- [ ] फाइलों और रजिस्ट्री में [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] पासवर्ड स्वचालित रूप से खोजने के लिए [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] क्या आपके पास किसी administrator द्वारा चलाए गए process का कोई handler access है?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] जाँच करें कि क्या आप इसका अपव्यवहार कर सकते हैं

{{#include ../banners/hacktricks-training.md}}
