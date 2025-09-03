# चेकलिस्ट - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने का सबसे अच्छा टूल:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] प्राप्त करें [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] खोजें **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] kernel **exploits** खोजने के लिए **Google** का उपयोग करें
- [ ] kernel **exploits** खोजने के लिए **searchsploit** का उपयोग करें
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) में कोई रोचक जानकारी?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) में पासवर्ड?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) में कोई रोचक जानकारी?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] जांचें [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)और [**WEF** ](windows-local-privilege-escalation/index.html#wef)settings
- [ ] जांचें [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] जांचें क्या [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)सक्रिय है
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] जांचें क्या कोई [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] जांचें [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] क्या आप [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] जांचें क्या आपके पास इनमें से कोई token सक्षम है](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] जांचें[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] जांचें [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] क्या है[ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] जांचें **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] बाहरी से restricted छिपी हुई local services की जाँच करें

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries के [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` से रोचक processes के साथ क्रेडेंशियल चुराएँ ? (firefox, chrome, आदि ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] क्या आप किसी भी service को **modify** कर सकते हैं? (permissions) (Can you **modify any service**?)
- [ ] क्या आप किसी भी service द्वारा **execute** किए जाने वाले **binary** को **modify** कर सकते हैं? (Can you **modify** the **binary** that is **executed** by any **service**?)
- [ ] क्या आप किसी भी service के **registry** को **modify** कर सकते हैं? (Can you **modify** the **registry** of any **service**?)
- [ ] क्या आप किसी भी **unquoted service** binary **path** का फायदा उठा सकते हैं? (unquoted service paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] इंस्टॉल किए गए applications पर **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] क्या आप PATH के किसी भी फोल्डर में **write** कर सकते हैं? (Can you **write in any folder inside PATH**?)
- [ ] क्या कोई जाना-पहचाना service binary है जो कोई non-existant DLL लोड करने की कोशिश करता है?
- [ ] क्या आप किसी भी **binaries folder** में **write** कर सकते हैं?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] नेटवर्क का enumeration करें (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) पर सुनने वाली network services पर विशेष ध्यान दें

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] क्या उपयोग करने योग्य [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials हैं?
- [ ] रोचक [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] सेव्ड [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) के पासवर्ड?
- [ ] सेव्ड RDP कनेक्शनों में रोचक जानकारी [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) में पासवर्ड?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) पासवर्ड?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) में पासवर्ड?
- [ ] कोई [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) फाइल?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) में पासवर्ड?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) में रोचक जानकारी?
- [ ] क्या आप उपयोगकर्ता से क्रेडेंशियल पूछना चाहेंगे? [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)
- [ ] रीसायकल बिन के अंदर रोचक [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] अन्य [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)
- [ ] ब्राउज़र डेटा के अंदर (dbs, history, bookmarks, ...) [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history)?
- [ ] फाइलों और रजिस्ट्री में [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] पासवर्ड ऑटोमेटिकली खोजने के लिए [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] क्या आपके पास किसी administrator द्वारा चलाए गए process का कोई handler है?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] जांचें क्या आप इसका दुरुपयोग कर सकते हैं

{{#include ../banners/hacktricks-training.md}}
