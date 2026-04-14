# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors ढूँढने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) प्राप्त करें
- [ ] script का उपयोग करके **kernel** [**exploits**](windows-local-privilege-escalation/index.html#version-exploits) खोजें
- [ ] kernel **exploits** खोजने के लिए **Google** का उपयोग करें
- [ ] kernel **exploits** खोजने के लिए **searchsploit** का उपयोग करें
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) में interesting info?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) में passwords?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) में interesting info?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)और [**WEF** ](windows-local-privilege-escalation/index.html#wef) settings check करें
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) check करें
- [ ] check करें कि [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) active है या नहीं
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] देखें कि कोई [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) है या नहीं
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] वर्तमान user [**privileges**](windows-local-privilege-escalation/index.html#users-and-groups) check करें
- [ ] क्या आप किसी [**privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) के member हैं?
- [ ] check करें कि क्या आपके पास इनमें से कोई token enabled है: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] check करें कि raw volumes पढ़ने और file ACLs bypass करने के लिए आपके पास [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) है या नहीं
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) check करें (access?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) check करें
- [ ] [**Clipboard के अंदर**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) क्या है?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] वर्तमान [**network** **information**](windows-local-privilege-escalation/index.html#network) check करें
- [ ] बाहर से restricted hidden local services check करें

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] **ProcDump.exe** के जरिए **interesting processes** से credentials चुराएँ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] क्या आप कोई भी **service modify** कर सकते हैं?
- [ ] क्या आप किसी **service** द्वारा execute किए गए **binary** को **modify** कर सकते हैं?
- [ ] क्या आप किसी **service** की **registry** को **modify** कर सकते हैं?
- [ ] क्या आप किसी **unquoted service** binary **path** का फायदा उठा सकते हैं?
- [ ] [Service Triggers: privileged services enumerate और trigger करें](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] installed applications पर **Write** [**permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] क्या आप PATH के अंदर किसी भी folder में **write** कर सकते हैं?
- [ ] क्या कोई known service binary है जो किसी non-existant DLL को load करने की कोशिश करता है?
- [ ] क्या आप किसी **binaries folder** में **write** कर सकते हैं?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] network enumerate करें (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) पर listening network services पर खास ध्यान दें

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials जो आप use कर सकते हैं?
- [ ] interesting [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] saved [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) के passwords?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) में interesting info?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) में passwords?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) के passwords?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **और** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) में passwords?
- [ ] कोई [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] यदि [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) मौजूद है, तो `SAM`, `SYSTEM`, DPAPI material, और `MachineKeys` के लिए raw-volume reads try करें
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) में password?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) में interesting info?
- [ ] क्या आप user से [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) करना चाहते हैं?
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) के अंदर interesting [**files**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] अन्य [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) के अंदर (dbs, history, bookmarks, ...)?
- [ ] files और registry में [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] passwords automatically search करने के लिए [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] क्या आपके पास administrator द्वारा run किए गए किसी process के किसी handler तक access है?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] check करें कि क्या आप इसका abuse कर सकते हैं



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
