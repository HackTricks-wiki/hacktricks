# Checklist - स्थानीय Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने का सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) प्राप्त करें
- [ ] **kernel** [**exploits खोजने के लिए scripts का उपयोग करें**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] **kernel exploits खोजने के लिए Google का उपयोग करें**
- [ ] **kernel exploits खोजने के लिए searchsploit का उपयोग करें**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) में कोई दिलचस्प जानकारी?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) में passwords?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) में कोई दिलचस्प जानकारी?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)और [**WEF** ](windows-local-privilege-escalation/index.html#wef) settings जाँचें
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) जाँचें
- [ ] जाँचें कि [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) सक्रिय है या नहीं
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] जाँचें कि कोई [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) मौजूद है या नहीं
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] वर्तमान user के [**privileges**](windows-local-privilege-escalation/index.html#users-and-groups) जाँचें
- [ ] क्या आप किसी [**privileged group के member**](windows-local-privilege-escalation/index.html#privileged-groups) हैं?
- [ ] जाँचें कि ये [privileges वर्तमान token में मौजूद हैं](windows-local-privilege-escalation/access-tokens.md) या नहीं, भले ही वे **Disabled** दिखाए गए हों: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**। Disabled privilege को तभी enable किया जा सकता है, जब वह पहले से token में मौजूद हो।<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] जाँचें कि [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) volume-maintenance right के रूप में मौजूद है या नहीं। यह अपने-आप raw-volume read access नहीं देता; disk या volume खोलने के लिए अलग access requirements भी होती हैं।<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) जाँचें (access?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) जाँचें
- [ ] [**Clipboard के अंदर**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) क्या है?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] वर्तमान [**network information**](windows-local-privilege-escalation/index.html#network) जाँचें
- [ ] बाहर से प्रतिबंधित **hidden local services** जाँचें

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries की [**file और folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` के ज़रिए **दिलचस्प processes** (firefox, chrome, आदि ...) से credentials चुराएँ?

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [क्या आप किसी **service को modify** कर सकते हैं?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [क्या आप किसी **service** द्वारा **executed binary** को **modify** कर सकते हैं?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [क्या आप किसी **service की registry को modify** कर सकते हैं?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [क्या आप किसी **unquoted service binary path** का फ़ायदा उठा सकते हैं?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: privileged services की enumeration और उन्हें trigger करना](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Installed applications पर** [**Write permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] क्या आप PATH के किसी folder में **write** कर सकते हैं?
- [ ] क्या कोई ज्ञात service binary है जो **किसी ऐसी DLL को load करने की कोशिश करती है जो मौजूद नहीं है**?
- [ ] क्या आप किसी **binaries folder** में **write** कर सकते हैं?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Network की enumeration करें (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) पर सुन रही network services को विशेष रूप से जाँचें

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] क्या [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials हैं जिनका आप उपयोग कर सकते हैं?
- [ ] कोई दिलचस्प [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] सेव किए गए [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) के passwords?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) में कोई दिलचस्प जानकारी?
- [ ] [**हाल ही में चलाए गए commands**](windows-local-privilege-escalation/index.html#recently-run-commands) में passwords?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords?
- [ ] [**AppCmd.exe मौजूद है**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **और** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**registry में SSH keys**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) में passwords?
- [ ] कोई [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] अगर readable raw-volume handle की अनुमति अलग से है, तो `SAM`, `SYSTEM`, DPAPI material, और `MachineKeys` के संभावित exposure का आकलन करें; केवल **SeManageVolumePrivilege** के आधार पर इस access का अनुमान न लगाएँ।<sup>[[5]](#references)</sup>
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) में password?
- [ ] [**web logs**](windows-local-privilege-escalation/index.html#logs) में कोई दिलचस्प जानकारी?
- [ ] क्या आप user से [**credentials माँगना**](windows-local-privilege-escalation/index.html#ask-for-credentials) चाहते हैं?
- [ ] [**Recycle Bin में मौजूद files**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) दिलचस्प हैं?
- [ ] अन्य [**credentials वाली registry entries**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) के अंदर (dbs, history, bookmarks, ...)?
- [ ] files और registry में [**सामान्य password खोज**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] passwords को अपने-आप खोजने के लिए [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] क्या आपके पास administrator द्वारा चलाए जा रहे किसी process के handler का access है?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] जाँचें कि क्या आप इसका दुरुपयोग कर सकते हैं



## References

- [1] [Project Zero - UI Access का दुरुपयोग करके Administrator Protection को bypass करना](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Token में Privileges बदलना](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - Physical disks और volumes के लिए CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - File System में Privileges प्रबंधित करना](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
