# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectorsını aramak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) elde et
- [ ] [scriptler kullanarak](windows-local-privilege-escalation/index.html#version-exploits) **kernel** [**exploits**](windows-local-privilege-escalation/index.html#version-exploits) ara
- [ ] **kernel exploits** için **Google** ile ara
- [ ] **kernel exploits** için **searchsploit** kullanarak ara
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) içinde ilginç bilgi var mı?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) içinde şifreler var mı?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) içinde ilginç bilgi var mı?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)ve [**WEF** ](windows-local-privilege-escalation/index.html#wef)ayarlarını kontrol et
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) kontrol et
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktif mi kontrol et
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) var mı kontrol et
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] geçerli kullanıcının [**privileges**](windows-local-privilege-escalation/index.html#users-and-groups) kontrol et
- [ ] herhangi bir [**privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) üyesi misin?
- [ ] [**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**]([windows-local-privilege-escalation/index.html#token-manipulation](windows-local-privilege-escalation/index.html#token-manipulation)) tokenlarından herhangi biri etkin mi kontrol et?
- [ ] ham volumes okumak ve file ACL'lerini bypass etmek için [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) var mı kontrol et
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) kontrol et (erişim?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) kontrol et
- [ ] [**Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) içinde ne var?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] geçerli [**network** **information**](windows-local-privilege-escalation/index.html#network) kontrol et
- [ ] dışarıya kısıtlı gizli local services kontrol et

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Process binary'lerinin [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) kontrol et
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` ile ilginç processlerden credentials çal? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] herhangi bir service'i [**modify**](windows-local-privilege-escalation/index.html#permissions) edebilir misin?
- [ ] herhangi bir **service** tarafından **executed** edilen **binary**'yi [**modify**](windows-local-privilege-escalation/index.html#modify-service-binary-path) edebilir misin?
- [ ] herhangi bir **service**'in **registry**'sini [**modify**](windows-local-privilege-escalation/index.html#services-registry-modify-permissions) edebilir misin?
- [ ] herhangi bir **unquoted service** binary **path** avantajından yararlanabilir misin?
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] yüklü applications üzerinde **write** [**permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH içindeki herhangi bir folder'a **write** edebiliyor musun?
- [ ] bilinen herhangi bir service binary'si var mı, var olmayan herhangi bir DLL yüklemeye çalışıyor?
- [ ] herhangi bir **binaries folder** içine **write** edebiliyor musun?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] network'ü enumerate et (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) üzerinde dinleyen network services'e özellikle bak

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] kullanabileceğin [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials var mı?
- [ ] ilginç [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] kayıtlı [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) şifreleri?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) içinde ilginç bilgi var mı?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) içinde şifreler?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) şifreleri?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **ve** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) içinde şifreler?
- [ ] herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] Eğer [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) varsa, `SAM`, `SYSTEM`, DPAPI material ve `MachineKeys` için raw-volume reads dene
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) içinde şifre?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) içinde ilginç bilgi var mı?
- [ ] kullanıcıya [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) sormak ister misin?
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) içindeki ilginç files?
- [ ] credentials içeren başka [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) içinde (dbs, history, bookmarks, ...)?
- [ ] files ve registry içinde [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] şifreleri otomatik aramak için [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] administrator tarafından çalıştırılan herhangi bir process'in handler'ına erişimin var mı?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] bunu kötüye kullanıp kullanamayacağını kontrol et



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
