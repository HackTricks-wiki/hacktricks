# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vector'lerini aramak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) elde et
- [ ] [**scripts kullanarak kernel exploit'lerini**](windows-local-privilege-escalation/index.html#version-exploits) ara
- [ ] Kernel **exploit'lerini aramak için Google kullan**
- [ ] Kernel **exploit'lerini aramak için searchsploit kullan**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) içinde ilginç bilgiler var mı?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) içinde password'ler var mı?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) içinde ilginç bilgiler var mı?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)ve [**WEF** ](windows-local-privilege-escalation/index.html#wef)settings'i kontrol et
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps)'i kontrol et
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)'in aktif olup olmadığını kontrol et
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) olup olmadığını kontrol et
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**current**] kullanıcının **privileges**'ını kontrol et [**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**privileged group'lardan herhangi birinin üyesi misin**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Şu [token'ların etkin olup olmadığını kontrol et](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Raw volume'ları okumak ve file ACL'lerini bypass etmek için [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) yetkisine sahip misin?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [ **users homes**](windows-local-privilege-escalation/index.html#home-folders)'u kontrol et (erişim var mı?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)'yi kontrol et
- [ ] [**Clipboard'ın içinde**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ne var?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)'ı kontrol et
- [ ] Dışarıya erişimi kısıtlanmış **hidden local services**'leri kontrol et

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Process binary'lerinin [**file ve folder permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)'larını kontrol et
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` aracılığıyla **ilginç process'lerden** credential çalabilir misin? (firefox, chrome, vb. ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Herhangi bir **service'i değiştirebilir misin**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] Herhangi bir **service** tarafından **execute edilen** [**binary'yi değiştirebilir misin**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Herhangi bir **service'in** [**registry'sini değiştirebilir misin**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Herhangi bir **unquoted service** binary **path'inden** yararlanabilir misin?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: privileged service'leri enumerate et ve tetikle](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Yüklü application'larda** [**write permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] **PATH içindeki herhangi bir folder'a write yapabilir misin**?
- [ ] Herhangi bir bilinen service binary'si **mevcut olmayan bir DLL'i yüklemeye** çalışıyor mu?
- [ ] Herhangi bir **binaries folder'ına write** yapabilir misin?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Network'ü enumerate et (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) üzerinde listening durumundaki network services'lerine özellikle bak

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] Kullanabileceğin [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials'ları var mı?
- [ ] İlginç [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) var mı?
- [ ] Kayıtlı [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)'ün password'leri
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) içinde ilginç bilgiler var mı?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) içinde password'ler var mı?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) password'leri?
- [ ] [**AppCmd.exe exists**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **ve** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**registry'deki SSH keys**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) içinde password'ler var mı?
- [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup'ı var mı?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) mevcutsa `SAM`, `SYSTEM`, DPAPI material ve `MachineKeys` için raw-volume read'leri dene
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file'ı?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) içinde password var mı?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) içinde ilginç bilgiler var mı?
- [ ] Kullanıcıdan [**credential istemek**](windows-local-privilege-escalation/index.html#ask-for-credentials) ister misin?
- [ ] [**Recycle Bin içindeki file'lar**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) içinde ilginç bilgiler var mı?
- [ ] Credential içeren başka [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry) var mı?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) içinde (db'ler, history, bookmarks, ...)?
- [ ] File'larda ve registry'de [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] Password'leri otomatik olarak aramak için [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Administrator tarafından çalıştırılan bir process'in herhangi bir handler'ına erişimin var mı?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Bunu abuse edip edemeyeceğini kontrol et

## References

- [1] [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
