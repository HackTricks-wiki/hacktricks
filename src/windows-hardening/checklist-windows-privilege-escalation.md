# Checklist - Yerel Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows yerel privilege escalation vektörlerini aramak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) edinin
- [ ] [**Script'leri kullanarak exploit'leri**](windows-local-privilege-escalation/index.html#version-exploits) arayın
- [ ] Kernel **exploit'lerini aramak için Google'ı kullanın**
- [ ] Kernel **exploit'lerini aramak için searchsploit kullanın**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) içinde ilginç bilgiler var mı?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) içinde password'ler var mı?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) içinde ilginç bilgiler var mı?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) ve [**WEF** ](windows-local-privilege-escalation/index.html#wef) ayarlarını kontrol edin
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) kontrolü yapın
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)'in aktif olup olmadığını kontrol edin
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) olup olmadığını kontrol edin
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**current**] kullanıcının [**privileges**](windows-local-privilege-escalation/index.html#users-and-groups) bilgilerini kontrol edin
- [ ] [**privileged group'lardan herhangi birinin üyesi misiniz**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Şu [token'ların etkin olup olmadığını](windows-local-privilege-escalation/index.html#token-manipulation) kontrol edin: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Raw volume'ları okumak ve file ACL'lerini bypass etmek için [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) yetkiniz var mı kontrol edin
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (erişim var mı?) kontrol edin
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) kontrolü yapın
- [ ] [**Clipboard'ın içinde**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ne var?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] **current** [**network** **information**](windows-local-privilege-escalation/index.html#network) bilgilerini kontrol edin
- [ ] Dışarıya erişimi kısıtlanmış **hidden local services**'leri kontrol edin

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Process binary'lerinin [**file ve folder permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) bilgilerini kontrol edin
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` kullanarak **ilginç process'ler** üzerinden credential'ları çalabilir misiniz? (firefox, chrome vb. ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Herhangi bir **service'i modify edebilir misiniz**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] Herhangi bir **service** tarafından **execute edilen** [**binary'yi modify edebilir misiniz**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Herhangi bir **service'in** [**registry'sini modify edebilir misiniz**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Herhangi bir **unquoted service** binary **path**'inden yararlanabilir misiniz?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: privileged service'leri enumerate ve trigger edin](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] [**installed applications üzerindeki write permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] **PATH içindeki herhangi bir folder'a write edebilir misiniz**?
- [ ] **Var olmayan herhangi bir DLL'i load etmeye çalışan bilinen bir service binary'si var mı**?
- [ ] Herhangi bir **binary folder'ına** **write** edebilir misiniz?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Network'ü enumerate edin (shares, interfaces, routes, neighbours, ...)
- [ ] localhost'ta (127.0.0.1) listening durumundaki network service'lerine özellikle bakın

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credential'ları
- [ ] Kullanabileceğiniz [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credential'ları var mı?
- [ ] İlginç [**DPAPI credential'ları**](windows-local-privilege-escalation/index.html#dpapi) var mı?
- [ ] Kayıtlı [**Wifi network'lerinin**](windows-local-privilege-escalation/index.html#wifi) password'leri
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) içinde ilginç bilgiler var mı?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) içinde password'ler var mı?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) password'leri?
- [ ] [**AppCmd.exe mevcut mu**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credential'lar?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **ve** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Registry'deki SSH key'leri**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) içinde password'ler var mı?
- [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup'ı var mı?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) mevcutsa `SAM`, `SYSTEM`, DPAPI material'ı ve `MachineKeys` için raw-volume okumalarını deneyin
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file'ı?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) içinde password var mı?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) içinde ilginç bilgiler var mı?
- [ ] Kullanıcıdan credential [**istemek**](windows-local-privilege-escalation/index.html#ask-for-credentials) ister misiniz?
- [ ] [**Recycle Bin içindeki file'lar**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) içinde ilginç bilgiler var mı?
- [ ] Credential içeren başka [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry) alanları var mı?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) içinde (db'ler, history, bookmarks, ...)?
- [ ] File ve registry'de [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] Password'leri otomatik olarak arayan [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Administrator tarafından çalıştırılan bir process'in herhangi bir handler'ına erişiminiz var mı?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Abuse edip edemeyeceğinizi kontrol edin

## References

- [1] [Project Zero - UI Access Abuse ile Administrator Protection'ı Bypass Etme](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
