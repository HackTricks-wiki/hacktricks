# Kontrol Listesi - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vektörlerini araştırmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) elde et
- [ ] **kernel** için [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits) ara
- [ ] Google'ı kullanarak kernel **exploits** ara
- [ ] searchsploit kullanarak kernel **exploits** ara
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) içinde ilginç bilgiler var mı?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) içinde parolalar var mı?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) içinde ilginç bilgiler var mı?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives) var mı?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus) var mı?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md) kontrol et
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) etkin mi?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) ve [**WEF**](windows-local-privilege-escalation/index.html#wef) ayarlarını kontrol et
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) kontrol et
- [ ] [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) aktif mi?
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection) etkin mi?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials) etkin mi?
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials) var mı?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) var mı?
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) kontrol et
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) kontrol et
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups) kontrol et
- [ ] [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups) kontrol et
- [ ] [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) üyesi misiniz?
- [ ] [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation) var mı: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions) var mı?
- [ ] [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) kontrol et (erişim?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) kontrol et
- [ ] Panodaki içerik nedir: [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] **current** [**network** **information**](windows-local-privilege-escalation/index.html#network) kontrol et
- [ ] Dışarıya kapalı gizli local servisleri kontrol et

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Process binary'lerinin [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) kontrol et
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining) kontrol et
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps) kontrol et
- [ ] `ProcDump.exe` ile **interesting processes** üzerinden kimlik bilgisi çalın? (firefox, chrome, vb ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions) kontrol et
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path) kontrol et
- [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions) kontrol et
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths) yararlanılabilir mi?

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Yazma** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions) izni var mı?
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup) kontrol et
- [ ] **Zayıf** [**Drivers**](windows-local-privilege-escalation/index.html#drivers) var mı?

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH içindeki herhangi bir klasöre **yazabilir misiniz**?
- [ ] Bilinen bir servis binary'si herhangi bir mevcut olmayan DLL'i yüklemeye çalışıyor mu?
- [ ] Herhangi bir **binaries folder**'a yazma izniniz var mı?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Ağı enumerate et (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) üzerinde dinleyen network servislerine özellikle bak

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] Kullanabileceğiniz [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials var mı?
- [ ] İlginç [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) var mı?
- [ ] Kaydedilmiş [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) şifreleri var mı?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) içinde ilginç bilgiler var mı?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) içinde parolalar var mı?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) parolaları?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials var mı?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **ve** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) var mı?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) içinde parolalar var mı?
- [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) yedeği var mı?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials) var mı?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) dosyası var mı?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) var mı?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) içindeki parola?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) içinde ilginç bilgiler var mı?
- [ ] Kullanıcıdan [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) istemek ister misiniz?
- [ ] [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) içinde ilginç dosyalar var mı?
- [ ] Diğer [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry) kayıtlarını kontrol et
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) içinde (dbs, history, bookmarks, ...) var mı?
- [ ] Dosyalarda ve registry'de [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) yap
- [ ] Parolaları otomatik aramak için [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) kullan

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Yönetici tarafından çalıştırılan bir process'in herhangi bir handler'ına erişiminiz var mı?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Bunu kötüye kullanıp kullanamayacağınızı kontrol et

{{#include ../banners/hacktricks-training.md}}
