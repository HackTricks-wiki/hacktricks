# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Elde et [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Ara **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] **Google** ile kernel **exploits** için ara
- [ ] **searchsploit** ile kernel **exploits** ara
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) içinde ilginç bilgi var mı?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) içinde parolalar var mı?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) içinde ilginç bilgi var mı?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) ve [**WEF** ](windows-local-privilege-escalation/index.html#wef) ayarlarını kontrol et
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) kontrol et
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) etkin mi kontrol et
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) var mı kontrol et
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) kontrol et
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups) kontrol et
- [ ] [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) misiniz?
- [ ] [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation) sahibi olup olmadığını kontrol et: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (erişim?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) kontrol et
- [ ] Nedir[ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] [**current**](windows-local-privilege-escalation/index.html#network) **network** **information** kontrol et
- [ ] Dış erişime kısıtlı gizli local servisleri kontrol et

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] İlginç process'lerle kimlik bilgilerini çalmak için `ProcDump.exe` kullanabilir misiniz? (firefox, chrome, vb.)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Herhangi bir servisi **modify** edebilir misiniz? (değiştirme izinleri) [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] Herhangi bir servisin **çalıştırdığı binary'i modify** edebilir misiniz? [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Herhangi bir servisin **registry**sini modify edebilir misiniz? [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Hiçbir tırnak içermeyen (unquoted) servis binary path'inden faydalanabilir misiniz? [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] Service Triggers: ayrı olarak enumerate et ve privileged servisleri trigger et (service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] Yüklü uygulamalarda **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH içindeki herhangi bir klasöre **yazabilir** misiniz?
- [ ] Bilinen bir servis binary'si herhangi bir non-existant DLL yüklemeye çalışıyor mu?
- [ ] Herhangi bir **binaries folder** içine **yazabilir** misiniz?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Ağı enumerate et (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) üzerinde dinleyen network servislerine özel dikkat göster

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kullanabileceğin credential'lar var mı?
- [ ] İlginç [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Kaydedilmiş [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) parolaları?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) içinde ilginç bilgi?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) içinde parolalar?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) parolaları?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credential'lar?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) içinde parolalar?
- [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) yedeği var mı?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) dosyası?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) içinde parola?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) içinde ilginç bilgi?
- [ ] Kullanıcıdan [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) istemek ister misin?
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) içindeki ilginç dosyalar?
- [ ] Diğer [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) içinde mi? (dbs, history, bookmarks, ...)
- [ ] Dosya ve registry içinde [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] Parolaları otomatik arayan [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Administrator tarafından çalıştırılan bir process'e ait herhangi bir handler'a erişiminiz var mı?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Bunu suistimal edip edemeyeceğini kontrol et

{{#include ../banners/hacktricks-training.md}}
