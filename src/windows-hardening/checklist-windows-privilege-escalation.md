# Kontrol Listesi - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Elde edin [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Ara **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] **Google to search** ile kernel **exploits** için ara
- [ ] **searchsploit to search** ile kernel **exploits** için ara
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) içinde ilginç bilgi var mı?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) içinde parolalar var mı?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) içinde ilginç bilgi var mı?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kontrol edin [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) ve [**WEF** ](windows-local-privilege-escalation/index.html#wef) ayarlarını
- [ ] Kontrol edin [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) aktif mi kontrol edin
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) kontrol edin
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) kontrol edin
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Mevcut kullanıcı [**privileges**](windows-local-privilege-escalation/index.html#users-and-groups) kontrol edin
- [ ] Herhangi bir [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) misiniz?
- [ ] Aşağıdaki token'lara sahip misiniz kontrol edin (enabled): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) kontrol edin (erişim?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) kontrol edin
- [ ] [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) içinde ne var?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Mevcut [**network information**](windows-local-privilege-escalation/index.html#network) kontrol edin
- [ ] Dışa kapalı gizli local servisleri kontrol edin

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Process binary'lerinin [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) izinlerini kontrol edin
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] İlginç process'lerle **ProcDump.exe** kullanarak kimlik bilgilerini çalın? (firefox, chrome, vb.)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Herhangi bir service'yi **değiştirebilir** misiniz? (modify) (permissions) [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] Herhangi bir service tarafından **çalıştırılan binary'yi** **değiştirebilir** misiniz? [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Herhangi bir service'in **registry**'sini **değiştirebilir** misiniz? [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Herhangi bir **unquoted service** binary **path**'inden yararlanabilir misiniz? [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] Yüklü uygulamalarda **write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH içindeki herhangi bir klasöre **yazabilir** misiniz?
- [ ] Hiçbir servisin bilinen ve **olmayan** bir DLL'i yüklemeye çalıştığı biliniyor mu?
- [ ] Herhangi bir **binaries folder** içine **yazabilir** misiniz?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Ağı enumerate edin (shares, interfaces, routes, neighbours, ...)
- [ ] Localhost (127.0.0.1) üzerinde dinleyen network servislerine özellikle bakın

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) kimlik bilgileri
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kullanabileceğiniz kimlik bilgileri var mı?
- [ ] İlginç [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Kaydedilmiş [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) parolaları?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) içinde ilginç bilgi?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) içinde parolalar var mı?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) parolaları?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Kimlik bilgileri?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) içinde parolalar?
- [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) yedeği var mı?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) dosyası?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) içindeki parola?
- [ ] [**web logs**](windows-local-privilege-escalation/index.html#logs) içinde ilginç bilgi?
- [ ] Kullanıcıdan [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) ister misiniz?
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) içindeki ilginç dosyalar?
- [ ] Diğer [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) içinde (dbs, history, bookmarks, ...)?
- [ ] Dosya ve registry'de [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] Parola aramak için [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Yönetici tarafından çalıştırılan bir process'in herhangi bir handler'ına erişiminiz var mı?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kötüye kullanıp kullanamayacağınızı kontrol edin

{{#include ../banners/hacktricks-training.md}}
