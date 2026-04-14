# Checklist - ローカル Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows の local privilege escalation vector を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) を取得する
- [ ] スクリプトを使って **kernel** [**exploits**](windows-local-privilege-escalation/index.html#version-exploits) を検索する
- [ ] Google を使って kernel **exploits** を検索する
- [ ] searchsploit を使って kernel **exploits** を検索する
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) に興味深い情報はあるか?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) に passwords はあるか?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) に興味深い情報はあるか?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)と [**WEF** ](windows-local-privilege-escalation/index.html#wef)設定を確認する
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) を確認する
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) が有効か確認する
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] 何らかの [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) があるか確認する
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 現在の user の [**privileges**](windows-local-privilege-escalation/index.html#users-and-groups) を確認する
- [ ] [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) か?
- [ ] [**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**] のいずれかの token が有効か確認する?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) があり raw volumes を読み取り、file ACLs を bypass できるか確認する
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) を確認する (access?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) を確認する
- [ ] [**Clipboard** の中身](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) は何か?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 現在の [**network** **information**](windows-local-privilege-escalation/index.html#network) を確認する
- [ ] 外部から制限された hidden local services を確認する

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries の [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) を確認する
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` を使って **interesting processes** から credentials を盗む? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] 何らかの **service** を **modify** できる?
- [ ] 何らかの **service** によって **executed** される **binary** を **modify** できる?
- [ ] 何らかの **service** の **registry** を **modify** できる?
- [ ] **unquoted service** binary **path** を悪用できる?
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] インストール済み applications に対する **Write** [**permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH 内の任意の folder に **write** できる?
- [ ] 既知の service binary で、存在しない DLL を読み込もうとするものはある?
- [ ] 任意の **binaries folder** に **write** できる?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] network を列挙する (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) で listen している network services を特に確認する

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] 使えそうな [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials はある?
- [ ] 興味深い [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] 保存された [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) の passwords?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) に興味深い情報はある?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) に passwords はある?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) の passwords?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) に passwords はある?
- [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup はある?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) がある場合、raw-volume read を試して `SAM`, `SYSTEM`, DPAPI material, `MachineKeys` を取得する
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) に password はある?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) に興味深い情報はある?
- [ ] ユーザーに [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) したい?
- [ ] [**Recycle Bin** 内のファイル](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) に興味深いものはある?
- [ ] credentials を含む他の [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry) はある?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) の中 (dbs, history, bookmarks, ...) は?
- [ ] ファイルと registry での [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] passwords を自動で探すための [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] administrator によって実行されている process の handler にアクセスできる?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 悪用できるか確認する



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
