# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] 取得する [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] 検索する **kernel** の [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] **Google** を使用して kernel **exploits** を検索する
- [ ] **searchsploit** を使用して kernel **exploits** を検索する
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) に興味深い情報はあるか？
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) にパスワードはあるか？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) に興味深い情報はあるか？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives) はどうか？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus) はあるか？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) は設定されているか？

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)と [**WEF** ](windows-local-privilege-escalation/index.html#wef) の設定を確認する
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) を確認する
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) が有効か確認する
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection) はどうか？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials) はどうか？
- [ ] 何か **AV** があるか確認する (https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) はどうか？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) を確認する
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups) を確認する
- [ ] 現在のユーザーの **privileges** を確認する (windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] あなたは [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) か？
- [ ] 次のトークンが有効か確認する (windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions) はどうか？
- [ ] Check[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (アクセス権は？)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) を確認する
- [ ] クリップボードの中身は何か？ (windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 現在の [**network** **information**](windows-local-privilege-escalation/index.html#network) を確認する
- [ ] 外部から制限された **hidden local services** を確認する

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] プロセスのバイナリの [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) を確認する
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 興味深いプロセスから **ProcDump.exe** などで資格情報を盗めるか？ (firefox, chrome, など)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] どのサービスでも **modify** できるか？ (windows-local-privilege-escalation/index.html#permissions)
- [ ] どのサービスでも実行される **binary** を **modify** できるか？ (windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] どのサービスの **registry** を **modify** できるか？ (windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] unquoted service binary **path** を悪用できるか？ (windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] インストール済みアプリケーションに対する **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] 脆弱な **Drivers** はあるか？ (windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#Path-dll-hijacking)

- [ ] PATH 内の任意のフォルダに **write** できるか？
- [ ] 存在しない DLL を読み込もうとする既知のサービスバイナリはあるか？
- [ ] 任意の **binaries folder** に **write** できるか？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] ネットワークを列挙する (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1) で待ち受けているネットワークサービスに注目する

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) の資格情報
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) に使用できる資格情報はあるか？
- [ ] 興味深い [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) はあるか？
- [ ] 保存された [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) のパスワードは？
- [ ] 保存された [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) に興味深い情報はあるか？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) にパスワードはあるか？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) のパスワードは？
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? 資格情報は？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) はあるか？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) にパスワードはあるか？
- [ ] 何か [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) のバックアップはあるか？
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials) はあるか？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) ファイルはあるか？
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) はあるか？
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) にパスワードはあるか？
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) に興味深い情報はあるか？
- [ ] ユーザーに対して [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) したいか？
- [ ] [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) に興味深いものはあるか？
- [ ] その他の [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)
- [ ] ブラウザ内の [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...) はどうか？
- [ ] ファイルやレジストリ内の [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] パスワードを自動的に検索する [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 管理者が実行しているプロセスのハンドラにアクセスできるか？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 悪用できるか確認する

{{#include ../banners/hacktricks-training.md}}
