# チェックリスト - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探す最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] 取得する [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] **kernel** の [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits) を検索する
- [ ] **Google** で kernel の **exploits** を検索する
- [ ] **searchsploit** で kernel の **exploits** を検索する
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) に興味深い情報はあるか？
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) にパスワードはないか？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) に興味深い情報はあるか？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives) はどうか？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus) はないか？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md) を確認する
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) は有効か？

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) と [**WEF** ](windows-local-privilege-escalation/index.html#wef) の設定を確認する
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) を確認する
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) が有効か確認する
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection) はどうか？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard) はどうか？[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials) はどうか？
- [ ] 存在する [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) を確認する
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) はどうか？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) を確認する
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups) を確認する
- [ ] 現在のユーザーの **privileges** を確認する ( [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups) )
- [ ] あなたは [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) か？
- [ ] [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation) があるか確認する: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions) を確認する
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) を確認する（アクセス可否）
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) を確認する
- [ ] クリップボードの中身は何か確認する ([**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard))？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 現在の [**network information**](windows-local-privilege-escalation/index.html#network) を確認する
- [ ] 外部に制限されている隠れたローカルサービスがないか確認する

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] プロセスのバイナリの [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) を確認する
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining) を確認する
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps) を確認する
- [ ] `ProcDump.exe` を使って興味深いプロセスから資格情報を奪えないか？（firefox, chrome, など）

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] どのサービスでも **modify** できるか？ ([Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions))
- [ ] どのサービスでも実行される **binary** を **modify** できるか？ ([Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path))
- [ ] どのサービスの **registry** でも **modify** できるか？ ([Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions))
- [ ] unquoted service binary **path** を利用できないか？ ([Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths))

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] インストール済みアプリケーションに対する **Write** 権限がないか？ ([**Write** permissions on installed applications](windows-local-privilege-escalation/index.html#write-permissions))
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup) を確認する
- [ ] 脆弱な [**Drivers**](windows-local-privilege-escalation/index.html#drivers) がないか？

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH 内の任意のフォルダに書き込みできるか？
- [ ] 存在しない DLL をロードしようとする既知のサービスバイナリはあるか？
- [ ] 任意の **binaries folder** に書き込みできるか？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] ネットワークを列挙する（shares, interfaces, routes, neighbours, ...）
- [ ] localhost (127.0.0.1) でリッスンしているネットワークサービスに特に注意する

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) の資格情報
- [ ] 使用可能な [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) の資格情報はあるか？
- [ ] 興味深い [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) はないか？
- [ ] 保存された [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) のパスワードは？
- [ ] 保存された [**RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) に興味深い情報はあるか？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) にパスワードはないか？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) のパスワードは？
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)？ 資格情報は？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)？ DLL Side Loading の可能性は？

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) はあるか？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) にパスワードはないか？
- [ ] 何か [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) のバックアップはないか？
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials) はないか？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) ファイルはないか？
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) はないか？
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) にパスワードはないか？
- [ ] [**web logs**](windows-local-privilege-escalation/index.html#logs) に興味深い情報はないか？
- [ ] ユーザーに資格情報を [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) したいか？
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) 内の興味深いファイルは？
- [ ] その他の資格情報を含む [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry) はないか？
- [ ] ブラウザ内のデータ（dbs, history, bookmarks, ...）はどうか？ ([**inside Browser data**](windows-local-privilege-escalation/index.html#browsers-history))
- [ ] ファイルやレジストリ内の [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] パスワードを自動で検索する [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 管理者が実行しているプロセスのハンドラにアクセスできるか？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 悪用できるか確認する

{{#include ../banners/hacktricks-training.md}}
