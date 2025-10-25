# チェックリスト - ローカル Windows 権限昇格

{{#include ../banners/hacktricks-training.md}}

### **Windows ローカル権限昇格のベクターを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [システム情報](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**システム情報**](windows-local-privilege-escalation/index.html#system-info) を取得する
- [ ] カーネル用の [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits) を検索する
- [ ] カーネルの **exploits** を探すために **Google** を使う
- [ ] カーネルの **exploits** を探すために **searchsploit** を使う
- [ ] [**環境変数**](windows-local-privilege-escalation/index.html#environment) に興味深い情報はあるか？
- [ ] [**PowerShell 履歴**](windows-local-privilege-escalation/index.html#powershell-history) にパスワードはあるか？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) に興味深い情報はあるか？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives) は？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus) は？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) ?

### [ログ / AV 列挙](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) と [**WEF**](windows-local-privilege-escalation/index.html#wef) の設定を確認する
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) を確認する
- [ ] [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) が有効か確認する
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection) ?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials) ?
- [ ] 何か **AV** があるか確認する (https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) は？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) を確認する
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups) を確認する
- [ ] 現在のユーザーの **privileges** を確認する (windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) か？
- [ ] 以下のトークンが有効か確認する (windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions) ?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) を確認する（アクセス可能か？）
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) を確認する
- [ ] クリップボードの中身は何か？ [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)

### [ネットワーク](windows-local-privilege-escalation/index.html#network)

- [ ] 現在の [**network information**](windows-local-privilege-escalation/index.html#network) を確認する
- [ ] 外部に制限されている隠れたローカルサービスを確認する

### [実行中のプロセス](windows-local-privilege-escalation/index.html#running-processes)

- [ ] プロセスのバイナリの [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) を確認する
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 興味のあるプロセスから `ProcDump.exe` を使って資格情報を盗めるか？ (firefox, chrome, etc ...)

### [サービス](windows-local-privilege-escalation/index.html#services)

- [ ] 任意のサービスを**変更**できるか？ (windows-local-privilege-escalation/index.html#permissions)
- [ ] 任意のサービスによって**実行されるバイナリ**を**修正**できるか？ (windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] 任意のサービスの**レジストリ**を**変更**できるか？ (windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] 引用符のないサービスバイナリの**パス**を利用できるか？ (windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] Service Triggers: 権限の高いサービスを列挙してトリガーできるか (windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] インストール済みアプリケーションに対する**書き込み権限** (windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **脆弱な** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH 内の任意のフォルダに書き込めるか？
- [ ] 存在しない DLL を読み込もうとする既知のサービスバイナリはあるか？
- [ ] 任意の**バイナリフォルダ**に書き込めるか？

### [ネットワーク](windows-local-privilege-escalation/index.html#network)

- [ ] ネットワークを列挙する（shares, interfaces, routes, neighbours, ...）
- [ ] localhost (127.0.0.1) でリッスンしているネットワークサービスを特に確認する

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) の認証情報
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) の認証情報は使えるか？
- [ ] 興味深い [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) はあるか？
- [ ] 保存された [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) のパスワード？
- [ ] 保存された [**RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) に興味深い情報はあるか？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) にパスワードはあるか？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) のパスワード？
- [ ] [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe) が存在するか？認証情報はあるか？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) の DLL Side Loading？

### [ファイルとレジストリ（認証情報）](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **および** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] レジストリ内の [**SSH keys**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) は？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) にパスワードはあるか？
- [ ] 何か [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) のバックアップはあるか？
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials) は？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) ファイルは？
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) は？
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) にパスワードはあるか？
- [ ] [**web logs**](windows-local-privilege-escalation/index.html#logs) に興味深い情報はあるか？
- [ ] ユーザーに認証情報を要求するか？ (windows-local-privilege-escalation/index.html#ask-for-credentials)
- [ ] ごみ箱内の興味深いファイルはあるか？ (windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)
- [ ] 認証情報を含むその他の [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry) は？
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) の中身 (dbs, history, bookmarks, ...) は？
- [ ] ファイルとレジストリ内の [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] パスワードを自動で検索する [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 管理者で実行されているプロセスのハンドルにアクセスできるか？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 悪用できるか確認する

{{#include ../banners/hacktricks-training.md}}
