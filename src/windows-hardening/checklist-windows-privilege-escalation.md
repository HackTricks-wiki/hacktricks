# チェックリスト - Windows ローカル権限昇格

{{#include ../banners/hacktricks-training.md}}

### **Windows ローカル権限昇格のベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [システム情報](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**システム情報**](windows-local-privilege-escalation/index.html#system-info)を取得する
- [ ] スクリプトを使って**kernel** [**exploit**](windows-local-privilege-escalation/index.html#version-exploits)を検索する
- [ ] **Googleで検索**して kernel **exploit** を探す
- [ ] **searchsploitで検索**して kernel **exploit** を探す
- [ ] [**環境変数**](windows-local-privilege-escalation/index.html#environment)に興味深い情報はあるか？
- [ ] [**PowerShellの履歴**](windows-local-privilege-escalation/index.html#powershell-history)にパスワードはあるか？
- [ ] [**インターネット設定**](windows-local-privilege-escalation/index.html#internet-settings)に興味深い情報はあるか？
- [ ] [**ドライブ**](windows-local-privilege-escalation/index.html#drives)は？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)は？
- [ ] [**サードパーティ製エージェントの自動更新機能 / IPCの悪用**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)は？

### [ログ / AVの列挙](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)と[**WEF** ](windows-local-privilege-escalation/index.html#wef)の設定を確認する
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps)を確認する
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)が有効か確認する
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)は？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**キャッシュされた認証情報**](windows-local-privilege-escalation/index.html#cached-credentials)は？
- [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)が存在するか確認する
- [ ] [**AppLockerポリシー**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)は？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccessによるサイレント昇格**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)は？<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktopのアクセシビリティレジストリ伝播 (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)は？<sup>[[2]](#references)</sup>
- [ ] [**ユーザー権限**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**現在の**ユーザーの**権限**](windows-local-privilege-escalation/index.html#users-and-groups)を確認する
- [ ] [**特権グループのメンバー**](windows-local-privilege-escalation/index.html#privileged-groups)か？
- [ ] [次のいずれかのトークンが有効](windows-local-privilege-escalation/index.html#token-manipulation)か確認する: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)を使ってraw volumeを読み取り、ファイルACLを回避できるか確認する
- [ ] [**ユーザーセッション**](windows-local-privilege-escalation/index.html#logged-users-sessions)は？
- [ ] [**ユーザーのホームフォルダー**](windows-local-privilege-escalation/index.html#home-folders)を確認する (アクセス可能か？)
- [ ] [**パスワードポリシー**](windows-local-privilege-escalation/index.html#password-policy)を確認する
- [ ] [**クリップボード内**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)には何があるか？

### [ネットワーク](windows-local-privilege-escalation/index.html#network)

- [ ] **現在の**[**ネットワーク** **情報**](windows-local-privilege-escalation/index.html#network)を確認する
- [ ] 外部からのアクセスが制限されている**隠れたローカルサービス**を確認する

### [実行中のプロセス](windows-local-privilege-escalation/index.html#running-processes)

- [ ] プロセスのバイナリに対する[**ファイルおよびフォルダーの権限**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**メモリ上のパスワードマイニング**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**安全でないGUIアプリ**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`を使い、**興味深いプロセス** (firefox、chromeなど) から認証情報を盗めるか？

### [サービス](windows-local-privilege-escalation/index.html#services)

- [ ] [**変更できるサービス**](windows-local-privilege-escalation/index.html#permissions)はあるか？
- [ ] [サービスによって**実行される** **バイナリ**を**変更**できるか？](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [サービスの**レジストリ**を**変更**できるか？](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [**引用符で囲まれていないサービス**のバイナリ**パス**を悪用できるか？](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [サービス トリガー: 特権サービスを列挙してトリガーする](windows-local-privilege-escalation/service-triggers.md)

### [**アプリケーション**](windows-local-privilege-escalation/index.html#applications)

- [ ] [インストール済みアプリケーションに対する**書き込み** **権限**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**スタートアップアプリケーション**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **脆弱な**[**ドライバー**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH内のいずれかのフォルダーに**書き込み**できるか？
- [ ] **存在しないDLLの読み込みを試みる**ことが知られているサービスバイナリはあるか？
- [ ] いずれかの**バイナリフォルダー**に**書き込み**できるか？

### [ネットワーク](windows-local-privilege-escalation/index.html#network)

- [ ] ネットワークを列挙する (共有、インターフェース、ルート、近隣ホストなど)
- [ ] localhost (127.0.0.1) で待ち受けているネットワークサービスを重点的に確認する

### [Windowsの認証情報](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)の認証情報
- [ ] 利用可能な[**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)の認証情報はあるか？
- [ ] 興味深い[**DPAPI認証情報**](windows-local-privilege-escalation/index.html#dpapi)はあるか？
- [ ] 保存済み[**Wifiネットワーク**](windows-local-privilege-escalation/index.html#wifi)のパスワードはあるか？
- [ ] [**保存済みRDP接続**](windows-local-privilege-escalation/index.html#saved-rdp-connections)に興味深い情報はあるか？
- [ ] [**最近実行されたコマンド**](windows-local-privilege-escalation/index.html#recently-run-commands)にパスワードはあるか？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)のパスワードはあるか？
- [ ] [**AppCmd.exe**が存在](windows-local-privilege-escalation/index.html#appcmd-exe)するか？認証情報はあるか？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)は？DLL Side Loadingは可能か？

### [ファイルとレジストリ (認証情報)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**認証情報**](windows-local-privilege-escalation/index.html#putty-creds)および[**SSHホストキー**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**レジストリ内のSSHキー**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)は？
- [ ] [**unattendedファイル**](windows-local-privilege-escalation/index.html#unattended-files)にパスワードはあるか？
- [ ] [**SAMとSYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)のバックアップはあるか？
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)がある場合、raw volumeを読み取って`SAM`、`SYSTEM`、DPAPIのデータ、`MachineKeys`を取得する
- [ ] [**クラウド認証情報**](windows-local-privilege-escalation/index.html#cloud-credentials)は？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)ファイルはあるか？
- [ ] [**キャッシュされたGPPパスワード**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)はあるか？
- [ ] [**IIS Web設定ファイル**](windows-local-privilege-escalation/index.html#iis-web-config)にパスワードはあるか？
- [ ] [**Web** **ログ**](windows-local-privilege-escalation/index.html#logs)に興味深い情報はあるか？
- [ ] ユーザーに[**認証情報を尋ねる**](windows-local-privilege-escalation/index.html#ask-for-credentials)か？
- [ ] [**ごみ箱内の興味深いファイル**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)はあるか？
- [ ] 認証情報を含むその他の[**レジストリ**](windows-local-privilege-escalation/index.html#inside-the-registry)はあるか？
- [ ] [**ブラウザデータ**](windows-local-privilege-escalation/index.html#browsers-history)内 (データベース、履歴、ブックマークなど) は？
- [ ] ファイルとレジストリ内の[**一般的なパスワード検索**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] パスワードを自動検索する[**ツール**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] administratorが実行したプロセスのhandlerにアクセスできるか？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] これを悪用できるか確認する

## References

- [1] [Project Zero - UI Accessの悪用によるAdministrator Protectionのバイパス](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
