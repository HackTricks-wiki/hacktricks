# チェックリスト - Windows ローカル権限昇格

{{#include ../banners/hacktricks-training.md}}

### **Windows ローカル権限昇格の vector を探す最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [システム情報](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**システム情報**](windows-local-privilege-escalation/index.html#system-info)を取得する
- [ ] スクリプトを使って**kernel** [**exploit**](windows-local-privilege-escalation/index.html#version-exploits)を検索する
- [ ] Googleでkernel **exploit**を検索する
- [ ] searchsploitでkernel **exploit**を検索する
- [ ] [**環境変数**](windows-local-privilege-escalation/index.html#environment)に興味深い情報はあるか？
- [ ] [**PowerShellの履歴**](windows-local-privilege-escalation/index.html#powershell-history)にパスワードはあるか？
- [ ] [**インターネット設定**](windows-local-privilege-escalation/index.html#internet-settings)に興味深い情報はあるか？
- [ ] [**ドライブ**](windows-local-privilege-escalation/index.html#drives)は？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)は？
- [ ] [**サードパーティー製エージェントの自動更新機能 / IPCの悪用**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)は？

### [ログ記録 / AVの列挙](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)と[**WEF** ](windows-local-privilege-escalation/index.html#wef)の設定を確認する
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps)を確認する
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)が有効か確認する
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)は？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**キャッシュされた認証情報**](windows-local-privilege-escalation/index.html#cached-credentials)は？
- [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)の有無を確認する
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)は？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccessによるサイレント昇格**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)は？<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktopのアクセシビリティレジストリ伝播 (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)は？<sup>[[2]](#references)</sup>
- [ ] [**ユーザー権限**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**現在の**ユーザーの**権限**](windows-local-privilege-escalation/index.html#users-and-groups)を確認する
- [ ] [**特権グループのメンバー**](windows-local-privilege-escalation/index.html#privileged-groups)か？
- [ ] **Disabled**と表示されていても、現在のtokenに以下の[権限が存在するか](windows-local-privilege-escalation/access-tokens.md)確認する: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**。無効な権限を有効化できるのは、その権限がすでにtokenに含まれている場合のみ。<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] ボリューム保守権限として[**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)があるか確認する。この権限だけではraw volumeへの読み取りアクセスは確立されない。ディスクまたはボリュームを開くには、別途アクセス要件がある。<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**ユーザーセッション**](windows-local-privilege-escalation/index.html#logged-users-sessions)は？
- [ ] [**ユーザーのホームフォルダー**](windows-local-privilege-escalation/index.html#home-folders)を確認する (アクセスできるか？)
- [ ] [**パスワードポリシー**](windows-local-privilege-escalation/index.html#password-policy)を確認する
- [ ] [**クリップボードの内容**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)は？

### [ネットワーク](windows-local-privilege-escalation/index.html#network)

- [ ] **現在の**[**ネットワーク** **情報**](windows-local-privilege-escalation/index.html#network)を確認する
- [ ] 外部からのアクセスが制限されている**隠れたローカルサービス**を確認する

### [実行中のプロセス](windows-local-privilege-escalation/index.html#running-processes)

- [ ] プロセスのバイナリに対する[**ファイルとフォルダーのアクセス許可**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**メモリからのパスワードマイニング**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**安全でないGUIアプリ**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`を使い、**興味深いプロセス** (firefox、chromeなど) から認証情報を窃取できるか？

### [サービス](windows-local-privilege-escalation/index.html#services)

- [ ] [**サービスを変更**できるか？](windows-local-privilege-escalation/index.html#permissions)
- [ ] [**サービス**が**実行する**バイナリを**変更**できるか？](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [**サービス**の**レジストリ**を**変更**できるか？](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [**引用符で囲まれていないサービス**のバイナリ**パス**を悪用できるか？](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: 特権サービスを列挙して起動する](windows-local-privilege-escalation/service-triggers.md)

### [**アプリケーション**](windows-local-privilege-escalation/index.html#applications)

- [ ] **インストール済みアプリケーションに対する**[**書き込み権限**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**スタートアップアプリケーション**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **脆弱な**[**ドライバー**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH内のフォルダーに**書き込み**できるか？
- [ ] **存在しないDLLを読み込もうとする**既知のサービスバイナリはあるか？
- [ ] **バイナリフォルダー**に**書き込み**できるか？

### [ネットワーク](windows-local-privilege-escalation/index.html#network)

- [ ] ネットワークを列挙する (shares、interfaces、routes、neighboursなど)
- [ ] localhost (127.0.0.1)で待ち受けているネットワークサービスを特に確認する

### [Windowsの認証情報](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)の認証情報
- [ ] 利用できる[**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)の認証情報はあるか？
- [ ] 興味深い[**DPAPI認証情報**](windows-local-privilege-escalation/index.html#dpapi)はあるか？
- [ ] 保存された[**Wi-Fiネットワーク**](windows-local-privilege-escalation/index.html#wifi)のパスワードはあるか？
- [ ] [**保存されたRDP接続**](windows-local-privilege-escalation/index.html#saved-rdp-connections)に興味深い情報はあるか？
- [ ] [**最近実行されたコマンド**](windows-local-privilege-escalation/index.html#recently-run-commands)にパスワードはあるか？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)のパスワードはあるか？
- [ ] [**AppCmd.exe**が存在するか](windows-local-privilege-escalation/index.html#appcmd-exe)？認証情報はあるか？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)は？DLL Side Loadingは可能か？

### [ファイルとレジストリ (認証情報)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**認証情報**](windows-local-privilege-escalation/index.html#putty-creds)と[**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**レジストリ内のSSH keys**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)はあるか？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)にパスワードはあるか？
- [ ] [**SAMとSYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)のバックアップはあるか？
- [ ] 読み取り可能なraw volume handleへのアクセスが別途許可されている場合は、`SAM`、`SYSTEM`、DPAPI material、`MachineKeys`が露出している可能性を調べる。**SeManageVolumePrivilege**だけからこのアクセスがあると推測してはならない。<sup>[[5]](#references)</sup>
- [ ] [**Cloud認証情報**](windows-local-privilege-escalation/index.html#cloud-credentials)はあるか？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)ファイルはあるか？
- [ ] [**キャッシュされたGPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)はあるか？
- [ ] [**IIS Web configファイル**](windows-local-privilege-escalation/index.html#iis-web-config)にパスワードはあるか？
- [ ] [**Web** **ログ**](windows-local-privilege-escalation/index.html#logs)に興味深い情報はあるか？
- [ ] ユーザーに[**認証情報を尋ねる**](windows-local-privilege-escalation/index.html#ask-for-credentials)か？
- [ ] [**ごみ箱内のファイル**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)に興味深いものはあるか？
- [ ] その他の[**認証情報を含むレジストリ**](windows-local-privilege-escalation/index.html#inside-the-registry)はあるか？
- [ ] [**ブラウザーデータ**](windows-local-privilege-escalation/index.html#browsers-history)内 (dbs、履歴、ブックマークなど) は？
- [ ] ファイルとレジストリ内の[**一般的なパスワード検索**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] パスワードを自動検索する[**ツール**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 管理者が実行しているプロセスのhandlerにアクセスできるか？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 悪用できるか確認する



## References

- [1] [Project Zero - UI Accessの悪用によるAdministrator Protectionのバイパス](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - 権限](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Token内の権限の変更](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - 物理ディスクとボリュームに対するCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - ファイルシステム内の権限の管理](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
