# チェックリスト - ローカルWindows特権昇格

{{#include ../banners/hacktricks-training.md}}

### **Windowsローカル特権昇格ベクトルを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [システム情報](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**システム情報**](windows-local-privilege-escalation/index.html#system-info)を取得
- [ ] **カーネル**の[**エクスプロイトをスクリプトで検索**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] **Googleでカーネルのエクスプロイトを検索**
- [ ] **searchsploitでカーネルのエクスプロイトを検索**
- [ ] [**環境変数**](windows-local-privilege-escalation/index.html#environment)?に興味深い情報はあるか？
- [ ] [**PowerShellの履歴**](windows-local-privilege-escalation/index.html#powershell-history)にパスワードはあるか？
- [ ] [**インターネット設定**](windows-local-privilege-escalation/index.html#internet-settings)に興味深い情報はあるか？
- [ ] [**ドライブ**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUSエクスプロイト**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [ログ/AV列挙](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**監査**](windows-local-privilege-escalation/index.html#audit-settings)と[**WEF**](windows-local-privilege-escalation/index.html#wef)設定を確認
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps)を確認
- [ ] [**WDigest**](windows-local-privilege-escalation/index.html#wdigest)がアクティブか確認
- [ ] [**LSA保護**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**キャッシュされた資格情報**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)が有効か確認
- [ ] [**AppLockerポリシー**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**ユーザー特権**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**現在の**ユーザーの**特権**](windows-local-privilege-escalation/index.html#users-and-groups)を確認
- [ ] [**特権グループのメンバー**](windows-local-privilege-escalation/index.html#privileged-groups)か？
- [ ] [これらのトークンが有効か確認](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**ユーザーセッション**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**ユーザーホーム**](windows-local-privilege-escalation/index.html#home-folders)を確認 (アクセス?)
- [ ] [**パスワードポリシー**](windows-local-privilege-escalation/index.html#password-policy)を確認
- [ ] [**クリップボードの中身**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)は何か？

### [ネットワーク](windows-local-privilege-escalation/index.html#network)

- [ ] **現在の**[**ネットワーク情報**](windows-local-privilege-escalation/index.html#network)を確認
- [ ] 外部に制限された**隠れたローカルサービス**を確認

### [実行中のプロセス](windows-local-privilege-escalation/index.html#running-processes)

- [ ] プロセスバイナリの[**ファイルとフォルダの権限**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**メモリパスワードマイニング**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**安全でないGUIアプリ**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`を介して**興味深いプロセス**から資格情報を盗む？ (firefox, chrome, etc ...)

### [サービス](windows-local-privilege-escalation/index.html#services)

- [ ] [**サービスを変更できるか**](windows-local-privilege-escalation/index.html#permissions)?
- [ ] [**サービスによって実行される**バイナリを**変更できるか**](windows-local-privilege-escalation/index.html#modify-service-binary-path)?
- [ ] [**サービスの**レジストリを**変更できるか**](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)?
- [ ] [**引用符なしのサービス**バイナリの**パスを利用できるか**](windows-local-privilege-escalation/index.html#unquoted-service-paths)?

### [**アプリケーション**](windows-local-privilege-escalation/index.html#applications)

- [ ] **インストールされたアプリケーションの**[**書き込み権限**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**スタートアップアプリケーション**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **脆弱な**[**ドライバー**](windows-local-privilege-escalation/index.html#drivers)

### [DLLハイジャック](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] **PATH内の任意のフォルダに書き込めるか**？
- [ ] **存在しないDLLを読み込もうとする**既知のサービスバイナリはあるか？
- [ ] **任意のバイナリフォルダに書き込めるか**？

### [ネットワーク](windows-local-privilege-escalation/index.html#network)

- [ ] ネットワークを列挙 (共有、インターフェース、ルート、隣接、...)
- [ ] localhost (127.0.0.1)でリッスンしているネットワークサービスに特に注意

### [Windows資格情報](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials)資格情報
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)の資格情報は使用できるか？
- [ ] 興味深い[**DPAPI資格情報**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] 保存された[**Wifiネットワーク**](windows-local-privilege-escalation/index.html#wifi)のパスワードは？
- [ ] [**保存されたRDP接続**](windows-local-privilege-escalation/index.html#saved-rdp-connections)に興味深い情報はあるか？
- [ ] [**最近実行されたコマンド**](windows-local-privilege-escalation/index.html#recently-run-commands)のパスワードは？
- [ ] [**リモートデスクトップ資格情報マネージャー**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)のパスワードは？
- [ ] [**AppCmd.exe**が存在するか](windows-local-privilege-escalation/index.html#appcmd-exe)? 資格情報は？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLLサイドローディング？

### [ファイルとレジストリ (資格情報)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**資格情報**](windows-local-privilege-escalation/index.html#putty-creds) **と** [**SSHホストキー**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**レジストリ内のSSHキー**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**無人ファイル**](windows-local-privilege-escalation/index.html#unattended-files)のパスワードは？
- [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)のバックアップはあるか？
- [ ] [**クラウド資格情報**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)ファイルは？
- [ ] [**キャッシュされたGPPパスワード**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web構成ファイル**](windows-local-privilege-escalation/index.html#iis-web-config)のパスワードは？
- [ ] [**ウェブログ**](windows-local-privilege-escalation/index.html#logs)に興味深い情報はあるか？
- [ ] ユーザーに[**資格情報を要求する**](windows-local-privilege-escalation/index.html#ask-for-credentials)か？
- [ ] [**ごみ箱内の興味深いファイル**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] 他の[**資格情報を含むレジストリ**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**ブラウザデータ**](windows-local-privilege-escalation/index.html#browsers-history)内 (dbs、履歴、ブックマーク、...)?
- [ ] [**ファイルとレジストリ内の一般的なパスワード検索**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] パスワードを自動的に検索するための[**ツール**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [漏洩したハンドラー](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 管理者によって実行されるプロセスのハンドラーにアクセスできるか？

### [パイプクライアントの偽装](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 悪用できるか確認

{{#include ../banners/hacktricks-training.md}}
