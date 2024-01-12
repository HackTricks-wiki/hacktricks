# チェックリスト - ローカルWindows特権昇格

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

### **Windowsローカル特権昇格ベクトルを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [システム情報](windows-local-privilege-escalation/#system-info)

* [ ] [**システム情報**](windows-local-privilege-escalation/#system-info)を取得する
* [ ] スクリプトを使用して**カーネル** [**エクスプロイトを探す**](windows-local-privilege-escalation/#version-exploits)
* [ ] **Googleを使用して**カーネル**エクスプロイトを探す**
* [ ] **searchsploitを使用して**カーネル**エクスプロイトを探す**
* [ ] [**環境変数**](windows-local-privilege-escalation/#environment)に興味深い情報はありますか？
* [ ] [**PowerShell履歴**](windows-local-privilege-escalation/#powershell-history)にパスワードはありますか？
* [ ] [**インターネット設定**](windows-local-privilege-escalation/#internet-settings)に興味深い情報はありますか？
* [ ] [**ドライブ**](windows-local-privilege-escalation/#drives)？
* [ ] [**WSUSエクスプロイト**](windows-local-privilege-escalation/#wsus)？
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)？

### [ログ/AV列挙](windows-local-privilege-escalation/#enumeration)

* [ ] [**監査**](windows-local-privilege-escalation/#audit-settings)と[**WEF**](windows-local-privilege-escalation/#wef)設定をチェックする
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps)をチェックする
* [ ] [**WDigest**](windows-local-privilege-escalation/#wdigest)がアクティブかどうかをチェックする
* [ ] [**LSA保護**](windows-local-privilege-escalation/#lsa-protection)？
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[？](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**キャッシュされた資格情報**](windows-local-privilege-escalation/#cached-credentials)？
* [ ] 任意の[**AV**](windows-av-bypass)があるかチェックする
* [ ] [**AppLockerポリシー**](authentication-credentials-uac-and-efs#applocker-policy)？
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**ユーザー権限**](windows-local-privilege-escalation/#users-and-groups)
* [ ] [**現在の**ユーザー**権限**](windows-local-privilege-escalation/#users-and-groups)をチェックする
* [ ] [**特権グループのメンバー**](windows-local-privilege-escalation/#privileged-groups)ですか？
* [ ] [これらのトークンが有効になっているかどうかをチェックする](windows-local-privilege-escalation/#token-manipulation)：**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**？
* [ ] [**ユーザーセッション**](windows-local-privilege-escalation/#logged-users-sessions)？
* [ ] [**ユーザーホーム**](windows-local-privilege-escalation/#home-folders)をチェックする（アクセス？）
* [ ] [**パスワードポリシー**](windows-local-privilege-escalation/#password-policy)をチェックする
* [ ] [**クリップボードの中身**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)は何ですか？

### [ネットワーク](windows-local-privilege-escalation/#network)

* [ ] [**現在の**ネットワーク**情報**](windows-local-privilege-escalation/#network)をチェックする
* [ ] 外部に制限された**隠されたローカルサービス**をチェックする

### [実行中のプロセス](windows-local-privilege-escalation/#running-processes)

* [ ] プロセスバイナリの[**ファイルとフォルダの権限**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**メモリパスワードマイニング**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**安全でないGUIアプリ**](windows-local-privilege-escalation/#insecure-gui-apps)

### [サービス](windows-local-privilege-escalation/#services)

* [ ] [**任意のサービスを変更できますか**？](windows-local-privilege-escalation#permissions)
* [ ] [**任意のサービスによって実行されるバイナリを変更できますか**？](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [**任意のサービスのレジストリを変更できますか**？](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [**引用符なしのサービスバイナリパス**](windows-local-privilege-escalation/#unquoted-service-paths)を利用できますか？

### [**アプリケーション**](windows-local-privilege-escalation/#applications)

* [ ] インストールされたアプリケーションの[**書き込み権限**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**スタートアップアプリケーション**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **脆弱な** [**ドライバー**](windows-local-privilege-escalation/#drivers)

### [DLLハイジャック](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] PATH内の任意のフォルダに**書き込みができますか**？
* [ ] 存在しないDLLをロードしようとする既知のサービスバイナリはありますか？
* [ ] 任意の**バイナリフォルダ**に**書き込み**ができますか？

### [ネットワーク](windows-local-privilege-escalation/#network)

* [ ] ネットワークを列挙する（共有、インターフェース、ルート、隣接、...）
* [ ] localhost (127.0.0.1)でリスニングしているネットワークサービスに特に注意する

### [Windows資格情報](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)資格情報
* [ ] 使用できる[**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault)資格情報はありますか？
* [ ] 興味深い[**DPAPI資格情報**](windows-local-privilege-escalation/#dpapi)？
* [ ] 保存された[**Wifiネットワーク**](windows-local-privilege-escalation/#wifi)のパスワード？
* [ ] [**保存されたRDP接続**](windows-local-privilege-escalation/#saved-rdp-connections)に興味深い情報はありますか？
* [ ] [**最近実行されたコマンド**](windows-local-privilege-escalation/#recently-run-commands)にパスワードはありますか？
* [ ] [**リモートデスクトップ資格情報マネージャー**](windows-local-privilege-escalation/#remote-desktop-credential-manager)のパスワード？
* [ ] [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)が存在しますか？資格情報？
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)？DLLサイドローディング？

### [ファイルとレジストリ（資格情報）](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**資格情報**](windows-local-privilege-escalation/#putty-creds) **と** [**SSHホストキー**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**レジストリ内のSSHキー**](windows-local-privilege-escalation/#ssh-keys-in-registry)？
* [ ] [**自動実行ファイル**](windows-local-privilege-escalation/#unattended-files)にパスワードはありますか？
* [ ] 任意の[**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)バックアップ？
* [ ] [**クラウド資格情報**](windows-local-privilege-escalation/#cloud-credentials)？
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)ファイル？
* [ ] [**キャッシュされたGPPパスワード**](windows-local-privilege-escalation/#cached-gpp-pasword)？
* [ ] [**IIS Web設定ファイル**](windows-local-privilege-escalation/#iis-web-config)にパスワードはありますか？
* [ ] [**ウェブログ**](windows-local-privilege-escalation/#logs)に興味深い情報はありますか？
* [ ] ユーザーに[**資格情報を求める**](windows-local-privilege-escalation/#ask-for-credentials)ことを望みますか？
* [ ] [**ごみ箱内のファイル**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)に興味深いものはありますか？
* [ ] 他の[**資格情報を含むレジストリ**](windows-local-privilege-escalation/#inside-the-registry)？
* [ ] [**ブラウザーデータ内**](windows-local-privilege-escalation/#browsers-history)（dbs、履歴、ブックマーク、...）？
* [ ] ファイルとレジストリでの[**一般的なパスワード検索**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
* [ ] パスワードを自動的に検索する[**ツール**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [リークされたハンドラ](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 管理者によって実行されるプロセスのハンドラにアクセスできますか？

### [パイプクライアントのなりすまし](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] それを悪用できるかどうかをチェックする

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
