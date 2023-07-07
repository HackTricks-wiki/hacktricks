# チェックリスト - ローカルWindows特権昇格

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**してください。

</details>

### **Windowsローカル特権昇格のための最適なツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [システム情報](windows-local-privilege-escalation/#system-info)

* [ ] [**システム情報**](windows-local-privilege-escalation/#system-info)を取得する
* [ ] スクリプトを使用して**カーネル**の[**脆弱性を検索**](windows-local-privilege-escalation/#version-exploits)する
* [ ] グーグルを使用してカーネルの**脆弱性を検索**する
* [ ] searchsploitを使用してカーネルの**脆弱性を検索**する
* [ ] [**環境変数**](windows-local-privilege-escalation/#environment)に興味深い情報はありますか？
* [ ] [**PowerShellの履歴**](windows-local-privilege-escalation/#powershell-history)にパスワードはありますか？
* [ ] [**インターネット設定**](windows-local-privilege-escalation/#internet-settings)に興味深い情報はありますか？
* [ ] [**ドライブ**](windows-local-privilege-escalation/#drives)をチェックする
* [ ] [**WSUSの脆弱性**](windows-local-privilege-escalation/#wsus)をチェックする
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)をチェックする

### [ログ/AV列挙](windows-local-privilege-escalation/#enumeration)

* [ ] [**監査**](windows-local-privilege-escalation/#audit-settings)と[**WEF**](windows-local-privilege-escalation/#wef)の設定をチェックする
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps)をチェックする
* [ ] [**WDigest**](windows-local-privilege-escalation/#wdigest)が有効かどうかをチェックする
* [ ] [**LSA Protection**](windows-local-privilege-escalation/#lsa-protection)をチェックする
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)をチェックする
* [ ] [**キャッシュされた資格情報**](windows-local-privilege-escalation/#cached-credentials)をチェックする
* [ ] いずれかの[**AV**](windows-av-bypass)があるかどうかをチェックする
* [ ] [**AppLockerポリシー**](authentication-credentials-uac-and-efs#applocker-policy)をチェックする
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)をチェックする
* [ ] [**ユーザー特権**](windows-local-privilege-escalation/#users-and-groups)をチェックする
* [ ] [**現在の**ユーザーの**特権**](windows-local-privilege-escalation/#users-and-groups)をチェックする
* [ ] 特権のあるグループのメンバーですか？[**特権のあるグループ**](windows-local-privilege-escalation/#privileged-groups)のメンバーですか？
* [ ] これらのトークンのいずれかが有効になっているかどうかをチェックする：**SeImpersonatePrivilege、SeAssignPrimaryPrivilege、SeTcbPrivilege、SeBackupPrivilege、SeRestorePrivilege、SeCreateTokenPrivilege、SeLoadDriverPrivilege、SeTakeOwnershipPrivilege、SeDebugPrivilege** ?
* [ ] [**ユーザーセッション**](windows-local-privilege-escalation/#logged-users-sessions)をチェックする
* [ ] [**ユーザーのホームフォルダ**](windows-local-privilege-escalation/#home-folders)をチェックする（アクセス可能か？）
* [ ] [**パスワードポリシー**](windows-local-privilege-escalation/#password-policy)をチェックする
* [ ] [**クリップボードの内容**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)は何ですか？

### [ネットワーク](windows-local-privilege-escalation/#network)

* [ ] **現在の**[**ネットワーク情報**](windows-local-privilege-escalation/#network)をチェックする
* [ ] 外部に制限された**非表示のローカルサービス**をチェックする

### [実行中のプロセス](windows-local-privilege-escalation/#running-processes)

* [ ] プロセスのバイナリの[**ファイルとフォルダのアクセス権**](windows-local-privilege-escalation/#file-and-folder-permissions)をチェックする
* [ ] [**メモリパスワードの収集**](windows-local-privilege-escalation/#memory-password-mining)を行う
* [ ] [**安全でないGUIアプリ**](windows-local-privilege-escalation/#insecure-gui-apps)をチェックする
### [サービス](windows-local-privilege-escalation/#services)

* [ ] どのサービスでも**変更**できますか？(windows-local-privilege-escalation#permissions)
* [ ] どのサービスでも**実行される**バイナリを**変更**できますか？(windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] どのサービスでも**レジストリ**を**変更**できますか？(windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] **クォートされていないサービス**のバイナリ**パス**を利用できますか？(windows-local-privilege-escalation/#unquoted-service-paths)

### [**アプリケーション**](windows-local-privilege-escalation/#applications)

* [ ] インストールされたアプリケーションの**書き込み**[**権限**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**起動時のアプリケーション**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **脆弱な**[**ドライバ**](windows-local-privilege-escalation/#drivers)

### [DLLハイジャッキング](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] **PATH内の任意のフォルダに書き込む**ことができますか？
* [ ] **存在しないDLL**を読み込もうとする既知のサービスバイナリはありますか？
* [ ] **バイナリフォルダ**に**書き込む**ことができますか？

### [ネットワーク](windows-local-privilege-escalation/#network)

* [ ] ネットワークを列挙します(共有、インターフェース、ルート、隣接者、...)
* [ ] ローカルホスト(127.0.0.1)でリッスンしているネットワークサービスに特別な注意を払います

### [Windowsの資格情報](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)の資格情報
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault)の利用可能な資格情報はありますか？
* [ ] 興味深い[**DPAPIの資格情報**](windows-local-privilege-escalation/#dpapi)はありますか？
* [ ] 保存された[**Wifiネットワークのパスワード**](windows-local-privilege-escalation/#wifi)はありますか？
* [ ] [**保存されたRDP接続**](windows-local-privilege-escalation/#saved-rdp-connections)に興味深い情報はありますか？
* [ ] 最近実行されたコマンドの中にパスワードはありますか？(windows-local-privilege-escalation/#recently-run-commands)
* [ ] [**リモートデスクトップ資格情報マネージャー**](windows-local-privilege-escalation/#remote-desktop-credential-manager)のパスワードはありますか？
* [ ] [**AppCmd.exe**が存在しますか](windows-local-privilege-escalation/#appcmd-exe)？資格情報はありますか？
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)？DLLサイドローディング？

### [ファイルとレジストリ(資格情報)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**資格情報**](windows-local-privilege-escalation/#putty-creds) **および** [**SSHホストキー**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] レジストリに[**SSHキー**](windows-local-privilege-escalation/#ssh-keys-in-registry)はありますか？
* [ ] [**未承認ファイル**](windows-local-privilege-escalation/#unattended-files)のパスワードはありますか？
* [ ] いずれかの[**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)のバックアップはありますか？
* [ ] [**クラウドの資格情報**](windows-local-privilege-escalation/#cloud-credentials)はありますか？
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)ファイルはありますか？
* [ ] [**キャッシュされたGPPパスワード**](windows-local-privilege-escalation/#cached-gpp-pasword)はありますか？
* [ ] [**IIS Web構成ファイル**](windows-local-privilege-escalation/#iis-web-config)のパスワードはありますか？
* [ ] [**Webログ**](windows-local-privilege-escalation/#logs)に興味深い情報はありますか？
* [ ] ユーザーに[**資格情報を要求**](windows-local-privilege-escalation/#ask-for-credentials)しますか？
* [ ] [**ゴミ箱内の興味深いファイル**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)はありますか？
* [ ] 他の[**資格情報を含むレジストリ**](windows-local-privilege-escalation/#inside-the-registry)はありますか？
* [ ] [**ブラウザデータ**](windows-local-privilege-escalation/#browsers-history)(dbs、履歴、ブックマークなど)の中に興味深い情報はありますか？
* [ ] ファイルとレジストリでの[**一般的なパスワード検索**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
* [ ] パスワードを自動的に検索する[**ツール**](windows-local-privilege-escalation/#tools-that-search-for-passwords)はありますか？

### [漏洩したハンドラ](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 管理者が実行したプロセスのハンドラにアクセスできますか？

### [パイプクライアントの擬似化](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] 乱用できるかどうかを確認します

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**
