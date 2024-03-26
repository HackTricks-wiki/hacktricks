# チェックリスト - ローカルWindows特権昇格

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を通じて、ゼロからヒーローまでAWSハッキングを学ぶ</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **Discordグループ**に**参加**する💬 ([**Discord group**](https://discord.gg/hRep4RUj7f))または[**telegram group**](https://t.me/peass)に参加するか、**Twitter** 🐦で私たちをフォローする [**@carlospolopm**](https://twitter.com/hacktricks_live)。
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

---

### **Windowsローカル特権昇格ベクターを探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [システム情報](windows-local-privilege-escalation/#system-info)

- [ ] [**システム情報**](windows-local-privilege-escalation/#system-info)を取得する
- [ ] スクリプトを使用して**カーネル**の[**脆弱性を検索**](windows-local-privilege-escalation/#version-exploits)
- [ ] Googleを使用してカーネルの**脆弱性を検索**する
- [ ] searchsploitを使用してカーネルの**脆弱性を検索**する
- [ ] [**環境変数**](windows-local-privilege-escalation/#environment)に興味深い情報はありますか？
- [ ] PowerShell履歴にパスワードはありますか？ [**PowerShell履歴**](windows-local-privilege-escalation/#powershell-history)
- [ ] [**インターネット設定**](windows-local-privilege-escalation/#internet-settings)に興味深い情報はありますか？
- [ ] [**ドライブ**](windows-local-privilege-escalation/#drives)は？
- [ ] [**WSUSの脆弱性**](windows-local-privilege-escalation/#wsus)は？
- [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)は？

### [ログ/AV列挙](windows-local-privilege-escalation/#enumeration)

- [ ] [**監査**](windows-local-privilege-escalation/#audit-settings)と[**WEF**](windows-local-privilege-escalation/#wef)の設定を確認する
- [ ] [**LAPS**](windows-local-privilege-escalation/#laps)を確認する
- [ ] [**WDigest**](windows-local-privilege-escalation/#wdigest)がアクティブかどうかを確認する
- [ ] [**LSA保護**](windows-local-privilege-escalation/#lsa-protection)は？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)は？
- [ ] [**キャッシュされた資格情報**](windows-local-privilege-escalation/#cached-credentials)は？
- [ ] いずれかの[**AV**](windows-av-bypass)があるかどうかを確認する
- [ ] [**AppLockerポリシー**](authentication-credentials-uac-and-efs#applocker-policy)は？
- [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)は？
- [**ユーザー権限**](windows-local-privilege-escalation/#users-and-groups)は？
- [ ] [**現在の**ユーザーの**権限**](windows-local-privilege-escalation/#users-and-groups)を確認する
- [ ] どの特権グループのメンバーですか？ [**特権グループ**](windows-local-privilege-escalation/#privileged-groups)を確認する
- [ ] これらのトークンのいずれかが有効になっているかどうかを確認する：**SeImpersonatePrivilege、SeAssignPrimaryPrivilege、SeTcbPrivilege、SeBackupPrivilege、SeRestorePrivilege、SeCreateTokenPrivilege、SeLoadDriverPrivilege、SeTakeOwnershipPrivilege、SeDebugPrivilege** [**トークン操作**](windows-local-privilege-escalation/#token-manipulation)は？
- [**ユーザーセッション**](windows-local-privilege-escalation/#logged-users-sessions)は？
- [ ] [**ユーザーのホーム**](windows-local-privilege-escalation/#home-folders)を確認する（アクセスは？）
- [ ] [**パスワードポリシー**](windows-local-privilege-escalation/#password-policy)は？
- [ ] クリップボードの中身は何ですか？ [**クリップボードの内容**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)は？

### [ネットワーク](windows-local-privilege-escalation/#network)

- [ ] **現在の**[**ネットワーク情報**](windows-local-privilege-escalation/#network)を確認する
- [ ] 外部に制限された**非表示のローカルサービス**を確認する

### [実行中のプロセス](windows-local-privilege-escalation/#running-processes)

- [ ] プロセスのバイナリ[**ファイルとフォルダの権限**](windows-local-privilege-escalation/#file-and-folder-permissions)を確認する
- [ ] [**メモリパスワードの採掘**](windows-local-privilege-escalation/#memory-password-mining)を行う
- [ ] [**セキュリティの脆弱なGUIアプリ**](windows-local-privilege-escalation/#insecure-gui-apps)を確認する
- [ ] `ProcDump.exe`を使用して、**興味深いプロセス**から資格情報を盗むことができますか？（firefox、chromeなど...）

### [サービス](windows-local-privilege-escalation/#services)

- [ ] 任意のサービスを**変更**できますか？ [**権限**](windows-local-privilege-escalation#permissions)を確認する
- [ ] 任意のサービスが実行する**バイナリ**を**変更**できますか？ [**サービスのバイナリパスの変更**](windows-local-privilege-escalation/#modify-service-binary-path)を確認する
- [ ] 任意のサービスの**レジストリ**を**変更**できますか？ [**サービスのレジストリ変更権限**](windows-local-privilege-escalation/#services-registry-modify-permissions)を確認する
- [ ] いずれかの**未引用サービス**バイナリ**パス**を利用できますか？ [**引用されていないサービスパス**](windows-local-privilege-escalation/#unquoted-service-paths)を確認する

### [**アプリケーション**](windows-local-privilege-escalation/#applications)

- インストールされたアプリケーションに**書き込み**権限がありますか？ [**インストールされたアプリケーションの書き込み権限**](windows-local-privilege-escalation/#write-permissions)を確認する
- [**起動アプリケーション**](windows-local-privilege-escalation/#run-at-startup)を確認する
- **脆弱な**[**ドライバー**](windows-local-privilege-escalation/#drivers)を確認する
### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] **PATH**内の**任意のフォルダに書き込めます**か？
* [ ] **存在しないDLLを読み込もうとする**既知のサービスバイナリはありますか？
* [ ] **バイナリフォルダに書き込めます**か？

### [ネットワーク](windows-local-privilege-escalation/#network)

* [ ] ネットワークを列挙します（共有、インターフェース、ルート、隣接者など）
* [ ] ローカルホスト（127.0.0.1）でリッスンしているネットワークサービスに特に注意します

### [Windows資格情報](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)資格情報
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault)で使用できる資格情報はありますか？
* [ ] 興味深い[**DPAPI資格情報**](windows-local-privilege-escalation/#dpapi)はありますか？
* [ ] 保存された[**Wifiネットワーク**](windows-local-privilege-escalation/#wifi)のパスワード
* [ ] 保存されたRDP接続に関する興味深い情報はありますか？
* [ ] [**リモートデスクトップ資格情報マネージャー**](windows-local-privilege-escalation/#remote-desktop-credential-manager)のパスワード
* [ ] [**AppCmd.exe**が存在](windows-local-privilege-escalation/#appcmd-exe)しますか？資格情報は？
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)はありますか？DLLサイドローディングは？

### [ファイルとレジストリ（資格情報）](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**資格情報**](windows-local-privilege-escalation/#putty-creds) **および** [**SSHホストキー**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] レジストリにある[**SSHキー**](windows-local-privilege-escalation/#ssh-keys-in-registry)はありますか？
* [ ] [**無人ファイル**](windows-local-privilege-escalation/#unattended-files)にパスワードはありますか？
* [ ] [**SAM＆SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)のバックアップはありますか？
* [ ] [**クラウド資格情報**](windows-local-privilege-escalation/#cloud-credentials)はありますか？
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)ファイルはありますか？
* [ ] [**キャッシュされたGPPパスワード**](windows-local-privilege-escalation/#cached-gpp-pasword)はありますか？
* [ ] [**IIS Web構成ファイル**](windows-local-privilege-escalation/#iis-web-config)にパスワードはありますか？
* [ ] [**Webログ**](windows-local-privilege-escalation/#logs)に興味深い情報はありますか？
* [ ] ユーザーに[**資格情報を要求**](windows-local-privilege-escalation/#ask-for-credentials)したいですか？
* [ ] リサイクルビン内の[**興味深いファイル**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)はありますか？
* [ ] 他の[**資格情報を含むレジストリ**](windows-local-privilege-escalation/#inside-the-registry)はありますか？
* [ ] ブラウザデータ（データベース、履歴、ブックマークなど）内にありますか？
* [**ファイルとレジストリ**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)内の一般的なパスワード検索
* パスワードを自動的に検索する[**ツール**](windows-local-privilege-escalation/#tools-that-search-for-passwords)はありますか？

### [漏洩したハンドラ](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 管理者によって実行されたプロセスのハンドラにアクセスできますか？

### [パイプクライアントの擬似化](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] それを悪用できるかどうかを確認します
