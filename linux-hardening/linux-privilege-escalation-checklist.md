# チェックリスト - Linux特権エスカレーション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有する**ために、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**HackenProofをフォロー**](https://bit.ly/3xrrDrL) **して、web3のバグについてもっと学びましょう**

🐞 web3のバグチュートリアルを読む

🔔 新しいバグバウンティについて通知を受ける

💬 コミュニティディスカッションに参加する

### **Linuxローカル特権エスカレーションのベストツール：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/#system-information)

* [ ] **OS情報を取得する**
* [ ] [**PATH**](privilege-escalation/#path)をチェックする、**書き込み可能なフォルダ**はありますか？
* [ ] [**環境変数**](privilege-escalation/#env-info)をチェックする、**機密情報**はありますか？
* [ ] スクリプトを使用して[**カーネルの脆弱性**](privilege-escalation/#kernel-exploits)を検索する（DirtyCowなど）。
* [ ] [**sudoのバージョン**が脆弱性を持っているかどうかをチェックする](privilege-escalation/#sudo-version)
* [ ] [**Dmesg**の署名検証に失敗しました](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] システムの列挙（日付、システム統計、CPU情報、プリンターなど）をさらに行う（privilege-escalation/#more-system-enumeration）
* [ ] [より多くの防御策を列挙する](privilege-escalation/#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/#drives)

* [ ] マウントされたドライブをリストアップする
* [ ] マウントされていないドライブはありますか？
* [ ] fstabにクレデンシャルはありますか？

### [**インストールされたソフトウェア**](privilege-escalation/#installed-software)

* [ ] [**有用なソフトウェア**](privilege-escalation/#useful-software)がインストールされているかどうかをチェックする
* [ ] [**脆弱なソフトウェア**](privilege-escalation/#vulnerable-software-installed)がインストールされているかどうかをチェックする

### [プロセス](privilege-escalation/#processes)

* [ ] **不明なソフトウェアが実行されていますか**？
* [ ] **必要以上の権限で実行されているソフトウェア**はありますか？
* [ ] 実行中のプロセスの**脆弱性**を検索する（特に実行中のバージョン）。
* [ ] 実行中のプロセスのバイナリを**変更**できますか？
* [ ] プロセスを**監視**し、頻繁に実行されている興味深いプロセスがあるかどうかをチェックする。
* [ ] 興味深いプロセスのメモリ（パスワードが保存されている可能性のある場所）を**読み取る**ことができますか？

### [スケジュールされた/Cronジョブ？](privilege-escalation/#scheduled-jobs)

* [ ] cronによって[**PATH** ](privilege-escalation/#cron-path)が変更され、書き込みができますか？
* [ ] cronジョブに[**ワイルドカード** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)がありますか？
* [ ] 実行されている**変更可能なスクリプト**または**変更可能なフォルダ**にありますか？
* [ ] いくつかのスクリプトが非常に頻繁に実行されていることが検出されましたか？（1分、2分、または5分ごと）

### [サービス](privilege-escalation/#services)

* [ ] **書き込み可能な.service**ファイルはありますか？
* [ ] **サービス**によって実行される**書き込み可能なバイナリ**はありますか？
* [ ] systemd PATHに**書き込み可能なフォルダ**はありますか？

### [タイマー](privilege-escalation/#timers)

* [ ] **書き込み可能なタイマー**はありますか？

### [ソケット](privilege-escalation/#sockets)

* [ ] **書き込み可能な.socket**ファイルはありますか？
* [ ] 任意のソケットと**通信**できますか？
* [ ] おもしろい情報が含まれる**HTTPソケット**はありますか？
### [D-Bus](privilege-escalation/#d-bus)

* [ ] どのD-Busとも**通信できますか**？

### [ネットワーク](privilege-escalation/#network)

* [ ] 自分がどこにいるかを知るためにネットワークを列挙します
* [ ] **シェルを取得する前にアクセスできなかったポート**を開けますか？
* [ ] `tcpdump`を使用してトラフィックを**スニフィング**できますか？

### [ユーザー](privilege-escalation/#users)

* [ ] 一般的なユーザー/グループの**列挙**
* [ ] **非常に大きなUID**を持っていますか？**マシン**は**脆弱**ですか？
* [ ] 所属しているグループを利用して特権を**エスカレーション**できますか？([**Linux特権エスカレーションの興味深いグループ**](privilege-escalation/interesting-groups-linux-pe/))
* [ ] **クリップボード**のデータ？
* [ ] パスワードポリシー？
* [ ] 以前に発見した**すべての既知のパスワード**を使用して、**各**可能な**ユーザー**でログインしようとしてみてください。パスワードなしでもログインしてみてください。

### [書き込み可能なPATH](privilege-escalation/#writable-path-abuses)

* [ ] PATH内の**いくつかのフォルダに書き込み権限**がある場合、特権をエスカレーションできるかもしれません

### [SUDOとSUIDコマンド](privilege-escalation/#sudo-and-suid)

* [ ] **sudoで任意のコマンドを実行**できますか？それを使用してrootとして何かを**読み取り、書き込み、実行**できますか？([**GTFOBins**](https://gtfobins.github.io))
* [ ] **悪用可能なSUIDバイナリ**はありますか？([**GTFOBins**](https://gtfobins.github.io))
* [ ] [**sudoコマンドがパスで制限**されていますか？制限を**バイパス**できますか](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**パスが指定されていないSUDO/SUIDバイナリ**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**パスが指定されたSUIDバイナリ**](privilege-escalation/#suid-binary-with-command-path)? バイパス
* [ ] [**LD\_PRELOADの脆弱性**](privilege-escalation/#ld\_preload)
* [ ] 書き込み可能なフォルダからの**SUIDバイナリに.soライブラリがない**([**GTFOBins**](https://gtfobins.github.io))？
* [ ] [**SUDOトークンが利用可能**](privilege-escalation/#reusing-sudo-tokens)ですか？[**SUDOトークンを作成**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)できますか？
* [ ] [**sudoersファイルを読み取るか変更**](privilege-escalation/#etc-sudoers-etc-sudoers-d)できますか？
* [ ] [**/etc/ld.so.conf.d/**を**変更**](privilege-escalation/#etc-ld-so-conf-d)できますか？
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas)コマンド

### [機能](privilege-escalation/#capabilities)

* [ ] どのバイナリにも**予期しない機能**がありますか？

### [ACL](privilege-escalation/#acls)

* [ ] どのファイルにも**予期しないACL**がありますか？

### [オープンシェルセッション](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian**の[**OpenSSL予測可能なPRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSHの興味深い設定値**](privilege-escalation/#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/#interesting-files)

* [ ] **プロファイルファイル** - 機密データを読み取る？特権エスカレーションに書き込む？
* [ ] **passwd/shadowファイル** - 機密データを読み取る？特権エスカレーションに書き込む？
* [ ] 機密データが含まれる可能性のある**一般的に興味深いフォルダ**をチェックします
* [ ] **奇妙な場所/所有ファイル**、アクセスまたは実行可能なファイルを変更できるかもしれません
* [ ] 最後の数分で**変更**されましたか
* [ ] **Sqlite DBファイル**
* [ ] **隠しファイル**
* [ ] **PATH内のスクリプト/バイナリ**
* [ ] **Webファイル**（パスワード？）
* [ ] **バックアップ**？
* [ ] パスワードを含む**既知のファイル**：**Linpeas**と**LaZagne**を使用します
* [ ] **一般的な検索**

### [**書き込み可能なファイル**](privilege-escalation/#writable-files)

* [ ] **Pythonライブラリ**を変更して任意のコマンドを実行できますか？
* [ ] **ログファイル**を変更できますか？**Logtotten**の脆弱性
* [ ] **/etc/sysconfig/network-scripts/**を変更できますか？Centos/Redhatの脆弱性
* [ ] ini、int.d、systemd、またはrc.dファイルに**書き込み**できますか？

### [**その他のトリック**](privilege-escalation/#other-tricks)

* [ ] 特権をエスカレーションするために**NFSを悪用**できますか？
* [ ] 制限のあるシェルから**脱出**する必要がありますか？

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**HackenProofをフォロー**](https://bit.ly/3xrrDrL) **して、web3のバグについてもっと学びましょう**

🐞 web3のバグチュートリアルを読む

🔔 新しいバグバウンティについて通知を受ける

💬 コミュニティディスカッションに参加する

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？**HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlo
</details>
