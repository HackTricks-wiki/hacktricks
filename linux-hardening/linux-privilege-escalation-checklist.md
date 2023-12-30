# チェックリスト - Linux権限昇格

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **あなたのハッキングのコツを共有するために、** [**HackTricksリポジトリ**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。​

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に焦点を当てたコンテンツに参加する

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、速いペースのハッキングの世界に追いつく

**最新の発表**\
最新のバグバウンティの開始と重要なプラットフォームの更新情報を入手する

**[**Discord**](https://discord.com/invite/N3FrSbmwdy)に参加して、今日からトップハッカーと協力し始めましょう！**

### **Linuxローカル権限昇格ベクトルを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/#system-information)

* [ ] **OS情報**を取得する
* [ ] [**PATH**](privilege-escalation/#path)をチェックする、**書き込み可能なフォルダ**はありますか？
* [ ] [**環境変数**](privilege-escalation/#env-info)をチェックする、機密情報はありますか？
* [ ] スクリプトを使用して[**カーネルの脆弱性**](privilege-escalation/#kernel-exploits)を探す（DirtyCow？）
* [ ] [**sudoバージョン**が脆弱かどうかをチェックする](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** 署名検証に失敗](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] より多くのシステム列挙（[日付、システム統計、CPU情報、プリンター](privilege-escalation/#more-system-enumeration)）
* [ ] [より多くの防御を列挙する](privilege-escalation/#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/#drives)

* [ ] **マウントされた**ドライブをリストする
* [ ] **マウントされていないドライブはありますか？**
* [ ] **fstabにクレデンシャルはありますか？**

### [**インストールされたソフトウェア**](privilege-escalation/#installed-software)

* [ ] **インストールされた**[ **便利なソフトウェア**](privilege-escalation/#useful-software)をチェックする
* [ ] **インストールされた** [**脆弱なソフトウェア**](privilege-escalation/#vulnerable-software-installed)をチェックする

### [プロセス](privilege-escalation/#processes)

* [ ] **不明なソフトウェアが実行されていますか？**
* [ ] **必要以上の権限で実行されているソフトウェアはありますか？**
* [ ] 実行中のプロセスの**脆弱性を探す**（特に実行中のバージョン）。
* [ ] 実行中のプロセスの**バイナリを変更**できますか？
* [ ] **プロセスを監視**し、頻繁に実行されている興味深いプロセスがないかチェックする。
* [ ] 興味深い**プロセスのメモリを読む**ことができますか？（パスワードが保存されている可能性があります）

### [スケジュールされた/クロンジョブは？](privilege-escalation/#scheduled-jobs)

* [ ] 何かのcronが[**PATH**](privilege-escalation/#cron-path)を変更しており、あなたがそれに**書き込む**ことができますか？
* [ ] cronジョブに[**ワイルドカード**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)はありますか？
* [ ] 何かの[**変更可能なスクリプト**](privilege-escalation/#cron-script-overwriting-and-symlink)が**実行されている**、または**変更可能なフォルダ内にありますか**？
* [ ] 何かの**スクリプト**が[**非常に頻繁に**](privilege-escalation/#frequent-cron-jobs)（1、2、5分ごとに）**実行されている**ことを検出しましたか？

### [サービス](privilege-escalation/#services)

* [ ] **書き込み可能な.serviceファイルはありますか？**
* [ ] **サービスによって実行される書き込み可能なバイナリはありますか？**
* [ ] **systemd PATH内の書き込み可能なフォルダはありますか？**

### [タイマー](privilege-escalation/#timers)

* [ ] **書き込み可能なタイマーはありますか？**

### [ソケット](privilege-escalation/#sockets)

* [ ] **書き込み可能な.socketファイルはありますか？**
* [ ] **何かのソケットと通信できますか？**
* [ ] 興味深い情報を持つ**HTTPソケットはありますか？**

### [D-Bus](privilege-escalation/#d-bus)

* [ ] **何かのD-Busと通信できますか？**

### [ネットワーク](privilege-escalation/#network)

* [ ] ネットワークを列挙して、あなたがどこにいるかを知る
* [ ] マシン内にシェルを取得する前にアクセスできなかった**オープンポートはありますか？**
* [ ] `tcpdump`を使用して**トラフィックを嗅ぐ**ことができますか？

### [ユーザー](privilege-escalation/#users)

* [ ] 一般的なユーザー/グループの**列挙**
* [ ] **非常に大きなUID**を持っていますか？**マシンは脆弱ですか？**
* [ ] 所属しているグループのおかげで[**権限を昇格させることができますか？**](privilege-escalation/interesting-groups-linux-pe/)
* [ ] **クリップボード**のデータは？
* [ ] パスワードポリシーは？
* [ ] 以前に発見した**すべての既知のパスワード**を使用して、可能な**各ユーザー**でログインを試みます。パスワードなしでのログインも試してください。

### [書き込み可能なPATH](privilege-escalation/#writable-path-abuses)

* [ ] PATH内のいくつかのフォルダに**書き込み権限がある場合**、権限を昇格させることができるかもしれません

### [SUDOとSUIDコマンド](privilege-escalation/#sudo-and-suid)

* [ ] **sudoを使用して任意のコマンドを実行できますか？** rootとしてREAD、WRITE、またはEXECUTEを使用できますか？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] **悪用可能なSUIDバイナリはありますか？**（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] [**sudo** コマンドは**パスによって制限されていますか？** 制限を**バイパス**できますか？](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**パスが指定されていないSudo/SUIDバイナリ**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**パスを指定するSUIDバイナリ**](privilege-escalation/#suid-binary-with-command-path)? バイパス
* [ ] [**LD\_PRELOADの脆弱性**](privilege-escalation/#ld\_preload)
* [ ] [**SUIDバイナリで書き込み可能なフォルダから.soライブラリが欠けている**](privilege-escalation/#suid-binary-so-injection)?
* [ ] [**利用可能なSUDOトークン**](privilege-escalation/#reusing-sudo-tokens)? [**SUDOトークンを作成できますか**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] [**sudoersファイルを読んだり変更したりできますか**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] [**/etc/ld.so.conf.d/を変更できますか？**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) コマンド

### [機能](privilege-escalation/#capabilities)

* [ ] 何かのバイナリに**予期しない機能**はありますか？

### [ACL](privilege-escalation/#acls)

* [ ] 何かのファイルに**予期しないACL**はありますか？

### [オープンなシェルセッション](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSHの興味深い設定値**](privilege-escalation/#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/#interesting-files)

* [ ] **プロファイルファイル** - 機密データを読む？privescに書き込む？
* [ ] **passwd/shadowファイル** - 機密データを読む？privescに書き込む？
* [ ] 機密データのために**一般的に興味深いフォルダ**をチェックする
* [ ] **変わった場所/所有されたファイル**、実行可能なファイルにアクセスしたり変更したりできるかもしれません
* [ ] 最後の数分で**変更された**
* [ ] **Sqlite DBファイル**
* [ ] **隠しファイル**
* [ ] **PATH内のスクリプト/バイナリ**
* [ ] **Webファイル**（パスワード？）
* [ ] **バックアップ**は？
* [ ] **パスワードが含まれている既知のファイル**: **Linpeas**と**LaZagne**を使用する
* [ ] **一般的な検索**

### [**書き込み可能なファイル**](privilege-escalation/#writable-files)

* [ ] **任意のコマンドを実行するためにpythonライブラリを変更できますか？**
* [ ] **ログファイルを変更できますか？** **Logtotten** exploit
* [ ] **/etc/sysconfig/network-scripts/を変更できますか？** Centos/Redhat exploit
* [ ] [**ini、int.d、systemd、またはrc.dファイルに書き込むことができますか？**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**その他のコツ**](privilege-escalation/#other-tricks)

* [ ] [**NFSを悪用して権限を昇格させることができますか？**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] [**制限されたシェルから脱出する必要がありますか？**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><
