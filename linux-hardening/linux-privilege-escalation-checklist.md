# チェックリスト - Linux権限昇格

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のPRを提出して、あなたのハッキングのコツを共有する。

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に焦点を当てたコンテンツに参加する

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、速いペースのハッキングの世界に最新の情報を保つ

**最新の発表**\
最新のバグバウンティの開始と重要なプラットフォームの更新情報を入手する

**[**Discord**](https://discord.com/invite/N3FrSbmwdy)に参加して、今日からトップハッカーと協力しましょう！

### **Linuxローカル権限昇格ベクトルを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/#system-information)

* [ ] **OS情報**を取得する
* [ ] [**PATH**](privilege-escalation/#path)をチェックする、**書き込み可能なフォルダー**はあるか？
* [ ] [**環境変数**](privilege-escalation/#env-info)をチェックする、機密情報はあるか？
* [ ] スクリプトを使用して[**カーネルの脆弱性**](privilege-escalation/#kernel-exploits)を探す（DirtyCow？）
* [ ] [**sudoバージョン**が脆弱かどうかを**チェック**する](privilege-escalation/#sudo-version)
* [ ] [**Dmesg**署名検証に失敗](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] より多くのシステム列挙（[日付、システム統計、CPU情報、プリンター](privilege-escalation/#more-system-enumeration)）
* [ ] [より多くの防御を列挙する](privilege-escalation/#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/#drives)

* [ ] **マウントされた**ドライブをリストする
* [ ] **マウントされていないドライブはあるか？**
* [ ] **fstabにクレデンシャルはあるか？**

### [**インストールされたソフトウェア**](privilege-escalation/#installed-software)

* [ ] **インストールされた**[ **便利なソフトウェア**](privilege-escalation/#useful-software)を**チェックする**
* [ ] **インストールされた** [**脆弱なソフトウェア**](privilege-escalation/#vulnerable-software-installed)を**チェックする**

### [プロセス](privilege-escalation/#processes)

* [ ] **不明なソフトウェアが実行されているか？**
* [ ] 何かのソフトウェアが**本来よりも多くの権限で実行されているか？**
* [ ] 実行中のプロセスの**脆弱性を探す**（特に実行中のバージョン）。
* [ ] 実行中のプロセスの**バイナリを変更**できるか？
* [ ] **プロセスを監視**し、頻繁に実行されている興味深いプロセスがないかチェックする。
* [ ] 興味深い**プロセスのメモリを読む**ことができるか？（パスワードが保存されている可能性がある）

### [スケジュールされた/クロンジョブは？](privilege-escalation/#scheduled-jobs)

* [ ] クロンによって[**PATH** ](privilege-escalation/#cron-path)が変更されていて、あなたが**書き込み**ができるか？
* [ ] クロンジョブに[**ワイルドカード** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)はあるか？
* [ ] 何か[**変更可能なスクリプト** ](privilege-escalation/#cron-script-overwriting-and-symlink)が**実行されている**、または**変更可能なフォルダー**の中にあるか？
* [ ] 何かの**スクリプト**が[**非常に頻繁に**実行されている](privilege-escalation/#frequent-cron-jobs)ことを検出したか？（1、2、5分ごと）

### [サービス](privilege-escalation/#services)

* [ ] どんな**書き込み可能な.service**ファイルはあるか？
* [ ] サービスによって実行される**書き込み可能なバイナリ**はあるか？
* [ ] systemd PATH内の**書き込み可能なフォルダー**はあるか？

### [タイマー](privilege-escalation/#timers)

* [ ] どんな**書き込み可能なタイマー**はあるか？

### [ソケット](privilege-escalation/#sockets)

* [ ] どんな**書き込み可能な.socket**ファイルはあるか？
* [ ] どんなソケットとも**通信できるか**？
* [ ] 興味深い情報を持つ**HTTPソケット**はあるか？

### [D-Bus](privilege-escalation/#d-bus)

* [ ] どんなD-Busとも**通信できるか**？

### [ネットワーク](privilege-escalation/#network)

* [ ] ネットワークを列挙して、自分がどこにいるかを知る
* [ ] マシン内にシェルを取得する前にアクセスできなかった**オープンポート**はあるか？
* [ ] `tcpdump`を使用して**トラフィックを嗅ぐ**ことができるか？

### [ユーザー](privilege-escalation/#users)

* [ ] 一般的なユーザー/グループの**列挙**
* [ ] **非常に大きなUID**を持っているか？**マシン**は**脆弱**か？
* [ ] 所属しているグループのおかげで[**権限を昇格させることができるか**](privilege-escalation/interesting-groups-linux-pe/)？
* [ ] **クリップボード**のデータは？
* [ ] パスワードポリシーは？
* [ ] 以前に発見したすべての**既知のパスワード**を使用して、可能な**各ユーザー**でログインを**試みる**。パスワードなしでのログインも試みる。

### [書き込み可能なPATH](privilege-escalation/#writable-path-abuses)

* [ ] PATHの中のいくつかのフォルダーに**書き込み権限がある**場合、権限を昇格させることができるかもしれない

### [SUDOとSUIDコマンド](privilege-escalation/#sudo-and-suid)

* [ ] **任意のコマンドをsudoで実行**できるか？rootとしてREAD、WRITE、またはEXECUTEを使用できるか？([**GTFOBins**](https://gtfobins.github.io))
* [ ] どんな**利用可能なSUIDバイナリ**はあるか？([**GTFOBins**](https://gtfobins.github.io))
* [ ] [**sudo**コマンドは**パス**によって**制限されている**か？制限を**バイパス**できるか](privilege-escalation/#sudo-execution-bypassing-paths)？
* [ ] [**パスが指定されていないSudo/SUIDバイナリ**](privilege-escalation/#sudo-command-suid-binary-without-command-path)？
* [ ] [**パスを指定するSUIDバイナリ**](privilege-escalation/#suid-binary-with-command-path)？バイパス
* [ ] [**LD\_PRELOADの脆弱性**](privilege-escalation/#ld\_preload)
* [ ] [**SUIDバイナリで.soライブラリが不足している**](privilege-escalation/#suid-binary-so-injection) 書き込み可能なフォルダーから？
* [ ] [**SUDOトークンが利用可能**](privilege-escalation/#reusing-sudo-tokens)か？[**SUDOトークンを作成できるか**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)？
* [ ] [**sudoersファイルを読み取りまたは変更できるか**](privilege-escalation/#etc-sudoers-etc-sudoers-d)？
* [ ] [**/etc/ld.so.conf.d/を変更できるか**](privilege-escalation/#etc-ld-so-conf-d)？
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas)コマンド

### [機能](privilege-escalation/#capabilities)

* [ ] どんなバイナリにも**予期しない機能**はあるか？

### [ACL](privilege-escalation/#acls)

* [ ] どんなファイルにも**予期しないACL**はあるか？

### [オープンシェルセッション](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSHの興味深い設定値**](privilege-escalation/#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/#interesting-files)

* [ ] **プロファイルファイル** - 機密データを読む？privescに書き込む？
* [ ] **passwd/shadowファイル** - 機密データを読む？privescに書き込む？
* [ ] 機密データのために**一般的に興味深いフォルダー**をチェックする
* [ ] **変わった場所/所有されたファイル**、実行可能なファイルにアクセスしたり変更したりできるかもしれない
* [ ] 最後の数分で**変更された**
* [ ] **Sqlite DBファイル**
* [ ] **隠しファイル**
* [ ] **PATH内のスクリプト/バイナリ**
* [ ] **Webファイル**（パスワード？）
* [ ] **バックアップ**は？
* [ ] **パスワードが含まれている既知のファイル**: **Linpeas**と**LaZagne**を使用する
* [ ] **一般的な検索**

### [**書き込み可能なファイル**](privilege-escalation/#writable-files)

* [ ] **pythonライブラリを変更**して任意のコマンドを実行できるか？
* [ ] **ログファイルを変更**できるか？**Logtotten**の脆弱性
* [ ] **/etc/sysconfig/network-scripts/**を変更できるか？Centos/Redhatの脆弱性
* [ ] [**ini、int.d、systemd、またはrc.dファイルに書き込む**](privilege-escalation/#init-init-d-systemd-and-rc-d)ことができるか？

### [**その他のトリック**](privilege-escalation/#other-tricks)

* [ ] [**NFSを悪用して権限を昇格させることができるか**](privilege-escalation/#nfs-privilege-escalation)？
* [ ] [**制限されたシェルから脱出する必要があるか**](privilege-escalation/#escaping-from-restricted-shells)？

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に焦点を当てたコンテンツに参加する

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、速い
