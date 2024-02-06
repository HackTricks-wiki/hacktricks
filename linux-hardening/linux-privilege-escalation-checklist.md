# チェックリスト - Linux 特権昇格

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでのAWSハッキングを学ぶ**！</summary>

HackTricks をサポートする他の方法:

- **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
- **Discordグループ**💬 に参加するか、[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 で **@hacktricks_live** をフォローする。

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取ろう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に深く入り込むコンテンツに参加

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を最新の状態に保つ

**最新のアナウンス**\
最新のバグバウンティの開始や重要なプラットフォームの更新情報を把握

**Discord** で [**参加**](https://discord.com/invite/N3FrSbmwdy) し、今日からトップハッカーと協力し始めよう！

### **Linux ローカル特権昇格ベクターを探すための最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/#system-information)

- [ ] **OS情報**を取得する
- [ ] [**PATH**](privilege-escalation/#path)をチェックし、**書き込み可能なフォルダ**はあるか？
- [ ] [**環境変数**](privilege-escalation/#env-info)をチェックし、機密情報はあるか？
- [ ] スクリプトを使用して [**カーネルの脆弱性**](privilege-escalation/#kernel-exploits) を検索する（DirtyCowなど）
- [ ] [**sudoのバージョン**が脆弱かどうかをチェック](privilege-escalation/#sudo-version)する
- [ ] [**Dmesg** 署名検証に失敗](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] その他のシステム列挙（日付、システム統計、CPU情報、プリンタ）を行う（[**詳細はこちら**](privilege-escalation/#more-system-enumeration)）
- [ ] [さらなる防御策を列挙](privilege-escalation/#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/#drives)

- [ ] マウントされたドライブをリストアップする
- [ ] マウントされていないドライブはあるか？
- [ ] fstab に資格情報はあるか？

### [**インストールされたソフトウェア**](privilege-escalation/#installed-software)

- [ ] **インストールされた便利なソフトウェア**をチェックする（[**詳細はこちら**](privilege-escalation/#useful-software)）
- [ ] **インストールされた脆弱なソフトウェア**をチェックする（[**詳細はこちら**](privilege-escalation/#vulnerable-software-installed)）

### [プロセス](privilege-escalation/#processes)

- [ ] **不明なソフトウェアが実行中**か？
- [ ] **必要以上の権限で実行されているソフトウェア**があるか？
- [ ] 実行中のプロセスの **脆弱性を検索**する（特に実行中のバージョン）
- [ ] 実行中のプロセスのバイナリを **変更**できるか？
- [ ] プロセスを **監視**し、頻繁に実行されている興味深いプロセスがあるかどうかを確認する
- [ ] 興味深い **プロセスメモリ**（パスワードが保存されている可能性のある場所）を **読み取る**ことができるか？

### [スケジュールされた/Cronジョブ？](privilege-escalation/#scheduled-jobs)

- [ ] いくつかの cron によって **PATH** が変更され、書き込み可能になっているか？
- [ ] cron ジョブに **ワイルドカード** があるか？
- [ ] 実行されている **変更可能なスクリプト** があるか、または **変更可能なフォルダ** の中にあるか？
- [ ] いくつかの **スクリプト** が非常に **頻繁に実行**されていることが検出されたか？（1分、2分、5分ごと）

### [サービス](privilege-escalation/#services)

- [ ] **書き込み可能な .service** ファイルはあるか？
- [ ] **サービス** によって実行される **書き込み可能なバイナリ** はあるか？
- [ ] systemd PATH に **書き込み可能なフォルダ** はあるか？

### [タイマー](privilege-escalation/#timers)

- [ ] **書き込み可能なタイマー** はあるか？

### [ソケット](privilege-escalation/#sockets)

- [ ] **書き込み可能な .socket** ファイルはあるか？
- [ ] 任意のソケットと **通信**できるか？
- [ ] 興味深い情報を持つ **HTTPソケット** はあるか？

### [D-Bus](privilege-escalation/#d-bus)

- [ ] 任意の **D-Bus** と **通信**できるか？

### [ネットワーク](privilege-escalation/#network)

- ネットワークを列挙して、自分がどこにいるかを知る
- シェルを取得する前にアクセスできなかった **オープンポート** はあるか？
- `tcpdump` を使用して **トラフィックをスニッフ** できるか？

### [ユーザー](privilege-escalation/#users)

- 一般的なユーザー/グループを **列挙** する
- **非常に大きなUID** を持っているか？ **マシン** は **脆弱** か？
- 所属しているグループを通じて特権を昇格できるか？
- **クリップボード** データは？
- パスワードポリシーは？
- 以前に発見した **すべての既知のパスワード** を使用して、各 **可能なユーザー** でログインしてみる。パスワードなしでもログインできるかも試してみる。

### [書き込み可能なPATH](privilege-escalation/#writable-path-abuses)

- **PATH内のいくつかのフォルダに書き込み権限** がある場合、特権を昇格できるかもしれない

### [SUDOとSUIDコマンド](privilege-escalation/#sudo-and-suid)

- **sudoで任意のコマンドを実行**できるか？それを使用して何かをルートとして **読み取り、書き込み、実行** できるか？（[**GTFOBins**](https://gtfobins.github.io)）
- **悪用可能なSUIDバイナリ** はあるか？（[**GTFOBins**](https://gtfobins.github.io)）
- **sudoコマンドがパスによって制限**されているか？ 制限を **バイパス** できるか？
- **パスが指定されていないSudo/SUIDバイナリ** はあるか？（[**詳細はこちら**](privilege-escalation/#sudo-command-suid-binary-without-command-path)）
- **パスが指定されたSUIDバイナリ** はあるか？ バイパスできるか？
- **LD\_PRELOAD脆弱性** はあるか？（[**詳細はこちら**](privilege-escalation/#ld\_preload)）
- 書き込み可能なフォルダからの **SUIDバイナリにおける.soライブラリの不足** はあるか？（[**詳細はこちら**](privilege-escalation/#suid-binary-so-injection)）
- **SUDOトークンが利用可能** か？ [**SUDOトークンを作成**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)できるか？
- **sudoersファイルを読み取るか変更** できるか？（[**詳細はこちら**](privilege-escalation/#etc-sudoers-etc-sudoers-d)）
- **/etc/ld.so.conf.d/** を **変更** できるか？（[**詳細はこちら**](privilege-escalation/#etc-ld-so-conf-d)）
- **OpenBSD DOAS** コマンド

### [機能](privilege-escalation/#capabilities)

- 任意のバイナリに **予期しない機能** があるか？

### [ACL](privilege-escalation/#acls)

- 任意のファイルに **予期しないACL** があるか？

### [オープンシェルセッション](privilege-escalation/#open-shell-sessions)

- **screen**
- **tmux**

### [SSH](privilege-escalation/#ssh)

- **Debian** の [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [**SSHの興味深い構成値**](privilege-escalation/#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/#interesting-files)

- **プロファイルファイル** - 機密データを読み取る？ 特権昇格に書き込む？
- **passwd/shadowファイル** - 機密データを読み取る？ 特権昇格に書き込む？
- 機密データが含まれる可能性のある **一般的に興味深いフォルダ** をチェックする
- **奇妙な場所/所有ファイル**、アクセス権があるか、実行可能ファイルを変更できるか
- **最後の数分で変更**されたファイル
- **Sqlite DBファイル**
- **隠しファイル**
- **PATH内のスクリプト/バイナリ**
- **Webファイル**（パスワード？）
- **バックアップ**？
- **パスワードを含む既知のファイル**：**Linpeas** と **LaZagne** を使用
- **一般的な検索**

### [**書き込み可能なファイル**](privilege-escalation/#writable-files)

- **Pythonライブラリを変更**して任意のコマンドを実行できるか？
- **ログファイルを変更**できるか？ **Logtotten** exploit
- **/etc/sysconfig/network-scripts/** を変更できるか？ Centos/Redhat exploit
- **ini、int.d、systemd、rc.dファイルに書き込む**ことができるか？（[**詳細はこちら**](privilege-escalation/#init-init-d-systemd-and-rc-d)）

### [**その他のトリック**](privilege-escalation/#other-tricks)

- 特権昇格するために **NFSを悪用** できるか？
- **制限的なシェルから脱出**する必要があるか？（[**詳細はこちら**](privilege-escalation/#escaping-from-restricted-shells)）

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取ろう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に深く入り込むコンテンツに参加

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を最新の状態に保つ

**最新のアナウンス**\
最新のバグバウンティの開始や重要なプラットフォームの更新情報を把握

**Discord** で [**参加**](https://discord.com/invite/N3FrSbmwdy) し、今日からトップハッカーと協力し始めよう！

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでのAWSハッキングを学ぶ**！</summary>

HackTricks をサポートする他の方法:

- **HackTricks で企業を宣
