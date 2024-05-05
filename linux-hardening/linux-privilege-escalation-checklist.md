# チェックリスト - Linux特権昇格

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong>！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする
- **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加しましょう

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を最新の状態に保ちましょう

**最新のアナウンスメント**\
最新のバグバウンティの開始や重要なプラットフォームのアップデートについて情報を得ましょう

**Discord**で[**参加**](https://discord.com/invite/N3FrSbmwdy)し、今日からトップハッカーと協力しましょう！

### **Linuxローカル特権昇格ベクターを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/#system-information)

- [ ] **OS情報を取得**
- [ ] [**PATH**](privilege-escalation/#path)をチェックし、**書き込み可能なフォルダ**はあるか？
- [ ] [**環境変数**](privilege-escalation/#env-info)をチェックし、機密情報はあるか？
- [ ] スクリプトを使用して[**カーネルの脆弱性**](privilege-escalation/#kernel-exploits)を検索する（DirtyCowなど）
- [ ] [**sudoバージョンが脆弱**](privilege-escalation/#sudo-version)かどうかをチェック
- [ ] [**Dmesg**署名検証に失敗](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] その他のシステム列挙（日付、システム統計、CPU情報、プリンタ）を実行する[**（詳細はこちら）**](privilege-escalation/#more-system-enumeration)
- [ ] [さらなる防御策を列挙](privilege-escalation/#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/#drives)

- [ ] マウントされたドライブをリストアップ
- [ ] マウントされていないドライブはあるか？
- [ ] fstabにクレデンシャルはあるか？

### [**インストールされたソフトウェア**](privilege-escalation/#installed-software)

- [ ] **インストールされた**[ **有用なソフトウェア**](privilege-escalation/#useful-software)をチェック
- [ ] **インストールされた**[**脆弱なソフトウェア**](privilege-escalation/#vulnerable-software-installed)をチェック

### [プロセス](privilege-escalation/#processes)

- [ ] **不明なソフトウェアが実行中**か？
- [ ] **必要以上の権限で実行されているソフトウェア**があるか？
- [ ] 実行中のプロセスの**脆弱性を検索**する（特に実行中のバージョン）
- [ ] 実行中のプロセスのバイナリを**変更**できるか？
- [ ] プロセスを**監視**し、興味深いプロセスが頻繁に実行されていないか確認する
- [ ] 興味深い**プロセスメモリ**（パスワードが保存されている可能性がある場所）を**読み取る**ことができるか？

### [スケジュールされた/Cronジョブ？](privilege-escalation/#scheduled-jobs)

- [ ] 一部のcronによって[**PATH** ](privilege-escalation/#cron-path)が変更され、書き込み可能になっているか？
- [ ] クロンジョブに[**ワイルドカード** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)があるか？
- [ ] 実行されている[**変更可能なスクリプト** ](privilege-escalation/#cron-script-overwriting-and-symlink)があるか、または変更可能なフォルダ内にあるか？
- [ ] いくつかのスクリプトが非常に**頻繁に実行**されていることを検出しましたか？（1分、2分、5分ごと）

### [サービス](privilege-escalation/#services)

- [ ] 書き込み可能な.serviceファイルはありますか？
- [ ] サービスによって実行される**書き込み可能なバイナリ**はありますか？
- [ ] systemd PATH内に**書き込み可能なフォルダ**はありますか？

### [タイマー](privilege-escalation/#timers)

- [ ] 書き込み可能な**タイマー**はありますか？

### [ソケット](privilege-escalation/#sockets)

- [ ] 書き込み可能な.socketファイルはありますか？
- [ ] 任意のソケットと**通信**できますか？
- [ ] 興味深い情報を持つ**HTTPソケット**はありますか？

### [D-Bus](privilege-escalation/#d-bus)

- [ ] 任意のD-Busと**通信**できますか？

### [ネットワーク](privilege-escalation/#network)

- ネットワークを列挙して、自分がどこにいるかを知る
- シェルを取得する前にアクセスできなかった**オープンポート**はありますか？
- `tcpdump`を使用してトラフィックを**スニッフィング**できますか？

### [ユーザー](privilege-escalation/#users)

- 一般的なユーザー/グループを**列挙**
- **非常に大きなUID**を持っていますか？**マシン**は**脆弱**ですか？
- 所属しているグループを通じて特権を昇格できますか？
- **クリップボード**のデータは？
- パスワードポリシーは？
- 以前に発見した**すべての既知のパスワード**を使用して、**各**可能な**ユーザー**でログインできるか試してください。パスワードなしでもログインできるかもしれません。

### [書き込み可能なPATH](privilege-escalation/#writable-path-abuses)

- PATH内の**いくつかのフォルダに書き込み権限**がある場合、特権を昇格できるかもしれません

### [SUDOおよびSUIDコマンド](privilege-escalation/#sudo-and-suid)

- **sudoで任意のコマンドを実行**できますか？それを使用して、ルートとして**読み取り、書き込み、実行**できますか？（[**GTFOBins**](https://gtfobins.github.io)）
- **悪用可能なSUIDバイナリ**がありますか？（[**GTFOBins**](https://gtfobins.github.io)）
- [**sudo**コマンドが**パス**で**制限**されていますか？制限を**バイパス**できますか](privilege-escalation/#sudo-execution-bypassing-paths)?
- [**パスが指定されていないSudo/SUIDバイナリ**](privilege-escalation/#sudo-command-suid-binary-without-command-path)がありますか？
- [**パスが指定されているSUIDバイナリ**](privilege-escalation/#suid-binary-with-command-path)はありますか？バイパス
- [**LD\_PRELOAD脆弱性**](privilege-escalation/#ld\_preload)
- 書き込み可能なフォルダからのSUIDバイナリに**.soライブラリが不足**していますか？（[**詳細はこちら**](privilege-escalation/#suid-binary-so-injection)）
- [**SUDOトークンが利用可能**](privilege-escalation/#reusing-sudo-tokens)ですか？[**SUDOトークンを作成**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)できますか？
- [**sudoersファイルを読み取る**](privilege-escalation/#etc-sudoers-etc-sudoers-d)ことができますか？
- [**/etc/ld.so.conf.d/**を**変更**できますか？（[**詳細はこちら**](privilege-escalation/#etc-ld-so-conf-d)）
- [**OpenBSD DOAS**](privilege-escalation/#doas)コマンド
### [機能](privilege-escalation/#capabilities)

* [ ] どのバイナリにも**予期しない機能**がありますか？

### [ACL](privilege-escalation/#acls)

* [ ] どのファイルにも**予期しないACL**がありますか？

### [オープンシェルセッション](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH興味深い構成値**](privilege-escalation/#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/#interesting-files)

* [ ] **プロファイルファイル** - 機密データを読む？権限昇格に書き込む？
* [ ] **passwd/shadowファイル** - 機密データを読む？権限昇格に書き込む？
* [ ] **一般的に興味深いフォルダ**に機密データがあるかどうかを確認
* [ ] **奇妙な場所/所有ファイル**、アクセス権があるか実行可能ファイルを変更できるかもしれません
* [ ] 最後の数分で**変更**
* [ ] **Sqlite DBファイル**
* [ ] **隠しファイル**
* [ ] **PATH内のスクリプト/バイナリ**
* [ ] **Webファイル**（パスワード？）
* [ ] **バックアップ**？
* [ ] **パスワードを含む既知のファイル**：**Linpeas**と**LaZagne**を使用
* [ ] **一般的な検索**

### [**書き込み可能ファイル**](privilege-escalation/#writable-files)

* [ ] **Pythonライブラリを変更**して任意のコマンドを実行できますか？
* [ ] **ログファイルを変更**できますか？ **Logtotten** exploit
* [ ] **/etc/sysconfig/network-scripts/**を変更できますか？ Centos/Redhat exploit
* [ ] [**ini、int.d、systemd、またはrc.dファイルに書き込むことができますか**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**その他のトリック**](privilege-escalation/#other-tricks)

* [ ] [**特権を昇格するためにNFSを悪用できますか**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] [**制限されたシェルから脱出する必要がありますか**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を追いかける

**最新の発表**\
最新のバグバウンティの開始や重要なプラットフォームの更新に関する情報を入手

[**Discord**](https://discord.com/invite/N3FrSbmwdy) に参加して、今日からトップハッカーと協力しましょう！
