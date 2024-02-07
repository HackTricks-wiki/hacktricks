# チェックリスト - Linux特権昇格

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでのAWSハッキングを学ぶ**</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **Discordグループ**に参加したり、[**Telegramグループ**](https://t.me/peass)に参加したり、**Twitter**で**フォロー**する🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加

**リアルタイムハックニュース**\
リアルタイムのニュースと情報を通じてハッキングの世界を最新の状態に保つ

**最新のアナウンスメント**\
最新のバグバウンティの開始や重要なプラットフォームの更新情報を把握

**Discord**で[**参加**](https://discord.com/invite/N3FrSbmwdy)して、今日からトップハッカーと協力を始めましょう！

### **Linuxローカル特権昇格ベクターを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/#system-information)

- [ ] **OS情報**を取得する
- [ ] [**PATH**](privilege-escalation/#path)をチェックし、**書き込み可能なフォルダ**はあるか？
- [ ] [**環境変数**](privilege-escalation/#env-info)をチェックし、機密情報はあるか？
- [ ] スクリプトを使用して[**カーネルの脆弱性**](privilege-escalation/#kernel-exploits)を検索する（DirtyCowなど）
- [ ] [**sudoバージョンが脆弱**](privilege-escalation/#sudo-version)かどうかを**チェック**
- [ ] [**Dmesg**署名検証に失敗](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] 他のシステム列挙（[日付、システム統計、CPU情報、プリンタ](privilege-escalation/#more-system-enumeration)）
- [ ] [**さらなる防御策の列挙**](privilege-escalation/#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/#drives)

- [ ] マウントされたドライブをリストアップする
- [ ] マウントされていないドライブはあるか？
- [ ] fstabにクレデンシャルはあるか？

### [**インストールされたソフトウェア**](privilege-escalation/#installed-software)

- [ ] **インストールされた**[ **有用なソフトウェア**](privilege-escalation/#useful-software)をチェックする
- [ ] **インストールされた**[**脆弱なソフトウェア**](privilege-escalation/#vulnerable-software-installed)をチェックする

### [プロセス](privilege-escalation/#processes)

- [ ] **不明なソフトウェアが実行**されているか？
- [ ] **適切でない権限で実行**されているソフトウェアはあるか？
- [ ] 実行中のプロセスの**脆弱性**を検索する（特に実行中のバージョン）
- [ ] 実行中のプロセスのバイナリを**変更**できるか？
- [ ] プロセスを**監視**し、興味深いプロセスが頻繁に実行されていないかをチェックする
- [ ] 興味深い**プロセスメモリ**（パスワードが保存されている可能性のある場所）を**読み取る**ことができるか？

### [スケジュールされた/Cronジョブ？](privilege-escalation/#scheduled-jobs)

- [ ] 一部のcronによって[**PATH** ](privilege-escalation/#cron-path)が変更され、書き込み可能になっているか？
- [ ] クロンジョブに[**ワイルドカード** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)があるか？
- [ ] 実行されている[**変更可能なスクリプト** ](privilege-escalation/#cron-script-overwriting-and-symlink)があるか、または**変更可能なフォルダ**にあるか？
- [ ] いくつかの**スクリプト**が非常に**頻繁に実行**されていることを検出しましたか？（1分、2分、または5分ごと）

### [サービス](privilege-escalation/#services)

- [ ] **書き込み可能な .service** ファイルはあるか？
- [ ] **サービス**によって実行される**書き込み可能なバイナリ**はあるか？
- [ ] systemd PATHに**書き込み可能なフォルダ**はあるか？

### [タイマー](privilege-escalation/#timers)

- [ ] **書き込み可能なタイマー**はあるか？

### [ソケット](privilege-escalation/#sockets)

- [ ] **書き込み可能な .socket** ファイルはあるか？
- [ ] 任意のソケットと**通信**できるか？
- [ ] 興味深い情報を持つ**HTTPソケット**はあるか？

### [D-Bus](privilege-escalation/#d-bus)

- [ ] 任意のD-Busと**通信**できるか？

### [ネットワーク](privilege-escalation/#network)

- 自分がどこにいるかを知るためにネットワークを列挙する
- シェル内でアクセスできなかった**オープンポート**はあるか？
- `tcpdump`を使用してトラフィックを**スニッフ**できるか？

### [ユーザー](privilege-escalation/#users)

- 一般的なユーザー/グループを**列挙**する
- **非常に大きなUID**を持っていますか？**マシン**は**脆弱**ですか？
- 所属しているグループを通じて特権を昇格できますか？
- **クリップボード**のデータは？
- パスワードポリシーは？
- 以前に発見した**すべての既知のパスワード**を使用して、**各**可能な**ユーザー**でログインしてみてください。パスワードなしでもログインできるかもしれません。

### [書き込み可能なPATH](privilege-escalation/#writable-path-abuses)

- **PATH内のいくつかのフォルダに書き込み権限**がある場合、特権を昇格できるかもしれません

### [SUDOおよびSUIDコマンド](privilege-escalation/#sudo-and-suid)

- **sudoで任意のコマンドを実行**できますか？それを使用して何かをルートとして**読み取り、書き込み、実行**できますか？（[**GTFOBins**](https://gtfobins.github.io)）
- **悪用可能なSUIDバイナリ**はありますか？（[**GTFOBins**](https://gtfobins.github.io)）
- [**sudo**コマンドが**パス**で**制限**されていますか？ 制限を**バイパス**できますか](privilege-escalation/#sudo-execution-bypassing-paths)?
- [**パスが指定されていないSudo/SUIDバイナリ**](privilege-escalation/#sudo-command-suid-binary-without-command-path)はありますか？
- [**パスが指定されているSUIDバイナリ**](privilege-escalation/#suid-binary-with-command-path)はありますか？バイパス
- [**LD\_PRELOAD脆弱性**](privilege-escalation/#ld\_preload)
- 書き込み可能なフォルダからのSUIDバイナリに**.soライブラリが不足**していますか？
- [**SUDOトークンが利用可能**](privilege-escalation/#reusing-sudo-tokens)ですか？ [**SUDOトークンを作成**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)できますか？
- [**sudoersファイルを読み取る**](privilege-escalation/#etc-sudoers-etc-sudoers-d)ことができますか？
- [**/etc/ld.so.conf.d/**を**変更**](privilege-escalation/#etc-ld-so-conf-d)できますか？
- [**OpenBSD DOAS**](privilege-escalation/#doas)コマンド

### [機能](privilege-escalation/#capabilities)

- 任意のバイナリに**予期しない機能**がありますか？

### [ACL](privilege-escalation/#acls)

- 任意のファイルに**予期しないACL**がありますか？

### [オープンシェルセッション](privilege-escalation/#open-shell-sessions)

- **screen**
- **tmux**

### [SSH](privilege-escalation/#ssh)

- **Debian**の[**OpenSSL予測可能なPRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [**SSHの興味深い構成値**](privilege-escalation/#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/#interesting-files)

- **プロファイルファイル** - 機密データを読み取ることができますか？特権昇格に書き込むことができますか？
- **passwd/shadowファイル** - 機密データを読み取ることができますか？特権昇格に書き込むことができますか？
- 一般的に興味深いフォルダをチェックして、機密データがないか確認します
- **奇妙な場所/所有ファイル**、アクセス権限を持っているか、または実行可能ファイルを変更できるかもしれません
- 最後の数分で**変更**されましたか
- **Sqlite DBファイル**
- **隠しファイル**
- **スクリプト/バイナリPATH**
- **Webファイル**（パスワード？）
- **バックアップ**？
- **パスワードを含む既知のファイル**：**Linpeas**と**LaZagne**を使用します
- **一般的な検索**

### [**書き込み可能なファイル**](privilege-escalation/#writable-files)

- **Pythonライブラリを変更**して任意のコマンドを実行できますか？
- **ログファイルを変更**できますか？ **Logtotten** exploit
- **/etc/sysconfig/network-scripts/**を変更できますか？ Centos/Redhat exploit
- [**ini、int.d、systemd、rc.dファイルに書き込む**](privilege-escalation/#init-init-d-systemd-and-rc-d)ことができますか？

### [**その他のトリック**](privilege-escalation/#other-tricks)

- 特権を昇格するために**NFSを悪用**できますか？
- **制限的なシェルから脱出**する必要がありますか？

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加

**リアルタイムハックニュース**\
リアルタイムのニュースと情報を通じてハッキングの世界を最新の状態に保つ

**最新のアナウンスメント**\
最新のバグバウンティの開始や重要なプラットフォームの更新情報を把握

**Discord**で[**参加**](https://discord.com/invite/N3FrSbmwdy)して、今日からトップハッカーと協力を始めましょう！
