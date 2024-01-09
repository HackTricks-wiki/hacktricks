```markdown
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* あなたの**会社をHackTricksに広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* 独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のGitHubリポジトリ[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>


[https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)からコピー

U-bootのようなデバイスの起動とブートローダーを変更する際には、以下のことを試みてください:

* 起動中に"0"、スペース、または他の特定された「マジックコード」を押して、ブートローダーのインタープリターシェルにアクセスを試みる。
* ブート引数の最後に'`init=/bin/sh`'を追加するなどして、シェルコマンドを実行するように設定を変更する。
* `#printenv`
* `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
* `#saveenv`
* `#boot`
* ワークステーションからローカルにネットワーク経由でイメージをロードするためにtftpサーバーを設定する。デバイスがネットワークアクセスを持っていることを確認する。
* `#setenv ipaddr 192.168.2.2 #デバイスのローカルIP`
* `#setenv serverip 192.168.2.1 #tftpサーバーのIP`
* `#saveenv`
* `#reset`
* `#ping 192.168.2.1 #ネットワークアクセスが利用可能か確認する`
* `#tftp ${loadaddr} uImage-3.6.35 #loadaddrは2つの引数を取る: ファイルをロードするアドレスとTFTPサーバー上のイメージのファイル名`
* `ubootwrite.py`を使用してubootイメージを書き込み、変更されたファームウェアをプッシュしてroot権限を取得する
* 以下のような有効なデバッグ機能をチェックする:
  * 詳細なログ
  * 任意のカーネルのロード
  * 信頼されていないソースからのブート
* \*注意: 1本のピンをグラウンドに接続し、デバイスの起動シーケンスを観察する。カーネルが解凍される前に、グラウンドされたピンをSPIフラッシュチップのデータピン(DO)に短絡/接続する
* \*注意: 1本のピンをグラウンドに接続し、デバイスの起動シーケンスを観察する。カーネルが解凍される前に、グラウンドされたピンをNANDフラッシュチップのピン8と9に短絡/接続する。U-bootがUBIイメージを解凍する瞬間に行う
* \*ピンを短絡する前にNANDフラッシュチップのデータシートを確認する
* 悪意のあるパラメータを入力としてデバイスが摂取するように設定された不正なDHCPサーバーを構成する
* Metasploitの(MSF) DHCP補助サーバーを使用し、`‘a";/bin/sh;#’`のようなコマンドインジェクションコマンドで‘`FILENAME`’パラメータを変更して、デバイスの起動手順の入力検証をテストする。

\*ハードウェアセキュリティテスト


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* あなたの**会社をHackTricksに広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* 独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のGitHubリポジトリ[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>
```
