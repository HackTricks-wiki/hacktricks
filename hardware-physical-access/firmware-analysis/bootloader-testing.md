<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

デバイスの起動構成やU-bootなどのブートローダーを変更するために推奨される手順は次のとおりです：

1. **ブートローダーのインタープリターシェルにアクセス**：
- 起動中に "0"、スペース、または他の特定の "マジックコード" を押して、ブートローダーのインタープリターシェルにアクセスします。

2. **ブート引数の変更**：
- 以下のコマンドを実行して、ブート引数に '`init=/bin/sh`' を追加し、シェルコマンドを実行できるようにします：
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTPサーバーの設定**：
- ローカルネットワーク経由でイメージをロードするためにTFTPサーバーを構成します：
%%%
#setenv ipaddr 192.168.2.2 #デバイスのローカルIP
#setenv serverip 192.168.2.1 #TFTPサーバーのIP
#saveenv
#reset
#ping 192.168.2.1 #ネットワークアクセスを確認
#tftp ${loadaddr} uImage-3.6.35 #loadaddrはファイルをロードするアドレスとTFTPサーバー上のイメージのファイル名を取ります
%%%

4. **`ubootwrite.py`の利用**：
- `ubootwrite.py`を使用してU-bootイメージを書き込み、ルートアクセスを取得するために変更されたファームウェアをプッシュします。

5. **デバッグ機能の確認**：
- デバッグ機能が有効になっているかどうかを確認します。詳細なログ記録、任意のカーネルの読み込み、または信頼されていないソースからのブートなど。

6. **注意深いハードウェア干渉**：
- デバイスの起動シーケンス中に1つのピンを接地に接続し、特にカーネルが解凍される前にSPIまたはNANDフラッシュチップとやり取りする際には、極めて注意してください。ピンをショートする前にNANDフラッシュチップのデータシートを参照してください。

7. **ローグDHCPサーバーの設定**：
- デバイスがPXEブート中に摂取する悪意のあるパラメータを持つローグDHCPサーバーを設定します。Metasploit（MSF）のDHCP補助サーバーなどのツールを利用します。 'FILENAME'パラメータを`'a";/bin/sh;#'`などのコマンドインジェクションコマンドで変更して、デバイスの起動手順の入力検証をテストします。

**注意**: デバイスのピンと物理的なやり取りを伴う手順（*アスタリスクでマークされています）は、デバイスを損傷させないように極めて注意してアプローチする必要があります。


## 参考文献
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
