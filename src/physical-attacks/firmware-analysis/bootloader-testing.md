{{#include ../../banners/hacktricks-training.md}}

デバイスの起動構成やブートローダー（U-bootなど）を変更するために推奨される手順は以下の通りです：

1. **ブートローダーのインタプリタシェルにアクセス**：

- ブート中に「0」やスペース、または他の特定された「マジックコード」を押してブートローダーのインタプリタシェルにアクセスします。

2. **ブート引数の変更**：

- 次のコマンドを実行して、ブート引数に '`init=/bin/sh`' を追加し、シェルコマンドの実行を可能にします：
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTPサーバーの設定**：

- ローカルネットワーク経由でイメージをロードするためにTFTPサーバーを設定します：
%%%
#setenv ipaddr 192.168.2.2 #デバイスのローカルIP
#setenv serverip 192.168.2.1 #TFTPサーバーのIP
#saveenv
#reset
#ping 192.168.2.1 #ネットワークアクセスを確認
#tftp ${loadaddr} uImage-3.6.35 #loadaddrはファイルをロードするアドレスとTFTPサーバー上のイメージのファイル名を取ります
%%%

4. **`ubootwrite.py`の利用**：

- `ubootwrite.py`を使用してU-bootイメージを書き込み、ルートアクセスを得るために修正されたファームウェアをプッシュします。

5. **デバッグ機能の確認**：

- 詳細なログ記録、任意のカーネルのロード、または信頼できないソースからのブートなどのデバッグ機能が有効になっているか確認します。

6. **注意が必要なハードウェア干渉**：

- デバイスのブートアップシーケンス中、特にカーネルが解凍される前に、1つのピンをグラウンドに接続し、SPIまたはNANDフラッシュチップと相互作用する際には注意が必要です。ピンをショートする前にNANDフラッシュチップのデータシートを参照してください。

7. **悪意のあるDHCPサーバーの設定**：
- PXEブート中にデバイスが取り込む悪意のあるパラメータを持つ悪意のあるDHCPサーバーを設定します。Metasploitの（MSF）DHCP補助サーバーなどのツールを利用します。'FILENAME'パラメータをコマンドインジェクションコマンド（例：`'a";/bin/sh;#'`）で変更し、デバイスの起動手順に対する入力検証をテストします。

**注意**：デバイスのピンとの物理的相互作用を伴う手順（\*アスタリスクでマークされたもの）は、デバイスを損傷しないように極めて注意して行うべきです。

## 参考文献

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
