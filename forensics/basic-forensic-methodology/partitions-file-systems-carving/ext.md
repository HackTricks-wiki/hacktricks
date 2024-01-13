```markdown
<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

他のHackTricksをサポートする方法:

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>


# Ext - 拡張ファイルシステム

**Ext2**は、ブートパーティションのような**ジャーナリングされていない**パーティション（あまり変更されないパーティション）に最も一般的に使用されるファイルシステムです。**Ext3/4**は**ジャーナリング**されており、通常は**その他のパーティション**に使用されます。

ファイルシステム内のすべてのブロックグループは同じサイズであり、連続して格納されています。これにより、カーネルは整数インデックスからディスク内のブロックグループの位置を簡単に導き出すことができます。

各ブロックグループには以下の情報が含まれています：

* ファイルシステムのスーパーブロックのコピー
* ブロックグループ記述子のコピー
* グループ内の空きブロックを識別するためのデータブロックビットマップ
* グループ内の空きinodeを識別するためのinodeビットマップ
* inodeテーブル：連続するブロックのシリーズで構成され、それぞれが事前に定義された図1 Ext2 inode数のinodeを含んでいます。すべてのinodeは同じサイズです：128バイト。1,024バイトのブロックには8つのinodeが含まれ、4,096バイトのブロックには32のinodeが含まれます。Ext2では、inode番号と対応するブロック番号の間のディスク上のマッピングを格納する必要はありません。なぜなら、後者の値はブロックグループ番号とinodeテーブル内の相対位置から導き出すことができるからです。例えば、各ブロックグループに4,096のinodeが含まれているとし、ディスク上のinode 13,021のアドレスを知りたいとします。この場合、inodeは3番目のブロックグループに属しており、そのディスクアドレスは対応するinodeテーブルの733番目のエントリに格納されています。ご覧の通り、inode番号はExt2ルーチンがディスク上の適切なinode記述子を迅速に取得するために使用するキーに過ぎません
* ファイルを含むデータブロック。意味のある情報を含まないブロックは空きと言われています。

![](<../../../.gitbook/assets/image (406).png>)

## Ext オプショナル機能

**機能はデータの位置に影響を与え**、inode内のデータの格納方法に影響を与え、いくつかは分析のために**追加のメタデータ**を提供する可能性があるため、Extでは機能が重要です。

Extには、OSがサポートしているかどうかによって異なるオプショナル機能があります。3つの可能性があります：

* 互換性あり
* 互換性なし
* 読み取り専用互換性：書き込みはできませんが、マウントは可能

**互換性がない**機能がある場合、OSはデータへのアクセス方法を知らないため、ファイルシステムをマウントすることができません。

{% hint style="info" %}
疑わしい攻撃者は非標準の拡張機能を持っている可能性があります。
{% endhint %}

**任意のユーティリティ**は**スーパーブロック**を読むことができ、**Extファイルシステム**の**機能**を示すことができますが、`file -sL /dev/sd*`も使用できます。

## スーパーブロック

スーパーブロックは開始から最初の1024バイトであり、各グループの最初のブロックに繰り返され、以下を含みます：

* ブロックサイズ
* 総ブロック数
* ブロックグループごとのブロック数
* 最初のブロックグループの前の予約ブロック
* 総inode数
* ブロックグループごとのinode数
* ボリューム名
* 最終書き込み時間
* 最終マウント時間
* ファイルシステムが最後にマウントされたパス
* ファイルシステムの状態（クリーン？）

Extファイルシステムファイルからこの情報を取得することが可能です：
```
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
以下は無料のGUIアプリケーションを使用することもできます：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
または、**python**を使用してスーパーブロック情報を取得することもできます：[https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodes

**inodes**は、**ファイル**の実際の**データ**を**含む** **ブロック**のリストを含んでいます。\
ファイルが大きい場合、inodeはブロック/ファイルデータを含むさらなるinodesを指す**他のinodes**への**ポインターを含む**ことがあります。

![](<../../../.gitbook/assets/image (416).png>)

**Ext2**と**Ext3**ではinodeのサイズは**128B**で、**Ext4**は現在**156B**を使用していますが、将来の拡張のためにディスク上で**256B**を割り当てています。

Inode構造：

| オフセット | サイズ | 名前              | 説明F                                     |
| ------ | ---- | ----------------- | ------------------------------------------------ |
| 0x0    | 2    | ファイルモード         | ファイルモードとタイプ                               |
| 0x2    | 2    | UID               | 所有者IDの下位16ビット                        |
| 0x4    | 4    | サイズIl           | ファイルサイズの下位32ビット                       |
| 0x8    | 4    | アクセス時間             | エポックからのアクセス時間（秒）               |
| 0xC    | 4    | 変更時間             | エポックからの変更時間（秒）               |
| 0x10   | 4    | 修正時間             | エポックからの修正時間（秒）               |
| 0x14   | 4    | 削除時間             | エポックからの削除時間（秒）               |
| 0x18   | 2    | GID               | グループIDの下位16ビット                        |
| 0x1A   | 2    | ハードリンク数       | ハードリンクの数                                  |
| 0xC    | 4    | ブロックIo         | ブロック数の下位32ビット                     |
| 0x20   | 4    | フラグ             | フラグ                                            |
| 0x24   | 4    | Union osd1        | Linux: Iバージョン                                 |
| 0x28   | 69   | ブロック\[15]        | 15はデータブロックを指す                         |
| 0x64   | 4    | バージョン           | NFS用のファイルバージョン                             |
| 0x68   | 4    | ファイルACL下      | 拡張属性（ACLなど）の下位32ビット  |
| 0x6C   | 4    | ファイルサイズ上      | ファイルサイズの上位32ビット（ext4のみ）           |
| 0x70   | 4    | 廃止されたフラグメント | 廃止されたフラグメントアドレス                    |
| 0x74   | 12   | Osd 2             | 第二のオペレーティングシステム依存のユニオン          |
| 0x74   | 2    | ブロック上         | ブロック数の上位16ビット                     |
| 0x76   | 2    | ファイルACL上       | 拡張属性（ACLなど）の上位16ビット |
| 0x78   | 2    | UID上            | 所有者IDの上位16ビット                        |
| 0x7A   | 2    | GID上            | グループIDの上位16ビット                        |
| 0x7C   | 2    | チェックサムIo       | inodeチェックサムの下位16ビット                  |

"修正"は、ファイルの_内容_が最後に変更された時のタイムスタンプです。これは通常"_mtime_"と呼ばれます。\
"変更"は、ファイルの_inode_が最後に変更された時のタイムスタンプで、例えば権限、所有権、ファイル名、ハードリンクの数を変更することによります。これは通常"_ctime_"と呼ばれます。

Inode構造拡張（Ext4）：

| オフセット | サイズ | 名前         | 説明                                 |
| ------ | ---- | ------------ | ------------------------------------------- |
| 0x80   | 2    | 追加サイズ   | 標準の128バイトを超える使用バイト数 |
| 0x82   | 2    | チェックサム上  | inodeチェックサムの上位16ビット             |
| 0x84   | 4    | 変更時間追加  | 変更時間の追加ビット                      |
| 0x88   | 4    | 修正時間追加  | 修正時間の追加ビット                      |
| 0x8C   | 4    | アクセス時間追加  | アクセス時間の追加ビット                      |
| 0x90   | 4    | 作成時間       | ファイル作成時間（エポックからの秒）      |
| 0x94   | 4    | 作成時間追加 | ファイル作成時間の追加ビット                 |
| 0x98   | 4    | バージョン上   | バージョンの上位32ビット                    |
| 0x9C   |      | 未使用       | 将来の拡張のための予約スペース        |

特別なinodes：

| Inode | 特別な目的                                      |
| ----- | ---------------------------------------------------- |
| 0     | そのようなinodeはなく、番号付けは1から始まります                |
| 1     | 不良ブロックリスト                                 |
| 2     | ルートディレクトリ                                       |
| 3     | ユーザークォータ                                          |
| 4     | グループクォータ                                         |
| 5     | ブートローダー                                          |
| 6     | アンデリートディレクトリ                                   |
| 7     | ファイルシステムのリサイズ用に予約されたグループ記述子 |
| 8     | ジャーナル                                              |
| 9     | スナップショット用の除外inode                        |
| 10    | レプリカinode                                        |
| 11    | 最初の非予約inode（よくlost + foundとなる）        |

{% hint style="info" %}
作成時間はExt4にのみ表示されることに注意してください。
{% endhint %}

inode番号を知っていれば、そのインデックスを簡単に見つけることができます：

* **ブロックグループ**：inodeが属する（Inode番号 - 1）/（グループごとのInodes）
* **グループ内のインデックス**：（Inode番号 - 1）mod（グループごとのInodes）
* **inodeテーブルへのオフセット**：Inode番号 \* （Inodeサイズ）
* "-1"はinode 0が未定義（未使用）であるためです
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
ファイルモード

| 数値 | 説明                                                                                         |
| ---- | -------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **ディレクトリ/ブロックビット13**                                                                          |
| **13** | **キャラクタデバイス/ブロックビット14**                                                                        |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | スティッキービット（これがないと、ディレクトリに書き込み＆実行権限がある人はファイルを削除やリネームできる）  |
| 8      | オーナー読み取り                                                                                          |
| 7      | オーナー書き込み                                                                                         |
| 6      | オーナー実行                                                                                          |
| 5      | グループ読み取り                                                                                         |
| 4      | グループ書き込み                                                                                        |
| 3      | グループ実行                                                                                          |
| 2      | その他読み取り                                                                                         |
| 1      | その他書き込み                                                                                        |
| 0      | その他実行                                                                                         |

太字のビット（12, 13, 14, 15）はファイルの種類（ディレクトリ、ソケットなど）を示しており、太字のオプションは1つだけ存在します。

ディレクトリ

| オフセット | サイズ | 名前      | 説明                                                                                                                                                  |
| ------ | ---- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x0    | 4    | Inode     |                                                                                                                                                      |
| 0x4    | 2    | Rec len   | レコード長                                                                                                                                            |
| 0x6    | 1    | Name len  | 名前の長さ                                                                                                                                            |
| 0x7    | 1    | ファイルタイプ | <p>0x00 不明<br>0x01 通常</p><p>0x02 ディレクトリ</p><p>0x03 キャラクタデバイス</p><p>0x04 ブロックデバイス</p><p>0x05 FIFO</p><p>0x06 ソケット</p><p>0x07 シンボリックリンク</p> |
| 0x8    |      | 名前      | 名前文字列（最大255文字）                                                                                                                           |

**パフォーマンス向上のため、Root hash Directoryブロックが使用されることがあります。**

**拡張属性**

以下に格納可能：

* inode間の余分なスペース（256 - inodeサイズ、通常は100）
* inodeのfile_aclによって指されたデータブロック

名前が"user"で始まる場合、ユーザー属性として何でも格納できるため、この方法でデータを隠すことができます。

拡張属性エントリ

| オフセット | サイズ | 名前         | 説明                                                                                                                                                                                                        |
| ------ | ---- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x0    | 1    | Name len     | 属性名の長さ                                                                                                                                                                                               |
| 0x1    | 1    | Name index   | <p>0x0 = プレフィックスなし</p><p>0x1 = user. プレフィックス</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2    | Value offs   | 最初のinodeエントリまたはブロック開始からのオフセット                                                                                                                                                                    |
| 0x4    | 4    | Value blocks | 値が格納されているディスクブロック、またはこのブロックの場合はゼロ                                                                                                                                                               |
| 0x8    | 4    | Value size   | 値の長さ                                                                                                                                                                                                    |
| 0xC    | 4    | Hash         | ブロック内の属性のハッシュ、またはinode内の場合はゼロ                                                                                                                                                                      |
| 0x10   |      | 名前         | 末尾のNULLなしの属性名                                                                                                                                                                                   |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## ファイルシステムビュー

ファイルシステムの内容を見るために、無料ツールを**使用できます**：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
または、Linuxで`mount`コマンドを使用してマウントすることができます。

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.)


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
