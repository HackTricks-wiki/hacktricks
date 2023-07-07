<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


# Ext - 拡張ファイルシステム

**Ext2**は、**ジャーナリングされていない**パーティション（**あまり変更されないパーティション**）の最も一般的なファイルシステムです。ブートパーティションなどに使用されます。**Ext3/4**は**ジャーナリング**され、通常は**その他のパーティション**に使用されます。

ファイルシステムのすべてのブロックグループは同じサイズで順次格納されます。これにより、カーネルはブロックグループのディスク上の位置を整数インデックスから簡単に導出できます。

各ブロックグループには、次の情報が含まれています。

* ファイルシステムのスーパーブロックのコピー
* ブロックグループディスクリプタのコピー
* データブロックビットマップ：グループ内の空きブロックを識別するために使用されます
* inodeビットマップ：グループ内の空きinodeを識別するために使用されます
* inodeテーブル：連続したブロックのシリーズで構成され、各ブロックには事前定義された図1のExt2 inode番号のinodeが含まれます。すべてのinodeのサイズは同じです：128バイトです。1,024バイトのブロックには8つのinodeが含まれ、4,096バイトのブロックには32のinodeが含まれます。Ext2では、inode番号と対応するブロック番号のマッピングをディスク上に保存する必要はありません。なぜなら、後者の値はブロックグループ番号とinodeテーブル内の相対位置から導出できるからです。たとえば、各ブロックグループに4,096のinodeが含まれ、inode 13,021のディスク上のアドレスを知りたい場合、このinodeは3番目のブロックグループに属しており、そのディスクアドレスは対応するinodeテーブルの733番目のエントリに格納されています。inode番号は、Ext2のルーチンがディスク上の適切なinodeディスクリプタを迅速に取得するために使用するキーであることがわかります。
* ファイルを含むデータブロック。意味のない情報を含まないブロックは、空きと言われます。

![](<../../../.gitbook/assets/image (406).png>)

## Extのオプション機能

**機能は**データの配置場所に影響を与え、**inode内のデータの格納方法**や、いくつかの機能は**追加のメタデータ**を提供する場合があります。したがって、Extでは機能が重要です。

Extには、OSがサポートするかどうかによって、オプションの機能があります。3つの可能性があります。

* 互換性あり
* 互換性なし
* 読み取り専用の互換性あり：マウントはできますが、書き込みはできません

**互換性のない**機能がある場合、OSはデータにアクセスする方法を知らないため、ファイルシステムをマウントできません。

{% hint style="info" %}
疑わしい攻撃者は、非標準の拡張機能を持っている可能性があります
{% endhint %}

**スーパーブロック**を読み取る**任意のユーティリティ**は、**Extファイルシステム**の**機能**を示すことができますが、`file -sL /dev/sd*`を使用することもできます。

## スーパーブロック

スーパーブロックは、最初の1024バイトから始まり、各グループの最初のブロックに繰り返され、次の情報を含んでいます。

* ブロックサイズ
* 総ブロック数
* ブロックグループごとのブロック数
* 最初のブロックグループの前に予約されたブロック数
* 総inode数
* ブロックグループごとのinode数
* ボリューム名
* 最終書き込み時刻
* 最終マウント時刻
* ファイルシステムが最後にマウントされた場所
* ファイルシステムのステータス（クリーン？）

Extファイルシステムファイルからこの情報を取得することができます。
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
無料のGUIアプリケーションも使用できます：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
または、**python**を使用してスーパーブロック情報を取得することもできます：[https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodes

**inodes**には、**ファイル**の実際の**データ**を含む**ブロック**のリストが含まれています。\
ファイルが大きい場合、inodeにはファイルデータを含むブロック/より多くのinodeを指す他のinodeへのポインタが含まれる場合があります。

![](<../../../.gitbook/assets/image (416).png>)

**Ext2**および**Ext3**では、inodeのサイズは**128B**です。**Ext4**は現在**156B**を使用していますが、将来の拡張を許可するためにディスク上に**256B**を割り当てます。

inodeの構造：

| オフセット | サイズ | 名前              | 説明                                             |
| ------ | ---- | ----------------- | ------------------------------------------------ |
| 0x0    | 2    | ファイルモード         | ファイルモードとタイプ                                |
| 0x2    | 2    | UID               | オーナーIDの下位16ビット                              |
| 0x4    | 4    | サイズ Il           | ファイルサイズの下位32ビット                           |
| 0x8    | 4    | Atime             | エポックからのアクセス時間（秒単位）                     |
| 0xC    | 4    | Ctime             | エポックからの変更時間（秒単位）                         |
| 0x10   | 4    | Mtime             | エポックからの変更時間（秒単位）                         |
| 0x14   | 4    | Dtime             | エポックからの削除時間（秒単位）                         |
| 0x18   | 2    | GID               | グループIDの下位16ビット                              |
| 0x1A   | 2    | Hlink count       | ハードリンクの数                                     |
| 0xC    | 4    | Blocks Io         | ブロック数の下位32ビット                               |
| 0x20   | 4    | フラグ             | フラグ                                              |
| 0x24   | 4    | Union osd1        | Linux：Iバージョン                                   |
| 0x28   | 69   | Block\[15]        | データブロックへのポイント（15個）                      |
| 0x64   | 4    | バージョン           | NFS用のファイルバージョン                               |
| 0x68   | 4    | File ACL low      | 拡張属性（ACLなど）の下位32ビット                        |
| 0x6C   | 4    | File size hi      | ファイルサイズの上位32ビット（ext4のみ）                  |
| 0x70   | 4    | Obsolete fragment | 廃止されたフラグメントアドレス                           |
| 0x74   | 12   | Osd 2             | 2番目のオペレーティングシステム依存のユニオン               |
| 0x74   | 2    | Blocks hi         | ブロック数の上位16ビット                               |
| 0x76   | 2    | File ACL hi       | 拡張属性（ACLなど）の上位16ビット                         |
| 0x78   | 2    | UID hi            | オーナーIDの上位16ビット                               |
| 0x7A   | 2    | GID hi            | グループIDの上位16ビット                               |
| 0x7C   | 2    | Checksum Io       | inodeチェックサムの下位16ビット                          |

「Modify」は、ファイルの_内容_が最後に変更された時間のタイムスタンプです。これは通常「_mtime_」と呼ばれます。\
「Change」は、ファイルの_inode_が変更された最後の時間のタイムスタンプです。これは、アクセス許可、所有権、ファイル名、ハードリンクの数などを変更することによって呼ばれることがあります。これは通常「_ctime_」と呼ばれます。

拡張されたinodeの構造（Ext4）：

| オフセット | サイズ | 名前         | 説明                                 |
| ------ | ---- | ------------ | ------------------------------------------- |
| 0x80   | 2    | Extra size   | 標準の128バイトを超えるバイト数 |
| 0x82   | 2    | Checksum hi  | inodeチェックサムの上位16ビット             |
| 0x84   | 4    | Ctime extra  | 変更時間の追加ビット                      |
| 0x88   | 4    | Mtime extra  | 変更時間の追加ビット                      |
| 0x8C   | 4    | Atime extra  | アクセス時間の追加ビット                      |
| 0x90   | 4    | Crtime       | ファイル作成時間（エポックからの秒数）      |
| 0x94   | 4    | Crtime extra | ファイル作成時間の追加ビット                 |
| 0x98   | 4    | Version hi   | バージョンの上位32ビット                    |
| 0x9C   |      | Unused       | 将来の拡張のための予約済みスペース        |

特殊なinode：

| Inode | 特殊な目的                                      |
| ----- | ---------------------------------------------------- |
| 0     | そのようなinodeは存在せず、番号付けは1から開始されます                |
| 1     | 欠陥ブロックリスト                                 |
| 2     | ルートディレクトリ                                       |
| 3     | ユーザークォータ                                          |
| 4     | グループクォータ                                         |
| 5     | ブートローダ                                          |
| 6     | 削除されたディレクトリ                                   |
| 7     | 予約済みグループ記述子（ファイルシステムのサイズ変更用） |
| 8     | ジャーナル                                              |
| 9     | スナップショット用の除外inode                        |
| 10    | レプリカinode                                        |
| 11    | 最初の非予約inode（しばしばlost + found）        |

{% hint style="info" %}
作成時刻はExt4にのみ表示されることに注意してください。
{% endhint %}

inode番号を知っている場合、そのインデックスを簡単に見つけることができます：

* inodeが所属する**ブロックグループ**：（Inode番号 - 1）/（グループごとのinode数）
* グループ内の**インデックス**：（Inode番号 - 1）mod（Inodes/グループ）
* **inodeテーブル**への**オフセット**：Inode番号 \*（Inodeサイズ）
* "-1"は、inode 0が未定義（使用されていない）であるためです。
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
ファイルモード

| 数字 | 説明                                                                                                 |
| ---- | ---------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **Directory/Block Bit 13**                                                                          |
| **13** | **Char Device/Block Bit 14**                                                                        |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | Sticky Bit（ディレクトリ上の書き込みと実行権限を持つユーザーはファイルを削除および名前変更できます） |
| 8      | オーナーの読み取り権限                                                                                |
| 7      | オーナーの書き込み権限                                                                                |
| 6      | オーナーの実行権限                                                                                    |
| 5      | グループの読み取り権限                                                                                |
| 4      | グループの書き込み権限                                                                                |
| 3      | グループの実行権限                                                                                    |
| 2      | その他のユーザーの読み取り権限                                                                        |
| 1      | その他のユーザーの書き込み権限                                                                        |
| 0      | その他のユーザーの実行権限                                                                            |

太字のビット（12、13、14、15）は、ファイルの種類（ディレクトリ、ソケットなど）を示しており、太字のオプションのいずれか1つしか存在しません。

ディレクトリ

| オフセット | サイズ | 名前      | 説明                                                                                          |
| ------ | ---- | --------- | -------------------------------------------------------------------------------------------- |
| 0x0    | 4    | Inode     |                                                                                              |
| 0x4    | 2    | Rec len   | レコードの長さ                                                                                |
| 0x6    | 1    | Name len  | 名前の長さ                                                                                    |
| 0x7    | 1    | File type | <p>0x00 不明<br>0x01 通常</p><p>0x02 ディレクトリ</p><p>0x03 文字デバイス</p><p>0x04 ブロックデバイス</p><p>0x05 FIFO</p><p>0x06 ソケット</p><p>0x07 シンボリックリンク</p> |
| 0x8    |      | Name      | 名前の文字列（最大255文字まで）                                                                 |

**パフォーマンスを向上させるために、ルートハッシュディレクトリブロックを使用することができます。**

**拡張属性**

以下に保存することができます。

* inode内のfile\_aclが指すデータブロック
* inodeの間の余分なスペース（256 - inodeサイズ、通常は100）

"ユーザー"で始まる名前の場合、ユーザーの属性として任意のデータを保存することができます。この方法でデータを隠すことができます。

拡張属性エントリ

| オフセット | サイズ | 名前         | 説明                                                                                          |
| ------ | ---- | ------------ | -------------------------------------------------------------------------------------------- |
| 0x0    | 1    | Name len     | 属性名の長さ                                                                                  |
| 0x1    | 1    | Name index   | <p>0x0 = プレフィックスなし</p><p>0x1 = user. プレフィックス</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2    | Value offs   | 最初のinodeエントリまたはブロックの開始位置からのオフセット                                          |
| 0x4    | 4    | Value blocks | 値が保存されているディスクブロック、またはこのブロックの場合はゼロ                                  |
| 0x8    | 4    | Value size   | 値の長さ                                                                                      |
| 0xC    | 4    | Hash         | ブロック内の属性のハッシュ、またはinode内の場合はゼロ                                              |
| 0x10   |      | Name         | 末尾のNULLを含まない属性名                                                                        |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## ファイルシステムの表示

ファイルシステムの内容を表示するには、次の方法があります。

- 無料のツールを使用する：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)
- または、`mount`コマンドを使用してLinuxにマウントすることもできます。

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksのリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudのリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
