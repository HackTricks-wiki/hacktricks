<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>でAWSハッキングをゼロからヒーローまで学びましょう！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**する
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>


# Ext - 拡張ファイルシステム

**Ext2**は、ブートパーティションのような**ほとんど変更されないパーティション**に最も一般的な**ジャーナリングされていない**ファイルシステムです。**Ext3/4**は**ジャーナリング**され、通常は**残りのパーティション**に使用されます。

ファイルシステム内のすべてのブロックグループは同じサイズで連続して格納されています。これにより、カーネルは整数インデックスからディスク上のブロックグループの場所を簡単に導出できます。

各ブロックグループには、次の情報が含まれています：

- ファイルシステムのスーパーブロックのコピー
- ブロックグループ記述子のコピー
- グループ内の空きブロックを識別するために使用されるデータブロックビットマップ
- グループ内の空きinodeを識別するために使用されるinodeビットマップ
- inodeテーブル：連続した一連のブロックで構成され、それぞれが事前定義の図1 Ext2 inode番号のinodeを含んでいます。すべてのinodeのサイズは同じです：128バイト。1,024バイトのブロックには8つのinodeが含まれ、4,096バイトのブロックには32のinodeが含まれます。Ext2では、inode番号と対応するブロック番号のマッピングをディスク上に保存する必要はないため、後者の値はブロックグループ番号とinodeテーブル内の相対位置から導出できます。たとえば、各ブロックグループに4,096のinodeが含まれ、ディスク上のinode 13,021のアドレスを知りたい場合を考えてみましょう。この場合、inodeは3番目のブロックグループに属し、そのディスクアドレスは対応するinodeテーブルの733番目のエントリに格納されています。inode番号は、Ext2ルーチンがディスク上の適切なinode記述子を迅速に取得するために使用するキーであることがわかります。
- ファイルを含むデータブロック。意味のない情報を含まないブロックはすべて空きと言われます。

![](<../../../.gitbook/assets/image (406).png>)

## Extオプション機能

**機能は**データの配置場所に影響を与え、**inode内のデータの格納方法**に影響を与え、いくつかは**分析のための追加メタデータ**を提供する可能性があるため、機能はExtで重要です。

ExtにはOSがサポートするかしないかに関わらず、3つの可能性があるオプション機能があります：

- 互換性あり
- 互換性なし
- 読み取り専用互換性：マウントできますが書き込みはできません

**互換性のない**機能がある場合、OSはデータへのアクセス方法を知らないため、ファイルシステムをマウントできません。

{% hint style="info" %}
疑わしい攻撃者は標準外の拡張機能を持っている可能性があります
{% endhint %}

**スーパーブロック**を読む**任意のユーティリティ**は、**Extファイルシステム**の**機能**を示すことができますが、`file -sL /dev/sd*`を使用しても同様の情報を取得できます。

## スーパーブロック

スーパーブロックは最初の1024バイトから始まり、各グループの最初のブロックに繰り返され、次の情報を含んでいます：

- ブロックサイズ
- 総ブロック数
- ブロックグループごとのブロック数
- 最初のブロックグループの前に予約されたブロック数
- 総inode数
- ブロックグループごとのinode数
- ボリューム名
- 最終書き込み時刻
- 最終マウント時刻
- ファイルシステムが最後にマウントされたパス
- ファイルシステムのステータス（クリーン？）

Extファイルシステムファイルからこの情報を取得することが可能です：
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
あなたは無料のGUIアプリケーションを使用することもできます：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
また、**python**を使用してスーパーブロック情報を取得することもできます：[https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodes

**inodes**には、**ファイル**の実際の**データ**を含む**ブロック**のリストが含まれています。\
ファイルが大きい場合、inodeにはファイルデータを含むブロック/他のinodeを指すポインタが含まれる場合があります。

![](<../../../.gitbook/assets/image (416).png>)

**Ext2**および**Ext3**のinodeはサイズが**128B**であり、**Ext4**は現在**156B**を使用していますが、将来の拡張を許可するためにディスク上に**256B**を割り当てています。

Inode構造：

| オフセット | サイズ | 名前              | 説明                                             |
| ------ | ---- | ----------------- | ------------------------------------------------ |
| 0x0    | 2    | ファイルモード         | ファイルモードとタイプ                               |
| 0x2    | 2    | UID               | オーナーIDの下位16ビット                        |
| 0x4    | 4    | サイズ Il           | ファイルサイズの下位32ビット                       |
| 0x8    | 4    | Atime             | エポックからのアクセス時間（秒単位）               |
| 0xC    | 4    | Ctime             | エポックからの変更時間（秒単位）               |
| 0x10   | 4    | Mtime             | エポックからの変更時間（秒単位）               |
| 0x14   | 4    | Dtime             | エポックからの削除時間（秒単位）               |
| 0x18   | 2    | GID               | グループIDの下位16ビット                        |
| 0x1A   | 2    | Hlink count       | ハードリンク数                                  |
| 0xC    | 4    | Blocks Io         | ブロック数の下位32ビット                     |
| 0x20   | 4    | フラグ             | フラグ                                            |
| 0x24   | 4    | Union osd1        | Linux：Iバージョン                                 |
| 0x28   | 69   | Block\[15]        | 15つのデータブロックを指す                         |
| 0x64   | 4    | バージョン           | NFS用のファイルバージョン                             |
| 0x68   | 4    | File ACL low      | 拡張属性（ACLなど）の下位32ビット  |
| 0x6C   | 4    | File size hi      | ファイルサイズの上位32ビット（ext4のみ）           |
| 0x70   | 4    | Obsolete fragment | 廃止されたフラグメントアドレス                    |
| 0x74   | 12   | Osd 2             | 第2のオペレーティングシステム依存のユニオン          |
| 0x74   | 2    | Blocks hi         | ブロック数の上位16ビット                     |
| 0x76   | 2    | File ACL hi       | 拡張属性（ACLなど）の上位16ビット |
| 0x78   | 2    | UID hi            | オーナーIDの上位16ビット                        |
| 0x7A   | 2    | GID hi            | グループIDの上位16ビット                        |
| 0x7C   | 2    | Checksum Io       | inodeチェックサムの下位16ビット                  |

"Modify"はファイルの_内容_が最後に変更された時間のタイムスタンプです。これは一般的に"_mtime_"と呼ばれます。\
"Change"はファイルの_inode_が変更された最後の時間のタイムスタンプであり、権限、所有権、ファイル名、およびハードリンクの数などが変更されたことを示します。これは一般的に"_ctime_"と呼ばれます。

Inode構造の拡張（Ext4）：

| オフセット | サイズ | 名前         | 説明                                 |
| ------ | ---- | ------------ | ------------------------------------------- |
| 0x80   | 2    | 追加サイズ   | 標準の128バイトを超えて使用されるバイト数 |
| 0x82   | 2    | チェックサム上位  | inodeチェックサムの上位16ビット             |
| 0x84   | 4    | Ctime extra  | 変更時間の追加ビット                      |
| 0x88   | 4    | Mtime extra  | 変更時間の追加ビット                      |
| 0x8C   | 4    | Atime extra  | アクセス時間の追加ビット                      |
| 0x90   | 4    | Crtime       | ファイル作成時間（エポックからの秒数）      |
| 0x94   | 4    | Crtime extra | ファイル作成時間の追加ビット                 |
| 0x98   | 4    | Version hi   | バージョンの上位32ビット                    |
| 0x9C   |      | 未使用       | 将来の拡張のための予約スペース        |

特別なinode：

| Inode | 特別な目的                                      |
| ----- | ---------------------------------------------------- |
| 0     | そのようなinodeは存在せず、番号付けは1から開始します                |
| 1     | 欠陥ブロックリスト                                 |
| 2     | ルートディレクトリ                                       |
| 3     | ユーザークォータ                                          |
| 4     | グループクォータ                                         |
| 5     | ブートローダ                                          |
| 6     | 削除されたディレクトリ                                   |
| 7     | 予約されたグループ記述子（ファイルシステムのサイズ変更用） |
| 8     | ジャーナル                                              |
| 9     | 除外inode（スナップショット用）                        |
| 10    | レプリカinode                                        |
| 11    | 最初の非予約inode（しばしばlost + found）        |

{% hint style="info" %}
作成時間はExt4にのみ表示されることに注意してください。
{% endhint %}

inode番号を知っていると、そのインデックスを簡単に見つけることができます：

* inodeが属する**ブロックグループ**：（Inode番号 - 1）/（グループあたりのinode数）
* **グループ内のインデックス**：（Inode番号 - 1）mod（Inodes/groups）
* **inodeテーブルへのオフセット**：Inode番号 \*（Inodeサイズ）
* inode 0は未定義（使用されていない）ため、「-1」があります。
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
### ファイルモード

| 番号 | 説明                                                                                               |
| ------ | --------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **Directory/Block Bit 13**                                                                          |
| **13** | **Char Device/Block Bit 14**                                                                        |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | Sticky Bit (without it, anyone with Write & exec perms on a directory can delete and rename files)  |
| 8      | Owner Read                                                                                          |
| 7      | Owner Write                                                                                         |
| 6      | Owner Exec                                                                                          |
| 5      | Group Read                                                                                          |
| 4      | Group Write                                                                                         |
| 3      | Group Exec                                                                                          |
| 2      | Others Read                                                                                         |
| 1      | Others Write                                                                                        |
| 0      | Others Exec                                                                                         |

太字のビット（12、13、14、15）はファイルの種類を示し、太字のオプションは1つだけ存在します。

### ディレクトリ

| オフセット | サイズ | 名前      | 説明                                                                                                                                                  |
| ------ | ---- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 4    | Inode     |                                                                                                                                                              |
| 0x4    | 2    | Rec len   | Record length                                                                                                                                                |
| 0x6    | 1    | Name len  | Name length                                                                                                                                                  |
| 0x7    | 1    | File type | <p>0x00 Unknown<br>0x01 Regular</p><p>0x02 Director</p><p>0x03 Char device</p><p>0x04 Block device</p><p>0x05 FIFO</p><p>0x06 Socket</p><p>0x07 Sym link</p> |
| 0x8    |      | Name      | Name string (up to 255 characters)                                                                                                                           |

**パフォーマンスを向上させるために、Root hash Directory blocks may be used.**

### 拡張属性

保存される場所

- イノード間の余分なスペース（256 - イノードサイズ、通常 = 100）
- イノード内のfile_aclが指すデータブロック

"ユーザー"で始まる名前の属性を使用して、ユーザーの属性として何でも保存できます。この方法でデータを隠すことができます。

拡張属性エントリ

| オフセット | サイズ | 名前         | 説明                                                                                                                                                                                                        |
| ------ | ---- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 1    | Name len     | 属性名の長さ                                                                                                                                                                                           |
| 0x1    | 1    | Name index   | <p>0x0 = no prefix</p><p>0x1 = user. Prefix</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2    | Value offs   | 最初のイノードエントリまたはブロックの開始からのオフセット                                                                                                                                                                    |
| 0x4    | 4    | Value blocks | 値が保存されているディスクブロック、またはこのブロックの場合はゼロ                                                                                                                                                               |
| 0x8    | 4    | Value size   | 値の長さ                                                                                                                                                                                                    |
| 0xC    | 4    | Hash         | ブロック内の属性のハッシュ、またはイノード内の場合はゼロ                                                                                                                                                                      |
| 0x10   |      | Name         | 末尾のNULLを除いた属性名                                                                                                                                                                                   |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## ファイルシステムビュー

ファイルシステムの内容を確認するには、**無料ツール**を使用できます: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
または、`mount`コマンドを使用してLinuxにマウントすることもできます。

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.)
