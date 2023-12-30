```markdown
# パーティション/ファイルシステム/カービング

## パーティション/ファイルシステム/カービング

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## パーティション

ハードドライブまたは**SSDディスクは、データを物理的に分離する目的で異なるパーティションを含むことができます**。\
ディスクの**最小**単位は**セクター**（通常は512Bで構成されます）。したがって、各パーティションのサイズはそのサイズの倍数である必要があります。

### MBR (マスターブートレコード)

これは、ブートコードの446Bの後のディスクの**最初のセクターに割り当てられています**。このセクターは、PCに対してどのパーティションをどこからマウントするかを指示するために不可欠です。\
最大で**4つのパーティション**を許可します（最大で**1つだけ**がアクティブ/ブータブルであることができます）。しかし、より多くのパーティションが必要な場合は、**拡張パーティション**を使用できます。この最初のセクターの**最後のバイト**はブートレコードシグネチャ**0x55AA**です。アクティブとしてマークできるパーティションは1つだけです。\
MBRは最大**2.2TB**を許可します。

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

MBRの**440バイト目から443バイト目**には、Windowsが使用されている場合に**Windowsディスクシグネチャ**を見つけることができます。ハードディスクの論理ドライブ文字は、Windowsディスクシグネチャに依存します。このシグネチャを変更すると、Windowsが起動しなくなる可能性があります（ツール: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**。

![](<../../../.gitbook/assets/image (493).png>)

**フォーマット**

| オフセット | 長さ | アイテム |
| ----------- | ---- | -------- |
| 0 (0x00)    | 446(0x1BE) | ブートコード |
| 446 (0x1BE) | 16 (0x10)  | 第1パーティション |
| 462 (0x1CE) | 16 (0x10)  | 第2パーティション |
| 478 (0x1DE) | 16 (0x10)  | 第3パーティション |
| 494 (0x1EE) | 16 (0x10)  | 第4パーティション |
| 510 (0x1FE) | 2 (0x2)    | シグネチャ 0x55 0xAA |

**パーティションレコードフォーマット**

| オフセット | 長さ | アイテム |
| --------- | ---- | ------ |
| 0 (0x00)  | 1 (0x01) | アクティブフラグ (0x80 = ブータブル) |
| 1 (0x01)  | 1 (0x01) | スタートヘッド |
| 2 (0x02)  | 1 (0x01) | スタートセクター (ビット0-5); シリンダーの上位ビット (6- 7) |
| 3 (0x03)  | 1 (0x01) | スタートシリンダーの最下位8ビット |
| 4 (0x04)  | 1 (0x01) | パーティションタイプコード (0x83 = Linux) |
| 5 (0x05)  | 1 (0x01) | エンドヘッド |
| 6 (0x06)  | 1 (0x01) | エンドセクター (ビット0-5); シリンダーの上位ビット (6- 7) |
| 7 (0x07)  | 1 (0x01) | エンドシリンダーの最下位8ビット |
| 8 (0x08)  | 4 (0x04) | パーティションの前にあるセクター (リトルエンディアン) |
| 12 (0x0C) | 4 (0x04) | パーティション内のセクター |

LinuxでMBRをマウントするには、まずスタートオフセットを取得する必要があります（`fdisk`と`p`コマンドを使用できます）

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

そして、以下のコードを使用します
```
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**LBA（ロジカルブロックアドレッシング）**は、コンピュータストレージデバイスに格納されているデータブロックの**位置を指定する**ために一般的に使用される方式です。特にハードディスクドライブなどのセカンダリストレージシステムです。LBAは特にシンプルな線形アドレッシング方式であり、**ブロックは整数インデックスによって位置付けられます**。最初のブロックがLBA 0、2番目がLBA 1、というように続きます。

### GPT (GUID Partition Table)

ドライブ上の各パーティションに**グローバルに一意の識別子**があるため、GUIDパーティションテーブルと呼ばれます。

MBRと同様に**セクター0**から始まります。MBRは32ビットを占有する一方で、**GPT**は**64ビット**を使用します。\
GPTはWindowsでは最大**128パーティション**まで、最大**9.4ZB**までを許容します。\
また、パーティションには36文字のUnicode名を付けることができます。

MBRディスクでは、パーティショニングとブートデータが1か所に格納されています。このデータが上書きされたり破損したりすると、問題が発生します。対照的に、**GPTはこのデータの複数のコピーをディスク全体に保存するため**、はるかに堅牢で、データが破損した場合に回復することができます。

GPTはまた、そのデータが無事であることを確認するための**巡回冗長検査（CRC）**値を保存します。データが破損している場合、GPTは問題を認識し、ディスク上の別の場所から**損傷したデータの回復を試みる**ことができます。

**Protective MBR (LBA0)**

限定的な後方互換性のために、GPT仕様ではレガシーMBRのスペースが引き続き予約されていますが、MBRベースのディスクユーティリティがGPTディスクを誤認し、誤って上書きするのを防ぐ**方法で使用されます**。これはプロテクティブMBRと呼ばれます。

![](<../../../.gitbook/assets/image (491).png>)

**Hybrid MBR (LBA 0 + GPT)**

BIOSサービスを介して**GPTベースのブートをサポートする**オペレーティングシステムでは、最初のセクターは**ブートローダー**コードの最初のステージを格納するために使用されることもありますが、**GPT** **パーティション**を認識するように**変更**されます。MBR内のブートローダーは、セクターサイズが512バイトであると仮定してはいけません。

**Partition table header (LBA 1)**

パーティションテーブルヘッダーは、ディスク上の使用可能なブロックを定義します。また、パーティションテーブルを構成するパーティションエントリの数とサイズも定義します（テーブルのオフセット80および84）。

| Offset    | Length   | Contents                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) for UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, usually 5Ch 00h 00h 00h or 92 bytes)                                                                                                    |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) of header (offset +0 up to header size) in little endian, with this field zeroed during calculation                                |
| 20 (0x14) | 4 bytes  | Reserved; must be zero                                                                                                                                                          |
| 24 (0x18) | 8 bytes  | Current LBA (location of this header copy)                                                                                                                                      |
| 32 (0x20) | 8 bytes  | Backup LBA (location of the other header copy)                                                                                                                                  |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                          |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                       |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                       |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                        |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                            |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                           |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                               |
| 92 (0x5C) | \*       | Reserved; must be zeroes for the rest of the block (420 bytes for a sector size of 512 bytes; but can be more with larger sector sizes)                                         |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                          |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                              |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                                 |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                                   |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                                   |

**Partitions Types**

![](<../../../.gitbook/assets/image (492).png>)

その他のパーティションタイプは[https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)で確認できます。

### Inspecting

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)でフォレンジックイメージをマウントした後、Windowsツール[**Active Disk Editor**](https://www.disk-editor.org/index.html)を使用して最初のセクターを検査できます。次の画像では、**セクター0**に**MBR**が検出され、解釈されています：

![](<../../../.gitbook/assets/image (494).png>)

もし**MBRの代わりにGPTテーブル**があれば、**セクター1**に_EFI PART_の署名が表示されるはずです（前の画像では空です）。

## File-Systems

### Windows file-systems list

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT（ファイル割り当てテーブル）**ファイルシステムは、その組織方法であるファイル割り当てテーブルにちなんで名付けられています。このテーブルはボリュームの先頭にあります。ボリュームを保護するために、テーブルの**2つのコピー**が保持されています。さらに、ファイル割り当てテーブルとルートフォルダは、システムの起動に必要なファイルが正しく位置付けられるように、**固定位置**に格納されなければなりません。

![](<../../../.gitbook/assets/image (495).png>)

このファイルシステムが使用する最小のスペース単位は、通常512Bの**クラスター**です（これは複数のセクターで構成されます）。

初期の**FAT12**は、最大**4078** **クラスター**までの12ビット値のクラスターアドレスを持っていました。UNIXでは4084クラスターまで許容されていました。より効率的な**FAT16**は16ビットのクラスターアドレスに増加し、ボリュームあたり最大**65,517クラスター**まで可能にしました。FAT32は32ビットのクラスターアドレスを使用し、ボリュームあたり最大**268,435,456クラスター**まで可能です。

FATによって許可される**最大ファイルサイズは4GB**（1バイトを除く）です。これは、ファイルシステムがファイルサイズをバイト単位で格納するために32ビットのフィールドを使用し、2^32バイト = 4 GiBだからです。これはFAT12、FAT16、FAT32に当てはまります。

**ルートディレクトリ**は、FAT12とFAT16の両方において**特定の位置**を占めます（FAT32では他のフォルダと同じ位置を占めます）。各ファイル/フォルダエントリには以下の情報が含まれています：

* ファイル/フォルダの名前（最大8文字）
* 属性
* 作成日
* 変更日
* 最終アクセス日
* ファイルの最初のクラスターが始まるFATテーブルのアドレス
* サイズ

FATファイルシステムを使用してファイルを「削除」すると、ファイル名の**最初の文字**が0xE5に変更される以外は、ディレクトリエントリはほぼ**変更されません**。これにより、「削除された」ファイルの名前、タイムスタンプ、ファイル長、そして最も重要なこととして、ディスク上の物理的な位置が保存されます。ただし、ファイルによって占有されていたディスククラスターのリストは、ファイル割り当てテーブルから消去され、その後作成または変更された他のファイルによって使用されるセクターとしてマークされます。FAT32の場合、ファイルの開始クラスター値の上位16ビットを担当するフィールドも追加で消去されます。

### **NTFS**

{% content-ref url="ntfs.md" %}
[ntfs.md](ntfs.md)
{% endcontent-ref %}

### EXT

**Ext2**は、ブートパーティションなどの**ジャーナリングされていない**パーティション（あまり変更されないパーティション）に最も一般的に使用されるファイルシステムです。**Ext3/4**は**ジャーナリング**されており、通常は**残りのパーティション**に使用されます。

{% content-ref url="ext.md" %}
[ext.md](ext.md)
{% endcontent-ref %}

## **Metadata**

一部のファイルにはメタデータが含まれています。この情報はファイルの内容に関するものであり、ファイルタイプによっては、タイトル、MS Officeのバージョン、著者、作成日と最終変更日、カメラのモデル、GPS座標、画像情報などの情報が含まれている場合があります。

[**exiftool**](https://exiftool.org)や[**Metadiver**](https://www.easymetadata.com/metadiver-2/)などのツールを使用して、ファイルのメタデータを取得できます。

## **Deleted Files Recovery**

### Logged Deleted Files

前に見たように、「削除」された後もファイルが保存されている場所がいくつかあります。これは、通常、ファイルシステムからのファイルの削除は、データを削除済みとしてマークするだけで、データ自体は触れられないためです。そのため、ファイルのレジストリ（MFTなど）を検査し、削除されたファイルを見つけることが可能です。

また、OSは通常、ファイルシステムの変更やバックアップに関する多くの情報を保存しているため、それらを使用してファイルを回復するか、できるだけ多くの情報を回復することが可能です。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **File Carving**

**ファイルカービング**は、データの塊の中からファイルを**見つけ出す**ための技術です。このようなツールが機能する3つの主な方法は、ファイルタイプのヘッダーとフッターに基づくもの、ファイルタイプの**構造**に基づくもの、そして**内容**自体に基づくものです。

この技術は、**断片化されたファイルの回復には機能しない**ことに注意してください。ファイルが**連続したセクターに保存されていない**場合、この技術では見つけることができないか、少なくともその一部を見つけることができません。

検索したいファイルタイプを指
