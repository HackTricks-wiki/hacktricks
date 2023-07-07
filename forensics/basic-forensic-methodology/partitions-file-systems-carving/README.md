# パーティション/ファイルシステム/カービング

## パーティション/ファイルシステム/カービング

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## パーティション

ハードドライブまたは**SSDディスクには、データを物理的に分離するための異なるパーティションが含まれる**場合があります。\
ディスクの**最小単位はセクタ**です（通常は512Bで構成されています）。したがって、各パーティションのサイズはそのサイズの倍数である必要があります。

### MBR（マスターブートレコード）

これは、**ブートコードの446Bの後のディスクの最初のセクタ**に割り当てられます。このセクタは、PCにパーティションをどこからマウントするかを示すために必要です。\
最大で**4つのパーティション**（最大で**1つだけがアクティブ/ブート可能**）を許可します。ただし、より多くのパーティションが必要な場合は、**拡張パーティション**を使用できます。この最初のセクタの最後のバイトは、ブートレコードの署名**0x55AA**です。1つのパーティションのみがアクティブにマークされることができます。\
MBRは**最大2.2TB**を許可します。

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

MBRの**バイト440から443**には、**Windowsディスクシグネチャ**（Windowsを使用している場合）が含まれています。ハードディスクの論理ドライブレターは、Windowsディスクシグネチャに依存します。このシグネチャを変更すると、Windowsの起動が阻止される可能性があります（ツール：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**）**。

![](<../../../.gitbook/assets/image (493).png>)

**フォーマット**

| オフセット   | 長さ       | 項目             |
| ------------ | ---------- | ---------------- |
| 0（0x00）    | 446（0x1BE）| ブートコード     |
| 446（0x1BE） | 16（0x10） | 最初のパーティション |
| 462（0x1CE） | 16（0x10） | 2番目のパーティション |
| 478（0x1DE） | 16（0x10） | 3番目のパーティション |
| 494（0x1EE） | 16（0x10） | 4番目のパーティション |
| 510（0x1FE） | 2（0x2）   | シグネチャ0x55 0xAA |

**パーティションレコードのフォーマット**

| オフセット  | 長さ      | 項目                                                   |
| ----------- | --------- | ------------------------------------------------------ |
| 0（0x00）   | 1（0x01） | アクティブフラグ（0x80 = ブート可能）                   |
| 1（0x01）   | 1（0x01） | 開始ヘッド                                             |
| 2（0x02）   | 1（0x01） | 開始セクタ（ビット0-5）；シリンダの上位ビット（6-7）   |
| 3（0x03）   | 1（0x01） | 開始シリンダの下位8ビット                             |
| 4（0x04）   | 1（0x01） | パーティションタイプコード（0x83 = Linux）               |
| 5（0x05）   | 1（0x01） | 終了ヘッド                                             |
| 6（0x06）   | 1（0x01） | 終了セクタ（ビット0-5）；シリンダの上位ビット（6-7）   |
| 7（0x07）   | 1（0x01） | 終了シリンダの下位8ビット                             |
| 8（0x08）   | 4（0x04） | パーティションの前にあるセクタ（リトルエンディアン）   |
| 12（0x0C）  | 4（0x04） | パーティション内のセクタ数                             |

LinuxでMBRをマウントするには、まず開始オフセットを取得する必要があります（`fdisk`と`p`コマンドを使用できます）

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA（論理ブロックアドレッシング）**

**論理ブロックアドレッシング**（LBA）は、コンピュータのストレージデバイス（一般的にはハードディスクドライブなどの二次記憶装置）に格納されたデータのブロックの場所を指定するために使用される一般的なスキームです。LBAは特にシンプルな線形アドレッシングスキームであり、ブロックは整数のインデックスによって特定されます。最初のブロックはLBA 0、2番目のブロックはLBA 1、以降のブロックは順に増加します。

### GPT（GUIDパーティションテーブル）

GPT（GUIDパーティションテーブル）とは、ドライブ上の各パーティションに**グローバルに一意の識別子**があるため、この名前が付けられています。

MBRと同様に、GPTも**セクター0**から始まります。MBRは32ビットを占有しているのに対し、**GPT**は**64ビット**を使用します。\
GPTでは、Windowsでは最大128のパーティションを作成でき、最大**9.4ZB**までサポートされています。\
また、パーティションには36文字のUnicode名を付けることができます。

MBRディスクでは、パーティショニングとブートデータは1か所に格納されます。このデータが上書きされたり破損したりすると、問題が発生します。一方、**GPTはディスク全体に複数のコピーを保存**するため、より堅牢で、データが破損した場合でも回復することができます。

GPTはまた、データが破損しているかどうかを確認するために**巡回冗長検査（CRC）**値を保存します。データが破損している場合、GPTは問題に気付き、ディスク上の別の場所から**破損したデータを回復しようとします**。

**保護MBR（LBA0）**

互換性のために、GPT仕様では従来のMBRの領域が予約されていますが、これはMBRベースのディスクユーティリティがGPTディスクを誤認識して上書きすることを防ぐ**方法で使用**されています。これは保護MBRと呼ばれます。

![](<../../../.gitbook/assets/image (491).png>)

**ハイブリッドMBR（LBA 0 + GPT）**

BIOSを介して**GPTベースのブート**をサポートするオペレーティングシステムでは、最初のセクターは**ブートローダー**コードの最初のステージを格納するために使用される場合がありますが、**変更**されて**GPTパーティション**を認識するようになります。MBRのブートローダーは、セクターサイズが512バイトであるとは想定しないでください。

**パーティションテーブルヘッダー（LBA 1）**

パーティションテーブルヘッダーは、ディスク上の使用可能なブロックを定義します。また、パーティションテーブルを構成するパーティションエントリの数とサイズも定義します（テーブル内のオフセット80と84）。

| オフセット   | 長さ     | 内容                                                                                                                                                                          |
| ------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)     | 8バイト   | シグネチャ（"EFI PART"、45h 46h 49h 20h 50h 41h 52h 54hまたは0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)、リトルエンディアンマシンでは） |
| 8 (0x08)     | 4バイト   | UEFI 2.8用のリビジョン1.0（00h 00h 01h 00h）                                                                                                                                  |
| 12 (0x0C)    | 4バイト   | ヘッダーサイズ（リトルエンディアンでのバイト単位、通常は5Ch 00h 00h 00hまたは92バイト）                                                                                       |
| 16 (0x10)    | 4バイト   | ヘッダーのCRC32（オフセット+0からヘッダーサイズまで）のリトルエンディアンでの値。計算中にこのフィールドはゼロになります。                                                   |
| 20 (0x14)    | 4バイト   | 予約済み；ゼロである必要があります                                                                                                                                            |
| 24 (0x18)    | 8バイト   | 現在のLBA（このヘッダーコピーの場所）                                                                                                                                          |
| 32 (0x20)    | 8バイト   | バックアップLBA（他のヘッダーコピーの場所）                                                                                                                                    |
| 40 (0x28)    | 8バイト   | パーティションの最初の使用可能なLBA（プライマリパーティションテーブルの最後のLBA + 1）                                                                                          |
| 48 (0x30)    | 8バイト   | 最後の使用可能なLBA（セカンダリパーティションテーブルの最初のLBA−1）                                                                                                           |
| 56 (0x38)    | 16バイト  | ディスクのGUID（ミックスエンディアン）                                                                                                                                         |
| 72 (0x48)    | 8バイト   | パーティションエントリの配列の開始LBA（プライマリコピーでは常に2）                                                                                                               |
| 80 (0x50)    | 4バイト   | 配列内のパーティションエントリの数                                                                                                                                            |
| 84 (0x54)    | 4バイト   | 単一のパーティションエントリのサイズ（通常は80hまたは128）                                                                                                                     |
| 88 (0x58)    | 4バイト   | パーティションエントリ配列のCRC32（リトルエンディアン）                                                                                                                         |
| 92 (0x5C)    | \*       | ブロックの残りの部分にはゼロでなければなりません（セクターサイズが512バイトの場合は420バイトですが、より大きなセクターサイズの場合はそれ以上になる場合があります）                                         |

**パーティションエントリ（LBA 2–33）**

| GUIDパーティションエントリ形式 |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| オフセット                   | 長さ     | 内容                                                                                                              |
| 0 (0x00)                    | 16バイト | [パーティションタイプGUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs)（ミックスエンディアン） |
| 16 (0x10)                   | 16バイト | ユニークなパーティションGUID（ミックスエンディアン）                                                               |
| 32 (0x20)                   | 8バイト   | 最初のLBA（[リトルエンディアン](https://en.wikipedia.org/wiki/Little\_endian)）                                     |
| 40 (0x28)                   | 8バイト   | 最後のLBA（包括的、通常は奇数）                                                                                     |
| 48 (0x30)                   | 8バイト   | 属性フラグ（例：ビット60は読み取り専用を示す）                                                                     |
| 56 (0x38)                   | 72バイト  | パーティション名（36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LEコードユニット）                                 |

**パーティションタイプ**

![](<../../../.gitbook/assets/image (492).png>)

詳細なパーティションタイプは[https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)を参照してください。

### 検査

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)を使用してフォレンジックイメージ
## ファイルシステム

### Windowsのファイルシステム一覧

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT（File Allocation Table）**ファイルシステムは、その組織方法であるファイル割り当てテーブルにちなんで名付けられています。このテーブルはボリュームの先頭に存在し、ボリュームを保護するために**2つのコピー**が保持されます。さらに、ファイル割り当てテーブルとルートフォルダは、システムの起動に必要なファイルを正しく見つけるために**固定位置**に保存される必要があります。

![](<../../../.gitbook/assets/image (495).png>)

このファイルシステムで使用される最小のスペース単位は、通常512Bの**クラスタ**です（セクタの数で構成されています）。

初期の**FAT12**は、最大で**4078**の**クラスタ**を持つ12ビットのクラスタアドレスを使用し、UNIXでは最大で4084のクラスタを許可していました。より効率的な**FAT16**は、最大で**65,517のクラスタ**を許可する16ビットのクラスタアドレスを使用しています。FAT32は32ビットのクラスタアドレスを使用し、ボリュームあたり最大**268,435,456のクラスタ**を許可します。

FATが許容する**最大ファイルサイズは4GB**（1バイトを引いたもの）です。これは、ファイルシステムがバイト単位でファイルサイズを格納するために32ビットのフィールドを使用しており、2^32バイト=4 GiBになるためです。これはFAT12、FAT16、FAT32の場合に起こります。

**ルートディレクトリ**は、FAT12とFAT16の場合には**特定の位置**を占めます（FAT32の場合は他のフォルダと同じ位置を占めます）。各ファイル/フォルダエントリには、次の情報が含まれています。

* ファイル/フォルダの名前（最大8文字）
* 属性
* 作成日時
* 変更日時
* 最終アクセス日時
* ファイルの最初のクラスタが格納されているFATテーブルのアドレス
* サイズ

FATファイルシステムを使用してファイルが「削除」されると、ディレクトリエントリはほとんど**変更されません**（ファイル名の最初の文字が0xE5に変更されます）。これにより、「削除」されたファイルの名前のほとんど、タイムスタンプ、ファイルの長さ、そして最も重要なことにディスク上の物理的な場所が保持されます。ただし、その後に作成または変更された他のファイルによって使用されるため、ファイルが占有するディスククラスタのリストはファイル割り当てテーブルから消去されます。FAT32の場合、ファイルの開始クラスタ値の上位16ビットを担当する消去されたフィールドが追加されます。

### **NTFS**

{% content-ref url="ntfs.md" %}
[ntfs.md](ntfs.md)
{% endcontent-ref %}

### EXT

**Ext2**は、ブートパーティションなどの**変更がほとんどない**パーティションに対して最も一般的なジャーナリングされていないファイルシステムです。**Ext3/4**は**ジャーナリング**されており、通常は**その他のパーティション**に使用されます。

{% content-ref url="ext.md" %}
[ext.md](ext.md)
{% endcontent-ref %}

## **メタデータ**

一部のファイルにはメタデータが含まれています。この情報はファイルの内容に関するものであり、ファイルの種類によっては、次のような情報が含まれる場合があります。

* タイトル
* 使用されたMS Officeのバージョン
* 作成日時と最終変更日時
* カメラのモデル
* GPS座標
* 画像情報

[**exiftool**](https://exiftool.org)や[**Metadiver**](https://www.easymetadata.com/metadiver-2/)などのツールを使用して、ファイルのメタデータを取得することができます。

## **削除されたファイルの回復**

### 削除されたファイルのログ

以前に見たように、ファイルが「削除」された後もまだいくつかの場所に保存されています。これは通常、ファイルシステムからのファイルの削除は単に削除されたとマークされるだけで、データは触れられないためです。そのため、ファイルのレジストリ（MFTなど）を調査し、削除されたファイルを見つけることが可能です。

また、OSは通常、ファイルシステムの変更やバックアップに関する多くの情報を保存するため、ファイルまたは可能な限り多くの情報を回復するためにそれらを使用することができます。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **ファイルカービング**

**ファイルカービング**は、データの一括からファイルを見つけようとする技術です。このようなツールが動作する方法は、**ファイルタイプのヘッダとフッタ**に基づく方法、ファイルタイプの**構造**に基づく方法、および**コンテンツ**自体に基づく方法の3つがあります。

この技術は、**断片化されたファイルを回復するためには機能しません**。ファイルが**連続したセクタに保存されていない**場合、この技術ではそれを見つけることができないか、少なくとも一部を見つけることができません。

ファイルカービングには、検索したいファイルタイプを指定して使用できるいくつかのツールがあります。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### データストリーム**カービング**

データストリームカービングは、ファイルカービングと似ていますが、**完全なファイルではなく興味深い断片**の情報を探します。\
たとえば、ログに記録されたURLを含む完全なファイルを探すのではなく、この技術ではURLを検索します。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 安全な削除

明らかに、ファイルを「安全に」削除し、それに関する一部のログを削除する方法があります。たとえば、ファイルの内容を複数回ジャンクデータで上書きし、その後、ファイルに関する**$MFT**と**$LOGFILE**のログを**削除**し、**ボリュームシャドウコピー**を削除することができます。\
この操作を実行しても、ファイルの存在がまだログに記録されている他の部分があるかもしれないことに注意してください。これは、フォレンジックの専門家の仕事の一部です。
## 参考文献

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
