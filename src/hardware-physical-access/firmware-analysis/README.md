# ファームウェア解析

{{#include ../../banners/hacktricks-training.md}}

## **はじめに**

### 関連リソース


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


ファームウェアは、デバイスが正しく動作するためにハードウェアコンポーネントとユーザーが扱うソフトウェア間の通信を管理・仲介する重要なソフトウェアです。不揮発性メモリに格納され、電源投入直後からデバイスが必要な命令へアクセスできるようにしてOSの起動に繋がります。ファームウェアを調査し、場合によっては改変することは、セキュリティ脆弱性を特定する上で重要なステップです。

## **情報収集**

**情報収集** は、デバイスの構成や使用技術を理解するための重要な初期段階です。このプロセスでは次のようなデータを収集します:

- CPUアーキテクチャと実行しているOS
- ブートローダの詳細
- ハードウェアのレイアウトとデータシート
- コードベースのメトリクスとソースの所在
- 外部ライブラリとライセンス種別
- 更新履歴と規制認証
- アーキテクチャ図やフロー図
- セキュリティ評価と特定された脆弱性

この目的には、**open-source intelligence (OSINT)** ツールが非常に有用であり、入手可能なオープンソースソフトウェアコンポーネントを手動・自動でレビューして解析することも重要です。Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) は、潜在的な問題を見つけるために活用できる無料の静的解析を提供しています。

## **ファームウェアの入手**

ファームウェアの入手方法はいくつかあり、それぞれ難易度が異なります:

- **直接** 開発者やメーカーから入手
- **Building** 提供された手順からビルドする
- **Downloading** 公式サポートサイトからダウンロード
- ホストされているファームウェアファイルを見つけるために**Google dork**クエリを利用
- [S3Scanner](https://github.com/sa7mon/S3Scanner) のようなツールで**クラウドストレージ**へ直接アクセス
- man-in-the-middle 技術を用いて**updates**を傍受
- **Extracting** デバイスから **UART**, **JTAG**, または **PICit** のような接続経由で抽出
- デバイス通信内の更新リクエストを監視する**Sniffing**
- ハードコードされた更新エンドポイントを特定して利用
- ブートローダやネットワークからの**Dumping**
- それでも駄目な場合、適切なハードウェアツールを使ってストレージチップを**取り外し・読み取り**

## ファームウェアの解析

**ファームウェアを入手したので**、処理方法を決めるためにその情報を抽出する必要があります。これに使える様々なツール:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
もしこれらのツールであまり見つからない場合は、`binwalk -E <bin>` でイメージの **entropy** を確認してください。entropy が低ければ暗号化されている可能性は低く、entropy が高ければ暗号化されている（あるいは何らかの方法で圧縮されている）可能性が高いです。

さらに、これらのツールを使って **ファームウェア内に埋め込まれたファイル** を抽出できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

あるいは [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使ってファイルを確認できます。

### Getting the Filesystem

`binwalk -ev <bin>` のような前述のツールを使えば、**ファイルシステムを抽出できているはずです**.\ Binwalk は通常、抽出したものを **ファイルシステムの種類を名前にしたフォルダ** 内に保存します。通常、以下のいずれかです: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

場合によっては、binwalk のシグネチャにファイルシステムの **マジックバイトが含まれていない** ことがあります。このような場合は、binwalk を使って **ファイルシステムのオフセットを特定し、バイナリから圧縮されたファイルシステムを切り出す** ことで、以下の手順に従ってファイルシステムを **手動で抽出** してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
以下の **dd command** を実行して Squashfs filesystem をカービングしてください。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, the following command could also be run.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの解析

ファームウェアを取得したら、その構造や潜在的な脆弱性を理解するために解析することが重要です。このプロセスでは、ファームウェアイメージから有用なデータを解析・抽出するためにさまざまなツールを使用します。

### 初期解析ツール

以下は、バイナリファイル（`<bin>`と呼ぶ）の初期検査に使用するコマンド群です。これらのコマンドは、ファイルタイプの特定、文字列抽出、バイナリデータの解析、パーティションやファイルシステムの詳細把握に役立ちます:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
イメージの暗号化状態を評価するために、**エントロピー**を`binwalk -E <bin>`で確認します。エントロピーが低い場合は暗号化されていないことを示唆し、エントロピーが高い場合は暗号化または圧縮の可能性を示します。

埋め込みファイルを抽出するために、**file-data-carving-recovery-tools**のドキュメントやファイル検査用の**binvis.io**のようなツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>` を使うと、通常ファイルシステムを抽出でき、多くの場合ファイルシステムタイプ（例: squashfs、ubifs）にちなんだディレクトリに展開されます。しかし、マジックバイトが欠けているために **binwalk** がファイルシステムタイプを認識できない場合は、手動での抽出が必要です。これには `binwalk` でファイルシステムのオフセットを特定し、続いて `dd` コマンドでファイルシステムを切り出す作業が含まれます：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムのタイプ（例：squashfs、cpio、jffs2、ubifs）に応じて、内容を手動で展開するために異なるコマンドが使用されます。

### ファイルシステム解析

ファイルシステムを展開した後、セキュリティ上の欠陥を探し始めます。特に注意する項目は、脆弱なネットワークデーモン、ハードコードされた資格情報、API endpoints、更新サーバー機能、未コンパイルのコード、起動スクリプト、およびオフライン解析用のコンパイル済みバイナリです。

**主に確認すべき場所** と **項目** は次のとおりです：

- **etc/shadow** および **etc/passwd**（ユーザー資格情報）
- **etc/ssl** にあるSSL証明書と鍵
- 潜在的な脆弱性を含む設定ファイルやスクリプト
- 追加解析のための組み込みバイナリ
- 一般的なIoTデバイスの web サーバーやバイナリ

ファイルシステム内の機密情報や脆弱性を発見するのに役立つツール：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker)：機密情報の検索用
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)：包括的なファームウェア解析用
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および [**EMBA**](https://github.com/e-m-b-a/emba)：for static and dynamic analysis

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリの両方を脆弱性について精査する必要があります。Unixバイナリ向けの **checksec.sh** や Windowsバイナリ向けの **PESecurity** のようなツールは、悪用可能な保護のないバイナリを特定するのに役立ちます。

## ファームウェアをエミュレートして Dynamic Analysis を行う

ファームウェアをエミュレートすることで、デバイス全体の動作や個々のプログラムの dynamic analysis が可能になります。この方法はハードウェアやアーキテクチャ依存の問題に直面することがありますが、ルートファイルシステムや特定のバイナリを、アーキテクチャとエンディアンが一致するデバイス（例：Raspberry Pi）や事前構築された仮想マシンに移すことで、さらなるテストが容易になります。

### 個々のバイナリのエミュレーション

単一のプログラムを解析する場合、プログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPS アーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレートするには、次のコマンドを使用できます：
```bash
file ./squashfs-root/bin/busybox
```
そして、必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

この段階では、実機またはエミュレートしたデバイス環境のいずれかを用いて解析を行います。OS とファイルシステムへのシェルアクセスを維持することが重要です。エミュレーションはハードウェアとの相互作用を完全には再現しない場合があり、そのためエミュレーションの再起動が必要になることがあります。解析ではファイルシステムを再確認し、公開されているウェブページやネットワークサービスを悪用し、ブートローダの脆弱性を調査するべきです。ファームウェアの整合性テストは、バックドアとなりうる脆弱性を特定するために重要です。

## Runtime Analysis Techniques

ランタイム解析は、プロセスやバイナリをその実行環境で操作することを含み、ブレークポイントの設定や fuzzing などの手法で脆弱性を特定するために gdb-multiarch、Frida、Ghidra のようなツールを使用します。

## Binary Exploitation and Proof-of-Concept

既知の脆弱性に対する PoC を開発するには、ターゲットアーキテクチャの深い理解と低レベル言語でのプログラミングが必要です。組み込みシステムではバイナリのランタイム保護は稀ですが、存在する場合は Return Oriented Programming (ROP) のような手法が必要になることがあります。

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS は Internet of Things (IoT) デバイスの security assessment と penetration testing を行うためのディストリビューションです。必要なツールがプリコンフィグ済みで全てロードされている環境を提供することで、多くの時間を節約できます。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 をベースとした embedded security testing 用のオペレーティングシステムで、ファームウェアセキュリティテスト用のツールがプリロードされています。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

ベンダーがファームウェアイメージに対して暗号署名のチェックを実装していても、**version rollback (downgrade) protection はしばしば欠如しています**。ブートローダやリカバリーローダが埋め込み公開鍵で署名のみを検証し、フラッシュされるイメージの *version*（または単調増加カウンタ）を比較しない場合、攻撃者は合法的に有効な署名を保持した **古い脆弱なファームウェアをインストール** でき、パッチ済みの脆弱性を再導入できます。

Typical attack workflow:

1. **Obtain an older signed image**
* ベンダーの公開ダウンロードポータル、CDN、またはサポートサイトから入手する。
* コンパニオンのモバイル/デスクトップアプリケーションから抽出する（例：Android APK 内の `assets/firmware/` に含まれる場合）。
* VirusTotal、Internet archives、フォーラムなどのサードパーティリポジトリから取得する。
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* 多くのコンシューマ向け IoT デバイスは *unauthenticated* な HTTP(S) エンドポイントを公開しており、Base64-encoded なファームウェアブロブを受け取り、サーバー側でデコードしてリカバリ/アップグレードをトリガーします。
3. ダウングレード後、新しいリリースでパッチされた脆弱性を悪用する（例えば後から追加された command-injection フィルタなど）。
4. 永続化を得た後、検出を避けるためにオプションで最新のイメージに再フラッシュするか、更新を無効にする。

### 例: Command Injection のダウングレード後
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
脆弱な（ダウングレードされた）ファームウェアでは、`md5` パラメータがサニタイズされずに直接シェルコマンドに連結されており、任意のコマンドを注入できる（ここでは SSH key-based root access を有効にする）。後続のファームウェアバージョンでは基本的な文字フィルタが導入されたが、ダウングレード保護がないため修正は意味を成さない。

### モバイルアプリからのファームウェア抽出

多くのベンダは、コンパニオンのモバイルアプリ内に完全なファームウェアイメージをバンドルしており、アプリが Bluetooth/Wi‑Fi 経由でデバイスを更新できるようにしている。これらのパッケージは通常、APK/APEX の `assets/fw/` や `res/raw/` のようなパスに暗号化されずに格納されている。`apktool`、`ghidra`、または単純に `unzip` などのツールを使えば、物理ハードウェアに触れずに署名済みイメージを取り出すことができる。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 更新ロジック評価チェックリスト

* *update endpoint* のトランスポート／認証は十分に保護されているか（TLS + authentication）?
* デバイスはフラッシュの前に **バージョン番号** または **monotonic anti-rollback counter** を比較しているか?
* イメージはセキュアブートチェーンの内部で検証されているか（例：ROM code による署名チェック）?
* userland code は追加の妥当性チェックを実行しているか（例：許可された partition map、model number）?
* *partial* や *backup* のアップデートフローは同じ検証ロジックを再利用しているか?

> 💡  上記のいずれかが欠けている場合、プラットフォームはおそらく rollback attacks に対して脆弱です。

## 演習向けの脆弱なファームウェア

ファームウェアの脆弱性発見を練習するには、以下の脆弱なファームウェアプロジェクトを出発点として利用してください。

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

## トレーニングと認定

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
