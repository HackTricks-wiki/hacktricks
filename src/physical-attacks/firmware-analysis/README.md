# ファームウェア分析

{{#include ../../banners/hacktricks-training.md}}

## **はじめに**

ファームウェアは、デバイスが正しく動作するために必要なソフトウェアであり、ハードウェアコンポーネントとユーザーが対話するソフトウェア間の通信を管理し促進します。これは永続的なメモリに保存されており、デバイスが電源を入れた瞬間から重要な指示にアクセスできるようにし、オペレーティングシステムの起動につながります。ファームウェアを調査し、潜在的に変更することは、セキュリティの脆弱性を特定するための重要なステップです。

## **情報収集**

**情報収集**は、デバイスの構成や使用されている技術を理解するための重要な初期ステップです。このプロセスには、以下のデータを収集することが含まれます：

- CPUアーキテクチャと実行されているオペレーティングシステム
- ブートローダーの詳細
- ハードウェアのレイアウトとデータシート
- コードベースのメトリクスとソースの場所
- 外部ライブラリとライセンスの種類
- 更新履歴と規制認証
- アーキテクチャ図とフローダイアグラム
- セキュリティ評価と特定された脆弱性

この目的のために、**オープンソースインテリジェンス（OSINT）**ツールは非常に貴重であり、手動および自動レビュープロセスを通じて利用可能なオープンソースソフトウェアコンポーネントの分析も重要です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)のようなツールは、潜在的な問題を見つけるために活用できる無料の静的分析を提供します。

## **ファームウェアの取得**

ファームウェアを取得する方法はいくつかあり、それぞれ異なる複雑さがあります：

- **直接**ソース（開発者、製造業者）から
- 提供された指示から**ビルド**する
- 公式サポートサイトから**ダウンロード**する
- ホストされたファームウェアファイルを見つけるために**Google dork**クエリを利用する
- [S3Scanner](https://github.com/sa7mon/S3Scanner)のようなツールを使って**クラウドストレージ**に直接アクセスする
- マンインザミドル技術を介して**更新**を傍受する
- **UART**、**JTAG**、または**PICit**のような接続を通じてデバイスから**抽出**する
- デバイス通信内での更新リクエストを**スニッフィング**する
- **ハードコーディングされた更新エンドポイント**を特定して使用する
- ブートローダーまたはネットワークから**ダンプ**する
- すべてが失敗した場合、適切なハードウェアツールを使用してストレージチップを**取り外して読み取る**

## ファームウェアの分析

今や**ファームウェアを持っている**ので、それについての情報を抽出してどのように扱うかを知る必要があります。それに使用できるさまざまなツール：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
画像の**エントロピー**を`binwalk -E <bin>`で確認し、エントロピーが低ければ、暗号化されている可能性は低いです。エントロピーが高ければ、暗号化されている（または何らかの方法で圧縮されている）可能性があります。

さらに、これらのツールを使用して**ファームウェア内に埋め込まれたファイル**を抽出できます：

{{#ref}}
../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

または[**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）を使用してファイルを検査します。

### ファイルシステムの取得

前述のツール`binwalk -ev <bin>`を使用して**ファイルシステムを抽出**できたはずです。\
Binwalkは通常、**ファイルシステムのタイプとして名前付けされたフォルダー**内に抽出します。通常、以下のいずれかです：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手動ファイルシステム抽出

場合によっては、binwalkが**ファイルシステムのマジックバイトをシグネチャに持っていない**ことがあります。このような場合は、binwalkを使用して**ファイルシステムのオフセットを見つけ、バイナリから圧縮されたファイルシステムを切り出し、以下の手順に従って**ファイルシステムを手動で抽出します。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
次の**ddコマンド**を実行してSquashfsファイルシステムを切り出します。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
代わりに、次のコマンドも実行できます。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs（上記の例で使用）

`$ unsquashfs dir.squashfs`

ファイルはその後「`squashfs-root`」ディレクトリにあります。

- CPIOアーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2ファイルシステム用

`$ jefferson rootfsfile.jffs2`

- NANDフラッシュを使用したubifsファイルシステム用

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## ファームウェアの分析

ファームウェアが取得されたら、その構造と潜在的な脆弱性を理解するために解剖することが重要です。このプロセスでは、さまざまなツールを利用してファームウェアイメージから貴重なデータを分析および抽出します。

### 初期分析ツール

バイナリファイル（`<bin>`と呼ばれる）の初期検査のためのコマンドセットが提供されています。これらのコマンドは、ファイルタイプの特定、文字列の抽出、バイナリデータの分析、パーティションおよびファイルシステムの詳細の理解に役立ちます：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
画像の暗号化状態を評価するために、**エントロピー**は`binwalk -E <bin>`でチェックされます。低エントロピーは暗号化の欠如を示唆し、高エントロピーは暗号化または圧縮の可能性を示します。

**埋め込まれたファイル**を抽出するためには、**file-data-carving-recovery-tools**のドキュメントやファイル検査のための**binvis.io**などのツールとリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>`を使用することで、通常はファイルシステムを抽出でき、しばしばファイルシステムタイプにちなんだ名前のディレクトリに抽出されます（例：squashfs、ubifs）。ただし、**binwalk**がマジックバイトの欠如によりファイルシステムタイプを認識できない場合、手動抽出が必要です。これには、`binwalk`を使用してファイルシステムのオフセットを特定し、その後`dd`コマンドを使用してファイルシステムを切り出します。
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
その後、ファイルシステムのタイプ（例：squashfs、cpio、jffs2、ubifs）に応じて、異なるコマンドが使用されて手動で内容を抽出します。

### ファイルシステム分析

ファイルシステムが抽出されると、セキュリティの欠陥を探し始めます。注意が払われるのは、安全でないネットワークデーモン、ハードコーディングされた資格情報、APIエンドポイント、更新サーバー機能、未コンパイルのコード、スタートアップスクリプト、およびオフライン分析用のコンパイル済みバイナリです。

**確認すべき主要な場所**と**項目**には以下が含まれます：

- **etc/shadow** と **etc/passwd** のユーザー資格情報
- **etc/ssl** のSSL証明書とキー
- 潜在的な脆弱性のための設定ファイルとスクリプトファイル
- さらなる分析のための埋め込まれたバイナリ
- 一般的なIoTデバイスのウェブサーバーとバイナリ

いくつかのツールがファイルシステム内の機密情報や脆弱性を明らかにするのを助けます：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) と [**Firmwalker**](https://github.com/craigz28/firmwalker) の機密情報検索
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) の包括的なファームウェア分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および [**EMBA**](https://github.com/e-m-b-a/emba) の静的および動的分析

### コンパイル済みバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイル済みバイナリは、脆弱性のために精査されなければなりません。Unixバイナリ用の**checksec.sh**やWindowsバイナリ用の**PESecurity**のようなツールは、悪用される可能性のある保護されていないバイナリを特定するのに役立ちます。

## 動的分析のためのファームウェアのエミュレーション

ファームウェアをエミュレートするプロセスは、デバイスの動作または個々のプログラムの**動的分析**を可能にします。このアプローチは、ハードウェアやアーキテクチャの依存関係に関する課題に直面することがありますが、ルートファイルシステムや特定のバイナリを、Raspberry Piのような一致するアーキテクチャとエンディアンネスを持つデバイスや、事前構築された仮想マシンに転送することで、さらなるテストを促進できます。

### 個々のバイナリのエミュレーション

単一のプログラムを調査するためには、プログラムのエンディアンネスとCPUアーキテクチャを特定することが重要です。

#### MIPSアーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレートするには、次のコマンドを使用できます：
```bash
file ./squashfs-root/bin/busybox
```
必要なエミュレーションツールをインストールするには:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS（ビッグエンディアン）には `qemu-mips` が使用され、リトルエンディアンバイナリには `qemu-mipsel` が選択されます。

#### ARMアーキテクチャエミュレーション

ARMバイナリの場合、プロセスは似ており、エミュレーションには `qemu-arm` エミュレーターが利用されます。

### フルシステムエミュレーション

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) などのツールは、フルファームウェアエミュレーションを容易にし、プロセスを自動化し、動的分析を支援します。

## 実践における動的分析

この段階では、実際のデバイス環境またはエミュレートされたデバイス環境が分析に使用されます。OSおよびファイルシステムへのシェルアクセスを維持することが重要です。エミュレーションはハードウェアの相互作用を完全に模倣できない場合があるため、時折エミュレーションの再起動が必要です。分析はファイルシステムを再訪し、公開されたウェブページやネットワークサービスを悪用し、ブートローダーの脆弱性を探るべきです。ファームウェアの整合性テストは、潜在的なバックドアの脆弱性を特定するために重要です。

## 実行時分析技術

実行時分析は、gdb-multiarch、Frida、Ghidraなどのツールを使用して、プロセスまたはバイナリとその動作環境で相互作用し、ブレークポイントを設定し、ファジングやその他の技術を通じて脆弱性を特定します。

## バイナリの悪用と概念実証

特定された脆弱性のPoCを開発するには、ターゲットアーキテクチャの深い理解と低レベル言語でのプログラミングが必要です。組み込みシステムにおけるバイナリ実行時保護は稀ですが、存在する場合は、Return Oriented Programming（ROP）などの技術が必要になることがあります。

## ファームウェア分析のための準備されたオペレーティングシステム

[AttifyOS](https://github.com/adi0x90/attifyos) や [EmbedOS](https://github.com/scriptingxss/EmbedOS) などのオペレーティングシステムは、必要なツールを備えたファームウェアセキュリティテストのための事前構成された環境を提供します。

## ファームウェアを分析するための準備されたOS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOSは、IoTデバイスのセキュリティ評価とペネトレーションテストを行うためのディストリビューションです。必要なツールがすべてロードされた事前構成された環境を提供することで、多くの時間を節約します。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ファームウェアセキュリティテストツールがプリロードされたUbuntu 18.04に基づく組み込みセキュリティテストオペレーティングシステムです。

## 脆弱なファームウェアの練習

ファームウェアの脆弱性を発見する練習をするために、以下の脆弱なファームウェアプロジェクトを出発点として使用してください。

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

## トレーニングと認証

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
