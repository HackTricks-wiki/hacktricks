# Firmware Analysis

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)**に参加するか、**[**telegramグループ**](https://t.me/peass)**に参加するか、Twitter 🐦で @carlospolopmをフォローする**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>

## **導入**

ファームウェアは、デバイスが正しく動作するための不可欠なソフトウェアであり、ハードウェアコンポーネントとユーザーがやり取りするソフトウェアとの間の通信を管理し、容易にします。デバイスが電源を入れた瞬間から重要な命令にアクセスできるように、永続メモリに保存され、オペレーティングシステムの起動につながります。ファームウェアの調査および可能な変更は、セキュリティの脆弱性を特定するための重要なステップです。

## **情報収集**

**情報収集**は、デバイスの構成と使用されているテクノロジーを理解するための重要な初期ステップです。このプロセスには、次のデータの収集が含まれます:

* CPUアーキテクチャと実行されているオペレーティングシステム
* ブートローダーの詳細
* ハードウェアレイアウトとデータシート
* コードベースのメトリクスとソースの場所
* 外部ライブラリとライセンスタイプ
* 更新履歴と規制認証
* アーキテクチャとフローダイアグラム
* セキュリティアセスメントと特定された脆弱性

この目的のために、\*\*オープンソースインテリジェンス（OSINT）\*\*ツールが非常に有用であり、利用可能なオープンソースソフトウェアコンポーネントの手動および自動レビュープロセスを通じて分析することも重要です。[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのツールは、潜在的な問題を見つけるために活用できる無料の静的解析を提供しています。

## **ファームウェアの取得**

ファームウェアの取得は、それぞれ異なる複雑さレベルを持つさまざまな手段を通じてアプローチできます:

* **ソースから**（開発者、製造業者）**直接**
* 提供された手順に従って**ビルド**する
* 公式サポートサイトから**ダウンロード**
* ホストされているファームウェアファイルを見つけるための**Googleドーク**クエリを利用する
* [S3Scanner](https://github.com/sa7mon/S3Scanner)などのツールを使用して、**クラウドストレージ**に直接アクセスする
* 中間者攻撃技術を使用して**更新**を傍受する
* **UART**、**JTAG**、または**PICit**などの接続を介してデバイスから**抽出**
* デバイス通信内の更新リクエストを**スニッフィング**
* **ハードコードされた更新エンドポイント**を特定して使用する
* ブートローダーまたはネットワークから**ダンプ**
* 適切なハードウェアツールを使用して、他の手段が失敗した場合に、ストレージチップを**取り外して読み取る**

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

もしそれらのツールであまり情報が見つからない場合は、`binwalk -E <bin>`で画像の**エントロピー**をチェックしてください。エントロピーが低い場合、暗号化されていない可能性が高いです。エントロピーが高い場合、暗号化されている可能性が高いです（または何らかの方法で圧縮されています）。

さらに、これらのツールを使用してファームウェアに埋め込まれた**ファイルを抽出**することができます：

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

または[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) を使用してファイルを検査できます。

### ファイルシステムの取得

以前にコメントアウトされた`binwalk -ev <bin>`のようなツールを使用すると、**ファイルシステムを抽出**できるはずです。\
通常、Binwalkは**ファイルシステムの種類と同じ名前のフォルダ**内に抽出します。ファイルシステムの種類は通常、次のいずれかです：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手動ファイルシステムの抽出

時々、binwalkには**シグネチャにファイルシステムのマジックバイトが含まれていない**ことがあります。そのような場合は、binwalkを使用して**ファイルシステムのオフセットを見つけ、バイナリから圧縮されたファイルシステムを切り出し**、以下の手順に従ってファイルシステムを**手動で抽出**してください。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

以下の**ddコマンド**を実行して、Squashfsファイルシステムを彫刻してください。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

## ファームウェアの解析

ファームウェアを取得したら、その構造と潜在的な脆弱性を理解するために解析することが不可欠です。このプロセスには、ファームウェアイメージから価値あるデータを抽出し、分析するためのさまざまなツールを利用します。

### 初期解析ツール

バイナリファイル（`<bin>`と呼ばれる）の初期検査のために、以下のコマンドセットが提供されています。これらのコマンドは、ファイルタイプの識別、文字列の抽出、バイナリデータの解析、およびパーティションやファイルシステムの詳細の理解に役立ちます。

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

画像の暗号化状態を評価するために、**エントロピー**は`binwalk -E <bin>`でチェックされます。低いエントロピーは暗号化の不足を示し、高いエントロピーは暗号化または圧縮の可能性を示します。

**埋め込まれたファイル**を抽出するためには、**file-data-carving-recovery-tools**のドキュメントやファイル検査のための**binvis.io**などのツールやリソースが推奨されます。

### ファイルシステムの抽出

`binwalk -ev <bin>`を使用すると、通常ファイルシステムを抽出でき、ファイルシステムの種類（例：squashfs、ubifs）に基づいてディレクトリに抽出されます。ただし、**binwalk**がマジックバイトが不足しているためにファイルシステムの種類を認識できない場合は、手動で抽出する必要があります。これには、`binwalk`を使用してファイルシステムのオフセットを特定し、その後`dd`コマンドを使用してファイルシステムを切り出す作業が含まれます。

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

### ファイルシステムの解析

ファイルシステムを抽出した後、セキュリティの脆弱性を探す作業が始まります。セキュリティの脆弱性を見つけるために、不安定なネットワークデーモン、ハードコードされた資格情報、APIエンドポイント、更新サーバー機能、未コンパイルのコード、起動スクリプト、オフライン解析用のコンパイルされたバイナリに注意が払われます。

検査すべき**主要な場所**と**アイテム**には次のものがあります:

* ユーザーの資格情報のための**etc/shadow**と**etc/passwd**
* **etc/ssl**内のSSL証明書とキー
* 潜在的な脆弱性のための構成ファイルとスクリプトファイル
* 追加の解析のための埋め込みバイナリ
* 一般的なIoTデバイスのWebサーバーとバイナリ

ファイルシステム内の機密情報や脆弱性を明らかにするのに役立ついくつかのツールがあります:

* 機密情報の検索のための[**LinPEAS**](https://github.com/carlospolop/PEASS-ng)と[**Firmwalker**](https://github.com/craigz28/firmwalker)
* 包括的なファームウェア解析のための[**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core)
* 静的および動的解析のための[**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)、および[**EMBA**](https://github.com/e-m-b-a/emba)

### コンパイルされたバイナリのセキュリティチェック

ファイルシステム内で見つかったソースコードとコンパイルされたバイナリの両方は、脆弱性を検査する必要があります。Unixバイナリ用の**checksec.sh**やWindowsバイナリ用の**PESecurity**などのツールを使用して、悪用される可能性のある保護されていないバイナリを特定するのに役立ちます。

## ダイナミック解析のためのファームウェアのエミュレーション

ファームウェアをエミュレートするプロセスは、デバイスの動作または個々のプログラムの**ダイナミック解析**を可能にします。このアプローチはハードウェアやアーキテクチャの依存関係に関する課題に直面する可能性がありますが、ルートファイルシステムや特定のバイナリを、Raspberry Piなどのアーキテクチャとエンディアンが一致するデバイスや、事前に構築された仮想マシンに転送することで、さらなるテストを容易にすることができます。

### 個々のバイナリのエミュレーション

単一のプログラムを調査するために、プログラムのエンディアンとCPUアーキテクチャを特定することが重要です。

#### MIPSアーキテクチャの例

MIPSアーキテクチャのバイナリをエミュレートするには、次のコマンドを使用できます:

```bash
file ./squashfs-root/bin/busybox
```

そして、必要なエミュレーションツールをインストールします:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

### MIPSアーキテクチャのエミュレーション

MIPS（ビッグエンディアン）の場合、`qemu-mips`が使用され、リトルエンディアンバイナリの場合は`qemu-mipsel`が選択されます。

### ARMアーキテクチャのエミュレーション

ARMバイナリの場合、`qemu-arm`エミュレータが使用されます。

### フルシステムエミュレーション

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)などのツールは、フルファームウェアエ
