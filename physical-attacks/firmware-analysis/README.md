# ファームウェア分析

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## はじめに

ファームウェアは、デバイスのハードウェアコンポーネントに対する通信と制御を提供するソフトウェアの一種です。デバイスが実行する最初のコードです。通常、**オペレーティングシステムを起動**し、**さまざまなハードウェアコンポーネントとの通信**によってプログラムのための非常に特定のランタイムサービスを提供します。ほとんどの電子デバイスにはファームウェアがあります。

デバイスは、ROM、EPROM、またはフラッシュメモリなどの**不揮発性メモリ**にファームウェアを格納します。

セキュリティの問題を多く発見できるため、ファームウェアを**調査**し、それを**変更**しようとすることが重要です。

## **情報収集と偵察**

この段階では、ターゲットに関するできるだけ多くの情報を収集し、その全体的な構成と基礎となる技術を理解するために必要な情報を収集しようとします。次の情報を収集しようとしてください。

* サポートされているCPUアーキテクチャ
* オペレーティングシステムプラットフォーム
* ブートローダの設定
* ハードウェアの回路図
* データシート
* コード行数（LoC）の推定
* ソースコードリポジトリの場所
* サードパーティのコンポーネント
* オープンソースライセンス（例：GPL）
* 変更履歴
* FCC ID
* 設計およびデータフローダイアグラム
* 脅威モデル
* 以前の侵入テストレポート
* バグトラッキングチケット（例：Jira、BugCrowd、HackerOneなどのバグバウンティプラットフォーム）

可能な限り、オープンソースインテリジェンス（OSINT）ツールと技術を使用してデータを取得します。オープンソースソフトウェアが使用されている場合は、リポジトリをダウンロードし、コードベースに対して手動および自動の静的解析を実行します。オープンソースソフトウェアプロジェクトでは、ベンダーが提供する無料の静的解析ツール（[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)など）を既に使用している場合があります。

## ファームウェアの取得

ファームウェアをダウンロードするためには、異なる難易度の方法があります。

* 開発チーム、メーカー/ベンダー、またはクライアントから**直接**ダウンロードする
* メーカーが提供する手順に従って**ゼロからビルド**する
* ベンダーのサポートサイトから**ダウンロード**する
* バイナリファイルの拡張子やDropbox、Box、Googleドライブなどのファイル共有プラットフォームに対して**Googleドーク**クエリを使用する
* フォーラムやブログにコンテンツをアップロードする顧客からファームウェアイメージに出くわすことがよくあります。また、問題のトラブルシューティングのためにメーカーに問い合わせ、zipファイルやフラッシュドライブを送ってもらったことがある場合もあります。
* 例：`intitle:"Netgear" intext:"Firmware Download"`
* [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner)などのツールを使用して、Amazon Web Services（AWS）のS3バケットなどの公開されたクラウドプロバイダのストレージ場所からビルドをダウンロードする
* **アップデート**時のデバイス間通信の**中間者攻撃**（MITM）
* **UART**、**JTAG**、**PICit**などを介してハードウェアから直接抽出する
* アップデートサーバリクエストのためのハードウェアコンポーネント内の**シリアル通信**をスニフィングする
* モバイルアプリケーションや厚いアプリケーション内の**ハードコードされたエンドポイント**を介して
* ブートローダ（例：U-boot）からフラッシュストレージまたは**tftp**を介してネットワーク経由でファームウェアを**ダンプ**する
* オフライン分析とデータ抽出のために、ボードから**フラッシュチップ**（例：SPI）またはMCUを取り外す（最終手段）。
* フラッシュストレージと/またはMCUのサポートされているチッププログラマが必要です。

## ファームウェアの分析

これで、**ファームウェアを取得**したので、それに関する情報を抽出して、どのように扱うかを知る必要があります。そのために使用できるさまざまなツール:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
もしもそれらのツールであまり情報を見つけられない場合は、`binwalk -E <bin>`コマンドで画像の**エントロピー**をチェックしてください。エントロピーが低い場合、暗号化されていない可能性が高いです。エントロピーが高い場合、暗号化されている可能性があります（または何らかの方法で圧縮されています）。

さらに、次のツールを使用して**ファームウェアに埋め込まれたファイル**を抽出することができます：

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

または、[**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))を使用してファイルを検査することができます。

### ファイルシステムの取得

以前にコメントされた`binwalk -ev <bin>`のようなツールを使用すると、**ファイルシステムを抽出**することができます。\
通常、Binwalkは**ファイルシステムの種類と同じ名前のフォルダ**に抽出します。ファイルシステムの種類は通常、以下のいずれかです：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手動でのファイルシステムの抽出

場合によっては、binwalkには**ファイルシステムのマジックバイトがシグネチャに含まれていない**ことがあります。この場合、binwalkを使用して**ファイルシステムのオフセットを見つけ、バイナリから圧縮されたファイルシステムを切り出し**、以下の手順に従ってファイルシステムを手動で抽出してください。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
次の**ddコマンド**を実行して、Squashfsファイルシステムを切り出します。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, you can run the following command.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in the "`squashfs-root`" directory afterwards.

* CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

* For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### ファイルシステムの分析

ファイルシステムを取得したら、以下のような悪いプラクティスを探すことができます。

* telnetdなどの**セキュリティの脆弱性のあるネットワークデーモン**（メーカーがバイナリの名前を変更して隠すこともあります）
* **ハードコードされた認証情報**（ユーザー名、パスワード、APIキー、SSHキー、バックドアのバリエーションなど）
* **ハードコードされたAPI**エンドポイントとバックエンドサーバーの詳細
* エントリーポイントとして使用できる**アップデートサーバーの機能**
* リモートコード実行のための**コンパイルされていないコードと起動スクリプトの確認**
* **オフライン分析**のためにコンパイルされたバイナリの抽出

ファームウェア内で探すべき興味深いもの：

* etc/shadowとetc/passwd
* etc/sslディレクトリの一覧
* .pem、.crtなどのSSL関連ファイルの検索
* 設定ファイルの検索
* スクリプトファイルの検索
* 他の.binファイルの検索
* admin、password、remote、AWSキーなどのキーワードの検索
* IoTデバイスで使用される一般的なWebサーバーの検索
* ssh、tftp、dropbearなどの一般的なバイナリの検索
* 禁止されたC関数の検索
* 一般的なコマンドインジェクションの脆弱な関数の検索
* URL、メールアドレス、IPアドレスの検索
* その他...

この種の情報を検索するツール（常に手動でファイルシステムの構造を確認し、ツールを使用して**隠されたもの**を見つけることができます）：

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** ファイルシステム内の**機密情報**を検索するために便利な素晴らしいbashスクリプトです。ファームウェアファイルシステムに**chroot**して実行します。
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** 潜在的な機密情報を検索するためのbashスクリプト
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core):
* オペレーティングシステム、CPUアーキテクチャ、サードパーティのコンポーネントなどのソフトウェアコンポーネントの識別と関連するバージョン情報
* イメージからのファームウェアファイルシステム（s）の抽出
* 証明書と秘密鍵の検出
* Common Weakness Enumeration（CWE）にマッピングされる弱い実装の検出
* 脆弱性のフィードと署名に基づく検出
* 基本的な静的行動分析
* ファームウェアバージョンとファイルの比較（diff）
* QEMUを使用したファイルシステムバイナリのユーザーモードエミュレーション
* NX、DEP、ASLR、スタックキャナリー、RELRO、FORTIFY\_SOURCEなどのバイナリの防御機能の検出
* REST API
* その他...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer): FwAnalyzerは、設定可能なルールセットを使用して、（ext2/3/4）、FAT/VFat、SquashFS、UBIFSファイルシステムイメージ、cpioアーカイブ、およびディレクトリコンテンツを分析するツールです。
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep): 無料のIoTファームウェアセキュリティ分析ツール
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go): これは、元のByteSweepプロジェクトをGoで完全に書き直したものです。
* [**EMBA**](https://github.com/e-m-b-a/emba): _EMBA_は、ペネトレーションテスター向けの中央ファームウェア分析ツールとして設計されています。_EMBA_は、ファームウェアの抽出プロセスから始まり、静的分析、エミュレーションを介した動的分析、最終的にはレポートの生成まで、セキュリティ分析プロセス全体をサポートします。_EMBA_は、ファームウェア内の可能な脆弱性や弱点を自動的に検出します。例としては、セキュリティの脆弱性のあるバイナリ、古くて非推奨のソフトウェアコンポーネント、潜在的に脆弱なスクリプトやハードコードされたパスワードなどがあります。

{% hint style="warning" %}
ファイルシステム内にはプログラムの**ソースコード**（常に**確認**する必要があります）だけでなく、**コンパイルされたバイナリ**も含まれている場合があります。これらのプログラムは何らかの形で公開されている可能性があり、潜在的な脆弱性を**逆コンパイル**して**確認**する必要があります。

[**checksec.sh**](https://github.com/slimm609/checksec.sh)のようなツールは、保護されていないバイナリを見つけるのに役立ちます。Windowsバイナリの場合は、[**PESecurity**](https://github.com/NetSPI/PESecurity)を使用できます。
{% endhint %}

## ファームウェアのエミュレーション

ファームウェアをエミュレートすることで、デバイスの**実行中**または**単一のプログラム**の**動的分析**を実行できます。

{% hint style="info" %}
ハードウェアやアーキテクチャの依存関係により、一部または完全なエミュレーションが**動作しない場合**があります。アーキテクチャとエンディアンが一致する場合、ラズベリーパイなどの所有しているデバイスにファームウェアのルートファイルシステムまたは特定のバイナリを転送してさらなるテストを行うことができます。この方法は、ターゲットと同じアーキテクチャとエンディアンを使用する事前にビルドされた仮想マシンにも適用されます。
{% endhint %}

### バイナリのエミュレーション

脆弱性を検索するために単一のプログラムをエミュレートしたい場合は、まずそのエンディアンとコンパイルされたCPUアーキテクチャを特定する必要があります。

#### MIPSの例
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
今、**QEMU**を使用してbusybox実行ファイルを**エミュレート**することができます。
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
実行可能ファイルは**MIPS**向けにコンパイルされており、**ビッグエンディアン**のバイト順序に従っているため、**`qemu-mips`**エミュレータを使用します。**リトルエンディアン**の実行可能ファイルをエミュレートする場合は、`el`サフィックスを持つエミュレータを選択する必要があります（`qemu-mipsel`）。
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### ARMの例

```html
<details>
<summary>Click to expand!</summary>

##### Firmware Analysis

- **Firmware Extraction**: The first step in firmware analysis is to extract the firmware from the target device. This can be done by using tools like `binwalk`, `firmware-mod-kit`, or by directly accessing the device's memory.

- **Firmware Reverse Engineering**: Once the firmware is extracted, it can be reverse engineered to understand its inner workings. Tools like `IDA Pro`, `Ghidra`, or `Radare2` can be used for this purpose.

- **Firmware Vulnerability Analysis**: After reverse engineering, the firmware can be analyzed for vulnerabilities. This involves identifying potential security flaws, such as buffer overflows, format string vulnerabilities, or hardcoded credentials.

- **Firmware Patching**: If vulnerabilities are found, patches can be developed to fix them. These patches can be applied to the firmware to enhance its security.

- **Firmware Emulation**: Emulating the firmware can help in understanding its behavior without running it on the actual device. Tools like `QEMU` or `Unicorn` can be used for firmware emulation.

- **Firmware Debugging**: Debugging the firmware can provide insights into its execution flow and help in identifying vulnerabilities. Tools like `GDB` or `OllyDbg` can be used for firmware debugging.

- **Firmware Exploitation**: Exploiting vulnerabilities in the firmware can lead to unauthorized access or control over the target device. Techniques like stack smashing, return-oriented programming (ROP), or code injection can be used for firmware exploitation.

</details>
```

#### ARMの例

```html
<details>
<summary>クリックして展開する！</summary>

##### ファームウェア解析

- **ファームウェアの抽出**: ファームウェア解析の最初のステップは、対象デバイスからファームウェアを抽出することです。これは、`binwalk`、`firmware-mod-kit`などのツールを使用するか、デバイスのメモリに直接アクセスすることで行うことができます。

- **ファームウェアの逆アセンブリ**: ファームウェアが抽出されたら、その内部動作を理解するために逆アセンブリすることができます。この目的のために、`IDA Pro`、`Ghidra`、`Radare2`などのツールを使用することができます。

- **ファームウェアの脆弱性分析**: 逆アセンブリ後、ファームウェアは脆弱性の分析のために調査されます。これには、バッファオーバーフロー、フォーマット文字列の脆弱性、ハードコードされた認証情報などの潜在的なセキュリティ上の問題の特定が含まれます。

- **ファームウェアのパッチ適用**: 脆弱性が見つかった場合、それらを修正するためのパッチを開発することができます。これらのパッチは、ファームウェアに適用してセキュリティを強化することができます。

- **ファームウェアのエミュレーション**: ファームウェアのエミュレーションは、実際のデバイス上で実行せずにその動作を理解するのに役立ちます。`QEMU`や`Unicorn`などのツールを使用してファームウェアのエミュレーションを行うことができます。

- **ファームウェアのデバッグ**: ファームウェアのデバッグは、実行フローを分析し、脆弱性の特定に役立ちます。`GDB`や`OllyDbg`などのツールを使用してファームウェアのデバッグを行うことができます。

- **ファームウェアの攻撃**: ファームウェアの脆弱性を悪用することで、対象デバイスへの不正アクセスや制御を行うことができます。スタックスマッシング、リターンオリエンテッドプログラミング（ROP）、コードインジェクションなどの技術を使用してファームウェアの攻撃を行うことができます。

</details>
```
```bash
file bin/busybox
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```
エミュレーション：
```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```
### フルシステムエミュレーション

一部のツールは、一般的に**qemu**をベースにしており、完全なファームウェアをエミュレートすることができます。

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**:**
* ファームウェアを抽出するためにextractor.pyスクリプトを実行し、getArch.shスクリプトを使用してアーキテクチャを取得するために、いくつかのものをインストールし、postgresを設定する必要があります。次に、tar2db.pyおよびmakeImage.shスクリプトを使用して、抽出したイメージからの情報をデータベースに保存し、エミュレートできるQEMUイメージを生成します。次に、ネットワークインターフェースを取得するためにinferNetwork.shスクリプトを使用し、最後に./scratch/1/folderに自動的に作成されるrun.shスクリプトを使用します。
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**:**
* このツールはfirmadyneに依存しており、firmadyneを使用してファームウェアをエミュレートするプロセスを自動化します。使用する前に`fat.config`を設定する必要があります：`sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **動的解析**

この段階では、攻撃対象のファームウェアを実行しているデバイスまたはエミュレートされたファームウェアを攻撃するために、**実行中のOSとファイルシステムにシェルがあることが強く推奨されます**。

ファームウェアをエミュレートしている場合、**エミュレーション内の一部のアクティビティが失敗する**ことがあり、エミュレーションを再起動する必要があるかもしれません。たとえば、ウェブアプリケーションは、元のデバイスが統合されているデバイスから情報を取得する必要があるかもしれませんが、エミュレーションではそれをエミュレートしていません。

実行環境では、新しい情報にアクセスできる可能性があるため、**ファイルシステムを再確認する必要があります**。

**ウェブページ**が公開されている場合、コードを読み、アクセスできるようになったら、それらを**テスト**する必要があります。hacktricksでは、さまざまなウェブハッキングテクニックに関する多くの情報を見つけることができます。

**ネットワークサービス**が公開されている場合、それらを攻撃しようとする必要があります。hacktricksでは、さまざまなネットワークサービスのハッキングテクニックに関する多くの情報を見つけることができます。また、[Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer)、[boofuzz](https://github.com/jtpereyda/boofuzz)、および[kitty](https://github.com/cisco-sas/kitty)などのネットワークおよびプロトコルのファジングツールを使用して、それらをファズすることもできます。

ブートローダを攻撃してルートシェルを取得できるかどうかを確認する必要があります：

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

デバイスがいかなる種類の**ファームウェア整合性テスト**を行っているかをテストする必要があります。そうでない場合、攻撃者はバックドア付きのファームウェアを提供したり、他の人が所有するデバイスにそれをインストールしたり、ファームウェアの更新に脆弱性がある場合はリモートで展開したりすることができます：

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

ファームウェアの更新の脆弱性は、ファームウェアの**整合性**が**検証されない**、**暗号化されていない** **ネットワーク**プロトコルの使用、**ハードコードされた** **資格情報**の使用、クラウドコンポーネントへの**安全でない認証**、および過剰で安全でない**ロギング**（機密データ）などが原因です。また、検証なしで**物理的な更新**を許可します。

## **ランタイム解析**

ランタイム解析では、デバイスが通常の環境またはエミュレートされた環境で実行されている間に、実行中のプロセスまたはバイナリにアタッチします。基本的なランタイム解析の手順は以下の通りです：

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. gdb-multiarchをアタッチするか、IDAを使用してバイナリをエミュレートします
3. memcpy、strncpy、strcmpなどのステップ4で特定された関数にブレークポイントを設定します。
4. ファズツールを使用して、オーバーフローやプロセスのクラッシュを特定するために、大きなペイロード文字列を実行します。
5. 脆弱性が特定された場合は、ステップ8に進んでください。

役立つツール（非網羅的）は次のとおりです：

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **バイナリの攻撃**

前の手順でバイナリ内の脆弱性を特定した後、実世界の影響とリスクを示すために適切な概念実証（PoC）が必要です。エクスプロイトコードの開発には、低レベルの言語（ASM、C/C++、シェルコードなど）でのプログラミング経験と、特定のターゲットアーキテクチャ（MIPS、ARM、x86など）の背景が必要です。PoCコードは、メモリ内の命令を制御することによって、デバイスまたはアプリケーションで任意の実行を取得することを目的としています。

組み込みシステムでは、バイナリのランタイム保護（NX、DEP、ASLRなど）が一般的には行われないことが一般的ですが、これが発生する場合、ROP（Return Oriented Programming）などの追加のテクニックが必要になる場合があります。ROPは、既存のコードを連鎖させることによって、ターゲットプロセス/バイナリのコード内に任意の悪意のある機能を実装することを攻撃者に可能にします。バッファオーバーフローなどの特定された脆弱性を悪用するためには、ROPチェーンを形成するための手順を踏む必要があります。このような状況に役立つツールとしては、CapstoneのガジェットファインダーやROPGadget- [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget)があります。

詳しいガイダンスについては、以下の参考文献を利用してください：

* [https://azeria-labs.com/writing-arm-shellcode/](https://azeria-labs.com/writing-arm
## 脆弱なファームウェアの練習

ファームウェアの脆弱性を発見するための練習として、以下の脆弱なファームウェアプロジェクトを利用してください。

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## 参考文献

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## トレーニングと認定

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**または**[telegramグループ](https://t.me/peass)**に参加するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
