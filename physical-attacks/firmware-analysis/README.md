# ファームウェア解析

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## はじめに

ファームウェアは、デバイスのハードウェアコンポーネントを制御し、通信するためのソフトウェアの一種です。デバイスが実行する最初のコードです。通常、**オペレーティングシステムを起動**し、**様々なハードウェアコンポーネントと通信**することでプログラムのための非常に特定のランタイムサービスを提供します。ほとんどの電子デバイスにはファームウェアがあります。

デバイスはファームウェアを**不揮発性メモリ**に保存します。例えば、ROM、EPROM、フラッシュメモリなどです。

ファームウェアを**調査**し、それを**変更**しようとすることは重要です。なぜなら、このプロセス中に多くのセキュリティ問題を発見することができるからです。

## **情報収集と偵察**

この段階では、ターゲットに関する可能な限り多くの情報を収集し、その全体的な構成と基盤となる技術を理解します。以下を収集しようと試みます：

* サポートされるCPUアーキテクチャ
* オペレーティングシステムプラットフォーム
* ブートローダーの設定
* ハードウェアの回路図
* データシート
* コード行数（LoC）の見積もり
* ソースコードリポジトリの場所
* サードパーティコンポーネント
* オープンソースライセンス（例：GPL）
* 変更履歴
* FCC ID
* 設計とデータフロー図
* 脅威モデル
* 以前のペネトレーションテストレポート
* バグ追跡チケット（例：Jira、バグバウンティプラットフォームのBugCrowdやHackerOne）

可能であれば、オープンソースインテリジェンス（OSINT）ツールと技術を使用してデータを取得します。オープンソースソフトウェアが使用されている場合は、リポジトリをダウンロードし、コードベースに対して手動および自動の静的解析を実行します。時々、オープンソースソフトウェアプロジェクトは、[Coverity Scan](https://scan.coverity.com)や[Semmle’s LGTM](https://lgtm.com/#explore)などのベンダーが提供する無料の静的解析ツールを既に使用しており、スキャン結果を提供しています。

## ファームウェアの取得

ファームウェアをダウンロードする方法は異なり、難易度も異なります

* 開発チーム、メーカー/ベンダー、またはクライアントから**直接**
* メーカーが提供する手順に従って**ゼロからビルド**
* ベンダーの**サポートサイト**から
* Dropbox、Box、Googleドライブなどのファイル共有プラットフォームやバイナリファイル拡張子を対象とした**Googleドーク**クエリ
* フォーラム、ブログ、またはメーカーに問題を解決するために連絡したサイトでコメントする顧客がコンテンツをアップロードすることで、ファームウェアイメージに遭遇することがよくあります。zipやフラッシュドライブで提供されます。
* 例：`intitle:"Netgear" intext:"Firmware Download"`
* Amazon Web Services（AWS）S3バケットなどの露出したクラウドプロバイダーのストレージ場所からビルドをダウンロードする（ツール例：[https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner)）
* **アップデート中の**デバイス通信を**中間者攻撃**（MITM）
* **UART**、**JTAG**、**PICit**などを介して**ハードウェアから直接**抽出
* ハードウェアコンポーネント内の**シリアル通信**をスニッフして**アップデートサーバーのリクエスト**を探る
* モバイルまたは厚いアプリケーション内の**ハードコードされたエンドポイント**経由
* **ブートローダー**（例：U-boot）からフラッシュストレージまたは**ネットワーク**経由で**tftp**を使用してファームウェアを**ダンプ**
* オフライン分析とデータ抽出のために**フラッシュチップ**（例：SPI）またはMCUをボードから取り外す（最終手段）。
* フラッシュストレージおよび/またはMCU用のサポートされているチッププログラマが必要です。

## ファームウェアの分析

ファームウェアを**入手した**ので、それについての情報を抽出して、どのように扱うかを知る必要があります。それに使用できる異なるツール：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
以下のツールであまり情報が見つからない場合は、`binwalk -E <bin>`でイメージの**エントロピー**をチェックしてください。エントロピーが低ければ、暗号化されている可能性は低いです。エントロピーが高ければ、暗号化されている可能性が高いです（または何らかの方法で圧縮されています）。

さらに、これらのツールを使用して**ファームウェア内に埋め込まれたファイル**を抽出することができます：

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

または、ファイルを検査するために[**binvis.io**](https://binvis.io/#/)（[コード](https://code.google.com/archive/p/binvis/)）を使用できます。

### ファイルシステムの取得

先にコメントされたツール`binwalk -ev <bin>`を使用して、**ファイルシステムを抽出**できるはずです。\
Binwalkは通常、squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfsなど、**ファイルシステムのタイプと同じ名前のフォルダ**内に抽出します。

#### 手動でのファイルシステム抽出

時には、binwalkがそのシグネチャにファイルシステムの**マジックバイトを持っていない**ことがあります。そのような場合は、binwalkを使用してファイルシステムのオフセットを見つけ、バイナリから圧縮されたファイルシステムを**カービング**し、以下の手順に従ってファイルシステムのタイプに応じて**手動で抽出**します。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
以下の**ddコマンド**を実行して、Squashfsファイルシステムを切り出します。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
以下のコマンドも実行可能です。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* squashfsの場合（上記の例で使用）

`$ unsquashfs dir.squashfs`

その後、ファイルは"`squashfs-root`"ディレクトリにあります。

* CPIOアーカイブファイル

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* jffs2ファイルシステムの場合

`$ jefferson rootfsfile.jffs2`

* NANDフラッシュを使用するubifsファイルシステムの場合

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### ファイルシステムの分析

ファイルシステムを取得したら、以下のような悪い実践を探し始める時です：

* 古い**セキュリティが不十分なネットワークデーモン**（例えばtelnetd。時には製造業者がバイナリを変更して偽装することがあります）
* **ハードコードされた認証情報**（ユーザー名、パスワード、APIキー、SSHキー、バックドアのバリエーション）
* **ハードコードされたAPI**エンドポイントとバックエンドサーバーの詳細
* 攻撃の入り口として使用される可能性のある**アップデートサーバー機能**
* リモートコード実行のための**未コンパイルのコードとスタートアップスクリプトのレビュー**
* 今後のステップでディスアセンブラを使用してオフライン分析のために**コンパイルされたバイナリを抽出**

ファームウェア内で探すべき**興味深いもの**：

* etc/shadow と etc/passwd
* etc/sslディレクトリのリストアップ
* .pem、.crtなどのSSL関連ファイルの検索
* 設定ファイルの検索
* スクリプトファイルの検索
* 他の.binファイルの検索
* admin、password、remote、AWSキーなどのキーワードの検索
* IoTデバイスで使用される一般的なウェブサーバーの検索
* ssh、tftp、dropbearなどの一般的なバイナリの検索
* 禁止されたC関数の検索
* コマンドインジェクションに弱い関数の検索
* URL、メールアドレス、IPアドレスの検索
* その他…

この種の情報を検索するツール（ファイルシステムの構造に慣れ、手動でチェックすることが常に重要ですが、ツールは**隠されたもの**を見つけるのに役立ちます）：

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** ファイルシステム内の**機密情報**を検索するのに役立つ素晴らしいbashスクリプト。ファームウェアのファイルシステム内で**chrootして実行します**。
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** 潜在的に機密情報を検索するためのBashスクリプト
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core):
* オペレーティングシステム、CPUアーキテクチャ、およびそれらの関連するバージョン情報などのソフトウェアコンポーネントの識別
* イメージからのファームウェアファイルシステムの抽出
* 証明書とプライベートキーの検出
* Common Weakness Enumeration (CWE)にマッピングする弱い実装の検出
* 脆弱性のフィード＆シグネチャベースの検出
* 基本的な静的な行動分析
* ファームウェアバージョンとファイルの比較（diff）
* QEMUを使用したファイルシステムバイナリのユーザーモードエミュレーション
* NX、DEP、ASLR、スタックカナリー、RELRO、FORTIFY_SOURCEなどのバイナリ軽減の検出
* REST API
* その他...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer): FwAnalyzerは、設定可能なルールを使用して(ext2/3/4)、FAT/VFat、SquashFS、UBIFSファイルシステムイメージ、cpioアーカイブ、およびディレクトリコンテンツを分析するツールです。
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep): 無料のソフトウェアIoTファームウェアセキュリティ分析ツール
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go): これは、元のByteSweepプロジェクトをGoで完全に書き直したものです。
* [**EMBA**](https://github.com/e-m-b-a/emba): _EMBA_は、ペネトレーションテスターのための中心的なファームウェア分析ツールとして設計されています。_ファームウェア抽出_プロセスから始まり、_静的分析_およびエミュレーションを介した_動的分析_を行い、最終的にレポートを生成します。_EMBA_は自動的にファームウェアの潜在的な弱点や脆弱性を発見します。例えば、セキュリティが不十分なバイナリ、古くて時代遅れのソフトウェアコンポーネント、潜在的に脆弱なスクリプト、ハードコードされたパスワードなどです。

{% hint style="warning" %}
ファイルシステム内には、常に**チェック**すべきプログラムの**ソースコード**も見つかりますが、**コンパイルされたバイナリ**もあります。これらのプログラムは何らかの形で露出している可能性があり、潜在的な脆弱性をチェックするために**デコンパイル**して**チェック**する必要があります。

[**checksec.sh**](https://github.com/slimm609/checksec.sh)のようなツールは、保護されていないバイナリを見つけるのに役立ちます。Windowsバイナリの場合は、[**PESecurity**](https://github.com/NetSPI/PESecurity)を使用できます。
{% endhint %}

## ファームウェアのエミュレーション

ファームウェアをエミュレートするアイデアは、デバイス**実行中**または**単一プログラム**の**動的分析**を実行できるようにすることです。

{% hint style="info" %}
時には、ハードウェアやアーキテクチャの依存関係のために、部分的または完全なエミュレーションが**機能しないことがあります**。アーキテクチャとエンディアンがラズベリーパイなどの所有デバイスと一致する場合、ルートファイルシステムまたは特定のバイナリをデバイスに転送してさらにテストを行うことができます。この方法は、ターゲットと同じアーキテクチャとエンディアンを使用する事前に構築された仮想マシンにも適用されます。
{% endhint %}

### バイナリエミュレーション

脆弱性を探すために単一のプログラムをエミュレートしたい場合、まずそのエンディアンとコンパイルされたCPUアーキテクチャを特定する必要があります。

#### MIPSの例
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
Now you can **QEMU** を使用して busybox 実行ファイルを**エミュレート**することができます。
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
実行ファイルが**MIPS**用にコンパイルされており、**big-endian**バイト順を採用しているため、QEMUの**`qemu-mips`**エミュレータを使用します。**little-endian**実行ファイルをエミュレートする場合は、`el`サフィックスが付いたエミュレータ(`qemu-mipsel`)を選択する必要があります：
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### ARMの例
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

以下のツールは、一般的に**qemu**に基づいており、完全なファームウェアをエミュレートすることができます：

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**:**
* 複数のインストールが必要で、postgresを設定した後、extractor.pyスクリプトを実行してファームウェアを抽出し、getArch.shスクリプトを使用してアーキテクチャを取得します。次に、tar2db.pyとmakeImage.shスクリプトを使用して、抽出されたイメージからデータベースに情報を格納し、エミュレートできるQEMUイメージを生成します。その後、inferNetwork.shスクリプトを使用してネットワークインターフェースを取得し、最後に./scratch/1/folderに自動的に作成されるrun.shスクリプトを使用します。
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**:**
* このツールはfirmadyneに依存しており、firmadyneeを使用してファームウェアのエミュレーションプロセスを自動化します。使用する前に`fat.config`を設定する必要があります：`sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **動的分析**

この段階では、攻撃するファームウェアを実行しているデバイスか、エミュレートされているファームウェアがあるべきです。いずれの場合も、**OSとファイルシステムにシェルがあることが強く推奨されます**。

エミュレーション内での**一部の活動が失敗する**ことがあり、エミュレーションを再起動する必要があるかもしれません。例えば、ウェブアプリケーションがオリジナルのデバイスと統合されているデバイスから情報を取得する必要があるが、エミュレーションではそれをエミュレートしていない場合です。

**ファイルシステムを再確認する**べきです。**以前のステップで行ったように、実行環境では新しい情報がアクセス可能になるかもしれません。**

**ウェブページ**が公開されている場合、コードを読んでアクセスできるようになったら、**テストする**べきです。HackTricksでは、さまざまなウェブハッキング技術に関する多くの情報を見つけることができます。

**ネットワークサービス**が公開されている場合、攻撃を試みるべきです。HackTricksでは、さまざまなネットワークサービスのハッキング技術に関する多くの情報を見つけることができます。また、[Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer)、[boofuzz](https://github.com/jtpereyda/boofuzz)、[kitty](https://github.com/cisco-sas/kitty)などのネットワークおよびプロトコル**ファジャー**を使用してファズテストを試みることもできます。

**ブートローダーを攻撃**してrootシェルを取得できるかどうかを確認するべきです：

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

デバイスが**ファームウェアの整合性テスト**を行っているかどうかをテストするべきです。そうでない場合、攻撃者はバックドア付きのファームウェアを提供し、他人が所有するデバイスにインストールしたり、ファームウェアのアップデートの脆弱性がある場合はリモートで展開することができます：

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

ファームウェアのアップデートの脆弱性は通常、**ファームウェア**の**整合性**が**検証されていない**、**暗号化されていない** **ネットワーク**プロトコルを使用している、**ハードコードされた** **クレデンシャル**の使用、ファームウェアをホストするクラウドコンポーネントへの**不安全な認証**、過度で不安全な**ログ記録**（機密データ）、検証なしに**物理的なアップデート**を許可することなどが原因で発生します。

## **ランタイム分析**

ランタイム分析には、デバイスが通常の環境またはエミュレートされた環境で実行中のときに、実行中のプロセスまたはバイナリにアタッチすることが含まれます。基本的なランタイム分析手順は以下の通りです：

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. gdb-multiarchにアタッチするか、IDAを使用してバイナリをエミュレートする
3. memcpy、strncpy、strcmpなど、ステップ4で特定された関数にブレークポイントを設定する
4. ファジャーを使用してオーバーフローやプロセスクラッシュを特定するために大きなペイロード文字列を実行する
5. 脆弱性が特定された場合はステップ8に進む

役立つツールは以下の通りです（網羅的ではありません）：

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **バイナリエクスプロイト**

前のステップでバイナリ内の脆弱性を特定した後、実際の影響とリスクを示すために適切な実証コンセプト（PoC）が必要です。エクスプロイトコードの開発には、低レベル言語（例：ASM、C/C++、シェルコードなど）でのプログラミング経験と、特定のターゲットアーキテクチャ（例：MIPS、ARM、x86など）に関する知識が必要です。PoCコードには、メモリ内の命令を制御することでデバイスやアプリケーション上で任意の実行を得ることが含まれます。

組み込みシステム内でバイナリランタイム保護（例：NX、DEP、ASLRなど）が存在することは一般的ではありませんが、発生した場合、リターン指向プログラミング（ROP）などの追加技術が必要になることがあります。ROPを使用すると、攻撃者はターゲットプロセス/バイナリのコード内に既存のコードをチェーンして、ガジェットとして知られる任意の悪意のある機能を実装することができます。バッファオーバーフローなどの特定された脆弱性を利用するためにROPチェーンを形成する手順が必要になります。このような状況に役立つツールは、CapstoneのガジェットファインダーやROPGadget- [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget)です。

さらなるガイダンスには以下の参考文献を利用してください：

* [https://azeria-labs.com/writing-arm-shellcode/](https://azeria-labs.com/writing-arm-shellcode/)
* [https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)

## ファームウェア分析用に準備されたOS

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOSは、IoTデバイスのセキュリティ評価とペネトレーションテストを行うために設計されたディストリビューションです。必要なツールがすべてロードされた事前設定された環境を提供することで、多くの時間を節約できます。
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04に基づいた組み込みセキュリティテスト用オペレーティングシステムで、ファームウェアセキュリティテストツールがプリロードされています。

## 練習用の脆弱なファームウェア

ファームウェアの脆弱性を発見する練習をするために、以下の脆弱なファームウェアプロジェクトを出発点として使用してください。

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

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>
