# macOS ユニバーサルバイナリ & Mach-O フォーマット

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または **HackTricksをPDFでダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や [**テレグラムグループ**](https://t.me/peass)に**参加する**、または **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

Mac OSのバイナリは通常、**ユニバーサルバイナリ**としてコンパイルされます。**ユニバーサルバイナリ**は、同じファイルで**複数のアーキテクチャをサポート**できます。

これらのバイナリは、基本的に以下の構成要素からなる**Mach-O構造**に従います：

* ヘッダー
* ロードコマンド
* データ

![](<../../../.gitbook/assets/image (559).png>)

## Fat ヘッダー

ファイルを検索するには：`mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC または FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* 続く構造体の数 */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* CPUの指定子 (int) */
cpu_subtype_t	cpusubtype;	/* マシンの指定子 (int) */
uint32_t	offset;		/* このオブジェクトファイルへのファイルオフセット */
uint32_t	size;		/* このオブジェクトファイルのサイズ */
uint32_t	align;		/* 2のべき乗としてのアライメント */
};
</code></pre>

ヘッダーには**マジックバイト**が続き、ファイルが**含むアーキテクチャの数**(`nfat_arch`)があり、各アーキテクチャには`fat_arch`構造体があります。

以下で確認できます：

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O ユニバーサルバイナリで、2つのアーキテクチャがあります: [x86_64:Mach-O 64ビット実行可能ファイル x86_64] [arm64e:Mach-O 64ビット実行可能ファイル arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64ビット実行可能ファイル x86_64
/bin/ls (for architecture arm64e):	Mach-O 64ビット実行可能ファイル arm64e

% otool -f -v /bin/ls
Fat ヘッダー
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

または [Mach-O View](https://sourceforge.net/projects/machoview/) ツールを使用して：

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

お考えの通り、通常、2つのアーキテクチャ用にコンパイルされたユニバーサルバイナリは、1つのアーキテクチャ用にコンパイルされたものの**サイズが2倍**になります。

## **Mach-O ヘッダー**

ヘッダーには、ファイルをMach-Oファイルとして識別するためのマジックバイトや、ターゲットアーキテクチャに関する情報など、ファイルに関する基本情報が含まれています。ここで見つけることができます：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
**ファイルタイプ**:

* MH\_EXECUTE (0x2): 標準のMach-O実行ファイル
* MH\_DYLIB (0x6): Mach-O動的リンクライブラリ（例：.dylib）
* MH\_BUNDLE (0x8): Mach-Oバンドル（例：.bundle）
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
または、[Mach-O View](https://sourceforge.net/projects/machoview/)を使用してください：

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O ロードコマンド**

これは**メモリ内のファイルのレイアウト**を指定します。**シンボルテーブルの位置**、実行開始時のメインスレッドコンテキスト、必要な**共有ライブラリ**が含まれています。
コマンドは基本的に動的ローダー**（dyld）にバイナリをメモリにロードする方法を指示します。**

ロードコマンドはすべて、前述の**`loader.h`**で定義されている**load\_command**構造体から始まります：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
システムが異なって扱う**約50種類のロードコマンド**があります。最も一般的なものには、`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`、および`LC_CODE_SIGNATURE`があります。

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
基本的に、このタイプのロードコマンドは、バイナリが実行されたときに**データセクションに示されたオフセットに従って、\_\_TEXT**（実行可能コード）**および\_\_DATA**（プロセスのデータ）**セグメントをロードする方法を定義します**。
{% endhint %}

これらのコマンドは、実行されるプロセスの**仮想メモリ空間**に**マップされるセグメントを定義します**。

**\_\_TEXT** セグメント（プログラムの実行可能コードを保持する）や **\_\_DATA** セグメント（プロセスが使用するデータを含む）など、**異なるタイプのセグメント**があります。これらの**セグメントはMach-Oファイルのデータセクションに位置しています**。

**各セグメント**は、複数の**セクション**にさらに**分割**されることがあります。**ロードコマンド構造**には、それぞれのセグメント内の**これらのセクションに関する情報**が含まれています。

ヘッダーの最初には**セグメントヘッダー**があります：

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* 64ビットアーキテクチャ用 */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* section_64構造体のサイズを含む */
char		segname[16];	/* セグメント名 */
uint64_t	vmaddr;		/* このセグメントのメモリアドレス */
uint64_t	vmsize;		/* このセグメントのメモリサイズ */
uint64_t	fileoff;	/* このセグメントのファイルオフセット */
uint64_t	filesize;	/* ファイルからマップする量 */
int32_t		maxprot;	/* 最大VM保護 */
int32_t		initprot;	/* 初期VM保護 */
<strong>	uint32_t	nsects;		/* セグメント内のセクション数 */
</strong>	uint32_t	flags;		/* フラグ */
};
</code></pre>

セグメントヘッダーの例：

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

このヘッダーは、その後に表示される**セクションの数を定義します**：
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
**セクションヘッダー**の例：

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

もし**セクションオフセット**（0x37DC）に、この場合は`0x18000`で始まる**アーキテクチャの開始地点**の**オフセット**を**加える**と、`0x37DC + 0x18000 = 0x1B7DC`になります。

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

また、**コマンドライン**から**ヘッダー情報**を取得することも可能です：
```bash
otool -lv /bin/ls
```
このcmdによってロードされる一般的なセグメント:

* **`__PAGEZERO`:** カーネルに**アドレスゼロ**を**マップ**するよう指示し、そこからは**読み取り、書き込み、実行ができない**ようにします。構造体内のmaxprotおよびminprot変数は、このページに**読み書き実行権限がない**ことを示すためにゼロに設定されています。
* この割り当ては、**NULLポインタ参照の脆弱性を軽減する**ために重要です。
* **`__TEXT`**: **実行可能な** **コード**を含み、**読み取り**と**実行**の権限があります（書き込み不可）。このセグメントの一般的なセクション:
* `__text`: コンパイルされたバイナリコード
* `__const`: 定数データ
* `__cstring`: 文字列定数
* `__stubs` と `__stubs_helper`: 動的ライブラリのロードプロセスに関与
* **`__DATA`**: **読み取り可能**かつ**書き込み可能**なデータを含みます（実行不可）。
* `__data`: 初期化されたグローバル変数
* `__bss`: 初期化されていない静的変数
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, など): Objective-Cランタイムによって使用される情報
* **`__LINKEDIT`**: リンカー(dyld)によって使用される情報、例えば "シンボル、文字列、および再配置テーブルエントリ" を含みます。
* **`__OBJC`**: Objective-Cランタイムによって使用される情報を含みます。この情報は\_\_DATAセグメント内の\_\_objc\_\*セクションにも見られることがあります。

### **`LC_MAIN`**

**entryoff属性**にエントリポイントを含みます。ロード時に、**dyld**はこの値をバイナリの（メモリ内の）**ベースに単純に加算**し、バイナリのコードの実行を開始するためにこの命令に**ジャンプ**します。

### **LC\_CODE\_SIGNATURE**

Mach-Oファイルの**コード署名**に関する情報を含みます。これには、**署名ブロブ**を**指し示す** **オフセット**のみが含まれています。これは通常、ファイルの最後にあります。
しかし、このセクションに関する情報は[**このブログ投稿**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)とこの[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)で見つけることができます。

### **LC\_LOAD\_DYLINKER**

プロセスのアドレス空間に共有ライブラリをマップする動的リンカー実行可能ファイルへの**パス**を含みます。**値は常に`/usr/lib/dyld`に設定されています**。macOSでは、dylibのマッピングは**カーネルモードではなくユーザーモード**で行われることに注意が必要です。

### **`LC_LOAD_DYLIB`**

このロードコマンドは、**動的** **ライブラリ**の依存関係を記述し、ローダー(dyld)にそのライブラリを**ロードしてリンクする**よう**指示**します。Mach-Oバイナリが必要とするライブラリごとにLC\_LOAD\_DYLIBロードコマンドがあります。

* このロードコマンドは、実際の依存する動的ライブラリを記述する構造体dylibを含む**`dylib_command`**型の構造体です。
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
```plaintext
cliでこの情報を取得することもできます:
```
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
潜在的なマルウェア関連ライブラリには以下があります：

* **DiskArbitration**：USBドライブの監視
* **AVFoundation**：オーディオとビデオのキャプチャ
* **CoreWLAN**：Wifiスキャン。

{% hint style="info" %}
Mach-Oバイナリには、**LC\_MAIN**で指定されたアドレスの**前に** **実行される**1つまたは**複数の** **コンストラクタ**を含むことができます。
コンストラクタのオフセットは、**\_\_DATA\_CONST**セグメントの**\_\_mod\_init\_func**セクションに保持されています。
{% endhint %}

## **Mach-Oデータ**

ファイルの核心は、最終領域であるデータで、ロードコマンド領域にレイアウトされたいくつかのセグメントで構成されています。**各セグメントには複数のデータセクションが含まれる可能性があります**。これらのセクションはそれぞれ、特定のタイプの**コードまたはデータを含んでいます**。

{% hint style="success" %}
データは基本的に、ロードコマンド**LC\_SEGMENTS\_64**によってロードされるすべての**情報**を含む部分です。
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

これには以下が含まれます：

* **関数テーブル**：プログラム関数に関する情報を保持しています。
* **シンボルテーブル**：バイナリによって使用される外部関数に関する情報を含んでいます。
* 内部関数や変数名なども含まれる可能性があります。

これを確認するには、[**Mach-O View**](https://sourceforge.net/projects/machoview/)ツールを使用できます：

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

またはCLIから：
```bash
size -m /bin/ls
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
