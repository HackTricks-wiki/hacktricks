# macOSのUniversalバイナリとMach-Oフォーマット

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[Telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する
- **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

## 基本情報

Mac OSのバイナリは通常、**universal binaries**としてコンパイルされます。**universal binary**は**同じファイル内で複数のアーキテクチャをサポート**できます。

これらのバイナリは、基本的に以下のような**Mach-O構造**に従います：

- ヘッダー
- ロードコマンド
- データ

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

## Fatヘッダー

次のコマンドでファイルを検索します：`mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* 後続する構造体の数 */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* CPU指定子（int） */
cpu_subtype_t	cpusubtype;	/* マシン指定子（int） */
uint32_t	offset;		/* このオブジェクトファイルへのファイルオフセット */
uint32_t	size;		/* このオブジェクトファイルのサイズ */
uint32_t	align;		/* 2の累乗としてのアライメント */
};
</code></pre>

ヘッダーには**マジック**バイトが続き、ファイルが含む**アーキテクチャ**の**数**（`nfat_arch`）と各アーキテクチャには`fat_arch`構造体があります。

次のコマンドで確認します：

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
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

または[Mach-O View](https://sourceforge.net/projects/machoview/)ツールを使用して：

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

通常、2つのアーキテクチャ向けにコンパイルされたuniversal binaryは、通常の1つのアーキテクチャ向けにコンパイルされたものの**サイズを倍に**します。

## **Mach-Oヘッダー**

ヘッダーには、ファイルを識別するためのマジックバイトや対象アーキテクチャに関する情報など、ファイルに関する基本情報が含まれています。次の場所にあります：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

* MH\_EXECUTE (0x2): 標準のMach-O実行可能ファイル
* MH\_DYLIB (0x6): Mach-Oダイナミックリンクライブラリ（.dylib）
* MH\_BUNDLE (0x8): Mach-Oバンドル（.bundle）
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
または、[Mach-O View](https://sourceforge.net/projects/machoview/) を使用する：

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O ロードコマンド**

**メモリ内のファイルのレイアウト** がここで指定され、**シンボルテーブルの位置**、実行開始時のメインスレッドのコンテキスト、および必要な **共有ライブラリ** が詳細に記載されています。メモリへのバイナリの読み込みプロセスに関する指示が **動的ローダー（dyld）** に提供されます。

これには、**`loader.h`** で定義された **load\_command** 構造が使用されます。
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
システムが異なる**50種類のロードコマンド**を異なる方法で処理しています。最も一般的なものは、`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`、および`LC_CODE_SIGNATURE`です。

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
基本的に、このタイプのロードコマンドは、バイナリが実行されるときに、**\_\_TEXT**（実行コード）および**\_\_DATA**（プロセス用のデータ）**セグメントをどのようにロードするか**を、データセクションで示されたオフセットに従って定義します。
{% endhint %}

これらのコマンドは、プロセスが実行されるときに、**仮想メモリ空間にマップされるセグメント**を**定義**します。

**\_\_TEXT**セグメント（プログラムの実行コードを保持する）や**\_\_DATA**セグメント（プロセスで使用されるデータを含む）など、**さまざまなタイプのセグメント**があります。これらの**セグメントは、Mach-Oファイルのデータセクションに配置**されています。

**各セグメント**は、さらに複数の**セクション**に**分割**できます。**ロードコマンド構造**には、それぞれのセグメント内の**これらのセクションに関する情報**が含まれています。

ヘッダー内にはまず、**セグメントヘッダー**があります：

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* for 64-bit architectures */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* includes sizeof section_64 structs */
char		segname[16];	/* segment name */
uint64_t	vmaddr;		/* memory address of this segment */
uint64_t	vmsize;		/* memory size of this segment */
uint64_t	fileoff;	/* file offset of this segment */
uint64_t	filesize;	/* amount to map from the file */
int32_t		maxprot;	/* maximum VM protection */
int32_t		initprot;	/* initial VM protection */
<strong>	uint32_t	nsects;		/* number of sections in segment */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

セグメントヘッダーの例：

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

このヘッダーは、**その後に表示されるセクションヘッダーの数を定義**しています。
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
例：**セクションヘッダー**の例：

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

もし**セクションオフセット**（0x37DC）に**アーキテクチャが始まるオフセット**（この場合`0x18000`）を**追加**すると、`0x37DC + 0x18000 = 0x1B7DC` になります。

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

また、**コマンドライン**から**ヘッダー情報**を取得することも可能です。
```bash
otool -lv /bin/ls
```
```markdown
このcmdによってロードされる一般的なセグメント：

* **`__PAGEZERO`:** カーネルに**アドレスゼロ**を**読み取り、書き込み、実行**できないように**マップ**するよう指示します。構造体内のmaxprotとminprot変数はゼロに設定され、このページには**読み取り書き込み実行権限がない**ことを示します。
* この割り当ては**NULLポインターのデリファレンス脆弱性を緩和**するために重要です。
* **`__TEXT`**: **読み取り**および**実行**権限（書き込みなし）を持つ**実行可能コード**を含みます。このセグメントの一般的なセクション：
* `__text`: コンパイルされたバイナリコード
* `__const`: 定数データ
* `__cstring`: 文字列定数
* `__stubs`および`__stubs_helper`: ダイナミックライブラリの読み込みプロセス中に関与します
* **`__DATA`**: **読み取り書き込み可能**なデータを含みます（実行不可）。
* `__data`: 初期化されたグローバル変数
* `__bss`: 初期化されていない静的変数
* `__objc_*`（\_\_objc\_classlist、\_\_objc\_protolistなど）：Objective-Cランタイムで使用される情報
* **`__LINKEDIT`**: リンカー（dyld）のための情報を含み、「シンボル、文字列、および再配置テーブルエントリ」などが含まれます。
* **`__OBJC`**: Objective-Cランタイムで使用される情報を含みます。ただし、この情報は\_\_DATAセグメント内のさまざまな\_\_objc\_\*セクションでも見つけることができます。

### **`LC_MAIN`**

**entryoff属性**にエントリーポイントを含みます。ロード時に、**dyld**は単純にこの値を（メモリ内の）**バイナリのベースに追加**し、その後この命令に**ジャンプ**してバイナリのコードの実行を開始します。

### **LC\_CODE\_SIGNATURE**

Macho-Oファイルの**コード署名に関する情報**を含みます。これには通常、ファイルの最後にある**署名ブロブを指す****オフセット**のみが含まれます。\
ただし、このセクションに関する情報は[**このブログ投稿**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)やこの[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)で見つけることができます。

### **LC\_LOAD\_DYLINKER**

プロセスのアドレス空間に共有ライブラリをマップする**動的リンカー実行ファイルへのパス**を含みます。**値は常に`/usr/lib/dyld`に設定**されます。macOSでは、dylibのマッピングは**カーネルモードではなくユーザーモード**で行われることに注意することが重要です。

### **`LC_LOAD_DYLIB`**

このロードコマンドは、**ローダー**（dyld）に**ライブラリをロードおよびリンクするよう指示する****動的ライブラリ**の依存関係を記述します。Mach-Oバイナリが必要とする各ライブラリにはLC\_LOAD\_DYLIBロードコマンドがあります。

* このロードコマンドは、実際の依存動的ライブラリを記述する**`dylib_command`**型の構造体（struct dylibを含む）です：
```
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
以下のコマンドでもこの情報を取得できます:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
いくつかの潜在的なマルウェア関連ライブラリは次のとおりです：

- **DiskArbitration**：USBドライブの監視
- **AVFoundation**：オーディオとビデオのキャプチャ
- **CoreWLAN**：Wifiスキャン

{% hint style="info" %}
Mach-Oバイナリには、**LC\_MAIN**で指定されたアドレスの**前に実行される**1つ以上の**コンストラクタ**が含まれる可能性があります。\
任意のコンストラクタのオフセットは、**\_\_DATA\_CONST**セグメントの**\_\_mod\_init\_func**セクションに保持されます。
{% endhint %}

## **Mach-Oデータ**

ファイルの中心には、ロードコマンド領域で定義された複数のセグメントで構成されるデータ領域があります。**各セグメントにはさまざまなデータセクションが収容されており**、各セクションには**コードまたはデータ**が含まれています。

{% hint style="success" %}
データは基本的に、ロードコマンド**LC\_SEGMENTS\_64**によって読み込まれる**すべての情報**を含む部分です。
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

これには次のものが含まれます：

- **関数テーブル**：プログラム関数に関する情報を保持します。
- **シンボルテーブル**：バイナリで使用される外部関数に関する情報を含みます。
- 内部関数、変数名なども含まれる可能性があります。

確認するには、[**Mach-O View**](https://sourceforge.net/projects/machoview/)ツールを使用できます：

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

または、CLIから：
```bash
size -m /bin/ls
```
<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする。**
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する。

</details>
