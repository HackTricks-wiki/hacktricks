# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Mac OS のバイナリは通常 **universal binaries** としてコンパイルされます。**universal binary** は同一ファイル内で複数のアーキテクチャを**サポートできます**。

これらのバイナリは **Mach-O structure** に従っており、基本的に以下で構成されています:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Search for the file with: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* number of structs that follow */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu specifier (int) */
cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
uint32_t	offset;		/* file offset to this object file */
uint32_t	size;		/* size of this object file */
uint32_t	align;		/* alignment as a power of 2 */
};
</code></pre>

ヘッダは **magic** バイトの後にファイルが含む **archs** の**数**（`nfat_arch`）が続き、各 arch は `fat_arch` 構造体を持ちます。

Check it with:

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

or using the [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

おそらく想像できるように、通常 2 つのアーキテクチャ向けにコンパイルされた universal binary は、1 つのアーキテクチャ向けにコンパイルされたものよりも **サイズが2倍** になります。

## **Mach-O Header**

ヘッダには、Mach-O ファイルであることを識別するための magic バイトや、ターゲットアーキテクチャに関する情報など、ファイルの基本情報が含まれます。場所は: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O File Types

さまざまなファイルタイプがあり、[**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) に定義されています。最も重要なものは:

- `MH_OBJECT`: 再配置可能なオブジェクトファイル（コンパイルの中間生成物で、まだ実行ファイルではありません）。
- `MH_EXECUTE`: 実行可能ファイル。
- `MH_FVMLIB`: 固定VMライブラリファイル。
- `MH_CORE`: コアダンプ。
- `MH_PRELOAD`: プリロードされた実行ファイル（XNUではもはやサポートされていません）。
- `MH_DYLIB`: 動的ライブラリ。
- `MH_DYLINKER`: 動的リンカ。
- `MH_BUNDLE`: 「プラグインファイル」。-bundle in gcc を使って生成され、`NSBundle` または `dlopen` により明示的にロードされます。
- `MH_DYSM`: 補助的な `.dSym` ファイル（デバッグ用のシンボルを含むファイル）。
- `MH_KEXT_BUNDLE`: カーネル拡張。
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
または [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O フラグ**

ソースコードは、ライブラリをロードする際に有用な複数のフラグも定義しています:

- `MH_NOUNDEFS`: No undefined references (fully linked)
- `MH_DYLDLINK`: dyld によるリンク
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: File splits r/o and r/w segments.
- `MH_WEAK_DEFINES`: Binary has weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary uses weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Make the stack executable
- `MH_NO_REEXPORTED_DYLIBS`: ライブラリが LC_REEXPORT コマンドを持たない
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: スレッドローカル変数を含むセクションがある
- `MH_NO_HEAP_EXECUTION`: ヒープ/データページの実行を許可しない
- `MH_HAS_OBJC`: バイナリが Objective-C セクションを持つ
- `MH_SIM_SUPPORT`: シミュレータサポート
- `MH_DYLIB_IN_CACHE`: shared library cache 内の dylib/framework に使用される。

## **Mach-O ロードコマンド**

ここでは、**ファイルのメモリ上のレイアウト** が指定され、**シンボルテーブルの位置**、実行開始時のメインスレッドのコンテキスト、必要な **共有ライブラリ** などが詳述されます。バイナリをメモリにロードする際の指示は、動的ローダー **(dyld)** に提供されます。

ここでは、前述の **`loader.h`** に定義された **load_command** 構造体が使用されます:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本的に、このタイプの Load Command は、バイナリが実行される際に Data セクションで示されたオフセットに従って **どのように \_\_TEXT をロードするか** (実行可能コード) **および \_\_DATA** (プロセスのデータ) **セグメント** を定義します。

These commands **define segments** that are **mapped** into the **virtual memory space** of a process when it is executed.

There are **different types** of segments, such as the **\_\_TEXT** segment, which holds the executable code of a program, and the **\_\_DATA** segment, which contains data used by the process. These **segments are located in the data section** of the Mach-O file.

**Each segment** can be further **divided** into multiple **sections**. The **load command structure** contains **information** about **these sections** within the respective segment.

In the header first you find the **segment header**:

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

Example of segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

This header defines the **number of sections whose headers appear after** it:
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
例: **セクションヘッダー**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

もし **section offset** (0x37DC) と **arch が始まるオフセット**、この場合 `0x18000` を **足す** と --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

また、**ヘッダー情報**を**コマンドライン**から取得することもできます:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** カーネルに対して **address zero** を **マップしない（読み取り・書き込み・実行ができないようにする）** よう指示します。構造体内の maxprot と minprot はゼロに設定され、このページに対して **読み・書き・実行の権限が一切ない** ことを示します。
- この割り当ては **NULL pointer dereference 脆弱性を軽減する** ために重要です。これは XNU がハードな page zero を強制し、最初のページ（最初の1ページのみ）をアクセス不可にするためです（i386 を除く）。バイナリは小さな __PAGEZERO（`-pagezero_size` を使用）を作成して最初の4kを覆い、残りの32bitメモリをユーザ・カーネル両方でアクセス可能にすることでこの要件を満たせます。
- **`__TEXT`**: **実行可能なコード** を含み、**読み取り** と **実行** の権限を持ちます（書き込み不可）。このセグメントの一般的なセクション:
- `__text`: コンパイル済みバイナリコード
- `__const`: 定数データ（読み取り専用）
- `__[c/u/os_log]string`: C、Unicode、または os ログの文字列定数
- `__stubs` と `__stubs_helper`: 動的ライブラリ読み込みプロセスで関与
- `__unwind_info`: スタックアンワインド情報
- これらの内容はすべて署名されていますが、同時に実行可能としてマークされている点に注意してください（文字列専用のセクションなど、本来この権限を必要としないセクションの悪用機会を生みます）。
- **`__DATA`**: **読み取り** と **書き込み** が可能なデータを含みます（実行不可）。
- `__got:` グローバルオフセットテーブル（Global Offset Table）
- `__nl_symbol_ptr`: Non-lazy（ロード時にバインドされる）シンボルポインタ
- `__la_symbol_ptr`: Lazy（使用時にバインドされる）シンボルポインタ
- `__const`: 本来は読み取り専用であるべきデータ（実際にはそうでないことがある）
- `__cfstring`: CoreFoundation 文字列
- `__data`: 初期化済みのグローバル変数
- `__bss`: 初期化されていない静的変数
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Objective-C runtime が使用する情報
- **`__DATA_CONST`**: \_\_DATA.\_\_const は定数である保証がなく（書き込み権限がある）、他のポインタや GOT も同様です。このセクションは `mprotect` を使用して `__const`、いくつかの初期化子、および（解決後の）GOT テーブルを **読み取り専用** にします。
- **`__LINKEDIT`**: リンカ（dyld）用の情報を含みます。たとえばシンボル、文字列、リロケーションテーブルのエントリなどです。`__TEXT` や `__DATA` に含まれない内容の汎用コンテナであり、その内容は他の load command で説明されます。
- dyld information: Rebase、Non-lazy/lazy/weak binding opcode と export 情報
- Functions starts: 関数の開始アドレスのテーブル
- Data In Code: `__text` 内のデータ領域（データアイランド）
- Symbol Table: バイナリ内のシンボル
- Indirect Symbol Table: ポインタ／スタブシンボル
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime が使用する情報を含みます。これらの情報は `__DATA` セグメント内の各種 `__objc_*` セクションにも存在する場合があります。
- **`__RESTRICT`**: コンテンツを持たないセグメントで、`__restrict` という単一の（こちらも空の）セクションを持ち、バイナリ実行時に DYLD の環境変数を無視することを保証します。

コードからも分かるように、**segments はフラグをサポート** しています（あまり多用されませんが）:

- `SG_HIGHVM`: Core 専用（未使用）
- `SG_FVMLIB`: 未使用
- `SG_NORELOC`: セグメントにリロケーションがない
- `SG_PROTECTED_VERSION_1`: 暗号化。たとえば Finder が `__TEXT` セグメントのテキストを暗号化するのに使われます。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** は **entryoff 属性** にエントリポイントを含みます。ロード時に、**dyld** はこの値を（メモリ上の）**バイナリのベース** に単純に **加算** し、その命令に **ジャンプ** してバイナリのコードの実行を開始します。

**`LC_UNIXTHREAD`** はメインスレッド開始時にレジスタが持つべき値を含みます。これは既に非推奨ですが **`dyld`** はまだ使用しています。これによって設定されるレジスタの値は次の方法で確認できます:
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Contains information about the **code signature of the Macho-O file**. It only contains an **offset** that **points** to the **signature blob**. This is typically at the very end of the file.\
However, you can find some information about this section in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) and this [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Support for binary encryption. However, of course, if an attacker manages to compromise the process, he will be able to dump the memory unencrypted.

### **`LC_LOAD_DYLINKER`**

Contains the **path to the dynamic linker executable** that maps shared libraries into the process address space. The **value is always set to `/usr/lib/dyld`**. It’s important to note that in macOS, dylib mapping happens in **user mode**, not in kernel mode.

### **`LC_IDENT`**

Obsolete but when configured to geenrate dumps on panic, a Mach-O core dump is created and the kernel version is set in the `LC_IDENT` command.

### **`LC_UUID`**

Random UUID. It's useful for anything directly but XNU caches it with the rest of the process info. It can be used in crash reports.

### **`LC_DYLD_ENVIRONMENT`**

Allows to indicate environment variables to the dyld beforenthe process is executed. This can be vary dangerous as it can allow to execute arbitrary code inside the process so this load command is only used in dyld build with `#define SUPPORT_LC_DYLD_ENVIRONMENT` and further restricts processing only to variables of the form `DYLD_..._PATH` specifying load paths.

### **`LC_LOAD_DYLIB`**

This load command describes a **dynamic** **library** dependency which **instructs** the **loader** (dyld) to **load and link said library**. There is a `LC_LOAD_DYLIB` load command **for each library** that the Mach-O binary requires.

- This load command is a structure of type **`dylib_command`** (which contains a struct dylib, describing the actual dependent dynamic library):
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
![](<../../../images/image (486).png>)

この情報はcliから次のコマンドでも取得できます:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
いくつかのマルウェアに関連するライブラリの例:

- **DiskArbitration**: USBドライブの監視
- **AVFoundation:** 音声および映像のキャプチャ
- **CoreWLAN**: Wifi スキャン

> [!TIP]
> Mach-O バイナリは1つまたは**複数の****コンストラクタ**を含むことがあり、これらは**LC_MAIN**で指定されたアドレスより**前に****実行**されます。\
> 任意のコンストラクタのオフセットは**\_\_DATA_CONST**セグメントの**\_\_mod_init_func**セクションに格納されます。

## **Mach-O データ**

ファイルの中心にはデータ領域があり、これは load-commands 領域で定義された複数のセグメントから構成されます。**各セグメント内にはさまざまなデータセクションを収めることができ**、各セクションはタイプ固有の**コードやデータを保持します**。

> [!TIP]
> このデータは基本的に load commands **LC_SEGMENTS_64** によってロードされるすべての**情報**を含む部分です

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

これには以下が含まれます:

- **Function table:** プログラムの関数に関する情報を保持します。
- **Symbol table**: バイナリで使用される外部関数に関する情報を含みます
- また内部関数や変数名なども含まれることがあります。

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Objetive-C の一般的なセクション

`__TEXT` セグメント内 (r-x):

- `__objc_classname`: クラス名（文字列）
- `__objc_methname`: メソッド名（文字列）
- `__objc_methtype`: メソッドの型（文字列）

`__DATA` セグメント内 (rw-):

- `__objc_classlist`: すべての Objetive-C クラスへのポインタ
- `__objc_nlclslist`: Non-Lazy Objective-C クラスへのポインタ
- `__objc_catlist`: Categories へのポインタ
- `__objc_nlcatlist`: Non-Lazy Categories へのポインタ
- `__objc_protolist`: プロトコルのリスト
- `__objc_const`: 定数データ
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
