# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Mac OS のバイナリは通常、**universal binaries** としてコンパイルされます。**universal binary** は、**同じファイル内で複数のアーキテクチャをサポート**できます。

これらのバイナリは、基本的に以下で構成される **Mach-O 構造**に従います。

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

次のコマンドでファイルを検索します: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header には **magic** bytes があり、その後にファイルに**含まれる** **archs** の**数** (`nfat_arch`) が続きます。また、各 arch には `fat_arch` struct が存在します。

次のように確認できます。

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

または [Mach-O View](https://sourceforge.net/projects/machoview/) tool を使用します。

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

ご想像のとおり、通常、2 つのアーキテクチャ向けにコンパイルされた universal binary は、1 つの arch 向けにコンパイルされたものの**約 2 倍のサイズ**になります。

> [!TIP]
> malware や suspicious apps を triage する際は、`file` が報告した「最適な」アーキテクチャだけを確認して終わらせないでください。universal binary では、各 slice に異なる imports、load commands、compiler metadata が隠されている可能性があります。そのため、まず**すべての** slice を列挙し、その後それぞれを個別に調査してください:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Recent macOS SDKs では、`<mach-o/utils.h>` に `macho_for_each_slice()` や `macho_best_slice()` などのヘルパーも公開されています。後者は dyld/kernel がロードするものをエミュレートするのに便利ですが、scanner は arch-specific なコンテンツを見落とさないよう、すべての slice を引き続き反復処理する必要があります。<sup>[[1]](#references)</sup>

## **Mach-O Header**

header には、Mach-O file であることを識別する magic bytes や、対象 architecture に関する情報など、file の基本情報が含まれています。次のコマンドで見つけられます: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-Oファイルタイプ

さまざまなファイルタイプがあり、[**ソースコードの例はこちら**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)で定義されています。最も重要なものは次のとおりです。

- `MH_OBJECT`: 再配置可能なオブジェクトファイル（コンパイルの中間生成物で、まだ実行可能ファイルではありません）。
- `MH_EXECUTE`: 実行可能ファイル。
- `MH_FVMLIB`: Fixed VMライブラリファイル。
- `MH_CORE`: コードダンプ。
- `MH_PRELOAD`: Preloaded executable file（現在はXNUでサポートされていません）。
- `MH_DYLIB`: Dynamic Libraries。
- `MH_DYLINKER`: Dynamic Linker。
- `MH_BUNDLE`: 「Plugin files」。gccで`-bundle`を使用して生成され、`NSBundle`または`dlopen`によって明示的にロードされます。
- `MH_DYSM`: Companion `.dSym`ファイル（デバッグ用シンボルを含むファイル）。
- `MH_KEXT_BUNDLE`: Kernel Extensions。
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
または [Mach-O View](https://sourceforge.net/projects/machoview/) を使用します：

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

ソースコードでは、libraries のロードに役立ついくつかの flags も定義されています：

- `MH_NOUNDEFS`: undefined references がない（完全にリンク済み）
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references が prebound されている
- `MH_SPLIT_SEGS`: ファイルが r/o セグメントと r/w セグメントに分割されている
- `MH_WEAK_DEFINES`: Binary に weak defined symbols がある
- `MH_BINDS_TO_WEAK`: Binary が weak symbols を使用する
- `MH_ALLOW_STACK_EXECUTION`: stack を executable にする
- `MH_NO_REEXPORTED_DYLIBS`: Library に LC_REEXPORT commands がない
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: thread local variables を含む section がある
- `MH_NO_HEAP_EXECUTION`: heap/data pages での execution を禁止
- `MH_HAS_OBJC`: Binary に oBject-C sections がある
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: shared library cache 内の dylibs/frameworks で使用される

## **Mach-O Load commands**

**file のメモリ内レイアウト**はここで指定され、**symbol table の位置**、実行開始時の main thread のコンテキスト、および必要な **shared libraries** の詳細が定義されます。Binary のメモリへのロード処理について、dynamic loader **(dyld)** への指示が提供されます。

これは、記載されている **`loader.h`** で定義された **load_command** 構造体を使用します：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
システムがそれぞれ異なる方法で処理する **load command** には、約 **50種類** あります。最も一般的なものは、`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`、`LC_CODE_SIGNATURE` です。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本的に、このタイプの Load Command は、バイナリの実行時に **Data section** に示された **offsets** に従って、**\_\_TEXT**（実行可能コード）および **\_\_DATA**（プロセス用のデータ）**segments** をどのようにロードするかを定義します。

これらのコマンドは、プロセスの実行時にその **virtual memory space** に **mapped** される **segments** を定義します。

**\_\_TEXT** segment など、さまざまな種類の **segments** があります。**\_\_TEXT** segment にはプログラムの実行可能コードが格納され、**\_\_DATA** segment にはプロセスが使用するデータが含まれます。これらの **segments** は Mach-O ファイルの **data section** に配置されています。

**各 segment** は、さらに複数の **sections** に分割できます。**load command structure** には、それぞれの segment 内にある **これらの sections** に関する **information** が含まれています。

ヘッダーにはまず **segment header** があります。

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

segment header の例：

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

このヘッダーは、**その後に headers が続く sections の数**を定義します。
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
**セクションヘッダー**の例:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

**セクションオフセット** (0x37DC) に、この場合は `0x18000` である **arch starts** の位置の **オフセット**を**加算**すると、`0x37DC + 0x18000 = 0x1B7DC` になります。

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**ヘッダー情報**は、**コマンドライン**から次のように取得することもできます:
```bash
otool -lv /bin/ls
```
この cmd によってロードされる一般的なセグメント:

- **`__PAGEZERO`:** **address zero** を **map** し、そこから **read**、**write**、**execute** できないようにするよう kernel に指示します。構造体内の maxprot および minprot 変数はゼロに設定され、このページに **read-write-execute 権限がない**ことを示します。
- この allocation は、**NULL pointer dereference vulnerabilities** を**緩和**するために重要です。これは、XNU が hard page zero を強制し、memory の最初のページ（最初のページのみ）をアクセス不可にするためです（i386 を除く）。binary は、小さな \_\_PAGEZERO（`-pagezero_size` を使用）を作成して最初の 4k をカバーし、残りの 32bit memory を user mode と kernel mode の両方からアクセス可能にすることで、この要件を満たせます。
- **`__TEXT`**: **read** および **execute** 権限（writable ではない）を持つ **executable** **code** が含まれます。このセグメントの一般的な sections:
- `__text`: Compile された binary code
- `__const`: Constant data（read only）
- `__[c/u/os_log]string`: C、Unicode、または os logs の string constants
- `__stubs` および `__stubs_helper`: dynamic library の loading process 中に使用されます
- `__unwind_info`: Stack unwind data。
- これらの content はすべて signed されていますが、executable としても marked されています（string 専用 sections のように、必ずしもこの privilege を必要としない sections の exploitation に、より多くの選択肢が生まれます）。
- **`__DATA`**: **readable** かつ **writable** な data（executable ではない）**。**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy（load 時に bind）symbol pointer
- `__la_symbol_ptr`: Lazy（use 時に bind）symbol pointer
- `__const`: Read-only data であるべきもの（実際にはそうではない）
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables（initialized 済みのもの）
- `__bss`: Static variables（initialized されていないもの）
- `__objc_*`（\_\_objc_classlist、\_\_objc_protolist など）: Objective-C runtime が使用する information
- **`__DATA_CONST`**: \_\_DATA.\_\_const は constant（write permissions）であることが保証されず、その他の pointers や GOT も同様です。この section は `mprotect` を使用して、`__const`、一部の initializers、解決済みの GOT table を **read only** にします。
- **`__AUTH` / `__AUTH_CONST`**: 最近の Apple Silicon binaries で一般的です。これらの segments には、load 時または use 時に authenticated される必要がある pointers（例: `__auth_got`）が格納されます。rebinding、hook、import-patching の trick が legacy の `__got` / `__la_symbol_ptr` sections だけを確認する場合、modern な `arm64e` binaries の実際の call sites を見落とす可能性があります。これらの sections の詳細については、[this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) を確認してください。
- **`__LINKEDIT`**: symbol、string、relocation table entries など、linker（dyld）のための information が含まれます。`__TEXT` や `__DATA` のいずれにも含まれない contents の generic container であり、その content は他の load commands に記述されています。
- dyld information: Rebase、Non-lazy/lazy/weak binding opcodes、export info
- Functions starts: Functions の start addresses の table
- Data In Code: \_\_text 内の data islands
- SYmbol Table: Binary 内の symbols
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime が使用する information が含まれます。ただし、この information は \_\_DATA segment 内のさまざまな \_\_objc\_\* sections にも存在する場合があります。
- **`__RESTRICT`**: `__restrict` という単一の section（これも empty）を持つ content のない segment であり、binary の実行時に DYLD environmental variables を無視することを保証します。

コードで確認できたように、**segments は flags もサポートします**（ただし、あまり使用されません）。

- `SG_HIGHVM`: Core only（未使用）
- `SG_FVMLIB`: 未使用
- `SG_NORELOC`: Segment に relocation がない
- `SG_PROTECTED_VERSION_1`: Encryption。たとえば Finder が text `__TEXT` segment を encrypt するために使用します。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** は **`entryoff attribute` に entrypoint を含みます。** load 時に、**dyld** はこの value を binary の（in-memory）**base に加算**し、その後この instruction に **jump** して binary の code の execution を開始します。

**`LC_UNIXTHREAD`** には、main thread の開始時に register が持つ必要のある values が含まれます。これはすでに deprecated ですが、**`dyld`** は現在も使用しています。これによって設定された registers の vlaues は、次のコマンドで確認できます:
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


**Mach-O fileのコード署名**に関する情報が含まれます。含まれているのは、**署名blob**を**指す****offset**だけです。通常、これはファイルの末尾にあります。\
ただし、このセクションに関する情報は[**このブログ記事**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)と、この[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)から確認できます。<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

バイナリの暗号化をサポートします。ただし、もちろん、攻撃者がプロセスのcompromiseに成功した場合、暗号化されていない状態でメモリをdumpできます。

### **`LC_LOAD_DYLINKER`**

共有ライブラリをプロセスのアドレス空間にマッピングする**dynamic linker executableへのパス**が含まれます。**値は常に`/usr/lib/dyld`に設定されます**。macOSでは、dylibのマッピングはkernel modeではなく、**user mode**で行われる点に注意が必要です。

### **`LC_IDENT`**

obsoleteですが、panic時にdumpを生成するよう設定されている場合、Mach-O core dumpが作成され、kernel versionが`LC_IDENT` commandに設定されます。

### **`LC_UUID`**

ランダムなUUIDです。それ自体には直接的な用途はありませんが、XNUはこれをプロセス情報の他の部分とともにcacheします。crash reportで使用できます。

### **`LC_BUILD_VERSION`**

Modern binaryには通常、このcommandが含まれており、**target platform**、**minimum OS version**、**SDK version**、さらにオプションで、そのsliceのbuildに使用された**tool versions**を宣言します。offensive/reversingの観点では、sampleがどのようにbuildされたかをfingerprintし、あるsliceが別のSDKやdeployment targetでcompileされた奇妙なuniversal binaryを素早く見つけるのに非常に役立ちます。古いbinaryでは、代わりに`LC_VERSION_MIN_*`が使用されている場合があります。
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

プロセスが実行される前に、dyld に環境変数を指定できます。これはプロセス内で任意のコードを実行できる可能性があるため非常に危険です。そのため、この load command は `#define SUPPORT_LC_DYLD_ENVIRONMENT` を使用してビルドされた dyld でのみ使用され、さらに `DYLD_..._PATH` 形式で load paths を指定する変数だけに処理を制限します。

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains では、古い `LC_DYLD_INFO[_ONLY]` opcodes だけに依存する代わりに、これらの commands に export/bind/rebase metadata を格納することがよくあります。どちらも **`__LINKEDIT`** 内を指す `linkedit_data_command` entries です。

- **`LC_DYLD_EXPORTS_TRIE`**: image によって export される symbols を含む Compact trie。
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld が rebases と binds を適用するために使用する、segment ごとの fixup chains。Apple Silicon では、現代的な authenticated pointer fixups の多くもここで確認できます。

この metadata は、imports/exports を再構築したり、`@rpath` で load された dependency がそのように resolve された理由を理解したり、現代的な `arm64e` target で hook/rebinding の試行が失敗した理由を特定したりする際に非常に便利です。`dyld_info` は、disk 上に standalone files として存在しない **cache-only dylib paths** に対しても使用できます。現代の macOS では、多くの system libraries が shared cache にのみ存在するため、これは非常に便利です。<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

この modern load command は、**kernel collections / kernelcache-style filesets** を調査する際に主に関係します。単一の standalone image を表す代わりに、外側の Mach-O はコンテナとして機能し、各 `LC_FILESET_ENTRY` は、それぞれ固有のパス風 **entry id**、VM アドレス、ファイルオフセットを持つ埋め込み Mach-O を指します。modern macOS/iOS の kernel components を reverse する場合、この command は、トップレベルのコンテナと、extract または disassemble したい実際の image の間をつなぐ役割を果たすことがよくあります。
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
実用的な抽出ワークフローについては、[macOS kernel extensions と kernelcache に関するこちらのページ](../mac-os-architecture/macos-kernel-extensions.md)を参照してください。

### **`LC_LOAD_DYLIB`**

この load command は、**loader**（dyld）に対象の **library** を **load して link するよう指示する** **dynamic** **library** 依存関係を記述します。Mach-O binary が必要とする**各 library**に対して、`LC_LOAD_DYLIB` load command が1つ存在します。

- この load command は **`dylib_command`** 型の構造体です（実際に依存する dynamic library を記述する `struct dylib` を含みます）。:
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / library's compatibility vers number /](<../../../images/image (486).png>)

この情報は、CLIから次のコマンドでも取得できます：
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
潜在的な malware 関連ライブラリには、次のようなものがあります:

- **DiskArbitration**: USB ドライブの監視
- **AVFoundation:** audio と video のキャプチャ
- **CoreWLAN**: Wi-Fi スキャン。

> [!TIP]
> Mach-O binary には **1 つ以上**の **constructor** を含めることができ、**LC_MAIN** で指定されたアドレスより**前に** **実行**されます。\
> constructor の offset は、**\_\_DATA_CONST** segment の **\_\_mod_init_func** section に保持されます。

## **Mach-O データ**

file の中心には data region があり、これは load-commands region で定義された複数の segment で構成されます。**各 segment にはさまざまな data section を格納でき**、各 section には特定の type に対応する **code または data** が格納されます。

> [!TIP]
> data は基本的に、load commands **LC_SEGMENTS_64** によってロードされるすべての **information** を含む部分です。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

これには次のものが含まれます:

- **Function table:** program の function に関する information を保持します。
- **Symbol table**: binary によって使用される external function に関する information を含みます。
- internal function や variable の name などが含まれることもあります。

確認するには、[**Mach-O View**](https://sourceforge.net/projects/machoview/) tool を使用できます:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

または cli から:
```bash
size -m /bin/ls
```
## Objective-Cの一般的なセクション

`__TEXT`セグメント（r-x）内:

- `__objc_classname`: Class names（文字列）
- `__objc_methname`: Method names（文字列）
- `__objc_methtype`: Method types（文字列）

`__DATA`セグメント（rw-）内:

- `__objc_classlist`: すべてのObjective-C classへのポインタ
- `__objc_nlclslist`: Non-Lazy Objective-C classへのポインタ
- `__objc_catlist`: Categoriesへのポインタ
- `__objc_nlcatlist`: Non-Lazy Categoriesへのポインタ
- `__objc_protolist`: Protocolsのリスト
- `__objc_const`: 定数データ
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

## 参考文献

- [1] [Mach-O slicesは、考えているほど単純ではない](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1)のmanページ](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [自身のEntitlementsの読み取り](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
