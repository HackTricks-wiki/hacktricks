# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

These binaries follows the **Mach-O structure** which is basically compased of:

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

ヘッダーには **magic** バイトがあり、その後にファイルが**含む** **archs** の**数**（`nfat_arch`）が続き、各 arch には `fat_arch` 構造体があります。

次のように確認できます:

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

または [Mach-O View](https://sourceforge.net/projects/machoview/) ツールを使って確認できます:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

おそらく想像できるように、2つのアーキテクチャ向けにコンパイルされた universal binary は、1つの arch のみでコンパイルされたものより**サイズが2倍**になります。

> [!TIP]
> malware や suspicious apps をトリアージする際は、`file` が "best" architecture を報告したところで止まらないでください。universal binary は、スライスごとに異なる imports、load commands、または compiler metadata を隠せるため、まず**すべて**のスライスを列挙し、その後で個別に調べてください:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
最近の macOS SDK では、`<mach-o/utils.h>` に `macho_for_each_slice()` や `macho_best_slice()` のようなヘルパーも公開されています。後者は dyld/kernel が何を読み込むかをエミュレートするのに便利ですが、スキャナーはそれでも各 slice をすべて走査して、arch 固有の内容を見落とさないようにする必要があります。

## **Mach-O Header**

header には、Mach-O file であることを識別するための magic bytes や、target architecture に関する情報など、file の基本情報が含まれています。以下で見つけられます: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

さまざまな file type があり、[**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) で定義されています。最も重要なものは以下です:

- `MH_OBJECT`: Relocatable object file (コンパイルの中間生成物で、まだ executable ではない)。
- `MH_EXECUTE`: Executable files。
- `MH_FVMLIB`: Fixed VM library file。
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (XNU ではもはや supported されていない)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files"。gcc の `-bundle` で生成され、`NSBundle` または `dlopen` によって明示的に loaded される。
- `MH_DYSM`: Companion `.dSym` file (debugging 用の symbols を含む file)。
- `MH_KEXT_BUNDLE`: Kernel Extensions。
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
または [Mach-O View](https://sourceforge.net/projects/machoview/) を使用します:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

ソースコードでは、ライブラリの読み込みに役立ついくつかのフラグも定義されています:

- `MH_NOUNDEFS`: 未定義参照なし（完全にリンク済み）
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: 動的参照は事前バインド済み。
- `MH_SPLIT_SEGS`: ファイルは r/o と r/w セグメントに分割される。
- `MH_WEAK_DEFINES`: Binary has weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary uses weak symbols
- `MH_ALLOW_STACK_EXECUTION`: スタックを実行可能にする
- `MH_NO_REEXPORTED_DYLIBS`: Library not LC_REEXPORT commands
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: thread local variables を含むセクションがある
- `MH_NO_HEAP_EXECUTION`: heap/data pages の実行なし
- `MH_HAS_OBJC`: Binary has oBject-C sections
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: 共有ライブラリキャッシュ内の dylibs/frameworks に使用される。

## **Mach-O Load commands**

**メモリ内でのファイルのレイアウト**はここで指定され、**シンボルテーブルの位置**、実行開始時のメインスレッドのコンテキスト、必要な**共有ライブラリ**が詳述されます。バイナリがメモリに読み込まれる過程について、動的ローダー **(dyld)** に指示が与えられます。

これには、前述の **`loader.h`** で定義されている **load_command** 構造体が使われます:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
約 **50種類の異なる load commands** があり、system はそれぞれを異なる方法で扱います。最も一般的なものは `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE` です。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本的に、このタイプの Load Command は、binary が実行されるときに **Data section に示された offsets** に従って、**\_\_TEXT**（executable code）と **\_\_DATA**（process の data）**segments** を **どのように load するか** を定義します。

これらの commands は、実行時に process の **virtual memory space** に **mapped** される **segments** を **define** します。

**異なる種類** の **segments** があり、たとえばプログラムの executable code を保持する **\_\_TEXT** segment や、process が使用する data を含む **\_\_DATA** segment があります。これらの **segments are located in the data section** of the Mach-O file.

**各 segment** は、さらに複数の **sections** に **divided** できます。**load command structure** には、対応する segment 内の **these sections** に関する **information** が含まれています。

header の先頭では、まず **segment header** を見つけます:

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
<strong>	uint32_t	nsects;		/* segment 内の section 数 */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

segment header の例:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

この header は、**その後に header が現れる sections の数** を定義します:
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
**section header** の例:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

**section offset** (0x37DC) に、**arch starts** の **offset** を加えると、この場合 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**command line** から **headers information** を取得することも可能で、以下のようにします:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** カーネルに **アドレス0** を **map** するよう指示し、**読み取り・書き込み・実行** できないようにする。structure 内の maxprot と minprot 変数は 0 に設定され、このページに **read-write-execute 権限がない** ことを示す。
- この割り当ては **NULL pointer dereference vulnerabilities** を **mitigate** するうえで重要。これは XNU が hard page zero を強制し、メモリの最初のページ（最初の1ページのみ）を到達不能にするため（i386 を除く）。binary は `-pagezero_size` を使って小さな \_\_PAGEZERO を作成し最初の 4k を覆い、32bit memory の残りを user mode と kernel mode の両方でアクセス可能にすることで、この要件を満たせる。
- **`__TEXT`**: **read** と **execute** 権限を持つ **executable** **code** を含む（writable ではない）**。** この segment の一般的な section:
- `__text`: Compiled binary code
- `__const`: 定数データ（read only）
- `__[c/u/os_log]string`: C, Unicode, または os logs の文字列定数
- `__stubs` and `__stubs_helper`: dynamic library loading process 中に関与する
- `__unwind_info`: Stack unwind data.
- これらすべての content は署名されているが、同時に executable としてマークされていることに注意（この権限を必ずしも必要としない section、たとえば文字列専用 section などに対する exploitation の余地が増える）。
- **`__DATA`**: **readable** で **writable** なデータを含む（executable ではない）**。**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: read-only data であるべき（実際にはそうではない）
- `__cfstring`: CoreFoundation strings
- `__data`: 初期化済みの global variables
- `__bss`: 初期化されていない static variables
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Objective-C runtime で使用される情報
- **`__DATA_CONST`**: \_\_DATA.\_\_const は constant であることが保証されず（write permissions がある）、他の pointers や GOT も同様。 この section は `mprotect` を使って `__const`、一部の initializers、そして（解決後の）GOT table を **read only** にする。
- **`__AUTH` / `__AUTH_CONST`**: 最近の Apple Silicon binaries で一般的。 これらの segment は、load 時または use 時に認証されなければならない pointers を保持する（たとえば `__auth_got`）。rebinding、hook、または import-patching の手法が従来の `__got` / `__la_symbol_ptr` section だけを確認する場合、最新の `arm64e` binaries にある実際の call sites を見逃す可能性がある。これらの section の詳細は [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) を参照。
- **`__LINKEDIT`**: linker (dyld) 向けの情報を含む。たとえば symbol、string、relocation table entries など。`__TEXT` や `__DATA` に属さない内容の generic container であり、その content は他の load commands で記述される。
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: 関数の開始アドレスの table
- Data In Code: `__text` 内の data islands
- SYmbol Table: binary 内の symbols
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime で使用される情報を含む。 ただしこの情報は、\_\_DATA segment 内のさまざまな \_\_objc\_\* section にも見つかる場合がある。
- **`__RESTRICT`**: **`__restrict`** という単一の section（これも空）だけを持つ content のない segment で、binary 実行時に DYLD environmental variables を無視するようにする。

コードで見られるように、**segments also support flags**（あまり使われないが）:

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** は **entryoff attribute** に entrypoint を含む。load 時に、**dyld** は単にこの値を binary の（メモリ上の）**base** に **add** し、その後この instruction に **jump** して binary の code の実行を開始する。

**`LC_UNIXTHREAD`** は main thread の開始時に register が持つべき値を含む。これはすでに deprecated だが、**dyld** はまだ使用している。これで設定される register の vlaues は以下で確認できる:
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


**Mach-Oファイルのcode signature** に関する情報を含みます。これは **signature blob** を **指し示す** **offset** だけを含みます。通常、これはファイルの最後尾にあります。\
ただし、このセクションについては [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) と [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) でいくつかの情報を見つけられます。

### **`LC_ENCRYPTION_INFO[_64]`**

バイナリ暗号化のサポートです。ただし、もちろん、攻撃者がプロセスの侵害に成功した場合、メモリを暗号化されていない状態でダンプできます。

### **`LC_LOAD_DYLINKER`**

共有ライブラリをプロセスのアドレス空間にマッピングする **dynamic linker executable へのパス** を含みます。**値は常に `/usr/lib/dyld` に設定されます**。macOS では、dylib のマッピングは kernel mode ではなく **user mode** で行われる点に注意してください。

### **`LC_IDENT`**

古い形式ですが、panic 時に dump を生成するよう設定されている場合、Mach-O core dump が作成され、kernel version が `LC_IDENT` コマンドに設定されます。

### **`LC_UUID`**

ランダムな UUID です。直接的に何かに使うというより、XNU が他の process info と一緒にキャッシュします。crash reports で使用できます。

### **`LC_BUILD_VERSION`**

現代のバイナリは通常、このコマンドを持ち、**target platform**、**minimum OS version**、**SDK version**、およびその slice をビルドするために使用された **tool versions** を任意で宣言します。攻撃/リバースエンジニアリングの観点では、サンプルがどのようにビルドされたかを特定するのに非常に役立ち、また、ある slice が異なる SDK や deployment target でコンパイルされた奇妙な universal binaries を素早く見つけるのにも役立ちます。古いバイナリでは代わりに `LC_VERSION_MIN_*` を使うことがあります。
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

dyld に、プロセスが実行される前に環境変数を指定できるようにします。これは非常に危険で、プロセス内で任意のコードを実行できる可能性があります。そのため、この load command は `#define SUPPORT_LC_DYLD_ENVIRONMENT` でビルドされた dyld でのみ使用され、さらに `DYLD_..._PATH` 形式の変数、つまり load paths を指定するものだけに処理を制限します。

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

最近の toolchains では、旧来の `LC_DYLD_INFO[_ONLY]` の opcodes のみに依存する代わりに、export/bind/rebase の metadata をこれらのコマンドに保存することがよくあります。どちらも **`__LINKEDIT`** を指す `linkedit_data_command` エントリです。

- **`LC_DYLD_EXPORTS_TRIE`**: イメージによって export された symbols を含むコンパクトな trie。
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld が rebases と binds を適用するために使う、セグメントごとの fixup chains。Apple Silicon では、ここで多くの modern authenticated pointer fixups にも遭遇します。

この metadata は、imports/exports の再構築、`@rpath` で読み込まれた dependency がそのように解決された理由の理解、または modern `arm64e` ターゲットで hook/rebinding の試みが失敗した理由の特定に非常に役立ちます。`dyld_info` は、ディスク上に単独のファイルとして存在しない **cache-only dylib paths** に対しても使用でき、これは多くの system libraries が shared cache にのみ存在する modern macOS では非常に便利です。
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

この आधुनिकな load command は、主に **kernel collections / kernelcache-style filesets** を調べるときに関係します。単一の独立した image を表す代わりに、外側の Mach-O はコンテナとして機能し、各 `LC_FILESET_ENTRY` は埋め込まれた Mach-O を指し示します。その Mach-O には、独自の path-like な **entry id**、VM address、file offset があります。modern macOS/iOS の kernel components を reverse している場合、この command は多くの場合、トップレベルのコンテナと、実際に extract したり disassemble したい image をつなぐ bridge になります。
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
For practical extraction workflows, check [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

この load command は、**loader** (dyld) に**その library を load して link するよう指示する**、**dynamic** な **library** 依存関係を記述します。Mach-O binary が必要とする各 library について、`LC_LOAD_DYLIB` load command が 1 つあります。

- この load command は **`dylib_command`** 型の structure です（実際の依存 dynamic library を記述する struct dylib を含みます）：
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

これらの情報は cli から次のようにも取得できます:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: USBドライブの監視
- **AVFoundation:** 音声と動画のキャプチャ
- **CoreWLAN**: Wifi スキャン。

> [!TIP]
> Mach-O binary は 1 つ以上の **constructors** を含むことができ、それらは **LC_MAIN** で指定されたアドレスより前に **executed** される。\
> どの constructors のオフセットも **\_\_DATA_CONST** セグメントの **\_\_mod_init_func** セクションに保持されている。

## **Mach-O Data**

ファイルの中核には data region があり、これは load-commands region で定義される複数の segments で構成されている。**各 segment 内にはさまざまな data sections を格納でき**、各 section は種類ごとに固有の code または data を **holding** する。

> [!TIP]
> data は基本的に、load commands **LC_SEGMENTS_64** によって読み込まれるすべての **information** を含む部分。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

これには以下が含まれる:

- **Function table:** プログラムの functions に関する情報を保持する。
- **Symbol table**: binary で使用される外部 function に関する情報を含む
- 内部 function、variable names なども含むことがある。

確認するには、[**Mach-O View**](https://sourceforge.net/projects/machoview/) ツールを使える:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

または cli から:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

`__TEXT` セグメント (r-x) で:

- `__objc_classname`: クラス名 (strings)
- `__objc_methname`: メソッド名 (strings)
- `__objc_methtype`: メソッド型 (strings)

`__DATA` セグメント (rw-) で:

- `__objc_classlist`: すべての Objetive-C クラスへのポインタ
- `__objc_nlclslist`: Non-Lazy Objective-C クラスへのポインタ
- `__objc_catlist`: Categories へのポインタ
- `__objc_nlcatlist`: Non-Lazy Categories へのポインタ
- `__objc_protolist`: Protocols のリスト
- `__objc_const`: 定数データ
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
