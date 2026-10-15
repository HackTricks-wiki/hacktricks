# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOSは**Mach-O**実行ファイル形式を使用します。**universal**（fat）binaryは、複数のアーキテクチャ固有のMach-Oスライスを1つのファイルに含みます。Appleのオープンソースヘッダー`fat.h`および`loader.h`では、このページで説明する構造体と定数が定義されています。 <sup>[[5]](#references)</sup>

Mach-Oイメージは次の要素で構成されます。

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

Headerには**magic** bytesがあり、その後にファイルに**含まれる**アーキテクチャの**数**（`nfat_arch`）が続きます。各アーキテクチャには`fat_arch` structがあります。

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

または、[Mach-O View](https://sourceforge.net/projects/machoview/)ツールを使用します。

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

ご想像のとおり、通常、2つのアーキテクチャ向けにコンパイルされたuniversal binaryは、1つのアーキテクチャ向けにコンパイルされたものの**2倍のサイズ**になります。

> [!TIP]
> malwareや疑わしいアプリを調査するときは、`file`が「最適な」アーキテクチャを報告しても、それだけで終わらせないでください。universal binaryでは、各スライスに異なるimports、load commands、またはcompiler metadataが含まれている可能性があります。まず**すべての**スライスを列挙し、それぞれを個別に調査してください。

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

最近のmacOS SDKでは、`<mach-o/utils.h>`に`macho_for_each_slice()`や`macho_best_slice()`などのヘルパーも公開されています。後者はdyld/kernelが読み込むものをエミュレートするのに便利ですが、スキャナーはアーキテクチャ固有のコンテンツを見逃さないよう、すべてのsliceを引き続き走査する必要があります。<sup>[[1]](#references)</sup>

## **Mach-Oヘッダー**

ヘッダーには、ファイルがMach-Oファイルであることを識別するマジックバイトや、ターゲットアーキテクチャに関する情報など、ファイルの基本情報が含まれています。次のコマンドで見つけることができます: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

### Mach-O ファイルタイプ

さまざまなファイルタイプがあり、[**こちらのソースコードの例**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)で定義を確認できます。主なものは次のとおりです。

- `MH_OBJECT`: 再配置可能なオブジェクトファイル（コンパイルの中間生成物で、まだ実行ファイルではありません）。
- `MH_EXECUTE`: 実行ファイル。
- `MH_FVMLIB`: 固定 VM ライブラリファイル。
- `MH_CORE`: コードダンプ。
- `MH_PRELOAD`: プリロードされた実行ファイル（XNUではサポートされなくなりました）。
- `MH_DYLIB`: 動的ライブラリ。
- `MH_DYLINKER`: 動的リンカー。
- `MH_BUNDLE`: 「プラグインファイル」。gccで -bundle を使用して生成され、`NSBundle` または `dlopen` で明示的に読み込まれます。
- `MH_DYSM`: 付属の `.dSym` ファイル（デバッグ用のシンボルを含むファイル）。
- `MH_KEXT_BUNDLE`: カーネル拡張機能。

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

または [Mach-O View](https://sourceforge.net/projects/machoview/) を使用します。

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O フラグ**

ソースコードでは、ライブラリの読み込みに役立ついくつかのフラグも定義されています。

- `MH_NOUNDEFS`: 未定義の参照なし（完全にリンク済み）
- `MH_DYLDLINK`: Dyld によるリンク
- `MH_PREBOUND`: 動的参照が事前バインド済み
- `MH_SPLIT_SEGS`: ファイルを読み取り専用セグメントと読み書き可能セグメントに分割
- `MH_WEAK_DEFINES`: バイナリに weak 定義のシンボルがある
- `MH_BINDS_TO_WEAK`: バイナリが weak シンボルを使用する
- `MH_ALLOW_STACK_EXECUTION`: スタックを実行可能にする
- `MH_NO_REEXPORTED_DYLIBS`: ライブラリに LC_REEXPORT コマンドがない
- `MH_PIE`: 位置独立実行ファイル
- `MH_HAS_TLV_DESCRIPTORS`: スレッドローカル変数を含むセクションがある
- `MH_NO_HEAP_EXECUTION`: ヒープ／データページでの実行を禁止
- `MH_HAS_OBJC`: バイナリに Objective-C セクションがある
- `MH_SIM_SUPPORT`: シミュレーターをサポート
- `MH_DYLIB_IN_CACHE`: 共有ライブラリキャッシュ内の dylib／framework で使用される

## **Mach-O ロードコマンド**

**ファイルのメモリ上のレイアウト**はここで指定され、**シンボルテーブルの位置**、実行開始時のメインスレッドのコンテキスト、必要な**共有ライブラリ**が詳しく記述されます。バイナリをメモリに読み込む処理について、動的ローダー **(dyld)** への指示が記載されています。

これは、前述の **`loader.h`** で定義されている **load_command** 構造体を使用します。

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

システムがそれぞれ異なる方法で処理する **Load Command は約50種類**あります。最も一般的なものは、`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`、`LC_CODE_SIGNATURE` です。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本的に、このタイプの Load Command は、バイナリの実行時に、Data セクションに示された **offsets** に従って、**\_\_TEXT**（実行コード）および **\_\_DATA**（プロセスのデータ）**segments** をどのようにロードするかを定義します。

これらのコマンドは、プロセスの実行時に、その**仮想メモリ空間**に**マッピング**される**segments**を定義します。

**\_\_TEXT** segment のようにプログラムの実行コードを格納するものや、プロセスが使用するデータを含む **\_\_DATA** segment など、**さまざまなタイプ**の segments があります。これらの **segments は Mach-O ファイルの Data セクションにあります**。

**各 segment** は、さらに複数の **sections** に**分割**できます。**Load Command の構造**には、それぞれの segment 内にある**これらの sections に関する情報**が含まれます。

ヘッダーの最初にあるのは、**segment header** です。

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

このヘッダーは、その後にヘッダーが続く sections の**数**を定義します。

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

**section header**の例:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

**section offset** (0x37DC) と、この場合は `0x18000` である**arch starts**の位置の**offset**を足すと、`0x37DC + 0x18000 = 0x1B7DC` になります。

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

次のコマンドを使って、**headers information**を**command line**から取得することもできます。

```bash
otool -lv /bin/ls
```

この cmd によってロードされる一般的なセグメント:

- **`__PAGEZERO`:** カーネルに対し、**アドレス 0** を**マップ**し、そこからの**読み取り、書き込み、実行を禁止**するよう指示します。構造体内の maxprot と minprot 変数は 0 に設定され、このページに**読み取り・書き込み・実行の権限がない**ことを示します。
  - この割り当ては、**NULL pointer dereference vulnerabilities の緩和**に重要です。これは、XNU が最初のメモリページ（最初のページのみ）をアクセス不能にする hard page zero を強制するためです（i386 を除く）。バイナリは、小さな \_\_PAGEZERO（`-pagezero_size` を使用）を作成して最初の 4k をカバーし、残りの 32bit メモリをユーザーモードとカーネルモードの両方でアクセス可能にすることで、この要件を満たせます。
- **`__TEXT`**: **読み取り**および**実行**権限（書き込み不可）を持つ**実行可能な** **コード**が含まれます。このセグメントの一般的なセクション:
  - `__text`: コンパイル済みバイナリコード
  - `__const`: 定数データ（読み取り専用）
  - `__[c/u/os_log]string`: C、Unicode、または os logs の文字列定数
  - `__stubs` および `__stubs_helper`: dynamic library のロード処理中に使用される
  - `__unwind_info`: Stack unwind データ。
  - これらのコンテンツはすべて署名されていますが、実行可能としてもマークされています（string 専用セクションなど、この権限を必ずしも必要としないセクションを悪用する選択肢が増えます）。
- **`__DATA`**: **読み取り**および**書き込み**可能なデータ（実行不可）が含まれます。
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Non lazy（ロード時に bind）symbol pointer
  - `__la_symbol_ptr`: Lazy（使用時に bind）symbol pointer
  - `__const`: 読み取り専用データであるべき（実際はそうではない）
  - `__cfstring`: CoreFoundation strings
  - `__data`: Global variables（初期化済み）
  - `__bss`: Static variables（未初期化）
  - `__objc_*` (\_\_objc_classlist、\_\_objc_protolist など): Objective-C runtime が使用する情報
- **`__DATA_CONST`**: \_\_DATA.\_\_const は定数であるとは限らず（書き込み権限があります）、他のポインターや GOT も同様です。このセクションは `mprotect` を使用して、`__const`、一部の initializer、GOT table（解決後）を**読み取り専用**にします。
- **`__AUTH` / `__AUTH_CONST`**: 最近の Apple Silicon バイナリで一般的です。これらのセグメントには、ロード時または使用時に認証が必要なポインター（たとえば `__auth_got`）が格納されます。rebinding、hook、import-patching の手法が legacy の `__got` / `__la_symbol_ptr` セクションだけを確認する場合、最新の `arm64e` バイナリにある実際の call site を見落とすことがあります。これらのセクションの詳細については、[このページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。
- **`__LINKEDIT`**: symbol、string、relocation table のエントリーなど、linker（dyld）の情報が含まれます。`__TEXT` または `__DATA` のどちらにも属さないコンテンツを格納する汎用コンテナで、内容は他の load command で記述されます。
  - dyld 情報: Rebase、Non-lazy/lazy/weak binding opcodes、export info
  - Functions starts: 関数の開始アドレスのテーブル
  - Data In Code: \_\_text 内のデータ領域
  - SYmbol Table: バイナリ内の symbols
  - Indirect Symbol Table: Pointer/stub symbols
  - String Table
  - Code Signature
- **`__OBJC`**: Objective-C runtime が使用する情報が含まれます。この情報は、\_\_DATA セグメント内のさまざまな \_\_objc\_\* セクションにも存在する場合があります。
- **`__RESTRICT`**: **`__restrict`** という単一のセクション（これも空）を持つ、コンテンツのないセグメントです。バイナリの実行時に DYLD の環境変数を無視するようにします。

コードで確認できたように、**セグメントはフラグにも対応しています**（ただし、あまり使われません）。

- `SG_HIGHVM`: Core のみ（未使用）
- `SG_FVMLIB`: 未使用
- `SG_NORELOC`: セグメントに relocation がない
- `SG_PROTECTED_VERSION_1`: Encryption。たとえば Finder がテキスト `__TEXT` セグメントを暗号化するために使用します。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** には、**entryoff 属性に entrypoint が格納されます。** ロード時に **dyld** はこの値を（メモリ上の）**バイナリのベースアドレスに加算**し、その後この命令に**ジャンプ**してバイナリのコードの実行を開始します。

**`LC_UNIXTHREAD`** には、main thread の開始時にレジスターが持つべき値が含まれます。これはすでに非推奨ですが、**`dyld`** は今も使用しています。これによって設定されたレジスターの値は、次の方法で確認できます:

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


**Mach-Oファイルのコード署名**に関する情報が含まれています。含まれているのは、**署名 blob**を**指す****オフセット**だけです。通常、これはファイルの末尾にあります。\
このセクションの詳細については、[**こちらのブログ記事**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)および[**こちらのgist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)を参照してください。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

バイナリの暗号化をサポートします。ただし、もちろん、攻撃者がプロセスを侵害できれば、暗号化されていない状態のメモリをダンプできます。

### **`LC_LOAD_DYLINKER`**

共有ライブラリをプロセスのアドレス空間にマップする**動的リンカー実行ファイルへのパス**が含まれています。**値は常に`/usr/lib/dyld`に設定されています**。macOSでは、dylibのマッピングはカーネルモードではなく、**ユーザーモード**で行われる点に注意が必要です。

### **`LC_IDENT`**

現在は廃止されていますが、panic時にダンプを生成するよう設定されている場合、Mach-O core dumpが作成され、カーネルバージョンが`LC_IDENT`コマンドに設定されます。

### **`LC_UUID`**

ランダムなUUIDです。直接的な用途はありませんが、XNUはプロセス情報とともにこれをキャッシュします。クラッシュレポートで使用されることがあります。

### **`LC_BUILD_VERSION`**

最新のバイナリでは通常、このコマンドを使って**対象プラットフォーム**、**最小OSバージョン**、**SDKバージョン**、および任意でそのスライスのビルドに使用した**ツールのバージョン**を宣言します。攻撃やリバースの観点では、サンプルのビルド方法を特定したり、スライスごとに異なるSDKやdeployment targetでコンパイルされた不審なuniversal binaryを素早く見つけたりするのに非常に役立ちます。古いバイナリでは、代わりに`LC_VERSION_MIN_*`が使われている場合があります。

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

プロセスの実行前に dyld に環境変数を指定できます。プロセス内で任意のコードを実行できてしまう可能性があるため、非常に危険です。そのため、このロードコマンドは `#define SUPPORT_LC_DYLD_ENVIRONMENT` が定義された dyld ビルドでのみ使用され、さらに処理対象はロードパスを指定する `DYLD_..._PATH` 形式の変数に限定されます。

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

最近のツールチェーンでは、古い `LC_DYLD_INFO[_ONLY]` opcode だけに頼らず、これらのコマンドに export/bind/rebase メタデータを格納することがよくあります。どちらも **`__LINKEDIT`** 内の領域を指す `linkedit_data_command` エントリです。

- **`LC_DYLD_EXPORTS_TRIE`**: イメージが export するシンボルを格納したコンパクトな trie。
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld が rebase と bind を適用するために使う、セグメントごとの fixup chain。Apple Silicon では、現代的な認証付きポインターの fixup の多くもここにあります。

このメタデータは、import/export の再構築、`@rpath` でロードされた依存関係がそのように解決された理由の理解、または現代の `arm64e` ターゲットで hook/rebinding の試みが失敗した理由の特定にとても役立ちます。`dyld_info` は、ディスク上に単独のファイルとして存在しない **cache-only dylib パス** に対しても使用できます。多くのシステムライブラリが共有キャッシュ内にのみ存在する現代の macOS では、これは非常に便利です。<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

この新しいロードコマンドは、主に**kernel collections / kernelcache形式のfileset**を調査する際に関係します。単独のイメージを表すのではなく、外側のMach-Oがコンテナとして機能し、各`LC_FILESET_ENTRY`が、独自のパス形式の**entry id**、VMアドレス、ファイルオフセットを持つ埋め込みMach-Oを指します。最新のmacOS/iOSのカーネルコンポーネントをリバースする場合、このコマンドが、トップレベルのコンテナと抽出または逆アセンブルしたい実際のイメージをつなぐ役割を果たすことがよくあります。

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

実践的な抽出ワークフローについては、[macOS kernel extensions and kernelcache に関するこちらのページ](../mac-os-architecture/macos-kernel-extensions.md)を確認してください。

### **`LC_LOAD_DYLIB`**

この load command は、**dynamic** **library** の依存関係を記述し、**loader**（dyld）にその **library をロードしてリンクするよう指示**します。Mach-O binary が必要とする **各 library に対して**、`LC_LOAD_DYLIB` load command が存在します。

- この load command は、型が **`dylib_command`** の構造体です（実際に依存する dynamic library を記述する struct dylib を含みます）。

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t 互換性バージョン; / ライブラリの互換性バージョン番号 /](<../../../images/image (486).png>)

この情報は、次の CLI コマンドでも取得できます:

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
- **CoreWLAN**: Wi-Fiスキャン

> [!TIP]
> Mach-Oバイナリには、**1つ以上の** **コンストラクタ**を含めることができ、**LC_MAIN**で指定されたアドレスより前に**実行**されます。\
> コンストラクタのオフセットは、**\_\_DATA_CONST**セグメントの**\_\_mod_init_func**セクションに格納されています。

## **Mach-Oデータ**

ファイルの中心にはデータ領域があり、これはload-commands領域で定義された複数のセグメントで構成されています。**各セグメントにはさまざまなデータセクションを格納でき**、各セクションには特定の種類の**コードまたはデータ**が格納されます。

> [!TIP]
> データは基本的に、load commands **LC_SEGMENTS_64**によって読み込まれるすべての**情報**を含む部分です。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

これには次のものが含まれます。

- **関数テーブル:** プログラムの関数に関する情報を格納します。
- **シンボルテーブル**: バイナリが使用する外部関数に関する情報を含みます。
- 内部関数や変数の名前などが含まれる場合もあります。

確認には[**Mach-O View**](https://sourceforge.net/projects/machoview/)ツールを使用できます。

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

またはCLIから確認できます。

```bash
size -m /bin/ls
```

### 追記データと逆方向に解析されるオーバーレイ

loaderは、名前付きMach-Oセクションではなく、追記データ内に設定を保持できます。その後、reverse parserは末尾のマーカーを基点にし、その直前に保存されたサイズを読み取り、その値を使って先行するblobの位置を特定して復号します。観測されたuniversal loaderの1つは、XOR暗号化されたダウンローダーURLにこのレイアウトを使用していました:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

見慣れない binary を解析するときは、認識可能な終端マーカーの周辺のバイトを調べ、文字列や設定が load-command セクションに属すると決めつける前に、サイズを逆算する処理をすべて追跡してください。マーカーと XOR キーはサンプル固有です。再利用できる手法は、自己記述型トレーラーです。

## Objective-C の一般的なセクション

`__TEXT` セグメント (r-x):

- `__objc_classname`: クラス名 (文字列)
- `__objc_methname`: メソッド名 (文字列)
- `__objc_methtype`: メソッド型 (文字列)

`__DATA` セグメント (rw-):

- `__objc_classlist`: すべての Objective-C クラスへのポインター
- `__objc_nlclslist`: Non-Lazy Objective-C クラスへのポインター
- `__objc_catlist`: Categories へのポインター
- `__objc_nlcatlist`: Non-Lazy Categories へのポインター
- `__objc_protolist`: Protocols のリスト
- `__objc_const`: 定数データ
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

こちらも参照: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata)。

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-O のスライスは、考えているほど単純ではない](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) の man ページ](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [自分自身の Entitlements を読み取る](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` および `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - MacSync macOS stealer の新バージョン、暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
