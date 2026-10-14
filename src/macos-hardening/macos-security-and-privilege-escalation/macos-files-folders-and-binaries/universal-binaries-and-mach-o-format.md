# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOS は **Mach-O** 実行ファイル形式を使用します。**universal**、または fat binary は、複数のアーキテクチャ固有の Mach-O スライスを1つのファイルに含みます。Apple のオープンソースヘッダー `fat.h` と `loader.h` では、このページで説明する構造体と定数が定義されています。 <sup>[[5]](#references)</sup>

Mach-O イメージは次の要素で構成されます。

- ヘッダー
- Load Commands
- データ

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

ヘッダーには **magic** バイトがあり、その後にファイルに**含まれる** **arch** の**数**（`nfat_arch`）が続きます。各 arch は `fat_arch` 構造体を持ちます。

次のコマンドで確認できます。

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

または、[Mach-O View](https://sourceforge.net/projects/machoview/) ツールを使用します。

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

ご想像のとおり、通常、2つのアーキテクチャ向けにコンパイルされた universal binary は、1つの arch 向けにコンパイルされたものの**2倍のサイズ**になります。

> [!TIP]
> マルウェアや不審なアプリを調査するときは、`file` が「最適な」アーキテクチャを報告しただけで確認を終えないでください。universal binary では、スライスごとに異なる imports、load commands、コンパイラメタデータが隠されていることがあります。まず**すべての**スライスを列挙し、その後、それぞれを個別に調査してください。

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Recent macOS SDKでは、`<mach-o/utils.h>`内の`macho_for_each_slice()`や`macho_best_slice()`などのヘルパーも公開されています。後者はdyld/kernelが読み込むものを再現するのに便利ですが、スキャナーではアーキテクチャ固有のコンテンツを見落とさないよう、すべてのスライスを反復処理する必要があります。<sup>[[1]](#references)</sup>

## **Mach-O ヘッダー**

ヘッダーには、ファイルがMach-Oファイルであることを識別するマジックバイトや、ターゲットアーキテクチャに関する情報など、ファイルの基本情報が含まれています。次のコマンドで確認できます: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

さまざまなファイルタイプがあり、[**たとえばこちらのソースコード**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)で定義されています。主なものは次のとおりです。

- `MH_OBJECT`: 再配置可能なオブジェクトファイル（コンパイルの中間生成物で、まだ実行ファイルではありません）。
- `MH_EXECUTE`: 実行ファイル。
- `MH_FVMLIB`: 固定 VM ライブラリファイル。
- `MH_CORE`: コードダンプ。
- `MH_PRELOAD`: プリロードされた実行ファイル（XNU ではサポートされなくなっています）。
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: 「プラグインファイル」。gcc の `-bundle` を使って生成され、`NSBundle` または `dlopen` によって明示的に読み込まれます。
- `MH_DYSM`: 対応する `.dSym` ファイル（デバッグ用のシンボルを含むファイル）。
- `MH_KEXT_BUNDLE`: Kernel Extensions。

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

または [Mach-O View](https://sourceforge.net/projects/machoview/) を使います:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O フラグ**

ソースコードでは、ライブラリのロードに役立つフラグもいくつか定義されています:

- `MH_NOUNDEFS`: 未定義の参照なし（完全にリンク済み）
- `MH_DYLDLINK`: Dyld によるリンク
- `MH_PREBOUND`: 動的参照が事前にバインドされている。
- `MH_SPLIT_SEGS`: ファイルが読み取り専用セグメントと読み書き可能セグメントに分割されている。
- `MH_WEAK_DEFINES`: バイナリに weak 定義シンボルがある
- `MH_BINDS_TO_WEAK`: バイナリが weak シンボルを使用する
- `MH_ALLOW_STACK_EXECUTION`: スタックを実行可能にする
- `MH_NO_REEXPORTED_DYLIBS`: ライブラリに LC_REEXPORT コマンドがない
- `MH_PIE`: 位置独立実行ファイル
- `MH_HAS_TLV_DESCRIPTORS`: スレッドローカル変数を含むセクションがある
- `MH_NO_HEAP_EXECUTION`: ヒープ/データページでの実行を禁止する
- `MH_HAS_OBJC`: バイナリに Objective-C セクションがある
- `MH_SIM_SUPPORT`: シミュレーターをサポートする
- `MH_DYLIB_IN_CACHE`: 共有ライブラリキャッシュ内の dylib/framework で使用される。

## **Mach-O ロードコマンド**

ここでは**メモリ内のファイルレイアウト**を指定します。**シンボルテーブルの位置**、実行開始時のメインスレッドのコンテキスト、必要な**共有ライブラリ**について詳しく記述します。バイナリをメモリにロードするプロセスについて、動的ローダー **(dyld)** への命令が記述されています。

Mach-O は、前述の **`loader.h`** で定義されている **load_command** 構造体を使用します:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

システムが異なる方法で処理する **ロードコマンドの種類は約50種類**あります。最も一般的なものは、`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`、`LC_CODE_SIGNATURE` です。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本的に、このタイプのロードコマンドは、バイナリの実行時にデータセクションで示された**オフセット**に従って、**\_\_TEXT**（実行コード）と**\_\_DATA**（プロセスのデータ）**セグメントをどのようにロードするか**を定義します。

これらのコマンドは、プロセスの実行時にその**仮想メモリ空間にマッピングされるセグメント**を定義します。

**\_\_TEXT** セグメント（プログラムの実行コードを格納）や、プロセスが使用するデータを含む **\_\_DATA** セグメントなど、**さまざまな種類**のセグメントがあります。これらの**セグメントは Mach-O ファイルのデータセクションに配置されています**。

**各セグメント**は、さらに複数の**セクション**に**分割**できます。**ロードコマンドの構造**には、それぞれのセグメント内にある**これらのセクションに関する情報**が含まれています。

ヘッダーの最初にあるのは、**セグメントヘッダー**です。

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

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

このヘッダーは、**その後にヘッダーが続くセクションの数**を定義します。

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

**セクションオフセット** (0x37DC) と、この場合は `0x18000` の **arch の開始位置のオフセット**を足すと、`0x37DC + 0x18000 = 0x1B7DC` になります。

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**ヘッダー情報**は、次のように**コマンドライン**から取得することもできます。

```bash
otool -lv /bin/ls
```

このコマンドで読み込まれる一般的なセグメント:

- **`__PAGEZERO`:** カーネルに対し、**アドレス0**を**マップ**し、そこからの**読み取り、書き込み、実行を禁止**するよう指示します。構造体内のmaxprot変数とminprot変数は0に設定され、このページに**読み取り・書き込み・実行の権限がない**ことを示します。
  - この割り当ては、**NULLポインタのデリファレンス脆弱性を緩和する**うえで重要です。これは、XNUがハードページゼロを強制し、メモリの最初のページ（最初のページのみ）をアクセス不可にするためです（i386を除く）。バイナリは、小さな \_\_PAGEZERO（`-pagezero_size` を使用）を作成して最初の4kをカバーし、残りの32bitメモリをユーザーモードとカーネルモードの両方からアクセス可能にすることで、この要件を満たせます。
- **`__TEXT`**: **読み取り**および**実行**権限を持つ**実行可能**な**コード**（書き込み不可）を含みます。このセグメントの一般的なセクション:
  - `__text`: コンパイルされたバイナリコード
  - `__const`: 定数データ（読み取り専用）
  - `__[c/u/os_log]string`: C、Unicode、またはosログの文字列定数
  - `__stubs`および`__stubs_helper`: 動的ライブラリの読み込みプロセスで使用
  - `__unwind_info`: スタックのアンワインドデータ。
  - これらのコンテンツはすべて署名されていますが、実行可能としてもマークされている点に注意してください（文字列専用セクションのように、必ずしもこの権限を必要としないセクションを悪用する選択肢が増えます）。
- **`__DATA`**: **読み取り**および**書き込み**可能なデータ（実行不可）を含みます。
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Non lazy（ロード時にbind）シンボルポインタ
  - `__la_symbol_ptr`: Lazy（使用時にbind）シンボルポインタ
  - `__const`: 読み取り専用データであるべきもの（実際はそうではない）
  - `__cfstring`: CoreFoundation文字列
  - `__data`: グローバル変数（初期化済み）
  - `__bss`: 静的変数（未初期化）
  - `__objc_*` (\_\_objc_classlist、\_\_objc_protolistなど): Objective-Cランタイムが使用する情報
- **`__DATA_CONST`**: \_\_DATA.\_\_constは定数であることが保証されておらず（書き込み権限があります）、他のポインタやGOTも同様です。このセクションでは、`mprotect`を使って、`__const`、一部のイニシャライザ、および解決後のGOTテーブルを**読み取り専用**にします。
- **`__AUTH` / `__AUTH_CONST`**: 最近のApple Siliconバイナリで一般的です。これらのセグメントには、ロード時または使用時に認証が必要なポインタ（例: `__auth_got`）が格納されます。リバインド、フック、インポートパッチの手法が従来の`__got` / `__la_symbol_ptr`セクションしかチェックしない場合、最新の`arm64e`バイナリにある実際の呼び出し箇所を見落とす可能性があります。これらのセクションの詳細は[こちらのページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。
- **`__LINKEDIT`**: シンボル、文字列、再配置テーブルのエントリなど、リンカー（dyld）のための情報を含みます。`__TEXT`にも`__DATA`にも含まれないコンテンツを格納する汎用コンテナで、その内容は他のロードコマンドで記述されます。
  - dyld情報: Rebase、Non-lazy/lazy/weak binding opcode、エクスポート情報
  - Functions starts: 関数の開始アドレスのテーブル
  - Data In Code: \_\_text内のデータ領域
  - Symbol Table: バイナリ内のシンボル
  - Indirect Symbol Table: ポインタ／スタブのシンボル
  - String Table
  - Code Signature
- **`__OBJC`**: Objective-Cランタイムが使用する情報を含みます。ただし、この情報は\_\_DATAセグメント内のさまざまな\_\_objc\_\*セクションにも存在する場合があります。
- **`__RESTRICT`**: **`__restrict`**という単一のセクション（これも空）を持つ空のセグメントで、バイナリの実行時にDYLD環境変数を無視させます。

コードで確認できたように、**セグメントはフラグにも対応しています**（ただし、あまり使われません）。

- `SG_HIGHVM`: Core専用（未使用）
- `SG_FVMLIB`: 未使用
- `SG_NORELOC`: セグメントに再配置がない
- `SG_PROTECTED_VERSION_1`: 暗号化。たとえばFinderがテキストの`__TEXT`セグメントを暗号化するために使用します。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**には、**entryoff属性にエントリポイント**が含まれます。ロード時に**dyld**はこの値を（メモリ上の）**バイナリのベースアドレスに単純に加算**し、その後、その命令に**ジャンプ**してバイナリのコード実行を開始します。

**`LC_UNIXTHREAD`**には、メインスレッドの開始時にレジスタが持つべき値が含まれます。これはすでに非推奨ですが、**`dyld`**は今でも使用しています。これによって設定されるレジスタの値は、次のコマンドで確認できます。

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


Mach-Oファイルの**コード署名に関する情報**を含みます。含まれるのは、**署名 blob を指す** **オフセット**のみです。通常、これはファイルの末尾にあります。\
このセクションの詳細については、[**こちらのブログ記事**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)と[**こちらの gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)をご覧ください。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

バイナリ暗号化をサポートします。ただし、当然ながら、攻撃者がプロセスを侵害できれば、メモリを暗号化されていない状態でダンプできます。

### **`LC_LOAD_DYLINKER`**

共有ライブラリをプロセスのアドレス空間にマッピングする**dynamic linker 実行ファイルへのパス**を含みます。**値は常に `/usr/lib/dyld` に設定されています**。macOSでは、dylibのマッピングはカーネルモードではなく、**ユーザーモード**で行われる点に注意が必要です。

### **`LC_IDENT`**

これは廃止されていますが、panic時にダンプを生成するよう設定されている場合、Mach-O core dumpが作成され、カーネルのバージョンが`LC_IDENT`コマンドに設定されます。

### **`LC_UUID`**

ランダムなUUIDです。直接的な用途はほとんどありませんが、XNUは他のプロセス情報とともにこれをキャッシュします。クラッシュレポートで使用されることがあります。

### **`LC_BUILD_VERSION`**

最近のバイナリには通常、**対象プラットフォーム**、**最小OSバージョン**、**SDKバージョン**、および任意でそのsliceのビルドに使用した**ツールのバージョン**を宣言するこのコマンドが含まれています。攻撃やリバースの観点では、サンプルのビルド方法を特定し、異なるSDKやdeployment targetでコンパイルされたsliceを含む不審なuniversal binaryを素早く見つけるのに役立ちます。古いバイナリでは、代わりに`LC_VERSION_MIN_*`が使われている場合があります。

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

プロセスの実行前に、dyld に環境変数を指定できます。プロセス内で任意のコードを実行できる可能性があるため、これは非常に危険です。そのため、この load command は `#define SUPPORT_LC_DYLD_ENVIRONMENT` を指定してビルドされた dyld でのみ使用され、さらに処理対象はロードパスを指定する `DYLD_..._PATH` 形式の変数に限定されています。

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

最近の toolchain では、古い `LC_DYLD_INFO[_ONLY]` の opcode だけに依存せず、これらの command に export/bind/rebase のメタデータを格納することがよくあります。どちらも **`__LINKEDIT`** 内を指す `linkedit_data_command` エントリです。

- **`LC_DYLD_EXPORTS_TRIE`**: イメージが export するシンボルを格納したコンパクトな trie。
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld が rebase と bind を適用するために使う、セグメントごとの fixup chain。Apple Silicon では、最新の authenticated pointer fixup の多くもここにあります。

このメタデータは、import/export の再構築、`@rpath` でロードされた依存関係がそのように解決された理由の把握、または最新の `arm64e` ターゲットで hook/rebinding が失敗した理由の特定に非常に役立ちます。`dyld_info` は、ディスク上に単独ファイルとして存在しない **cache-only dylib path** に対しても使用できます。多くのシステムライブラリが shared cache 内にのみ存在する最近の macOS では、これは非常に便利です。<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

この現代的なロードコマンドは、主に**kernel collections / kernelcache-style filesets**の調査で重要になります。単独のイメージを表すのではなく、外側のMach-Oがコンテナとして機能し、各`LC_FILESET_ENTRY`が、それぞれ独自のパス形式の**entry id**、VMアドレス、ファイルオフセットを持つ埋め込みMach-Oを指します。現代のmacOS/iOSのカーネルコンポーネントをリバースエンジニアリングする場合、このコマンドは、最上位のコンテナと、抽出または逆アセンブルしたい実際のイメージをつなぐ役割を果たすことがよくあります。

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

実用的な抽出ワークフローについては、[macOS kernel extensions and kernelcache に関するこちらのページ](../mac-os-architecture/macos-kernel-extensions.md)を確認してください。

### **`LC_LOAD_DYLIB`**

このロードコマンドは、**動的**な**ライブラリ**依存関係を記述し、**ローダー**（dyld）に**そのライブラリをロードしてリンクするよう指示**します。Mach-O binary が必要とする**各ライブラリに対して**、`LC_LOAD_DYLIB` ロードコマンドがあります。

- このロードコマンドは **`dylib_command`** 型の構造体です（実際に依存する動的ライブラリを記述する struct dylib を含みます）。

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t 互換性バージョン; / ライブラリの互換性バージョン /](<../../../images/image (486).png>)

この情報は、CLIから取得することもできます。

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
- **CoreWLAN**: Wi-Fiスキャン。

> [!TIP]
> Mach-Oバイナリには1つまたは**複数の** **コンストラクタ**を含めることができ、これらは**LC_MAIN**で指定されたアドレスより**前に実行**されます。\
> コンストラクタのオフセットは、**\_\_DATA_CONST**セグメント内の**\_\_mod_init_func**セクションに格納されています。

## **Mach-Oデータ**

ファイルの中心にはデータ領域があり、これはload-commands領域で定義された複数のセグメントで構成されています。**各セグメントにはさまざまなデータセクションを格納でき**、各セクションには特定の種類の**コードまたはデータ**が含まれます。

> [!TIP]
> データとは基本的に、load commands **LC_SEGMENTS_64**によって読み込まれるすべての**情報**を含む部分です。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

これには次のものが含まれます。

- **関数テーブル:** プログラムの関数に関する情報を格納します。
- **シンボルテーブル**: バイナリが使用する外部関数に関する情報を含みます。
- 内部関数や変数名などが含まれる場合もあります。

確認するには、[**Mach-O View**](https://sourceforge.net/projects/machoview/)ツールを使用できます。

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

またはCLIから:

```bash
size -m /bin/ls
```

### 追記データと逆方向に解析されるオーバーレイ

loaderは、名前付きのMach-Oセクションではなく、追記データに設定情報を保持できます。reverse parserは、末尾のマーカーを基点にして、その直前に格納されたサイズを読み取り、その値を使って直前のblobを特定し、復号します。あるuniversal loaderでは、XOR暗号化されたdownloader URLにこのレイアウトが使われていました:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

見慣れないバイナリをリバースする際は、認識可能な終端マーカーの周辺のバイトを調べ、文字列や設定がロードコマンドのセクションに属すると決めつける前に、サイズを逆算する処理をすべて追跡してください。マーカーと XOR key はサンプル固有ですが、応用できる手法は自己記述型のトレーラーです。

## Objective-Cの一般的なセクション

`__TEXT` segment (r-x) 内:

- `__objc_classname`: クラス名 (strings)
- `__objc_methname`: メソッド名 (strings)
- `__objc_methtype`: メソッド型 (strings)

`__DATA` segment (rw-) 内:

- `__objc_classlist`: すべての Objective-C クラスへのポインター
- `__objc_nlclslist`: Non-Lazy Objective-C クラスへのポインター
- `__objc_catlist`: Categories へのポインター
- `__objc_nlcatlist`: Non-Lazy Categories へのポインター
- `__objc_protolist`: Protocols のリスト
- `__objc_const`: 定数データ
- `__objc_imageinfo`、`__objc_selrefs`、`objc__protorefs`...

## Swift

- `_swift_typeref`、`_swift3_capture`、`_swift3_assocty`、`_swift3_types`、`_swift3_proto`、`_swift3_fieldmd`、`_swift3_builtin`、`_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-Oのスライスは、思っているほど単純ではない](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) manページ](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [自分のEntitlementsを読む](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` と `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - MacSync macOS stealerの新バージョンが暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
