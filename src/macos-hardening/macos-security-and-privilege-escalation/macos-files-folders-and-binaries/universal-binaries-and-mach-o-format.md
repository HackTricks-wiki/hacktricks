# macOS Universal binaries と Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOS は **Mach-O** 実行ファイル形式を使用します。**universal**（fat）binary は、複数のアーキテクチャ固有の Mach-O slice を1つのファイルに含みます。Apple のオープンソースヘッダー `fat.h` と `loader.h` では、このページで説明する構造体と定数が定義されています。 <sup>[[5]](#references)</sup>

Mach-O image は次の要素で構成されます。

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

Header には **magic** bytes があり、その後にファイルに**含まれる** **arch** の**数** (`nfat_arch`) が続きます。各 arch には `fat_arch` struct があります。

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

または、[Mach-O View](https://sourceforge.net/projects/machoview/) tool を使用します。

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

通常、2つのアーキテクチャ向けにコンパイルされた universal binary は、1つの arch のみを対象にコンパイルされたものの**2倍のサイズ**になると考えられます。

> [!TIP]
> malware や不審なアプリをトリアージする際は、`file` が「最適な」アーキテクチャを報告しただけで調査を終えないでください。universal binary の各 slice で imports、load commands、compiler metadata が異なる場合があります。まず**すべての** slice を列挙し、その後それぞれを個別に調べてください。

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

最近の macOS SDK では、`<mach-o/utils.h>` の `macho_for_each_slice()` と `macho_best_slice()` も公開されています。Apple Silicon では、macOS 15 より前のバージョンで、`macho_best_slice()` が実行可能なサードパーティ製 `arm64` バイナリに対して誤って `EBADARCH` を返す場合がありました。この API は macOS 15 で修正されました。すべてのスライスを一覧表示するには、`macho_for_each_slice()` または `lipo -archs` を使用してください。最適なスライスの検索に失敗したことを、実行可能なスライスがない証拠として扱わないでください。<sup>[[1]](#references)[[7]](#references)</sup>

### スライス間でコード署名を比較する

ユニバーサルバイナリの各アーキテクチャには、それぞれ独自の CodeDirectory と CDHash があります。署名済みの実行ファイルや特権ヘルパーを監査する場合は、**各スライスの署名**を調べてください。CDHash が異なるのは正常です。代わりに、署名 ID、CodeDirectory のフラグ、entitlements を比較してください。<sup>[[8]](#references)</sup>

CDHash に一致するポリシーでは、1つのハッシュが識別するのは、アーキテクチャ固有の実行経路1つだけです。Apple は、スライスを列挙し、それぞれを調べるために `codesign --arch` を使用することを推奨しています。<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

署名構造と検証の詳細については、[macOS Code Signing](../macos-security-protections/macos-code-signing.md)を参照してください。

## **Mach-O Header**

ヘッダーには、ファイルがMach-Oファイルであることを識別するmagic bytesや、ターゲットアーキテクチャに関する情報など、ファイルの基本情報が含まれています。次の場所で確認できます: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

### Mach-O ファイルの種類

ファイルの種類はいくつかあり、[**ソースコードの例はこちら**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)で定義を確認できます。主なものは次のとおりです。

- `MH_OBJECT`: 再配置可能なオブジェクトファイル（コンパイルの中間生成物で、まだ実行可能ファイルではありません）。
- `MH_EXECUTE`: 実行可能ファイル。
- `MH_FVMLIB`: 固定 VM ライブラリファイル。
- `MH_CORE`: コアダンプ。
- `MH_PRELOAD`: プリロードされた実行可能ファイル（XNUではサポートされなくなりました）。
- `MH_DYLIB`: Dynamic Libraries。
- `MH_DYLINKER`: Dynamic Linker。
- `MH_BUNDLE`: 「プラグインファイル」。gccで `-bundle` を使用して生成され、`NSBundle` または `dlopen` によって明示的に読み込まれます。
- `MH_DSYM`: 対応する `.dSYM` ファイル（デバッグ用のシンボルを含むファイル）。
- `MH_KEXT_BUNDLE`: Kernel Extensions。

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

または [Mach-O View](https://sourceforge.net/projects/machoview/) を使用します。

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-Oフラグ**

ソースコードでは、ライブラリの読み込みに役立ついくつかのフラグも定義されています。

- `MH_NOUNDEFS`: 未定義参照なし（完全にリンク済み）
- `MH_DYLDLINK`: Dyldリンク
- `MH_PREBOUND`: 動的参照が事前にバインドされている
- `MH_SPLIT_SEGS`: ファイルが読み取り専用セグメントと読み書き可能セグメントに分割されている
- `MH_WEAK_DEFINES`: バイナリに弱い定義のシンボルがある
- `MH_BINDS_TO_WEAK`: バイナリが弱いシンボルを使用する
- `MH_ALLOW_STACK_EXECUTION`: スタックを実行可能にする
- `MH_NO_REEXPORTED_DYLIBS`: ライブラリにLC_REEXPORTコマンドがない
- `MH_PIE`: 位置独立実行ファイル
- `MH_HAS_TLV_DESCRIPTORS`: スレッドローカル変数を含むセクションがある
- `MH_NO_HEAP_EXECUTION`: ヒープ／データページでの実行なし
- `MH_HAS_OBJC`: バイナリにObjective-Cセクションがある
- `MH_SIM_SUPPORT`: シミュレーターをサポート
- `MH_DYLIB_IN_CACHE`: 共有ライブラリキャッシュ内のdylib／frameworkで使用される

## **Mach-Oロードコマンド**

ここでは、**ファイルのメモリ上のレイアウト**を指定します。これには、**シンボルテーブルの位置**、実行開始時のメインスレッドの状態、必要な**共有ライブラリ**が含まれます。バイナリをメモリに読み込む際の処理について、動的ローダー**（dyld）**に指示します。

ここでは、言及されている **`loader.h`** で定義された **load_command** 構造体を使用します。

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

システムが異なる方法で処理する Load Command は約 **50種類**あります。最も一般的なものは、`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`、`LC_CODE_SIGNATURE` です。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本的に、この種類の Load Command は、バイナリの実行時に Data セクションで示される **オフセット**に従って、**\_\_TEXT**（実行コード）および **\_\_DATA**（プロセスのデータ）**セグメント**をどのようにロードするかを定義します。

これらのコマンドは、プロセスの実行時にプロセスの**仮想メモリ空間**に**マッピング**される**セグメント**を定義します。

**\_\_TEXT**セグメント（プログラムの実行コードを格納）や、**\_\_DATA**セグメント（プロセスが使用するデータを格納）など、**さまざまな種類**のセグメントがあります。これらの**セグメントは Mach-O ファイルのデータセクション内にあります**。

**各セグメント**はさらに複数の**セクション**に**分割**できます。**Load Command の構造体**には、各セグメント内の**これらのセクションに関する情報**が含まれています。

ヘッダーでは、まず**セグメントヘッダー**を確認できます。

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

このヘッダーは、その後にヘッダーが続くセクションの**数**を定義します。

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

**section offset**（0x37DC）に、この場合は`0x18000`となる**arch starts**の位置の**offset**を足します --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

次のコマンドラインを使って、**headers information**を取得することもできます:

```bash
otool -lv /bin/ls
```

この cmd でロードされる一般的なセグメント:

- **`__PAGEZERO`:** カーネルに対し、**アドレス 0** を **マップ** し、そこからの **読み取り、書き込み、実行をすべて禁止** するよう指示します。構造体内の maxprot と minprot 変数はゼロに設定され、このページには **読み取り・書き込み・実行の権限がない** ことを示します。
  - この割り当ては、**NULL pointer dereference の脆弱性を緩和する** ために重要です。これは、XNU が最初のメモリページ（最初のページのみ）をアクセス不能にする hard page zero を強制するためです（i386 を除く）。バイナリは、小さな \_\_PAGEZERO（`-pagezero_size` を使用）を作成して最初の 4k をカバーし、残りの 32bit メモリをユーザーモードとカーネルモードの両方からアクセス可能にすることで、この要件を満たせます。
- **`__TEXT`**: **読み取り** と **実行** の権限を持つ **実行可能** な **コード** を格納します（書き込み不可）**。** このセグメントの一般的なセクション:
  - `__text`: コンパイル済みバイナリコード
  - `__const`: 定数データ（読み取り専用）
  - `__[c/u/os_log]string`: C、Unicode、または os logs の文字列定数
  - `__stubs` と `__stubs_helper`: dynamic library のロード処理中に使用される
  - `__unwind_info`: スタック unwind データ。
  - これらの内容はすべて署名されている一方、実行可能としてマークされている点に注意してください（文字列専用セクションなど、この権限を必ずしも必要としないセクションの exploitation にも選択肢が増えます）。
- **`__DATA`**: **読み取り可能** かつ **書き込み可能** なデータを格納します（実行不可）**。**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: 非 lazy（ロード時に bind）シンボルポインター
  - `__la_symbol_ptr`: lazy（使用時に bind）シンボルポインター
  - `__const`: 読み取り専用データであるべき（実際はそうではない）
  - `__cfstring`: CoreFoundation 文字列
  - `__data`: グローバル変数（初期化済み）
  - `__bss`: static 変数（未初期化）
  - `__objc_*` (\_\_objc_classlist、\_\_objc_protolist など): Objective-C runtime が使用する情報
- **`__DATA_CONST`**: \_\_DATA.\_\_const は定数であるとは限らず（書き込み権限があります）、他のポインターや GOT も同様です。このセクションは `mprotect` を使用して、`__const`、一部の initializer、および GOT table（解決後）を **読み取り専用** にします。
- **`__AUTH` / `__AUTH_CONST`**: 最近の Apple Silicon バイナリで一般的です。これらのセグメントには、ロード時または使用時に認証が必要なポインター（たとえば `__auth_got`）が格納されます。rebinding、hook、import-patching の手法で従来の `__got` / `__la_symbol_ptr` セクションしかチェックしない場合、最新の `arm64e` バイナリにおける実際の call site を見落とす可能性があります。これらのセクションの詳細は[このページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。
- **`__LINKEDIT`**: symbol、string、relocation table のエントリーなど、linker（dyld）向けの情報を格納します。`__TEXT` や `__DATA` に含まれない内容を収める汎用コンテナで、その内容は他の load command で記述されます。
  - dyld 情報: Rebase、Non-lazy/lazy/weak binding opcode、export 情報
  - Functions starts: 関数の開始アドレスの table
  - Data In Code: \_\_text 内のデータ領域
  - Symbol Table: バイナリ内のシンボル
  - Indirect Symbol Table: ポインター/stub シンボル
  - String Table
  - Code Signature
- **`__OBJC`**: Objective-C runtime が使用する情報を格納します。ただし、この情報は \_\_DATA セグメント内のさまざまな \_\_objc\_\* セクションにも含まれている場合があります。
- **`__RESTRICT`**: **`__restrict`** という単一のセクションを持つ（こちらも空の）内容のないセグメントで、バイナリ実行時に DYLD 環境変数を無視するようにします。

コードで確認できるように、**セグメントはフラグもサポートしています**（ただし、あまり使われていません）。

- `SG_HIGHVM`: Core 専用（未使用）
- `SG_FVMLIB`: 未使用
- `SG_NORELOC`: セグメントに relocation がない
- `SG_PROTECTED_VERSION_1`: 暗号化。たとえば Finder がテキストの `__TEXT` セグメントを暗号化するために使用します。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** は **entryoff 属性に** entrypoint を格納します。ロード時に **dyld** はこの値を（メモリ上の）**バイナリのベースアドレスに** 単純に **加算** し、バイナリのコードの実行を開始するために、この命令へ **ジャンプ** します。

**`LC_UNIXTHREAD`** は、main thread の開始時にレジスターが持つべき値を格納します。これはすでに deprecated ですが、**`dyld`** は現在も使用しています。これによって設定されたレジスターの値は、次のコマンドで確認できます:

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


**Mach-Oファイルのコード署名**に関する情報を含みます。含まれるのは、**署名blobを指す****オフセット**のみです。通常、これはファイルの末尾にあります。\
このセクションの詳細については、[**こちらのブログ記事**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)と[**こちらのgist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)を参照してください。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

バイナリの暗号化をサポートします。ただし、もちろん、攻撃者がプロセスを侵害できれば、暗号化されていない状態のメモリをダンプできます。

### **`LC_LOAD_DYLINKER`**

共有ライブラリをプロセスのアドレス空間にマッピングする**ダイナミックリンカー実行ファイルへのパス**を含みます。**値は常に`/usr/lib/dyld`に設定されます**。macOSでは、dylibのマッピングがカーネルモードではなく**ユーザーモード**で行われる点に注意してください。

### **`LC_IDENT`**

廃止されていますが、パニック時にダンプを生成するよう設定されている場合は、Mach-Oコアダンプが作成され、カーネルバージョンが`LC_IDENT`コマンドに設定されます。

### **`LC_UUID`**

ランダムなUUIDです。直接的な用途はありませんが、XNUはプロセス情報とともにこれをキャッシュします。クラッシュレポートで使用されることがあります。

### **`LC_BUILD_VERSION`**

最近のバイナリでは通常、このコマンドを使って**ターゲットプラットフォーム**、**最小OSバージョン**、**SDKバージョン**、および任意でそのスライスのビルドに使用した**ツールのバージョン**を宣言します。オフェンシブ／リバーシングの観点では、サンプルのビルド方法を特定したり、異なるSDKやデプロイメントターゲットでコンパイルされたスライスを含む不審なユニバーサルバイナリをすばやく見つけたりするのに非常に役立ちます。古いバイナリでは、代わりに`LC_VERSION_MIN_*`が使われる場合があります。

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

プロセスの実行前に dyld に環境変数を指定できます。プロセス内で任意のコードを実行できる可能性があるため、非常に危険です。そのため、この load command は `#define SUPPORT_LC_DYLD_ENVIRONMENT` を指定してビルドされた dyld でのみ使用され、さらに処理対象はロードパスを指定する `DYLD_..._PATH` 形式の変数に限定されます。

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

最近の toolchain では、古い `LC_DYLD_INFO[_ONLY]` opcode だけに頼らず、これらの command に export/bind/rebase のメタデータを格納することがよくあります。どちらも **`__LINKEDIT`** 内のデータを指す `linkedit_data_command` エントリです。

- **`LC_DYLD_EXPORTS_TRIE`**: イメージが export するシンボルを格納したコンパクトな trie。
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld が rebase と bind を適用するための、セグメントごとの fixup chain。Apple Silicon では、現代的な認証付きポインターの fixup も数多くここで確認できます。

このメタデータは、import/export の再構築、`@rpath` でロードされた依存ライブラリがそのように解決された理由の把握、あるいは現代の `arm64e` ターゲットで hook/rebinding が失敗した理由の調査に非常に役立ちます。`dyld_info` は、ディスク上に単独のファイルとして存在しない **cache-only dylib paths** に対しても使用できます。多くのシステムライブラリが shared cache 内にしか存在しない現代の macOS では、これは非常に便利です。<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

この最新の load command は、主に **kernel collections / kernelcache-style fileset** の調査で重要になります。単独のイメージを表すのではなく、外側の Mach-O がコンテナとして機能し、各 `LC_FILESET_ENTRY` が、パスのような **entry id**、VM アドレス、ファイルオフセットを持つ埋め込み Mach-O を指します。最新の macOS/iOS のカーネルコンポーネントをリバースエンジニアリングする場合、このコマンドがトップレベルのコンテナと、抽出または逆アセンブルしたい実際のイメージをつなぐ役割を担うことがよくあります。

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

実践的な抽出ワークフローについては、[macOSのカーネル拡張機能とkernelcacheに関するこちらのページ](../mac-os-architecture/macos-kernel-extensions.md)を確認してください。

### **`LC_LOAD_DYLIB`**

このロードコマンドは、**動的**な**ライブラリ**依存関係を記述し、**ローダー**（dyld）に対して、そのライブラリを**ロードしてリンクするよう指示**します。Mach-Oバイナリが必要とする**各ライブラリに対して**、`LC_LOAD_DYLIB`ロードコマンドが存在します。

- このロードコマンドは、**`dylib_command`**型の構造体です（実際に依存する動的ライブラリを記述するstruct dylibを含みます）。

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

この情報は、CLIからも取得できます:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

マルウェアに関連する可能性のあるライブラリには、次のものがあります。

- **DiskArbitration**: USBドライブの監視
- **AVFoundation:** 音声と動画のキャプチャ
- **CoreWLAN**: Wi-Fiスキャン

> [!TIP]
> Mach-Oバイナリには1つまたは**複数の** **コンストラクタ**を含めることができ、これらは**LC_MAIN**で指定されたアドレスより前に**実行**されます。\
> コンストラクタのオフセットは、**\_\_DATA_CONST**セグメント内の**\_\_mod_init_func**セクションに格納されています。

## **Mach-Oのデータ**

ファイルの中核にはデータ領域があり、これはload-commands領域で定義された複数のセグメントで構成されています。**各セグメントにはさまざまなデータセクションを格納でき**、各セクションには特定の種類の**コードまたはデータ**が格納されます。

> [!TIP]
> データとは基本的に、load commands **LC_SEGMENTS_64**によって読み込まれるすべての**情報**を含む部分です。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

これには次のものが含まれます。

- **関数テーブル:** プログラムの関数に関する情報を保持します。
- **シンボルテーブル**: バイナリが使用する外部関数に関する情報を含みます。
- 内部関数や変数の名前などが含まれる場合もあります。

確認するには、[**Mach-O View**](https://sourceforge.net/projects/machoview/)ツールを使用できます。

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

またはcliから:

```bash
size -m /bin/ls
```

### 追加データと逆方向に解析されるオーバーレイ

ローダーは、名前付きの Mach-O セクションではなく、追加データ内に設定を保持できます。逆方向に解析するパーサーは、トレーラーマーカーを起点にし、その直前に格納されたサイズを読み取って、その値を使って先行する blob の位置を特定し、復号します。確認されたあるユニバーサルローダーは、XOR 暗号化されたダウンローダーの URL にこのレイアウトを使用していました:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

不慣れなバイナリをリバースする際は、見覚えのある終端マーカーの周辺のバイトを調べ、文字列や設定がロードコマンドセクションに属すると決めつける前に、サイズを逆算する処理をすべて追跡してください。マーカーと XOR key はサンプル固有です。再利用できる手法は、自己記述型トレーラーです。

## Objective-C 共通セクション

`__TEXT` セグメント (r-x):

- `__objc_classname`: クラス名 (文字列)
- `__objc_methname`: メソッド名 (文字列)
- `__objc_methtype`: メソッド型 (文字列)

`__DATA` セグメント (rw-):

- `__objc_classlist`: すべての Objective-C クラスへのポインター
- `__objc_nlclslist`: Non-Lazy Objective-C クラスへのポインター
- `__objc_catlist`: Categories へのポインター
- `__objc_nlcatlist`: Non-Lazy Categories へのポインター
- `__objc_protolist`: Protocols リスト
- `__objc_const`: 定数データ
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

こちらも参照: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Mach-O のスライスは、思ったほど単純ではない](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) の man ページ](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [自分の Entitlements を読む](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple オープンソース - Mach-O `fat.h` と `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - MacSync macOS stealer の新バージョン、暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
- [7] [The Art of Mac Malware, Volume 2 — バイナリの解析](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: コード署名の内部: ハッシュ](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — アプリとバイナリの許可と拒否](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
