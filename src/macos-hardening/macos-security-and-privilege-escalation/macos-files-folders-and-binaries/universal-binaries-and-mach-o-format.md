# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Mac OSのバイナリは通常、**ユニバーサルバイナリ**としてコンパイルされます。**ユニバーサルバイナリ**は**同じファイル内で複数のアーキテクチャをサポート**できます。

これらのバイナリは**Mach-O構造**に従い、基本的には以下で構成されています：

- ヘッダー
- ロードコマンド
- データ

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## ファットヘッダー

ファイルを検索するには： `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGICまたはFAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* 後に続く構造体の数 */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* CPU指定子 (int) */
cpu_subtype_t	cpusubtype;	/* マシン指定子 (int) */
uint32_t	offset;		/* このオブジェクトファイルへのファイルオフセット */
uint32_t	size;		/* このオブジェクトファイルのサイズ */
uint32_t	align;		/* 2の累乗としてのアライメント */
};
</code></pre>

ヘッダーには**マジック**バイトがあり、その後にファイルが**含む**アーキテクチャの**数**（`nfat_arch`）が続き、各アーキテクチャには`fat_arch`構造体があります。

次のコマンドで確認できます：

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

または、[Mach-O View](https://sourceforge.net/projects/machoview/)ツールを使用して：

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

おそらく考えているように、通常、2つのアーキテクチャ用にコンパイルされたユニバーサルバイナリは、1つのアーキテクチャ用にコンパイルされたものの**サイズを倍増**させます。

## **Mach-Oヘッダー**

ヘッダーには、ファイルをMach-Oファイルとして識別するためのマジックバイトや、ターゲットアーキテクチャに関する情報など、ファイルに関する基本情報が含まれています。これを見つけるには： `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

異なるファイルタイプがあり、[**ソースコードの例はこちら**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)で定義されています。最も重要なものは次のとおりです：

- `MH_OBJECT`: 再配置可能なオブジェクトファイル（コンパイルの中間生成物、まだ実行可能ではない）。
- `MH_EXECUTE`: 実行可能ファイル。
- `MH_FVMLIB`: 固定VMライブラリファイル。
- `MH_CORE`: コードダンプ
- `MH_PRELOAD`: プリロードされた実行可能ファイル（XNUではもはやサポートされていない）
- `MH_DYLIB`: 動的ライブラリ
- `MH_DYLINKER`: 動的リンカー
- `MH_BUNDLE`: "プラグインファイル"。gccの-bundleを使用して生成され、`NSBundle`または`dlopen`によって明示的にロードされる。
- `MH_DYSM`: 付随する`.dSym`ファイル（デバッグ用のシンボルを含むファイル）。
- `MH_KEXT_BUNDLE`: カーネル拡張。
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O フラグ**

ソースコードは、ライブラリをロードするために便利な複数のフラグを定義しています：

- `MH_NOUNDEFS`: 未定義の参照なし（完全にリンク済み）
- `MH_DYLDLINK`: Dyld リンク
- `MH_PREBOUND`: 動的参照が事前にバインドされています。
- `MH_SPLIT_SEGS`: ファイルが r/o と r/w セグメントに分割されます。
- `MH_WEAK_DEFINES`: バイナリには弱い定義のシンボルがあります
- `MH_BINDS_TO_WEAK`: バイナリは弱いシンボルを使用します
- `MH_ALLOW_STACK_EXECUTION`: スタックを実行可能にします
- `MH_NO_REEXPORTED_DYLIBS`: ライブラリは LC_REEXPORT コマンドではありません
- `MH_PIE`: 位置独立実行可能ファイル
- `MH_HAS_TLV_DESCRIPTORS`: スレッドローカル変数を持つセクションがあります
- `MH_NO_HEAP_EXECUTION`: ヒープ/データページの実行なし
- `MH_HAS_OBJC`: バイナリには oBject-C セクションがあります
- `MH_SIM_SUPPORT`: シミュレータサポート
- `MH_DYLIB_IN_CACHE`: 共有ライブラリキャッシュ内の dylibs/frameworks に使用されます。

## **Mach-O ロードコマンド**

**メモリ内のファイルのレイアウト**はここで指定され、**シンボルテーブルの位置**、実行開始時のメインスレッドのコンテキスト、および必要な**共有ライブラリ**が詳細に説明されています。動的ローダー **(dyld)** に対して、バイナリのメモリへのロードプロセスに関する指示が提供されます。

**load_command** 構造体を使用し、前述の **`loader.h`** で定義されています：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
約**50種類の異なるロードコマンド**があり、システムはそれらを異なる方法で処理します。最も一般的なものは、`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`、および`LC_CODE_SIGNATURE`です。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本的に、このタイプのロードコマンドは、バイナリが実行されるときに**データセクションに示されたオフセット**に従って、**\_\_TEXT**（実行可能コード）**と\_\_DATA**（プロセスのデータ）**セグメントをどのようにロードするかを定義します**。

これらのコマンドは、プロセスが実行されるときに**仮想メモリ空間**に**マッピング**される**セグメント**を**定義**します。

**\_\_TEXT**セグメントのように、プログラムの実行可能コードを保持する**異なるタイプ**のセグメントがあり、プロセスによって使用されるデータを含む**\_\_DATA**セグメントがあります。これらの**セグメントはMach-Oファイルのデータセクションに位置しています**。

**各セグメント**はさらに**複数のセクション**に**分割**できます。**ロードコマンド構造**には、各セグメント内の**これらのセクション**に関する**情報**が含まれています。

ヘッダーの最初には**セグメントヘッダー**があります：

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

このヘッダーは、**その後に表示されるヘッダーのセクションの数を定義します**：
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
例としての**セクションヘッダー**：

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

**セクションオフセット** (0x37DC) と **アーキテクチャが始まるオフセット**を加えると、この場合 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**コマンドライン**から**ヘッダー情報**を取得することも可能です：
```bash
otool -lv /bin/ls
```
共通のセグメントはこのコマンドによってロードされます：

- **`__PAGEZERO`:** カーネルに**アドレスゼロをマップする**よう指示し、**読み取り、書き込み、実行できない**ようにします。構造体内のmaxprotおよびminprot変数は、このページに**読み書き実行権限がない**ことを示すためにゼロに設定されます。
- この割り当ては**NULLポインタデリファレンス脆弱性を軽減する**ために重要です。これは、XNUがハードページゼロを強制し、メモリの最初のページ（最初のページのみ）がアクセス不可であることを保証するためです（i386を除く）。バイナリは、最初の4kをカバーする小さな\_\_PAGEZEROを作成し、残りの32ビットメモリをユーザーモードとカーネルモードの両方でアクセス可能にすることで、この要件を満たすことができます。
- **`__TEXT`**: **実行可能な** **コード**を含み、**読み取り**および**実行**権限（書き込み不可）を持ちます。 このセグメントの一般的なセクション：
- `__text`: コンパイルされたバイナリコード
- `__const`: 定数データ（読み取り専用）
- `__ [c/u/os_log]string`: C、Unicodeまたはosログの文字列定数
- `__stubs`および`__stubs_helper`: 動的ライブラリのロードプロセスに関与
- `__unwind_info`: スタックアンワインドデータ。
- これらのすべてのコンテンツは署名されていますが、実行可能としてもマークされています（文字列専用セクションのように、この特権を必ずしも必要としないセクションの悪用のためのオプションが増えます）。
- **`__DATA`**: **読み取り可能**および**書き込み可能**なデータを含みます（実行不可）。
- `__got:` グローバルオフセットテーブル
- `__nl_symbol_ptr`: 非遅延（ロード時にバインド）シンボルポインタ
- `__la_symbol_ptr`: 遅延（使用時にバインド）シンボルポインタ
- `__const`: 読み取り専用データであるべき（実際にはそうではない）
- `__cfstring`: CoreFoundation文字列
- `__data`: グローバル変数（初期化済み）
- `__bss`: 静的変数（未初期化）
- `__objc_*`（\_\_objc_classlist、\_\_objc_protolistなど）: Objective-Cランタイムによって使用される情報
- **`__DATA_CONST`**: \_\_DATA.\_\_constは定数であることが保証されていません（書き込み権限）、他のポインタやGOTも同様です。このセクションは、`mprotect`を使用して`__const`、いくつかの初期化子、およびGOTテーブル（解決後）を**読み取り専用**にします。
- **`__LINKEDIT`**: リンカ（dyld）用の情報を含み、シンボル、文字列、および再配置テーブルのエントリなどが含まれます。これは、`__TEXT`または`__DATA`に含まれないコンテンツのための一般的なコンテナであり、その内容は他のロードコマンドで説明されています。
- dyld情報: リベース、非遅延/遅延/弱バインディングオペコードおよびエクスポート情報
- 関数開始: 関数の開始アドレスのテーブル
- コード内のデータ: \_\_text内のデータアイランド
- シンボルテーブル: バイナリ内のシンボル
- 間接シンボルテーブル: ポインタ/スタブシンボル
- 文字列テーブル
- コード署名
- **`__OBJC`**: Objective-Cランタイムによって使用される情報を含みます。この情報は、\_\_DATAセグメント内のさまざまな\_\_objc\_\*セクションにも見つかる可能性があります。
- **`__RESTRICT`**: コンテンツのないセグメントで、**`__restrict`**と呼ばれる単一のセクション（空）を持ち、バイナリを実行する際にDYLD環境変数を無視することを保証します。

コードで見ることができたように、**セグメントはフラグもサポートしています**（ただし、あまり使用されていません）：

- `SG_HIGHVM`: コアのみ（使用されていない）
- `SG_FVMLIB`: 使用されていない
- `SG_NORELOC`: セグメントに再配置がない
- `SG_PROTECTED_VERSION_1`: 暗号化。Finderが`__TEXT`セグメントのテキストを暗号化するために使用する例があります。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**は、**entryoff属性**にエントリポイントを含みます。ロード時に、**dyld**は単にこの値を（メモリ内の）**バイナリのベースに追加し**、この命令に**ジャンプ**してバイナリのコードの実行を開始します。

**`LC_UNIXTHREAD`**は、メインスレッドを開始する際にレジスタが持つべき値を含みます。これはすでに非推奨ですが、**`dyld`**はまだ使用しています。これによって設定されたレジスタの値を見ることができます：
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

Mach-Oファイルの**コード署名**に関する情報を含みます。これは通常、**署名ブロブ**を指す**オフセット**のみを含みます。これは通常、ファイルの非常に最後にあります。\
ただし、このセクションに関する情報は[**このブログ投稿**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)やこの[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)で見つけることができます。

### **`LC_ENCRYPTION_INFO[_64]`**

バイナリ暗号化のサポート。ただし、もちろん、攻撃者がプロセスを侵害することに成功した場合、彼はメモリを暗号化されていない状態でダンプすることができます。

### **`LC_LOAD_DYLINKER`**

プロセスアドレス空間に共有ライブラリをマッピングする**動的リンカ実行可能ファイルへのパス**を含みます。**値は常に`/usr/lib/dyld`に設定されています**。macOSでは、dylibのマッピングは**ユーザーモード**で行われることに注意が必要です。

### **`LC_IDENT`**

廃止されていますが、パニック時にダンプを生成するように設定されていると、Mach-Oコアダンプが作成され、カーネルバージョンが`LC_IDENT`コマンドに設定されます。

### **`LC_UUID`**

ランダムUUID。直接的には何にでも役立ちますが、XNUはそれをプロセス情報の残りとキャッシュします。クラッシュレポートで使用できます。

### **`LC_DYLD_ENVIRONMENT`**

プロセスが実行される前にdyldに環境変数を示すことを許可します。これは、プロセス内で任意のコードを実行できる可能性があるため、非常に危険です。このロードコマンドは、`#define SUPPORT_LC_DYLD_ENVIRONMENT`でビルドされたdyldでのみ使用され、`DYLD_..._PATH`形式の変数にのみ処理をさらに制限します。

### **`LC_LOAD_DYLIB`**

このロードコマンドは、**ライブラリ**の依存関係を**動的**に記述し、**ローダー**（dyld）に**指定されたライブラリをロードおよびリンクするように指示します**。Mach-Oバイナリが必要とする**各ライブラリ**に対して`LC_LOAD_DYLIB`ロードコマンドがあります。

- このロードコマンドは、実際の依存動的ライブラリを記述する構造体dylibを含む**`dylib_command`**型の構造体です：
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

この情報は、CLIを使用して取得することもできます:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
いくつかの潜在的なマルウェア関連ライブラリは次のとおりです：

- **DiskArbitration**: USBドライブの監視
- **AVFoundation:** 音声と映像のキャプチャ
- **CoreWLAN**: Wifiスキャン。

> [!NOTE]
> Mach-Oバイナリは、**LC_MAIN**で指定されたアドレスの**前に**実行される**1つ以上の** **コンストラクタ**を含むことができます。\
> すべてのコンストラクタのオフセットは、**\_\_DATA_CONST**セグメントの**\_\_mod_init_func**セクションに保持されます。

## **Mach-Oデータ**

ファイルの中心にはデータ領域があり、これはロードコマンド領域で定義された複数のセグメントで構成されています。**各セグメント内にはさまざまなデータセクションが格納される可能性があり**、各セクションは**特定のタイプに関連するコードまたはデータ**を保持します。

> [!TIP]
> データは基本的に、ロードコマンド**LC_SEGMENTS_64**によってロードされるすべての**情報**を含む部分です。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

これには次のものが含まれます：

- **関数テーブル:** プログラム関数に関する情報を保持します。
- **シンボルテーブル**: バイナリによって使用される外部関数に関する情報を含みます
- 内部関数、変数名なども含まれる可能性があります。

これを確認するには、[**Mach-O View**](https://sourceforge.net/projects/machoview/)ツールを使用できます：

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

またはCLIから：
```bash
size -m /bin/ls
```
## Objetive-Cの一般的なセクション

`__TEXT`セグメント (r-x):

- `__objc_classname`: クラス名 (文字列)
- `__objc_methname`: メソッド名 (文字列)
- `__objc_methtype`: メソッドタイプ (文字列)

`__DATA`セグメント (rw-):

- `__objc_classlist`: すべてのObjective-Cクラスへのポインタ
- `__objc_nlclslist`: 非遅延Objective-Cクラスへのポインタ
- `__objc_catlist`: カテゴリへのポインタ
- `__objc_nlcatlist`: 非遅延カテゴリへのポインタ
- `__objc_protolist`: プロトコルリスト
- `__objc_const`: 定数データ
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
