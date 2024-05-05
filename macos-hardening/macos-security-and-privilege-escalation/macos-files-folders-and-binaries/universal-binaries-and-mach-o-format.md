# macOSのUniversalバイナリとMach-Oフォーマット

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする

- **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

## 基本情報

Mac OSのバイナリは通常、**universal binaries**としてコンパイルされます。**universal binary**は**同じファイル内で複数のアーキテクチャをサポート**できます。

これらのバイナリは基本的に以下のような**Mach-O構造**に従います：

- ヘッダー
- ロードコマンド
- データ

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Fatヘッダー

次のコマンドでファイルを検索します：`mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

```c
#define FAT_MAGIC	0xcafebabe
#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */

struct fat_header {
	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
	uint32_t	nfat_arch;	/* number of structs that follow */
};

struct fat_arch {
	cpu_type_t	cputype;	/* cpu specifier (int) */
	cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
	uint32_t	offset;		/* file offset to this object file */
	uint32_t	size;		/* size of this object file */
	uint32_t	align;		/* alignment as a power of 2 */
};
```

ヘッダーには**magic**バイトが続き、ファイルが含む**archs**の**数**（`nfat_arch`）と各アーキテクチャが`fat_arch`構造体を持ちます。

次のコマンドで確認します：

```shell
% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
nfat_arch 2
architecture x86_64
    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
    offset 16384
    size 72896
    align 2^14 (16384)
architecture arm64e
    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
    offset 98304
    size 88816
    align 2^14 (16384)
```

または[Mach-O View](https://sourceforge.net/projects/machoview/)ツールを使用して確認できます：

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

通常、2つのアーキテクチャ向けにコンパイルされたuniversal binaryは、1つのアーキテクチャ向けにコンパイルされたものの**サイズを倍に**します。

## **Mach-Oヘッダー**

ヘッダーには、ファイルを識別するためのマジックバイトや対象アーキテクチャに関する情報など、ファイルに関する基本情報が含まれています。次のコマンドで確認できます：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

異なるファイルタイプがあります。これらは[**例えばこちらのソースコード**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h)で定義されています。最も重要なものは次のとおりです：

- `MH_OBJECT`: 再配置可能なオブジェクトファイル（コンパイルの中間生成物であり、まだ実行可能ではありません）。
- `MH_EXECUTE`: 実行可能ファイル。
- `MH_FVMLIB`: 固定VMライブラリファイル。
- `MH_CORE`: コードダンプ
- `MH_PRELOAD`: プリロードされた実行可能ファイル（XNUではもはやサポートされていません）
- `MH_DYLIB`: ダイナミックライブラリ
- `MH_DYLINKER`: ダイナミックリンカ
- `MH_BUNDLE`: "プラグインファイル"。gccの-bundleを使用して生成され、`NSBundle`または`dlopen`によって明示的にロードされます。
- `MH_DYSM`: デバッグ用シンボルを持つ`.dSym`ファイル（補助ファイル）。
- `MH_KEXT_BUNDLE`: カーネル拡張。
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
または、[Mach-O View](https://sourceforge.net/projects/machoview/) を使用する：

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O フラグ**

ソースコードでは、ライブラリの読み込みに役立ついくつかのフラグも定義されています：

* `MH_NOUNDEFS`: 未定義の参照なし（完全にリンクされている）
* `MH_DYLDLINK`: Dyld リンク
* `MH_PREBOUND`: 動的参照が事前にバインドされています。
* `MH_SPLIT_SEGS`: ファイルが r/o および r/w セグメントに分割されています。
* `MH_WEAK_DEFINES`: バイナリには弱く定義されたシンボルが含まれています
* `MH_BINDS_TO_WEAK`: バイナリが弱いシンボルを使用しています
* `MH_ALLOW_STACK_EXECUTION`: スタックを実行可能にします
* `MH_NO_REEXPORTED_DYLIBS`: ライブラリに LC\_REEXPORT コマンドが含まれていません
* `MH_PIE`: 位置に依存しない実行可能ファイル
* `MH_HAS_TLV_DESCRIPTORS`: スレッドローカル変数を持つセクションがあります
* `MH_NO_HEAP_EXECUTION`: ヒープ/データページの実行がありません
* `MH_HAS_OBJC`: バイナリに oBject-C セクションが含まれています
* `MH_SIM_SUPPORT`: シミュレータサポート
* `MH_DYLIB_IN_CACHE`: 共有ライブラリキャッシュ内の dylibs/frameworks で使用されます。

## **Mach-O ロードコマンド**

**メモリ内のファイルのレイアウト** がここで指定され、**シンボルテーブルの位置**、実行開始時のメインスレッドのコンテキスト、および必要な **共有ライブラリ** が詳細に記載されています。メモリへのバイナリの読み込みプロセスに関する指示が、動的ローダー **(dyld)** に提供されます。

これには、**`loader.h`** で定義された **load\_command** 構造が使用されます。
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
### **LC_SEGMENT/LC_SEGMENT_64**

{% hint style="success" %}
基本的に、このタイプのロードコマンドは、バイナリが実行されるときに、**\_\_TEXT**（実行コード）と**\_\_DATA**（プロセス用データ）**セグメントをどのようにロードするか**を、データセクションで示されたオフセットに従って定義します。
{% endhint %}

これらのコマンドは、プロセスが実行されるときに、**仮想メモリ空間にマップされるセグメント**を**定義**します。

**異なる種類**のセグメントがあり、プログラムの実行コードを保持する**\_\_TEXT**セグメントや、プロセスによって使用されるデータを含む**\_\_DATA**セグメントなどがあります。これらの**セグメントは、Mach-Oファイルのデータセクションに配置**されています。

**各セグメント**は、さらに複数の**セクション**に**分割**できます。**ロードコマンド構造**には、それぞれのセグメント内の**これらのセクションに関する情報**が含まれています。

ヘッダー内にはまず、**セグメントヘッダー**があります：

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

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

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
### **セクションヘッダーの例**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

もし、**セクションオフセット**（0x37DC）に**アーキテクチャが始まるオフセット**（この場合 `0x18000`）を**追加**すると、`0x37DC + 0x18000 = 0x1B7DC` になります。

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

また、**コマンドライン**からも**ヘッダー情報**を取得することが可能です。
```bash
otool -lv /bin/ls
```
```markdown
このcmdによってロードされる一般的なセグメント：

* **`__PAGEZERO`:** カーネルに**アドレスゼロをマップ**するよう指示し、**読み取り、書き込み、実行**ができないようにします。構造体内のmaxprotとminprot変数はゼロに設定され、このページには**読み取り書き込み実行権限がない**ことを示します。
* この割り当ては**NULLポインターのデリファレンス脆弱性を緩和**するために重要です。これは、XNUが最初のページ（i386を除く）がアクセスできないようにする厳格なページゼロを強制するためです。バイナリは、最初の4kをカバーする小さな\_\_PAGEZERO（`-pagezero_size`を使用）を作成し、残りの32ビットメモリをユーザーモードとカーネルモードの両方でアクセス可能にすることでこれらの要件を満たすことができます。
* **`__TEXT`**: **読み取り**および**実行**権限（書き込みなし）を持つ**実行可能なコード**を含みます。このセグメントの一般的なセクション：
* `__text`: コンパイルされたバイナリコード
* `__const`: 定数データ（読み取り専用）
* `__[c/u/os_log]string`: C、Unicode、またはosログの文字列定数
* `__stubs`および`__stubs_helper`: ダイナミックライブラリの読み込みプロセス中に関与
* `__unwind_info`: スタックアンワインドデータ
* このすべてのコンテンツが署名されているが、実行可能としてマークされていることに注意してください（この特権が必要ないセクションの悪用のためのさらなるオプションを作成します、例えば文字列専用セクション）。
* **`__DATA`**: **読み取り**および**書き込み**可能なデータを含みます（実行不可）。
* `__got:` グローバルオフセットテーブル
* `__nl_symbol_ptr`: 遅延なし（ロード時にバインド）シンボルポインタ
* `__la_symbol_ptr`: 遅延（使用時にバインド）シンボルポインタ
* `__const`: 読み取り専用データであるべき（実際にはそうではない）
* `__cfstring`: CoreFoundation文字列
* `__data`: 初期化されたグローバル変数
* `__bss`: 初期化されていない静的変数
* `__objc_*`（\_\_objc\_classlist、\_\_objc\_protolistなど）：Objective-Cランタイムで使用される情報
* **`__DATA_CONST`**: \_\_DATA.\_\_constは定数であることが保証されていません（書き込み権限があります）、他のポインタやGOTも同様です。このセクションは、`mprotect`を使用して`__const`、一部の初期化子、およびGOTテーブル（解決後）を**読み取り専用**にします。
* **`__LINKEDIT`**: リンカー（dyld）のための情報を含み、シンボル、文字列、および再配置テーブルエントリが含まれます。これは`__TEXT`または`__DATA`に含まれないコンテンツのための一般的なコンテナであり、その内容は他のロードコマンドで説明されています。
* dyld情報：再配置、遅延なし/遅延/弱いバインディングオペコードおよびエクスポート情報
* 関数開始：関数の開始アドレスのテーブル
* コード内データ：\_\_text内のデータアイランド
* シンボルテーブル：バイナリ内のシンボル
* 間接シンボルテーブル：ポインタ/スタブシンボル
* 文字列テーブル
* コード署名
* **`__OBJC`**: Objective-Cランタイムで使用される情報を含みます。ただし、この情報は、さまざまな\_\_objc\_\*セクション内にも見つかる可能性があります。
* **`__RESTRICT`**: コンテンツのないセグメントで、**`__restrict`**（空でも）という単一のセクションがあり、バイナリを実行する際にDYLD環境変数を無視することを保証します。

コードで見られたように、**セグメントもフラグをサポート**しています（あまり使用されていませんが）：

* `SG_HIGHVM`: コアのみ（使用されていません）
* `SG_FVMLIB`: 使用されていません
* `SG_NORELOC`: セグメントに再配置がない
* `SG_PROTECTED_VERSION_1`: 暗号化。例えばFinderが`__TEXT`セグメントのテキストを暗号化するために使用されます。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** は**entryoff属性**にエントリーポイントを含みます。ロード時に、**dyld**は単にこの値を（メモリ内の）バイナリのベースに**追加**し、その後この命令に**ジャンプ**してバイナリのコードの実行を開始します。

**`LC_UNIXTHREAD`** は、メインスレッドを開始するときにレジスタが持っている必要がある値を含みます。これはすでに非推奨となっていますが、**`dyld`** はまだ使用しています。これによって設定されたレジスタの値を次のように確認できます：
```
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

Macho-Oファイルの**コード署名**に関する情報を含みます。**署名ブロブ**を指す**オフセット**のみを含んでいます。通常、ファイルの最後にあります。\
ただし、このセクションに関する情報は、[**このブログ投稿**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)とこの[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)で見つけることができます。

### **`LC_ENCRYPTION_INFO[_64]`**

バイナリの暗号化をサポートします。ただし、攻撃者がプロセスを侵害してメモリを復号化することができる場合があります。

### **`LC_LOAD_DYLINKER`**

共有ライブラリをプロセスのアドレス空間にマップする**動的リンカー実行ファイルへのパス**を含みます。**値は常に`/usr/lib/dyld`に設定**されています。macOSでは、dylibのマッピングが**カーネルモードではなくユーザーモード**で行われることに注意することが重要です。

### **`LC_IDENT`**

古いですが、パニック時にダンプを生成するように構成されている場合、Mach-Oコアダンプが作成され、カーネルバージョンが`LC_IDENT`コマンドに設定されます。

### **`LC_UUID`**

ランダムUUIDです。直接的には役立ちませんが、XNUはプロセス情報の残りと一緒にキャッシュします。クラッシュレポートで使用できます。

### **`LC_DYLD_ENVIRONMENT`**

プロセスが実行される前にdyldに環境変数を示すことを許可します。これはプロセス内で任意のコードを実行できる可能性があるため、非常に危険です。このロードコマンドは、`#define SUPPORT_LC_DYLD_ENVIRONMENT`で構築されたdyldでのみ使用され、`DYLD_..._PATH`形式の変数のみを指定して処理をさらに制限します。

### **`LC_LOAD_DYLIB`**

このロードコマンドは、**ローダー**(dyld)に**ライブラリをロードしてリンクするよう指示する** **動的ライブラリ**依存関係を記述します。Mach-Oバイナリが必要とする**各ライブラリ**には`LC_LOAD_DYLIB`ロードコマンドがあります。

* このロードコマンドは、**実際の依存する動的ライブラリを記述するstruct dylibを含むdylib_command**型の構造体です。
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
![](<../../../.gitbook/assets/image (486).png>)

次のコマンドラインからもこの情報を取得できます：
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
いくつかの潜在的なマルウェア関連ライブラリは次のとおりです：

- **DiskArbitration**: USB ドライブの監視
- **AVFoundation**: 音声とビデオのキャプチャ
- **CoreWLAN**: Wifi スキャン

{% hint style="info" %}
Mach-O バイナリには、**LC\_MAIN** で指定されたアドレスの**前に実行される**1つ以上の**コンストラクタ**が含まれる可能性があります。\
任意のコンストラクタのオフセットは、**\_\_DATA\_CONST** セグメントの**\_\_mod\_init\_func** セクションに保持されます。
{% endhint %}

## **Mach-O データ**

ファイルの中心には、ロードコマンド領域で定義された複数のセグメントで構成されるデータ領域があります。**各セグメント内にはさまざまなデータセクションが収められており**、各セクションには**コードまたはデータ**が特定のタイプに固有のものが含まれています。

{% hint style="success" %}
データは基本的に、ロードコマンド**LC\_SEGMENTS\_64**によって読み込まれる**すべての情報**を含む部分です。
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

これには次のものが含まれます：

- **関数テーブル**：プログラム関数に関する情報を保持
- **シンボルテーブル**：バイナリで使用される外部関数に関する情報を含む
- 内部関数、変数名なども含まれる可能性があります。

確認するには、[**Mach-O View**](https://sourceforge.net/projects/machoview/) ツールを使用できます：

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

または、CLI から：
```bash
size -m /bin/ls
```
## Objective-C共通セクション

`__TEXT`セグメント（r-x）内：

- `__objc_classname`: クラス名（文字列）
- `__objc_methname`: メソッド名（文字列）
- `__objc_methtype`: メソッドタイプ（文字列）

`__DATA`セグメント（rw-）内：

- `__objc_classlist`: すべてのObjective-Cクラスへのポインタ
- `__objc_nlclslist`: 遅延ロードされないObjective-Cクラスへのポインタ
- `__objc_catlist`: カテゴリへのポインタ
- `__objc_nlcatlist`: 遅延ロードされないカテゴリへのポインタ
- `__objc_protolist`: プロトコルリスト
- `__objc_const`: 定数データ
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
