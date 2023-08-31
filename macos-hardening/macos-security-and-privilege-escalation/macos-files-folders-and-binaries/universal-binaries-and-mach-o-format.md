# macOSのユニバーサルバイナリとMach-Oフォーマット

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。

</details>

## 基本情報

Mac OSのバイナリは通常、**ユニバーサルバイナリ**としてコンパイルされます。**ユニバーサルバイナリ**は、**同じファイル内で複数のアーキテクチャをサポート**することができます。

これらのバイナリは、基本的には**Mach-O構造**に従います。

* ヘッダー
* ロードコマンド
* データ

![](<../../../.gitbook/assets/image (559).png>)

## Fatヘッダー

次のコマンドでファイルを検索します：`mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* 後に続く構造体の数 */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* CPUの指定子（int） */
cpu_subtype_t	cpusubtype;	/* マシンの指定子（int） */
uint32_t	offset;		/* このオブジェクトファイルへのファイルオフセット */
uint32_t	size;		/* このオブジェクトファイルのサイズ */
uint32_t	align;		/* 2の累乗としてのアライメント */
};
</code></pre>

ヘッダーには**マジック**バイトが続き、ファイルが含む**アーキテクチャの数**（`nfat_arch`）と、各アーキテクチャには`fat_arch`構造体があります。

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

または[Mach-O View](https://sourceforge.net/projects/machoview/)ツールを使用することもできます：

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

通常、2つのアーキテクチャ用にコンパイルされたユニバーサルバイナリは、1つのアーキテクチャ用にコンパイルされたものの**サイズが2倍**になります。

## **Mach-Oヘッダー**

ヘッダーには、ファイルを識別するためのマジックバイトや、ターゲットアーキテクチャに関する情報など、ファイルに関する基本情報が含まれています。次のコマンドで確認できます：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
または、[Mach-O View](https://sourceforge.net/projects/machoview/)を使用する方法もあります：

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O ロードコマンド**

これは、ファイルのメモリ内の**レイアウト**を指定します。これには、シンボルテーブルの場所、実行の開始時のメインスレッドのコンテキスト、および必要な**共有ライブラリ**が含まれています。\
これらのコマンドは基本的に、動的ローダー**(dyld)がバイナリをメモリにロードする方法を指示します。**

ロードコマンドはすべて、以前に言及した**`loader.h`**で定義された**load\_command**構造体で始まります。
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
約50種類のロードコマンドがあり、システムはそれらを異なる方法で処理します。最も一般的なものは、`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB`、および`LC_CODE_SIGNATURE`です。

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
基本的に、このタイプのロードコマンドは、バイナリが実行されるときにDATAに格納されたセクションをどのようにロードするかを定義します。
{% endhint %}

これらのコマンドは、プロセスが実行されるときに仮想メモリ空間にマップされるセグメントを定義します。

__TEXTセグメントは、プログラムの実行可能コードを保持し、__DATAセグメントはプロセスによって使用されるデータを含んでいます。これらのセグメントは、Mach-Oファイルのデータセクションに配置されています。

各セグメントは、さらに複数のセクションに分割することができます。ロードコマンドの構造には、それぞれのセグメント内のこれらのセクションに関する情報が含まれています。

ヘッダーの最初には、セグメントヘッダーがあります：

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

このヘッダーは、それに続くヘッダーのセクションの数を定義しています：
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
例えば、**セクションヘッダ**の例：

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

もし、**セクションオフセット**（0x37DC）に**アーキテクチャが始まるオフセット**（この場合は`0x18000`）を**追加**すると、`0x37DC + 0x18000 = 0x1B7DC`となります。

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

また、**コマンドライン**からも**ヘッダ情報**を取得することが可能です。
```bash
otool -lv /bin/ls
```
このコマンドによって読み込まれる一般的なセグメントは次のとおりです：

* **`__PAGEZERO`**：カーネルに対して、**アドレスゼロをマップ**しないように指示します。このセグメントは、読み取り、書き込み、実行ができないようにするために、構造体内のmaxprotとminprot変数がゼロに設定されます。
* この割り当ては、**NULLポインタの逆参照の脆弱性を軽減**するために重要です。
* **`__TEXT`**：**実行可能なコード**と**読み取り専用のデータ**を含んでいます。このセグメントの一般的なセクションは次のとおりです：
* `__text`：コンパイルされたバイナリコード
* `__const`：定数データ
* `__cstring`：文字列定数
* `__stubs`と`__stubs_helper`：ダイナミックライブラリの読み込みプロセス中に関与します。
* **`__DATA`**：**書き込み可能な**データを含んでいます。
* `__data`：初期化されたグローバル変数
* `__bss`：初期化されていない静的変数
* `__objc_*`（\_\_objc\_classlist、\_\_objc\_protolistなど）：Objective-Cランタイムで使用される情報
* **`__LINKEDIT`**：リンカ（dyld）のための情報を含んでいます。「シンボル、文字列、および再配置テーブルエントリ」などです。
* **`__OBJC`**：Objective-Cランタイムで使用される情報を含んでいます。ただし、この情報は\_\_DATAセグメント内のさまざまな\_\_objc\_\*セクションにも見つかる場合があります。

### **`LC_MAIN`**

**entryoff属性**にエントリーポイントが含まれています。ロード時に、**dyld**はこの値を（メモリ内の）**バイナリのベースに追加**し、バイナリのコードの実行を開始するためにこの命令にジャンプします。

### **LC\_CODE\_SIGNATURE**

Macho-Oファイルの**コード署名に関する情報**が含まれています。これには、**署名ブロブ**を指す**オフセット**のみが含まれます。通常、これはファイルの最後にあります。\
ただし、このセクションに関する情報は、[**このブログ記事**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)とこの[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)で見つけることができます。

### **LC\_LOAD\_DYLINKER**

プロセスのアドレス空間に共有ライブラリをマップする**動的リンカの実行可能ファイルへのパス**が含まれています。**値は常に`/usr/lib/dyld`**に設定されます。重要な点として、macOSではdylibのマッピングは**カーネルモードではなくユーザーモード**で行われることに注意してください。

### **`LC_LOAD_DYLIB`**

このロードコマンドは、Mach-Oバイナリが必要とする**動的ライブラリの依存関係**を記述します。Mach-Oバイナリが必要とする各ライブラリには、LC\_LOAD\_DYLIBロードコマンドがあります。

* このロードコマンドは、実際の依存する動的ライブラリを記述する**`dylib_command`**型の構造体です。
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
![](<../../../.gitbook/assets/image (558).png>)

また、次のコマンドラインからもこの情報を取得できます。
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
いくつかの潜在的なマルウェア関連のライブラリは次のとおりです：

* **DiskArbitration**: USBドライブの監視
* **AVFoundation:** 音声とビデオのキャプチャ
* **CoreWLAN**: Wifiスキャン。

{% hint style="info" %}
Mach-Oバイナリには、**1つ以上のコンストラクタ**が含まれており、これらは**LC\_MAIN**で指定されたアドレスの**前に実行**されます。\
コンストラクタのオフセットは、**\_\_DATA\_CONST**セグメントの**\_\_mod\_init\_func**セクションに保持されます。
{% endhint %}

## **Mach-Oデータ**

ファイルの中心部は、データであり、ロードコマンド領域に配置されたセグメントの数で構成されています。**各セグメントには複数のデータセクションが含まれる**ことがあります。これらのセクションは、特定のタイプのコードまたはデータを含んでいます。

{% hint style="success" %}
データは基本的に、ロードコマンドLC\_SEGMENTS\_64によってロードされるすべての情報を含む部分です。
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

これには以下が含まれます：

* **関数テーブル**：プログラムの関数に関する情報を保持します。
* **シンボルテーブル**：バイナリで使用される外部関数に関する情報を含みます。
* 内部関数、変数名なども含まれる場合があります。

[Mach-O View](https://sourceforge.net/projects/machoview/)ツールを使用して確認できます：

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

またはCLIから：
```bash
size -m /bin/ls
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
