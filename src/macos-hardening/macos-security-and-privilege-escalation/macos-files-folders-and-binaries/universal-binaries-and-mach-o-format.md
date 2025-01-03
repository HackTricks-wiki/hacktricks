# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

Mac OS 二进制文件通常被编译为 **universal binaries**。一个 **universal binary** 可以 **在同一个文件中支持多个架构**。

这些二进制文件遵循 **Mach-O 结构**，基本由以下部分组成：

- 头部
- 加载命令
- 数据

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

使用以下命令搜索文件： `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC 或 FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* 后续结构的数量 */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu 说明符 (int) */
cpu_subtype_t	cpusubtype;	/* 机器说明符 (int) */
uint32_t	offset;		/* 文件偏移到此目标文件 */
uint32_t	size;		/* 此目标文件的大小 */
uint32_t	align;		/* 以 2 的幂为单位的对齐 */
};
</code></pre>

头部包含 **magic** 字节，后面是文件 **包含** 的 **archs** 的 **数量** (`nfat_arch`)，每个架构将有一个 `fat_arch` 结构。

使用以下命令检查：

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

或者使用 [Mach-O View](https://sourceforge.net/projects/machoview/) 工具：

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

正如你所想，通常为 2 个架构编译的 universal binary **会使文件大小翻倍**，而为 1 个架构编译的文件则不会。

## **Mach-O Header**

头部包含有关文件的基本信息，例如用于识别它为 Mach-O 文件的 magic 字节和有关目标架构的信息。你可以在以下路径找到它： `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O 文件类型

有不同的文件类型，可以在[**源代码中找到定义，例如这里**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)。最重要的类型有：

- `MH_OBJECT`: 可重定位目标文件（编译的中间产品，尚未成为可执行文件）。
- `MH_EXECUTE`: 可执行文件。
- `MH_FVMLIB`: 固定虚拟机库文件。
- `MH_CORE`: 代码转储
- `MH_PRELOAD`: 预加载的可执行文件（在 XNU 中不再支持）
- `MH_DYLIB`: 动态库
- `MH_DYLINKER`: 动态链接器
- `MH_BUNDLE`: “插件文件”。使用 gcc 的 -bundle 生成，并由 `NSBundle` 或 `dlopen` 显式加载。
- `MH_DYSM`: 伴随的 `.dSym` 文件（用于调试的符号文件）。
- `MH_KEXT_BUNDLE`: 内核扩展。
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
或使用 [Mach-O View](https://sourceforge.net/projects/machoview/)：

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 标志**

源代码还定义了几个用于加载库的标志：

- `MH_NOUNDEFS`：没有未定义的引用（完全链接）
- `MH_DYLDLINK`：Dyld 链接
- `MH_PREBOUND`：动态引用预绑定。
- `MH_SPLIT_SEGS`：文件分割 r/o 和 r/w 段。
- `MH_WEAK_DEFINES`：二进制文件具有弱定义符号
- `MH_BINDS_TO_WEAK`：二进制文件使用弱符号
- `MH_ALLOW_STACK_EXECUTION`：使堆栈可执行
- `MH_NO_REEXPORTED_DYLIBS`：库没有 LC_REEXPORT 命令
- `MH_PIE`：位置无关可执行文件
- `MH_HAS_TLV_DESCRIPTORS`：有一个包含线程局部变量的部分
- `MH_NO_HEAP_EXECUTION`：堆/数据页面不执行
- `MH_HAS_OBJC`：二进制文件具有 oBject-C 部分
- `MH_SIM_SUPPORT`：模拟器支持
- `MH_DYLIB_IN_CACHE`：用于共享库缓存中的 dylibs/frameworks。

## **Mach-O 加载命令**

**文件在内存中的布局**在这里指定，详细说明了 **符号表的位置**、执行开始时主线程的上下文以及所需的 **共享库**。向动态加载器 **(dyld)** 提供了有关二进制文件加载到内存中的过程的指令。

使用 **load_command** 结构，该结构在提到的 **`loader.h`** 中定义：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
有大约 **50 种不同类型的加载命令**，系统以不同方式处理它们。最常见的有： `LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB` 和 `LC_CODE_SIGNATURE`。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本上，这种类型的加载命令定义了 **如何加载 \_\_TEXT**（可执行代码）**和 \_\_DATA**（进程数据）**段**，根据二进制文件执行时在数据部分中指示的 **偏移量**。

这些命令 **定义了段**，在执行进程时被 **映射** 到 **虚拟内存空间** 中。

有 **不同类型** 的段，例如 **\_\_TEXT** 段，它包含程序的可执行代码，以及 **\_\_DATA** 段，它包含进程使用的数据。这些 **段位于 Mach-O 文件的数据部分** 中。

**每个段** 可以进一步 **划分** 为多个 **节**。**加载命令结构** 包含关于 **这些节** 在各自段中的 **信息**。

在头部，首先找到 **段头**：

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

段头的示例：

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

该头部定义了 **其后出现的节头的数量**：
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
示例 **节标题**：

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

如果你 **添加** **节偏移** (0x37DC) + **架构开始的偏移**，在这种情况下 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

也可以通过 **命令行** 获取 **头信息**：
```bash
otool -lv /bin/ls
```
常见的由此命令加载的段：

- **`__PAGEZERO`：** 它指示内核**映射** **地址零**，以便**无法读取、写入或执行**。结构中的maxprot和minprot变量设置为零，以指示此页面上**没有读写执行权限**。
- 此分配对于**缓解NULL指针解引用漏洞**非常重要。这是因为XNU强制实施一个硬页面零，确保内存的第一页（仅第一页）不可访问（在i386中除外）。一个二进制文件可以通过制作一个小的\_\_PAGEZERO（使用`-pagezero_size`）来满足这些要求，以覆盖前4k，并使其余的32位内存在用户模式和内核模式下可访问。
- **`__TEXT`**：包含**可执行** **代码**，具有**读取**和**执行**权限（不可写）。此段的常见部分：
- `__text`：编译的二进制代码
- `__const`：常量数据（只读）
- `__ [c/u/os_log]string`：C、Unicode或os日志字符串常量
- `__stubs`和`__stubs_helper`：在动态库加载过程中涉及
- `__unwind_info`：堆栈展开数据。
- 请注意，所有这些内容都是签名的，但也被标记为可执行（为不一定需要此权限的部分（如专用字符串部分）创建更多的利用选项）。
- **`__DATA`**：包含**可读**和**可写**的数据（不可执行）。
- `__got:` 全局偏移表
- `__nl_symbol_ptr`：非惰性（加载时绑定）符号指针
- `__la_symbol_ptr`：惰性（使用时绑定）符号指针
- `__const`：应为只读数据（实际上不是）
- `__cfstring`：CoreFoundation字符串
- `__data`：全局变量（已初始化）
- `__bss`：静态变量（未初始化）
- `__objc_*`（\_\_objc_classlist，\_\_objc_protolist等）：由Objective-C运行时使用的信息
- **`__DATA_CONST`**：\_\_DATA.\_\_const不保证是常量（写权限），其他指针和GOT也是如此。此部分使用`mprotect`使`__const`、一些初始化程序和GOT表（解析后）**只读**。
- **`__LINKEDIT`**：包含链接器（dyld）所需的信息，例如符号、字符串和重定位表条目。它是一个通用容器，包含不在`__TEXT`或`__DATA`中的内容，其内容在其他加载命令中描述。
- dyld信息：重定位、非惰性/惰性/弱绑定操作码和导出信息
- 函数开始：函数的起始地址表
- 代码中的数据：\_\_text中的数据岛
- 符号表：二进制中的符号
- 间接符号表：指针/存根符号
- 字符串表
- 代码签名
- **`__OBJC`**：包含由Objective-C运行时使用的信息。尽管这些信息也可能在\_\_DATA段中找到，在各种\_\_objc\_\*部分中。
- **`__RESTRICT`**：一个没有内容的段，只有一个名为**`__restrict`**（也为空）的单一部分，确保在运行二进制文件时，它将忽略DYLD环境变量。

正如在代码中所看到的，**段也支持标志**（尽管它们并不常用）：

- `SG_HIGHVM`：仅核心（未使用）
- `SG_FVMLIB`：未使用
- `SG_NORELOC`：段没有重定位
- `SG_PROTECTED_VERSION_1`：加密。例如，Finder用于加密文本`__TEXT`段。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**包含**entryoff属性**中的入口点。在加载时，**dyld**简单地**将**此值添加到（内存中的）**二进制文件基址**，然后**跳转**到此指令以开始执行二进制代码。

**`LC_UNIXTHREAD`**包含启动主线程时寄存器必须具有的值。这已经被弃用，但**`dyld`**仍在使用它。可以通过以下方式查看寄存器设置的值：
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

包含关于 **Macho-O 文件的代码签名** 的信息。它仅包含一个 **偏移量**，指向 **签名 blob**。这通常位于文件的最末尾。\
然而，您可以在 [**这篇博客文章**](https://davedelong.com/blog/2018/01/10/reading-your-own_entitlements/) 和这个 [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) 中找到一些关于此部分的信息。

### **`LC_ENCRYPTION_INFO[_64]`**

支持二进制加密。然而，当然，如果攻击者设法破坏了进程，他将能够以未加密的方式转储内存。

### **`LC_LOAD_DYLINKER`**

包含 **动态链接器可执行文件的路径**，该文件将共享库映射到进程地址空间。**值始终设置为 `/usr/lib/dyld`**。重要的是要注意，在 macOS 中，dylib 映射发生在 **用户模式**，而不是内核模式。

### **`LC_IDENT`**

过时，但当配置为在崩溃时生成转储时，会创建一个 Mach-O 核心转储，并在 `LC_IDENT` 命令中设置内核版本。

### **`LC_UUID`**

随机 UUID。它对任何直接的事情都很有用，但 XNU 将其与其他进程信息一起缓存。它可以在崩溃报告中使用。

### **`LC_DYLD_ENVIRONMENT`**

允许在进程执行之前向 dyld 指示环境变量。这可能非常危险，因为它可能允许在进程内部执行任意代码，因此此加载命令仅在使用 `#define SUPPORT_LC_DYLD_ENVIRONMENT` 构建的 dyld 中使用，并进一步限制处理仅限于形式为 `DYLD_..._PATH` 的变量，指定加载路径。

### **`LC_LOAD_DYLIB`**

此加载命令描述了一个 **动态** **库** 依赖关系，**指示** **加载器** (dyld) **加载和链接该库**。每个 Mach-O 二进制文件所需的库都有一个 `LC_LOAD_DYLIB` 加载命令。

- 此加载命令是 **`dylib_command`** 类型的结构（其中包含一个描述实际依赖动态库的 struct dylib）：
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

您还可以通过命令行获取此信息：
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
一些潜在的与恶意软件相关的库包括：

- **DiskArbitration**: 监控 USB 驱动器
- **AVFoundation:** 捕获音频和视频
- **CoreWLAN**: Wifi 扫描。

> [!NOTE]
> Mach-O 二进制文件可以包含一个或 **多个** **构造函数**，这些构造函数将在 **LC_MAIN** 指定的地址 **之前** 被 **执行**。\
> 任何构造函数的偏移量保存在 **\_\_mod_init_func** 段的 **\_\_DATA_CONST** 部分中。

## **Mach-O 数据**

文件的核心是数据区域，由加载命令区域中定义的多个段组成。**每个段中可以包含多种数据部分**，每个部分 **保存特定类型的代码或数据**。

> [!TIP]
> 数据基本上是包含所有由加载命令 **LC_SEGMENTS_64** 加载的 **信息** 的部分。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

这包括：

- **函数表:** 包含有关程序函数的信息。
- **符号表**: 包含有关二进制文件使用的外部函数的信息
- 还可能包含内部函数、变量名称等。

要检查它，您可以使用 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 工具：

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

或者从命令行：
```bash
size -m /bin/ls
```
## Objetive-C 常见部分

在 `__TEXT` 段 (r-x):

- `__objc_classname`: 类名 (字符串)
- `__objc_methname`: 方法名 (字符串)
- `__objc_methtype`: 方法类型 (字符串)

在 `__DATA` 段 (rw-):

- `__objc_classlist`: 所有 Objective-C 类的指针
- `__objc_nlclslist`: 非懒加载 Objective-C 类的指针
- `__objc_catlist`: 类别的指针
- `__objc_nlcatlist`: 非懒加载类别的指针
- `__objc_protolist`: 协议列表
- `__objc_const`: 常量数据
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
