# macOS 通用二进制 & Mach-O 格式

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

Mac OS 二进制通常被编译为 **universal binaries**。一个 **universal binary** 可以在同一文件中 **支持多个架构**。

这些二进制遵循 **Mach-O 结构**，基本由以下部分组成：

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

使用以下命令搜索文件：`mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

该 header 包含 **magic** 字节，后跟文件包含的 **架构数量** (`nfat_arch`)，每个架构都会有一个 `fat_arch` 结构。

检查示例：

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

正如你可能想到的，通常为 2 个架构编译的 universal binary 的大小会是只为 1 个架构编译的 **两倍**。

## **Mach-O Header**

该 header 包含关于文件的基本信息，例如用于识别为 Mach-O 文件的 magic 字节以及目标架构的信息。你可以在以下位置找到它：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

存在不同的文件类型，你可以在 [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) 中找到它们的定义。最重要的有：

- `MH_OBJECT`: 可重定位目标文件（编译的中间产物，尚非可执行文件）。
- `MH_EXECUTE`: 可执行文件。
- `MH_FVMLIB`: 固定 VM 库文件。
- `MH_CORE`: 代码转储。
- `MH_PRELOAD`: 预加载的可执行文件（XNU 不再支持）。
- `MH_DYLIB`: 动态库。
- `MH_DYLINKER`: 动态链接器。
- `MH_BUNDLE`: "插件文件"。使用 gcc 的 `-bundle` 生成，并由 `NSBundle` 或 `dlopen` 显式加载。
- `MH_DYSM`: 配套的 `.dSym` 文件（包含调试符号）。
- `MH_KEXT_BUNDLE`: 内核扩展。
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
或者使用 [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 标志**

源代码还定义了若干对加载库有用的标志：

- `MH_NOUNDEFS`: 没有未定义引用（完全链接）
- `MH_DYLDLINK`: Dyld 链接
- `MH_PREBOUND`: 动态引用预绑定
- `MH_SPLIT_SEGS`: 文件将只读与读写段分离
- `MH_WEAK_DEFINES`: 二进制包含弱定义符号
- `MH_BINDS_TO_WEAK`: 二进制使用弱符号
- `MH_ALLOW_STACK_EXECUTION`: 使栈可执行
- `MH_NO_REEXPORTED_DYLIBS`: 库不包含 LC_REEXPORT 命令
- `MH_PIE`: 位置无关可执行（PIE）
- `MH_HAS_TLV_DESCRIPTORS`: 包含线程局部变量（TLV）段
- `MH_NO_HEAP_EXECUTION`: 堆/数据页不可执行
- `MH_HAS_OBJC`: 二进制包含 Objective-C 段
- `MH_SIM_SUPPORT`: 模拟器支持
- `MH_DYLIB_IN_CACHE`: 用于位于共享库缓存中的 dylibs/frameworks

## **Mach-O 加载命令**

这里指定了文件在内存中的布局，说明了符号表的位置、执行开始时主线程的上下文以及所需的共享库。还向动态加载器（dyld）提供了如何将二进制加载到内存的指示。

该文件使用在提到的 `loader.h` 中定义的 **load_command** 结构：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
有大约 **50 种不同类型的 load commands**，系统会以不同方式处理。最常见的有：`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB` 和 `LC_CODE_SIGNATURE`。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本上，这种类型的加载命令定义了在二进制被执行时**如何根据 Data 部分中指示的偏移量加载 \_\_TEXT**（可执行代码）**和 \_\_DATA**（进程数据）**段**。

这些命令**定义了段（segments）**，在进程执行时会被**映射（mapped）**到进程的**虚拟内存空间**中。

存在不同类型的段，例如包含程序可执行代码的 **\_\_TEXT** 段，以及包含进程使用数据的 **\_\_DATA** 段。这些**段位于 Mach-O 文件的数据节**中。

**每个段**还可以进一步**划分为多个节（sections）**。load command 的结构包含关于该段中**这些节**的信息。

在头部首先可以找到**段头（segment header）**：

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

该头部定义了其后出现的**节头数量**：
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
关于 **节标题** 的示例：

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

如果你把 **section 偏移量** (0x37DC) 与 **arch 起始处的偏移量** 相加，在本例中 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

还可以通过 **命令行** 获取 **头部信息**：
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** 它指示内核 **映射** **地址零**，因此**无法被读取、写入或执行**。结构中的 maxprot 和 minprot 变量被设置为零，以表示该页**没有读写执行权限**。
- 这种分配对于**缓解 NULL 指针解引用 漏洞**非常重要。因为 XNU 强制实施一个硬性的 page zero，确保内存的第一页（仅第一页）不可访问（i386 除外）。一个二进制可以通过构造一个小的 \_\_PAGEZERO（使用 `-pagezero_size`）以覆盖前 4k，并使剩余的 32 位内存在用户态和内核态都可访问，从而满足这一要求。
- **`__TEXT`**: 包含具有**读取**和**执行**权限的**可执行****代码**（不可写）。此段的常见节：
- `__text`: 已编译的二进制代码
- `__const`: 常量数据（只读）
- `__[c/u/os_log]string`: C、Unicode 或 os 日志字符串常量
- `__stubs` and `__stubs_helper`: 在动态库加载过程中参与
- `__unwind_info`: 栈展开（unwind）数据
- 注意所有这些内容都已签名且被标记为可执行（这为某些并不一定需要此权限的节（例如专用于字符串的节）提供了更多利用途径）。
- **`__DATA`**: 包含**可读**且**可写**的数据（不可执行）。
- `__got:` 全局偏移表
- `__nl_symbol_ptr`: 非懒（在加载时绑定）符号指针
- `__la_symbol_ptr`: 懒（按需绑定）符号指针
- `__const`: 应为只读数据（但实际上并非如此）
- `__cfstring`: CoreFoundation 字符串
- `__data`: 已初始化的全局变量
- `__bss`: 未初始化的静态变量
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): 由 Objective-C 运行时使用的信息
- **`__DATA_CONST`**: \_\_DATA.\_\_const 并不保证是常量（存在写权限），其他指针和 GOT 也一样。此段使用 `mprotect` 将 `__const`、一些初始化器和 GOT 表（解析后）设置为**只读**。
- **`__LINKEDIT`**: 包含链路器（dyld）所需的信息，例如符号、字符串和重定位表条目。它是一个通用容器，用于存放既不在 `__TEXT` 也不在 `__DATA` 中的内容，其内容在其它加载命令中有描述。
- dyld 信息：Rebase、Non-lazy/lazy/weak binding opcodes 和导出信息
- Functions starts：函数起始地址表
- Data In Code：\_\_text 中的数据岛
- SYmbol Table：二进制中的符号
- Indirect Symbol Table：指针/存根符号
- String Table：字符串表
- Code Signature：代码签名
- **`__OBJC`**: 包含由 Objective-C 运行时使用的信息。尽管这些信息也可能出现在 \_\_DATA 段内的各种 \_\_objc\_\* 节中。
- **`__RESTRICT`**: 一个没有内容的段，只有一个名为 **`__restrict`**（同样为空）的节，确保在运行二进制时会忽略 DYLD 环境变量。

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: 仅限内核（未使用）
- `SG_FVMLIB`: 未使用
- `SG_NORELOC`: 段没有重定位
- `SG_PROTECTED_VERSION_1`: 加密。例如 Finder 使用它来加密 `__TEXT` 段的文本。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** 包含入口点于 **entryoff 属性**。在加载时，**dyld** 简单地**将该值添加到**（二进制在内存中的）**基地址**，然后**跳转**到该指令以开始执行二进制的代码。

**`LC_UNIXTHREAD`** 包含启动主线程时寄存器应具有的值。它已被弃用，但 **`dyld`** 仍在使用它。可以通过下面的方法查看由此设置的寄存器值：
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


包含有关 Mach-O 文件**代码签名**的信息。它仅包含一个**偏移量（offset）**，指向**签名 blob**。该偏移通常位于文件的末尾。\
你可以在[**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) 和 [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) 中找到关于该段的一些信息。

### **`LC_ENCRYPTION_INFO[_64]`**

支持二进制加密。不过，如果攻击者成功攻陷进程，当然可以将内存以未加密形式 dump 出来。

### **`LC_LOAD_DYLINKER`**

包含将共享库映射到进程地址空间的动态链接器可执行文件的路径。该值**始终设置为 `/usr/lib/dyld`**。需要注意的是，在 macOS 中，dylib 的映射发生在**user mode**，而不是内核态（kernel mode）。

### **`LC_IDENT`**

已废弃，但当配置为在 panic 时生成转储时，会创建 Mach-O core dump，并且内核版本会在 `LC_IDENT` 命令中设置。

### **`LC_UUID`**

随机 UUID。本身直接用途有限，但 XNU 会将其与其他进程信息一起缓存，可用于崩溃报告。

### **`LC_DYLD_ENVIRONMENT`**

允许在进程执行前向 dyld 指定环境变量。这可能非常危险，因为它可能允许在进程内执行任意代码，因此该 load command 仅在 dyld 使用 `#define SUPPORT_LC_DYLD_ENVIRONMENT` 构建时使用，并且进一步将处理限制为形如 `DYLD_..._PATH` 的变量（用于指定加载路径）。

### **`LC_LOAD_DYLIB`**

该 load command 描述了一个**动态库（dynamic library）**依赖，指示 loader（dyld）去加载并链接该库。对于 Mach-O 二进制所需的每个库，都会有一个 `LC_LOAD_DYLIB` load command。

- 该 load command 的结构类型为 **`dylib_command`**（其中包含一个 struct dylib，描述实际的依赖动态库）：
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

你也可以通过 cli 使用以下命令获取这些信息：
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
一些可能与 malware 相关的库有：

- **DiskArbitration**：监控 USB 驱动器
- **AVFoundation:** 捕获音频和视频
- **CoreWLAN**：Wi‑Fi 扫描。

> [!TIP]
> 一个 Mach-O 二进制可以包含一个或多个 **构造函数**，这些函数会在 **LC_MAIN** 指定的地址之前被 **执行**。\
> 任何构造函数的偏移量保存在 **__mod_init_func** section 的 **__DATA_CONST** segment。

## **Mach-O 数据**

在文件的核心是数据区域，该区域由 load-commands 区域定义的多个段组成。**每个段中可以包含多种数据节**，每个节都**包含特定类型的代码或数据**。

> [!TIP]
> 数据基本上是由 load commands **LC_SEGMENTS_64** 加载的包含所有**信息**的部分

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

这包括：

- **函数表：** 保存关于程序函数的信息。
- **符号表：** 包含二进制使用的外部函数的信息
- 它还可以包含内部函数、变量名等信息。

要检查它，你可以使用 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 工具：

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

或在命令行中：
```bash
size -m /bin/ls
```
## Objetive-C 常见节

在 `__TEXT` 段 (r-x):

- `__objc_classname`: 类名（字符串）
- `__objc_methname`: 方法名（字符串）
- `__objc_methtype`: 方法类型（字符串）

在 `__DATA` 段 (rw-):

- `__objc_classlist`: 指向所有 Objetive-C 类的指针
- `__objc_nlclslist`: 指向非延迟 Objective-C 类的指针
- `__objc_catlist`: 指向类别的指针
- `__objc_nlcatlist`: 指向非延迟类别的指针
- `__objc_protolist`: 协议列表
- `__objc_const`: 常量数据
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
