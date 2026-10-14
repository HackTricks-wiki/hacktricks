# macOS Universal 二进制文件与 Mach-O 格式

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

macOS 使用 **Mach-O** 可执行文件格式。**Universal** 二进制文件（也称 fat 二进制文件）在一个文件中包含多个特定于架构的 Mach-O 切片。Apple 的开源 `fat.h` 和 `loader.h` 头文件定义了本页介绍的结构和常量。 <sup>[[5]](#references)</sup>

Mach-O 镜像由以下部分组成：

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

使用以下命令搜索该文件：`mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header 以 **magic** 字节开头，后跟文件**包含**的 **arch** 数量（`nfat_arch`），每个 arch 都有一个 `fat_arch` 结构体。

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

你可能已经想到，通常，为 2 种架构编译的 universal 二进制文件，其大小是只为 1 种架构编译的二进制文件的**两倍**。

> [!TIP]
> 对恶意软件或可疑应用进行初步分析时，不要在 `file` 报告“最佳”架构后就停止检查。Universal 二进制文件的不同切片可能包含不同的 imports、load commands 或编译器元数据，因此应先枚举**所有**切片，再分别检查：

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

近期的 macOS SDK 还在 `<mach-o/utils.h>` 中提供了 `macho_for_each_slice()` 和 `macho_best_slice()` 等辅助函数。后者便于模拟 dyld/kernel 会加载的内容，但扫描器仍应遍历每个 slice，以免遗漏特定架构的内容。<sup>[[1]](#references)</sup>

## **Mach-O 头部**

头部包含文件的基本信息，例如用于识别 Mach-O 文件的魔数，以及目标架构的信息。可以通过以下命令找到它：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

有不同的文件类型，可以在[**此处的示例源代码**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)中找到它们的定义。最重要的类型有：

- `MH_OBJECT`：可重定位目标文件（编译的中间产物，尚不是可执行文件）。
- `MH_EXECUTE`：可执行文件。
- `MH_FVMLIB`：固定 VM 库文件。
- `MH_CORE`：代码转储。
- `MH_PRELOAD`：预加载的可执行文件（XNU 已不再支持）。
- `MH_DYLIB`：动态库。
- `MH_DYLINKER`：动态链接器。
- `MH_BUNDLE`：“插件文件”。使用 gcc 的 -bundle 选项生成，并由 `NSBundle` 或 `dlopen` 显式加载。
- `MH_DYSM`：配套的 `.dSym` 文件（包含调试符号的文件）。
- `MH_KEXT_BUNDLE`：内核扩展。

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

或者使用 [Mach-O View](https://sourceforge.net/projects/machoview/)：

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 标志**

源代码还定义了几个用于加载库的标志：

- `MH_NOUNDEFS`：没有未定义引用（已完全链接）
- `MH_DYLDLINK`：Dyld 链接
- `MH_PREBOUND`：动态引用已预绑定。
- `MH_SPLIT_SEGS`：文件将只读和读写段分开。
- `MH_WEAK_DEFINES`：二进制文件具有弱定义符号
- `MH_BINDS_TO_WEAK`：二进制文件使用弱符号
- `MH_ALLOW_STACK_EXECUTION`：使栈可执行
- `MH_NO_REEXPORTED_DYLIBS`：库没有 LC_REEXPORT 命令
- `MH_PIE`：位置无关可执行文件
- `MH_HAS_TLV_DESCRIPTORS`：存在包含线程局部变量的段
- `MH_NO_HEAP_EXECUTION`：不允许执行堆/数据页
- `MH_HAS_OBJC`：二进制文件包含 Objective-C 段
- `MH_SIM_SUPPORT`：模拟器支持
- `MH_DYLIB_IN_CACHE`：用于共享库缓存中的 dylib/framework。

## **Mach-O 加载命令**

这里指定了**文件在内存中的布局**，详细说明**符号表的位置**、执行开始时主线程的上下文，以及所需的**共享库**。它向动态加载器 **(dyld)** 提供有关将二进制文件加载到内存中的指令。

它使用在所提到的 **`loader.h`** 中定义的 **load_command** 结构：

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

系统会以不同方式处理约 **50 种不同类型的 load command**。最常见的有：`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB` 和 `LC_CODE_SIGNATURE`。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本上，这种 Load Command 定义了在执行二进制文件时，如何根据 Data section 中指定的 **offsets** 加载 **\_\_TEXT**（可执行代码）和 **\_\_DATA**（进程数据）**segments**。

这些命令定义了在进程执行时映射到其虚拟内存空间中的 **segments**。

**segments** 有多种类型，例如存放程序可执行代码的 **\_\_TEXT** segment，以及包含进程所用数据的 **\_\_DATA** segment。这些 **segments 位于 Mach-O 文件的 data section 中**。

**每个 segment** 还可以进一步划分为多个 **sections**。**load command 结构**包含相应 segment 中**这些 sections 的信息**。

在 header 中，首先会看到 **segment header**：

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

segment header 示例：

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

此 header 定义了其后出现 header 的 section 数量：

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

**section header** 示例：

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

如果将 **section offset**（0x37DC）与 **arch starts** 的 **offset** 相加，本例中为 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

也可以通过 **command line** 获取 **headers information**：

```bash
otool -lv /bin/ls
```

此命令加载的常见段：

- **`__PAGEZERO`:** 它指示内核**映射** **地址零**，使其**无法被读取、写入或执行**。结构中的 maxprot 和 minprot 变量设为零，表示**此页面没有读、写或执行权限**。
  - 此分配对于**缓解 NULL 指针解引用漏洞**很重要。这是因为 XNU 会强制设置一个硬性零页，确保内存的第一页（仅第一页）不可访问（i386 除外）。二进制文件可以通过构造一个较小的 \_\_PAGEZERO（使用 `-pagezero_size`）来满足此要求，使其覆盖前 4k，同时让其余 32 位内存可在用户模式和内核模式下访问。
- **`__TEXT`**：包含具有**读取**和**执行**权限（不可写）的**可执行** **代码**。此段的常见 section：
  - `__text`：编译后的二进制代码
  - `__const`：常量数据（只读）
  - `__[c/u/os_log]string`：C、Unicode 或 os logs 字符串常量
  - `__stubs` 和 `__stubs_helper`：在动态库加载过程中使用
  - `__unwind_info`：栈展开数据。
  - 请注意，所有这些内容都经过签名，但也被标记为可执行（这为利用不一定需要此权限的 section 提供了更多选择，例如专用于字符串的 section）。
- **`__DATA`**：包含**可读**且**可写**（不可执行）的数据。
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`：非 lazy（加载时绑定）符号指针
  - `__la_symbol_ptr`：Lazy（使用时绑定）符号指针
  - `__const`：应为只读数据（实际上并非如此）
  - `__cfstring`：CoreFoundation 字符串
  - `__data`：全局变量（已初始化）
  - `__bss`：静态变量（未初始化）
  - `__objc_*` (\_\_objc_classlist、\_\_objc_protolist 等)：Objective-C runtime 使用的信息
- **`__DATA_CONST`**：\_\_DATA.\_\_const 不保证是常量（具有写权限），其他指针和 GOT 也一样。此段会使用 `mprotect` 将 `__const`、某些初始化器以及 GOT 表（解析后）设为**只读**。
- **`__AUTH` / `__AUTH_CONST`**：常见于较新的 Apple Silicon 二进制文件。这些段存放必须在加载时或使用时进行认证的指针（例如 `__auth_got`）。如果 rebinding、hook 或 import-patching 技巧只检查旧版的 `__got` / `__la_symbol_ptr` section，就可能漏掉现代 `arm64e` 二进制文件中的实际调用点。有关这些 section 的更多详情，请查看[此页面](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)。
- **`__LINKEDIT`**：包含供 linker（dyld）使用的信息，例如符号、字符串和重定位表条目。它是一个通用容器，用于存放既不在 `__TEXT` 也不在 `__DATA` 中的内容，其内容由其他 load commands 描述。
  - dyld 信息：Rebase、Non-lazy/lazy/weak binding opcodes 和导出信息
  - Functions starts：函数起始地址表
  - Data In Code：\_\_text 中的数据岛
  - SYmbol Table：二进制文件中的符号
  - Indirect Symbol Table：指针/stub 符号
  - String Table
  - Code Signature
- **`__OBJC`**：包含 Objective-C runtime 使用的信息。不过，这些信息也可能位于 \_\_DATA 段的各种 \_\_objc\_\* section 中。
- **`__RESTRICT`**：一个不含内容的段，其中只有一个名为 **`__restrict`** 的 section（同样为空），它会确保运行二进制文件时忽略 DYLD 环境变量。

从代码中可以看到，**段也支持 flags**（尽管很少使用）：

- `SG_HIGHVM`：仅用于 Core（未使用）
- `SG_FVMLIB`：未使用
- `SG_NORELOC`：段没有重定位
- `SG_PROTECTED_VERSION_1`：加密。例如 Finder 会使用它来加密 `__TEXT` 段。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** 在 **entryoff 属性中**包含入口点。加载时，**dyld** 只需将此值**加到**（内存中的）二进制文件**基址**上，然后**跳转**到此指令以开始执行二进制文件的代码。

**`LC_UNIXTHREAD`** 包含启动主线程时寄存器必须具有的值。虽然它已弃用，但 **`dyld`** 仍会使用它。可以通过以下方式查看由此设置的寄存器值：

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


包含有关 **Mach-O 文件代码签名**的信息。它只包含一个指向**签名 blob**的**偏移量**。该 blob 通常位于文件末尾。\
有关此 section 的更多信息，请参阅[**这篇博客文章**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)和[**这段 gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

支持二进制加密。不过，如果攻击者设法攻陷进程，就能以未加密的形式转储内存。

### **`LC_LOAD_DYLINKER`**

包含将共享库映射到进程地址空间的**动态链接器可执行文件的路径**。**该值始终为 `/usr/lib/dyld`**。值得注意的是，在 macOS 中，dylib 映射发生在**用户态**，而非内核态。

### **`LC_IDENT`**

此命令已过时，但如果配置为在 panic 时生成转储，就会创建 Mach-O core dump，并在 `LC_IDENT` 命令中设置内核版本。

### **`LC_UUID`**

随机 UUID。它本身没有直接用途，但 XNU 会将其与其余进程信息一同缓存。它可用于 crash report。

### **`LC_BUILD_VERSION`**

现代二进制文件通常包含此命令，用于声明**目标平台**、**最低 OS 版本**、**SDK 版本**，以及可选的用于构建该 slice 的**工具版本**。从攻击或逆向分析的角度来看，这对于识别样本的构建方式非常有用，也能快速发现异常的 universal binary，例如其中一个 slice 使用了不同的 SDK 或 deployment target 编译。较旧的二进制文件可能仍会使用 `LC_VERSION_MIN_*`。

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

允许在进程执行前向 dyld 指定环境变量。这可能非常危险，因为它可能允许在进程内部执行任意代码，因此此 load command 仅用于定义了 `#define SUPPORT_LC_DYLD_ENVIRONMENT` 的 dyld build，并进一步将处理范围限制为指定加载路径的 `DYLD_..._PATH` 形式的变量。

### **`LC_DYLD_EXPORTS_TRIE` 和 `LC_DYLD_CHAINED_FIXUPS`**

较新的工具链通常会将 export/bind/rebase 元数据存储在这些命令中，而不是仅依赖较旧的 `LC_DYLD_INFO[_ONLY]` 操作码。两者都是指向 **`__LINKEDIT`** 的 `linkedit_data_command` 条目：

- **`LC_DYLD_EXPORTS_TRIE`**：包含映像导出符号的紧凑 trie。
- **`LC_DYLD_CHAINED_FIXUPS`**：dyld 用于应用 rebases 和 binds 的逐段 fixup 链。在 Apple Silicon 上，你也会在这里遇到许多现代的 authenticated pointer fixups。

在重建 imports/exports、了解通过 `@rpath` 加载的依赖为何以某种方式解析，或排查 hook/rebinding 尝试为何在现代 `arm64e` 目标上失败时，这些元数据非常有用。`dyld_info` 也可用于检查仅存在于 cache 中、磁盘上没有独立文件的 dylib 路径。在现代 macOS 上，许多系统库仅存在于 shared cache 中，因此这一点非常实用。<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

这个现代 load command 主要用于检查 **kernel collections / kernelcache-style filesets**。外层 Mach-O 不再表示单个独立映像，而是充当容器；每个 `LC_FILESET_ENTRY` 都指向一个内嵌的 Mach-O，并包含其类似路径的 **entry id**、VM 地址和文件偏移。如果你正在逆向现代 macOS/iOS 内核组件，这个 command 通常是连接顶层容器与要提取或反汇编的实际映像的桥梁。

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

For practical extraction workflows, check [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

此加载命令描述一个**动态** **库**依赖项，它会**指示** **加载器**（dyld）**加载并链接该库**。Mach-O 二进制文件所需的**每个库**都有一个 `LC_LOAD_DYLIB` 加载命令。

- 此加载命令是 **`dylib_command`** 类型的结构（其中包含一个 struct dylib，用于描述实际依赖的动态库）：

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t 兼容版本；/ 库的兼容版本号 /](<../../../images/image (486).png>)

也可以通过以下命令行获取此信息：

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

一些可能与 malware 相关的库包括：

- **DiskArbitration**：监控 USB 驱动器
- **AVFoundation:** 捕获音频和视频
- **CoreWLAN**：扫描 Wi-Fi。

> [!TIP]
> Mach-O binary 可以包含一个或**多个** **constructors**，它们会在 **LC_MAIN** 指定的地址之前**执行**。\
> 任何 constructor 的偏移量都保存在 **\_\_DATA_CONST** segment 的 **\_\_mod_init_func** section 中。

## **Mach-O Data**

文件的核心是 data 区域，它由 load-commands 区域中定义的多个 segment 组成。每个 segment 中可以包含**各种 data section**，每个 section **存放特定类型的代码或数据**。

> [!TIP]
> Data 基本上是由 load commands **LC_SEGMENTS_64** 加载的所有**信息**所在的部分。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

其中包括：

- **Function table:** 存放程序函数的信息。
- **Symbol table**：包含 binary 使用的外部函数的信息。
- 它也可能包含内部函数名、变量名等。

可以使用 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 工具进行检查：

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

或者通过 CLI：

```bash
size -m /bin/ls
```

### 附加数据与反向解析覆盖数据

loader 可以将配置保存在附加数据中，而不是命名的 Mach-O section 中。反向解析器随后以尾部标记为定位点，读取紧邻其前存储的大小，并利用该值定位并解密前面的 blob。某个被观察到的 universal loader 使用这种布局来存放经过 XOR 加密的 downloader URL：<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

对陌生的二进制文件进行逆向分析时，应检查可识别结束标记附近的字节，并追踪每一处向后计算大小的逻辑，然后再假设字符串或配置必定属于某个 load-command section。标记和 XOR 密钥因样本而异；可复用的技术是自描述尾部。

## Objective-C 常见 Sections

在 `__TEXT` segment (r-x) 中：

- `__objc_classname`：类名（字符串）
- `__objc_methname`：方法名（字符串）
- `__objc_methtype`：方法类型（字符串）

在 `__DATA` segment (rw-) 中：

- `__objc_classlist`：指向所有 Objective-C 类的指针
- `__objc_nlclslist`：指向 Non-Lazy Objective-C 类的指针
- `__objc_catlist`：指向 Categories 的指针
- `__objc_nlcatlist`：指向 Non-Lazy Categories 的指针
- `__objc_protolist`：Protocols 列表
- `__objc_const`：常量数据
- `__objc_imageinfo`、`__objc_selrefs`、`objc__protorefs`...

## Swift

- `_swift_typeref`、`_swift3_capture`、`_swift3_assocty`、`_swift3_types, _swift3_proto`、`_swift3_fieldmd`、`_swift3_builtin`、`_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-O slices 并不像你想的那么简单](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) 手册页](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [读取你自己的 Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py（gist）](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple 开源项目 - Mach-O `fat.h` 和 `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - 新版 MacSync macOS 窃密程序瞄准加密货币爱好者和开发者](https://securelist.com/macsync-new-version/121383/)
