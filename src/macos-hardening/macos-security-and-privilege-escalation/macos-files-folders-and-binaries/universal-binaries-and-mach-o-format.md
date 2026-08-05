# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

Mac OS binaries 通常会被编译为 **universal binaries**。**universal binary** 可以在**同一个文件中支持多种架构**。

这些 binaries 遵循 **Mach-O 结构**，基本由以下部分组成：

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

Header 包含 **magic** bytes，后面是文件**包含**的 **archs** **数量**（`nfat_arch`），并且每个 arch 都会有一个 `fat_arch` struct。

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

正如你可能想到的，通常为 2 种架构编译的 universal binary，其大小是仅为 1 种 arch 编译的 binary 的**两倍**。

> [!TIP]
> 在分析 malware 或可疑 app 时，不要在 `file` 报告“最佳”架构后就停止。universal binary 可能会在每个 slice 中隐藏不同的 imports、load commands 或 compiler metadata，因此应先枚举**所有** slice，然后分别对其进行检查：
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
近期的 macOS SDK 还在 `<mach-o/utils.h>` 中提供了 `macho_for_each_slice()` 和 `macho_best_slice()` 等辅助函数。后者便于模拟 dyld/kernel 会加载的内容，但 scanners 仍应遍历每个 slice，以避免遗漏特定架构的内容。<sup>[[1]](#references)</sup>

## **Mach-O Header**

该 header 包含文件的基本信息，例如用于将其识别为 Mach-O 文件的 magic bytes，以及目标架构的信息。你可以使用以下命令找到它：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

存在不同的文件类型，你可以在[**例如这里的源代码中找到它们的定义**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)。最重要的类型包括：

- `MH_OBJECT`：可重定位目标文件（编译的中间产物，尚未成为可执行文件）。
- `MH_EXECUTE`：可执行文件。
- `MH_FVMLIB`：固定 VM 库文件。
- `MH_CORE`：代码转储。
- `MH_PRELOAD`：预加载的可执行文件（XNU 已不再支持）。
- `MH_DYLIB`：动态库。
- `MH_DYLINKER`：动态链接器。
- `MH_BUNDLE`：“插件文件”。使用 gcc 中的 -bundle 生成，并由 `NSBundle` 或 `dlopen` 显式加载。
- `MH_DYSM`：配套的 `.dSym` 文件（包含用于调试的符号的文件）。
- `MH_KEXT_BUNDLE`：Kernel Extensions。
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
或者使用 [Mach-O View](https://sourceforge.net/projects/machoview/)：

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

源代码还定义了几个用于加载 libraries 的 flags：

- `MH_NOUNDEFS`：没有 undefined references（已完全链接）
- `MH_DYLDLINK`：Dyld linking
- `MH_PREBOUND`：Dynamic references 已预绑定。
- `MH_SPLIT_SEGS`：文件将 r/o 和 r/w segments 分开。
- `MH_WEAK_DEFINES`：Binary 包含 weak defined symbols
- `MH_BINDS_TO_WEAK`：Binary 使用 weak symbols
- `MH_ALLOW_STACK_EXECUTION`：使 stack 可执行
- `MH_NO_REEXPORTED_DYLIBS`：Library 不包含 LC_REEXPORT commands
- `MH_PIE`：Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`：存在包含 thread local variables 的 section
- `MH_NO_HEAP_EXECUTION`：heap/data pages 不可执行
- `MH_HAS_OBJC`：Binary 包含 oBject-C sections
- `MH_SIM_SUPPORT`：Simulator support
- `MH_DYLIB_IN_CACHE`：用于 shared library cache 中的 dylibs/frameworks。

## **Mach-O Load commands**

**文件在内存中的布局**在此处指定，其中详细说明了 **symbol table 的位置**、执行开始时主线程的上下文，以及所需的 **shared libraries**。这些 instructions 会提供给 dynamic loader **(dyld)**，说明 binary 如何加载到内存中。

该文件使用 **`loader.h`** 中定义的 **load_command** structure：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
系统会以不同方式处理大约 **50 种不同类型的 load commands**。最常见的有：`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB` 和 `LC_CODE_SIGNATURE`。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本上，这类 Load Command 定义了在 binary 执行时，如何根据 Data section 中标示的 **offsets** 加载 **\_\_TEXT**（executable code）和 **\_\_DATA**（process 使用的数据）**segments**。

这些 commands 定义了在执行 process 时映射到其 **virtual memory space** 中的 **segments**。

**segments** 有不同类型，例如保存程序 executable code 的 **\_\_TEXT** segment，以及包含 process 使用数据的 **\_\_DATA** segment。这些 **segments 位于 Mach-O 文件的 data section 中**。

**每个 segment** 还可以进一步划分为多个 **sections**。**load command structure** 包含相应 segment 中这些 **sections** 的**信息**。

在 header 中，首先可以找到 **segment header**：

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

该 header 定义了其后出现 section headers 的 **sections 数量**：
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

也可以通过以下 **command line** 获取 **headers information**：
```bash
otool -lv /bin/ls
```
此 cmd 加载的常见 segment：

- **`__PAGEZERO`：** 它指示 kernel **映射** **地址零**，使其**无法被读取、写入或执行**。结构中的 maxprot 和 minprot 变量被设为零，表示**此页面没有读-写-执行权限**。
- 此分配对于**缓解 NULL pointer dereference vulnerabilities**非常重要。这是因为 XNU 强制实施 hard page zero，确保内存的第一页（仅第一页）不可访问（i386 除外）。二进制文件可以通过构造一个较小的 \_\_PAGEZERO（使用 `-pagezero_size`）来覆盖前 4k，并使其余 32bit 内存可在 user 和 kernel mode 下访问，从而满足此要求。
- **`__TEXT`**：包含具有**读取**和**执行**权限的**可执行**代码（不可写）**。**此 segment 的常见 sections：
- `__text`：编译后的二进制代码
- `__const`：常量数据（只读）
- `__[c/u/os_log]string`：C、Unicode 或 os logs 字符串常量
- `__stubs` 和 `__stubs_helper`：在 dynamic library 加载过程中使用
- `__unwind_info`：stack unwind 数据。
- 请注意，所有这些内容都经过签名，同时也被标记为可执行（这为利用不一定需要此权限的 sections（例如专用于字符串的 sections）创造了更多选择）。
- **`__DATA`**：包含**可读**且**可写**的数据（不可执行）**。**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`：Non lazy（在加载时 bind）symbol pointer
- `__la_symbol_ptr`：Lazy（使用时 bind）symbol pointer
- `__const`：应为只读数据（实际上并非如此）
- `__cfstring`：CoreFoundation 字符串
- `__data`：全局变量（已初始化）
- `__bss`：静态变量（未初始化）
- `__objc_*`（\_\_objc_classlist、\_\_objc_protolist 等）：Objective-C runtime 使用的信息
- **`__DATA_CONST`**：\_\_DATA.\_\_const 不保证为常量（具有写权限），其他 pointers 和 GOT 也同样如此。此 section 使用 `mprotect` 将 `__const`、某些 initializers 以及 GOT table（解析后）设为**只读**。
- **`__AUTH` / `__AUTH_CONST`**：常见于较新的 Apple Silicon 二进制文件。这些 segments 保存必须在加载或使用时进行 authenticated 的 pointers（例如 `__auth_got`）。如果 rebinding、hook 或 import-patching trick 只检查 legacy `__got` / `__la_symbol_ptr` sections，可能会遗漏现代 `arm64e` 二进制文件中的真实 call sites。有关这些 sections 的更多详细信息，请查看[此页面](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)。
- **`__LINKEDIT`**：包含 linker（dyld）所需的信息，例如 symbol、string 和 relocation table entries。它是一个通用容器，用于存放既不属于 `__TEXT` 也不属于 `__DATA` 的内容，其内容会在其他 load commands 中描述。
- dyld 信息：Rebase、Non-lazy/lazy/weak binding opcodes 和 export info
- Functions starts：函数起始地址表
- Data In Code：\_\_text 中的数据 islands
- SYmbol Table：二进制文件中的 Symbols
- Indirect Symbol Table：Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**：包含 Objective-C runtime 使用的信息。不过，这些信息也可能位于 \_\_DATA segment 中的各种 \_\_objc\_\* sections 内。
- **`__RESTRICT`**：一个不包含内容的 segment，其中只有一个名为 **`__restrict`** 的 section（同样为空），用于确保运行二进制文件时忽略 DYLD environmental variables。

正如在代码中所见，**segments 也支持 flags**（尽管它们并不常用）：

- `SG_HIGHVM`：仅 Core（未使用）
- `SG_FVMLIB`：未使用
- `SG_NORELOC`：Segment 没有 relocation
- `SG_PROTECTED_VERSION_1`：Encryption。例如，Finder 使用它来加密 `__TEXT` segment。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** 在 **`entryoff` attribute 中包含 entrypoint。**在加载时，**dyld** 只需将此值加到二进制文件的（内存中）**base** 上，然后**跳转**到此 instruction，以开始执行二进制文件的代码。

**`LC_UNIXTHREAD`** 包含主 thread 启动时 registers 必须具有的值。虽然这已经被 deprecated，但 **`dyld`** 仍然使用它。可以使用以下命令查看通过此方式设置的 registers 值：
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


包含 **Mach-O 文件代码签名**的信息。它只包含一个 **offset**，用于 **指向** **signature blob**。该 blob 通常位于文件的最末尾。\
不过，你可以在[**这篇 blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)以及这些 [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)中找到有关此 section 的一些信息。<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

支持 binary encryption。不过，当然，如果 attacker 成功 compromise 该 process，他将能够 dump 未加密的 memory。

### **`LC_LOAD_DYLINKER`**

包含用于将 shared libraries 映射到 process address space 中的 **dynamic linker executable 的路径**。**该值始终设置为 `/usr/lib/dyld`**。需要注意的是，在 macOS 中，dylib mapping 发生在 **user mode**，而不是 kernel mode。

### **`LC_IDENT`**

该命令已过时，但在配置为在 panic 时生成 dumps 后，会创建 Mach-O core dump，并且 kernel version 会设置在 `LC_IDENT` command 中。

### **`LC_UUID`**

随机 UUID。它本身没有直接用途，但 XNU 会将其与其余 process info 一起缓存。它可以用于 crash reports。

### **`LC_BUILD_VERSION`**

现代 binaries 通常包含此 command，用于声明 **target platform**、**minimum OS version**、**SDK version**，以及可选的用于构建该 slice 的 **tool versions**。从 offensive/reversing 的角度来看，这对于 fingerprint sample 的构建方式非常有用，也能快速发现异常的 universal binaries，例如其中一个 slice 使用了不同的 SDK 或 deployment target 进行编译。较旧的 binaries 可能仍会使用 `LC_VERSION_MIN_*`。
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

允许在执行进程之前向 dyld 指定环境变量。这可能非常危险，因为它可能允许在进程内部执行任意代码，因此该 load command 仅在包含 `#define SUPPORT_LC_DYLD_ENVIRONMENT` 的 dyld build 中使用，并进一步将处理范围限制为指定 load paths 的 `DYLD_..._PATH` 形式变量。

### **`LC_DYLD_EXPORTS_TRIE` 和 `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains 经常将 export/bind/rebase metadata 存储在这些 commands 中，而不是仅依赖较旧的 `LC_DYLD_INFO[_ONLY]` opcodes。两者都是指向 **`__LINKEDIT`** 内部数据的 `linkedit_data_command` entries：

- **`LC_DYLD_EXPORTS_TRIE`**：包含该 image 所 export symbols 的 Compact trie。
- **`LC_DYLD_CHAINED_FIXUPS`**：由 dyld 使用的 per-segment fixup chains，用于应用 rebases 和 binds。在 Apple Silicon 上，这里也会遇到许多现代的 authenticated pointer fixups。

在重建 imports/exports、理解某个通过 `@rpath` 加载的 dependency 为何以特定方式解析，或查明 hook/rebinding 尝试为何在现代 `arm64e` target 上失败时，这些 metadata 非常有用。`dyld_info` 还可以用于分析 **cache-only dylib paths**，即磁盘上不存在对应 standalone files 的路径；在现代 macOS 中，许多 system libraries 仅存在于 shared cache 中，因此这一点非常实用。<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

这个现代 load command 主要用于检查 **kernel collections / kernelcache-style filesets**。外层 Mach-O 不再表示单个独立 image，而是充当一个容器；每个 `LC_FILESET_ENTRY` 都指向一个嵌入其中的 Mach-O，并包含其自身的类路径 **entry id**、VM 地址和文件偏移。如果你正在逆向现代 macOS/iOS kernel 组件，这个 command 通常是连接顶层容器与实际要提取或反汇编的 image 的桥梁。
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
对于实际的提取流程，请查看[这个关于 macOS kernel extensions 和 kernelcache 的页面](../mac-os-architecture/macos-kernel-extensions.md)。

### **`LC_LOAD_DYLIB`**

此 load command 描述一个**动态** **库**依赖项，它会**指示** **loader**（dyld）**加载并链接该库**。对于 Mach-O binary 所需的**每个库**，都会有一个 `LC_LOAD_DYLIB` load command。

- 此 load command 是 `dylib_command` 类型的结构（其中包含一个 `dylib` 结构，用于描述实际依赖的动态库）：
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

你也可以通过 CLI 获取此信息：
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
一些与 malware 相关的潜在 libraries 包括：

- **DiskArbitration**：监控 USB drives
- **AVFoundation:** 捕获 audio 和 video
- **CoreWLAN**：执行 Wifi scans。

> [!TIP]
> Mach-O binary 可以包含一个或**多个** **constructors**，它们会在 **LC_MAIN** 中指定的 address 之前被**执行**。\
> 任意 constructors 的 offsets 都保存在 **\_\_DATA_CONST** segment 的 **\_\_mod_init_func** section 中。

## **Mach-O Data**

文件的核心是 data region，由 load-commands region 中定义的多个 segments 组成。**每个 segment 中都可以包含各种 data sections**，每个 section **保存特定类型的 code 或 data**。

> [!TIP]
> data 基本上就是包含由 load commands **LC_SEGMENTS_64** 加载的所有**信息**的部分。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

其中包括：

- **Function table:** 保存 program functions 的信息。
- **Symbol table**：包含 binary 所使用的 external functions 的信息
- 它还可以包含 internal functions、variable names 以及更多内容。

要检查这些内容，可以使用 [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool：

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

或者从 cli：
```bash
size -m /bin/ls
```
## Objective-C 常见区段

在 `__TEXT` 段（r-x）中：

- `__objc_classname`：类名（字符串）
- `__objc_methname`：方法名（字符串）
- `__objc_methtype`：方法类型（字符串）

在 `__DATA` 段（rw-）中：

- `__objc_classlist`：指向所有 Objective-C 类的指针
- `__objc_nlclslist`：指向 Non-Lazy Objective-C 类的指针
- `__objc_catlist`：指向 Categories 的指针
- `__objc_nlcatlist`：指向 Non-Lazy Categories 的指针
- `__objc_protolist`：Protocols 列表
- `__objc_const`：常量数据
- `__objc_imageinfo`、`__objc_selrefs`、`objc__protorefs`……

## Swift

- `_swift_typeref`、`_swift3_capture`、`_swift3_assocty`、`_swift3_types`、`_swift3_proto`、`_swift3_fieldmd`、`_swift3_builtin`、`_swift3_reflstr`



## 参考资料

- [1] [Mach-O slices 并不像你想象的那么简单](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man 页面](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [读取你自己的 Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py（gist）](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
