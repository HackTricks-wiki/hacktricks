# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

Mac OS 二进制文件通常会被编译为 **universal binaries**。**universal binary** 可以在同一个文件中 **支持多种架构**。

这些二进制文件遵循 **Mach-O 结构**，基本由以下部分组成：

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

Header 包含 **magic** 字节，后面跟着文件 **包含** 的 **arch 数量**（`nfat_arch`），并且每个 arch 都会有一个 `fat_arch` 结构体。

使用以下命令进行检查：

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

正如你可能想到的那样，通常为 2 种架构编译的 universal binary，其大小会是仅为 1 种架构编译的二进制文件的 **两倍**。

> [!TIP]
> 对 malware 或可疑应用进行 triage 时，不要在 `file` 报告了“最佳”架构后就停止。universal binary 可能会在每个 slice 中隐藏不同的 imports、load commands 或 compiler metadata，因此应先枚举 **所有** slice，然后分别进行检查：
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Recent macOS SDK 还在 `<mach-o/utils.h>` 中提供了 `macho_for_each_slice()` 和 `macho_best_slice()` 等辅助函数。后者便于模拟 dyld/kernel 将加载的内容，但 scanners 仍应遍历每个 slice，以避免遗漏特定架构的内容。<sup>[[1]](#references)</sup>

## **Mach-O Header**

该 header 包含文件的基本信息，例如用于将其识别为 Mach-O 文件的 magic bytes，以及目标架构的信息。可以通过以下命令找到它：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

存在不同的文件类型，你可以在[**例如这里的源代码中找到它们的定义**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)。其中最重要的有：

- `MH_OBJECT`：可重定位目标文件（编译的中间产物，尚未成为可执行文件）。
- `MH_EXECUTE`：可执行文件。
- `MH_FVMLIB`：固定 VM 库文件。
- `MH_CORE`：代码转储。
- `MH_PRELOAD`：预加载的可执行文件（XNU 已不再支持）。
- `MH_DYLIB`：动态库。
- `MH_DYLINKER`：动态链接器。
- `MH_BUNDLE`：“Plugin 文件”。使用 gcc 中的 -bundle 生成，并由 `NSBundle` 或 `dlopen` 显式加载。
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

源代码还定义了几个对加载 libraries 很有用的 flags：

- `MH_NOUNDEFS`：没有未定义的引用（已完全链接）
- `MH_DYLDLINK`：Dyld linking
- `MH_PREBOUND`：Dynamic references prebound。
- `MH_SPLIT_SEGS`：文件将 r/o 和 r/w segments 分开。
- `MH_WEAK_DEFINES`：Binary 包含 weak defined symbols
- `MH_BINDS_TO_WEAK`：Binary 使用 weak symbols
- `MH_ALLOW_STACK_EXECUTION`：使 stack 可执行
- `MH_NO_REEXPORTED_DYLIBS`：Library 不包含 LC_REEXPORT commands
- `MH_PIE`：Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`：存在包含 thread local variables 的 section
- `MH_NO_HEAP_EXECUTION`：heap/data pages 不可执行
- `MH_HAS_OBJC`：Binary 包含 oBject-C sections
- `MH_SIM_SUPPORT`：Simulator 支持
- `MH_DYLIB_IN_CACHE`：用于 shared library cache 中的 dylibs/frameworks。

## **Mach-O Load commands**

**文件在内存中的布局**在此处指定，其中详细说明了**symbol table 的位置**、执行开始时主线程的上下文，以及所需的 **shared libraries**。其中向 dynamic loader **(dyld)** 提供了有关如何将 binary 加载到内存中的指令。

它使用 **load_command** structure，该 structure 定义在前面提到的 **`loader.h`** 中：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
系统会以不同方式处理大约 **50 种不同类型的 load commands**。最常见的类型包括：`LC_SEGMENT_64`、`LC_LOAD_DYLINKER`、`LC_MAIN`、`LC_LOAD_DYLIB` 和 `LC_CODE_SIGNATURE`。

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 基本上，这类 Load Command 定义了在 binary 执行时，如何根据 Data section 中指示的 **offsets** 加载 **\_\_TEXT**（可执行代码）和 **\_\_DATA**（进程数据）**segments**。

这些 commands 定义了在进程执行时映射到其**虚拟内存空间**中的 **segments**。

**segments** 有不同类型，例如用于存放程序可执行代码的 **\_\_TEXT** segment，以及包含进程所使用数据的 **\_\_DATA** segment。这些 **segments 位于 Mach-O 文件的 data section 中**。

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

该 header 定义了其后出现 section headers 的**section 数量**：
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
此命令加载的常见 segment：

- **`__PAGEZERO`：** 它指示 kernel **map** **address zero**，使其无法被 **read、written 或 executed**。结构中的 maxprot 和 minprot 变量被设置为零，表示 **此 page 没有 read-write-execute 权限**。
- 此 allocation 对于**缓解 NULL pointer dereference vulnerabilities** 非常重要。这是因为 XNU enforces a hard page zero，确保 memory 的第一个 page（仅第一个）无法访问（i386 除外）。binary 可以通过构造一个较小的 \_\_PAGEZERO（使用 `-pagezero_size`）来满足此要求，使其覆盖前 4k，同时让其余 32bit memory 在 user 和 kernel mode 下都可访问。
- **`__TEXT`**：包含具有 **read** 和 **execute** 权限的 **executable** **code**（不可 writable）**。**此 segment 的常见 sections：
- `__text`：Compiled binary code
- `__const`：Constant data（read only）
- `__[c/u/os_log]string`：C、Unicode 或 os logs 的 string constants
- `__stubs` 和 `__stubs_helper`：在 dynamic library loading 过程中使用
- `__unwind_info`：Stack unwind data。
- 注意，所有这些内容都经过 signed，但也被标记为 executable（这为利用不一定需要此 privilege 的 sections 创造了更多选项，例如专用于 string 的 sections）。
- **`__DATA`**：包含可 **readable** 且 **writable** 的 data（不可 executable）**。**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`：Non lazy（bind at load）symbol pointer
- `__la_symbol_ptr`：Lazy（bind on use）symbol pointer
- `__const`：应为 read-only data（实际上并非如此）
- `__cfstring`：CoreFoundation strings
- `__data`：Global variables（已 initialized）
- `__bss`：Static variables（尚未 initialized）
- `__objc_*`（\_\_objc_classlist、\_\_objc_protolist 等）：Objective-C runtime 使用的信息
- **`__DATA_CONST`**：\_\_DATA.\_\_const 不保证为 constant（具有 write permissions），其他 pointers 和 GOT 也同样如此。此 section 使用 `mprotect` 将 `__const`、某些 initializers 以及 GOT table（resolved 后）设置为 **read only**。
- **`__AUTH` / `__AUTH_CONST`**：常见于较新的 Apple Silicon binaries。这些 segments 保存必须在 load 或 use 时经过 authenticated 的 pointers（例如 `__auth_got`）。如果 rebinding、hook 或 import-patching trick 只检查 legacy `__got` / `__la_symbol_ptr` sections，可能会遗漏 modern `arm64e` binaries 中真正的 call sites。有关这些 sections 的更多 details，请查看 [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)。
- **`__LINKEDIT`**：包含 linker（dyld）所需的信息，例如 symbol、string 和 relocation table entries。它是一个用于存放既不属于 `__TEXT` 也不属于 `__DATA` 的内容的通用 container，其内容会在其他 load commands 中描述。
- dyld information：Rebase、Non-lazy/lazy/weak binding opcodes 和 export info
- Functions starts：Functions start addresses 的 table
- Data In Code：\_\_text 中的 data islands
- SYmbol Table：Binary 中的 symbols
- Indirect Symbol Table：Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**：包含 Objective-C runtime 使用的信息。虽然这些信息也可能位于 \_\_DATA segment 中的各种 \_\_objc\_\* sections 内。
- **`__RESTRICT`**：一个不含 content 的 segment，其中只有一个名为 **`__restrict`** 的 section（同样为空），用于确保运行 binary 时忽略 DYLD environmental variables。

如代码中所见，**segments 也支持 flags**（尽管它们并不常用）：

- `SG_HIGHVM`：仅 Core（未使用）
- `SG_FVMLIB`：未使用
- `SG_NORELOC`：Segment 没有 relocation
- `SG_PROTECTED_VERSION_1`：Encryption。例如 Finder 用它来 encrypt `__TEXT` segment。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** 在 **`entryoff attribute` 中包含 entrypoint。** 在 load 时，**dyld** 只需将此值加到 binary 的（in-memory）**base**，然后 **jump** 到此 instruction，以开始执行 binary 的 code。

**`LC_UNIXTHREAD`** 包含 main thread 启动时 registers 必须具有的 values。该方式已被 deprecated，但 **`dyld`** 仍会使用它。可以使用以下命令查看通过此方式设置的 registers 的 vlaues：
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


包含有关 **Mach-O 文件代码签名**的信息。它只包含一个 **offset**，该 **offset** **指向** **signature blob**。该 blob 通常位于文件的最末尾。\
不过，你可以在[**这篇博客文章**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)以及这些 [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) 中找到关于此 section 的一些信息。<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

支持二进制加密。不过，当然，如果攻击者成功 compromise 了该进程，他就能够 dump 未加密的内存。

### **`LC_LOAD_DYLINKER`**

包含将共享库映射到进程地址空间中的 **dynamic linker executable 的路径**。**该值始终设置为 `/usr/lib/dyld`**。需要注意的是，在 macOS 中，dylib mapping 发生在 **user mode**，而不是 **kernel mode**。

### **`LC_IDENT`**

已废弃，但在配置为 panic 时生成 dump 的情况下，会创建 Mach-O core dump，并将 kernel 版本设置在 `LC_IDENT` command 中。

### **`LC_UUID`**

随机 UUID。它本身并不直接用于任何功能，但 XNU 会将其与其余进程信息一起缓存。它可以用于 crash reports。

### **`LC_BUILD_VERSION`**

现代 binaries 通常包含此 command，用于声明 **target platform**、**minimum OS version**、**SDK version**，以及可选的用于构建该 slice 的 **tool versions**。从 offensive/reversing 的角度来看，这对于 fingerprint sample 的构建方式非常有用，也可以快速发现异常的 universal binaries，例如其中一个 slice 使用了不同的 SDK 或 deployment target 进行编译。较旧的 binaries 可能仍使用 `LC_VERSION_MIN_*`。
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

允许在进程执行之前向 dyld 指定环境变量。这可能非常危险，因为它可能允许在进程内执行任意代码，因此该 load command 仅在使用 `#define SUPPORT_LC_DYLD_ENVIRONMENT` 构建的 dyld 中使用，并进一步将处理限制为 `DYLD_..._PATH` 形式、用于指定加载路径的变量。

### **`LC_DYLD_EXPORTS_TRIE` 和 `LC_DYLD_CHAINED_FIXUPS`**

近期的 toolchain 经常将 export/bind/rebase metadata 存储在这些 commands 中，而不是仅依赖旧版的 `LC_DYLD_INFO[_ONLY]` opcodes。两者都是指向 **`__LINKEDIT`** 的 `linkedit_data_command` 条目：

- **`LC_DYLD_EXPORTS_TRIE`**：包含由该 image 导出的 symbols 的紧凑 trie。
- **`LC_DYLD_CHAINED_FIXUPS`**：按 segment 划分的 fixup chains，dyld 使用它们来应用 rebases 和 binds。在 Apple Silicon 上，这里还会遇到许多现代的 authenticated pointer fixups。

在重建 imports/exports、了解某个通过 `@rpath` 加载的 dependency 为何以这种方式解析，或确定 hook/rebinding 尝试为何在现代 `arm64e` target 上失败时，这些 metadata 都非常有用。`dyld_info` 还可以用于检查仅存在于 **cache** 中的 dylib paths，即磁盘上不存在对应的 standalone files；在现代 macOS 中，许多 system libraries 仅存在于 shared cache 中，因此这一点非常实用。<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

这个现代 load command 在检查 **kernel collections / kernelcache-style filesets** 时尤其相关。它不表示单个独立的 image，而是将外层 Mach-O 作为容器；每个 `LC_FILESET_ENTRY` 都指向一个内嵌的 Mach-O，并包含其自身的类路径 **entry id**、VM address 和文件偏移。如果你正在 reverse engineering 现代 macOS/iOS kernel 组件，此 command 通常是连接顶层容器与实际要提取或反汇编的 image 的桥梁。
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
对于实际的提取工作流，请参阅[这个关于 macOS kernel extensions 和 kernelcache 的页面](../mac-os-architecture/macos-kernel-extensions.md)。

### **`LC_LOAD_DYLIB`**

此 load command 描述一个**动态** **library**依赖项，用于**指示** **loader**（dyld）**加载并链接该 library**。Mach-O binary 所需的**每个 library**都有一个 `LC_LOAD_DYLIB` load command。

- 此 load command 是 **`dylib_command`** 类型的结构（其中包含一个 `struct dylib`，用于描述实际依赖的动态 library）：
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t 兼容性版本；/ library 的兼容性版本号 /](<../../../images/image (486).png>)

你也可以使用以下命令从 cli 获取此信息：
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
一些与 malware 相关的潜在库包括：

- **DiskArbitration**：监控 USB 驱动器
- **AVFoundation:** 捕获音频和视频
- **CoreWLAN**：WiFi 扫描。

> [!TIP]
> 一个 Mach-O binary 可以包含一个或**多个** **constructor**，它们会在 **LC_MAIN** 中指定的地址之前被**执行**。\
> 任意 constructor 的偏移量都保存在 **\_\_DATA_CONST** segment 的 **\_\_mod_init_func** section 中。

## **Mach-O Data**

文件的核心是 data region，它由 load-commands region 中定义的多个 segment 组成。**每个 segment 中都可以包含各种 data section**，每个 section **保存**特定类型的 **code 或 data**。

> [!TIP]
> data 基本上就是包含由 load commands **LC_SEGMENTS_64** 加载的所有**信息**的部分。

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

其中包括：

- **Function table：**保存有关程序 functions 的信息。
- **Symbol table**：包含 binary 使用的 external function 的信息
- 它还可能包含 internal function、variable names 等更多内容。

要检查这些内容，可以使用 [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool：

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

也可以通过 CLI：
```bash
size -m /bin/ls
```
## Objective-C 常见节区

在 `__TEXT` segment（r-x）中：

- `__objc_classname`：Class 名称（字符串）
- `__objc_methname`：Method 名称（字符串）
- `__objc_methtype`：Method 类型（字符串）

在 `__DATA` segment（rw-）中：

- `__objc_classlist`：指向所有 Objective-C Class 的指针
- `__objc_nlclslist`：指向 Non-Lazy Objective-C Class 的指针
- `__objc_catlist`：指向 Categories 的指针
- `__objc_nlcatlist`：指向 Non-Lazy Categories 的指针
- `__objc_protolist`：Protocols 列表
- `__objc_const`：常量数据
- `__objc_imageinfo`、`__objc_selrefs`、`objc__protorefs`……

## Swift

- `_swift_typeref`、`_swift3_capture`、`_swift3_assocty`、`_swift3_types`、`_swift3_proto`、`_swift3_fieldmd`、`_swift3_builtin`、`_swift3_reflstr`

## References

- [1] [Mach-O slices 并不像你想象的那么简单](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man 页面](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [读取你自己的 Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py（gist）](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
