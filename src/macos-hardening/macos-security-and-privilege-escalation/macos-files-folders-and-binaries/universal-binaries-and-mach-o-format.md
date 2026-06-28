# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

These binaries follows the **Mach-O structure** which is basically compased of:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Search for the file with: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

The header has the **magic** bytes followed by the **number** of **archs** the file **contains** (`nfat_arch`) and each arch will have a `fat_arch` struct.

Check it with:

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

or using the [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

As you may be thinking usually a universal binary compiled for 2 architectures **doubles the size** of one compiled for just 1 arch.

> [!TIP]
> When triaging malware or suspicious apps, don't stop after `file` reports the "best" architecture. A universal binary can hide different imports, load commands or compiler metadata in each slice, so enumerate **all** the slices first and then inspect them independently:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
最近的 macOS SDK 还暴露了诸如 `<mach-o/utils.h>` 中的 `macho_for_each_slice()` 和 `macho_best_slice()` 之类的 helper。后者很适合模拟 dyld/kernel 会加载什么，但 scanners 仍然应该遍历每个 slice，以避免遗漏特定架构的内容。

## **Mach-O Header**

header 包含文件的基本信息，例如用于将其标识为 Mach-O 文件的 magic bytes，以及关于目标架构的信息。你可以在这里找到它：`mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

有不同的文件类型，你可以在 [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) 中找到它们的定义。最重要的是：

- `MH_OBJECT`: 可重定位对象文件（编译的中间产物，还不是可执行文件）。
- `MH_EXECUTE`: 可执行文件。
- `MH_FVMLIB`: 固定 VM library 文件。
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: 预加载的可执行文件（在 XNU 中已不再支持）
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". 使用 gcc 中的 -bundle 生成，并由 `NSBundle` 或 `dlopen` 显式加载。
- `MH_DYSM`: 配套的 `.dSym` 文件（包含用于调试的符号的文件）。
- `MH_KEXT_BUNDLE`: Kernel Extensions。
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

源代码还定义了几个对加载库很有用的标志：

- `MH_NOUNDEFS`: 没有未定义引用（完全链接）
- `MH_DYLDLINK`: Dyld 链接
- `MH_PREBOUND`: 动态引用已预绑定。
- `MH_SPLIT_SEGS`: 文件将 r/o 和 r/w 段分开。
- `MH_WEAK_DEFINES`: Binary 有 weak 定义的符号
- `MH_BINDS_TO_WEAK`: Binary 使用 weak 符号
- `MH_ALLOW_STACK_EXECUTION`: 使 stack 可执行
- `MH_NO_REEXPORTED_DYLIBS`: Library 没有 LC_REEXPORT 命令
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: 存在一个包含 thread local variables 的 section
- `MH_NO_HEAP_EXECUTION`: heap/data pages 不允许执行
- `MH_HAS_OBJC`: Binary 有 oBject-C sections
- `MH_SIM_SUPPORT`: Simulator 支持
- `MH_DYLIB_IN_CACHE`: 用于 shared library cache 中的 dylibs/frameworks。

## **Mach-O Load commands**

这里指定了 **file 在 memory 中的布局**，详细说明了 **symbol table 的位置**、程序开始执行时 main thread 的上下文，以及所需的 **shared libraries**。会向 dynamic loader **(dyld)** 提供关于 Binary 加载到 memory 过程的指令。

使用的是 **load_command** structure，定义在前面提到的 **`loader.h`** 中：
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basically, this type of Load Command define **how to load the \_\_TEXT** (executable code) **and \_\_DATA** (data for the process) **segments** according to the **offsets indicated in the Data section** when the binary is executed.

These commands **define segments** that are **mapped** into the **virtual memory space** of a process when it is executed.

There are **different types** of segments, such as the **\_\_TEXT** segment, which holds the executable code of a program, and the **\_\_DATA** segment, which contains data used by the process. These **segments are located in the data section** of the Mach-O file.

**Each segment** can be further **divided** into multiple **sections**. The **load command structure** contains **information** about **these sections** within the respective segment.

In the header first you find the **segment header**:

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

This header defines the **number of sections whose headers appear after** it:
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
Example of **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

If you **add** the **section offset** (0x37DC) + the **offset** where the **arch starts**, in this case `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

也可以通过以下方式从**命令行**获取**头部信息**：
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** 它指示 kernel **map** **address zero**，使其**无法被读取、写入或执行**。结构中的 maxprot 和 minprot 变量被设为 0，以表示该页上**没有读写执行权限**。
- 这个分配对于**缓解 NULL pointer dereference vulnerabilities** 很重要。这是因为 XNU 强制使用硬 page zero，确保内存的第一页（仅第一页）不可访问（i386 例外）。binary 可以通过构造一个较小的 \_\_PAGEZERO（使用 `-pagezero_size`）来覆盖前 4k，并让其余 32bit memory 在 user mode 和 kernel mode 下都可访问，从而满足这个要求。
- **`__TEXT`**: 包含具有**read** 和 **execute** 权限的**可执行** **code**（不可写）**。** 该 segment 的常见 section:
- `__text`: 编译后的 binary code
- `__const`: 常量数据（只读）
- `__[c/u/os_log]string`: C、Unicode 或 os logs 字符串常量
- `__stubs` and `__stubs_helper`: 参与 dynamic library 加载过程
- `__unwind_info`: 栈展开数据。
- 注意，这些内容都经过签名，但也被标记为可执行（这为那些不一定需要该权限的 section 提供了更多 exploitation 选项，例如专门存放字符串的 section）。
- **`__DATA`**: 包含**可读**且**可写**的数据（不可执行）**。**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy（load 时绑定）symbol pointer
- `__la_symbol_ptr`: Lazy（use 时绑定）symbol pointer
- `__const`: 应该是只读数据（但实际上不一定）
- `__cfstring`: CoreFoundation strings
- `__data`: 已初始化的全局变量
- `__bss`: 未初始化的静态变量
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Objective-C runtime 使用的信息
- **`__DATA_CONST`**: \_\_DATA.\_\_const 并不保证是常量（有写权限），其他 pointers 和 GOT 也一样。这个 section 使用 `mprotect` 将 `__const`、部分 initializers 以及 GOT table（解析后）设为**只读**。
- **`__AUTH` / `__AUTH_CONST`**: 在近期的 Apple Silicon binary 中很常见。这些 segment 保存的 pointers 必须在 load 时或 use 时经过认证（例如 `__auth_got`）。如果 rebinding、hook 或 import-patching trick 只检查旧的 `__got` / `__la_symbol_ptr` section，就可能漏掉现代 `arm64e` binary 中真正的 call sites。有关这些 section 的更多细节，请查看 [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)。
- **`__LINKEDIT`**: 包含给 linker（dyld）使用的信息，例如 symbol、string 和 relocation table entries。它是一个通用容器，存放不属于 `__TEXT` 或 `__DATA` 的内容，其内容在其他 load commands 中描述。
- dyld 信息：Rebase、Non-lazy/lazy/weak binding opcodes 和 export info
- Functions starts: 函数起始地址表
- Data In Code: `__text` 中的数据岛
- SYmbol Table: binary 中的符号
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: 包含 Objective-C runtime 使用的信息。尽管这些信息也可能出现在 `__DATA` segment 中的各种 \_\_objc\_\* section 内。
- **`__RESTRICT`**: 一个没有内容的 segment，只有一个名为 **`__restrict`** 的 section（同样为空），它确保 binary 运行时会忽略 DYLD 环境变量。

正如在 code 中可以看到的，**segments 也支持 flags**（不过它们不太常用）：

- `SG_HIGHVM`: 仅 Core 使用（未使用）
- `SG_FVMLIB`: 未使用
- `SG_NORELOC`: Segment 没有 relocation
- `SG_PROTECTED_VERSION_1`: Encryption。例如 Finder 使用它来加密 text `__TEXT` segment。

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** 在 **entryoff attribute** 中包含 entrypoint。加载时，**dyld** 只是将这个值**加到** binary 的（内存中的）**base** 上，然后**跳转**到该指令，以开始执行 binary 的 code。

**`LC_UNIXTHREAD`** 包含启动 main thread 时寄存器必须具有的值。它已经被弃用，但 **`dyld`** 仍然使用它。可以通过以下方式查看由此设置的寄存器值：
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


包含 **Mach-O 文件的 code signature** 信息。它只包含一个 **offset**，用于 **指向** **signature blob**。这通常位于文件的最末尾。\
不过，你可以在[**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)和这个[**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)中找到关于这一部分的一些信息。

### **`LC_ENCRYPTION_INFO[_64]`**

支持 binary encryption。不过，当然，如果攻击者成功 compromise 了该 process，他就能把内存以未加密的形式 dump 出来。

### **`LC_LOAD_DYLINKER`**

包含 **dynamic linker executable 的路径**，它会把 shared libraries 映射到 process address space 中。其 **值始终设置为 `/usr/lib/dyld`**。需要注意的是，在 macOS 中，dylib mapping 发生在 **user mode**，而不是 kernel mode。

### **`LC_IDENT`**

已废弃，但在配置为在 panic 时生成 dumps 时，会创建一个 Mach-O core dump，并且 kernel version 会设置在 `LC_IDENT` command 中。

### **`LC_UUID`**

随机 UUID。它本身没有直接用途，但 XNU 会将它和其余的 process info 一起缓存。它可用于 crash reports。

### **`LC_BUILD_VERSION`**

现代 binaries 通常会携带这个 command，用于声明 **target platform**、**minimum OS version**、**SDK version**，以及可选的用于构建该 slice 的 **tool versions**。从 offensive/reversing 的角度来看，这对 fingerprint 采样是如何构建的非常有用，也能快速发现奇怪的 universal binaries，其中某个 slice 是用不同的 SDK 或 deployment target 编译的。较旧的 binaries 可能仍然使用 `LC_VERSION_MIN_*`。
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

允许在进程执行之前向 dyld 指定环境变量。这可能非常危险，因为它可以允许在进程内执行任意代码，所以这个 load command 只会在启用了 `#define SUPPORT_LC_DYLD_ENVIRONMENT` 的 dyld build 中使用，并且还会进一步限制只处理形如 `DYLD_..._PATH` 的变量，用于指定 load paths。

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

最近的 toolchains 经常将 export/bind/rebase metadata 存储在这些命令中，而不是只依赖旧的 `LC_DYLD_INFO[_ONLY]` opcodes。二者都是指向 **`__LINKEDIT`** 的 `linkedit_data_command` 条目：

- **`LC_DYLD_EXPORTS_TRIE`**：包含 image 导出符号的紧凑 trie。
- **`LC_DYLD_CHAINED_FIXUPS`**：按 segment 分段的 fixup chains，由 dyld 用来应用 rebases 和 binds。在 Apple Silicon 上，你还会在这里遇到许多现代的 authenticated pointer fixups。

当你重建 imports/exports、理解为什么一个通过 `@rpath` 加载的 dependency 会以那种方式解析，或者弄清为什么在现代 `arm64e` 目标上 hook/rebinding 尝试失败时，这些 metadata 都非常有用。`dyld_info` 也可以用于 **cache-only dylib paths**，这些路径在磁盘上并不存在为独立文件，在现代 macOS 上尤其有用，因为许多系统库只存在于 shared cache 中。
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

这个现代 load command 主要在检查 **kernel collections / kernelcache-style filesets** 时相关。它不表示一个单独的独立 image，而是让外层 Mach-O 作为一个容器，每个 `LC_FILESET_ENTRY` 都指向一个嵌入的 Mach-O，并带有自己的类似路径的 **entry id**、VM address 和 file offset。如果你正在 reverse 现代 macOS/iOS kernel 组件，这个命令通常就是顶层容器与实际想要提取或 disassemble 的 image 之间的桥梁。
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
For practical extraction workflows, check [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

This load command describes a **dynamic** **library** dependency which **instructs** the **loader** (dyld) to **load and link said library**. There is a `LC_LOAD_DYLIB` load command **for each library** that the Mach-O binary requires.

- This load command is a structure of type **`dylib_command`** (which contains a struct dylib, describing the actual dependent dynamic library):
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

你也可以通过 cli 获取这些信息：
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: 监控 USB drives
- **AVFoundation:** 捕获 audio and video
- **CoreWLAN**: Wifi scans.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

At the core of the file lies the data region, which is composed of several segments as defined in the load-commands region. **A variety of data sections can be housed within each segment**, with each section **holding code or data** specific to a type.

> [!TIP]
> The data is basically the part containing all the **information** that is loaded by the load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

This includes:

- **Function table:** Which holds information about the program functions.
- **Symbol table**: Which contains information about the external function used by the binary
- It could also contain internal function, variable names as well and more.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

在 `__TEXT` segment (r-x) 中：

- `__objc_classname`: 类名（strings）
- `__objc_methname`: 方法名（strings）
- `__objc_methtype`: 方法类型（strings）

在 `__DATA` segment (rw-) 中：

- `__objc_classlist`: 指向所有 Objetive-C 类的指针
- `__objc_nlclslist`: 指向 Non-Lazy Objective-C 类的指针
- `__objc_catlist`: 指向 Categories 的指针
- `__objc_nlcatlist`: 指向 Non-Lazy Categories 的指针
- `__objc_protolist`: Protocols 列表
- `__objc_const`: 常量数据
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
