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
최근 macOS SDK는 `<mach-o/utils.h>`에서 `macho_for_each_slice()` 및 `macho_best_slice()`와 같은 helper도 제공합니다. 후자는 dyld/kernel이 로드할 내용을 에뮬레이션하는 데 유용하지만, scanners는 여전히 모든 slice를 반복해야 arch-specific content를 놓치지 않습니다.

## **Mach-O Header**

header에는 Mach-O file로 식별하기 위한 magic bytes와 target architecture에 대한 정보 같은 파일의 기본 정보가 들어 있습니다. 다음에서 찾을 수 있습니다: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

다양한 파일 유형이 있으며, [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)에서 정의를 찾을 수 있습니다. 가장 중요한 것은 다음과 같습니다:

- `MH_OBJECT`: Relocatable object file (컴파일 중간 산출물, 아직 executable이 아님).
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (XNU에서 더 이상 지원되지 않음)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". `gcc`의 `-bundle`로 생성되며 `NSBundle` 또는 `dlopen`으로 명시적으로 로드됩니다.
- `MH_DYSM`: Companion `.dSym` file (디버깅용 symbols가 있는 파일).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

소스 코드는 라이브러리 로딩에 유용한 몇 가지 플래그도 정의합니다:

- `MH_NOUNDEFS`: 정의되지 않은 참조 없음(완전히 링크됨)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: 동적 참조가 미리 바인딩됨.
- `MH_SPLIT_SEGS`: 파일이 r/o 및 r/w 세그먼트로 분할됨.
- `MH_WEAK_DEFINES`: Binary에 weak 정의 심볼이 있음
- `MH_BINDS_TO_WEAK`: Binary가 weak 심볼을 사용함
- `MH_ALLOW_STACK_EXECUTION`: 스택을 executable로 만듦
- `MH_NO_REEXPORTED_DYLIBS`: Library에 LC_REEXPORT commands가 없음
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: thread local variables가 있는 섹션이 있음
- `MH_NO_HEAP_EXECUTION`: heap/data pages에서 execution 불가
- `MH_HAS_OBJC`: Binary에 oBject-C 섹션이 있음
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: shared library cache의 dylibs/frameworks에 사용됨.

## **Mach-O Load commands**

**메모리 내 파일의 레이아웃**은 여기에서 지정되며, **심볼 테이블의 위치**, 실행 시작 시 메인 스레드의 컨텍스트, 그리고 필요한 **shared libraries**를 자세히 설명합니다. 바이너리가 메모리에 로드되는 과정에 대해 dynamic loader **(dyld)**에 지시가 제공됩니다.

사용되는 **load_command** 구조체는 언급된 **`loader.h`**에 정의되어 있습니다:
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
<strong>	uint32_t	nsects;		/* segment의 섹션 수 */
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
Example of **섹션 헤더**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

**섹션 오프셋** (0x37DC) + **arch가 시작하는** **오프셋**을 더하면, 이 경우 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**command line**에서 **headers 정보**를 가져오는 것도 가능합니다:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** It instructs the kernel to **map** the **address zero** so it **cannot be read from, written to, or executed**. The maxprot and minprot variables in the structure are set to zero to indicate there are **no read-write-execute rights on this page**.
- This allocation is important to **mitigate NULL pointer dereference vulnerabilities**. This is because XNU enforces a hard page zero that ensures the first page (only the first) of memory is innaccesible (except in i386). A binary could fulfil this requirements by crafting a small \_\_PAGEZERO (using the `-pagezero_size`) to cover the first 4k and having the rest of 32bit memory accessible in both user and kernel mode.
- **`__TEXT`**: Contains **executable** **code** with **read** and **execute** permissions (no writable)**.** Common sections of this segment:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode or os logs string constants
- `__stubs` and `__stubs_helper`: Involved during the dynamic library loading process
- `__unwind_info`: Stack unwind data.
- Note that all this content is signed but also marked as executable (creating more options for exploitation of sections that doesn't necessarily need this privilege, like string dedicated sections).
- **`__DATA`**: Contains data that is **readable** and **writable** (no executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Should be read-only data (not really)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (that have been initialized)
- `__bss`: Static variables (that have not been initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Information used by the Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const is not guaranteed to be constant (write permissions), nor are other pointers and the GOT. This section makes `__const`, some initializers and the GOT table (once resolved) **read only** using `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Common in recent Apple Silicon binaries. These segments hold pointers that must be authenticated at load or use time (for example `__auth_got`). If a rebinding, hook or import-patching trick only checks the legacy `__got` / `__la_symbol_ptr` sections, it may miss the real call sites in modern `arm64e` binaries. For more details on these sections check [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contains information for the linker (dyld) such as, symbol, string, and relocation table entries. It' a generic container for contents that are neither in `__TEXT` or `__DATA` and its content is decribed in other load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Contains information used by the Objective-C runtime. Though this information might also be found in the \_\_DATA segment, within various in \_\_objc\_\* sections.
- **`__RESTRICT`**: A segment without content with a single section called **`__restrict`** (also empty) that ensures that when running the binary, it will ignore DYLD environmental variables.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contains the entrypoint in the **entryoff attribute.** At load time, **dyld** simply **adds** this value to the (in-memory) **base of the binary**, then **jumps** to this instruction to start execution of the binary’s code.

**`LC_UNIXTHREAD`** contains the values the register must have when starting the main thread. This was already deprecated but **`dyld`** still uses it. It's possible to see the vlaues of the registers set by this with:
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


**Macho-O 파일의 코드 서명**에 대한 정보를 담고 있습니다. **서명 blob**을 **가리키는** **오프셋**만 포함합니다. 이는 일반적으로 파일의 맨 끝에 있습니다.\
하지만 [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)와 [**this gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)에서 이 섹션에 대한 일부 정보를 찾을 수 있습니다.

### **`LC_ENCRYPTION_INFO[_64]`**

바이너리 암호화를 지원합니다. 하지만 물론 공격자가 프로세스를 침해하는 데 성공하면, 메모리를 암호화되지 않은 상태로 덤프할 수 있습니다.

### **`LC_LOAD_DYLINKER`**

공유 라이브러리를 프로세스 주소 공간에 매핑하는 **dynamic linker 실행 파일의 경로**를 담고 있습니다. **값은 항상 `/usr/lib/dyld`로 설정됩니다**. macOS에서는 dylib 매핑이 커널 모드가 아니라 **user mode**에서 일어난다는 점이 중요합니다.

### **`LC_IDENT`**

구식이지만, panic 시 덤프 생성을 설정하면 Mach-O core dump가 생성되고 커널 버전이 `LC_IDENT` command에 설정됩니다.

### **`LC_UUID`**

무작위 UUID입니다. 직접적으로 어떤 용도에든 유용하지만 XNU는 이를 다른 process info와 함께 캐시합니다. crash reports에서 사용할 수 있습니다.

### **`LC_BUILD_VERSION`**

현대적인 binaries는 보통 이 command를 포함하여 **target platform**, **minimum OS version**, **SDK version**, 그리고 선택적으로 해당 slice를 빌드할 때 사용된 **tool versions**를 선언합니다. offensive/reversing 관점에서 이는 샘플이 어떻게 빌드되었는지 fingerprinting하고, 한 slice가 다른 SDK나 deployment target으로 컴파일된 이상한 universal binaries를 빠르게 찾아내는 데 매우 유용합니다. 오래된 binaries는 대신 여전히 `LC_VERSION_MIN_*`를 사용할 수 있습니다.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

프로세스가 실행되기 전에 dyld에 환경 변수를 지정할 수 있게 합니다. 이는 매우 위험할 수 있는데, 프로세스 내부에서 임의 코드를 실행할 수 있게 할 수 있기 때문입니다. 그래서 이 load command는 `#define SUPPORT_LC_DYLD_ENVIRONMENT`가 있는 dyld 빌드에서만 사용되며, 추가로 `DYLD_..._PATH` 형식의 변수로만 처리 대상을 제한하여 load paths를 지정합니다.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

최근 toolchain은 이전의 `LC_DYLD_INFO[_ONLY]` opcodes에만 의존하지 않고, export/bind/rebase 메타데이터를 이러한 command에 자주 저장합니다. 둘 다 **`__LINKEDIT`**를 가리키는 `linkedit_data_command` 항목입니다:

- **`LC_DYLD_EXPORTS_TRIE`**: 이미지에서 export된 symbol을 담은 compact trie.
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld가 rebases와 binds를 적용하는 데 사용하는 segment별 fixup chain. Apple Silicon에서는 많은 현대적인 authenticated pointer fixup도 여기서 볼 수 있습니다.

이 메타데이터는 imports/exports를 재구성하거나, `@rpath`로 로드된 dependency가 왜 그런 방식으로 resolve되었는지 이해하거나, 최신 `arm64e` 타겟에서 hook/rebinding 시도가 왜 실패했는지 파악할 때 매우 유용합니다. `dyld_info`는 디스크에 독립된 파일로 존재하지 않는 **cache-only dylib paths**에도 사용할 수 있는데, 현대 macOS에서는 많은 시스템 라이브러리가 shared cache에만 존재하므로 매우 유용합니다.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

이 현대적인 load command는 주로 **kernel collections / kernelcache-style filesets**를 검사할 때 중요합니다. 단일 독립 이미지가 아니라, 외부 Mach-O가 컨테이너처럼 동작하고 각 `LC_FILESET_ENTRY`가 자체 path-like **entry id**, VM address, file offset을 가진 내장 Mach-O를 가리킵니다. 현대 macOS/iOS kernel components를 reverse하는 경우, 이 command는 종종 최상위 컨테이너와 실제로 추출하거나 disassemble하려는 이미지 사이를 연결하는 bridge입니다.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
For practical extraction workflows, check [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

이 load command는 **동적** **library** 의존성을 설명하며, **loader**(dyld)에게 **해당 library를 load and link**하도록 **지시**합니다. Mach-O binary가 필요로 하는 **각 library마다** `LC_LOAD_DYLIB` load command가 있습니다.

- 이 load command는 **`dylib_command`** 타입의 구조체입니다(여기에는 실제 종속 동적 library를 설명하는 struct dylib가 포함됩니다):
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

이 정보는 cli에서도 다음과 같이 얻을 수 있습니다:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: USB 드라이브 모니터링
- **AVFoundation:** 오디오 및 비디오 캡처
- **CoreWLAN**: Wifi 스캔.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

파일의 핵심에는 데이터 영역이 있으며, 이는 load-commands 영역에 정의된 여러 세그먼트로 구성됩니다. **각 세그먼트에는 다양한 데이터 섹션이 포함될 수 있으며**, 각 섹션은 특정 유형의 코드 또는 데이터를 **보유**합니다.

> [!TIP]
> 데이터는 기본적으로 **LC_SEGMENTS_64** 로드 명령에 의해 로드되는 모든 **정보**를 포함하는 부분입니다.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

여기에는 다음이 포함됩니다:

- **Function table:** 프로그램 함수에 대한 정보를 보관합니다.
- **Symbol table**: 바이너리에서 사용되는 외부 함수에 대한 정보를 포함합니다.
- 내부 함수, 변수 이름 등도 포함할 수 있습니다.

이를 확인하려면 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 도구를 사용할 수 있습니다:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

또는 cli에서:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

`__TEXT` segment (r-x)에서:

- `__objc_classname`: Class names (strings)
- `__objc_methname`: Method names (strings)
- `__objc_methtype`: Method types (strings)

`__DATA` segment (rw-)에서:

- `__objc_classlist`: 모든 Objetive-C classes에 대한 포인터
- `__objc_nlclslist`: Non-Lazy Objective-C classes에 대한 포인터
- `__objc_catlist`: Categories에 대한 포인터
- `__objc_nlcatlist`: Non-Lazy Categories에 대한 포인터
- `__objc_protolist`: Protocols list
- `__objc_const`: 상수 데이터
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
