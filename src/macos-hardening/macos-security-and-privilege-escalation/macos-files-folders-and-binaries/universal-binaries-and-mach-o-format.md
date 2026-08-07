# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Mac OS 바이너리는 일반적으로 **universal binaries**로 컴파일됩니다. **universal binary**는 **하나의 파일에서 여러 아키텍처를 지원할 수 있습니다**.

이러한 바이너리는 기본적으로 다음으로 구성된 **Mach-O 구조**를 따릅니다:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

다음 명령으로 파일을 검색합니다: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header에는 **magic** 바이트가 있고, 그 뒤에 파일이 **포함하는** **arch**의 **개수**(`nfat_arch`)가 이어지며 각 arch에는 `fat_arch` 구조체가 포함됩니다.

다음과 같이 확인할 수 있습니다:

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

또는 [Mach-O View](https://sourceforge.net/projects/machoview/) 도구를 사용할 수 있습니다:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

예상할 수 있듯이 일반적으로 2개의 아키텍처용으로 컴파일된 universal binary는 1개의 arch용으로 컴파일된 바이너리보다 **크기가 2배**가 됩니다.

> [!TIP]
> malware 또는 의심스러운 앱을 triage할 때 `file`이 "가장 적합한" 아키텍처를 보고했다고 해서 중단하지 마세요. universal binary는 각 slice에 서로 다른 imports, load commands 또는 compiler metadata를 숨길 수 있으므로, 먼저 **모든** slice를 열거한 다음 각각을 독립적으로 검사해야 합니다:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
최근 macOS SDK는 `<mach-o/utils.h>`에서 `macho_for_each_slice()` 및 `macho_best_slice()`와 같은 helper도 제공합니다. 후자는 dyld/kernel이 로드할 대상을 에뮬레이트할 때 유용하지만, scanner는 아키텍처별 content를 놓치지 않도록 여전히 모든 slice를 순회해야 합니다.<sup>[[1]](#references)</sup>

## **Mach-O Header**

header에는 파일을 Mach-O 파일로 식별하기 위한 magic bytes와 target architecture 정보 등 파일에 대한 기본 정보가 포함됩니다. 다음 명령으로 찾을 수 있습니다: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O 파일 유형

다양한 파일 유형이 있으며, [**예를 들어 여기의 source code에서 확인할 수 있습니다**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). 가장 중요한 유형은 다음과 같습니다.

- `MH_OBJECT`: Relocatable object file (아직 executable이 아닌 compilation의 중간 결과물).
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (더 이상 XNU에서 지원되지 않음).
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". gcc에서 -bundle을 사용해 생성되며 `NSBundle` 또는 `dlopen`으로 명시적으로 로드됩니다.
- `MH_DYSM`: Companion `.dSym` file (debugging을 위한 symbols가 포함된 파일).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
또는 [Mach-O View](https://sourceforge.net/projects/machoview/)를 사용할 수 있습니다:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

소스 코드에는 libraries를 loading하는 데 유용한 여러 flags도 정의되어 있습니다:

- `MH_NOUNDEFS`: undefined references 없음 (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references가 prebound됨
- `MH_SPLIT_SEGS`: 파일이 r/o 및 r/w segments로 분할됨
- `MH_WEAK_DEFINES`: Binary에 weak defined symbols가 있음
- `MH_BINDS_TO_WEAK`: Binary가 weak symbols를 사용함
- `MH_ALLOW_STACK_EXECUTION`: Stack을 executable로 설정
- `MH_NO_REEXPORTED_DYLIBS`: Library에 LC_REEXPORT commands가 없음
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Thread local variables가 있는 section이 존재함
- `MH_NO_HEAP_EXECUTION`: Heap/data pages에서 execution이 허용되지 않음
- `MH_HAS_OBJC`: Binary에 oBject-C sections가 있음
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: Shared library cache의 dylibs/frameworks에서 사용됨

## **Mach-O Load commands**

**Memory에서 file의 layout**은 여기에서 지정되며, **symbol table의 위치**, execution 시작 시 main thread의 context, 필요한 **shared libraries**에 대한 정보를 자세히 설명합니다. Dynamic loader **(dyld)**가 binary를 memory로 loading하는 방식에 대한 instructions가 제공됩니다.

이는 언급된 **`loader.h`**에 정의된 **load_command** structure를 사용합니다:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
시스템이 서로 다르게 처리하는 **약 50가지 유형의 load command**가 있습니다. 가장 일반적인 유형은 다음과 같습니다: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 기본적으로 이 유형의 Load Command는 binary가 실행될 때 **Data section**에 표시된 **offset**에 따라 **\_\_TEXT** (executable code) 및 **\_\_DATA** (process용 data) **segment**를 **load하는 방법**을 정의합니다.

이 command는 process가 실행될 때 **virtual memory space**에 **mapping**되는 **segment**를 정의합니다.

**\_\_TEXT** segment처럼 program의 executable code를 저장하는 segment와 process가 사용하는 data를 포함하는 **\_\_DATA** segment 등 **다양한 유형의** segment가 있습니다. 이러한 **segment는 Mach-O file의 data section에 위치**합니다.

**각 segment**는 여러 **section**으로 다시 **나뉠** 수 있습니다. **load command structure**에는 해당 segment 내 **이러한 section**에 대한 **정보**가 포함됩니다.

header에서 먼저 **segment header**를 확인할 수 있습니다:

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

segment header 예시:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

이 header는 그 뒤에 header가 표시되는 **section의 수**를 정의합니다:
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
**section header**의 예:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

**section offset**(0x37DC)에 **arch starts** 지점의 **offset**(이 경우 `0x18000`)을 **더하면** --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**command line**을 사용하여 **headers 정보**를 가져오는 것도 가능합니다:
```bash
otool -lv /bin/ls
```
이 cmd로 로드되는 일반적인 segment:

- **`__PAGEZERO`:** 커널에 **address zero**를 **map**하도록 지시하여, 해당 영역을 **read**, **write** 또는 **execute**할 수 없게 합니다. 구조체의 maxprot 및 minprot 변수는 0으로 설정되어 이 page에 **read-write-execute 권한이 없음**을 나타냅니다.
- 이 할당은 **NULL pointer dereference vulnerabilities**를 **mitigate**하는 데 중요합니다. XNU가 첫 번째 page(첫 번째 page만)의 memory를 접근할 수 없도록 보장하는 hard page zero를 적용하기 때문입니다(i386 제외). 바이너리는 작은 \_\_PAGEZERO를 생성하여(`-pagezero_size` 사용) 첫 4k를 포함하고, 나머지 32bit memory를 user mode와 kernel mode 모두에서 접근 가능하게 함으로써 이 요구 사항을 충족할 수 있습니다.
- **`__TEXT`**: **read** 및 **execute** 권한이 있는 **executable** **code**를 포함합니다(**writable 권한 없음).** 이 segment의 일반적인 section:
- `__text`: 컴파일된 바이너리 code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode 또는 os logs string constants
- `__stubs` 및 `__stubs_helper`: dynamic library loading 과정에서 사용됨
- `__unwind_info`: Stack unwind data
- 이 모든 content는 signed되어 있지만 executable로도 표시됩니다. 따라서 이 권한이 반드시 필요하지 않은 section(예: string 전용 section)을 exploit할 수 있는 선택지가 더 많아집니다.
- **`__DATA`**: **readable** 및 **writable**한 data를 포함합니다(**executable 권한 없음).**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (load 시 bind) symbol pointer
- `__la_symbol_ptr`: Lazy (사용 시 bind) symbol pointer
- `__const`: Read-only data여야 하지만(실제로는 그렇지 않음)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (initialized된 변수)
- `__bss`: Static variables (initialized되지 않은 변수)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist 등): Objective-C runtime에서 사용하는 정보
- **`__DATA_CONST`**: \_\_DATA.\_\_const는 constant(write permissions)로 보장되지 않으며, 다른 pointer와 GOT도 마찬가지입니다. 이 section은 `mprotect`를 사용하여 `__const`, 일부 initializer 및 GOT table(resolve된 후)을 **read only**로 만듭니다.
- **`__AUTH` / `__AUTH_CONST`**: 최근 Apple Silicon binaries에서 일반적으로 사용됩니다. 이 segment들은 load 또는 use 시점에 authenticated되어야 하는 pointer를 포함합니다(예: `__auth_got`). rebinding, hook 또는 import-patching trick이 legacy `__got` / `__la_symbol_ptr` section만 확인한다면, modern `arm64e` binaries의 실제 call site를 놓칠 수 있습니다. 이 section에 대한 자세한 내용은 [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)를 확인하세요.
- **`__LINKEDIT`**: symbol, string 및 relocation table entry와 같은 linker(dyld)용 정보를 포함합니다. `__TEXT`나 `__DATA`에 포함되지 않는 content를 위한 generic container이며, 해당 content는 다른 load command에 설명되어 있습니다.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes 및 export info
- Functions starts: function의 start address table
- Data In Code: \_\_text 내의 data islands
- SYmbol Table: binary 내의 symbols
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime에서 사용하는 정보를 포함합니다. 이 정보는 여러 \_\_objc\_\* section 내의 \_\_DATA segment에서도 확인할 수 있습니다.
- **`__RESTRICT`**: `__restrict`라는 단일 section을 포함하는 content 없는 segment입니다. 이 section 역시 비어 있으며, binary 실행 시 DYLD environmental variables를 무시하도록 합니다.

code에서 확인할 수 있듯이 **segments는 flags도 지원합니다**(많이 사용되지는 않음).

- `SG_HIGHVM`: Core only (사용되지 않음)
- `SG_FVMLIB`: 사용되지 않음
- `SG_NORELOC`: Segment에 relocation이 없음
- `SG_PROTECTED_VERSION_1`: Encryption. 예를 들어 Finder가 text `__TEXT` segment를 encrypt할 때 사용됨.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**은 **`entryoff attribute`에 entrypoint를 포함합니다.** load 시 **dyld**는 이 값을 (memory 내) **binary의 base**에 단순히 **더한** 다음, binary code의 실행을 시작하기 위해 이 instruction으로 **jump**합니다.

**`LC_UNIXTHREAD`**은 main thread를 시작할 때 register가 가져야 하는 값을 포함합니다. 이는 이미 deprecated되었지만 **`dyld`**는 여전히 이를 사용합니다. 다음 명령으로 이를 통해 설정된 register 값을 확인할 수 있습니다:
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


**Macho-O 파일의 code signature**에 관한 정보를 포함합니다. **signature blob**을 **가리키는** **offset**만 포함합니다. 일반적으로 파일의 가장 끝에 위치합니다.\
하지만 이 섹션에 관한 일부 정보는 [**이 블로그 포스트**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)와 이 [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)에서 확인할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

binary encryption을 지원합니다. 하지만 물론 attacker가 process를 compromise하는 데 성공하면, 암호화되지 않은 memory를 dump할 수 있습니다.

### **`LC_LOAD_DYLINKER`**

shared libraries를 process address space에 매핑하는 **dynamic linker executable의 path**를 포함합니다. **value는 항상 `/usr/lib/dyld`로 설정**됩니다. macOS에서는 dylib mapping이 kernel mode가 아니라 **user mode**에서 발생한다는 점이 중요합니다.

### **`LC_IDENT`**

사용되지 않지만 panic 발생 시 dump를 생성하도록 구성된 경우 Mach-O core dump가 생성되며, kernel version이 `LC_IDENT` command에 설정됩니다.

### **`LC_UUID`**

Random UUID입니다. 그 자체로는 유용한 용도가 없지만 XNU는 이를 나머지 process info와 함께 cache합니다. crash reports에서 사용할 수 있습니다.

### **`LC_BUILD_VERSION`**

Modern binaries는 일반적으로 이 command를 포함하여 **target platform**, **minimum OS version**, **SDK version**, 그리고 선택적으로 해당 slice를 build하는 데 사용된 **tool versions**를 선언합니다. Offensive/reversing 관점에서 이는 sample이 어떻게 build되었는지 fingerprinting하고, 한 slice가 다른 SDK 또는 deployment target으로 compile된 이상한 universal binaries를 빠르게 발견하는 데 매우 유용합니다. Older binaries는 대신 여전히 `LC_VERSION_MIN_*`을 사용할 수 있습니다.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

프로세스가 실행되기 전에 dyld에 환경 변수를 지정할 수 있습니다. 프로세스 내부에서 임의의 code를 실행할 수 있으므로 매우 위험할 수 있습니다. 따라서 이 load command는 `#define SUPPORT_LC_DYLD_ENVIRONMENT`가 정의된 dyld build에서만 사용되며, 처리는 load paths를 지정하는 `DYLD_..._PATH` 형식의 변수로만 추가 제한됩니다.

### **`LC_DYLD_EXPORTS_TRIE` 및 `LC_DYLD_CHAINED_FIXUPS`**

최근 toolchain은 이전의 `LC_DYLD_INFO[_ONLY]` opcodes에만 의존하는 대신 이러한 commands에 export/bind/rebase metadata를 저장하는 경우가 많습니다. 둘 다 **`__LINKEDIT`** 내부를 가리키는 `linkedit_data_command` entries입니다.

- **`LC_DYLD_EXPORTS_TRIE`**: image가 export하는 symbols가 포함된 Compact trie입니다.
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld가 rebases 및 binds를 적용하는 데 사용하는 segment별 fixup chains입니다. Apple Silicon에서는 여러 최신 authenticated pointer fixups도 이곳에서 확인할 수 있습니다.

이 metadata는 imports/exports를 재구성하거나, `@rpath`로 load된 dependency가 해당 방식으로 resolve된 이유를 이해하거나, 최신 `arm64e` target에서 hook/rebinding 시도가 실패한 이유를 파악할 때 매우 유용합니다. `dyld_info`는 디스크에 standalone files로 존재하지 않는 **cache-only dylib paths**에도 사용할 수 있습니다. 이는 많은 system libraries가 shared cache에만 존재하는 최신 macOS에서 특히 유용합니다.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

이 modern load command는 **kernel collections / kernelcache-style filesets**를 검사할 때 주로 관련이 있습니다. 단일 standalone image를 나타내는 대신, 외부 Mach-O가 container로 동작하며 각 `LC_FILESET_ENTRY`는 고유한 path-like **entry id**, VM address 및 file offset을 가진 embedded Mach-O를 가리킵니다. modern macOS/iOS kernel components를 reversing하는 경우, 이 command는 최상위 container와 실제로 extract하거나 disassemble하려는 image를 연결하는 bridge인 경우가 많습니다.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
실제 추출 workflow는 [macOS kernel extensions 및 kernelcache에 관한 다른 페이지](../mac-os-architecture/macos-kernel-extensions.md)를 참고하세요.

### **`LC_LOAD_DYLIB`**

이 load command는 **loader**(dyld)가 해당 **library를 load하고 link하도록 지시하는** **dynamic** **library** dependency를 설명합니다. Mach-O binary가 필요로 하는 **각 library**마다 `LC_LOAD_DYLIB` load command가 하나씩 존재합니다.

- 이 load command는 **`dylib_command`** 타입의 structure입니다(실제 dependent dynamic library를 설명하는 struct dylib를 포함합니다).
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t 호환성 버전; / library의 호환성 버전 /](<../../../images/image (486).png>)

다음 명령을 사용하여 CLI에서도 이 정보를 확인할 수 있습니다:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
일부 malware 관련 library는 다음과 같습니다:

- **DiskArbitration**: USB drive 모니터링
- **AVFoundation:** audio 및 video 캡처
- **CoreWLAN**: WiFi scan.

> [!TIP]
> Mach-O binary에는 하나 또는 **그 이상**의 **constructor**가 포함될 수 있으며, 이는 **LC_MAIN**에 지정된 address보다 **먼저 실행**됩니다.\
> 모든 constructor의 offset은 **\_\_DATA_CONST** segment의 **\_\_mod_init_func** section에 저장됩니다.

## **Mach-O 데이터**

파일의 핵심에는 data region이 있으며, 이는 load-commands region에 정의된 여러 segment로 구성됩니다. **각 segment에는 다양한 data section이 포함될 수 있으며**, 각 section은 특정 type에 해당하는 **code 또는 data**를 **저장**합니다.

> [!TIP]
> data는 기본적으로 load command **LC_SEGMENTS_64**에 의해 load되는 모든 **information**이 포함된 부분입니다.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

여기에는 다음이 포함됩니다:

- **Function table:** program function에 대한 information을 저장합니다.
- **Symbol table**: binary에서 사용되는 external function에 대한 information을 포함합니다.
- 또한 internal function, variable name 및 기타 항목도 포함할 수 있습니다.

이를 확인하려면 [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool을 사용할 수 있습니다:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

또는 CLI에서:
```bash
size -m /bin/ls
```
## Objetive-C 공통 섹션

`__TEXT` 세그먼트 (r-x):

- `__objc_classname`: 클래스 이름 (문자열)
- `__objc_methname`: 메서드 이름 (문자열)
- `__objc_methtype`: 메서드 유형 (문자열)

`__DATA` 세그먼트 (rw-):

- `__objc_classlist`: 모든 Objetive-C 클래스에 대한 포인터
- `__objc_nlclslist`: Non-Lazy Objective-C 클래스에 대한 포인터
- `__objc_catlist`: Categories에 대한 포인터
- `__objc_nlcatlist`: Non-Lazy Categories에 대한 포인터
- `__objc_protolist`: Protocols 목록
- `__objc_const`: 상수 데이터
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

## References

- [1] [Mach-O 슬라이스는 생각만큼 간단하지 않습니다](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man 페이지](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [자신의 Entitlements 읽기](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
