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

Header에는 **magic** 바이트가 있으며, 그 뒤에 파일이 **포함하는** **arch 수**(`nfat_arch`)가 이어집니다. 각 arch에는 `fat_arch` struct가 포함됩니다.

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

또는 [Mach-O View](https://sourceforge.net/projects/machoview/) tool을 사용할 수 있습니다:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

예상할 수 있듯이 일반적으로 2개의 아키텍처용으로 컴파일된 universal binary는 1개의 arch용으로 컴파일된 바이너리보다 **크기가 2배**가 됩니다.

> [!TIP]
> malware 또는 의심스러운 앱을 triage할 때 `file`이 "best" 아키텍처를 보고했다고 해서 중단하지 마세요. universal binary는 각 slice에서 서로 다른 imports, load commands 또는 compiler metadata를 숨길 수 있으므로, 먼저 **모든** slice를 열거한 다음 각각을 독립적으로 검사하세요:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
최근 macOS SDK는 `<mach-o/utils.h>`에서 `macho_for_each_slice()` 및 `macho_best_slice()`와 같은 helper도 제공합니다. 후자는 dyld/kernel이 로드할 항목을 에뮬레이션하는 데 유용하지만, scanner는 아키텍처별 콘텐츠를 놓치지 않도록 여전히 모든 slice를 순회해야 합니다.<sup>[[1]](#references)</sup>

## **Mach-O 헤더**

헤더에는 파일을 Mach-O 파일로 식별하기 위한 magic bytes와 대상 아키텍처 정보 등 파일에 대한 기본 정보가 포함됩니다. 다음 명령으로 찾을 수 있습니다: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

다양한 파일 유형이 있으며, [**예를 들어 여기의 소스 코드에서 확인할 수 있습니다**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). 가장 중요한 유형은 다음과 같습니다:

- `MH_OBJECT`: 재배치 가능한 object 파일(아직 실행 파일이 아닌 컴파일 중간 결과물).
- `MH_EXECUTE`: 실행 파일.
- `MH_FVMLIB`: Fixed VM library 파일.
- `MH_CORE`: 코드 덤프.
- `MH_PRELOAD`: 사전 로드된 실행 파일(XNU에서는 더 이상 지원되지 않음).
- `MH_DYLIB`: 동적 라이브러리.
- `MH_DYLINKER`: 동적 링커.
- `MH_BUNDLE`: "Plugin 파일". gcc에서 -bundle을 사용하여 생성되며 `NSBundle` 또는 `dlopen`으로 명시적으로 로드됩니다.
- `MH_DYSM`: Companion `.dSym` 파일(디버깅을 위한 심볼이 포함된 파일).
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

## **Mach-O 플래그**

소스 코드에는 libraries를 로드하는 데 유용한 여러 플래그도 정의되어 있습니다:

- `MH_NOUNDEFS`: 정의되지 않은 참조 없음 (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: 파일이 r/o 및 r/w 세그먼트로 분할됨.
- `MH_WEAK_DEFINES`: Binary에 weak defined symbols가 있음
- `MH_BINDS_TO_WEAK`: Binary가 weak symbols를 사용함
- `MH_ALLOW_STACK_EXECUTION`: Stack을 executable로 설정
- `MH_NO_REEXPORTED_DYLIBS`: Library에 LC_REEXPORT commands가 없음
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Thread local variables가 있는 section이 존재함
- `MH_NO_HEAP_EXECUTION`: Heap/data pages에서 execution 불가
- `MH_HAS_OBJC`: Binary에 oBject-C sections가 있음
- `MH_SIM_SUPPORT`: Simulator 지원
- `MH_DYLIB_IN_CACHE`: Shared library cache의 dylibs/frameworks에 사용됨.

## **Mach-O Load commands**

**파일의 메모리 내 레이아웃**은 여기에서 지정되며, **symbol table의 위치**, 실행 시작 시 main thread의 context, 필요한 **shared libraries**가 자세히 설명됩니다. Binary를 메모리에 로드하는 과정에 대한 지침이 dynamic loader **(dyld)**에 제공됩니다.

이는 언급된 **`loader.h`**에 정의된 **load_command** structure를 사용합니다:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
시스템이 서로 다르게 처리하는 **약 50가지의 load command 유형**이 있습니다. 가장 일반적인 유형은 다음과 같습니다: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 기본적으로 이 유형의 Load Command는 binary가 실행될 때 **Data section에 표시된 offset**에 따라 **\_\_TEXT** (executable code) 및 **\_\_DATA** (process용 data) **segment를 load하는 방법**을 정의합니다.

이 command는 실행될 때 process의 **virtual memory space**에 **mapping되는** **segment**를 정의합니다.

**\_\_TEXT** segment처럼 program의 executable code를 저장하는 segment와, process에서 사용하는 data를 포함하는 **\_\_DATA** segment 등 **다양한 유형의** segment가 있습니다. 이러한 **segment는 Mach-O file의 data section에 위치**합니다.

**각 segment**는 여러 **section**으로 다시 **나뉠** 수 있습니다. **load command structure**에는 해당 segment 내 **이러한 section에 대한 정보**가 포함됩니다.

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

segment header의 예시:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

이 header는 **그 뒤에 header가 나타나는 section의 수**를 정의합니다:
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

**section offset**(0x37DC)에 **arch가 시작되는 offset**(이 경우 `0x18000`)을 더하면 됩니다. --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

다음 명령줄을 사용해 **header 정보**를 가져올 수도 있습니다:
```bash
otool -lv /bin/ls
```
이 cmd로 로드되는 일반적인 segments:

- **`__PAGEZERO`:** kernel에 **address zero**를 **map**하도록 지시하여 **read**, **written**, 또는 **executed**할 수 없도록 합니다. 구조체의 maxprot 및 minprot 변수는 이 페이지에 **read-write-execute rights가 없음**을 나타내기 위해 0으로 설정됩니다.
- 이 allocation은 **NULL pointer dereference vulnerabilities**를 **mitigate**하는 데 중요합니다. XNU가 첫 번째 페이지(첫 번째 페이지만)의 memory를 inaccessible하게 보장하는 hard page zero를 enforce하기 때문입니다(i386 제외). binary는 작은 \_\_PAGEZERO를 생성하여(`-pagezero_size` 사용) 첫 4k를 cover하고, 나머지 32bit memory를 user 및 kernel mode 모두에서 accessible하게 함으로써 이 requirements를 충족할 수 있습니다.
- **`__TEXT`**: **read** 및 **execute** permissions를 가진 **executable** **code**를 포함합니다(**writable**하지 않음). 이 segment의 일반적인 sections:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode 또는 os logs string constants
- `__stubs` 및 `__stubs_helper`: dynamic library loading process 중 사용됨
- `__unwind_info`: Stack unwind data.
- 이 모든 content는 signed되어 있지만 executable로도 표시됩니다(이 privilege가 반드시 필요하지 않은 sections, 예를 들어 string 전용 sections를 exploitation할 수 있는 더 많은 options를 생성함).
- **`__DATA`**: **readable** 및 **writable**한 data를 포함합니다(**executable**하지 않음).
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Read-only data여야 하지만(실제로는 아님)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (initialized된 변수)
- `__bss`: Static variables (initialized되지 않은 변수)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist 등): Objective-C runtime에서 사용하는 information
- **`__DATA_CONST`**: \_\_DATA.\_\_const는 constant(write permissions 없음)으로 보장되지 않으며, 다른 pointers 및 GOT도 마찬가지입니다. 이 section은 `mprotect`를 사용하여 `__const`, 일부 initializers 및 GOT table(resolve된 후)을 **read only**로 만듭니다.
- **`__AUTH` / `__AUTH_CONST`**: 최근 Apple Silicon binaries에서 일반적으로 사용됩니다. 이 segments는 load 또는 use time에 authenticated되어야 하는 pointers(예: `__auth_got`)를 보유합니다. rebinding, hook 또는 import-patching trick이 legacy `__got` / `__la_symbol_ptr` sections만 확인하는 경우, 최신 `arm64e` binaries의 실제 call sites를 놓칠 수 있습니다. 이 sections에 대한 자세한 내용은 [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)를 확인하세요.
- **`__LINKEDIT`**: symbol, string 및 relocation table entries와 같은 linker(dyld)용 information을 포함합니다. `__TEXT` 또는 `__DATA`에 속하지 않는 contents를 위한 generic container이며, 해당 content는 다른 load commands에 설명되어 있습니다.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes 및 export info
- Functions starts: functions의 start addresses table
- Data In Code: \_\_text 내의 data islands
- SYmbol Table: binary 내의 Symbols
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime에서 사용하는 information을 포함합니다. 다만 이 information은 \_\_DATA segment 내의 다양한 \_\_objc\_\* sections에서도 찾을 수 있습니다.
- **`__RESTRICT`**: `__restrict`라는 하나의 section만 포함하는 content 없는 segment입니다. 이 section도 비어 있으며, binary 실행 시 DYLD environmental variables를 ignore하도록 보장합니다.

code에서 확인할 수 있듯이 **segments는 flags도 지원합니다**(많이 사용되지는 않지만):

- `SG_HIGHVM`: Core only (사용되지 않음)
- `SG_FVMLIB`: 사용되지 않음
- `SG_NORELOC`: Segment에 relocation이 없음
- `SG_PROTECTED_VERSION_1`: Encryption. 예를 들어 Finder가 text `__TEXT` segment를 encrypt하는 데 사용됩니다.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**은 **`entryoff attribute`에 entrypoint를 포함합니다.** load time에 **dyld**는 이 값을 (memory 내) **binary의 base**에 단순히 **더한** 다음, binary code의 execution을 시작하기 위해 해당 instruction으로 **jump**합니다.

**`LC_UNIXTHREAD`**는 main thread를 시작할 때 register가 가져야 하는 values를 포함합니다. 이는 이미 deprecated되었지만 **`dyld`**는 여전히 이를 사용합니다. 다음 명령으로 이를 통해 설정된 registers의 values를 확인할 수 있습니다:
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


**Mach-O 파일의 code signature**에 대한 정보를 포함합니다. **signature blob**을 **가리키는** **offset**만 포함합니다. 일반적으로 파일의 가장 끝에 위치합니다.\
하지만 이 섹션에 대한 일부 정보는 [**이 blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)와 이 [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)에서 확인할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

binary encryption을 지원합니다. 하지만 물론 attacker가 process를 compromise하는 데 성공하면, 암호화되지 않은 memory를 dump할 수 있습니다.

### **`LC_LOAD_DYLINKER`**

shared libraries를 process address space에 매핑하는 **dynamic linker executable의 path**를 포함합니다. **value는 항상 `/usr/lib/dyld`로 설정**됩니다. macOS에서는 dylib mapping이 kernel mode가 아니라 **user mode**에서 발생한다는 점을 알아두는 것이 중요합니다.

### **`LC_IDENT`**

obsolete 명령이지만, panic 발생 시 dump를 생성하도록 구성된 경우 Mach-O core dump가 생성되고 kernel version이 `LC_IDENT` command에 설정됩니다.

### **`LC_UUID`**

Random UUID입니다. 직접적으로는 유용하지 않지만 XNU는 이를 나머지 process info와 함께 cache합니다. crash reports에서 사용할 수 있습니다.

### **`LC_BUILD_VERSION`**

Modern binaries에는 일반적으로 **target platform**, **minimum OS version**, **SDK version**, 그리고 선택적으로 해당 slice를 build하는 데 사용된 **tool versions**를 선언하기 위한 이 command가 포함됩니다. Offensive/reversing 관점에서는 sample이 어떻게 build되었는지 fingerprinting하고, 한 slice가 다른 SDK 또는 deployment target으로 compile된 이상한 universal binaries를 빠르게 찾아내는 데 매우 유용합니다. Older binaries는 대신 `LC_VERSION_MIN_*`을 여전히 사용할 수 있습니다.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

프로세스가 실행되기 전에 dyld에 환경 변수를 지정할 수 있습니다. 프로세스 내부에서 임의의 코드를 실행할 수 있으므로 매우 위험할 수 있으며, 따라서 이 load command는 `#define SUPPORT_LC_DYLD_ENVIRONMENT`가 활성화된 dyld 빌드에서만 사용되고, 처리는 load paths를 지정하는 `DYLD_..._PATH` 형식의 변수로 추가 제한됩니다.

### **`LC_DYLD_EXPORTS_TRIE` 및 `LC_DYLD_CHAINED_FIXUPS`**

최근 toolchain은 이전의 `LC_DYLD_INFO[_ONLY]` opcode에만 의존하는 대신, 이러한 command에 export/bind/rebase metadata를 저장하는 경우가 많습니다. 둘 다 **`__LINKEDIT`** 내부를 가리키는 `linkedit_data_command` 항목입니다.

- **`LC_DYLD_EXPORTS_TRIE`**: image가 export하는 symbols가 포함된 compact trie입니다.
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld가 rebases와 binds를 적용하는 데 사용하는 segment별 fixup chain입니다. Apple Silicon에서는 최신 authenticated pointer fixup도 여기에서 많이 확인할 수 있습니다.

이 metadata는 imports/exports를 재구성하거나, `@rpath`로 load된 dependency가 해당 방식으로 resolve된 이유를 이해하거나, 최신 `arm64e` target에서 hook/rebinding 시도가 실패한 이유를 파악할 때 매우 유용합니다. 또한 **cache-only dylib paths**에 대해 `dyld_info`를 사용할 수도 있으며, 이러한 paths는 disk에 standalone file로 존재하지 않습니다. 많은 system library가 shared cache에만 존재하는 최신 macOS에서 이는 매우 유용합니다.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

이 최신 load command는 **kernel collections / kernelcache-style filesets**를 분석할 때 주로 중요합니다. 하나의 독립적인 image를 나타내는 대신, 외부 Mach-O가 container 역할을 하며 각 `LC_FILESET_ENTRY`는 자체 path-like **entry id**, VM address 및 file offset을 가진 내장 Mach-O를 가리킵니다. 최신 macOS/iOS kernel component를 reverse engineering할 때 이 command는 최상위 container와 실제로 추출하거나 disassemble하려는 image를 연결하는 다리 역할을 하는 경우가 많습니다.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
실제 추출 workflow는 [macOS kernel extensions 및 kernelcache에 관한 다른 페이지](../mac-os-architecture/macos-kernel-extensions.md)를 참고하세요.

### **`LC_LOAD_DYLIB`**

이 load command는 **dynamic** **library** dependency를 설명하며, **loader**(dyld)가 해당 **library를 load하고 link**하도록 지시합니다. Mach-O binary가 필요로 하는 **각 library**마다 하나의 `LC_LOAD_DYLIB` load command가 존재합니다.

- 이 load command는 **`dylib_command`** 타입의 구조체입니다(여기에는 실제 dependent dynamic library를 설명하는 struct dylib가 포함됨):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t 호환성 버전; / 라이브러리의 호환성 버전 번호 /](<../../../images/image (486).png>)

CLI를 사용해서도 이 정보를 확인할 수 있습니다:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
잠재적인 malware 관련 libraries는 다음과 같습니다:

- **DiskArbitration**: USB drive 모니터링
- **AVFoundation:** audio 및 video 캡처
- **CoreWLAN**: Wi-Fi scan.

> [!TIP]
> Mach-O binary에는 하나 또는 **여러 개의** **constructor**가 포함될 수 있으며, 이러한 **constructor**는 **LC_MAIN**에 지정된 address보다 **먼저 실행**됩니다.\
> 모든 constructor의 offset은 **\_\_DATA_CONST** segment의 **\_\_mod_init_func** section에 저장됩니다.

## **Mach-O 데이터**

파일의 핵심에는 data region이 있으며, 이는 load-commands region에 정의된 여러 segment로 구성됩니다. **각 segment에는 다양한 data section이 포함될 수 있으며**, 각 section은 특정 type에 해당하는 **code 또는 data를 저장**합니다.

> [!TIP]
> data는 기본적으로 load command **LC_SEGMENTS_64**가 load하는 모든 **정보**를 포함하는 부분입니다.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

여기에는 다음이 포함됩니다:

- **Function table:** program function에 대한 정보를 저장합니다.
- **Symbol table**: binary가 사용하는 external function에 대한 정보를 포함합니다.
- 또한 internal function, variable name 및 기타 정보도 포함할 수 있습니다.

이를 확인하려면 [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool을 사용할 수 있습니다:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

또는 CLI에서:
```bash
size -m /bin/ls
```
## Objective-C Common Sections

`__TEXT` 세그먼트 (r-x) 내:

- `__objc_classname`: 클래스 이름 (문자열)
- `__objc_methname`: 메서드 이름 (문자열)
- `__objc_methtype`: 메서드 타입 (문자열)

`__DATA` 세그먼트 (rw-) 내:

- `__objc_classlist`: 모든 Objective-C 클래스에 대한 포인터
- `__objc_nlclslist`: Non-Lazy Objective-C 클래스에 대한 포인터
- `__objc_catlist`: Categories에 대한 포인터
- `__objc_nlcatlist`: Non-Lazy Categories에 대한 포인터
- `__objc_protolist`: Protocols 목록
- `__objc_const`: 상수 데이터
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Reading Your Own Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
