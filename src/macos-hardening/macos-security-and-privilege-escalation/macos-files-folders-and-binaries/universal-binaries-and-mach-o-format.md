# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Mac OS 바이너리는 보통 **universal binaries**로 컴파일됩니다. **universal binary**는 단일 파일에서 **여러 아키텍처를 지원할 수 있습니다**.

이러한 바이너리는 기본적으로 다음으로 구성된 **Mach-O 구조**를 따릅니다:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

다음으로 파일을 검색하세요: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

헤더는 **magic** 바이트와 뒤따르는 파일이 포함하는 **archs**의 **개수** (`nfat_arch`)를 포함하며, 각 arch는 `fat_arch` 구조체를 가집니다.

다음으로 확인하세요:

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

또는 [Mach-O View](https://sourceforge.net/projects/machoview/) 도구를 사용하여:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

아마 생각하셨겠지만, 보통 2개 아키텍처용으로 컴파일된 universal binary는 단일 아키텍처용으로 컴파일된 것보다 크기가 **2배**가 됩니다.

## **Mach-O Header**

헤더에는 Mach-O 파일로 식별하기 위한 magic 바이트와 대상 아키텍처에 대한 정보 등 파일의 기본 정보가 포함됩니다. 다음에서 찾을 수 있습니다: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O 파일 형식

여러 가지 파일 형식이 있으며, [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)에서 정의된 것을 확인할 수 있습니다. 가장 중요한 것들은 다음과 같습니다:

- `MH_OBJECT`: 재배치 가능한 오브젝트 파일 (컴파일의 중간 산출물로 아직 실행 파일이 아님).
- `MH_EXECUTE`: 실행 파일.
- `MH_FVMLIB`: 고정 VM 라이브러리 파일.
- `MH_CORE`: 코드 덤프
- `MH_PRELOAD`: 사전 로드된 실행 파일 (현재 XNU에서 더 이상 지원되지 않음)
- `MH_DYLIB`: 동적 라이브러리
- `MH_DYLINKER`: 동적 링커
- `MH_BUNDLE`: "플러그인 파일". -bundle in gcc로 생성되며 명시적으로 `NSBundle` 또는 `dlopen`으로 로드됩니다.
- `MH_DYSM`: 동반 `.dSym` 파일 (디버깅을 위한 심볼이 포함된 파일).
- `MH_KEXT_BUNDLE`: 커널 확장.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
또는 [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 플래그**

소스 코드에는 라이브러리 로딩에 유용한 여러 플래그도 정의되어 있다:

- `MH_NOUNDEFS`: 정의되지 않은 참조 없음 (완전 링크됨)
- `MH_DYLDLINK`: Dyld 링크
- `MH_PREBOUND`: 동적 참조가 사전 바인딩됨
- `MH_SPLIT_SEGS`: 파일이 r/o 및 r/w 세그먼트로 분리됨
- `MH_WEAK_DEFINES`: 바이너리에 weak로 정의된 심볼이 있음
- `MH_BINDS_TO_WEAK`: 바이너리가 weak 심볼을 사용함
- `MH_ALLOW_STACK_EXECUTION`: 스택을 실행 가능하게 함
- `MH_NO_REEXPORTED_DYLIBS`: 라이브러리에 LC_REEXPORT 명령이 없음
- `MH_PIE`: 위치 독립 실행 파일
- `MH_HAS_TLV_DESCRIPTORS`: 스레드 로컬 변수 섹션이 있음
- `MH_NO_HEAP_EXECUTION`: 힙/데이터 페이지에서 실행 불가
- `MH_HAS_OBJC`: 바이너리에 Objective-C 섹션이 있음
- `MH_SIM_SUPPORT`: 시뮬레이터 지원
- `MH_DYLIB_IN_CACHE`: shared library cache에 있는 dylib/framework에 사용됨.

## **Mach-O 로드 명령**

파일의 메모리 레이아웃이 여기서 지정되며, 심볼 테이블의 위치, 실행 시작 시 메인 스레드의 컨텍스트, 그리고 필요한 공유 라이브러리들이 상세히 기술된다. 바이너리를 메모리에 로드하는 과정에 대해 동적 로더(dyld)에 지침을 제공한다.

여기서는 앞서 언급한 **`loader.h`**에 정의된 **load_command** 구조체를 사용한다:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 기본적으로, 이 유형의 Load Command는 바이너리가 실행될 때 데이터 섹션에 표시된 **오프셋에 따라 \_\_TEXT**(실행 코드) **및 \_\_DATA**(프로세스의 데이터) **세그먼트를 어떻게 로드하는지 정의합니다.**

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
예: **섹션 헤더**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

만약 **더하면** **섹션 오프셋** (0x37DC) + **arch가 시작하는 오프셋**, 이 경우 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

또한 **헤더 정보**를 **command line**에서 얻을 수도 있습니다:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** 커널에게 **주소 0(address zero)**를 **매핑(map)**하도록 지시하여 **읽기/쓰기/실행이 불가능**하도록 합니다. 구조체의 maxprot 및 minprot 변수는 이 페이지에 대한 **읽기-쓰기-실행 권한이 없음을** 나타내기 위해 0으로 설정됩니다.
- 이 할당은 **NULL pointer dereference vulnerabilities**를 완화하는 데 중요합니다. 이는 XNU가 하드 페이지 제로를 적용하여 메모리의 첫 번째 페이지(첫 페이지만)를 접근 불가로 만들기 때문입니다(i386 제외). 바이너리는 작은 \_\_PAGEZERO( `-pagezero_size` 사용)를 만들어 처음 4K를 덮고 나머지 32비트 메모리는 유저 및 커널 모드에서 접근 가능하도록 하여 이 요구사항을 충족할 수 있습니다.
- **`__TEXT`**: **실행 가능한(executable)** **코드(code)**를 포함하며 **읽기(read)** 및 **실행(execute)** 권한을 가집니다(쓰기 권한 없음). 이 세그먼트의 일반 섹션:
- `__text`: 컴파일된 바이너리 코드
- `__const`: 상수 데이터(읽기 전용)
- `__[c/u/os_log]string`: C, Unicode 또는 os 로그 문자열 상수
- `__stubs` and `__stubs_helper`: 동적 라이브러리 로딩 과정에 관여
- `__unwind_info`: 스택 언와인드 데이터
- 이 모든 내용은 서명되어 있되 실행 가능으로 표시되어 있다는 점에 유의하세요(문자열 전용 섹션처럼 반드시 실행 권한을 필요로 하지 않는 섹션을 악용할 수 있는 가능성이 증가합니다).
- **`__DATA`**: **읽기(readable)** 및 **쓰기(writable)** 가능한 데이터를 포함합니다(실행 불가).
- `__got`: 전역 오프셋 테이블(Global Offset Table)
- `__nl_symbol_ptr`: Non-lazy(로딩 시 바인딩) 심볼 포인터
- `__la_symbol_ptr`: Lazy(사용 시 바인딩) 심볼 포인터
- `__const`: 원래는 읽기 전용 데이터여야 함(실제론 그렇지 않음)
- `__cfstring`: CoreFoundation 문자열
- `__data`: 초기화된 전역 변수
- `__bss`: 초기화되지 않은 정적 변수
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, 등): Objective-C 런타임에서 사용하는 정보
- **`__DATA_CONST`**: \_\_DATA.\_\_const는 상수(쓰기 금지)라고 보장되지 않으며, 다른 포인터들과 GOT 또한 마찬가지입니다. 이 섹션은 `__const`, 일부 이니셜라이저 및 (해결된 후의) GOT 테이블을 `mprotect`를 사용해 **읽기 전용**으로 만듭니다.
- **`__LINKEDIT`**: 링커(dyld)를 위한 정보(심볼, 문자열, 재배치 테이블 엔트리 등)를 포함합니다. `__TEXT`나 `__DATA`에 속하지 않는 내용을 담는 일반 컨테이너이며 그 내용은 다른 로드 커맨드에서 기술됩니다.
- dyld 정보: Rebase, Non-lazy/lazy/weak binding opcodes 및 export 정보
- Functions starts: 함수들의 시작 주소 표
- Data In Code: 데이터 섬들 in \_\_text
- Symbol Table: 바이너리 내의 심볼
- Indirect Symbol Table: 포인터/스텁 심볼
- String Table
- Code Signature
- **`__OBJC`**: Objective-C 런타임에서 사용하는 정보를 포함합니다. 이 정보는 \_\_DATA 세그먼트 내의 다양한 \_\_objc\_\* 섹션에서도 찾을 수 있습니다.
- **`__RESTRICT`**: 내용이 없는 세그먼트로, **`__restrict`**라는 단일 섹션(역시 비어 있음)을 가지며, 바이너리 실행 시 DYLD 환경 변수를 무시하도록 보장합니다.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core 전용(사용 안 함)
- `SG_FVMLIB`: 사용되지 않음
- `SG_NORELOC`: 세그먼트에 재배치 없음
- `SG_PROTECTED_VERSION_1`: 암호화. 예를 들어 Finder가 텍스트 `__TEXT` 세그먼트를 암호화하는 데 사용됩니다.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**은 **entryoff attribute**에 엔트리포인트를 포함합니다. 로드 시, **dyld**는 단순히 이 값을 (메모리 상의) **바이너리의 베이스(base of the binary)**에 더한 후 해당 명령으로 **점프(jumps)**하여 바이너리 코드를 실행합니다.

**`LC_UNIXTHREAD`**는 메인 스레드를 시작할 때 레지스터가 가져야 할 값들을 포함합니다. 이는 이미 deprecated 되었지만 **`dyld`**는 여전히 이를 사용합니다. 이로 인해 설정된 레지스터 값들은 다음을 통해 확인할 수 있습니다:
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


Contains information about the **code signature of the Macho-O file**. It only contains an **offset** that **points** to the **signature blob**. This is typically at the very end of the file.\
However, you can find some information about this section in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) and this [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

바이너리 암호화를 지원합니다. 그러나 공격자가 프로세스를 침해하면 메모리를 암호화되지 않은 상태로 덤프할 수 있습니다.

### **`LC_LOAD_DYLINKER`**

공유 라이브러리를 프로세스 주소 공간에 맵핑하는 dynamic linker 실행 파일의 경로를 포함합니다. 값은 항상 `/usr/lib/dyld`로 설정됩니다. macOS에서는 dylib 매핑이 커널 모드가 아니라 사용자 모드에서 발생한다는 점을 유의하세요.

### **`LC_IDENT`**

구식이지만, panic 시 덤프를 생성하도록 구성하면 Mach-O 코어 덤프가 생성되고 커널 버전이 `LC_IDENT` 명령에 설정됩니다.

### **`LC_UUID`**

무작위 UUID입니다. 자체적으로는 직접적인 용도는 제한적이지만 XNU가 이를 다른 프로세스 정보와 함께 캐시합니다. 크래시 리포트에 사용할 수 있습니다.

### **`LC_DYLD_ENVIRONMENT`**

프로세스가 실행되기 전에 dyld에 환경 변수를 지정할 수 있게 합니다. 이는 프로세스 내부에서 임의의 코드를 실행할 수 있게 하므로 매우 위험할 수 있습니다. 따라서 이 load command는 `#define SUPPORT_LC_DYLD_ENVIRONMENT`로 빌드된 dyld에서만 사용되며, 처리는 로드 경로를 지정하는 `DYLD_..._PATH` 형태의 변수로만 제한됩니다.

### **`LC_LOAD_DYLIB`**

이 load command는 loader(dyld)에게 라이브러리를 로드하고 링크하도록 지시하는 dynamic library 의존성을 설명합니다. Mach-O 바이너리가 필요로 하는 각 라이브러리마다 하나의 `LC_LOAD_DYLIB` load command가 있습니다.

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
![](<../../../images/image (486).png>)

또는 cli에서 다음과 같이 이 정보를 얻을 수도 있습니다:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
일부 잠재적 악성코드 관련 라이브러리:

- **DiskArbitration**: USB 드라이브 모니터링
- **AVFoundation:** 오디오 및 비디오 캡처
- **CoreWLAN**: Wifi 스캔.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O 데이터**

파일의 핵심에는 load-commands 영역에 정의된 여러 세그먼트로 구성된 데이터 영역이 있습니다. **각 세그먼트 안에는 다양한 데이터 섹션이 존재할 수 있으며**, 각 섹션은 특정 타입에 대한 **코드 또는 데이터를 보관**합니다.

> [!TIP]
> 데이터는 기본적으로 **LC_SEGMENTS_64** 로드 커맨드에 의해 로드되는 모든 **정보**를 포함하는 부분입니다.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

이에는 다음이 포함됩니다:

- **함수 테이블:** 프로그램 함수에 대한 정보를 보관합니다.
- **심볼 테이블**: 바이너리에서 사용되는 외부 함수에 대한 정보를 포함합니다.
- 내부 함수나 변수 이름 등도 포함될 수 있습니다.

확인하려면 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 도구를 사용할 수 있습니다:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

또는 CLI에서:
```bash
size -m /bin/ls
```
## Objetive-C 공통 섹션

`__TEXT` 세그먼트 (r-x):

- `__objc_classname`: 클래스 이름(문자열)
- `__objc_methname`: 메서드 이름(문자열)
- `__objc_methtype`: 메서드 타입(문자열)

`__DATA` 세그먼트 (rw-):

- `__objc_classlist`: 모든 Objetive-C 클래스에 대한 포인터
- `__objc_nlclslist`: Non-Lazy Objective-C 클래스에 대한 포인터
- `__objc_catlist`: 카테고리에 대한 포인터
- `__objc_nlcatlist`: Non-Lazy 카테고리에 대한 포인터
- `__objc_protolist`: 프로토콜 목록
- `__objc_const`: 상수 데이터
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
