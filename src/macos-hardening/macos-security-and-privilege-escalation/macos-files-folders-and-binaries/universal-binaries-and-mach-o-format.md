# macOS Universal 바이너리 및 Mach-O 형식

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

macOS는 **Mach-O** 실행 파일 형식을 사용합니다. **universal** 또는 fat 바이너리에는 하나의 파일에 여러 아키텍처별 Mach-O slice가 포함됩니다. Apple의 오픈 소스 `fat.h` 및 `loader.h` 헤더는 이 페이지에서 설명하는 구조체와 상수를 정의합니다. <sup>[[5]](#references)</sup>

Mach-O 이미지는 다음으로 구성됩니다.

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

다음 명령어로 파일을 검색합니다: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

헤더에는 **magic** 바이트가 있고, 그 뒤에 파일에 **포함된** **아키텍처** 수(`nfat_arch`)가 이어집니다. 각 아키텍처에는 `fat_arch` 구조체가 있습니다.

다음 명령어로 확인합니다.

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

또는 [Mach-O View](https://sourceforge.net/projects/machoview/) 도구를 사용할 수 있습니다.

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

보통 2개 아키텍처용으로 컴파일된 universal 바이너리는 1개 아키텍처용으로 컴파일된 바이너리보다 **크기가 두 배**가 됩니다.

> [!TIP]
> malware나 의심스러운 앱을 조사할 때 `file`이 "가장 적합한" 아키텍처를 보고했다고 해서 멈추지 마세요. universal 바이너리는 각 slice마다 서로 다른 imports, load commands 또는 compiler metadata를 숨길 수 있으므로, 먼저 **모든** slice를 열거한 다음 각각을 독립적으로 검사하세요:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

최근 macOS SDK에는 `<mach-o/utils.h>`의 `macho_for_each_slice()` 및 `macho_best_slice()` 같은 헬퍼도 제공됩니다. 후자는 dyld/kernel이 로드할 항목을 에뮬레이트하는 데 유용하지만, 스캐너는 아키텍처별 콘텐츠를 놓치지 않도록 모든 slice를 계속 순회해야 합니다.<sup>[[1]](#references)</sup>

## **Mach-O 헤더**

헤더에는 파일이 Mach-O 파일임을 식별하는 magic bytes와 대상 아키텍처 정보 등 파일의 기본 정보가 포함되어 있습니다. 다음 위치에서 찾을 수 있습니다: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

다양한 파일 유형이 있으며, [**예를 들어 여기의 소스 코드에서**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) 정의를 확인할 수 있습니다. 가장 중요한 유형은 다음과 같습니다.

- `MH_OBJECT`: 재배치 가능한 객체 파일(컴파일 중간 산출물이며 아직 실행 파일은 아님).
- `MH_EXECUTE`: 실행 파일.
- `MH_FVMLIB`: 고정 VM 라이브러리 파일.
- `MH_CORE`: 코드 덤프.
- `MH_PRELOAD`: 사전 로드된 실행 파일(XNU에서 더 이상 지원되지 않음).
- `MH_DYLIB`: 동적 라이브러리.
- `MH_DYLINKER`: 동적 링커.
- `MH_BUNDLE`: "플러그인 파일". gcc에서 -bundle을 사용해 생성하며 `NSBundle` 또는 `dlopen`으로 명시적으로 로드됩니다.
- `MH_DYSM`: 관련 `.dSym` 파일(디버깅용 심볼이 포함된 파일).
- `MH_KEXT_BUNDLE`: 커널 확장.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

또는 [Mach-O View](https://sourceforge.net/projects/machoview/)를 사용합니다:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 플래그**

소스 코드에는 라이브러리를 로드할 때 유용한 여러 플래그도 정의되어 있습니다.

- `MH_NOUNDEFS`: 정의되지 않은 참조가 없음(완전히 링크됨)
- `MH_DYLDLINK`: Dyld 링크
- `MH_PREBOUND`: 동적 참조가 미리 바인딩됨.
- `MH_SPLIT_SEGS`: 파일이 읽기 전용 및 읽기/쓰기 세그먼트로 분할됨.
- `MH_WEAK_DEFINES`: 바이너리에 weak로 정의된 심볼이 있음
- `MH_BINDS_TO_WEAK`: 바이너리가 weak 심볼을 사용함
- `MH_ALLOW_STACK_EXECUTION`: 스택을 실행 가능하게 설정
- `MH_NO_REEXPORTED_DYLIBS`: 라이브러리에 LC_REEXPORT 명령이 없음
- `MH_PIE`: 위치 독립 실행 파일
- `MH_HAS_TLV_DESCRIPTORS`: 스레드 로컬 변수가 있는 섹션이 있음
- `MH_NO_HEAP_EXECUTION`: 힙/데이터 페이지에서 실행하지 않음
- `MH_HAS_OBJC`: 바이너리에 Objective-C 섹션이 있음
- `MH_SIM_SUPPORT`: 시뮬레이터 지원
- `MH_DYLIB_IN_CACHE`: 공유 라이브러리 캐시의 dylib/framework에 사용됨.

## **Mach-O 로드 명령**

**메모리에서 파일의 레이아웃**은 여기에서 지정됩니다. 여기에는 **심볼 테이블의 위치**, 실행 시작 시 메인 스레드의 컨텍스트, 필요한 **공유 라이브러리**가 자세히 설명되어 있습니다. 바이너리를 메모리에 로드하는 과정에서 동적 로더 **(dyld)**가 따를 지침이 제공됩니다.

이 구조는 언급된 **`loader.h`**에 정의된 **load_command** 구조체를 사용합니다:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

시스템이 서로 다르게 처리하는 **로드 명령 유형은 약 50가지**입니다. 가장 일반적인 유형은 `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE`입니다.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> 기본적으로 이 유형의 로드 명령은 바이너리가 실행될 때 **데이터 섹션에 표시된 오프셋**에 따라 **\_\_TEXT**(실행 코드) **및 \_\_DATA**(프로세스의 데이터) **세그먼트를 로드하는 방법**을 정의합니다.

이 명령은 프로세스가 실행될 때 해당 프로세스의 **가상 메모리 공간에 매핑되는 세그먼트를 정의**합니다.

**\_\_TEXT** 세그먼트처럼 프로그램의 실행 코드를 담는 세그먼트와, 프로세스가 사용하는 데이터를 포함하는 **\_\_DATA** 세그먼트 등 **다양한 유형의 세그먼트**가 있습니다. 이러한 **세그먼트는 Mach-O 파일의 데이터 섹션에 위치**합니다.

**각 세그먼트**는 다시 여러 **섹션으로 나뉠** 수 있습니다. **로드 명령 구조체**에는 해당 세그먼트에 포함된 **이러한 섹션에 대한 정보**가 들어 있습니다.

헤더에서 먼저 **세그먼트 헤더**를 볼 수 있습니다.

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

세그먼트 헤더 예시:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

이 헤더는 **뒤에 헤더가 나오는 섹션의 개수**를 정의합니다.

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

**section offset**(0x37DC)와 이 경우 **arch starts** 위치의 **offset**인 `0x18000`을 더하면 --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

다음 명령어를 사용해 **command line**에서도 **headers information**을 확인할 수 있습니다:

```bash
otool -lv /bin/ls
```

Common segments 이 cmd로 로드됩니다:

- **`__PAGEZERO`:** 커널에 **주소 0을 매핑**하되, 해당 주소를 **읽거나, 쓰거나, 실행할 수 없도록** 지시합니다. 구조체의 maxprot 및 minprot 변수는 이 페이지에 **읽기-쓰기-실행 권한이 없음**을 나타내도록 0으로 설정됩니다.
  - 이 할당은 **NULL 포인터 역참조 취약점을 완화**하는 데 중요합니다. XNU가 첫 번째 메모리 페이지(첫 페이지만)에 접근할 수 없도록 하는 hard page zero를 적용하기 때문입니다(i386은 예외). 바이너리는 작은 \_\_PAGEZERO를 만들어(`-pagezero_size` 사용) 첫 4k를 포함하고, 나머지 32bit 메모리는 사용자 모드와 커널 모드 모두에서 접근 가능하게 하여 이 요구 사항을 충족할 수 있습니다.
- **`__TEXT`**: **읽기** 및 **실행** 권한이 있고 쓰기 권한은 없는 **실행 가능한 코드**를 포함합니다. 이 세그먼트의 일반적인 섹션:
  - `__text`: 컴파일된 바이너리 코드
  - `__const`: 상수 데이터(읽기 전용)
  - `__[c/u/os_log]string`: C, Unicode 또는 os 로그 문자열 상수
  - `__stubs` 및 `__stubs_helper`: 동적 라이브러리 로딩 과정에서 사용
  - `__unwind_info`: 스택 언와인드 데이터.
  - 이 콘텐츠는 모두 서명되어 있지만 실행 가능으로 표시되기도 합니다. (문자열 전용 섹션처럼 반드시 이 권한이 필요하지 않은 섹션을 악용할 수 있는 선택지가 더 많아집니다.)
- **`__DATA`**: **읽기** 및 **쓰기**가 가능하고 실행 권한은 없는 데이터를 포함합니다.
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: non-lazy 심볼 포인터(로드 시 바인딩)
  - `__la_symbol_ptr`: lazy 심볼 포인터(사용 시 바인딩)
  - `__const`: 읽기 전용 데이터여야 함(실제로는 그렇지 않음)
  - `__cfstring`: CoreFoundation 문자열
  - `__data`: 전역 변수(초기화된 변수)
  - `__bss`: 정적 변수(초기화되지 않은 변수)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist 등): Objective-C runtime에서 사용하는 정보
- **`__DATA_CONST`**: \_\_DATA.\_\_const는 상수(쓰기 권한 없음)라고 보장되지 않으며, 다른 포인터나 GOT도 마찬가지입니다. 이 섹션은 `mprotect`를 사용하여 `__const`, 일부 초기화 데이터, 그리고 (해석이 끝난 후) GOT 테이블을 **읽기 전용**으로 만듭니다.
- **`__AUTH` / `__AUTH_CONST`**: 최근 Apple Silicon 바이너리에서 흔히 볼 수 있습니다. 이 세그먼트에는 로드 시점이나 사용 시점에 인증해야 하는 포인터가 들어 있습니다(예: `__auth_got`). rebinding, hook 또는 import-patching 기법이 기존 `__got` / `__la_symbol_ptr` 섹션만 확인한다면, 최신 `arm64e` 바이너리의 실제 호출 지점을 놓칠 수 있습니다. 이 섹션에 대한 자세한 내용은 [이 페이지](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)를 참조하세요.
- **`__LINKEDIT`**: 심볼, 문자열, 재배치 테이블 항목 등 linker(dyld)에 필요한 정보를 포함합니다. `__TEXT`나 `__DATA`에 속하지 않는 콘텐츠를 담는 일반 컨테이너이며, 해당 콘텐츠는 다른 load command에 기술됩니다.
  - dyld 정보: Rebase, non-lazy/lazy/weak 바인딩 opcode 및 export 정보
  - 함수 시작 지점: 함수 시작 주소 테이블
  - 코드 내 데이터: \_\_text의 데이터 영역
  - 심볼 테이블: 바이너리의 심볼
  - 간접 심볼 테이블: 포인터/stub 심볼
  - 문자열 테이블
  - 코드 서명
- **`__OBJC`**: Objective-C runtime에서 사용하는 정보를 포함합니다. 이 정보는 \_\_DATA 세그먼트의 여러 \_\_objc\_\* 섹션에서도 찾을 수 있습니다.
- **`__RESTRICT`**: 콘텐츠가 없는 세그먼트로, **`__restrict`**라는 단일 섹션을 포함합니다(이 섹션도 비어 있음). 바이너리를 실행할 때 DYLD 환경 변수를 무시하도록 합니다.

코드에서 확인했듯이, **세그먼트는 플래그도 지원합니다**(다만 자주 사용되지는 않습니다).

- `SG_HIGHVM`: Core 전용(사용하지 않음)
- `SG_FVMLIB`: 사용하지 않음
- `SG_NORELOC`: 세그먼트에 재배치가 없음
- `SG_PROTECTED_VERSION_1`: 암호화. 예를 들어 Finder가 텍스트 `__TEXT` 세그먼트를 암호화하는 데 사용합니다.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**은 **entryoff 속성에 진입점을 포함합니다.** 로드 시 **dyld**는 이 값을 (메모리에 로드된) **바이너리의 베이스 주소에 더한 다음**, 해당 명령어로 **점프**하여 바이너리 코드 실행을 시작합니다.

**`LC_UNIXTHREAD`**에는 메인 스레드가 시작될 때 레지스터가 가져야 할 값이 들어 있습니다. 이미 deprecated되었지만 **`dyld`**는 여전히 이를 사용합니다. 다음 명령어로 이 항목에서 설정된 레지스터 값을 확인할 수 있습니다:

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


Mach-O 파일의 **code signature에 대한 정보**를 포함합니다. **signature blob**을 **가리키는** **offset**만 포함하며, 일반적으로 파일의 맨 끝에 있습니다.\
이 섹션에 대한 자세한 내용은 [**이 블로그 게시물**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)과 [**이 gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)를 참조하세요.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

binary encryption을 지원합니다. 하지만 물론 공격자가 프로세스를 침해하는 데 성공하면 암호화되지 않은 메모리를 덤프할 수 있습니다.

### **`LC_LOAD_DYLINKER`**

shared libraries를 프로세스의 address space에 매핑하는 **dynamic linker executable의 경로**를 포함합니다. **값은 항상 `/usr/lib/dyld`로 설정됩니다**. macOS에서는 dylib 매핑이 kernel mode가 아닌 **user mode**에서 이루어진다는 점에 유의해야 합니다.

### **`LC_IDENT`**

사용되지 않는 명령이지만, panic 발생 시 dump를 생성하도록 설정하면 Mach-O core dump가 생성되고 kernel version이 `LC_IDENT` 명령에 설정됩니다.

### **`LC_UUID`**

임의의 UUID입니다. 직접적으로는 별 쓸모가 없지만, XNU가 나머지 프로세스 정보와 함께 이를 캐시합니다. crash reports에서 사용할 수 있습니다.

### **`LC_BUILD_VERSION`**

최신 binaries에는 일반적으로 **target platform**, **minimum OS version**, **SDK version**, 그리고 선택적으로 해당 slice를 빌드하는 데 사용된 **tool versions**를 선언하는 이 명령이 포함됩니다. offensive/reversing 관점에서 이는 sample의 빌드 방식을 파악하고, 한 slice가 다른 SDK나 deployment target으로 컴파일된 이상한 universal binaries를 빠르게 찾아내는 데 매우 유용합니다. 오래된 binaries는 대신 `LC_VERSION_MIN_*`을 사용할 수 있습니다.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

프로세스가 실행되기 전에 dyld에 환경 변수를 지정할 수 있습니다. 프로세스 내부에서 임의의 코드를 실행할 수 있으므로 매우 위험할 수 있습니다. 따라서 이 load command는 `#define SUPPORT_LC_DYLD_ENVIRONMENT`가 정의된 dyld 빌드에서만 사용되며, 처리 대상도 로드 경로를 지정하는 `DYLD_..._PATH` 형식의 변수로 제한됩니다.

### **`LC_DYLD_EXPORTS_TRIE` 및 `LC_DYLD_CHAINED_FIXUPS`**

최근 툴체인은 이전 `LC_DYLD_INFO[_ONLY]` opcode에만 의존하지 않고, 이 명령을 사용해 export/bind/rebase 메타데이터를 저장하는 경우가 많습니다. 둘 다 **`__LINKEDIT`** 내부를 가리키는 `linkedit_data_command` 항목입니다.

- **`LC_DYLD_EXPORTS_TRIE`**: 이미지가 export하는 심볼을 담은 압축 trie입니다.
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld가 rebase와 bind를 적용하는 데 사용하는 세그먼트별 fixup 체인입니다. Apple Silicon에서는 최신 인증 포인터 fixup도 다수 이곳에서 확인할 수 있습니다.

이 메타데이터는 import/export를 재구성하거나, `@rpath`로 로드된 종속성이 특정 방식으로 확인된 이유를 파악하거나, 최신 `arm64e` 대상에서 hook/rebinding 시도가 실패한 이유를 알아낼 때 매우 유용합니다. `dyld_info`는 디스크에 독립 파일로 존재하지 않는 **캐시 전용 dylib 경로**에도 사용할 수 있습니다. 많은 시스템 라이브러리가 공유 캐시에만 존재하는 최신 macOS 환경에서 특히 유용합니다.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

이 최신 load command는 **kernel collections / kernelcache 스타일의 fileset**을 검사할 때 주로 관련이 있습니다. 외부 Mach-O가 독립된 단일 이미지가 아니라 컨테이너 역할을 하며, 각 `LC_FILESET_ENTRY`는 경로와 비슷한 자체 **entry id**, VM 주소, 파일 오프셋을 가진 내장 Mach-O를 가리킵니다. 최신 macOS/iOS 커널 구성 요소를 리버싱할 때 이 command는 최상위 컨테이너와 추출하거나 디스어셈블하려는 실제 이미지 사이를 연결하는 역할을 하는 경우가 많습니다.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

실제 추출 워크플로는 [macOS 커널 확장 및 kernelcache에 관한 이 페이지](../mac-os-architecture/macos-kernel-extensions.md)를 확인하세요.

### **`LC_LOAD_DYLIB`**

이 로드 명령은 **동적** **라이브러리** 종속성을 설명하며, **로더**(dyld)에 해당 **라이브러리를 로드하고 링크하도록 지시**합니다. Mach-O 바이너리에 필요한 **각 라이브러리마다** `LC_LOAD_DYLIB` 로드 명령이 있습니다.

- 이 로드 명령은 **`dylib_command`** 유형의 구조체입니다(여기에는 실제 종속 동적 라이브러리를 설명하는 struct dylib가 포함됨):

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

CLI를 사용해 이 정보도 확인할 수 있습니다:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Some 잠재적인 malware 관련 라이브러리는 다음과 같습니다.

- **DiskArbitration**: USB 드라이브 모니터링
- **AVFoundation:** 오디오 및 비디오 캡처
- **CoreWLAN**: Wi-Fi 스캔

> [!TIP]
> Mach-O 바이너리에는 하나 또는 **여러 개의** **constructor**가 포함될 수 있으며, 이들은 **LC_MAIN**에 지정된 주소보다 **먼저** **실행됩니다**.\
> constructor의 오프셋은 **\_\_DATA_CONST** 세그먼트의 **\_\_mod_init_func** 섹션에 저장됩니다.

## **Mach-O 데이터**

파일의 핵심에는 데이터 영역이 있으며, 이 영역은 load-command 영역에 정의된 여러 세그먼트로 구성됩니다. **각 세그먼트에는 다양한 데이터 섹션이 포함될 수 있으며**, 각 섹션은 특정 유형의 **코드 또는 데이터**를 담습니다.

> [!TIP]
> 데이터는 기본적으로 load command **LC_SEGMENTS_64**가 로드하는 모든 **정보**가 포함된 부분입니다.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

여기에는 다음이 포함됩니다.

- **Function table:** 프로그램 함수에 대한 정보를 담습니다.
- **Symbol table**: 바이너리에서 사용하는 외부 함수에 대한 정보를 담습니다.
- 내부 함수와 변수 이름 등도 포함될 수 있습니다.

이를 확인하려면 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 도구를 사용할 수 있습니다.

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

또는 CLI에서:

```bash
size -m /bin/ls
```

### 추가 데이터와 역방향으로 파싱되는 오버레이

로더는 이름이 지정된 Mach-O 섹션 대신 추가 데이터에 구성을 저장할 수 있습니다. 그러면 역방향 파서는 트레일러 마커를 기준점으로 삼고, 그 바로 앞에 저장된 크기를 읽은 다음 해당 값을 사용해 앞에 있는 블롭의 위치를 찾고 복호화합니다. 관찰된 한 유니버설 로더는 XOR로 암호화된 다운로더 URL에 이 레이아웃을 사용했습니다:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

익숙하지 않은 바이너리를 리버스 엔지니어링할 때는 알아볼 수 있는 끝 마커 주변의 바이트를 살펴보고, 문자열이나 구성이 반드시 로드 명령 섹션에 속한다고 단정하기 전에 모든 역방향 크기 계산을 추적하세요. 마커와 XOR 키는 샘플마다 다릅니다. 재사용할 수 있는 기법은 자기 기술형 트레일러입니다.

## Objective-C 공통 섹션

`__TEXT` 세그먼트 (r-x):

- `__objc_classname`: 클래스 이름 (문자열)
- `__objc_methname`: 메서드 이름 (문자열)
- `__objc_methtype`: 메서드 타입 (문자열)

`__DATA` 세그먼트 (rw-):

- `__objc_classlist`: 모든 Objective-C 클래스의 포인터
- `__objc_nlclslist`: Non-Lazy Objective-C 클래스의 포인터
- `__objc_catlist`: Categories의 포인터
- `__objc_nlcatlist`: Non-Lazy Categories의 포인터
- `__objc_protolist`: Protocols 목록
- `__objc_const`: 상수 데이터
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

함께 보기: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-O 슬라이스는 생각만큼 간단하지 않습니다](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) 매뉴얼 페이지](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [자신의 Entitlements 읽기](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple 오픈 소스 - Mach-O `fat.h` 및 `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - 암호화폐 애호가와 개발자를 노리는 MacSync macOS 스틸러의 새 버전](https://securelist.com/macsync-new-version/121383/)
