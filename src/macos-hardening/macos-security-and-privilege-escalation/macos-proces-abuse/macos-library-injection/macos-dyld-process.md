# macOS Dyld 프로세스

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

Mach-o 바이너리의 실제 **엔트리포인트**는 동적 링커이며, `LC_LOAD_DYLINKER`에 정의되고 보통 `/usr/lib/dyld`입니다.<sup>[[3]](#references)</sup>

이 링커는 모든 실행 파일 라이브러리를 찾아 메모리에 매핑하고, 모든 non-lazy 라이브러리를 링크해야 합니다. 이 과정이 끝난 뒤에야 바이너리의 엔트리포인트가 실행됩니다.

물론 **`dyld`**에는 의존성이 없습니다(syscall과 libSystem 발췌 부분을 사용합니다).

> [!CAUTION]
> 이 링커에 취약점이 있다면, 어떤 바이너리(높은 권한을 가진 바이너리 포함)가 실행되기 전에 먼저 실행되므로 **권한 상승**이 가능할 수 있습니다.

### 흐름

Dyld는 **`dyldboostrap::start`**에 의해 로드되며, 이 함수는 **스택 카나리** 같은 항목도 로드합니다. 이 함수는 **`apple`** 인수 벡터에서 이 값과 그 밖의 **민감한** **값**을 받기 때문입니다.<sup>[[1]](#references)</sup>

**`dyls::_main()`**은 dyld의 엔트리포인트이며, 첫 번째 작업으로 `configureProcessRestrictions()`를 실행합니다. 이 함수는 일반적으로 다음에서 설명하는 **`DYLD_*`** 환경 변수를 제한합니다.<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

그런 다음 중요한 시스템 라이브러리를 미리 링크하는 dyld 공유 캐시를 매핑하고, 바이너리가 의존하는 라이브러리를 매핑합니다. 필요한 모든 라이브러리가 로드될 때까지 이 과정을 재귀적으로 이어갑니다. 따라서:

1. `DYLD_INSERT_LIBRARIES`로 삽입된 라이브러리(허용된 경우)를 로드하기 시작합니다.
2. 그런 다음 공유 캐시에 있는 라이브러리를 로드합니다.
3. 그런 다음 가져온 라이브러리를 로드합니다.
   1. 이후 라이브러리를 재귀적으로 계속 가져옵니다.

모두 로드되면 해당 라이브러리의 **초기화 함수**가 실행됩니다. 이 함수들은 `LC_ROUTINES[_64]`(현재는 사용 중단됨)에 정의된 **`__attribute__((constructor))`**를 사용하거나, `S_MOD_INIT_FUNC_POINTERS` 플래그가 지정된 섹션(보통 **`__DATA.__MOD_INIT_FUNC`**)의 포인터로 구현됩니다.

종료 함수는 **`__attribute__((destructor))`**로 구현되며, `S_MOD_TERM_FUNC_POINTERS` 플래그가 지정된 섹션(**`__DATA.__mod_term_func`**)에 위치합니다.

참고: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### 스텁

macOS의 모든 바이너리는 동적으로 링크됩니다. 따라서 바이너리에는 여러 시스템과 컨텍스트에서 올바른 코드로 이동하도록 돕는 스텁 섹션이 포함되어 있습니다. 바이너리 실행 시 이러한 주소를 확인해야 하는 역할은 dyld가 담당합니다(최소한 non-lazy 항목의 경우).

바이너리에 있는 스텁 섹션의 예:

- **`__TEXT.__[auth_]stubs`**: `__DATA` 섹션의 포인터
- **`__TEXT.__stub_helper`**: 호출할 함수 정보와 함께 동적 링크를 호출하는 짧은 코드
- **`__DATA.__[auth_]got`**: Global Offset Table(가져온 함수의 주소. 확인되면 로드 시 바인딩됨. `S_NON_LAZY_SYMBOL_POINTERS` 플래그로 표시됨)
- **`__DATA.__nl_symbol_ptr`**: non-lazy 심볼 포인터(로드 시 바인딩됨. `S_NON_LAZY_SYMBOL_POINTERS` 플래그로 표시됨)
- **`__DATA.__la_symbol_ptr`**: lazy 심볼 포인터(처음 접근할 때 바인딩됨)

> [!WARNING]
> "auth\_" 접두사가 붙은 포인터는 프로세스 내 암호화 키를 사용해 보호합니다(PAC). 또한 포인터를 따라가기 전에 arm64 명령어 `BLRA[A/B]`를 사용해 포인터를 검증할 수 있습니다. RET 주소 대신 RETA\[A/B]를 사용할 수도 있습니다.\
> 실제로 **`__TEXT.__auth_stubs`**의 코드는 요청된 함수를 호출할 때 **`bl`** 대신 **`braa`**를 사용해 포인터를 인증합니다.
>
> 현재 dyld 버전은 모든 항목을 non-lazy로 로드한다는 점도 알아두세요.

### lazy 심볼 찾기

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

흥미로운 디스어셈블리 부분:

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

`printf` 호출을 위한 점프가 **`__TEXT.__stubs`**로 향하는 것을 확인할 수 있습니다:

```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
  0 __text        00000038 0000000100003f60 TEXT
  1 __stubs       0000000c 0000000100003f98 TEXT
  2 __cstring     00000004 0000000100003fa4 DATA
  3 __unwind_info 00000058 0000000100003fa8 DATA
  4 __got         00000008 0000000100004000 DATA
```

**`__stubs`** 섹션의 디스어셈블리에서:

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

you can see that we are **GOT의 주소로 점프**하고 있습니다. 이 경우 해당 주소는 non-lazy로 resolve되며, `printf` 함수의 주소를 포함합니다.

다른 상황에서는 GOT로 직접 점프하는 대신 **`__DATA.__la_symbol_ptr`**로 점프할 수 있습니다. 이곳에서 로드하려는 함수를 나타내는 값을 로드한 다음, **`__TEXT.__stub_helper`**로 점프합니다. 이곳은 **`dyld_stub_binder`**의 주소를 포함하는 **`__DATA.__nl_symbol_ptr`**로 점프하며, `dyld_stub_binder`는 함수 번호와 주소를 매개변수로 받습니다.\
마지막 함수는 검색된 함수의 주소를 찾은 후, 이후에 다시 조회하지 않도록 해당 주소를 **`__TEXT.__stub_helper`**의 해당 위치에 씁니다.

> [!TIP]
> 단, 현재 dyld 버전은 모든 항목을 non-lazy로 로드한다는 점에 유의하세요.

#### Dyld opcode

마지막으로, **`dyld_stub_binder`**는 지정된 함수를 찾아 다시 검색하지 않도록 올바른 주소에 기록해야 합니다. 이를 위해 dyld 내부의 opcode(유한 상태 기계)를 사용합니다.

## apple\[] 인자 벡터

macOS에서 main 함수는 실제로 인자 3개가 아니라 4개를 받습니다. 네 번째 인자는 apple이라고 하며, 각 항목은 `key=value` 형식입니다. 예를 들면:

```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    for (int i=0; apple[i]; i++)
        printf("%d: %s\n", i, apple[i])
}
```

결과:

```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```

> [!TIP]
> 이러한 값이 main function에 도달할 때쯤이면 민감한 정보는 이미 제거된 상태입니다. 그렇지 않으면 data leak이 발생했을 것입니다.

main에 진입하기 전에 디버깅을 통해 다음과 같은 흥미로운 값을 모두 확인할 수 있습니다:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

이는 dyld의 상태 정보를 담은 dyld가 export하는 구조체입니다. 버전, dyld_image_info 배열 포인터, dyld_image_notifier 포인터, proc이 shared cache에서 분리되었는지 여부, libSystem initializer가 호출되었는지 여부, dyld 자체의 Mach header 포인터, dyld 버전 문자열 포인터 등의 정보를 포함하며, [**소스 코드**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)에서 확인할 수 있습니다.<sup>[[4]](#references)</sup>

## dyld 환경 변수

### dyld 디버깅

dyld가 수행하는 작업을 파악하는 데 유용한 환경 변수:

- **DYLD_PRINT_LIBRARIES**

로드되는 각 library를 확인합니다:

```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```

- **DYLD_PRINT_SEGMENTS**

각 라이브러리가 어떻게 로드되는지 확인합니다:

```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```

- **DYLD_PRINT_INITIALIZERS**

각 라이브러리 초기화 함수가 실행될 때 출력합니다:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### 기타

- `DYLD_BIND_AT_LAUNCH`: Lazy binding을 non-lazy binding과 함께 해결
- `DYLD_DISABLE_PREFETCH`: \_\_DATA 및 \_\_LINKEDIT 콘텐츠의 pre-fetch 비활성화
- `DYLD_FORCE_FLAT_NAMESPACE`: 단일 수준 binding
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: 경로 확인
- `DYLD_INSERT_LIBRARIES`: 지정한 library 로드
- `DYLD_PRINT_TO_FILE`: dyld 디버그 정보를 파일에 기록
- `DYLD_PRINT_APIS`: libdyld API 호출 출력
- `DYLD_PRINT_APIS_APP`: main이 수행한 libdyld API 호출 출력
- `DYLD_PRINT_BINDINGS`: binding될 때 심볼 출력
- `DYLD_WEAK_BINDINGS`: binding될 때 weak 심볼만 출력
- `DYLD_PRINT_CODE_SIGNATURES`: code signature 등록 작업 출력
- `DYLD_PRINT_DOFS`: 로드된 D-Trace object format 섹션 출력
- `DYLD_PRINT_ENV`: dyld가 확인한 환경 변수 출력
- `DYLD_PRINT_INTERPOSTING`: interposting 작업 출력
- `DYLD_PRINT_LIBRARIES`: 로드된 library 출력
- `DYLD_PRINT_OPTS`: 로드 옵션 출력
- `DYLD_REBASING`: 심볼 rebasing 작업 출력
- `DYLD_RPATHS`: @rpath 확장 출력
- `DYLD_PRINT_SEGMENTS`: Mach-O 세그먼트 매핑 출력
- `DYLD_PRINT_STATISTICS`: 타이밍 통계 출력
- `DYLD_PRINT_STATISTICS_DETAILS`: 자세한 타이밍 통계 출력
- `DYLD_PRINT_WARNINGS`: 경고 메시지 출력
- `DYLD_SHARED_CACHE_DIR`: shared library cache에 사용할 경로
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: closures 활성화

다음과 같은 방법으로 더 많이 찾을 수 있습니다.

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

또는 [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)에서 dyld 프로젝트를 다운로드한 뒤 폴더 내에서 실행:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```

## References

- [1] [dyld — `dyld/dyldMain.cpp` (프로세스 시작 경로)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (프로세스/보안 구성)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (`execve`의 커널 측 처리 및 dyld 로드)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (`dyld_all_image_infos` 구조체)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
