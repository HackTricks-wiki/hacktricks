# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Mach-o 바이너리의 실제 **entrypoint**는 `LC_LOAD_DYLINKER`에 정의된 동적 링크로, 일반적으로는 `/usr/lib/dyld`입니다.

이 링크는 모든 실행 가능한 라이브러리를 찾아 메모리에 매핑하고 모든 비게으른 라이브러리를 링크해야 합니다. 이 과정이 끝난 후에야 바이너리의 entry-point가 실행됩니다.

물론, **`dyld`**는 어떤 의존성도 없습니다(시스템 호출과 libSystem 발췌를 사용합니다).

> [!CAUTION]
> 이 링크에 취약점이 있다면, 어떤 바이너리(특히 높은 권한의 것)도 실행되기 전에 실행되기 때문에 **권한 상승**이 가능할 수 있습니다.

### Flow

Dyld는 **`dyldboostrap::start`**에 의해 로드되며, 이 함수는 **스택 카나리**와 같은 것들도 로드합니다. 이는 이 함수가 **`apple`** 인자 벡터에서 이와 다른 **민감한** **값**을 받기 때문입니다.

**`dyls::_main()`**은 dyld의 entry point이며, 첫 번째 작업은 `configureProcessRestrictions()`를 실행하는 것입니다. 이 함수는 일반적으로 **`DYLD_*`** 환경 변수를 제한합니다:

{{#ref}}
./
{{#endref}}

그런 다음, dyld 공유 캐시를 매핑하여 모든 중요한 시스템 라이브러리를 미리 링크하고, 바이너리가 의존하는 라이브러리를 매핑하며, 필요한 모든 라이브러리가 로드될 때까지 재귀적으로 계속합니다. 따라서:

1. `DYLD_INSERT_LIBRARIES`로 삽입된 라이브러리를 로드하기 시작합니다(허용되는 경우)
2. 그런 다음 공유 캐시된 라이브러리
3. 그런 다음 가져온 라이브러리
1. &#x20;그런 다음 라이브러리를 재귀적으로 계속 가져옵니다

모든 라이브러리가 로드되면 이들 라이브러리의 **초기화 함수**가 실행됩니다. 이들은 `LC_ROUTINES[_64]`(현재는 사용 중단됨)에서 정의된 **`__attribute__((constructor))`**를 사용하여 코딩되거나 `S_MOD_INIT_FUNC_POINTERS` 플래그가 설정된 섹션의 포인터로 코딩됩니다(일반적으로: **`__DATA.__MOD_INIT_FUNC`**).

종료자는 **`__attribute__((destructor))`**로 코딩되며, `S_MOD_TERM_FUNC_POINTERS` 플래그가 설정된 섹션에 위치합니다(**`__DATA.__mod_term_func`**).

### Stubs

macOS의 모든 바이너리는 동적으로 링크됩니다. 따라서, 이들은 바이너리가 다양한 머신과 컨텍스트에서 올바른 코드로 점프하는 데 도움이 되는 일부 스텁 섹션을 포함합니다. 바이너리가 실행될 때 dyld는 이러한 주소를 해결해야 하는 두뇌입니다(최소한 비게으른 것들).

바이너리의 일부 스텁 섹션:

- **`__TEXT.__[auth_]stubs`**: `__DATA` 섹션의 포인터
- **`__TEXT.__stub_helper`**: 호출할 함수에 대한 정보와 함께 동적 링크를 호출하는 작은 코드
- **`__DATA.__[auth_]got`**: 전역 오프셋 테이블(해결된 가져온 함수의 주소, 로드 시간에 바인딩됨, `S_NON_LAZY_SYMBOL_POINTERS` 플래그가 설정됨)
- **`__DATA.__nl_symbol_ptr`**: 비게으른 심볼 포인터(로드 시간에 바인딩됨, `S_NON_LAZY_SYMBOL_POINTERS` 플래그가 설정됨)
- **`__DATA.__la_symbol_ptr`**: 게으른 심볼 포인터(첫 번째 접근 시 바인딩됨)

> [!WARNING]
> "auth\_" 접두사가 있는 포인터는 이를 보호하기 위해 프로세스 내 암호화 키를 사용하고 있습니다(PAC). 또한, arm64 명령어 `BLRA[A/B]`를 사용하여 포인터를 따라가기 전에 확인할 수 있습니다. RETA\[A/B]는 RET 주소 대신 사용할 수 있습니다.\
> 실제로 **`__TEXT.__auth_stubs`**의 코드는 요청된 함수를 호출하기 위해 **`braa`**를 사용합니다.
>
> 또한 현재 dyld 버전은 **모든 것을 비게으른** 것으로 로드합니다.

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
흥미로운 분해 부분:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
`printf`를 호출하는 점프가 **`__TEXT.__stubs`**로 가고 있음을 확인할 수 있습니다:
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
당신은 **GOT의 주소로 점프하고** 있음을 알 수 있습니다. 이 경우는 비지연 방식으로 해결되며 printf 함수의 주소를 포함합니다.

다른 상황에서는 GOT에 직접 점프하는 대신 **`__DATA.__la_symbol_ptr`**로 점프할 수 있으며, 이는 로드하려는 함수의 값을 로드한 다음 **`__TEXT.__stub_helper`**로 점프합니다. 이곳은 **`__DATA.__nl_symbol_ptr`**로 점프하며, 여기에는 **`dyld_stub_binder`**의 주소가 포함되어 있습니다. 이 함수는 함수 번호와 주소를 매개변수로 받습니다.\
이 마지막 함수는 검색된 함수의 주소를 찾은 후, 향후 조회를 피하기 위해 **`__TEXT.__stub_helper`**의 해당 위치에 기록합니다.

> [!TIP]
> 그러나 현재 dyld 버전은 모든 것을 비지연 방식으로 로드합니다.

#### Dyld opcodes

마지막으로, **`dyld_stub_binder`**는 지정된 함수를 찾아 적절한 주소에 기록하여 다시 검색하지 않도록 해야 합니다. 이를 위해 dyld 내에서 opcodes(유한 상태 기계)를 사용합니다.

## apple\[] argument vector

macOS에서 main 함수는 실제로 3개 대신 4개의 인수를 받습니다. 네 번째는 apple이라고 하며 각 항목은 `key=value` 형식입니다. 예를 들어:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
죄송하지만, 요청하신 내용을 처리할 수 없습니다.
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
> 이러한 값들이 main 함수에 도달할 때쯤에는 민감한 정보가 이미 제거되었거나 데이터 유출이 발생했을 것입니다.

main에 들어가기 전에 디버깅을 통해 이러한 흥미로운 값을 모두 볼 수 있습니다:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>현재 실행 파일이 '/tmp/a' (arm64)로 설정되었습니다.
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

이것은 dyld가 내보내는 구조체로, dyld 상태에 대한 정보가 포함되어 있으며, [**소스 코드**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)에서 찾을 수 있습니다. 여기에는 버전, dyld_image_info 배열에 대한 포인터, dyld_image_notifier, 프로세스가 공유 캐시에서 분리되었는지 여부, libSystem 초기화가 호출되었는지 여부, dyls의 자체 Mach 헤더에 대한 포인터, dyld 버전 문자열에 대한 포인터 등이 포함됩니다.

## dyld env variables

### debug dyld

dyld가 무엇을 하고 있는지 이해하는 데 도움이 되는 흥미로운 환경 변수:

- **DYLD_PRINT_LIBRARIES**

로드된 각 라이브러리를 확인합니다:
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

각 라이브러리가 어떻게 로드되는지 확인하세요:
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

각 라이브러리 초기화 프로그램이 실행될 때 출력합니다:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### 기타

- `DYLD_BIND_AT_LAUNCH`: 지연 바인딩이 비지연 바인딩과 함께 해결됨
- `DYLD_DISABLE_PREFETCH`: \_\_DATA 및 \_\_LINKEDIT 콘텐츠의 사전 가져오기 비활성화
- `DYLD_FORCE_FLAT_NAMESPACE`: 단일 수준 바인딩
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: 해상도 경로
- `DYLD_INSERT_LIBRARIES`: 특정 라이브러리 로드
- `DYLD_PRINT_TO_FILE`: dyld 디버그를 파일에 기록
- `DYLD_PRINT_APIS`: libdyld API 호출 인쇄
- `DYLD_PRINT_APIS_APP`: main에 의해 이루어진 libdyld API 호출 인쇄
- `DYLD_PRINT_BINDINGS`: 바인딩될 때 기호 인쇄
- `DYLD_WEAK_BINDINGS`: 바인딩될 때 약한 기호만 인쇄
- `DYLD_PRINT_CODE_SIGNATURES`: 코드 서명 등록 작업 인쇄
- `DYLD_PRINT_DOFS`: 로드된 D-Trace 객체 형식 섹션 인쇄
- `DYLD_PRINT_ENV`: dyld가 보는 환경 인쇄
- `DYLD_PRINT_INTERPOSTING`: 인터포스팅 작업 인쇄
- `DYLD_PRINT_LIBRARIES`: 로드된 라이브러리 인쇄
- `DYLD_PRINT_OPTS`: 로드 옵션 인쇄
- `DYLD_REBASING`: 기호 재배치 작업 인쇄
- `DYLD_RPATHS`: @rpath의 확장 인쇄
- `DYLD_PRINT_SEGMENTS`: Mach-O 세그먼트의 매핑 인쇄
- `DYLD_PRINT_STATISTICS`: 타이밍 통계 인쇄
- `DYLD_PRINT_STATISTICS_DETAILS`: 상세 타이밍 통계 인쇄
- `DYLD_PRINT_WARNINGS`: 경고 메시지 인쇄
- `DYLD_SHARED_CACHE_DIR`: 공유 라이브러리 캐시를 위한 경로
- `DYLD_SHARED_REGION`: "사용", "개인", "회피"
- `DYLD_USE_CLOSURES`: 클로저 활성화

더 많은 정보를 찾으려면 다음과 같은 방법을 사용할 수 있습니다:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
dyld 프로젝트를 [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)에서 다운로드하거나 폴더 내에서 실행합니다:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
