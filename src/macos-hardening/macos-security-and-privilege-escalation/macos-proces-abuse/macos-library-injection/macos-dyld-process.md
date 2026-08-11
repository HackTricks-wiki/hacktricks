# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Mach-o binary의 실제 **entrypoint**는 `LC_LOAD_DYLINKER`에 정의된 dynamic linker이며, 일반적으로 `/usr/lib/dyld`입니다.<sup>[[3]](#references)</sup>

이 linker는 모든 executable libraries를 찾고, 메모리에 매핑하며, 모든 non-lazy libraries를 link해야 합니다. 이 과정이 끝난 후에야 binary의 entry-point가 실행됩니다.

물론 **`dyld`**에는 어떠한 dependencies도 없습니다(syscalls와 libSystem excerpts를 사용합니다).

> [!CAUTION]
> 이 linker에는 모든 binary(높은 privilege를 가진 binary 포함)가 실행되기 전에 실행되는 취약점이 존재하므로, **escalate privileges**가 가능할 수 있습니다.

### Flow

Dyld는 **`dyldboostrap::start`**에 의해 로드되며, 이 함수는 **stack canary**와 같은 항목도 로드합니다. 이는 이 함수가 **`apple`** argument vector에서 이 값과 기타 **sensitive** **values**를 전달받기 때문입니다.<sup>[[1]](#references)</sup>

**`dyls::_main()`**은 dyld의 entry point이며, 첫 번째 작업은 일반적으로 **`DYLD_*`** environment variables를 제한하는 `configureProcessRestrictions()`를 실행하는 것입니다. 자세한 내용은 다음에 설명되어 있습니다:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

그런 다음 모든 중요한 system libraries를 prelink하는 dyld shared cache를 매핑하고, binary가 의존하는 libraries를 매핑한 뒤 필요한 모든 libraries가 로드될 때까지 재귀적으로 계속합니다. 따라서:

1. `DYLD_INSERT_LIBRARIES`를 사용하여 inserted libraries를 로드하기 시작합니다(허용되는 경우).
2. 그런 다음 shared cached ones를 로드합니다.
3. 그런 다음 imported ones를 로드합니다.
1. 그런 다음 libraries를 재귀적으로 계속 import합니다.

모두 로드되면 이 libraries의 **initialisers**가 실행됩니다. 이는 `LC_ROUTINES[_64]`(현재 deprecated)에 정의된 **`__attribute__((constructor))`**를 사용하거나, `S_MOD_INIT_FUNC_POINTERS`가 지정된 section(일반적으로 **`__DATA.__MOD_INIT_FUNC`**)의 pointer로 작성됩니다.

Terminators는 **`__attribute__((destructor))`**를 사용하여 작성되며, `S_MOD_TERM_FUNC_POINTERS`가 지정된 section(**`__DATA.__mod_term_func`**)에 있습니다.

### Stubs

macOS의 모든 binaries는 dynamically linked됩니다. 따라서 binary가 서로 다른 machines와 contexts에서 올바른 code로 jump할 수 있도록 돕는 일부 stubs sections를 포함합니다. binary가 실행될 때 이러한 addresses(적어도 non-lazy ones)를 resolve해야 하는 주체는 바로 dyld입니다.

binary의 일부 stub sections:

- **`__TEXT.__[auth_]stubs`**: `__DATA` sections의 Pointers
- **`__TEXT.__stub_helper`**: 호출할 function에 대한 정보와 함께 dynamic linking을 호출하는 작은 code
- **`__DATA.__[auth_]got`**: Global Offset Table(Imported functions에 대한 addresses이며, `S_NON_LAZY_SYMBOL_POINTERS` flag가 지정되어 있으므로 resolve될 때 load time에 bound됨)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointers(`S_NON_LAZY_SYMBOL_POINTERS` flag가 지정되어 있으므로 load time에 bound됨)
- **`__DATA.__la_symbol_ptr`**: Lazy symbols pointers(첫 번째 access 시 bound됨)

> [!WARNING]
> "auth_" prefix가 붙은 pointers는 이를 보호하기 위해 하나의 in-process encryption key(PAC)를 사용합니다. 또한 arm64 instruction `BLRA[A/B]`를 사용하여 pointer를 따라가기 전에 이를 verify할 수 있습니다. 그리고 RETA\[A/B]는 RET address 대신 사용할 수 있습니다.\
> 실제로 **`__TEXT.__auth_stubs`**의 code는 요청된 function을 호출하고 pointer를 authenticate하기 위해 **`bl`** 대신 **`braa`**를 사용합니다.
>
> 또한 현재 dyld versions는 모든 항목을 non-lazy로 로드한다는 점에 유의해야 합니다.

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
흥미로운 disassembly 부분:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
printf로 jump하는 것이 **`__TEXT.__stubs`**로 향하는 것을 확인할 수 있습니다:
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
**`__stubs`** 섹션을 disassemble한 결과:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
GOT의 주소로 **jumping하고 있음**을 확인할 수 있습니다. 이 경우 해당 주소는 non-lazy로 resolve되며, `printf` function의 주소를 포함합니다.

다른 상황에서는 GOT로 직접 jump하는 대신 **`__DATA.__la_symbol_ptr`**로 jump할 수 있습니다. 이 영역은 load하려는 function을 나타내는 값을 load한 다음, **`__TEXT.__stub_helper`**로 jump합니다. 이후 **`__DATA.__nl_symbol_ptr`**로 jump하며, 이 영역에는 **`dyld_stub_binder`**의 주소가 포함되어 있습니다. `dyld_stub_binder`는 function 번호와 address를 parameters로 받습니다.\
이 마지막 function은 검색된 function의 address를 찾은 후, 나중에 다시 lookup하지 않도록 이를 **`__TEXT.__stub_helper`**의 해당 위치에 기록합니다.

> [!TIP]
> 그러나 최신 dyld versions에서는 모든 항목을 non-lazy로 load한다는 점에 유의하세요.

#### Dyld opcodes

마지막으로 **`dyld_stub_binder`**는 지정된 function을 찾아 다시 검색하지 않도록 올바른 address에 기록해야 합니다. 이를 위해 dyld 내부의 opcodes(유한 상태 머신)를 사용합니다.

## apple\[] argument vector

macOS에서 main function은 실제로 3개가 아닌 4개의 arguments를 받습니다. 네 번째 argument는 apple이라고 하며, 각 entry는 `key=value` 형식입니다. 예:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
번역할 영어 원문이 제공되지 않았습니다.%timeout
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
> 이 값들이 main function에 도달할 때쯤이면 민감한 정보가 이미 값에서 제거되었거나, 그렇지 않다면 data leak이 발생했을 것입니다.

다음과 같이 main에 진입하기 전에 debugging을 수행하면 이 흥미로운 값들을 모두 확인할 수 있습니다:

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

이는 dyld가 export하는 structure로, dyld state에 대한 정보를 담고 있습니다. [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)에서 확인할 수 있으며, version, dyld_image_info array에 대한 pointer, dyld_image_notifier에 대한 pointer, proc가 shared cache에서 분리되었는지 여부, libSystem initializer가 호출되었는지 여부, dyld 자체 Mach header에 대한 pointer, dyld version string 등의 정보를 포함합니다.<sup>[[4]](#references)</sup>

## dyld 환경 변수

### debug dyld

dyld가 무엇을 수행하는지 이해하는 데 도움이 되는 흥미로운 env variables:

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

각 library가 어떻게 로드되는지 확인:
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

각 library initializer가 실행될 때 출력합니다:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### 기타

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings를 non lazy bindings와 함께 resolve
- `DYLD_DISABLE_PREFETCH`: \_\_DATA 및 \_\_LINKEDIT 콘텐츠의 pre-fetching 비활성화
- `DYLD_FORCE_FLAT_NAMESPACE`: Single-level bindings
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Resolution paths
- `DYLD_INSERT_LIBRARIES`: 특정 library 로드
- `DYLD_PRINT_TO_FILE`: dyld debug 정보를 파일에 기록
- `DYLD_PRINT_APIS`: libdyld API calls 출력
- `DYLD_PRINT_APIS_APP`: main이 수행한 libdyld API calls 출력
- `DYLD_PRINT_BINDINGS`: binding 시 symbols 출력
- `DYLD_WEAK_BINDINGS`: binding 시 weak symbols만 출력
- `DYLD_PRINT_CODE_SIGNATURES`: code signature registration operations 출력
- `DYLD_PRINT_DOFS`: 로드된 D-Trace object format sections 출력
- `DYLD_PRINT_ENV`: dyld가 확인한 env 출력
- `DYLD_PRINT_INTERPOSTING`: interposting operations 출력
- `DYLD_PRINT_LIBRARIES`: 로드된 libraries 출력
- `DYLD_PRINT_OPTS`: load options 출력
- `DYLD_REBASING`: symbol rebasing operations 출력
- `DYLD_RPATHS`: @rpath의 expansions 출력
- `DYLD_PRINT_SEGMENTS`: Mach-O segments의 mappings 출력
- `DYLD_PRINT_STATISTICS`: timing statistics 출력
- `DYLD_PRINT_STATISTICS_DETAILS`: 상세 timing statistics 출력
- `DYLD_PRINT_WARNINGS`: warning messages 출력
- `DYLD_SHARED_CACHE_DIR`: shared library cache에 사용할 path
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: closures 활성화

다음과 같은 방법으로 더 많은 항목을 확인할 수 있습니다:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
또는 [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)에서 dyld project를 다운로드한 후 해당 폴더에서 실행합니다:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (프로세스 시작 경로)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (프로세스/보안 구성)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (커널 측 `execve`, dyld 로딩)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (`dyld_all_image_infos` 구조체)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
