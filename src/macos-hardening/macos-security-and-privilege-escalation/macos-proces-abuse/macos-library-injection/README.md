# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld의 코드**는 오픈 소스이며 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)에서 찾을 수 있으며 **URL을 사용하여** tar로 다운로드할 수 있습니다: [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld 프로세스**

Dyld가 바이너리 내에서 라이브러리를 로드하는 방법을 살펴보세요:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

이것은 [**Linux의 LD_PRELOAD**](../../../../linux-hardening/privilege-escalation/#ld_preload)와 유사합니다. 실행될 프로세스가 특정 경로에서 라이브러리를 로드하도록 지시할 수 있습니다(환경 변수가 활성화된 경우).

이 기술은 모든 설치된 애플리케이션이 "Info.plist"라는 plist를 가지고 있어 **환경 변수를 할당할 수 있도록 하는** 키 `LSEnvironmental`을 사용하기 때문에 **ASEP 기술로도 사용될 수 있습니다**.

> [!NOTE]
> 2012년 이후 **Apple은 `DYLD_INSERT_LIBRARIES`의 권한을 대폭 축소했습니다.**
>
> 코드를 확인하고 **`src/dyld.cpp`**를 확인하세요. 함수 **`pruneEnvironmentVariables`**에서 **`DYLD_*`** 변수가 제거되는 것을 볼 수 있습니다.
>
> 함수 **`processRestricted`**에서 제한의 이유가 설정됩니다. 해당 코드를 확인하면 이유는 다음과 같습니다:
>
> - 바이너리가 `setuid/setgid`입니다.
> - macho 바이너리에 `__RESTRICT/__restrict` 섹션이 존재합니다.
> - 소프트웨어에 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) 권한이 없는 권한(강화된 런타임)이 있습니다.
>   - 바이너리의 **권한**을 확인하려면: `codesign -dv --entitlements :- </path/to/bin>`
>
> 더 최신 버전에서는 이 논리를 함수 **`configureProcessRestrictions`**의 두 번째 부분에서 찾을 수 있습니다. 그러나 최신 버전에서 실행되는 것은 함수의 **시작 검사**입니다(이것은 macOS에서 사용되지 않을 iOS 또는 시뮬레이션과 관련된 if를 제거할 수 있습니다).

### 라이브러리 검증

바이너리가 **`DYLD_INSERT_LIBRARIES`** 환경 변수를 사용하도록 허용하더라도, 바이너리가 로드할 라이브러리의 서명을 확인하면 사용자 정의 라이브러리를 로드하지 않습니다.

사용자 정의 라이브러리를 로드하려면 바이너리가 **다음 권한 중 하나를 가져야 합니다**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

또는 바이너리가 **강화된 런타임 플래그** 또는 **라이브러리 검증 플래그**를 **가지지 않아야** 합니다.

바이너리에 **강화된 런타임**이 있는지 확인하려면 `codesign --display --verbose <bin>`을 사용하여 **`CodeDirectory`**에서 플래그 런타임을 확인하세요: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

바이너리와 동일한 인증서로 서명된 라이브러리를 로드할 수도 있습니다.

이것을 (악용)하는 방법과 제한 사항을 확인하려면:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib 하이재킹

> [!CAUTION]
> **이전 라이브러리 검증 제한 사항도 Dylib 하이재킹 공격을 수행하는 데 적용됩니다.**

Windows와 마찬가지로 MacOS에서도 **dylibs를 하이재킹**하여 **애플리케이션이 임의의 코드를 실행**하도록 만들 수 있습니다(실제로 일반 사용자에게는 TCC 권한이 필요할 수 있으므로 `.app` 번들 내에서 쓰기 위해 라이브러리를 하이재킹하는 것은 불가능할 수 있습니다).\
그러나 **MacOS** 애플리케이션이 **라이브러리**를 **로드하는 방식은 Windows보다 더 제한적입니다.** 이는 **악성 소프트웨어** 개발자가 여전히 이 기술을 **은폐**를 위해 사용할 수 있지만, **권한 상승을 악용할 가능성은 훨씬 낮습니다.**

우선, **MacOS 바이너리가 로드할 라이브러리의 전체 경로를 지정하는 것이 더 일반적입니다.** 둘째, **MacOS는 라이브러리를 위해 **$PATH**의 폴더를 검색하지 않습니다.**

이 기능과 관련된 **주요** 코드는 **`ImageLoader::recursiveLoadLibraries`**에 있습니다 `ImageLoader.cpp`.

macho 바이너리가 라이브러리를 로드하는 데 사용할 수 있는 **4가지 다른 헤더 명령**이 있습니다:

- **`LC_LOAD_DYLIB`** 명령은 dylib를 로드하는 일반적인 명령입니다.
- **`LC_LOAD_WEAK_DYLIB`** 명령은 이전 명령과 유사하지만, dylib가 발견되지 않으면 오류 없이 실행이 계속됩니다.
- **`LC_REEXPORT_DYLIB`** 명령은 다른 라이브러리의 기호를 프록시(또는 재수출)합니다.
- **`LC_LOAD_UPWARD_DYLIB`** 명령은 두 라이브러리가 서로 의존할 때 사용됩니다(이를 _상향 의존성_이라고 합니다).

그러나 **dylib 하이재킹**에는 **2가지 유형**이 있습니다:

- **누락된 약한 연결 라이브러리**: 이는 애플리케이션이 **LC_LOAD_WEAK_DYLIB**로 구성된 존재하지 않는 라이브러리를 로드하려고 시도함을 의미합니다. 그런 다음 **공격자가 예상되는 위치에 dylib를 배치하면 로드됩니다**.
- 링크가 "약한"이라는 것은 라이브러리가 발견되지 않더라도 애플리케이션이 계속 실행된다는 것을 의미합니다.
- 이와 관련된 **코드는** `ImageLoaderMachO::doGetDependentLibraries` 함수에 있으며, 여기서 `lib->required`는 **`LC_LOAD_WEAK_DYLIB`**가 true일 때만 `false`입니다.
- **바이너리에서 약한 연결 라이브러리 찾기** (하이재킹 라이브러리를 만드는 방법에 대한 예가 나중에 있습니다):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath로 구성됨**: Mach-O 바이너리는 **`LC_RPATH`** 및 **`LC_LOAD_DYLIB`** 명령을 가질 수 있습니다. 이러한 명령의 **값**에 따라 **라이브러리**는 **다른 디렉토리**에서 **로드**됩니다.
- **`LC_RPATH`**는 바이너리가 라이브러리를 로드하는 데 사용하는 일부 폴더의 경로를 포함합니다.
- **`LC_LOAD_DYLIB`**는 로드할 특정 라이브러리의 경로를 포함합니다. 이러한 경로는 **`@rpath`**를 포함할 수 있으며, 이는 **`LC_RPATH`**의 값으로 **대체됩니다**. **`LC_RPATH`**에 여러 경로가 있는 경우 모든 경로가 라이브러리를 로드하는 데 사용됩니다. 예:
- **`LC_LOAD_DYLIB`**에 `@rpath/library.dylib`가 포함되고 **`LC_RPATH`**에 `/application/app.app/Contents/Framework/v1/` 및 `/application/app.app/Contents/Framework/v2/`가 포함된 경우, 두 폴더가 `library.dylib`를 로드하는 데 사용됩니다. **`[...] /v1/`에 라이브러리가 존재하지 않으면 공격자가 그곳에 배치하여 `[...]/v2/`에서 라이브러리 로드를 하이재킹할 수 있습니다.** **`LC_LOAD_DYLIB`**의 경로 순서가 따릅니다.
- **바이너리에서 rpath 경로 및 라이브러리 찾기**: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **주 실행 파일**이 포함된 디렉토리의 **경로**입니다.
>
> **`@loader_path`**: **로드 명령**이 포함된 **Mach-O 바이너리**가 있는 **디렉토리**의 **경로**입니다.
>
> - 실행 파일에서 사용될 때, **`@loader_path`**는 사실상 **`@executable_path`**와 동일합니다.
> - **dylib**에서 사용될 때, **`@loader_path`**는 **dylib**의 **경로**를 제공합니다.

이 기능을 악용하여 **권한을 상승시키는 방법**은 **루트**에 의해 실행되는 **애플리케이션**이 **공격자가 쓰기 권한이 있는 폴더에서 라이브러리를 찾는 경우**에 해당합니다.

> [!TIP]
> 애플리케이션에서 **누락된 라이브러리**를 찾기 위한 좋은 **스캐너**는 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 또는 [**CLI 버전**](https://github.com/pandazheng/DylibHijack)입니다.\
> 이 기술에 대한 **기술 세부정보가 포함된 좋은 보고서**는 [**여기**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)에서 찾을 수 있습니다.

**예시**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen 하이재킹

> [!CAUTION]
> **이전 라이브러리 검증 제한 사항도 Dlopen 하이재킹 공격을 수행하는 데 적용됩니다.**

**`man dlopen`**에서:

- 경로에 **슬래시 문자가 포함되지 않으면**(즉, 단순한 리프 이름인 경우) **dlopen()이 검색을 수행합니다**. **`$DYLD_LIBRARY_PATH`**가 시작 시 설정된 경우, dyld는 먼저 **해당 디렉토리**를 **확인합니다**. 다음으로, 호출된 macho 파일이나 주 실행 파일이 **`LC_RPATH`**를 지정하면 dyld는 **해당 디렉토리**를 **확인합니다**. 다음으로, 프로세스가 **제한되지 않은 경우**, dyld는 **현재 작업 디렉토리**를 검색합니다. 마지막으로, 오래된 바이너리의 경우, dyld는 몇 가지 대체 경로를 시도합니다. **`$DYLD_FALLBACK_LIBRARY_PATH`**가 시작 시 설정된 경우, dyld는 **해당 디렉토리**를 검색합니다. 그렇지 않으면 dyld는 **`/usr/local/lib/`**(프로세스가 제한되지 않은 경우)에서 검색한 다음 **`/usr/lib/`**에서 검색합니다(이 정보는 **`man dlopen`**에서 가져온 것입니다).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(제한되지 않은 경우)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (제한되지 않은 경우)
6. `/usr/lib/`

> [!CAUTION]
> 이름에 슬래시가 없으면 하이재킹을 수행할 수 있는 2가지 방법이 있습니다:
>
> - **`LC_RPATH`**가 **쓰기 가능**한 경우(하지만 서명이 확인되므로 이를 위해서는 바이너리가 제한되지 않아야 함)
> - 바이너리가 **제한되지 않은 경우** CWD에서 무언가를 로드하거나 언급된 환경 변수를 악용할 수 있습니다.

- 경로가 **프레임워크** 경로처럼 보이는 경우(예: `/stuff/foo.framework/foo`), **`$DYLD_FRAMEWORK_PATH`**가 시작 시 설정된 경우, dyld는 먼저 **프레임워크 부분 경로**(예: `foo.framework/foo`)를 찾기 위해 해당 디렉토리를 확인합니다. 다음으로, dyld는 **제공된 경로를 있는 그대로** 시도합니다(상대 경로의 경우 현재 작업 디렉토리를 사용). 마지막으로, 오래된 바이너리의 경우, dyld는 몇 가지 대체 경로를 시도합니다. **`$DYLD_FALLBACK_FRAMEWORK_PATH`**가 시작 시 설정된 경우, dyld는 해당 디렉토리를 검색합니다. 그렇지 않으면 **`/Library/Frameworks`**(macOS에서 프로세스가 제한되지 않은 경우)에서 검색한 다음 **`/System/Library/Frameworks`**에서 검색합니다.
1. `$DYLD_FRAMEWORK_PATH`
2. 제공된 경로(제한되지 않은 경우 상대 경로에 대해 현재 작업 디렉토리 사용)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (제한되지 않은 경우)
5. `/System/Library/Frameworks`

> [!CAUTION]
> 프레임워크 경로인 경우, 하이재킹하는 방법은:
>
> - 프로세스가 **제한되지 않은 경우**, CWD의 상대 경로를 악용하여 언급된 환경 변수를 사용합니다(문서에 명시되어 있지 않더라도 프로세스가 제한된 경우 DYLD\_\* 환경 변수가 제거됩니다).

- 경로에 **슬래시가 포함되어 있지만 프레임워크 경로가 아닌 경우**(즉, dylib에 대한 전체 경로 또는 부분 경로), dlopen()은 먼저 **`$DYLD_LIBRARY_PATH`**(경로의 리프 부분 포함)에서 확인합니다. 다음으로, dyld는 **제공된 경로**를 시도합니다(제한되지 않은 프로세스의 경우 상대 경로에 대해 현재 작업 디렉토리를 사용). 마지막으로, 오래된 바이너리의 경우, dyld는 대체 경로를 시도합니다. **`$DYLD_FALLBACK_LIBRARY_PATH`**가 시작 시 설정된 경우, dyld는 해당 디렉토리에서 검색합니다. 그렇지 않으면 dyld는 **`/usr/local/lib/`**(프로세스가 제한되지 않은 경우)에서 검색한 다음 **`/usr/lib/`**에서 검색합니다.
1. `$DYLD_LIBRARY_PATH`
2. 제공된 경로(제한되지 않은 경우 상대 경로에 대해 현재 작업 디렉토리 사용)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (제한되지 않은 경우)
5. `/usr/lib/`

> [!CAUTION]
> 이름에 슬래시가 포함되고 프레임워크가 아닌 경우, 하이재킹하는 방법은:
>
> - 바이너리가 **제한되지 않은 경우** CWD 또는 `/usr/local/lib`에서 무언가를 로드하거나 언급된 환경 변수를 악용할 수 있습니다.

> [!NOTE]
> 참고: **dlopen 검색을 제어하는** 구성 파일이 **없습니다**.
>
> 참고: 주 실행 파일이 **set\[ug]id 바이너리이거나 권한으로 서명된 경우**, **모든 환경 변수는 무시되며**, 전체 경로만 사용할 수 있습니다([DYLD_INSERT_LIBRARIES 제한 사항 확인](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)에서 더 자세한 정보 확인).
>
> 참고: Apple 플랫폼은 32비트 및 64비트 라이브러리를 결합하기 위해 "유니버설" 파일을 사용합니다. 이는 **별도의 32비트 및 64비트 검색 경로가 없음을 의미합니다.**
>
> 참고: Apple 플랫폼에서 대부분의 OS dylibs는 **dyld 캐시에 결합되어** 있으며 디스크에 존재하지 않습니다. 따라서 OS dylib가 존재하는지 사전 확인하기 위해 **`stat()`**를 호출하는 것은 **작동하지 않습니다**. 그러나 **`dlopen_preflight()`**는 **`dlopen()`**과 동일한 단계를 사용하여 호환 가능한 mach-o 파일을 찾습니다.

**경로 확인**

다음 코드를 사용하여 모든 옵션을 확인해 보겠습니다:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
컴파일하고 실행하면 **각 라이브러리가 어디에서 성공적으로 검색되지 않았는지** 볼 수 있습니다. 또한 **FS 로그를 필터링할 수 있습니다**:
```bash
sudo fs_usage | grep "dlopentest"
```
## 상대 경로 하이재킹

**특권 이진 파일/앱**(예: SUID 또는 강력한 권한이 있는 이진 파일)이 **상대 경로** 라이브러리(예: `@executable_path` 또는 `@loader_path` 사용)를 **로드**하고 **라이브러리 검증이 비활성화**된 경우, 공격자가 **상대 경로로 로드된 라이브러리**를 **수정**할 수 있는 위치로 이진 파일을 이동시켜 프로세스에 코드를 주입할 수 있습니다.

## `DYLD_*` 및 `LD_LIBRARY_PATH` 환경 변수 정리

파일 `dyld-dyld-832.7.1/src/dyld2.cpp`에서 **`pruneEnvironmentVariables`** 함수가 있으며, 이 함수는 **`DYLD_`**로 시작하는 모든 환경 변수와 **`LD_LIBRARY_PATH=`**를 제거합니다.

또한 **suid** 및 **sgid** 이진 파일에 대해 **`DYLD_FALLBACK_FRAMEWORK_PATH`** 및 **`DYLD_FALLBACK_LIBRARY_PATH`** 환경 변수를 **null**로 설정합니다.

이 함수는 OSX를 대상으로 할 때 같은 파일의 **`_main`** 함수에서 호출됩니다:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
그리고 이러한 불리언 플래그는 코드의 동일한 파일에 설정됩니다:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
이것은 기본적으로 바이너리가 **suid** 또는 **sgid**이거나 헤더에 **RESTRICT** 세그먼트가 있거나 **CS_RESTRICT** 플래그로 서명된 경우, **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`**가 참이 되고 환경 변수가 제거된다는 것을 의미합니다.

CS_REQUIRE_LV가 참이면 변수가 제거되지 않지만 라이브러리 검증은 원래 바이너리와 동일한 인증서를 사용하고 있는지 확인합니다.

## 제한 사항 확인

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### 섹션 `__RESTRICT`와 세그먼트 `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### 강화된 런타임

Keychain에서 새 인증서를 생성하고 이를 사용하여 바이너리에 서명합니다:
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
> [!CAUTION]
> **`0x0(none)`** 플래그로 서명된 바이너리가 있더라도, 실행 시 동적으로 **`CS_RESTRICT`** 플래그를 가질 수 있으므로 이 기술은 그들에 대해 작동하지 않습니다.
>
> 프로세스에 이 플래그가 있는지 확인하려면 (get [**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> 그런 다음 플래그 0x800이 활성화되어 있는지 확인하십시오.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
