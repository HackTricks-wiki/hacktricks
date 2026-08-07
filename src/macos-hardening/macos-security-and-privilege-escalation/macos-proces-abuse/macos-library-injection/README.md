# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld의 코드는 오픈 소스**이며 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)에서 확인할 수 있고, **다음과 같은 URL**을 사용해 tar로 다운로드할 수 있습니다: [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Dyld가 바이너리 내부에서 라이브러리를 로드하는 방식은 다음을 참조하세요:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

이는 [**Linux의 LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload)와 같습니다. 실행될 프로세스가 특정 경로의 특정 라이브러리를 로드하도록 지정할 수 있습니다(환경 변수가 활성화된 경우)<sup>[[4]](#references)</sup>

이 기법은 **ASEP 기법으로도 사용**할 수 있습니다. 설치된 모든 애플리케이션에는 "Info.plist"라는 plist가 있으며, `LSEnvironmental`이라는 키를 사용해 **환경 변수를 할당**할 수 있습니다.

> [!TIP]
> 2012년 이후 **Apple은 `DYLD_INSERT_LIBRARIES`의 권한을 크게 축소**했습니다. 다음 조건 중 하나라도 충족되면 프로세스는 **restricted**로 간주되며, `dyld`는 해당 프로세스의 환경에서 모든 `DYLD_*` 변수를 삭제합니다.
>
> - 바이너리가 `setuid/setgid`임
> - Mach-O에 **`__RESTRICT/__restrict`** 섹션이 있음
> - 바이너리가 hardened runtime으로 서명되었고 AMFI가 "path/print variables" 권한을 부여하지 않음. 즉, [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)가 없음<sup>[[3]](#references)</sup>
>   - 다음 명령으로 바이너리의 **entitlements**를 확인할 수 있습니다: `codesign -dv --entitlements :- </path/to/bin>`
>
> 현재 `dyld`에서는 더 이상 `dyld`만으로 결정되지 않습니다. `ProcessConfig::Security::Security()`가 `amfi_check_dyld_policy_self()`를 통해 **AMFI**에 요청한 후 `pruneEnvVars()`를 호출합니다. 정확한 코드는 아래의 [Prune `DYLD_*` env variables](#prune-dyld_-env-variables)에서 설명합니다.

### Library Validation

바이너리가 **`DYLD_INSERT_LIBRARIES`** 환경 변수 사용을 허용하더라도, 로드할 라이브러리의 서명을 확인한다면 custom 라이브러리를 로드하지 않습니다.

custom 라이브러리를 로드하려면 바이너리에 다음 **entitlements 중 하나**가 있어야 합니다.

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

또는 바이너리에 **hardened runtime flag**나 **library validation flag**가 없어야 합니다.

`codesign --display --verbose <bin>`을 사용해 **hardened runtime** 여부를 확인할 수 있습니다. **`CodeDirectory`**의 runtime flag를 다음과 같이 확인하면 됩니다: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

라이브러리가 바이너리와 동일한 certificate로 서명되어 있어도 로드할 수 있습니다.

이를 (악용하여) 사용하는 방법과 제한 사항을 확인하려면 다음을 참조하세요:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> 이전의 **Library Validation 제한 사항도 Dylib hijacking 공격에 적용**된다는 점을 기억하세요.

Windows와 마찬가지로 MacOS에서도 **dylib를 hijack**하여 **애플리케이션이 임의의** **코드를 실행**하도록 만들 수 있습니다(단, 일반 사용자에게는 `.app` bundle 내부에 쓰고 라이브러리를 hijack하기 위해 TCC 권한이 필요할 수 있으므로 실제로는 불가능할 수 있습니다).\
그러나 **MacOS** 애플리케이션이 라이브러리를 **로드**하는 방식은 Windows보다 **더 제한적**입니다. 따라서 **malware** 개발자는 여전히 이 기법을 **stealth** 목적으로 사용할 수 있지만, 이를 악용해 권한을 상승시킬 가능성은 훨씬 **낮습니다**.

첫째, **MacOS 바이너리**는 로드할 라이브러리의 전체 경로를 지정하는 경우가 **더 일반적**입니다. 둘째, **MacOS는 라이브러리를 찾기 위해** **$PATH**의 폴더를 **검색하지 않습니다**.

이 기능과 관련된 **코드**의 **주요** 부분은 `ImageLoader.cpp`의 **`ImageLoader::recursiveLoadLibraries`**에 있습니다.

macho 바이너리가 라이브러리를 로드하는 데 사용할 수 있는 header Command는 **4가지**입니다.

- **`LC_LOAD_DYLIB`** command는 dylib를 로드하는 일반적인 command입니다.
- **`LC_LOAD_WEAK_DYLIB`** command는 이전 command와 유사하지만, dylib를 찾지 못해도 오류 없이 실행이 계속됩니다.
- **`LC_REEXPORT_DYLIB`** command는 다른 라이브러리의 symbol을 proxy하거나 re-export합니다.
- **`LC_LOAD_UPWARD_DYLIB`** command는 두 라이브러리가 서로 의존할 때 사용됩니다(이를 _upward dependency_라고 합니다).

하지만 dylib hijacking에는 **2가지 유형**이 있습니다.

- **Missing weak linked libraries**: 애플리케이션이 **LC_LOAD_WEAK_DYLIB**로 구성된 존재하지 않는 라이브러리를 로드하려고 한다는 의미입니다. 그런 다음 **공격자가 예상되는 위치에 dylib를 배치하면 로드됩니다**.
- link가 "weak"하다는 것은 라이브러리를 찾지 못해도 애플리케이션이 계속 실행된다는 의미입니다.
- 이와 관련된 **코드**는 `ImageLoader.cpp`의 `ImageLoaderMachO::doGetDependentLibraries` 함수에 있으며, `LC_LOAD_WEAK_DYLIB`가 true인 경우에만 `lib->required`가 `false`가 됩니다.
- 바이너리에서 **weak linked libraries**를 찾으려면 다음을 사용합니다(hijacking libraries를 만드는 방법은 뒤에 예제가 있습니다).
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O 바이너리에는 **`LC_RPATH`** 및 **`LC_LOAD_DYLIB`** command가 있을 수 있습니다. 이러한 command의 **값**을 기반으로 **서로 다른 디렉터리**에서 **라이브러리**가 **로드**됩니다.
- **`LC_RPATH`**에는 바이너리가 라이브러리를 로드하는 데 사용하는 일부 폴더의 경로가 포함됩니다.
- **`LC_LOAD_DYLIB`**에는 로드할 특정 라이브러리의 경로가 포함됩니다. 이러한 경로에는 **`@rpath`**가 포함될 수 있으며, 이는 **`LC_RPATH`**의 값으로 대체됩니다. **`LC_RPATH`**에 여러 경로가 있으면 라이브러리 로드를 위해 모두 검색됩니다. 예:
- **`LC_LOAD_DYLIB`**에 `@rpath/library.dylib`가 포함되고 **`LC_RPATH`**에 `/application/app.app/Contents/Framework/v1/` 및 `/application/app.app/Contents/Framework/v2/`가 포함된 경우, 두 폴더 모두 `library.dylib`를 로드하는 데 사용됩니다**.** `[...]/v1/`에 라이브러리가 존재하지 않고 공격자가 해당 위치에 라이브러리를 배치할 수 있다면, **`LC_LOAD_DYLIB`**의 경로 순서가 우선되므로 `[...]/v2/`의 라이브러리 로드를 hijack할 수 있습니다.
- 바이너리에서 **rpath 경로와 라이브러리**를 찾으려면 다음을 사용합니다: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file**을 포함하는 디렉터리의 **경로**입니다.
>
> **`@loader_path`**: load command를 포함하는 **Mach-O 바이너리**가 있는 **디렉터리**의 **경로**입니다.
>
> - executable에서 사용하면 **`@loader_path`**는 사실상 **`@executable_path`**와 같습니다.
> - dylib에서 사용하면 **`@loader_path`**는 해당 **dylib**의 **경로**를 가리킵니다.

이 기능을 악용해 **권한을 상승**하는 방법은 **root에 의해** 실행되는 **애플리케이션**이 공격자에게 쓰기 권한이 있는 폴더에서 **라이브러리를 찾는** 드문 경우입니다.

> [!TIP]
> 애플리케이션에서 **missing libraries**를 찾는 유용한 **scanner**로는 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 또는 [**CLI version**](https://github.com/pandazheng/DylibHijack)이 있습니다.\
> 이 기법에 대한 기술적 세부 정보가 담긴 유용한 **report**는 [**여기**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)에서 확인할 수 있습니다.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> 이전의 **Library Validation 제한 사항도 Dlopen hijacking 공격에 적용**된다는 점을 기억하세요.

**`man dlopen`**에서:

- path에 slash character가 **포함되지 않는 경우**(즉, leaf name일 뿐인 경우), **dlopen()은 검색을 수행**합니다. 실행 시 **`$DYLD_LIBRARY_PATH`**가 설정되어 있다면 dyld는 먼저 해당 **디렉터리**를 **검색**합니다. 다음으로 호출하는 mach-o 파일 또는 main executable이 **`LC_RPATH`**를 지정했다면 dyld는 해당 디렉터리들을 **검색**합니다. 다음으로 프로세스가 **unrestricted**라면 dyld는 현재 working directory를 검색합니다. 마지막으로 이전 바이너리의 경우 dyld는 일부 fallback을 시도합니다. 실행 시 **`$DYLD_FALLBACK_LIBRARY_PATH`**가 설정되어 있다면 dyld는 **해당 디렉터리들**을 검색하고, 그렇지 않으면 **`/usr/local/lib/`**(프로세스가 unrestricted인 경우), 그 다음 **`/usr/lib/`**를 검색합니다(이 정보는 **`man dlopen`**에서 가져왔습니다).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(unrestricted인 경우)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (unrestricted인 경우)
6. `/usr/lib/`

> [!CAUTION]
> 이름에 slash가 없는 경우 hijacking하는 방법은 다음 2가지입니다.
>
> - **`LC_RPATH`**가 writable인 경우(단, signature가 확인되므로 바이너리도 unrestricted여야 함)
> - 바이너리가 **unrestricted**이므로 CWD에서 무언가를 로드할 수 있는 경우(또는 언급된 환경 변수 중 하나를 악용)

- path가 framework path처럼 보이는 경우(예: `/stuff/foo.framework/foo`), 실행 시 **`$DYLD_FRAMEWORK_PATH`**가 설정되어 있다면 dyld는 먼저 해당 디렉터리에서 **framework partial path**(예: `foo.framework/foo`)를 검색합니다. 다음으로 dyld는 **제공된 path를 있는 그대로** 시도합니다(relative path에는 current working directory 사용). 마지막으로 이전 바이너리의 경우 dyld는 일부 fallback을 시도합니다. 실행 시 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**가 설정되어 있다면 dyld는 해당 디렉터리들을 검색합니다. 그렇지 않으면 **`/Library/Frameworks`**(프로세스가 unrestricted인 macOS의 경우), 그 다음 **`/System/Library/Frameworks`**를 검색합니다.
1. `$DYLD_FRAMEWORK_PATH`
2. 제공된 path (unrestricted인 경우 relative path에 current working directory 사용)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (unrestricted인 경우)
5. `/System/Library/Frameworks`

> [!CAUTION]
> framework path인 경우 hijack하는 방법은 다음과 같습니다.
>
> - 프로세스가 **unrestricted**라면 CWD의 **relative path** 또는 앞서 언급한 환경 변수를 악용합니다(프로세스가 restricted인 경우 DYLD\_\* 환경 변수가 제거된다는 점은 문서에 명시되어 있지 않음)

- path에 slash가 포함되지만 framework path가 아닌 경우(즉, dylib에 대한 전체 path 또는 partial path), dlopen()은 먼저 (설정되어 있다면) **`$DYLD_LIBRARY_PATH`**에서 검색합니다(path의 leaf 부분 사용). 다음으로 dyld는 **제공된 path**를 시도합니다(relative path에는 current working directory를 사용하지만, unrestricted 프로세스에서만 해당). 마지막으로 이전 바이너리의 경우 dyld는 fallback을 시도합니다. 실행 시 **`$DYLD_FALLBACK_LIBRARY_PATH`**가 설정되어 있다면 dyld는 해당 디렉터리들을 검색하고, 그렇지 않으면 **`/usr/local/lib/`**(프로세스가 unrestricted인 경우), 그 다음 **`/usr/lib/`**를 검색합니다.
1. `$DYLD_LIBRARY_PATH`
2. 제공된 path (unrestricted인 경우 relative path에 current working directory 사용)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (unrestricted인 경우)
5. `/usr/lib/`

> [!CAUTION]
> 이름에 slash가 있고 framework가 아닌 경우 hijacking하는 방법은 다음과 같습니다.
>
> - 바이너리가 **unrestricted**라면 CWD 또는 `/usr/local/lib`에서 무언가를 로드할 수 있습니다(또는 언급된 환경 변수 중 하나를 악용)

> [!TIP]
> 참고: **dlopen searching을 제어하는** configuration file은 **없습니다**.
>
> 참고: main executable이 **set\[ug]id binary**이거나 entitlements로 codesign된 경우 **모든 환경 변수가 무시**되며, full path만 사용할 수 있습니다(자세한 내용은 [check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) 참조).
>
> 참고: Apple 플랫폼은 32-bit와 64-bit 라이브러리를 결합하기 위해 "universal" file을 사용합니다. 따라서 **별도의 32-bit 및 64-bit search path는 없습니다**.
>
> 참고: Apple 플랫폼에서는 대부분의 OS dylib가 **dyld cache에 결합**되어 디스크에 존재하지 않습니다. 따라서 OS dylib가 존재하는지 확인하기 위해 **`stat()`**을 호출하는 preflight는 **작동하지 않습니다**. 그러나 **`dlopen_preflight()`**는 **`dlopen()`**과 동일한 단계를 사용해 호환되는 mach-o file을 찾습니다.

**Check paths**

다음 코드로 모든 옵션을 확인해 보겠습니다:
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
컴파일하고 실행하면 **각 library를 찾지 못한 위치**를 확인할 수 있습니다. 또한 **FS logs를 필터링**할 수도 있습니다:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

**privileged binary/app**(예: SUID 또는 강력한 entitlements를 가진 binary)이 **relative path** library(예: `@executable_path` 또는 `@loader_path` 사용)를 **Library Validation disabled** 상태로 로드하는 경우, 공격자가 해당 binary를 **relative path**로 로드되는 library를 수정할 수 있는 위치로 이동한 뒤 이를 악용해 프로세스에 code를 inject할 수 있습니다.

## Prune `DYLD_*` env variables

이전 `dyld` 릴리스(`dyld2.cpp`)에서는 `issetugid()`, `hasRestrictedSegment()` 및 `csops(CS_OPS_STATUS)`를 사용해 in-process에서 이를 결정했습니다. **current `dyld`에서는 이 결정이 AMFI에 위임**되며, 관련 code는 `dyld/DyldProcessConfig.cpp`의 `ProcessConfig::Security::Security()`에 있습니다:<sup>[[1]](#references)</sup>
```cpp
const uint64_t amfiFlags = getAMFI(process, syscall);
this->allowAtPaths              = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_AT_PATH);
this->allowEnvVarsPrint         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS);
this->allowEnvVarsPath          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS);
this->allowEnvVarsSharedCache   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE);
this->allowClassicFallbackPaths = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS);
this->allowInsertFailures       = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION);
this->allowInterposing          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING);
this->allowEmbeddedVars         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS);
this->allowDevelopmentVars      = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS);
this->allowLibSystemOverrides   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE);
...
// env vars are only pruned on macOS
switch ( process.platform.value() ) {
case PLATFORM_MACOS:
case PLATFORM_IOSMAC:
case PLATFORM_DRIVERKIT:
break;
default:
return;
}

// env vars are only pruned when process is restricted
if ( this->allowEnvVarsPrint || this->allowEnvVarsPath || this->allowEnvVarsSharedCache )
return;

this->pruneEnvVars(process);
```
여기서 두 가지를 주목할 만합니다:

- **macOS / Mac Catalyst / DriverKit**에서만 pruning이 발생하며, AMFI가 `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` 중 어느 것도 부여하지 않은 경우에만 발생합니다.
- AMFI query에는 executable 자체의 properties가 전달됩니다:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
여기서 `isRestricted()`는 말 그대로 `__RESTRICT` segment check입니다(`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()`는 그런 다음 이름이 `DYLD_`로 시작하는 **모든** 변수를 제거하고 `apple[]` 매개변수를 아래로 이동시키므로, 제한된 프로세스의 자식 프로세스도 해당 변수들을 상속하지 않습니다:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* enviroment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> 실제 결과: 프로세스가 제한된 경우 — setuid/setgid, `__RESTRICT/__restrict` section, 또는 AMFI가 path/print flags를 부여하지 않는 hardened-runtime/entitled binary — **`DYLD_*`는 제거됩니다**. 반대로 프로세스에 **library validation** (`CS_REQUIRE_LV`)만 적용된 경우 변수는 유지되지만, 삽입된 dylib는 **동일한 Team ID**(또는 Apple)가 서명한 것이어야 하므로 실제로 code를 주입하려면 library-validation-disabling entitlements 중 하나가 필요합니다.

이제 결정 권한이 AMFI에 있으므로, 특정 binary가 어떤 동작을 적용받는지 확인하는 가장 빠른 방법은 `dyld` 자체가 아니라 AMFI가 참조하는 항목인 entitlements와 signing flags를 확인하는 것입니다:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
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
### segment `__restrict`이 포함된 Section `__RESTRICT`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Keychain에 새 인증서를 생성하고 이를 사용하여 바이너리에 서명합니다:
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
> **`0x0(none)`** flags로 서명된 binary라도 실행 시 **`CS_RESTRICT`** flag가 동적으로 설정될 수 있으므로, 이 technique은 해당 binary에서 작동하지 않습니다.
>
> 다음 명령으로 proc에 이 flag가 있는지 확인할 수 있습니다([**csops here**](https://github.com/axelexic/CSOps) 참조):
>
> ```bash
> csops -status <pid>
> ```
>
> 그런 다음 0x800 flag가 활성화되어 있는지 확인합니다.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup and library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
