# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld의 코드는 open source**이며 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)에서 확인할 수 있고, [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)와 같은 **URL을 사용해** tar로 다운로드할 수 있습니다.

## **Dyld Process**

Dyld가 바이너리 내부의 library를 로드하는 방식을 다음에서 확인하세요:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

이는 [**Linux의 LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload)와 유사합니다. 실행될 process가 특정 path의 library를 로드하도록 지정할 수 있습니다(env var가 활성화된 경우).

이 technique은 **ASEP technique으로도 사용**할 수 있습니다. 설치된 모든 application에는 `"Info.plist"`라는 plist가 있으며, `LSEnvironmental`이라는 key를 사용해 **environmental variables를 할당**할 수 있습니다.

> [!TIP]
> 2012년 이후 **Apple은** **`DYLD_INSERT_LIBRARIES`**의 **권한을 크게 제한**했습니다.
>
> 코드로 이동해 **`src/dyld.cpp`**를 **확인**하세요. **`pruneEnvironmentVariables`** function에서 **`DYLD_*`** variables가 제거되는 것을 볼 수 있습니다.
>
> **`processRestricted`** function에서 restriction의 이유가 설정됩니다. 해당 코드를 확인하면 다음과 같은 이유가 있음을 알 수 있습니다.
>
> - 바이너리가 `setuid/setgid`임
> - macho 바이너리에 `__RESTRICT/__restrict` section이 존재함
> - software에 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) entitlement 없이 entitlements(hardened runtime)가 있음
>  - 다음 명령으로 바이너리의 **entitlements**를 확인합니다: `codesign -dv --entitlements :- </path/to/bin>`
>
> 더 최신 version에서는 이 logic을 **`configureProcessRestrictions`** function의 두 번째 부분에서 확인할 수 있습니다. 그러나 최신 version에서 실행되는 것은 function **초반부의 checks**입니다(macOS에서는 사용되지 않는 iOS 또는 simulation 관련 if는 제거할 수 있습니다).

### Library Validation

바이너리가 **`DYLD_INSERT_LIBRARIES`** env variable 사용을 허용하더라도, 로드할 library의 signature를 확인하는 경우 custom library를 로드하지 않습니다.

custom library를 로드하려면 바이너리에 다음 entitlement 중 **하나가 있어야** 합니다.

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

또는 바이너리에 **hardened runtime flag**나 **library validation flag**가 없어야 합니다.

`codesign --display --verbose <bin>`을 사용해 바이너리에 **hardened runtime**이 있는지 확인할 수 있으며, **`CodeDirectory`**의 runtime flag를 다음과 같이 확인합니다: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

또한 바이너리와 동일한 certificate로 **sign된 library**도 로드할 수 있습니다.

이를 (ab)use하는 방법과 restriction을 확인하는 예시는 다음에서 찾을 수 있습니다.


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **이전의 Library Validation restrictions도 Dylib hijacking attacks를 수행할 때 적용**된다는 점을 기억하세요.

Windows와 마찬가지로 MacOS에서도 **dylibs를 hijack**해 **application이** **arbitrary** **code를 execute**하도록 만들 수 있습니다(실제로 일반 user에게는 `.app` bundle 내부에 write하려면 TCC permission이 필요할 수 있으므로 불가능할 수 있습니다).\
그러나 **MacOS** application이 library를 **load**하는 방식은 Windows보다 **더 제한적**입니다. 따라서 **malware** developers는 여전히 이 technique을 **stealth** 목적으로 사용할 수 있지만, 이를 **privilege escalation에 abuse할 가능성은 훨씬 낮습니다**.

첫째, **MacOS binaries가 로드할 library의 full path를 지정하는 경우가 더 흔합니다**. 둘째, **MacOS는 library를 찾기 위해** **$PATH**의 folder를 **검색하지 않습니다**.

이 기능과 관련된 **code의 주요 부분**은 `ImageLoader.cpp`의 **`ImageLoader::recursiveLoadLibraries`**에 있습니다.

macho 바이너리가 library를 로드할 때 사용할 수 있는 header Commands는 **4가지**입니다.

- **`LC_LOAD_DYLIB`** command는 dylib를 로드하는 일반적인 command입니다.
- **`LC_LOAD_WEAK_DYLIB`** command는 이전 command처럼 동작하지만, dylib를 찾지 못해도 error 없이 execution이 계속됩니다.
- **`LC_REEXPORT_DYLIB`** command는 다른 library의 symbols를 proxy(또는 re-export)합니다.
- **`LC_LOAD_UPWARD_DYLIB`** command는 두 library가 서로 의존할 때 사용됩니다(이를 _upward dependency_라고 합니다).

그러나 dylib hijacking에는 **2가지 type**이 있습니다.

- **Missing weak linked libraries**: 이는 application이 **LC_LOAD_WEAK_DYLIB**로 configure된 존재하지 않는 library를 로드하려고 한다는 의미입니다. 그런 다음 **attacker가 예상되는 위치에 dylib를 배치하면 로드됩니다**.
- link가 "weak"하다는 것은 library를 찾지 못해도 application이 계속 실행된다는 의미입니다.
- 이와 **관련된 code**는 `ImageLoader.cpp`의 `ImageLoaderMachO::doGetDependentLibraries` function에 있으며, `lib->required`는 `LC_LOAD_WEAK_DYLIB`가 true일 때만 `false`가 됩니다.
- **binaries에서 weak linked libraries 찾기**(뒤에서 hijacking libraries를 생성하는 방법에 대한 예제가 제공됩니다):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath로 configure됨**: Mach-O binaries에는 **`LC_RPATH`** 및 **`LC_LOAD_DYLIB`** commands가 있을 수 있습니다. 이러한 commands의 **values**에 따라 **서로 다른 directory**에서 **libraries가 로드**됩니다.
- **`LC_RPATH`**에는 binary가 libraries를 로드하는 데 사용하는 일부 folder의 paths가 포함됩니다.
- **`LC_LOAD_DYLIB`**에는 로드할 특정 libraries의 path가 포함됩니다. 이러한 paths에는 **`@rpath`**가 포함될 수 있으며, 이는 **`LC_RPATH`**의 values로 **대체**됩니다. **`LC_RPATH`**에 여러 path가 있으면 library를 로드하기 위해 모두 사용됩니다. 예:
- **`LC_LOAD_DYLIB`**에 `@rpath/library.dylib`가 포함되고 **`LC_RPATH`**에 `/application/app.app/Contents/Framework/v1/` 및 `/application/app.app/Contents/Framework/v2/`가 포함된 경우, 두 folder가 모두 `library.dylib`를 로드하는 데 사용됩니다**.** library가 `[...]/v1/`에 존재하지 않고 attacker가 해당 위치에 library를 배치할 수 있다면, **`LC_LOAD_DYLIB`**의 path 순서가 따르므로 `[...]/v2/`의 library load를 hijack할 수 있습니다.
- 다음 명령으로 **binaries에서 rpath paths 및 libraries 찾기**: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file이 포함된 directory의 path**입니다.
>
> **`@loader_path`**: load command를 포함하는 **Mach-O binary가 포함된 directory의 path**입니다.
>
> - executable에서 사용되면 **`@loader_path`**는 사실상 **`@executable_path`**와 같습니다.
> - **dylib에서 사용되면** **`@loader_path`**는 **dylib의 path**를 제공합니다.

이 기능을 abuse해 **privilege를 escalate**하는 방법은 **root가 실행하는 application이 attacker에게 write permission이 있는 folder에서 일부 library를 찾는 드문 경우**입니다.

> [!TIP]
> application에서 **missing libraries를 찾는 좋은 scanner**로는 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 또는 [**CLI version**](https://github.com/pandazheng/DylibHijack)이 있습니다.\
> 이 technique에 대한 **technical details가 포함된 좋은 report**는 [**여기**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)에서 확인할 수 있습니다.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **이전의 Library Validation restrictions도 Dlopen hijacking attacks를 수행할 때 적용**된다는 점을 기억하세요.

**`man dlopen`**에서:

- path에 slash character가 **포함되지 않으면**(즉, leaf name일 뿐이면), **dlopen()이 searching을 수행**합니다. launch 시 **`$DYLD_LIBRARY_PATH`**가 설정되어 있었다면 dyld는 먼저 해당 **directory**를 확인합니다. 다음으로 calling mach-o file 또는 main executable에 **`LC_RPATH`**가 지정되어 있으면 dyld는 해당 directory들을 **확인**합니다. 다음으로 process가 **unrestricted**라면 dyld는 current working directory를 검색합니다. 마지막으로 old binaries의 경우 dyld는 일부 fallbacks를 시도합니다. launch 시 **`$DYLD_FALLBACK_LIBRARY_PATH`**가 설정되어 있었다면 dyld는 해당 **directories**를 검색하고, 그렇지 않으면 dyld는 **`/usr/local/lib/`**(process가 unrestricted인 경우)를 확인한 다음 **`/usr/lib/`**를 확인합니다(이 정보는 **`man dlopen`**에서 가져왔습니다).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> name에 slash가 없을 때 hijacking하는 방법은 2가지입니다.
>
> - **`LC_RPATH`**가 writable인 경우(signature가 확인되므로 이를 위해서는 binary도 unrestricted여야 함)
> - binary가 **unrestricted**인 경우 CWD에서 무언가를 로드할 수 있음(또는 언급된 env variables 중 하나를 abuse)

- path가 framework path처럼 보이는 경우(예: `/stuff/foo.framework/foo`), launch 시 **`$DYLD_FRAMEWORK_PATH`**가 설정되어 있었다면 dyld는 먼저 해당 directory에서 **framework partial path**(예: `foo.framework/foo`)를 확인합니다. 다음으로 dyld는 **제공된 path를 있는 그대로** 시도합니다(relative paths에는 current working directory 사용). 마지막으로 old binaries의 경우 dyld는 일부 fallbacks를 시도합니다. launch 시 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**가 설정되어 있었다면 dyld는 해당 directories를 검색합니다. 그렇지 않으면 **`/Library/Frameworks`**(process가 unrestricted인 macOS의 경우)를 검색한 다음 **`/System/Library/Frameworks`**를 검색합니다.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> framework path인 경우 hijack하는 방법은 다음과 같습니다.
>
> - process가 **unrestricted**라면 **CWD의 relative path** 또는 언급된 env variables를 abuse합니다(process가 restricted인 경우 DYLD\_\* env vars가 제거된다는 내용이 docs에 명시되어 있지는 않습니다).

- path에 slash가 포함되지만 framework path가 아닌 경우(즉, dylib의 full path 또는 partial path인 경우), dlopen()은 먼저(설정되어 있다면) **`$DYLD_LIBRARY_PATH`**에서 확인합니다(path의 leaf 부분 사용). 다음으로 dyld는 **제공된 path**를 시도합니다(relative paths에는 current working directory 사용하지만, unrestricted processes인 경우에만 해당). 마지막으로 older binaries의 경우 dyld는 fallbacks를 시도합니다. launch 시 **`$DYLD_FALLBACK_LIBRARY_PATH`**가 설정되어 있었다면 dyld는 해당 directories를 검색하고, 그렇지 않으면 dyld는 **`/usr/local/lib/`**(process가 unrestricted인 경우)를 확인한 다음 **`/usr/lib/`**를 확인합니다.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> name에 slash가 있고 framework가 아닌 경우 hijack하는 방법은 다음과 같습니다.
>
> - binary가 **unrestricted**라면 CWD 또는 `/usr/local/lib`에서 무언가를 로드할 수 있습니다(또는 언급된 env variables 중 하나를 abuse).

> [!TIP]
> 참고: **dlopen searching을 제어하는 configuration files는 없습니다**.
>
> 참고: main executable이 **set\[ug]id binary**이거나 entitlements로 codesign된 경우 **모든 environment variables가 무시**되며 full path만 사용할 수 있습니다([자세한 정보는 DYLD_INSERT_LIBRARIES restrictions 확인](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)).
>
> 참고: Apple platforms는 32-bit와 64-bit libraries를 결합하기 위해 "universal" files를 사용합니다. 따라서 **별도의 32-bit 및 64-bit search paths가 없습니다**.
>
> 참고: Apple platforms에서는 대부분의 OS dylibs가 **dyld cache에 결합**되어 disk에 존재하지 않습니다. 따라서 OS dylib의 존재 여부를 사전 확인하기 위해 **`stat()`**을 호출해도 **작동하지 않습니다**. 그러나 **`dlopen_preflight()`**는 **`dlopen()`과 동일한 steps**를 사용해 호환 가능한 mach-o file을 찾습니다.

**Check paths**

다음 code로 모든 option을 확인해 보겠습니다:
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
컴파일하고 실행하면 **각 library를 찾는 데 실패한 위치**를 확인할 수 있습니다. 또한 **FS logs를 필터링**할 수도 있습니다:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

**privileged binary/app**(예: SUID 또는 강력한 entitlements를 가진 일부 binary)이 **relative path** library(예: `@executable_path` 또는 `@loader_path` 사용)를 로드하고 **Library Validation이 비활성화**되어 있다면, 공격자가 binary를 **relative path로 로드되는 library를 수정할 수 있는** 위치로 이동시킨 후 이를 악용해 process에 code를 inject할 수 있습니다.

## `DYLD_*` 및 `LD_LIBRARY_PATH` env variable 제거

`dyld-dyld-832.7.1/src/dyld2.cpp` 파일에서 **`pruneEnvironmentVariables`** function을 찾을 수 있으며, 이 function은 **`DYLD_`로 시작하는** 모든 env variable과 **`LD_LIBRARY_PATH=`**를 제거합니다.

또한 **suid** 및 **sgid** binary에 대해서는 **`DYLD_FALLBACK_FRAMEWORK_PATH`**와 **`DYLD_FALLBACK_LIBRARY_PATH`** env variable을 명시적으로 **null**로 설정합니다.

이 function은 OSX를 대상으로 할 경우 같은 파일의 **`_main`** function에서 다음과 같이 호출됩니다:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
그리고 해당 boolean 플래그는 코드에서 동일한 파일에 설정됩니다:
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
이는 기본적으로 바이너리가 **suid** 또는 **sgid**이거나, 헤더에 **RESTRICT** segment가 있거나, **CS_RESTRICT** flag로 서명된 경우 **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`**가 true가 되어 env variables가 제거된다는 의미입니다.

CS_REQUIRE_LV가 true인 경우 variables는 제거되지 않지만, library validation에서 원본 바이너리와 동일한 certificate를 사용하는지 확인합니다.

## Restrictions 확인

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
### `__restrict` 세그먼트가 포함된 `__RESTRICT` 섹션
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

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
> **`0x0(none)`** 플래그가 설정된 바이너리라도 실행 시 동적으로 **`CS_RESTRICT`** 플래그를 얻을 수 있으므로, 이러한 바이너리에서는 이 기법이 작동하지 않습니다.
>
> 다음 명령어로 proc에 이 플래그가 설정되어 있는지 확인할 수 있습니다([**csops here**](https://github.com/axelexic/CSOps)에서 가져오기):
>
> ```bash
> csops -status <pid>
> ```
>
> 그런 다음 플래그 0x800이 활성화되어 있는지 확인합니다.

## 참고문헌

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
