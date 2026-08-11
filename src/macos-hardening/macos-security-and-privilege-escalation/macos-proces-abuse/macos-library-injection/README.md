# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld의 code는 open source**이며 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)에서 확인할 수 있고, [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)와 같은 **URL을 사용하여** tar로 다운로드할 수 있습니다.

## **Dyld Process**

Dyld가 바이너리 내부에서 libraries를 로드하는 방식을 다음에서 확인하세요:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

이는 [**Linux의 LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload)와 같습니다. 실행될 process가 경로에서 특정 library를 로드하도록 지정할 수 있습니다(environment variable이 활성화된 경우)<sup>[[4]](#references)</sup>

이 technique은 **ASEP technique으로도 사용**할 수 있습니다. 설치된 모든 application에는 `"Info.plist"`라는 plist가 있으며, `LSEnvironmental`이라는 key를 사용하여 **environmental variables를 할당**할 수 있습니다.

> [!TIP]
> 2012년 이후 **Apple은** **`DYLD_INSERT_LIBRARIES`의 권한을 크게 축소**했습니다. 다음 조건 중 하나라도 충족되면 process는 **restricted**로 간주되며, `dyld`는 해당 process의 environment에서 모든 `DYLD_*` variable을 삭제합니다.
>
> - 바이너리가 `setuid/setgid`인 경우
> - Mach-O에 **`__RESTRICT/__restrict`** section이 있는 경우
> - 바이너리가 hardened runtime으로 signed되었고 AMFI가 "path/print variables" permissions를 부여하지 않은 경우, 즉 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)가 없는 경우<sup>[[3]](#references)</sup>
>   - 다음 명령으로 바이너리의 **entitlements**를 확인할 수 있습니다: `codesign -dv --entitlements :- </path/to/bin>`
>
> 현재 `dyld`에서는 이 결정이 더 이상 `dyld`만으로 이루어지지 않습니다. `ProcessConfig::Security::Security()`가 `amfi_check_dyld_policy_self()`를 통해 **AMFI에 요청**한 다음 `pruneEnvVars()`를 호출합니다. 정확한 code 흐름은 아래의 [Prune `DYLD_*` env variables](#prune-dyld_-env-variables)에서 설명합니다.

### Library Validation

바이너리가 **`DYLD_INSERT_LIBRARIES`** environment variable을 허용하더라도, library의 signature를 검증한다면 custom library를 로드하지 않습니다.

custom library를 로드하려면 바이너리에 다음 entitlement 중 **하나가 있어야 합니다**.

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

또는 바이너리에 **hardened runtime flag**나 **library validation flag**가 없어야 합니다.

`codesign --display --verbose <bin>`을 사용하여 바이너리에 **hardened runtime**이 있는지 확인할 수 있습니다. **`CodeDirectory`**에서 다음과 같이 runtime flag를 확인합니다: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

또한 library가 바이너리와 **동일한 certificate로 signed**되어 있다면 로드할 수 있습니다.

이를 (ab)use하고 restrictions를 확인하는 방법은 다음에서 확인하세요:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **이전에 설명한 Library Validation restrictions도 Dylib hijacking attacks 수행에 적용**된다는 점을 기억하세요.

Windows와 마찬가지로 macOS에서도 **dylibs를 hijack**하여 **applications가 arbitrary code를 실행**하도록 만들 수 있습니다. 일반 user account에서는 이것이 불가능할 수 있습니다. library를 hijack하기 위해 `.app` bundle 내부에 write하려면 TCC permission이 필요할 수 있기 때문입니다.\
그러나 **macOS** applications가 libraries를 **load**하는 방식은 Windows보다 **더 restricted**되어 있습니다. Malware developers는 여전히 stealth를 위해 이 technique을 사용할 수 있지만, 이를 abuse하여 privileges를 escalate하는 것은 훨씬 가능성이 낮습니다.

우선 **MacOS binaries가 로드할 libraries의 full path를 표시하는 경우가 더 흔합니다**. 또한 **MacOS는 libraries를 찾기 위해** **$PATH**의 folders를 **검색하지 않습니다**.

이 기능과 관련된 **code의 주요** 부분은 `ImageLoader.cpp`의 **`ImageLoader::recursiveLoadLibraries`**에 있습니다.

macho 바이너리가 libraries를 로드하는 데 사용할 수 있는 header Commands는 **4가지**입니다.

- **`LC_LOAD_DYLIB`** command는 dylib를 로드하는 일반적인 command입니다.
- **`LC_LOAD_WEAK_DYLIB`** command는 이전 command와 같이 작동하지만, dylib를 찾지 못해도 execution은 error 없이 계속됩니다.
- **`LC_REEXPORT_DYLIB`** command는 다른 library의 symbols를 proxy(또는 re-export)합니다.
- **`LC_LOAD_UPWARD_DYLIB`** command는 두 libraries가 서로 의존할 때 사용됩니다(이를 _upward dependency_라고 합니다).

하지만 dylib hijacking에는 **2가지 유형**이 있습니다.

- **Missing weak linked libraries**: 이는 application이 **LC_LOAD_WEAK_DYLIB**로 설정된 존재하지 않는 library를 로드하려 한다는 의미입니다. 이후 **attacker가 예상되는 위치에 dylib를 배치하면 해당 dylib가 로드됩니다**.
- link가 "weak"하다는 것은 library를 찾지 못해도 application이 계속 실행된다는 의미입니다.
- 이와 **관련된 code**는 `ImageLoaderMachO.cpp`의 `ImageLoaderMachO::doGetDependentLibraries` function에 있으며, `lib->required`는 `LC_LOAD_WEAK_DYLIB`가 true일 때만 `false`가 됩니다.
- 바이너리에서 **weak linked libraries를 찾으려면** 다음을 사용합니다(뒤에서 hijacking libraries를 생성하는 방법의 예시도 제공합니다).
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binaries에는 **`LC_RPATH`** 및 **`LC_LOAD_DYLIB`** commands가 있을 수 있습니다. 이러한 commands의 **values를 기반으로**, **libraries는** 서로 **다른 directories**에서 로드됩니다.
- **`LC_RPATH`**에는 바이너리가 libraries를 로드하는 데 사용하는 일부 folders의 paths가 포함됩니다.
- **`LC_LOAD_DYLIB`**에는 로드할 특정 libraries의 path가 포함됩니다. 이러한 paths에는 **`@rpath`**가 포함될 수 있으며, 이는 **`LC_RPATH`**의 values로 대체됩니다. **`LC_RPATH`**에 여러 paths가 있으면 library를 로드하기 위해 모든 paths가 사용됩니다. 예:
- **`LC_LOAD_DYLIB`**에 `@rpath/library.dylib`가 포함되고 **`LC_RPATH`**에 `/application/app.app/Contents/Framework/v1/` 및 `/application/app.app/Contents/Framework/v2/`가 포함된 경우, 두 folders 모두 `library.dylib`를 로드하는 데 사용됩니다**.** library가 `[...]/v1/`에 존재하지 않고 attacker가 해당 위치에 배치할 수 있다면, **`LC_LOAD_DYLIB`**의 path order가 적용되므로 `[...]/v2/`에서 library가 로드되는 것을 hijack할 수 있습니다.
- 바이너리에서 **rpath paths와 libraries를 찾으려면** 다음을 사용합니다: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file을 포함하는 directory의 path**입니다.
>
> **`@loader_path`**: load command를 포함하는 **Mach-O binary가 있는 directory의 path**입니다.
>
> - executable에서 사용하면 **`@loader_path`**는 사실상 **`@executable_path`**와 동일합니다.
> - **dylib**에서 사용하면 **`@loader_path`**는 **dylib의 path**를 제공합니다.

이 기능을 abuse하여 **privileges를 escalate**하는 방법은, **root가 실행하는** **application**이 attacker가 write permissions를 가진 folder에서 **일부 library를 찾는** 드문 경우입니다.

> [!TIP]
> applications에서 **missing libraries를 찾는** 유용한 **scanner**로는 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 또는 [**CLI version**](https://github.com/pandazheng/DylibHijack)이 있습니다.\
> 이 technique에 대한 **technical details가 포함된 유용한 report**는 [**여기**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)에서 확인할 수 있습니다.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **이전에 설명한 Library Validation restrictions도 Dlopen hijacking attacks 수행에 적용**된다는 점을 기억하세요.

**`man dlopen`**에서:

- path에 slash character가 **포함되지 않는 경우**(즉, leaf name만 있는 경우), **dlopen()은 searching을 수행**합니다. launch 시 **`$DYLD_LIBRARY_PATH`**가 설정되어 있었다면 dyld는 먼저 해당 **directory를 검색**합니다. 다음으로 calling mach-o file 또는 main executable이 **`LC_RPATH`**를 지정했다면 dyld는 해당 directories를 **검색**합니다. 다음으로 process가 **unrestricted**라면 dyld는 current working directory를 검색합니다. 마지막으로 old binaries의 경우 dyld는 일부 fallbacks를 시도합니다. launch 시 **`$DYLD_FALLBACK_LIBRARY_PATH`**가 설정되어 있었다면 dyld는 **해당 directories**를 검색하고, 그렇지 않으면 dyld는 **`/usr/local/lib/`**(process가 unrestricted인 경우), 이어서 **`/usr/lib/`**를 검색합니다(이 정보는 **`man dlopen`**에서 가져왔습니다).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> name에 slash가 없다면 hijacking을 수행하는 방법은 2가지입니다.
>
> - **`LC_RPATH`** 중 하나라도 **writable**한 경우(단, signature가 확인되므로 이 경우에도 바이너리가 unrestricted여야 함)
> - 바이너리가 **unrestricted**이므로 CWD에서 무언가를 로드할 수 있는 경우(또는 언급된 environment variables 중 하나를 abuse하는 경우)

- path가 framework path처럼 보이는 경우(예: `/stuff/foo.framework/foo`), launch 시 **`$DYLD_FRAMEWORK_PATH`**가 설정되어 있었다면 dyld는 먼저 해당 directory에서 **framework partial path**(예: `foo.framework/foo`)를 찾습니다. 다음으로 dyld는 **제공된 path를 그대로** 시도합니다(relative paths에는 current working directory 사용). 마지막으로 old binaries의 경우 dyld는 일부 fallbacks를 시도합니다. launch 시 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**가 설정되어 있었다면 dyld는 해당 directories를 검색합니다. 그렇지 않으면 **`/Library/Frameworks`**(macOS에서 process가 unrestricted인 경우), 이어서 **`/System/Library/Frameworks`**를 검색합니다.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> framework path인 경우 hijack하는 방법은 다음과 같습니다.
>
> - process가 **unrestricted**라면 언급된 environment variables에서 **CWD의 relative path를 abuse**하는 방법입니다(process가 restricted인 경우 `DYLD\_\*` env vars가 제거된다는 내용이 docs에 명시되어 있지 않더라도).

- path에 slash가 포함되지만 framework path가 아닌 경우(즉, dylib의 full path 또는 partial path), dlopen()은 먼저 (설정되어 있다면) **`$DYLD_LIBRARY_PATH`**에서 검색합니다(path의 leaf 부분 사용). 다음으로 dyld는 **제공된 path를 시도**합니다(relative paths에는 current working directory를 사용하지만, unrestricted processes에만 해당). 마지막으로 older binaries의 경우 dyld는 fallbacks를 시도합니다. launch 시 **`$DYLD_FALLBACK_LIBRARY_PATH`**가 설정되어 있었다면 dyld는 해당 directories를 검색하고, 그렇지 않으면 dyld는 **`/usr/local/lib/`**(process가 unrestricted인 경우), 이어서 **`/usr/lib/`**를 검색합니다.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> name에 slash가 있고 framework가 아닌 경우 hijack하는 방법은 다음과 같습니다.
>
> - 바이너리가 **unrestricted**라면 CWD 또는 `/usr/local/lib`에서 무언가를 로드할 수 있습니다(또는 언급된 environment variables 중 하나를 abuse하는 경우).

> [!TIP]
> 참고: **dlopen searching을 control하는 configuration files는 없습니다**.
>
> 참고: main executable이 **set\[ug]id binary**이거나 entitlements로 codesigned된 경우, **모든 environment variables가 무시**되며 full path만 사용할 수 있습니다([더 자세한 정보는 DYLD_INSERT_LIBRARIES restrictions 확인](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)).
>
> 참고: Apple platforms는 32-bit와 64-bit libraries를 결합하기 위해 "universal" files를 사용합니다. 따라서 **별도의 32-bit 및 64-bit search paths가 없습니다**.
>
> 참고: Apple platforms에서는 대부분의 OS dylibs가 **dyld cache에 결합**되어 있으며 disk에 존재하지 않습니다. 따라서 OS dylib가 존재하는지 사전 확인하기 위해 **`stat()`**을 호출하는 방식은 **작동하지 않습니다**. 그러나 **`dlopen_preflight()`**는 **`dlopen()`과 동일한 steps**를 사용하여 호환 가능한 mach-o file을 찾습니다.

**Check paths**

다음 code를 사용하여 모든 options를 확인해 보겠습니다.
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

**privileged binary/app**(예: SUID 또는 강력한 entitlements를 가진 일부 binary)이 **relative path** library(예: `@executable_path` 또는 `@loader_path` 사용)를 **loading**하고 **Library Validation disabled** 상태라면, attacker가 **relative path로 로드되는 library를 modify**할 수 있는 위치로 binary를 이동한 뒤 이를 악용해 process에 코드를 inject할 수 있습니다.

## Prune `DYLD_*` env variables

이전 `dyld` 릴리스(`dyld2.cpp`)에서는 `issetugid()`, `hasRestrictedSegment()` 및 `csops(CS_OPS_STATUS)`를 사용해 프로세스 내부에서 이를 결정했습니다. **현재 `dyld`에서는 이 결정이 AMFI에 위임**되며, 관련 코드는 `dyld/DyldProcessConfig.cpp`의 `ProcessConfig::Security::Security()`에 있습니다:<sup>[[1]](#references)</sup>
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
이 내용에서 두 가지를 추출할 수 있습니다.

- **macOS / Mac Catalyst / DriverKit**에서만 pruning이 발생하며, AMFI가 `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` 중 어느 것도 허용하지 않은 경우에만 발생합니다.
- AMFI query에는 executable 자체의 properties가 전달됩니다:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
여기서 `isRestricted()`는 말 그대로 `__RESTRICT` 세그먼트 검사입니다(`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()`는 그런 다음 이름이 `DYLD_`로 시작하는 **모든** 변수를 제거하고 `apple[]` 매개변수를 앞으로 이동시키므로, restricted process의 자식 프로세스도 이를 상속하지 않습니다:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* environment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> 실질적인 결과: 프로세스가 제한된 경우 — setuid/setgid, `__RESTRICT/__restrict` 섹션, 또는 AMFI가 경로/print 플래그 부여를 거부하는 hardened-runtime/entitled 바이너리 — **`DYLD_*`는 제거됩니다**. 반대로 프로세스에 **library validation**(`CS_REQUIRE_LV`)만 적용된 경우에는 변수가 유지되지만, 삽입되는 dylib는 **동일한 Team ID**(또는 Apple)로 서명되어야 하므로 실제로 코드를 삽입하려면 library validation을 비활성화하는 entitlement 중 하나가 필요합니다.

이제 결정 주체가 AMFI이므로, 특정 바이너리가 무엇을 적용받는지 확인하는 가장 빠른 방법은 `dyld` 자체가 아니라 AMFI가 참조하는 항목 — entitlement와 signing flag — 을 확인하는 것입니다:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## 제한 사항 확인

### SUID 및 SGID
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

Keychain에 새 인증서를 생성하고 이를 사용해 binary에 서명합니다:
```bash
# Apply runtime protection
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
> 바이너리가 **`0x0(none)`** 플래그로 서명되어 있더라도 실행 시 **`CS_RESTRICT`** 플래그가 동적으로 설정될 수 있으므로, 이러한 바이너리에서는 이 기법이 작동하지 않습니다.
>
> 다음 명령으로 proc에 이 플래그가 있는지 확인할 수 있습니다([**csops here**](https://github.com/axelexic/CSOps) 참조):
>
> ```bash
> csops -status <pid>
> ```
>
> 그런 다음 플래그 0x800이 활성화되어 있는지 확인합니다.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` 확인)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (프로세스 시작 및 library 삽입)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
