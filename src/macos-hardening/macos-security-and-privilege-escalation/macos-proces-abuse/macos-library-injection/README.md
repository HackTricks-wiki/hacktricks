# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld의 code는 open source**이며 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)에서 확인할 수 있고, [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)와 같은 **URL을 사용하여** tar로 다운로드할 수 있습니다.

## **Dyld Process**

Dyld가 바이너리 내부에서 library를 load하는 방법은 다음을 확인하십시오:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

이는 [**Linux의 LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload)와 같습니다. 실행될 process가 특정 path의 library를 load하도록 지정할 수 있습니다(env var가 활성화된 경우)<sup>[[4]](#references)</sup>

이 technique은 **ASEP technique으로도 사용**할 수 있습니다. 설치된 모든 application에는 `"Info.plist"`라는 plist가 있으며, `LSEnvironmental`이라는 key를 사용하여 **environmental variable을 assign**할 수 있습니다.

> [!TIP]
> 2012년 이후 **Apple은** **`DYLD_INSERT_LIBRARIES`**의 **권한을 크게 줄였습니다**. 다음 조건 중 하나라도 충족되면 process는 **restricted**로 간주되며, `dyld`는 environment에서 모든 `DYLD_*` variable을 삭제합니다.
>
> - 바이너리가 `setuid/setgid`임
> - Mach-O에 **`__RESTRICT/__restrict`** section이 있음
> - 바이너리가 hardened runtime으로 sign되었고 AMFI가 "path/print variables" permission을 부여하지 않음. 즉 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)가 없음<sup>[[3]](#references)</sup>
>   - 다음 명령으로 바이너리의 **entitlements**를 확인합니다: `codesign -dv --entitlements :- </path/to/bin>`
>
> 현재 `dyld`에서는 더 이상 `dyld`만으로 결정되지 않습니다. `ProcessConfig::Security::Security()`가 `amfi_check_dyld_policy_self()`를 통해 **AMFI**에 요청한 다음 `pruneEnvVars()`를 호출합니다. 정확한 code 흐름은 아래 [Prune `DYLD_*` env variables](#prune-dyld_-env-variables)에서 설명합니다.

### Library Validation

바이너리가 **`DYLD_INSERT_LIBRARIES`** environment variable을 허용하더라도 library의 signature를 validate하면 custom library를 load하지 않습니다.

custom library를 load하려면 바이너리에 다음 entitlement 중 **하나가 있어야** 합니다.

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

또는 바이너리에 **hardened runtime flag**나 **library validation flag**가 없어야 합니다.

`codesign --display --verbose <bin>`을 사용하여 바이너리에 **hardened runtime**이 있는지 확인할 수 있으며, **`CodeDirectory`**의 runtime flag를 확인합니다. 예시는 다음과 같습니다: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

또한 바이너리와 **동일한 certificate로 sign된** library도 load할 수 있습니다.

이를 (ab)use하는 방법과 restriction을 확인하는 예시는 다음에서 찾을 수 있습니다.


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **이전 Library Validation restriction도 Dylib hijacking attack 수행에 적용**된다는 점을 기억하십시오.

Windows와 마찬가지로 MacOS에서도 **dylib을 hijack**하여 **application이** **arbitrary** **code를 execute**하도록 만들 수 있습니다(실제로 일반 user에게는 `.app` bundle 내부에 write하고 library를 hijack하기 위해 TCC permission이 필요할 수 있으므로 불가능할 수 있습니다).\
그러나 **MacOS** application이 library를 **load**하는 방식은 Windows보다 **더 restricted**되어 있습니다. 이는 **malware** developer가 여전히 이 technique을 **stealth**에 사용할 수 있지만, 이를 **privilege escalation에 abuse할 가능성은 훨씬 낮다**는 것을 의미합니다.

첫째, **MacOS binary가 load할 library의 full path를 지정하는 경우가 더 많습니다**. 둘째, **MacOS는 library를 찾기 위해** `$PATH`의 folder를 **절대 search하지 않습니다**.

이 functionality와 관련된 **code**의 **main** 부분은 `ImageLoader.cpp`의 **`ImageLoader::recursiveLoadLibraries`**에 있습니다.

macho binary가 library를 load하는 데 사용할 수 있는 header Command는 **4가지**입니다.

- **`LC_LOAD_DYLIB`** command는 dylib을 load하는 일반적인 command입니다.
- **`LC_LOAD_WEAK_DYLIB`** command는 이전 command처럼 동작하지만, dylib을 찾지 못해도 error 없이 execution이 계속됩니다.
- **`LC_REEXPORT_DYLIB`** command는 다른 library의 symbol을 proxy하거나(re-export)합니다.
- **`LC_LOAD_UPWARD_DYLIB`** command는 두 library가 서로 의존할 때 사용됩니다(이를 _upward dependency_라고 합니다).

그러나 dylib hijacking에는 **2가지 type**이 있습니다.

- **Missing weak linked libraries**: 이는 application이 **LC_LOAD_WEAK_DYLIB**로 설정된 존재하지 않는 library를 load하려 한다는 의미입니다. 이후 **attacker가 예상되는 위치에 dylib을 배치하면 load됩니다**.
- link가 "weak"하다는 것은 library를 찾지 못해도 application이 계속 실행된다는 의미입니다.
- 이와 관련된 **code**는 `ImageLoaderMachO.cpp`의 `ImageLoaderMachO::doGetDependentLibraries` function에 있으며, `LC_LOAD_WEAK_DYLIB`가 true인 경우에만 `lib->required`가 `false`가 됩니다.
- 다음 명령으로 binary에서 **weak linked libraries**를 찾을 수 있습니다(hijacking library를 생성하는 방법은 뒤에 예시가 있습니다).
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **`@rpath`로 configure됨**: Mach-O binary에는 **`LC_RPATH`** 및 **`LC_LOAD_DYLIB`** command가 있을 수 있습니다. 이러한 command의 **value**에 따라 **library는** 서로 **다른 directory에서 load**됩니다.
- **`LC_RPATH`**에는 binary가 library를 load하는 데 사용하는 일부 folder의 path가 포함됩니다.
- **`LC_LOAD_DYLIB`**에는 load할 특정 library의 path가 포함됩니다. 이 path에는 **`@rpath`**가 포함될 수 있으며, 이는 **`LC_RPATH`**의 value로 대체됩니다. **`LC_RPATH`**에 여러 path가 있으면 모두 library를 search하는 데 사용됩니다. 예:
- **`LC_LOAD_DYLIB`**에 `@rpath/library.dylib`가 포함되고 **`LC_RPATH`**에 `/application/app.app/Contents/Framework/v1/` 및 `/application/app.app/Contents/Framework/v2/`가 포함된 경우, 두 folder 모두 `library.dylib`를 load하는 데 사용됩니다. library가 `[...]/v1/`에 존재하지 않고 attacker가 해당 위치에 배치할 수 있다면 **`LC_LOAD_DYLIB`의 path 순서가 적용되므로** `[...]/v2/`의 library load를 hijack할 수 있습니다.
- 다음 명령으로 binary에서 **rpath path와 library**를 찾을 수 있습니다: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file을 포함하는 directory의 path**입니다.
>
> **`@loader_path`**: load command를 포함하는 **Mach-O binary가 있는 directory의 path**입니다.
>
> - executable에서 사용하면 **`@loader_path`**는 사실상 **`@executable_path`**와 같습니다.
> - **dylib**에서 사용하면 **`@loader_path`**는 **dylib의 path**를 반환합니다.

이 functionality를 abuse하여 **privilege escalation**하는 방법은, **root가 execute하는 application이** attacker에게 write permission이 있는 folder에서 **어떤 library를 search하는 드문 경우**입니다.

> [!TIP]
> application에서 **missing library**를 찾는 데 유용한 **scanner**는 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 또는 [**CLI version**](https://github.com/pandazheng/DylibHijack)입니다.\
> 이 technique에 대한 **technical detail이 포함된 유용한 report**는 [**여기**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)에서 확인할 수 있습니다.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **이전 Library Validation restriction도 Dlopen hijacking attack 수행에 적용**된다는 점을 기억하십시오.

**`man dlopen`**에서:

- path에 slash character가 **포함되지 않으면**(즉 leaf name만 있는 경우), **dlopen()은 search를 수행**합니다. launch 시 **`$DYLD_LIBRARY_PATH`**가 set되어 있으면 dyld는 먼저 해당 director**y**를 **search**합니다. 다음으로 calling mach-o file 또는 main executable이 **`LC_RPATH`**를 지정한 경우 dyld는 해당 directory를 **search**합니다. 다음으로 process가 **unrestricted**이면 dyld는 current working directory를 search합니다. 마지막으로 old binary의 경우 dyld는 일부 fallback을 시도합니다. launch 시 **`$DYLD_FALLBACK_LIBRARY_PATH`**가 set되어 있으면 dyld는 **해당 directory**를 search하고, 그렇지 않으면 dyld는 **`/usr/local/lib/`**(process가 unrestricted인 경우), 그다음 **`/usr/lib/`**를 search합니다(이 정보는 **`man dlopen`**에서 가져왔습니다).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(unrestricted인 경우)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (unrestricted인 경우)
6. `/usr/lib/`

> [!CAUTION]
> name에 slash가 없는 경우 hijacking하는 방법은 2가지입니다.
>
> - **`LC_RPATH`** 중 writable한 것이 있는 경우(signature가 check되므로 binary도 unrestricted여야 함)
> - binary가 **unrestricted**여서 CWD에서 무언가를 load할 수 있는 경우(또는 언급된 env variable 중 하나를 abuse하는 경우)

- path가 framework path처럼 보이는 경우(예: `/stuff/foo.framework/foo`), launch 시 **`$DYLD_FRAMEWORK_PATH`**가 set되어 있으면 dyld는 먼저 해당 directory에서 **framework partial path**(예: `foo.framework/foo`)를 search합니다. 다음으로 dyld는 **제공된 path를 그대로** 시도합니다(relative path에는 current working directory 사용). 마지막으로 old binary의 경우 dyld는 일부 fallback을 시도합니다. launch 시 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**가 set되어 있으면 해당 directory를 search합니다. 그렇지 않으면 **`/Library/Frameworks`**(process가 unrestricted인 macOS의 경우), 그다음 **`/System/Library/Frameworks`**를 search합니다.
1. `$DYLD_FRAMEWORK_PATH`
2. 제공된 path(unrestricted인 경우 relative path에는 current working directory 사용)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (unrestricted인 경우)
5. `/System/Library/Frameworks`

> [!CAUTION]
> framework path인 경우 이를 hijack하는 방법은 다음과 같습니다.
>
> - process가 **unrestricted**인 경우, CWD의 **relative path** 또는 언급된 env variable을 abuse합니다(문서에 process가 restricted이면 DYLD\_\* env variable이 제거된다고 명시되어 있지 않더라도).

- path에 slash가 포함되지만 framework path가 아닌 경우(즉 dylib에 대한 full path 또는 partial path), dlopen()은 먼저(설정되어 있다면) **`$DYLD_LIBRARY_PATH`**에서 search합니다(path의 leaf 부분 사용). 다음으로 dyld는 **제공된 path를 시도**합니다(relative path에는 current working directory를 사용하지만, **unrestricted process에서만** 해당). 마지막으로 older binary의 경우 dyld는 fallback을 시도합니다. launch 시 **`$DYLD_FALLBACK_LIBRARY_PATH`**가 set되어 있으면 해당 directory를 search하고, 그렇지 않으면 dyld는 **`/usr/local/lib/`**(process가 unrestricted인 경우), 그다음 **`/usr/lib/`**를 search합니다.
1. `$DYLD_LIBRARY_PATH`
2. 제공된 path(unrestricted인 경우 relative path에는 current working directory 사용)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (unrestricted인 경우)
5. `/usr/lib/`

> [!CAUTION]
> name에 slash가 있고 framework가 아닌 경우 hijack하는 방법은 다음과 같습니다.
>
> - binary가 **unrestricted**여서 CWD 또는 `/usr/local/lib`에서 무언가를 load할 수 있는 경우(또는 언급된 env variable 중 하나를 abuse하는 경우)

> [!TIP]
> 참고: **dlopen searching을 control하는 configuration file은 없습니다**.
>
> 참고: main executable이 **set\[ug]id binary이거나 entitlements로 codesign된 경우**, **모든 environment variable이 무시**되며 full path만 사용할 수 있습니다([더 자세한 정보는 DYLD_INSERT_LIBRARIES restriction 확인](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)).
>
> 참고: Apple platform은 32-bit와 64-bit library를 결합하기 위해 "universal" file을 사용합니다. 따라서 **별도의 32-bit 및 64-bit search path가 없습니다**.
>
> 참고: Apple platform에서는 대부분의 OS dylib이 **dyld cache에 결합**되어 disk에 존재하지 않습니다. 따라서 OS dylib이 존재하는지 사전에 확인하기 위해 **`stat()`**을 호출해도 **동작하지 않습니다**. 그러나 **`dlopen_preflight()`**는 **`dlopen()`과 동일한 단계**를 사용하여 호환 가능한 mach-o file을 찾습니다.

**Check paths**

다음 code를 사용하여 모든 option을 확인해 보겠습니다.
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
컴파일하고 실행하면 **각 라이브러리를 어디에서 검색했지만 찾지 못했는지** 확인할 수 있습니다. 또한 **FS 로그를 필터링**할 수도 있습니다:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

**privileged binary/app**(예: SUID 또는 강력한 entitlement를 가진 일부 binary)이 **relative path** library(예: `@executable_path` 또는 `@loader_path` 사용)를 **loading**하고 **Library Validation disabled** 상태라면, attacker가 **relative path**로 로드되는 library를 **modify**할 수 있는 위치로 binary를 이동한 후 이를 악용하여 process에 code를 inject할 수 있습니다.

## `DYLD_*` env variables 정리

이전 `dyld` 릴리스(`dyld2.cpp`)에서는 `issetugid()`, `hasRestrictedSegment()` 및 `csops(CS_OPS_STATUS)`를 사용하여 이 결정을 process 내부에서 수행했습니다. 현재 **dyld**에서는 이 결정이 **AMFI**에 위임되며, 관련 code는 `dyld/DyldProcessConfig.cpp`의 `ProcessConfig::Security::Security()`에 있습니다:<sup>[[1]](#references)</sup>
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
이 내용에서 두 가지를 추출할 수 있습니다:

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
`pruneEnvVars()`는 이후 이름이 `DYLD_`로 시작하는 **모든** 변수를 제거하고 `apple[]` 매개변수를 앞으로 이동시키므로, 제한된 프로세스의 자식 프로세스 역시 해당 변수를 상속하지 않습니다:
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
> 실제 결과: 프로세스가 제한된 경우 — setuid/setgid, `__RESTRICT/__restrict` 섹션, 또는 AMFI가 경로/print 플래그 부여를 거부하는 hardened-runtime/entitled 바이너리 — `DYLD_*`가 제거됩니다. 반대로 프로세스에 **library validation** (`CS_REQUIRE_LV`)만 적용된 경우에는 변수가 유지되지만, 삽입되는 dylib는 **동일한 Team ID**로 서명되었거나 Apple이 서명한 것이어야 합니다. 따라서 실제로 코드를 삽입하려면 library-validation을 비활성화하는 entitlement 중 하나가 필요합니다.

이제 결정은 AMFI가 내리므로, 특정 바이너리가 무엇을 적용받는지 확인하는 가장 빠른 방법은 `dyld` 자체가 아니라 AMFI가 참조하는 항목인 entitlements와 signing flags를 확인하는 것입니다:
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
### `__RESTRICT` 섹션과 `__restrict` 세그먼트
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Keychain에서 새 인증서를 생성하고 이를 사용하여 binary에 서명합니다:
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
> 바이너리에 **`0x0(none)`** flags가 signed되어 있더라도 실행 시 동적으로 **`CS_RESTRICT`** flag를 얻을 수 있으므로 이 technique은 해당 바이너리에서 작동하지 않습니다.
>
> 다음을 사용하여 proc에 이 flag가 있는지 확인할 수 있습니다([**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> 그런 다음 flag 0x800이 활성화되어 있는지 확인합니다.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup and library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
