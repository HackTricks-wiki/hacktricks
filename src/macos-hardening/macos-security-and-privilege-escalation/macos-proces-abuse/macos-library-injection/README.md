# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld의 코드가 오픈 소스**이며 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)에서 확인할 수 있습니다. **다음과 같은 URL**에서 tar 파일을 다운로드할 수도 있습니다: [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Dyld가 바이너리 내부에서 라이브러리를 로드하는 방식을 확인하려면 다음을 참고하세요:


{{#ref}}
macos-dyld-process.md
{{#endref}}

함께 보기: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

## **DYLD_INSERT_LIBRARIES**

이는 [**Linux의 LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload)와 유사합니다. 환경 변수가 활성화되어 있으면 실행될 프로세스에 경로에서 특정 라이브러리를 로드하도록 지정할 수 있습니다.<sup>[[4]](#references)</sup>

이 기법은 **ASEP 기법으로도 사용**할 수 있습니다. 설치된 모든 애플리케이션에는 `Info.plist`라는 plist가 있으며, 이 plist에서 `LSEnvironmental`이라는 키를 사용해 **환경 변수를 할당**할 수 있습니다.

> [!TIP]
> 2012년 이후 **Apple은 `DYLD_INSERT_LIBRARIES`의 기능을 크게 제한**했습니다. 다음 조건 중 하나라도 충족되면 프로세스는 **restricted**로 간주되며, `dyld`는 환경 변수에서 모든 `DYLD_*` 변수를 삭제합니다.
>
> - 바이너리가 `setuid/setgid`임
> - Mach-O에 **`__RESTRICT/__restrict`** 섹션이 있음
> - 바이너리가 hardened runtime으로 서명되어 있고 AMFI가 "path/print variables" 권한을 부여하지 않음. 즉, [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)가 없음<sup>[[3]](#references)</sup>
>   - 다음 명령으로 바이너리의 **entitlements**를 확인하세요: `codesign -dv --entitlements :- </path/to/bin>`
>
> 현재 `dyld`에서는 이 결정이 더 이상 `dyld` 단독으로 이루어지지 않습니다. `ProcessConfig::Security::Security()`가 `amfi_check_dyld_policy_self()`를 통해 **AMFI**에 확인을 요청한 다음 `pruneEnvVars()`를 호출합니다. 관련 코드는 아래의 [Prune `DYLD_*` env variables](#prune-dyld_-env-variables)에서 자세히 설명합니다.

### Library Validation

바이너리에서 **`DYLD_INSERT_LIBRARIES`** 환경 변수를 허용하더라도, 라이브러리의 서명을 검증하면 사용자 지정 라이브러리를 로드하지 않습니다.

사용자 지정 라이브러리를 로드하려면 바이너리에 다음 **entitlement 중 하나가 있어야 합니다**.

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

또는 바이너리에 **hardened runtime 플래그**나 **library validation 플래그**가 없어야 합니다.

`codesign --display --verbose <bin>`을 실행하고 **`CodeDirectory`**의 runtime 플래그를 확인하면 바이너리에 **hardened runtime**이 있는지 확인할 수 있습니다. 예: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

라이브러리가 **바이너리와 동일한 인증서로 서명된 경우에도** 로드할 수 있습니다.

이 기능을 어떻게 (악용)할 수 있는지와 제한 사항은 다음에서 확인하세요:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Dylib hijacking 공격을 수행할 때는 **앞서 설명한 Library Validation 제한 사항도 적용된다는 점을 기억하세요.**

Windows와 마찬가지로 macOS에서도 **dylib를 hijack**해 **애플리케이션이 임의 코드를 실행하도록** 할 수 있습니다. 일반 사용자 계정으로는 불가능할 수 있습니다. 라이브러리를 hijack하려고 `.app` 번들 내부에 파일을 쓰려면 TCC 권한이 필요할 수 있기 때문입니다.\
하지만 **macOS** 애플리케이션이 라이브러리를 **로드하는 방식은** Windows보다 **더 제한적**입니다. Malware 개발자는 이 기법을 여전히 **은밀성**을 위해 사용할 수 있지만, 이를 악용해 권한을 상승시키기는 훨씬 어렵습니다.

먼저 **MacOS 바이너리에서 로드할 라이브러리의 전체 경로를 지정하는 경우가 더 흔합니다**. 또한 **MacOS는 라이브러리를 찾을 때 $PATH의 폴더를 검색하지 않습니다**.

이 기능과 관련된 **코드의 주요 부분**은 `ImageLoader.cpp`의 **`ImageLoader::recursiveLoadLibraries`**에 있습니다.

macho 바이너리가 라이브러리를 로드하는 데 사용할 수 있는 헤더 Command는 **4가지**입니다.

- **`LC_LOAD_DYLIB`** command는 dylib를 로드하는 데 사용하는 일반적인 command입니다.
- **`LC_LOAD_WEAK_DYLIB`** command는 앞선 command와 유사하지만, dylib를 찾지 못해도 오류 없이 실행을 계속합니다.
- **`LC_REEXPORT_DYLIB`** command는 다른 라이브러리의 심볼을 프록시하거나 재노출합니다.
- **`LC_LOAD_UPWARD_DYLIB`** command는 두 라이브러리가 서로 의존할 때 사용됩니다(이를 _upward dependency_라고 합니다).

하지만 dylib hijacking에는 **2가지 유형**이 있습니다.

- **Missing weak linked libraries**: 애플리케이션이 **LC_LOAD_WEAK_DYLIB**로 설정된, 존재하지 않는 라이브러리를 로드하려고 한다는 뜻입니다. 그러면 **공격자가 예상 경로에 dylib를 배치할 경우 해당 dylib가 로드됩니다**.
  - 링크가 "weak"하다는 것은 라이브러리를 찾지 못해도 애플리케이션이 계속 실행된다는 뜻입니다.
  - 관련 **코드**는 `ImageLoaderMachO.cpp`의 `ImageLoaderMachO::doGetDependentLibraries` 함수에 있습니다. `LC_LOAD_WEAK_DYLIB`가 true인 경우에만 `lib->required`가 `false`가 됩니다.
  - 바이너리에서 **weak linked libraries**를 찾으려면 다음 명령을 사용하세요(아래에 hijacking 라이브러리를 만드는 예제가 있습니다).
    - ```bash
      otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
      cmdsize 56
      name /var/tmp/lib/libUtl.1.dylib (offset 24)
      time stamp 2 Wed Jun 21 12:23:31 1969
      current version 1.0.0
      compatibility version 1.0.0
      ```
- **Configured with @rpath**: Mach-O binaries can have the commands **`LC_RPATH`** and **`LC_LOAD_DYLIB`**. Base on the **values** of those commands, **libraries** are going to be **loaded** from **different directories**.
  - **`LC_RPATH`** contains the paths of some folders used to load libraries by the binary.
  - **`LC_LOAD_DYLIB`** contains the path to specific libraries to load. These paths can contain **`@rpath`**, which will be **replaced** by the values in **`LC_RPATH`**. If there are several paths in **`LC_RPATH`** everyone will be used to search the library to load. Example:
    - If **`LC_LOAD_DYLIB`** contains `@rpath/library.dylib` and **`LC_RPATH`** contains `/application/app.app/Contents/Framework/v1/` and `/application/app.app/Contents/Framework/v2/`. Both folders are going to be used to load `library.dylib`**.** If the library doesn't exist in `[...]/v1/` and attacker could place it there to hijack the load of the library in `[...]/v2/` as the order of paths in **`LC_LOAD_DYLIB`** is followed.
  - **Find rpath paths and libraries** in binaries with: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Is the **path** to the directory containing the **main executable file**.
>
> **`@loader_path`**: Is the **path** to the **directory** containing the **Mach-O binary** which contains the load command.
>
> - When used in an executable, **`@loader_path`** is effectively the **same** as **`@executable_path`**.
> - When used in a **dylib**, **`@loader_path`** gives the **path** to the **dylib**.

The way to **escalate privileges** abusing this functionality would be in the rare case that an **application** being executed **by** **root** is **looking** for some **library in some folder where the attacker has write permissions.**

> [!TIP]
> A nice **scanner** to find **missing libraries** in applications is [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) or a [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> A nice **report with technical details** about this technique can be found [**here**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Remember that **previous Library Validation restrictions also apply** to perform Dlopen hijacking attacks.

From **`man dlopen`**:

- When path **does not contain a slash character** (i.e. it is just a leaf name), **dlopen() will do searching**. If **`$DYLD_LIBRARY_PATH`** was set at launch, dyld will first **look in that director**y. Next, if the calling mach-o file or the main executable specify an **`LC_RPATH`**, then dyld will **look in those** directories. Next, if the process is **unrestricted**, dyld will search in the **current working directory**. Lastly, for old binaries, dyld will try some fallbacks. If **`$DYLD_FALLBACK_LIBRARY_PATH`** was set at launch, dyld will search in **those directories**, otherwise, dyld will look in **`/usr/local/lib/`** (if the process is unrestricted), and then in **`/usr/lib/`** (this info was taken from **`man dlopen`**).
  1. `$DYLD_LIBRARY_PATH`
  2. `LC_RPATH`
  3. `CWD`(if unrestricted)
  4. `$DYLD_FALLBACK_LIBRARY_PATH`
  5. `/usr/local/lib/` (if unrestricted)
  6. `/usr/lib/`

> [!CAUTION]
> If no slashes in the name, there would be 2 ways to do an hijacking:
>
> - If any **`LC_RPATH`** is **writable** (but signature is checked, so for this you also need the binary to be unrestricted)
> - If the binary is **unrestricted** and then it's possible to load something from the CWD (or abusing one of the mentioned env variables)

- When path **looks like a framework** path (e.g. `/stuff/foo.framework/foo`), if **`$DYLD_FRAMEWORK_PATH`** was set at launch, dyld will first look in that directory for the **framework partial path** (e.g. `foo.framework/foo`). Next, dyld will try the **supplied path as-is** (using current working directory for relative paths). Lastly, for old binaries, dyld will try some fallbacks. If **`$DYLD_FALLBACK_FRAMEWORK_PATH`** was set at launch, dyld will search those directories. Otherwise, it will search **`/Library/Frameworks`** (on macOS if process is unrestricted), then **`/System/Library/Frameworks`**.
  1. `$DYLD_FRAMEWORK_PATH`
  2. supplied path (using current working directory for relative paths if unrestricted)
  3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
  4. `/Library/Frameworks` (if unrestricted)
  5. `/System/Library/Frameworks`

> [!CAUTION]
> If a framework path, the way to hijack it would be:
>
> - If the process is **unrestricted**, abusing the **relative path from CWD** the mentioned env variables (even if it's not said in the docs if the process is restricted DYLD\_\* env vars are removed)

- When path **contains a slash but is not a framework path** (i.e. a full path or a partial path to a dylib), dlopen() first looks in (if set) in **`$DYLD_LIBRARY_PATH`** (with leaf part from path ). Next, dyld **tries the supplied path** (using current working directory for relative paths (but only for unrestricted processes)). Lastly, for older binaries, dyld will try fallbacks. If **`$DYLD_FALLBACK_LIBRARY_PATH`** was set at launch, dyld will search in those directories, otherwise, dyld will look in **`/usr/local/lib/`** (if the process is unrestricted), and then in **`/usr/lib/`**.
  1. `$DYLD_LIBRARY_PATH`
  2. supplied path (using current working directory for relative paths if unrestricted)
  3. `$DYLD_FALLBACK_LIBRARY_PATH`
  4. `/usr/local/lib/` (if unrestricted)
  5. `/usr/lib/`

> [!CAUTION]
> If slashes in the name and not a framework, the way to hijack it would be:
>
> - If the binary is **unrestricted** and then it's possible to load something from the CWD or `/usr/local/lib` (or abusing one of the mentioned env variables)

> [!TIP]
> Note: There are **no** configuration files to **control dlopen searching**.
>
> Note: If the main executable is a **set\[ug]id binary or codesigned with entitlements**, then **all environment variables are ignored**, and only a full path can be used ([check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) for more detailed info)
>
> Note: Apple platforms use "universal" files to combine 32-bit and 64-bit libraries. This means there are **no separate 32-bit and 64-bit search paths**.
>
> Note: On Apple platforms most OS dylibs are **combined into the dyld cache** and do not exist on disk. Therefore, calling **`stat()`** to preflight if an OS dylib exists **won't work**. However, **`dlopen_preflight()`** uses the same steps as **`dlopen()`** to find a compatible mach-o file.

**Check paths**

Lets check all the options with the following code:

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

If you compile and execute it you can see **where each library was unsuccessfully searched for**. Also, you could **filter the FS logs**:

```bash
sudo fs_usage | grep "dlopentest"
```

## Relative Path Hijacking

If a **privileged binary/app** (like a SUID or some binary with powerful entitlements) is **loading a relative path** library (for example using `@executable_path` or `@loader_path`) and has **Library Validation disabled**, it could be possible to move the binary to a location where the attacker could **modify the relative path loaded library**, and abuse it to inject code on the process.

## Prune `DYLD_*` env variables

Older `dyld` releases (`dyld2.cpp`) decided this in-process with `issetugid()`, `hasRestrictedSegment()` and `csops(CS_OPS_STATUS)`. In **current `dyld` the decision is delegated to AMFI**, and the code lives in `ProcessConfig::Security::Security()` in `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>

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

Two things are worth extracting from this:

- Pruning only happens on **macOS / Mac Catalyst / DriverKit** — and only when AMFI granted **none** of `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- The AMFI query is fed the executable's own properties:

```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
                                   proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```

where `isRestricted()` is literally the `__RESTRICT` segment check (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>

```cpp
bool UnsafeHeader::isRestricted() const
{
    return this->hasSection("__RESTRICT", "__restrict");
}
```

`pruneEnvVars()` then strips **every** variable whose name begins with `DYLD_` and slides the `apple[]` parameters down, so the children of a restricted process don't inherit them either:

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
> Practical consequence: **`DYLD_*` is pruned when the process is restricted** — setuid/setgid, a `__RESTRICT/__restrict` section, or hardened-runtime/entitled binaries that AMFI refuses to grant the path/print flags to. If instead the process only has **library validation** (`CS_REQUIRE_LV`), the variables survive but the inserted dylib must be signed by the **same Team ID** (or by Apple), so you need one of the library-validation-disabling entitlements to actually land code.

Because the decision is now AMFI's, the fastest way to know what a given binary will get is to look at what AMFI keys off — entitlements and signing flags — rather than at `dyld` itself:

```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
  egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```

## Check Restrictions

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

### Section `__RESTRICT` with segment `__restrict`

```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```

### Hardened runtime

Create a new certificate in the Keychain and use it to sign the binary:

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
> Note that even if there are binaries signed with flags **`0x0(none)`**, they can get the **`CS_RESTRICT`** flag dynamically when executed and therefore this technique won't work in them.
>
> You can check if a proc has this flag with (get [**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> and then check if the flag 0x800 is enabled.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup and library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
