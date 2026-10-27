# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Mã nguồn của **dyld là mã nguồn mở** và có thể tìm thấy tại [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) và tải xuống dưới dạng tar bằng **URL chẳng hạn như** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Xem cách Dyld tải thư viện bên trong các binary tại:


{{#ref}}
macos-dyld-process.md
{{#endref}}

Xem thêm: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

## **DYLD_INSERT_LIBRARIES**

Tương tự như [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Biến này cho phép chỉ định một tiến trình sẽ được chạy để tải một thư viện cụ thể từ một đường dẫn (nếu biến môi trường được bật)<sup>[[4]](#references)</sup>

Kỹ thuật này cũng có thể được **dùng như một kỹ thuật ASEP**, vì mỗi ứng dụng được cài đặt đều có một plist tên là "Info.plist", cho phép **gán các biến môi trường** bằng khóa `LSEnvironmental`.

> [!TIP]
> Kể từ năm 2012, **Apple đã giảm đáng kể khả năng** của **`DYLD_INSERT_LIBRARIES`**. Một tiến trình được xem là **bị hạn chế** — khi đó `dyld` xóa mọi biến `DYLD_*` khỏi môi trường của tiến trình — nếu thỏa mãn bất kỳ điều kiện nào sau đây:
>
> - Binary có `setuid/setgid`
> - Mach-O có section **`__RESTRICT/__restrict`**
> - Binary được ký bằng hardened runtime và AMFI không cấp quyền "path/print variables", tức là binary không có [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Kiểm tra **entitlements** của binary bằng: `codesign -dv --entitlements :- </path/to/bin>`
>
> Trong `dyld` hiện tại, quyết định này không còn do riêng `dyld` đưa ra: `ProcessConfig::Security::Security()` truy vấn **AMFI** qua `amfi_check_dyld_policy_self()` rồi gọi `pruneEnvVars()`. Phần mã chính xác sẽ được phân tích trong [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) bên dưới.

### Library Validation

Ngay cả khi binary cho phép biến môi trường **`DYLD_INSERT_LIBRARIES`**, nó sẽ không tải thư viện tùy chỉnh nếu xác thực chữ ký của thư viện.

Để tải thư viện tùy chỉnh, binary cần có **một trong các entitlements sau**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

hoặc binary **không được** có **hardened runtime flag** hay **library validation flag**.

Bạn có thể kiểm tra binary có **hardened runtime** hay không bằng `codesign --display --verbose <bin>`, xem runtime flag trong **`CodeDirectory`**, ví dụ: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Bạn cũng có thể tải một thư viện nếu thư viện đó **được ký bằng cùng chứng chỉ với binary**.

Xem ví dụ về cách (lạm dụng) kỹ thuật này và kiểm tra các giới hạn tại:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Hãy nhớ rằng **các giới hạn Library Validation đã nêu ở trên cũng áp dụng** cho các cuộc tấn công Dylib hijacking.

Tương tự Windows, trên macOS, bạn có thể **chiếm quyền dylib** để khiến **ứng dụng thực thi mã tùy ý**. Việc này có thể không khả thi từ tài khoản người dùng thông thường, vì ghi vào bên trong một bundle `.app` để chiếm quyền thư viện có thể cần quyền TCC.\
Tuy nhiên, cách các ứng dụng **macOS** **tải** thư viện **bị hạn chế hơn** so với Windows. Nhà phát triển malware vẫn có thể dùng kỹ thuật này để **ẩn mình**, nhưng khả năng lạm dụng nó để leo thang đặc quyền thấp hơn nhiều.

Trước hết, việc **binary MacOS chỉ định đường dẫn đầy đủ** đến thư viện cần tải là **phổ biến hơn**. Thứ hai, **MacOS không bao giờ tìm kiếm** thư viện trong các thư mục thuộc **$PATH**.

Phần **chính** của **mã nguồn** liên quan đến chức năng này nằm trong **`ImageLoader::recursiveLoadLibraries`** ở `ImageLoader.cpp`.

Có **4 loại header Command** mà binary macho có thể dùng để tải thư viện:

- Command **`LC_LOAD_DYLIB`** là command thường dùng để tải dylib.
- Command **`LC_LOAD_WEAK_DYLIB`** hoạt động như command trước, nhưng nếu không tìm thấy dylib, quá trình thực thi vẫn tiếp tục mà không báo lỗi.
- Command **`LC_REEXPORT_DYLIB`** chuyển tiếp (hoặc tái xuất) các symbol từ một thư viện khác.
- Command **`LC_LOAD_UPWARD_DYLIB`** được dùng khi hai thư viện phụ thuộc lẫn nhau (được gọi là _upward dependency_).

Tuy nhiên, có **2 loại dylib hijacking**:

- **Missing weak linked libraries**: Nghĩa là ứng dụng sẽ cố tải một thư viện không tồn tại, được cấu hình bằng **LC_LOAD_WEAK_DYLIB**. Khi đó, **nếu kẻ tấn công đặt một dylib vào vị trí ứng dụng mong đợi, dylib đó sẽ được tải**.
  - Việc liên kết là "weak" có nghĩa là ứng dụng vẫn tiếp tục chạy ngay cả khi không tìm thấy thư viện.
  - **Mã nguồn liên quan** nằm trong hàm `ImageLoaderMachO::doGetDependentLibraries` của `ImageLoaderMachO.cpp`, nơi `lib->required` chỉ là `false` khi `LC_LOAD_WEAK_DYLIB` là true.
  - **Tìm các thư viện weak linked** trong binary bằng lệnh sau (bên dưới có ví dụ về cách tạo thư viện hijacking):
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
