# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld 的代码是开源的**，可以在 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) 找到，也可以使用**类似以下的 URL** 下载 tar 包：[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

查看 Dyld 如何在二进制文件中加载 libraries：


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

这类似于 [**Linux 上的 LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload)。它允许指定一个即将运行的 process，使其从某个路径加载特定的 library（前提是启用了该环境变量）<sup>[[4]](#references)</sup>

此技术也可以**作为 ASEP technique 使用**，因为每个已安装的 application 都有一个名为 "Info.plist" 的 plist，其中可以使用名为 `LSEnvironmental` 的 key **分配环境变量**。

> [!TIP]
> 自 2012 年以来，**Apple 大幅削弱了** **`DYLD_INSERT_LIBRARIES`** 的能力。当满足以下任一条件时，一个 process 会被视为 **restricted**——此时 `dyld` 会从其环境中删除所有 `DYLD_*` 变量：
>
> - binary 是 `setuid/setgid`
> - Mach-O 包含 **`__RESTRICT/__restrict`** section
> - binary 使用 hardened runtime 签名，且 AMFI 没有授予它 "path/print variables" 权限，即缺少 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - 使用以下命令检查 binary 的 **entitlements**：`codesign -dv --entitlements :- </path/to/bin>`
>
> 在当前的 `dyld` 中，这不再仅由 `dyld` 决定：`ProcessConfig::Security::Security()` 会通过 `amfi_check_dyld_policy_self()` 询问 **AMFI**，然后调用 `pruneEnvVars()`。下面的 [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) 会详细分析具体代码。

### Library Validation

即使 binary 允许使用 **`DYLD_INSERT_LIBRARIES`** 环境变量，如果 binary 会检查待加载 library 的签名，它也不会加载自定义 library。

要加载自定义 library，binary 需要具备以下 **entitlements** 之一：

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

或者 binary **不应具有** **hardened runtime flag** 或 **library validation flag**。

可以使用 `codesign --display --verbose <bin>` 检查 binary 是否具有 **hardened runtime**，具体是在 **`CodeDirectory`** 中检查 runtime flag，例如：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

如果 library 与 binary 使用相同的 certificate 签名，也可以加载该 library。

在以下位置查看如何（滥用）此功能，以及如何检查限制：


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> 请记住，之前介绍的 Library Validation restrictions 同样适用于执行 Dylib hijacking attacks。

与 Windows 一样，在 MacOS 中也可以**劫持 dylibs**，使 **applications** **执行** **任意** **code**（实际上，普通 user 可能无法做到，因为你可能需要 TCC permission 才能写入 `.app` bundle 并劫持 library）。\
不过，**MacOS** applications **加载** libraries 的方式比 Windows 更受限制。这意味着 **malware** developers 仍然可以使用此 technique 来实现 **stealth**，但利用它来**提升 privileges 的可能性要低得多**。

首先，**MacOS binaries 指定待加载 libraries 的完整路径**更为常见。其次，**MacOS 从不在** **$PATH** 的 folders 中搜索 libraries。

与此功能相关的**代码**主要位于 `ImageLoader.cpp` 的 **`ImageLoader::recursiveLoadLibraries`** 中。

macho binary 可以使用 **4 种不同的 header Commands** 来加载 libraries：

- **`LC_LOAD_DYLIB`** command 是加载 dylib 的常用 command。
- **`LC_LOAD_WEAK_DYLIB`** command 的工作方式与前一个相同，但如果找不到 dylib，execution 会继续且不会报错。
- **`LC_REEXPORT_DYLIB`** command 会代理（或重新导出）另一个 library 中的 symbols。
- **`LC_LOAD_UPWARD_DYLIB`** command 用于两个 libraries 相互依赖的情况（这称为 _upward dependency_）。

不过，dylib hijacking 有 **2 种类型**：

- **Missing weak linked libraries**：这意味着 application 会尝试加载一个不存在的 library，该 library 通过 **LC_LOAD_WEAK_DYLIB** 配置。之后，**如果 attacker 将 dylib 放置在预期位置，它就会被加载**。
- link 是 "weak" 意味着，即使找不到 library，application 仍会继续运行。
- 相关**代码**位于 `ImageLoader.cpp` 的 `ImageLoaderMachO::doGetDependentLibraries` function 中，只有当 `LC_LOAD_WEAK_DYLIB` 为 true 时，`lib->required` 才是 `false`。
- 使用以下命令在 binaries 中**查找 weak linked libraries**（稍后会提供如何创建 hijacking libraries 的示例）：
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**：Mach-O binaries 可以包含 **`LC_RPATH`** 和 **`LC_LOAD_DYLIB`** commands。根据这些 commands 的**值**，libraries 将从**不同目录**中加载。
- **`LC_RPATH`** 包含 binary 用于加载 libraries 的某些 folders 的 paths。
- **`LC_LOAD_DYLIB`** 包含要加载的特定 libraries 的 path。这些 paths 可以包含 **`@rpath`**，它会被 **`LC_RPATH`** 中的值替换。如果 **`LC_RPATH`** 中有多个 paths，则会使用每个 path 搜索要加载的 library。示例：
- 如果 **`LC_LOAD_DYLIB`** 包含 `@rpath/library.dylib`，而 **`LC_RPATH`** 包含 `/application/app.app/Contents/Framework/v1/` 和 `/application/app.app/Contents/Framework/v2/`，则两个 folders 都会用于加载 `library.dylib`**。**如果 library 不存在于 `[...]/v1/` 中，且 attacker 可以将其放在那里，就能劫持原本从 `[...]/v2/` 加载的 library，因为会遵循 **`LC_LOAD_DYLIB`** 中 paths 的顺序。
- 使用以下命令在 binaries 中**查找 rpath paths 和 libraries**：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**：包含**主 executable file** 的 directory 的 **path**。
>
> **`@loader_path`**：包含 load command 的 **Mach-O binary** 所在 **directory** 的 **path**。
>
> - 在 executable 中使用时，**`@loader_path`** 实际上与 **`@executable_path`** 相同。
> - 在 **dylib** 中使用时，**`@loader_path`** 给出该 **dylib** 的 **path**。

利用此功能来**提升 privileges** 的方式，是在极少见的情况下，某个由 **root** **执行**的 **application** 正在**查找**一个位于 attacker 具有写权限的 folder 中的 **library**。

> [!TIP]
> 一个用于查找 applications 中**缺失 libraries** 的优秀 **scanner** 是 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)，或者使用其 [**CLI version**](https://github.com/pandazheng/DylibHijack)。\
> 关于此 technique 的一份优秀、包含 technical details 的**报告**可以在[**这里**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)找到。

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> 请记住，之前介绍的 Library Validation restrictions 同样适用于执行 Dlopen hijacking attacks。

根据 **`man dlopen`**：

- 当 path **不包含 slash character**（即它只是一个 leaf name）时，**dlopen() 会进行搜索**。如果在 launch 时设置了 **`$DYLD_LIBRARY_PATH`**，dyld 会首先在该 director y 中查找。接下来，如果调用方 mach-o file 或 main executable 指定了 **`LC_RPATH`**，dyld 会在这些 directories 中查找。然后，如果该 process 是 **unrestricted**，dyld 会在当前 working directory 中搜索。最后，对于旧 binaries，dyld 会尝试一些 fallbacks。如果在 launch 时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 会在**这些 directories** 中搜索；否则，dyld 会查找 **`/usr/local/lib/`**（如果 process 是 unrestricted），然后查找 **`/usr/lib/`**（此信息来自 **`man dlopen`**）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（如果 unrestricted）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（如果 unrestricted）
6. `/usr/lib/`

> [!CAUTION]
> 如果 name 中没有 slashes，则有 2 种 hijacking 方式：
>
> - 如果任何 **`LC_RPATH`** 可写（但会检查 signature，因此还需要 binary 为 unrestricted）
> - 如果 binary 是 **unrestricted**，那么就可以从 CWD 加载内容（或滥用上述某个环境变量）

- 当 path **看起来像 framework path**（例如 `/stuff/foo.framework/foo`）时，如果在 launch 时设置了 **`$DYLD_FRAMEWORK_PATH`**，dyld 会首先在该 directory 中查找 **framework partial path**（例如 `foo.framework/foo`）。接下来，dyld 会尝试**原样使用 supplied path**（relative paths 使用 current working directory）。最后，对于旧 binaries，dyld 会尝试一些 fallbacks。如果在 launch 时设置了 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**，dyld 会在这些 directories 中搜索。否则，它会先搜索 **`/Library/Frameworks`**（在 macOS 上，如果 process 是 unrestricted），然后搜索 **`/System/Library/Frameworks`**。
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path（如果是 relative paths，则使用 current working directory）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（如果 unrestricted）
5. `/System/Library/Frameworks`

> [!CAUTION]
> 如果是 framework path，进行 hijack 的方式是：
>
> - 如果 process 是 **unrestricted**，则滥用来自 CWD 的 **relative path** 或上述环境变量（文档没有说明这一点，但如果 process 是 restricted，DYLD\_\* env vars 会被移除）

- 当 path **包含 slash 但不是 framework path**（即 dylib 的 full path 或 partial path）时，dlopen() 首先查找（如果已设置） **`$DYLD_LIBRARY_PATH`**（使用 path 的 leaf 部分）。接下来，dyld **尝试 supplied path**（relative paths 使用 current working directory，但仅适用于 unrestricted processes）。最后，对于旧 binaries，dyld 会尝试 fallbacks。如果在 launch 时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 会在这些 directories 中搜索；否则，dyld 会查找 **`/usr/local/lib/`**（如果 process 是 unrestricted），然后查找 **`/usr/lib/`**。
1. `$DYLD_LIBRARY_PATH`
2. supplied path（如果是 relative paths，则使用 current working directory；仅适用于 unrestricted）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（如果 unrestricted）
5. `/usr/lib/`

> [!CAUTION]
> 如果 name 中包含 slashes 且不是 framework，进行 hijack 的方式是：
>
> - 如果 binary 是 **unrestricted**，则可以从 CWD 或 `/usr/local/lib` 加载内容（或滥用上述某个环境变量）

> [!TIP]
> 注意：没有用于**控制 dlopen 搜索**的 configuration files。
>
> 注意：如果 main executable 是 **set\[ug]id binary** 或使用 entitlements 签名，则会忽略**所有环境变量**，并且只能使用 full path（有关更详细的信息，请查看 [check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)）
>
> 注意：Apple platforms 使用 "universal" files 来组合 32-bit 和 64-bit libraries。这意味着不存在单独的 32-bit 和 64-bit search paths。
>
> 注意：在 Apple platforms 上，大多数 OS dylibs 都被**合并到 dyld cache** 中，并不存在于磁盘上。因此，调用 **`stat()`** 预先检查 OS dylib 是否存在**不会生效**。但是，**`dlopen_preflight()`** 使用与 **`dlopen()`** 相同的步骤来查找兼容的 mach-o file。

**Check paths**

让我们使用以下 code 检查所有 options：
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
如果编译并执行它，你可以看到**每个 library 搜索失败的位置**。此外，你还可以**过滤 FS logs**：
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

如果一个 **privileged binary/app**（例如 SUID 或具有强大 entitlements 的某个 binary）正在 **loading a relative path** library（例如使用 `@executable_path` 或 `@loader_path`），并且禁用了 **Library Validation**，那么攻击者可能可以将该 binary 移动到一个能够 **modify the relative path loaded library** 的位置，并利用它向该进程注入代码。

## Prune `DYLD_*` env variables

较旧版本的 `dyld`（`dyld2.cpp`）会通过 `issetugid()`、`hasRestrictedSegment()` 和 `csops(CS_OPS_STATUS)` 在进程内决定这一点。在 **current `dyld` 中，该决定由 AMFI 委托处理**，相关代码位于 `dyld/DyldProcessConfig.cpp` 的 `ProcessConfig::Security::Security()` 中：<sup>[[1]](#references)</sup>
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
从中值得提取两点：

- 只有在 **macOS / Mac Catalyst / DriverKit** 上，并且 AMFI 未授予 `allowEnvVarsPrint`、`allowEnvVarsPath`、`allowEnvVarsSharedCache` 中的任何一项时，才会执行 Pruning。
- AMFI 查询使用的是可执行文件自身的属性：
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
其中 `isRestricted()` 实际上就是对 `__RESTRICT` segment 的检查（`mach_o/UnsafeHeader.cpp`）：<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` 随后会剥离名称以 `DYLD_` 开头的**所有**变量，并将 `apple[]` 参数向前移动，因此受限进程的子进程也不会继承这些变量：
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
> 实际影响：**当进程受到限制时，`DYLD_*` 会被清除** —— 例如 setuid/setgid、存在 `__RESTRICT/__restrict` section，或 hardened-runtime/entitled binaries 被 AMFI 拒绝授予 path/print flags。如果进程仅启用了 **library validation**（`CS_REQUIRE_LV`），这些变量会保留，但插入的 dylib 必须由**相同的 Team ID**（或 Apple）签名，因此需要使用某个禁用 library validation 的 entitlement，代码才能真正加载。

由于现在由 AMFI 做出决定，了解某个 binary 将获得什么的最快方法，是查看 AMFI 所依据的内容 —— entitlements 和 signing flags —— 而不是查看 `dyld` 本身：
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## 检查限制

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
### 包含 `__restrict` 段的 `__RESTRICT` 区段
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

在 Keychain 中创建一个新证书，并使用它为 binary 签名：
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
> 注意，即使存在使用 **`0x0(none)`** 标志签名的二进制文件，它们在执行时也可能动态获得 **`CS_RESTRICT`** 标志，因此此技术对它们不起作用。
>
> 你可以使用以下命令检查某个进程是否具有此标志（获取 [**csops here**](https://github.com/axelexic/CSOps)）：
>
> ```bash
> csops -status <pid>
> ```
>
> 然后检查是否启用了 0x800 标志。

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp`（`ProcessConfig::Security`、`getAMFI`、`pruneEnvVars`）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp`（`isRestricted()` / `__RESTRICT` 检查）](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp`（进程启动和库插入）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
