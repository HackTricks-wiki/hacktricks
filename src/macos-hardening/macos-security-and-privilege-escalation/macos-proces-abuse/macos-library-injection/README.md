# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld 的代码是开源的**，可以在 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) 找到，也可以使用**类似以下的 URL** 下载 tar 文件：[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

查看 Dyld 如何在二进制文件中加载 libraries：

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

这类似于 [**Linux 上的 LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload)。它允许指定一个即将运行的 process，使其从某个路径加载特定的 library（前提是启用了该环境变量）。

该技术也可以作为 **ASEP technique** 使用，因为每个已安装的应用程序都有一个名为 "Info.plist" 的 plist，可以通过名为 `LSEnvironmental` 的 key 来**分配环境变量**。

> [!TIP]
> 自 2012 年以来，**Apple 大幅削弱了** **`DYLD_INSERT_LIBRARIES`** 的能力。当满足以下任一条件时，process 会被视为 **restricted** ——随后 `dyld` 会从其环境中删除所有 `DYLD_*` 变量：
>
> - 二进制文件是 `setuid/setgid`
> - Mach-O 包含 **`__RESTRICT/__restrict`** section
> - 二进制文件使用 hardened runtime 签名，且 AMFI 未授予它 "path/print variables" 权限，即缺少 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[3]</sup>
>   - 使用以下命令检查二进制文件的 **entitlements**：`codesign -dv --entitlements :- </path/to/bin>`
>
> 在当前版本的 `dyld` 中，这已不再完全由 `dyld` 单独决定：`ProcessConfig::Security::Security()` 会通过 `amfi_check_dyld_policy_self()` 询问 **AMFI**，然后调用 `pruneEnvVars()`。下面的 [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) 会详细介绍相关代码。

### Library Validation

即使二进制文件允许使用 **`DYLD_INSERT_LIBRARIES`** 环境变量，如果二进制文件会检查待加载 library 的签名，它也不会加载自定义 library。

要加载自定义 library，二进制文件需要具备以下 **entitlements** 之一：

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

或者，二进制文件**不应具有** **hardened runtime flag** 或 **library validation flag**。

可以通过 `codesign --display --verbose <bin>` 检查二进制文件是否启用了 **hardened runtime**，具体是在 **`CodeDirectory`** 中检查 runtime flag，例如：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

如果 library 使用与二进制文件相同的 certificate 签名，也可以加载该 library。

以下文档中有如何（滥）用该功能以及检查限制条件的示例：

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> 记住，执行 Dylib hijacking attacks 时，**之前介绍的 Library Validation restrictions 也同样适用**。

和 Windows 一样，在 MacOS 中也可以 **hijack dylibs**，使**应用程序** **执行** **任意** **代码**（不过，对于普通用户来说，这实际上可能无法实现，因为可能需要 TCC permission 才能写入 `.app` bundle 并 hijack library）。\
但是，**MacOS** 应用程序**加载** libraries 的方式比 Windows **更加受限**。这意味着 **malware** developers 仍然可以将此技术用于**隐蔽性**，但利用它来**提升权限**的可能性要低得多。

首先，**MacOS binaries 更常见的情况是指定要加载 libraries 的完整路径**。其次，**MacOS 从不在** **$PATH** 的文件夹中**搜索** libraries。

与该功能相关的**代码**主要位于 `ImageLoader.cpp` 的 **`ImageLoader::recursiveLoadLibraries`** 中。

macho binary 可以使用 **4 种不同的 header Commands** 来加载 libraries：

- **`LC_LOAD_DYLIB`** command 是加载 dylib 的常用 command。
- **`LC_LOAD_WEAK_DYLIB`** command 的工作方式与前一个相同，但如果找不到 dylib，execution 会继续进行且不会报错。
- **`LC_REEXPORT_DYLIB`** command 会代理（或重新导出）另一个 library 中的 symbols。
- **`LC_LOAD_UPWARD_DYLIB`** command 用于两个 libraries 相互依赖的情况（这称为 _upward dependency_）。

不过，dylib hijacking 有 **2 种类型**：

- **Missing weak linked libraries**：这意味着应用程序会尝试加载一个不存在、但通过 **LC_LOAD_WEAK_DYLIB** 配置的 library。之后，**如果 attacker 将 dylib 放置在预期位置，它就会被加载**。
- link 是 "weak" 意味着，即使找不到 library，应用程序也会继续运行。
- 相关**代码**位于 `ImageLoader.cpp` 的 `ImageLoaderMachO::doGetDependentLibraries` function 中，只有当 `LC_LOAD_WEAK_DYLIB` 为 true 时，`lib->required` 才是 `false`。
- 使用以下命令在 binaries 中**查找 weak linked libraries**（后面会有如何创建 hijacking libraries 的示例）：
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**：Mach-O binaries 可以包含 **`LC_RPATH`** 和 **`LC_LOAD_DYLIB`** commands。根据这些 commands 的**值**，libraries 会从**不同目录**中**加载**。
- **`LC_RPATH`** 包含 binary 用于加载 libraries 的若干文件夹路径。
- **`LC_LOAD_DYLIB`** 包含要加载的特定 libraries 的路径。这些路径可以包含 **`@rpath`**，它会被 **`LC_RPATH`** 中的值替换。如果 **`LC_RPATH`** 中有多个路径，则会逐一用于搜索要加载的 library。示例：
- 如果 **`LC_LOAD_DYLIB`** 包含 `@rpath/library.dylib`，而 **`LC_RPATH`** 包含 `/application/app.app/Contents/Framework/v1/` 和 `/application/app.app/Contents/Framework/v2/`，则两个文件夹都会用于加载 `library.dylib`**。** 如果 library 不存在于 `[...]/v1/` 中，而 attacker 可以在那里放置 library，就能够 hijack 对 `[...]/v2/` 中 library 的加载，因为会遵循 **`LC_LOAD_DYLIB`** 中的路径顺序。
- 使用以下命令在 binaries 中**查找 rpath paths 和 libraries**：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**：是包含**主 executable 文件**的目录的**路径**。
>
> **`@loader_path`**：是包含 load command 的 **Mach-O binary** 所在**目录的路径**。
>
> - 在 executable 中使用时，**`@loader_path`** 实际上与 **`@executable_path`** 相同。
> - 在 **dylib** 中使用时，**`@loader_path`** 提供的是 **dylib** 所在的**路径**。

利用此功能进行**权限提升**的情况非常少见：某个由 **root** **执行**的**应用程序**正在某个 attacker 具有写权限的文件夹中**寻找**某个 library。

> [!TIP]
> 用于在应用程序中查找**缺失 libraries** 的优秀 **scanner** 是 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)，或者其 [**CLI version**](https://github.com/pandazheng/DylibHijack)。\
> 关于该技术及其技术细节的一份优秀**报告**可以在[**这里**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)找到。

**Example**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> 记住，执行 Dlopen hijacking attacks 时，**之前介绍的 Library Validation restrictions 也同样适用**。

来自 **`man dlopen`**：

- 当路径**不包含斜杠字符**（即只有 leaf name）时，**dlopen() 会进行搜索**。如果启动时设置了 **`$DYLD_LIBRARY_PATH`**，dyld 会首先**在该目录中查找**。接下来，如果调用方 mach-o file 或 main executable 指定了 **`LC_RPATH`**，dyld 会**在这些目录中查找**。然后，如果 process 是 **unrestricted**，dyld 会在**当前工作目录**中搜索。最后，对于旧 binaries，dyld 会尝试一些 fallback。如果启动时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 会在**这些目录中**搜索；否则，dyld 会先在 **`/usr/local/lib/`** 中查找（如果 process 是 unrestricted），然后在 **`/usr/lib/`** 中查找（该信息来自 **`man dlopen`**）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（如果 unrestricted）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（如果 unrestricted）
6. `/usr/lib/`

> [!CAUTION]
> 如果名称中没有斜杠，则有 2 种 hijacking 方式：
>
> - 如果某个 **`LC_RPATH`** **可写**（但会检查签名，因此还需要 binary 是 unrestricted）
> - 如果 binary 是 **unrestricted**，则可以从 CWD 加载内容（或者滥用上述环境变量之一）

- 当路径**看起来像 framework** path（例如 `/stuff/foo.framework/foo`）时，如果启动时设置了 **`$DYLD_FRAMEWORK_PATH`**，dyld 会首先在该目录中查找 framework 的**部分路径**（例如 `foo.framework/foo`）。接下来，dyld 会尝试**原样使用提供的路径**（相对路径使用当前工作目录）。最后，对于旧 binaries，dyld 会尝试一些 fallback。如果启动时设置了 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**，dyld 会搜索这些目录。否则，它会先搜索 **`/Library/Frameworks`**（在 macOS 上，如果 process 是 unrestricted），然后搜索 **`/System/Library/Frameworks`**。
1. `$DYLD_FRAMEWORK_PATH`
2. 提供的路径（如果 unrestricted，相对路径使用当前工作目录）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（如果 unrestricted）
5. `/System/Library/Frameworks`

> [!CAUTION]
> 如果是 framework path，hijack 方式是：
>
> - 如果 process 是 **unrestricted**，则滥用从 CWD 开始的**相对路径**或上述环境变量（文档没有说明 restricted process 会移除 DYLD\_\* env vars，但实际情况如此）

- 当路径**包含斜杠但不是 framework path**（即 dylib 的完整路径或部分路径）时，dlopen() 首先在（如果已设置）**`$DYLD_LIBRARY_PATH`** 中查找（使用 path 中的 leaf part）。接下来，dyld **尝试提供的路径**（相对路径使用当前工作目录，但仅适用于 unrestricted processes）。最后，对于旧 binaries，dyld 会尝试 fallback。如果启动时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 会在这些目录中搜索；否则，dyld 会先在 **`/usr/local/lib/`** 中查找（如果 process 是 unrestricted），然后在 **`/usr/lib/`** 中查找。
1. `$DYLD_LIBRARY_PATH`
2. 提供的路径（如果 unrestricted，相对路径使用当前工作目录）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（如果 unrestricted）
5. `/usr/lib/`

> [!CAUTION]
> 如果名称中有斜杠且不是 framework，hijack 方式是：
>
> - 如果 binary 是 **unrestricted**，则可以从 CWD 或 `/usr/local/lib` 加载内容（或者滥用上述环境变量之一）

> [!TIP]
> 注意：没有用于**控制 dlopen 搜索**的 configuration files。
>
> 注意：如果 main executable 是 **set\[ug]id binary** 或使用 entitlements 签名，则**所有环境变量都会被忽略**，只能使用完整路径（有关更多详细信息，请参阅 [check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)）
>
> 注意：Apple platforms 使用 "universal" files 来组合 32-bit 和 64-bit libraries。这意味着不存在独立的 32-bit 和 64-bit search paths。
>
> 注意：在 Apple platforms 上，大多数 OS dylibs 都被**合并到 dyld cache** 中，并不存在于磁盘上。因此，调用 **`stat()`** 预先检查 OS dylib 是否存在**不会生效**。但是，**`dlopen_preflight()`** 使用与 **`dlopen()`** 相同的步骤来查找兼容的 mach-o file。

**Check paths**

让我们使用以下代码检查所有选项：
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
如果编译并执行它，你可以看到**每个库搜索失败的位置**。此外，你还可以**过滤 FS 日志**：
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

如果一个 **privileged binary/app**（例如 SUID 或具有强大 entitlements 的某个 binary）正在 **loading a relative path** library（例如使用 `@executable_path` 或 `@loader_path`），并且已禁用 **Library Validation**，那么攻击者可能可以将该 binary 移动到一个能够 **modify the relative path loaded library** 的位置，并利用它向该进程注入代码。

## Prune `DYLD_*` env variables

较旧版本的 `dyld`（`dyld2.cpp`）会通过 `issetugid()`、`hasRestrictedSegment()` 和 `csops(CS_OPS_STATUS)` 在进程内做出此决定。在**当前版本的 `dyld` 中，该决定由 AMFI 委托处理**，相关代码位于 `dyld/DyldProcessConfig.cpp` 中的 `ProcessConfig::Security::Security()`：<sup>[1]</sup>
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
从中有两点值得提取：

- 仅在 **macOS / Mac Catalyst / DriverKit** 上执行 pruning ——并且仅当 AMFI 未授予 `allowEnvVarsPrint`、`allowEnvVarsPath`、`allowEnvVarsSharedCache` 中的任何一项时。
- AMFI 查询使用的是可执行文件自身的属性：
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
其中，`isRestricted()` 实际上就是对 `__RESTRICT` segment 的检查（`mach_o/UnsafeHeader.cpp`）：<sup>[2]</sup>
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
> 实际影响：当进程受到限制时，`DYLD_*` 会被清除——例如 setuid/setgid、包含 `__RESTRICT/__restrict` section，或 AMFI 拒绝授予 path/print flags 的 hardened-runtime/entitled binaries。若进程仅启用了 **library validation**（`CS_REQUIRE_LV`），这些变量会保留，但插入的 dylib 必须由**相同的 Team ID**（或 Apple）签名，因此需要使用某个可禁用 library validation 的 entitlement，代码才能实际注入。

由于现在由 AMFI 作出决定，判断给定 binary 将获得什么的最快方法，是查看 AMFI 依赖的内容——entitlements 和 signing flags——而不是直接查看 `dyld`：
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## 检查限制

### SUID 和 SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### 包含 segment `__restrict` 的 Section `__RESTRICT`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

在 Keychain 中创建一个新证书，并使用它对二进制文件进行签名：
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
> 请注意，即使存在使用 **`0x0(none)`** 标志签名的二进制文件，它们也可能在执行时动态获得 **`CS_RESTRICT`** 标志，因此此技术无法在这些二进制文件中生效。
>
> 你可以使用以下命令检查某个进程是否具有此标志（获取 [**csops here**](https://github.com/axelexic/CSOps)）：
>
> ```bash
> csops -status <pid>
> ```
>
> 然后检查标志 0x800 是否已启用。

## 参考资料

- [1] [dyld — `dyld/DyldProcessConfig.cpp`（`ProcessConfig::Security`、`getAMFI`、`pruneEnvVars`）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp`（`isRestricted()` / `__RESTRICT` 检查）](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp`（进程启动和库插入）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
