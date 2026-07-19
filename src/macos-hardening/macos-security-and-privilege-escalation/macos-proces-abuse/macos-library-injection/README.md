# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld 的代码是开源的**，可以在 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) 找到，也可以使用**类似以下的 URL** 下载 tar 文件：[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

查看 Dyld 如何在二进制文件中加载库：


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

这类似于 [**Linux 上的 LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload)。它允许指定一个即将运行的进程，使其从某个路径加载特定库（如果启用了该环境变量）。

该技术也可以**用作 ASEP 技术**，因为每个已安装的应用程序都有一个名为 "Info.plist" 的 plist，它允许使用名为 `LSEnvironmental` 的键来**分配环境变量**。

> [!TIP]
> 自 2012 年以来，**Apple 大幅削弱了** **`DYLD_INSERT_LIBRARIES`** 的能力。
>
> 查看代码并**检查 `src/dyld.cpp`**。在 **`pruneEnvironmentVariables`** 函数中可以看到，**`DYLD_*`** 变量会被移除。
>
> 在 **`processRestricted`** 函数中会设置限制原因。检查该代码可以看到，原因包括：
>
> - 二进制文件是 `setuid/setgid`
> - macho 二进制文件中存在 `__RESTRICT/__restrict` section。
> - 软件具有 entitlements（hardened runtime），但没有 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) entitlement
>  - 使用以下命令检查二进制文件的 **entitlements**：`codesign -dv --entitlements :- </path/to/bin>`
>
> 在较新版本中，可以在 **`configureProcessRestrictions`** 函数的后半部分找到该逻辑。不过，在更新版本中执行的是该函数开头的检查（可以移除与 iOS 或 simulation 相关的 if，因为它们不会在 macOS 中使用）。

### Library Validation

即使二进制文件允许使用 **`DYLD_INSERT_LIBRARIES`** 环境变量，如果二进制文件会检查待加载库的签名，它也不会加载自定义库。

要加载自定义库，二进制文件需要具有以下 entitlements 之一：

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

或者，二进制文件**不应具有** **hardened runtime flag** 或 **library validation flag**。

可以使用 `codesign --display --verbose <bin>` 检查二进制文件是否具有 **hardened runtime**，方法是检查 **`CodeDirectory`** 中的 runtime flag，例如：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

如果库使用与二进制文件相同的 certificate 签名，也可以加载该库。

请在以下位置查看如何 (ab)use 此技术以及检查相关限制：


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> 请记住，**之前介绍的 Library Validation 限制同样适用于**执行 Dylib hijacking attacks。

与 Windows 一样，在 MacOS 中也可以**劫持 dylib**，使**应用程序**执行**任意** **代码**（实际上，普通用户可能无法做到这一点，因为可能需要 TCC permission 才能写入 `.app` bundle 并劫持库）。\
不过，**MacOS** 应用程序**加载**库的方式比 Windows 更受限制。这意味着 **malware** 开发者仍然可以使用该技术来实现**隐蔽性**，但利用它来**提升权限的可能性要低得多**。

首先，**MacOS 二进制文件更常见的情况是指定要加载库的完整路径**。其次，**MacOS 从不在** **$PATH** 的文件夹中搜索库。

与该功能相关的**代码**主要位于 `ImageLoader.cpp` 的 **`ImageLoader::recursiveLoadLibraries`** 中。

macho 二进制文件可以使用 **4 种不同的 header Commands** 来加载库：

- **`LC_LOAD_DYLIB`** command 是加载 dylib 的常用 command。
- **`LC_LOAD_WEAK_DYLIB`** command 的工作方式与前一个相同，但如果找不到 dylib，执行会继续且不会报错。
- **`LC_REEXPORT_DYLIB`** command 会代理（或重新导出）其他库中的 symbols。
- **`LC_LOAD_UPWARD_DYLIB`** command 用于两个库相互依赖的情况（这称为 _upward dependency_）。

不过，dylib hijacking 有 **2 种类型**：

- **Missing weak linked libraries**：这意味着应用程序会尝试加载一个不存在的库，该库通过 **LC_LOAD_WEAK_DYLIB** 配置。然后，**如果攻击者将 dylib 放置到预期位置，它就会被加载**。
- link 是 "weak" 意味着，即使找不到库，应用程序也会继续运行。
- 与此相关的**代码**位于 `ImageLoader.cpp` 的 `ImageLoaderMachO::doGetDependentLibraries` 函数中，其中只有当 `LC_LOAD_WEAK_DYLIB` 为 true 时，`lib->required` 才是 `false`。
- 使用以下命令在二进制文件中**查找 weak linked libraries**（稍后会有如何创建 hijacking libraries 的示例）：
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**：Mach-O 二进制文件可以包含 **`LC_RPATH`** 和 **`LC_LOAD_DYLIB`** commands。根据这些 commands 的**值**，**libraries** 将从**不同目录**加载。
- **`LC_RPATH`** 包含二进制文件用于加载库的若干文件夹路径。
- **`LC_LOAD_DYLIB`** 包含要加载的特定库的路径。这些路径可以包含 **`@rpath`**，它会被 **`LC_RPATH`** 中的值替换。如果 **`LC_RPATH`** 中有多个路径，所有路径都会用于搜索要加载的库。示例：
- 如果 **`LC_LOAD_DYLIB`** 包含 `@rpath/library.dylib`，而 **`LC_RPATH`** 包含 `/application/app.app/Contents/Framework/v1/` 和 `/application/app.app/Contents/Framework/v2/`，那么两个文件夹都会用于加载 `library.dylib`**。** 如果库在 `[...]/v1/` 中不存在，攻击者可以将其放在那里，从而劫持原本在 `[...]/v2/` 中加载的库，因为会按照 **`LC_LOAD_DYLIB`** 中路径的顺序进行搜索。
- 使用以下命令在二进制文件中**查找 rpath paths 和 libraries**：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**：是包含**主可执行文件**的目录的**路径**。
>
> **`@loader_path`**：是包含 load command 的 **Mach-O binary** 所在**目录**的**路径**。
>
> - 在 executable 中使用时，**`@loader_path`** 实际上与 **`@executable_path`** 相同。
> - 在 **dylib** 中使用时，**`@loader_path`** 给出 **dylib** 的**路径**。

利用此功能**提升权限**的方式，是在极少数情况下，某个由 **root** 执行的**应用程序**会在攻击者拥有写权限的文件夹中**查找某个库**。

> [!TIP]
> 用于在应用程序中查找**缺失库**的优秀 **scanner** 是 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)，或者其 [**CLI 版本**](https://github.com/pandazheng/DylibHijack)。\
> 关于该技术的优秀[**技术细节报告**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)可以在[**这里**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)找到。

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> 请记住，**之前介绍的 Library Validation 限制同样适用于**执行 Dlopen hijacking attacks。

来自 **`man dlopen`**：

- 当 path **不包含斜杠字符**（即它只是一个 leaf name）时，**dlopen() 会进行搜索**。如果在启动时设置了 **`$DYLD_LIBRARY_PATH`**，dyld 会首先**在该目录**中查找。接下来，如果调用方 mach-o 文件或主 executable 指定了 **`LC_RPATH`**，dyld 就会**在这些**目录中查找。然后，如果进程是 **unrestricted**，dyld 会在**当前工作目录**中搜索。最后，对于旧二进制文件，dyld 会尝试一些 fallback。如果在启动时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 会在**这些目录**中搜索；否则，dyld 会先查找 **`/usr/local/lib/`**（如果进程是 unrestricted），然后查找 **`/usr/lib/`**（此信息来自 **`man dlopen`**）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（如果 unrestricted）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（如果 unrestricted）
6. `/usr/lib/`

> [!CAUTION]
> 如果名称中没有斜杠，则有 2 种 hijacking 方式：
>
> - 如果某个 **`LC_RPATH`** 可写（但会检查签名，因此还需要二进制文件是 unrestricted）
> - 如果二进制文件是 **unrestricted**，那么就可以从 CWD 加载内容（或滥用前面提到的环境变量之一）

- 当 path **看起来像 framework** path（例如 `/stuff/foo.framework/foo`）时，如果在启动时设置了 **`$DYLD_FRAMEWORK_PATH`**，dyld 会首先在该目录中查找 **framework partial path**（例如 `foo.framework/foo`）。接下来，dyld 会尝试**按原样使用所提供的 path**（相对路径使用当前工作目录）。最后，对于旧二进制文件，dyld 会尝试一些 fallback。如果在启动时设置了 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**，dyld 会在这些目录中搜索。否则，它会先搜索 **`/Library/Frameworks`**（在 macOS 中，如果进程是 unrestricted），然后搜索 **`/System/Library/Frameworks`**。
1. `$DYLD_FRAMEWORK_PATH`
2. 所提供的 path（如果 unrestricted，相对路径使用当前工作目录）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（如果 unrestricted）
5. `/System/Library/Frameworks`

> [!CAUTION]
> 如果是 framework path，劫持方式是：
>
> - 如果进程是 **unrestricted**，则滥用来自 CWD 的**相对路径**或上述环境变量（即使文档没有说明，如果进程受限，DYLD\_\* 环境变量也会被移除）

- 当 path **包含斜杠但不是 framework path**（即 dylib 的完整路径或部分路径）时，dlopen() 首先在（如果设置了）**`$DYLD_LIBRARY_PATH`** 中查找（使用 path 中的 leaf part）。接下来，dyld **尝试所提供的 path**（相对路径使用当前工作目录，但仅适用于 unrestricted processes）。最后，对于旧二进制文件，dyld 会尝试 fallback。如果在启动时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 会在这些目录中搜索；否则，dyld 会先查找 **`/usr/local/lib/`**（如果进程是 unrestricted），然后查找 **`/usr/lib/`**。
1. `$DYLD_LIBRARY_PATH`
2. 所提供的 path（如果 unrestricted，相对路径使用当前工作目录）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（如果 unrestricted）
5. `/usr/lib/`

> [!CAUTION]
> 如果名称中包含斜杠且不是 framework，劫持方式是：
>
> - 如果二进制文件是 **unrestricted**，则可以从 CWD 或 `/usr/local/lib` 加载内容（或滥用前面提到的环境变量之一）

> [!TIP]
> 注意：没有用于**控制 dlopen 搜索**的配置文件。
>
> 注意：如果主 executable 是 **set\[ug]id binary** 或使用 entitlements 进行 codesign，则会忽略**所有环境变量**，并且只能使用完整路径（有关更多详细信息，请参阅 [check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)）
>
> 注意：Apple platforms 使用 "universal" 文件来组合 32-bit 和 64-bit 库。这意味着不存在单独的 32-bit 和 64-bit 搜索路径。
>
> 注意：在 Apple platforms 中，大多数 OS dylib 都被合并到 dyld cache 中，并不存在于磁盘上。因此，调用 **`stat()`** 预先检查 OS dylib 是否存在**无法正常工作**。但是，**`dlopen_preflight()`** 使用与 **`dlopen()`** 相同的步骤来查找兼容的 mach-o 文件。

**Check paths**

使用以下代码检查所有选项：
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
如果编译并执行它，你可以看到**搜索每个 library 失败的位置**。此外，你还可以**过滤 FS logs**：
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

如果一个**privileged binary/app**（例如 SUID，或带有强大 entitlements 的某个 binary）正在加载一个**relative path** library（例如使用 `@executable_path` 或 `@loader_path`），并且已禁用 **Library Validation**，那么攻击者可能可以将该 binary 移动到一个能够**修改 relative path loaded library** 的位置，并利用它向该进程注入代码。

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

在文件 `dyld-dyld-832.7.1/src/dyld2.cpp` 中，可以找到函数 **`pruneEnvironmentVariables`**。该函数会移除所有**以 `DYLD_` 开头**以及 **`LD_LIBRARY_PATH=`** 的 env variable。

对于 **suid** 和 **sgid** binary，它还会专门将 env variables **`DYLD_FALLBACK_FRAMEWORK_PATH`** 和 **`DYLD_FALLBACK_LIBRARY_PATH`** 设置为 **`null`**。

如果 targeting OSX，该函数会从同一文件的 **`_main`** 函数中以如下方式调用：
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
并且这些 boolean flags 在代码中的同一个文件里设置：
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
这基本意味着，如果该二进制文件是 **suid** 或 **sgid**，或者其 headers 中包含 **RESTRICT** segment，或使用 **CS_RESTRICT** flag 签名，那么 **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** 为 true，env variables 将被清理。

请注意，如果 CS_REQUIRE_LV 为 true，那么这些 variables 不会被清理，但 library validation 会检查它们是否使用与原始二进制文件相同的 certificate。

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
### 包含 `__restrict` 段的 `__RESTRICT` 节
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### 强化运行时

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
> 请注意，即使存在使用 **`0x0(none)`** flags 签名的 binaries，它们在执行时也可能动态获得 **`CS_RESTRICT`** flag，因此该 technique 在这些 binaries 中将无法工作。
>
> 你可以使用以下命令检查某个 proc 是否具有此 flag（获取 [**csops here**](https://github.com/axelexic/CSOps)）：
>
> ```bash
> csops -status <pid>
> ```
>
> 然后检查 flag 0x800 是否已启用。

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
