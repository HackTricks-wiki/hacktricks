# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld 的代码是开源的**，可以在 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) 找到，并可以使用 **URL 如** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) 下载为 tar 文件。

## **Dyld 进程**

查看 Dyld 如何在二进制文件中加载库：

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

这类似于 [**Linux 上的 LD_PRELOAD**](../../../../linux-hardening/privilege-escalation/#ld_preload)。它允许指示即将运行的进程从路径加载特定库（如果环境变量已启用）。

此技术也可以作为 **ASEP 技术** 使用，因为每个安装的应用程序都有一个名为 "Info.plist" 的 plist，允许使用名为 `LSEnvironmental` 的键 **分配环境变量**。

> [!NOTE]
> 自 2012 年以来，**Apple 大幅减少了 `DYLD_INSERT_LIBRARIES` 的权限**。
>
> 查看代码并 **检查 `src/dyld.cpp`**。在函数 **`pruneEnvironmentVariables`** 中，您可以看到 **`DYLD_*`** 变量被移除。
>
> 在函数 **`processRestricted`** 中，设置了限制的原因。检查该代码，您可以看到原因是：
>
> - 二进制文件是 `setuid/setgid`
> - macho 二进制文件中存在 `__RESTRICT/__restrict` 部分。
> - 软件具有权限（强化运行时），但没有 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) 权限
>   - 使用以下命令检查二进制文件的 **权限**：`codesign -dv --entitlements :- </path/to/bin>`
>
> 在更新版本中，您可以在函数 **`configureProcessRestrictions`** 的第二部分找到此逻辑。然而，在较新版本中执行的是该函数的 **开始检查**（您可以删除与 iOS 或模拟相关的 if，因为这些在 macOS 中不会使用）。

### 库验证

即使二进制文件允许使用 **`DYLD_INSERT_LIBRARIES`** 环境变量，如果二进制文件检查要加载的库的签名，它也不会加载自定义库。

为了加载自定义库，二进制文件需要具有 **以下任一权限**：

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

或者二进制文件 **不应该** 具有 **强化运行时标志** 或 **库验证标志**。

您可以使用 `codesign --display --verbose <bin>` 检查二进制文件是否具有 **强化运行时**，检查 **`CodeDirectory`** 中的 runtime 标志，如：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**。

如果库 **使用与二进制文件相同的证书签名**，您也可以加载该库。

找到一个示例，了解如何（滥用）此功能并检查限制：

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib 劫持

> [!CAUTION]
> 请记住，**先前的库验证限制也适用于执行 Dylib 劫持攻击**。

与 Windows 一样，在 MacOS 中，您也可以 **劫持 dylibs** 使 **应用程序** **执行** **任意** **代码**（实际上，作为普通用户，这可能不可行，因为您可能需要 TCC 权限才能写入 `.app` 包并劫持库）。\
然而，**MacOS** 应用程序 **加载** 库的方式 **比 Windows 更受限制**。这意味着 **恶意软件** 开发人员仍然可以使用此技术进行 **隐蔽**，但能够 **滥用此技术以提升权限的可能性要低得多**。

首先，**更常见** 的情况是 **MacOS 二进制文件指示要加载的库的完整路径**。其次，**MacOS 从不在 **$PATH** 的文件夹中搜索库**。

与此功能相关的 **主要** 代码部分在 **`ImageLoader::recursiveLoadLibraries`** 中，位于 `ImageLoader.cpp`。

macho 二进制文件可以使用 **4 种不同的头命令** 来加载库：

- **`LC_LOAD_DYLIB`** 命令是加载 dylib 的常用命令。
- **`LC_LOAD_WEAK_DYLIB`** 命令的工作方式与前一个相同，但如果未找到 dylib，执行将继续而不会出现任何错误。
- **`LC_REEXPORT_DYLIB`** 命令代理（或重新导出）来自不同库的符号。
- **`LC_LOAD_UPWARD_DYLIB`** 命令在两个库相互依赖时使用（这称为 _向上依赖_）。

然而，有 **2 种类型的 dylib 劫持**：

- **缺失的弱链接库**：这意味着应用程序将尝试加载一个不存在的库，配置为 **LC_LOAD_WEAK_DYLIB**。然后，**如果攻击者在预期加载的位置放置了一个 dylib，它将被加载**。
- 链接是“弱”的事实意味着即使未找到库，应用程序仍将继续运行。
- 与此相关的 **代码** 在 `ImageLoaderMachO::doGetDependentLibraries` 函数中，`lib->required` 仅在 `LC_LOAD_WEAK_DYLIB` 为 true 时为 `false`。
- **在二进制文件中查找弱链接库**（稍后您将看到如何创建劫持库的示例）：
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **配置为 @rpath**：Mach-O 二进制文件可以具有 **`LC_RPATH`** 和 **`LC_LOAD_DYLIB`** 命令。根据这些命令的 **值**，**库** 将从 **不同目录** 加载。
- **`LC_RPATH`** 包含用于通过二进制文件加载库的一些文件夹的路径。
- **`LC_LOAD_DYLIB`** 包含要加载的特定库的路径。这些路径可以包含 **`@rpath`**，将被 **`LC_RPATH`** 中的值替换。如果 **`LC_RPATH`** 中有多个路径，将使用所有路径来搜索要加载的库。例如：
- 如果 **`LC_LOAD_DYLIB`** 包含 `@rpath/library.dylib`，而 **`LC_RPATH`** 包含 `/application/app.app/Contents/Framework/v1/` 和 `/application/app.app/Contents/Framework/v2/`。这两个文件夹将用于加载 `library.dylib`**。** 如果库在 `[...]/v1/` 中不存在，攻击者可以将其放置在那里以劫持在 `[...]/v2/` 中加载库，因为遵循 **`LC_LOAD_DYLIB`** 中路径的顺序。
- **在二进制文件中查找 rpath 路径和库**：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**：是 **主可执行文件** 所在目录的 **路径**。
>
> **`@loader_path`**：是 **包含** **Mach-O 二进制文件** 的 **目录** 的 **路径**，该文件包含加载命令。
>
> - 在可执行文件中使用时，**`@loader_path`** 实际上与 **`@executable_path`** 相同。
> - 在 **dylib** 中使用时，**`@loader_path`** 给出 **dylib** 的 **路径**。

滥用此功能以 **提升权限** 的方式是在 **应用程序** 由 **root** 执行时 **查找** 一些 **攻击者具有写权限的文件夹中的库**。

> [!TIP]
> 一个很好的 **扫描器** 用于查找应用程序中的 **缺失库** 是 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 或 [**CLI 版本**](https://github.com/pandazheng/DylibHijack)。\
> 关于此技术的 **技术细节** 的很好的 **报告** 可以在 [**这里**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) 找到。

**示例**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen 劫持

> [!CAUTION]
> 请记住，**先前的库验证限制也适用于执行 Dlopen 劫持攻击**。

来自 **`man dlopen`**：

- 当路径 **不包含斜杠字符**（即它只是一个叶名称）时，**dlopen() 将进行搜索**。如果 **`$DYLD_LIBRARY_PATH`** 在启动时设置，dyld 将首先 **在该目录中查找**。接下来，如果调用的 mach-o 文件或主可执行文件指定了 **`LC_RPATH`**，则 dyld 将 **在这些** 目录中查找。接下来，如果进程是 **不受限制的**，dyld 将在 **当前工作目录** 中搜索。最后，对于旧二进制文件，dyld 将尝试一些后备方案。如果 **`$DYLD_FALLBACK_LIBRARY_PATH`** 在启动时设置，dyld 将在 **这些目录** 中搜索，否则，dyld 将在 **`/usr/local/lib/`** 中查找（如果进程不受限制），然后在 **`/usr/lib/`** 中查找（此信息来自 **`man dlopen`**）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（如果不受限制）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（如果不受限制）
6. `/usr/lib/`

> [!CAUTION]
> 如果名称中没有斜杠，则有 2 种方法可以进行劫持：
>
> - 如果任何 **`LC_RPATH`** 是 **可写的**（但签名会被检查，因此为此您还需要二进制文件不受限制）
> - 如果二进制文件是 **不受限制的**，那么可以从 CWD 加载某些内容（或滥用提到的环境变量之一）

- 当路径 **看起来像框架** 路径（例如 `/stuff/foo.framework/foo`）时，如果 **`$DYLD_FRAMEWORK_PATH`** 在启动时设置，dyld 将首先在该目录中查找 **框架部分路径**（例如 `foo.framework/foo`）。接下来，dyld 将尝试 **按原样使用提供的路径**（使用当前工作目录进行相对路径）。最后，对于旧二进制文件，dyld 将尝试一些后备方案。如果 **`$DYLD_FALLBACK_FRAMEWORK_PATH`** 在启动时设置，dyld 将在这些目录中搜索。否则，它将搜索 **`/Library/Frameworks`**（在 macOS 上，如果进程不受限制），然后 **`/System/Library/Frameworks`**。
1. `$DYLD_FRAMEWORK_PATH`
2. 提供的路径（如果不受限制，使用当前工作目录进行相对路径）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（如果不受限制）
5. `/System/Library/Frameworks`

> [!CAUTION]
> 如果是框架路径，劫持它的方法是：
>
> - 如果进程是 **不受限制的**，滥用 **相对路径从 CWD** 和提到的环境变量（即使文档中没有说明，如果进程受限，DYLD_* 环境变量会被移除）

- 当路径 **包含斜杠但不是框架路径**（即到 dylib 的完整路径或部分路径）时，dlopen() 首先在（如果设置） **`$DYLD_LIBRARY_PATH`** 中查找（使用路径的叶部分）。接下来，dyld **尝试提供的路径**（使用当前工作目录进行相对路径（但仅适用于不受限制的进程））。最后，对于旧二进制文件，dyld 将尝试后备方案。如果 **`$DYLD_FALLBACK_LIBRARY_PATH`** 在启动时设置，dyld 将在这些目录中搜索，否则，dyld 将在 **`/usr/local/lib/`** 中查找（如果进程不受限制），然后在 **`/usr/lib/`** 中查找。
1. `$DYLD_LIBRARY_PATH`
2. 提供的路径（如果不受限制，使用当前工作目录进行相对路径）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（如果不受限制）
5. `/usr/lib/`

> [!CAUTION]
> 如果名称中有斜杠且不是框架，则劫持它的方法是：
>
> - 如果二进制文件是 **不受限制的**，那么可以从 CWD 或 `/usr/local/lib` 加载某些内容（或滥用提到的环境变量之一）

> [!NOTE]
> 注意：没有配置文件来 **控制 dlopen 搜索**。
>
> 注意：如果主可执行文件是 **set\[ug]id 二进制文件或具有权限的代码签名**，则 **所有环境变量都将被忽略**，只能使用完整路径（[检查 DYLD_INSERT_LIBRARIES 限制](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)以获取更详细的信息）。
>
> 注意：Apple 平台使用“通用”文件来组合 32 位和 64 位库。这意味着没有单独的 32 位和 64 位搜索路径。
>
> 注意：在 Apple 平台上，大多数操作系统 dylibs 被 **组合到 dyld 缓存中**，并且在磁盘上不存在。因此，调用 **`stat()`** 预检操作系统 dylib 是否存在 **将不起作用**。然而，**`dlopen_preflight()`** 使用与 **`dlopen()`** 相同的步骤来查找兼容的 mach-o 文件。

**检查路径**

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
如果你编译并执行它，你可以看到**每个库被搜索的失败位置**。此外，你还可以**过滤文件系统日志**：
```bash
sudo fs_usage | grep "dlopentest"
```
## 相对路径劫持

如果一个 **特权二进制文件/应用程序**（如 SUID 或某些具有强大权限的二进制文件）正在 **加载相对路径** 库（例如使用 `@executable_path` 或 `@loader_path`）并且 **禁用库验证**，攻击者可能会将二进制文件移动到一个位置，在那里攻击者可以 **修改相对路径加载的库**，并利用它在进程中注入代码。

## 修剪 `DYLD_*` 和 `LD_LIBRARY_PATH` 环境变量

在文件 `dyld-dyld-832.7.1/src/dyld2.cpp` 中，可以找到函数 **`pruneEnvironmentVariables`**，该函数将删除任何 **以 `DYLD_`** 和 **`LD_LIBRARY_PATH=`** 开头的环境变量。

它还将特定地将环境变量 **`DYLD_FALLBACK_FRAMEWORK_PATH`** 和 **`DYLD_FALLBACK_LIBRARY_PATH`** 设置为 **null**，适用于 **suid** 和 **sgid** 二进制文件。

如果目标是 OSX，该函数会从同一文件的 **`_main`** 函数中调用，如下所示：
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
这些布尔标志在代码中的同一文件中设置：
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
这基本上意味着，如果二进制文件是 **suid** 或 **sgid**，或者在头文件中有 **RESTRICT** 段，或者它是用 **CS_RESTRICT** 标志签名的，那么 **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** 为真，环境变量将被修剪。

请注意，如果 CS_REQUIRE_LV 为真，则变量不会被修剪，但库验证将检查它们是否使用与原始二进制文件相同的证书。

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
### Section `__RESTRICT` with segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### 加固运行时

在钥匙串中创建一个新证书，并使用它来签署二进制文件：
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
> 请注意，即使有二进制文件带有标志 **`0x0(none)`**，它们在执行时也可以动态获取 **`CS_RESTRICT`** 标志，因此此技术在它们中将不起作用。
>
> 您可以通过 (get [**csops here**](https://github.com/axelexic/CSOps)) 检查进程是否具有此标志：
>
> ```bash
> csops -status <pid>
> ```
>
> 然后检查标志 0x800 是否启用。

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
