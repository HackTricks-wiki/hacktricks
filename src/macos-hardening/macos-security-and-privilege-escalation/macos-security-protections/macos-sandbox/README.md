# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

MacOS Sandbox（最初称为 Seatbelt）**限制在沙箱内运行的应用程序**只能执行**沙箱配置文件中指定的允许操作**。这有助于确保**应用程序仅访问预期的资源**。

任何具有**权限** **`com.apple.security.app-sandbox`**的应用程序将会在沙箱内执行。**Apple 二进制文件**通常在沙箱内执行，所有来自**App Store**的应用程序都有该权限。因此，多个应用程序将在沙箱内执行。

为了控制进程可以或不能做什么，**沙箱在几乎所有进程可能尝试的操作中都有钩子**（包括大多数系统调用），使用**MACF**。然而，**根据**应用程序的**权限**，沙箱可能对进程更加宽松。

沙箱的一些重要组件包括：

- **内核扩展** `/System/Library/Extensions/Sandbox.kext`
- **私有框架** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- 在用户空间运行的**守护进程** `/usr/libexec/sandboxd`
- **容器** `~/Library/Containers`

### 容器

每个沙箱应用程序将在 `~/Library/Containers/{CFBundleIdentifier}` 中拥有自己的容器：
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
在每个 bundle id 文件夹内，您可以找到应用的 **plist** 和 **数据目录**，其结构模仿主目录：
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> 请注意，即使符号链接存在以“逃离”沙箱并访问其他文件夹，应用程序仍然需要**具有权限**才能访问它们。这些权限在`RedirectablePaths`中的**`.plist`**内。

**`SandboxProfileData`**是编译后的沙箱配置文件CFData，已转义为B64。
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> 由沙盒应用程序创建/修改的所有内容将获得**隔离属性**。如果沙盒应用程序尝试使用**`open`** 执行某些操作，这将通过触发 Gatekeeper 来阻止沙盒空间。

## 沙盒配置文件

沙盒配置文件是指示在该**沙盒**中将被**允许/禁止**的配置文件。它使用**沙盒配置文件语言 (SBPL)**，该语言使用[**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) 编程语言。

这里有一个示例：
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> 查看这个 [**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **以检查更多可能被允许或拒绝的操作。**
>
> 请注意，在配置文件的编译版本中，操作的名称被其在一个数组中的条目所替代，该数组为dylib和kext所知，使得编译版本更短且更难阅读。

重要的 **系统服务** 也在其自定义 **沙箱** 内运行，例如 `mdnsresponder` 服务。您可以在以下位置查看这些自定义 **沙箱配置文件**：

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- 其他沙箱配置文件可以在 [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) 中查看。

**App Store** 应用使用 **配置文件** **`/System/Library/Sandbox/Profiles/application.sb`**。您可以在此配置文件中检查诸如 **`com.apple.security.network.server`** 的权限如何允许进程使用网络。

然后，一些 **Apple 守护进程服务** 使用位于 `/System/Library/Sandbox/Profiles/*.sb` 或 `/usr/share/sandbox/*.sb` 的不同配置文件。这些沙箱在调用 API `sandbox_init_XXX` 的主函数中应用。

**SIP** 是一个名为 platform_profile 的沙箱配置文件，位于 `/System/Library/Sandbox/rootless.conf`。

### 沙箱配置文件示例

要使用 **特定沙箱配置文件** 启动应用程序，您可以使用：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!NOTE]
> 请注意，**Apple 编写的** **软件** 在 **Windows** 上 **没有额外的安全措施**，例如应用程序沙箱。

绕过示例：

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（他们能够写入以 `~$` 开头的沙箱外部文件）。

### 沙箱跟踪

#### 通过配置文件

可以跟踪每次检查操作时沙箱执行的所有检查。为此，只需创建以下配置文件：
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
然后只需使用该配置文件执行某些操作：
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
在 `/tmp/trace.out` 中，您将能够看到每次调用时执行的每个沙箱检查（因此，有很多重复项）。

还可以使用 **`-t`** 参数跟踪沙箱：`sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### 通过 API

`libsystem_sandbox.dylib` 导出的函数 `sandbox_set_trace_path` 允许指定一个跟踪文件名，沙箱检查将写入该文件。\
还可以通过调用 `sandbox_vtrace_enable()` 做类似的事情，然后通过调用 `sandbox_vtrace_report()` 从缓冲区获取日志错误。

### 沙箱检查

`libsandbox.dylib` 导出一个名为 `sandbox_inspect_pid` 的函数，该函数提供进程的沙箱状态列表（包括扩展）。但是，只有平台二进制文件可以使用此函数。

### MacOS 和 iOS 沙箱配置文件

MacOS 将系统沙箱配置文件存储在两个位置：**/usr/share/sandbox/** 和 **/System/Library/Sandbox/Profiles**。

如果第三方应用程序携带 _**com.apple.security.app-sandbox**_ 权限，则系统将 **/System/Library/Sandbox/Profiles/application.sb** 配置文件应用于该进程。

在 iOS 中，默认配置文件称为 **container**，我们没有 SBPL 文本表示。在内存中，这个沙箱被表示为每个权限的允许/拒绝二叉树。

### App Store 应用中的自定义 SBPL

公司可能会使其应用程序 **使用自定义沙箱配置文件**（而不是默认配置文件）。他们需要使用权限 **`com.apple.security.temporary-exception.sbpl`**，该权限需要得到苹果的授权。

可以在 **`/System/Library/Sandbox/Profiles/application.sb:`** 中检查该权限的定义。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
这将**在此权限之后评估字符串**作为沙箱配置文件。

### 编译和反编译沙箱配置文件

**`sandbox-exec`** 工具使用 `libsandbox.dylib` 中的 `sandbox_compile_*` 函数。导出的主要函数有：`sandbox_compile_file`（期望文件路径，参数 `-f`），`sandbox_compile_string`（期望字符串，参数 `-p`），`sandbox_compile_name`（期望容器名称，参数 `-n`），`sandbox_compile_entitlements`（期望权限 plist）。

这个反向和[**开源版本的工具 sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) 允许 **`sandbox-exec`** 将编译的沙箱配置文件写入文件。

此外，为了将进程限制在容器内，它可能会调用 `sandbox_spawnattrs_set[container/profilename]` 并传递一个容器或现有配置文件。

## 调试和绕过沙箱

在 macOS 上，与 iOS 不同，iOS 中的进程从一开始就被内核沙箱化，**进程必须自行选择进入沙箱**。这意味着在 macOS 上，进程在主动决定进入沙箱之前不会受到沙箱的限制，尽管 App Store 应用始终是沙箱化的。

如果进程具有权限 `com.apple.security.app-sandbox`，则在启动时会自动从用户空间沙箱化。有关此过程的详细说明，请查看：

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **沙箱扩展**

扩展允许为对象提供进一步的权限，并通过调用以下函数之一来实现：

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

扩展存储在可从进程凭据访问的第二个 MACF 标签槽中。以下 **`sbtool`** 可以访问此信息。

请注意，扩展通常由允许的进程授予，例如，当进程尝试访问照片并在 XPC 消息中被允许时，`tccd` 将授予 `com.apple.tcc.kTCCServicePhotos` 的扩展令牌。然后，进程需要消耗扩展令牌，以便将其添加到其中。\
请注意，扩展令牌是长十六进制数，编码了授予的权限。然而，它们没有硬编码的允许 PID，这意味着任何可以访问令牌的进程可能会被**多个进程消耗**。

请注意，扩展与权限密切相关，因此拥有某些权限可能会自动授予某些扩展。

### **检查 PID 权限**

[**根据这个**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)，**`sandbox_check`** 函数（它是一个 `__mac_syscall`）可以检查**某个 PID、审计令牌或唯一 ID 是否允许某个操作**。

[**工具 sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c)（在[这里编译](https://newosxbook.com/articles/hitsb.html)）可以检查某个 PID 是否可以执行某些操作：
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

也可以使用 `libsystem_sandbox.dylib` 中的 `sandbox_suspend` 和 `sandbox_unsuspend` 函数来暂停和恢复沙箱。

请注意，调用暂停函数时会检查一些权限，以授权调用者调用它，例如：

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

此系统调用 (#381) 期望第一个参数为一个字符串，指示要运行的模块，然后第二个参数为一个代码，指示要运行的函数。第三个参数将取决于执行的函数。

函数 `___sandbox_ms` 调用封装了 `mac_syscall`，在第一个参数中指示 `"Sandbox"`，就像 `___sandbox_msp` 是 `mac_set_proc` (#387) 的封装一样。然后，`___sandbox_ms` 支持的一些代码可以在下表中找到：

- **set_profile (#0)**: 将编译或命名的配置文件应用于进程。
- **platform_policy (#1)**: 强制执行特定于平台的策略检查（在 macOS 和 iOS 之间有所不同）。
- **check_sandbox (#2)**: 执行特定沙箱操作的手动检查。
- **note (#3)**: 向沙箱添加注释。
- **container (#4)**: 将注释附加到沙箱，通常用于调试或识别。
- **extension_issue (#5)**: 为进程生成新扩展。
- **extension_consume (#6)**: 消耗给定的扩展。
- **extension_release (#7)**: 释放与已消耗扩展相关的内存。
- **extension_update_file (#8)**: 修改沙箱内现有文件扩展的参数。
- **extension_twiddle (#9)**: 调整或修改现有文件扩展（例如，TextEdit、rtf、rtfd）。
- **suspend (#10)**: 暂时暂停所有沙箱检查（需要适当的权限）。
- **unsuspend (#11)**: 恢复所有先前暂停的沙箱检查。
- **passthrough_access (#12)**: 允许直接通过访问资源，绕过沙箱检查。
- **set_container_path (#13)**: （仅限 iOS）为应用组或签名 ID 设置容器路径。
- **container_map (#14)**: （仅限 iOS）从 `containermanagerd` 检索容器路径。
- **sandbox_user_state_item_buffer_send (#15)**: （iOS 10+）在沙箱中设置用户模式元数据。
- **inspect (#16)**: 提供有关沙箱进程的调试信息。
- **dump (#18)**: （macOS 11）转储沙箱的当前配置文件以供分析。
- **vtrace (#19)**: 跟踪沙箱操作以进行监控或调试。
- **builtin_profile_deactivate (#20)**: （macOS < 11）停用命名配置文件（例如，`pe_i_can_has_debugger`）。
- **check_bulk (#21)**: 在一次调用中执行多个 `sandbox_check` 操作。
- **reference_retain_by_audit_token (#28)**: 为审计令牌创建引用，以便在沙箱检查中使用。
- **reference_release (#29)**: 释放先前保留的审计令牌引用。
- **rootless_allows_task_for_pid (#30)**: 验证是否允许 `task_for_pid`（类似于 `csr` 检查）。
- **rootless_whitelist_push (#31)**: （macOS）应用系统完整性保护（SIP）清单文件。
- **rootless_whitelist_check (preflight) (#32)**: 在执行之前检查 SIP 清单文件。
- **rootless_protected_volume (#33)**: （macOS）将 SIP 保护应用于磁盘或分区。
- **rootless_mkdir_protected (#34)**: 将 SIP/DataVault 保护应用于目录创建过程。

## Sandbox.kext

请注意，在 iOS 中，内核扩展包含 **硬编码的所有配置文件**，以避免被修改。以下是内核扩展中的一些有趣函数：

- **`hook_policy_init`**: 它挂钩 `mpo_policy_init`，并在 `mac_policy_register` 之后被调用。它执行沙箱的大部分初始化。它还初始化 SIP。
- **`hook_policy_initbsd`**: 它设置 sysctl 接口，注册 `security.mac.sandbox.sentinel`、`security.mac.sandbox.audio_active` 和 `security.mac.sandbox.debug_mode`（如果与 `PE_i_can_has_debugger` 一起引导）。
- **`hook_policy_syscall`**: 它由 `mac_syscall` 调用，第一个参数为 "Sandbox"，第二个参数为指示操作的代码。使用 switch 来根据请求的代码查找要运行的代码。

### MACF Hooks

**`Sandbox.kext`** 通过 MACF 使用了超过一百个钩子。大多数钩子只会检查一些微不足道的情况，如果允许执行该操作，则会调用 **`cred_sb_evalutate`**，并传入来自 MACF 的 **凭据** 和一个对应于要执行的 **操作** 的数字，以及一个用于输出的 **缓冲区**。

一个很好的例子是函数 **`_mpo_file_check_mmap`**，它挂钩了 **`mmap`**，并将开始检查新内存是否可写（如果不可写则允许执行），然后检查它是否用于 dyld 共享缓存，如果是，则允许执行，最后调用 **`sb_evaluate_internal`**（或其一个封装）以执行进一步的允许检查。

此外，在沙箱使用的数百个钩子中，有三个特别有趣：

- `mpo_proc_check_for`: 如果需要并且之前未应用，则应用配置文件。
- `mpo_vnode_check_exec`: 当进程加载相关二进制文件时调用，然后执行配置文件检查，并检查禁止 SUID/SGID 执行。
- `mpo_cred_label_update_execve`: 当分配标签时调用。这是最长的一个，因为它在二进制文件完全加载但尚未执行时调用。它将执行诸如创建沙箱对象、将沙箱结构附加到 kauth 凭据、移除对 mach 端口的访问等操作。

请注意 **`_cred_sb_evalutate`** 是 **`sb_evaluate_internal`** 的封装，该函数获取传入的凭据，然后使用 **`eval`** 函数执行评估，该函数通常评估默认应用于所有进程的 **平台配置文件**，然后是 **特定进程配置文件**。请注意，平台配置文件是 **SIP** 在 macOS 中的主要组成部分之一。

## Sandboxd

沙箱还有一个用户守护进程，暴露了 XPC Mach 服务 `com.apple.sandboxd` 并绑定特殊端口 14 (`HOST_SEATBELT_PORT`)，内核扩展使用该端口与其通信。它通过 MIG 暴露了一些函数。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
