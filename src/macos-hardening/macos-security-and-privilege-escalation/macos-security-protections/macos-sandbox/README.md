# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

MacOS Sandbox（最初称为 Seatbelt）**会限制**在 sandbox 中运行的**应用程序**，使其只能执行应用程序所使用的 Sandbox profile 中**允许的操作**。这有助于确保**应用程序只会访问预期的资源**。

任何具有**entitlement** **`com.apple.security.app-sandbox`** 的应用程序都会在 sandbox 内执行。**Apple 二进制文件**通常会在 Sandbox 中执行，并且来自 **App Store 的所有应用程序都具有该 entitlement**。因此，许多应用程序都会在 sandbox 中执行。<sup>[[4]](#references)</sup>

为了控制进程可以或不可以执行的操作，**Sandbox 使用 MACF 在几乎所有进程可能尝试的操作（包括大多数 syscall）中设置了 hooks**。但是，**取决于**应用程序的 **entitlements**，Sandbox 可能会对该进程更加宽松。

Sandbox 的一些重要组件包括：

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- 在 userland 中运行的 **daemon** `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

每个 sandboxed 应用程序都会在 `~/Library/Containers/{CFBundleIdentifier}` 中拥有自己的 container：
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
在每个 bundle id 文件夹中，你可以找到 App 的 **plist** 和 **Data directory**，其结构仿照 Home 文件夹：
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
> 请注意，即使存在用于从 Sandbox 中“逃逸”并访问其他文件夹的 symlinks，App 仍然需要拥有访问这些文件夹的 **permissions**。这些 permissions 位于 **`.plist`** 中的 `RedirectablePaths`。

**`SandboxProfileData`** 是经过编译的 sandbox profile CFData，并以 B64 形式转义。
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
> 沙箱应用创建/修改的所有内容都会获得 **quarantine attribute**。如果沙箱应用尝试使用 **`open`** 执行某些内容，这将通过触发 Gatekeeper 来阻止沙箱空间。

## Sandbox Profiles

Sandbox profiles 是用于指示在该 **Sandbox** 中哪些操作将被**允许/禁止**的配置文件。它使用 **Sandbox Profile Language (SBPL)**，该语言使用 [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) 编程语言。

你可以在这里找到一个示例：
```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

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
> 查看此[**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)，以了解更多可能被允许或拒绝的操作。<sup>[[5]](#references)</sup>
>
> 请注意，在 profile 的编译版本中，操作名称会被替换为 dylib 和 kext 已知数组中的条目，使编译版本更短且更难读取。

重要的**系统服务**也会在其自定义的 **sandbox** 中运行，例如 `mdnsresponder` 服务。你可以在以下位置查看这些自定义的 **sandbox profiles**：

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- 其他 sandbox profiles 可在 [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) 中查看。
- 在 iOS 中，platform profile 位于 sandbox `.kext` 内二进制文件的 `_platform_profile_data` 中。

**App Store** 应用使用 **profile** **`/System/Library/Sandbox/Profiles/application.sb`**。你可以在此 profile 中查看诸如 **`com.apple.security.network.server`** 之类的 entitlements 如何允许进程使用网络。

此外，一些 **Apple daemon services** 使用位于 `/System/Library/Sandbox/Profiles/*.sb` 或 `/usr/share/sandbox/*.sb` 中的不同 profiles。这些 sandbox 会在调用 API `sandbox_init_XXX` 的 main 函数中应用。<sup>[[3]](#references)</sup>

**SIP** 是位于 `/System/Library/Sandbox/rootless.conf` 中、名为 platform_profile 的 Sandbox profile。

### Sandbox Profile Examples

要使用**特定的 sandbox profile** 启动应用程序，可以使用：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
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

> [!TIP]
> 请注意，在 **Windows** 上运行的 **Apple-authored** **software** 没有额外的安全防护措施，例如 application sandboxing。

绕过示例：

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（它们能够将文件写入 sandbox 外部，且文件名以 `~$` 开头）。<sup>[[7]](#references)</sup>

### Sandbox 跟踪

#### 通过 profile

可以跟踪 sandbox 每次检查某个操作时执行的所有检查。为此，只需创建以下 profile：
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
然后使用该 profile 执行某些操作即可：
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
在 `/tmp/trace.out` 中，你可以看到每次执行 sandbox check 时记录的内容（因此会有大量重复项）。

也可以使用 **`-t`** 参数来 trace sandbox：`sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

`libsystem_sandbox.dylib` 导出的函数 `sandbox_set_trace_path` 可以指定一个 trace 文件名，sandbox checks 将写入该文件。\
也可以调用 `sandbox_vtrace_enable()` 实现类似功能，然后调用 `sandbox_vtrace_report()` 从 buffer 中获取错误日志。

### Sandbox Inspection

`libsandbox.dylib` 导出名为 sandbox_inspect_pid 的函数，该函数可以列出进程的 sandbox 状态（包括 extensions）。但是，只有 platform binaries 才能使用此函数。

### MacOS & iOS Sandbox Profiles

MacOS 将系统 sandbox profiles 存储在两个位置：**/usr/share/sandbox/** 和 **/System/Library/Sandbox/Profiles**。

如果第三方应用携带 _**com.apple.security.app-sandbox**_ entitlement，系统会将 **/System/Library/Sandbox/Profiles/application.sb** profile 应用到该进程。

在 iOS 中，默认 profile 称为 **container**，并且没有其 SBPL 文本表示。在内存中，该 sandbox 对 sandbox 中的每项权限都表示为 Allow/Deny binary tree。

### Custom SBPL in App Store apps

公司可以让其应用使用 **custom Sandbox profiles**（而不是默认 profile）运行。它们需要使用 entitlement **`com.apple.security.temporary-exception.sbpl`**，并且该 entitlement 需要获得 Apple 授权。

可以在 **`/System/Library/Sandbox/Profiles/application.sb:`** 中检查该 entitlement 的定义。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
这将把此 entitlement 后的字符串作为 Sandbox profile 进行 **eval**。

### 编译和反编译 Sandbox Profile

**`sandbox-exec`** 工具使用 `libsandbox.dylib` 中的 `sandbox_compile_*` 函数。导出的主要函数包括：`sandbox_compile_file`（需要文件路径，参数为 `-f`）、`sandbox_compile_string`（需要字符串，参数为 `-p`）、`sandbox_compile_name`（需要 container 的名称，参数为 `-n`）、`sandbox_compile_entitlements`（需要 entitlements plist）。

这个经过逆向且[**开源的 sandbox-exec 工具**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c)可以让 **`sandbox-exec`** 将编译后的 Sandbox profile 写入文件。

此外，为了将进程限制在 container 内，它可能会调用 `sandbox_spawnattrs_set[container/profilename]`，并传入一个 container 或预先存在的 profile。

## 调试和绕过 Sandbox

在 macOS 上，不同于进程从一开始就由内核进行 Sandbox 限制的 iOS，**进程必须自行选择加入 Sandbox**。这意味着在 macOS 上，进程在主动决定进入 Sandbox 之前不会受到 Sandbox 限制，不过 App Store 应用始终处于 Sandbox 中。

如果进程具有 `com.apple.security.app-sandbox` entitlement，则会在启动时自动从 userland 进入 Sandbox。有关此过程的详细说明，请查看：

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions 允许向对象授予额外权限，并通过调用以下函数来授予：

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions 存储在进程凭据中可访问的第二个 MACF label slot 中。以下 **`sbtool`** 可以访问这些信息。

请注意，Extensions 通常由允许执行相关操作的进程授予，例如，当进程尝试访问照片并在 XPC message 中获得允许时，`tccd` 将授予 `com.apple.tcc.kTCCServicePhotos` 的 extension token。随后，进程需要 consume 此 extension token，使其被添加到自身。\
请注意，extension token 通常是编码了所授予权限的长十六进制字符串。不过，其中没有硬编码允许的 PID，这意味着任何能够访问该 token 的进程都可能被**多个进程 consume**。

请注意，Extensions 也与 entitlements 密切相关，因此拥有某些 entitlements 可能会自动授予某些 Extensions。

### **检查 PID 权限**

[**根据此处内容**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)，**`sandbox_check`** 函数（它是一个 `__mac_syscall`）可以检查某个 PID、audit token 或 unique ID 是否被 Sandbox 允许执行某项操作。<sup>[[8]](#references)</sup>

[**工具 sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c)可以检查某个 PID 是否能够执行特定操作（可在[此处找到其编译版本](https://newosxbook.com/articles/hitsb.html))：
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

还可以使用 `libsystem_sandbox.dylib` 中的 `sandbox_suspend` 和 `sandbox_unsuspend` 函数来暂停和恢复 sandbox。

请注意，要调用 suspend 函数，需要检查一些 entitlements，以授权调用者执行该操作，例如：

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

该系统调用（#381）首先需要一个字符串参数，用于指示要运行的模块；然后第二个参数中的代码用于指示要运行的函数。第三个参数则取决于所执行的函数。<sup>[[2]](#references)</sup>

函数 `___sandbox_ms` 封装了 `mac_syscall`，并将第一个参数指定为 `"Sandbox"`，就像 `___sandbox_msp` 是 `mac_set_proc`（#387）的封装函数一样。以下是 `___sandbox_ms` 支持的一些代码：

- **set_profile (#0)**：将已编译或命名的 profile 应用到进程。
- **platform_policy (#1)**：执行特定于平台的 policy 检查（macOS 和 iOS 之间有所不同）。
- **check_sandbox (#2)**：手动检查特定的 sandbox 操作。
- **note (#3)**：向 Sandbox 添加注释。
- **container (#4)**：向 sandbox 附加注释，通常用于调试或标识。
- **extension_issue (#5)**：为进程生成新的 extension。
- **extension_consume (#6)**：使用给定的 extension。
- **extension_release (#7)**：释放与已使用 extension 关联的内存。
- **extension_update_file (#8)**：修改 sandbox 中现有 file extension 的参数。
- **extension_twiddle (#9)**：调整或修改现有的 file extension（例如 TextEdit、rtf、rtfd）。
- **suspend (#10)**：暂时暂停所有 sandbox 检查（需要适当的 entitlements）。
- **unsuspend (#11)**：恢复之前暂停的所有 sandbox 检查。
- **passthrough_access (#12)**：允许直接 passthrough 访问资源，绕过 sandbox 检查。
- **set_container_path (#13)**：（仅限 iOS）为 app group 或 signing ID 设置 container 路径。
- **container_map (#14)**：（仅限 iOS）从 `containermanagerd` 获取 container 路径。
- **sandbox_user_state_item_buffer_send (#15)**：（iOS 10+）在 sandbox 中设置 user mode 元数据。
- **inspect (#16)**：提供有关 sandboxed 进程的调试信息。
- **dump (#18)**：（macOS 11）导出 sandbox 的当前 profile 以供分析。
- **vtrace (#19)**：跟踪 sandbox 操作以进行监控或调试。
- **builtin_profile_deactivate (#20)**：（macOS < 11）停用命名 profile（例如 `pe_i_can_has_debugger`）。
- **check_bulk (#21)**：在单次调用中执行多个 `sandbox_check` 操作。
- **reference_retain_by_audit_token (#28)**：为 audit token 创建引用，以便在 sandbox 检查中使用。
- **reference_release (#29)**：释放之前保留的 audit token 引用。
- **rootless_allows_task_for_pid (#30)**：验证是否允许 `task_for_pid`（类似于 `csr` 检查）。
- **rootless_whitelist_push (#31)**：（macOS）应用 System Integrity Protection（SIP）manifest 文件。
- **rootless_whitelist_check (preflight) (#32)**：在执行前检查 SIP manifest 文件。
- **rootless_protected_volume (#33)**：（macOS）将 SIP 保护应用到磁盘或分区。
- **rootless_mkdir_protected (#34)**：将 SIP/DataVault 保护应用到目录创建过程。

## Sandbox.kext

请注意，在 iOS 中，kernel extension 将所有 profile 硬编码在 `__TEXT.__const` segment 中，以防止它们被修改。以下是 kernel extension 中一些有趣的函数：

- **`hook_policy_init`**：hook `mpo_policy_init`，并在 `mac_policy_register` 后调用。它执行 Sandbox 的大部分初始化工作，同时也初始化 SIP。
- **`hook_policy_initbsd`**：设置 sysctl interface，注册 `security.mac.sandbox.sentinel`、`security.mac.sandbox.audio_active` 和 `security.mac.sandbox.debug_mode`（如果通过 `PE_i_can_has_debugger` 启动）。
- **`hook_policy_syscall`**：当第一个参数为 `"Sandbox"` 且第二个参数中的 code 指示操作时，由 `mac_syscall` 调用。它使用 switch，根据请求的 code 查找要运行的代码。

### MACF Hooks

**`Sandbox.kext`** 通过 MACF 使用了一百多个 hooks。大多数 hooks 只会检查一些简单情况；如果允许执行该操作，就会使用 MACF 中的 **credentials** 和对应要执行的 **operation** 的编号，以及用于保存输出的 **buffer**，调用 **`cred_sb_evalutate`**。<sup>[[1]](#references)</sup>

一个很好的例子是函数 **`_mpo_file_check_mmap`**，它 hook 了 `mmap`。该函数首先检查新内存是否将被设置为可写（如果不是，则允许执行），然后检查其是否用于 dyld shared cache；如果是，则允许执行。最后，它会调用 **`sb_evaluate_internal`**（或其某个 wrapper）执行进一步的允许检查。

此外，在 Sandbox 使用的一百多个 hooks 中，有 3 个尤其值得关注：

- `mpo_proc_check_for`：在需要且此前尚未应用 profile 的情况下应用 profile。
- `mpo_vnode_check_exec`：当进程加载关联的 binary 时调用，然后执行 profile 检查，同时检查并禁止 SUID/SGID 执行。
- `mpo_cred_label_update_execve`：在分配 label 时调用。这是最长的函数，因为它会在 binary 完全加载但尚未执行时调用。它会执行诸如创建 sandbox object、将 sandbox struct 附加到 kauth credentials、移除对 mach ports 的访问权限等操作。

请注意，**`_cred_sb_evalutate`** 是 **`sb_evaluate_internal`** 的 wrapper。该函数接收传入的 credentials，然后使用 **`eval`** 函数执行评估；该函数通常会先评估默认应用于所有进程的 **platform profile**，然后评估 **specific process profile**。请注意，platform profile 是 macOS 中 **SIP** 的主要组成部分之一。

## Sandboxd

Sandbox 还拥有一个运行在 user space 中的 daemon，对外提供 XPC Mach service `com.apple.sandboxd`，并绑定特殊 port 14（`HOST_SEATBELT_PORT`）；kernel extension 使用该 port 与其通信。它通过 MIG 对外提供一些函数。

## References

- [1] [XNU — `security/mac_policy.h`（Sandbox kext 注册的 MACF hooks）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c`（`__mac_syscall`，`__sandbox_ms` 背后的 entry point）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
