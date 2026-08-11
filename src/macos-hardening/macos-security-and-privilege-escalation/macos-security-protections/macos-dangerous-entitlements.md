# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements 声明操作系统授予已签名代码的功能和安全例外。以下条目重点介绍在 offensive review 期间尤其有用的 Entitlements。<sup>[[13]](#references)</sup>

> [!WARNING]
> 请注意，以 **`com.apple`** 开头的 Entitlements 不提供给第三方，只有 Apple 可以授予它们……不过，如果你使用 enterprise certificate，实际上可以创建以 **`com.apple`** 开头的自定义 Entitlements，并绕过基于此的保护。

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement 允许进程 **bypass SIP**。查看[此处获取更多信息](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement 允许进程 **bypass SIP**。查看[此处获取更多信息](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports`（以前称为 `task_for_pid-allow`）**

此 entitlement 允许进程获取除 kernel 之外**任何**进程的 **task port**。查看[**此处获取更多信息**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.get-task-allow`

此 entitlement 允许其他具有 **`com.apple.security.cs.debugger`** entitlement 的进程获取由带有此 entitlement 的 binary 运行的进程的 task port，并在其上**inject code**。查看[**此处获取更多信息**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.cs.debugger`

具有 Debugging Tool Entitlement 的 App 可以调用 `task_for_pid()`，以获取未签名 App 以及设置了 `Get Task Allow` entitlement 且值为 `true` 的第三方 App 的有效 task port。但是，即使拥有 debugging tool entitlement，debugger **也无法获取**那些**不具有 `Get Task Allow entitlement**、因此受到 System Integrity Protection 保护的进程的 task port。查看[**此处获取更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)。<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

此 entitlement 允许应用程序**加载 framework、plug-in 或 library，而无需它们由 Apple 签名，或使用与主 executable 相同的 Team ID 签名**，因此攻击者可以滥用任意 library load 来 inject code。查看[**此处获取更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)。<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

此 entitlement 与 **`com.apple.security.cs.disable-library-validation`** 非常相似，但它**不是直接禁用** library validation，而是允许进程在运行时**调用 `csops` system call 来禁用它**。

该 entitlement 名称与使用它的 `csops` 操作一起硬编码在 XNU 中：<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` 的内核处理程序（`bsd/kern/kern_proc.c`）准确展示了该 primitive 的局限性：<sup>[[2]](#references)</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
因此，该操作：

- **仅限 macOS**（在其他所有平台上均返回 `ENOTSUP`）。
- 仅适用于**自身**（`forself == 1`）——无法使用它移除另一个进程的 library validation。
- 要求进程实际**持有该 entitlement**，并且如果进程被标记为 `CS_INSTALLER` 或正在 subsystem root path 下运行，则会拒绝执行。
- 从进程的 code-signing flags 中清除 **`CS_REQUIRE_LV | CS_FORCED_LV`**。

XNU 注释解释了其预期用途，也说明了它为何会引起攻击者的兴趣：

> 此选项用于从正在运行的进程中移除 library validation。当程序需要加载不受信任的 libraries 时，可在 plugin architectures 中使用此功能。[...] 一旦进程加载了不受信任的 library，未来再依赖 library validation 将不会有效。

换句话说，**任何携带此 entitlement 的 binary 都是 dylib-injection target**：在它放弃 `CS_REQUIRE_LV` 后，让代码在其中运行（或诱使它加载你的 plug-in），然后你就能继承 host process 被信任执行的所有操作。

### `com.apple.security.cs.allow-dyld-environment-variables`

此 entitlement 允许**使用 DYLD environment variables**，而这些变量可用于注入 libraries 和 code。更多信息请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)。<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` 或 `com.apple.rootless.storage`.`TCC`

[**根据此 blog**](https://objective-see.org/blog/blog_0x4C.html) **以及**[**此 blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)，这些 entitlements 允许进程**修改** **TCC** database。<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** 和 **`system.install.apple-software.standar-user`**

这些 entitlements 允许进程**在无需请求用户许可的情况下安装 software**，这对**privilege escalation** 很有帮助。

### `com.apple.private.security.kext-management`

请求 **kernel 加载 kernel extension** 所需的 entitlement。

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement 使进程能够与 **`com.apple.iCloudHelper`** XPC service 通信，该 service 将**提供 iCloud tokens**。

**iMovie** 和 **Garageband** 曾拥有此 entitlement。

有关利用该 entitlement **获取 icloud tokens** 的 exploit 的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO：我不知道这允许执行什么操作

### `com.apple.private.apfs.revert-to-snapshot`

TODO：[**此报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)提到，该 entitlement 可用于在重启后更新受 SSV 保护的 contents。如果你知道具体方法，请发送 PR！<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO：[**同一份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)提到，创建 sealed snapshot 可用于在重启后更新受 SSV 保护的 contents。如果你知道具体方法，请发送 PR！<sup>[[9]](#references)</sup>

### `keychain-access-groups`

此 entitlement 列出了应用程序有权访问的 **keychain** groups：
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

授予 **Full Disk Access** 权限，这是你可以拥有的最高级别 TCC 权限之一。

### **`kTCCServiceAppleEvents`**

允许应用向通常用于**自动化任务**的其他应用发送事件。通过控制其他应用，它可以滥用授予这些应用的权限。

例如，让这些应用要求用户输入密码：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
或让它们执行**任意操作**。

### **`kTCCServiceEndpointSecurityClient`**

除其他权限外，还允许**写入用户的 TCC 数据库**。

### **`kTCCServiceSystemPolicySysAdminFiles`**

允许**更改**用户的 **`NFSHomeDirectory`** 属性，从而更改其主文件夹路径，因此可以**绕过 TCC**。

### **`kTCCServiceSystemPolicyAppBundles`**

允许修改应用 bundle（app.app 内部）的文件，而这**默认情况下是不允许的**。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

可以在 _System Settings_ > _Privacy & Security_ > _App Management_ 中查看哪些用户或进程拥有此访问权限。

### `kTCCServiceAccessibility`

该进程将能够**滥用 macOS 的辅助功能**，这意味着，例如，它能够模拟按键。因此，它可以请求控制 Finder 等应用的权限，并使用此权限批准对话框。

## 与 Trustcache/CDhash 相关的 entitlements

有一些 entitlements 可用于绕过 Trustcache/CDhash 保护，这些保护机制会阻止执行 Apple 二进制文件的降级版本。

## 中等

### `com.apple.security.cs.allow-jit`

此 entitlement 允许进程通过向 `mmap()` 系统函数传递 `MAP_JIT` 标志来**创建可写且可执行的内存**。有关更多信息，请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)。<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

此 entitlement 允许**覆盖或修补 C 代码**、使用长期弃用的 **`NSCreateObjectFileImageFromMemory`**（其本质上并不安全），或使用 **DVDPlayback** framework。有关更多信息，请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)。<sup>[[11]](#references)</sup>

> [!CAUTION]
> 包含此 entitlement 会使你的应用暴露于内存不安全编程语言中的常见漏洞。请仔细考虑你的应用是否确实需要此例外。

### `com.apple.security.cs.disable-executable-page-protection`

此 entitlement 允许**修改磁盘上自身可执行文件的节**，从而强制退出。有关更多信息，请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)。<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement 是一种极端 entitlement，它会移除应用的一项基础安全保护，使攻击者能够在不被检测的情况下重写应用的可执行代码。如果可能，请优先使用范围更窄的 entitlements。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

此 entitlement 允许挂载 nullfs 文件系统（默认禁止）。工具：[**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

### `kTCCServiceAll`

根据这篇博客文章，此 TCC 权限通常以以下形式出现：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
允许进程**请求所有 TCC 权限**。

### **`kTCCServicePostEvent`**

允许通过 `CGEventPost()` 在系统范围内**注入合成键盘和鼠标事件**。拥有此权限的进程可以在任意应用中模拟按键、鼠标点击和滚动事件，从而实际上获得对桌面的**远程控制**。

与 `kTCCServiceAccessibility` 或 `kTCCServiceListenEvent` 结合使用时尤其危险，因为这既允许读取输入，也允许注入输入。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

允许在系统范围内**拦截所有键盘和鼠标事件**（输入监控 / keylogging）。进程可以注册 `CGEventTap`，捕获任何应用中输入的每次按键，包括密码、信用卡号和私人消息。

有关详细的 exploitation techniques，请参阅：

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

允许**读取显示缓冲区**——对任何应用进行截图和屏幕视频录制，包括安全文本字段。结合 OCR 后，可以自动从屏幕中提取密码和敏感数据。

> [!WARNING]
> 从 macOS Sonoma 开始，屏幕捕获会显示持久的菜单栏指示器。在较旧版本中，屏幕录制可以完全静默地进行。

### **`kTCCServiceCamera`**

允许从内置摄像头或连接的 USB 摄像头**捕获照片和视频**。向拥有摄像头权限的二进制文件中注入代码，可以实现静默的视觉监控。

### **`kTCCServiceMicrophone`**

允许从所有输入设备**录制音频**。具有麦克风访问权限的后台 daemon 可在没有可见应用窗口的情况下，持续进行环境音频监控。

### **`kTCCServiceLocation`**

允许通过 Wi-Fi 三角定位或 Bluetooth 信标查询设备的**物理位置**。持续监控可以暴露家庭 / 工作地址、出行模式和日常活动规律。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

可访问**Contacts**（姓名、电子邮件、电话号码——可用于 spear-phishing）、**Calendar**（会议日程、参会者列表）和**Photos**（个人照片、可能包含凭据的屏幕截图以及位置元数据）。

有关通过 TCC 权限进行完整 credential theft exploitation techniques 的信息，请参阅：

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** 通过允许与系统范围的 Mach/XPC 服务通信来削弱 App Sandbox，而该沙箱通常会阻止此类通信。这是**主要的 sandbox escape primitive**——遭到 compromise 的 sandboxed app 可以利用 mach-lookup exceptions 访问特权 daemon 并攻击其 XPC interfaces。
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
对于详细的 exploitation chain：sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape，请参阅：

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** 允许用户空间驱动程序二进制文件通过 IOKit interfaces 直接与 kernel 通信。DriverKit 二进制文件用于管理硬件：USB、Thunderbolt、PCIe、HID devices、音频设备和网络设备。

攻陷 DriverKit 二进制文件可实现：
- 通过格式错误的 `IOConnectCallMethod` 调用扩大 **Kernel attack surface**
- **USB device spoofing**（模拟键盘以进行 HID injection）
- 通过 PCIe/Thunderbolt interfaces 发起 **DMA attacks**
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
如需了解详细的 IOKit/DriverKit exploitation，请参阅：

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` 操作和 `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` 处理程序）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement（`com.apple.security.cs.debugger`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934：绕过 TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — 播放音乐并绕过 TCC，即 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0：“Mac 上发生的事情，会留在 Apple 的 iCloud 上吗？！” - Wojciech Regula（YouTube）](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple OTA 更新的噩梦：绕过签名验证并攻破 Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement（`com.apple.security.cs.allow-jit`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
