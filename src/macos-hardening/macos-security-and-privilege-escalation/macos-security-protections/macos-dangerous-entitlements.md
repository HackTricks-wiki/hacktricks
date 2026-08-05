# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> 注意，以 **`com.apple`** 开头的 entitlements 不提供给第三方，只有 Apple 可以授予它们……或者，如果你使用 enterprise certificate，实际上可以创建以 **`com.apple`** 开头的自定义 entitlements，从而绕过基于此的 protections。

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement 允许 **bypass SIP**。查看[此处了解更多信息](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement 允许 **bypass SIP**。查看[此处了解更多信息](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports`（之前称为 `task_for_pid-allow`）**

此 entitlement 允许获取除 kernel 之外**任何** process 的 **task port**。查看[**此处了解更多信息**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.get-task-allow`

此 entitlement 允许拥有 **`com.apple.security.cs.debugger`** entitlement 的其他 processes 获取运行此 entitlement 对应 binary 的 process 的 task port，并在其中**注入 code**。查看[**此处了解更多信息**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.cs.debugger`

拥有 Debugging Tool Entitlement 的 apps 可以调用 `task_for_pid()`，以获取未签名 apps 以及设置了 `Get Task Allow` entitlement 为 `true` 的 third-party apps 的有效 task port。然而，即使拥有 debugging tool entitlement，debugger 也**无法获取**不具备 **`Get Task Allow` entitlement** 的 processes 的 **task ports**，因此这些 processes 受到 System Integrity Protection 的保护。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)。

### `com.apple.security.cs.disable-library-validation`

此 entitlement 允许加载 framework、plug-in 或 library，而无需由 Apple 签名，也无需与主 executable 使用相同的 Team ID 签名，因此 attacker 可以滥用某些 arbitrary library load 来注入 code。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

此 entitlement 与 **`com.apple.security.cs.disable-library-validation`** 非常相似，但它**不是直接禁用** library validation，而是允许 process 在 runtime 调用 `csops` system call 来禁用它。

该 entitlement 名称与使用它的 `csops` operation 一起硬编码在 XNU 中：<sup>[[2]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` 的内核处理程序（`bsd/kern/kern_proc.c`）准确展示了该原语的局限性：<sup>[[3]](#references)</sup>
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
所以该操作：

- 仅适用于 **macOS**（在其他所有平台上均返回 `ENOTSUP`）。
- 只能作用于**自身**（`forself == 1`）——无法通过它移除其他进程的 library validation。
- 要求进程实际**持有该 entitlement**，并且如果进程被标记为 `CS_INSTALLER`，或运行在 subsystem root path 下，则操作会被拒绝。
- 从进程的 code-signing flags 中清除 **`CS_REQUIRE_LV | CS_FORCED_LV`**。

XNU 中的注释解释了其预期用途，也说明了为什么它对攻击者很有吸引力：

> 此选项用于从运行中的进程移除 library validation。当程序需要加载不受信任的库时，可在 plugin architectures 中使用此功能。[...] 一旦进程加载了不受信任的库，今后再依赖 library validation 将不会有效。

换句话说，**任何携带此 entitlement 的二进制文件都是 dylib-injection 目标**：在它放弃 `CS_REQUIRE_LV` 后，让代码在其中运行（或诱使它加载你的 plug-in），即可继承 host process 被信任执行的所有操作。

### `com.apple.security.cs.allow-dyld-environment-variables`

此 entitlement 允许**使用 DYLD 环境变量**，而这些变量可能被用于注入库和代码。更多信息请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**根据此 blog**](https://objective-see.org/blog/blog_0x4C.html)以及[**此 blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)，这些 entitlements 允许**修改** **TCC** 数据库。

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

这些 entitlements 允许**无需向用户请求权限即可安装软件**，这可能有助于进行 **privilege escalation**。

### `com.apple.private.security.kext-management`

请求**内核加载 kernel extension** 所需的 entitlement。

### **`com.apple.private.icloud-account-access`**

拥有 entitlement **`com.apple.private.icloud-account-access`** 后，可以与 **`com.apple.iCloudHelper`** XPC service 通信，而该服务将**提供 iCloud tokens**。

**iMovie** 和 **Garageband** 曾拥有此 entitlement。

有关利用该 entitlement **获取 iCloud tokens** 的 exploit 的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 我不知道这允许执行什么操作

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**此报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)**提到，该 entitlement 可能可用于**在重启后更新受 SSV 保护的内容。如果你知道如何使用它，请提交 PR！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**此报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)**提到，该 entitlement 可能可用于**在重启后更新受 SSV 保护的内容。如果你知道如何使用它，请提交 PR！

### `keychain-access-groups`

此 entitlement 列出了应用程序可访问的 **keychain** groups：
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

授予 **Full Disk Access** 权限，这是你能拥有的 TCC 最高权限之一。

### **`kTCCServiceAppleEvents`**

允许应用向其他通常用于**自动化任务**的应用发送事件。通过控制其他应用，它可以滥用授予这些其他应用的权限。

例如，让它们要求用户输入密码：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
或让它们执行**任意操作**。

### **`kTCCServiceEndpointSecurityClient`**

除其他权限外，允许**写入用户的 TCC 数据库**。

### **`kTCCServiceSystemPolicySysAdminFiles`**

允许**更改**用户的 **`NFSHomeDirectory`** 属性，从而更改其主文件夹路径，并因此允许**绕过 TCC**。

### **`kTCCServiceSystemPolicyAppBundles`**

允许修改应用 bundle（位于 app.app 内）的文件，而这**默认情况下是不允许的**。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

可以在 _系统设置_ > _隐私与安全性_ > _App 管理_ 中检查哪些对象拥有此访问权限。

### `kTCCServiceAccessibility`

该进程将能够**滥用 macOS 的辅助功能**，例如，它将能够模拟按键。因此，它可以请求访问权限来控制 Finder 等应用，并使用此权限批准对话框。

## 与 Trustcache/CDhash 相关的 entitlements

有一些 entitlements 可用于绕过 Trustcache/CDhash 保护机制，这些保护机制会阻止执行 Apple 二进制文件的降级版本。

## 中等

### `com.apple.security.cs.allow-jit`

此 entitlement 允许通过向 `mmap()` 系统函数传递 `MAP_JIT` 标志，**创建可写且可执行的内存**。有关更多信息，请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

此 entitlement 允许**覆盖或修补 C 代码**、使用已被长期弃用的 **`NSCreateObjectFileImageFromMemory`**（其本质上不安全），或使用 **DVDPlayback** framework。有关更多信息，请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)。

> [!CAUTION]
> 包含此 entitlement 会使你的应用暴露于内存不安全代码语言中的常见漏洞。请仔细考虑你的应用是否需要此例外。

### `com.apple.security.cs.disable-executable-page-protection`

此 entitlement 允许在磁盘上**修改其自身可执行文件的 section**，以强制退出。有关更多信息，请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)。

> [!CAUTION]
> Disable Executable Memory Protection Entitlement 是一种极端的 entitlement，它会移除应用的一项基础安全保护，使攻击者能够在不被检测的情况下重写应用的可执行代码。如果可能，请优先使用范围更窄的 entitlements。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

此 entitlement 允许挂载 nullfs 文件系统（默认情况下被禁止）。Tool：[**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

### `kTCCServiceAll`

根据这篇 blogpost，此 TCC 权限通常以以下形式出现：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
允许进程**请求所有 TCC 权限**。

### **`kTCCServicePostEvent`**

通过 `CGEventPost()` 在系统范围内**注入合成键盘和鼠标事件**。拥有此权限的进程可以在任意应用中模拟按键、鼠标点击和滚动事件，从而实际上获得对桌面的**远程控制**能力。

与 `kTCCServiceAccessibility` 或 `kTCCServiceListenEvent` 结合使用时尤其危险，因为这允许同时读取和注入输入。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

允许在系统范围内**拦截所有键盘和鼠标事件**（input monitoring / keylogging）。进程可以注册 `CGEventTap`，捕获任何应用中输入的每一次按键，包括密码、信用卡号和私人消息。

有关详细的 exploitation techniques，请参阅：

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

允许**读取显示缓冲区**——对任何应用进行截图和屏幕录像，包括安全文本字段。结合 OCR 后，可以自动从屏幕中提取密码和敏感数据。

> [!WARNING]
> 从 macOS Sonoma 开始，屏幕捕获会显示一个持续存在的菜单栏指示器。在旧版本中，屏幕录制可以完全静默进行。

### **`kTCCServiceCamera`**

允许从内置摄像头或已连接的 USB 摄像头**捕获照片和视频**。向具有摄像头 entitlement 的 binary 中注入代码，可以实现静默的视觉监控。

### **`kTCCServiceMicrophone`**

允许从所有输入设备**录制音频**。具有麦克风访问权限的后台 daemon 可以在没有可见应用窗口的情况下，持续进行环境音频监控。

### **`kTCCServiceLocation`**

允许通过 Wi-Fi 三角定位或 Bluetooth beacon 查询设备的**物理位置**。持续监控可以暴露家庭/工作地址、出行模式和日常规律。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

可访问 **Contacts**（姓名、电子邮件、电话号码——可用于 spear-phishing）、**Calendar**（会议安排、参会者列表）和 **Photos**（个人照片、可能包含凭据的屏幕截图、位置元数据）。

有关通过 TCC 权限进行完整 credential theft exploitation techniques 的内容，请参阅：

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** 会通过允许与系统范围的 Mach/XPC 服务通信来削弱 App Sandbox，而这些服务通常会被 Sandbox 阻止。这是**主要的 sandbox escape primitive**——遭到 compromise 的 sandboxed app 可以利用 mach-lookup exceptions 访问特权 daemon，并 exploit 其 XPC interfaces。
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
有关详细的 exploitation chain：sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape，请参阅：

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit 权限**允许用户空间驱动二进制文件通过 IOKit 接口直接与内核通信。DriverKit 二进制文件负责管理硬件：USB、Thunderbolt、PCIe、HID 设备、音频设备和网络设备。

攻陷 DriverKit 二进制文件可实现：
- 通过构造异常的 `IOConnectCallMethod` 调用攻击**内核攻击面**
- **USB 设备 spoofing**（模拟键盘以执行 HID 注入）
- 通过 PCIe/Thunderbolt 接口执行 **DMA attacks**
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
如需了解详细的 IOKit/DriverKit exploitation，请参阅：

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## 参考资料

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` 操作和 `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` 处理程序）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
