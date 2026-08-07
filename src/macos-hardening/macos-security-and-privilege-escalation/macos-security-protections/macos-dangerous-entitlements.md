# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> 请注意，以 **`com.apple`** 开头的 entitlements 不适用于第三方，只有 Apple 可以授予它们……不过，如果你使用 enterprise certificate，实际上可以创建以 **`com.apple`** 开头的自定义 entitlements，从而绕过基于此机制的保护。

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement 允许 **bypass SIP**。更多信息请参见 [this for more info](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement 允许 **bypass SIP**。更多信息请参见 [this for more info](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

此 entitlement 允许获取除 kernel 之外**任意**进程的 **task port**。更多信息请参见 [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.get-task-allow`

此 entitlement 允许拥有 **`com.apple.security.cs.debugger`** entitlement 的其他进程获取运行该 binary 的进程的 task port，并在其上**inject code**。更多信息请参见 [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.cs.debugger`

拥有 Debugging Tool Entitlement 的 apps 可以调用 `task_for_pid()`，为设置了 `Get Task Allow` entitlement 且值为 `true` 的 unsigned 和 third-party apps 获取有效的 task port。但是，即使拥有 debugging tool entitlement，debugger **也无法获取**未设置 **`Get Task Allow` entitlement** 的进程的 task ports；因此，这些进程受到 System Integrity Protection 的保护。更多信息请参见 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)。<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

此 entitlement 允许加载未由 Apple 签名、或未使用与主 executable **相同 Team ID** 签名的 frameworks、plug-ins 或 libraries，因此攻击者可以滥用某些 arbitrary library load 来 inject code。更多信息请参见 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)。<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

此 entitlement 与 **`com.apple.security.cs.disable-library-validation`** 非常相似，但它**不是直接禁用** library validation，而是允许进程在运行时调用 `csops` system call 来禁用它。

该 entitlement 名称在 XNU 中是 hardcoded 的，与使用它的 `csops` operation 相邻：<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` 的 kernel handler（`bsd/kern/kern_proc.c`）准确展示了这一 primitive 的范围有多窄：<sup>[[2]](#references)</sup>
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

- 仅适用于 **macOS**（在其他所有平台上均返回 `ENOTSUP`）。
- 只能作用于**自身**（`forself == 1`）——无法使用它移除其他进程的 library validation。
- 要求进程实际**持有该 entitlement**，并且如果进程被标记为 `CS_INSTALLER` 或运行在 subsystem root path 下，则会拒绝操作。
- 从进程的 code-signing flags 中清除 **`CS_REQUIRE_LV | CS_FORCED_LV`**。

XNU 注释解释了其预期用途，也说明了它为何会引起攻击者的兴趣：

> 此选项用于从正在运行的进程中移除 library validation。当程序需要加载不受信任的 libraries 时，可在 plugin architectures 中使用此功能。[...] 一旦进程加载了不受信任的 library，未来继续依赖 library validation 将不再有效。

换句话说，**任何携带此 entitlement 的 binary 都是 dylib-injection target**：在它放弃 `CS_REQUIRE_LV` 后，让代码在其中运行（或诱使其加载你的 plug-in），即可继承 host process 被信任执行的所有操作。

### `com.apple.security.cs.allow-dyld-environment-variables`

此 entitlement 允许**使用 DYLD environment variables**，而这些变量可用于注入 libraries 和代码。更多信息请查看[**此处**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)。<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` 或 `com.apple.rootless.storage`.`TCC`

[**根据此 blog**](https://objective-see.org/blog/blog_0x4C.html)以及[**此 blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)，这些 entitlements 允许**修改** **TCC** database。<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** 和 **`system.install.apple-software.standar-user`**

这些 entitlements 允许**无需向用户请求权限即可安装 software**，这可能有助于实现 **privilege escalation**。

### `com.apple.private.security.kext-management`

请求 **kernel 加载 kernel extension** 所需的 entitlement。

### **`com.apple.private.icloud-account-access`**

拥有 entitlement **`com.apple.private.icloud-account-access`** 后，可以与 **`com.apple.iCloudHelper`** XPC service 通信，而该 service 将**提供 iCloud tokens**。

**iMovie** 和 **Garageband** 曾拥有此 entitlement。

有关利用该 entitlement **获取 iCloud tokens** 的 exploit 的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO：我不知道这允许执行什么操作

### `com.apple.private.apfs.revert-to-snapshot`

TODO：[**此 report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中提到，这可能用于在 reboot 后更新受 SSV 保护的 contents。如果你知道如何实现，请提交 PR！<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO：[**此 report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中提到，这可能用于在 reboot 后更新受 SSV 保护的 contents。如果你知道如何实现，请提交 PR！<sup>[[9]](#references)</sup>

### `keychain-access-groups`

此 entitlement 列出了该 application 有权访问的 **keychain** groups：
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

授予 **Full Disk Access** 权限，这是你可以拥有的 TCC 最高权限之一。

### **`kTCCServiceAppleEvents`**

允许应用向其他通常用于**自动化任务**的应用发送事件。通过控制其他应用，它可以滥用授予这些应用的权限。

例如，让它们请求用户输入密码：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
或者让它们执行**任意操作**。

### **`kTCCServiceEndpointSecurityClient`**

除其他权限外，允许**写入用户的 TCC 数据库**。

### **`kTCCServiceSystemPolicySysAdminFiles`**

允许**更改**用户的 **`NFSHomeDirectory`** 属性，从而更改其主文件夹路径，并因此允许**绕过 TCC**。

### **`kTCCServiceSystemPolicyAppBundles`**

允许修改应用 bundle（位于 app.app 内）的文件，而这类操作**默认被禁止**。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

可以在 _System Settings_ > _Privacy & Security_ > _App Management_ 中检查哪些用户或进程拥有此访问权限。

### `kTCCServiceAccessibility`

该进程将能够**滥用 macOS 的辅助功能**，例如可以模拟按键。因此，它可以请求控制 Finder 等应用的权限，并利用此权限批准该对话框。

## 与 Trustcache/CDhash 相关的 entitlements

有一些 entitlements 可用于绕过 Trustcache/CDhash 保护，而这些保护机制会阻止执行 Apple 二进制文件的降级版本。

## 中等

### `com.apple.security.cs.allow-jit`

此 entitlement 允许通过向 `mmap()` 系统函数传递 `MAP_JIT` 标志来**创建同时可写和可执行的内存**。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)。<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

此 entitlement 允许**覆盖或修补 C 代码**、使用长期弃用的 **`NSCreateObjectFileImageFromMemory`**（其本质上并不安全），或使用 **DVDPlayback** framework。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)。<sup>[[11]](#references)</sup>

> [!CAUTION]
> 包含此 entitlement 会使你的应用暴露于内存不安全代码语言中的常见漏洞。请仔细考虑你的应用是否确实需要此例外。

### `com.apple.security.cs.disable-executable-page-protection`

此 entitlement 允许**修改磁盘上自身可执行文件的各个区段**，从而强制退出。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)。<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement 是一种极端 entitlement，它会移除应用的一项基础安全保护，使攻击者能够在不被检测的情况下重写应用的可执行代码。如果可能，请优先使用限制范围更小的 entitlements。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

此 entitlement 允许挂载 nullfs 文件系统（默认禁止）。工具：[**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

### `kTCCServiceAll`

根据这篇 blogpost，此 TCC 权限通常以下列形式出现：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
允许进程**请求所有 TCC 权限**。

### **`kTCCServicePostEvent`**

允许通过 `CGEventPost()` 在系统范围内**注入合成键盘和鼠标事件**。具有此权限的进程可以在任何应用程序中模拟按键、鼠标点击和滚动事件——实际上可以对桌面进行**远程控制**。

与 `kTCCServiceAccessibility` 或 `kTCCServiceListenEvent` 结合使用时尤其危险，因为这允许同时读取和注入输入。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

允许在系统范围内**拦截所有键盘和鼠标事件**（输入监控 / keylogging）。进程可以注册 `CGEventTap`，捕获任何应用中输入的每次击键，包括密码、信用卡号码和私人消息。

如需了解详细的 exploitation techniques，请参阅：

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

允许**读取显示缓冲区**——对任何应用截屏和录制屏幕视频，包括安全文本字段。结合 OCR 后，可以自动从屏幕中提取密码和敏感数据。

> [!WARNING]
> 从 macOS Sonoma 开始，屏幕捕获会显示一个持续存在的菜单栏指示器。在较旧版本中，屏幕录制可以完全静默进行。

### **`kTCCServiceCamera`**

允许从内置摄像头或已连接的 USB 摄像头**捕获照片和视频**。向具有摄像头权限的 binary 中注入代码，可以实现静默的视觉监控。

### **`kTCCServiceMicrophone`**

允许从所有输入设备**录制音频**。具有麦克风访问权限的后台 daemon 可以在没有可见应用窗口的情况下，持续进行环境音频监控。

### **`kTCCServiceLocation`**

允许通过 Wi-Fi 三角定位或 Bluetooth 信标查询设备的**物理位置**。持续监控可以暴露家庭 / 工作地址、出行模式和日常活动规律。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

可访问**Contacts**（姓名、电子邮件、电话号码——对 spear-phishing 很有用）、**Calendar**（会议日程、参会者列表）和 **Photos**（个人照片、可能包含凭据的屏幕截图以及位置元数据）。

如需了解通过 TCC 权限实施完整 credential theft exploitation techniques，请参阅：

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox 与 Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox 临时例外**通过允许与系统范围内的 Mach/XPC 服务通信来削弱 App Sandbox，而沙盒通常会阻止此类通信。这是**主要的 sandbox escape primitive**——遭入侵的沙盒应用可以利用 mach-lookup 例外访问特权 daemon，并攻击其 XPC 接口。
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

**DriverKit entitlements** 允许 user-space driver binaries 通过 IOKit interfaces 直接与 kernel 通信。DriverKit binaries 用于管理硬件：USB、Thunderbolt、PCIe、HID devices、音频和网络。

Compromising a DriverKit binary enables:
- **Kernel attack surface** via malformed `IOConnectCallMethod` calls
- **USB device spoofing**（模拟键盘以进行 HID injection）
- 通过 PCIe/Thunderbolt interfaces 进行 **DMA attacks**
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

- [1] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` 操作和 `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` handler）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement（`com.apple.security.cs.debugger`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934：Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0：“What Happens on your Mac, Stays on Apple's iCloud?!” - Wojciech Regula（YouTube）](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [The Nightmare of Apple's OTA Update：Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement（`com.apple.security.cs.allow-jit`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
