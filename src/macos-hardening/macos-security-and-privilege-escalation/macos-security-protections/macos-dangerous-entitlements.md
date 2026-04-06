# macOS 危险的 Entitlements 与 TCC 权限

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> 注意以 **`com.apple`** 开头的 entitlements 第三方无法获得，只有 Apple 能授予……或者如果你使用企业证书，实际上可以创建你自己的以 **`com.apple`** 开头的 entitlements，从而绕过基于此的保护。

## 高危

### `com.apple.rootless.install.heritable`

该 entitlement **`com.apple.rootless.install.heritable`** 允许 **绕过 SIP**。详见 [此处了解更多](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

该 entitlement **`com.apple.rootless.install`** 允许 **绕过 SIP**。详见 [此处了解更多](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

该 entitlement 允许获取 **任何** 进程的 task port（内核除外）。详见 [此处了解更多](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.get-task-allow`

该 entitlement 允许具有 **`com.apple.security.cs.debugger`** entitlement 的其他进程获取由带有此 entitlement 的二进制运行的进程的 task port 并在其上 **注入代码**。详见 [此处了解更多](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.cs.debugger`

拥有 Debugging Tool Entitlement 的应用可以调用 `task_for_pid()` 来检索对未签名和第三方应用（其 `Get Task Allow` entitlement 设置为 `true`）的有效 task port。然而，即使具有 debugging tool entitlement，调试器也无法获得那些**没有 `Get Task Allow` entitlement**、因此受 System Integrity Protection 保护的进程的 task ports。详见 [此处了解更多](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)。

### `com.apple.security.cs.disable-library-validation`

该 entitlement 允许 **加载未由 Apple 签名或未使用与主执行文件相同 Team ID 签名** 的 frameworks、plug-ins 或 libraries，因此攻击者可能滥用任意库加载来注入代码。详见 [此处了解更多](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

此 entitlement 与 **`com.apple.security.cs.disable-library-validation`** 非常相似，但**不是直接禁用**库验证，而是允许进程**调用 `csops` 系统调用来禁用它**。\
详见 [此处了解更多](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

该 entitlement 允许使用可能用于注入 libraries 和代码的 **DYLD 环境变量**。详见 [此处了解更多](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**根据这篇博客**](https://objective-see.org/blog/blog_0x4C.html) **以及** [**这篇博客**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)，这些 entitlements 允许 **修改 TCC** 数据库。

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

这些 entitlements 允许 **在不提示用户许可的情况下安装软件**，这在 **提权** 场景中可能很有用。

### `com.apple.private.security.kext-management`

请求内核加载 kernel extension 所需的 entitlement。

### **`com.apple.private.icloud-account-access`**

拥有 **`com.apple.private.icloud-account-access`** entitlement 的进程可以与 **`com.apple.iCloudHelper`** XPC 服务通信，后者会**提供 iCloud tokens**。

**iMovie** 和 **Garageband** 曾拥有此 entitlement。

关于利用该 entitlement 获取 iCloud tokens 的更多信息，请参见演讲：[ #OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula ](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 我不知道这允许做什么

### `com.apple.private.apfs.revert-to-snapshot`

TODO: 在 [此报告](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) 中提到这可能被用来在重启后更新 SSV 保护的内容。如果你知道如何使用，欢迎提交 PR！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: 在 [此报告](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) 中提到这可能被用来在重启后更新 SSV 保护的内容。如果你知道如何使用，欢迎提交 PR！

### `keychain-access-groups`

该 entitlement 列出应用有权访问的 **钥匙串(keychain)** 组：
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

赋予 **Full Disk Access** 权限，这是你可以拥有的 TCC 最高权限之一。

### **`kTCCServiceAppleEvents`**

允许该应用向其他通常用于 **自动化任务** 的应用发送事件。通过控制其他应用，它可以滥用授予这些应用的权限。

例如，使它们向用户请求密码：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
或者让它们执行**任意操作**。

### **`kTCCServiceEndpointSecurityClient`**

允许（在其他权限之外）**写入用户的 TCC 数据库**。

### **`kTCCServiceSystemPolicySysAdminFiles`**

允许**更改**用户的**`NFSHomeDirectory`**属性，从而更改其主目录路径，因此可以**绕过 TCC**。

### **`kTCCServiceSystemPolicyAppBundles`**

允许修改应用包内的文件（位于 app.app 内），这在默认情况下是**不允许的**。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

可以在 _System Settings_ > _Privacy & Security_ > _App Management._ 中检查哪些应用拥有此访问权限。

### `kTCCServiceAccessibility`

该进程将能够**滥用 macOS 的辅助功能（accessibility）特性**，例如能够发送按键。因此它可以请求控制像 Finder 这样的应用并使用此权限批准对话框。

## Trustcache/CDhash related entitlements

有一些 entitlements 可被用于绕过 Trustcache/CDhash 保护，这些保护防止执行降级版本的 Apple 二进制文件。

## 中等

### `com.apple.security.cs.allow-jit`

该 entitlement 允许通过向 `mmap()` 系统函数传递 `MAP_JIT` 标志来**创建可写且可执行的内存**。参见 [**更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

该 entitlement 允许**覆盖或修补 C 代码**、使用早已废弃的 **`NSCreateObjectFileImageFromMemory`**（本质上不安全），或使用 **DVDPlayback** 框架。参见 [**更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> 包含此 entitlement 会使你的应用暴露于内存不安全语言中的常见漏洞。请认真考虑你的应用是否需要此例外。

### `com.apple.security.cs.disable-executable-page-protection`

该 entitlement 允许**修改其自身在磁盘上的可执行文件的部分区域**以强制退出。参见 [**更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> The Disable Executable Memory Protection Entitlement is an extreme entitlement that removes a fundamental security protection from your app, making it possible for an attacker to rewrite your app’s executable code without detection. Prefer narrower entitlements if possible.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

该 entitlement 允许挂载 nullfs 文件系统（默认被禁止）。工具： [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

根据这篇博客文章，这个 TCC 权限通常以以下形式出现：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
允许该进程**请求所有 TCC 权限**。

### **`kTCCServicePostEvent`**

允许通过 `CGEventPost()` 在系统范围内**注入合成的键盘和鼠标事件**。

拥有此权限的进程可以在任何应用中模拟按键、鼠标点击和滚动事件 —— 实际上可以对桌面进行**远程控制**。

当与 `kTCCServiceAccessibility` 或 `kTCCServiceListenEvent` 结合时，这尤其危险，因为它既允许读取又允许注入输入。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

允许在系统范围内**拦截所有键盘和鼠标事件**（input monitoring / keylogging）。进程可以注册一个 `CGEventTap` 来捕获在任何应用中输入的每一个按键，包括密码、信用卡号和私人消息。

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

允许**读取显示缓冲区**——对任意应用进行截图和录制屏幕视频，包括安全文本字段。结合 OCR，这可以自动从屏幕上提取密码和敏感数据。

> [!WARNING]
> Starting with macOS Sonoma, screen capture shows a persistent menu bar indicator. On older versions, screen recording can be completely silent.

### **`kTCCServiceCamera`**

允许从内置摄像头或连接的 USB 摄像头**捕获照片和视频**。Code injection 到具有 camera 权限的二进制文件可以实现静默的视觉监控。

### **`kTCCServiceMicrophone`**

允许**录制来自所有输入设备的音频**。有麦克风访问权限的后台守护进程可提供持续的环境音频监控，且没有可见的应用窗口。

### **`kTCCServiceLocation`**

允许通过 Wi‑Fi 三角定位或 Bluetooth 信标查询设备的**物理位置**。持续监控会暴露家庭/工作地址、出行模式和日常行程。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

访问 **Contacts**（姓名、电子邮件、电话 —— 对 spear-phishing 很有用）、**Calendar**（会议日程、与会者名单）和 **Photos**（个人照片、可能包含凭证的截图、位置元数据）。

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** 通过允许与系统范围的 Mach/XPC 服务通信来削弱 App Sandbox，而这些服务通常会被 sandbox 阻止。这是**主要的 sandbox escape primitive**——被攻破的 sandboxed 应用可以使用 mach-lookup 异常访问特权守护进程并利用它们的 XPC 接口。
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
有关详细利用链： sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape，参见：

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

DriverKit entitlements 允许用户态驱动二进制通过 IOKit 接口直接与内核通信。DriverKit 二进制负责管理硬件：USB、Thunderbolt、PCIe、HID 设备、音频和网络。

攻陷 DriverKit 二进制可导致：
- **内核攻击面** 通过畸形的 `IOConnectCallMethod` 调用
- **USB 设备伪装** (模拟键盘以进行 HID 注入)
- **DMA 攻击** 通过 PCIe/Thunderbolt 接口
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
有关 IOKit/DriverKit exploitation 的详细信息，请参阅：

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
