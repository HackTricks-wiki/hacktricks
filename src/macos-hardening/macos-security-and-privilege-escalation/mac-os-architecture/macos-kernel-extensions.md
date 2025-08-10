# macOS 内核扩展与调试

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

内核扩展（Kexts）是 **以 `.kext` 为扩展名的包**，直接 **加载到 macOS 内核空间**，为主操作系统提供额外功能。

### 废弃状态与 DriverKit / 系统扩展
从 **macOS Catalina (10.15)** 开始，Apple 将大多数遗留 KPI 标记为 *废弃*，并引入了 **系统扩展和 DriverKit** 框架，这些框架在 **用户空间** 中运行。从 **macOS Big Sur (11)** 开始，操作系统将 *拒绝加载* 依赖于废弃 KPI 的第三方 kext，除非机器以 **降低安全性** 模式启动。在 Apple Silicon 上，启用 kext 还要求用户：

1. 重启进入 **恢复** → *启动安全实用工具*。
2. 选择 **降低安全性** 并勾选 **“允许用户管理来自已识别开发者的内核扩展”**。
3. 重启并在 **系统设置 → 隐私与安全** 中批准 kext。

使用 DriverKit/系统扩展编写的用户空间驱动程序显著 **减少攻击面**，因为崩溃或内存损坏被限制在沙盒进程中，而不是内核空间。

> 📝 从 macOS Sequoia (15) 开始，Apple 完全移除了几个遗留的网络和 USB KPI – 唯一向前兼容的解决方案是迁移到系统扩展。

### 要求

显然，这么强大以至于 **加载内核扩展** 是 **复杂的**。内核扩展必须满足以下 **要求** 才能被加载：

- 当 **进入恢复模式** 时，必须 **允许加载内核扩展**：

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- 内核扩展必须 **使用内核代码签名证书签名**，该证书只能由 **Apple 授予**。Apple 将详细审核公司及其所需原因。
- 内核扩展还必须 **经过公证**，Apple 将能够检查其是否含有恶意软件。
- 然后，**root** 用户是唯一可以 **加载内核扩展** 的人，包内的文件必须 **属于 root**。
- 在上传过程中，包必须准备在 **受保护的非 root 位置**：`/Library/StagedExtensions`（需要 `com.apple.rootless.storage.KernelExtensionManagement` 授权）。
- 最后，在尝试加载时，用户将 [**收到确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)，如果接受，计算机必须 **重启** 以加载它。

### 加载过程

在 Catalina 中是这样的：有趣的是，**验证** 过程发生在 **用户空间**。然而，只有具有 **`com.apple.private.security.kext-management`** 授权的应用程序可以 **请求内核加载扩展**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli **启动** 加载扩展的 **验证** 过程
- 它将通过使用 **Mach 服务** 与 **`kextd`** 进行通信。
2. **`kextd`** 将检查多个事项，例如 **签名**
- 它将与 **`syspolicyd`** 进行通信以 **检查** 扩展是否可以 **加载**。
3. **`syspolicyd`** 将 **提示** **用户** 如果扩展尚未被加载。
- **`syspolicyd`** 将结果报告给 **`kextd`**
4. **`kextd`** 最终将能够 **告诉内核加载** 扩展

如果 **`kextd`** 不可用，**`kextutil`** 可以执行相同的检查。

### 枚举与管理（已加载的 kexts）

`kextstat` 是历史工具，但在最近的 macOS 版本中已 **废弃**。现代接口是 **`kmutil`**：
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
旧语法仍可供参考：
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` 还可以用于 **转储内核集合 (KC)** 的内容或验证 kext 是否解析所有符号依赖：
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> 尽管内核扩展预计位于 `/System/Library/Extensions/` 中，但如果你去这个文件夹，你 **不会找到任何二进制文件**。这是因为 **kernelcache**，为了反向工程一个 `.kext`，你需要找到获取它的方法。

**kernelcache** 是 **XNU 内核的预编译和预链接版本**，以及必要的设备 **驱动程序** 和 **内核扩展**。它以 **压缩** 格式存储，并在启动过程中解压到内存中。kernelcache 通过提供一个准备就绪的内核和关键驱动程序的版本，促进了 **更快的启动时间**，减少了在启动时动态加载和链接这些组件所需的时间和资源。

### Local Kerlnelcache

在 iOS 中，它位于 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**，在 macOS 中你可以通过以下命令找到它：**`find / -name "kernelcache" 2>/dev/null`** \
在我的 macOS 中，我找到了它在：

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 文件格式是苹果在其 iOS 和 macOS 设备中用于安全 **存储和验证固件** 组件（如 **kernelcache**）的容器格式。IMG4 格式包括一个头部和几个标签，这些标签封装了不同的数据片段，包括实际的有效载荷（如内核或引导加载程序）、签名和一组清单属性。该格式支持加密验证，允许设备在执行固件组件之前确认其真实性和完整性。

它通常由以下组件组成：

- **有效载荷 (IM4P)**：
- 通常被压缩（LZFSE4, LZSS, …）
- 可选加密
- **清单 (IM4M)**：
- 包含签名
- 额外的键/值字典
- **恢复信息 (IM4R)**：
- 也称为 APNonce
- 防止某些更新的重放
- 可选：通常不会找到

解压 Kernelcache：
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### 下载

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

在 [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) 可以找到所有的内核调试工具包。你可以下载它，挂载它，用 [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) 工具打开它，访问 **`.kext`** 文件夹并 **提取它**。

使用以下命令检查符号：
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

有时，Apple 会发布带有 **symbols** 的 **kernelcache**。您可以通过这些页面上的链接下载一些带有符号的固件。固件将包含 **kernelcache** 以及其他文件。

要 **extract** 文件，首先将扩展名从 `.ipsw` 更改为 `.zip` 并 **unzip** 它。

提取固件后，您将获得一个文件，如：**`kernelcache.release.iphone14`**。它是 **IMG4** 格式，您可以使用以下工具提取有趣的信息：

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

检查 kernelcache 是否具有符号
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
通过这个，我们现在可以**提取所有扩展**或**您感兴趣的扩展：**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## 最近的漏洞与利用技术

| 年份 | CVE | 摘要 |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`** 中的逻辑缺陷允许 *root* 攻击者注册一个恶意文件系统包，最终加载一个 **未签名的 kext**，**绕过系统完整性保护 (SIP)** 并启用持久性 rootkit。已在 macOS 14.2 / 15.2 中修补。   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | 带有 `com.apple.rootless.install` 权限的安装守护进程可能被滥用以执行任意后安装脚本，禁用 SIP 并加载任意 kext。  |

**红队员的要点**

1. **寻找与磁盘仲裁、安装程序或 Kext 管理交互的有权限的守护进程 (`codesign -dvv /path/bin | grep entitlements`)。**
2. **滥用 SIP 绕过几乎总是授予加载 kext 的能力 → 内核代码执行**。

**防御提示**

*保持 SIP 启用*，监控来自非 Apple 二进制文件的 `kmutil load`/`kmutil create -n aux` 调用，并对任何写入 `/Library/Extensions` 的操作发出警报。端点安全事件 `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` 提供近实时的可见性。

## 调试 macOS 内核与 kexts

苹果推荐的工作流程是构建一个与正在运行的版本匹配的 **内核调试工具包 (KDK)**，然后通过 **KDP (内核调试协议)** 网络会话附加 **LLDB**。

### 一次性本地调试 panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### 从另一台 Mac 进行实时远程调试

1. 下载并安装目标机器的确切 **KDK** 版本。
2. 使用 **USB-C 或 Thunderbolt 电缆** 将目标 Mac 和主机 Mac 连接起来。
3. 在 **目标**：
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. 在**主机**上：
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### 将 LLDB 附加到特定加载的 kext
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP 仅暴露一个 **只读** 接口。对于动态插桩，您需要在磁盘上修补二进制文件，利用 **内核函数钩子**（例如 `mach_override`）或将驱动程序迁移到 **虚拟机监控程序** 以实现完全的读/写。

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
