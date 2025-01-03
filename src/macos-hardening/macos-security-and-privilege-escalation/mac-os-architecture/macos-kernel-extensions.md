# macOS 内核扩展与调试

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

内核扩展（Kexts）是 **以 `.kext`** 扩展名的 **包**，它们 **直接加载到 macOS 内核空间**，为主操作系统提供额外功能。

### 要求

显然，这非常强大，以至于 **加载内核扩展** 是 **复杂的**。内核扩展必须满足以下 **要求** 才能被加载：

- 当 **进入恢复模式** 时，内核 **扩展必须被允许** 加载：

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- 内核扩展必须 **使用内核代码签名证书签名**，该证书只能由 **Apple** 授予。谁将详细审查公司及其所需的原因。
- 内核扩展还必须 **经过公证**，Apple 将能够检查其是否含有恶意软件。
- 然后，**root** 用户是唯一可以 **加载内核扩展** 的人，包内的文件必须 **属于 root**。
- 在上传过程中，包必须准备在 **受保护的非 root 位置**：`/Library/StagedExtensions`（需要 `com.apple.rootless.storage.KernelExtensionManagement` 授权）。
- 最后，当尝试加载时，用户将 [**收到确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)，如果接受，计算机必须 **重启** 以加载它。

### 加载过程

在 Catalina 中是这样的：有趣的是，**验证** 过程发生在 **用户空间**。然而，只有具有 **`com.apple.private.security.kext-management`** 授权的应用程序可以 **请求内核加载扩展**：`kextcache`，`kextload`，`kextutil`，`kextd`，`syspolicyd`

1. **`kextutil`** cli **启动** 加载扩展的 **验证** 过程
- 它将通过发送 **Mach 服务** 与 **`kextd`** 进行通信。
2. **`kextd`** 将检查多个事项，例如 **签名**
- 它将与 **`syspolicyd`** 进行通信以 **检查** 扩展是否可以 **加载**。
3. **`syspolicyd`** 将 **提示** **用户** 如果扩展尚未被加载。
- **`syspolicyd`** 将结果报告给 **`kextd`**
4. **`kextd`** 最终将能够 **告诉内核加载** 扩展

如果 **`kextd`** 不可用，**`kextutil`** 可以执行相同的检查。

### 枚举（已加载的 kexts）
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> 尽管内核扩展预计位于 `/System/Library/Extensions/` 中，但如果你去这个文件夹，你 **找不到任何二进制文件**。这是因为 **kernelcache**，为了反向工程一个 `.kext`，你需要找到获取它的方法。

**kernelcache** 是 **XNU 内核的预编译和预链接版本**，以及必要的设备 **驱动程序** 和 **内核扩展**。它以 **压缩** 格式存储，并在启动过程中解压到内存中。kernelcache 通过提供一个准备就绪的内核和关键驱动程序的版本，促进了 **更快的启动时间**，减少了在启动时动态加载和链接这些组件所需的时间和资源。

### Local Kerlnelcache

在 iOS 中，它位于 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**，在 macOS 中你可以通过以下命令找到它：**`find / -name "kernelcache" 2>/dev/null`** \
在我的 macOS 中，我找到了它在：

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 文件格式是苹果在其 iOS 和 macOS 设备中用于安全 **存储和验证固件** 组件（如 **kernelcache**）的容器格式。IMG4 格式包括一个头部和几个标签，这些标签封装了不同的数据片段，包括实际的有效载荷（如内核或引导加载程序）、签名和一组清单属性。该格式支持加密验证，允许设备在执行固件组件之前确认其真实性和完整性。

它通常由以下组件组成：

- **有效载荷 (IM4P)**：
- 通常是压缩的 (LZFSE4, LZSS, …)
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
# img4tool (https://github.com/tihmstar/img4tool
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
### 检查 kernelcache

检查 kernelcache 是否具有符号。
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
## 调试

## 参考文献

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
