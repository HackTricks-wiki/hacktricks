# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

Kernel extensions（Kexts）是带有 **`.kext`** 扩展名的 **packages**，它们会被**直接加载到 macOS 内核空间**，为主操作系统提供额外功能。

### 弃用状态与 DriverKit / System Extensions
从 **macOS Catalina (10.15)** 开始，Apple 将大多数旧版 KPI 标记为*弃用*，并引入了运行在**用户空间**的 **System Extensions & DriverKit** frameworks。从 **macOS Big Sur (11)** 开始，除非机器以 **Reduced Security** 模式启动，否则操作系统将*拒绝加载*依赖已弃用 KPI 的第三方 kext。在 Apple Silicon 上，启用 kext 还要求用户：

1. 重启进入 **Recovery** → *Startup Security Utility*。
2. 选择 **Reduced Security**，并勾选 **“Allow user management of kernel extensions from identified developers”**。
3. 重启，并从 **System Settings → Privacy & Security** 批准该 kext。

使用 DriverKit/System Extensions 编写的用户态 drivers 能显著**减少攻击面**，因为崩溃或内存损坏会被限制在 sandboxed process 中，而不是发生在内核空间。<sup>[[1]](#references)</sup>

> 📝 从 macOS Sequoia (15) 开始，Apple 已完全移除多个旧版 networking 和 USB KPI——对 vendors 而言，唯一向前兼容的解决方案是迁移到 System Extensions。

### 要求

显然，这项功能非常强大，因此**加载 kernel extension** 会比较**复杂**。kernel extension 必须满足以下**要求**才能被加载：

- **进入 recovery mode** 时，必须允许加载 kernel **extensions**：

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension 必须使用 kernel code signing certificate **签名**，该证书只能由 **Apple** 授予。Apple 将详细审核公司及其申请理由。
- kernel extension 还必须经过 **notarized**，Apple 将能够检查其中是否存在 malware。
- 然后，只有 **root** 用户才能**加载 kernel extension**，并且 package 内的文件必须**属于 root**。
- 在 upload 过程中，package 必须准备在一个受保护的非 root 位置：`/Library/StagedExtensions`（需要 `com.apple.rootless.storage.KernelExtensionManagement` grant）。
- 最后，在尝试加载它时，用户将[**收到确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)，如果接受，则必须**重启**计算机才能加载它。

### 加载过程

在 Catalina 中，过程如下：值得注意的是，**verification** 过程发生在**用户态**。但是，只有具有 **`com.apple.private.security.kext-management`** grant 的 applications 才能**请求内核加载 extension**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli **启动**加载 extension 的 **verification** 过程
- 它会通过 Mach service 发送请求，与 **`kextd`** 通信。
2. **`kextd`** 将检查多项内容，例如**签名**
- 它会与 **`syspolicyd`** 通信，以**检查**该 extension 是否可以被**加载**。
3. 如果该 extension 之前未被加载，**`syspolicyd`** 将向**用户**显示提示。
- **`syspolicyd`** 会将结果报告给 **`kextd`**
4. **`kextd`** 最终能够通知内核**加载**该 extension

如果 **`kextd`** 不可用，**`kextutil`** 可以执行相同的检查。

### 枚举与管理（已加载的 kexts）

`kextstat` 曾是历史上的工具，但在较新的 macOS 版本中已被**弃用**。现代接口是 **`kmutil`**：
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
旧版语法仍可供参考：
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` 还可用于 **dump Kernel Collection (KC) 的内容**，或验证某个 kext 是否解析了所有符号依赖：
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> 尽管 kernel extensions 预计位于 `/System/Library/Extensions/` 中，但如果你进入此文件夹，**不会找到任何 binary**。这是因为存在 **kernelcache**；要 reverse 一个 `.kext`，你需要找到获取它的方法。

**kernelcache** 是 **XNU kernel** 的**预编译和预链接版本**，其中包含必要的设备 **drivers** 和 **kernel extensions**。它以**压缩**格式存储，并在启动过程中被解压到内存中。kernelcache 通过提供一个可直接运行的 kernel 版本以及关键 drivers，减少了启动时动态加载和链接这些组件所需的时间与资源，从而实现**更快的启动速度**。

kernelcache 的主要优势是**加载速度**，并且所有 modules 都已预先链接（不会产生加载时间阻碍）。此外，一旦所有 modules 完成预链接，就可以从内存中移除 KXLD，因此 **XNU 无法加载新的 KEXTs。**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) 工具可以解密 Apple 的 AEA（Apple Encrypted Archive / AEA asset）containers —— 这是 Apple 用于 OTA assets 和部分 IPSW pieces 的加密 container 格式 —— 并生成底层的 .dmg/asset archive，随后你可以使用提供的 aastuff tools 将其 extract。


### Local Kernelcache

在 iOS 中，它位于 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**；在 macOS 中，你可以使用：**`find / -name "kernelcache" 2>/dev/null`** \
在我的 macOS 环境中，我在这里找到了它：

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

另请在此处查找[**带有 symbols 的 version 14 kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en)。

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format 是 Apple 在其 iOS 和 macOS devices 中使用的一种 container format，用于安全地**存储和验证 firmware** components（例如 **kernelcache**）。IMG4 format 包含一个 header 和多个 tags，用于封装不同的数据片段，包括实际的 payload（例如 kernel 或 bootloader）、signature，以及一组 manifest properties。该 format 支持 cryptographic verification，使 device 能够在执行 firmware component 之前确认其 authenticity 和 integrity。

它通常由以下 components 组成：

- **Payload (IM4P)**：
- 通常经过压缩（LZFSE4、LZSS、……）
- 可选加密
- **Manifest (IM4M)**：
- 包含 Signature
- Additional Key/Value dictionary
- **Restore Info (IM4R)**：
- 也称为 APNonce
- 防止 replay 某些 updates
- OPTIONAL：通常不会找到

Decompress the Kernelcache：
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### 用于 kernel 的 Disarm symbols

**`Disarm`** 允许使用 matchers 对 kernelcache 中的函数进行 symbolicate。这些 matchers 只是简单的 pattern rules（文本行），用于告诉 disarm 如何识别并自动 symbolicate 二进制文件中的函数、参数以及 panic/log 字符串。

基本上，你只需要指定某个函数使用的字符串，disarm 就会找到它并对其进行 **symbolicate**。

你可以在 [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) 的 **`Matchers`** 部分找到一些 `xnu.matchers`。你也可以创建自己的 matchers。
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### 下载

**IPSW（iPhone/iPad Software）** 是 Apple 用于设备恢复、更新和完整 firmware bundle 的 firmware package 格式。其中包含 **kernelcache**。

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

在 [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) 中可以找到所有 kernel debug kits。你可以下载并挂载它，然后使用 [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) 工具打开，访问 **`.kext`** 文件夹并将其**提取出来**。

使用以下命令检查其中的 symbols：
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

有时 Apple 会发布带有 **symbols** 的 **kernelcache**。你可以通过这些页面上的链接下载一些带有 symbols 的 firmwares。这些 firmwares 除了其他文件外，还会包含 **kernelcache**。

要 **extract** kernel cache，可以执行：
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
另一种**提取**文件的方法是先将扩展名从 `.ipsw` 更改为 `.zip`，然后将其**解压**。

解压固件后，你会得到类似 **`kernelcache.release.iphone14`** 的文件。它采用 **IMG4** 格式，你可以使用以下工具提取其中的有用信息：

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**：**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### 检查 kernelcache

使用以下命令检查 kernelcache 是否包含 symbols：
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
这样我们现在可以**提取所有扩展**，或是**你感兴趣的那个扩展：**
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
## 最新漏洞与 exploitation 技术

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`** 中的逻辑缺陷允许 *root* attacker 注册恶意文件系统 bundle，最终加载**未签名 kext**，从而**绕过 System Integrity Protection (SIP)** 并实现持久化 rootkit。已在 macOS 14.2 / 15.2 中修复。 <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | 具有 `com.apple.rootless.install` entitlement 的安装 daemon 可被滥用来执行任意 post-install scripts、禁用 SIP 并加载任意 kext。 <sup>[[3]](#references)</sup> |

**给 red-teamers 的要点**

1. **查找具有 entitlement 的 daemon（`codesign -dvv /path/bin | grep entitlements`），尤其关注与 Disk Arbitration、Installer 或 Kext Management 交互的 daemon。**
2. **滥用 SIP bypass 几乎总能获得加载 kext 的能力 → 执行 kernel code**。

**防御建议**

*保持 SIP 启用*，监控来自非 Apple binaries 的 `kmutil load`/`kmutil create -n aux` 调用，并针对任何写入 `/Library/Extensions` 的行为发出告警。Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` 可提供近实时的可见性。

## 调试 macOS kernel 与 kexts

Apple 推荐的工作流程是构建一个与当前运行 build 匹配的 **Kernel Debug Kit (KDK)**，然后通过 **KDP (Kernel Debugging Protocol)** 网络会话连接 **LLDB**。

### 一次性本地调试 panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### 从另一台 Mac 进行实时远程调试

1. 下载并安装与目标机器完全匹配的 **KDK** 版本。
2. 使用 **USB-C 或 Thunderbolt cable** 连接目标 Mac 和主机 Mac。
3. 在**目标 Mac** 上：
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. 在 **host** 上：
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### 将 LLDB 附加到指定的已加载 kext
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP 仅公开 **只读** 接口。要进行 dynamic instrumentation，你需要修补磁盘上的 binary、利用 **kernel function hooking**（例如 `mach_override`），或将 driver 迁移到 **hypervisor**，以实现完整的读写功能。

## 参考资料

- [1] [macOS 的 DriverKit 安全性 - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [分析 CVE-2024-44243：一种通过 kernel extensions 绕过 macOS System Integrity Protection 的漏洞 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft 发现新的 macOS 漏洞 Shrootless，该漏洞可绕过 System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
