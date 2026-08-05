# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

Kernel extensions（Kexts）是扩展名为 **`.kext`** 的 **packages**，会被**直接加载到 macOS kernel space** 中，为主操作系统提供额外功能。

### 弃用状态与 DriverKit / System Extensions
从 **macOS Catalina (10.15)** 开始，Apple 将大多数 legacy KPI 标记为*deprecated*，并引入了运行在 **user-space** 中的 **System Extensions & DriverKit** frameworks。从 **macOS Big Sur (11)** 开始，除非机器以 **Reduced Security** 模式启动，否则操作系统将*拒绝加载*依赖 deprecated KPI 的第三方 kext。在 Apple Silicon 上，启用 kext 还要求用户：

1. 重启进入 **Recovery** → *Startup Security Utility*。
2. 选择 **Reduced Security**，并勾选 **“Allow user management of kernel extensions from identified developers”**。
3. 重启，并从 **System Settings → Privacy & Security** 中批准该 kext。

使用 DriverKit/System Extensions 编写的 User-land drivers 可以显著**减少 attack surface**，因为崩溃或内存损坏会被限制在 sandboxed process 中，而不是 kernel space 中。<sup>[[1]](#references)</sup>

> 📝 从 macOS Sequoia (15) 开始，Apple 已完全移除多个 legacy networking 和 USB KPI——对于 vendors 来说，唯一向前兼容的解决方案是迁移到 System Extensions。

### 要求

显然，这项功能非常强大，因此**加载 kernel extension 十分复杂**。kernel extension 要被加载，必须满足以下**要求**：

- **进入 recovery mode** 时，必须允许加载 kernel **extensions**：

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension 必须使用 kernel code signing certificate **进行签名**，该证书只能由 **Apple 授予**。Apple 会详细审核公司及其所需该证书的原因。
- kernel extension 还必须经过 **notarization**，Apple 将能够对其进行 malware 检查。
- 然后，只有 **root** user 才能**加载 kernel extension**，并且 package 内的文件必须**属于 root**。
- 在上传过程中，package 必须被准备在受保护的 non-root location：`/Library/StagedExtensions`（需要 `com.apple.rootless.storage.KernelExtensionManagement` grant）。
- 最后，在尝试加载它时，用户将[**收到确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)，并且如果接受，必须**重启 computer** 才能加载它。

### 加载过程

在 Catalina 中，流程如下：值得注意的是，**verification** 过程发生在 **userland** 中。不过，只有具有 **`com.apple.private.security.kext-management`** grant 的 applications 才能**请求 kernel 加载 extension**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli **启动**加载 extension 的 **verification** 过程
- 它会通过 **Mach service** 发送请求，与 **`kextd`** 通信。
2. **`kextd`** 会检查多项内容，例如 **signature**
- 它会与 **`syspolicyd`** 通信，以**检查**该 extension 是否可以被**加载**。
3. 如果该 extension 之前没有被加载过，**`syspolicyd`** 会向**用户发出提示**。
- **`syspolicyd`** 会将结果报告给 **`kextd`**
4. **`kextd`** 最终可以**通知 kernel 加载**该 extension

如果 **`kextd`** 不可用，**`kextutil`** 可以执行相同的检查。

### 枚举与管理（已加载的 kexts）

`kextstat` 曾是历史工具，但在近期 macOS 版本中已被**弃用**。现代接口是 **`kmutil`**：
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
较旧的语法仍可供参考：
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` 也可用于 **dump Kernel Collection (KC) 的内容**，或验证某个 kext 是否解析了所有符号依赖：
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> 尽管 kernel extensions 应位于 `/System/Library/Extensions/`，但如果你进入此文件夹，**不会找到任何 binary**。这是因为存在 **kernelcache**；要 reverse 一个 `.kext`，你需要找到获取它的方法。

**kernelcache** 是 **XNU kernel 的预编译和预链接版本**，其中包含必要的设备 **drivers** 和 **kernel extensions**。它以**压缩**格式存储，并在启动过程中解压到内存中。kernelcache 通过提供可直接运行的 kernel 和关键 drivers 版本来实现**更快的启动时间**，减少启动时动态加载和链接这些组件所需的时间与资源。

kernelcache 的主要优势是**加载速度**，并且所有 modules 都已预链接（不会产生加载时间开销）。而且，在所有 modules 完成预链接后，可以将 KXLD 从内存中移除，因此 **XNU 无法加载新的 KEXTs。**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) 工具可以解密 Apple 的 AEA（Apple Encrypted Archive / AEA asset）containers ——这是 Apple 用于 OTA assets 和部分 IPSW components 的加密 container 格式——并生成底层的 `.dmg`/asset archive，然后你可以使用随附的 aastuff tools 对其进行提取。


### 本地 Kernelcache

在 iOS 中，它位于 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**；在 macOS 中，你可以使用以下命令找到它：**`find / -name "kernelcache" 2>/dev/null`** \
在我的案例中，我在 macOS 中找到了它：

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

也可以在这里找到[**带有 symbols 的 version 14 kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en)。

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format 是 Apple 在其 iOS 和 macOS devices 中使用的 container format，用于安全地**存储和验证 firmware** components（例如 **kernelcache**）。IMG4 format 包含一个 header 和多个 tags，这些 tags 封装了不同的数据片段，包括实际的 payload（例如 kernel 或 bootloader）、signature，以及一组 manifest properties。该 format 支持 cryptographic verification，使 device 能够在执行 firmware component 之前确认其 authenticity 和 integrity。

它通常由以下 components 组成：

- **Payload (IM4P)**：
- 通常经过 compressed（LZFSE4、LZSS、……）
- 可选 encrypted
- **Manifest (IM4M)**：
- 包含 Signature
- Additional Key/Value dictionary
- **Restore Info (IM4R)**：
- 也称为 APNonce
- 防止 replay 某些 updates
- OPTIONAL：通常找不到此项

Decompress Kernelcache：
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
#### 为 kernel 禁用 symbols

**`Disarm`** allows to symbolicate functions from the kernelcache using matchers. 这些 matcher 只是简单的 pattern rules（文本行），用于告诉 disarm 如何在 binary 中识别并自动 symbolicate functions、arguments 以及 panic/log strings。

因此，你只需指定某个 function 使用的 string，disarm 就会找到它并对其进行 **symbolicate**。
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# 前往 disarm 提取 filesets 的 /tmp/extracted
disarm -e filesets kernelcache.release.d23 # 始终提取到 /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # 注意，xnu.matchers 实际上是包含 matchers 的文件
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# 安装 ipsw tool
brew install blacktop/tap/ipsw

# 仅从 IPSW 中提取 kernelcache
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# 你应该会得到类似以下内容：
#   out/Firmware/kernelcache.release.iPhoneXX
#   或 IMG4 payload：out/Firmware/kernelcache.release.iPhoneXX.im4p

# 如果得到的是 IMG4 payload：
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

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

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# 列出所有 extensions
kextex -l kernelcache.release.iphone14.e
## 提取 com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# 提取全部
kextex_all kernelcache.release.iphone14.e

# 检查 extension 中的 symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# 为最新的 panic 创建符号化 bundle
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # 获取 kernel context 中的 backtrace
```

### Attaching LLDB to a specific loaded kext

```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
