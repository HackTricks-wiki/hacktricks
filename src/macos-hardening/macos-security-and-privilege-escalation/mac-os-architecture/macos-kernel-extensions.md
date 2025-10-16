# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) are **packages** with a **`.kext`** extension that are **loaded directly into the macOS kernel space**, providing additional functionality to the main operating system.

### Deprecation status & DriverKit / System Extensions
Starting with **macOS Catalina (10.15)** Apple marked most legacy KPIs as *deprecated* and introduced the **System Extensions & DriverKit** frameworks that run in **user-space**. From **macOS Big Sur (11)** the operating system will *refuse to load* third-party kexts that rely on deprecated KPIs unless the machine is booted in **Reduced Security** mode. On Apple Silicon, enabling kexts additionally requires the user to:

1. Reboot into **Recovery** → *Startup Security Utility*.
2. Select **Reduced Security** and tick **“Allow user management of kernel extensions from identified developers”**.
3. Reboot and approve the kext from **System Settings → Privacy & Security**.

User-land drivers written with DriverKit/System Extensions dramatically **reduce attack surface** because crashes or memory corruption are confined to a sandboxed process rather than kernel space.

> 📝 From macOS Sequoia (15) Apple has removed several legacy networking and USB KPIs entirely – the only forward-compatible solution for vendors is to migrate to System Extensions.

### Requirements

Obviously, this is so powerful that it is **complicated to load a kernel extension**. These are the **requirements** that a kernel extension must meet to be loaded:

- When **entering recovery mode**, kernel **extensions must be allowed** to be loaded:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- The kernel extension must be **signed with a kernel code signing certificate**, which can only be **granted by Apple**. Who will review in detail the company and the reasons why it is needed.
- The kernel extension must also be **notarized**, Apple will be able to check it for malware.
- Then, the **root** user is the one who can **load the kernel extension** and the files inside the package must **belong to root**.
- During the upload process, the package must be prepared in a **protected non-root location**: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Finally, when attempting to load it, the user will [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) and, if accepted, the computer must be **restarted** to load it.

### Loading process

In Catalina it was like this: It is interesting to note that the **verification** process occurs in **userland**. However, only applications with the **`com.apple.private.security.kext-management`** grant can **request the kernel to load an extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **starts** the **verification** process for loading an extension
- It will talk to **`kextd`** by sending using a **Mach service**.
2. **`kextd`** will check several things, such as the **signature**
- It will talk to **`syspolicyd`** to **check** if the extension can be **loaded**.
3. **`syspolicyd`** will **prompt** the **user** if the extension has not been previously loaded.
- **`syspolicyd`** will report the result to **`kextd`**
4. **`kextd`** will finally be able to **tell the kernel to load** the extension

If **`kextd`** is not available, **`kextutil`** can perform the same checks.

### Enumeration & management (loaded kexts)

`kextstat` was the historical tool but it is **deprecated** in recent macOS releases. The modern interface is **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
旧语法仍可作为参考：
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` 也可用于 **转储 Kernel Collection (KC) 的内容** 或验证 kext 是否解析了所有符号依赖：
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> 即便 kernel extensions 预期位于 `/System/Library/Extensions/`，如果你进入该文件夹你 **不会找到任何二进制文件**。这是由于 **kernelcache** 的存在，若要对某个 `.kext` 进行逆向，你需要想办法获得它。

The **kernelcache** 是 XNU kernel 的一个 **预编译且预链接的版本**，同时包含必要的设备 **drivers** 和 **kernel extensions**。它以 **压缩** 格式存储，并在启动过程中解压到内存。kernelcache 通过提供一个可直接运行的内核和关键 drivers 的版本来加快启动时间，减少在启动时动态加载和链接这些组件所需的时间和资源。

kernelcache 的主要优点是 **加载速度**，并且所有模块都已预链接（没有加载时的阻碍）。一旦所有模块被预链接，KXLD 可以从内存中移除，因此 **XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool 解密 Apple 的 AEA (Apple Encrypted Archive / AEA asset) 容器——Apple 用于 OTA 资产和某些 IPSW 组件的加密容器格式——并能生成底层的 .dmg/asset 存档，然后你可以使用随附的 aastuff 工具提取它。

### Local Kerlnelcache

在 iOS 中它位于 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**，在 macOS 上你可以用：**`find / -name "kernelcache" 2>/dev/null`** 来查找。 \
就我在 macOS 上的情况，我在以下位置找到了它：

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

也可以在这里找到 [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en)。

#### IMG4 / BVX2 (LZFSE) compressed

The IMG4 file format 是 Apple 在其 iOS 和 macOS 设备中用于安全地 **存储和验证固件** 组件（例如 **kernelcache**）的容器格式。IMG4 格式包含一个头部和若干标签，这些标签封装了不同的数据片段，包括实际的 payload（例如内核或 bootloader）、签名，以及一组 manifest 属性。该格式支持加密验证，使设备在执行固件组件之前能够确认其真实性和完整性。

It's usually composed of the following components:

- **Payload (IM4P)**:
  - Often compressed (LZFSE4, LZSS, …)
  - Optionally encrypted
- **Manifest (IM4M)**:
  - Contains Signature
  - Additional Key/Value dictionary
- **Restore Info (IM4R)**:
  - Also known as APNonce
  - Prevents replaying of some updates
  - OPTIONAL: Usually this isn't found

Decompress the Kernelcache:
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
#### Disarm 内核符号

**`Disarm`** 允许使用 matchers 从 kernelcache 对函数进行 symbolicate。

这些 matchers 只是简单的模式规则（文本行），用于告诉 disarm 如何识别并 auto-symbolicate 二进制中的函数、参数和 panic/log 字符串。

所以基本上你指出函数使用的字符串，disarm 会找到它并 **symbolicate it**。
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# 转到 /tmp/extracted（disarm 解压 filesets 的位置）
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
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
# 安装 ipsw 工具
brew install blacktop/tap/ipsw

# 仅从 IPSW 提取 kernelcache
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# 你应该得到类似:
#   out/Firmware/kernelcache.release.iPhoneXX
#   或者为 IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# 如果得到 IMG4 payload:
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
# 列出所有扩展
kextex -l kernelcache.release.iphone14.e
## 提取 com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# 提取所有
kextex_all kernelcache.release.iphone14.e

# 检查扩展是否有符号
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
# 为最新 panic 创建符号化包
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
(lldb) bt  # 在内核上下文获取回溯
```

### Attaching LLDB to a specific loaded kext

```bash
# 确定 kext 的加载地址
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# 附加
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
