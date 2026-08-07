# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

I/O Kit 是 XNU kernel 中开源的、面向对象的 **device-driver framework**，用于处理 **dynamically loaded device drivers**。它允许将模块化代码动态添加到 kernel 中，从而支持多种硬件。

IOKit drivers 基本上会 **export functions from the kernel**。这些函数参数的 **types** 是 **predefined** 的，并且会经过验证。此外，与 XPC 类似，IOKit 只是构建在 **Mach messages** 之上的另一层。

**IOKit XNU kernel code** 由 Apple 在 [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) 中开源。此外，user space IOKit components 也已开源：[https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

不过，**没有任何 IOKit drivers** 是开源的。尽管如此，某些 driver 的发布版本有时会包含 symbols，从而使调试更加容易。查看如何[**从 firmware 中获取 driver extensions**](#ipsw)**。**

它使用 **C++** 编写。你可以使用以下命令获取经过 demangle 的 C++ symbols：
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions** 在客户端尝试调用函数时可能会执行**额外的安全检查**，但请注意，应用通常会受到 **sandbox** 的限制，只能与部分 IOKit 函数进行交互。

## 驱动程序

在 macOS 中，它们位于：

- **`/System/Library/Extensions`**
- 内置于 OS X 操作系统中的 KEXT 文件。
- **`/Library/Extensions`**
- 由第三方软件安装的 KEXT 文件

在 iOS 中，它们位于：

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
直到编号 9，所列出的 drivers 都是**加载在地址 0**。这意味着它们并不是真正的 drivers，而是**kernel 的一部分，无法被卸载**。

要查找特定的 extensions，可以使用：
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
要加载和卸载 kernel extensions，请执行：
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** 是 macOS 和 iOS 中 IOKit framework 的关键组成部分，用作表示系统硬件配置和状态的数据库。它是一个**分层对象集合，用于表示系统上加载的所有硬件和驱动程序**，以及它们之间的关系。

你可以使用 CLI **`ioreg`** 从 console 检查 IORegistry（对 iOS 特别有用）。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
你可以从 [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) 的 **Xcode Additional Tools** 中下载 **`IORegistryExplorer`**，并通过**图形化**界面检查 **macOS IORegistry**。

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

在 IORegistryExplorer 中，"planes" 用于组织和显示 IORegistry 中不同对象之间的关系。每个 plane 表示特定类型的关系，或系统硬件与驱动配置的特定视图。以下是你可能在 IORegistryExplorer 中遇到的一些常见 plane：

1. **IOService Plane**：这是最通用的 plane，显示代表驱动和 nubs（驱动之间通信通道）的 service objects。它展示这些对象之间的 provider-client 关系。
2. **IODeviceTree Plane**：此 plane 表示设备连接到系统后的物理连接关系。它通常用于可视化通过 USB 或 PCI 等总线连接的设备层级结构。
3. **IOPower Plane**：根据电源管理显示对象及其关系。它可以显示哪些对象正在影响其他对象的电源状态，对于调试电源相关问题很有用。
4. **IOUSB Plane**：专门关注 USB 设备及其关系，显示 USB hubs 和已连接设备的层级结构。
5. **IOAudio Plane**：此 plane 用于表示系统中的音频设备及其关系。
6. ...

## Driver Comm Code Example

以下代码连接到 IOKit service `YourServiceNameHere`，并调用 selector 0：

- 首先调用 **`IOServiceMatching`** 和 **`IOServiceGetMatchingServices`** 来获取 service。
- 然后调用 **`IOServiceOpen`** 建立连接。
- 最后调用 **`IOConnectCallScalarMethod`** 执行函数，并指定 selector 0（selector 是要调用的函数所分配的编号）。

<details>
<summary>Example user-space call to a driver selector</summary>
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
</details>

还有**其他**可用于调用 IOKit 函数的 function，除了 **`IOConnectCallScalarMethod`**，例如 **`IOConnectCallMethod`**、**`IOConnectCallStructMethod`**……

## 逆向 driver entrypoint

例如，你可以从 [**firmware image (ipsw)**](#ipsw) 中获取这些内容。然后，将其加载到你喜欢的 decompiler 中。

你可以从反编译 **`externalMethod`** function 开始，因为这是接收调用并调用正确 function 的 driver function：

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

那个糟糕的调用名称反混淆后意味着：
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
注意，在前面的定义中遗漏了 **`self`** 参数，正确的定义应为：
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
实际上，你可以在 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) 中找到真正的定义：
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
使用这些信息，你可以重写 Ctrl+Right -> `Edit function signature`，并设置已知类型：

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

新的反编译代码如下：

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

下一步需要定义 **`IOExternalMethodDispatch2022`** struct。它是 opensource 的，位于 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)，你可以定义它：

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

现在，沿着 `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`，你可以看到大量数据：

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

将 Data Type 更改为 **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

更改之后：

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

现在我们知道这里有一个**包含 7 个元素的数组**（检查最终的反编译代码），点击创建一个包含 7 个元素的数组：

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

创建数组后，你可以看到所有 exported functions：

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你还记得，要从 user space **call** 一个 **exported** function，我们不需要调用函数名称，而是调用 **selector number**。这里可以看到，selector **0** 是函数 **`initializeDecoder`**，selector **1** 是 **`startDecoder`**，selector **2** 是 **`initializeEncoder`**……

## 近期 IOKit attack surface（2023–2025）

- **通过 IOHIDFamily capture keystroke** – CVE-2024-27799（14.5）表明，即使启用了 secure input，权限过于宽松的 `IOHIDSystem` client 仍然可以获取 HID events；应确保 `externalMethod` handlers 强制执行 entitlements，而不只是检查 user-client type。<sup>[[2]](#references)</sup>
- **IOGPUFamily memory corruption** – CVE-2024-44197 和 CVE-2025-24257 修复了可由 sandboxed apps 触发的 OOB writes；这些 apps 会向 GPU user clients 传递格式错误的 variable-length data；常见 bug 是对 `IOConnectCallStructMethod` arguments 的 bounds 检查不充分。<sup>[[1]](#references)</sup>
- **Legacy keystroke monitoring** – CVE-2023-42891（14.2）确认 HID user clients 仍然是 sandbox-escape vector；应对所有暴露 keyboard/event queues 的 driver 进行 fuzz。<sup>[[3]](#references)</sup>

### Quick triage & fuzzing tips

- 从 userland 枚举 user client 的所有 external methods，为 fuzzer 提供初始输入：
```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
print(f"{sel:02d} {name}")
PY
```
- 进行逆向分析时，请注意 `IOExternalMethodDispatch2022` 的数量。近期 CVE 中常见的一种 bug 模式是，`structureInputSize`/`structureOutputSize` 与实际的 `copyin` 长度不一致，从而在 `IOConnectCallStructMethod` 中导致 heap OOB。
- Sandbox 的可达性仍取决于 entitlements。在花时间分析目标之前，请先检查第三方 app 是否被允许访问：
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- 对于 GPU/iomfb bugs，通过 `IOConnectCallMethod` 传递超大数组通常足以触发错误的边界检查。用于触发 size confusion 的最小 harness（selector X）：
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — 用户空间驱动程序

### 基本信息

**DriverKit** 是 Apple 用于替代 kernel extensions（kexts）的用户空间方案，于 macOS 10.15 中引入。DriverKit 二进制文件（`.dext` bundles）作为用户空间进程运行，但通过特权 IOKit interface 直接与 kernel 通信。<sup>[[4]](#references)</sup>

DriverKit extensions 管理以下硬件：
- **USB** controllers 和 devices
- **Thunderbolt** / PCIe devices
- **HID**（keyboards、mice、game controllers）
- **Audio** hardware
- **Networking** interfaces
- **Serial** 和 **Block Storage** devices

与 kexts 不同（kexts 要求以禁用 SIP 的方式启动，或经过 notarization），DriverKit extensions 通过 `SystemExtensions.framework` 安装，只需要用户**一次性批准**。<sup>[[5]](#references)</sup>

### 发现与枚举
```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```
### 安全影响

> [!WARNING]
> DriverKit binaries 具有与 **kernel 的直接 communication channel**。通过该 channel 发送 malformed messages 可能触发 kernel vulnerabilities。每个 driver 都会注册特定的 user-client classes，而 malformed `IOConnectCallMethod` calls 可能导致 kernel memory corruption。

**Attack surface:**
1. **Kernel IOKit message fuzzing** — 每个 DriverKit user-client 都会暴露可从 user space 调用的 selectors。Malformed arguments 会触发 kernel bugs。
2. **USB device spoofing** — 被 compromise 的 USB DriverKit binary 可以呈现恶意的 USB device profile（例如，模拟 keyboard 以进行 HID injection）。
3. **DMA attacks** — PCIe/Thunderbolt DriverKit extensions 可能具有对 physical memory 的 DMA access。
4. **Persistence** — 一旦作为 system extension 安装，DriverKit binaries 会跨 reboot 和 app updates 持久存在。

### DriverKit IOKit User-Client Fuzzing
```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
| grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```
### DriverKit CVE

| CVE | 描述 |
|---|---|
| CVE-2022-26766 | DriverKit USB stack 漏洞 —— kernel code execution |
| CVE-2021-30838 | graphic drivers 中的 IOKit user-client type confusion |
| CVE-2024-44197 | 通过 malformed DriverKit arguments 实现的 IOGPUFamily OOB write |

## 参考资料

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
