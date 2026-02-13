# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

I/O Kit 是 XNU 内核中的一个开源、面向对象的 **设备驱动框架**，负责处理 **动态加载的设备驱动**。它允许将模块化代码即时添加到内核，以支持多样化的硬件。

IOKit 驱动基本上会 **从内核导出函数**。这些函数的参数 **类型** 是 **预定义的** 并会被验证。此外，类似于 XPC，IOKit 只是基于 **Mach 消息** 之上的另一层。

**IOKit XNU kernel code** 已由 Apple 在 [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) 开源。此外，用户空间的 IOKit 组件也已开源 [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

然而，**没有 IOKit 驱动** 是开源的。不过，驱动的某些发行版有时会附带符号，这会使调试更容易。查看如何 [**在此从固件获取驱动扩展**](#ipsw)**.**

它是用 **C++** 编写的。你可以使用以下方式获得反修饰的 C++ 符号：
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions** 在客户端尝试调用函数时可能会执行 **额外的安全检查**，但请注意，应用通常受 **sandbox** 的限制，只能与特定的 IOKit functions 交互。

## 驱动程序

在 macOS 中它们位于：

- **`/System/Library/Extensions`**
- KEXT files built into the OS X operating system.
- **`/Library/Extensions`**
- 由第三方软件安装的 KEXT 文件

在 iOS 中它们位于：

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
直到编号 9，列出的驱动都被**加载在地址 0**。这意味着它们不是真正的驱动，而是**内核的一部分，无法被卸载**。

为了查找特定的扩展，你可以使用：
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
要加载和卸载内核扩展，请执行：
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

The **IORegistry** 是 IOKit 框架在 macOS 和 iOS 中的关键部分，充当表示系统硬件配置和状态的数据库。它是一个 **分层的对象集合，表示系统中加载的所有硬件和驱动程序** 以及它们彼此之间的关系。

你可以使用命令行 **`ioreg`** 从控制台获取 IORegistry 并进行检查（在 iOS 上尤其有用）。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **graphical** interface.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

在 IORegistryExplorer 中，“planes”用于组织并展示 IORegistry 中不同对象之间的关系。每个 plane 表示一类特定的关系或系统硬件与驱动配置的某种视图。下面是 IORegistryExplorer 中常见的一些 planes：

1. **IOService Plane**: 这是最通用的 plane，显示表示驱动和 nubs（驱动之间的通信通道）的 service 对象。它展示这些对象之间的提供者-客户端（provider-client）关系。
2. **IODeviceTree Plane**: 该 plane 表示设备附着到系统时的物理连接。它常用于可视化通过 USB 或 PCI 等总线连接的设备层次结构。
3. **IOPower Plane**: 按电源管理的角度显示对象及其关系。它可以展示哪些对象影响其他对象的电源状态，对于调试与电源相关的问题很有用。
4. **IOUSB Plane**: 专注于 USB 设备及其关系，展示 USB 集线器与连接设备的层次结构。
5. **IOAudio Plane**: 该 plane 用于表示音频设备及其在系统内的关系。
6. ...

## 驱动通信代码示例

下面的代码连接到 IOKit 服务 `YourServiceNameHere` 并调用 selector 0：

- 首先调用 **`IOServiceMatching`** 和 **`IOServiceGetMatchingServices`** 来获取服务。
- 随后通过调用 **`IOServiceOpen`** 建立连接。
- 最后调用 **`IOConnectCallScalarMethod`**，传入 selector 为 0（selector 是分配给你想调用的函数的编号）。

<details>
<summary>示例：从用户空间调用驱动的 selector</summary>
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

还有 **other** 函数可以用来调用 IOKit 函数，除了 **`IOConnectCallScalarMethod`** 之外，还可以使用 **`IOConnectCallMethod`**、**`IOConnectCallStructMethod`**...

## 反编译驱动入口点

你可以例如从 [**firmware image (ipsw)**](#ipsw) 获取这些。然后，将其加载到你喜欢的反编译器中。

你可以从反编译 **`externalMethod`** 函数开始，因为这是接收调用并调用正确函数的驱动函数：

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

那条可怕的 demagled 调用意味着：
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
注意在前面的定义中缺少 **`self`** 参数，正确的定义应该是：
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
实际上，你可以在 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
有了这些信息，你可以按 Ctrl+Right -> `Edit function signature` 并设置已知类型：

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

新的反编译代码将如下所示：

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

下一步我们需要定义 **`IOExternalMethodDispatch2022`** struct。它是开源的，见 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176)，你可以定义它：

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

现在，沿着 `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` 可以看到很多数据：

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

将 Data Type 更改为 **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

更改后：

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

现在我们可以看到有一个包含 **7 个元素的数组**（查看最终反编译代码），点击创建一个包含 7 个元素的数组：

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

创建数组后，你可以看到所有导出的函数：

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果你还记得，要从用户态调用一个导出函数，我们不需要使用函数名，而是使用 **selector number**。在这里你可以看到 selector **0** 是函数 **`initializeDecoder`**，selector **1** 是 **`startDecoder`**，selector **2** 是 **`initializeEncoder`**...

## 最近的 IOKit 攻击面（2023–2025）

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) 显示一个权限宽松的 `IOHIDSystem` client 即使在 secure input 下也能抓取 HID 事件；确保 `externalMethod` handlers 强制执行 entitlements，而不仅仅依赖 user-client 类型。
- **IOGPUFamily memory corruption** – CVE-2024-44197 和 CVE-2025-24257 修复了来自 sandboxed apps 的 OOB 写，这些应用向 GPU user clients 传递格式错误的可变长度数据；常见错误是在 `IOConnectCallStructMethod` 参数周围的边界检查不足。
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) 确认 HID user clients 仍然是一个 sandbox-escape vector；fuzz 任何暴露 keyboard/event queues 的 driver。

### 快速 排查 & fuzzing 提示

- 从 userland 枚举一个 user client 的所有 external methods，以便为 fuzzer 提供种子：
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
- 当进行逆向时，注意 `IOExternalMethodDispatch2022` 的计数。最近的 CVE 中常见的一个漏洞模式是 `structureInputSize`/`structureOutputSize` 与实际的 `copyin` 长度不一致，导致在 `IOConnectCallStructMethod` 中发生 heap OOB。
- Sandbox 的可达性仍取决于 entitlements。在对目标投入时间之前，检查是否可以从 third‑party app 以 client 身份访问：
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- 对于 GPU/iomfb 漏洞，通过 `IOConnectCallMethod` 传递超大数组通常足以触发错误的边界检查。触发大小混淆的最小 harness (selector X)：
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## 参考资料

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
