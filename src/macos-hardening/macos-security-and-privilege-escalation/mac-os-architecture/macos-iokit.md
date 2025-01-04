# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

I/O Kit 是一个开源的面向对象的 **设备驱动框架**，位于 XNU 内核中，处理 **动态加载的设备驱动程序**。它允许在运行时将模块化代码添加到内核中，支持多种硬件。

IOKit 驱动程序基本上会 **从内核导出函数**。这些函数参数 **类型** 是 **预定义** 的并经过验证。此外，类似于 XPC，IOKit 只是 **Mach 消息** 之上的另一层。

**IOKit XNU 内核代码** 由 Apple 在 [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) 开源。此外，用户空间的 IOKit 组件也开源 [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

然而，**没有 IOKit 驱动程序** 是开源的。无论如何，驱动程序的发布有时可能会附带符号，使其更易于调试。查看如何 [**从固件获取驱动程序扩展这里**](#ipsw)**。**

它是用 **C++** 编写的。您可以使用以下命令获取去除修饰的 C++ 符号：
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **暴露的函数** 可能在客户端尝试调用函数时执行 **额外的安全检查**，但请注意，应用程序通常受到 **沙箱** 的 **限制**，只能与特定的 IOKit 函数进行交互。

## 驱动程序

在 macOS 中，它们位于：

- **`/System/Library/Extensions`**
- 内置于 OS X 操作系统的 KEXT 文件。
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
直到第9个，列出的驱动程序是**加载在地址0**。这意味着这些不是实际的驱动程序，而是**内核的一部分，无法卸载**。

为了找到特定的扩展，您可以使用：
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

**IORegistry** 是 macOS 和 iOS 中 IOKit 框架的一个关键部分，作为表示系统硬件配置和状态的数据库。它是一个 **层次化的对象集合，表示系统上加载的所有硬件和驱动程序** 及其相互关系。

您可以使用 cli **`ioreg`** 从控制台检查 IORegistry（对 iOS 特别有用）。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
您可以从 **Xcode 附加工具** 下载 **`IORegistryExplorer`**，并通过 **图形** 界面检查 **macOS IORegistry**。

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

在 IORegistryExplorer 中，“平面”用于组织和显示 IORegistry 中不同对象之间的关系。每个平面代表特定类型的关系或系统硬件和驱动程序配置的特定视图。以下是您可能在 IORegistryExplorer 中遇到的一些常见平面：

1. **IOService 平面**：这是最一般的平面，显示代表驱动程序和 nubs（驱动程序之间的通信通道）的服务对象。它显示这些对象之间的提供者-客户端关系。
2. **IODeviceTree 平面**：该平面表示设备与系统之间的物理连接。它通常用于可视化通过 USB 或 PCI 等总线连接的设备层次结构。
3. **IOPower 平面**：以电源管理的方式显示对象及其关系。它可以显示哪些对象影响其他对象的电源状态，对于调试与电源相关的问题非常有用。
4. **IOUSB 平面**：专注于 USB 设备及其关系，显示 USB 集线器和连接设备的层次结构。
5. **IOAudio 平面**：该平面用于表示音频设备及其在系统中的关系。
6. ...

## 驱动程序通信代码示例

以下代码连接到 IOKit 服务 `"YourServiceNameHere"` 并调用选择器 0 内的函数。为此：

- 首先调用 **`IOServiceMatching`** 和 **`IOServiceGetMatchingServices`** 来获取服务。
- 然后通过调用 **`IOServiceOpen`** 建立连接。
- 最后调用一个函数，使用 **`IOConnectCallScalarMethod`** 指定选择器 0（选择器是您要调用的函数分配的数字）。
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
有**其他**函数可以用来调用 IOKit 函数，除了 **`IOConnectCallScalarMethod`**，还有 **`IOConnectCallMethod`**、**`IOConnectCallStructMethod`**...

## 反向工程驱动入口点

您可以从 [**固件映像 (ipsw)**](#ipsw) 中获取这些。例如，将其加载到您喜欢的反编译器中。

您可以开始反编译 **`externalMethod`** 函数，因为这是接收调用并调用正确函数的驱动函数：

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

那个可怕的调用去掉混淆后的意思是：
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
注意在之前的定义中缺少了 **`self`** 参数，好的定义应该是：
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
实际上，您可以在 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) 找到真实的定义：
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
使用此信息，您可以重写 Ctrl+Right -> `Edit function signature` 并设置已知类型：

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

新的反编译代码将如下所示：

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

在下一步中，我们需要定义 **`IOExternalMethodDispatch2022`** 结构体。它是开源的，您可以在 [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) 中找到，您可以定义它：

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

现在，跟随 `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`，您可以看到很多数据：

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

将数据类型更改为 **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

更改后：

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

现在我们知道这里有一个 **7 个元素的数组**（检查最终的反编译代码），点击创建一个 7 个元素的数组：

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

数组创建后，您可以看到所有导出的函数：

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 如果您记得，从用户空间 **调用** 一个 **导出** 函数时，我们不需要调用函数的名称，而是 **选择器编号**。在这里，您可以看到选择器 **0** 是函数 **`initializeDecoder`**，选择器 **1** 是 **`startDecoder`**，选择器 **2** 是 **`initializeEncoder`**...

{{#include ../../../banners/hacktricks-training.md}}
