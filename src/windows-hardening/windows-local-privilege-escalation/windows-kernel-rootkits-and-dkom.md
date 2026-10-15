# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## 范围

入侵后植入物可以将已签名的内核驱动作为服务加载，并通过 `IRP_MJ_DEVICE_CONTROL` 暴露用户模式控制平面。驱动签名只能证明 Windows 接受该映像，并不能保证 IOCTL 授权、内存操作、回调或 hook 安全。一个经过分析的 rootkit 在正常运行时使用了三个处理程序，却额外暴露了数十种后利用原语，因此逆向工程必须检查完整的分发器，而不只是恶意软件跟踪中观察到的请求。<sup>[[1]](#references)</sup>

## 已签名驱动和 IOCTL 初步分析

从 `DriverEntry` 开始，记录设备对象和 DOS 符号链接，找到 `MajorFunction[IRP_MJ_DEVICE_CONTROL]` 例程，并梳理所有能到达处理程序的比较操作和表项。将用户模式打开的名称与驱动实际创建的名称交叉核对：观察到的一条调用链打开了 `\\.\msagent`，而其驱动创建了 `\Device\ToolTool` 和 `\DosDevices\ToolTool`。这种不匹配可能说明存在另一个样本/配置、缺失的初始化逻辑，或分析结果不一致。<sup>[[1]](#references)</sup>

在还原输入结构之前，先解码每个控制码。<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

这三个代码分别解码为 `FILE_DEVICE_UNKNOWN`、`FILE_ANY_ACCESS` 和 `METHOD_BUFFERED`。这**并不能**证明低权限调用者可以访问这些代码：还要检查设备 DACL、create/open 分发、逐请求调用者检查、预期缓冲区长度、嵌入式指针、PID 生命周期处理，以及处理程序是否信任调用者提供的 PID 或标志。<sup>[[1]](#references)</sup>

当 implant 只使用部分命令时，应按原语对其余处理程序分组，而不是将它们视为无用代码。一个多功能驱动曾暴露以下所有类别：<sup>[[1]](#references)</sup>

- **控制/配置：**切换 rootkit 状态；添加、移除、查询或清除受保护路径、进程和 C2 地址。
- **进程操作：**终止 PID、取消映射其映像、使用 `NtCreateThreadEx` 注入、隐藏/恢复进程或用户模块，以及移除 PPL 保护。
- **内核操作：**从已加载驱动链表中摘除驱动、枚举/禁用/恢复通知回调、手动映射另一个驱动，以及写入任意内核地址。
- **对象操作：**删除/解密文件，以及创建或修改注册表值。

## 通过易受攻击的已签名驱动进行内核手动映射

具有内核内存读写操作的已签名驱动，可以作为未签名驱动映像的加载器，而无需让 Windows 将该映像作为普通驱动加载。<sup>[[2]](#references)[[7]](#references)</sup> LocalStranger 示例会打开现有的 `\\.\WinNotify` 设备；其源代码并未表明低权限用户能在任意主机上安装、启动或打开该驱动。<sup>[[2]](#references)[[3]](#references)</sup> 映射器接收映像路径，查询已加载内核的基址，并使用该设备的虚拟内存读写 IOCTL。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

要将读写权限转化为内核调用，映射器会从 `MmGetVirtualForPhysical` 读取一个 PTE 基址立即数，并遍历覆盖 `NtAddAtom` 的分页项。<sup>[[5]](#references)[[7]](#references)</sup> 其 PTE 计算公式为 `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`；代码还会检查是否存在大页 PDE。<sup>[[5]](#references)[[7]](#references)</sup> 它会暂时将覆盖该地址的项设为可写，把系统调用入口替换为跳转到目标内核函数的指令，调用用户态 `NtAddAtom` stub，然后恢复原始字节和页表项。<sup>[[6]](#references)</sup>

映射器通过这条调用路径调用 `ExAllocatePool`，将 PE 节、导入项和重定位项映射到映像中，将映像写入分配区域，并调用其入口点。<sup>[[7]](#references)[[8]](#references)</sup> 此实现只接受 x64、可重定位的 PE 映像；读取 PTE 基址时还假设 `MmGetVirtualForPhysical + 34` 的布局固定。<sup>[[5]](#references)[[8]](#references)</sup> 应将其视为依赖特定 build 的实现，而非独立的 KASLR 绕过手段，也不能据此证明 HVCI 或 PatchGuard 允许这种映射。<sup>[[5]](#references)[[8]](#references)</sup> 关于内核 R/W 的纯数据用途，请参阅 [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md)。

## 受信任进程豁免

一种实用的设计模式是通过 IOCTL 注册 PID 和一个**受信任**标志。随后，文件、注册表、进程和线程过滤器都会查询相同的信任信息：不受信任的工具会收到经过过滤的枚举结果、被削减的句柄权限或 `STATUS_ACCESS_DENIED`，而 implant 仍可更新自身隐藏的对象。应将其视为授权边界，并验证条目如何进行身份验证、同步，以及进程退出或 PID 重用后如何移除。<sup>[[1]](#references)</sup>

Rootkit 可以将策略持久化在 `REG_MULTI_SZ` 值中，并将文件、目录、注册表项、注册表值、忽略映像、受保护映像和隐藏映像列表编译成 AVL 树。分析时，应追踪这些共享树的所有读取者和写入者；即使函数名已被剥除，它们仍能将注册表配置、IOCTL、回调和过滤逻辑关联起来。<sup>[[1]](#references)</sup>

## DKOM 进程和模块隐藏

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` 的偏移量因 Windows build 而异。兼容不同版本的 rootkit 可以测试已知候选偏移，然后扫描 `EPROCESS`，查找邻居指回候选项且自身一致的 `LIST_ENTRY`。它会保留找到的偏移，通过重新连接邻居的 `Flink`/`Blink` 来隐藏进程，并保存状态以便之后重新链接该项。进程仍在运行，但会从遍历活动进程链表的枚举器中消失。<sup>[[1]](#references)</sup>

这是 **DKOM**，不是终止进程。检测时，应将基于链表的结果与独立证据进行比较，例如 pool/object 扫描、线程所有权、句柄表、调度器痕迹和内核内存检查。扫描发现的进程若不在规范链表中，比单独查看任一结果更有意义。<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

等效的模块隐藏原语会在 `PsLoadedModuleList` 中找到目标项，并修改相邻项的 `Flink`/`Blink` 指针。该驱动仍然已映射且可执行，但基于链表的模块查询不会列出它。应将加载器链表与可执行内核映射、pool tag、设备/驱动对象、服务项、回调地址，以及落在已列出映像之外的分发指针进行比较。<sup>[[1]](#references)</sup>

## 基于回调的保护和隐匿

Rootkit 可以将有文档记录的回调框架与 DKOM 和 hooks 结合使用：<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` 的 `PsProcessType` 和 `PsThreadType` 预操作处理程序会在不受信任的调用者打开受保护目标时，移除用于终止、VM 访问、复制或线程操作的权限。记录回调的 altitude，并解析每个回调地址所属的模块。
- `PsSetCreateProcessNotifyRoutineEx` 和 `PsSetLoadImageNotifyRoutine` 会在进程和映像出现时维护受保护/忽略/隐藏进程状态；注册前已存在的对象可以通过一次性进程遍历补录。
- 文件系统 minifilter 会拒绝访问已配置的路径。某些不常见的实现可能会创建其 `Instances` 项，动态选择 altitude，并在 `FltRegisterFilter` 报告冲突时递增并重试。
- `CmRegisterCallbackEx` 例程可以在枚举时隐藏受保护名称，并拒绝直接打开、重命名、设置或删除操作，同时豁免已注册的受信任进程。

关联 `ObRegisterCallbacks` 注册信息、注册表回调 altitude、`fltmc filters` 输出、服务 `Instances` 项和回调地址。如果常规工具受到过滤，应从离线内存映像或其他可信采集层检查这些结构。<sup>[[1]](#references)</sup>

## Nsiproxy 结果过滤

网络隐匿可以针对 `\Driver\Nsiproxy`：通过 `ObReferenceObjectByName` 获取驱动对象，保存处理程序指针，将其替换为 wrapper，并在用户态收到返回结果之前，移除与 IOCTL 管理的 C2 列表匹配的 IPv4 记录。依赖经过过滤的 NSI 数据的应用程序可能不再显示该连接，尽管流量仍然存在。<sup>[[1]](#references)</sup>

将主机连接视图与数据包捕获、WFP/ETW telemetry 和内核内存网络对象进行比较。还要检查 `Nsiproxy` 分发/处理程序指针，并确认每个指针都指向预期的已签名模块；指向未列出映射区域的指针，可能将网络过滤与 `PsLoadedModuleList` DKOM 联系起来。<sup>[[1]](#references)</sup>

## 调查检查清单

最有力的信号是不同层之间存在不一致，而不是某个文件名或哈希。请关联以下信息：<sup>[[1]](#references)</sup>

1. 内核服务的创建情况，以及证书年代、发布者或路径与已安装产品不一致的已签名驱动。
2. 设备创建、DOS 链接和 IOCTL 流量，包括用户态与内核态设备名称不匹配的情况。
3. PID 注册请求，以及随后其他进程无法打开、枚举、修改或删除相同对象的情况。
4. 对象/注册表/进程/映像回调、minifilter 实例，以及地址不属于正常枚举驱动的 hooks。
5. 基于链表与基于扫描的进程、模块、回调和网络清单之间的差异。

## References

- [1] [Kaspersky Securelist - HoneyMyte 使用已签名的 Windows 内核 Rootkit 增强 CoolClient](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [LocalStranger README](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [LocalStranger 驱动初始化](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [LocalStranger 映射器命令行](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [LocalStranger 内核导出项和 PTE 基址解析](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [LocalStranger 内核调用 trampoline](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [LocalStranger 映射器内存分配和入口点调用](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [LocalStranger PE 映射](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [LocalStranger 内核和系统调用上下文](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [LocalStranger 虚拟内存 IOCTL wrapper](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
