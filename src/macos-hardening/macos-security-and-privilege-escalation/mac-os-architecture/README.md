# macOS 内核与系统扩展

{{#include ../../../banners/hacktricks-training.md}}

## XNU 内核

**macOS 的核心是 XNU**，其含义是 “X is Not Unix”。该内核主要由 **Mach 微内核**（稍后讨论）以及 Berkeley Software Distribution（**BSD**）的部分组件构成。XNU 还通过名为 **I/O Kit 的系统**为**内核驱动程序**提供支持。XNU 内核是 Darwin 开源项目的一部分，这意味着**其源代码可以自由访问**。

从安全研究人员或 Unix 开发者的角度来看，**macOS** 可能与带有优雅 GUI 和大量自定义应用程序的 **FreeBSD** 系统非常**相似**。大多数为 BSD 开发的应用程序无需修改即可在 macOS 上编译和运行，因为 Unix 用户熟悉的命令行工具在 macOS 中都存在。不过，由于 XNU 内核集成了 Mach，传统类 Unix 系统与 macOS 之间存在一些显著差异，而这些差异可能导致潜在问题，也可能带来独特优势。

XNU 的开源版本：[https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach 是一个旨在兼容 **UNIX** 的**微内核**。其关键设计原则之一是**最小化**运行在**内核**空间中的**代码**数量，并允许许多典型的内核功能（例如文件系统、网络和 I/O）以**用户级任务**的形式**运行**。

在 XNU 中，Mach **负责许多内核通常处理的关键底层操作**，例如处理器调度、多任务处理和虚拟内存管理。

### BSD

XNU **内核**还**集成**了大量源自 **FreeBSD** 项目的代码。这些代码与 Mach 一起作为内核的一部分运行，并且位于相同的地址空间中。不过，XNU 中的 FreeBSD 代码可能与原始 FreeBSD 代码存在较大差异，因为必须进行修改以确保其与 Mach 兼容。FreeBSD 为许多内核操作提供支持，包括：

- 进程管理
- 信号处理
- 基本安全机制，包括用户和组管理
- 系统调用基础设施
- TCP/IP 协议栈和套接字
- 防火墙和数据包过滤

由于 BSD 和 Mach 采用不同的概念框架，理解二者之间的交互可能较为复杂。例如，BSD 使用进程作为基本执行单元，而 Mach 基于线程运行。XNU 通过**将每个 BSD 进程关联到一个 Mach 任务**来调和这一差异，该任务恰好包含一个 Mach 线程。当使用 BSD 的 fork() 系统调用时，内核中的 BSD 代码会使用 Mach 函数创建任务和线程结构。

此外，**Mach 和 BSD 各自维护着不同的安全模型**：**Mach** 的安全模型基于**端口权限**，而 BSD 的安全模型则基于**进程所有权**。这两种模型之间的差异有时会导致本地权限提升漏洞。除典型的系统调用外，还存在允许用户空间程序与内核交互的 **Mach traps**。这些不同组件共同构成了 macOS 内核多层次的混合架构。

### I/O Kit - 驱动程序

I/O Kit 是 XNU 内核中的开源、面向对象的**设备驱动程序框架**，用于处理**动态加载的设备驱动程序**。它允许将模块化代码动态添加到内核中，从而支持各种硬件。


{{#ref}}
macos-iokit.md
{{#endref}}

### macOS 架构中的协处理器

Apple 平台依赖多个协处理器，将对延迟敏感的工作从主核心转移出去，并隔离安全关键功能。

- **Secure Enclave Processor (SEP)**：一个专用 ARM 核心，拥有自己的微内核和安全启动链，通常运行在 **EL3/安全世界**。macOS 中 EL1 上的 mailbox 驱动程序负责与其交互。
- 攻击面：SEP 固件更新以及代理请求的用户空间守护进程（`seputil`、`securityd`）。
- 失陷影响：泄露长期密钥、绕过生物识别门控，并破坏 FileVault 或 Apple Pay 的保护。
- **System Management Controller (SMC)**：在 ARM 异常级别之外的微控制器上运行专有固件。macOS（EL1）通过 I/O Kit 用户客户端访问它。
- 攻击面：USB-C 电力传输消息、风扇/电池管理接口以及固件更新路径。
- 失陷影响：覆盖温度限制、注入伪造的传感器数据、切断电源，或植入持久化 NVRAM 后门。
- **T1/T2 Security Chips**：在各自的 ARM 核心上运行 bridgeOS（源自 watchOS），主要处于 EL1/EL3。macOS 通过由 IOKit 中介的 PCIe/类似 USB 的通道与其通信。
- 攻击面：DFU/恢复路径、由 `tccd` 等服务暴露的 IPC 端点，以及桥接到 T2 的媒体处理管线。
- 失陷影响：禁用安全启动、解密 SSD 内容、劫持摄像头/麦克风门控，或模拟 HID 输入以实现隐蔽持久化。
- **Display Coprocessor (DCP)**：在由 DART（Apple 的 IOMMU）保护的隔离地址空间中，以 EL1 运行固件。
- 攻击面：`DCPAVService` 接口、共享描述符缓冲区以及固件镜像解析。
- 失陷影响：注入任意帧、窥探帧缓冲区，或使显示处理管线失效以造成 DoS。
- **Apple Neural Engine (ANE)**：在专用 ML 集群上运行 microcode（没有 ARM EL 级别）。macOS 通过 `ANECompilerService` 和 IOKit 调度工作。
- 攻击面：已编译的模型二进制文件（`.ane`）、为自定义内核提供输入的 Core ML API，以及固件加载器。
- 失陷影响：篡改或窃取 ML 模型、泄露处理后的音频/视觉数据，或破坏设备端推理。
- **AGX GPU**：固件在带有调度器的自定义 GPU 核心上运行；EL0 提交 Metal 命令，由 EL1 进行验证。
- 攻击面：Metal shader 编译器、共享缓冲区映射 API 以及 `com.apple.AGXFirmware` ioctl 接口。
- 失陷影响：获得对系统内存的 DMA 访问权限、通过 GPU 驱动程序逃逸 sandbox，或植入持久化固件。
- **Apple Video Encoder (AVE)**：固件在 Media Engine 中类似 EL1 的 sandbox 内执行。macOS 通过 VideoToolbox 和 `AppleAVE2` 与其交互。
- 攻击面：编解码器 bitstream、参数集、用户提供的缓冲区以及固件更新 blob。
- 失陷影响：泄露未压缩帧、绕过 DRM，或获得可访问 DMA 引擎的代码执行能力。
- **Image Signal Processor (ISP)**：在 Media Engine 集群中运行安全固件；macOS 摄像头驱动程序在 EL1 上运行。
- 攻击面：摄像头 HAL、RAW 帧描述符、ISP 配置队列以及固件更新。
- 失陷影响：静默捕获原始摄像头画面、禁用隐私指示器，或注入伪造图像。
- **AMX Matrix cores**：作为协处理器单元运行，通过新指令在 EL0/EL1 上暴露。
- 攻击面：内核对 AMX 状态的虚拟化（`thread_set_state`、上下文切换）以及用户空间代码生成。
- 失陷影响：泄露其他进程的 tile 寄存器、识别工作负载特征，或通过内核内存损坏实现权限提升。

现代 macOS 将这些协处理器视为信任链中的可信组件。SEP、SMC 和 T2 的固件由 Apple 签名，并且握手协议（通常通过 mailbox 或 I/O Kit family 实现）包含 challenge-response 检查，以确保只有经过身份验证的固件才能处理请求。

### IPC - 进程间通信

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS 内核扩展

由于代码运行时拥有很高的权限，macOS 对加载 Kernel Extensions（.kext）**限制非常严格**。实际上，默认情况下几乎不可能加载（除非找到绕过方法）。

在以下页面中，还可以了解如何恢复 macOS 加载到其**kernelcache**中的 `.kext`：

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS 系统扩展

macOS 创建了 System Extensions 来替代 Kernel Extensions，后者提供用户级 API 以便与内核交互。这样，开发者可以避免使用 Kernel Extensions。

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptex 与 RSR（Rapid Security Response）

- **Cryptex** 代表 **CRYPTographically-sealed EXtension**。它是一种密封磁盘镜像（容器），Apple 使用它来存放在主要 OS 更新之间更可能发生变化的 OS 部分（framework、共享库和应用程序）。
- 在 macOS 和 iOS 上，放置在 cryptex 中的组件可以通过 RSR 进行**修补或替换**，而无需重新密封整个系统卷。
- Cryptex 位于 **Preboot 卷**中，与启动固件并列，并在运行时 graft 到 OS 文件系统中。
- 加载 cryptex 内容时会进行验证：系统检查文件 seal、manifest 和 root hash，然后挂载或“graft” cryptex 内容，使应用程序在运行时使用其中存在的 cryptex 版本。
- 在启动日志中，cryptex 的加载发生在内核初始化之后、完整系统服务启动之前。


#### Rapid Security Response (RSR)

- **RSR** 是 Apple 用于在**常规 OS 更新之间提供安全补丁**的机制。它针对 cryptex 内容更新存在漏洞的部分（例如库和 framework），而无需修改核心系统卷。
- 应用 RSR 更新时，设备会从 Apple 的签名服务器请求 **Cryptex1 Image4 manifest**。该 manifest 以加密方式与设备及新的 cryptex 内容绑定。
- 基础系统现有的 AP boot ticket **不会**被 RSR 修改。该补丁以附加方式作用于已密封的基础 OS。
- 在 macOS 上，某些已修补的组件（例如 Safari）会在应用重新启动后立即生效；不一定需要完整重启系统。
- RSR **可以移除**：每个 RSR 同时提供补丁和可回滚到基础 OS 版本的“antipatch”。移除后，cryptex 内容会恢复。
- RSR 更新通常比完整 OS 更新小得多，安装所需的电池电量也更低。


## 参考资料

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
