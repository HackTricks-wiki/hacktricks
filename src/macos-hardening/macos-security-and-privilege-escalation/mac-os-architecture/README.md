# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOS 的核心是 XNU**，其名称代表 “X is Not Unix”。该 kernel 主要由 **Mach 微内核**（稍后讨论）以及 Berkeley Software Distribution（**BSD**）的相关组件构成。XNU 还通过名为 **I/O Kit** 的系统为 **kernel drivers** 提供支持。XNU kernel 是 Darwin 开源项目的一部分，因此**其源代码可以自由访问**。

从安全研究人员或 Unix 开发者的角度来看，**macOS** 可能非常**类似于**拥有优雅 GUI 和大量自定义应用程序的 **FreeBSD** 系统。大多数为 BSD 开发的应用程序都可以在 macOS 上编译和运行而无需修改，因为 Unix 用户熟悉的命令行工具在 macOS 中都存在。不过，由于 XNU kernel 集成了 Mach，传统类 Unix 系统与 macOS 之间存在一些显著差异，这些差异可能导致潜在问题，也可能带来独特优势。

XNU 的开源版本：[https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach 是一个设计为**兼容 UNIX** 的**微内核**。其关键设计原则之一是**尽量减少**运行在 **kernel** 空间中的**代码**数量，转而允许许多典型的 kernel 功能（例如文件系统、网络和 I/O）以**用户级任务**的形式运行。

在 XNU 中，Mach **负责许多 kernel 通常处理的关键底层操作**，例如处理器调度、多任务处理和虚拟内存管理。

### BSD

XNU **kernel** 还**集成**了大量源自 **FreeBSD** 项目的代码。这些代码与 Mach 一起作为 kernel 的一部分运行，并处于相同的地址空间中。不过，XNU 中的 FreeBSD 代码可能与原始 FreeBSD 代码存在较大差异，因为必须进行修改以确保其与 Mach 兼容。FreeBSD 为许多 kernel 操作提供支持，包括：

- 进程管理
- 信号处理
- 基本安全机制，包括用户和组管理
- 系统调用基础设施
- TCP/IP 协议栈和套接字
- Firewall 和数据包过滤

由于 BSD 和 Mach 采用不同的概念框架，理解二者之间的交互可能比较复杂。例如，BSD 使用进程作为基本执行单元，而 Mach 基于线程运行。XNU 通过**将每个 BSD 进程关联到一个 Mach 任务**来调和这一差异，该任务恰好包含一个 Mach 线程。当使用 BSD 的 fork() 系统调用时，kernel 中的 BSD 代码会使用 Mach 函数创建任务和线程结构。

此外，**Mach 和 BSD 各自维护不同的安全模型**：**Mach** 的安全模型基于**端口权限**，而 BSD 的安全模型基于**进程所有权**。这两个模型之间的差异偶尔会导致本地权限提升漏洞。除了典型的系统调用外，还存在允许用户空间程序与 kernel 交互的 **Mach traps**。这些不同元素共同构成了 macOS kernel 多层次的混合架构。<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

I/O Kit 是 XNU kernel 中开源、面向对象的**设备驱动框架**，负责处理**动态加载的设备驱动程序**。它允许将模块化代码即时添加到 kernel 中，从而支持各种硬件。


{{#ref}}
macos-iokit.md
{{#endref}}

### macOS Architecture 中的 Coprocessors

Apple 平台依赖多个 coprocessors，将对延迟敏感的工作从主核心转移出去，并隔离安全关键功能。

- **Secure Enclave Processor (SEP)**：专用 ARM 核心，拥有自己的微内核和安全启动链，通常运行在 **EL3/secure world**。macOS 在 EL1 中通过 mailbox drivers 与其交互。
- 攻击面：SEP firmware 更新，以及代理请求的用户空间守护进程（`seputil`、`securityd`）。
- 失陷影响：泄露长期密钥、绕过生物识别限制，以及破坏 FileVault 或 Apple Pay 的保护。
- **System Management Controller (SMC)**：在 ARM exception levels 之外的 microcontroller 上运行专有 firmware。macOS（EL1）通过 I/O Kit user clients 与其交互。
- 攻击面：USB-C power delivery 消息、风扇/电池管理接口和 firmware 更新路径。
- 失陷影响：覆盖 thermal limits、注入伪造的传感器数据、切断电源，或植入持久化 NVRAM 后门。
- **T1/T2 Security Chips**：在各自的 ARM 核心上运行 bridgeOS（源自 watchOS），主要位于 EL1/EL3。macOS 通过由 IOKit 管理的 PCIe/类似 USB 的通道与其通信。
- 攻击面：DFU/restore 路径、`tccd` 等服务暴露的 IPC endpoints，以及桥接到 T2 的 media pipelines。
- 失陷影响：禁用安全启动、解密 SSD 内容、劫持 camera/mic gating，或模拟 HID 输入以实现隐蔽持久化。
- **Display Coprocessor (DCP)**：在由 DART（Apple 的 IOMMU）保护的隔离地址空间中，于 EL1 内执行 firmware。
- 攻击面：`DCPAVService` interfaces、共享 descriptor buffers 和 firmware image parsing。
- 失陷影响：注入任意帧、窥探 framebuffers，或使 display pipeline 失效以造成 DoS。
- **Apple Neural Engine (ANE)**：在专用 ML cluster 上运行 microcode（不使用 ARM EL levels）。macOS 通过 `ANECompilerService` 和 IOKit 调度任务。
- 攻击面：编译后的 model binaries（`.ane`）、向 custom kernels 提供数据的 Core ML APIs，以及 firmware loaders。
- 失陷影响：篡改或窃取 ML models、泄露处理后的音频/视觉数据，或破坏设备端推理。
- **AGX GPU**：firmware 在带有 scheduler 的 custom GPU cores 上运行；EL0 提交 Metal commands，由 EL1 进行验证。
- 攻击面：Metal shader compiler、共享 buffer mapping APIs，以及 `com.apple.AGXFirmware` ioctl interfaces。
- 失陷影响：获得对 system memory 的 DMA 访问、通过 GPU drivers 逃逸 sandbox，或植入持久化 firmware。
- **Apple Video Encoder (AVE)**：firmware 在 Media Engine 的类似 EL1 sandbox 中执行。macOS 通过 VideoToolbox 和 `AppleAVE2` 与其交互。
- 攻击面：codec bitstreams、parameter sets、用户提供的 buffers，以及 firmware update blobs。
- 失陷影响：泄露未压缩帧、绕过 DRM，或获得能够访问 DMA engines 的代码执行能力。
- **Image Signal Processor (ISP)**：在 Media Engine cluster 中运行 secure firmware；macOS camera drivers 在 EL1 中运行。
- 攻击面：Camera HALs、RAW frame descriptors、ISP configuration queues 和 firmware updates。
- 失陷影响：静默捕获原始 camera feeds、禁用隐私指示器，或注入伪造图像。
- **AMX Matrix cores**：作为 coprocessor units 运行，通过新指令在 EL0/EL1 暴露。
- 攻击面：kernel 对 AMX 状态的虚拟化（`thread_set_state`、context switches）以及用户空间代码生成。
- 失陷影响：泄露其他进程的 tile registers、识别 workloads，或通过 kernel memory corruption 提升权限。

现代 macOS 将这些 coprocessors 视为 trust chain 中的受信任组件。SEP、SMC 和 T2 的 firmware 均由 Apple 签名，并且 handshake protocols（通常通过 mailboxes 或 I/O Kit families 实现）包含 challenge-response checks，确保只有经过认证的 firmware 才能处理请求。

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

由于代码运行时拥有极高权限，macOS 对加载 Kernel Extensions（.kext）**限制极其严格**。实际上，默认情况下几乎不可能加载（除非找到 bypass）。

在以下页面中，还可以查看如何从 macOS 加载到其 **kernelcache** 中的内容恢复 `.kext`：

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

macOS 创建了 System Extensions 来替代 Kernel Extensions，它在用户级提供与 kernel 交互的 APIs。这样，开发者就可以避免使用 Kernel Extensions。

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** 代表 **CRYPTographically-sealed EXtension**。它是一种密封磁盘映像（container），Apple 使用它来存放在主要 OS 更新之间更可能发生变化的 OS 部分（frameworks、shared libraries、apps）。
- 在 macOS 和 iOS 上，放置在 cryptex 中的组件可以通过 RSR 进行**修补或替换**，而无需重新密封整个 system volume。
- Cryptex 位于 **Preboot volume** 中，与 boot firmware 一同存在，并在运行时 graft 到 OS file system 中。
- 加载 cryptex 内容需要进行验证：系统检查 file seals、manifests 和 root hashes，然后挂载或“graft” cryptex 内容，使 apps 在运行时使用其中存在的 cryptex 版本。
- 在 boot logs 中，cryptex loading 发生在 kernel initialization 之后、完整 system services 启动之前。


#### Rapid Security Response (RSR)

- **RSR** 是 Apple 用于在**常规 OS 更新之间推送 security patches** 的机制。它针对 cryptex 内容更新存在漏洞的部分（例如 libraries、frameworks），而无需修改核心 system volume。
- 应用 RSR update 时，设备会向 Apple 的 signing server 请求 **Cryptex1 Image4 manifest**。该 manifest 以加密方式绑定到设备和新的 cryptex 内容。
- 基础系统现有的 AP boot ticket **不会**由 RSR 修改。该 patch 以 additive 方式作用于 sealed base OS 之上。
- 在 macOS 上，某些 patched components（例如 Safari）会在 app relaunch 后立即生效；不一定需要完整 system restart。
- RSRs **可以移除**：每个 RSR 都同时提供 patch 和可回滚到 base OS 版本的“antipatch”。移除时，cryptex 内容会恢复。
- RSR updates 通常远小于完整 OS updates，并且安装所需的 battery state 更低。


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
