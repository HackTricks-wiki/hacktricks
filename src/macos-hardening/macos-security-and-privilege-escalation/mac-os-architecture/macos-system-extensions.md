# macOS 系统扩展

{{#include ../../../banners/hacktricks-training.md}}

## 系统扩展 / Endpoint Security Framework

与 Kernel Extensions 不同，**System Extensions 在用户空间而非内核空间运行**，从而降低因扩展故障导致系统崩溃的风险。

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

系统扩展有三种类型：**DriverKit** Extensions、**Network** Extensions 和 **Endpoint Security** Extensions。

### **DriverKit Extensions**

DriverKit 是 Kernel Extensions 的替代方案，用于**提供硬件支持**。它允许设备驱动程序（如 USB、Serial、NIC 和 HID 驱动程序）在用户空间而不是内核空间运行。DriverKit framework 包含**某些 I/O Kit 类的用户空间版本**，内核会将常规 I/O Kit 事件转发到用户空间，为这些驱动程序提供更安全的运行环境。<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions 提供了自定义网络行为的能力。Network Extensions 有多种类型：

- **App Proxy**：用于创建实现面向流的自定义 VPN protocol 的 VPN client。这意味着它会根据连接（或流）而不是单个数据包处理网络流量。
- **Packet Tunnel**：用于创建实现面向数据包的自定义 VPN protocol 的 VPN client。这意味着它会根据单个数据包处理网络流量。
- **Filter Data**：用于过滤网络“流”。它可以在流级别监控或修改网络数据。
- **Filter Packet**：用于过滤单个网络数据包。它可以在数据包级别监控或修改网络数据。
- **DNS Proxy**：用于创建自定义 DNS provider。它可用于监控或修改 DNS 请求和响应。<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security 是 Apple 在 macOS 中提供的一个 framework，提供了一组用于系统安全的 API。它旨在供**security vendors 和 developers 构建能够监控和控制系统活动的产品**，以识别和防御恶意活动。

此 framework 提供了**一组用于监控和控制系统活动的 API**，例如进程执行、文件系统事件、网络事件和内核事件。

此 framework 的核心在内核中实现，是一个位于 **`/System/Library/Extensions/EndpointSecurity.kext`** 的 Kernel Extension (KEXT)。<sup>[[2]](#references)</sup> 此 KEXT 由多个关键组件组成：

- **EndpointSecurityDriver**：充当 Kernel Extension 的“入口点”。它是 OS 与 Endpoint Security framework 之间交互的主要接口。
- **EndpointSecurityEventManager**：负责实现 kernel hooks。Kernel hooks 允许该 framework 通过拦截 system calls 来监控系统事件。
- **EndpointSecurityClientManager**：管理与用户空间 clients 的通信，跟踪已连接且需要接收事件通知的 clients。
- **EndpointSecurityMessageManager**：向用户空间 clients 发送消息和事件通知。

Endpoint Security framework 能够监控的事件分为以下几类：

- 文件事件
- 进程事件
- Socket 事件
- 内核事件（例如加载/卸载 Kernel Extension 或打开 I/O Kit device）

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

与 Endpoint Security framework 的**用户空间通信**通过 IOUserClient class 完成。根据 caller 类型的不同，会使用两个不同的 subclasses：

- **EndpointSecurityDriverClient**：需要 `com.apple.private.endpoint-security.manager` entitlement，该 entitlement 仅由系统进程 `endpointsecurityd` 持有。
- **EndpointSecurityExternalClient**：需要 `com.apple.developer.endpoint-security.client` entitlement。通常需要与 Endpoint Security framework 交互的第三方 security software 会使用此项。<sup>[[1]](#references)</sup>

Endpoint Security Extensions：**`libEndpointSecurity.dylib`** 是 system extensions 用于与内核通信的 C library。此 library 使用 I/O Kit (`IOKit`) 与 Endpoint Security KEXT 通信。<sup>[[2]](#references)</sup>

**`endpointsecurityd`** 是负责管理和启动 endpoint security system extensions 的关键系统 daemon，尤其是在 early boot process 期间。只有在其 `Info.plist` 文件中标记了 **`NSEndpointSecurityEarlyBoot`** 的 **system extensions** 才会接受这种 early boot 处理。<sup>[[2]](#references)</sup>

另一个系统 daemon **`sysextd`** 会**验证 system extensions**，并将其移动到正确的系统位置。随后，它会请求相关 daemon 加载该 extension。**`SystemExtensions.framework`** 负责激活和停用 system extensions。<sup>[[2]](#references)</sup>

## 绕过 ESF

ESF 被 security tools 用来检测 red teamer，因此任何关于如何避免被检测的信息都很有趣。

### CVE-2021-30965

问题在于 security application 需要拥有 **Full Disk Access permissions**。因此，如果 attacker 能够移除该权限，就可以阻止该软件运行：<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
有关此 bypass 及相关 bypass 的**更多信息**，请查看演讲 [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

最终，通过向由 **`tccd`** 管理的安全应用授予新权限 **`kTCCServiceEndpointSecurityClient`** 修复了此问题，这样 `tccutil` 就不会清除其权限，从而阻止其运行。<sup>[[3]](#references)</sup>

## 参考资料

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
