# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Unlike Kernel Extensions, **System Extensions run in user space** instead of kernel space, reducing the risk of a system crash due to extension malfunction.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

There are three types of system extensions: **DriverKit** Extensions, **Network** Extensions, and **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit is a replacement for kernel extensions that **provide hardware support**. It allows device drivers (like USB, Serial, NIC, and HID drivers) to run in user space rather than kernel space. The DriverKit framework includes **user space versions of certain I/O Kit classes**, and the kernel forwards normal I/O Kit events to user space, offering a safer environment for these drivers to run.<sup>[2]</sup>

### **Network Extensions**

Network Extensions provide the ability to customize network behaviors. There are several types of Network Extensions:

- **App Proxy**: 用于创建实现面向 flow 的自定义 VPN protocol 的 VPN client。这意味着它根据连接（或 flow）而非单个 packet 处理 network traffic。
- **Packet Tunnel**: 用于创建实现面向 packet 的自定义 VPN protocol 的 VPN client。这意味着它根据单个 packet 处理 network traffic。
- **Filter Data**: 用于过滤 network "flows"。它可以在 flow 层面监控或修改 network data。
- **Filter Packet**: 用于过滤单个 network packet。它可以在 packet 层面监控或修改 network data。
- **DNS Proxy**: 用于创建自定义 DNS provider。它可以用于监控或修改 DNS requests 和 responses。<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security 是 Apple 在 macOS 中提供的 framework，提供一组用于 system security 的 APIs。它旨在供 **security vendors 和 developers 构建能够 monitor 和 control system activity 的 products**，以识别并防御 malicious activity。

该 framework 提供了**用于 monitor 和 control system activity 的 APIs 集合**，例如 process executions、file system events、network 和 kernel events。

该 framework 的核心在 kernel 中实现，是一个位于 **`/System/Library/Extensions/EndpointSecurity.kext`** 的 Kernel Extension (KEXT)。<sup>[2]</sup> 此 KEXT 由多个关键组件组成：

- **EndpointSecurityDriver**：充当 Kernel Extension 的“entry point”。它是 OS 与 Endpoint Security framework 之间交互的主要接口。
- **EndpointSecurityEventManager**：负责实现 kernel hooks。Kernel hooks 通过拦截 system calls，使 framework 能够 monitor system events。
- **EndpointSecurityClientManager**：管理与 user space clients 的 communication，跟踪已连接以及需要接收 event notifications 的 clients。
- **EndpointSecurityMessageManager**：向 user space clients 发送 messages 和 event notifications。

Endpoint Security framework 可以 monitor 的 events 分为：

- File events
- Process events
- Socket events
- Kernel events（例如 loading/unloading a kernel extension 或 opening an I/O Kit device）

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security framework 的 **user-space communication** 通过 IOUserClient class 实现。根据 caller 的类型，使用两个不同的 subclasses：

- **EndpointSecurityDriverClient**：需要 `com.apple.private.endpoint-security.manager` entitlement，该 entitlement 仅由 system process `endpointsecurityd` 持有。
- **EndpointSecurityExternalClient**：需要 `com.apple.developer.endpoint-security.client` entitlement。通常由需要与 Endpoint Security framework 交互的 third-party security software 使用。<sup>[1]</sup>

Endpoint Security Extensions：**`libEndpointSecurity.dylib`** 是 system extensions 用于与 kernel communication 的 C library。该 library 使用 I/O Kit (`IOKit`) 与 Endpoint Security KEXT communication。<sup>[2]</sup>

**`endpointsecurityd`** 是负责管理和启动 endpoint security system extensions 的关键 system daemon，尤其是在 early boot process 期间。只有在其 `Info.plist` file 中标记了 **`NSEndpointSecurityEarlyBoot`** 的 **system extensions** 才会接受这种 early boot 处理。<sup>[2]</sup>

另一个 system daemon **`sysextd`** 会**验证 system extensions**，并将其移动到正确的 system locations。随后，它会请求相关 daemon 加载该 extension。**`SystemExtensions.framework`** 负责激活和停用 system extensions。<sup>[2]</sup>

## Bypassing ESF

ESF 被 security tools 用于尝试 detect red teamer，因此任何关于如何避免被 detect 的信息听起来都很有趣。

### CVE-2021-30965

问题在于 security application 需要拥有 **Full Disk Access permissions**。因此，如果 attacker 能够移除该权限，就可以阻止该 software 运行：<sup>[3]</sup>
```bash
tccutil reset All
```
如需**更多信息**了解此 bypass 及相关 bypass，请查看演讲 [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

最终，通过向由 **`tccd`** 管理的 security app 授予新权限 **`kTCCServiceEndpointSecurityClient`** 修复了此问题，因此 `tccutil` 不会清除其权限，从而阻止其运行。<sup>[3]</sup>

## References

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
