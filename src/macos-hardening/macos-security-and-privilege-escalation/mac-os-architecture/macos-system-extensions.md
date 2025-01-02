# macOS 系统扩展

{{#include ../../../banners/hacktricks-training.md}}

## 系统扩展 / 端点安全框架

与内核扩展不同，**系统扩展在用户空间中运行**，而不是内核空间，从而降低了由于扩展故障导致系统崩溃的风险。

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

系统扩展有三种类型：**DriverKit** 扩展、**网络** 扩展和 **端点安全** 扩展。

### **DriverKit 扩展**

DriverKit 是内核扩展的替代品，**提供硬件支持**。它允许设备驱动程序（如 USB、串行、NIC 和 HID 驱动程序）在用户空间中运行，而不是内核空间。DriverKit 框架包括 **某些 I/O Kit 类的用户空间版本**，内核将正常的 I/O Kit 事件转发到用户空间，为这些驱动程序提供了一个更安全的运行环境。

### **网络扩展**

网络扩展提供了自定义网络行为的能力。网络扩展有几种类型：

- **应用代理**：用于创建实现流式定制 VPN 协议的 VPN 客户端。这意味着它根据连接（或流）而不是单个数据包处理网络流量。
- **数据包隧道**：用于创建实现数据包导向定制 VPN 协议的 VPN 客户端。这意味着它根据单个数据包处理网络流量。
- **过滤数据**：用于过滤网络“流”。它可以在流级别监控或修改网络数据。
- **过滤数据包**：用于过滤单个网络数据包。它可以在数据包级别监控或修改网络数据。
- **DNS 代理**：用于创建自定义 DNS 提供程序。它可以用于监控或修改 DNS 请求和响应。

## 端点安全框架

端点安全是 Apple 在 macOS 中提供的一个框架，提供了一组用于系统安全的 API。它旨在供 **安全供应商和开发人员构建能够监控和控制系统活动** 的产品，以识别和防止恶意活动。

该框架提供了一组 **监控和控制系统活动的 API**，例如进程执行、文件系统事件、网络和内核事件。

该框架的核心在内核中实现，作为位于 **`/System/Library/Extensions/EndpointSecurity.kext`** 的内核扩展（KEXT）。该 KEXT 由几个关键组件组成：

- **EndpointSecurityDriver**：作为内核扩展的“入口点”。它是操作系统与端点安全框架之间的主要交互点。
- **EndpointSecurityEventManager**：该组件负责实现内核钩子。内核钩子允许框架通过拦截系统调用来监控系统事件。
- **EndpointSecurityClientManager**：管理与用户空间客户端的通信，跟踪哪些客户端已连接并需要接收事件通知。
- **EndpointSecurityMessageManager**：向用户空间客户端发送消息和事件通知。

端点安全框架可以监控的事件分为：

- 文件事件
- 进程事件
- 套接字事件
- 内核事件（例如加载/卸载内核扩展或打开 I/O Kit 设备）

### 端点安全框架架构

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

与端点安全框架的 **用户空间通信** 通过 IOUserClient 类进行。根据调用者的类型使用两种不同的子类：

- **EndpointSecurityDriverClient**：这需要 `com.apple.private.endpoint-security.manager` 权限，仅由系统进程 `endpointsecurityd` 持有。
- **EndpointSecurityExternalClient**：这需要 `com.apple.developer.endpoint-security.client` 权限。通常由需要与端点安全框架交互的第三方安全软件使用。

端点安全扩展：**`libEndpointSecurity.dylib`** 是系统扩展用于与内核通信的 C 库。该库使用 I/O Kit (`IOKit`) 与端点安全 KEXT 进行通信。

**`endpointsecurityd`** 是一个关键的系统守护进程，负责管理和启动端点安全系统扩展，特别是在早期启动过程中。**只有标记为** **`NSEndpointSecurityEarlyBoot`** **的系统扩展** 在其 `Info.plist` 文件中接收这种早期启动处理。

另一个系统守护进程 **`sysextd`** **验证系统扩展** 并将其移动到适当的系统位置。然后，它请求相关守护进程加载扩展。**`SystemExtensions.framework`** 负责激活和停用系统扩展。

## 绕过 ESF

ESF 被安全工具使用，这些工具会尝试检测红队，因此任何关于如何避免这一点的信息都很有趣。

### CVE-2021-30965

问题在于安全应用程序需要具有 **完全磁盘访问权限**。因此，如果攻击者能够移除该权限，他可以阻止软件运行：
```bash
tccutil reset All
```
有关此绕过及相关内容的**更多信息**，请查看演讲 [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

最终，通过将新的权限 **`kTCCServiceEndpointSecurityClient`** 授予由 **`tccd`** 管理的安全应用程序来修复此问题，因此 `tccutil` 不会清除其权限，从而防止其运行。

## 参考文献

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
