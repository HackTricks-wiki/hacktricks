# macOS xpc_connection_get_audit_token 攻击

{{#include ../../../../../../banners/hacktricks-training.md}}

**有关更多信息，请查看原始帖子：** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。这是一个总结：

## Mach 消息基本信息

如果你不知道 Mach 消息是什么，请开始查看此页面：

{{#ref}}
../../
{{#endref}}

目前请记住（[此处定义](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：\
Mach 消息通过 _mach 端口_ 发送，这是一个内置于 mach 内核的 **单接收者，多发送者通信** 通道。**多个进程可以向 mach 端口发送消息**，但在任何时候 **只有一个进程可以从中读取**。就像文件描述符和套接字一样，mach 端口由内核分配和管理，进程只看到一个整数，可以用来指示内核它们想使用哪个 mach 端口。

## XPC 连接

如果你不知道如何建立 XPC 连接，请查看：

{{#ref}}
../
{{#endref}}

## 漏洞总结

你需要知道的是 **XPC 的抽象是一个一对一的连接**，但它是基于一种 **可以有多个发送者的技术，因此：**

- Mach 端口是单接收者，**多个发送者**。
- XPC 连接的审计令牌是 **从最近接收到的消息中复制的审计令牌**。
- 获取 XPC 连接的 **审计令牌** 对许多 **安全检查** 至关重要。

尽管前面的情况听起来很有前景，但在某些场景中这不会导致问题（[来自这里](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：

- 审计令牌通常用于授权检查，以决定是否接受连接。由于这是通过向服务端口发送消息进行的，因此 **尚未建立连接**。在此端口上的更多消息将被视为额外的连接请求。因此，任何 **在接受连接之前的检查都不易受攻击**（这也意味着在 `-listener:shouldAcceptNewConnection:` 中审计令牌是安全的）。因此，我们 **正在寻找验证特定操作的 XPC 连接**。
- XPC 事件处理程序是同步处理的。这意味着一个消息的事件处理程序必须在调用下一个之前完成，即使在并发调度队列中。因此，在 **XPC 事件处理程序内部，审计令牌不能被其他正常（非回复！）消息覆盖**。

这可能被利用的两种不同方法：

1. 变体1：
- **利用** **连接** 到服务 **A** 和服务 **B**
- 服务 **B** 可以调用服务 A 中用户无法调用的 **特权功能**
- 服务 **A** 在 **`dispatch_async`** 中的 **事件处理程序** _**外部**_ 调用 **`xpc_connection_get_audit_token`**。
- 因此，**不同** 的消息可能会 **覆盖审计令牌**，因为它在事件处理程序外部异步调度。
- 利用将 **发送权** 传递给 **服务 B** 的服务 **A**。
- 因此，服务 **B** 实际上将 **发送** 消息到服务 **A**。
- **利用** 尝试 **调用** **特权操作**。在 RC 服务 **A** **检查** 此 **操作** 的授权时，**服务 B 覆盖了审计令牌**（使利用能够调用特权操作）。
2. 变体 2：
- 服务 **B** 可以调用服务 A 中用户无法调用的 **特权功能**
- 利用与 **服务 A** 连接，**服务 A** 向利用发送一条 **期望回复** 的 **消息**，在特定的 **回复** **端口** 中。
- 利用向 **服务** B 发送一条消息，传递 **该回复端口**。
- 当服务 **B 回复** 时，它 **发送消息到服务 A**，**同时** **利用** 向服务 **A** 发送不同的 **消息**，试图 **达到特权功能**，并期望服务 B 的回复在完美时刻覆盖审计令牌（竞争条件）。

## 变体 1：在事件处理程序外部调用 xpc_connection_get_audit_token <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

- 两个 mach 服务 **`A`** 和 **`B`**，我们都可以连接（基于沙箱配置文件和接受连接之前的授权检查）。
- _**A**_ 必须对 **`B`** 可以传递的特定操作进行 **授权检查**（但我们的应用程序不能）。
- 例如，如果 B 拥有某些 **权限** 或以 **root** 身份运行，它可能允许他请求 A 执行特权操作。
- 对于此授权检查，**`A`** 异步获取审计令牌，例如通过从 **`dispatch_async`** 调用 `xpc_connection_get_audit_token`。

> [!CAUTION]
> 在这种情况下，攻击者可以触发 **竞争条件**，使 **利用** **多次请求 A 执行操作**，同时使 **B 向 `A` 发送消息**。当 RC **成功** 时，**B** 的 **审计令牌** 将在 **利用** 的请求被 **处理** 时复制到内存中，从而使其 **访问只有 B 可以请求的特权操作**。

这发生在 **`A`** 作为 `smd` 和 **`B`** 作为 `diagnosticd`。函数 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) 可以用于安装新的特权辅助工具（作为 **root**）。如果 **以 root 身份运行的进程联系** **smd**，将不会执行其他检查。

因此，服务 **B** 是 **`diagnosticd`**，因为它以 **root** 身份运行并可用于 **监控** 进程，因此一旦监控开始，它将 **每秒发送多条消息**。

要执行攻击：

1. 使用标准 XPC 协议初始化与名为 `smd` 的服务的 **连接**。
2. 形成与 `diagnosticd` 的二次 **连接**。与正常程序相反，而不是创建并发送两个新的 mach 端口，客户端端口发送权被替换为与 `smd` 连接相关联的 **发送权** 的副本。
3. 结果，XPC 消息可以调度到 `diagnosticd`，但来自 `diagnosticd` 的响应被重定向到 `smd`。对 `smd` 来说，来自用户和 `diagnosticd` 的消息似乎来自同一连接。

![描述利用过程的图像](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 下一步是指示 `diagnosticd` 启动对所选进程（可能是用户自己的进程）的监控。同时，向 `smd` 发送大量常规 1004 消息。这里的意图是安装具有提升权限的工具。
5. 此操作触发 `handle_bless` 函数中的竞争条件。时机至关重要：`xpc_connection_get_pid` 函数调用必须返回用户进程的 PID（因为特权工具位于用户的应用程序包中）。然而，`xpc_connection_get_audit_token` 函数，特别是在 `connection_is_authorized` 子例程中，必须引用属于 `diagnosticd` 的审计令牌。

## 变体 2：回复转发

在 XPC（跨进程通信）环境中，尽管事件处理程序不会并发执行，但回复消息的处理具有独特的行为。具体而言，存在两种不同的方法来发送期望回复的消息：

1. **`xpc_connection_send_message_with_reply`**：在这里，XPC 消息在指定队列上接收和处理。
2. **`xpc_connection_send_message_with_reply_sync`**：相反，在此方法中，XPC 消息在当前调度队列上接收和处理。

这种区别至关重要，因为它允许 **回复数据包与 XPC 事件处理程序的执行并发解析**。值得注意的是，虽然 `_xpc_connection_set_creds` 确实实现了锁定以防止审计令牌的部分覆盖，但它并未将此保护扩展到整个连接对象。因此，这造成了一个漏洞，即审计令牌可以在解析数据包和执行其事件处理程序之间的间隔中被替换。

要利用此漏洞，需要以下设置：

- 两个 mach 服务，称为 **`A`** 和 **`B`**，都可以建立连接。
- 服务 **`A`** 应包括对只有 **`B`** 可以执行的特定操作的授权检查（用户的应用程序无法）。
- 服务 **`A`** 应发送一条期望回复的消息。
- 用户可以向 **`B`** 发送一条消息，**B** 将对此作出回应。

利用过程涉及以下步骤：

1. 等待服务 **`A`** 发送一条期望回复的消息。
2. 不直接回复 **`A`**，而是劫持回复端口并用于向服务 **`B`** 发送消息。
3. 随后，发送一条涉及禁止操作的消息，期望它与来自 **`B`** 的回复并发处理。

以下是所描述攻击场景的可视化表示：

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 发现问题

- **定位实例的困难**：静态和动态搜索 `xpc_connection_get_audit_token` 使用实例都很具挑战性。
- **方法论**：使用 Frida 钩住 `xpc_connection_get_audit_token` 函数，过滤不来自事件处理程序的调用。然而，这种方法仅限于被钩住的进程，并需要主动使用。
- **分析工具**：使用 IDA/Ghidra 等工具检查可达的 mach 服务，但该过程耗时，复杂性增加，涉及 dyld 共享缓存的调用。
- **脚本限制**：尝试为从 `dispatch_async` 块调用 `xpc_connection_get_audit_token` 的分析编写脚本时，由于解析块和与 dyld 共享缓存的交互的复杂性而受到阻碍。

## 修复 <a href="#the-fix" id="the-fix"></a>

- **报告问题**：向 Apple 提交了一份报告，详细说明了在 `smd` 中发现的一般和特定问题。
- **Apple 的回应**：Apple 通过将 `xpc_connection_get_audit_token` 替换为 `xpc_dictionary_get_audit_token` 解决了 `smd` 中的问题。
- **修复的性质**：`xpc_dictionary_get_audit_token` 函数被认为是安全的，因为它直接从与接收的 XPC 消息相关的 mach 消息中检索审计令牌。然而，它不是公共 API 的一部分，类似于 `xpc_connection_get_audit_token`。
- **缺乏更广泛的修复**：尚不清楚为什么 Apple 没有实施更全面的修复，例如丢弃与连接的保存审计令牌不对齐的消息。在某些情况下（例如，使用 `setuid`）合法的审计令牌更改的可能性可能是一个因素。
- **当前状态**：该问题在 iOS 17 和 macOS 14 中仍然存在，给那些寻求识别和理解它的人带来了挑战。

{{#include ../../../../../../banners/hacktricks-training.md}}
