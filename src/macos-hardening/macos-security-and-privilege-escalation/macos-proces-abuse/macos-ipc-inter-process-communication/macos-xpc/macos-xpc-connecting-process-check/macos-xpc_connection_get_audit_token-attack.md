# macOS xpc_connection_get_audit_token 攻击

{{#include ../../../../../../banners/hacktricks-training.md}}

**有关更多信息请查看原文：** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。以下为摘要：

## Mach Messages 基本信息

如果你不知道什么是 Mach Messages，请先查阅此页面：


{{#ref}}
../../
{{#endref}}

目前记住（来自此处的定义）：\
Mach messages 是通过 _mach port_ 发送的，它是内核提供的一个 **单接收者、多发送者通信** 通道。**多个进程可以向同一个 mach port 发送消息**，但在任何时刻**只有一个进程能从中读取**。就像文件描述符和 sockets 一样，mach ports 由内核分配和管理，进程只看到一个整数，用以向内核指示它们想要使用哪个 mach port。

## XPC Connection

如果你不知道 XPC connection 如何建立，请查看：


{{#ref}}
../
{{#endref}}

## 漏洞概述

对你重要的是，**XPC 的抽象是点对点连接（one-to-one）**，但它构建在一个**可以有多个发送者**的技术之上，所以：

- Mach ports 是单接收者、**多发送者**的。
- 一个 XPC connection 的 audit token 是**从最近接收的消息复制过来**的 audit token。
- 获取 XPC connection 的 **audit token** 对许多 **安全检查** 至关重要。

尽管上述情况看起来有问题，但在某些场景下不会造成影响（来源）： 

- Audit tokens 常用于授权检查以决定是否接受连接。由于这是通过向 service port 发送消息来完成的，此时**尚未建立连接**。该端口上的更多消息只会被视为额外的连接请求。因此，任何**在接受连接之前的检查都不易受到影响**（这也意味着在 `-listener:shouldAcceptNewConnection:` 中 audit token 是安全的）。因此我们**关注那些验证特定操作的 XPC 连接**。
- XPC 事件处理器是同步处理的。这意味着一个消息的事件处理器必须完成后才能处理下一个消息，即便是在并发的 dispatch 队列上。因此在 **XPC 事件处理器内部，audit token 不会被其他普通（非 reply）消息覆盖**。

两种不同的方法可能被利用：

1. Variant1:
- **Exploit** 连接到 service **A** 和 service **B**
- Service **B** 可以在 service A 中调用一个用户不能调用的 **特权功能**
- Service **A** 在**不**处于该连接的事件处理器内，而是在 `dispatch_async` 中调用 **`xpc_connection_get_audit_token`**
- 因此，**不同**的消息可能会覆盖 Audit Token，因为它在事件处理器之外被异步调度。
- Exploit 将 **对 svc A 的 SEND 权限** 传递给 **service B**。
- 所以 svc **B** 实际上会**发送**消息到 svc **A**。
- **Exploit** 尝试调用该 **特权操作**。在一个 RC（竞态）情形中，svc **A** 在 **svc B 覆盖 Audit token** 时对该操作进行了授权检查（从而使 exploit 获得调用该特权操作的权限）。
2. Variant 2:
- Service **B** 可以在 service A 中调用一个用户不能调用的 **特权功能**
- Exploit 与 **service A** 建立连接，service A 将向 exploit 发送一条**期望在特定 reply port 上得到响应**的消息。
- Exploit 将该 **reply port** 发送给 service **B**。
- 当 service **B** 回复时，它会**将消息发送到 service A**，与此同时 **exploit** 向 service **A** 发送另一条尝试**触及特权功能**的消息，并期望来自 service B 的回复在恰当时机覆盖 Audit token（竞态条件）。

## Variant 1: 在事件处理器外调用 xpc_connection_get_audit_token <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

- 两个 mach services **`A`** 和 **`B`**，我们都能连接到它们（基于 sandbox 配置和在接受连接前的授权检查）。
- _**A**_ 必须对某个特定动作进行 **授权检查**，而 **`B`** 可以通过该检查（但我们的应用不能）。
- 例如，如果 B 有某些 **entitlements** 或以 **root** 身份运行，它可能被允许请求 A 执行一个特权操作。
- 在这个授权检查中，**`A`** 异步获取 audit token，例如在 **`dispatch_async`** 中调用 `xpc_connection_get_audit_token`。

> [!CAUTION]
> 在这种情况下，攻击者可以触发一个**竞态条件（Race Condition）**：攻击者让 **exploit** 多次请求 A 执行某个操作，同时让 **B 向 A 发送消息**。当竞态成功时，**B 的 audit token** 会在我们的 **exploit** 的请求被 A 处理时被复制到内存中，从而使 exploit 获得只有 B 能请求的特权操作的访问权限。

这曾发生在 **`A`** 是 `smd`，**`B`** 是 `diagnosticd` 的情形。smb 中的函数 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) 可用于以 root 身份安装新的特权 helper tool。如果一个 **以 root 运行的进程联系** `smd`，则不会执行其他检查。

因此，service **B** 为 **`diagnosticd`**，因为它以 **root** 身份运行且可用于 **监控** 进程，一旦开始监控，它会**每秒发送多条消息**。

攻击步骤：

1. 使用标准 XPC 协议对名为 `smd` 的 service 发起 **连接**。
2. 再对 `diagnosticd` 建立一个次要 **连接**。与常规流程不同，客户端端口的 send 权被替换为 `smd` 连接所关联的 **send right 的副本**，而不是创建并发送两个全新的 mach ports。
3. 结果是，XPC 消息可以发送到 `diagnosticd`，但来自 `diagnosticd` 的响应被重定向到了 `smd`。对 `smd` 而言，看起来来自用户和 `diagnosticd` 的消息都来自同一个连接。

![图示漏洞利用过程](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 接下来指示 `diagnosticd` 开始监控选定的进程（可能是用户自己的进程）。同时，向 `smd` 发送大量常规的 1004 消息。目标是安装一个具有提升权限的工具。
5. 该操作在 `handle_bless` 函数中触发了竞态条件。时间点非常关键：`xpc_connection_get_pid` 必须返回用户进程的 PID（因为特权工具位于用户的 app bundle 中）。但是，`xpc_connection_get_audit_token`（特别是在 `connection_is_authorized` 子例程中）必须引用属于 `diagnosticd` 的 audit token。

## Variant 2: reply forwarding

在 XPC（跨进程通信）环境中，尽管事件处理器不会并发执行，但 reply 消息的处理具有特殊行为。具体来说，存在两种不同的方法来发送期望回复的消息：

1. **`xpc_connection_send_message_with_reply`**：在此方法中，XPC 消息会在指定的队列上被接收和处理。
2. **`xpc_connection_send_message_with_reply_sync`**：相反，在此方法中，XPC 消息会在当前的 dispatch 队列上被接收和处理。

这种区别很关键，因为它允许**在 XPC 事件处理器执行的同时并发解析 reply 包**的可能性。值得注意的是，尽管 `_xpc_connection_set_creds` 实现了加锁以防止 audit token 的部分覆盖，但它并未对整个 connection 对象提供保护。因此，这就产生了一个漏洞：audit token 可能在解析一个数据包与其事件处理器执行之间的时间窗口被替换。

要利用此漏洞，需要以下设置：

- 两个 mach services，称为 **`A`** 和 **`B`**，两者都能建立连接。
- Service **`A`** 应对某个只有 **`B`** 能执行（用户应用不能）的特定动作进行授权检查。
- Service **`A`** 应发送一条期望回复的消息。
- 用户可以向 **`B`** 发送一条它会回复的消息。

利用过程如下：

1. 等待 service **`A`** 发送一条期望回复的消息。
2. 不直接回复给 **`A`**，而是劫持该 reply port 并用它向 service **`B`** 发送消息。
3. 随后发送一条涉及被禁止动作的消息，期望它在与来自 **`B`** 的回复并发处理时被执行，从而利用 audit token 被覆盖的时机。

下面是该攻击场景的可视化表示：

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 发现问题的难点

- **定位实例困难**：查找 `xpc_connection_get_audit_token` 的使用实例既困难于静态分析，也困难于动态分析。
- **方法论**：使用 Frida hook `xpc_connection_get_audit_token`，并过滤那些非来自事件处理器的调用路径。然而，这种方法仅限于被 hook 的进程且需要进程处于活跃使用状态。
- **分析工具**：使用 IDA/Ghidra 检查可达的 mach services，但该过程耗时且复杂，尤其是涉及 dyld shared cache 调用时。
- **脚本化限制**：尝试脚本化对来自 `dispatch_async` 块调用 `xpc_connection_get_audit_token` 的分析受限于解析 blocks 的复杂性以及与 dyld shared cache 的交互。

## 修复情况 <a href="#the-fix" id="the-fix"></a>

- **已上报的问题**：已向 Apple 提交报告，说明在 `smd` 中发现的一般性和具体问题。
- **Apple 的回应**：Apple 在 `smd` 中用 `xpc_dictionary_get_audit_token` 替换了 `xpc_connection_get_audit_token`。
- **修复的性质**：`xpc_dictionary_get_audit_token` 被认为是安全的，因为它直接从与接收到的 XPC 消息关联的 mach message 中获取 audit token。不过，它并不是公开 API 的一部分，和 `xpc_connection_get_audit_token` 类似。
- **没有更广泛的修复**：尚不清楚 Apple 为什么没有实施更全面的修复，比如丢弃那些与连接保存的 audit token 不一致的消息。某些场景下 audit token 合法改变（例如使用 `setuid`）的可能性可能是一个因素。
- **当前状态**：该问题在 iOS 17 和 macOS 14 中仍然存在，这使得定位和理解该问题具有挑战性。

## 在实践中查找易受影响的代码路径（2024–2025）

审计 XPC services 时，重点关注在消息的事件处理器之外或在 reply 处理并发期间执行的授权检查。

静态初筛提示：
- 搜索可从通过 `dispatch_async`/`dispatch_after` 队列排入的 blocks 或其他在消息处理器外运行的工作队列中到达的 `xpc_connection_get_audit_token` 调用。
- 查找混合连接级和消息级状态的授权 helper（例如从 `xpc_connection_get_pid` 获取 PID，但从 `xpc_connection_get_audit_token` 获取 audit token）。
- 在 NSXPC 代码中，确认检查是在 `-listener:shouldAcceptNewConnection:` 中完成的，或者对于按消息的检查，确保实现使用按消息的 audit token（例如在底层代码中通过消息的 dictionary 使用 `xpc_dictionary_get_audit_token`）。

动态初筛技巧：
- Hook `xpc_connection_get_audit_token` 并标记那些其用户栈不包含事件递送路径（例如 `_xpc_connection_mach_event`）的调用。示例 Frida hook：
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
注意事项:
- 在 macOS 上，对受保护的/Apple 二进制文件进行插装可能需要禁用 SIP 或使用开发环境；建议优先在你自己的构建或用户态服务（userland services）上进行测试。
- 对于 reply-forwarding races (Variant 2)，通过 fuzzing `xpc_connection_send_message_with_reply` 与正常请求的时序来监控回复数据包的并发解析，并检查在授权期间使用的有效 audit token 是否可以被影响。

## 你可能需要的利用原语

- Multi-sender setup (Variant 1): 创建到 A 和 B 的连接；复制 A 的 client port 的 send right 并将其作为 B 的 client port 使用，使得 B 的回复被送达至 A。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): 从 A 的 pending request (reply port) 中捕获 send-once right，然后使用该 reply port 向 B 发送伪造消息，使得 B 的回复在你的特权请求被解析时落到 A 上。

这些方法需要对低级别 mach message 进行构造，以适配 XPC bootstrap 和消息格式；请查看本节中的 mach/XPC primer 页面以获取精确的数据包布局和标志。

## Useful tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) 可帮助枚举连接并观察流量，以验证 multi-sender 设置和时序。示例： `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: 对 `xpc_connection_send_message*` 和 `xpc_connection_get_audit_token` 进行 interpose，以在 black-box testing 期间记录调用位置和调用栈。



## References

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
