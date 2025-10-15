# macOS xpc_connection_get_audit_token 攻击

{{#include ../../../../../../banners/hacktricks-training.md}}

**如需更多信息请查看原文文章：** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). 下面是摘要：

## Mach Messages Basic Info

如果你不知道什么是 Mach Messages，请先查看这一页：


{{#ref}}
../../
{{#endref}}

目前请记住（[定义来自这里](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：\
Mach messages 通过 _mach port_ 发送，mach port 是内建在 mach kernel 中的一个 **单接收者、多发送者通信** 通道。**多个进程可以向一个 mach port 发送消息**，但在任意时刻**只有单个进程可以从中读取**。就像 file descriptors 和 sockets 一样，mach ports 由内核分配和管理，进程只看到一个整数，通过它告诉内核想要使用哪个 mach port。

## XPC Connection

如果你不知道 XPC connection 是如何建立的，请查看：


{{#ref}}
../
{{#endref}}

## Vuln Summary

重要的是要知道 XPC 的抽象是“一对一连接”，但它构建在一个**可以有多个发送者**的技术之上，因此：

- Mach ports 是单接收者、**多发送者**。
- 一个 XPC connection 的 audit token 是**从最近收到的消息复制过来的 audit token**。
- 获取 XPC connection 的 **audit token** 对许多 **安全检查** 非常关键。

尽管上面的情况看起来有问题，但以下场景不会造成影响（[来源](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：

- Audit tokens 常用于授权检查以决定是否接受连接。由于这是使用对服务端口的消息完成的，因此**还没有建立连接**。对该端口的更多消息只会被作为额外的连接请求处理。因此，任何**在接受连接之前的检查都不易受影响**（这也意味着在 `-listener:shouldAcceptNewConnection:` 中 audit token 是安全的）。因此我们**关注那些验证特定操作的 XPC 连接**。
- XPC 事件处理器是同步处理的。这意味着一个消息的事件处理器必须在调用下一个消息的事件处理器之前完成，即使在并发的 dispatch queues 上也是如此。因此在 **XPC 事件处理器内部，audit token 无法被其他普通（非 reply）消息覆盖**。

两种不同的方法可能被利用：

1. Variant1:
- **Exploit** **connects** 到服务 **A** 和服务 **B**
- 服务 **B** 可以在服务 **A** 中调用用户不能调用的 **privileged functionality**
- 服务 **A** 在**不**处于连接的事件处理器内部、而是从 **`dispatch_async`** 中调用 `xpc_connection_get_audit_token`
- 因此，一个**不同的**消息可能会**覆盖 Audit Token**，因为它在事件处理器外异步分派
- exploit 将 **svc A 的 SEND right** 传给 **service B**
- 所以 svc **B** 实际上会**发送**消息到 svc **A**
- **Exploit** 尝试**调用**那个受限的操作。在 RC 成功时，svc **A** 在检查该操作的授权时，**svc B 已覆盖了 Audit token**（从而使 exploit 获得调用该受限操作的权限）
2. Variant 2:
- 服务 **B** 可以调用服务 A 中用户不能调用的 **privileged functionality**
- Exploit 与 **service A** 建立连接，service A 向 exploit 发送一个**期望在特定 reply port 收到响应**的消息
- Exploit 将该 **reply port** 传给 **service B**
- 当 service **B** 回复时，它会**将消息发送回 service A**，与此同时 **exploit** 发送另一条消息到 service **A** 尝试**调用受限功能**，并期望 service B 的回复在完美时机覆盖 Audit token（竞态条件）

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

- 两个 mach services，**`A`** 和 **`B`**，我们都能连接（基于 sandbox 配置和接受连接之前的授权检查）。
- _**A**_ 必须对某个特定操作做**授权检查**，而该操作 **`B`** 能通过（但我们的应用不能）。
- 例如，如果 B 有某些 **entitlements** 或以 **root** 身份运行，它可能允许向 A 请求执行受限操作。
- 为了这个授权检查，**`A`** 异步获取 audit token，例如在 **`dispatch_async`** 中调用 `xpc_connection_get_audit_token`。

> [!CAUTION]
> 在这种情况下，攻击者可以触发一个 **Race Condition**：让**exploit** 多次请求 A 执行某个操作，同时让 **B 向 A 发送消息**。当 RC 成功时，**B 的 audit token 会在我们的请求被 A 处理时被复制进内存**，从而赋予 exploit 对只有 B 能请求的受限操作的访问权限。

这在 **`A`** 为 `smd` 且 **`B`** 为 `diagnosticd` 时发生过。来自 smb 的函数 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) 可用于安装一个新的具有特权的 helper tool（以 **root**）。如果一个以 **root** 运行的进程联系 `smd`，可能不会执行其他检查。

因此，服务 **B** 是 **`diagnosticd`**，因为它以 **root** 运行并且可以用于**监控**进程，一旦开始监控，它会**每秒发送多条消息**。

执行该攻击的步骤：

1. 使用标准 XPC 协议向名为 `smd` 的服务初始化一个**连接**。
2. 建立到 `diagnosticd` 的第二个**连接**。与正常流程不同，不是创建并发送两个新的 mach ports，而是用与 `smd` 连接相关联的 **send right** 的副本替换客户端端口的 send right。
3. 结果是，XPC 消息可以被分派到 `diagnosticd`，但来自 `diagnosticd` 的响应被重新路由到 `smd`。对 `smd` 来说，看起来来自用户和 `diagnosticd` 的消息都源自同一个连接。

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 接下来指示 `diagnosticd` 开始监控一个选定的进程（可能是用户自己的进程）。同时，向 `smd` 发送大量常规的 1004 消息。目的是安装一个具有提升权限的工具。
5. 该操作在 `handle_bless` 函数内触发了一个竞态条件。时机至关重要：`xpc_connection_get_pid` 调用必须返回用户进程的 PID（因为特权工具位于用户的 app bundle 中）。但 `xpc_connection_get_audit_token`（特别是在 `connection_is_authorized` 子例程中）必须引用属于 `diagnosticd` 的 audit token。

## Variant 2: reply forwarding

在 XPC（跨进程通信）环境中，尽管事件处理器不会并发执行，但 reply 消息的处理有独特行为。具体来说，有两种不同的方法用于发送期望回复的消息：

1. **`xpc_connection_send_message_with_reply`**：在此方式中，XPC 消息在指定的队列上被接收并处理。
2. **`xpc_connection_send_message_with_reply_sync`**：相反，在此方法中，XPC 消息在当前 dispatch queue 上被接收并处理。

这个区别很关键，因为它允许**reply 数据包在 XPC 事件处理器执行的同时被解析**。值得注意的是，虽然 `_xpc_connection_set_creds` 确实实现了锁以防止部分覆盖 audit token，但它并没有将这种保护扩展到整个 connection 对象。因此，就出现了这样一种漏洞：在解析数据包和执行其事件处理器之间的间隙，audit token 可能被替换。

要利用此漏洞，需要以下设置：

- 两个 mach services，称为 **`A`** 和 **`B`**，两者都可以建立连接。
- 服务 **`A`** 应包含对某个只有 **`B`** 能执行（而用户应用不能）的操作的授权检查。
- 服务 **`A`** 应发送一条期望回复的消息。
- 用户可以向 **`B`** 发送一条它会回复的消息。

利用过程包括以下步骤：

1. 等待服务 **`A`** 发送一条期望回复的消息。
2. 不直接回复给 **`A`**，而是劫持 reply port 并使用它向服务 **`B`** 发送消息。
3. 随后发送一条涉及受限操作的消息，期望它会与来自 **`B`** 的回复同时被处理。

下面是对该攻击场景的可视化表示：

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **难以定位实例**：静态和动态地搜索 `xpc_connection_get_audit_token` 的使用都很困难。
- **方法学**：使用 Frida hook `xpc_connection_get_audit_token`，过滤那些不来自事件处理器的调用。但此方法仅限于被 hook 的进程并且需要进程处于被动用状态。
- **分析工具**：使用 IDA/Ghidra 检查可达的 mach services，但过程耗时，并且被涉及 dyld shared cache 的调用复杂化。
- **脚本化限制**：尝试为从 `dispatch_async` block 调用 `xpc_connection_get_audit_token` 的分析编写脚本时，因解析 blocks 及与 dyld shared cache 的交互而受阻。

## The fix <a href="#the-fix" id="the-fix"></a>

- **已上报的问题**：已向 Apple 提交报告，说明在 `smd` 中发现的通用和具体问题。
- **Apple 的回应**：Apple 在 `smd` 中用 `xpc_dictionary_get_audit_token` 替换了 `xpc_connection_get_audit_token`。
- **修复性质**：`xpc_dictionary_get_audit_token` 被认为是安全的，因为它直接从与接收到的 XPC 消息关联的 mach message 中检索 audit token。不过，它并不是公共 API 的一部分，类似于 `xpc_connection_get_audit_token`。
- **没有更广泛的修复**：不清楚为什么 Apple 没有实施更全面的修复，例如丢弃与连接保存的 audit token 不匹配的消息。某些场景（比如使用 `setuid`）中 audit token 合法变更的可能性或许是一个因素。
- **当前状态**：该问题在 iOS 17 和 macOS 14 中仍然存在，给想要识别和理解它的人带来挑战。

## Finding vulnerable code paths in practice (2024–2025)

在审计 XPC 服务以查找此类漏洞时，重点关注在消息的事件处理器之外或在 reply 处理并发期间执行的授权检查。

静态初筛提示：
- 搜索可从通过 `dispatch_async`/`dispatch_after` 排队的 blocks 或在消息处理器外运行的其他 worker queues 可达的 `xpc_connection_get_audit_token` 调用。
- 查找将 per-connection 和 per-message 状态混合的授权辅助函数（例如，从 `xpc_connection_get_pid` 获取 PID，但从 `xpc_connection_get_audit_token` 获取 audit token）。
- 在 NSXPC 代码中，验证检查是否在 `-listener:shouldAcceptNewConnection:` 中完成，或对于每条消息的检查，确保实现使用每条消息的 audit token（例如在底层代码中通过消息的字典使用 `xpc_dictionary_get_audit_token`）。

动态初筛技巧：
- Hook `xpc_connection_get_audit_token`，并标记那些其用户栈不包含事件传递路径（例如 `_xpc_connection_mach_event`）的调用。示例 Frida hook:
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
Notes:
- 在 macOS 上，对受保护的/Apple binaries 进行插桩可能需要禁用 SIP 或使用开发环境；建议优先测试你自己的构建或 userland services。
- 对于 reply-forwarding races (Variant 2)，通过对比 `xpc_connection_send_message_with_reply` 与正常请求 的时序进行模糊测试，监视回复数据包的并发解析，并检查在授权时使用的有效 audit token 是否可以被影响。

## Exploitation primitives you will likely need

- Multi-sender setup (Variant 1): 为 A 和 B 建立连接；复制 A 的 client port 的 send right 并将其用作 B 的 client port，使得 B 的回复被送达 A。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): 从 A 的挂起请求（reply port）中捕获 send-once 权限，然后使用该 reply port 向 B 发送一个精心构造的消息，使 B 的回复在你的特权请求被解析时返回到 A。

这些情况需要对 XPC bootstrap 和消息格式进行低级别的 mach 消息构造；请查看本节的 mach/XPC primer 页面以获取确切的 packet layouts 和 flags。

## 有用的 tooling

- XPC sniffing/dynamic inspection: gxpc（开源 XPC sniffer）可帮助枚举连接并观察流量，以验证 multi-sender 配置和时序。示例：`gxpc -p <PID> --whitelist <service-name>`。
- Classic dyld interposing for libxpc: 对 `xpc_connection_send_message*` 和 `xpc_connection_get_audit_token` 进行 interpose，以在 black-box testing 期间记录调用位置和堆栈。



## 参考资料

- Sector 7 – Don’t Talk All at Once! 提升 macOS 权限的方法：Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – 关于 macOS Ventura 13.4 的安全内容 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
