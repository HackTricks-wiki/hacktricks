# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**如需进一步了解，请查看原始文章：** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。以下是摘要：<sup>[[1]](#references)</sup>

## Mach Messages 基本信息

如果你不了解 Mach Messages，请先查看此页面：


{{#ref}}
../../
{{#endref}}

目前请记住以下内容（[定义来自此处](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：<sup>[[1]](#references)</sup>\
Mach messages 通过 _mach port_ 发送。mach port 是 Mach kernel 内置的**单接收者、多发送者通信**通道。**多个进程可以向 mach port 发送消息**，但在任何时刻**只有一个进程可以从中读取消息**。与文件描述符和 sockets 一样，mach ports 由 kernel 分配和管理，进程只能看到一个整数，并使用该整数告知 kernel 要使用自己的哪个 mach port。

## XPC Connection

如果你不了解如何建立 XPC connection，请查看：


{{#ref}}
../
{{#endref}}

## 漏洞摘要

你需要了解的重点是，**XPC 的抽象模型是一对一 connection**，但它建立在一种**可以拥有多个发送者的技术**之上，因此：

- Mach ports 是单接收者、**多发送者**。
- XPC connection 的 audit token 是**从最近收到的 message 中复制而来**的 audit token。
- 获取 XPC connection 的 **audit token** 对许多**安全检查**至关重要。<sup>[[1]](#references)</sup>

尽管上述情况听起来很有希望，但在某些场景下不会造成问题（[来源](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：<sup>[[1]](#references)</sup>

- Audit tokens 通常用于授权检查，以决定是否接受 connection。由于这是通过向 service port 发送 message 来完成的，此时**尚未建立 connection**。在该 port 上发送的其他 messages 只会被当作额外的 connection requests 处理。因此，**接受 connection 之前的检查不易受影响**（这也意味着在 `-listener:shouldAcceptNewConnection:` 中，audit token 是安全的）。所以我们要**寻找会验证特定操作的 XPC connections**。
- XPC event handlers 是同步处理的。这意味着，即使使用并发 dispatch queues，一条 message 的 event handler 也必须完成后，才能调用下一条 message 的 event handler。因此，在 **XPC event handler 内，audit token 不会被其他普通（非 reply！）messages 覆盖**。<sup>[[1]](#references)</sup>

这可能被利用的两种不同方法：

1. Variant1:
- **Exploit** **连接**到 service **A** 和 service **B**
- Service **B** 可以调用 service A 中用户无法调用的**特权功能**
- Service **A** 在**不处于 connection 的 event handler 中**且位于 **`dispatch_async`** 内时调用 **`xpc_connection_get_audit_token`**。
- 因此，**不同的** message 可能会**覆盖 Audit Token**，因为该调用是在 event handler 外部异步 dispatch 的。
- **Exploit** 将 service **A** 的 SEND right 传递给 **service B**。
- 因此，svc **B** 实际上会向 **service A** **发送** **messages**。
- **Exploit** 尝试调用**特权操作**。在 RC 中，svc **A** 会在 **svc B 覆盖 Audit token** 时检查该操作的授权（从而让 exploit 获得调用特权操作的权限）。
2. Variant 2:
- Service **B** 可以调用 service A 中用户无法调用的**特权功能**
- Exploit 连接到 **service A**，后者向 exploit 发送一条**期待响应**的 message，并使用特定的 **replay** **port**。
- Exploit 向 **service B** 发送一条 message，并传递**该 reply port**。
- 当 service **B** 回复时，它会将 message **发送给 service A**，而与此同时，**exploit** 向 service A 发送另一条 message，尝试**访问特权功能**，并期望 service B 的回复在恰当时机覆盖 Audit token（Race Condition）。

## Variant 1: 在 event handler 外部调用 xpc_connection_get_audit_token <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

- 有两个我们都可以连接的 Mach services **`A`** 和 **`B`**（取决于 sandbox profile 以及接受 connection 前的授权检查）。
- _**A**_ 必须针对某个特定操作执行**授权检查**，而该检查是 **`B`** 可以通过、但我们的 app 无法通过的。
- 例如，如果 B 具有某些 **entitlements** 或以 **root** 身份运行，它可能会被允许请求 A 执行特权操作。
- 对于此授权检查，**`A`** 会异步获取 audit token，例如从 **`dispatch_async`** 中调用 `xpc_connection_get_audit_token`。

> [!CAUTION]
> 在这种情况下，攻击者可以触发 **Race Condition**，构造一个 **exploit**，在让 **B** 向 **`A`** 发送 messages 的同时，多次请求 **A** 执行某个操作。当 RC **成功**时，**B** 的 **audit token** 会在内存中被复制，而此时 **exploit** 的请求正在由 A **处理**，从而让 exploit 获得只有 B 才能请求的特权操作权限。

这一问题曾出现在 **`A`** 为 `smd`、**`B`** 为 `diagnosticd` 的情况下。可以使用 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) 函数安装新的特权 helper toot（以 **root** 身份）。如果**以 root 身份运行的进程联系** **smd**，则不会执行其他检查。

因此，service **B** 是 **`diagnosticd`**，因为它以 **root** 身份运行，并可用于**监控**进程；监控开始后，它会**每秒发送多条 messages**。

执行攻击：

1. 使用标准 XPC protocol 初始化与名为 `smd` 的 service 的 **connection**。
2. 与 `diagnosticd` 建立 secondary **connection**。与正常流程不同，客户端 port send right 不创建并发送两个新的 mach ports，而是替换为与 `smd` connection 关联的 **send right** 的副本。
3. 结果是，XPC messages 可以被 dispatch 到 `diagnosticd`，但来自 `diagnosticd` 的响应会被重新路由到 `smd`。对于 `smd` 来说，来自用户和 `diagnosticd` 的 messages 看起来都源自同一个 connection。

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 下一步是指示 `diagnosticd` 开始监控指定进程（可能是用户自己的进程）。与此同时，向 `smd` 发送大量常规 1004 messages。目标是在提升的权限下安装工具。
5. 此操作会在 `handle_bless` 函数内触发 race condition。时机至关重要：`xpc_connection_get_pid` 函数调用必须返回用户进程的 PID（因为特权工具位于用户的 app bundle 中）。但是，`xpc_connection_get_audit_token` 函数，具体来说是 `connection_is_authorized` 子程序中的调用，必须引用属于 `diagnosticd` 的 audit token。<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

在 XPC（Cross-Process Communication）环境中，虽然 event handlers 不会并发执行，但 reply messages 的处理具有独特行为。具体来说，发送期待 reply 的 messages 有两种不同方法：

1. **`xpc_connection_send_message_with_reply`**：在这种方式中，XPC message 会在指定的 queue 上接收并处理。
2. **`xpc_connection_send_message_with_reply_sync`**：相反，在这种方式中，XPC message 会在当前 dispatch queue 上接收并处理。

这一差异非常关键，因为它可能允许 **reply packets 在 XPC event handler 执行期间被并发解析**。值得注意的是，虽然 `_xpc_connection_set_creds` 确实实现了 locking 来防止 audit token 被部分覆盖，但这种保护并未扩展到整个 connection object。因此，这会产生一个漏洞：在 packet 被解析与其 event handler 执行之间的时间窗口内，audit token 可能被替换。

要利用此漏洞，需要满足以下设置：

- 两个 Mach services，分别称为 **`A`** 和 **`B`**，二者都可以建立 connection。
- Service **`A`** 应包含针对某项特定操作的授权检查，且只有 **`B`** 可以执行该操作（用户的 application 无法执行）。
- Service **`A`** 应发送一条期待 reply 的 message。
- 用户可以向 **`B`** 发送一条它会响应的 message。

利用过程包括以下步骤：

1. 等待 service **`A`** 发送一条期待 reply 的 message。
2. 不直接向 **`A`** 回复，而是劫持 reply port，并利用它向 service **`B`** 发送 message。
3. 随后 dispatch 一条涉及被禁止操作的 message，并期望它与来自 **`B`** 的 reply 并发处理。<sup>[[1]](#references)</sup>

以下是所述攻击场景的可视化表示：

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 发现问题

- **定位实例的困难**：无论是静态还是动态方式，搜索 `xpc_connection_get_audit_token` 的使用实例都很困难。
- **方法**：使用 Frida hook `xpc_connection_get_audit_token` 函数，并过滤非 event handlers 发起的调用。但这种方法仅限于被 hook 的进程，并且要求该函数处于活跃使用状态。
- **分析工具**：使用 IDA/Ghidra 检查可访问的 Mach services，但这一过程耗时较长，并且会因涉及 dyld shared cache 的调用而更加复杂。
- **Scripting 限制**：尝试对来自 `dispatch_async` blocks 的 `xpc_connection_get_audit_token` 调用进行 scripting 分析时，受到 blocks 解析以及与 dyld shared cache 交互的复杂性影响。<sup>[[1]](#references)</sup>

## 修复 <a href="#the-fix" id="the-fix"></a>

- **报告的问题**：向 Apple 提交了一份报告，详细说明在 `smd` 中发现的一般性和具体问题。
- **Apple 的响应**：Apple 在 `smd` 中使用 `xpc_dictionary_get_audit_token` 替换了 `xpc_connection_get_audit_token`，从而修复了该问题。<sup>[[1]](#references)[[2]](#references)</sup>
- **修复性质**：`xpc_dictionary_get_audit_token` 函数被认为是安全的，因为它直接从与收到的 XPC message 关联的 Mach message 中获取 audit token。不过，它与 `xpc_connection_get_audit_token` 一样，并不属于 public API。
- **缺乏更广泛的修复**：目前尚不清楚 Apple 为什么没有实施更全面的修复，例如丢弃与 connection 已保存 audit token 不一致的 messages。某些场景下 audit token 可能合法发生变化（例如使用 `setuid`）或许是其中一个原因。
- **当前状态**：该问题在 iOS 17 和 macOS 14 中仍然存在，这给希望识别和理解该问题的人带来了挑战。<sup>[[1]](#references)</sup>

## 实际查找易受攻击的代码路径（2024–2025）

审计 XPC services 是否存在此类 bug 时，应重点关注在 message 的 event handler 外部执行的授权，或与 reply 处理并发执行的授权。

静态 triage 提示：

- 搜索从通过 `dispatch_async`/`dispatch_after` 或其他 worker queues 排队的 blocks 可达的 `xpc_connection_get_audit_token` 调用，这些 blocks 会在 message handler 外部运行。
- 查找混合使用 per-connection 和 per-message 状态的授权 helper（例如从 `xpc_connection_get_pid` 获取 PID，但从 `xpc_connection_get_audit_token` 获取 audit token）。
- 在 NSXPC code 中，确认检查是在 `-listener:shouldAcceptNewConnection:` 中执行的；或者对于 per-message 检查，确认实现使用的是 per-message audit token（例如在较低层 code 中通过 message 的 dictionary 使用 `xpc_dictionary_get_audit_token`）。

动态 triage 提示：

- Hook `xpc_connection_get_audit_token`，并标记其 user stack 不包含 event-delivery path 的调用（例如 `_xpc_connection_mach_event`）。Frida hook 示例：
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
注意：
- 在 macOS 上，对受保护的/Apple binaries 进行 instrumenting 可能需要禁用 SIP 或使用开发环境；优先测试你自己的 builds 或 userland services。
- 对于 reply-forwarding races（Variant 2），通过 fuzzing `xpc_connection_send_message_with_reply` 与普通请求之间的 timing，监控 reply packets 的并发解析，并检查授权过程中使用的 effective audit token 是否可能受到影响。

## 你可能需要的 Exploitation primitives

- Multi-sender setup（Variant 1）：创建到 A 和 B 的 connections；duplicate A 的 client port 的 send right，并将其用作 B 的 client port，使 B 的 replies 被 delivered 到 A。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2)：从 A 的 pending request（reply port）中捕获 send-once right，然后使用该 reply port 向 B 发送 crafted message，使 B 的 reply 在你的 privileged request 正在被解析时发送到 A。

这些操作需要针对 XPC bootstrap 和 message formats 进行 low-level mach message crafting；请查看本节中的 mach/XPC primer 页面，了解确切的 packet layouts 和 flags。

## 有用的 tooling

- XPC sniffing/dynamic inspection：gxpc（open-source XPC sniffer）可帮助枚举 connections 并观察 traffic，以验证 multi-sender setups 和 timing。例如：`gxpc -p <PID> --whitelist <service-name>`。
- 用于 libxpc 的经典 dyld interposing：对 `xpc_connection_send_message*` 和 `xpc_connection_get_audit_token` 进行 interpose，在 black-box testing 期间记录 call sites 和 stacks。



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
