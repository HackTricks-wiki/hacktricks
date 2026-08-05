# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**如需进一步了解，请查看原始文章：** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。以下是摘要：

## Mach Messages 基础信息

如果你不了解 Mach Messages，请先查看此页面：


{{#ref}}
../../
{{#endref}}

目前请记住以下内容（[定义来源](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：\
Mach messages 通过 _mach port_ 发送。mach port 是 mach kernel 内置的**单接收者、多发送者通信** channel。**多个进程可以向 mach port 发送 messages**，但在任意时刻**只能有一个进程从中读取**。与 file descriptors 和 sockets 一样，mach ports 由 kernel 分配和管理，进程只能看到一个 integer，并使用它告知 kernel 想要使用哪个 mach port。

## XPC Connection

如果你不了解如何建立 XPC connection，请查看：


{{#ref}}
../
{{#endref}}

## 漏洞摘要

你需要了解的重点是，**XPC 的 abstraction 是一对一 connection**，但它建立在一种**可以拥有多个发送者的 technology**之上，因此：

- Mach ports 是单接收者、**多发送者**。
- XPC connection 的 audit token 是**从最近接收到的 message 中复制的 audit token**。
- 获取 XPC connection 的 **audit token** 对许多**安全检查**至关重要。<sup>[1]</sup>

虽然上述情况听起来很有希望，但在某些场景下不会造成问题（[来源](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：

- Audit tokens 通常用于 authorization check，以决定是否接受 connection。由于该操作通过向 service port 发送 message 完成，**此时 connection 尚未建立**。该 port 上的更多 messages 只会被作为额外的 connection requests 处理。因此，**接受 connection 之前的 checks 不存在漏洞**（这也意味着在 `-listener:shouldAcceptNewConnection:` 中 audit token 是安全的）。所以我们要寻找的是会验证特定 actions 的 XPC connections。
- XPC event handlers 是同步处理的。这意味着，即使使用 concurrent dispatch queues，一个 message 的 event handler 也必须完成后，才能处理下一个 message。因此，在 **XPC event handler 内部，audit token 不会被其他普通的（非 reply！）messages 覆盖**。<sup>[1]</sup>

此问题可能有两种不同的可利用方式：

1. Variant1:
- **Exploit** **connects** 到 service **A** 和 service **B**
- Service **B** 可以在 service A 中调用用户无法调用的 **privileged functionality**
- Service **A** 在**不位于**某个 connection 的 **`dispatch_async`** **event handler** 内部时调用 **`xpc_connection_get_audit_token`**。
- 因此，**不同的** message 可能会**覆盖 Audit Token**，因为该调用是在 event handler 外部异步 dispatch 的。
- Exploit 将指向 service A 的 **SEND right** 传递给 **service B**。
- 因此，svc **B** 实际上会向 service **A** **发送** **messages**。
- **Exploit** 尝试调用 **privileged action**。在 RC 中，svc **A** 会在 **svc B 覆盖 Audit token** 时检查该 **action** 的 authorization（从而让 exploit 获得调用 privileged action 的权限）。
2. Variant 2:
- Service **B** 可以在 service A 中调用用户无法调用的 **privileged functionality**
- Exploit 与 **service A** 建立 connection，**service A** 向 exploit 发送一条**期待 response** 的 message，该 message 使用特定的 **replay** **port**。
- Exploit 向 **service** B 发送一条 message，并传递**该 reply port**。
- 当 service **B** 回复时，它会向 service A **发送该 message**；与此同时，**exploit** 向 service A 发送另一条 message，尝试**访问 privileged functionality**，并希望 service B 的 reply 能在恰当时刻覆盖 Audit token（Race Condition）。

## Variant 1：在 event handler 外部调用 xpc_connection_get_audit_token <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

- 两个 mach services **`A`** 和 **`B`**，我们都可以与它们建立 connection（取决于 sandbox profile 以及接受 connection 前的 authorization checks）。
- _**A**_ 必须针对某个特定 action 执行 **authorization check**，且 **`B`** 可以通过该 check（但我们的 app 无法通过）。
- 例如，如果 B 具有某些 **entitlements** 或以 **root** 身份运行，它可能允许自己请求 A 执行 privileged action。
- 对于此 authorization check，**A** 会异步获取 audit token，例如通过从 `dispatch_async` 调用 `xpc_connection_get_audit_token`。

> [!CAUTION]
> 在这种情况下，攻击者可以触发 **Race Condition**：创建一个 **exploit**，多次请求 A 执行某个 action，同时让 **B** 向 `A` 发送 messages。当 RC **成功**时，**B** 的 **audit token** 会被复制到内存中，而我们的 **exploit** request 正在由 A 处理，从而让 exploit 获得仅 B 才能请求的 privileged action 的访问权限。

该问题出现在 `A` 为 `smd`、`B` 为 `diagnosticd` 的场景中。可以使用 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) 函数安装新的 privileged helper tool（以 **root** 身份运行）。如果一个**以 root 身份运行的 process contact** **smd**，则不会执行其他 checks。

因此，service **B** 是 **`diagnosticd`**，因为它以 **root** 身份运行，并且可以用于**监控** process；监控开始后，它会**每秒发送多条 messages**。

执行 attack 的步骤如下：

1. 使用标准 XPC protocol 向名为 `smd` 的 service 发起 **connection**。
2. 向 `diagnosticd` 建立 secondary **connection**。与正常流程不同，client port send right 不创建并发送两个新的 mach ports，而是替换为与 `smd` connection 关联的 **send right** 的 duplicate。
3. 因此，XPC messages 可以被 dispatch 到 `diagnosticd`，但来自 `diagnosticd` 的 responses 会被重新路由到 `smd`。对于 `smd` 而言，来自 user 和 `diagnosticd` 的 messages 看起来都源自同一个 connection。

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 下一步是指示 `diagnosticd` 开始监控指定的 process（可能是 user 自己的 process）。与此同时，向 `smd` 发送大量常规的 1004 messages。目标是安装一个具有 elevated privileges 的 tool。
5. 此 action 会在 `handle_bless` function 内触发 race condition。时机非常关键：`xpc_connection_get_pid` function call 必须返回 user process 的 PID（因为 privileged tool 位于 user 的 app bundle 中）。但是，`xpc_connection_get_audit_token` function，特别是 `connection_is_authorized` subroutine 中的该 function，必须引用属于 `diagnosticd` 的 audit token。<sup>[1]</sup>

## Variant 2：reply forwarding

在 XPC（Cross-Process Communication）environment 中，虽然 event handlers 不会并发执行，但 reply messages 的处理具有独特行为。具体而言，发送期待 reply 的 messages 有两种不同的方法：

1. **`xpc_connection_send_message_with_reply`**：在此方法中，XPC message 会在指定的 queue 上接收和处理。
2. **`xpc_connection_send_message_with_reply_sync`**：相反，在此方法中，XPC message 会在当前 dispatch queue 上接收和处理。

这一差异非常关键，因为它可能导致 reply packets 与 XPC event handler 的执行并发进行。值得注意的是，虽然 `_xpc_connection_set_creds` 确实实现了 locking 来防止 audit token 被部分覆盖，但这种保护并未扩展到整个 connection object。因此，这会产生一个 vulnerability：在 packet 被解析后、其 event handler 执行前的时间窗口内，audit token 可能被替换。

要利用此 vulnerability，需要满足以下 setup：

- 两个 mach services，分别称为 **`A`** 和 **`B`**，二者都可以建立 connection。
- Service **`A`** 应包含一个针对特定 action 的 authorization check，且只有 **`B`** 能执行该 action（user 的 application 无法执行）。
- Service **`A`** 应发送一条期待 reply 的 message。
- User 可以向 **`B`** 发送一条 B 会响应的 message。

利用过程包括以下步骤：

1. 等待 service **`A`** 发送一条期待 reply 的 message。
2. 不直接向 **`A`** 回复，而是劫持 reply port，并使用它向 service **`B`** 发送 message。
3. 随后 dispatch 一条涉及 forbidden action 的 message，并希望该 message 与来自 **`B`** 的 reply 并发处理。<sup>[1]</sup>

下面是上述 attack scenario 的可视化表示：

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 发现问题

- **定位实例的困难**：无论静态还是动态地搜索 `xpc_connection_get_audit_token` 的使用实例都很困难。
- **Methodology**：使用 Frida hook `xpc_connection_get_audit_token` function，并过滤出不是从 event handlers 发起的 calls。但该方法仅适用于被 hook 的 process，并且要求目标处于 active usage 状态。
- **Analysis Tooling**：使用 IDA/Ghidra 检查可访问的 mach services，但该过程耗时较长；涉及 dyld shared cache 的 calls 进一步增加了复杂性。
- **Scripting Limitations**：尝试对来自 `dispatch_async` blocks 的 `xpc_connection_get_audit_token` calls 进行 scripting 时，受到 block 解析以及与 dyld shared cache 交互的复杂性限制。<sup>[1]</sup>

## 修复 <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**：向 Apple 提交 report，详细说明在 `smd` 中发现的 general 和 specific issues。
- **Apple's Response**：Apple 在 `smd` 中将 `xpc_connection_get_audit_token` 替换为 `xpc_dictionary_get_audit_token`，从而修复了该问题。<sup>[1][2]</sup>
- **Nature of the Fix**：`xpc_dictionary_get_audit_token` function 被认为是 secure 的，因为它直接从与接收到的 XPC message 关联的 mach message 中获取 audit token。不过，它与 `xpc_connection_get_audit_token` 一样，并不属于 public API。
- **Absence of a Broader Fix**：目前不清楚 Apple 为什么没有实现更 comprehensive 的 fix，例如丢弃与 connection 已保存的 audit token 不匹配的 messages。某些场景下 audit token 可能合法发生变化（例如使用 `setuid`），这可能是原因之一。
- **Current Status**：该问题在 iOS 17 和 macOS 14 中仍然存在，这给尝试识别和理解该问题的人带来了挑战。<sup>[1]</sup>

## Finding vulnerable code paths in practice (2024–2025)

审计 XPC services 是否存在此类 bug 时，应重点关注在 message 的 event handler 外部执行的 authorization，或与 reply processing 并发执行的 authorization。

Static triage hints:
- 搜索从通过 `dispatch_async`/`dispatch_after` 或其他在 message handler 外部运行的 worker queues 排队的 blocks 中可到达的 `xpc_connection_get_audit_token` calls。
- 查找混合使用 per-connection 和 per-message state 的 authorization helpers（例如从 `xpc_connection_get_pid` 获取 PID，却从 `xpc_connection_get_audit_token` 获取 audit token）。
- 在 NSXPC code 中，确认 checks 是否在 `-listener:shouldAcceptNewConnection:` 中执行；对于 per-message checks，确认 implementation 使用的是 per-message audit token（例如在 lower-level code 中通过 message 的 dictionary 使用 `xpc_dictionary_get_audit_token`）。

Dynamic triage tips:
- Hook `xpc_connection_get_audit_token`，并标记其 user stack 不包含 event-delivery path（例如 `_xpc_connection_mach_event`）的 invocations。Example Frida hook:
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
- 在 macOS 上，对受保护的/Apple binaries 进行 instrumenting 可能需要禁用 SIP 或使用 development environment；优先测试你自己的 builds 或 userland services。
- 对于 reply-forwarding races（Variant 2），通过 fuzzing `xpc_connection_send_message_with_reply` 与普通 requests 的时序，监控 reply packets 的并发解析，并检查授权期间使用的 effective audit token 是否可被影响。

## 你可能需要的 Exploitation primitives

- Multi-sender setup（Variant 1）：创建到 A 和 B 的 connections；duplicate A 的 client port 的 send right，并将其用作 B 的 client port，使 B 的 replies 被 delivered 到 A。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2)：从 A 的 pending request（reply port）中捕获 send-once right，然后使用该 reply port 向 B 发送 crafted message，使 B 的 reply 在你的 privileged request 被解析期间抵达 A。

这些操作需要为 XPC bootstrap 和 message formats 构造底层 mach message；请查看本节中的 mach/XPC primer 页面，以了解确切的 packet layouts 和 flags。

## Useful tooling

- XPC sniffing/dynamic inspection：gxpc（open-source XPC sniffer）可以帮助枚举 connections 并观察 traffic，从而验证 multi-sender setups 和 timing。示例：`gxpc -p <PID> --whitelist <service-name>`。
- 针对 libxpc 的经典 dyld interposing：对 `xpc_connection_send_message*` 和 `xpc_connection_get_audit_token` 进行 interpose，以便在 black-box testing 期间记录 call sites 和 stacks。



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
