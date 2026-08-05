# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**如需更多信息，请查看原始文章：** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。以下是摘要：

## Mach Messages 基础信息

如果你不了解 Mach Messages，请先查看此页面：


{{#ref}}
../../
{{#endref}}

目前请记住以下内容（[定义来源](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：\
Mach messages 通过 _mach port_ 发送。这是构建于 mach kernel 中的**单接收方、多发送方通信**通道。**多个进程可以向 mach port 发送 messages**，但在任何时刻**只有一个进程可以从中读取**。与 file descriptors 和 sockets 一样，mach ports 由 kernel 分配和管理，进程只能看到一个整数，并可使用该整数告知 kernel 要使用其哪个 mach port。

## XPC Connection

如果你不了解如何建立 XPC connection，请查看：


{{#ref}}
../
{{#endref}}

## Vuln Summary

需要了解的重点是，**XPC 的抽象是一对一 connection**，但它建立在一种**可以有多个发送方的技术之上，因此：**

- Mach ports 是单接收方、**多发送方**。
- XPC connection 的 audit token 是**从最近接收的 message 中复制的 audit token**。
- 获取 XPC connection 的 **audit token** 对许多**安全检查**至关重要。<sup>[[1]](#references)</sup>

尽管上述情况听起来很有希望，但在某些场景下不会造成问题（[来源](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：

- Audit tokens 通常用于 authorization check，以决定是否接受 connection。由于该过程通过向 service port 发送 message 完成，**此时还没有建立 connection**。该 port 上的更多 messages 只会作为额外的 connection requests 处理。因此，**接受 connection 之前的 checks 不会受到影响**（这也意味着在 `-listener:shouldAcceptNewConnection:` 中 audit token 是安全的）。因此，我们需要寻找**会验证特定 actions 的 XPC connections**。
- XPC event handlers 是同步处理的。这意味着，即使使用并发 dispatch queues，也必须先完成一个 message 的 event handler，才能处理下一个 message。因此，在 **XPC event handler 内部，audit token 不会被其他普通（非 reply！）messages 覆盖**。<sup>[[1]](#references)</sup>

这种情况可能有两种不同的可利用方式：

1. Variant1:
- **Exploit** **连接**到 service **A** 和 service **B**
- Service **B** 可以调用 service A 中用户无法调用的**特权功能**。
- Service **A** 在不处于某个 connection 的 **event handler** 中、且位于 **`dispatch_async`** 内部时调用 **`xpc_connection_get_audit_token`**。
- 因此，**不同的** message 可能会**覆盖 Audit Token**，因为该调用是在 event handler 外部异步 dispatch 的。
- Exploit 将 **service A 的 SEND right** 传递给 **service B**。
- 因此，svc **B** 实际上会向 service **A** **发送** messages。
- **Exploit** 尝试调用**特权 action**。在 RC 中，svc **A** 会在 **svc B 覆盖 Audit token** 时检查该 action 的 authorization，从而让 exploit 获得调用特权 action 的权限。
2. Variant 2:
- Service **B** 可以调用 service A 中用户无法调用的**特权功能**。
- Exploit 连接到 **service A**，后者向 exploit 发送一个 message，并期望在特定的 **replay** **port** 上获得响应。
- Exploit 向 service B 发送一个 message，并传递**该 reply port**。
- 当 service **B** 回复时，它会将 message **发送给 service A**；与此同时，**exploit** 向 service A 发送另一个 message，尝试访问**特权功能**，并期望 service B 的 reply 在恰当时机覆盖 Audit token（Race Condition）。

## Variant 1: 在 event handler 外调用 xpc_connection_get_audit_token <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

- 有两个我们都可以连接的 mach services **`A`** 和 **`B`**（取决于 sandbox profile 以及接受 connection 前的 authorization checks）。
- _**A**_ 必须针对某个特定 action 执行 **authorization check**，且 **`B`** 可以通过该 check（但我们的 app 无法通过）。
- 例如，如果 B 具有某些 **entitlements** 或以 **root** 身份运行，它可能允许自己请求 A 执行特权 action。
- 对于此 authorization check，**A** 异步获取 audit token，例如通过从 **`dispatch_async`** 中调用 `xpc_connection_get_audit_token`。

> [!CAUTION]
> 在这种情况下，攻击者可以触发 **Race Condition**，构造一个 **exploit**，多次请求 **A** 执行某个 action，同时让 **B** 向 **`A`** 发送 messages。当 RC **成功**时，**B** 的 **audit token** 会被复制到内存中，而此时 **exploit** 的 request 正由 A 处理，从而使其获得只有 B 才能请求的特权 action 的访问权限。

这一问题出现在 `A` 为 `smd`、`B` 为 `diagnosticd` 的情况下。可以使用 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) 函数安装一个新的特权 helper toot（以 **root** 身份）。如果一个**以 root 身份运行的进程联系** `smd`，则不会执行其他 checks。

因此，service **B** 是 **`diagnosticd`**，因为它以 **root** 身份运行，并且可用于**监控**进程；一旦监控开始，它就会**每秒发送多条 messages**。

执行 attack 的步骤如下：

1. 使用标准 XPC protocol，向名为 `smd` 的 service 发起 **connection**。
2. 与 `diagnosticd` 建立 secondary **connection**。不同于正常流程，client port send right 不创建并发送两个新的 mach ports，而是替换为与 `smd` connection 关联的 **send right** 的副本。
3. 因此，XPC messages 可以被 dispatch 到 `diagnosticd`，但来自 `diagnosticd` 的 responses 会被重新路由到 `smd`。对 `smd` 而言，看起来 user 和 `diagnosticd` 的 messages 都来自同一个 connection。

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 下一步是指示 `diagnosticd` 开始监控一个选定的进程（可能是 user 自己的进程）。与此同时，向 `smd` 发送大量常规的 1004 messages。目标是安装一个具有 elevated privileges 的 tool。
5. 此 action 会在 `handle_bless` 函数中触发 race condition。时机至关重要：`xpc_connection_get_pid` 函数调用必须返回 user 进程的 PID（因为特权 tool 位于 user 的 app bundle 中）。但是，`xpc_connection_get_audit_token` 函数，特别是在 `connection_is_authorized` subroutine 中，必须引用属于 `diagnosticd` 的 audit token。<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

在 XPC（Cross-Process Communication）环境中，虽然 event handlers 不会并发执行，但 reply messages 的处理具有独特行为。具体来说，发送期望 reply 的 messages 有两种不同的方法：

1. **`xpc_connection_send_message_with_reply`**：在此方法中，XPC message 会在指定的 queue 上接收和处理。
2. **`xpc_connection_send_message_with_reply_sync`**：相反，在此方法中，XPC message 会在当前 dispatch queue 上接收和处理。

这种区别非常重要，因为它使 **reply packets 可以与 XPC event handler 的执行并发解析**。值得注意的是，虽然 `_xpc_connection_set_creds` 实现了 locking 来防止 audit token 被部分覆盖，但该保护并未扩展到整个 connection object。因此会产生一个 vulnerability：在 packet 解析完成到其 event handler 执行之间的时间窗口内，audit token 可能被替换。

要利用此 vulnerability，需要满足以下设置：

- 两个 mach services，分别称为 **`A`** 和 **`B`**，且二者都可以建立 connection。
- Service **`A`** 应包含一个 authorization check，针对某个只有 **`B`** 能执行的特定 action（user 的 application 无法执行）。
- Service **`A`** 应发送一个预期获得 reply 的 message。
- User 可以向 **`B`** 发送一个 message，并且 B 会对其作出响应。

利用过程包括以下步骤：

1. 等待 service **`A`** 发送一个预期获得 reply 的 message。
2. 不直接回复 **`A`**，而是劫持 reply port，并使用它向 service **`B`** 发送 message。
3. 随后 dispatch 一个涉及被禁止 action 的 message，并期望该 message 与来自 **`B`** 的 reply 并发处理。<sup>[[1]](#references)</sup>

下面是所述 attack 场景的可视化表示：

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **定位实例的困难**：无论静态还是动态方式，搜索 `xpc_connection_get_audit_token` 的使用实例都很困难。
- **Methodology**：使用 Frida hook `xpc_connection_get_audit_token` 函数，并过滤来源不是 event handlers 的 calls。但是，这种方法仅限于被 hook 的 process，并且要求该函数处于实际使用状态。
- **Analysis Tooling**：使用 IDA/Ghidra 检查可达的 mach services，但这一过程耗时较长，而且涉及 dyld shared cache 的 calls 使其更加复杂。
- **Scripting Limitations**：尝试对来自 `dispatch_async` blocks 的 `xpc_connection_get_audit_token` calls 进行 scripting 时，由于解析 blocks 以及与 dyld shared cache 交互的复杂性而受到阻碍。<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**：向 Apple 提交了一份 report，详细说明在 `smd` 中发现的一般和具体问题。
- **Apple's Response**：Apple 在 `smd` 中通过将 `xpc_connection_get_audit_token` 替换为 `xpc_dictionary_get_audit_token` 解决了该问题。<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**：`xpc_dictionary_get_audit_token` 函数被认为是安全的，因为它直接从与接收到的 XPC message 关联的 mach message 中获取 audit token。但是，与 `xpc_connection_get_audit_token` 一样，它不属于 public API。
- **Absence of a Broader Fix**：目前尚不清楚 Apple 为什么没有实施更全面的 fix，例如丢弃与 connection 已保存 audit token 不匹配的 messages。某些场景中 audit token 可能合法发生变化（例如使用 `setuid`），这可能是其中一个因素。
- **Current Status**：该问题在 iOS 17 和 macOS 14 中仍然存在，这给试图识别和理解该问题的人带来了挑战。<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

审计 XPC services 是否存在此 bug class 时，应重点关注在 message 的 event handler 外部执行的 authorization，或与 reply processing 并发执行的 authorization。

Static triage hints：
- 搜索从通过 `dispatch_async`/`dispatch_after` 或其他在 message handler 外部运行的 worker queues 排队的 blocks 中可达的 `xpc_connection_get_audit_token` calls。
- 查找混合使用 per-connection 和 per-message state 的 authorization helpers（例如从 `xpc_connection_get_pid` 获取 PID，却从 `xpc_connection_get_audit_token` 获取 audit token）。
- 对于 NSXPC code，确认 checks 在 `-listener:shouldAcceptNewConnection:` 中执行；或者对于 per-message checks，确认实现使用 per-message audit token（例如在 lower-level code 中通过 message 的 dictionary 使用 `xpc_dictionary_get_audit_token`）。

Dynamic triage tips：
- Hook `xpc_connection_get_audit_token`，并标记其 user stack 不包含 event-delivery path（例如 `_xpc_connection_mach_event`）的 invocations。Frida hook 示例：
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
- 在 macOS 上，对受保护的/Apple binaries 进行 instrumenting 可能需要禁用 SIP 或使用 development environment；优先测试你自己的 builds 或 userland services。
- 对于 reply-forwarding races（Variant 2），通过 fuzzing `xpc_connection_send_message_with_reply` 与 normal requests 的 timing，监控 reply packets 的 concurrent parsing，并检查 authorization 使用的 effective audit token 是否可能受到影响。

## 你可能需要的 Exploitation primitives

- Multi-sender setup（Variant 1）：创建到 A 和 B 的 connections；duplicate A 的 client port 的 send right，并将其用作 B 的 client port，使 B 的 replies 被 delivered 到 A。
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2)：从 A 的待处理请求（reply port）中捕获 send-once right，然后使用该 reply port 向 B 发送 crafted message，使 B 的回复在你的 privileged request 正在被解析时传递到 A。

这些操作需要对 XPC bootstrap 和 message formats 进行低级 mach message crafting；请查看本节中的 mach/XPC primer 页面，了解确切的 packet layouts 和 flags。

## Useful tooling

- XPC sniffing/dynamic inspection：gxpc（open-source XPC sniffer）可帮助枚举 connections 并观察 traffic，以验证 multi-sender setups 和 timing。例如：`gxpc -p <PID> --whitelist <service-name>`。
- 针对 libxpc 的经典 dyld interposing：对 `xpc_connection_send_message*` 和 `xpc_connection_get_audit_token` 进行 interpose，在 black-box testing 期间记录 call sites 和 stacks。



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
