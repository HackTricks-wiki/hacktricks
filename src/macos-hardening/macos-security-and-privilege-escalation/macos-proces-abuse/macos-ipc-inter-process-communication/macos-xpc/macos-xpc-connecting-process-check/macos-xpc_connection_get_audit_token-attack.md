# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**추가 정보는 original post를 확인하세요:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). 다음은 요약입니다:

## Mach Messages Basic Info

Mach Messages가 무엇인지 모른다면 다음 페이지부터 확인하세요:


{{#ref}}
../../
{{#endref}}

일단 다음 내용을 기억하세요 ([이곳의 definition](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages는 _mach port_를 통해 전송됩니다. _mach port_는 mach kernel에 내장된 **single receiver, multiple sender communication** channel입니다. **여러 process가 mach port로 messages를 보낼 수 있지만**, 어느 시점에서든 **단 하나의 process만 이를 읽을 수 있습니다**. file descriptors 및 sockets와 마찬가지로 mach ports는 kernel이 할당하고 관리하며, process는 integer만 볼 수 있습니다. 이 integer를 사용해 자신이 사용하려는 mach port를 kernel에 지정할 수 있습니다.

## XPC Connection

XPC connection이 어떻게 설정되는지 모른다면 다음을 확인하세요:


{{#ref}}
../
{{#endref}}

## Vuln Summary

알아두어야 할 중요한 점은 **XPC의 abstraction은 one-to-one connection**이지만, **multiple senders를 가질 수 있는 technology를 기반으로 한다는 것**입니다. 따라서:

- Mach ports는 single receiver, **multiple sender**입니다.
- XPC connection의 audit token은 **가장 최근에 수신된 message에서 복사된 audit token**입니다.
- XPC connection의 **audit token**을 얻는 것은 여러 **security checks**에서 중요합니다.<sup>[[1]](#references)</sup>

앞선 상황은 유망해 보이지만, 이로 인해 문제가 발생하지 않는 몇 가지 scenario가 있습니다 ([이곳에서 가져옴](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens는 connection을 허용할지 결정하기 위한 authorization check에 자주 사용됩니다. 이는 service port로 message를 보내는 과정에서 수행되므로 **아직 connection이 established되지 않았습니다**. 이 port로 들어오는 추가 messages는 단순히 추가 connection requests로 처리됩니다. 따라서 **connection을 accept하기 전의 checks는 vulnerable하지 않습니다** (`-listener:shouldAcceptNewConnection:` 내부에서는 audit token이 safe하다는 의미이기도 합니다). 따라서 **specific actions를 verify하는 XPC connections**를 찾아야 합니다.
- XPC event handlers는 synchronously 처리됩니다. 즉, concurrent dispatch queues에서도 하나의 message에 대한 event handler가 완료된 후에야 다음 message에 대한 handler가 호출됩니다. 따라서 **XPC event handler 내부에서는 다른 일반적인 (non-reply!) messages에 의해 audit token이 overwritten될 수 없습니다**.<sup>[[1]](#references)</sup>

이를 exploit할 수 있는 두 가지 서로 다른 methods가 있습니다:

1. Variant1:
- **Exploit**이 service **A**와 service **B**에 **connect**합니다.
- Service **B**는 사용자가 호출할 수 없는 **privileged functionality**를 service A에서 호출할 수 있습니다.
- Service **A**는 **`dispatch_async`** 내부의 connection에 대한 **event handler** 외부에서 **`xpc_connection_get_audit_token`**을 호출합니다.
- 따라서 다른 message가 **Audit Token을 overwrite**할 수 있습니다. 해당 message가 event handler 외부에서 asynchronously dispatched되기 때문입니다.
- **Exploit**은 service **B**에 service **A**로 향하는 **SEND right**를 전달합니다.
- 그러면 svc **B**가 실제로 **messages를 service A로 전송**하게 됩니다.
- **Exploit**은 **privileged action**을 호출하려고 시도합니다. RC에서 svc **A**는 **svc B가 Audit token을 overwrite한 상태에서** 이 **action의 authorization을 check**하므로, exploit이 privileged action을 호출할 수 있게 됩니다.
2. Variant 2:
- Service **B**는 사용자가 호출할 수 없는 **privileged functionality**를 service A에서 호출할 수 있습니다.
- Exploit은 **service A**에 connect하고, service A는 특정 **reply** **port**에서 response를 기대하는 **message**를 exploit에 보냅니다.
- Exploit은 **해당 reply port**를 전달하는 message를 **service B**로 보냅니다.
- Service **B**가 reply할 때 **service A로 message를 전송**하는 동시에, **exploit**은 privileged functionality에 도달하려고 다른 **message를 service A로 전송**합니다. 이때 service B의 reply가 적절한 순간에 Audit token을 overwrite하기를 기대합니다 (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- 우리가 모두 connect할 수 있는 두 개의 mach services **`A`**와 **`B`**가 있습니다 (sandbox profile 및 connection을 accept하기 전의 authorization checks를 기준으로 함).
- _**A**_에는 **specific action**에 대한 **authorization check**가 있어야 하며, 이 check는 **`B`**는 통과할 수 있지만 우리 app은 통과할 수 없어야 합니다.
- 예를 들어 B에 일부 **entitlements**가 있거나 root로 실행 중이라면, A에 privileged action을 수행하도록 요청할 수 있습니다.
- 이 authorization check를 위해 **`A`**는 audit token을 asynchronously 가져옵니다. 예를 들어 `dispatch_async`에서 `xpc_connection_get_audit_token`을 호출합니다.

> [!CAUTION]
> 이 경우 attacker는 **Race Condition**을 trigger할 수 있습니다. 이를 위해 **exploit**이 A에 action 수행을 여러 번 요청하는 동시에 **B가 `A`로 messages를 보내도록** 합니다. RC가 **successful**하면 **B**의 **audit token**이 memory에 복사되는 순간 **우리 exploit의 request가 A에서 처리 중**이므로, B만 요청할 수 있는 privileged action에 **access**할 수 있게 됩니다.

이는 **`A`**가 `smd`이고 **`B`**가 `diagnosticd`인 경우에 발생했습니다. smb의 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function을 사용하면 새로운 privileged helper toot을 ( **root**로) 설치할 수 있습니다. **root로 실행 중인 process가** **smd에 contact**하면 다른 checks는 수행되지 않습니다.

따라서 service **B**는 **`diagnosticd`**입니다. 이 process는 **root**로 실행되고 process를 **monitor**하는 데 사용할 수 있으므로, monitoring이 시작되면 **초당 여러 messages를 전송합니다.**

Attack을 수행하려면:

1. Standard XPC protocol을 사용해 `smd`라는 이름의 service에 **connection**을 initiate합니다.
2. `diagnosticd`에 대한 secondary **connection**을 구성합니다. 일반적인 절차와 달리 두 개의 새로운 mach ports를 생성하고 전송하는 대신, client port send right를 `smd` connection과 연결된 **send right**의 duplicate로 대체합니다.
3. 그 결과 XPC messages는 `diagnosticd`로 dispatch될 수 있지만, `diagnosticd`의 responses는 `smd`로 reroute됩니다. `smd`의 관점에서는 user와 `diagnosticd`에서 온 messages가 모두 동일한 connection에서 originate한 것처럼 보입니다.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 다음 단계는 `diagnosticd`에 선택한 process (잠재적으로 user 자신의 process)에 대한 monitoring을 initiate하도록 지시하는 것입니다. 동시에 routine 1004 messages를 `smd`로 flood합니다. 목적은 elevated privileges를 가진 tool을 설치하는 것입니다.
5. 이 action은 `handle_bless` function 내부에서 race condition을 trigger합니다. Timing이 critical합니다. `xpc_connection_get_pid` function call은 user process의 PID를 return해야 합니다 (privileged tool이 user의 app bundle에 있기 때문입니다). 그러나 `connection_is_authorized` subroutine 내부의 `xpc_connection_get_audit_token` function은 `diagnosticd`에 속한 audit token을 reference해야 합니다.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

XPC (Cross-Process Communication) environment에서는 event handlers가 concurrently execute되지 않지만, reply messages 처리에는 unique behavior가 있습니다. 구체적으로 reply를 기대하는 messages를 전송하는 두 가지 서로 다른 methods가 있습니다:

1. **`xpc_connection_send_message_with_reply`**: 이 경우 XPC message는 지정된 queue에서 receive되고 processed됩니다.
2. **`xpc_connection_send_message_with_reply_sync`**: 반대로 이 method에서는 XPC message가 current dispatch queue에서 receive되고 processed됩니다.

이 차이는 **reply packets가 XPC event handler 실행과 concurrently parsing될 가능성**을 허용하므로 중요합니다. 특히 `_xpc_connection_set_creds`는 audit token의 partial overwrite를 보호하기 위한 locking을 구현하지만, 이 보호를 전체 connection object로 확장하지는 않습니다. 따라서 packet parsing과 event handler 실행 사이의 interval에 audit token이 replaced될 수 있는 vulnerability가 발생합니다.

이 vulnerability를 exploit하려면 다음 setup이 필요합니다:

- **`A`**와 **`B`**라고 부르는 두 개의 mach services. 두 service 모두 connection을 establish할 수 있어야 합니다.
- Service **`A`**에는 **`B`**만 수행할 수 있는 specific action에 대한 authorization check가 있어야 합니다 (user's application은 수행할 수 없어야 함).
- Service **`A`**는 reply를 예상하는 message를 보내야 합니다.
- User는 **`B`**에 message를 보낼 수 있어야 하며, B는 이에 respond해야 합니다.

Exploitation process는 다음 steps로 구성됩니다:

1. Service **`A`**가 reply를 기대하는 message를 보낼 때까지 기다립니다.
2. **`A`**에 직접 reply하는 대신 reply port를 hijack하여 service **`B`**로 message를 보내는 데 사용합니다.
3. 이후 forbidden action과 관련된 message를 dispatch하고, 이 message가 **`B`**의 reply와 concurrently processed되기를 기대합니다.<sup>[[1]](#references)</sup>

다음은 설명한 attack scenario의 visual representation입니다:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instances를 찾는 어려움**: `xpc_connection_get_audit_token` 사용 instances를 static 및 dynamic하게 search하기가 어려웠습니다.
- **Methodology**: Frida를 사용해 `xpc_connection_get_audit_token` function을 hook하고, event handlers에서 originate하지 않은 calls를 filter했습니다. 그러나 이 method는 hooked process로 제한되며 active usage가 필요했습니다.
- **Analysis Tooling**: IDA/Ghidra 같은 tools를 사용해 reachable mach services를 examine했지만, dyld shared cache와 관련된 calls 때문에 process가 time-consuming하고 복잡했습니다.
- **Scripting Limitations**: `dispatch_async` blocks에서 `xpc_connection_get_audit_token`으로 향하는 calls를 script로 분석하려는 attempts는 blocks parsing 및 dyld shared cache와의 interactions가 복잡해 어려움을 겪었습니다.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: `smd` 내부에서 발견된 general 및 specific issues를 Apple에 report했습니다.
- **Apple's Response**: Apple은 `xpc_connection_get_audit_token`을 `xpc_dictionary_get_audit_token`으로 substitute하여 `smd`의 issue를 해결했습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function은 received XPC message에 연결된 mach message에서 audit token을 직접 retrieve하므로 secure한 것으로 간주됩니다. 그러나 `xpc_connection_get_audit_token`과 마찬가지로 public API의 일부가 아닙니다.
- **Absence of a Broader Fix**: connection에 저장된 audit token과 일치하지 않는 messages를 discard하는 것과 같은 보다 comprehensive한 fix를 Apple이 구현하지 않은 이유는 여전히 unclear합니다. 특정 scenarios (예: `setuid` usage)에서 legitimate한 audit token changes가 가능하다는 점이 factor일 수 있습니다.
- **Current Status**: 이 issue는 iOS 17 및 macOS 14에서도 persist하며, 이를 identify하고 이해하려는 사람들에게 challenge가 되고 있습니다.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

이 bug class에 대해 XPC services를 audit할 때는 message의 event handler 외부에서 수행되는 authorization 또는 reply processing과 concurrently 수행되는 authorization에 집중하세요.

Static triage hints:
- `dispatch_async`/`dispatch_after` 또는 message handler 외부에서 실행되는 다른 worker queues를 통해 queued된 blocks에서 reachable한 `xpc_connection_get_audit_token` calls를 search합니다.
- per-connection 및 per-message state를 혼합하는 authorization helpers를 찾습니다 (예: `xpc_connection_get_pid`에서 PID를 가져오지만 audit token은 `xpc_connection_get_audit_token`에서 가져오는 경우).
- NSXPC code에서는 checks가 `-listener:shouldAcceptNewConnection:`에서 수행되는지 확인합니다. per-message checks의 경우 implementation이 per-message audit token을 사용하는지 확인합니다 (예: lower-level code에서 message의 dictionary를 통한 `xpc_dictionary_get_audit_token`).

Dynamic triage tips:
- `xpc_connection_get_audit_token`을 hook하고, user stack에 event-delivery path (예: `_xpc_connection_mach_event`)가 포함되지 않은 invocations를 flag합니다. Example Frida hook:
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
참고:
- macOS에서 보호된/Apple 바이너리를 instrumenting하려면 SIP를 비활성화하거나 development environment가 필요할 수 있습니다. 자체 빌드 또는 userland services에서 테스트하는 것을 우선하세요.
- reply-forwarding races(Variant 2)의 경우, `xpc_connection_send_message_with_reply`와 일반 요청의 타이밍을 fuzzing하여 reply packet의 동시 parsing을 모니터링하고, authorization에 사용되는 effective audit token이 영향을 받을 수 있는지 확인하세요.

## Exploitation primitives you will likely need

- Multi-sender setup(Variant 1): A와 B에 대한 connections를 생성하고, A의 client port에 대한 send right를 duplicate한 다음 B의 client port로 사용하여 B의 replies가 A로 전달되도록 합니다.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A의 pending request(reply port)에서 send-once right를 capture한 다음, 해당 reply port를 사용해 B에 crafted message를 전송합니다. 그러면 privileged request가 parsing되는 동안 B의 reply가 A에 도착합니다.

이를 위해서는 XPC bootstrap 및 message format을 low-level mach message로 crafting해야 합니다. 정확한 packet layout과 flag는 이 section의 mach/XPC primer 페이지를 검토하세요.

## 유용한 tooling

- XPC sniffing/dynamic inspection: gxpc(open-source XPC sniffer)를 사용하면 connection을 enumerate하고 traffic을 observe하여 multi-sender setup 및 timing을 검증할 수 있습니다. 예: `gxpc -p <PID> --whitelist <service-name>`.
- libxpc를 위한 Classic dyld interposing: `xpc_connection_send_message*` 및 `xpc_connection_get_audit_token`에 interpose하여 black-box testing 중 call site와 stack을 log할 수 있습니다.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
