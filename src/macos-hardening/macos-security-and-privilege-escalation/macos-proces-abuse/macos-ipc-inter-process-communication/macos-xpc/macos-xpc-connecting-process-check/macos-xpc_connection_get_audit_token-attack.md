# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**추가 정보는 원문을 확인하세요:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). 다음은 요약입니다:<sup>[[1]](#references)</sup>

## Mach Messages Basic Info

Mach Messages가 무엇인지 모른다면 다음 페이지부터 확인하세요:


{{#ref}}
../../
{{#endref}}

일단 다음 내용을 기억하세요 ([여기서 가져온 정의](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages는 _mach port_를 통해 전송됩니다. mach port는 mach kernel에 내장된 **단일 수신자, 다중 송신자 통신** 채널입니다. **여러 프로세스가 mach port로 messages를 전송**할 수 있지만, 어느 시점에서든 **단 하나의 프로세스만 이를 읽을 수 있습니다**. file descriptors 및 sockets와 마찬가지로 mach ports는 kernel이 할당하고 관리하며, 프로세스에는 정수만 노출됩니다. 프로세스는 이 정수를 사용해 사용할 mach port를 kernel에 지정할 수 있습니다.

## XPC Connection

XPC connection이 어떻게 설정되는지 모른다면 다음을 확인하세요:


{{#ref}}
../
{{#endref}}

## Vuln Summary

알아야 할 중요한 점은 **XPC의 abstraction이 일대일 connection**이라는 것입니다. 하지만 이는 **여러 송신자를 가질 수 있는** 기술 위에 구축되어 있으므로 다음과 같습니다.

- Mach ports는 단일 수신자, **다중 송신자**입니다.
- XPC connection의 audit token은 **가장 최근에 수신된 message에서 복사된 audit token**입니다.
- XPC connection의 **audit token**을 획득하는 것은 많은 **security checks**에서 핵심적입니다.<sup>[[1]](#references)</sup>

앞선 상황은 유망해 보이지만, 이로 인해 문제가 발생하지 않는 시나리오도 있습니다 ([여기서 가져옴](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit tokens는 connection을 허용할지 결정하기 위한 authorization check에 자주 사용됩니다. 이 과정은 service port로 보내는 message를 통해 수행되므로, 아직 **connection이 established되지 않았습니다**. 이 port로 들어오는 추가 messages는 단순히 추가 connection requests로 처리됩니다. 따라서 **connection을 허용하기 전의 checks는 vulnerable하지 않습니다**(이는 `-listener:shouldAcceptNewConnection:` 내부에서는 audit token이 안전하다는 의미이기도 합니다). 따라서 우리는 특정 actions를 검증하는 XPC connections를 **찾아야 합니다**.
- XPC event handlers는 synchronous하게 처리됩니다. 즉, concurrent dispatch queues에서도 한 message의 event handler가 완료된 후에야 다음 message의 event handler가 호출됩니다. 따라서 **XPC event handler 내부에서는 다른 일반적인(non-reply!) messages에 의해 audit token이 overwrite될 수 없습니다**.<sup>[[1]](#references)</sup>

이를 exploit할 수 있는 두 가지 방법은 다음과 같습니다.

1. Variant1:
- **Exploit**이 service **A**와 service **B**에 **connect**합니다.
- Service **B**는 사용자가 호출할 수 없는 **privileged functionality**를 service A에서 호출할 수 있습니다.
- Service **A**는 **`dispatch_async`**에서 connection의 **event handler** 내부에 있지 않을 때 **`xpc_connection_get_audit_token`**을 호출합니다.
- 따라서 다른 message가 **Audit Token을 overwrite**할 수 있습니다. 이는 event handler 외부에서 asynchronous하게 dispatch되기 때문입니다.
- Exploit은 **service B에 service A의 SEND right를 전달**합니다.
- 그러면 svc **B**가 실제로 service **A**에 **messages를 전송**하게 됩니다.
- **Exploit**은 **privileged action을 호출**하려고 합니다. RC 상황에서 svc **A**는 **svc B가 Audit token을 overwrite한 상태에서** 해당 **action의 authorization을 check**하므로, exploit이 privileged action을 호출할 수 있게 됩니다.
2. Variant 2:
- Service **B**는 사용자가 호출할 수 없는 **privileged functionality**를 service A에서 호출할 수 있습니다.
- Exploit은 **service A**에 연결하고, service A는 특정 **replay** **port**에서 response를 기대하는 message를 exploit에 전송합니다.
- Exploit은 해당 reply port를 전달하는 message를 **service B**에 보냅니다.
- Service **B**가 reply하면 service **A**로 message를 **전송**하는 동안, **exploit**은 privileged functionality에 도달하려고 다른 **message를 service A에 전송**합니다. 이때 service B의 reply가 정확한 순간에 Audit token을 overwrite하기를 기대합니다(Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

시나리오:

- 우리가 모두 connect할 수 있는 두 개의 mach services **`A`**와 **`B`**가 있습니다(sandbox profile 및 connection을 허용하기 전의 authorization checks를 기준으로 함).
- _**A**_에는 **특정 action에 대한 authorization check**가 있어야 하며, 이 check는 **`B`**는 통과할 수 있지만 우리 app은 통과할 수 없어야 합니다.
- 예를 들어 B에 일부 **entitlements**가 있거나 **root**로 실행 중이라면, A에 privileged action을 수행하도록 요청하는 것을 허용할 수 있습니다.
- 이 authorization check를 위해 **`A`**는 audit token을 asynchronous하게 획득합니다. 예를 들어 `dispatch_async`에서 `xpc_connection_get_audit_token`을 호출합니다.

> [!CAUTION]
> 이 경우 attacker는 **Race Condition**을 유발할 수 있습니다. 즉, **exploit**이 A에 action 수행을 여러 번 요청하는 동시에 **B가 `A`에 messages를 전송**하도록 만들 수 있습니다. RC가 **성공하면**, **B**의 **audit token**이 메모리에 복사되는 시점이 **exploit의 request가 A에서 처리되는 동안** 발생하므로, B만 요청할 수 있는 privileged action에 **access**할 수 있게 됩니다.

이 문제는 **`A`**가 `smd`이고 **`B`**가 `diagnosticd`인 경우에 발생했습니다. `smb`의 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function을 사용하면 새로운 privileged helper toot을 ( **root**로) 설치할 수 있습니다. **root로 실행 중인 process가** **smd에 contact**하면 다른 checks는 수행되지 않습니다.

따라서 service **B**는 **`diagnosticd`**입니다. 이 service는 **root**로 실행되며 process를 **monitor**하는 데 사용할 수 있으므로, monitoring이 시작되면 **초당 여러 개의 messages를 전송**합니다.

Attack을 수행하려면 다음 단계를 따릅니다.

1. 표준 XPC protocol을 사용해 `smd`라는 이름의 service에 **connection**을 시작합니다.
2. `diagnosticd`에 대한 secondary **connection**을 생성합니다. 일반적인 절차와 달리 두 개의 새로운 mach ports를 생성하고 전송하는 대신, client port send right를 `smd` connection에 연결된 **send right**의 duplicate로 대체합니다.
3. 그 결과 XPC messages는 `diagnosticd`로 dispatch될 수 있지만, `diagnosticd`의 responses는 `smd`로 reroute됩니다. `smd`에서는 user와 `diagnosticd` 양쪽의 messages가 동일한 connection에서 originate된 것처럼 보입니다.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 다음 단계는 `diagnosticd`에 선택한 process(잠재적으로 user 자신의 process)를 monitoring하도록 지시하는 것입니다. 동시에 routine 1004 messages를 `smd`에 flood합니다. 목적은 elevated privileges를 가진 tool을 설치하는 것입니다.
5. 이 action은 `handle_bless` function 내부에서 race condition을 trigger합니다. Timing이 중요합니다. `xpc_connection_get_pid` function call은 user process의 PID를 반환해야 합니다(privileged tool이 user의 app bundle에 있기 때문). 그러나 `connection_is_authorized` subroutine 내부의 `xpc_connection_get_audit_token` function은 `diagnosticd`에 속한 audit token을 참조해야 합니다.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

XPC(Cross-Process Communication) 환경에서는 event handlers가 concurrent하게 실행되지 않지만, reply messages 처리에는 고유한 동작이 있습니다. 구체적으로 reply를 기대하는 messages를 전송하는 두 가지 방법이 있습니다.

1. **`xpc_connection_send_message_with_reply`**: 이 경우 XPC message는 지정된 queue에서 수신되고 처리됩니다.
2. **`xpc_connection_send_message_with_reply_sync`**: 반대로 이 method에서는 XPC message가 현재 dispatch queue에서 수신되고 처리됩니다.

이 차이는 **reply packets가 XPC event handler 실행과 concurrent하게 parse될 수 있는** 가능성을 만들기 때문에 중요합니다. `_xpc_connection_set_creds`는 audit token의 partial overwrite를 방지하기 위한 locking을 구현하지만, 이 보호는 전체 connection object까지 확장되지 않습니다. 따라서 packet을 parsing한 시점과 event handler를 실행하는 시점 사이에 audit token이 대체될 수 있는 vulnerability가 발생합니다.

이 vulnerability를 exploit하려면 다음과 같은 setup이 필요합니다.

- 둘 다 connection을 establish할 수 있는 두 개의 mach services, 즉 **`A`**와 **`B`**가 필요합니다.
- Service **`A`**에는 **`B`**만 수행할 수 있는 특정 action에 대한 authorization check가 있어야 합니다(user application은 수행할 수 없음).
- Service **`A`**는 reply를 예상하는 message를 전송해야 합니다.
- User는 **`B`**에 message를 보낼 수 있어야 하며, B는 이에 respond해야 합니다.

Exploitation process는 다음 단계로 진행됩니다.

1. Service **`A`**가 reply를 기대하는 message를 전송할 때까지 기다립니다.
2. `A`에 직접 reply하는 대신 reply port를 hijack하고 이를 사용해 service **`B`**에 message를 전송합니다.
3. 그런 다음 forbidden action과 관련된 message를 dispatch하고, 이 message가 **`B`**의 reply와 concurrent하게 처리되기를 기대합니다.<sup>[[1]](#references)</sup>

다음은 설명한 attack scenario를 시각적으로 나타낸 것입니다.

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instances를 찾는 데 따르는 어려움**: `xpc_connection_get_audit_token` 사용 instances를 static 및 dynamic 방식 모두로 검색하기 어려웠습니다.
- **Methodology**: Frida를 사용해 `xpc_connection_get_audit_token` function을 hook하고, event handlers에서 originate되지 않은 calls를 filter했습니다. 그러나 이 방법은 hooked process로 제한되며 active usage가 필요했습니다.
- **Analysis Tooling**: IDA/Ghidra와 같은 tools를 사용해 reachable mach services를 검사했지만, dyld shared cache와 관련된 calls 때문에 process가 time-consuming하고 복잡했습니다.
- **Scripting Limitations**: `dispatch_async` blocks에서 `xpc_connection_get_audit_token`으로 향하는 calls를 script로 분석하려는 시도는 blocks parsing 및 dyld shared cache와의 interaction이 복잡해 방해를 받았습니다.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: `smd` 내부에서 발견된 일반 및 구체적인 issues를 설명하는 report를 Apple에 제출했습니다.
- **Apple's Response**: Apple은 `xpc_connection_get_audit_token`을 `xpc_dictionary_get_audit_token`으로 대체하여 `smd`의 issue를 해결했습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function은 수신된 XPC message에 연결된 mach message에서 직접 audit token을 가져오므로 secure한 것으로 간주됩니다. 그러나 `xpc_connection_get_audit_token`과 마찬가지로 public API의 일부가 아닙니다.
- **Absence of a Broader Fix**: connection에 저장된 audit token과 일치하지 않는 messages를 폐기하는 방식과 같은 더 comprehensive한 fix를 Apple이 구현하지 않은 이유는 여전히 명확하지 않습니다. 특정 시나리오(예: `setuid` 사용)에서 legitimate한 audit token changes가 발생할 수 있다는 점이 요인일 수 있습니다.
- **Current Status**: 이 issue는 iOS 17 및 macOS 14에서도 여전히 존재하므로, 이를 식별하고 이해하려는 사람들에게 challenge가 되고 있습니다.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

이 bug class에 대해 XPC services를 auditing할 때는 message의 event handler 외부에서 수행되는 authorization 또는 reply processing과 concurrent하게 수행되는 authorization에 집중하세요.

Static triage hints:
- `dispatch_async`/`dispatch_after` 또는 message handler 외부에서 실행되는 기타 worker queues를 통해 queue된 blocks에서 도달 가능한 `xpc_connection_get_audit_token` calls를 검색하세요.
- per-connection state와 per-message state를 혼합하는 authorization helpers를 찾으세요(예: `xpc_connection_get_pid`에서 PID를 가져오면서 `xpc_connection_get_audit_token`에서 audit token을 가져오는 경우).
- NSXPC code에서는 checks가 `-listener:shouldAcceptNewConnection:`에서 수행되는지 확인하세요. per-message checks의 경우 implementation이 per-message audit token을 사용하는지 확인하세요(예: lower-level code에서 message의 dictionary를 통한 `xpc_dictionary_get_audit_token` 사용).

Dynamic triage tips:
- `xpc_connection_get_audit_token`을 hook하고, user stack에 event-delivery path(예: `_xpc_connection_mach_event`)가 포함되지 않은 invocations를 flag하세요. Example Frida hook:
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
- macOS에서 보호된/Apple binary를 instrumenting하려면 SIP가 비활성화되어 있거나 development environment가 필요할 수 있습니다. 자체적으로 빌드한 binary 또는 userland service를 대상으로 테스트하는 것을 우선하세요.
- reply-forwarding race(Variant 2)의 경우, `xpc_connection_send_message_with_reply`와 일반 요청 간의 timing을 fuzzing하여 reply packet의 동시 parsing을 모니터링하고, authorization에 사용되는 effective audit token이 영향을 받을 수 있는지 확인하세요.

## Exploitation primitives you will likely need

- Multi-sender setup(Variant 1): A와 B에 대한 connection을 생성하고, A의 client port에 대한 send right를 duplicate한 다음 이를 B의 client port로 사용하여 B의 reply가 A에 전달되도록 합니다.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A의 pending request(reply port)에서 send-once right를 캡처한 다음, 해당 reply port를 사용해 B에 crafted message를 전송합니다. 그러면 privileged request가 parsing되는 동안 B의 reply가 A에 도착합니다.

이 공격에는 XPC bootstrap 및 message format을 위한 low-level mach message crafting이 필요합니다. 정확한 packet layout과 flag는 이 섹션의 mach/XPC primer 페이지를 확인하세요.

## 유용한 tooling

- XPC sniffing/dynamic inspection: gxpc(open-source XPC sniffer)를 사용하면 connection을 열거하고 traffic을 관찰하여 multi-sender setup과 timing을 검증할 수 있습니다. 예: `gxpc -p <PID> --whitelist <service-name>`.
- libxpc를 위한 Classic dyld interposing: `xpc_connection_send_message*` 및 `xpc_connection_get_audit_token`에 interpose하여 black-box testing 중 call site와 stack을 기록할 수 있습니다.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
