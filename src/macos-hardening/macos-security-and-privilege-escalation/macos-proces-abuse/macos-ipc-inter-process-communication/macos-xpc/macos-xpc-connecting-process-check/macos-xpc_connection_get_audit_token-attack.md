# macOS xpc_connection_get_audit_token 공격

{{#include ../../../../../../banners/hacktricks-training.md}}

**추가 정보는 원문 글을 확인하세요:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).  
요약:

## Mach Messages 기본 정보

If you don't know what Mach Messages are start checking this page:


{{#ref}}
../../
{{#endref}}

우선 기억할 점 ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):  
Mach messages는 _mach port_를 통해 전송되며, 이는 mach 커널에 내장된 **단일 수신자, 다중 송신자 통신** 채널입니다. **여러 프로세스가** mach 포트로 메시지를 보낼 수 있지만, 언제나 **하나의 프로세스만** 해당 포트에서 읽을 수 있습니다. 파일 디스크립터나 소켓과 마찬가지로, mach 포트는 커널이 할당하고 관리하며 프로세스는 정수 하나만 보게 되고 이를 통해 커널에게 어떤 mach 포트를 사용할지 지정합니다.

## XPC 연결

If you don't know how a XPC connection is established check:


{{#ref}}
../
{{#endref}}

## 취약점 요약

알아둘 중요한 점은 **XPC의 추상화는 일대일 연결(one-to-one connection)** 이지만, 그 기반이 되는 기술은 **다중 송신자를 가질 수 있다**는 것입니다. 그래서:

- Mach ports는 단일 수신자, **다중 송신자**입니다.
- XPC 연결의 audit token은 **가장 최근에 수신된 메시지에서 복사된** audit token입니다.
- XPC 연결의 **audit token**을 얻는 것은 많은 **보안 검사**에 중요합니다.

비록 위 상황이 문제를 일으킬 것처럼 보이지만, 몇몇 시나리오에서는 문제가 발생하지 않습니다 ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit token은 종종 연결을 수락할지 결정하는 권한 확인에 사용됩니다. 이 검사는 서비스 포트에 메시지를 사용해 수행되므로 **아직 연결이 수립되지 않은 상태**입니다. 이 포트로 들어오는 추가 메시지들은 단지 추가 연결 요청으로 처리됩니다. 따라서 연결 수락 전에 이루어지는 **검사들은 취약하지 않습니다** (`-listener:shouldAcceptNewConnection:` 내부의 경우 audit token은 안전합니다). 우리는 따라서 **특정 동작을 검증하는 XPC 연결**을 찾고 있습니다.
- XPC 이벤트 핸들러는 동기적으로 처리됩니다. 이는 한 메시지의 이벤트 핸들러가 완료되어야 다음 메시지에 대해 호출된다는 뜻이며, 동시성 dispatch 큐에서도 마찬가지입니다. 따라서 **XPC 이벤트 핸들러 내부에서는 audit token이 다른 정상(응답이 아닌) 메시지에 의해 덮어써질 수 없습니다.**

다음 두 가지 방법으로 악용 가능성이 있습니다:

1. Variant1:
- **Exploit**가 서비스 **A**와 서비스 **B**에 **연결**합니다.
- 서비스 **B**는 사용자가 할 수 없는 **권한 있는 기능**을 서비스 A에 요청할 수 있습니다.
- 서비스 **A**는 **이벤트 핸들러 내부가 아닌**, 예를 들어 **`dispatch_async`**에서 `xpc_connection_get_audit_token`을 호출합니다.
- 따라서 다른 메시지가 비동기적으로 디스패치되는 동안 **Audit Token이 덮어써질 수 있습니다**.
- 익스플로잇은 서비스 **A에 대한 SEND 권한**을 서비스 **B**에 전달합니다.
- 따라서 svc **B**가 실제로 서비스 **A**에 **메시지를 보낼 것**입니다.
- 익스플로잇은 권한이 필요한 동작을 호출하려 시도합니다. 서비스 **A**는 이 동작의 권한을 검사하는데, **svc B가 Audit token을 덮어썼다면**(익스플로잇이 B의 권한을 이용해) 익스플로잇이 권한 있는 동작을 실행할 수 있게 됩니다.
2. Variant 2:
- 서비스 **B**가 사용자가 할 수 없는 **권한 있는 기능**을 서비스 A에 요청할 수 있습니다.
- 익스플로잇은 **service A**에 연결하고, A는 특정 **reply 포트**에서 응답을 기대하는 메시지를 익스플로잇에게 보냅니다.
- 익스플로잇은 그 **reply port**를 포함한 메시지를 서비스 **B**에 전송합니다.
- 서비스 **B**가 응답을 보낼 때, 이 메시지는 **service A로 전송**되고, 동시에 익스플로잇은 서비스 **A**에 권한 있는 기능을 호출하는 다른 메시지를 보내어 응답이 정확한 순간에 Audit token을 덮어쓰도록 시도합니다(경쟁 상태).

## Variant 1: 이벤트 핸들러 외부에서 xpc_connection_get_audit_token 호출 <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

시나리오:

- 샌드박스 프로필 및 연결 수락 전의 권한 검사에 기반해 우리가 둘 다 연결할 수 있는 두 개의 mach 서비스 **`A`**와 **`B`**.
- _**A**_는 **`B`가 통과시킬 수 있는**, 그러나 우리의 앱은 통과시킬 수 없는 특정 동작에 대해 **권한 검사**를 해야 합니다.
- 예를 들어, B가 일부 **entitlements**을 갖고 있거나 **root**로 실행 중이라면 A에 권한 있는 동작을 요청할 수 있습니다.
- 이 권한 검사에서 **`A`**는 비동기적으로 audit token을 얻습니다(예: **`dispatch_async`**에서 `xpc_connection_get_audit_token`을 호출함).

> [!CAUTION]
> 이 경우 공격자는 **Race Condition**을 유발할 수 있으며, **익스플로잇**은 **A에 여러 번 동작 수행을 요청**하면서 동시에 **B가 `A`로 메시지를 보내도록** 유도할 수 있습니다. RC가 **성공하면**, 요청을 처리하는 동안 메모리에 **B의 audit token이 복사되어** 들어오게 되어, 익스플로잇은 **B만 요청할 수 있는 권한 있는 동작에 접근**할 수 있게 됩니다.

이 사례에서는 **`A`**가 `smd`, **`B`**가 `diagnosticd`였습니다. smb의 함수 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc)는 새로운 권한 상승 helper tool(루트로 실행)을 설치하는 데 사용될 수 있습니다. 만약 **root로 실행 중인 프로세스가** `smd`에 연락하면 다른 검사들이 수행되지 않을 수 있습니다.

따라서 서비스 **B**는 **root**로 실행되어 프로세스를 **모니터링**할 수 있는 `diagnosticd`이며, 모니터링이 시작되면 초당 여러 개의 메시지를 보낼 수 있습니다.

공격 수행 절차:

1. 표준 XPC 프로토콜을 사용해 `smd`라는 서비스에 **연결**을 시작합니다.
2. 두 번째로 `diagnosticd`에 **연결**을 형성합니다. 일반적인 절차와 달리, 클라이언트 포트의 send 권한을 새 mach 포트를 생성하여 보내는 대신 `smd` 연결에 연관된 **send right**의 복제로 대체합니다.
3. 결과적으로 XPC 메시지는 `diagnosticd`로 디스패치될 수 있지만, `diagnosticd`의 응답은 `smd`로 리다이렉트됩니다. `smd` 입장에서는 사용자와 `diagnosticd` 양쪽에서 온 메시지가 같은 연결에서 온 것처럼 보입니다.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 다음으로 `diagnosticd`에게 선택한 프로세스(예: 사용자의 프로세스) 모니터링을 시작하도록 지시합니다. 동시에 `smd`로 1004 형식의 일상적 메시지를 대량으로 보냅니다. 목적은 권한이 상승된 툴을 설치하는 것입니다.
5. 이 동작은 `handle_bless` 함수 내에서 경쟁 상태를 촉발합니다. 타이밍이 중요합니다: `xpc_connection_get_pid` 호출은 사용자의 프로세스 PID를 반환해야 합니다(권한 있는 툴이 사용자의 앱 번들에 위치하기 때문에). 그러나 `connection_is_authorized` 서브루틴 내의 `xpc_connection_get_audit_token` 호출은 `diagnosticd`의 audit token을 참조해야 합니다.

## Variant 2: reply forwarding

XPC(Cross-Process Communication) 환경에서 이벤트 핸들러는 동시에 실행되지는 않지만, reply 메시지의 처리에는 고유한 동작이 있습니다. 구체적으로, 응답을 기대하는 메시지를 보내는 방법에는 두 가지가 있습니다:

1. **`xpc_connection_send_message_with_reply`**: 이 경우 XPC 메시지는 지정된 큐에서 수신되고 처리됩니다.
2. **`xpc_connection_send_message_with_reply_sync`**: 반대로 이 방법에서는 XPC 메시지가 현재의 dispatch 큐에서 수신되고 처리됩니다.

이 차이는 reply 패킷이 XPC 이벤트 핸들러의 실행과 동시에 파싱될 가능성을 제공하기 때문에 중요합니다. 주목할 점은 `_xpc_connection_set_creds`가 audit token의 부분적 덮어쓰기를 방지하기 위해 락을 구현하긴 하지만, 이는 연결 객체 전체에 대한 보호를 확장하지는 않습니다. 결과적으로 패킷 파싱과 그 이벤트 핸들러 실행 사이의 간격 동안 audit token이 교체될 수 있는 취약점이 생깁니다.

이 취약점을 악용하려면 다음과 같은 준비가 필요합니다:

- 연결할 수 있는 두 개의 mach 서비스, 즉 **`A`**와 **`B`**.
- 서비스 **`A`**는 오직 **`B`**만 수행할 수 있는(사용자 앱은 할 수 없는) 특정 동작에 대한 권한 검사를 포함해야 합니다.
- 서비스 **`A`**는 응답을 기대하는 메시지를 전송해야 합니다.
- 사용자는 응답할 수 있는 메시지를 **`B`**에게 보낼 수 있어야 합니다.

악용 절차:

1. 서비스 **`A`**가 응답을 기대하는 메시지를 보낼 때까지 기다립니다.
2. 응답을 직접 **A에 보내는 대신**, reply 포트를 가로채 서비스 **B**에 메시지를 보냅니다.
3. 이후 금지된 동작을 포함한 메시지를 전송하여, 이 메시지가 **B의 응답과 동시에 처리되어** 응답이 audit token을 덮어쓰기를 기대합니다.

아래는 설명된 공격 시나리오의 시각적 표현입니다:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 발견의 어려움

- **인스턴스 찾기의 어려움**: `xpc_connection_get_audit_token` 사용 사례를 정적/동적 모두에서 찾는 것은 어려웠습니다.
- **방법론**: Frida를 사용해 `xpc_connection_get_audit_token`을 후킹하고 이벤트 핸들러에서 기원하지 않은 호출을 필터링했습니다. 그러나 이 방법은 후킹된 프로세스에만 적용되며 프로세스가 활성 상태일 때만 동작했습니다.
- **분석 도구**: IDA/Ghidra 같은 도구로 접근 가능한 mach 서비스들을 조사했지만, dyld shared cache와 연관된 호출들 때문에 시간이 많이 걸리고 복잡했습니다.
- **스크립팅 한계**: `dispatch_async` 블록에서 호출되는 `xpc_connection_get_audit_token`을 찾기 위해 분석을 스크립팅하려 했으나, 블록 파싱과 dyld shared cache 상호작용의 복잡성으로 인해 어려움이 있었습니다.

## 수정 사항 <a href="#the-fix" id="the-fix"></a>

- **보고된 문제**: `smd` 내에서 발견된 일반적 및 구체적 문제들이 Apple에 보고되었습니다.
- **Apple의 대응**: Apple은 `smd`에서 `xpc_connection_get_audit_token`을 `xpc_dictionary_get_audit_token`으로 대체하는 방식으로 문제를 수정했습니다.
- **수정의 성격**: `xpc_dictionary_get_audit_token` 함수는 수신된 XPC 메시지에 연결된 mach 메시지로부터 audit token을 직접 가져오므로 안전하다고 간주됩니다. 다만, 이 함수는 `xpc_connection_get_audit_token`처럼 공개 API의 일부는 아닙니다.
- **포괄적 수정의 부재**: Apple이 연결의 저장된 audit token과 일치하지 않는 메시지를 폐기하는 등 더 광범위한 수정을 왜 적용하지 않았는지는 불명확합니다. 일부 시나리오(예: `setuid` 사용)에서는 합법적으로 audit token이 변경될 가능성이 있어 고려 요인일 수 있습니다.
- **현재 상태**: 이 문제는 iOS 17 및 macOS 14에 여전히 존재하며 이를 식별하고 이해하려는 사람들에게 난제로 남아 있습니다.

## 실제로 취약한 코드 경로 찾기 (2024–2025)

XPC 서비스 감사를 할 때는 메시지의 이벤트 핸들러 외부에서 또는 응답 처리와 동시에 수행되는 권한 검사에 주목하세요.

정적 트리아지 힌트:
- `xpc_connection_get_audit_token` 호출을 찾아보되, 이 호출이 `dispatch_async`/`dispatch_after`나 메시지 핸들러 외부에서 실행되는 다른 워커 큐로 큐잉된 블록에서 도달 가능한지 검사하세요.
- 연결당 상태와 메시지당 상태를 혼합하는 권한 헬퍼를 찾아보세요(예: `xpc_connection_get_pid`로 PID를 가져오지만 `xpc_connection_get_audit_token`에서 audit token을 가져오는 경우).
- NSXPC 코드에서는 검사들이 `-listener:shouldAcceptNewConnection:`에서 수행되는지, 또는 메시지당 검사가 필요한 경우 구현이 per-message audit token을 사용하고 있는지(예: 하위 레벨 코드에서 메시지의 dictionary를 통해 `xpc_dictionary_get_audit_token`을 사용하는지) 확인하세요.

동적 트리아지 팁:
- `xpc_connection_get_audit_token`을 후킹하고 사용자 스택에 이벤트 전달 경로(예: `_xpc_connection_mach_event`)가 포함되지 않은 호출을 표시하세요. 예시 Frida 후킹:
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
- macOS에서는 보호된/Apple 바이너리를 계측하려면 SIP를 비활성화하거나 개발 환경이 필요할 수 있습니다; 자체 빌드나 userland 서비스에서 테스트하는 것을 권장합니다.
- reply-forwarding races (Variant 2)의 경우, `xpc_connection_send_message_with_reply`와 일반 요청의 타이밍을 퍼징하여 응답 패킷의 동시 파싱을 모니터링하고 권한 확인 시 사용되는 유효한 audit token이 조작될 수 있는지 확인하세요.

## 필요할 가능성이 높은 익스플로잇 프리미티브

- Multi-sender setup (Variant 1): A와 B에 대한 연결을 생성합니다; A의 client port에 대한 send right를 복제해서 B의 client port로 사용하면 B의 replies가 A로 전달됩니다.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A의 pending request (reply port)에서 send-once right를 가로채고, 그 reply port를 사용해 B에 조작된 메시지를 보내면 B의 응답이 당신의 권한 있는 요청이 파싱되는 동안 A로 도착하게 된다.

이들은 XPC bootstrap 및 메시지 포맷에 대해 저수준 mach 메시지 조작을 필요로 한다; 정확한 패킷 레이아웃과 플래그는 이 섹션의 mach/XPC primer 페이지를 검토하라.

## 유용한 도구

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer)는 연결을 열거하고 트래픽을 관찰해 multi-sender 설정과 타이밍을 검증하는 데 도움을 준다. 예: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: libxpc에 대해 `xpc_connection_send_message*` 및 `xpc_connection_get_audit_token`에 interpose하여 블랙박스 테스트 중 호출 지점과 스택을 로깅하라.

## 참고자료

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – macOS Ventura 13.4의 보안 내용에 관하여 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
