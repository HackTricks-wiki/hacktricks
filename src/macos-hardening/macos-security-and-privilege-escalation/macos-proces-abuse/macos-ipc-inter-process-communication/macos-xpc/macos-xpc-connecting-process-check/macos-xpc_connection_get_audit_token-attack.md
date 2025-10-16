# macOS xpc_connection_get_audit_token 공격

{{#include ../../../../../../banners/hacktricks-training.md}}

**자세한 정보는 원본 포스트를 확인하세요:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). 요약은 다음과 같습니다:

## Mach 메시지 기본 정보

Mach Messages가 무엇인지 모른다면 이 페이지를 먼저 확인하세요:


{{#ref}}
../../
{{#endref}}

우선 ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing))를 기억하세요:\
Mach 메시지는 _mach port_을 통해 전송되며, 이는 mach 커널에 내장된 **단일 수신자, 다중 송신자 통신** 채널입니다. **여러 프로세스가** mach 포트로 메시지를 보낼 수 있지만, 언제든지 **단 하나의 프로세스만 해당 포트에서 읽을 수** 있습니다. 파일 디스크립터나 소켓처럼 mach 포트는 커널에 의해 할당되고 관리되며 프로세스는 정수 하나만 보고, 이를 통해 커널에 자신이 사용하려는 mach 포트를 지정합니다.

## XPC 연결

XPC 연결이 어떻게 성립되는지 모른다면 다음을 확인하세요:


{{#ref}}
../
{{#endref}}

## 취약점 요약

알아둘 중요한 점은 **XPC의 추상화는 일대일 연결**이지만, 그 기반 기술은 **다중 송신자**를 가질 수 있다는 것입니다. 따라서:

- Mach 포트는 단일 수신자, **다중 송신자**입니다.
- XPC 연결의 audit token은 **가장 최근에 수신된 메시지에서 복사된** audit token입니다.
- XPC 연결의 **audit token을 얻는 것**은 많은 **보안 체크**에서 중요합니다.

위 상황은 유망해 보이지만 다음과 같은 시나리오에서는 문제가 되지 않을 수 있습니다 ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit token은 연결을 수락할지 여부를 결정하는 권한 검사에 자주 사용됩니다. 이 검사는 서비스 포트로 메시지를 통해 이루어지기 때문에 **아직 연결이 수립되지 않은 상태**입니다. 이 포트로 더 많은 메시지가 도착하면 추가 연결 요청으로 처리됩니다. 따라서 연결 수락 전에 이뤄지는 모든 **체크는 취약하지 않습니다** (`-listener:shouldAcceptNewConnection:` 내부의 audit token은 안전합니다). 우리는 따라서 **특정 동작을 검증하는 XPC 연결**을 찾고 있습니다.
- XPC 이벤트 핸들러는 동기적으로 처리됩니다. 이는 한 메시지의 이벤트 핸들러가 완료되어야 다음 메시지에 대해 호출된다는 의미로, 동시 디스패치 큐에서도 마찬가지입니다. 따라서 **XPC 이벤트 핸들러 내부에서는 audit token이 다른 일반(응답이 아닌!) 메시지에 의해 덮어쓰여질 수 없습니다.**

이 상황이 악용될 수 있는 두 가지 다른 방법:

1. Variant1:
- **Exploit**가 서비스 **A**와 서비스 **B**에 **연결**합니다.
- 서비스 **B**는 사용자가 할 수 없는 **privileged functionality**를 서비스 A에서 호출할 수 있습니다.
- 서비스 **A**는 **이벤트 핸들러 내부가 아닌**, 예를 들어 **`dispatch_async`**에서 `xpc_connection_get_audit_token`을 호출합니다.
- 따라서 비동기적으로 디스패치되는 외부에서 **다른** 메시지가 **Audit Token을 덮어쓸 수 있습니다**.
- 익스플로잇은 서비스 **A에 대한 SEND 권한**을 **service B**에 전달합니다.
- 그래서 svc **B**가 실제로 서비스 **A**에 **메시지들을 보낼** 것입니다.
- **익스플로잇**은 **privileged action**을 **호출하려고 시도**합니다. RC 상황에서 svc **A**는 이 **동작의 권한을 검사하는데**, 그 시점에 **svc B가 Audit token을 덮어썼다면** (익스플로잇이 privileged action을 호출할 권한을 얻게 됩니다).
2. Variant 2:
- 서비스 **B**는 사용자가 할 수 없는 **privileged functionality**를 서비스 A에서 호출할 수 있습니다.
- 익스플로잇은 **service A**에 연결하고, 서비스 A는 특정 **reply 포트**에서 응답을 기대하는 메시지를 익스플로잇에게 보냅니다.
- 익스플로잇은 그 **reply port**를 전달하는 메시지를 서비스 **B**에 보냅니다.
- 서비스 **B**가 응답할 때, 그 메시지는 **service A로 전송**되며, 동시에 익스플로잇은 서비스 A에 다른 메시지를 보내 **privileged functionality**에 도달하려 시도하고, 서비스 B의 응답이 정확한 순간에 Audit token을 덮어쓸 것이라고 기대합니다 (Race Condition).

## Variant 1: 이벤트 핸들러 외부에서 xpc_connection_get_audit_token 호출 <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

시나리오:

- 샌드박스 프로필과 연결 수락 전 권한 검사에 따라 둘 다 연결할 수 있는 두 개의 mach 서비스 **`A`**와 **`B`**.
- _**A**_는 **`B`**가 전달할 수 있는 특정 동작에 대한 **권한 검사**를 해야 합니다(우리 앱은 할 수 없음).
- 예를 들어, B가 일부 **entitlements**를 가지고 있거나 **root**로 실행 중이면 A에게 privileged action을 요청할 수 있습니다.
- 이 권한 검사에서 **`A`**는 예를 들어 **`dispatch_async`**에서 `xpc_connection_get_audit_token`을 호출하여 비동기적으로 audit token을 얻습니다.

> [!CAUTION]
> 이 경우 공격자는 **Race Condition**을 유발할 수 있으며, **익스플로잇**은 **A에게 여러 번 동작 수행을 요청**하면서 **B가 `A`에 메시지를 보내도록** 만듭니다. RC가 **성공**하면, **B의 audit token**이 우리의 요청이 **A에서 처리되는 동안** 메모리에 복사되어 들어가며, 이는 오직 B만 요청할 수 있던 privileged action에 우리의 접근을 허용합니다.

이 사례는 **`A`**가 `smd`이고 **`B`**가 `diagnosticd`였을 때 발생했습니다. smb의 함수 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc)는 새로운 privileged helper tool을 설치하는 데 사용할 수 있습니다 (root로서). root로 실행되는 프로세스가 **smd**에 연락하면 추가 검사가 수행되지 않습니다.

따라서 서비스 **B**는 **root로 실행되기 때문에** 프로세스를 모니터링할 수 있는 `diagnosticd`이며, 모니터링이 시작되면 초당 여러 메시지를 전송합니다.

공격 수행 방법:

1. 표준 XPC 프로토콜을 사용하여 `smd`라는 서비스에 대한 **연결**을 시작합니다.
2. `diagnosticd`에 대한 보조 **연결**을 형성합니다. 일반적인 절차와 달리, 클라이언트 포트 send 권한을 새로 생성하여 보내는 대신 `smd` 연결과 연관된 **send right**의 복제본으로 대체합니다.
3. 결과적으로 XPC 메시지는 `diagnosticd`로 디스패치될 수 있지만, `diagnosticd`의 응답은 `smd`로 리다이렉트됩니다. `smd` 입장에서는 사용자와 `diagnosticd` 양쪽에서 오는 메시지들이 같은 연결에서 온 것처럼 보입니다.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 다음 단계는 `diagnosticd`에게 선택한 프로세스(잠재적으로 사용자의 프로세스)를 모니터링하도록 지시하는 것입니다. 동시에 `smd`에 일상적인 1004 메시지를 대량으로 보냅니다. 목적은 권한이 상승된 도구를 설치하는 것입니다.
5. 이 동작은 `handle_bless` 함수 내에서 레이스 컨디션을 유발합니다. 타이밍이 중요합니다: `xpc_connection_get_pid` 호출은 사용자의 프로세스 PID를 반환해야 합니다(권한 있는 도구가 사용자의 앱 번들에 있음). 그러나 `connection_is_authorized` 하위 루틴 내의 `xpc_connection_get_audit_token`은 `diagnosticd`의 audit token을 참조해야 합니다.

## Variant 2: reply 전달

XPC 환경에서는 이벤트 핸들러가 동시에 실행되지는 않지만, reply 메시지 처리는 고유한 동작을 합니다. 구체적으로, 응답을 기대하는 메시지를 보내는 두 가지 방법이 있습니다:

1. **`xpc_connection_send_message_with_reply`**: 이 방식에서는 XPC 메시지가 지정된 큐에서 수신되고 처리됩니다.
2. **`xpc_connection_send_message_with_reply_sync`**: 반대로 이 방식에서는 XPC 메시지가 현재 디스패치 큐에서 수신되고 처리됩니다.

이 구분은 **reply 패킷이 XPC 이벤트 핸들러의 실행과 동시에 파싱될 수 있는 가능성**을 제공합니다. 주목할 점은 `_xpc_connection_set_creds`가 audit token의 부분적 덮어쓰기를 방지하기 위해 락을 적용하지만, 연결 객체 전체에 대해서는 이 보호를 확장하지 않는다는 점입니다. 결과적으로 패킷 파싱과 이벤트 핸들러 실행 사이의 간격에서 audit token이 교체될 수 있는 취약점이 생깁니다.

이 취약점을 악용하려면 다음과 같은 준비가 필요합니다:

- 연결을 설정할 수 있는 두 개의 mach 서비스, **`A`**와 **`B`**.
- 서비스 **`A`**는 오직 **`B`**만 수행할 수 있는 특정 동작에 대한 권한 검사를 포함해야 합니다(사용자 앱은 아님).
- 서비스 **`A`**는 응답을 기대하는 메시지를 보냅니다.
- 사용자는 서비스 **`B`**에 응답할 메시지를 보낼 수 있습니다.

악용 절차:

1. 서비스 **`A`**가 응답을 기대하는 메시지를 보낼 때까지 대기합니다.
2. 그 응답을 직접 A에 보내지 않고, reply 포트를 탈취하여 서비스 **`B`**에 메시지를 보내는 데 사용합니다.
3. 그 후 금지된 동작을 포함한 메시지를 전송하여, 그것이 서비스 B의 응답과 동시에 처리되길 기대합니다.

아래는 설명된 공격 시나리오의 시각적 표현입니다:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 발견상의 문제

- **인스턴스 찾기의 어려움**: `xpc_connection_get_audit_token` 사용 인스턴스를 정적/동적으로 찾는 것이 어려웠습니다.
- **방법론**: Frida를 사용해 `xpc_connection_get_audit_token`을 후킹하고 이벤트 핸들러에서 시작하지 않는 호출을 필터링했습니다. 그러나 이 방법은 후킹한 프로세스에만 적용되며 해당 기능을 실제로 사용 중일 때에만 효과적이었습니다.
- **분석 툴링**: IDA/Ghidra 같은 도구를 사용해 도달 가능한 mach 서비스들을 조사했지만, dyld shared cache 관련 호출로 인해 시간이 많이 소요되고 복잡했습니다.
- **스크립팅 한계**: `dispatch_async` 블록에서 `xpc_connection_get_audit_token`으로의 호출을 스크립트로 분석하려는 시도는 블록 파싱과 dyld shared cache와의 상호작용 때문에 어려움을 겪었습니다.

## 수정 사항 <a href="#the-fix" id="the-fix"></a>

- **보고된 문제**: `smd` 내에서 발견된 일반적 및 특정 문제를 Apple에 보고했습니다.
- **Apple의 대응**: Apple은 `smd`에서 `xpc_connection_get_audit_token`을 `xpc_dictionary_get_audit_token`으로 대체하는 방식으로 문제를 수정했습니다.
- **수정의 성격**: `xpc_dictionary_get_audit_token` 함수는 수신된 XPC 메시지와 연관된 mach 메시지에서 직접 audit token을 가져오기 때문에 안전한 것으로 간주됩니다. 다만, 이 함수는 `xpc_connection_get_audit_token`과 마찬가지로 공개 API의 일부가 아닙니다.
- **광범위한 수정 부재**: 왜 Apple이 연결의 저장된 audit token과 일치하지 않는 메시지를 폐기하는 등 더 포괄적인 수정을 하지 않았는지는 불분명합니다. 특정 시나리오(예: `setuid` 사용)에서 정당한 audit token 변경이 발생할 가능성이 이유일 수 있습니다.
- **현재 상태**: 이 문제는 iOS 17 및 macOS 14에 여전히 존재하며, 이를 식별하고 이해하려는 사람들에게 도전 과제를 제공합니다.

## 실무에서 취약 코드 경로 찾기 (2024–2025)

XPC 서비스를 감사할 때, 메시지의 이벤트 핸들러 외부에서 수행되는 권한 검사나 응답 처리와 동시에 수행되는 권한 검사에 주목하세요.

정적 탐색 힌트:
- `dispatch_async`/`dispatch_after` 또는 메시지 핸들러 외부에서 실행되는 다른 워커 큐를 통해 큐에 추가될 수 있는 블록에서 도달 가능한 `xpc_connection_get_audit_token` 호출을 검색하세요.
- per-connection과 per-message 상태를 혼합하는 권한 헬퍼를 찾아보세요(예: `xpc_connection_get_pid`에서 PID를 가져오지만 `xpc_connection_get_audit_token`에서 audit token을 가져오는 경우).
- NSXPC 코드에서는 `-listener:shouldAcceptNewConnection:`에서 체크가 수행되는지 확인하거나, 메시지별 체크의 경우 구현이 per-message audit token을 사용하도록 되어 있는지 확인하세요(예: 하위 레벨 코드에서 메시지의 dictionary를 통해 `xpc_dictionary_get_audit_token` 사용).

동적 탐색 팁:
- `xpc_connection_get_audit_token`을 후킹하고, 사용자 스택에 이벤트 전달 경로가 포함되지 않은 호출을 플래그하세요(예: `_xpc_connection_mach_event`). 예시 Frida 후킹:
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
- macOS에서는 보호된/Apple 바이너리를 instrumenting하려면 SIP를 비활성화하거나 개발 환경이 필요할 수 있습니다; 자체 빌드나 userland services를 테스트하는 것을 권장합니다.
- reply-forwarding races (Variant 2)의 경우, `xpc_connection_send_message_with_reply`와 일반 요청의 타이밍을 퍼징하여 응답 패킷의 동시 파싱을 모니터링하고 권한 검사(authorization) 동안 사용되는 유효한 audit token이 영향을 받을 수 있는지 확인하십시오.

## Exploitation primitives you will likely need

- Multi-sender setup (Variant 1): A와 B에 대한 connections를 생성합니다; A의 client port의 send right을 복제하여 B의 client port로 사용하면 B의 replies가 A로 전달됩니다.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A의 대기 중인 요청(reply port)에서 send-once right를 가로채고, 그 reply port를 사용해 B에게 조작된 메시지를 보내 B의 응답이 당신의 권한 있는 요청이 파싱되는 동안 A로 도달하게 합니다.

이들은 XPC bootstrap 및 메시지 형식을 위한 저수준 mach message crafting을 필요로 합니다; 정확한 패킷 레이아웃과 플래그는 이 섹션의 mach/XPC primer 페이지를 검토하세요.

## 유용한 도구

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer)는 연결을 열거하고 트래픽을 관찰하여 multi-sender 설정과 타이밍을 검증하는 데 도움이 됩니다. 예: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: libxpc에 대한 고전적인 dyld interposing을 통해 `xpc_connection_send_message*`와 `xpc_connection_get_audit_token`을 interpose하여 블랙박스 테스트 중에 호출 지점과 스택을 로그하세요.



## 참고자료

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
