# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

처음에, `task_threads()` 함수가 원격 작업에서 스레드 목록을 얻기 위해 작업 포트에서 호출됩니다. 스레드가 하이재킹을 위해 선택됩니다. 이 접근 방식은 `thread_create_running()`을 차단하는 완화 조치로 인해 새로운 원격 스레드를 생성하는 것이 금지되므로 기존의 코드 주입 방법과 다릅니다.

스레드를 제어하기 위해 `thread_suspend()`가 호출되어 실행이 중단됩니다.

원격 스레드에서 허용되는 유일한 작업은 **중지** 및 **시작**과 **레지스터 값**을 **가져오고**/**수정하는** 것입니다. 원격 함수 호출은 레지스터 `x0`에서 `x7`을 **인수**로 설정하고, `pc`를 원하는 함수로 설정한 후 스레드를 재개하여 시작됩니다. 반환 후 스레드가 충돌하지 않도록 하려면 반환을 감지해야 합니다.

한 가지 전략은 `thread_set_exception_ports()`를 사용하여 원격 스레드에 대한 **예외 처리기**를 등록하고, 함수 호출 전에 `lr` 레지스터를 잘못된 주소로 설정하는 것입니다. 이는 함수 실행 후 예외를 발생시켜 예외 포트에 메시지를 전송하고, 스레드의 상태를 검사하여 반환 값을 복구할 수 있게 합니다. 또는 Ian Beer의 *triple_fetch* 익스플로잇에서 채택한 대로, `lr`을 무한 루프에 설정하여 스레드의 레지스터를 지속적으로 모니터링하다가 `pc`가 해당 명령어를 가리킬 때까지 기다립니다.

## 2. Mach ports for communication

다음 단계는 원격 스레드와의 통신을 용이하게 하기 위해 Mach 포트를 설정하는 것입니다. 이러한 포트는 작업 간에 임의의 송신/수신 권한을 전송하는 데 필수적입니다.

양방향 통신을 위해 두 개의 Mach 수신 권한이 생성됩니다: 하나는 로컬 작업에, 다른 하나는 원격 작업에 있습니다. 이후 각 포트에 대한 송신 권한이 상대 작업으로 전송되어 메시지 교환이 가능해집니다.

로컬 포트에 집중하면, 수신 권한은 로컬 작업에 의해 보유됩니다. 포트는 `mach_port_allocate()`로 생성됩니다. 이 포트에 송신 권한을 원격 작업으로 전송하는 것이 도전 과제가 됩니다.

전략은 `thread_set_special_port()`를 활용하여 원격 스레드의 `THREAD_KERNEL_PORT`에 로컬 포트에 대한 송신 권한을 배치하는 것입니다. 그런 다음 원격 스레드에 `mach_thread_self()`를 호출하여 송신 권한을 가져오도록 지시합니다.

원격 포트의 경우, 과정은 본질적으로 반대로 진행됩니다. 원격 스레드는 `mach_reply_port()`를 통해 Mach 포트를 생성하도록 지시받습니다(반환 메커니즘 때문에 `mach_port_allocate()`는 적합하지 않음). 포트가 생성되면, 원격 스레드에서 `mach_port_insert_right()`가 호출되어 송신 권한이 설정됩니다. 이 권한은 `thread_set_special_port()`를 사용하여 커널에 저장됩니다. 로컬 작업으로 돌아가서, `thread_get_special_port()`를 사용하여 원격 작업의 새로 할당된 Mach 포트에 대한 송신 권한을 획득합니다.

이 단계가 완료되면 Mach 포트가 설정되어 양방향 통신을 위한 기초가 마련됩니다.

## 3. Basic Memory Read/Write Primitives

이 섹션에서는 기본 메모리 읽기/쓰기 원시 작업을 설정하기 위해 실행 원시 작업을 활용하는 데 중점을 둡니다. 이러한 초기 단계는 원격 프로세스에 대한 더 많은 제어를 얻는 데 중요하지만, 이 단계의 원시 작업은 많은 용도로 사용되지 않을 것입니다. 곧 더 고급 버전으로 업그레이드될 것입니다.

### Memory reading and writing using the execute primitive

목표는 특정 함수를 사용하여 메모리 읽기 및 쓰기를 수행하는 것입니다. **메모리 읽기**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**메모리 쓰기**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
이 함수들은 다음 어셈블리에 해당합니다:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 적합한 함수 식별

일반 라이브러리를 스캔한 결과 이러한 작업에 적합한 후보가 발견되었습니다:

1. **메모리 읽기 — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **메모리 쓰기 — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
임의의 주소에 64비트 쓰기를 수행하려면:
```c
_xpc_int64_set_value(address - 0x18, value);
```
이러한 원시 기능이 설정되면, 원격 프로세스를 제어하는 데 있어 중요한 진전을 이루는 공유 메모리를 생성할 준비가 됩니다.

## 4. 공유 메모리 설정

목표는 로컬 및 원격 작업 간에 공유 메모리를 설정하여 데이터 전송을 간소화하고 여러 인수를 가진 함수 호출을 용이하게 하는 것입니다. 이 접근 방식은 `libxpc`와 Mach 메모리 항목을 기반으로 구축된 `OS_xpc_shmem` 객체 유형을 활용합니다.

### 프로세스 개요

1. **메모리 할당**
* `mach_vm_allocate()`를 사용하여 공유할 메모리를 할당합니다.
* 할당된 영역에 대해 `xpc_shmem_create()`를 사용하여 `OS_xpc_shmem` 객체를 생성합니다.
2. **원격 프로세스에서 공유 메모리 생성**
* 원격 프로세스에서 `OS_xpc_shmem` 객체를 위한 메모리를 할당합니다 (`remote_malloc`).
* 로컬 템플릿 객체를 복사합니다; `0x18` 오프셋에서 내장된 Mach 전송 권한의 수정이 여전히 필요합니다.
3. **Mach 메모리 항목 수정**
* `thread_set_special_port()`로 전송 권한을 삽입하고 `0x18` 필드를 원격 항목의 이름으로 덮어씁니다.
4. **최종화**
* 원격 객체를 검증하고 `xpc_shmem_remote()`에 대한 원격 호출로 매핑합니다.

## 5. 완전한 제어 달성

임의 실행 및 공유 메모리 백 채널이 가능해지면, 효과적으로 대상 프로세스를 소유하게 됩니다:

* **임의 메모리 R/W** — 로컬 및 공유 영역 간에 `memcpy()`를 사용합니다.
* **8개 이상의 인수를 가진 함수 호출** — arm64 호출 규약에 따라 스택에 추가 인수를 배치합니다.
* **Mach 포트 전송** — 설정된 포트를 통해 Mach 메시지에서 권한을 전달합니다.
* **파일 설명자 전송** — 파일 포트를 활용합니다 (참조: *triple_fetch*).

이 모든 것은 쉽게 재사용할 수 있도록 [`threadexec`](https://github.com/bazad/threadexec) 라이브러리에 포장되어 있습니다.

---

## 6. Apple Silicon (arm64e) 뉘앙스

Apple Silicon 장치(arm64e)에서는 **포인터 인증 코드(PAC)**가 모든 반환 주소와 많은 함수 포인터를 보호합니다. 기존 코드를 재사용하는 스레드 하이재킹 기술은 `lr`/`pc`의 원래 값이 이미 유효한 PAC 서명을 가지고 있기 때문에 계속 작동합니다. 공격자가 제어하는 메모리로 점프하려고 할 때 문제가 발생합니다:

1. 대상 내부에 실행 가능한 메모리를 할당합니다 (원격 `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. 페이로드를 복사합니다.
3. *원격* 프로세스 내에서 포인터에 서명합니다:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. 하이재킹된 스레드 상태에서 `pc = ptr` 설정.

또는 기존의 가젯/함수를 연결하여 PAC 준수를 유지합니다 (전통적인 ROP).

## 7. 탐지 및 EndpointSecurity를 통한 강화

**EndpointSecurity (ES)** 프레임워크는 방어자가 스레드 주입 시도를 관찰하거나 차단할 수 있도록 하는 커널 이벤트를 노출합니다:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – 프로세스가 다른 작업의 포트를 요청할 때 발생합니다 (예: `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – *다른* 작업에서 스레드가 생성될 때마다 발생합니다.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (macOS 14 Sonoma에 추가됨) – 기존 스레드의 레지스터 조작을 나타냅니다.

원격 스레드 이벤트를 출력하는 최소한의 Swift 클라이언트:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
**osquery** ≥ 5.8로 쿼리하기:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime considerations

애플리케이션을 `com.apple.security.get-task-allow` 권한 없이 배포하면 비루트 공격자가 해당 작업 포트를 얻는 것을 방지할 수 있습니다. 시스템 무결성 보호(SIP)는 여전히 많은 Apple 바이너스에 대한 접근을 차단하지만, 서드파티 소프트웨어는 명시적으로 옵트아웃해야 합니다.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma에서 PAC 인식 스레드 하이재킹을 보여주는 간결한 PoC |
| `remote_thread_es` | 2024 | 여러 EDR 공급자가 `REMOTE_THREAD_CREATE` 이벤트를 표출하는 데 사용하는 EndpointSecurity 헬퍼 |

> 이러한 프로젝트의 소스 코드를 읽는 것은 macOS 13/14에서 도입된 API 변경 사항을 이해하고 Intel ↔ Apple Silicon 간의 호환성을 유지하는 데 유용합니다.

## References

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
