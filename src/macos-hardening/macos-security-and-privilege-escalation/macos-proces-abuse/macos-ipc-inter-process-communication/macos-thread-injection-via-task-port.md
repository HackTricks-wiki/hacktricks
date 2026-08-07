# macOS Task port를 통한 Thread Injection

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

처음에는 원격 task에서 thread 목록을 가져오기 위해 task port에 `task_threads()` 함수가 호출됩니다. 그런 다음 hijacking할 thread가 선택됩니다. `thread_create_running()`을 차단하는 mitigation으로 인해 새로운 remote thread를 생성할 수 없으므로, 이 접근 방식은 일반적인 code-injection 방법과 다릅니다.<sup>[[1]](#references)</sup>

thread를 제어하려면 `thread_suspend()`를 호출하여 실행을 중지합니다.<sup>[[1]](#references)</sup>

remote thread에서 허용되는 작업은 **중지** 및 **시작**, 그리고 register 값의 **검색**/**수정**뿐입니다. Remote function call은 register `x0`부터 `x7`까지를 **arguments**로 설정하고, `pc`를 원하는 function을 가리키도록 구성한 다음 thread를 재개하여 시작합니다. return 후 thread가 crash하지 않도록 하려면 return을 감지해야 합니다.<sup>[[1]](#references)</sup>

한 가지 방법은 `thread_set_exception_ports()`를 사용하여 remote thread에 **exception handler**를 등록하고, function call 전에 `lr` register를 유효하지 않은 주소로 설정하는 것입니다. 그러면 function 실행 후 exception이 발생하여 exception port로 message가 전송되고, 이를 통해 thread의 state를 검사하여 return value를 복구할 수 있습니다. 또는 Ian Beer의 *triple_fetch* exploit에서 사용된 방식처럼 `lr`을 무한 loop로 설정할 수도 있습니다. 그런 다음 `pc`가 해당 instruction을 가리킬 때까지 thread의 registers를 지속적으로 모니터링합니다.<sup>[[1]](#references)</sup>

## 2. 통신을 위한 Mach ports

다음 단계에서는 remote thread와 통신하기 위해 Mach ports를 설정합니다. 이러한 ports는 task 간에 임의의 send/receive rights를 전송하는 데 사용됩니다.<sup>[[1]](#references)</sup>

양방향 통신을 위해 두 개의 Mach receive rights를 생성합니다. 하나는 local task에, 다른 하나는 remote task에 생성합니다. 그런 다음 각 port의 send right를 상대 task로 전송하여 message exchange를 가능하게 합니다.<sup>[[1]](#references)</sup>

local port를 살펴보면 receive right는 local task가 보유합니다. 이 port는 `mach_port_allocate()`로 생성됩니다. 문제는 이 port에 대한 send right를 remote task로 전송하는 것입니다.<sup>[[1]](#references)</sup>

한 가지 방법은 `thread_set_special_port()`를 사용하여 local port에 대한 send right를 remote thread의 `THREAD_KERNEL_PORT`에 넣는 것입니다. 그런 다음 remote thread에 `mach_thread_self()`를 호출하도록 지시하여 send right를 가져옵니다.<sup>[[1]](#references)</sup>

remote port의 경우 과정은 본질적으로 반대입니다. `mach_port_allocate()`는 return mechanism에 적합하지 않으므로, remote thread에 `mach_reply_port()`를 통해 Mach port를 생성하도록 지시합니다. port가 생성되면 remote thread에서 `mach_port_insert_right()`를 호출하여 send right를 설정합니다. 그런 다음 이 right를 `thread_set_special_port()`를 사용하여 kernel에 보관합니다. local task로 돌아와서는 remote thread에 `thread_get_special_port()`를 사용하여 remote task에 새로 할당된 Mach port에 대한 send right를 획득합니다.<sup>[[1]](#references)</sup>

이 단계를 완료하면 Mach ports가 설정되어 양방향 통신을 위한 기반이 마련됩니다.<sup>[[1]](#references)</sup>

## 3. 기본 Memory Read/Write Primitives

이 section에서는 execute primitive을 사용하여 기본 memory read/write primitives를 설정하는 방법을 다룹니다. 이러한 초기 단계는 remote process를 더 많이 제어하기 위해 중요하지만, 이 단계의 primitives는 아직 많은 용도로 사용되지는 않습니다. 곧 더 advanced한 버전으로 업그레이드됩니다.<sup>[[1]](#references)</sup>

### execute primitive을 사용한 Memory reading 및 writing

목표는 특정 functions를 사용하여 memory reading 및 writing을 수행하는 것입니다. **reading memory**의 경우:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**memory writing의 경우:**
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

일반적인 libraries를 scan한 결과, 이러한 operations에 적합한 candidates를 확인할 수 있었습니다:<sup>[[1]](#references)</sup>

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
이러한 primitives가 확립되면 shared memory를 생성할 단계가 마련되며, 이는 remote process를 제어하는 데 있어 중요한 진전입니다.<sup>[[1]](#references)</sup>

## 4. Shared Memory Setup

목표는 local task와 remote task 간에 shared memory를 설정하여 data transfer를 간소화하고 여러 arguments를 사용한 function 호출을 가능하게 하는 것입니다. 이 접근 방식은 Mach memory entries를 기반으로 구축된 `OS_xpc_shmem` object type과 `libxpc`를 활용합니다.<sup>[[1]](#references)</sup>

### Process overview

1. **Memory allocation**
* `mach_vm_allocate()`를 사용하여 sharing을 위한 memory를 allocate합니다.
* `xpc_shmem_create()`를 사용하여 할당된 영역에 대한 `OS_xpc_shmem` object를 생성합니다.
2. **Creating shared memory in the remote process**
* remote process에서 `OS_xpc_shmem` object를 위한 memory를 allocate합니다(`remote_malloc`).
* local template object를 copy합니다. 단, offset `0x18`에 있는 embedded Mach send right의 fix-up이 여전히 필요합니다.
3. **Correcting the Mach memory entry**
* `thread_set_special_port()`로 send right를 insert하고 `0x18` field를 remote entry의 name으로 overwrite합니다.
4. **Finalising**
* remote object를 validate하고 remote call을 통해 `xpc_shmem_remote()`로 map합니다.

## 5. Achieving Full Control

arbitrary execution과 shared-memory back-channel을 사용할 수 있게 되면 사실상 target process를 완전히 장악한 것입니다:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — local 영역과 shared 영역 사이에서 `memcpy()`를 사용합니다.
* **Function calls with > 8 args** — arm64 calling convention에 따라 추가 arguments를 stack에 배치합니다.
* **Mach port transfer** — 설정된 ports를 통해 Mach messages로 rights를 전달합니다.
* **File-descriptor transfer** — fileports를 활용합니다(*triple_fetch* 참조).

이 모든 기능은 쉽게 재사용할 수 있도록 [`threadexec`](https://github.com/bazad/threadexec) library에 포함되어 있습니다.

---

## 6. Apple Silicon (arm64e) Nuances

Apple Silicon devices(arm64e)에서는 **Pointer Authentication Codes(PAC)**가 모든 return addresses와 많은 function pointers를 보호합니다. 기존 code를 *reuse*하는 thread-hijacking techniques는 `lr`/`pc`의 original values에 이미 유효한 PAC signatures가 포함되어 있으므로 계속 작동합니다. Attacker-controlled memory로 jump하려고 하면 문제가 발생합니다.

1. target 내부에 executable memory를 allocate합니다(remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. payload를 copy합니다.
3. *remote* process 내부에서 pointer에 sign을 적용합니다:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. 하이재킹된 thread state에서 `pc = ptr`을 설정합니다.

또는 기존 gadgets/functions를 체이닝하여(PAC를 준수하는 전통적인 ROP) PAC-compliant 상태를 유지합니다.

## 7. EndpointSecurity를 사용한 Detection & Hardening

**EndpointSecurity (ES)** framework는 defenders가 thread-injection 시도를 관찰하거나 차단할 수 있도록 kernel events를 노출합니다:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – 프로세스가 다른 task의 port를 요청할 때 발생합니다(예: `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – 다른 task에서 thread가 생성될 때마다 발생합니다.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (macOS 14 Sonoma에 추가됨) – 기존 thread의 register manipulation을 나타냅니다.

remote-thread events를 출력하는 최소한의 Swift client:
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
**osquery** ≥ 5.8을 사용한 조회:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime 고려 사항

애플리케이션을 `com.apple.security.get-task-allow` entitlement 없이 배포하면 non-root attackers가 해당 애플리케이션의 task-port를 획득하지 못합니다. System Integrity Protection (SIP)은 여전히 많은 Apple binaries에 대한 access를 차단하지만, third-party software는 명시적으로 opt-out해야 합니다.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma에서 PAC-aware thread hijacking을 시연하는 compact PoC<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | 여러 EDR vendors가 `REMOTE_THREAD_CREATE` events를 확인하는 데 사용하는 EndpointSecurity helper |

> 이 project들의 source code를 읽으면 macOS 13/14에서 도입된 API changes를 이해하고 Intel ↔ Apple Silicon 환경 간 호환성을 유지하는 데 도움이 됩니다.

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
