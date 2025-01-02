# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

처음에, **`task_threads()`** 함수가 원격 작업에서 스레드 목록을 얻기 위해 작업 포트에서 호출됩니다. 스레드가 하이재킹을 위해 선택됩니다. 이 접근 방식은 새로운 원격 스레드를 생성하는 것이 금지되어 있기 때문에 기존의 코드 주입 방법과 다릅니다. 이는 새로운 완화가 `thread_create_running()`을 차단하기 때문입니다.

스레드를 제어하기 위해 **`thread_suspend()`**가 호출되어 실행이 중단됩니다.

원격 스레드에서 허용되는 유일한 작업은 **중지** 및 **시작**과 **레지스터 값**을 **가져오고** **수정하는** 것입니다. 원격 함수 호출은 레지스터 `x0`에서 `x7`을 **인수**로 설정하고, **`pc`**를 원하는 함수로 설정한 후 스레드를 활성화하여 시작됩니다. 반환 후 스레드가 충돌하지 않도록 보장하기 위해 반환을 감지해야 합니다.

한 가지 전략은 `thread_set_exception_ports()`를 사용하여 원격 스레드에 대한 예외 처리기를 **등록**하는 것입니다. 함수 호출 전에 `lr` 레지스터를 잘못된 주소로 설정합니다. 이는 함수 실행 후 예외를 발생시켜 예외 포트에 메시지를 보내고, 스레드의 상태를 검사하여 반환 값을 복구할 수 있게 합니다. 또는 Ian Beer의 triple_fetch exploit에서 채택한 대로, `lr`을 무한 루프에 설정할 수 있습니다. 그런 다음 스레드의 레지스터를 지속적으로 모니터링하여 **`pc`가 해당 명령어를 가리킬 때까지** 대기합니다.

## 2. Mach ports for communication

다음 단계는 원격 스레드와의 통신을 용이하게 하기 위해 Mach 포트를 설정하는 것입니다. 이러한 포트는 작업 간에 임의의 송신 및 수신 권한을 전송하는 데 필수적입니다.

양방향 통신을 위해 두 개의 Mach 수신 권한이 생성됩니다: 하나는 로컬 작업에, 다른 하나는 원격 작업에 있습니다. 이후 각 포트에 대한 송신 권한이 상대 작업으로 전송되어 메시지 교환이 가능해집니다.

로컬 포트에 집중하면, 수신 권한은 로컬 작업에 의해 보유됩니다. 포트는 `mach_port_allocate()`로 생성됩니다. 이 포트에 송신 권한을 원격 작업으로 전송하는 것이 도전 과제가 됩니다.

전략 중 하나는 `thread_set_special_port()`를 활용하여 원격 스레드의 `THREAD_KERNEL_PORT`에 로컬 포트에 대한 송신 권한을 배치하는 것입니다. 그런 다음 원격 스레드에 `mach_thread_self()`를 호출하여 송신 권한을 가져오도록 지시합니다.

원격 포트의 경우, 과정이 본질적으로 반대로 진행됩니다. 원격 스레드는
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
메모리에 쓰기 위해, 이 구조와 유사한 함수들이 사용됩니다:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
이 함수는 주어진 어셈블리 명령어에 해당합니다:
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

1. **메모리 읽기:**
`property_getName()` 함수는 [Objective-C 런타임 라이브러리](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)에서 메모리를 읽기 위한 적합한 함수로 확인되었습니다. 함수는 아래에 설명되어 있습니다:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
이 함수는 `objc_property_t`의 첫 번째 필드를 반환함으로써 효과적으로 `read_func`처럼 작동합니다.

2. **메모리 쓰기:**
메모리를 쓰기 위한 미리 구축된 함수를 찾는 것은 더 어려운 일입니다. 그러나 libxpc의 `_xpc_int64_set_value()` 함수는 다음과 같은 디스어셈블리와 함께 적합한 후보입니다:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
특정 주소에 64비트 쓰기를 수행하기 위해 원격 호출은 다음과 같이 구성됩니다:
```c
_xpc_int64_set_value(address - 0x18, value)
```
이러한 원시 기능이 설정되면, 원격 프로세스를 제어하는 데 있어 중요한 진전을 이루는 공유 메모리를 생성할 준비가 됩니다.

## 4. 공유 메모리 설정

목표는 로컬 및 원격 작업 간에 공유 메모리를 설정하여 데이터 전송을 간소화하고 여러 인수를 가진 함수 호출을 용이하게 하는 것입니다. 이 접근 방식은 `libxpc`와 Mach 메모리 항목을 기반으로 하는 `OS_xpc_shmem` 객체 유형을 활용하는 것입니다.

### 프로세스 개요:

1. **메모리 할당**:

- `mach_vm_allocate()`를 사용하여 공유할 메모리를 할당합니다.
- 할당된 메모리 영역에 대해 `xpc_shmem_create()`를 사용하여 `OS_xpc_shmem` 객체를 생성합니다. 이 함수는 Mach 메모리 항목의 생성을 관리하고 `OS_xpc_shmem` 객체의 오프셋 `0x18`에 Mach 전송 권한을 저장합니다.

2. **원격 프로세스에서 공유 메모리 생성**:

- 원격 호출을 통해 원격 프로세스에서 `OS_xpc_shmem` 객체를 위한 메모리를 할당합니다.
- 로컬 `OS_xpc_shmem` 객체의 내용을 원격 프로세스로 복사합니다. 그러나 이 초기 복사는 오프셋 `0x18`에서 잘못된 Mach 메모리 항목 이름을 가질 것입니다.

3. **Mach 메모리 항목 수정**:

- `thread_set_special_port()` 메서드를 사용하여 원격 작업에 Mach 메모리 항목에 대한 전송 권한을 삽입합니다.
- 원격 메모리 항목의 이름으로 오프셋 `0x18`의 Mach 메모리 항목 필드를 덮어써서 수정합니다.

4. **공유 메모리 설정 완료**:
- 원격 `OS_xpc_shmem` 객체를 검증합니다.
- 원격 호출을 통해 공유 메모리 매핑을 설정합니다 `xpc_shmem_remote()`.

이 단계를 따르면 로컬 및 원격 작업 간에 공유 메모리가 효율적으로 설정되어 데이터 전송과 여러 인수를 요구하는 함수 실행이 간단해집니다.

## 추가 코드 스니펫

메모리 할당 및 공유 메모리 객체 생성을 위한:
```c
mach_vm_allocate();
xpc_shmem_create();
```
원격 프로세스에서 공유 메모리 객체를 생성하고 수정하기 위해:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Mach 포트와 메모리 항목 이름의 세부 사항을 올바르게 처리하여 공유 메모리 설정이 제대로 작동하도록 해야 합니다.

## 5. 완전한 제어 달성

공유 메모리를 성공적으로 설정하고 임의 실행 기능을 얻으면 본질적으로 대상 프로세스에 대한 완전한 제어를 얻게 됩니다. 이 제어를 가능하게 하는 주요 기능은 다음과 같습니다:

1. **임의 메모리 작업**:

- `memcpy()`를 호출하여 공유 영역에서 데이터를 복사하여 임의 메모리 읽기를 수행합니다.
- `memcpy()`를 사용하여 공유 영역으로 데이터를 전송하여 임의 메모리 쓰기를 실행합니다.

2. **다중 인수를 가진 함수 호출 처리**:

- 8개 이상의 인수를 요구하는 함수의 경우, 호출 규약에 따라 추가 인수를 스택에 배치합니다.

3. **Mach 포트 전송**:

- 이전에 설정된 포트를 통해 Mach 메시지를 통해 작업 간에 Mach 포트를 전송합니다.

4. **파일 설명자 전송**:
- Ian Beer가 `triple_fetch`에서 강조한 기술인 fileports를 사용하여 프로세스 간에 파일 설명자를 전송합니다.

이 포괄적인 제어는 [threadexec](https://github.com/bazad/threadexec) 라이브러리에 캡슐화되어 있으며, 피해자 프로세스와의 상호 작용을 위한 상세한 구현과 사용자 친화적인 API를 제공합니다.

## 중요한 고려 사항:

- 시스템 안정성과 데이터 무결성을 유지하기 위해 메모리 읽기/쓰기 작업에 `memcpy()`를 적절히 사용해야 합니다.
- Mach 포트나 파일 설명자를 전송할 때는 적절한 프로토콜을 따르고 자원을 책임감 있게 처리하여 누수나 의도하지 않은 접근을 방지해야 합니다.

이 가이드라인을 준수하고 `threadexec` 라이브러리를 활용함으로써, 프로세스를 세밀하게 관리하고 상호 작용하여 대상 프로세스에 대한 완전한 제어를 달성할 수 있습니다.

## 참고 문헌

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{{#include ../../../../banners/hacktricks-training.md}}
