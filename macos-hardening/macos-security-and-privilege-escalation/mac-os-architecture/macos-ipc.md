# macOS IPC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## IPC - Inter Process Communication

### Ports

Mach uses **tasks** as the **smallest unit** for sharing resources, and each task can contain **multiple threads**. These **tasks and threads are mapped 1:1 to POSIX processes and threads**.

Communication between tasks occurs via Mach Inter-Process Communication (IPC), utilizing one-way communication channels. **Messages are transferred between ports**, which act like **message queues** managed by the kernel.

Port rights, which define what operations a task can perform, are key to this communication. The possible **port rights** are:

* **Receive right**, which allows receiving messages sent to the port. Mach ports are MPSC (multiple-producer, single-consumer) queues, which means that there may only ever be **one receive right for each port** in the whole system (unlike with pipes, where multiple processes can all hold file descriptors to the read end of one pipe).
  * A **task with the Receive** right can receive messages and **create Send rights**, allowing it to send messages. Originally only the **own task has Receive right over its por**t.
* **Send right**, which allows sending messages to the port.
* **Send-once right**, which allows sending one message to the port and then disappears.
* **Port set right**, which denotes a _port set_ rather than a single port. Dequeuing a message from a port set dequeues a message from one of the ports it contains. Port sets can be used to listen on several ports simultaneously, a lot like `select`/`poll`/`epoll`/`kqueue` in Unix.
* **Dead name**, which is not an actual port right, but merely a placeholder. When a port is destroyed, all existing port rights to the port turn into dead names.

**Tasks can transfer SEND rights to others**, enabling them to send messages back. **SEND rights can also be cloned, so a task can duplicate and give the right to a third task**. This, combined with an intermediary process known as the **bootstrap server**, allows for effective communication between tasks.

#### Steps:

As it's mentioned, in order to establish the communication channel, the **bootstrap server** (**launchd** in mac) is involved.

1. Task **A** initiates a **new port**, obtaining a **RECEIVE right** in the process.
2. Task **A**, being the holder of the RECEIVE right, **generates a SEND right for the port**.
3. Task **A** establishes a **connection** with the **bootstrap server**, providing the **port's service name** and the **SEND right** through a procedure known as the bootstrap register.
4. Task **B** interacts with the **bootstrap server** to execute a bootstrap **lookup for the service** name. If successful, the **server duplicates the SEND right** received from Task A and **transmits it to Task B**.
5. Upon acquiring a SEND right, Task **B** is capable of **formulating** a **message** and dispatching it **to Task A**.

The bootstrap server **cannot authenticate** the service name claimed by a task. This means a **task** could potentially **impersonate any system task**, such as falsely **claiming an authorization service name** and then approving every request.

Then, Apple stores the **names of system-provided services** in secure configuration files, located in **SIP-protected** directories: `/System/Library/LaunchDaemons` and `/System/Library/LaunchAgents`. Alongside each service name, the **associated binary is also stored**. The bootstrap server, will create and hold a **RECEIVE right for each of these service names**.

For these predefined services, the **lookup process differs slightly**. When a service name is being looked up, launchd starts the service dynamically. The new workflow is as follows:

* Task **B** initiates a bootstrap **lookup** for a service name.
* **launchd** checks if the task is running and if it isn’t, **starts** it.
* Task **A** (the service) performs a **bootstrap check-in**. Here, the **bootstrap** server creates a SEND right, retains it, and **transfers the RECEIVE right to Task A**.
* launchd duplicates the **SEND right and sends it to Task B**.

However, this process only applies to predefined system tasks. Non-system tasks still operate as described originally, which could potentially allow for impersonation.

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

### Privileged Ports

* **Task port** (aka kernel port)**:** With Send permission over this port it's possible to control the task (read/write memory, create threads...).
  * Call `mach_task_self()` to **get the name** for this port for the caller task. This port is only **inherited** across **`exec()`**; a new task created with `fork()` gets a new task port (as a special case, a task also gets a new task port after `exec()`ing a suid binary). The only way to spawn a task and get its port is to perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) while doing a `fork()`.
* **Host port**: If a process has **Send** privilege over this port he can get **information** about the **system** (e.g. `host_processor_info`).
* **Host priv port**: A process with **Send** right over this port can perform **privileged actions** like loading a kernel extension. The **process need to be root** to get tis permission.
  * Moreover, in order to call `kext_request` API it's needed to have the entitlement `com.apple.private.kext` which is only given to Apple binaries.
* **Task name port:** An unprivileged version of the _task port_. It references the task, but does not allow controlling it. The only thing that seems to be available through it is `task_info()`.

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
