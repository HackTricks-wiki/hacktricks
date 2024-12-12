# macOS Thread Injection via Task port

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

## Code

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Thread Hijacking

Initially, the **`task_threads()`** function is invoked on the task port to obtain a thread list from the remote task. A thread is selected for hijacking. This approach diverges from conventional code injection methods as creating a new remote thread is prohibited due to the new mitigation blocking `thread_create_running()`.

To control the thread, **`thread_suspend()`** is called, halting its execution.

The only operations permitted on the remote thread involve **stopping** and **starting** it, **retrieving** and **modifying** its register values. Remote function calls are initiated by setting registers `x0` to `x7` to the **arguments**, configuring **`pc`** to target the desired function, and activating the thread. Ensuring the thread does not crash after the return necessitates detection of the return.

One strategy involves **registering an exception handler** for the remote thread using `thread_set_exception_ports()`, setting the `lr` register to an invalid address before the function call. This triggers an exception post-function execution, sending a message to the exception port, enabling state inspection of the thread to recover the return value. Alternatively, as adopted from Ian Beer’s triple\_fetch exploit, `lr` is set to loop infinitely. The thread's registers are then continuously monitored until **`pc` points to that instruction**.

## 2. Mach ports for communication

The subsequent phase involves establishing Mach ports to facilitate communication with the remote thread. These ports are instrumental in transferring arbitrary send and receive rights between tasks.

For bidirectional communication, two Mach receive rights are created: one in the local and the other in the remote task. Subsequently, a send right for each port is transferred to the counterpart task, enabling message exchange.

Focusing on the local port, the receive right is held by the local task. The port is created with `mach_port_allocate()`. The challenge lies in transferring a send right to this port into the remote task.

A strategy involves leveraging `thread_set_special_port()` to place a send right to the local port in the remote thread’s `THREAD_KERNEL_PORT`. Then, the remote thread is instructed to call `mach_thread_self()` to retrieve the send right.

For the remote port, the process is essentially reversed. The remote thread is directed to generate a Mach port via `mach_reply_port()` (as `mach_port_allocate()` is unsuitable due to its return mechanism). Upon port creation, `mach_port_insert_right()` is invoked in the remote thread to establish a send right. This right is then stashed in the kernel using `thread_set_special_port()`. Back in the local task, `thread_get_special_port()` is used on the remote thread to acquire a send right to the newly allocated Mach port in the remote task.

Completion of these steps results in the establishment of Mach ports, laying the groundwork for bidirectional communication.

## 3. Basic Memory Read/Write Primitives

In this section, the focus is on utilizing the execute primitive to establish basic memory read and write primitives. These initial steps are crucial for gaining more control over the remote process, though the primitives at this stage won't serve many purposes. Soon, they will be upgraded to more advanced versions.

### Memory Reading and Writing Using Execute Primitive

The goal is to perform memory reading and writing using specific functions. For reading memory, functions resembling the following structure are used:

```c
uint64_t read_func(uint64_t *address) {
    return *address;
}
```

And for writing to memory, functions similar to this structure are used:

```c
void write_func(uint64_t *address, uint64_t value) {
    *address = value;
}
```

These functions correspond to the given assembly instructions:

```
_read_func:
    ldr x0, [x0]
    ret
_write_func:
    str x1, [x0]
    ret
```

### Identifying Suitable Functions

A scan of common libraries revealed appropriate candidates for these operations:

1. **Reading Memory:**
   The `property_getName()` function from the [Objective-C runtime library](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) is identified as a suitable function for reading memory. The function is outlined below:

```c
const char *property_getName(objc_property_t prop) {
      return prop->name;
}
```
   
   This function effectively acts like the `read_func` by returning the first field of `objc_property_t`.

2. **Writing Memory:**
   Finding a pre-built function for writing memory is more challenging. However, the `_xpc_int64_set_value()` function from libxpc is a suitable candidate with the following disassembly:

```c
__xpc_int64_set_value:
    str x1, [x0, #0x18]
    ret
```


To perform a 64-bit write at a specific address, the remote call is structured as:

```c
_xpc_int64_set_value(address - 0x18, value)
```

With these primitives established, the stage is set for creating shared memory, marking a significant progression in controlling the remote process.

## 4. Shared Memory Setup

The objective is to establish shared memory between local and remote tasks, simplifying data transfer and facilitating the calling of functions with multiple arguments. The approach involves leveraging `libxpc` and its `OS_xpc_shmem` object type, which is built upon Mach memory entries.

### Process Overview:

1. **Memory Allocation**:
   - Allocate the memory for sharing using `mach_vm_allocate()`.
   - Use `xpc_shmem_create()` to create an `OS_xpc_shmem` object for the allocated memory region. This function will manage the creation of the Mach memory entry and store the Mach send right at offset `0x18` of the `OS_xpc_shmem` object.

2. **Creating Shared Memory in Remote Process**:
   - Allocate memory for the `OS_xpc_shmem` object in the remote process with a remote call to `malloc()`.
   - Copy the contents of the local `OS_xpc_shmem` object to the remote process. However, this initial copy will have incorrect Mach memory entry names at offset `0x18`.

3. **Correcting the Mach Memory Entry**:
   - Utilize the `thread_set_special_port()` method to insert a send right for the Mach memory entry into the remote task.
   - Correct the Mach memory entry field at offset `0x18` by overwriting it with the remote memory entry's name.

4. **Finalizing Shared Memory Setup**:
   - Validate the remote `OS_xpc_shmem` object.
   - Establish the shared memory mapping with a remote call to `xpc_shmem_remote()`.

By following these steps, shared memory between the local and remote tasks will be efficiently set up, allowing for straightforward data transfers and the execution of functions requiring multiple arguments.

## Additional Code Snippets

For memory allocation and shared memory object creation:
```c
mach_vm_allocate();
xpc_shmem_create();
```

For creating and correcting the shared memory object in the remote process:

```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```

Remember to handle the details of Mach ports and memory entry names correctly to ensure that the shared memory setup functions properly.


## 5. Achieving Full Control

Upon successfully establishing shared memory and gaining arbitrary execution capabilities, we have essentially gained full control over the target process. The key functionalities enabling this control are:

1. **Arbitrary Memory Operations**:
   - Perform arbitrary memory reads by invoking `memcpy()` to copy data from the shared region.
   - Execute arbitrary memory writes by using `memcpy()` to transfer data to the shared region.

2. **Handling Function Calls with Multiple Arguments**:
   - For functions requiring more than 8 arguments, arrange the additional arguments on the stack in compliance with the calling convention.

3. **Mach Port Transfer**:
   - Transfer Mach ports between tasks through Mach messages via previously established ports.

4. **File Descriptor Transfer**:
   - Transfer file descriptors between processes using fileports, a technique highlighted by Ian Beer in `triple_fetch`.

This comprehensive control is encapsulated within the [threadexec](https://github.com/bazad/threadexec) library, providing a detailed implementation and a user-friendly API for interaction with the victim process.

## Important Considerations:

- Ensure proper use of `memcpy()` for memory read/write operations to maintain system stability and data integrity.
- When transferring Mach ports or file descriptors, follow proper protocols and handle resources responsibly to prevent leaks or unintended access.

By adhering to these guidelines and utilizing the `threadexec` library, one can efficiently manage and interact with processes at a granular level, achieving full control over the target process.

## References
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

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
