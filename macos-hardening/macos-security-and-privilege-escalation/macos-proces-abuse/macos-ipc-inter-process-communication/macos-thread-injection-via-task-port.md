# macOS Thread Injection via Task port

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

This post was copied from [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/) (which contains more information)

### Code

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. Thread Hijacking

The first thing we do is call **`task_threads()`** on the task port to get a list of threads in the remote task and then choose one of them to hijack. Unlike traditional code injection frameworks, we **can’t create a new remote thread** because `thread_create_running()` will be blocked by the new mitigation.

Then, we can call **`thread_suspend()`** to stop the thread from running.

At this point, the only useful control we have over the remote thread is **stopping** it, **starting** it, **getting** its **register** values, and **setting** its register **values**. Thus, we can **initiate a remote function** call by setting **registers** `x0` through `x7` in the remote thread to the **arguments**, **setting** **`pc`** to the function we want to execute, and starting the thread. At this point, we need to detect the return and make sure that the thread doesn’t crash.

There are a few ways to go about this. One way would be to **register an exception handler** for the remote thread using `thread_set_exception_ports()` and to set the return address register, `lr`, to an invalid address before calling the function; that way, after the function runs an exception would be generated and a message would be sent to our exception port, at which point we can inspect the thread’s state to retrieve the return value. However, for simplicity I copied the strategy used in Ian Beer’s triple\_fetch exploit, which was to **set `lr` to the address of an instruction that would infinite loop** and then poll the thread’s registers repeatedly until **`pc` pointed to that instruction**.

### 2. Mach ports for communication

The next step is to **create Mach ports over which we can communicate with the remote thread**. These Mach ports will be useful later in helping transfer arbitrary send and receive rights between the tasks.

In order to establish bidirectional communication, we will need to create two Mach receive rights: one in the **local task and one in the remote task**. Then, we will need to **transfer a send right** to each port **to the other task**. This will give each task a way to send a message that can be received by the other.

Let’s first focus on setting up the local port, that is, the port to which the local task holds the receive right. We can create the Mach port just like any other, by calling `mach_port_allocate()`. The trick is to get a send right to that port into the remote task.

A convenient trick we can use to copy a send right from the current task into a remote task using only a basic execute primitive is to stash a **send right to our local port in the remote thread’**s `THREAD_KERNEL_PORT` special port using `thread_set_special_port()`; then, we can make the remote thread call `mach_thread_self()` to retrieve the send right.

Next we will set up the remote port, which is pretty much the inverse of what we just did. We can make the **remote thread allocate a Mach port by calling `mach_reply_port()`**; we can’t use `mach_port_allocate()` because the latter returns the allocated port name in memory and we don’t yet have a read primitive. Once we have a port, we can create a send right by calling `mach_port_insert_right()` in the remote thread. Then, we can stash the port in the kernel by calling `thread_set_special_port()`. Finally, back in the local task, we can retrieve the port by calling `thread_get_special_port()` on the remote thread, **giving us a send right to the Mach port just allocated in the remote task**.

At this point, we have created the Mach ports we will use for bidirectional communication.

### 3. Basic memory read/write <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

Now we will use the execute primitive to create basic memory read and write primitives. These primives won’t be used for much (we will soon upgrade to much more powerful primitives), but they are a key step in helping us to expand our control of the remote process.

In order to read and write memory using our execute primitive, we will be looking for functions like these:

```c
uint64_t read_func(uint64_t *address) {
    return *address;
}
void write_func(uint64_t *address, uint64_t value) {
    *address = value;
}
```

They might correspond to the following assembly:

```
_read_func:
    ldr     x0, [x0]
    ret
_write_func:
    str     x1, [x0]
    ret
```

A quick scan of some common libraries revealed some good candidates. To read memory, we can use the `property_getName()` function from the [Objective-C runtime library](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html):

```c
const char *property_getName(objc_property_t prop)
{
    return prop->name;
}
```

As it turns out, `prop` is the first field of `objc_property_t`, so this corresponds directly to the hypothetical `read_func` above. We just need to perform a remote function call with the first argument being the address we want to read, and the return value will be the data at that address.

Finding a pre-made function to write memory is slightly harder, but there are still great options without undesired side effects. In libxpc, the `_xpc_int64_set_value()` function has the following disassembly:

```
__xpc_int64_set_value:
    str     x1, [x0, #0x18]
    ret
```

Thus, to perform a 64-bit write at address `address`, we can perform the remote call:

```c
_xpc_int64_set_value(address - 0x18, value)
```

With these primitives in hand, we are ready to create shared memory.

### 4. Shared memory

Our next step is to create shared memory between the remote and local task. This will allow us to more easily transfer data between the processes: with a shared memory region, arbitrary memory read and write is as simple as a remote call to `memcpy()`. Additionally, having a shared memory region will allow us to easily set up a stack so that we can call functions with more than 8 arguments.

To make things easier, we can reuse the shared memory features of libxpc. Libxpc provides an XPC object type, `OS_xpc_shmem`, which allows establishing shared memory regions over XPC. By reversing libxpc, we determine that `OS_xpc_shmem` is based on Mach memory entries, which are Mach ports that represent a region of virtual memory. And since we already have shown how to send Mach ports to the remote task, we can use this to easily set up our own shared memory.

First things first, we need to allocate the memory we will share using `mach_vm_allocate()`. We need to use `mach_vm_allocate()` so that we can use `xpc_shmem_create()` to create an `OS_xpc_shmem` object for the region. `xpc_shmem_create()` will take care of creating the Mach memory entry for us and will store the Mach send right to the memory entry in the opaque `OS_xpc_shmem` object at offset `0x18`.

Once we have the memory entry port, we will create an `OS_xpc_shmem` object in the remote process representing the same memory region, allowing us to call `xpc_shmem_map()` to establish the shared memory mapping. First, we perform a remote call to `malloc()` to allocate memory for the `OS_xpc_shmem` and use our basic write primitive to copy in the contents of the local `OS_xpc_shmem` object. Unfortunately, the resulting object isn’t quite correct: its Mach memory entry field at offset `0x18` contains the local task’s name for the memory entry, not the remote task’s name. To fix this, we use the `thread_set_special_port()` trick to insert a send right to the Mach memory entry into the remote task and then overwrite field `0x18` with the remote memory entry’s name. At this point, the remote `OS_xpc_shmem` object is valid and the memory mapping can be established with a remote call to `xpc_shmem_remote()`.

### 5. Full control <a href="#step-5-full-control" id="step-5-full-control"></a>

With shared memory at a known address and an arbitrary execution primitive, we are basically done. Arbitrary memory reads and writes are implemented by calling `memcpy()` to and from the shared region, respectively. Function calls with more than 8 arguments are performed by laying out additional arguments beyond the first 8 on the stack according to the calling convention. Transferring arbitrary Mach ports between the tasks can be done by sending Mach messages over the ports established earlier. We can even transfer file descriptors between the processes by using fileports (special thanks to Ian Beer for demonstrating this technique in triple\_fetch!).

In short, we now have full and easy control over the victim process. You can see the full implementation and the exposed API in the [threadexec](https://github.com/bazad/threadexec) library.\






<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
