# macOS Process Abuse

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

## Processes Basic Information

A process is an instance of a running executable, however processes doesn't run code, these are threads. Therefore **processes are just containers for running threads** providing the memory, descriptors, ports, permissions...

Traditionally, processes where started within other processes (except PID 1) by calling **`fork`** which would create a exact copy of the current process and then the **child process** would generally call **`execve`** to load the new executable and run it. Then, **`vfork`** was introduced to make this process faster without any memory copying.\
Then **`posix_spawn`** was introduced combining **`vfork`** and **`execve`** in one call and accepting flags:

* `POSIX_SPAWN_RESETIDS`: Reset effective ids to real ids
* `POSIX_SPAWN_SETPGROUP`: Set process group affiliation
* `POSUX_SPAWN_SETSIGDEF`: Set signal default behaviour
* `POSIX_SPAWN_SETSIGMASK`: Set signal mask
* `POSIX_SPAWN_SETEXEC`: Exec in the same process (like `execve` with more options)
* `POSIX_SPAWN_START_SUSPENDED`: Start suspended
* `_POSIX_SPAWN_DISABLE_ASLR`: Start without ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Use libmalloc's Nano allocator
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Allow `rwx` on data segments
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Close all file descriptions on exec(2) by default
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomize high bits of ASLR slide

Moreover, `posix_spawn` allows to specify an array of **`posix_spawnattr`** that controls some aspects of the spawned process, and **`posix_spawn_file_actions`** to modify the state of the descriptors.

When a process dies it send the **return code to the parent process** (if the parent died, the new parent is PID 1) with the signal `SIGCHLD`. The parent needs to get this value calling `wait4()` or `waitid()` and until that happen the child stays in a zombie state where it's still listed but doesn't consume resources.

### PIDs

PIDs, process identifiers, identifies a uniq process. In XNU the **PIDs** are of **64bits** increasing monotonically and **never wrap** (to avoid abuses).

### Process Groups, Sessions & Coalations

**Processes** can be inserted in **groups** to make it easier to handle them. For example, commands in a shell script will be in the same process group so it's possible to **signal them together** using kill for example.\
It's also possible to **group processes in sessions**. When a process starts a session (`setsid(2)`), the children processes are set inside the session, unless they start their own session.

Coalition is another waya to group processes in Darwin. A process joining a coalation allows it to access pool resources, sharing a ledger or facing Jetsam. Coalations have different roles: Leader, XPC service, Extension.

### Credentials & Personae

Each process with hold **credentials** that **identify its privileges** in the system. Each process will have one primary `uid` and one primary `gid` (although might belong to several groups).\
It's also possible to change the user and group id if the binary has the `setuid/setgid` bit.\
There are several functions to **set new uids/gids**.

The syscall **`persona`** provides an **alternate** set of **credentials**. Adopting a persona assumes its uid, gid and group memberships **at one**. In the [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) it's possible to find the struct:

```c
struct kpersona_info { uint32_t persona_info_version;
    uid_t    persona_id; /* overlaps with UID */
    int      persona_type;
    gid_t    persona_gid;
    uint32_t persona_ngroups;
    gid_t    persona_groups[NGROUPS];
    uid_t    persona_gmuid;
    char     persona_name[MAXLOGNAME + 1];
    
    /* TODO: MAC policies?! */
}
```

## Threads Basic Information

1. **POSIX Threads (pthreads):** macOS supports POSIX threads (`pthreads`), which are part of a standard threading API for C/C++. The implementation of pthreads in macOS is found in `/usr/lib/system/libsystem_pthread.dylib`, which comes from the publicly available `libpthread` project. This library provides the necessary functions to create and manage threads.
2. **Creating Threads:** The `pthread_create()` function is used to create new threads. Internally, this function calls `bsdthread_create()`, which is a lower-level system call specific to the XNU kernel (the kernel macOS is based on). This system call takes various flags derived from `pthread_attr` (attributes) that specify thread behavior, including scheduling policies and stack size.
   * **Default Stack Size:** The default stack size for new threads is 512 KB, which is sufficient for typical operations but can be adjusted via thread attributes if more or less space is needed.
3. **Thread Initialization:** The `__pthread_init()` function is crucial during thread setup, utilizing the `env[]` argument to parse environment variables that can include details about the stack's location and size.

#### Thread Termination in macOS

1. **Exiting Threads:** Threads are typically terminated by calling `pthread_exit()`. This function allows a thread to exit cleanly, performing necessary cleanup and allowing the thread to send a return value back to any joiners.
2. **Thread Cleanup:** Upon calling `pthread_exit()`, the function `pthread_terminate()` is invoked, which handles the removal of all associated thread structures. It deallocates Mach thread ports (Mach is the communication subsystem in the XNU kernel) and calls `bsdthread_terminate`, a syscall that removes the kernel-level structures associated with the thread.

#### Synchronization Mechanisms

To manage access to shared resources and avoid race conditions, macOS provides several synchronization primitives. These are critical in multi-threading environments to ensure data integrity and system stability:

1. **Mutexes:**
   * **Regular Mutex (Signature: 0x4D555458):** Standard mutex with a memory footprint of 60 bytes (56 bytes for the mutex and 4 bytes for the signature).
   * **Fast Mutex (Signature: 0x4d55545A):** Similar to a regular mutex but optimized for faster operations, also 60 bytes in size.
2. **Condition Variables:**
   * Used for waiting for certain conditions to occur, with a size of 44 bytes (40 bytes plus a 4-byte signature).
   * **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes for condition variables, sized at 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
   * Ensures that a piece of initialization code is executed only once. Its size is 12 bytes.
4. **Read-Write Locks:**
   * Allows multiple readers or one writer at a time, facilitating efficient access to shared data.
   * **Read Write Lock (Signature: 0x52574c4b):** Sized at 196 bytes.
   * **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes for read-write locks, 20 bytes in size.

{% hint style="success" %}
The last 4 bytes of those objects are used to deetct overflows.
{% endhint %}

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** in the context of Mach-O files (the format for executables in macOS) are used to declare variables that are specific to **each thread** in a multi-threaded application. This ensures that each thread has its own separate instance of a variable, providing a way to avoid conflicts and maintain data integrity without needing explicit synchronization mechanisms like mutexes.

In C and related languages, you can declare a thread-local variable using the **`__thread`** keyword. Here’s how it works in your example:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

This snippet defines `tlv_var` as a thread-local variable. Each thread running this code will have its own `tlv_var`, and changes one thread makes to `tlv_var` will not affect `tlv_var` in another thread.

In the Mach-O binary, the data related to thread local variables is organized into specific sections:

* **`__DATA.__thread_vars`**: This section contains the metadata about the thread-local variables, like their types and initialization status.
* **`__DATA.__thread_bss`**: This section is used for thread-local variables that are not explicitly initialized. It's a part of memory set aside for zero-initialized data.

Mach-O also provides a specific API called **`tlv_atexit`** to manage thread-local variables when a thread exits. This API allows you to **register destructors**—special functions that clean up thread-local data when a thread terminates.

### Threading Priorities

Understanding thread priorities involves looking at how the operating system decides which threads to run and when. This decision is influenced by the priority level assigned to each thread. In macOS and Unix-like systems, this is handled using concepts like `nice`, `renice`, and Quality of Service (QoS) classes.

#### Nice and Renice

1. **Nice:**
   * The `nice` value of a process is a number that affects its priority. Every process has a nice value ranging from -20 (the highest priority) to 19 (the lowest priority). The default nice value when a process is created is typically 0.
   * A lower nice value (closer to -20) makes a process more "selfish," giving it more CPU time compared to other processes with higher nice values.
2. **Renice:**
   * `renice` is a command used to change the nice value of an already running process. This can be used to dynamically adjust the priority of processes, either increasing or decreasing their CPU time allocation based on new nice values.
   * For example, if a process needs more CPU resources temporarily, you might lower its nice value using `renice`.

#### Quality of Service (QoS) Classes

QoS classes are a more modern approach to handling thread priorities, particularly in systems like macOS that support **Grand Central Dispatch (GCD)**. QoS classes allow developers to **categorize** work into different levels based on their importance or urgency. macOS manages thread prioritization automatically based on these QoS classes:

1. **User Interactive:**
   * This class is for tasks that are currently interacting with the user or require immediate results to provide a good user experience. These tasks are given the highest priority to keep the interface responsive (e.g., animations or event handling).
2. **User Initiated:**
   * Tasks that the user initiates and expects immediate results, such as opening a document or clicking a button that requires computations. These are high priority but below user interactive.
3. **Utility:**
   * These tasks are long-running and typically show a progress indicator (e.g., downloading files, importing data). They are lower in priority than user-initiated tasks and do not need to finish immediately.
4. **Background:**
   * This class is for tasks that operate in the background and are not visible to the user. These can be tasks like indexing, syncing, or backups. They have the lowest priority and minimal impact on system performance.

Using QoS classes, developers do not need to manage the exact priority numbers but rather focus on the nature of the task, and the system optimizes the CPU resources accordingly.

Moreover, there are different **thread scheduling policies** that flows to specify a set of scheduling parameters that the scheduler will take into consideration. This can be done using `thread_policy_[set/get]`. This might be useful in race condition attacks.

## MacOS Process Abuse

MacOS, like any other operating system, provides a variety of methods and mechanisms for **processes to interact, communicate, and share data**. While these techniques are essential for efficient system functioning, they can also be abused by threat actors to **perform malicious activities**.

### Library Injection

Library Injection is a technique wherein an attacker **forces a process to load a malicious library**. Once injected, the library runs in the context of the target process, providing the attacker with the same permissions and access as the process.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Function Hooking

Function Hooking involves **intercepting function calls** or messages within a software code. By hooking functions, an attacker can **modify the behavior** of a process, observe sensitive data, or even gain control over the execution flow.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Inter Process Communication

Inter Process Communication (IPC) refers to different methods by which separate processes **share and exchange data**. While IPC is fundamental for many legitimate applications, it can also be misused to subvert process isolation, leak sensitive information, or perform unauthorized actions.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Electron Applications Injection

Electron applications executed with specific env variables could be vulnerable to process injection:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Chromium Injection

It's possible to use the flags `--load-extension` and `--use-fake-ui-for-media-stream` to perform a **man in the browser attack** allowing to steal keystrokes, traffic, cookies, inject scripts in pages...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Dirty NIB

NIB files **define user interface (UI) elements** and their interactions within an application. However, they can **execute arbitrary commands** and **Gatekeeper doesn't stop** an already executed application from being executed if a **NIB file is modified**. Therefore, they could be used to make arbitrary programs execute arbitrary commands:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Java Applications Injection

It's possible to abuse certain java capabilities (like the **`_JAVA_OPTS`** env variable) to make a java application execute **arbitrary code/commands**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Net Applications Injection

It's possible to inject code into .Net applications by **abusing the .Net debugging functionality** (not protected by macOS protections such as runtime hardening).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl Injection

Check different options to make a Perl script execute arbitrary code in:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby Injection

I't also possible to abuse ruby env variables to make arbitrary scripts execute arbitrary code:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Python Injection

If the environment variable **`PYTHONINSPECT`** is set, the python process will drop into a python cli once it's finished. It's also possible to use **`PYTHONSTARTUP`** to indicate a python script to execute at the beginning of an interactive session.\
However, note that **`PYTHONSTARTUP`** script won't be executed when **`PYTHONINSPECT`** creates the interactive session.

Other env variables such as **`PYTHONPATH`** and **`PYTHONHOME`** could also be useful to make a python command execute arbitrary code.

Note that executables compiled with **`pyinstaller`** won't use these environmental variables even if they are running using an embedded python.

{% hint style="danger" %}
Overall I couldn't find a way to make python execute arbitrary code abusing environment variables.\
However, most of the people install pyhton using **Hombrew**, which will install pyhton in a **writable location** for the default admin user. You can hijack it with something like:

```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```

Even **root** will run this code when running python.
{% endhint %}

## Detection

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) is an open source application that can **detect and block process injection** actions:

* Using **Environmental Variables**: It will monitor the presence of any of the following environmental variables: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** and **`ELECTRON_RUN_AS_NODE`**
* Using **`task_for_pid`** calls: To find when one process wants to get the **task port of another** which allows to inject code in the process.
* **Electron apps params**: Someone can use **`--inspect`**, **`--inspect-brk`** and **`--remote-debugging-port`** command line argument to start an Electron app in debugging mode, and thus inject code to it.
* Using **symlinks** or **hardlinks**: Typically the most common abuse is to **place a link with our user privileges**, and **point it to a higher privilege** location. The detection is very simple for both hardlink and symlinks. If the process creating the link has a **different privilege level** than the target file, we create an **alert**. Unfortunately in the case of symlinks blocking is not possible, as we don’t have information about the destination of the link prior creation. This is a limitation of Apple’s EndpointSecuriy framework.

### Calls made by other processes

In [**this blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) you can find how it's possible to use the function **`task_name_for_pid`** to get information about other **processes injecting code in a process** and then getting information about that other process.

Note that to call that function you need to be **the same uid** as the one running the process or **root** (and it returns info about the process, not a way to inject code).

## References

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

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
