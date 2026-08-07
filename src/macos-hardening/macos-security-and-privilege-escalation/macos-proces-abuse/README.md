# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

进程是正在运行的可执行文件的实例，但进程本身不运行代码，运行代码的是线程。因此，**进程只是运行线程的容器**，为线程提供内存、描述符、端口、权限等资源。

传统上，进程会在其他进程中启动（PID 1 除外），方法是调用 **`fork`**。该调用会创建当前进程的精确副本，然后**子进程**通常会调用 **`execve`** 来加载新的可执行文件并运行它。随后引入了 **`vfork`**，在不复制内存的情况下提升这一过程的速度。\
之后又引入了 **`posix_spawn`**，将 **`vfork`** 和 **`execve`** 合并为一个调用，并接受以下标志：

- `POSIX_SPAWN_RESETIDS`：将有效 id 重置为实际 id
- `POSIX_SPAWN_SETPGROUP`：设置进程组归属
- `POSUX_SPAWN_SETSIGDEF`：设置信号默认行为
- `POSIX_SPAWN_SETSIGMASK`：设置信号掩码
- `POSIX_SPAWN_SETEXEC`：在同一进程中执行（类似带有更多选项的 `execve`）
- `POSIX_SPAWN_START_SUSPENDED`：以挂起状态启动
- `_POSIX_SPAWN_DISABLE_ASLR`：在不启用 ASLR 的情况下启动
- `_POSIX_SPAWN_NANO_ALLOCATOR:` 使用 libmalloc 的 Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 允许数据段具有 `rwx`
- `POSIX_SPAWN_CLOEXEC_DEFAULT`：默认在 exec(2) 时关闭所有文件描述
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` 随机化 ASLR 偏移的高位

此外，`posix_spawn` 允许指定一个 **`posix_spawnattr`** 数组，用于控制生成进程的某些属性；还允许指定 **`posix_spawn_file_actions`**，用于修改描述符的状态。

当进程终止时，它会通过 `SIGCHLD` 信号将**返回码发送给父进程**（如果父进程已终止，则新的父进程是 PID 1）。父进程需要调用 `wait4()` 或 `waitid()` 获取该值，在此之前，子进程会处于僵尸状态：它仍会显示在进程列表中，但不会消耗资源。

### PIDs

PID（进程标识符）用于标识唯一的进程。在 XNU 中，**PID** 为 **64 位**，单调递增且**永不回绕**（用于避免滥用）。

### Process Groups, Sessions & Coalations

可以将**进程**加入**进程组**，以便更容易地管理它们。例如，shell 脚本中的命令会处于同一个进程组中，因此可以使用 kill 等方式**统一向它们发送信号**。\
也可以将**进程分组到会话中**。当进程启动一个会话（`setsid(2)`）时，其子进程会被置于该会话中，除非它们启动自己的会话。

Coalition 是 Darwin 中另一种对进程进行分组的方式。进程加入 Coalition 后，可以访问资源池、共享 ledger 或受到 Jetsam 的管理。Coalition 具有不同的角色：Leader、XPC service、Extension。

### Credentials & Personae

每个进程都持有用于**标识其在系统中权限**的 **credentials**。每个进程都有一个主要的 `uid` 和一个主要的 `gid`（尽管它可能属于多个组）。\
如果二进制文件具有 `setuid/setgid` 位，也可以更改用户和组 id。\
有多个函数可用于**设置新的 uid/gid**。

系统调用 **`persona`** 提供了一组**替代的** **credentials**。采用某个 persona 会**同时**使用其 uid、gid 和组成员身份。在[**源代码**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)中可以找到该结构体：
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
## Threads 基本信息

1. **POSIX Threads (pthreads)：** macOS 支持 POSIX threads（`pthreads`），它们属于 C/C++ 的标准 threading API。macOS 中的 pthreads 实现在 `/usr/lib/system/libsystem_pthread.dylib`，该实现来自公开可用的 `libpthread` project。此 library 提供创建和管理 threads 所需的 functions。
2. **创建 Threads：** `pthread_create()` function 用于创建新的 threads。在内部，此 function 会调用 `bsdthread_create()`，这是 XNU kernel（macOS 所基于的 kernel）专用的较低级别 system call。该 system call 接收从 `pthread_attr`（attributes）派生的各种 flags，用于指定 thread 行为，包括 scheduling policies 和 stack size。
- **Default Stack Size：** 新 threads 的 default stack size 为 512 KB，足以应对典型操作；如果需要更多或更少空间，可以通过 thread attributes 进行调整。
3. **Thread Initialization：** `__pthread_init()` function 在 thread setup 期间非常关键，它使用 `env[]` argument 解析 environment variables，其中可能包含 stack location 和 size 等详细信息。

#### macOS 中的 Thread Termination

1. **Exiting Threads：** Threads 通常通过调用 `pthread_exit()` 终止。此 function 允许 thread cleanly exit，执行必要的 cleanup，并允许 thread 向任何 joiners 发送 return value。
2. **Thread Cleanup：** 调用 `pthread_exit()` 后，会调用 `pthread_terminate()` function，该 function 负责移除所有关联的 thread structures。它会释放 Mach thread ports（Mach 是 XNU kernel 中的 communication subsystem），并调用 `bsdthread_terminate`，这是一个用于移除与 thread 关联的 kernel-level structures 的 syscall。

#### Synchronization Mechanisms

为管理对 shared resources 的访问并避免 race conditions，macOS 提供了多种 synchronization primitives。这些机制对于 multi-threading environments 至关重要，可确保 data integrity 和 system stability：

1. **Mutexes：**
- **Regular Mutex (Signature: 0x4D555458)：** 标准 mutex，占用 60 bytes（56 bytes 用于 mutex，4 bytes 用于 signature）。
- **Fast Mutex (Signature: 0x4d55545A)：** 与 regular mutex 类似，但针对更快的操作进行了优化，大小同样为 60 bytes。
2. **Condition Variables：**
- 用于等待特定 conditions 发生，大小为 44 bytes（40 bytes 加上 4-byte signature）。
- **Condition Variable Attributes (Signature: 0x434e4441)：** 用于 condition variables 的 configuration attributes，大小为 12 bytes。
3. **Once Variable (Signature: 0x4f4e4345)：**
- 确保一段 initialization code 只执行一次。其大小为 12 bytes。
4. **Read-Write Locks：**
- 允许同时存在多个 readers，或一次存在一个 writer，从而实现对 shared data 的高效访问。
- **Read Write Lock (Signature: 0x52574c4b)：** 大小为 196 bytes。
- **Read Write Lock Attributes (Signature: 0x52574c41)：** read-write locks 的 attributes，大小为 20 bytes。

> [!TIP]
> 这些 objects 的最后 4 bytes 用于检测 overflows。

### Thread Local Variables (TLV)

在 Mach-O files（macOS 中 executables 所使用的格式）中，**Thread Local Variables (TLV)** 用于声明仅属于 multi-threaded application 中**每个 thread**的 variables。这确保每个 thread 都拥有 variable 的独立 instance，从而无需 mutexes 等显式 synchronization mechanisms 即可避免 conflicts 并维持 data integrity。

在 C 和相关 languages 中，可以使用 **`__thread`** keyword 声明 thread-local variable。以下是其在示例中的工作方式：
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
此代码片段将 `tlv_var` 定义为 thread-local variable。运行此代码的每个线程都会拥有自己的 `tlv_var`，一个线程对 `tlv_var` 所做的修改不会影响另一个线程中的 `tlv_var`。

在 Mach-O 二进制文件中，与 thread local variables 相关的数据会被组织到特定的 sections 中：

- **`__DATA.__thread_vars`**：此 section 包含 thread-local variables 的元数据，例如其类型和初始化状态。
- **`__DATA.__thread_bss`**：此 section 用于未显式初始化的 thread-local variables。它是为零初始化数据预留的一部分内存。

Mach-O 还提供了一个名为 **`tlv_atexit`** 的专用 API，用于在线程退出时管理 thread-local variables。此 API 允许你**注册 destructors**——在线程终止时清理 thread-local data 的特殊函数。

### Threading Priorities

理解线程优先级需要了解操作系统如何决定运行哪些线程以及何时运行。这一决策会受到分配给每个线程的优先级级别影响。在 macOS 和类 Unix 系统中，这通常通过 `nice`、`renice` 和 Quality of Service (QoS) classes 等概念实现。

#### Nice 和 Renice

1. **Nice：**
- 进程的 `nice` 值是一个会影响其优先级的数字。每个进程的 nice 值范围为 -20（最高优先级）到 19（最低优先级）。进程创建时的默认 nice 值通常为 0。
- 较低的 nice 值（更接近 -20）会使进程更加“自私”，与 nice 值更高的其他进程相比获得更多 CPU 时间。
2. **Renice：**
- `renice` 是一个用于修改已运行进程 nice 值的命令。可以使用它动态调整进程的优先级，根据新的 nice 值增加或减少其 CPU 时间分配。
- 例如，如果某个进程暂时需要更多 CPU 资源，可以使用 `renice` 降低其 nice 值。

#### Quality of Service (QoS) Classes

QoS classes 是一种更现代的线程优先级管理方式，尤其适用于支持 **Grand Central Dispatch (GCD)** 的系统，例如 macOS。QoS classes 允许开发者根据任务的重要性或紧迫性，将工作**分类**到不同级别。macOS 会根据这些 QoS classes 自动管理线程优先级：

1. **User Interactive：**
- 此 class 用于当前正在与用户交互或需要立即返回结果以提供良好用户体验的任务。这些任务具有最高优先级，以保持界面的响应能力（例如动画或事件处理）。
2. **User Initiated：**
- 此类任务由用户发起，并且用户期望立即获得结果，例如打开文档或点击需要进行计算的按钮。这些任务具有较高优先级，但低于 user interactive。
3. **Utility：**
- 这些任务通常运行时间较长，并且一般会显示进度指示器（例如下载文件或导入数据）。它们的优先级低于 user-initiated 任务，不需要立即完成。
4. **Background：**
- 此 class 用于在后台运行且用户不可见的任务，例如索引、同步或备份。它们具有最低优先级，对系统性能的影响也最小。

使用 QoS classes 后，开发者不需要管理具体的优先级数值，而只需关注任务的性质，系统会相应地优化 CPU 资源。

此外，还有不同的 **thread scheduling policies**，用于指定一组 scheduler 将考虑的调度参数。可以使用 `thread_policy_[set/get]` 实现。这在 race condition attacks 中可能很有用。

## MacOS Process Abuse

MacOS 与其他操作系统一样，提供了各种方法和机制，供**进程进行交互、通信和共享数据**。虽然这些技术对于系统高效运行至关重要，但 threat actors 也可能滥用它们来**执行恶意活动**。

### Library Injection

Library Injection 是一种攻击者**强制进程加载恶意 library** 的技术。注入后，该 library 会在目标进程的上下文中运行，使攻击者获得与该进程相同的权限和访问能力。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking 涉及在软件代码中**拦截函数调用**或消息。通过 hooking functions，攻击者可以**修改进程行为**、观察敏感数据，甚至控制执行流程。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) 指不同进程之间**共享和交换数据**的各种方法。虽然 IPC 是许多合法应用的基础，但也可能被滥用来破坏进程隔离、leak 敏感信息或执行未授权操作。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

使用特定 env variables 执行的 Electron applications 可能容易受到 process injection 的影响：


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

可以使用 `--load-extension` 和 `--use-fake-ui-for-media-stream` flags 执行 **man in the browser attack**，从而窃取键盘输入、流量和 cookies，并向页面注入 scripts……：


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **定义应用程序中的用户界面（UI）元素**及其交互方式。不过，它们可以**执行任意命令**，并且如果已执行的应用程序中的 **NIB file 被修改**，**Gatekeeper 不会阻止**该应用程序再次执行。因此，它们可用于让任意程序执行任意命令：


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

可以滥用某些 java capabilities（例如 **`_JAVA_OPTS`** env variable），使 java application 执行**任意 code/commands**。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

可以通过**滥用 .Net debugging functionality** 向 .Net applications 注入 code（macOS protections，例如 runtime hardening，不会对此提供保护）。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

查看以下内容中让 Perl script 执行任意 code 的不同选项：


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

还可以滥用 ruby env variables，使任意 scripts 执行任意 code：


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

如果设置了环境变量 **`PYTHONINSPECT`**，python process 将在执行结束后进入 python cli。还可以使用 **`PYTHONSTARTUP`** 指定一个 python script，使其在 interactive session 开始时执行。\
不过请注意，当 **`PYTHONINSPECT`** 创建 interactive session 时，不会执行 **`PYTHONSTARTUP`** script。

其他 env variables，例如 **`PYTHONPATH`** 和 **`PYTHONHOME`**，也可能有助于让 python command 执行任意 code。

请注意，使用 **`pyinstaller`** 编译的 executables 不会使用这些 environment variables，即使它们通过 embedded python 运行也是如此。

> [!CAUTION]
> 总体而言，我没能找到通过滥用环境变量让 python 执行任意 code 的方法。\
> 不过，大多数人使用 **Hombrew** 安装 pyhton，而它会将 pyhton 安装到默认 admin user 可写的位置。你可以使用类似下面的方式劫持它：
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> 即使是 **root**，运行 python 时也会执行这段 code。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) 是一个基于 **EndpointSecurity** 的 open source application，用于检测和阻止 process injection。它可以很好地帮助了解哪些 signals 实际上能够从 ES 中观察到，因为它会在以下情况发出警报：<sup>[[1]](#references)[[2]](#references)</sup>

- 进程 exec 时出现 **Injection environment variables**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH` 和 `ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls——一个进程请求另一个进程的 task port，这是向其注入 code 的前提条件。
- **Electron debugging arguments**——`--inspect`、`--inspect-brk` 和 `--remote-debugging-port`。这些 arguments 会以 debug mode 启动 Electron app，并允许任何人连接到其中执行 code。<sup>[[3]](#references)</sup>
- **跨 privilege levels 创建 symlink/hardlink**——经典的“以普通用户身份创建 link，再将其指向 privileged location” primitive。请注意：**symlinks 可以触发警报，但无法被阻止**：EndpointSecurity 不会在创建前公开 link destination。

### Calls made by other processes

在[**这篇 blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以了解如何使用 **`task_name_for_pid`** function 获取有关**向进程注入 code 的其他 processes**的信息，然后获取有关该其他 process 的信息。<sup>[[4]](#references)</sup>

请注意，要调用该 function，你必须与运行该 process 的用户具有**相同的 uid**，或者是 **root**（它返回的是有关该 process 的信息，而不是注入 code 的方法）。

## References

- [1] [Shield — macOS process-injection detection 的 open source tool (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - 为什么 Electron apps 无法机密地存储 secrets：--inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
