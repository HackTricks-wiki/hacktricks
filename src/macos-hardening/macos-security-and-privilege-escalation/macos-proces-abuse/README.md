# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## 进程基础信息

进程是正在运行的可执行文件的实例，但是进程并不运行代码，运行代码的是线程。因此，**进程只是运行线程的容器**，为其提供内存、描述符、端口、权限等资源。

传统上，进程是在其他进程中启动的（PID 1 除外），方法是调用 **`fork`**，该调用会创建当前进程的精确副本，然后**子进程**通常会调用 **`execve`** 来加载新的可执行文件并运行它。之后，引入了 **`vfork`**，在不复制内存的情况下加快这一过程。\
随后引入了 **`posix_spawn`**，将 **`vfork`** 和 **`execve`** 合并到一次调用中，并接受以下 flags：

- `POSIX_SPAWN_RESETIDS`：将有效 id 重置为真实 id
- `POSIX_SPAWN_SETPGROUP`：设置进程组归属
- `POSUX_SPAWN_SETSIGDEF`：设置 signal 默认行为
- `POSIX_SPAWN_SETSIGMASK`：设置 signal mask
- `POSIX_SPAWN_SETEXEC`：在同一进程中执行（类似于带有更多选项的 `execve`）
- `POSIX_SPAWN_START_SUSPENDED`：以 suspended 状态启动
- `_POSIX_SPAWN_DISABLE_ASLR`：在不启用 ASLR 的情况下启动
- `_POSIX_SPAWN_NANO_ALLOCATOR:` 使用 libmalloc 的 Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 允许数据段具有 `rwx` 权限
- `POSIX_SPAWN_CLOEXEC_DEFAULT`：默认在 exec(2) 时关闭所有文件描述
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` 随机化 ASLR slide 的高位

此外，`posix_spawn` 允许指定一个 **`posix_spawnattr`** 数组，用于控制 spawned process 的某些方面，以及指定 **`posix_spawn_file_actions`** 来修改描述符的状态。

当进程终止时，它会通过 signal `SIGCHLD` 将**返回码发送给父进程**（如果父进程已终止，则新的父进程为 PID 1）。父进程需要调用 `wait4()` 或 `waitid()` 获取该值，在此之前，子进程会处于 zombie 状态：它仍会显示在列表中，但不消耗资源。

### PIDs

PIDs，即进程标识符，用于标识唯一的进程。在 XNU 中，**PIDs** 为 **64 位**，单调递增且**永不回绕**（以避免滥用）。

### 进程组、Sessions 与 Coalations

**进程**可以被加入**组**中，从而更容易对其进行管理。例如，shell script 中的命令会属于同一个进程组，因此可以使用 kill 等方式**同时向它们发送 signal**。\
也可以将**进程分组到 sessions 中**。当一个进程启动一个 session（`setsid(2)`）时，其子进程会被置于该 session 中，除非它们启动自己的 session。

Coalition 是 Darwin 中另一种对进程进行分组的方式。进程加入 coalition 后，可以访问资源池、共享 ledger 或受到 Jetsam 影响。Coalations 具有不同的角色：Leader、XPC service、Extension。

### Credentials 与 Personae

每个进程都持有用于**标识其在系统中权限的 credentials**。每个进程都有一个主要的 `uid` 和一个主要的 `gid`（尽管它可能属于多个组）。\
如果二进制文件具有 `setuid/setgid` bit，也可以更改用户和组 id。\
有多个用于**设置新的 uids/gids** 的函数。

syscall **`persona`** 提供了一组**替代的** **credentials**。采用一个 persona 会**同时**取得其 uid、gid 和组成员身份。在[**源代码**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)中，可以找到该 struct：
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

1. **POSIX Threads (pthreads)：** macOS 支持 POSIX threads（`pthreads`），它们是 C/C++ 标准 threading API 的一部分。macOS 中 pthreads 的实现位于 `/usr/lib/system/libsystem_pthread.dylib`，该实现来自公开可用的 `libpthread` project。此 library 提供创建和管理 threads 所需的 functions。
2. **创建 Threads：** `pthread_create()` function 用于创建新的 threads。在内部，此 function 会调用 `bsdthread_create()`，这是 XNU kernel（macOS 所基于的 kernel）特有的 lower-level system call。此 system call 接收源自 `pthread_attr`（attributes）的各种 flags，用于指定 thread 行为，包括 scheduling policies 和 stack size。
- **默认 Stack Size：** 新 threads 的默认 stack size 为 512 KB，足以应对典型操作；如果需要更多或更少空间，也可以通过 thread attributes 进行调整。
3. **Thread 初始化：** `__pthread_init()` function 在 thread setup 期间至关重要，它使用 `env[]` argument 解析 environment variables，其中可能包含 stack location 和 size 的详细信息。

#### macOS 中的 Thread Termination

1. **退出 Threads：** Threads 通常通过调用 `pthread_exit()` 终止。此 function 允许 thread cleanly 退出，执行必要的 cleanup，并允许 thread 向等待 join 的 threads 发送 return value。
2. **Thread Cleanup：** 调用 `pthread_exit()` 后，会调用 `pthread_terminate()` function，负责移除所有相关的 thread structures。它会释放 Mach thread ports（Mach 是 XNU kernel 中的 communication subsystem），并调用 `bsdthread_terminate`，这是一个用于移除与该 thread 关联的 kernel-level structures 的 syscall。

#### Synchronization Mechanisms

为了管理对 shared resources 的访问并避免 race conditions，macOS 提供了多种 synchronization primitives。在 multi-threading 环境中，这些机制对于确保 data integrity 和 system stability 至关重要：

1. **Mutexes：**
- **Regular Mutex（Signature：0x4D555458）：** 标准 mutex，占用 60 bytes（56 bytes 用于 mutex，4 bytes 用于 signature）。
- **Fast Mutex（Signature：0x4d55545A）：** 与 regular mutex 类似，但针对更快的 operations 进行了优化，大小同样为 60 bytes。
2. **Condition Variables：**
- 用于等待特定 conditions 发生，大小为 44 bytes（40 bytes 加上 4-byte signature）。
- **Condition Variable Attributes（Signature：0x434e4441）：** condition variables 的 configuration attributes，大小为 12 bytes。
3. **Once Variable（Signature：0x4f4e4345）：**
- 确保某段 initialization code 只执行一次。大小为 12 bytes。
4. **Read-Write Locks：**
- 允许多个 readers 或一个 writer 同时访问，从而实现对 shared data 的高效访问。
- **Read Write Lock（Signature：0x52574c4b）：** 大小为 196 bytes。
- **Read Write Lock Attributes（Signature：0x52574c41）：** read-write locks 的 attributes，大小为 20 bytes。

> [!TIP]
> 这些 objects 的最后 4 bytes 用于检测 overflows。

### Thread Local Variables (TLV)

在 Mach-O files（macOS 中 executable 的格式）中，**Thread Local Variables (TLV)** 用于声明在 multi-threaded application 中**每个 thread**专属的 variables。这确保每个 thread 都拥有 variable 的独立 instance，从而无需 mutexes 等显式 synchronization mechanisms，即可避免 conflicts 并维护 data integrity。

在 C 及相关 languages 中，可以使用 **`__thread`** keyword 声明 thread-local variable。以下是它在示例中的工作方式：
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
此代码片段将 `tlv_var` 定义为线程局部变量。运行此代码的每个线程都会拥有自己的 `tlv_var`，一个线程对 `tlv_var` 所做的修改不会影响另一个线程中的 `tlv_var`。

在 Mach-O binary 中，与线程局部变量相关的数据被组织到特定的 sections 中：

- **`__DATA.__thread_vars`**：此 section 包含线程局部变量的 metadata，例如其类型和初始化状态。
- **`__DATA.__thread_bss`**：此 section 用于存放未显式初始化的线程局部变量。这是为零初始化数据预留的一部分 memory。

Mach-O 还提供了一个名为 **`tlv_atexit`** 的专用 API，用于在线程退出时管理线程局部变量。此 API 允许你**注册 destructors**——在线程终止时清理线程局部数据的特殊函数。

### Threading Priorities

理解线程优先级，需要了解操作系统如何决定运行哪些线程以及何时运行。这一决策受到分配给每个线程的优先级影响。在 macOS 和类 Unix 系统中，这通常通过 `nice`、`renice` 和 Quality of Service (QoS) classes 等概念实现。

#### Nice and Renice

1. **Nice：**
- 进程的 `nice` 值是一个会影响其优先级的数字。每个进程的 nice 值范围为 -20（最高优先级）到 19（最低优先级）。创建进程时，默认 nice 值通常为 0。
- 较低的 nice 值（更接近 -20）会使进程更加“自私”，相比 nice 值更高的其他进程获得更多 CPU 时间。
2. **Renice：**
- `renice` 是用于修改已运行进程 nice 值的命令。可以使用它动态调整进程的优先级，根据新的 nice 值增加或减少其 CPU 时间分配。
- 例如，如果某个进程暂时需要更多 CPU 资源，可以使用 `renice` 降低其 nice 值。

#### Quality of Service (QoS) Classes

QoS classes 是一种更现代的线程优先级管理方式，尤其适用于支持 **Grand Central Dispatch (GCD)** 的系统，例如 macOS。QoS classes 允许开发者根据任务的重要性或紧迫性，将工作**分类**到不同级别。macOS 会根据这些 QoS classes 自动管理线程优先级：

1. **User Interactive：**
- 此 class 用于当前正在与用户交互或需要立即返回结果以提供良好用户体验的任务。这些任务具有最高优先级，以保持界面响应能力（例如 animations 或 event handling）。
2. **User Initiated：**
- 此 class 用于由用户发起且用户期望立即获得结果的任务，例如打开 document 或点击需要进行计算的 button。这些任务具有较高优先级，但低于 user interactive。
3. **Utility：**
- 这些任务通常运行时间较长，并且一般会显示 progress indicator（例如下载 files 或导入 data）。其优先级低于 user-initiated tasks，不需要立即完成。
4. **Background：**
- 此 class 用于在 background 中运行且用户不可见的任务，例如 indexing、syncing 或 backups。这些任务具有最低优先级，对系统性能的影响也最小。

使用 QoS classes 后，开发者无需管理具体的优先级数值，而只需关注任务的性质，系统会相应地优化 CPU 资源分配。

此外，还存在不同的 **thread scheduling policies**，用于指定一组 scheduler 会考虑的 scheduling parameters。可以使用 `thread_policy_[set/get]` 完成设置。这可能对 race condition attacks 有用。

## MacOS Process Abuse

MacOS 和其他操作系统一样，提供了多种用于让 **processes 交互、通信和共享 data** 的方法与机制。虽然这些技术对于高效运行系统至关重要，但 threat actors 也可能滥用它们来**执行 malicious activities**。

### Library Injection

Library Injection 是一种攻击者**强制进程加载 malicious library** 的技术。注入后，该 library 会在目标进程的 context 中运行，使攻击者获得与该进程相同的 permissions 和 access。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking 涉及在 software code 中**拦截 function calls** 或 messages。通过 hook functions，攻击者可以**修改进程行为**、观察敏感 data，甚至控制 execution flow。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) 是指不同独立 processes **共享和交换 data** 的各种方法。虽然 IPC 是许多合法 applications 的基础，但也可能被滥用来破坏 process isolation、leak 敏感 information 或执行未经授权的 actions。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

使用特定 env variables 执行的 Electron applications 可能容易受到 process injection 攻击：


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

可以使用 `--load-extension` 和 `--use-fake-ui-for-media-stream` flags 执行 **man in the browser attack**，从而窃取 keystrokes、traffic 和 cookies，向 pages 中注入 scripts……


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **定义 application 中的 user interface (UI) elements** 及其交互方式。然而，它们可以**执行 arbitrary commands**，并且如果已执行的 application 的 **NIB file 被修改**，**Gatekeeper 不会阻止**该 application 再次执行。因此，可以利用它们让 arbitrary programs 执行 arbitrary commands：


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

可以滥用某些 Java capabilities（例如 **`_JAVA_OPTS`** env variable），使 Java application 执行 **arbitrary code/commands**。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

可以通过**滥用 .Net debugging functionality** 向 .Net applications 注入 code（该功能不受 runtime hardening 等 macOS protections 保护）。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

查看以下不同 options，了解如何让 Perl script 执行 arbitrary code：


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

也可以滥用 Ruby env variables，使 arbitrary scripts 执行 arbitrary code：


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

如果设置了 environment variable **`PYTHONINSPECT`**，Python process 在执行结束后会进入 Python CLI。也可以使用 **`PYTHONSTARTUP`** 指定一个 Python script，使其在 interactive session 开始时执行。\
但是请注意，当 **`PYTHONINSPECT`** 创建 interactive session 时，不会执行 **`PYTHONSTARTUP`** script。

其他 env variables，例如 **`PYTHONPATH`** 和 **`PYTHONHOME`**，也可能有助于让 Python command 执行 arbitrary code。

请注意，使用 **`pyinstaller`** 编译的 executables 不会使用这些 environmental variables，即使它们运行在 embedded Python 中。

> [!CAUTION]
> 总体而言，我没有找到通过滥用 environment variables 让 Python 执行 arbitrary code 的方法。\
> 但是，大多数人通过 **Hombrew** 安装 pyhton，而 Hombrew 会将 pyhton 安装到默认 admin user 可写的 **writable location** 中。你可以使用类似以下方式劫持它：
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
> 即使是 **root**，运行 Python 时也会执行这段 code。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) 是一个基于开源 **EndpointSecurity** 的 application，用于检测和阻止 process injection。它可以很好地说明哪些 signals 确实能够从 ES 中观察到，因为它会在以下情况发出 alerts：<sup>[1]</sup>

- 进程 exec 时的 **Injection environment variables**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH` 和 `ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls —— 一个 process 请求另一个 process 的 task port，这是向其中注入 code 的前提。
- **Electron debugging arguments** —— `--inspect`、`--inspect-brk` 和 `--remote-debugging-port`。这些 arguments 会以 debug mode 启动 Electron app，并允许任何人 attach 到其中并运行 code。
- **跨 privilege levels 创建 symlink/hardlink** —— 经典的“以普通 user 创建 link，并将其指向 privileged location” primitive。请注意，**symlinks 可以被 alert，但无法被 block**：EndpointSecurity 不会在创建之前暴露 link destination。

### Calls made by other processes

在[**这篇 blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以了解如何使用 **`task_name_for_pid`** function 获取有关**向某个 process 注入 code 的其他 processes** 的信息，然后获取该其他 process 的信息。<sup>[4]</sup>

请注意，要调用该 function，你必须与运行该 process 的 user 具有**相同的 uid**，或者是 **root**（并且它返回的是有关该 process 的信息，而不是注入 code 的方法）。

## References

- [1] [Shield — 开源 macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - 为什么 Electron apps 无法机密地存储你的 secrets：--inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
