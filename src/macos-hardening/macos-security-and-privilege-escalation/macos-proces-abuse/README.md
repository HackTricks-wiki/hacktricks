# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

进程是正在运行的可执行文件的一个实例，但进程本身不运行代码，运行代码的是线程。因此，**进程只是运行线程的容器**，为其提供内存、描述符、端口、权限……

传统上，进程是在其他进程（PID 1 除外）中通过调用 **`fork`** 启动的；该调用会创建当前进程的精确副本，随后**子进程**通常会调用 **`execve`** 来加载新的可执行文件并运行它。之后，引入了 **`vfork`**，通过避免内存复制来加快这一过程。\
随后引入了 **`posix_spawn`**，将 **`vfork`** 和 **`execve`** 合并到一次调用中，并接受以下 flags：

- `POSIX_SPAWN_RESETIDS`：将有效 id 重置为真实 id
- `POSIX_SPAWN_SETPGROUP`：设置进程组归属
- `POSUX_SPAWN_SETSIGDEF`：设置 signal 默认行为
- `POSIX_SPAWN_SETSIGMASK`：设置 signal mask
- `POSIX_SPAWN_SETEXEC`：在同一进程中执行（类似带有更多选项的 `execve`）
- `POSIX_SPAWN_START_SUSPENDED`：以 suspended 状态启动
- `_POSIX_SPAWN_DISABLE_ASLR`：在不启用 ASLR 的情况下启动
- `_POSIX_SPAWN_NANO_ALLOCATOR:` 使用 libmalloc 的 Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 允许数据段具有 `rwx` 权限
- `POSIX_SPAWN_CLOEXEC_DEFAULT`：默认在 exec(2) 时关闭所有文件描述
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` 随机化 ASLR slide 的高位

此外，`posix_spawn` 接受用于控制 spawned process 各方面的 **`posix_spawnattr`** 设置，以及用于修改文件描述符的 **`posix_spawn_file_actions`** 条目。

进程终止时，会通过 `SIGCHLD` signal 将**返回码发送给父进程**（如果父进程已终止，则新父进程为 PID 1）。父进程需要调用 `wait4()` 或 `waitid()` 获取该值，在此之前，子进程会处于 zombie 状态：它仍会被列出，但不会消耗资源。

### PIDs

PIDs，即进程标识符，用于标识一个唯一进程。在 XNU 中，**PIDs** 是 **64 位**、单调递增且**永不回绕**的（用于避免 abuse）。

### Process Groups, Sessions & Coalations

可以将**进程**加入**组**中，以便更容易地管理它们。例如，shell script 中的命令会处于同一个进程组中，因此可以使用 kill 等方式将 **signal 一起发送给它们**。\
也可以将**进程分组到 sessions 中**。当进程启动一个 session（`setsid(2)`）时，其子进程会被置于该 session 中，除非它们启动自己的 session。

Coalition 是 Darwin 中另一种对进程进行分组的方式。进程加入 coalition 后，可以访问 pool resources、共享 ledger 或受到 Jetsam 的影响。Coalition 具有不同的 roles：Leader、XPC service、Extension。

### Credentials & Personae

每个进程都持有用于**标识其在系统中权限**的 **credentials**。每个进程都会有一个主要的 `uid` 和一个主要的 `gid`（尽管它可能属于多个组）。\
如果 binary 具有 `setuid/setgid` bit，也可以更改 user 和 group id。\
有多个函数可用于**设置新的 uids/gids**。

syscall **`persona`** 提供一组**替代的****credentials**。采用一个 persona 会**同时**继承其 uid、gid 和组成员资格。在[**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)中，可以找到该 struct：
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

1. **POSIX Threads (pthreads)：** macOS 支持 POSIX threads（`pthreads`），它是 C/C++ 标准 threading API 的一部分。macOS 中的 pthreads 实现在 `/usr/lib/system/libsystem_pthread.dylib`，该实现来自公开可用的 `libpthread` project。此 library 提供创建和管理 threads 所需的 functions。
2. **Creating Threads：** `pthread_create()` function 用于创建新的 threads。在内部，该 function 会调用 `bsdthread_create()`，这是 XNU kernel（macOS 所基于的 kernel）特有的较低级别 system call。此 system call 接收从 `pthread_attr`（attributes）派生的各种 flags，用于指定 thread 行为，包括 scheduling policies 和 stack size。
- **Default Stack Size：** 新 threads 的默认 stack size 为 512 KB，足以应对典型操作；如果需要更多或更少空间，也可以通过 thread attributes 进行调整。
3. **Thread Initialization：** `__pthread_init()` function 在 thread setup 期间非常重要，它使用 `env[]` argument 解析 environment variables，其中可能包含 stack location 和 size 等详细信息。

#### macOS 中的 Thread Termination

1. **Exiting Threads：** Threads 通常通过调用 `pthread_exit()` 终止。此 function 允许 thread 正常退出，执行必要的 cleanup，并允许 thread 向任何 joiners 发送 return value。
2. **Thread Cleanup：** 调用 `pthread_exit()` 后，会调用 `pthread_terminate()` function，该 function 负责移除所有相关的 thread structures。它会释放 Mach thread ports（Mach 是 XNU kernel 中的 communication subsystem），并调用 `bsdthread_terminate`，这是一个用于移除与 thread 关联的 kernel-level structures 的 syscall。

#### Synchronization Mechanisms

为管理对 shared resources 的访问并避免 race conditions，macOS 提供了多种 synchronization primitives。在 multi-threading 环境中，这些机制对于确保 data integrity 和 system stability 至关重要：

1. **Mutexes：**
- **Regular Mutex (Signature: 0x4D555458)：** 标准 mutex，占用 60 bytes（56 bytes 用于 mutex，4 bytes 用于 signature）。
- **Fast Mutex (Signature: 0x4d55545A)：** 与 regular mutex 类似，但针对更快的操作进行了优化，大小同样为 60 bytes。
2. **Condition Variables：**
- 用于等待特定 conditions 发生，大小为 44 bytes（40 bytes 加上 4-byte signature）。
- **Condition Variable Attributes (Signature: 0x434e4441)：** condition variables 的 configuration attributes，大小为 12 bytes。
3. **Once Variable (Signature: 0x4f4e4345)：**
- 确保一段 initialization code 只执行一次。其大小为 12 bytes。
4. **Read-Write Locks：**
- 允许同时存在多个 readers，或一次存在一个 writer，从而实现对 shared data 的高效访问。
- **Read Write Lock (Signature: 0x52574c4b)：** 大小为 196 bytes。
- **Read Write Lock Attributes (Signature: 0x52574c41)：** read-write locks 的 attributes，大小为 20 bytes。

> [!TIP]
> 这些 objects 的最后 4 bytes 用于检测 overflows。

### Thread Local Variables (TLV)

在 Mach-O files（macOS 中 executables 所使用的格式）中，**Thread Local Variables (TLV)** 用于声明仅属于 multi-threaded application 中**每个 thread**的 variables。这确保每个 thread 都拥有 variable 的独立实例，从而无需 mutexes 等显式 synchronization mechanisms 即可避免 conflicts 并维护 data integrity。

在 C 及相关 languages 中，可以使用 **`__thread`** keyword 声明 thread-local variable。以下是其在示例中的工作方式：
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
此代码片段将 `tlv_var` 定义为线程局部变量。运行此代码的每个线程都会拥有自己的 `tlv_var`，一个线程对 `tlv_var` 所做的修改不会影响另一个线程中的 `tlv_var`。

在 Mach-O 二进制文件中，与线程局部变量相关的数据被组织在特定 section 中：

- **`__DATA.__thread_vars`**：此 section 包含线程局部变量的元数据，例如其类型和初始化状态。
- **`__DATA.__thread_bss`**：此 section 用于存储未显式初始化的线程局部变量。它是为零初始化数据预留的一部分内存。

Mach-O 还提供了一个名为 **`tlv_atexit`** 的专用 API，用于在线程退出时管理线程局部变量。此 API 允许你**注册析构函数**——在线程终止时清理线程局部数据的特殊函数。

### Threading Priorities

理解线程优先级需要了解操作系统如何决定运行哪些线程以及何时运行。这一决策会受到分配给每个线程的优先级级别影响。在 macOS 和类 Unix 系统中，这通常通过 `nice`、`renice` 和 Quality of Service（QoS）类等概念实现。

#### Nice and Renice

1. **Nice：**
- 进程的 `nice` 值是一个会影响其优先级的数字。每个进程的 nice 值范围为 -20（最高优先级）到 19（最低优先级）。进程创建时的默认 nice 值通常为 0。
- 较低的 nice 值（更接近 -20）会使进程更加“自私”，与 nice 值更高的其他进程相比获得更多 CPU 时间。
2. **Renice：**
- `renice` 是用于更改已运行进程 nice 值的命令。可以根据新的 nice 值动态调整进程的优先级，从而增加或减少其 CPU 时间分配。
- 例如，如果某个进程暂时需要更多 CPU 资源，可以使用 `renice` 降低其 nice 值。

#### Quality of Service (QoS) Classes

QoS 类是处理线程优先级的一种更现代的方法，尤其适用于支持 **Grand Central Dispatch (GCD)** 的 macOS 等系统。QoS 类允许开发者根据任务的重要性或紧迫性，将工作**分类**到不同级别。macOS 会根据这些 QoS 类自动管理线程优先级：

1. **User Interactive：**
- 此类用于当前正在与用户交互或需要立即返回结果以提供良好用户体验的任务。这些任务具有最高优先级，以保持界面响应（例如动画或事件处理）。
2. **User Initiated：**
- 此类用于由用户发起并期望立即得到结果的任务，例如打开文档或点击需要执行计算的按钮。这些任务具有较高优先级，但低于 User Interactive。
3. **Utility：**
- 此类用于长时间运行且通常会显示进度指示器的任务（例如下载文件或导入数据）。它们的优先级低于用户发起的任务，不需要立即完成。
4. **Background：**
- 此类用于在后台运行且用户不可见的任务。这些任务可以是索引、同步或备份等。它们的优先级最低，对系统性能的影响也最小。

使用 QoS 类后，开发者无需管理具体的优先级数值，而只需关注任务的性质，系统会相应地优化 CPU 资源。

此外，还存在不同的**线程调度策略**，用于指定一组调度参数，调度器会在调度时考虑这些参数。可以使用 `thread_policy_[set/get]` 完成设置。这可能对 race condition attacks 有用。

## macOS Process Abuse

macOS 提供了许多用于让**进程交互、通信和共享数据**的机制。尽管这些机制对系统正常运行至关重要，但攻击者可能滥用它们进行注入、代码执行或数据访问。

### Library Injection

Library Injection 是一种攻击者**强制进程加载恶意 library** 的技术。注入后，该 library 会在目标进程的上下文中运行，使攻击者获得与该进程相同的权限和访问能力。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking 涉及在软件代码中**拦截函数调用**或消息。通过 hook 函数，攻击者可以**修改**进程行为、观察敏感数据，甚至控制执行流程。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) 是指独立进程之间**共享和交换数据**的不同方法。虽然 IPC 是许多合法应用的基础，但也可能被滥用于破坏进程隔离、leak 敏感信息或执行未授权操作。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

使用特定环境变量执行的 Electron 应用可能容易受到 process injection 攻击：


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

可以使用 `--load-extension` 和 `--use-fake-ui-for-media-stream` flags 执行 **man in the browser attack**，从而窃取按键输入和流量、获取 cookies、向页面注入 scripts……


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB 文件**定义应用中的用户界面（UI）元素**及其交互方式。不过，它们可以**执行任意命令**，并且如果已执行的应用被修改了 **NIB file**，**Gatekeeper 不会阻止**该应用再次执行。因此，可以利用它们让任意程序执行任意命令：


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

可以通过 **`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`** 或 **`JDK_JAVA_OPTIONS`** 注入 JVM options，并在应用启动前加载 Java 或 native agent。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

可以通过 **`DOTNET_STARTUP_HOOKS`** 在 `Main` 之前向 .NET 应用注入代码，或者在满足前置条件时滥用 .NET debugging 功能。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非交互式 Bash 会读取 **`BASH_ENV`**；zsh 会读取 **`$ZDOTDIR/.zshenv`**；fish 会读取 **`XDG_CONFIG_HOME`** 或 **`XDG_DATA_DIRS`** 下的配置。每种 shell 都可以在预期命令执行前执行受控的启动文件：

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** 或 **`PHP_INI_SCAN_DIR`** 可以加载受控的 PHP 配置，其中的 **`auto_prepend_file`** 会在目标 script 执行前执行。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

独立的 Lua interpreter 会在处理目标 script 前，从 **`LUA_INIT`**（或其特定版本变体）执行代码或 `@file`。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** 和 **`R_PROFILE`** 会重定向包含 R 代码的启动 profiles。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** 加上 R library path，则可以自动加载已安装的 package。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** 会重定向 depot，其 `config/startup.jl` 会被自动执行。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`** 或 **`ERL_ZFLAGS`** 可以注入 Erlang VM **`-eval`** expression，无需 payload file；Elixir workloads 通常会启动相同的 VM。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 和 **`OCTAVE_VERSION_INITFILE`** 会重定向 Octave startup scripts。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

在 macOS 和 Linux 上，**`XDG_CONFIG_HOME`** 可以重定向 PowerShell user profiles；这些 profiles 会在 `pwsh` 启动时执行。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

查看不同的 options，使 Perl script 在以下位置执行任意代码：


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

也可以滥用 ruby environment variables，使任意 scripts 执行任意代码：


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** 和 **`BROWSER`** standard-library chain 可以在解析 warning-filter 时执行命令。一种基于文件的替代方法是将 `sitecustomize.py` 放入 **`PYTHONPATH`**，这样正常的 `site` initialization 会在目标 script 之前导入它。仅适用于 interactive 的变量（例如 **`PYTHONSTARTUP`**）适用范围更窄。

请注意，即使使用 embedded python 运行，使用 **`pyinstaller`** 编译的 executables 也不会使用这些 environment variables。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

另外，Homebrew 通常会将 Python 安装在 `/opt/homebrew` 下，当地 `admin` group 的成员可能能够替换 launcher。这属于 writable-binary hijack，而不是 environment-variable injection；在判断其是否可利用前，请确认 ownership 和 ACLs。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) 是一个基于开源 **EndpointSecurity** 的 application，用于检测并阻止 process injection。它是一个很好的参考，可以了解哪些 signals 能够通过 Endpoint Security 观察到，因为它会在以下情况发出 alert：<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- 进程 exec 时出现**注入环境变量**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH` 和 `ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls —— 一个进程请求另一个进程的 task port，这是向其注入代码的前置条件。
- **Electron debugging arguments** —— `--inspect`、`--inspect-brk` 和 `--remote-debugging-port`。这些参数会以 debug mode 启动 Electron application，并允许任何人 attach 到其中执行代码。<sup>[[3]](#references)</sup>
- **跨 privilege levels 创建 symlink/hardlink** —— 经典的“以普通用户身份创建 link，再将其指向 privileged location”原语。请注意，**可以对 symlinks 发出 alert，但无法阻止它们**：EndpointSecurity 不会在创建 link 之前公开其 destination。

### Calls made by other processes

在[**这篇 blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以了解如何使用 **`task_name_for_pid`** function 获取有关**向进程注入代码的其他 processes**的信息，然后获取有关该其他 process 的信息。<sup>[[4]](#references)</sup>

请注意，调用该 function 时，你必须与运行该 process 的用户具有**相同的 uid**，或者必须是 **root**（并且它返回的是有关该 process 的信息，而不是注入代码的方法）。

## References

- [1] [Shield — 开源 macOS process-injection detection（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
