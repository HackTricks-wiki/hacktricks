# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes 基本信息

一个 process 是正在运行的 executable 的实例，但 process 并不运行 code，运行 code 的是 thread。因此，**process 只是用于运行 thread 的容器**，提供 memory、descriptor、port、permission……

传统上，process 是通过调用 **`fork`** 在其他 process（PID 1 除外）中启动的；该调用会创建当前 process 的精确副本，然后 **child process** 通常会调用 **`execve`** 来加载新的 executable 并运行它。随后引入了 **`vfork`**，使这一过程无需复制 memory，从而提高速度。\
之后引入了 **`posix_spawn`**，将 **`vfork`** 和 **`execve`** 合并到一次调用中，并接受以下 flags：

- `POSIX_SPAWN_RESETIDS`: 将 effective id 重置为 real id
- `POSIX_SPAWN_SETPGROUP`: 设置 process group 归属
- `POSUX_SPAWN_SETSIGDEF`: 设置 signal 默认行为
- `POSIX_SPAWN_SETSIGMASK`: 设置 signal mask
- `POSIX_SPAWN_SETEXEC`: 在同一个 process 中执行（类似于具有更多选项的 `execve`）
- `POSIX_SPAWN_START_SUSPENDED`: 以 suspended 状态启动
- `_POSIX_SPAWN_DISABLE_ASLR`: 在不启用 ASLR 的情况下启动
- `_POSIX_SPAWN_NANO_ALLOCATOR:` 使用 libmalloc 的 Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 允许 data segment 使用 `rwx`
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: 默认在 exec(2) 时关闭所有 file description
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` 将 ASLR slide 的高位随机化

此外，`posix_spawn` 接受用于控制 spawned process 各方面的 **`posix_spawnattr`** 设置，以及用于修改 file descriptor 的 **`posix_spawn_file_actions`** 条目。

当一个 process 终止时，它会通过 `SIGCHLD` signal 将 **return code 发送给 parent process**（如果 parent 已终止，则新的 parent 是 PID 1）。parent 需要调用 `wait4()` 或 `waitid()` 获取该值，在此之前 child 会处于 zombie 状态：它仍会显示在列表中，但不会消耗资源。

### PIDs

PIDs，即 process identifiers，用于标识唯一的 process。在 XNU 中，**PIDs** 是单调递增的 **64bits** 值，并且**永远不会回绕**（用于避免 abuse）。

### Process Groups、Sessions 和 Coalations

**Processes** 可以被加入 **groups**，以便更容易地管理它们。例如，shell script 中的 commands 会处于同一个 process group 中，因此可以使用 kill 等方式将 **signal 一起发送给它们**。\
也可以将 **processes 归入 sessions**。当一个 process 启动一个 session（`setsid(2)`）时，其 children processes 会被置于该 session 中，除非它们启动自己的 session。

Coalition 是 Darwin 中另一种用于对 processes 进行分组的方式。加入 coalition 的 process 可以访问 pool resources，共享 ledger，或受到 Jetsam 的影响。Coalitions 具有不同的 roles：Leader、XPC service、Extension。

### Credentials 和 Personae

每个 process 都持有用于**标识其在系统中权限**的 **credentials**。每个 process 都有一个 primary `uid` 和一个 primary `gid`（尽管它可能属于多个 groups）。\
如果 binary 设置了 `setuid/setgid` bit，也可以更改 user 和 group id。\
有多个用于**设置新的 uids/gids**的 functions。

syscall **`persona`** 提供一组**替代的** **credentials**。采用 persona 会**一次性**采用其 uid、gid 和 group memberships。在[**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)中可以找到该 struct：
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

1. **POSIX Threads (pthreads)：** macOS 支持 POSIX threads (`pthreads`)，它们是 C/C++ 标准 threading API 的一部分。macOS 中的 pthreads 实现位于 `/usr/lib/system/libsystem_pthread.dylib`，其来源是公开可用的 `libpthread` project。该 library 提供创建和管理 threads 所需的 functions。
2. **创建 Threads：** `pthread_create()` function 用于创建新的 threads。在内部，该 function 会调用 `bsdthread_create()`，这是 XNU kernel（macOS 所基于的 kernel）专用的更底层 system call。该 system call 接收从 `pthread_attr`（attributes）派生的各种 flags，用于指定 thread 行为，包括 scheduling policies 和 stack size。
- **默认 Stack Size：** 新 threads 的默认 stack size 为 512 KB，足以应对典型操作；如果需要更多或更少空间，可以通过 thread attributes 进行调整。
3. **Thread 初始化：** `__pthread_init()` function 在 thread setup 期间非常重要，它利用 `env[]` argument 解析 environment variables，其中可以包含 stack location 和 size 的详细信息。

#### macOS 中的 Thread Termination

1. **退出 Threads：** Threads 通常通过调用 `pthread_exit()` 终止。该 function 允许 thread 正常退出，执行必要的 cleanup，并允许 thread 向任何 joiners 发送 return value。
2. **Thread Cleanup：** 调用 `pthread_exit()` 后，会调用 `pthread_terminate()` function，负责移除所有关联的 thread structures。它会释放 Mach thread ports（Mach 是 XNU kernel 中的 communication subsystem），并调用 `bsdthread_terminate`，这是一个用于移除与该 thread 关联的 kernel-level structures 的 syscall。

#### Synchronization Mechanisms

为了管理对 shared resources 的访问并避免 race conditions，macOS 提供了多种 synchronization primitives。这些机制对于 multi-threading environments 至关重要，可确保 data integrity 和 system stability：

1. **Mutexes：**
- **Regular Mutex (Signature: 0x4D555458)：** 标准 mutex，占用 60 bytes 的 memory footprint（56 bytes 用于 mutex，4 bytes 用于 signature）。
- **Fast Mutex (Signature: 0x4d55545A)：** 与 regular mutex 类似，但针对更快的 operations 进行了优化，大小同样为 60 bytes。
2. **Condition Variables：**
- 用于等待特定 conditions 发生，大小为 44 bytes（40 bytes 加 4-byte signature）。
- **Condition Variable Attributes (Signature: 0x434e4441)：** condition variables 的 configuration attributes，大小为 12 bytes。
3. **Once Variable (Signature: 0x4f4e4345)：**
- 确保某段 initialization code 只执行一次。其大小为 12 bytes。
4. **Read-Write Locks：**
- 允许同时存在多个 readers，或一次存在一个 writer，从而实现对 shared data 的高效访问。
- **Read Write Lock (Signature: 0x52574c4b)：** 大小为 196 bytes。
- **Read Write Lock Attributes (Signature: 0x52574c41)：** read-write locks 的 attributes，大小为 20 bytes。

> [!TIP]
> 这些 objects 的最后 4 bytes 用于检测 overflows。

### Thread Local Variables (TLV)

在 Mach-O files（macOS 中 executables 所使用的格式）中，**Thread Local Variables (TLV)** 用于声明在 multi-threaded application 中专属于**每个 thread**的 variables。这确保每个 thread 都拥有某个 variable 的独立 instance，从而无需 mutexes 等显式 synchronization mechanisms 即可避免 conflicts 并维护 data integrity。

在 C 及相关 languages 中，可以使用 **`__thread`** keyword 声明 thread-local variable。以下是其在示例中的工作方式：
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
此代码片段将 `tlv_var` 定义为 thread-local 变量。运行此代码的每个线程都会拥有自己的 `tlv_var`，一个线程对 `tlv_var` 所做的更改不会影响另一个线程中的 `tlv_var`。

在 Mach-O binary 中，与 thread local 变量相关的数据被组织在特定 sections 中：

- **`__DATA.__thread_vars`**：此 section 包含 thread-local 变量的 metadata，例如其类型和初始化状态。
- **`__DATA.__thread_bss`**：此 section 用于存储未显式初始化的 thread-local 变量。它是一段专门用于存放零初始化数据的 memory。

Mach-O 还提供了一个名为 **`tlv_atexit`** 的专用 API，用于在线程退出时管理 thread-local 变量。此 API 允许你**注册 destructors**——在线程终止时清理 thread-local 数据的特殊函数。

### Threading Priorities

理解 thread priorities 需要了解 operating system 如何决定运行哪些线程以及何时运行。这个决策会受到分配给每个线程的 priority level 影响。在 macOS 和 Unix-like systems 中，这通常通过 `nice`、`renice` 和 Quality of Service (QoS) classes 等概念实现。

#### Nice and Renice

1. **Nice：**
- 进程的 `nice` value 是一个会影响其 priority 的数字。每个进程的 nice value 范围为 -20（最高 priority）到 19（最低 priority）。进程创建时的默认 nice value 通常为 0。
- 较低的 nice value（接近 -20）会使进程更加“自私”，相比 nice value 较高的其他进程获得更多 CPU time。
2. **Renice：**
- `renice` 是用于更改已运行进程 nice value 的 command。可以使用它动态调整进程的 priority，根据新的 nice value 增加或减少其 CPU time allocation。
- 例如，如果某个进程暂时需要更多 CPU resources，可以使用 `renice` 降低其 nice value。

#### Quality of Service (QoS) Classes

QoS classes 是一种更现代的 thread priorities 管理方式，尤其适用于支持 **Grand Central Dispatch (GCD)** 的系统，例如 macOS。QoS classes 允许 developers 根据 work 的重要性或紧急程度，将其**分类**到不同 level。macOS 会根据这些 QoS classes 自动管理 thread prioritization：

1. **User Interactive：**
- 此 class 用于当前正在与 user 交互或需要立即返回结果以提供良好 user experience 的 tasks。这些 tasks 会获得最高 priority，以保持 interface 的响应能力（例如 animations 或 event handling）。
2. **User Initiated：**
- 由 user 发起且 user 期望立即得到结果的 tasks，例如打开 document 或点击需要执行 computations 的 button。这些 tasks 的 priority 较高，但低于 user interactive。
3. **Utility：**
- 这些 tasks 通常运行时间较长，并会显示 progress indicator（例如 downloading files、importing data）。它们的 priority 低于 user-initiated tasks，不需要立即完成。
4. **Background：**
- 此 class 用于在 background 中运行且 user 不可见的 tasks。这些 tasks 可以是 indexing、syncing 或 backups。它们拥有最低 priority，对 system performance 的影响也最小。

使用 QoS classes 后，developers 无需管理确切的 priority numbers，而是关注 task 的性质，由 system 依此优化 CPU resources。

此外，还有不同的 **thread scheduling policies**，用于指定一组 scheduler 会考虑的 scheduling parameters。可以使用 `thread_policy_[set/get]` 完成。这可能对 race condition attacks 有用。

## macOS Process Abuse

macOS 提供了许多机制，使 **processes 能够交互、通信和共享 data**。尽管这些机制对 system 的正常运行必不可少，但 attackers 可能滥用它们进行 injection、code execution 或 data access。

### Library Injection

Library Injection 是一种攻击者**强制进程加载 malicious library** 的 technique。注入后，该 library 会在 target process 的 context 中运行，使 attacker 获得与该 process 相同的 permissions 和 access。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking 涉及在 software code 中**拦截 function calls** 或 messages。通过 hooking functions，attacker 可以**修改 process 的行为**、观察 sensitive data，甚至控制 execution flow。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) 指不同 processes **共享和交换 data** 的各种 methods。虽然 IPC 是许多 legitimate applications 的基础，但也可能被滥用来破坏 process isolation、leak sensitive information 或执行 unauthorized actions。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

使用特定 env variables 执行的 Electron applications 可能存在 process injection 漏洞：


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

可以使用 `--load-extension` 和 `--use-fake-ui-for-media-stream` flags 执行 **man in the browser attack**，从而窃取 keystrokes、traffic、cookies，向 pages 中注入 scripts……：


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **定义 application 中的 user interface (UI) elements** 及其 interactions。然而，它们可以**执行 arbitrary commands**，并且如果某个 **NIB file 被修改**，Gatekeeper **不会阻止**已经执行的 application 再次执行。因此，可以利用它们让 arbitrary programs 执行 arbitrary commands：


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

可以通过 **`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`** 或 **`JDK_JAVA_OPTIONS`** 注入 JVM options，并在 application 启动前加载 Java 或 native agent。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** 通过 `--require`（file）或 `--import data:text/javascript,…`（fileless，Node ≥ 20.6）预加载 attacker JavaScript；**`NODE_REPL_EXTERNAL_MODULE`** 将 module 加载到 interactive REPL 中，而 **`ELECTRON_RUN_AS_NODE`** 会在 Electron binaries 上重新启用上述全部功能。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

可以在 `Main` 之前通过 **`DOTNET_STARTUP_HOOKS`** 向 .NET applications 注入 code，或者在满足 prerequisites 时滥用 .NET debugging functionality。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash 会读取 **`BASH_ENV`**；interactive POSIX shells 会读取 **`ENV`**；zsh 会读取 **`$ZDOTDIR/.zshenv`**；fish 会读取 **`XDG_CONFIG_HOME`** 或 **`XDG_DATA_DIRS`** 下的 configuration。每一种 shell 都能在 intended command 执行前执行受控 startup file。启用 xtrace 时，Bash 还会运行放置在 **`PS4`** 中的 command substitution（例如继承 **`SHELLOPTS=xtrace`**）：

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** 或 **`PHP_INI_SCAN_DIR`** 可以加载受控 PHP configuration，其中的 **`auto_prepend_file`** 会在 target script 之前执行。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

standalone Lua interpreter 会在处理 target script 前，从 **`LUA_INIT`**（或其 version-specific variant）执行 code 或 `@file`。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** 和 **`R_PROFILE`** 会重定向包含 R code 的 startup profiles。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** 加上 R library path，则可以改为自动加载已安装的 package。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** 会重定向 depot，其 `config/startup.jl` 会被自动执行。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`** 或 **`ERL_ZFLAGS`** 可以注入 Erlang VM **`-eval`** expression，而无需 payload file；Elixir workloads 通常会启动相同的 VM。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 和 **`OCTAVE_VERSION_INITFILE`** 会重定向 Octave startup scripts。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` 是一个 cross-platform .NET app，因此多个 environment variables 可以实现 pre-command execution：**`XDG_CONFIG_HOME`** 会重定向 startup 时运行的 profile scripts，**`PSModulePath`** 会劫持 module auto-loading（植入的 `.psm1` 会在 import 时运行，并可以 shadow built-in cmdlets），而 .NET 的 **`CORECLR_PROFILER`**/**`COR_PROFILER`** 和 **`DOTNET_STARTUP_HOOKS`** variables 会在 `Main` 之前将 attacker code 加载到 process 中。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

检查不同 options，使 Perl script 在以下位置执行 arbitrary code：


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

同样可以滥用 ruby env variables（**`RUBYOPT`**、**`RUBYLIB`**），使 arbitrary scripts 执行 arbitrary code：


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** 和 **`BROWSER`** standard-library chain 可以在 warning-filter parsing 期间执行 command。基于 file 的 alternative 会将 `sitecustomize.py` 放在 **`PYTHONPATH`** 中，使正常的 `site` initialization 在 target script 之前 import 它。**`PYTHONBREAKPOINT`** 会在 code 执行到 `breakpoint()` 时运行指定的 callable/module。仅用于 interactive 的 variables（例如 **`PYTHONSTARTUP`**）适用范围更窄。

注意，即使使用 embedded python 运行，使用 **`pyinstaller`** 编译的 executables 也不会使用这些 environmental variables。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`**（以及其 **`EXINIT`** fallback）会在正常 startup 时作为 Ex commands 执行，因此当 victim 在受控 environment 中打开 Vim/Neovim 时，`:!cmd` / `:call system(...)` 可以实现 code execution：

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

此外，Homebrew 通常会将 Python 安装在 `/opt/homebrew` 下，本地 `admin` group 的 members 可能能够替换 launcher。这属于 writable-binary hijack，而不是 environment-variable injection；在判断其是否可利用前，应验证 ownership 和 ACLs。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) 是一个基于 **EndpointSecurity** 的 open-source application，用于检测和阻止 process injection。它可以作为参考，帮助了解哪些 signals 能够通过 Endpoint Security 观察到，因为它会在以下情况发出 alerts：<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec 时出现 **injection environment variables**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH` 和 `ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls——一个 process 请求另一个 process 的 task port，这是向其中注入 code 的 prerequisite。
- **Electron debugging arguments**——`--inspect`、`--inspect-brk` 和 `--remote-debugging-port`，它们会以 debug mode 启动 Electron app，并允许任何人 attach 到其中执行 code。<sup>[[3]](#references)</sup>
- **跨 privilege levels 创建 symlink/hardlink**——经典的“以 normal user 身份植入 link，并将其指向 privileged location” primitive。注意，**symlinks 可以被 alert，但无法被 block**：EndpointSecurity 不会在 link 创建前暴露其 destination。

### Calls made by other processes

在[**这篇 blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以了解如何使用 **`task_name_for_pid`** function 获取有关**在某个 process 中注入 code 的其他 processes**的信息，然后获取该其他 process 的信息。<sup>[[4]](#references)</sup>

注意，调用该 function 需要与你运行该 process 的 uid **相同**，或拥有 **root** 权限（它会返回有关该 process 的信息，但不能用于注入 code）。

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - 为什么 Electron apps 无法以 confidentially 存储你的 secrets：--inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - 检测 task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
