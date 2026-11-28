# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## 进程基本信息

进程是正在运行的可执行文件的实例，不过进程并不运行代码，运行代码的是线程。因此，**进程只是运行线程的容器**，提供内存、描述符、端口、权限……

传统上，进程是在其他进程内启动的（PID 1 除外），方法是调用 **`fork`**，它会创建当前进程的精确副本；随后，**子进程**通常会调用 **`execve`** 来加载新的可执行文件并运行。之后，引入了 **`vfork`**，使这个过程无需复制内存即可更快完成。\
随后引入了 **`posix_spawn`**，将 **`vfork`** 和 **`execve`** 合并为一次调用，并接受以下 flags：

- `POSIX_SPAWN_RESETIDS`: 将有效 id 重置为真实 id
- `POSIX_SPAWN_SETPGROUP`: 设置进程组归属
- `POSUX_SPAWN_SETSIGDEF`: 设置 signal 默认行为
- `POSIX_SPAWN_SETSIGMASK`: 设置 signal mask
- `POSIX_SPAWN_SETEXEC`: 在同一进程中执行（类似带有更多选项的 `execve`）
- `POSIX_SPAWN_START_SUSPENDED`: 以挂起状态启动
- `_POSIX_SPAWN_DISABLE_ASLR`: 启动时不启用 ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` 使用 libmalloc 的 Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 允许数据段具有 `rwx` 权限
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: 默认在 exec(2) 时关闭所有文件描述
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` 随机化 ASLR slide 的高位

此外，`posix_spawn` 接受用于控制生成进程各方面的 **`posix_spawnattr`** 设置，以及用于修改文件描述符的 **`posix_spawn_file_actions`** 条目。

进程退出时，会通过 signal `SIGCHLD` 将**返回码发送给父进程**（如果父进程已退出，则新父进程为 PID 1）。父进程需要调用 `wait4()` 或 `waitid()` 获取此值；在此之前，子进程会处于僵尸状态，仍会出现在进程列表中，但不会消耗资源。

### PIDs

PID（进程标识符）用于标识一个唯一进程。在 XNU 中，**PID** 是 **64 位**的，单调递增且**永不回绕**（以避免滥用）。

### 进程组、会话与 Coalations

**进程**可以加入**组**，以便于统一管理。例如，shell 脚本中的命令会处于同一个进程组，因此可以使用 kill 等方式**向它们一起发送 signal**。\
进程也可以**组成会话**。当进程启动一个会话（`setsid(2)`）时，其子进程会加入该会话，除非它们启动自己的会话。

Coalition 是 Darwin 中另一种对进程分组的方式。进程加入 coalition 后，可以访问资源池、共享 ledger 或受到 Jetsam 管理。Coalition 有不同的角色：Leader、XPC service、Extension。

### Credentials 与 Personae

每个进程都持有**用于标识其在系统中权限的 credentials**。每个进程都有一个主要的 `uid` 和一个主要的 `gid`（但可能属于多个组）。\
如果二进制文件设置了 `setuid/setgid` 位，也可以更改用户和组 ID。\
有多个函数可以**设置新的 uids/gids**。

系统调用 **`persona`** 提供一组**备用**的 **credentials**。采用某个 persona 时，会**同时**使用其 uid、gid 和组成员身份。在[**源代码**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)中可以找到这个 struct：

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

1. **POSIX Threads (pthreads)：** macOS 支持 POSIX threads（`pthreads`），它是 C/C++ 的标准线程 API 的一部分。macOS 中 pthreads 的实现位于 `/usr/lib/system/libsystem_pthread.dylib`，该库来自公开的 `libpthread` 项目。这个库提供了创建和管理线程所需的函数。
2. **创建线程：** `pthread_create()` 函数用于创建新线程。该函数内部会调用 `bsdthread_create()`，这是 XNU kernel（macOS 所基于的 kernel）专用的较底层系统调用。此系统调用会接收从 `pthread_attr`（属性）派生的各种 flags，用于指定线程行为，包括调度策略和 stack 大小。
   - **默认 Stack 大小：** 新线程的默认 stack 大小为 512 KB，足以应对常见操作；如果需要更多或更少空间，可以通过线程属性进行调整。
3. **线程初始化：** `__pthread_init()` 函数在线程设置过程中至关重要，它使用 `env[]` 参数解析环境变量，这些变量可能包含 stack 的位置和大小等信息。

#### macOS 中的线程终止

1. **退出线程：** 通常通过调用 `pthread_exit()` 终止线程。此函数允许线程正常退出，执行必要的清理工作，并向任何等待 join 的线程返回一个值。
2. **线程清理：** 调用 `pthread_exit()` 后，会调用 `pthread_terminate()`，该函数负责移除所有相关的线程结构。它会释放 Mach thread ports（Mach 是 XNU kernel 中的通信子系统），并调用 `bsdthread_terminate`，这是一个用于移除与该线程关联的 kernel 级结构的 syscall。

#### 同步机制

为了管理对共享资源的访问并避免 race condition，macOS 提供了多种同步原语。这些原语在 multi-threading 环境中至关重要，有助于确保数据完整性和系统稳定性：

1. **Mutexes：**
   - **普通 Mutex（Signature: 0x4D555458）：** 标准 mutex，占用 60 bytes（56 bytes 用于 mutex，4 bytes 用于 signature）。
   - **Fast Mutex（Signature: 0x4d55545A）：** 类似于普通 mutex，但针对更快的操作进行了优化，大小同样为 60 bytes。
2. **Condition Variables：**
   - 用于等待特定条件发生，大小为 44 bytes（40 bytes 加上 4-byte signature）。
   - **Condition Variable Attributes（Signature: 0x434e4441）：** condition variables 的配置属性，大小为 12 bytes。
3. **Once Variable（Signature: 0x4f4e4345）：**
   - 确保一段初始化代码只执行一次，大小为 12 bytes。
4. **Read-Write Locks：**
   - 允许多个 reader 同时访问，或一次只有一个 writer，从而高效访问共享数据。
   - **Read Write Lock（Signature: 0x52574c4b）：** 大小为 196 bytes。
   - **Read Write Lock Attributes（Signature: 0x52574c41）：** read-write locks 的属性，大小为 20 bytes。

> [!TIP]
> 这些对象的最后 4 bytes 用于检测溢出。

### Thread Local Variables (TLV)

在 Mach-O 文件（macOS 中可执行文件的格式）中，**Thread Local Variables (TLV)** 用于声明在 multi-threaded 应用程序中**每个线程各自拥有**的变量。这确保每个线程都有自己的变量实例，从而避免冲突并维护数据完整性，而无需使用 mutexes 等显式同步机制。

在 C 及相关语言中，可以使用 **`__thread`** 关键字声明 thread-local 变量。下面说明了它在示例中的工作方式：

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

这个代码片段将 `tlv_var` 定义为线程局部变量。运行此代码的每个线程都会有自己的 `tlv_var`，一个线程对 `tlv_var` 所做的更改不会影响其他线程中的 `tlv_var`。

在 Mach-O 二进制文件中，与线程局部变量相关的数据会组织在特定的段中：

- **`__DATA.__thread_vars`**：此段包含线程局部变量的元数据，例如变量类型和初始化状态。
- **`__DATA.__thread_bss`**：此段用于存放未显式初始化的线程局部变量，是为零初始化数据预留的一部分内存。

Mach-O 还提供了一个名为 **`tlv_atexit`** 的专用 API，用于在线程退出时管理线程局部变量。此 API 可以**注册析构函数**——在线程终止时清理线程局部数据的特殊函数。

### 线程优先级

要理解线程优先级，需要了解操作系统如何决定运行哪些线程以及何时运行。此决策会受到分配给各线程的优先级影响。在 macOS 和类 Unix 系统中，这通常通过 `nice`、`renice` 和服务质量（QoS）类别等概念来处理。

#### Nice 和 Renice

1. **Nice：**
   - 进程的 `nice` 值是一个会影响其优先级的数字。每个进程的 `nice` 值范围为 -20（最高优先级）到 19（最低优先级）。进程创建时的默认 `nice` 值通常为 0。
   - 较低的 `nice` 值（更接近 -20）会让进程变得更“自私”，使其相比 `nice` 值较高的其他进程获得更多 CPU 时间。
2. **Renice：**
   - `renice` 是用于更改已运行进程 `nice` 值的命令。可以使用它动态调整进程优先级，根据新的 `nice` 值增加或减少分配给进程的 CPU 时间。
   - 例如，如果进程临时需要更多 CPU 资源，可以使用 `renice` 降低其 `nice` 值。

#### 服务质量（QoS）类别

QoS 类别是一种更现代的线程优先级处理方式，尤其适用于支持 **Grand Central Dispatch (GCD)** 的 macOS 等系统。QoS 类别允许开发者根据工作的重要性或紧急程度，将其**归类**到不同级别。macOS 会根据这些 QoS 类别自动管理线程优先级：

1. **User Interactive：**
   - 此类别适用于当前正在与用户交互，或需要立即给出结果以提供良好用户体验的任务。此类任务具有最高优先级，以保持界面响应及时（例如动画或事件处理）。
2. **User Initiated：**
   - 适用于由用户发起且用户期待立即得到结果的任务，例如打开文档或点击需要执行计算的按钮。此类任务优先级较高，但低于 User Interactive。
3. **Utility：**
   - 适用于运行时间较长且通常会显示进度指示器的任务（例如下载文件、导入数据）。此类任务的优先级低于用户发起的任务，不需要立即完成。
4. **Background：**
   - 此类别适用于在后台运行且用户不可见的任务，例如索引、同步或备份。此类任务优先级最低，对系统性能的影响也最小。

使用 QoS 类别时，开发者无需管理具体的优先级数值，而只需关注任务的性质，系统会据此优化 CPU 资源。

此外，还有不同的**线程调度策略**，可以指定一组供调度器参考的调度参数。可以使用 `thread_policy_[set/get]` 来设置。这可能对 race condition 攻击有用。

## macOS 进程滥用

macOS 提供了许多机制，让**进程之间能够交互、通信和共享数据**。尽管这些机制对系统正常运行至关重要，攻击者也可能滥用它们来进行注入、代码执行或数据访问。

### Library Injection

Library Injection 是一种攻击者**强制进程加载恶意库**的技术。注入后，该库会在目标进程的上下文中运行，使攻击者拥有与该进程相同的权限和访问能力。


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking 涉及**拦截软件代码中的函数调用**或消息。攻击者通过 Hook 函数，可以**修改进程行为**、观察敏感数据，甚至控制执行流程。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

此页面介绍 ARM64 unwind 元数据、arm64e PAC 约束以及合成调用链。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) 指不同进程之间**共享和交换数据**的各种方式。虽然 IPC 对许多合法应用至关重要，但也可能被滥用来破坏进程隔离、leak 敏感信息或执行未授权操作。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

使用特定环境变量运行的 Electron 应用可能容易受到进程注入攻击：


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

可以使用 `--load-extension` 和 `--use-fake-ui-for-media-stream` 标志发起 **man in the browser attack**，从而窃取按键输入、流量和 cookie，或向页面注入脚本……：


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB 文件**定义用户界面 (UI) 元素**及其在应用中的交互。不过，它们可以**执行任意命令**，而且如果**NIB 文件被修改**，Gatekeeper 不会阻止已执行过的应用再次执行。因此，可以利用它们让任意程序执行任意命令：


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

可以通过 **`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`** 或 **`JDK_JAVA_OPTIONS`** 注入 JVM 选项，在应用启动前加载 Java 或 native agent。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** 可通过 `--require`（文件）或 `--import data:text/javascript,…`（无文件，Node ≥ 20.6）预加载攻击者的 JavaScript；**`NODE_REPL_EXTERNAL_MODULE`** 可将模块加载到交互式 REPL 中；**`ELECTRON_RUN_AS_NODE`** 则会在 Electron 二进制文件上重新启用上述功能。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

可以通过 **`DOTNET_STARTUP_HOOKS`** 在 `Main` 运行前向 .NET 应用注入代码，也可以在满足前置条件时滥用 .NET 调试功能。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非交互式 Bash 会读取 **`BASH_ENV`**；交互式 POSIX shell 会读取 **`ENV`**；zsh 会读取 **`$ZDOTDIR/.zshenv`**；fish 则会读取 **`XDG_CONFIG_HOME`** 或 **`XDG_DATA_DIRS`** 下的配置。它们都可以在预期命令运行前执行受控的启动文件。启用 xtrace 时（例如继承了 **`SHELLOPTS=xtrace`**），Bash 还会在每次追踪时执行放在 **`PS4`** 中的命令替换：

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

启动 `/bin/zsh -s` 会让 shell 从标准输入读取程序。因此，如果下载器未经解析就将不可信的结构化文档复制到子进程的 stdin，整份文档就会变成 shell 源代码。曾观察到一个 loader 通过匿名管道逐行传入公开的 iCalendar 文件。日历元数据无法作为命令执行，但 zsh 会继续处理，直到遇到放在 `DESCRIPTION:` 之后的可执行行。这些行会下载并启动下一个应用程序包。载体的预期内容类型和可信托管来源并不能保证安全；危险边界在于将其字节传递给解释器。<sup>[[5]](#references)</sup>

相关阶段参见 [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)、[Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) 和 [macOS auto-start locations](../../macos-auto-start-locations.md)。

### PHP Injection

**`PHPRC`** 或 **`PHP_INI_SCAN_DIR`** 可以加载受控的 PHP 配置，其 **`auto_prepend_file`** 会在目标脚本运行前执行。

[PHP 配置与 `auto_prepend_file` 启动注入](macos-interpreter-startup-file-injection.md#php-startup-configuration)。

### Lua Injection

独立的 Lua 解释器会在处理目标脚本前，执行 **`LUA_INIT`**（或其版本特定变体）中的代码或 `@file`。

[Lua `LUA_INIT` 启动注入（文件和内联代码）](macos-interpreter-startup-file-injection.md#lua-startup-code)。

### R Injection

**`R_PROFILE_USER`** 和 **`R_PROFILE`** 可将启动配置文件重定向到包含 R 代码的文件。也可以结合 R 库路径使用 **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**，自动加载已安装的软件包。

[R 启动配置文件与软件包加载](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** 可重定向 depot，其 `config/startup.jl` 会被自动执行。

[Julia `JULIA_DEPOT_PATH` 与 `startup.jl` 注入](macos-interpreter-startup-file-injection.md#julia-startup-depot)。

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`** 或 **`ERL_ZFLAGS`** 可以注入 Erlang VM **`-eval`** 表达式，无需 payload 文件；Elixir 工作负载通常也会启动同一个 VM。

[Erlang/Elixir VM 标志注入](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 和 **`OCTAVE_VERSION_INITFILE`** 可重定向 Octave 启动脚本。

[GNU Octave 启动文件注入](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files)。

### PowerShell Injection

`pwsh` 是跨平台 .NET 应用，因此有多个环境变量可实现在命令运行前执行代码：**`XDG_CONFIG_HOME`** 可重定向启动时运行的配置文件脚本；**`PSModulePath`** 可劫持模块自动加载（植入的 `.psm1` 会在导入时运行，还可以遮蔽内置 cmdlet）；.NET 的 **`CORECLR_PROFILER`**/**`COR_PROFILER`** 和 **`DOTNET_STARTUP_HOOKS`** 变量则可在 `Main` 运行前将攻击者代码加载到进程中。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

查看让 Perl 脚本执行任意代码的不同选项：


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

还可以滥用 Ruby 环境变量（**`RUBYOPT`**、**`RUBYLIB`**），让任意脚本执行任意代码：


[Ruby `RUBYOPT`/`RUBYLIB` loader 选项](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

**`PYTHONWARNINGS`** 和 **`BROWSER`** 标准库链可以在解析 warning filter 时执行命令。另一种基于文件的方式是在 **`PYTHONPATH`** 中放置 `sitecustomize.py`，这样常规的 `site` 初始化就会在目标脚本前导入它。代码运行到 `breakpoint()` 时，**`PYTHONBREAKPOINT`** 会调用指定的 callable/module。

在 CPython 3.13 及更高版本中，如果脚本运行后 PyREPL 在终端中启动，**`PYTHONINSPECT`** 还可以执行 **`PYTHONSTARTUP`** 文件。<sup>[[6]](#references)</sup>

请注意，即使使用内嵌 Python 运行，通过 **`pyinstaller`** 编译的可执行文件也不会使用这些环境变量。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

正常启动时，**`VIMINIT`**（以及作为后备选项的 `EXINIT`）会作为 Ex 命令执行。因此，当受害者在受控环境中打开 Vim/Neovim 时，`:!cmd` / `:call system(...)` 可以实现代码执行：

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

另外，Homebrew 通常会在 `/opt/homebrew` 下安装 Python，而本地 `admin` 组成员可能有权替换其启动器。这属于可写二进制劫持，而不是环境变量注入；在判定其可被利用之前，应检查所有权和 ACL。


## 检测

### Shield

[**Shield**](https://github.com/theevilbit/Shield) 是一款基于 **EndpointSecurity** 的开源应用，可检测并阻止进程注入。它可以作为参考，帮助了解哪些信号可通过 Endpoint Security 观察到，因为它会在以下情况发出警报：<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- 进程执行时出现**注入环境变量**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH` 和 `ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** 调用——一个进程请求另一个进程的 task port，这是向其注入代码的前提。
- **Electron 调试参数**——`--inspect`、`--inspect-brk` 和 `--remote-debugging-port`，这些参数会让 Electron 应用以调试模式启动，允许任何人连接并在其中运行代码。<sup>[[3]](#references)</sup>
- **跨权限级别创建符号链接/硬链接**——经典操作“以普通用户身份创建链接，再将其指向特权位置”。请注意，**可以针对符号链接发出警报，但无法阻止其创建**：EndpointSecurity 不会在符号链接创建前提供其目标位置。

### 其他进程发起的调用

在[**这篇博客文章**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以了解如何使用 **`task_name_for_pid`** 函数获取关于**向进程注入代码的其他进程**的信息，然后进一步获取该进程的信息。<sup>[[4]](#references)</sup>

请注意，要调用该函数，你需要与运行该进程的用户具有**相同的 uid**，或者拥有 **root** 权限（该函数返回的是进程信息，而不是注入代码的方法）。



## References

- [1] [Shield — 开源 macOS 进程注入检测（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity 框架](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - 为什么 Electron 应用无法保密存储你的机密：--inspect 选项](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - 检测 task 修改](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - 新版 MacSync macOS 窃取程序针对加密货币爱好者和开发者](https://securelist.com/macsync-new-version/121383/)
- [6] [Python 命令行与环境 — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
