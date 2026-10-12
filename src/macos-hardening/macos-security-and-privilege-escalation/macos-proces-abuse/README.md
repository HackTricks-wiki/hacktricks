# macOS 进程滥用

{{#include ../../../banners/hacktricks-training.md}}

## 进程基础信息

进程是正在运行的可执行文件的一个实例，但进程本身不运行代码，线程才运行代码。因此，**进程只是运行线程的容器**，提供内存、描述符、端口、权限等。

传统上，进程是在其他进程中启动的（PID 1 除外）：调用 **`fork`** 创建当前进程的精确副本，然后**子进程**通常会调用 **`execve`** 加载新的可执行文件并运行。之后，**`vfork`** 被引入，以便在不复制内存的情况下加快这一过程。\
随后，**`posix_spawn`** 被引入，它将 **`vfork`** 和 **`execve`** 合并为一次调用，并接受以下标志：

- `POSIX_SPAWN_RESETIDS`：将有效 ID 重置为真实 ID
- `POSIX_SPAWN_SETPGROUP`：设置进程组归属
- `POSUX_SPAWN_SETSIGDEF`：设置默认信号行为
- `POSIX_SPAWN_SETSIGMASK`：设置信号掩码
- `POSIX_SPAWN_SETEXEC`：在同一进程中执行（类似于具有更多选项的 `execve`）
- `POSIX_SPAWN_START_SUSPENDED`：以暂停状态启动
- `_POSIX_SPAWN_DISABLE_ASLR`：启动时不启用 ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` 使用 libmalloc 的 Nano 分配器
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 允许数据段具有 `rwx` 权限
- `POSIX_SPAWN_CLOEXEC_DEFAULT`：默认在 exec(2) 时关闭所有文件描述符
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` 随机化 ASLR 偏移量的高位

此外，`posix_spawn` 接受用于控制生成进程各项属性的 **`posix_spawnattr`** 设置，以及用于修改文件描述符的 **`posix_spawn_file_actions`** 条目。

进程退出时，会通过信号 `SIGCHLD` 将**返回码发送给父进程**（如果父进程已退出，则新父进程为 PID 1）。父进程需要调用 `wait4()` 或 `waitid()` 获取该值；在此之前，子进程会处于僵尸状态，仍会显示在进程列表中，但不会消耗资源。

### PID

PID（进程标识符）用于标识唯一的进程。在 XNU 中，**PID** 为 **64 位**，单调递增且**永不回绕**（以避免滥用）。

### 进程组、会话与 Coalition

**进程**可以加入**组**，以便于管理。例如，shell 脚本中的命令会处于同一个进程组，因此可以使用 kill 等方式**同时向它们发送信号**。\
也可以将**进程分组到会话中**。进程启动会话（`setsid(2)`）后，其子进程会加入该会话，除非它们自行启动会话。

Coalition 是 Darwin 中另一种对进程进行分组的方式。进程加入 Coalition 后即可访问资源池、共享账本或受到 Jetsam 管理。Coalition 有不同的角色：Leader、XPC service、Extension。

### 凭证与 Persona

每个进程都持有用于**标识其系统权限**的**凭证**。每个进程都有一个主 `uid` 和一个主 `gid`（但可能属于多个组）。\
如果二进制文件设置了 `setuid/setgid` 位，也可以更改用户 ID 和组 ID。\
有多个函数可用于**设置新的 uid/gid**。

系统调用 **`persona`** 提供一组**备用**的**凭证**。采用某个 persona 后，会一次性采用其 uid、gid 和组成员身份。在[**源代码**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)中可以找到该 struct：

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

1. **POSIX Threads (pthreads)：** macOS 支持 POSIX threads（`pthreads`），这是 C/C++ 标准线程 API 的一部分。macOS 中的 pthreads 实现位于 `/usr/lib/system/libsystem_pthread.dylib`，该库来自公开的 `libpthread` 项目。此库提供创建和管理线程所需的函数。
2. **创建线程：** `pthread_create()` 函数用于创建新线程。在内部，此函数会调用 `bsdthread_create()`，这是 XNU 内核（macOS 所基于的内核）专用的底层系统调用。此系统调用会接收从 `pthread_attr`（属性）派生的各种标志，用于指定线程行为，包括调度策略和栈大小。
   - **默认栈大小：** 新线程的默认栈大小为 512 KB，足以应对常见操作；如果需要更多或更少空间，可以通过线程属性进行调整。
3. **线程初始化：** `__pthread_init()` 函数在设置线程时至关重要，它会使用 `env[]` 参数解析环境变量，其中可能包含栈的位置和大小等信息。

#### macOS 中的线程终止

1. **退出线程：** 通常通过调用 `pthread_exit()` 终止线程。此函数允许线程正常退出、执行必要的清理操作，并向等待该线程的线程返回一个值。
2. **线程清理：** 调用 `pthread_exit()` 后，会调用 `pthread_terminate()`，该函数负责移除所有关联的线程结构。它会释放 Mach thread ports（Mach 是 XNU 内核中的通信子系统），并调用 `bsdthread_terminate`——一个用于移除与该线程关联的内核级结构的系统调用。

#### 同步机制

为了管理对共享资源的访问并避免竞争条件，macOS 提供了多种同步原语。这些原语对于多线程环境至关重要，可确保数据完整性和系统稳定性：

1. **互斥锁：**
   - **普通互斥锁（签名：0x4D555458）：** 标准互斥锁，占用 60 字节（互斥锁本身占 56 字节，签名占 4 字节）。
   - **快速互斥锁（签名：0x4d55545A）：** 与普通互斥锁类似，但针对更快的操作进行了优化，大小同样为 60 字节。
2. **条件变量：**
   - 用于等待特定条件发生，占用 44 字节（40 字节加 4 字节签名）。
   - **条件变量属性（签名：0x434e4441）：** 条件变量的配置属性，占用 12 字节。
3. **Once 变量（签名：0x4f4e4345）：**
   - 确保初始化代码只执行一次。大小为 12 字节。
4. **读写锁：**
   - 允许多个读取者同时访问，或一次由一个写入者访问，从而高效地访问共享数据。
   - **读写锁（签名：0x52574c4b）：** 大小为 196 字节。
   - **读写锁属性（签名：0x52574c41）：** 读写锁的属性，大小为 20 字节。

> [!TIP]
> 这些对象的最后 4 个字节用于检测溢出。

### 线程局部变量 (TLV)

在 Mach-O 文件（macOS 中可执行文件的格式）中，**线程局部变量 (TLV)** 用于声明多线程应用程序中**每个线程**独有的变量。这样，每个线程都拥有该变量各自独立的实例，无需使用互斥锁等显式同步机制，就能避免冲突并保持数据完整性。

在 C 及相关语言中，可以使用 **`__thread`** 关键字声明线程局部变量。以下是它在示例中的用法：

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

这段代码将 `tlv_var` 定义为线程局部变量。运行这段代码的每个线程都有自己的 `tlv_var`，一个线程对 `tlv_var` 的修改不会影响其他线程中的 `tlv_var`。

在 Mach-O 二进制文件中，与线程局部变量相关的数据被组织在特定的段中：

- **`__DATA.__thread_vars`**：此段包含线程局部变量的元数据，例如变量类型和初始化状态。
- **`__DATA.__thread_bss`**：此段用于存放未显式初始化的线程局部变量，是为零初始化数据预留的一部分内存。

Mach-O 还提供了一个名为 **`tlv_atexit`** 的专用 API，用于在线程退出时管理线程局部变量。此 API 可以**注册析构函数**——在线程终止时清理线程局部数据的特殊函数。

### 线程优先级

要了解线程优先级，需要了解操作系统如何决定运行哪些线程以及何时运行。该决策会受到分配给每个线程的优先级影响。在 macOS 和类 Unix 系统中，这通常通过 `nice`、`renice` 和服务质量（QoS）类别等概念来处理。

#### Nice 和 Renice

1. **Nice：**
   - 进程的 `nice` 值是一个影响其优先级的数字。每个进程的 nice 值范围为 -20（最高优先级）到 19（最低优先级）。进程创建时的默认 nice 值通常为 0。
   - 较低的 nice 值（更接近 -20）会让进程更“自私”，使其相较于 nice 值较高的其他进程获得更多 CPU 时间。
2. **Renice：**
   - `renice` 是用于更改已运行进程 nice 值的命令。它可以动态调整进程的优先级，根据新的 nice 值增加或减少分配给进程的 CPU 时间。
   - 例如，如果进程暂时需要更多 CPU 资源，可以使用 `renice` 降低其 nice 值。

#### 服务质量（QoS）类别

QoS 类别是处理线程优先级的一种较现代的方法，尤其适用于支持 **Grand Central Dispatch (GCD)** 的 macOS 等系统。开发者可以根据工作的重要性或紧急程度，将工作**分类**到不同级别。macOS 会根据这些 QoS 类别自动管理线程优先级：

1. **User Interactive：**
   - 此类别适用于正在与用户交互或需要立即提供结果以确保良好用户体验的任务。此类任务具有最高优先级，以保持界面响应灵敏（例如动画或事件处理）。
2. **User Initiated：**
   - 此类别适用于用户发起且期望立即得到结果的任务，例如打开文档或点击需要进行计算的按钮。此类任务优先级较高，但低于 User Interactive。
3. **Utility：**
   - 此类别适用于长时间运行且通常会显示进度指示器的任务（例如下载文件、导入数据）。它们的优先级低于 User Initiated 任务，无需立即完成。
4. **Background：**
   - 此类别适用于在后台运行且对用户不可见的任务，例如索引、同步或备份。它们的优先级最低，对系统性能的影响也最小。

使用 QoS 类别时，开发者无需管理具体的优先级数值，只需关注任务的性质，系统会据此优化 CPU 资源分配。

此外，还有不同的**线程调度策略**，可用于指定调度器会考虑的一组调度参数。可以使用 `thread_policy_[set/get]` 来设置这些参数。这可能对竞态条件攻击有用。

## macOS 进程滥用

macOS 提供了许多机制，让**进程之间进行交互、通信和共享数据**。虽然这些机制对系统正常运行至关重要，但攻击者也可能滥用它们来进行注入、代码执行或数据访问。

### Library Injection

Library Injection 是一种攻击者**强制进程加载恶意库**的技术。注入后，该库会在目标进程的上下文中运行，使攻击者获得与该进程相同的权限和访问能力。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking 指拦截软件代码中的**函数调用**或消息。攻击者可以通过 hook 函数来**修改**进程的行为、观察敏感数据，甚至控制执行流程。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

本页介绍 ARM64 unwind 元数据、arm64e PAC 限制以及合成调用链。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### 进程间通信

进程间通信（IPC）指不同进程之间**共享和交换数据**的各种方式。虽然 IPC 对许多合法应用至关重要，但也可能被滥用来破坏进程隔离、泄露敏感信息或执行未授权操作。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

使用特定环境变量运行的 Electron 应用可能容易受到进程注入攻击：


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

可以使用 `--load-extension` 和 `--use-fake-ui-for-media-stream` 标志实施**浏览器中间人攻击**，从而窃取击键、流量和 cookie，并向页面注入脚本等：


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB 文件用于**定义用户界面 (UI) 元素**及其在应用中的交互方式。不过，它们也可以**执行任意命令**；如果已执行的应用中的 **NIB 文件被修改**，Gatekeeper 不会阻止该应用再次执行。因此，可以利用 NIB 文件让任意程序执行任意命令：


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

可以通过 **`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`** 或 **`JDK_JAVA_OPTIONS`** 注入 JVM 选项，在应用启动前加载 Java 或 native agent。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** 可通过 `--require`（文件）或 `--import data:text/javascript,…`（无文件，Node ≥ 20.6）预加载攻击者的 JavaScript；**`NODE_REPL_EXTERNAL_MODULE`** 可将模块加载到交互式 REPL 中；而 **`ELECTRON_RUN_AS_NODE`** 可在 Electron 二进制文件上重新启用上述功能。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

可以通过 **`DOTNET_STARTUP_HOOKS`** 在 `Main` 之前向 .NET 应用注入代码，也可以在满足先决条件时滥用 .NET 调试功能。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非交互式 Bash 会读取 **`BASH_ENV`**；交互式 POSIX shell 会读取 **`ENV`**；zsh 会读取 **`$ZDOTDIR/.zshenv`**；fish 则会读取 **`XDG_CONFIG_HOME`** 或 **`XDG_DATA_DIRS`** 下的配置文件。它们都可以在预期命令运行前执行受控的启动文件。启用 xtrace 时，Bash 还会执行放在 **`PS4`** 中的命令替换（例如继承了 **`SHELLOPTS=xtrace`** 时）：

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** 或 **`PHP_INI_SCAN_DIR`** 可以加载受控的 PHP 配置，其中的 **`auto_prepend_file`** 会在目标脚本运行前执行。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

独立 Lua 解释器会在处理目标脚本前，执行 **`LUA_INIT`**（或其特定版本的变体）指定的代码或 `@file`。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** 和 **`R_PROFILE`** 可以指定包含 R 代码的启动配置文件。也可以通过设置 **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** 以及 R 库路径，自动加载已安装的包。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** 可以重定向 depot 路径，其中的 `config/startup.jl` 会被自动执行。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`** 或 **`ERL_ZFLAGS`** 可以注入 Erlang VM **`-eval`** 表达式，无需 payload 文件；Elixir 工作负载通常也会启动同一个 VM。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 和 **`OCTAVE_VERSION_INITFILE`** 可以重定向 Octave 启动脚本。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` 是跨平台 .NET 应用，因此有多个环境变量可在命令运行前执行代码：**`XDG_CONFIG_HOME`** 可以重定向启动时运行的配置文件脚本；**`PSModulePath`** 可以劫持模块自动加载（植入的 `.psm1` 会在导入时运行，并可伪装成内置 cmdlet）；而 .NET 的 **`CORECLR_PROFILER`**/**`COR_PROFILER`** 和 **`DOTNET_STARTUP_HOOKS`** 变量则可以在 `Main` 运行前将攻击者代码加载到进程中。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

查看在以下页面中让 Perl 脚本执行任意代码的不同方法：


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

也可以滥用 Ruby 环境变量（**`RUBYOPT`**、**`RUBYLIB`**），让任意脚本执行任意代码：


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

标准库中的 **`PYTHONWARNINGS`** 和 **`BROWSER`** 组合链可以在解析 warning filter 时执行命令。另一种基于文件的方法是在 **`PYTHONPATH`** 上放置 `sitecustomize.py`，这样正常的 `site` 初始化就会在目标脚本运行前导入该文件。**`PYTHONBREAKPOINT`** 会在代码执行到 `breakpoint()` 时运行指定的可调用对象或模块。仅适用于交互模式的变量（例如 **`PYTHONSTARTUP`**）适用范围较窄。

请注意，即使使用内嵌 Python 运行，使用 **`pyinstaller`** 编译的可执行文件也不会使用这些环境变量。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

正常启动时，**`VIMINIT`**（以及其备用选项 `EXINIT`）会作为 Ex 命令执行。因此，当受害者在受控环境中打开 Vim/Neovim 时，`:!cmd` / `:call system(...)` 可以实现代码执行：

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

另外，Homebrew 通常会在 `/opt/homebrew` 下安装 Python，本地 `admin` 组的成员可能能够替换其启动器。这属于可写二进制劫持，而不是环境变量注入；在认定其可利用之前，请先确认文件所有权和 ACL。


## 检测

### Shield

[**Shield**](https://github.com/theevilbit/Shield) 是一款基于开源 **EndpointSecurity** 的应用，可检测并阻止进程注入。它有助于了解哪些信号可通过 Endpoint Security 观察到，因为它会在以下情况发出警报：<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- 进程 exec 时出现**注入环境变量**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH` 和 `ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** 调用——一个进程请求另一个进程的 task port，这是向该进程注入代码的前提条件。
- **Electron 调试参数**——`--inspect`、`--inspect-brk` 和 `--remote-debugging-port`。这些参数会让 Electron 应用以调试模式启动，使任何人都能附加到该应用并在其中运行代码。<sup>[[3]](#references)</sup>
- **跨权限级别创建符号链接/硬链接**——典型做法是“普通用户先创建链接，再将其指向特权位置”。请注意，**符号链接可以触发警报，但无法被阻止**：EndpointSecurity 无法在链接创建前获取其目标位置。

### 其他进程发起的调用

在[**这篇博客文章**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以了解如何使用 **`task_name_for_pid`** 函数获取有关**向进程注入代码的其他进程**的信息，以及该进程本身的信息。<sup>[[4]](#references)</sup>

请注意，要调用该函数，你必须与运行目标进程的用户具有**相同的 uid**，或拥有 **root** 权限（该函数会返回进程信息，但不提供注入代码的方式）。

## References

- [1] [Shield — 开源 macOS 进程注入检测工具（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity 框架](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - 为什么 Electron 应用无法保密存储你的秘密：--inspect 选项](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - 检测 task 修改](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
