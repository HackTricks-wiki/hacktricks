# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## 进程基本信息

进程是正在运行的可执行文件实例，不过进程本身不运行代码，运行代码的是线程。因此，**进程只是运行线程的容器**，提供内存、描述符、端口、权限等资源。

传统上，进程（PID 1 除外）通过调用 **`fork`** 在其他进程中启动。`fork` 会创建当前进程的精确副本，然后**子进程**通常会调用 **`execve`** 加载新的可执行文件并运行。随后引入了 **`vfork`**，让这一过程无需复制内存，从而提高速度。\
之后引入了 **`posix_spawn`**，将 **`vfork`** 和 **`execve`** 合并为一次调用，并支持以下标志：

- `POSIX_SPAWN_RESETIDS`：将有效 ID 重置为真实 ID
- `POSIX_SPAWN_SETPGROUP`：设置进程组归属
- `POSUX_SPAWN_SETSIGDEF`：设置默认信号行为
- `POSIX_SPAWN_SETSIGMASK`：设置信号掩码
- `POSIX_SPAWN_SETEXEC`：在同一进程中执行（类似带有更多选项的 `execve`）
- `POSIX_SPAWN_START_SUSPENDED`：以挂起状态启动
- `_POSIX_SPAWN_DISABLE_ASLR`：启动时不启用 ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` 使用 libmalloc 的 Nano 分配器
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 允许数据段具有 `rwx` 权限
- `POSIX_SPAWN_CLOEXEC_DEFAULT`：默认在 exec(2) 时关闭所有文件描述符
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` 随机化 ASLR 偏移的高位

此外，`posix_spawn` 接受 **`posix_spawnattr`** 设置，用于控制生成进程的各项属性；也接受 **`posix_spawn_file_actions`** 条目，用于修改文件描述符。

进程终止时，会通过信号 `SIGCHLD` **向父进程发送返回码**（如果父进程已终止，则新父进程为 PID 1）。父进程需要调用 `wait4()` 或 `waitid()` 获取该值。在此之前，子进程会处于僵尸状态：它仍会出现在进程列表中，但不会消耗资源。

### PIDs

PID（进程标识符）用于标识一个唯一进程。在 XNU 中，**PID** 为 **64 位**，会单调递增且**永不回绕**（以避免滥用）。

### Process Groups、Sessions 和 Coalations

**进程**可以加入**组**，以便于统一管理。例如，shell 脚本中的命令会属于同一个进程组，因此可以使用 kill 等方式**同时向它们发送信号**。\
进程也可以**归入会话**。当某个进程启动一个会话（`setsid(2)`）时，其子进程会加入该会话，除非它们自行启动会话。

Coalition 是 Darwin 中另一种对进程分组的方式。进程加入 coalition 后，便可使用资源池、共享账本或受到 Jetsam 管理。Coalition 有不同的角色：Leader、XPC service、Extension。

### Credentials 和 Personae

每个进程都持有用于**标识其系统权限**的 **credentials**。每个进程都有一个主要的 `uid` 和一个主要的 `gid`（但它可能属于多个组）。\
如果二进制文件设置了 `setuid/setgid` 位，也可以更改用户 ID 和组 ID。\
有多个函数可用于**设置新的 uid/gid**。

系统调用 **`persona`** 提供一组**备用**的 **credentials**。采用某个 persona 后，会同时继承其 uid、gid 和组成员身份。在[**源代码**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)中可以找到该结构体：

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

## 线程基础信息

1. **POSIX Threads (pthreads)：** macOS 支持 POSIX 线程（`pthreads`），这是 C/C++ 的标准线程 API 的一部分。macOS 中的 pthreads 实现在 `/usr/lib/system/libsystem_pthread.dylib`，该库来自公开的 `libpthread` 项目。此库提供创建和管理线程所需的函数。
2. **创建线程：** `pthread_create()` 函数用于创建新线程。该函数内部会调用 `bsdthread_create()`，这是 XNU 内核（macOS 所基于的内核）专用的底层系统调用。此系统调用接收从 `pthread_attr`（属性）派生的各种标志，用于指定线程行为，包括调度策略和堆栈大小。
   - **默认堆栈大小：** 新线程的默认堆栈大小为 512 KB，足以应对常见操作；如果需要更多或更少空间，可以通过线程属性进行调整。
3. **线程初始化：** `__pthread_init()` 函数在设置线程时至关重要，它会利用 `env[]` 参数解析环境变量，其中可能包含堆栈位置和大小等信息。

#### macOS 中的线程终止

1. **退出线程：** 通常通过调用 `pthread_exit()` 终止线程。该函数允许线程正常退出、执行必要的清理操作，并向等待其退出的线程返回值。
2. **线程清理：** 调用 `pthread_exit()` 后，会调用 `pthread_terminate()`，负责移除所有相关线程结构。该函数会释放 Mach 线程端口（Mach 是 XNU 内核中的通信子系统），并调用 `bsdthread_terminate` 系统调用，以移除与该线程关联的内核级结构。

#### 同步机制

macOS 提供多种同步原语，用于管理对共享资源的访问并避免竞争条件。这些机制对于多线程环境至关重要，有助于确保数据完整性和系统稳定性：

1. **互斥锁：**
   - **常规互斥锁（签名：0x4D555458）：** 标准互斥锁，占用 60 字节（互斥锁本身占 56 字节，签名占 4 字节）。
   - **快速互斥锁（签名：0x4d55545A）：** 与常规互斥锁类似，但针对更快的操作进行了优化，大小也是 60 字节。
2. **条件变量：**
   - 用于等待特定条件发生，大小为 44 字节（40 字节加 4 字节签名）。
   - **条件变量属性（签名：0x434e4441）：** 条件变量的配置属性，大小为 12 字节。
3. **Once 变量（签名：0x4f4e4345）：**
   - 确保某段初始化代码只执行一次。大小为 12 字节。
4. **读写锁：**
   - 允许多个读者同时访问，或一次由一个写者访问，从而高效访问共享数据。
   - **读写锁（签名：0x52574c4b）：** 大小为 196 字节。
   - **读写锁属性（签名：0x52574c41）：** 读写锁的属性，大小为 20 字节。

> [!TIP]
> 这些对象的最后 4 个字节用于检测溢出。

### Thread Local Variables (TLV)

在 Mach-O 文件（macOS 可执行文件格式）中，**Thread Local Variables (TLV)** 用于声明多线程应用程序中**每个线程各自拥有**的变量。这样，每个线程都有独立的变量实例，无需使用互斥锁等显式同步机制，也能避免冲突并保持数据完整性。

在 C 及相关语言中，可以使用 **`__thread`** 关键字声明线程局部变量。以下是示例中的用法：

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

这段代码将 `tlv_var` 定义为线程局部变量。运行这段代码的每个线程都有自己的 `tlv_var`，一个线程对 `tlv_var` 所做的更改不会影响其他线程中的 `tlv_var`。

在 Mach-O 二进制文件中，与线程局部变量相关的数据会组织在特定的段中：

- **`__DATA.__thread_vars`**：此段包含线程局部变量的元数据，例如变量类型和初始化状态。
- **`__DATA.__thread_bss`**：此段用于存放未显式初始化的线程局部变量，是为零初始化数据预留的一部分内存。

Mach-O 还提供了一个名为 **`tlv_atexit`** 的专用 API，用于在线程退出时管理线程局部变量。此 API 允许你**注册析构函数**——线程终止时清理线程局部数据的特殊函数。

### 线程优先级

要理解线程优先级，需要了解操作系统如何决定运行哪些线程以及何时运行。这一决策会受到分配给每个线程的优先级影响。在 macOS 和类 Unix 系统中，这通常通过 `nice`、`renice` 和服务质量（QoS）类别等概念来处理。

#### Nice 和 Renice

1. **Nice：**
   - 进程的 `nice` 值是一个会影响其优先级的数值。每个进程的 nice 值范围为 -20（最高优先级）到 19（最低优先级）。进程创建时的默认 nice 值通常为 0。
   - 较低的 nice 值（接近 -20）会让进程更“自私”，使其比 nice 值更高的其他进程获得更多 CPU 时间。
2. **Renice：**
   - `renice` 是用于更改已运行进程 nice 值的命令。它可以根据新的 nice 值动态调整进程优先级，从而增加或减少进程分配到的 CPU 时间。
   - 例如，如果进程暂时需要更多 CPU 资源，可以使用 `renice` 降低其 nice 值。

#### 服务质量（QoS）类别

QoS 类别是处理线程优先级的一种较现代的方法，尤其适用于支持 **Grand Central Dispatch (GCD)** 的 macOS 等系统。QoS 类别允许开发者根据工作的重要性或紧急程度，将工作**分类**到不同级别。macOS 会根据这些 QoS 类别自动管理线程优先级：

1. **用户交互：**
   - 此类别用于当前正在与用户交互，或需要立即给出结果以提供良好用户体验的任务。这些任务拥有最高优先级，以保持界面响应流畅（例如，动画或事件处理）。
2. **用户发起：**
   - 此类别用于用户发起且期望立即获得结果的任务，例如打开文档，或点击需要进行计算的按钮。这些任务优先级较高，但低于用户交互类别。
3. **实用工具：**
   - 这些任务耗时较长，通常会显示进度指示器（例如，下载文件、导入数据）。其优先级低于用户发起的任务，而且不需要立即完成。
4. **后台：**
   - 此类别用于在后台运行且用户不可见的任务，例如索引、同步或备份。这些任务优先级最低，对系统性能的影响也最小。

使用 QoS 类别后，开发者无需管理具体的优先级数值，只需关注任务的性质，系统便会相应地优化 CPU 资源。

此外，还有不同的**线程调度策略**，可用于指定一组供调度器参考的调度参数。可以使用 `thread_policy_[set/get]` 设置这些参数。这在竞态条件攻击中可能会有用。

## macOS 进程滥用

macOS 提供了许多机制，让**进程能够交互、通信和共享数据**。尽管这些机制对于系统正常运行至关重要，攻击者也可能滥用它们来进行注入、代码执行或数据访问。

### Library Injection

Library Injection 是一种攻击者**强制进程加载恶意库**的技术。库被注入后，会在目标进程的上下文中运行，使攻击者获得与该进程相同的权限和访问能力。


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking 涉及在软件代码中**拦截函数调用**或消息。攻击者通过 hook 函数，可以**修改进程行为**、观察敏感数据，甚至控制执行流程。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

本页面介绍 ARM64 unwind 元数据、arm64e PAC 限制以及合成调用链。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### 进程间通信

进程间通信（IPC）指不同进程之间**共享和交换数据**的各种方法。虽然 IPC 对许多合法应用至关重要，但也可能被滥用来破坏进程隔离、泄露敏感信息或执行未授权操作。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron 应用注入

使用特定环境变量运行的 Electron 应用可能容易受到进程注入攻击：


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium 注入

可以使用 `--load-extension` 和 `--use-fake-ui-for-media-stream` 标志发起**浏览器中间人攻击**，从而窃取按键输入、流量和 cookies，并向页面注入脚本等：


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB 文件**定义用户界面（UI）元素**及其在应用中的交互。不过，它们可以**执行任意命令**；而且，如果**NIB 文件被修改**，Gatekeeper 不会阻止已经执行过的应用再次执行。因此，可以利用它们让任意程序执行任意命令：


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java 应用注入

可以通过 **`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`** 或 **`JDK_JAVA_OPTIONS`** 注入 JVM 选项，在应用启动前加载 Java 或 native agent。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js 注入

**`NODE_OPTIONS`** 可通过 `--require`（文件）或 `--import data:text/javascript,…`（无文件，Node ≥ 20.6）预加载攻击者控制的 JavaScript；**`NODE_REPL_EXTERNAL_MODULE`** 可将模块加载到交互式 REPL 中；而 **`ELECTRON_RUN_AS_NODE`** 可在 Electron 二进制文件上重新启用上述功能。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net 应用注入

可以通过 **`DOTNET_STARTUP_HOOKS`** 在 `Main` 之前向 .NET 应用注入代码，或者在满足前提条件时滥用 .NET 调试功能。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell 注入

非交互式 Bash 会读取 **`BASH_ENV`**；交互式 POSIX shell 会读取 **`ENV`**；zsh 会读取 **`$ZDOTDIR/.zshenv`**；fish 会读取 **`XDG_CONFIG_HOME`** 或 **`XDG_DATA_DIRS`** 下的配置文件。它们都可以在预期命令运行前执行受控的启动文件。启用 xtrace 时（例如继承了 **`SHELLOPTS=xtrace`**），Bash 还会在每次跟踪执行时运行放在 **`PS4`** 中的命令替换：

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin 命令走私

启动 `/bin/zsh -s` 会使 shell 从标准输入读取程序。因此，如果下载器未解析不可信的结构化文档，就将其复制到子进程的 stdin 中，整个文档就会变成 shell 源代码。曾观察到一种加载器逐行将公开的 iCalendar 文件通过匿名管道传入。日历元数据无法作为命令执行，但 zsh 会继续处理，直到遇到放在 `DESCRIPTION:` 后面的可执行行。这些行会下载并启动下一个应用 bundle。载体的预期内容类型和可信托管并不能保证安全；危险之处在于将其字节交给解释器处理。<sup>[[5]](#references)</sup>

相关阶段见 [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)、[Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) 和 [macOS auto-start locations](../../macos-auto-start-locations.md)。

### PHP 注入

**`PHPRC`** 或 **`PHP_INI_SCAN_DIR`** 可以加载受控的 PHP 配置，其中的 **`auto_prepend_file`** 会在目标脚本运行前执行。

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration)。

### Lua 注入

独立的 Lua 解释器会在处理目标脚本前，执行 **`LUA_INIT`**（或其特定版本变体）中的代码或 `@file`。

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code)。

### R 注入

**`R_PROFILE_USER`** 和 **`R_PROFILE`** 可将启动配置文件重定向到包含 R 代码的文件。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** 配合 R 库路径，则可以自动加载已安装的包。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia 注入

**`JULIA_DEPOT_PATH`** 可重定向 depot，而其中的 `config/startup.jl` 会被自动执行。

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot)。

### Erlang 和 Elixir 注入

**`ERL_AFLAGS`**、**`ERL_FLAGS`** 或 **`ERL_ZFLAGS`** 可以注入 Erlang VM **`-eval`** 表达式，无需 payload 文件；Elixir 工作负载通常也会启动同一个 VM。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave 注入

**`OCTAVE_SITE_INITFILE`** 和 **`OCTAVE_VERSION_INITFILE`** 可重定向 Octave 启动脚本。

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files)。

### PowerShell 注入

`pwsh` 是跨平台 .NET 应用，因此有多个环境变量可在命令执行前运行代码：**`XDG_CONFIG_HOME`** 可重定向启动时运行的 profile 脚本；**`PSModulePath`** 可劫持模块自动加载（植入的 `.psm1` 会在导入时运行，并可覆盖内置 cmdlet）；.NET 的 **`CORECLR_PROFILER`**/**`COR_PROFILER`** 和 **`DOTNET_STARTUP_HOOKS`** 变量则可在 `Main` 运行前将攻击者代码加载到进程中。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl 注入

查看在以下位置让 Perl 脚本执行任意代码的不同选项：


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby 注入

也可以滥用 Ruby 环境变量（**`RUBYOPT`**、**`RUBYLIB`**），让任意脚本执行任意代码：


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python 注入

**`PYTHONWARNINGS`** 和 **`BROWSER`** 标准库链可以在解析警告过滤器时执行命令。另一种基于文件的方式是在 **`PYTHONPATH`** 中放置 `sitecustomize.py`，这样正常的 `site` 初始化过程会在目标脚本运行前导入该文件。代码执行到 `breakpoint()` 时，**`PYTHONBREAKPOINT`** 会运行指定的可调用对象或模块。**`PYTHONSTARTUP`** 等仅适用于交互模式的变量，适用范围更窄。

请注意，使用 **`pyinstaller`** 编译的可执行文件不会使用这些环境变量，即使它们运行时嵌入了 Python 也一样。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim 注入

在正常启动时，**`VIMINIT`**（以及其回退选项 `EXINIT`）会作为 Ex 命令执行。因此，当受害者在受控环境中打开 Vim/Neovim 时，`:!cmd` / `:call system(...)` 可导致代码执行：

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

此外，Homebrew 通常会将 Python 安装在 `/opt/homebrew` 下，本地 `admin` 组成员可能能够替换启动器。这属于可写二进制劫持，而非环境变量注入；在将其视为可利用问题之前，请先检查所有权和 ACL。


## 检测

### Shield

[**Shield**](https://github.com/theevilbit/Shield) 是一个基于 **EndpointSecurity** 的开源应用，可检测并阻止进程注入。它是了解哪些信号可通过 Endpoint Security 观察到的良好参考，因为它会对以下行为发出警报：<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- 进程执行时出现的**注入环境变量**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH` 和 `ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** 调用——一个进程请求另一个进程的 task port，这是向其注入代码的前提。
- **Electron 调试参数**——`--inspect`、`--inspect-brk` 和 `--remote-debugging-port`。这些参数会以调试模式启动 Electron 应用，使任何人都能连接到应用并在其中运行代码。<sup>[[3]](#references)</sup>
- **跨权限级别创建符号链接/硬链接**——经典的“以普通用户身份创建链接，再将其指向特权位置”的手法。请注意，**符号链接可以触发警报，但无法被阻止**：EndpointSecurity 不会在链接创建前公开其目标位置。

### 其他进程发起的调用

在[**这篇博客文章**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以了解如何使用 **`task_name_for_pid`** 函数获取有关**向进程注入代码的其他进程**的信息，并进一步获取该进程的信息。<sup>[[4]](#references)</sup>

请注意，调用该函数需要与运行目标进程的用户具有**相同的 uid**，或者是 **root**（它返回的是进程信息，而不是注入代码的方法）。

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — macOS 开源进程注入检测工具（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity 框架](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - 为什么 Electron 应用无法保密存储你的秘密：--inspect 选项](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - 检测 task 修改](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - 新版 MacSync macOS 窃取程序瞄准加密货币爱好者和开发者](https://securelist.com/macsync-new-version/121383/)
