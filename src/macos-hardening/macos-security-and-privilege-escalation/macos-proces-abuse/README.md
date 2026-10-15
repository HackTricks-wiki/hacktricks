# macOS 进程滥用

{{#include ../../../banners/hacktricks-training.md}}

## 进程基本信息

进程是正在运行的可执行文件的实例，不过进程本身不运行代码，运行代码的是线程。因此，**进程只是运行线程的容器**，提供内存、描述符、端口、权限……

传统上，进程（PID 1 除外）通过调用 **`fork`** 在其他进程中启动；它会创建当前进程的精确副本，然后**子进程**通常会调用 **`execve`** 来加载并运行新的可执行文件。之后，引入了 **`vfork`**，使这一过程无需复制内存就能更快完成。\
随后，引入了 **`posix_spawn`**，将 **`vfork`** 和 **`execve`** 合并为一次调用，并支持以下标志：

- `POSIX_SPAWN_RESETIDS`：将有效 ID 重置为真实 ID
- `POSIX_SPAWN_SETPGROUP`：设置进程组归属
- `POSUX_SPAWN_SETSIGDEF`：设置默认信号行为
- `POSIX_SPAWN_SETSIGMASK`：设置信号掩码
- `POSIX_SPAWN_SETEXEC`：在同一进程中执行（类似带更多选项的 `execve`）
- `POSIX_SPAWN_START_SUSPENDED`：以挂起状态启动
- `_POSIX_SPAWN_DISABLE_ASLR`：启动时不启用 ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` 使用 libmalloc 的 Nano 分配器
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` 允许数据段具有 `rwx` 权限
- `POSIX_SPAWN_CLOEXEC_DEFAULT`：默认在 exec(2) 时关闭所有文件描述符
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` 随机化 ASLR 滑动值的高位

此外，`posix_spawn` 接受用于控制生成进程各方面的 **`posix_spawnattr`** 设置，以及用于修改文件描述符的 **`posix_spawn_file_actions`** 条目。

进程退出时，会通过信号 `SIGCHLD` 将**返回代码发送给父进程**（如果父进程已退出，则新父进程为 PID 1）。父进程需要调用 `wait4()` 或 `waitid()` 获取这个值；在此之前，子进程会处于僵尸状态，仍会列在进程列表中，但不消耗资源。

### PID

PID（进程标识符）用于标识唯一的进程。在 XNU 中，**PID** 为 **64 位**，单调递增且**永不回绕**（以避免滥用）。

### 进程组、会话和 Coalition

**进程**可以加入**组**，以便于管理。例如，shell 脚本中的命令会属于同一个进程组，因此可以使用 kill 等方式**向它们统一发送信号**。\
也可以将**进程归入会话**。进程启动一个会话（`setsid(2)`）后，其子进程会被置于该会话中，除非它们启动自己的会话。

Coalition 是 Darwin 中另一种对进程分组的方式。进程加入 coalition 后，可以访问池资源、共享账本或受到 Jetsam 管理。Coalition 有不同的角色：Leader、XPC service、Extension。

### 凭据和 Persona

每个进程都持有用于**标识其系统权限**的**凭据**。每个进程都有一个主要的 `uid` 和一个主要的 `gid`（但可能属于多个组）。\
如果二进制文件设置了 `setuid/setgid` 位，也可以更改用户和组 ID。\
有多个函数可用于**设置新的 uid/gid**。

系统调用 **`persona`** 提供了一组**备用**的**凭据**。采用某个 persona 后，会同时采用其 uid、gid 和组成员身份。在[**源代码**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)中，可以找到以下结构体：

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

## 线程基本信息

1. **POSIX Threads (pthreads)：** macOS 支持 POSIX 线程（`pthreads`），这是 C/C++ 的标准线程 API 的一部分。macOS 中的 pthreads 实现在 `/usr/lib/system/libsystem_pthread.dylib`，该库源自公开可用的 `libpthread` 项目。此库提供创建和管理线程所需的函数。
2. **创建线程：** `pthread_create()` 函数用于创建新线程。在内部，该函数会调用 `bsdthread_create()`，这是 XNU 内核（macOS 所基于的内核）专用的底层系统调用。此系统调用会接收从 `pthread_attr`（属性）派生的各种标志，用于指定线程行为，包括调度策略和栈大小。
   - **默认栈大小：** 新线程的默认栈大小为 512 KB，足以应对常见操作；如果需要更多或更少空间，可以通过线程属性进行调整。
3. **线程初始化：** `__pthread_init()` 函数在设置线程时至关重要，它会使用 `env[]` 参数解析环境变量，其中可能包含栈的位置和大小等信息。

#### macOS 中的线程终止

1. **退出线程：** 通常通过调用 `pthread_exit()` 来终止线程。此函数允许线程干净地退出，执行必要的清理工作，并向所有等待其结束的线程返回一个值。
2. **线程清理：** 调用 `pthread_exit()` 时，会调用 `pthread_terminate()`，以移除所有相关的线程结构。它会释放 Mach 线程端口（Mach 是 XNU 内核中的通信子系统），并调用 `bsdthread_terminate`——一个用于移除与该线程相关内核级结构的系统调用。

#### 同步机制

为管理对共享资源的访问并避免竞态条件，macOS 提供了多种同步原语。它们对多线程环境至关重要，可确保数据完整性和系统稳定性：

1. **互斥锁：**
   - **常规互斥锁（签名：0x4D555458）：** 标准互斥锁，占用 60 字节（互斥锁本身占 56 字节，签名占 4 字节）。
   - **快速互斥锁（签名：0x4d55545A）：** 与常规互斥锁类似，但经过优化，操作更快，大小同样为 60 字节。
2. **条件变量：**
   - 用于等待特定条件发生，大小为 44 字节（40 字节加上 4 字节签名）。
   - **条件变量属性（签名：0x434e4441）：** 条件变量的配置属性，大小为 12 字节。
3. **Once 变量（签名：0x4f4e4345）：**
   - 确保初始化代码只执行一次。大小为 12 字节。
4. **读写锁：**
   - 允许多个读者同时访问，或一次只有一个写入者，从而高效访问共享数据。
   - **读写锁（签名：0x52574c4b）：** 大小为 196 字节。
   - **读写锁属性（签名：0x52574c41）：** 读写锁的属性，大小为 20 字节。

> [!TIP]
> 这些对象的最后 4 个字节用于检测溢出。

### 线程局部变量 (TLV)

在 Mach-O 文件（macOS 中可执行文件的格式）中，**线程局部变量 (TLV)** 用于声明仅属于多线程应用程序中**各个线程**的变量。这样，每个线程都有各自独立的变量实例，无需使用互斥锁等显式同步机制，也能避免冲突并保持数据完整性。

在 C 及相关语言中，可以使用 **`__thread`** 关键字声明线程局部变量。下面是它在示例中的工作方式：

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

这段代码将 `tlv_var` 定义为线程局部变量。运行这段代码的每个线程都有自己的 `tlv_var`，一个线程对 `tlv_var` 所做的更改不会影响其他线程中的 `tlv_var`。

在 Mach-O 二进制文件中，与线程局部变量相关的数据会被组织到特定的 section 中：

- **`__DATA.__thread_vars`**：此 section 包含线程局部变量的元数据，例如变量类型和初始化状态。
- **`__DATA.__thread_bss`**：此 section 用于存储未显式初始化的线程局部变量。它是为零初始化数据预留的一部分内存。

Mach-O 还提供了一个名为 **`tlv_atexit`** 的专用 API，用于在线程退出时管理线程局部变量。通过此 API，可以**注册析构函数**——在线程终止时清理线程局部数据的特殊函数。

### 线程优先级

要理解线程优先级，需要了解操作系统如何决定运行哪些线程以及何时运行。这个决定受到分配给每个线程的优先级影响。在 macOS 和类 Unix 系统中，这通过 `nice`、`renice` 和服务质量（QoS）类等概念实现。

#### Nice 和 Renice

1. **Nice：**
   - 进程的 `nice` 值是一个影响其优先级的数字。每个进程的 nice 值范围为 -20（最高优先级）到 19（最低优先级）。进程创建时的默认 nice 值通常为 0。
   - 较低的 nice 值（接近 -20）会让进程更“自私”，相较于 nice 值较高的其他进程，获得更多 CPU 时间。
2. **Renice：**
   - `renice` 是用于更改已在运行进程的 nice 值的命令。通过动态调整进程的 nice 值，可以相应地增加或减少其 CPU 时间分配。
   - 例如，如果某个进程暂时需要更多 CPU 资源，可以使用 `renice` 降低它的 nice 值。

#### 服务质量（QoS）类

QoS 类是处理线程优先级的较新方法，尤其适用于支持 **Grand Central Dispatch (GCD)** 的 macOS 等系统。QoS 类允许开发者根据工作的重要性或紧急程度，将其**分类**到不同级别。macOS 会根据这些 QoS 类自动管理线程优先级：

1. **User Interactive：**
   - 此类用于当前正在与用户交互，或需要立即提供结果以确保良好用户体验的任务。这些任务具有最高优先级，以保持界面响应迅速（例如动画或事件处理）。
2. **User Initiated：**
   - 此类用于用户主动发起且期望立即得到结果的任务，例如打开文档，或点击需要进行计算的按钮。这些任务优先级较高，但低于 User Interactive。
3. **Utility：**
   - 此类用于长时间运行且通常会显示进度指示器的任务（例如下载文件、导入数据）。其优先级低于 User Initiated，且无需立即完成。
4. **Background：**
   - 此类用于在后台运行且对用户不可见的任务，例如索引、同步或备份。这些任务优先级最低，对系统性能的影响也最小。

使用 QoS 类时，开发者无需管理具体的优先级数值，只需关注任务的性质，系统会据此优化 CPU 资源。

此外，还有不同的**线程调度策略**，它们用于指定一组调度参数，供调度器参考。可以通过 `thread_policy_[set/get]` 设置这些策略。这可能对 race condition 攻击有所帮助。

## macOS 进程滥用

macOS 提供了许多机制，供**进程交互、通信和共享数据**。这些机制对系统正常运行至关重要，但攻击者也可能滥用它们来进行注入、代码执行或数据访问。

### Library Injection

Library Injection 是一种攻击者**强制进程加载恶意库**的技术。注入后，该库会在目标进程的上下文中运行，使攻击者获得与该进程相同的权限和访问能力。


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking 涉及在软件代码中**拦截函数调用**或消息。通过 hook 函数，攻击者可以**修改进程的行为**、观察敏感数据，甚至控制执行流程。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

本页介绍 ARM64 unwind 元数据、arm64e PAC 限制，以及合成调用链。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication（IPC）指不同进程之间**共享和交换数据**的各种方法。IPC 对许多合法应用至关重要，但也可能被滥用来破坏进程隔离、leak 敏感信息或执行未授权操作。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

使用特定环境变量运行的 Electron 应用可能容易受到进程注入攻击：


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

可以使用 `--load-extension` 和 `--use-fake-ui-for-media-stream` 标志实施 **man in the browser attack**，从而窃取按键输入、流量、cookie，在页面中注入脚本……：


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB 文件**定义用户界面（UI）元素**及其在应用中的交互方式。不过，它们可以**执行任意命令**；如果修改了 **NIB 文件**，Gatekeeper 不会阻止已经执行过的应用再次执行。因此，可以利用它们让任意程序执行任意命令：


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

可以通过 **`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`** 或 **`JDK_JAVA_OPTIONS`** 注入 JVM 选项，在应用启动前加载 Java agent 或 native agent。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** 可通过 `--require`（文件）或 `--import data:text/javascript,…`（无文件，Node ≥ 20.6）预加载攻击者控制的 JavaScript；**`NODE_REPL_EXTERNAL_MODULE`** 可将模块加载到交互式 REPL 中，而 **`ELECTRON_RUN_AS_NODE`** 可在 Electron 二进制文件上重新启用上述所有功能。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

可以通过 **`DOTNET_STARTUP_HOOKS`** 在 `Main` 之前向 .NET 应用注入代码，也可以在满足前置条件时滥用 .NET 调试功能。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非交互式 Bash 会读取 **`BASH_ENV`**；交互式 POSIX shell 会读取 **`ENV`**；zsh 会读取 **`$ZDOTDIR/.zshenv`**；fish 会读取 **`XDG_CONFIG_HOME`** 或 **`XDG_DATA_DIRS`** 下的配置文件。它们都可以在预期命令执行前运行攻击者控制的启动文件。启用 xtrace 时，Bash 还会执行放在 **`PS4`** 中的命令替换（例如继承的 **`SHELLOPTS=xtrace`**）：

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

启动 `/bin/zsh -s` 会让 shell 从标准输入读取程序。因此，如果下载器没有先解析不可信的结构化文档，就将其复制到子进程的 stdin 中，整份文档就会变成 shell 源代码。曾观察到一个 loader 通过匿名管道逐行输入公开的 iCalendar 文件。日历元数据作为命令执行失败，但 zsh 会继续处理，直到遇到放在 `DESCRIPTION:` 后面的可执行行。这些行会下载并启动下一个应用程序 bundle。载体预期的内容类型和可信的托管服务并不能保证安全；真正危险之处在于将其字节传递给解释器。<sup>[[5]](#references)</sup>

相关阶段见 [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)、[Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) 和 [macOS auto-start locations](../../macos-auto-start-locations.md)。

### PHP Injection

**`PHPRC`** 或 **`PHP_INI_SCAN_DIR`** 可以加载攻击者控制的 PHP 配置，其中的 **`auto_prepend_file`** 会在目标脚本运行前执行。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

独立的 Lua 解释器会在处理目标脚本前，执行 **`LUA_INIT`**（或其特定版本变体）中指定的代码或 `@file`。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** 和 **`R_PROFILE`** 可将启动配置文件重定向到包含 R 代码的文件。也可以结合 R library 路径使用 **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**，自动加载已安装的 package。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** 可重定向 depot，自动执行其中的 `config/startup.jl`。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`** 或 **`ERL_ZFLAGS`** 可以注入 Erlang VM **`-eval`** 表达式，无需 payload 文件；Elixir 工作负载通常也会启动同一个 VM。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** 和 **`OCTAVE_VERSION_INITFILE`** 可重定向 Octave 启动脚本。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` 是跨平台 .NET 应用，因此多个环境变量可以让代码在命令执行前运行：**`XDG_CONFIG_HOME`** 可重定向启动时运行的 profile 脚本；**`PSModulePath`** 可劫持模块自动加载（植入的 `.psm1` 会在导入时运行，并可替代内置 cmdlet）；.NET 的 **`CORECLR_PROFILER`**/**`COR_PROFILER`** 和 **`DOTNET_STARTUP_HOOKS`** 变量可在 `Main` 之前将攻击者代码加载到进程中。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

了解如何通过不同选项让 Perl 脚本执行任意代码：


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

也可以滥用 Ruby 环境变量（**`RUBYOPT`**、**`RUBYLIB`**），让任意脚本执行任意代码：


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

标准库链 **`PYTHONWARNINGS`** 和 **`BROWSER`** 可在解析 warning filter 时执行命令。另一种基于文件的方法是在 **`PYTHONPATH`** 中放置 `sitecustomize.py`，让正常的 `site` 初始化在目标脚本运行前导入它。代码执行到 `breakpoint()` 时，**`PYTHONBREAKPOINT`** 会运行指定的 callable/module。仅适用于交互式环境的变量（例如 **`PYTHONSTARTUP`**）适用范围较窄。

请注意，即使使用内嵌 Python 运行，使用 **`pyinstaller`** 编译的可执行文件也不会使用这些环境变量。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`**（及其备用变量 `EXINIT`）会在正常启动时作为 Ex 命令执行。因此，当受害者在攻击者控制的环境中打开 Vim/Neovim 时，`:!cmd` / `:call system(...)` 可以实现代码执行：

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

此外，Homebrew 通常会在 `/opt/homebrew` 下安装 Python，当地 `admin` 组成员可能有权替换其启动器。这属于可写二进制文件劫持，而不是环境变量注入；在认定其可被利用前，请检查所有权和 ACL。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) 是一款基于 **EndpointSecurity** 的开源应用，可检测并阻止进程注入。它可以作为了解哪些信号能通过 Endpoint Security 观测到的参考，因为它会对以下行为发出警报：<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- 进程执行时出现的**注入环境变量**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH` 和 `ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** 调用——一个进程请求另一个进程的 task port，这是向其注入代码的前提。
- **Electron 调试参数**——`--inspect`、`--inspect-brk` 和 `--remote-debugging-port`，这些参数会以调试模式启动 Electron 应用，使任何人都能附加到其中并运行代码。<sup>[[3]](#references)</sup>
- **跨权限级别创建符号链接/硬链接**——经典的“以普通用户身份创建链接，再将其指向特权位置”的原语。请注意，**可以对符号链接发出警报，但无法阻止其创建**：EndpointSecurity 不会在链接创建前公开其目标位置。

### 其他进程发起的调用

在[**这篇博文**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以了解如何使用 **`task_name_for_pid`** 函数获取有关**向进程注入代码的其他进程**的信息，然后获取该其他进程的信息。<sup>[[4]](#references)</sup>

请注意，调用该函数需要与运行目标进程的用户具有**相同的 uid**，或者拥有 **root** 权限（该函数返回的是进程信息，而不是注入代码的方法）。

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — 开源 macOS 进程注入检测工具（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity 框架](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - 为什么 Electron 应用无法机密地存储你的秘密：--inspect 选项](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - 检测 task 修改](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer 新版本瞄准加密货币爱好者和开发者](https://securelist.com/macsync-new-version/121383/)
