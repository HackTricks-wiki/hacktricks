# macOS 应用 - 检查、调试与 Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## 静态分析

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (old jtool2)

你可以[**从这里下载 disarm**](https://newosxbook.com/tools/disarm.html)。

> [!TIP]
> 注意，**`disarm`** 也可以处理压缩的 IM4P 文件（例如 `kernelcache`），并提取所需部分，甚至无需提取即可分析所需部分。

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`** 可在 **macOS** 中找到，而 **`ldid`** 可在 **iOS** 中找到。

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) 是一个用于检查 **.pkg** 文件（安装程序）的工具，可以在安装前查看其中的内容。\
这些安装程序包含 `preinstall` 和 `postinstall` bash 脚本，恶意软件作者通常会滥用它们来让 **malware** **持久化**。

### hdiutil

这个工具可以**挂载** Apple 磁盘映像（`.dmg`）文件，以便在运行任何内容之前进行检查：

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

它将挂载在 `/Volumes`

### Packed binaries

- 检查是否具有高熵
- 检查字符串（如果几乎没有可理解的字符串，说明已打包）
- macOS 的 UPX packer 会生成一个名为 `__XHDR` 的 section。

## Objective-C 静态分析

### 元数据

> [!CAUTION]
> 请注意，用 Objective-C 编写的程序在编译为 [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) 后，仍会**保留**其类声明。这些类声明**包括**以下内容的名称和类型：

- 定义的接口
- 接口方法
- 接口实例变量
- 定义的协议

请注意，这些名称可能会被混淆，以增加逆向分析二进制文件的难度。

### 函数调用

在使用 Objective-C 的二进制文件中调用函数时，编译后的代码不会直接调用该函数，而是调用 **`objc_msgSend`**。它会调用最终的函数：

![元数据 - 函数调用：在使用 Objective-C 的二进制文件中调用函数时，编译后的代码不会直接调用该函数，而是调用 objc_msgSend。它会调用……](<../../../images/image (305).png>)

该函数需要以下参数：

- 第一个参数（**self**）是“一个指针，指向**接收消息的类实例**”。简单来说，它就是调用该方法的对象。如果是类方法，它指向类对象本身的一个实例；如果是实例方法，self 则指向该类的一个实例化对象。
- 第二个参数（**op**）是“处理该消息的方法的 selector”。简单来说，它就是**方法的名称**。
- 其余参数是该方法（op）所需的**任意值**。

请参阅此页面，了解如何在 **ARM64 中使用 `lldb` 轻松获取这些信息**：


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64：

| **参数** | **寄存器** | **（用于）objc_msgSend** |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **第 1 个参数**  | **rdi**                                                         | **self：调用该方法的对象** |
| **第 2 个参数**  | **rsi**                                                         | **op：方法名称**                             |
| **第 3 个参数**  | **rdx**                                                         | **方法的第 1 个参数**                         |
| **第 4 个参数**  | **rcx**                                                         | **方法的第 2 个参数**                         |
| **第 5 个参数**  | **r8**                                                          | **方法的第 3 个参数**                         |
| **第 6 个参数**  | **r9**                                                          | **方法的第 4 个参数**                         |
| **第 7 个及后续参数** | <p><strong>rsp+</strong><br><strong>（在栈上）</strong></p> | **方法的第 5 个及后续参数**                        |

### 转储 Objective-C 元数据

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) 是一个用于对 Objective-C binaries 执行 class-dump 的工具。GitHub 页面提到的是 dylibs，但它也适用于可执行文件。

```bash
./dynadump dump /path/to/bin
```

在撰写本文时，**目前这是效果最好的方法**。

#### 常规工具

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) 是最初用于从 ObjectiveC 格式的代码中生成类、类别和协议声明的工具。

它已经过时且无人维护，因此可能无法正常工作。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) 是一款现代、跨平台的 Objective-C 类转储工具。与现有工具相比，iCDump 可独立于 Apple 生态系统运行，并提供 Python 绑定。

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## 静态 Swift 分析

对于 Swift 二进制文件，由于兼容 Objective-C，有时可以使用 [class-dump](https://github.com/nygard/class-dump/) 提取声明，但并非总是可行。

使用 **`jtool -l`** 或 **`otool -l`** 命令行工具，可以找到若干以 **`__swift5`** 为前缀的 section：

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

你可以在[**这篇博客文章中找到有关这些 section 中存储的信息的更多内容**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)。<sup>[[5]](#references)</sup>

此外，**Swift 二进制文件可能包含符号**（例如，库需要存储符号，才能调用其中的函数）。**符号通常会以一种不易读的形式包含函数名称和属性信息**，因此非常有用；而且还有一些“**demangler**”，可以还原出原始名称：

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## 动态分析

> [!WARNING]
> **不要将禁用 SIP 作为默认调试步骤。**启用 `com.apple.security.get-task-allow` 的开发版本可在 SIP 开启时进行调试。尝试使用 LLDB 前，先用 `codesign -d --entitlements :- /path/to/binary` 检查目标。仅有调试器 entitlement 并不能授予访问受 SIP 保护目标的权限。<sup>[[15]](#references)</sup>
>
> 使用 hardened runtime 的已分发应用通常不会启用 `get-task-allow`，并会阻止调试器附加。如果可以，请使用开发者提供的调试版本；对临时副本重新签名可能会改变被测行为。如果受保护的目标必须在禁用 SIP 后才能调试，请使用专用测试机或 VM，而不要使用你日常依赖的机器。<sup>[[16]](#references)</sup>
>
> 早期针对隔离测试环境中受保护目标的指导列出了以下替代方案：
>
> 请注意，要调试二进制文件，需要禁用 SIP（`csrutil disable` 或 `csrutil enable --without debug`），或者将二进制文件复制到临时文件夹并使用 `codesign --remove-signature <binary-path>` 移除签名，或者允许调试该二进制文件（你可以使用[这个脚本](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)）
>
> 这并非 SIP 的通用要求：优先使用调试版本，并注意复制或更改签名可能会改变被测行为。

> [!WARNING]
> 请注意，要在 macOS 上**插桩系统二进制文件**（例如 `cloudconfigurationd`），**必须禁用 SIP**（仅移除签名不起作用）。

### APIs

macOS 提供了一些有用的 API，可用于获取进程信息：

- `proc_info`：这是主要接口，可提供大量进程信息。要获取其他进程的信息，你需要 root 权限，但不需要特殊 entitlement 或 mach port。
- `libsysmon.dylib`：通过 XPC 函数提供进程信息，但调用方需要 `com.apple.sysmond.client` entitlement。

### Stackshot 与 microstackshots

**Stackshot** 是一种用于捕获进程状态的技术，其中包括所有运行线程的调用栈。这对于调试、性能分析以及了解系统在特定时刻的行为尤其有用。在 iOS 和 macOS 上，可以使用 **`sample`** 和 **`spindump`** 等工具和方法执行 stackshot。

### Sysdiagnose

这个工具（`/usr/bini/ysdiagnose`）基本上会通过执行数十条不同的命令（例如 `ps`、`zprint`……）来收集计算机的大量信息。

必须以 **root** 身份运行；其守护进程 `/usr/libexec/sysdiagnosed` 拥有一些非常有趣的 entitlement，例如 `com.apple.system-task-ports` 和 `get-task-allow`。

它的 plist 位于 `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`，其中声明了 3 个 MachServices：

- `com.apple.sysdiagnose.CacheDelete`：删除 /var/rmp 中的旧归档
- `com.apple.sysdiagnose.kernel.ipc`：特殊端口 23（kernel）
- `com.apple.sysdiagnose.service.xpc`：通过 `Libsysdiagnose` Obj-C 类提供的用户模式接口。可以在字典中传入三个参数（`compress`、`display`、`run`）

### Unified Logs

macOS 会生成大量日志，有助于分析应用程序的行为。

某些日志字段会包含 `<private>` 标签，以隐藏可识别用户或设备的信息。较早的说明有时会提到安装证书以显示这些字段；当前的调试指导则使用作用范围明确的配置描述文件，其中设置 `Enable-Private-Data`，或使用针对单个应用程序的 `OSLogPreferences`。具体行为可能因子系统和 macOS 版本而异。较早的证书/描述文件说明保留在参考资料中。<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### 左侧面板

在 Hopper 的左侧面板中，可以查看二进制文件的符号（**Labels**）、过程和函数列表（**Proc**），以及字符串（**Str**）。这里并不包含所有字符串，只包含定义在 Mac-O 文件若干部分中的字符串（例如 _cstring 或 `objc_methname`）。

#### 中间面板

在中间面板中可以查看**反汇编代码**。点击相应图标，可以用**原始**反汇编、**图形**、**反编译**和**二进制**视图查看代码：

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

右键点击代码对象，可以查看该对象的**引用关系**，也可以更改其名称（在反编译的伪代码中无法使用此功能）：

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

此外，可以在**中下方输入 python 命令**。

#### 右侧面板

在右侧面板中可以查看有用信息，例如**导航历史记录**（了解你如何到达当前状态）、**调用图**（查看所有**调用此函数的函数**以及此函数**调用的所有函数**），还有**局部变量**信息。

### dtrace

它允许用户以极**底层**的方式访问应用程序，并提供一种**跟踪** **程序**甚至更改其执行流的方法。Dtrace 使用**探针**，这些探针**分布在整个 kernel 中**，并位于系统调用的开头和结尾等位置。

DTrace 使用 **`dtrace_probe_create`** 函数为每个系统调用创建探针。这些探针可在每个系统调用的**入口和出口处触发**。DTrace 通过 /dev/dtrace 进行交互，该设备仅 root 用户可用。<sup>[[1]](#references)</sup>

> [!TIP]
> 若要在不完全禁用 SIP 保护的情况下启用 Dtrace，可以在恢复模式下执行：`csrutil enable --without dtrace`
>
> 你也可以对**自己编译的**二进制文件使用 **`dtrace`** 或 **`dtruss`**。

可以通过以下命令获取 dtrace 的可用探针：

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

探针名称由四部分组成：provider、module、function 和 name（`fbt:mach_kernel:ptrace:entry`）。如果未指定名称中的某些部分，DTrace 会将这些部分视为通配符。

要配置 DTrace 激活探针，并指定探针触发时要执行的操作，我们需要使用 D 语言。

更详细的说明和更多示例请参见 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### 示例

运行 `man -k dtrace` 可列出**可用的 DTrace 脚本**。示例：`sudo dtruss -n binary`

- 行内

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- 脚本

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

这是一个 kernel tracing facility。文档中列出的 codes 可在 **`/usr/share/misc/trace.codes`** 找到。

`latency`、`sc_usage`、`fs_usage` 和 `trace` 等工具在内部使用它。

要与 `kdebug` 交互，可通过 `kern.kdebug` namespace 使用 `sysctl`；要使用的 MIB 可在 `sys/sysctl.h` 中找到，相关函数实现在 `bsd/kern/kdebug.c` 中。

使用自定义 client 与 kdebug 交互时，通常需要执行以下步骤：

- 使用 KERN_KDSETREMOVE 移除现有设置
- 使用 KERN_KDSETBUF 和 KERN_KDSETUP 设置 trace
- 使用 KERN_KDGETBUF 获取 buffer entries 的数量
- 使用 KERN_KDPINDEX 从 trace 中获取自己的 client
- 使用 KERN_KDENABLE 启用 tracing
- 调用 KERN_KDREADTR 读取 buffer
- 使用 KERN_KDTHRMAP 将每个 thread 与其 process 对应起来

要获取这些信息，可以使用 Apple 工具 **`trace`** 或自定义工具 [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**。**

**注意，Kdebug 同一时间只能供 1 个使用者使用。** 因此，同一时间只能运行一个基于 k-debug 的工具。

### ktrace

`ktrace_*` APIs 来自 `libktrace.dylib`，它封装了 `Kdebug` 的 APIs。随后，client 只需调用 `ktrace_session_create` 和 `ktrace_events_[single/class]`，为特定 codes 设置 callbacks，然后使用 `ktrace_start` 启动即可。

即使 **SIP 已启用**，也可以使用这个工具。

可以使用工具 `ktrace` 作为 client：

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

或者 `tailspin`。

### kperf

它用于进行内核级性能分析，并基于 `Kdebug` 调用点构建。

基本上，系统会检查全局变量 `kernel_debug_active`；如果该变量已设置，就会调用 `kperf_kdebug_handler`，并传入 `Kdebug` 代码和调用方内核栈帧的地址。如果 `Kdebug` 代码与某个已选代码匹配，就会执行以位图形式配置的“操作”（可查看 `osfmk/kperf/action.h` 中的选项）。

Kperf 还有一个 sysctl MIB 表：（以 root 身份运行）`sysctl kperf`。这些代码可以在 `osfmk/kperf/kperfbsd.c` 中找到。

此外，Kperf 的部分功能由 `kpc` 提供，它可以获取机器性能计数器的信息。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) 是一款非常实用的工具，可用于检查进程执行的相关操作（例如，监控某个进程创建了哪些新进程）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) 是一款用于显示进程间关系的工具。\
你需要使用类似 **`sudo eslogger fork exec rename create > cap.json`** 的命令监控你的 Mac（运行该命令的终端需要 FDA）。然后，你可以将 json 文件载入此工具，以查看所有关系：

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) 可监控文件事件，例如创建、修改和删除。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) 是一款 GUI 工具，其外观和使用体验类似于 Windows 用户熟悉的 Microsoft Sysinternals _Procmon_。该工具支持开始和停止记录各类事件，按文件、进程、网络等类别筛选这些事件，并可将记录的事件保存为 json 格式。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) 是 Xcode Developer tools 的一部分，可用于监控应用程序性能、识别内存泄漏以及跟踪文件系统活动。

![Crescendo - Apple Instruments：Apple Instruments 是 Xcode Developer tools 的一部分，可用于监控应用程序性能、识别内存泄漏以及跟踪文件系统活动](<../../../images/image (1138).png>)

### fs_usage

可用于跟踪进程执行的操作：

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) 可用于查看二进制文件使用的**库**、正在使用的**文件**以及**网络**连接。\
它还会将二进制文件的进程与 **virustotal** 进行比对，并显示有关该二进制文件的信息。

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

在[**这篇博客文章**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)中，你可以找到一个示例，介绍如何**调试正在运行的守护进程**，该进程使用 **`PT_DENY_ATTACH`** 阻止调试，即使 SIP 已禁用也不例外。<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` 是 Darwin 专用的 `ptrace(2)` 请求，值为 **31**（`0x1f`）；其他参数会被忽略。进程可以直接调用它，无需 fork，以拒绝之后由父进程进行的跟踪。<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU 状态与调用顺序

结果取决于哪个 `ptrace` 请求先到达 XNU：<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB 先附加：** `debugserver` 使用 `PT_ATTACHEXC`；XNU 将其转换为 `PT_ATTACH`，执行 `KAUTH_PROCESS_CANTRACE` 授权，并在目标进程上设置 `P_LTRACED`。随后到达的 `PT_DENY_ATTACH` 会检测到该标志，并以 `W_EXITCODE(ENOTSUP, 0)` 终止目标进程；LLDB 通常会将其显示为状态 **45** (`0x2d`)。
- **目标进程先拒绝：** XNU 设置 `P_LNOATTACH`。后续附加会被进程跟踪授权拒绝；附加错误处理路径检测到 `P_LNOATTACH` 后，会向发起附加的进程发送 `SIGSEGV`，这可能会在 LLDB 中表现为 `debugserver` 连接丢失。

要区分这两种路径，请在启动或附加之前启用 `debugserver` 日志，并检查其 `ptrace` 请求：<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 静态识别与绕过

对于未混淆的 ARM64 Mach-O，定位导入的 `_ptrace` stub 并检查调用点。第一个整数参数通过 `w0` 传递，因此可以从这段指令序列直接看出反调试请求。未导入该符号并不能证明不存在反调试检查，因为代码可以动态解析 `ptrace`。导入的 `_sysctl` 也可能表明存在反调试检查，但它同样可能通过动态解析获得。<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

在演示的示例中，将立即数从 `0x1f` 修补为 `0x0` 会把请求改为 `PT_TRACE_ME`，使程序能够在 LLDB 下继续运行。这是**针对特定示例的绕过方法**，并非通用的空操作：在决定是更改请求、跳过调用还是强制返回成功之前，请检查调用方对返回值的检查及其控制流。<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** 是 **macOS** 二进制文件 **调试** 的事实标准工具。

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

使用 lldb 时，可以在主目录中创建名为 **`.lldbinit`** 的文件，并添加以下行来设置 Intel 风格：

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> 在 lldb 中，使用 `process save-core` 转储进程

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) 命令</strong></td><td><strong>描述</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>开始执行，直到命中断点或进程终止。</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>开始执行，并在入口点处停止。</td></tr>
<tr><td><strong>continue (c)</strong></td><td>继续执行正在调试的进程。</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>执行下一条指令。此命令会跳过函数调用。</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>执行下一条指令。与 <code>nexti</code> 命令不同，此命令会进入函数调用。</td></tr>
<tr><td><strong>finish (f)</strong></td><td>执行当前函数（帧）中的剩余指令，返回并暂停。</td></tr>
<tr><td><strong>control + c</strong></td><td>暂停执行。如果进程已运行（<code>r</code>）或继续运行（<code>c</code>），此操作会让进程在当前执行位置停止。</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Any function called main</p>
<p><code>b &lt;binname&gt;`main</code> # Main function of the binary</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Main function of the indicated binary</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Any NSFileManager method</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint list</p>
<p><code>br e/dis &lt;num&gt;</code> # Enable/disable breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Get help for the breakpoint command</p>
<p><code>help memory write</code> # Get help for writing to memory</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>将内存显示为以 null 结尾的字符串。</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>将内存显示为汇编指令。</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>将内存显示为字节。</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>打印参数所引用的对象。</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>大多数 Apple Objective-C API 或方法都会返回对象，因此应使用“print object”（<code>po</code>）命令显示。如果 <code>po</code> 没有产生有意义的输出，请使用 <code>x/b</code>。</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Write AAAA at that address<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Write AAAA at the address
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassemble the current function</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassemble a function</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassemble a function<br>
<code>dis -c 6</code> # Disassemble six lines<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassemble from one address to the other<br>
<code>dis -p -c 4</code> # Start disassembling at the current address</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspect an array of three components in the <code>x1</code> register</td></tr>
<tr><td><strong>image dump sections</strong></td><td>打印当前进程内存的映射。</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Get the address of every symbol from CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> 调用 **`objc_sendMsg`** 函数时，**rsi** 寄存器保存着**方法名**，它是一个以 null 结尾的（“C”）字符串。要通过 lldb 打印方法名，请执行：
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### 反动态分析

#### VM 检测

- 在物理硬件上，命令 **`sysctl hw.model`** 通常会返回 Mac 型号标识符；在 VM 中则可能返回不同的值。<sup>[[3]](#references)</sup>
- 一些恶意软件会通过调整 **`hw.logicalcpu`** 和 **`hw.physicalcpu`** 的值，尝试检测是否运行在 VM 中。<sup>[[4]](#references)</sup>
- 加载器在解包下一阶段之前，也可能通过 `sysctl` 查询 `kern.hv_vmm_present` 和 `machdep.cpu.brand_string`，以检查是否运行在 VM 中。这些检查是对下文所述调试器附加检测的补充，而非替代。<sup>[[20]](#references)</sup>
- 一些恶意软件还可以根据 MAC 地址（00:50:56）**检测**机器是否基于 **VMware**。
- 也可以用如下简单代码检查**进程是否正在被调试**：
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- 还可以使用带有 `PT_DENY_ATTACH` 标志的 `ptrace` 系统调用。这会阻止调试器附加并跟踪进程。有关其依赖调用顺序的 XNU 行为、`debugserver` 日志记录和 ARM64 修补流程，请参阅 [PT_DENY_ATTACH 部分](#page-title)。<sup>[[7]](#references)[[12]](#references)</sup>
- 还可以使用带有 **`PT_DENY_ATTACH`** 标志的 **`ptrace`** 系统调用。有关其依赖调用顺序的 XNU 行为、`debugserver` 日志记录和 ARM64 修补流程，请参阅 [PT_DENY_ATTACH 部分](#page-title)。<sup>[[7]](#references)[[12]](#references)</sup>
  - 可以检查 **`sysctl`** 或 **`ptrace`** 函数是否被**导入**（但恶意软件可能会动态导入它）
  - 正如这篇文章 “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” 所述：<sup>[[7]](#references)</sup>\
    “_消息 Process # exited with **status = 45 (0x0000002d)** 通常是一个明显迹象，表明调试目标正在使用 **PT_DENY_ATTACH**_”

#### `fork()` 进程交接

进程可以在启动附近调用 `fork()`，以规避仍附加在原始 PID 上的调试器：终止父进程（`fork()` 返回正数子 PID），并仅在子进程中继续执行受保护逻辑（`fork()` 返回 `0`）。使用 `dlsym(RTLD_DEFAULT, "fork")` 解析 `fork` 也会隐藏直接的 `_fork` 调用点，但这只是一个反分析障碍：符号名称字符串和动态解析的数据流仍可在 Mach-O 二进制文件中看到。<sup>[[13]](#references)[[14]](#references)</sup>

在 arm64 上，应通过追踪数据流而非固定地址来识别此模式：传给 `dlsym` 的前两个参数位于 `x0` 和 `x1` 中，`RTLD_DEFAULT` 可能显示为 `-2`（例如 `movn x0, #1`），而 `adrp`/`add` 指令对通常会构造 `"fork"` 字符串的地址。在 `bl` 跳转到 `dlsym` 存根后，跟踪返回指针从 `x0` 经 null 检查和存储，直到后续的间接 `blr`。接着跟踪 `fork()` 在 `w0` 中的返回值：零会选择子进程的后续执行路径，正数和 `-1` 则会选择父进程或错误路径。<sup>[[13]](#references)[[14]](#references)</sup>

一种静态绕过方法是抑制间接调用，并强制现有结果检查走子进程路径。例如，如果编译器生成了下方所示的指令序列，可以将 `blr` 和结果存储指令修补为 `nop`，提供一个合成的零结果，并保留比较和分支逻辑。这样，应用程序就会在不创建子进程的情况下继续以原始 PID 运行；需要根据分析的构建版本调整指令寄存器和分支目标。<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## 核心转储

在以下情况下会创建核心转储：

- `kern.coredump` sysctl 设置为 1（默认值）
- 如果进程不是 suid/sgid，或者 `kern.sugid_coredump` 为 1（默认值为 0）
- `AS_CORE` 限制允许此操作。可以通过调用 `ulimit -c 0` 禁止创建核心转储，并通过 `ulimit -c unlimited` 重新启用。

在这些情况下，核心转储会根据 `kern.corefile` sysctl 生成，通常存储在 `/cores/core/.%P`。

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **会分析崩溃的进程，并将崩溃报告保存到磁盘**。崩溃报告包含的信息可以**帮助开发者诊断**崩溃原因。\
对于**在每用户 launchd 上下文中运行**的应用程序和其他进程，ReportCrash 会作为 LaunchAgent 运行，并将崩溃报告保存到用户的 `~/Library/Logs/DiagnosticReports/`\
对于守护进程、**在系统 launchd 上下文中运行**的其他进程，以及其他特权进程，ReportCrash 会作为 LaunchDaemon 运行，并将崩溃报告保存到系统的 `/Library/Logs/DiagnosticReports`

如果你担心崩溃报告**被发送给 Apple**，可以将其禁用。否则，崩溃报告有助于**查明服务器崩溃的原因**。

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### 睡眠

在 macOS 上进行 fuzzing 时，防止 Mac 进入睡眠状态：

- systemsetup -setsleep Never
- pmset、系统设置
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 断开连接

如果通过 SSH 连接进行 fuzzing，请务必确保会话不会断开。因此，请修改 sshd_config 文件：

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### 内部处理程序

**查看以下页面**，了解如何查找负责**处理指定 scheme 或 protocol** 的 app：


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### 枚举网络进程

这有助于查找管理网络数据的进程：

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

或者使用 `netstat` 或 `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### 有状态 Mach IPC fuzzing

特权 daemon 暴露的 Mach 服务是很有用的 fuzz 目标，前提是非特权或受沙箱限制的客户端能够获得 send right。从 daemon 的 `MachServices` launchd 条目入手，使用 [MIG 分析流程](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)将消息 ID 映射到处理程序。修改字节之前，先在正常客户端调用该服务时对 MIG server routine 设置断点，并保存有效的请求消息作为 seed inputs。保留必需的 header 字段、消息大小和 descriptor 布局，确保变异后的消息能到达处理程序，而不是在 dispatch 阶段立即失败。<sup>[[17]](#references)</sup>

许多处理程序依赖之前的调用。让 harness 初始化服务状态，然后将每个 fuzz 输入作为一系列**操作及参数**处理：发送设置请求（例如 open 或 create），保留返回的标识符，并在后续请求中使用。这样，coverage feedback 就能探索状态转换，而不是一再触发“对象未初始化”检查。<sup>[[17]](#references)</sup>

对于闭源目标，可使用 Jackalope/TinyInst 对调用 MIG dispatch routine 的进程内 harness 进行插桩。[CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) 是一个具体实现，并非可直接用于其他服务的通用 harness。<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**通过真实 IPC 路径验证每次崩溃。** 直接 dispatch 的 harness 会跳过内核对 Mach 消息的验证，因此可能产生误报，尤其是在提供无效的 out-of-line (OOL) 内存或 port descriptors 时。在 harness 中分配有效的 OOL 后备内存，然后通过具有原始服务访问权限的客户端，使用 `mach_msg` 重放精简后的 testcase，并确认 daemon 仍会崩溃。<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

适用于 CLI 工具

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

它对许多 macOS GUI 工具都“**开箱即用**”。某些应用还有额外要求，例如使用唯一文件名、指定扩展名，或从其沙箱容器读取文件（`~/Library/Containers/com.apple.Safari/Data`）。

一些示例：

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### 更多 macOS Fuzzing 信息

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [OS X 事件响应：脚本编写与分析](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Fuzzing 之夏：MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac Malware 技术：第一卷：分析](https://taomm.org/)
- [4] [No Starch Press - Mac Malware 技术：恶意软件分析指南](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - 本博客文章中这些 section 存储的信息](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - 调试使用 Pt Deny Attach 的 Apple 二进制文件](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - 绕过反调试技术：macOS ptrace 变体](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode 结构化日志和 `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - 在 macOS 统一日志中显示 private data](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h` 请求定义](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU 在 `mach_process.c` 中的 `ptrace` 实现](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptrace 内部机制：它如何阻止 debugger 附加](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - fork 示例](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - 使用 dlsym 和 fork 的反调试技术](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Debugging 工具 entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - 调试经过强化的第三方 app](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - 打破声音屏障：第一部分：使用 Mach Messages 对 CoreAudio 进行 Fuzzing](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - 新版 MacSync macOS 窃密程序瞄准加密货币爱好者和开发者](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
