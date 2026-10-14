# macOS Apps - 检查、调试和 Fuzzing

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

You can [**在这里下载 disarm**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> 请注意，**`disarm`** 也可以处理压缩的 IM4P 文件（如 `kernelcache`），并提取所需部分，甚至可以在不提取的情况下分析所需部分。

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) 是一款用于检查 **.pkg** 文件（安装程序）的工具，可在安装前查看其中的内容。\
这些安装程序包含 `preinstall` 和 `postinstall` bash 脚本，恶意软件作者通常会滥用这些脚本来实现恶意软件持久化。

### hdiutil

此工具可**挂载** Apple 磁盘映像（`.dmg`）文件，以便在运行任何内容之前进行检查：

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

它将挂载在 `/Volumes`

### Packed binaries

- 检查是否具有高熵
- 检查字符串（如果几乎没有可理解的字符串，则说明已打包）
- macOS 的 UPX packer 会生成一个名为 `__XHDR` 的 section。

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> 请注意，用 Objective-C 编写的程序在编译为 [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) 后，**仍会保留**其类声明。这些类声明**包括**以下内容的名称和类型：

- 定义的接口
- 接口方法
- 接口实例变量
- 定义的协议

请注意，这些名称可能会被混淆，使二进制文件更难逆向分析。

### Function calling

在使用 Objective-C 的二进制文件中调用函数时，编译后的代码不会直接调用该函数，而是调用 **`objc_msgSend`**。它会调用最终的函数：

![Metadata - Function calling：在使用 objective-C 的二进制文件中调用函数时，编译后的代码不会直接调用该函数，而是调用 objc msgSend。它会调用……](<../../../images/image (305).png>)

此函数需要以下参数：

- 第一个参数（**self**）是“一个指向**接收消息的类实例**的指针”。简单来说，它就是调用该方法的对象。如果该方法是类方法，那么它指向类对象（整体）的一个实例；如果该方法是实例方法，self 则指向该类的一个已实例化对象。
- 第二个参数（**op**）是“处理该消息的方法的 selector”。简单来说，它就是**方法的名称**。
- 其余参数是该方法（op）所需的**值**。

请参阅此页面，了解如何在 **ARM64 中使用 `lldb` 轻松获取这些信息**：


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64：

| **参数**       | **寄存器**                                                     | **（用于）objc_msgSend**                              |
| -------------- | -------------------------------------------------------------- | ----------------------------------------------------- |
| **第 1 个参数** | **rdi**                                                        | **self：调用该方法的对象**                            |
| **第 2 个参数** | **rsi**                                                        | **op：方法名称**                                      |
| **第 3 个参数** | **rdx**                                                        | **方法的第 1 个参数**                                 |
| **第 4 个参数** | **rcx**                                                        | **方法的第 2 个参数**                                 |
| **第 5 个参数** | **r8**                                                         | **方法的第 3 个参数**                                 |
| **第 6 个参数** | **r9**                                                         | **方法的第 4 个参数**                                 |
| **第 7 个及之后的参数** | <p><strong>rsp+</strong><br><strong>（在栈上）</strong></p> | **方法的第 5 个及之后的参数**                         |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) 是一个用于对 Objective-C 二进制文件执行 class-dump 的工具。GitHub 页面上说它适用于 dylibs，但它也适用于可执行文件。

```bash
./dynadump dump /path/to/bin
```

在撰写本文时，**目前这是效果最好的一个**。

#### 常规工具

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) 是最初用于从 Objective-C 格式的代码中生成类、类别和协议声明的工具。

它已经过时且无人维护，因此可能无法正常工作。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) 是一款现代、跨平台的 Objective-C 类转储工具。与现有工具相比，iCDump 可以独立于 Apple 生态系统运行，并提供 Python 绑定。

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## 静态 Swift 分析

对于 Swift 二进制文件，由于 Swift 兼容 Objective-C，有时可以使用 [class-dump](https://github.com/nygard/class-dump/) 提取声明，但并非总是可行。

使用 **`jtool -l`** 或 **`otool -l`** 命令行工具，可以找到几个以 **`__swift5`** 为前缀的 section：

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

你可以在[**这篇博客文章中找到关于这些 section 中存储的信息的更多资料**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)。<sup>[[5]](#references)</sup>

此外，**Swift 二进制文件可能包含符号**（例如，库需要存储符号，以便调用其中的函数）。**符号通常会以难以阅读的形式包含函数名称和属性信息**，因此非常有用，而且还有一些“**反混淆器"**可以还原出原始名称：

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## 动态分析

> [!WARNING]
> **不要将禁用 SIP 作为默认的调试步骤。** 启用了 `com.apple.security.get-task-allow` 的开发版本在 SIP 启用时也可以调试。在尝试使用 LLDB 前，先用 `codesign -d --entitlements :- /path/to/binary` 检查目标。仅有 debugger entitlement 并不能授予访问受 SIP 保护目标的权限。<sup>[[15]](#references)</sup>
>
> 使用 hardened runtime 的分发版应用通常不会包含 `get-task-allow`，并会阻止调试器附加。如果可以，请使用开发者提供的调试版本；对一次性副本重新签名可能会改变被测行为。如果受保护的目标必须在禁用 SIP 的情况下才能运行，请使用专用测试机器或 VM，而不是你日常依赖的机器。<sup>[[16]](#references)</sup>

> [!WARNING]
> 请注意，要在 macOS 上**对系统二进制文件进行插桩**（例如 `cloudconfigurationd`），**必须禁用 SIP**（仅移除签名不起作用）。

### APIs

macOS 提供了一些有用的 APIs，可用于获取进程信息：

- `proc_info`：这是主要的信息来源，可提供大量有关每个进程的信息。要获取其他进程的信息，你需要 root 权限，但不需要特殊 entitlements 或 mach ports。
- `libsysmon.dylib`：通过 XPC 函数提供进程信息，但调用者需要 `com.apple.sysmond.client` entitlement。

### Stackshot & microstackshots

**Stackshot** 是一种用于捕获进程状态的技术，其中包括所有运行中线程的调用栈。这对于调试、性能分析以及了解系统在特定时刻的行为尤其有用。在 iOS 和 macOS 上，可以使用 **`sample`** 和 **`spindump`** 等工具，通过多种工具和方法执行 stackshot。

### Sysdiagnose

此工具（`/usr/bini/ysdiagnose`）基本上会收集电脑上的大量信息，例如执行 `ps`、`zprint` 等数十种不同命令。

它必须以 **root** 身份运行，而守护进程 `/usr/libexec/sysdiagnosed` 拥有一些非常有趣的 entitlements，例如 `com.apple.system-task-ports` 和 `get-task-allow`。

它的 plist 位于 `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`，其中声明了 3 个 MachServices：

- `com.apple.sysdiagnose.CacheDelete`：删除 /var/rmp 中的旧归档
- `com.apple.sysdiagnose.kernel.ipc`：特殊端口 23（kernel）
- `com.apple.sysdiagnose.service.xpc`：通过 `Libsysdiagnose` Obj-C class 提供的用户模式接口。可以传入一个包含三个参数的 dict（`compress`、`display`、`run`）

### Unified Logs

macOS 会生成大量日志，可用于分析应用的行为。

某些日志字段会包含 `<private>` 标签，以隐藏可识别用户或设备的信息。较早的说明有时会提到安装证书来显示这些字段；目前的调试指南则使用明确限定范围的配置描述文件，其中设置 `Enable-Private-Data`，或使用针对单个应用的 `OSLogPreferences`。实际行为可能因 subsystem 和 macOS 版本而异。较早的证书/配置描述文件说明保留在参考资料中。<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### 左侧面板

在 Hopper 的左侧面板中，可以查看二进制文件的符号（**Labels**）、过程和函数列表（**Proc**），以及字符串（**Str**）。这里并不包含所有字符串，而是 Mac-O 文件若干部分（例如 _cstring 或 `objc_methname`）中定义的字符串。

#### 中间面板

在中间面板中，可以查看**反汇编代码**。点击相应图标，可以将代码显示为**原始**反汇编、**图形**、**反编译**或**二进制**形式：

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

右键点击代码对象，可以查看该对象的**引用关系**，也可以更改其名称（在反编译的伪代码中无法进行此操作）：

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

此外，你还可以在**中下方编写 Python 命令**。

#### 右侧面板

在右侧面板中，可以查看一些有用的信息，例如**导航历史记录**（了解你是如何到达当前状态的）、**调用图**（查看所有**调用此函数的函数**以及此函数**调用的所有函数**），以及**局部变量**信息。

### dtrace

它允许用户以极**底层**的方式访问应用，并提供一种**跟踪** **程序**甚至改变其执行流程的方法。Dtrace 使用**探针**，这些探针**分布在整个 kernel 中**，位置包括系统调用的开始和结束处。

DTrace 使用 **`dtrace_probe_create`** 函数为每个系统调用创建一个探针。这些探针可以在每个系统调用的**入口和出口处触发**。与 DTrace 的交互通过 /dev/dtrace 进行，该设备仅 root 用户可用。<sup>[[1]](#references)</sup>

> [!TIP]
> 若要在不完全禁用 SIP 保护的情况下启用 Dtrace，可以在恢复模式下执行：`csrutil enable --without dtrace`
>
> 你也可以对**自己编译的**二进制文件运行 **`dtrace`** 或 **`dtruss`**。

可以使用以下命令获取 dtrace 可用的探针：

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

探针名称由四部分组成：provider、module、function 和 name（`fbt:mach_kernel:ptrace:entry`）。如果未指定名称的某一部分，Dtrace 会将该部分视为通配符。

要配置 DTrace 激活探针并指定探针触发时执行的操作，我们需要使用 D 语言。

更多详细说明和示例，请参阅 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### 示例

运行 `man -k dtrace` 列出**可用的 DTrace 脚本**。例如：`sudo dtruss -n binary`

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

它是一种内核跟踪设施。已记录的代码可在 **`/usr/share/misc/trace.codes`** 中找到。

`latency`、`sc_usage`、`fs_usage` 和 `trace` 等工具都在内部使用它。

要与 `kdebug` 交互，可通过 `kern.kdebug` 命名空间使用 `sysctl`。要使用的 MIB 可在 `sys/sysctl.h` 中找到，其函数实现在 `bsd/kern/kdebug.c` 中。

使用自定义客户端与 kdebug 交互时，通常需要执行以下步骤：

- 使用 KERN_KDSETREMOVE 移除现有设置
- 使用 KERN_KDSETBUF 和 KERN_KDSETUP 设置跟踪
- 使用 KERN_KDGETBUF 获取缓冲区条目数
- 使用 KERN_KDPINDEX 从跟踪中获取客户端自身的信息
- 使用 KERN_KDENABLE 启用跟踪
- 调用 KERN_KDREADTR 读取缓冲区
- 调用 KERN_KDTHRMAP 将每个线程与其进程对应起来

要获取这些信息，可以使用 Apple 工具 **`trace`** 或自定义工具 [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**。**

**请注意，Kdebug 同一时间只能供 1 个用户使用。** 因此，同一时间只能运行一个由 k-debug 驱动的工具。

### ktrace

`ktrace_*` APIs 来自 `libktrace.dylib`，它们封装了 `Kdebug` 的 API。客户端只需调用 `ktrace_session_create` 和 `ktrace_events_[single/class]`，为特定代码设置回调，然后调用 `ktrace_start` 启动即可。

即使**启用了 SIP**，也可以使用这个工具。

可以使用实用程序 `ktrace` 作为客户端：

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

或者使用 `tailspin`。

### kperf

它用于进行内核级性能分析，并基于 `Kdebug` 回调构建。

基本上，它会检查全局变量 `kernel_debug_active`；如果该变量已设置，就会调用 `kperf_kdebug_handler`，并传入 `Kdebug` 代码和调用方内核栈帧的地址。如果 `Kdebug` 代码与某个已选代码匹配，就会执行配置为位图的“操作”（查看 `osfmk/kperf/action.h` 了解可用选项）。

Kperf 也有一个 sysctl MIB 表：（以 root 身份执行）`sysctl kperf`。这些代码位于 `osfmk/kperf/kperfbsd.c`。

此外，Kperf 的部分功能由 `kpc` 提供，它可以提供机器性能计数器的信息。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) 是一款非常实用的工具，可用于检查进程正在执行的相关操作（例如，监控某个进程创建了哪些新进程）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) 是一款用于显示进程间关系的工具。\
你需要使用类似 **`sudo eslogger fork exec rename create > cap.json`** 的命令监控你的 Mac（启动该命令的终端需要 FDA）。然后，你可以将 json 文件载入此工具，查看所有关系：

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) 可监控文件事件，例如创建、修改和删除。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) 是一款 GUI 工具，其外观和使用体验类似于 Windows 用户熟悉的 Microsoft Sysinternal 的 _Procmon_。此工具支持开始和停止记录各种事件类型，按文件、进程、网络等类别筛选这些事件，并可将记录的事件保存为 json 格式。

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
它还会使用 **virustotal** 检查二进制文件进程，并显示二进制文件的相关信息。

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

你可以在[**这篇博客文章**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)中找到一个示例，介绍如何**调试正在运行的守护进程**，该进程使用 **`PT_DENY_ATTACH`** 阻止调试，即使 SIP 已禁用也是如此。<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` 是 Darwin 专用的 `ptrace(2)` 请求，值为 **31** (`0x1f`)；其他参数会被忽略。进程可以直接调用它，无需 fork，以拒绝之后父进程对其进行跟踪。<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU 状态与调用顺序

结果取决于哪个 `ptrace` 请求先到达 XNU：<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB 先附加：** `debugserver` 使用 `PT_ATTACHEXC`；XNU 将其转换为 `PT_ATTACH`，执行 `KAUTH_PROCESS_CANTRACE` 授权，并在目标进程上设置 `P_LTRACED`。后续的 `PT_DENY_ATTACH` 会检测到该标志，并以 `W_EXITCODE(ENOTSUP, 0)` 终止目标进程；LLDB 通常会将其显示为状态 **45** (`0x2d`)。
- **目标进程先拒绝：** XNU 设置 `P_LNOATTACH`。后续附加请求会被进程跟踪授权拒绝；附加错误处理路径会检测到 `P_LNOATTACH`，并向发起附加的进程发送 `SIGSEGV`，在 LLDB 中可能表现为 `debugserver` 连接丢失。

要区分这两种情况，请在启动或附加前启用 `debugserver` 日志，并检查其 `ptrace` 请求：<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 静态识别与绕过

对于未混淆的 ARM64 Mach-O，找到导入的 `_ptrace` stub 并检查调用点。第一个整数参数通过 `w0` 传递，因此这段指令序列会直接暴露 anti-debug 请求。未找到该导入并不能确定不存在相关检查，因为代码可以动态解析 `ptrace`。导入的 `_sysctl` 也可能表明存在 anti-debug 检查，不过它同样可能被动态解析。<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

在演示的示例中，将立即数从 `0x1f` 修补为 `0x0`，会把请求改为 `PT_TRACE_ME`，使程序能够在 LLDB 下继续运行。这是**仅适用于该示例的绕过方法**，并非通用的 no-op：选择更改请求、跳过调用还是强制返回成功之前，请先检查调用方对返回值的检查以及控制流。<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** 是事实上的 **标准工具**，用于 **macOS** 二进制 **调试**。

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

使用 lldb 时，可以通过在主目录中创建名为 **`.lldbinit`** 的文件，并添加以下行来设置 Intel 风格：

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> 在 lldb 中，使用 `process save-core` 转储进程

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) 命令</strong></td><td><strong>说明</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>开始执行，直到命中断点或进程终止。</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>开始执行并在入口点停止。</td></tr>
<tr><td><strong>continue (c)</strong></td><td>继续执行正在调试的进程。</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>执行下一条指令。此命令会跳过函数调用。</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>执行下一条指令。与 <code>nexti</code> 命令不同，此命令会步入函数调用。</td></tr>
<tr><td><strong>finish (f)</strong></td><td>执行当前函数（帧）中剩余的指令，返回并暂停。</td></tr>
<tr><td><strong>control + c</strong></td><td>暂停执行。如果进程已运行（<code>r</code>）或继续执行（<code>c</code>），此命令会使其在当前执行位置停止。</td></tr>
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
<p>大多数 Apple Objective-C API 或方法都返回对象，因此应使用“print object”（<code>po</code>）命令显示。如果 <code>po</code> 未输出有意义的内容，请使用 <code>x/b</code>。</p>
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
> 调用 **`objc_sendMsg`** 函数时，**rsi** 寄存器保存的是以 null 结尾的（“C”）字符串，即**方法名称**。在 lldb 中打印该名称：
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### 反动态分析

#### 虚拟机检测

- 在物理硬件上，命令 **`sysctl hw.model`** 通常会返回 Mac 型号标识符；在 VM 中可能会返回不同的值。<sup>[[3]](#references)</sup>
- 一些恶意软件会通过调整 **`hw.logicalcpu`** 和 **`hw.physicalcpu`** 的值来尝试检测自己是否运行在 VM 中。<sup>[[4]](#references)</sup>
- 一些恶意软件还可以根据 MAC 地址（00:50:56）检测机器是否基于 **VMware**。
- 也可以通过简单的代码检查**进程是否正在被调试**，例如：
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- 它还可以调用带有 **`PT_DENY_ATTACH`** 标志的 **`ptrace`** 系统调用。有关其行为受调用顺序影响的 XNU 特性、`debugserver` 日志记录和 ARM64 patching 工作流，请参阅 [PT_DENY_ATTACH section](#page-title)。<sup>[[7]](#references)[[12]](#references)</sup>

- 它还可以调用带有 **`PT_DENY_ATTACH`** 标志的 **`ptrace`** 系统调用，从而**阻止**调试器附加并跟踪进程。
  - 可以检查是否导入了 **`sysctl`** 或 **`ptrace`** 函数（但恶意软件可能会动态导入它们）
  - 如这篇文章 “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” 所述：<sup>[[7]](#references)</sup>\
    “_消息 Process # exited with **status = 45 (0x0000002d)** 通常是一个明显迹象，表明调试目标正在使用 **PT_DENY_ATTACH**_”
#### `fork()` 进程切换

进程可以在启动时附近调用 `fork()`，终止父进程（`fork()` 返回一个正数子 PID），并仅在子进程中继续执行受保护的逻辑（`fork()` 返回 `0`），从而避开仍附加在原 PID 上的调试器。通过 `dlsym(RTLD_DEFAULT, "fork")` 解析 `fork` 也会移除直接的 `_fork` 调用点，但这只是一个反分析障碍：符号名称字符串和动态解析的数据流仍可在 Mach-O 二进制中看到。<sup>[[13]](#references)[[14]](#references)</sup>

在 arm64 上，应通过跟踪数据流而非固定地址来检测此模式：传给 `dlsym` 的前两个参数分别通过 `x0` 和 `x1` 传递，`RTLD_DEFAULT` 可能显示为 `-2`（例如 `movn x0, #1`），而 `adrp`/`add` 指令对通常会构造 `"fork"` 字符串的地址。在跳转到 `dlsym` stub 的 `bl` 指令之后，跟踪从 `x0` 返回的指针，观察它经过 null 检查和存储后，在之后的间接 `blr` 指令中使用。然后跟踪 `fork()` 在 `w0` 中返回的结果：零值会进入子进程的后续路径，正值和 `-1` 则会进入父进程或错误处理路径。<sup>[[13]](#references)[[14]](#references)</sup>

一种静态绕过方法是抑制间接调用，并强制现有的结果检查进入子进程路径。例如，如果编译器生成了下方所示的指令序列，可以将 `blr` 和结果存储指令 patch 为 `nop`，提供一个合成的零值，并保留比较和分支逻辑。这样，应用程序便会在不创建子进程的情况下继续使用原 PID 运行；指令寄存器和分支目标必须根据所分析的构建版本进行调整。<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

在以下情况下会创建 core dump：

- `kern.coredump` sysctl 设置为 1（默认值）
- 进程不是 suid/sgid，或者 `kern.sugid_coredump` 为 1（默认值为 0）
- `AS_CORE` 限制允许此操作。可以通过调用 `ulimit -c 0` 禁止创建 core dump，并通过 `ulimit -c unlimited` 重新启用。

在这些情况下，core dump 会根据 `kern.corefile` sysctl 生成，通常存储在 `/cores/core/.%P`。

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **会分析崩溃的进程，并将崩溃报告保存到磁盘**。崩溃报告包含的信息可以**帮助开发者诊断**崩溃原因。\
对于**在每用户 launchd 上下文中运行**的应用程序和其他进程，ReportCrash 会作为 LaunchAgent 运行，并将崩溃报告保存在用户的 `~/Library/Logs/DiagnosticReports/`\
对于守护进程、**在系统 launchd 上下文中运行**的其他进程以及其他特权进程，ReportCrash 会作为 LaunchDaemon 运行，并将崩溃报告保存在系统的 `/Library/Logs/DiagnosticReports`

如果你担心崩溃报告**被发送给 Apple**，可以将其禁用。否则，崩溃报告有助于**查明服务器为何崩溃**。

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### 睡眠

在 macOS 上进行 fuzzing 时，请防止 Mac 进入睡眠状态：

- systemsetup -setsleep Never
- pmset、系统设置
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 断开连接

如果你通过 SSH 连接进行 fuzzing，请确保会话不会断开。因此，请修改 sshd_config 文件，设置为：

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### 内部处理程序

**查看以下页面**，了解如何查找负责**处理指定 scheme 或协议的应用：**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### 枚举网络进程

这有助于查找正在管理网络数据的进程：

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

或使用 `netstat` 或 `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### 有状态 Mach IPC 模糊测试

特权守护进程暴露的 Mach 服务是有用的模糊测试目标，前提是非特权或沙盒客户端能够获得发送权限。从守护进程的 `MachServices` launchd 条目入手，使用 [MIG 分析工作流](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)将消息 ID 映射到处理程序。在修改字节之前，先在 MIG 服务器例程处设置断点，同时让普通客户端调用该服务，并保存有效请求消息作为种子输入。保留必需的头字段、消息大小和描述符布局，确保变异后的消息能够到达处理程序，而不是在分发时立即失败。<sup>[[17]](#references)</sup>

许多处理程序依赖先前的调用。让 harness 初始化服务状态，然后将每个模糊测试输入作为一系列**操作及参数**来处理：发送设置请求（例如 open 或 create），保留返回的标识符，并在后续请求中使用它们。这样，覆盖率反馈就能探索状态转换，而不是反复触发“对象未初始化”检查。<sup>[[17]](#references)</sup>

对于闭源目标，可以使用 Jackalope/TinyInst 为调用 MIG 分发例程的进程内 harness 添加插桩。[CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)是一个具体实现，并非可直接用于其他服务的通用 harness。<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**通过真实 IPC 路径验证每次崩溃。** 直接分发的 harness 会跳过内核对 Mach 消息的验证，可能产生误报，尤其是在提供无效的带外（OOL）内存或端口描述符时。在 harness 中分配有效的 OOL 后备内存，然后通过具有原始服务访问权限的客户端，使用 `mach_msg` 重放缩减后的测试用例，并确认守护进程仍会崩溃。<sup>[[17]](#references)</sup>

### 模糊测试器

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

适用于 CLI 工具

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

它对许多 macOS GUI 工具来说“**开箱即用**”。某些应用还有其他要求，例如使用唯一文件名、指定扩展名，或从其沙盒容器（`~/Library/Containers/com.apple.Safari/Data`）读取文件。

以下是一些示例：

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
- [3] [Mac 恶意软件之道，第一卷：分析](https://taomm.org/)
- [4] [No Starch Press - Mac 恶意软件之道：恶意软件分析指南](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - 这篇博客文章中这些 section 存储的信息](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - 调试使用 Pt Deny Attach 的 Apple 二进制文件](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - 绕过 Anti-Debug 技术：macOS ptrace 变体](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode 结构化日志与 `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - 在 macOS 统一日志中显示私有数据](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h` 请求定义](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU 在 `mach_process.c` 中的 `ptrace` 实现](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptrace 内部机制：它如何阻止调试器附加](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - fork 示例](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - 使用 dlsym 和 fork 的 Anti-Debug 技术](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - 调试工具 entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - 调试经过强化的第三方应用](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - 突破声障第一部分：使用 Mach 消息对 CoreAudio 进行 Fuzzing](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
{{#include ../../../banners/hacktricks-training.md}}
