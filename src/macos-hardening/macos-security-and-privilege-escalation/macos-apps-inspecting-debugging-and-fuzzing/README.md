# macOS Apps - 检查、调试与 Fuzzing

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
> 请注意，**`disarm`** 也可以处理压缩的 IM4P 文件（如 `kernelcache`），并仅提取所需部分，甚至无需提取即可分析所需部分。
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
> **`Codesign`** 可在 **macOS** 中找到，而 **`ldid`** 可在 **iOS** 中找到
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) 是一个用于检查 **.pkg** 文件（安装程序）的工具，可以在安装之前查看其中的内容。\
这些安装程序包含 `preinstall` 和 `postinstall` bash 脚本，恶意软件作者通常会滥用它们来**持久化** **恶意软件**。

### hdiutil

此工具可以挂载 Apple 磁盘映像（**.dmg**）文件，以便在运行任何内容之前对其进行检查：
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
It will be mounted in `/Volumes`

### Packed binaries

- 检查高熵
- 检查字符串（如果几乎没有可理解的字符串，则说明已打包）
- MacOS 的 UPX packer 会生成一个名为 "\_\_XHDR" 的 section

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> 请注意，使用 Objective-C 编写的程序在编译为 [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) 后，仍会**保留**其类声明。这些类声明**包括**以下内容的名称和类型：

- 定义的 interfaces
- interface methods
- interface instance variables
- 定义的 protocols

请注意，这些名称可能会被混淆，以增加 binary reversing 的难度。

### Function calling

当使用 Objective-C 的 binary 调用某个函数时，编译后的代码不会直接调用该函数，而是调用 **`objc_msgSend`**，由它调用最终的函数：

![Metadata - Function calling：当使用 Objective-C 的 binary 调用某个函数时，编译后的代码不会直接调用该函数，而是调用 objc msgSend，由它调用最终的函数...](<../../../images/image (305).png>)

该函数所需的参数包括：

- 第一个参数（**self**）是“指向**接收该消息的 class instance** 的指针”。更简单地说，它就是要调用其 method 的 object。如果该 method 是 class method，那么它将是 class object（整体）的一个 instance；而对于 instance method，self 将指向 class 的一个已实例化 instance，并作为 object 使用。
- 第二个参数（**op**）是“处理该消息的 method 的 selector”。更简单地说，这就是 **method 的名称**。
- 其余参数是该 method（op）所需的任意**值**。

请参阅此页面，了解如何在 **ARM64** 中使用 `lldb` **轻松获取这些信息**：


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64：

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self：调用其 method 的 object**                      |
| **2nd argument**  | **rsi**                                                         | **op：method 的名称**                                   |
| **3rd argument**  | **rdx**                                                         | **method 的第 1 个参数**                                |
| **4th argument**  | **rcx**                                                         | **method 的第 2 个参数**                                |
| **5th argument**  | **r8**                                                          | **method 的第 3 个参数**                                |
| **6th argument**  | **r9**                                                          | **method 的第 4 个参数**                                |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **method 的第 5 个及后续参数**                          |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) 是一个用于对 Objective-C binaries 执行 class-dump 的工具。GitHub 上的说明指定了 dylibs，但该工具同样适用于 executables。
```bash
./dynadump dump /path/to/bin
```
截至撰写本文时，**目前这是效果最好的工具**。

#### 常规工具
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) 是最初用于生成 Objective-C 格式代码中类、类别和协议声明的工具。

它已经过时且无人维护，因此可能无法正常工作。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) 是一款现代且跨平台的 Objective-C class dump 工具。与现有工具相比，iCDump 可以独立于 Apple 生态系统运行，并提供 Python bindings。
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift analysis

对于 Swift binaries，由于存在 Objective-C compatibility，有时可以使用 [class-dump](https://github.com/nygard/class-dump/) 提取 declarations，但并非总是可行。

使用 **`jtool -l`** 或 **`otool -l`** command lines，可以找到多个以 **`__swift5`** prefix 开头的 sections：
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
你可以在这篇[**博客文章中找到有关这些部分所存储信息的更多内容**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)。

此外，**Swift binaries 可能包含 symbols**（例如，库需要存储 symbols，以便调用其中的函数）。**symbols 通常会以一种难以阅读的方式包含函数名称和属性信息**，因此它们非常有用，并且存在可以获取原始名称的“**demanglers**”：
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## 动态分析

> [!WARNING]
> 请注意，为了调试二进制文件，**SIP 需要被禁用**（`csrutil disable` 或 `csrutil enable --without debug`），或者将二进制文件复制到临时文件夹，并使用 `codesign --remove-signature <binary-path>` **移除签名**，或允许对该二进制文件进行调试（可以使用[此脚本](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)）

> [!WARNING]
> 请注意，为了在 macOS 上**instrument system binaries**（例如 `cloudconfigurationd`），**必须禁用 SIP**（仅移除签名不起作用）。

### APIs

macOS 暴露了一些能够提供进程信息的有趣 APIs：

- `proc_info`：这是主要的 API，能够提供大量关于每个进程的信息。你需要成为 root 才能获取其他进程的信息，但不需要特殊 entitlements 或 mach ports。
- `libsysmon.dylib`：它允许通过 XPC 暴露的函数获取进程信息，但必须拥有 entitlement `com.apple.sysmond.client`。

### Stackshot & microstackshots

**Stackshotting** 是一种用于捕获进程状态的技术，包括所有运行中线程的调用栈。这对于调试、性能分析以及了解系统在特定时间点的行为特别有用。在 iOS 和 macOS 上，可以使用 **`sample`** 和 **`spindump`** 等工具和方法执行 stackshotting。

### Sysdiagnose

此工具（`/usr/bini/ysdiagnose`）基本上会通过执行几十个不同的命令（例如 `ps`、`zprint`……）来收集计算机中的大量信息。

它必须以 **root** 身份运行，并且 daemon `/usr/libexec/sysdiagnosed` 拥有一些非常有趣的 entitlements，例如 `com.apple.system-task-ports` 和 `get-task-allow`。

其 plist 位于 `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`，其中声明了 3 个 MachServices：

- `com.apple.sysdiagnose.CacheDelete`：删除 `/var/rmp` 中的旧归档
- `com.apple.sysdiagnose.kernel.ipc`：特殊端口 23（kernel）
- `com.apple.sysdiagnose.service.xpc`：通过 `Libsysdiagnose` Obj-C 类提供的用户模式接口。可以在字典中传递三个参数（`compress`、`display`、`run`）

### Unified Logs

MacOS 会生成大量日志，在运行应用程序并试图了解**它正在做什么**时，这些日志非常有用。

此外，有些日志会包含 `<private>` 标签，以**隐藏**某些**用户**或**计算机可识别**的信息。不过，可以**安装证书来披露这些信息**。请参阅[**此处**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)的说明。

### Hopper

#### 左侧面板

在 Hopper 的左侧面板中，可以看到二进制文件的符号（**Labels**）、过程和函数列表（**Proc**）以及字符串（**Str**）。这些并不是全部字符串，而是 Mac-O 文件多个部分中定义的字符串（例如 _cstring 或 `objc_methname`）。

#### 中间面板

在中间面板中可以看到**反汇编代码**。点击相应图标后，可以将其显示为**原始**反汇编、**图形**、**反编译**和**二进制**：

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

右键点击代码对象，可以查看**指向该对象的引用或来自该对象的引用**，甚至可以修改其名称（这对反编译的伪代码不起作用）：

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

此外，**中间面板下方可以编写 Python 命令**。

#### 右侧面板

在右侧面板中，可以看到一些有用的信息，例如**导航历史**（这样你就能知道如何到达当前状态）、**调用图**，其中可以看到所有**调用此函数的函数**以及**此函数调用的所有函数**，还有**局部变量**信息。

### dtrace

它允许用户以极**低的层级**访问应用程序，并为用户提供一种**跟踪** **程序**甚至改变其执行流程的方法。Dtrace 使用 **probes**，这些 **probes** 分布在整个 **kernel** 中，位置包括系统调用的开始和结束处。

DTrace 使用 **`dtrace_probe_create`** 函数为每个系统调用创建一个 probe。这些 probes 可以在每个系统调用的**进入点和退出点**触发。与 DTrace 的交互通过 `/dev/dtrace` 进行，该设备仅对 root 用户可用。

> [!TIP]
> 如果不完全禁用 SIP 保护，可以在 recovery mode 中执行以下命令来启用 Dtrace：`csrutil enable --without dtrace`
>
> 你也可以使用自己**编译的** **`dtrace`** 或 **`dtruss`** 二进制文件。

可以使用以下命令获取 dtrace 的可用 probes：
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
探针名称由四个部分组成：provider、module、function 和 name（`fbt:mach_kernel:ptrace:entry`）。如果未指定名称中的某些部分，Dtrace 会将这些部分作为通配符处理。

要配置 DTrace 以激活探针并指定探针触发时执行的操作，我们需要使用 D 语言。

更多详细说明和示例，请参阅 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### 示例

运行 `man -k dtrace` 以列出**可用的 DTrace scripts**。示例：`sudo dtruss -n binary`

- 在行
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- script
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

它是一个 kernel tracing facility。已记录的 codes 可在 **`/usr/share/misc/trace.codes`** 中找到。

`latency`、`sc_usage`、`fs_usage` 和 `trace` 等工具在内部使用它。

要与 `kdebug` 交互，可通过 `kern.kdebug` namespace 使用 `sysctl`，要使用的 MIBs 可在 `sys/sysctl.h` 中找到，其 functions 在 `bsd/kern/kdebug.c` 中实现。

要使用自定义 client 与 kdebug 交互，通常需要执行以下步骤：

- 使用 KERN_KDSETREMOVE 移除现有 settings
- 使用 KERN_KDSETBUF 和 KERN_KDSETUP 设置 trace
- 使用 KERN_KDGETBUF 获取 buffer entries 的数量
- 使用 KERN_KDPINDEX 将自身 client 从 trace 中移除
- 使用 KERN_KDENABLE 启用 tracing
- 调用 KERN_KDREADTR 读取 buffer
- 使用 KERN_KDTHRMAP 将每个 thread 与其 process 进行匹配。

要获取这些信息，可以使用 Apple 工具 **`trace`** 或自定义工具 [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**。**

**请注意，Kdebug 同一时间只能供 1 个 client 使用。** 因此，同一时间只能执行一个由 k-debug 驱动的工具。

### ktrace

`ktrace_*` APIs 来自 `libktrace.dylib`，后者封装了 `Kdebug` 的 APIs。随后，client 只需调用 `ktrace_session_create` 和 `ktrace_events_[single/class]`，即可为特定 codes 设置 callbacks，然后使用 `ktrace_start` 启动。

即使 **SIP 已激活**，也可以使用它。

你可以使用 utility `ktrace` 作为 client：
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
或者 `tailspin`。

### kperf

该工具用于执行 kernel level profiling，基于 `Kdebug` callouts 构建。

基本上，它会检查全局变量 `kernel_debug_active`；如果该变量已设置，则使用 `Kdebug` code 以及调用该 kernel frame 的地址调用 `kperf_kdebug_handler`。如果 `Kdebug` code 与选定的 code 匹配，则会获取以 bitmap 配置的“actions”（相关选项请参阅 `osfmk/kperf/action.h`）。

Kperf 还拥有一个 sysctl MIB table：（以 root 身份执行）`sysctl kperf`。这些 code 位于 `osfmk/kperf/kperfbsd.c`。

此外，Kperf 的部分功能位于 `kpc` 中，后者提供有关 machine performance counters 的信息。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) 是一个非常实用的工具，用于检查进程正在执行的、与进程相关的操作（例如，监控某个进程创建了哪些新进程）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) 是一个用于显示进程之间关系的工具。\
你需要使用类似 **`sudo eslogger fork exec rename create > cap.json`** 的命令监控 Mac（执行该命令的终端需要 FDA）。然后，你可以将 json 加载到此工具中，以查看所有关系：

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) 可监控文件事件（例如创建、修改和删除），并提供有关这些事件的详细信息。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) 是一个 GUI 工具，其外观和使用体验类似于 Windows 用户熟悉的 Microsoft Sysinternal 的 _Procmon_。该工具允许启动和停止对各种 event types 的记录，按 file、process、network 等类别过滤这些事件，并支持将记录的事件以 json 格式保存。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) 是 Xcode Developer tools 的一部分，用于监控 application performance、识别 memory leaks，以及跟踪 filesystem activity。

![Crescendo - Apple Instruments：Apple Instruments 是 Xcode Developer tools 的一部分，用于监控 application performance、识别 memory leaks，以及跟踪 filesystem activity](<../../../images/image (1138).png>)

### fs_usage

允许跟踪进程执行的操作：
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) 可用于查看某个 **binary** 使用的 **libraries**、正在使用的 **files** 以及 **network** 连接。\
它还会将 binary processes 与 **virustotal** 进行比对，并显示有关该 binary 的信息。

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

在[**这篇博客文章**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)中，你可以找到一个示例，介绍如何对使用 **`PT_DENY_ATTACH`** 来阻止 debugging 的 **running daemon** 进行 **debugging**，即使 SIP 已被禁用。

### lldb

**lldb** 是用于 **macOS** binary **debugging** 的 de facto 工具。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
使用 lldb 时，可以在主目录中创建一个名为 **`.lldbinit`** 的文件，并在其中添加以下内容：
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> 在 lldb 中，使用 `process save-core` 转储进程

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>描述</strong></td></tr><tr><td><strong>run (r)</strong></td><td>开始执行，并持续运行，直到命中断点或进程终止。</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>开始执行，并在入口点暂停</td></tr><tr><td><strong>continue (c)</strong></td><td>继续执行正在调试的进程。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>执行下一条指令。此命令会跳过函数调用。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>执行下一条指令。不同于 nexti 命令，此命令会步入函数调用。</td></tr><tr><td><strong>finish (f)</strong></td><td>执行当前函数（“frame”）中剩余的指令，返回并暂停。</td></tr><tr><td><strong>control + c</strong></td><td>暂停执行。如果进程已运行 (r) 或继续执行 (c)，此操作会使进程在当前执行位置停止。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>将内存显示为以 null 结尾的字符串。</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>将内存显示为汇编指令。</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>将内存显示为字节。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>此命令会打印参数所引用的对象</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>请注意，Apple 的大多数 Objective-C API 或方法都会返回对象，因此应使用 “print object”（po）命令显示。如果 po 没有产生有意义的输出，请使用 <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>打印当前进程内存的映射</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> 调用 **`objc_sendMsg`** 函数时，**rsi** 寄存器保存以 null 结尾的（“C”）字符串形式的方法名称。要通过 lldb 打印名称，请执行：
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- 命令 **`sysctl hw.model`** 在 **host 是 MacOS** 时返回 "Mac"，而在 VM 中返回其他内容。
- 一些 malware 会通过调整 **`hw.logicalcpu`** 和 **`hw.physicalcpu`** 的值来尝试检测是否处于 VM 中。
- 一些 malware 还可以根据 MAC 地址（00:50:56）检测机器是否为 **VMware**。
- 还可以通过如下简单代码判断**进程是否正在被调试**：
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- 它还可以使用带有 **`PT_DENY_ATTACH`** 标志的 **`ptrace`** 系统调用。这会**阻止调试器**附加并跟踪进程。
- 你可以检查 **`sysctl`** 或 **`ptrace`** 函数是否被**导入**（但 malware 可能动态导入它）
- 正如这篇 writeup “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” 中所述：\
“_消息 Process # exited with **status = 45 (0x0000002d)** 通常是调试目标正在使用 **`PT_DENY_ATTACH`** 的明显迹象_”

## Core Dumps

Core dumps 会在以下情况下创建：

- `kern.coredump` sysctl 设置为 1（默认值）
- 如果进程不是 suid/sgid，或者 `kern.sugid_coredump` 为 1（默认值为 0）
- `AS_CORE` 限制允许执行此操作。可以通过调用 `ulimit -c 0` 禁止创建 core dumps，并通过 `ulimit -c unlimited` 重新启用。

在这些情况下，core dumps 会根据 `kern.corefile` sysctl 生成，通常存储在 `/cores/core/.%P`。

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **分析崩溃的进程，并将 crash report 保存到磁盘**。crash report 包含的信息可以**帮助开发者诊断**崩溃原因。\
对于**在每用户 launchd context 中运行的应用程序和其他进程**，ReportCrash 以 LaunchAgent 身份运行，并将 crash reports 保存到用户的 `~/Library/Logs/DiagnosticReports/`\
对于 daemon、**在系统 launchd context 中运行的其他进程**以及其他特权进程，ReportCrash 以 LaunchDaemon 身份运行，并将 crash reports 保存到系统的 `/Library/Logs/DiagnosticReports`

如果你担心 crash reports **被发送给 Apple**，可以将其禁用。否则，crash reports 可用于**确定 server 崩溃的原因**。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### 睡眠

在 MacOS 上进行 fuzzing 时，重要的是不允许 Mac 进入睡眠状态：

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 断开

如果你通过 SSH 连接进行 fuzzing，重要的是确保会话不会意外断开。因此，修改 sshd_config 文件：

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### 内部处理程序

**查看以下页面**，了解如何查找负责**处理指定 scheme 或 protocol 的 app：**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### 枚举网络进程

查找管理网络数据的进程很有用：
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
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

适用于 CLI 工具

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

它与 macOS GUI 工具配合使用时**“开箱即用”**。请注意，某些 macOS 应用具有特定要求，例如唯一的文件名、正确的扩展名，或需要从 sandbox（`~/Library/Containers/com.apple.Safari/Data`）中读取文件……

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
### More Fuzzing MacOS Info

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 参考资料

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
