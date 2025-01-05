# macOS 应用 - 检查、调试和模糊测试

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
### jtool2 & Disarm

您可以[**从这里下载 disarm**](https://newosxbook.com/tools/disarm.html)。
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
您可以[**在这里下载 jtool2**](http://www.newosxbook.com/tools/jtool.html)或使用 `brew` 安装它。
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool 已被 disarm 取代**

### Codesign / ldid

> [!TIP] > **`Codesign`** 可以在 **macOS** 中找到，而 **`ldid`** 可以在 **iOS** 中找到
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) 是一个有用的工具，可以在安装之前检查 **.pkg** 文件（安装程序）并查看其内容。\
这些安装程序通常具有 `preinstall` 和 `postinstall` bash 脚本，恶意软件作者通常利用这些脚本来 **持久化** **恶意软件**。

### hdiutil

此工具允许 **挂载** Apple 磁盘映像 (**.dmg**) 文件，以便在运行任何内容之前进行检查：
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
它将被挂载在 `/Volumes`

### 打包的二进制文件

- 检查高熵
- 检查字符串（几乎没有可理解的字符串，已打包）
- MacOS 的 UPX 打包器生成一个名为 "\_\_XHDR" 的部分

## 静态 Objective-C 分析

### 元数据

> [!CAUTION]
> 请注意，用 Objective-C 编写的程序在编译成 [Mach-O 二进制文件](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) 时 **保留** 其类声明。这样的类声明 **包括**：

- 定义的接口
- 接口方法
- 接口实例变量
- 定义的协议

请注意，这些名称可能会被混淆，以使二进制文件的逆向工程更加困难。

### 函数调用

当在使用 Objective-C 的二进制文件中调用一个函数时，编译后的代码不会直接调用该函数，而是会调用 **`objc_msgSend`**。这将调用最终的函数：

![](<../../../images/image (305).png>)

该函数期望的参数为：

- 第一个参数 (**self**) 是 "指向 **接收消息的类实例的指针**"。更简单地说，它是方法被调用的对象。如果方法是类方法，这将是类对象的一个实例（作为整体），而对于实例方法，self 将指向类的一个实例化对象。
- 第二个参数 (**op**) 是 "处理消息的方法选择器"。同样，更简单地说，这只是 **方法的名称**。
- 剩余的参数是方法所需的任何 **值** (op)。

请参见如何在此页面中 **使用 `lldb` 在 ARM64 中轻松获取此信息**：

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **参数**         | **寄存器**                                                    | **(对于) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **第一个参数**    | **rdi**                                                         | **self: 方法被调用的对象**                             |
| **第二个参数**    | **rsi**                                                         | **op: 方法的名称**                                     |
| **第三个参数**    | **rdx**                                                         | **方法的第一个参数**                                   |
| **第四个参数**    | **rcx**                                                         | **方法的第二个参数**                                   |
| **第五个参数**    | **r8**                                                          | **方法的第三个参数**                                   |
| **第六个参数**    | **r9**                                                          | **方法的第四个参数**                                   |
| **第七个及以上参数** | <p><strong>rsp+</strong><br><strong>(在栈上)</strong></p> | **方法的第五个及以上参数**                             |

### 转储 ObjectiveC 元数据

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) 是一个用于类转储 Objective-C 二进制文件的工具。GitHub 指定了 dylibs，但这也适用于可执行文件。
```bash
./dynadump dump /path/to/bin
```
在撰写时，这是**目前效果最好的**。

#### 常规工具
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) 是一个原始工具，用于生成 ObjetiveC 格式代码中类、类别和协议的声明。

它已经过时且未维护，因此可能无法正常工作。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) 是一个现代的跨平台 Objective-C 类转储工具。与现有工具相比，iCDump 可以独立于 Apple 生态系统运行，并且它提供了 Python 绑定。
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## 静态 Swift 分析

对于 Swift 二进制文件，由于与 Objective-C 的兼容性，有时可以使用 [class-dump](https://github.com/nygard/class-dump/) 提取声明，但并不总是如此。

使用 **`jtool -l`** 或 **`otool -l`** 命令行，可以找到多个以 **`__swift5`** 前缀开头的部分：
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
您可以在[**此博客文章中找到有关这些部分存储的信息**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)。

此外，**Swift 二进制文件可能具有符号**（例如，库需要存储符号以便可以调用其函数）。**符号通常以丑陋的方式包含有关函数名称和属性的信息**，因此它们非常有用，并且有“**去混淆器**”可以获取原始名称：
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## 动态分析

> [!WARNING]
> 请注意，为了调试二进制文件，**需要禁用 SIP**（`csrutil disable` 或 `csrutil enable --without debug`），或者将二进制文件复制到临时文件夹并使用 `codesign --remove-signature <binary-path>` **移除签名**，或者允许调试该二进制文件（您可以使用 [this script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)）

> [!WARNING]
> 请注意，为了在 macOS 上**插桩系统二进制文件**（例如 `cloudconfigurationd`），**必须禁用 SIP**（仅移除签名是无效的）。

### APIs

macOS 暴露了一些有趣的 API，提供有关进程的信息：

- `proc_info`：这是主要的 API，提供有关每个进程的大量信息。您需要是 root 用户才能获取其他进程的信息，但不需要特殊的权限或 mach 端口。
- `libsysmon.dylib`：它允许通过 XPC 暴露的函数获取有关进程的信息，但需要具有 `com.apple.sysmond.client` 权限。

### Stackshot & microstackshots

**Stackshotting** 是一种用于捕获进程状态的技术，包括所有运行线程的调用栈。这对于调试、性能分析以及在特定时间点理解系统行为特别有用。在 iOS 和 macOS 上，可以使用多种工具和方法进行 stackshotting，例如工具 **`sample`** 和 **`spindump`**。

### Sysdiagnose

该工具（`/usr/bini/ysdiagnose`）基本上从您的计算机收集大量信息，执行数十个不同的命令，如 `ps`、`zprint`...

它必须以 **root** 身份运行，守护进程 `/usr/libexec/sysdiagnosed` 具有非常有趣的权限，如 `com.apple.system-task-ports` 和 `get-task-allow`。

其 plist 位于 `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`，声明了 3 个 MachServices：

- `com.apple.sysdiagnose.CacheDelete`：删除 /var/rmp 中的旧档案
- `com.apple.sysdiagnose.kernel.ipc`：特殊端口 23（内核）
- `com.apple.sysdiagnose.service.xpc`：通过 `Libsysdiagnose` Obj-C 类的用户模式接口。可以在字典中传递三个参数（`compress`、`display`、`run`）

### 统一日志

MacOS 生成大量日志，这在运行应用程序时尝试理解**它在做什么**时非常有用。

此外，有一些日志将包含标签 `<private>` 以**隐藏**某些**用户**或**计算机**的**可识别**信息。然而，可以**安装证书以披露此信息**。请按照 [**这里**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log) 的说明进行操作。

### Hopper

#### 左侧面板

在 Hopper 的左侧面板中，可以看到二进制文件的符号（**Labels**）、过程和函数的列表（**Proc**）以及字符串（**Str**）。这些并不是所有字符串，而是定义在 Mac-O 文件的多个部分中的字符串（如 _cstring 或_ `objc_methname`）。

#### 中间面板

在中间面板中，您可以看到**反汇编代码**。您可以以**原始**反汇编、**图形**、**反编译**和**二进制**的形式查看，点击相应的图标：

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

右键单击代码对象，您可以查看**对该对象的引用**或甚至更改其名称（这在反编译的伪代码中无效）：

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

此外，在**中间下方，您可以编写 Python 命令**。

#### 右侧面板

在右侧面板中，您可以看到有趣的信息，如**导航历史**（以便您知道如何到达当前状态）、**调用图**，您可以看到所有**调用此函数的函数**和所有**此函数调用的函数**，以及**局部变量**信息。

### dtrace

它允许用户以极低的**级别**访问应用程序，并提供了一种方法，让用户**跟踪** **程序**，甚至更改其执行流程。Dtrace 使用**探针**，这些探针**分布在内核中**，位于系统调用的开始和结束位置。

DTrace 使用 **`dtrace_probe_create`** 函数为每个系统调用创建一个探针。这些探针可以在**每个系统调用的入口和出口**触发。与 DTrace 的交互通过 /dev/dtrace 进行，该接口仅对 root 用户可用。

> [!TIP]
> 要在不完全禁用 SIP 保护的情况下启用 Dtrace，您可以在恢复模式下执行：`csrutil enable --without dtrace`
>
> 您还可以使用您**编译的** **`dtrace`** 或 **`dtruss`** 二进制文件。

dtrace 的可用探针可以通过以下方式获取：
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
探针名称由四个部分组成：提供者、模块、函数和名称（`fbt:mach_kernel:ptrace:entry`）。如果您未指定名称的某个部分，Dtrace 将将该部分应用为通配符。

要配置 DTrace 以激活探针并指定触发时要执行的操作，我们需要使用 D 语言。

更详细的解释和更多示例可以在 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) 中找到。

#### 示例

运行 `man -k dtrace` 列出 **可用的 DTrace 脚本**。示例：`sudo dtruss -n binary`
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

它是一个内核跟踪工具。文档代码可以在 **`/usr/share/misc/trace.codes`** 中找到。

像 `latency`、`sc_usage`、`fs_usage` 和 `trace` 这样的工具在内部使用它。

要与 `kdebug` 进行接口，使用 `sysctl` 通过 `kern.kdebug` 命名空间，使用的 MIB 可以在 `sys/sysctl.h` 中找到，相关函数在 `bsd/kern/kdebug.c` 中实现。

要与 kdebug 进行交互，通常步骤如下：

- 使用 KERN_KDSETREMOVE 移除现有设置
- 使用 KERN_KDSETBUF 和 KERN_KDSETUP 设置跟踪
- 使用 KERN_KDGETBUF 获取缓冲区条目数量
- 使用 KERN_KDPINDEX 从跟踪中获取自己的客户端
- 使用 KERN_KDENABLE 启用跟踪
- 调用 KERN_KDREADTR 读取缓冲区
- 要将每个线程与其进程匹配，调用 KERN_KDTHRMAP。

为了获取这些信息，可以使用 Apple 工具 **`trace`** 或自定义工具 [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**。**

**注意，Kdebug 每次只能为一个客户提供服务。** 因此，只有一个 k-debug 驱动的工具可以同时执行。

### ktrace

`ktrace_*` API 来自 `libktrace.dylib`，它封装了 `Kdebug` 的 API。然后，客户端可以调用 `ktrace_session_create` 和 `ktrace_events_[single/class]` 在特定代码上设置回调，然后使用 `ktrace_start` 启动它。

即使在 **SIP 激活** 的情况下也可以使用这个。

您可以使用实用程序 `ktrace` 作为客户端：
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
或 `tailspin`。

### kperf

这用于进行内核级别的性能分析，使用 `Kdebug` 调用构建。

基本上，检查全局变量 `kernel_debug_active`，如果设置了它，则调用 `kperf_kdebug_handler`，并传入 `Kdebug` 代码和调用的内核帧地址。如果 `Kdebug` 代码与所选的匹配，则获取配置为位图的“操作”（查看 `osfmk/kperf/action.h` 以获取选项）。

Kperf 还有一个 sysctl MIB 表： (作为 root) `sysctl kperf`。这些代码可以在 `osfmk/kperf/kperfbsd.c` 中找到。

此外，Kperf 的一部分功能位于 `kpc` 中，它提供有关机器性能计数器的信息。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) 是一个非常有用的工具，用于检查进程相关的操作（例如，监视一个进程正在创建哪些新进程）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) 是一个打印进程之间关系的工具。\
您需要使用类似 **`sudo eslogger fork exec rename create > cap.json`** 的命令监视您的 Mac（启动此终端需要 FDA）。然后，您可以在此工具中加载 json 以查看所有关系：

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) 允许监视文件事件（例如创建、修改和删除），提供有关这些事件的详细信息。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) 是一个 GUI 工具，外观和感觉与 Windows 用户可能熟悉的 Microsoft Sysinternal 的 _Procmon_ 相似。此工具允许开始和停止各种事件类型的录制，允许按文件、进程、网络等类别过滤这些事件，并提供以 json 格式保存录制事件的功能。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) 是 Xcode 开发工具的一部分 – 用于监视应用程序性能、识别内存泄漏和跟踪文件系统活动。

![](<../../../images/image (1138).png>)

### fs_usage

允许跟踪进程执行的操作：
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) 是一个有用的工具，可以查看二进制文件使用的 **libraries**、它正在使用的 **files** 和 **network** 连接。\
它还会将二进制进程与 **virustotal** 进行检查，并显示有关该二进制文件的信息。

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

在 [**这篇博客文章**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) 中，您可以找到一个关于如何 **调试一个正在运行的守护进程** 的示例，该守护进程使用 **`PT_DENY_ATTACH`** 来防止调试，即使 SIP 被禁用。

### lldb

**lldb** 是 **macOS** 二进制 **debugging** 的事实标准工具。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
您可以在使用 lldb 时设置 intel 风味，通过在您的主文件夹中创建一个名为 **`.lldbinit`** 的文件，并添加以下行：
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> 在 lldb 中，使用 `process save-core` 转储进程

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) 命令</strong></td><td><strong>描述</strong></td></tr><tr><td><strong>run (r)</strong></td><td>开始执行，直到命中断点或进程终止。</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>在入口点停止执行</td></tr><tr><td><strong>continue (c)</strong></td><td>继续调试的进程的执行。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>执行下一条指令。此命令将跳过函数调用。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>执行下一条指令。与 nexti 命令不同，此命令将进入函数调用。</td></tr><tr><td><strong>finish (f)</strong></td><td>执行当前函数（“帧”）中的其余指令，返回并停止。</td></tr><tr><td><strong>control + c</strong></td><td>暂停执行。如果进程已运行 (r) 或继续 (c)，这将导致进程在当前执行位置停止。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #任何名为 main 的函数</p><p><code>b <binname>`main</code> #二进制文件的主函数</p><p><code>b set -n main --shlib <lib_name></code> #指定二进制文件的主函数</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #任何 NSFileManager 方法</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # 在该库的所有函数中断</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #断点列表</p><p><code>br e/dis <num></code> #启用/禁用断点</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #获取断点命令的帮助</p><p>help memory write #获取写入内存的帮助</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>将内存显示为以 null 结尾的字符串。</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>将内存显示为汇编指令。</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>将内存显示为字节。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>这将打印由参数引用的对象</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>请注意，Apple 的大多数 Objective-C API 或方法返回对象，因此应通过“打印对象”（po）命令显示。如果 po 没有产生有意义的输出，请使用 <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #在该地址写入 AAAA<br>memory write -f s $rip+0x11f+7 "AAAA" #在地址中写入 AAAA</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #反汇编当前函数</p><p>dis -n <funcname> #反汇编函数</p><p>dis -n <funcname> -b <basename> #反汇编函数<br>dis -c 6 #反汇编 6 行<br>dis -c 0x100003764 -e 0x100003768 # 从一个地址到另一个地址<br>dis -p -c 4 # 从当前地址开始反汇编</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # 检查 x1 寄存器中 3 个组件的数组</td></tr><tr><td><strong>image dump sections</strong></td><td>打印当前进程内存的映射</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #获取 CoreNLP 的所有符号的地址</td></tr></tbody></table>

> [!NOTE]
> 调用 **`objc_sendMsg`** 函数时，**rsi** 寄存器保存方法的 **名称**，以 null 结尾的（“C”）字符串。要通过 lldb 打印名称，请执行：
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### 反动态分析

#### 虚拟机检测

- 命令 **`sysctl hw.model`** 在 **主机为 MacOS** 时返回 "Mac"，但在虚拟机中返回不同的内容。
- 一些恶意软件通过玩弄 **`hw.logicalcpu`** 和 **`hw.physicalcpu`** 的值来检测是否为虚拟机。
- 一些恶意软件还可以根据 MAC 地址（00:50:56）**检测**机器是否基于 **VMware**。
- 也可以通过简单的代码检查 **进程是否正在被调试**：
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //进程正在被调试 }`
- 它还可以调用 **`ptrace`** 系统调用，使用 **`PT_DENY_ATTACH`** 标志。这 **防止** 调试器附加和跟踪。
- 您可以检查 **`sysctl`** 或 **`ptrace`** 函数是否被 **导入**（但恶意软件可以动态导入它）
- 正如在这篇文章中所述，“[击败反调试技术：macOS ptrace 变体](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)”：\
“_消息 Process # exited with **status = 45 (0x0000002d)** 通常是调试目标使用 **PT_DENY_ATTACH** 的明显迹象_”

## 核心转储

核心转储在以下情况下创建：

- `kern.coredump` sysctl 设置为 1（默认值）
- 如果进程不是 suid/sgid 或 `kern.sugid_coredump` 为 1（默认值为 0）
- `AS_CORE` 限制允许该操作。可以通过调用 `ulimit -c 0` 来抑制核心转储的创建，并通过 `ulimit -c unlimited` 重新启用它们。

在这些情况下，核心转储根据 `kern.corefile` sysctl 生成，并通常存储在 `/cores/core/.%P` 中。

## 模糊测试

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **分析崩溃的进程并将崩溃报告保存到磁盘**。崩溃报告包含可以 **帮助开发人员诊断** 崩溃原因的信息。\
对于在每个用户 launchd 上下文中 **运行的应用程序和其他进程**，ReportCrash 作为 LaunchAgent 运行，并将崩溃报告保存在用户的 `~/Library/Logs/DiagnosticReports/` 中。\
对于守护进程、在系统 launchd 上下文中 **运行的其他进程** 和其他特权进程，ReportCrash 作为 LaunchDaemon 运行，并将崩溃报告保存在系统的 `/Library/Logs/DiagnosticReports` 中。

如果您担心崩溃报告 **被发送到 Apple**，可以禁用它们。如果不担心，崩溃报告可以帮助 **找出服务器崩溃的原因**。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### 睡眠

在 MacOS 中进行模糊测试时，重要的是不要让 Mac 进入睡眠状态：

- systemsetup -setsleep Never
- pmset, 系统偏好设置
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 断开连接

如果您通过 SSH 连接进行模糊测试，确保会话不会断开是很重要的。因此，请使用以下内容更改 sshd_config 文件：

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**查看以下页面** 以了解如何找到哪个应用程序负责 **处理指定的方案或协议：**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

这对于查找管理网络数据的进程很有趣：
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
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

适用于CLI工具

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

它“**可以正常工作**”与macOS GUI工具。注意一些macOS应用程序有一些特定要求，比如唯一的文件名、正确的扩展名，需要从沙盒中读取文件（`~/Library/Containers/com.apple.Safari/Data`）...

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
### 更多 Fuzzing MacOS 信息

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 参考文献

- [**OS X 事件响应：脚本和分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**Mac 恶意软件的艺术：分析恶意软件的指南**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
