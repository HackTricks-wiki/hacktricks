# macOS 通过任务端口进行线程注入

{{#include ../../../../banners/hacktricks-training.md}}

## 代码

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. 线程劫持

最初，**`task_threads()`** 函数在任务端口上被调用，以从远程任务中获取线程列表。选择一个线程进行劫持。这种方法与传统的代码注入方法不同，因为由于新的缓解措施阻止了 `thread_create_running()`，创建新的远程线程是被禁止的。

为了控制线程，调用 **`thread_suspend()`**，暂停其执行。

在远程线程上允许的唯一操作涉及 **停止** 和 **启动** 它，**检索** 和 **修改** 其寄存器值。通过将寄存器 `x0` 到 `x7` 设置为 **参数**，配置 **`pc`** 以指向所需函数，并激活线程，来发起远程函数调用。确保线程在返回后不崩溃需要检测返回。

一种策略是使用 `thread_set_exception_ports()` 为远程线程 **注册异常处理程序**，在函数调用之前将 `lr` 寄存器设置为无效地址。这会在函数执行后触发异常，向异常端口发送消息，使线程的状态可以被检查以恢复返回值。或者，借鉴 Ian Beer 的 triple_fetch 漏洞，将 `lr` 设置为无限循环。然后持续监控线程的寄存器，直到 **`pc` 指向该指令**。

## 2. 用于通信的 Mach 端口

接下来的阶段涉及建立 Mach 端口，以促进与远程线程的通信。这些端口在任务之间传输任意发送和接收权限方面至关重要。

为了实现双向通信，创建两个 Mach 接收权限：一个在本地任务中，另一个在远程任务中。随后，将每个端口的发送权限转移到对应的任务，从而实现消息交换。

关注本地端口，接收权限由本地任务持有。该端口通过 `mach_port_allocate()` 创建。挑战在于将此端口的发送权限转移到远程任务中。

一种策略是利用 `thread_set_special_port()` 将本地端口的发送权限放置在远程线程的 `THREAD_KERNEL_PORT` 中。然后，指示远程线程调用 `mach_thread_self()` 以检索发送权限。

对于远程端口，过程基本上是反向的。指示远程线程通过 `mach_reply_port()` 生成一个 Mach 端口（因为 `mach_port_allocate()` 由于其返回机制不适用）。在端口创建后，在远程线程中调用 `mach_port_insert_right()` 以建立发送权限。然后，该权限通过 `thread_set_special_port()` 存储在内核中。在本地任务中，使用 `thread_get_special_port()` 在远程线程上获取对远程任务中新分配的 Mach 端口的发送权限。

完成这些步骤后，建立了 Mach 端口，为双向通信奠定了基础。

## 3. 基本内存读/写原语

在本节中，重点是利用执行原语建立基本的内存读写原语。这些初步步骤对于获得对远程进程的更多控制至关重要，尽管此阶段的原语不会发挥太多作用。很快，它们将升级为更高级的版本。

### 使用执行原语进行内存读取和写入

目标是使用特定函数执行内存读取和写入。用于读取内存的函数类似于以下结构：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
用于写入内存的函数类似于以下结构：
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
这些函数对应于给定的汇编指令：
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 识别合适的函数

对常见库的扫描揭示了这些操作的合适候选者：

1. **读取内存：**
`property_getName()` 函数来自 [Objective-C runtime library](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)，被识别为读取内存的合适函数。该函数如下所述：
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
这个函数有效地充当了 `read_func`，通过返回 `objc_property_t` 的第一个字段。

2. **写入内存：**
找到一个预构建的写入内存的函数更具挑战性。然而，来自 libxpc 的 `_xpc_int64_set_value()` 函数是一个合适的候选者，具有以下反汇编：
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
要在特定地址执行64位写入，远程调用的结构为：
```c
_xpc_int64_set_value(address - 0x18, value)
```
通过建立这些原语，创建共享内存的阶段已经设定，这标志着在控制远程进程方面的重大进展。

## 4. 共享内存设置

目标是在本地和远程任务之间建立共享内存，简化数据传输并促进带有多个参数的函数调用。该方法涉及利用 `libxpc` 及其 `OS_xpc_shmem` 对象类型，该类型建立在 Mach 内存条目之上。

### 过程概述：

1. **内存分配**：

- 使用 `mach_vm_allocate()` 分配共享内存。
- 使用 `xpc_shmem_create()` 为分配的内存区域创建一个 `OS_xpc_shmem` 对象。此函数将管理 Mach 内存条目的创建，并在 `OS_xpc_shmem` 对象的偏移量 `0x18` 处存储 Mach 发送权限。

2. **在远程进程中创建共享内存**：

- 通过对 `malloc()` 的远程调用，在远程进程中为 `OS_xpc_shmem` 对象分配内存。
- 将本地 `OS_xpc_shmem` 对象的内容复制到远程进程。然而，这个初始复制在偏移量 `0x18` 处将具有不正确的 Mach 内存条目名称。

3. **修正 Mach 内存条目**：

- 利用 `thread_set_special_port()` 方法将 Mach 内存条目的发送权限插入到远程任务中。
- 通过用远程内存条目的名称覆盖偏移量 `0x18` 处的 Mach 内存条目字段来修正它。

4. **完成共享内存设置**：
- 验证远程 `OS_xpc_shmem` 对象。
- 通过对 `xpc_shmem_remote()` 的远程调用建立共享内存映射。

通过遵循这些步骤，本地和远程任务之间的共享内存将有效设置，从而允许简单的数据传输和执行需要多个参数的函数。

## 额外代码片段

用于内存分配和共享内存对象创建：
```c
mach_vm_allocate();
xpc_shmem_create();
```
在远程进程中创建和修正共享内存对象：
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
记得正确处理Mach端口和内存条目名称的细节，以确保共享内存设置正常工作。

## 5. 实现完全控制

在成功建立共享内存并获得任意执行能力后，我们基本上获得了对目标进程的完全控制。实现这种控制的关键功能包括：

1. **任意内存操作**：

- 通过调用`memcpy()`从共享区域复制数据，执行任意内存读取。
- 通过使用`memcpy()`将数据传输到共享区域，执行任意内存写入。

2. **处理具有多个参数的函数调用**：

- 对于需要超过8个参数的函数，按照调用约定将额外参数安排在栈上。

3. **Mach端口传输**：

- 通过先前建立的端口，通过Mach消息在任务之间传输Mach端口。

4. **文件描述符传输**：
- 使用fileports在进程之间传输文件描述符，这一技术由Ian Beer在`triple_fetch`中强调。

这种全面控制封装在[threadexec](https://github.com/bazad/threadexec)库中，提供了详细的实现和用户友好的API，以便与受害进程进行交互。

## 重要考虑事项：

- 确保正确使用`memcpy()`进行内存读/写操作，以维护系统稳定性和数据完整性。
- 在传输Mach端口或文件描述符时，遵循适当的协议并负责任地处理资源，以防止泄漏或意外访问。

通过遵循这些指南并利用`threadexec`库，可以有效地管理和与进程进行细粒度交互，实现对目标进程的完全控制。

## 参考文献

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{{#include ../../../../banners/hacktricks-training.md}}
