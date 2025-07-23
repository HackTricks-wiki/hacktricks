# macOS 通过任务端口进行线程注入

{{#include ../../../../banners/hacktricks-training.md}}

## 代码

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. 线程劫持

最初，`task_threads()` 函数在任务端口上被调用，以从远程任务获取线程列表。选择一个线程进行劫持。这种方法与传统的代码注入方法不同，因为由于阻止 `thread_create_running()` 的缓解措施，创建新的远程线程是被禁止的。

为了控制线程，调用 `thread_suspend()`，暂停其执行。

在远程线程上允许的唯一操作是 **停止** 和 **启动** 线程，以及 **检索**/**修改** 其寄存器值。通过将寄存器 `x0` 到 `x7` 设置为 **参数**，配置 `pc` 以指向所需函数，并恢复线程，从而发起远程函数调用。确保线程在返回后不崩溃需要检测返回。

一种策略是使用 `thread_set_exception_ports()` 为远程线程注册 **异常处理程序**，在函数调用之前将 `lr` 寄存器设置为无效地址。这会在函数执行后触发异常，向异常端口发送消息，使得可以检查线程的状态以恢复返回值。或者，借鉴 Ian Beer 的 *triple_fetch* 漏洞，将 `lr` 设置为无限循环；然后持续监控线程的寄存器，直到 `pc` 指向该指令。

## 2. 用于通信的 Mach 端口

接下来的阶段涉及建立 Mach 端口，以促进与远程线程的通信。这些端口在任务之间传输任意的发送/接收权限中起着重要作用。

为了实现双向通信，创建两个 Mach 接收权限：一个在本地任务中，另一个在远程任务中。随后，将每个端口的发送权限转移到对应的任务，从而实现消息交换。

关注本地端口，接收权限由本地任务持有。该端口通过 `mach_port_allocate()` 创建。挑战在于将该端口的发送权限转移到远程任务中。

一种策略是利用 `thread_set_special_port()` 将本地端口的发送权限放置在远程线程的 `THREAD_KERNEL_PORT` 中。然后，指示远程线程调用 `mach_thread_self()` 以检索发送权限。

对于远程端口，过程基本上是反向的。指示远程线程通过 `mach_reply_port()` 生成一个 Mach 端口（因为 `mach_port_allocate()` 不适合由于其返回机制）。在端口创建后，在远程线程中调用 `mach_port_insert_right()` 以建立发送权限。然后，该权限通过 `thread_set_special_port()` 存储在内核中。在本地任务中，使用 `thread_get_special_port()` 在远程线程上获取对远程任务中新分配的 Mach 端口的发送权限。

完成这些步骤后，建立了 Mach 端口，为双向通信奠定了基础。

## 3. 基本内存读/写原语

在本节中，重点是利用执行原语建立基本的内存读/写原语。这些初步步骤对于获得对远程进程的更多控制至关重要，尽管此阶段的原语不会发挥太多作用。很快，它们将升级为更高级的版本。

### 使用执行原语进行内存读写

目标是使用特定函数执行内存读写。对于 **读取内存**：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
对于 **写入内存**：
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
这些函数对应以下汇编：
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

1. **读取内存 — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **写入内存 — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
要在任意地址执行 64 位写入：
```c
_xpc_int64_set_value(address - 0x18, value);
```
建立这些原语后，创建共享内存的舞台已经设定，这标志着在控制远程进程方面的重大进展。

## 4. 共享内存设置

目标是在本地和远程任务之间建立共享内存，简化数据传输并促进带有多个参数的函数调用。该方法利用 `libxpc` 及其 `OS_xpc_shmem` 对象类型，该类型建立在 Mach 内存条目之上。

### 进程概述

1. **内存分配**
* 使用 `mach_vm_allocate()` 分配共享内存。
* 使用 `xpc_shmem_create()` 为分配的区域创建 `OS_xpc_shmem` 对象。
2. **在远程进程中创建共享内存**
* 在远程进程中为 `OS_xpc_shmem` 对象分配内存（`remote_malloc`）。
* 复制本地模板对象；仍需修复嵌入的 Mach 发送权限，偏移量为 `0x18`。
3. **修正 Mach 内存条目**
* 使用 `thread_set_special_port()` 插入发送权限，并用远程条目的名称覆盖 `0x18` 字段。
4. **最终化**
* 验证远程对象并通过远程调用 `xpc_shmem_remote()` 进行映射。

## 5. 实现完全控制

一旦可以进行任意执行和共享内存后通道，您就有效地拥有了目标进程：

* **任意内存读/写** — 在本地和共享区域之间使用 `memcpy()`。
* **带有 > 8 个参数的函数调用** — 按照 arm64 调用约定将额外参数放在栈上。
* **Mach 端口传输** — 通过已建立的端口在 Mach 消息中传递权限。
* **文件描述符传输** — 利用文件端口（见 *triple_fetch*）。

所有这些都封装在 [`threadexec`](https://github.com/bazad/threadexec) 库中，以便于重用。

---

## 6. Apple Silicon (arm64e) 的细微差别

在 Apple Silicon 设备（arm64e）上，**指针认证码 (PAC)** 保护所有返回地址和许多函数指针。线程劫持技术 *重用现有代码* 仍然有效，因为 `lr`/`pc` 中的原始值已经携带有效的 PAC 签名。当您尝试跳转到攻击者控制的内存时，会出现问题：

1. 在目标内部分配可执行内存（远程 `mach_vm_allocate` + `mprotect(PROT_EXEC)`）。
2. 复制您的有效载荷。
3. 在 *远程* 进程中对指针进行签名：
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. 在劫持的线程状态中设置 `pc = ptr`。

或者，通过链接现有的 gadgets/functions（传统 ROP）来保持 PAC 兼容。

## 7. 使用 EndpointSecurity 进行检测和加固

**EndpointSecurity (ES)** 框架暴露了内核事件，允许防御者观察或阻止线程注入尝试：

* `ES_EVENT_TYPE_AUTH_GET_TASK` – 当一个进程请求另一个任务的端口时触发（例如 `task_for_pid()`）。
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – 每当在 *不同* 任务中创建线程时发出。
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE`（在 macOS 14 Sonoma 中添加）– 表示对现有线程的寄存器操作。

最小的 Swift 客户端，打印远程线程事件：
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
使用 **osquery** ≥ 5.8 查询：
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### 加固运行时考虑

在没有 `com.apple.security.get-task-allow` 权限的情况下分发您的应用程序可以防止非根用户攻击者获取其任务端口。系统完整性保护（SIP）仍然阻止访问许多 Apple 二进制文件，但第三方软件必须明确选择退出。

## 8. 最近的公共工具（2023-2025）

| 工具 | 年份 | 备注 |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | 演示在 Ventura/Sonoma 上进行 PAC 感知线程劫持的紧凑 PoC |
| `remote_thread_es` | 2024 | 被多个 EDR 供应商使用的 EndpointSecurity 辅助工具，用于显示 `REMOTE_THREAD_CREATE` 事件 |

> 阅读这些项目的源代码有助于理解在 macOS 13/14 中引入的 API 更改，并保持在 Intel ↔ Apple Silicon 之间的兼容性。

## 参考文献

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
