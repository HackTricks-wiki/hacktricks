# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

首先，在 task port 上调用 `task_threads()` 函数，以从远程 task 获取线程列表。随后选择一个线程进行劫持。由于阻止 `thread_create_running()` 的 mitigation，创建新的远程线程是被禁止的，因此这种方法不同于传统的 code-injection 方法。<sup>[[1]](#references)</sup>

为了控制该线程，需要调用 `thread_suspend()` 暂停其执行。<sup>[[1]](#references)</sup>

对远程线程唯一允许的操作包括**停止**和**启动**线程，以及**获取**/**修改**其寄存器值。通过将寄存器 `x0` 到 `x7` 设置为**参数**、将 `pc` 配置为指向目标函数，然后恢复线程运行，即可发起远程函数调用。为了确保线程在函数返回后不会崩溃，还必须检测返回操作。<sup>[[1]](#references)</sup>

一种策略是使用 `thread_set_exception_ports()` 为远程线程注册一个**exception handler**，并在函数调用前将 `lr` 寄存器设置为无效地址。函数执行完毕后会触发异常，向 exception port 发送消息，从而可以检查线程状态并获取返回值。另一种方法借鉴了 Ian Beer 的 *triple_fetch* exploit：将 `lr` 设置为无限循环，然后持续监控线程寄存器，直到 `pc` 指向该指令。<sup>[[1]](#references)</sup>

## 2. 用于通信的 Mach ports

下一阶段是建立 Mach ports，以便与远程线程进行通信。这些 ports 用于在不同 task 之间传输任意的 send/receive rights。<sup>[[1]](#references)</sup>

为了实现双向通信，需要创建两个 Mach receive rights：一个位于本地 task，另一个位于远程 task。随后，将每个 port 的 send right 传输给对应的另一方 task，从而实现消息交换。<sup>[[1]](#references)</sup>

以本地 port 为例，其 receive right 由本地 task 持有。该 port 通过 `mach_port_allocate()` 创建。难点在于如何将指向该 port 的 send right 传输到远程 task 中。<sup>[[1]](#references)</sup>

一种策略是利用 `thread_set_special_port()`，将本地 port 的 send right 放入远程线程的 `THREAD_KERNEL_PORT` 中。随后指示远程线程调用 `mach_thread_self()` 来获取该 send right。<sup>[[1]](#references)</sup>

对于远程 port，过程基本相反。指示远程线程通过 `mach_reply_port()` 生成一个 Mach port（因为 `mach_port_allocate()` 的返回机制不适用）。创建 port 后，在远程线程中调用 `mach_port_insert_right()` 来建立一个 send right。然后通过 `thread_set_special_port()` 将该 right 暂存到 kernel 中。回到本地 task 后，对远程线程使用 `thread_get_special_port()`，以获取指向远程 task 中新分配 Mach port 的 send right。<sup>[[1]](#references)</sup>

完成这些步骤后，Mach ports 便建立起来，为双向通信奠定基础。<sup>[[1]](#references)</sup>

## 3. 基础 Memory Read/Write Primitives

本节重点介绍如何利用 execute primitive 建立基础的 memory read/write primitives。这些初始步骤对于进一步控制远程 process 至关重要，尽管当前阶段的 primitives 用途并不多。很快，它们将升级为更高级的版本。<sup>[[1]](#references)</sup>

### 使用 execute primitive 读取和写入 memory

目标是使用特定函数执行 memory 读取和写入。对于**读取 memory**：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
对于**写入内存**：
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
这些函数对应于以下汇编代码：
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 识别合适的函数

对常用库的扫描发现了适用于这些操作的候选函数：<sup>[[1]](#references)</sup>

1. **读取内存 — `property_getName()`**（libobjc）：
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **写入内存 — `_xpc_int64_set_value()`**（libxpc）：
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
要在任意地址执行 64 位写入：
```c
_xpc_int64_set_value(address - 0x18, value);
```
在建立这些原语后，创建共享内存的条件已经具备，这标志着对远程进程控制能力取得了重要进展。<sup>[[1]](#references)</sup>

## 4. 共享内存设置

目标是在本地 task 与远程 task 之间建立共享内存，从而简化数据传输，并便于调用带有多个参数的函数。该方法利用 `libxpc` 及其 `OS_xpc_shmem` object 类型，而后者构建于 Mach memory entries 之上。<sup>[[1]](#references)</sup>

### 进程概览

1. **内存分配**
* 使用 `mach_vm_allocate()` 分配用于共享的内存。
* 使用 `xpc_shmem_create()` 为已分配的区域创建一个 `OS_xpc_shmem` object。
2. **在远程进程中创建共享内存**
* 在远程进程中为 `OS_xpc_shmem` object 分配内存（`remote_malloc`）。
* 复制本地 template object；仍需要修正偏移量 `0x18` 处内嵌的 Mach send right。
3. **修正 Mach memory entry**
* 使用 `thread_set_special_port()` 插入一个 send right，并将 `0x18` 字段覆盖为远程 entry 的 name。
4. **完成**
* 验证远程 object，并通过对 `xpc_shmem_remote()` 的远程调用将其映射。

## 5. 实现完全控制

一旦具备任意执行能力和共享内存 back-channel，你实际上就已经控制了目标进程：<sup>[[1]](#references)</sup>

* **任意内存 R/W** — 使用 `memcpy()` 在本地区域与共享区域之间进行操作。
* **调用参数超过 8 个的函数** — 遵循 arm64 calling convention 将额外参数放置在 stack 上。
* **Mach port transfer** — 通过已建立的 ports，在 Mach messages 中传递 rights。
* **File-descriptor transfer** — 利用 fileports（参见 *triple_fetch*）。

以上功能都封装在 [`threadexec`](https://github.com/bazad/threadexec) library 中，便于重复使用。

---

## 6. Apple Silicon（arm64e）细节

在 Apple Silicon 设备（arm64e）上，**Pointer Authentication Codes（PAC）** 会保护所有返回地址和许多 function pointers。由于 `lr`/`pc` 中的原始值已经携带有效的 PAC signatures，复用现有 code 的 thread-hijacking 技术仍然有效。当你尝试跳转到由攻击者控制的内存时，问题就会出现：

1. 在目标进程内部申请可执行内存（远程 `mach_vm_allocate` + `mprotect(PROT_EXEC)`）。
2. 复制你的 payload。
3. 在*远程*进程中对该 pointer 进行签名：
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. 在被劫持线程的状态中设置 `pc = ptr`。

或者通过链接现有 gadget/function（传统 ROP）来保持 PAC-compliant。

## 7. 使用 EndpointSecurity 进行检测与加固

**EndpointSecurity (ES)** framework 提供了 kernel events，使 defenders 能够观察或阻止 thread-injection 尝试：

* `ES_EVENT_TYPE_AUTH_GET_TASK` – 当某个 process 请求另一个 task 的 port 时触发（例如 `task_for_pid()`）。
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – 每当在*不同* task 中创建 thread 时发出。<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE`（在 macOS 14 Sonoma 中新增）– 表示对现有 thread 的 register manipulation。

用于打印 remote-thread events 的最小 Swift client：
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
使用 **osquery** ≥ 5.8 进行查询：
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime 注意事项

分发应用时**不包含** `com.apple.security.get-task-allow` entitlement，可阻止非 root 攻击者获取其 task-port。System Integrity Protection (SIP) 仍会阻止访问许多 Apple binaries，但第三方软件必须显式选择退出保护。

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | 展示 Ventura/Sonoma 上 PAC-aware thread hijacking 的紧凑 PoC |
| `remote_thread_es` | 2024 | 多家 EDR 厂商使用的 EndpointSecurity helper，用于发现 `REMOTE_THREAD_CREATE` events |

> 阅读这些项目的源代码，有助于了解 macOS 13/14 引入的 API 变更，并保持 Intel ↔ Apple Silicon 之间的兼容性。

## References

- [1] [使用 task_threads() 绕过 platform binary restrictions - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
