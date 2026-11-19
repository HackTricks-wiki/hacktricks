# 通过线程名称和等待线程进行 Windows 进程注入

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) 可在不使用 `WriteProcessMemory` 的情况下，将字节传入正在运行的进程；Waiting Thread Hijacking (WTH) 可在不使用 `SetThreadContext` 或创建远程线程的情况下，在现有线程上运行这些字节。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> 这些是**进程注入原语，而非权限提升漏洞**：注入器仍需要访问目标进程和线程。线程描述 API 要求 Windows 10 版本 1607 或更高版本。<sup>[[1]](#references)[[3]](#references)</sup> 其他注入和规避方法，请参见 [Antivirus (AV) Bypass](av-bypass.md)。

## Thread Name-Calling：在目标进程中复制 payload

`NtSetInformationThread(ThreadNameInformation)` 会将传入的 `UNICODE_STRING` 复制到线程名称存储区。随后在**目标进程内部**调用 `GetThreadDescription`，会在用户模式堆上创建该名称的副本。这样就将 payload 传输与最终内存复制分开：注入器可以读取返回的堆**指针**，而在目标进程内部运行 `RtlMoveMemory` 的 APC 则会将字节复制到目标位置。<sup>[[1]](#references)</sup> 原始技术也支持特殊用户 APC；WhisperHijack 实现则改用普通的 `NtQueueApcThread`，并在等待线程上执行。<sup>[[1]](#references)[[3]](#references)</sup>

对于每个长度不超过 `0xFFFE` 字节的数据块，PoC 会按以下顺序操作。只有目标进程填充完暂存槽后，重复句柄的自动重置事件才会发出完成信号；注入器等待该信号后才读取指针。此事件确认的是堆指针 APC 已完成，而不是后续的复制 APC。PoC 在排入复制 APC 后会提醒同一线程，并依赖 APC 的执行顺序，而非使用第二个完成信号。<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

scratch 地址必须在目标进程中可写，并且注入器无需先写入即可知晓该地址。原始 PoC 使用 `PEB.SpareUlongs`。<sup>[[1]](#references)</sup> WhisperHijack 还提供 `PEB.PostProcessInitRoutine`，默认使用 `TEB.TlsSlots[63]`（通过 `NtQueryInformationThread(ThreadBasicInformation)` 定位）。在每个目标进程中，该 TLS slot **不一定未被使用**；覆盖正在使用的 slot 可能会破坏该线程。在 `Main.c` 中恰好启用一个选项。编译时检查会拒绝缺失或冲突的 PEB/TEB 选择。<sup>[[4]](#references)</sup>

普通的 `RtlInitUnicodeString` 调用会在遇到内嵌的宽字符 null 时停止。要传输二进制数据，需使用同等大小且不含 null 的填充缓冲区初始化 `UNICODE_STRING` 长度，再将其 `Buffer` 字节替换为实际数据块，然后传给 `NtSetInformationThread`。这种基于长度的传输方式不同于将 shellcode 作为以 null 结尾的字符串直接传给 `SetThreadDescription`。<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking：从队列等待中返回

使用 `NtQuerySystemInformation(SystemProcessInformation)` 枚举线程，并查找 `ThreadState == Waiting` 且 `WaitReason == WrQueue` 的线程。阻塞在 `NtWaitForWorkViaWorkerFactory` 等 syscall wrapper 中的线程，其保存的调用者返回地址位于 `[Rsp]`。替换该栈槽即可将 wrapper 的 `ret` 重定向到 stub，而无需通过 `SetThreadContext` 更改 `Rip`。stub 必须保存 flags 和寄存器，**调用**一个会返回的 payload，恢复状态，然后跳转到保存的原始返回地址。<sup>[[2]](#references)[[3]](#references)</sup>

在 x64 PoC 中，stub 在 `+0x00` 处有一个 8 字节的已保存返回地址槽，指令位于 `+0x08`，payload 位于 `+0x45`。栈槽中写入的是 `allocation_base + 0x08`，而不是数据槽地址。仅凭 `WrQueue` **不能证明**线程正处于 worker-factory wait：原始研究也将 `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` 识别为队列等待路径。在依赖此布局前，请检查实际的 wait/call stack，并确认 `[Rsp]` 是预期的返回地址槽。<sup>[[2]](#references)[[3]](#references)</sup>

## 组合 TNC 和 WTH，避免跨进程写入

WhisperHijack 展示了针对现有 native x64 进程的组合工作流。其 Writer 选择候选进程/线程，而 Flipper 子进程继承完成最终交接所需的句柄。进程句柄请求 `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`，**不包括** `PROCESS_VM_WRITE`；不过，当前 PoC 仍以 `THREAD_ALL_ACCESS` 打开线程。访问检查和进程缓解措施仍然适用。<sup>[[3]](#references)[[4]](#references)</sup>

组合 PoC 使用以下步骤；内存复制 APC 在目标进程中执行，而不是通过具有远程写入权限的句柄执行。<sup>[[4]](#references)</sup>

1. 在目标进程中预留按 64 KB 对齐的空闲块，然后将其中的 4-KB 页面提交为 `PAGE_READWRITE`。PoC 使用 `NtQueryVirtualMemory` 探测固定候选地址；这些地址只是实现选择，并非 TNC 或 WTH 的要求。
2. 组装 `[0x45-byte WTH stub][returning x64 payload][8-byte stub-entry pointer]`，其中最后一个指针为 `allocation_base + 0x08`。通过 TNC 分块循环传送此缓冲区。
3. 在 Flipper 中，使用 `NtGetContextThread(CONTEXT_CONTROL)` 获取等待线程的 `Rsp`。将一个在目标进程中执行的 `RtlMoveMemory` APC 入队，将 `[Rsp]` 处原有的 8 字节值复制到 stub 的数据槽。
4. 使用 `NtProtectVirtualMemory` 将暂存区域更改为可执行。由于其多态 payload 会自行解码，此 PoC 选择 `PAGE_EXECUTE_READWRITE`；WTH 本身并不要求 payload 自修改。
5. 再将一个在目标进程中执行的 `RtlMoveMemory` APC 入队，将**预先暂存的尾部指针**复制到 `[Rsp]`，然后调用 `NtAlertThread`。APC 的 FIFO 顺序会先保存原始返回地址，再将其替换；wrapper 返回时会进入 stub，并在 payload 返回后恢复执行原调用者。

没有使用 `NtWriteVirtualMemory` **并不**意味着没有对目标进程进行写入：`GetThreadDescription` 和 `RtlMoveMemory` 会在目标进程内部执行写入。<sup>[[1]](#references)[[3]](#references)</sup> 普通 user APC 的交付还取决于所选线程是否处理其 APC 队列；一次 `WrQueue` 快照和一次 alert 并不能保证 APC 会立即执行。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> 该示例避免了创建远程线程、挂起线程和直接替换上下文，但其 APC 和内存保护属性变更仍可被观察到。<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC and README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – WhisperHijack Main.c implementation](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
