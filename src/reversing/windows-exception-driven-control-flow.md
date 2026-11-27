# Windows 异常驱动的控制流与反调试

{{#include ../banners/hacktricks-training.md}}

受保护的 Windows 程序可以将有意触发的异常用作分支：触发异常的指令只是进入处理程序的入口，由处理程序选择下一个用户代码地址。这会隐藏线性反汇编中的控制流边，并将下一步转交给异常分发机制。<sup>[[1]](#references)</sup>

## 分发机制很重要

附加到进程的调试器会在应用程序处理程序之前收到**首次机会**异常。如果调试器将事件作为未处理异常传递，Windows 就会搜索进程的处理程序；若异常没有处理程序，则会以**最后机会**异常的形式返回给调试器。因此，调试器若处理断点或单步事件，就可能改变程序的处理程序是否会运行。<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` 会在向量化处理程序列表的最前端注册一个进程级 VEH。它在基于栈帧的 SEH 之前运行，但之后以最高优先级注册的处理程序可以排到它前面。返回 `EXCEPTION_CONTINUE_SEARCH` 会将异常留给其他处理程序；返回 `EXCEPTION_CONTINUE_EXECUTION` 则会从保存的 `CONTEXT` 恢复执行，其中也包括处理程序所做的寄存器更改。<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

经典 x86 SEH 使用栈链接的注册记录，可以通过 `!exchain` 检查。原生 x64 使用 `.pdata` 中的 `RUNTIME_FUNCTION` 条目和 `.xdata` 中的展开数据，而不是 x86 的链。不要对原生 x64 进程使用 [x86 SEH 覆写流程](../binary-exploitation/stack-overflow/windows-seh-overflow.md)。<sup>[[5]](#references)[[6]](#references)</sup>

## 将故障转化为控制流边

例如，除数为零可以有意触发 `EXCEPTION_INT_DIVIDE_BY_ZERO`，而不是表示程序错误。处理程序必须识别异常和故障地址，然后将 `ContextRecord->Rip`（或 x86 上的 `Eip`）设为有效的后续执行地址，再返回 `EXCEPTION_CONTINUE_EXECUTION`。<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

下面的 handler 核心假设 `fault_site` 和 `continuation` 是同一控制流上下文中的已知地址。实际实现必须保留预期的栈和寄存器，并且不得从同一条触发故障的指令处恢复执行，否则会再次触发故障。<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

同一机制也可以捕获有意触发的 `INT3`/`__debugbreak()`（`EXCEPTION_BREAKPOINT`）并重定向执行。**不要**盲目递增 `Rip` 来“跳过断点”：保存的地址和所需的调整取决于陷阱、指令编码和调试器行为。比较 `ExceptionRecord->ExceptionAddress` 与保存的指令指针，并反汇编相关字节，再决定继续执行的位置。<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) 是另一个独立的 hardware-breakpoint 示例，它会更改 loader syscall 的返回状态。

## 故障驱动的页面物化

VEH 可以将页面错误转变为**按需 loader**，而不只是跳转。预留一段私有 image 地址范围，其中的页面保持未提交状态；或者在支持的情况下，为映射页面设置 guard。在运行 image 之前，按目标页面索引重定位位置和 IAT thunk。当该范围内发生错误时，handler 会提交被访问的页面或将其设为可写，复制其 section 字节，应用该页面的重定位和导入项，设置最终保护属性，然后返回 `EXCEPTION_CONTINUE_EXECUTION`。原始指令会重试；**不要**像跳过错误的 handler 那样递增 `Rip`。从未访问的页面无需在内存中包含 payload。<sup>[[11]](#references)</sup>

对于访问冲突，`ExceptionRecord->ExceptionAddress` 标识发生错误的**指令**，而 `ExceptionInformation[1]` 标识被访问的地址。<sup>[[10]](#references)</sup> 在物化页面之前，检查异常代码、参数数量和被访问地址的范围；否则可能会将无关错误误认为 loader 请求。<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` 会在首次访问时引发 `STATUS_GUARD_PAGE_VIOLATION`（`0x80000001`），且 Windows 会自动清除 guard 位，因此重新设置 guard 是单独的步骤，而不是持续生效的 hook。<sup>[[12]](#references)</sup> 在分发异常期间，确保 VEH 及其所需的所有元数据都可访问。<sup>[[11]](#references)</sup> 在 x64 上，展开数据可能需要在首次错误发生前就已可用；引用的 loader 会在调用 `DllMain` 前预先物化页面，以避免初始化竞争。<sup>[[11]](#references)</sup> 写入代码后、执行代码前，刷新指令缓存。<sup>[[13]](#references)</sup>

逆向分析时，若要还原这一流程，可在 first-chance guard-page violations 和 access violations 处设置断点，检查异常记录，然后使用 `gn` 将事件传递给应用程序的 handler。<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> 对被访问的地址使用 `!vprot`，检查其当前页面保护属性。<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

在 handler 将页面 materialize 后，转储其字节并与文件映像进行比较。<sup>[[11]](#references)</sup> fault 之后执行 `!vprot` 无法证明该页面此前受过 guard 保护，因为 guard 状态是一次性的。<sup>[[11]](#references)[[12]](#references)</sup> 确定相关映像范围后，收窄异常筛选器或 handler 断点，以避免无关的 faults。<sup>[[16]](#references)</sup> 有关筛选器设置，请参阅 [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception)。<sup>[[16]](#references)</sup>

## Trap Flag 作为依赖调试器的门控

`EFLAGS`/`RFLAGS` 中的位 `0x100` 是 Trap Flag (TF)。设置该标志会在下一条指令边界触发 `STATUS_SINGLE_STEP` (`0x80000004`)。VEH 或 SEH 分支可以区分传递给应用程序的 single-step 事件和被调试器处理的事件，但这只是由**调试器异常策略控制的启发式方法**，不能可靠地证明调试器是否存在。<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

如果 handler 只需要单步执行一次，请在继续执行前清除恢复上下文 `EFlags` 中的 `0x100`。还要通过检查触发地址和调试状态，区分由 TF 触发的单步事件与硬件断点事件；两者都可能表现为 `EXCEPTION_SINGLE_STEP`。<sup>[[8]](#references)[[9]](#references)</sup> 有关 WinDbg 的 `sxe`、`sxd` 和 `sxi` 首次/第二次机会设置，请参阅 [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception)。

## References

- [1] [Check Point Research - 反调试：异常](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - 调试器异常处理](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - 向量化异常处理](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64 异常处理](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - 使用向量化异常处理程序](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - 反调试：汇编指令](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 架构](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - 故障驱动的映像加载](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - 创建保护页](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr（显示异常记录）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - sx 异常筛选器](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn（继续执行并将异常标记为未处理）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
