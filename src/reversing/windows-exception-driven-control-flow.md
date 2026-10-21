# Windows 异常驱动的控制流与反调试

{{#include ../banners/hacktricks-training.md}}

受保护的 Windows 程序可以将有意触发的异常用作分支：发生故障的指令只是处理程序的入口，处理程序会选择下一个用户代码地址。这会隐藏线性反汇编中的控制流边，并将下一步交由异常分发机制处理。<sup>[[1]](#references)</sup>

## 分发机制很重要

附加到进程的调试器会在应用程序处理程序之前收到 **first-chance** 异常。如果调试器将事件作为未处理异常传递，Windows 就会搜索进程的处理程序；如果异常没有处理程序，则会作为 **last-chance** 异常返回给调试器。因此，调试器若拦截断点或单步事件，可能会改变程序处理程序是否运行。<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` 会在向量处理程序列表的最前端注册一个进程级 VEH。它会在基于栈帧的 SEH 之前运行，但之后以最高优先级注册的处理程序可以排到它前面。返回 `EXCEPTION_CONTINUE_SEARCH` 会将异常留给其他处理程序；返回 `EXCEPTION_CONTINUE_EXECUTION` 则会从保存的 `CONTEXT` 恢复执行，包括处理程序所做的任何寄存器修改。<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

经典 x86 SEH 使用栈链接的注册记录，可以通过 `!exchain` 检查。原生 x64 使用 `.pdata` 中的 `RUNTIME_FUNCTION` 条目和 `.xdata` 中的展开数据，而不是 x86 链。不要将 [x86 SEH 覆盖工作流程](../binary-exploitation/stack-overflow/windows-seh-overflow.md)用于原生 x64 进程。<sup>[[5]](#references)[[6]](#references)</sup>

## 将故障转化为控制流边

例如，零除数可以有意触发 `EXCEPTION_INT_DIVIDE_BY_ZERO`，而不是代表程序错误。处理程序必须识别异常及故障地址，然后在返回 `EXCEPTION_CONTINUE_EXECUTION` 之前，将 `ContextRecord->Rip`（或 x86 上的 `Eip`）设为有效的后续执行地址。<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

下面的 handler 核心假设 `fault_site` 和 `continuation` 是同一控制流上下文中的已知地址。实际实现必须保留预期的栈和寄存器，且不得从同一条触发异常的指令处恢复执行，否则会再次触发异常。<sup>[[7]](#references)</sup>

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

同一机制也可以捕获有意触发的 `INT3`/`__debugbreak()`（`EXCEPTION_BREAKPOINT`）并重定向执行。不要盲目递增 `Rip` 来“跳过断点”：保存的地址和所需的调整取决于陷阱、指令编码以及调试器行为。选择继续执行的位置前，请将 `ExceptionRecord->ExceptionAddress` 与保存的指令指针进行比较，并反汇编相关字节。<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) 是另一个硬件断点示例，它会更改 loader 系统调用的返回状态。

## Trap Flag：依赖调试器的门控

`EFLAGS`/`RFLAGS` 中的位 `0x100` 是 Trap Flag（TF）。设置该位会在下一条指令边界触发 `STATUS_SINGLE_STEP`（`0x80000004`）。VEH 或 SEH 分支可以区分传递给应用程序的 single-step 事件和被调试器捕获的事件，但这只是受调试器异常策略控制的**启发式判断**，不能可靠地证明调试器存在。<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

如果 handler 只需要单步执行一次，请在继续执行前清除恢复上下文 `EFlags` 中的 `0x100`。还要通过检查触发地址和 debug 状态，区分 TF 驱动的单步事件与硬件断点事件；两者都可能表现为 `EXCEPTION_SINGLE_STEP`。<sup>[[8]](#references)[[9]](#references)</sup> 关于 WinDbg 的 `sxe`、`sxd` 和 `sxi` first-/second-chance 设置，请参阅 [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception)。

## References

- [1] [Check Point Research - 反调试：异常](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Debugger 异常处理](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - 向量化异常处理](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64 异常处理](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - 使用向量化异常处理程序](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - 反调试：汇编指令](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 架构](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
