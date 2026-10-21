# Windows Exception-Driven Control Flow and Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

A protected Windows program can use an intentional exception as a branch: the faulting instruction is only the entry to a handler that selects the next user-code address. This hides edges from linear disassembly and moves the next step into exception dispatch.<sup>[[1]](#references)</sup>

## Dispatch matters

A debugger attached to the process receives a **first-chance** exception before application handlers. If it passes the event as unhandled, Windows searches the process's handlers; an exception with no handler returns to the debugger as **last-chance**. A debugger that consumes a breakpoint or single-step event can therefore change whether the program's handler runs.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registers a process-wide VEH at the front of the vectored list. It runs before frame-based SEH, but a later first-priority registration can move another handler ahead of it. Returning `EXCEPTION_CONTINUE_SEARCH` leaves the exception for other handlers; `EXCEPTION_CONTINUE_EXECUTION` resumes from the saved `CONTEXT`, including any register changes made by the handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Classic x86 SEH uses stack-linked registrations, which `!exchain` can inspect. Native x64 uses `RUNTIME_FUNCTION` entries in `.pdata` with unwind data in `.xdata`, not that x86 chain. Do not apply the [x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md) to a native x64 process.<sup>[[5]](#references)[[6]](#references)</sup>

## Turn a fault into a control-flow edge

For example, a zero divisor can deliberately raise `EXCEPTION_INT_DIVIDE_BY_ZERO` rather than represent a bug. The handler must recognize the exception and fault address, then set `ContextRecord->Rip` (or `Eip` on x86) to a valid continuation before returning `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

The handler core below assumes `fault_site` and `continuation` are known addresses in the same control-flow context. A real implementation must preserve the expected stack and registers, and must not resume at the same faulting instruction or it will fault again.<sup>[[7]](#references)</sup>

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

The same mechanism can consume an intentional `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) and redirect execution. Do **not** blindly increment `Rip` to "skip the breakpoint": the saved address and required adjustment depend on the trap, instruction encoding, and debugger behavior. Compare `ExceptionRecord->ExceptionAddress` with the saved instruction pointer and disassemble the bytes before choosing the continuation.<sup>[[8]](#references)</sup> The [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) is a separate hardware-breakpoint example that changes a loader syscall's return state.

## Trap Flag as a debugger-dependent gate

Bit `0x100` in `EFLAGS`/`RFLAGS` is the Trap Flag (TF). Setting it makes the next instruction boundary raise `STATUS_SINGLE_STEP` (`0x80000004`). A VEH or SEH branch can distinguish a single-step event passed to the application from one consumed by a debugger, but this is a **heuristic controlled by debugger exception policy**, not reliable proof that a debugger exists.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

If the handler only wants one step, clear `0x100` in the resumed context's `EFlags` before continuing. Also distinguish TF-driven steps from hardware-breakpoint events by checking the triggering address and debug state; both can appear as `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> For WinDbg's `sxe`, `sxd`, and `sxi` first-/second-chance settings, see [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Debugger Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Vectored Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Using a Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembly Instructions](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 Architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
