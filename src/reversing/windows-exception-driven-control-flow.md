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

## Fault-driven page materialization

A VEH can turn a page fault into a **lazy loader**, not just a jump. Reserve a private image range with pages left uncommitted, or guard mapped pages where supported. Before running the image, index relocation sites and IAT thunks by their destination page. On a fault inside that range, the handler commits or makes the touched page writable, copies its section bytes, applies that page's relocations and imports, sets its final protection, and returns `EXCEPTION_CONTINUE_EXECUTION`. The original instruction is retried; do **not** advance `Rip` as in a skip-the-fault handler. Pages never touched need not contain the payload in memory.<sup>[[11]](#references)</sup>

For an access violation, `ExceptionRecord->ExceptionAddress` identifies the **instruction** that faulted, while `ExceptionInformation[1]` identifies the accessed address.<sup>[[10]](#references)</sup> Check the exception code, parameter count, and accessed-address range before materializing a page; otherwise an unrelated fault may be mistaken for a loader request.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` raises `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) on first access and Windows clears the guard bit automatically, so re-arming is a separate step, not a continuous hook.<sup>[[12]](#references)</sup> Keep the VEH and any metadata it needs accessible during dispatch.<sup>[[11]](#references)</sup> On x64, unwind data may need to be available before the first fault; the cited loader eagerly materializes pages before invoking `DllMain` to avoid initialization races.<sup>[[11]](#references)</sup> Flush the instruction cache after writing code and before executing it.<sup>[[13]](#references)</sup>

To recover this flow while reversing, break on first-chance guard-page violations and access violations, inspect the exception record, then pass the event to the application's handler with `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Use `!vprot` on the accessed address to inspect its current page protection.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

After the handler materializes the page, dump its bytes and compare them with the file image.<sup>[[11]](#references)</sup> A post-fault `!vprot` cannot prove that the page was guarded beforehand because guard status is one-shot.<sup>[[11]](#references)[[12]](#references)</sup> Narrow the exception filters or handler breakpoints once the relevant image range is known to avoid unrelated faults.<sup>[[16]](#references)</sup> See [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) for filter setup.<sup>[[16]](#references)</sup>

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
- [11] [Eidolon - Fault-driven image loading](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Creating Guard Pages](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Display Exception Record)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - sx exception filters](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Go with Exception Not Handled)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
