# Windows Process Injection via Thread Names and Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) transfers bytes into a running process without `WriteProcessMemory`; Waiting Thread Hijacking (WTH) runs them on an existing thread without `SetThreadContext` or creating a remote thread.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> These are **process-injection primitives, not privilege-escalation vulnerabilities**: the injector still needs access to the target process and thread.<sup>[[3]](#references)</sup> See [Antivirus (AV) Bypass](av-bypass.md) for other injection and evasion approaches.

## Thread Name-Calling: target-side payload copying

`NtSetInformationThread(ThreadNameInformation)` copies a supplied `UNICODE_STRING` into the thread-name storage. Calling `GetThreadDescription` **inside the target** then creates a user-mode heap copy of that name. This separates payload transfer from the final memory copy: the injector can read the returned heap **pointer**, while an APC running `RtlMoveMemory` inside the target copies the bytes to their destination.<sup>[[1]](#references)</sup> The original technique also supports special user APCs; the WhisperHijack implementation instead uses ordinary `NtQueueApcThread` on a waiting thread.<sup>[[1]](#references)[[3]](#references)</sup>

For each chunk of at most `0xFFFE` bytes, the PoC uses this ordering. A duplicated auto-reset event signals completion only after the target has filled the scratch slot; the injector waits for that signal before reading the pointer. The last APC must finish before the thread name is replaced with the next chunk.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

The scratch address must be writable in the target and known to the injector without first writing it. The original PoC uses `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack also offers `PEB.PostProcessInitRoutine` and defaults to `TEB.TlsSlots[63]` (located with `NtQueryInformationThread(ThreadBasicInformation)`). The TLS slot is **not guaranteed unused** in every target; overwriting a live slot can break that thread. Enable exactly one option in `Main.c`. The compile-time checks reject missing or conflicting PEB/TEB selections.<sup>[[4]](#references)</sup>

A normal `RtlInitUnicodeString` call would stop at an embedded wide null. To carry binary data, initialize the `UNICODE_STRING` length using a same-sized non-null padding buffer, replace its `Buffer` bytes with the real chunk, then pass it to `NtSetInformationThread`. This length-based transfer is distinct from passing the shellcode directly to `SetThreadDescription` as a terminated string.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: return from a queue wait

Enumerate threads with `NtQuerySystemInformation(SystemProcessInformation)` and look for `ThreadState == Waiting` with `WaitReason == WrQueue`. A thread blocked in a syscall wrapper such as `NtWaitForWorkViaWorkerFactory` has a saved caller return address at `[Rsp]`. Replacing that stack slot redirects the wrapper's `ret` to a stub without changing `Rip` through `SetThreadContext`. The stub must save flags and registers, **call** a payload that returns, restore state, then jump through the saved original return address.<sup>[[2]](#references)[[3]](#references)</sup>

In the x64 PoC, the stub has an 8-byte saved-return slot at `+0x00`, instructions at `+0x08`, and the payload at `+0x45`. The stack slot receives `allocation_base + 0x08`, not the data slot address. `WrQueue` alone is **not proof** of a worker-factory wait: the original research also identifies `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` as a queue-wait path. Check the actual wait/call stack and that `[Rsp]` is the intended return slot before relying on this layout.<sup>[[2]](#references)[[3]](#references)</sup>

## Combining TNC and WTH without cross-process writes

WhisperHijack demonstrates the combined workflow against an existing native x64 process. Build its x64 solution and run the executable without arguments; the Writer searches for a candidate process/thread, while a Flipper child inherits the handles needed for the final hand-off. The process handle requests `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **not** `PROCESS_VM_WRITE`; the current PoC nevertheless opens the thread with `THREAD_ALL_ACCESS`. Access checks and process mitigations still apply.<sup>[[3]](#references)[[4]](#references)</sup>

The combined PoC uses this sequence; the memory copy APCs execute in the target rather than through a handle with remote-write rights.<sup>[[4]](#references)</sup>

1. Reserve 64-KB-aligned free blocks in the target, then commit their 4-KB pages as `PAGE_READWRITE`. The PoC probes fixed candidate addresses with `NtQueryVirtualMemory`; these addresses are implementation choices, not a requirement of TNC or WTH.
2. Assemble `[0x45-byte WTH stub][returning x64 payload][8-byte stub-entry pointer]`, where the final pointer is `allocation_base + 0x08`. Deliver this buffer with the TNC chunk loop.
3. In the Flipper, obtain the waiting thread's `Rsp` with `NtGetContextThread(CONTEXT_CONTROL)`. Queue an in-target `RtlMoveMemory` APC to copy the original 8-byte value at `[Rsp]` to the stub's data slot.
4. Change the staged region to executable with `NtProtectVirtualMemory`. This PoC chooses `PAGE_EXECUTE_READWRITE` because its polymorphic payload self-decodes; WTH itself does not require a self-modifying payload.
5. Queue another in-target `RtlMoveMemory` APC to copy the **pre-staged tail pointer** into `[Rsp]`, then call `NtAlertThread`. FIFO APC ordering saves the original return before replacing it; the wrapper's return enters the stub and, after the payload returns, resumes the original caller.

The absence of `NtWriteVirtualMemory` does **not** mean there are no target writes: `GetThreadDescription` and `RtlMoveMemory` perform them inside the target.<sup>[[1]](#references)[[3]](#references)</sup> Ordinary user APC delivery also depends on the selected thread servicing its APC queue; a `WrQueue` snapshot and an alert are not a general guarantee of immediate execution.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> The example avoids remote-thread creation, suspension and direct context replacement, but remains observable through its APCs and protection transition.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC and README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – WhisperHijack Main.c implementation](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)

{{#include ../banners/hacktricks-training.md}}
