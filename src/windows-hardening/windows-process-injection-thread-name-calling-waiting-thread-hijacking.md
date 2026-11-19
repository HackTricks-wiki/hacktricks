# Windows Process Injection via Thread Names and Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC)은 `WriteProcessMemory` 없이 실행 중인 프로세스로 바이트를 전송하고, Waiting Thread Hijacking (WTH)은 `SetThreadContext`를 사용하거나 원격 스레드를 생성하지 않고 기존 스레드에서 바이트를 실행합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> 이는 **권한 상승 취약점이 아니라 프로세스 인젝션 프리미티브**입니다. 따라서 인젝터는 여전히 대상 프로세스와 스레드에 접근할 수 있어야 합니다. 스레드 설명 API를 사용하려면 Windows 10 version 1607 이상이 필요합니다.<sup>[[1]](#references)[[3]](#references)</sup> 다른 인젝션 및 회피 기법은 [Antivirus (AV) Bypass](av-bypass.md)를 참조하세요.

## Thread Name-Calling: target-side payload copying

`NtSetInformationThread(ThreadNameInformation)`은 전달된 `UNICODE_STRING`을 스레드 이름 저장소에 복사합니다. **대상 내부에서** `GetThreadDescription`을 호출하면 해당 이름의 user-mode heap 복사본이 생성됩니다. 이 방식은 페이로드 전송과 최종 메모리 복사를 분리합니다. 인젝터는 반환된 heap **포인터**를 읽고, 대상 내부에서 실행되는 APC가 `RtlMoveMemory`를 실행해 바이트를 목적지로 복사합니다.<sup>[[1]](#references)</sup> 원래 기법은 special user APC도 지원하지만, WhisperHijack 구현은 대기 중인 스레드에서 일반 `NtQueueApcThread`를 사용합니다.<sup>[[1]](#references)[[3]](#references)</sup>

각 청크의 크기는 최대 `0xFFFE`바이트이며, PoC는 다음 순서를 따릅니다. 복제된 auto-reset event는 대상이 scratch slot을 채운 뒤에만 완료를 알립니다. 인젝터는 이 신호를 기다린 다음 포인터를 읽습니다. 이 이벤트는 heap 포인터를 얻는 APC의 완료를 확인할 뿐, 이후의 복사 APC 완료를 확인하지는 않습니다. PoC는 복사 APC를 큐에 넣은 뒤 같은 스레드에 alert를 보내고, 두 번째 완료 신호 대신 APC 실행 순서에 의존합니다.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

scratch 주소는 target에서 쓰기 가능해야 하며, 먼저 기록하지 않고도 injector가 주소를 알고 있어야 합니다. 원본 PoC는 `PEB.SpareUlongs`를 사용합니다.<sup>[[1]](#references)</sup> WhisperHijack은 `PEB.PostProcessInitRoutine`도 제공하며, 기본값으로 `TEB.TlsSlots[63]`을 사용합니다(`NtQueryInformationThread(ThreadBasicInformation)`으로 위치 확인). TLS slot이 모든 target에서 **사용되지 않는다고 보장할 수는 없습니다**. 사용 중인 slot을 덮어쓰면 해당 thread가 오작동할 수 있습니다. `Main.c`에서 옵션을 정확히 하나만 활성화하세요. 컴파일 시 검사는 PEB/TEB 선택 누락이나 충돌을 거부합니다.<sup>[[4]](#references)</sup>

일반적인 `RtlInitUnicodeString` 호출은 wide null이 삽입된 지점에서 중단됩니다. 바이너리 데이터를 전달하려면 같은 크기의 null이 아닌 padding buffer를 사용해 `UNICODE_STRING` 길이를 초기화한 다음, `Buffer`의 바이트를 실제 chunk로 바꾸고 `NtSetInformationThread`에 전달합니다. 길이 기반 전송 방식은 shellcode를 종료 문자가 있는 문자열로 `SetThreadDescription`에 직접 전달하는 방식과 다릅니다.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: queue wait에서 복귀

`NtQuerySystemInformation(SystemProcessInformation)`으로 thread를 열거하고 `ThreadState == Waiting` 및 `WaitReason == WrQueue`인 thread를 찾습니다. `NtWaitForWorkViaWorkerFactory` 같은 syscall wrapper에서 대기 중인 thread는 `[Rsp]`에 저장된 호출자 return address를 갖습니다. 해당 stack slot을 바꾸면 `SetThreadContext`로 `Rip`을 변경하지 않고도 wrapper의 `ret`이 stub으로 이동합니다. stub은 flags와 registers를 저장하고, return하는 payload를 **호출**한 뒤, 상태를 복원하고 저장된 원래 return address로 이동해야 합니다.<sup>[[2]](#references)[[3]](#references)</sup>

x64 PoC에서 stub은 `+0x00`에 8바이트 saved-return slot을 두고, `+0x08`에 instructions를, `+0x45`에 payload를 둡니다. stack slot에는 data slot 주소가 아니라 `allocation_base + 0x08`을 넣습니다. `WrQueue`만으로는 worker-factory 대기 상태임을 **증명할 수 없습니다**. 원본 연구에서는 `NtRemoveIoCompletion`/`GetQueuedCompletionStatus`도 queue-wait 경로로 확인했습니다. 이 레이아웃을 신뢰하기 전에 실제 wait/call stack과 `[Rsp]`가 의도한 return slot인지 확인하세요.<sup>[[2]](#references)[[3]](#references)</sup>

## cross-process write 없이 TNC와 WTH 결합하기

WhisperHijack은 기존 native x64 process를 대상으로 결합된 workflow를 보여줍니다. Writer는 후보 process/thread를 선택하고, Flipper child는 최종 hand-off에 필요한 handles를 상속합니다. process handle은 `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`을 요청하며, `PROCESS_VM_WRITE`는 요청하지 않습니다. **그러나** 현재 PoC는 여전히 `THREAD_ALL_ACCESS`로 thread를 엽니다. Access 검사와 process mitigation은 여전히 적용됩니다.<sup>[[3]](#references)[[4]](#references)</sup>

결합된 PoC는 다음 순서를 사용합니다. memory copy APC는 remote-write 권한이 있는 handle을 통하지 않고 target 내에서 실행됩니다.<sup>[[4]](#references)</sup>

1. target에서 64-KB 정렬된 빈 block을 예약한 다음, 해당 4-KB page를 `PAGE_READWRITE`로 commit합니다. PoC는 `NtQueryVirtualMemory`로 고정된 후보 주소를 확인하지만, 이 주소들은 구현상 선택일 뿐 TNC나 WTH의 필수 조건은 아닙니다.
2. `[0x45-byte WTH stub][returning x64 payload][8-byte stub-entry pointer]`를 구성합니다. 마지막 pointer는 `allocation_base + 0x08`입니다. 이 buffer를 TNC chunk loop로 전달합니다.
3. Flipper에서 `NtGetContextThread(CONTEXT_CONTROL)`로 대기 중인 thread의 `Rsp`를 가져옵니다. target 내부에서 `RtlMoveMemory`를 실행하는 APC를 queue하여 `[Rsp]`의 원래 8바이트 값을 stub의 data slot으로 복사합니다.
4. `NtProtectVirtualMemory`로 staged region을 executable로 변경합니다. 이 PoC는 polymorphic payload가 자체적으로 decode되므로 `PAGE_EXECUTE_READWRITE`를 선택하지만, WTH 자체에는 self-modifying payload가 필요하지 않습니다.
5. target 내부에서 `RtlMoveMemory`를 실행하는 또 다른 APC를 queue하여 **미리 staging한 tail pointer**를 `[Rsp]`로 복사한 다음 `NtAlertThread`를 호출합니다. FIFO APC 순서에 따라 원래 return이 교체되기 전에 저장됩니다. wrapper의 return은 stub으로 이동하고, payload가 return한 뒤에는 원래 호출자로 복귀합니다.

`NtWriteVirtualMemory`가 없다고 해서 target 쓰기가 전혀 없는 것은 **아닙니다**. `GetThreadDescription`과 `RtlMoveMemory`가 target 내부에서 쓰기를 수행합니다.<sup>[[1]](#references)[[3]](#references)</sup> 일반 user APC 전달 역시 선택한 thread가 APC queue를 처리하는지에 달려 있습니다. `WrQueue` 상태 확인과 alert만으로는 즉시 실행을 일반적으로 보장할 수 없습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> 이 예시는 remote-thread 생성, suspension, 직접적인 context 교체를 피하지만, APC와 protection 전환을 통해 여전히 관찰될 수 있습니다.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC 및 README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – WhisperHijack Main.c 구현](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
