# Windows Exception-Driven Control Flow와 Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

보호된 Windows 프로그램은 의도적으로 예외를 발생시켜 분기할 수 있습니다. 오류를 일으키는 명령어는 핸들러로 들어가는 지점일 뿐이며, 핸들러가 다음 user-code 주소를 선택합니다. 이렇게 하면 선형 disassembly에서 제어 흐름의 edge가 숨겨지고, 다음 단계가 exception dispatch로 옮겨집니다.<sup>[[1]](#references)</sup>

## Dispatch가 중요한 이유

프로세스에 연결된 debugger는 애플리케이션 핸들러보다 먼저 **first-chance** 예외를 받습니다. debugger가 이벤트를 처리되지 않은 것으로 전달하면 Windows가 프로세스의 핸들러를 검색합니다. 처리기가 없는 예외는 **last-chance** 예외로 debugger에 돌아갑니다. 따라서 breakpoint 또는 single-step 이벤트를 처리하는 debugger는 프로그램 핸들러의 실행 여부를 바꿀 수 있습니다.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)`는 프로세스 전체에서 사용할 VEH를 vectored list의 맨 앞에 등록합니다. VEH는 frame-based SEH보다 먼저 실행되지만, 나중에 등록된 first-priority 핸들러가 이 핸들러보다 앞에 올 수 있습니다. `EXCEPTION_CONTINUE_SEARCH`를 반환하면 다른 핸들러가 예외를 처리하도록 남겨 둡니다. `EXCEPTION_CONTINUE_EXECUTION`을 반환하면 핸들러가 변경한 레지스터를 포함해 저장된 `CONTEXT`부터 실행을 재개합니다.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Classic x86 SEH는 스택에 연결된 registration을 사용하며, `!exchain`으로 확인할 수 있습니다. Native x64는 이 x86 chain 대신 `.pdata`의 `RUNTIME_FUNCTION` 항목과 `.xdata`의 unwind data를 사용합니다. Native x64 프로세스에 [x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md)를 적용하지 마세요.<sup>[[5]](#references)[[6]](#references)</sup>

## Fault를 control-flow edge로 바꾸기

예를 들어, 0으로 나누기는 버그가 아니라 의도적인 `EXCEPTION_INT_DIVIDE_BY_ZERO` 예외를 발생시키는 데 사용할 수 있습니다. 핸들러는 예외와 fault 주소를 식별한 다음, `EXCEPTION_CONTINUE_EXECUTION`을 반환하기 전에 `ContextRecord->Rip`(x86에서는 `Eip`)를 유효한 continuation으로 설정해야 합니다.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

아래 handler core는 `fault_site`와 `continuation`이 동일한 control-flow context 내의 알려진 주소라고 가정합니다. 실제 구현에서는 예상되는 stack과 register를 보존해야 하며, 같은 faulting instruction에서 다시 실행을 시작하면 다시 fault가 발생합니다.<sup>[[7]](#references)</sup>

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

같은 메커니즘으로 의도적인 `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`)를 처리하고 실행을 리디렉션할 수도 있습니다. **중단점을 건너뛰기 위해** `Rip`을 무작정 증가시키지 마세요. 저장된 주소와 필요한 조정은 트랩, 명령어 인코딩, 디버거 동작에 따라 달라집니다. 계속 실행할 위치를 선택하기 전에 `ExceptionRecord->ExceptionAddress`를 저장된 명령어 포인터와 비교하고 바이트를 디스어셈블하세요.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md)는 loader syscall의 반환 상태를 변경하는 별도의 hardware-breakpoint 예시입니다.

## Fault 기반 페이지 구체화

VEH는 페이지 폴트를 단순히 점프시키는 것이 아니라 **lazy loader**로 바꿀 수 있습니다. 커밋되지 않은 페이지가 있는 private image range를 예약하거나, 지원되는 경우 매핑된 페이지에 guard를 설정하세요. 이미지를 실행하기 전에 재배치 위치와 IAT thunk를 목적지 페이지별로 인덱싱하세요. 해당 범위에서 폴트가 발생하면 핸들러가 해당 페이지를 커밋하거나 쓰기 가능하게 만들고, 섹션 바이트를 복사하고, 해당 페이지의 재배치와 import를 적용한 뒤, 최종 보호 속성을 설정하고 `EXCEPTION_CONTINUE_EXECUTION`을 반환합니다. 원래 명령어가 다시 실행되므로, 폴트를 건너뛰는 핸들러처럼 `Rip`을 증가시키지 마세요. 한 번도 접근하지 않은 페이지에는 payload가 메모리에 존재할 필요가 없습니다.<sup>[[11]](#references)</sup>

Access violation에서 `ExceptionRecord->ExceptionAddress`는 폴트를 일으킨 **명령어**를 가리키고, `ExceptionInformation[1]`은 접근한 주소를 가리킵니다.<sup>[[10]](#references)</sup> 페이지를 구체화하기 전에 예외 코드, 매개변수 개수, 접근한 주소의 범위를 확인하세요. 그렇지 않으면 관련 없는 폴트를 loader 요청으로 오인할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD`는 첫 접근 시 `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`)을 발생시키며 Windows가 guard 비트를 자동으로 지우므로, 다시 설정하는 것은 별도의 단계이지 지속적인 hook이 아닙니다.<sup>[[12]](#references)</sup> 디스패치 중에도 VEH와 필요한 메타데이터에 접근할 수 있도록 유지하세요.<sup>[[11]](#references)</sup> x64에서는 첫 폴트가 발생하기 전에 unwind 데이터가 준비되어 있어야 할 수 있습니다. 인용된 loader는 초기화 경쟁을 피하기 위해 `DllMain`을 호출하기 전에 페이지를 eager materialize합니다.<sup>[[11]](#references)</sup> 코드를 쓰고 실행하기 전에 instruction cache를 flush하세요.<sup>[[13]](#references)</sup>

리버싱 중 이 흐름을 복원하려면 first-chance guard-page violation과 access violation에서 중단하고, 예외 레코드를 확인한 다음 `gn`으로 이벤트를 애플리케이션의 핸들러에 전달하세요.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> 접근한 주소에 `!vprot`을 사용해 현재 페이지 보호 속성을 확인하세요.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

핸들러가 페이지를 메모리에 올린 후 해당 바이트를 덤프하고 파일 이미지와 비교합니다.<sup>[[11]](#references)</sup> fault 발생 후 `!vprot`을 실행해도 페이지가 사전에 guarded 상태였다는 것을 증명할 수는 없습니다. guard 상태는 한 번만 적용되기 때문입니다.<sup>[[11]](#references)[[12]](#references)</sup> 관련 이미지 범위를 확인한 후에는 예외 필터나 핸들러 중단점의 범위를 좁혀 관련 없는 fault를 피합니다.<sup>[[16]](#references)</sup> 필터 설정은 [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception)을 참조하세요.<sup>[[16]](#references)</sup>

## debugger에 종속된 게이트로서의 Trap Flag

`EFLAGS`/`RFLAGS`의 비트 `0x100`은 Trap Flag(TF)입니다. 이 플래그를 설정하면 다음 명령어 경계에서 `STATUS_SINGLE_STEP`(`0x80000004`)이 발생합니다. VEH 또는 SEH 분기는 애플리케이션에 전달된 단일 단계 이벤트와 디버거가 처리한 이벤트를 구분할 수 있지만, 이는 **디버거 예외 정책에 좌우되는 휴리스틱**일 뿐 디버거의 존재를 신뢰성 있게 입증하지는 않습니다.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

핸들러가 한 단계만 실행하려는 경우, 계속하기 전에 재개된 context의 `EFlags`에서 `0x100`을 지우세요. 또한 트리거 주소와 debug 상태를 확인해 TF로 인한 단계 실행과 하드웨어 breakpoint 이벤트를 구분하세요. 둘 다 `EXCEPTION_SINGLE_STEP`으로 나타날 수 있습니다.<sup>[[8]](#references)[[9]](#references)</sup> WinDbg의 `sxe`, `sxd`, `sxi` first-/second-chance 설정은 [WinDbg 예외 자동화](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception)를 참조하세요.

## References

- [1] [Check Point Research - Anti-Debug: 예외](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - 디버거 예외 처리](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - 벡터 예외 처리](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64 예외 처리](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - 벡터 예외 처리기 사용](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: 어셈블리 명령어](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 아키텍처](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - 오류 기반 이미지 로딩](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Guard 페이지 만들기](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (예외 레코드 표시)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - sx 예외 필터](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (처리되지 않은 예외와 함께 계속 실행)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
