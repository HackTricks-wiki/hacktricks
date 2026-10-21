# Windows 예외 기반 제어 흐름 및 Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

보호된 Windows 프로그램은 의도적으로 예외를 발생시켜 분기할 수 있습니다. 오류를 일으키는 명령어는 핸들러로 진입하는 지점일 뿐이며, 핸들러가 다음 사용자 코드 주소를 선택합니다. 이렇게 하면 선형 디스어셈블리에서 제어 흐름의 연결이 숨겨지고, 다음 단계가 예외 디스패치로 옮겨집니다.<sup>[[1]](#references)</sup>

## 디스패치가 중요합니다

프로세스에 디버거가 연결되어 있으면 애플리케이션 핸들러보다 먼저 **first-chance** 예외를 받습니다. 디버거가 이벤트를 처리되지 않은 것으로 전달하면 Windows가 프로세스 핸들러를 검색합니다. 핸들러가 없는 예외는 **last-chance** 예외로 디버거에 돌아갑니다. 따라서 디버거가 breakpoint 또는 single-step 이벤트를 처리하면 프로그램의 핸들러 실행 여부가 달라질 수 있습니다.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)`는 프로세스 전체에 적용되는 VEH를 vectored 목록의 맨 앞에 등록합니다. 이 핸들러는 프레임 기반 SEH보다 먼저 실행되지만, 나중에 우선순위가 같은 핸들러가 등록되면 그 핸들러가 앞에 올 수 있습니다. `EXCEPTION_CONTINUE_SEARCH`를 반환하면 다른 핸들러가 예외를 처리하도록 둡니다. `EXCEPTION_CONTINUE_EXECUTION`을 반환하면 저장된 `CONTEXT`에서 실행을 재개하며, 여기에는 핸들러가 변경한 레지스터 값도 포함됩니다.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

기존 x86 SEH는 스택에 연결된 등록 정보를 사용하며, `!exchain`으로 확인할 수 있습니다. Native x64는 이 x86 체인 대신 `.pdata`의 `RUNTIME_FUNCTION` 항목과 `.xdata`의 unwind 데이터를 사용합니다. Native x64 프로세스에 [x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md)를 적용하지 마세요.<sup>[[5]](#references)[[6]](#references)</sup>

## 오류를 제어 흐름의 연결로 바꾸기

예를 들어 0으로 나누기는 버그가 아니라 의도적으로 `EXCEPTION_INT_DIVIDE_BY_ZERO`를 발생시키는 데 사용할 수 있습니다. 핸들러는 예외와 오류 주소를 식별한 다음, `EXCEPTION_CONTINUE_EXECUTION`을 반환하기 전에 `ContextRecord->Rip`(또는 x86의 `Eip`)를 유효한 실행 재개 지점으로 설정해야 합니다.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

아래 handler core는 `fault_site`와 `continuation`이 동일한 제어 흐름 컨텍스트 내에서 알려진 주소라고 가정한다. 실제 구현에서는 예상되는 스택과 레지스터를 보존해야 하며, 오류가 발생한 동일한 명령어에서 재개해서는 안 된다. 그렇지 않으면 다시 오류가 발생한다.<sup>[[7]](#references)</sup>

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

동일한 메커니즘으로 의도적인 `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`)를 처리하고 실행을 리디렉션할 수 있습니다. "브레이크포인트를 건너뛰기" 위해 `Rip`을 무조건 증가시키지 마세요. 저장된 주소와 필요한 조정은 트랩, 명령어 인코딩, 디버거 동작에 따라 달라집니다. 계속 실행할 위치를 선택하기 전에 `ExceptionRecord->ExceptionAddress`를 저장된 명령어 포인터와 비교하고 바이트를 디스어셈블하세요.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md)는 로더 syscall의 반환 상태를 변경하는 별도의 하드웨어 브레이크포인트 예제입니다.

## Trap Flag를 디버거 종속 게이트로 사용하기

`EFLAGS`/`RFLAGS`의 비트 `0x100`은 Trap Flag (TF)입니다. 이 비트를 설정하면 다음 명령어 경계에서 `STATUS_SINGLE_STEP` (`0x80000004`)이 발생합니다. VEH 또는 SEH 분기는 애플리케이션에 전달된 단일 단계 이벤트와 디버거가 처리한 이벤트를 구분할 수 있지만, 이는 디버거가 존재한다는 신뢰할 수 있는 증거가 아니라 **디버거 예외 정책에 따라 달라지는 휴리스틱**입니다.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

핸들러가 한 단계만 실행하려는 경우, 계속 진행하기 전에 재개된 context의 `EFlags`에서 `0x100`을 지웁니다. 또한 트리거 주소와 debug 상태를 확인해 TF 기반 단계 실행과 hardware-breakpoint 이벤트를 구분해야 합니다. 둘 다 `EXCEPTION_SINGLE_STEP`으로 나타날 수 있습니다.<sup>[[8]](#references)[[9]](#references)</sup> WinDbg의 `sxe`, `sxd`, `sxi` first-/second-chance 설정은 [WinDbg 예외 자동화](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception)를 참조하세요.

## References

- [1] [Check Point Research - Anti-Debug: 예외](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Debugger 예외 처리](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Vectored 예외 처리](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64 예외 처리](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Vectored Exception Handler 사용](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: 어셈블리 명령어](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 아키텍처](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
