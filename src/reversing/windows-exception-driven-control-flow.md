# Windows Exception-Driven Control Flow और Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

एक protected Windows program किसी intentional exception को branch की तरह इस्तेमाल कर सकता है: fault करने वाला instruction केवल उस handler तक पहुँचने का रास्ता होता है जो अगला user-code address चुनता है। इससे linear disassembly में edges छिप जाते हैं और अगला step exception dispatch में चला जाता है।<sup>[[1]](#references)</sup>

## Dispatch महत्वपूर्ण है

Process से जुड़ा debugger, application handlers से पहले **first-chance** exception प्राप्त करता है। अगर वह event को unhandled बताकर आगे भेजता है, तो Windows process के handlers को खोजता है; बिना handler वाला exception **last-chance** के रूप में debugger के पास लौटता है। इसलिए breakpoint या single-step event को consume करने वाला debugger यह बदल सकता है कि program का handler चलेगा या नहीं।<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` process-wide VEH को vectored list के सबसे आगे register करता है। यह frame-based SEH से पहले चलता है, लेकिन बाद में first-priority पर किया गया registration किसी दूसरे handler को इससे आगे ला सकता है। `EXCEPTION_CONTINUE_SEARCH` लौटाने से exception दूसरे handlers के लिए बना रहता है; `EXCEPTION_CONTINUE_EXECUTION` saved `CONTEXT` से execution फिर शुरू करता है, जिसमें handler द्वारा किए गए register changes भी शामिल हैं।<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Classic x86 SEH stack-linked registrations का इस्तेमाल करता है, जिन्हें `!exchain` से inspect किया जा सकता है। Native x64 में x86 chain के बजाय `.pdata` में `RUNTIME_FUNCTION` entries और `.xdata` में unwind data होते हैं। Native x64 process पर [x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md) लागू न करें।<sup>[[5]](#references)[[6]](#references)</sup>

## Fault को control-flow edge में बदलें

उदाहरण के लिए, zero divisor किसी bug के बजाय जानबूझकर `EXCEPTION_INT_DIVIDE_BY_ZERO` raise कर सकता है। Handler को exception और fault address पहचानना होगा, फिर `EXCEPTION_CONTINUE_EXECUTION` लौटाने से पहले `ContextRecord->Rip` (या x86 पर `Eip`) को किसी valid continuation पर सेट करना होगा।<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

नीचे दिया गया handler core मानता है कि `fault_site` और `continuation` एक ही control-flow context में ज्ञात addresses हैं। वास्तविक implementation में अपेक्षित stack और registers को सुरक्षित रखना होगा, और उसी faulting instruction पर resume नहीं करना चाहिए, वरना वह फिर से fault करेगा।<sup>[[7]](#references)</sup>

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

वही mechanism जानबूझकर दिए गए `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) को consume करके execution को redirect कर सकता है। Breakpoint को "skip" करने के लिए `Rip` को बिना सोचे-समझे increment **न करें**: saved address और ज़रूरी adjustment trap, instruction encoding और debugger behavior पर निर्भर करते हैं। Continuation चुनने से पहले `ExceptionRecord->ExceptionAddress` की तुलना saved instruction pointer से करें और bytes को disassemble करें।<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) एक अलग hardware-breakpoint उदाहरण है, जो loader syscall की return state को बदलता है।

## Trap Flag को debugger पर निर्भर gate के रूप में इस्तेमाल करना

`EFLAGS`/`RFLAGS` में bit `0x100` Trap Flag (TF) है। इसे set करने से अगली instruction boundary पर `STATUS_SINGLE_STEP` (`0x80000004`) raise होता है। VEH या SEH branch यह पहचान सकती है कि application को दिया गया single-step event debugger ने consume किया है या नहीं, लेकिन यह **debugger exception policy द्वारा नियंत्रित heuristic है**, debugger मौजूद होने का विश्वसनीय प्रमाण नहीं।<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

यदि handler को केवल एक step चाहिए, तो आगे जारी रखने से पहले resumed context के `EFlags` में `0x100` clear करें। Triggering address और debug state की जाँच करके TF-driven steps और hardware-breakpoint events में भी अंतर करें; दोनों `EXCEPTION_SINGLE_STEP` के रूप में दिखाई दे सकते हैं।<sup>[[8]](#references)[[9]](#references)</sup> WinDbg की `sxe`, `sxd` और `sxi` first-/second-chance settings के लिए, [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) देखें।

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
