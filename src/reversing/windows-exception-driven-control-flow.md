# Windows Exception-Driven Control Flow और Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

एक protected Windows program जानबूझकर exception का इस्तेमाल branch के रूप में कर सकता है: faulting instruction केवल उस handler तक पहुंचने का रास्ता होती है, जो अगला user-code address चुनता है। इससे linear disassembly में edges छिप जाते हैं और अगला step exception dispatch में चला जाता है।<sup>[[1]](#references)</sup>

## Dispatch मायने रखता है

Process से जुड़ा debugger application handlers से पहले **first-chance** exception प्राप्त करता है। अगर वह event को unhandled बताकर आगे भेजता है, तो Windows process के handlers खोजता है; बिना handler वाले exception के मामले में नियंत्रण **last-chance** के रूप में debugger को लौटता है। इसलिए breakpoint या single-step event को consume करने वाला debugger यह बदल सकता है कि program का handler चलेगा या नहीं।<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` process-wide VEH को vectored list के सबसे आगे register करता है। यह frame-based SEH से पहले चलता है, लेकिन बाद में किया गया कोई first-priority registration दूसरे handler को इससे आगे कर सकता है। `EXCEPTION_CONTINUE_SEARCH` लौटाने से exception दूसरे handlers के लिए छोड़ दिया जाता है; `EXCEPTION_CONTINUE_EXECUTION` saved `CONTEXT` से execution फिर शुरू करता है, जिसमें handler द्वारा किए गए register बदलाव भी शामिल हैं।<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Classic x86 SEH में stack-linked registrations होते हैं, जिन्हें `!exchain` से जांचा जा सकता है। Native x64 में उस x86 chain के बजाय `.pdata` में `RUNTIME_FUNCTION` entries और `.xdata` में unwind data होते हैं। Native x64 process पर [x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md) लागू न करें।<sup>[[5]](#references)[[6]](#references)</sup>

## Fault को control-flow edge में बदलना

उदाहरण के लिए, zero divisor को bug के बजाय जानबूझकर `EXCEPTION_INT_DIVIDE_BY_ZERO` raise करने के लिए इस्तेमाल किया जा सकता है। Handler को exception और fault address पहचानना होगा, फिर `EXCEPTION_CONTINUE_EXECUTION` लौटाने से पहले `ContextRecord->Rip` (या x86 पर `Eip`) को किसी valid continuation पर सेट करना होगा।<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

नीचे दिया गया handler core मानता है कि `fault_site` और `continuation` उसी control-flow context में ज्ञात addresses हैं। वास्तविक implementation में अपेक्षित stack और registers को सुरक्षित रखना होगा, और उसी faulting instruction पर फिर से execution शुरू नहीं करना चाहिए, वरना दोबारा fault होगा।<sup>[[7]](#references)</sup>

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

वही mechanism जानबूझकर दिए गए `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) को consume करके execution को redirect भी कर सकता है। Breakpoint को "skip" करने के लिए `Rip` को बिना सोचे-समझे increment **न करें**: saved address और ज़रूरी adjustment trap, instruction encoding और debugger behavior पर निर्भर करते हैं। Continuation चुनने से पहले `ExceptionRecord->ExceptionAddress` की तुलना saved instruction pointer से करें और bytes को disassemble करें।<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) एक अलग hardware-breakpoint उदाहरण है, जो loader syscall की return state बदलता है।

## Fault-driven page materialization

VEH page fault को सिर्फ jump नहीं, बल्कि **lazy loader** में बदल सकता है। ऐसा private image range reserve करें जिसके pages uncommitted हों, या जहाँ समर्थित हो, mapped pages को guard करें। Image चलाने से पहले relocation sites और IAT thunks को उनके destination page के अनुसार index करें। उस range के अंदर fault होने पर handler प्रभावित page को commit करता है या writable बनाता है, उसके section bytes copy करता है, उस page के relocations और imports लागू करता है, उसकी final protection सेट करता है और `EXCEPTION_CONTINUE_EXECUTION` लौटाता है। मूल instruction फिर से चलाया जाता है; skip-the-fault handler की तरह `Rip` को आगे **न बढ़ाएँ**। जिन pages को कभी access नहीं किया जाता, उनमें payload को memory में रखना ज़रूरी नहीं है।<sup>[[11]](#references)</sup>

Access violation के लिए, `ExceptionRecord->ExceptionAddress` उस **instruction** की पहचान करता है जिसने fault किया, जबकि `ExceptionInformation[1]` accessed address बताता है।<sup>[[10]](#references)</sup> Page materialize करने से पहले exception code, parameter count और accessed-address range जाँचें; वरना किसी unrelated fault को loader request समझा जा सकता है।<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` पहली access पर `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) उठाता है और Windows guard bit को अपने-आप clear कर देता है, इसलिए उसे फिर से arm करना एक अलग step है, continuous hook नहीं।<sup>[[12]](#references)</sup> Dispatch के दौरान VEH और उसके लिए ज़रूरी metadata accessible रखें।<sup>[[11]](#references)</sup> x64 पर, पहले fault से पहले unwind data उपलब्ध होना ज़रूरी हो सकता है; cited loader initialization races से बचने के लिए `DllMain` invoke करने से पहले pages को eagerly materialize करता है।<sup>[[11]](#references)</sup> Code लिखने के बाद और उसे execute करने से पहले instruction cache flush करें।<sup>[[13]](#references)</sup>

Reversing के दौरान इस flow को समझने के लिए, first-chance guard-page violations और access violations पर break करें, exception record देखें, फिर `gn` से event को application के handler तक पहुँचाएँ।<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> मौजूदा page protection देखने के लिए accessed address पर `!vprot` का उपयोग करें।<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Handler के page को materialize करने के बाद, उसके bytes dump करें और file image से उनकी तुलना करें।<sup>[[11]](#references)</sup> Fault के बाद का `!vprot` यह साबित नहीं कर सकता कि page पर पहले से guard लगा था, क्योंकि guard status का प्रभाव केवल एक बार होता है।<sup>[[11]](#references)[[12]](#references)</sup> संबंधित image range का पता चलने के बाद, असंबंधित faults से बचने के लिए exception filters या handler breakpoints को सीमित करें।<sup>[[16]](#references)</sup> Filter setup के लिए [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) देखें।<sup>[[16]](#references)</sup>

## Trap Flag को debugger पर निर्भर gate के रूप में इस्तेमाल करना

`EFLAGS`/`RFLAGS` में bit `0x100` को Trap Flag (TF) कहते हैं। इसे सेट करने पर अगले instruction boundary पर `STATUS_SINGLE_STEP` (`0x80000004`) उठता है। कोई VEH या SEH branch, application को दिए गए single-step event और debugger द्वारा consume किए गए event में अंतर कर सकता है, लेकिन यह **debugger exception policy द्वारा नियंत्रित heuristic है**, न कि इस बात का विश्वसनीय प्रमाण कि debugger मौजूद है।<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

यदि handler को केवल एक step चाहिए, तो आगे बढ़ने से पहले resumed context के `EFlags` में `0x100` clear करें। साथ ही, triggering address और debug state जाँचकर TF-driven steps और hardware-breakpoint events में अंतर करें; दोनों `EXCEPTION_SINGLE_STEP` के रूप में दिखाई दे सकते हैं।<sup>[[8]](#references)[[9]](#references)</sup> WinDbg की `sxe`, `sxd` और `sxi` first-/second-chance settings के लिए, [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) देखें।

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
