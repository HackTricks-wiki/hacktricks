# Windows Exception-Driven Control Flow and Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Programu ya Windows iliyolindwa inaweza kutumia exception ya makusudi kama tawi: instruction inayosababisha kosa ndiyo tu sehemu ya kuingia kwenye handler inayochagua anwani inayofuata ya user-code. Hii huficha edges zisizoonekana wakati wa linear disassembly na kuhamishia hatua inayofuata kwenye exception dispatch.<sup>[[1]](#references)</sup>

## Dispatch ni muhimu

Debugger iliyoambatishwa kwenye process hupokea exception ya **first-chance** kabla ya application handlers. Ikiipitisha event kama isiyoshughulikiwa, Windows hutafuta handlers za process; exception isiyo na handler hurudishwa kwa debugger kama **last-chance**. Kwa hiyo, debugger inayotumia breakpoint au event ya single-step inaweza kubadilisha kama handler ya programu itaendeshwa.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` husajili VEH ya process nzima mwanzoni mwa orodha ya vectored. Huendeshwa kabla ya SEH ya frame-based, lakini usajili wa baadaye wenye kipaumbele cha kwanza unaweza kuiweka handler nyingine mbele yake. Kurudisha `EXCEPTION_CONTINUE_SEARCH` huiacha exception ishughulikiwe na handlers nyingine; `EXCEPTION_CONTINUE_EXECUTION` huendelea kutoka kwenye `CONTEXT` iliyohifadhiwa, pamoja na mabadiliko yoyote ya register yaliyofanywa na handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

SEH ya kawaida ya x86 hutumia usajili unaounganishwa kupitia stack, ambao `!exchain` inaweza kukagua. x64 ya asili hutumia entries za `RUNTIME_FUNCTION` katika `.pdata` pamoja na unwind data katika `.xdata`, si chain hiyo ya x86. Usitumie [utaratibu wa x86 SEH overwrite](../binary-exploitation/stack-overflow/windows-seh-overflow.md) kwenye process asilia ya x64.<sup>[[5]](#references)[[6]](#references)</sup>

## Geuza kosa kuwa edge ya control-flow

Kwa mfano, divisor ya sifuri inaweza kusababisha kwa makusudi `EXCEPTION_INT_DIVIDE_BY_ZERO` badala ya kuwakilisha bug. Handler lazima itambue exception na anwani ilikosababishwa, kisha iweke `ContextRecord->Rip` (au `Eip` kwenye x86) kwenye continuation halali kabla ya kurudisha `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Kiini cha handler kilicho hapa chini kinadhania kuwa `fault_site` na `continuation` ni anwani zinazojulikana katika muktadha uleule wa control-flow. Utekelezaji halisi lazima uhifadhi stack na registers zinazotarajiwa, na usiendelee kutoka kwenye instruction ileile iliyosababisha kosa, la sivyo kosa litatokea tena.<sup>[[7]](#references)</sup>

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

Mekanisma hiyo hiyo inaweza kushughulikia `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) iliyowekwa kimakusudi na kuelekeza upya utekelezaji. **Usiongeze tu `Rip` bila kufikiri ili “kuruka breakpoint”**: anwani iliyohifadhiwa na marekebisho yanayohitajika hutegemea trap, encoding ya instruction na tabia ya debugger. Linganisha `ExceptionRecord->ExceptionAddress` na instruction pointer iliyohifadhiwa, kisha disassemble bytes kabla ya kuchagua mahali pa kuendelea.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) ni mfano tofauti wa hardware-breakpoint unaobadilisha hali ya kurudi ya syscall ya loader.

## Trap Flag kama lango linalotegemea debugger

Bit `0x100` katika `EFLAGS`/`RFLAGS` ni Trap Flag (TF). Kuiweka husababisha mpaka wa instruction unaofuata kutoa `STATUS_SINGLE_STEP` (`0x80000004`). Tawi la VEH au SEH linaweza kutofautisha tukio la single-step lililowasilishwa kwa programu na lile lililoshughulikiwa na debugger, lakini hii ni **heuristic inayodhibitiwa na sera ya debugger ya kushughulikia exceptions**, si uthibitisho wa kuaminika kwamba debugger ipo.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Ikiwa handler inahitaji hatua moja tu, futa `0x100` katika `EFlags` ya context iliyorejeshwa kabla ya kuendelea. Pia tofautisha hatua zinazoendeshwa na TF na matukio ya hardware-breakpoint kwa kukagua anwani iliyosababisha tukio na hali ya debug; vyote vinaweza kuonekana kama `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Kwa mipangilio ya `sxe`, `sxd`, na `sxi` ya WinDbg ya first-/second-chance, angalia [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Vighairi](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Ushughulikiaji wa Vighairi vya Debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Ushughulikiaji wa Vighairi vya Vectored](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Ushughulikiaji wa vighairi wa x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Kutumia Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Maelekezo ya Assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Usanifu wa x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
