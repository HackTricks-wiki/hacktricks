# Windows Exception-Driven Control Flow en Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

’n Beskermde Windows-program kan ’n opsetlike exception as ’n vertakking gebruik: die instruksie wat die fout veroorsaak, is slegs die ingang na ’n handler wat die volgende user-code-adres kies. Dit verberg rande vir lineêre disassembly en skuif die volgende stap na exception dispatch.<sup>[[1]](#references)</sup>

## Dispatch is belangrik

’n Debugger wat aan die proses gekoppel is, ontvang ’n **first-chance** exception voordat application handlers dit ontvang. As dit die gebeurtenis as onbehandeld deurgee, soek Windows na die proses se handlers; ’n exception waarvoor geen handler bestaan nie, keer as **last-chance** terug na die debugger. ’n Debugger wat ’n breakpoint- of single-step-gebeurtenis onderskep, kan dus bepaal of die program se handler loop.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registreer ’n proseswye VEH voor in die vectored list. Dit loop voor frame-based SEH, maar ’n latere registrasie met eerste prioriteit kan ’n ander handler daarvoor plaas. Deur `EXCEPTION_CONTINUE_SEARCH` terug te gee, bly die exception beskikbaar vir ander handlers; `EXCEPTION_CONTINUE_EXECUTION` hervat uitvoering vanaf die gestoorde `CONTEXT`, insluitend enige registerveranderinge wat die handler gemaak het.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klassieke x86 SEH gebruik stack-linked registrations, wat `!exchain` kan inspekteer. Native x64 gebruik `RUNTIME_FUNCTION`-inskrywings in `.pdata` met unwind-data in `.xdata`, nie daardie x86-ketting nie. Moenie die [x86 SEH overwrite-werkvloei](../binary-exploitation/stack-overflow/windows-seh-overflow.md) op ’n native x64-proses toepas nie.<sup>[[5]](#references)[[6]](#references)</sup>

## Verander ’n fout in ’n control-flow-rand

Byvoorbeeld, ’n deler van nul kan doelbewus `EXCEPTION_INT_DIVIDE_BY_ZERO` veroorsaak eerder as om ’n fout voor te stel. Die handler moet die exception en foutadres herken, en dan `ContextRecord->Rip` (of `Eip` op x86) op ’n geldige voortsettingspunt stel voordat dit `EXCEPTION_CONTINUE_EXECUTION` teruggee.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Die handler-kern hieronder neem aan dat `fault_site` en `continuation` bekende adresse in dieselfde control-flow-konteks is. ’n Werklike implementering moet die verwagte stapel en registers behou, en mag nie by dieselfde instruksie wat die fout veroorsaak het hervat nie, anders sal dit weer ’n fout veroorsaak.<sup>[[7]](#references)</sup>

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

Dieselfde meganisme kan ’n doelbewuste `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) verbruik en uitvoering herlei. Moenie blindelings `Rip` verhoog om “die breakpoint oor te slaan” nie: die gestoorde adres en vereiste aanpassing hang af van die trap, instruksie-enkodering en debuggergedrag. Vergelyk `ExceptionRecord->ExceptionAddress` met die gestoorde instruksiewyser en disassembleer die grepe voordat jy die voortsettingspunt kies.<sup>[[8]](#references)</sup> Die [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) is ’n afsonderlike hardeware-breakpoint-voorbeeld wat ’n loader-syscall se terugkeertoestand verander.

## Trap Flag as ’n debugger-afhanklike hek

Bit `0x100` in `EFLAGS`/`RFLAGS` is die Trap Flag (TF). As dit gestel word, veroorsaak dit dat die volgende instruksiegrens `STATUS_SINGLE_STEP` (`0x80000004`) laat ontstaan. ’n VEH- of SEH-vertakking kan onderskei tussen ’n single-step-gebeurtenis wat aan die toepassing deurgegee word en een wat deur ’n debugger verbruik word, maar dit is ’n **heuristiek wat deur die debugger se uitsonderingsbeleid beheer word**, nie betroubare bewys dat ’n debugger bestaan nie.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

As die handler net een stap wil hê, maak `0x100` in die hervatte konteks se `EFlags` skoon voordat jy voortgaan. Onderskei ook TF-gedrewe stappe van hardewarebreekpuntgebeurtenisse deur die snelleradres en ontfoutingstoestand na te gaan; albei kan as `EXCEPTION_SINGLE_STEP` verskyn.<sup>[[8]](#references)[[9]](#references)</sup> Vir WinDbg se `sxe`-, `sxd`- en `sxi`-instellings vir eerste- en tweede kans, sien [WinDbg-exception-outomatisering](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-ontfouting: uitsonderings](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Ontfouter se uitsonderingshantering](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Vektorgebaseerde uitsonderingshantering](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64-uitsonderingshantering](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Gebruik van ’n vektorgebaseerde uitsonderingshandler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-ontfouting: Assembly-instruksies](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86-argitektuur](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
