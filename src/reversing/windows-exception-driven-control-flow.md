# Windows-uitsonderingsgedrewe beheervloei en anti-debugging

{{#include ../banners/hacktricks-training.md}}

’n Beskermde Windows-program kan ’n opsetlike uitsondering as ’n vertakking gebruik: die instruksie wat die fout veroorsaak, is net die ingang na ’n hanteerder wat die volgende gebruiker-kodeadres kies. Dit verberg rande vir lineêre disassemblering en verskuif die volgende stap na uitsonderingversending.<sup>[[1]](#references)</sup>

## Versending maak saak

’n Ontfouter wat aan die proses gekoppel is, ontvang ’n **eerste-kans**-uitsondering voordat toepassingshanteerders dit ontvang. As dit die gebeurtenis as ongehanteer deurgee, soek Windows deur die proses se hanteerders; ’n uitsondering sonder ’n hanteerder keer as ’n **laaste-kans**-uitsondering terug na die ontfouter. ’n Ontfouter wat ’n breekpunt- of enkelstapgebeurtenis verbruik, kan dus verander of die program se hanteerder loop.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registreer ’n proseswye VEH voor in die vectored-lys. Dit loop voor raamgebaseerde SEH, maar ’n latere registrasie met eerste prioriteit kan ’n ander hanteerder voor dit plaas. As `EXCEPTION_CONTINUE_SEARCH` teruggegee word, bly die uitsondering vir ander hanteerders beskikbaar; `EXCEPTION_CONTINUE_EXECUTION` hervat uitvoering vanaf die gestoorde `CONTEXT`, insluitend enige registerveranderings wat die hanteerder gemaak het.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klassieke x86 SEH gebruik stapelgekoppelde registrasies, wat `!exchain` kan inspekteer. Native x64 gebruik `RUNTIME_FUNCTION`-inskrywings in `.pdata` met unwind-data in `.xdata`, nie daardie x86-ketting nie. Moenie die [x86 SEH-oorwerkwerkvloei](../binary-exploitation/stack-overflow/windows-seh-overflow.md) op ’n native x64-proses toepas nie.<sup>[[5]](#references)[[6]](#references)</sup>

## Verander ’n fout in ’n beheervloeirand

Byvoorbeeld, ’n nul as deler kan doelbewus `EXCEPTION_INT_DIVIDE_BY_ZERO` veroorsaak eerder as om ’n fout te wees. Die hanteerder moet die uitsondering en foutadres herken, en dan `ContextRecord->Rip` (of `Eip` op x86) na ’n geldige voortsetting stel voordat dit `EXCEPTION_CONTINUE_EXECUTION` teruggee.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Die handler-kern hieronder veronderstel dat `fault_site` en `continuation` bekende adresse in dieselfde beheer-vloeikonteks is. ’n Werklike implementering moet die verwagte stack en registers behou, en mag nie by dieselfde foutiewe instruksie hervat nie, anders sal dit weer ’n fout veroorsaak.<sup>[[7]](#references)</sup>

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

Dieselfde meganisme kan ’n opsetlike `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) verbruik en uitvoering herlei. Moenie `Rip` blindelings verhoog om die breekpunt te “skip” nie: die gestoorde adres en vereiste aanpassing hang af van die trap, instruksie-enkodering en debugger-gedrag. Vergelyk `ExceptionRecord->ExceptionAddress` met die gestoorde instruksiewyser en disassembleer die grepe voordat jy die voortsetting kies.<sup>[[8]](#references)</sup> Die [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) is ’n afsonderlike voorbeeld van ’n hardware breakpoint wat ’n loader-syscall se terugkeertoestand verander.

## Bladsy-materialisering aangedryf deur foute

’n VEH kan ’n bladsyfout in ’n **lazy loader** omskep, nie net ’n sprong nie. Reserveer ’n private image-reeks met bladsye wat ongecommit bly, of gebruik guard-bladsye op gemapte bladsye waar dit ondersteun word. Indekseer, voordat die image uitgevoer word, relokasieliggings en IAT-thunks volgens hul bestemmingsbladsy. Wanneer ’n fout binne daardie reeks voorkom, commit die handler die geraakte bladsy of maak dit skryfbaar, kopieer sy seksiegreepe, pas die relokasies en imports vir daardie bladsy toe, stel die finale beskerming daarvan in en gee `EXCEPTION_CONTINUE_EXECUTION` terug. Die oorspronklike instruksie word weer probeer; moenie `Rip` verhoog soos in ’n handler wat die fout oorslaan nie. Bladsye waaraan nooit geraak word nie, hoef nie die payload in die geheue te bevat nie.<sup>[[11]](#references)</sup>

Vir ’n access violation identifiseer `ExceptionRecord->ExceptionAddress` die **instruksie** wat die fout veroorsaak het, terwyl `ExceptionInformation[1]` die adres identifiseer waartoe toegang verkry is.<sup>[[10]](#references)</sup> Gaan die exception-kode, parameterhoeveelheid en reeks van die adres waartoe toegang verkry is na voordat jy ’n bladsy materialiseer; anders kan ’n onverwante fout verkeerdelik as ’n loader-versoek beskou word.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` veroorsaak met die eerste toegang `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`), en Windows maak die guard-bit outomaties skoon. Heraktivering is dus ’n aparte stap, nie ’n deurlopende hook nie.<sup>[[12]](#references)</sup> Hou die VEH en enige metadata wat dit benodig toeganklik tydens dispatch.<sup>[[11]](#references)</sup> Op x64 moet unwind-data moontlik beskikbaar wees voor die eerste fout; die aangehaalde loader materialiseer bladsye gretig voordat dit `DllMain` aanroep om initialiseringsresies te vermy.<sup>[[11]](#references)</sup> Spoel die instruksiekas ná die skryf van kode en voordat jy dit uitvoer.<sup>[[13]](#references)</sup>

Om hierdie vloei tydens reverse engineering te herwin, stel ’n breekpunt op eerste-kans guard-page- en access-violations, inspekteer die exception-record en gee dan die gebeurtenis met `gn` aan die toepassing se handler deur.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Gebruik `!vprot` op die adres waartoe toegang verkry is om die huidige bladsybeskerming daarvan te inspekteer.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Nadat die handler die bladsy gematerialiseer het, stort sy grepe uit en vergelyk dit met die lêerbeeld.<sup>[[11]](#references)</sup> ’n `!vprot` ná die fout kan nie bewys dat die bladsy voorheen beskerm was nie, omdat guard-status eenmalig is.<sup>[[11]](#references)[[12]](#references)</sup> Beperk die exception filters of handler-breekpunte sodra die relevante beeldreeks bekend is om onverwante foute te vermy.<sup>[[16]](#references)</sup> Sien [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) vir filteropstelling.<sup>[[16]](#references)</sup>

## Trap Flag as ’n debugger-afhanklike hek

Bietjie `0x100` in `EFLAGS`/`RFLAGS` is die Trap Flag (TF). As dit gestel word, veroorsaak dit dat die volgende instruksiegrens `STATUS_SINGLE_STEP` (`0x80000004`) opwek. ’n VEH- of SEH-vertakking kan onderskei tussen ’n single-step-gebeurtenis wat aan die toepassing deurgegee word en een wat deur ’n debugger verbruik word, maar dit is ’n **heuristiek wat deur die debugger se exception-beleid beheer word**, nie betroubare bewys dat ’n debugger bestaan nie.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

As die handler net een stap wil hê, maak `0x100` in die hervatte konteks se `EFlags` skoon voordat jy voortgaan. Onderskei ook TF-gedrewe stappe van hardewarebreekpuntgebeurtenisse deur die snelleradres en ontfoutingstoestand na te gaan; albei kan as `EXCEPTION_SINGLE_STEP` verskyn.<sup>[[8]](#references)[[9]](#references)</sup> Sien [WinDbg-uitsonderingsoutomatisering](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) vir WinDbg se first-/second-chance-instellings vir `sxe`, `sxd` en `sxi`.

## References

- [1] [Check Point Research - Anti-Debug: Uitsonderings](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Foutafhandeling deur die debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Vektorgebaseerde uitsonderingshantering](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64-uitsonderingshantering](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Gebruik van 'n Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembly-instruksies](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86-argitektuur](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Foutgedrewe beeldlaaiing](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Skep van Guard Pages](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Vertoon uitsonderingsrekord)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - sx-uitsonderingsfilters](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Gaan voort wanneer uitsondering nie hanteer is nie)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
