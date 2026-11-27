# Mtiririko wa Udhibiti wa Windows Unaotegemea Exception na Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Programu ya Windows iliyolindwa inaweza kutumia exception ya makusudi kama tawi: instruction inayosababisha fault ni mwanzo tu wa handler inayochagua anwani inayofuata ya user-code. Hii huficha edges kwenye linear disassembly na kuhamishia hatua inayofuata kwenye exception dispatch.<sup>[[1]](#references)</sup>

## Dispatch ni muhimu

Debugger iliyounganishwa na process hupokea exception ya **first-chance** kabla ya application handlers. Ikiipitisha event kama haijashughulikiwa, Windows hutafuta handlers za process; exception isiyo na handler hurudi kwa debugger kama **last-chance**. Kwa hiyo, debugger inayotumia breakpoint au tukio la single-step inaweza kubadilisha iwapo handler ya programu itaendeshwa.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` husajili VEH ya process nzima mwanzoni mwa orodha ya vectored. Huendeshwa kabla ya SEH inayotegemea frame, lakini usajili mwingine wa baadaye wenye kipaumbele cha kwanza unaweza kuiweka handler nyingine mbele yake. Kurejesha `EXCEPTION_CONTINUE_SEARCH` huacha exception kwa handlers nyingine; `EXCEPTION_CONTINUE_EXECUTION` huendelea kutoka kwenye `CONTEXT` iliyohifadhiwa, ikijumuisha mabadiliko yoyote ya register yaliyofanywa na handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

x86 SEH ya kawaida hutumia registrations zilizounganishwa kwenye stack, ambazo `!exchain` inaweza kukagua. x64 ya asili hutumia entries za `RUNTIME_FUNCTION` kwenye `.pdata` zenye unwind data kwenye `.xdata`, badala ya chain hiyo ya x86. Usitumie [x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md) kwenye process ya x64 ya asili.<sup>[[5]](#references)[[6]](#references)</sup>

## Geuza fault kuwa edge ya mtiririko wa udhibiti

Kwa mfano, divisor ya sifuri inaweza kusababisha kwa makusudi `EXCEPTION_INT_DIVIDE_BY_ZERO` badala ya kuwakilisha bug. Handler lazima itambue exception na anwani ya fault, kisha iweke `ContextRecord->Rip` (au `Eip` kwenye x86) kwenye continuation halali kabla ya kurejesha `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Kiini cha handler hapa chini kinachukulia kuwa `fault_site` na `continuation` ni anwani zinazojulikana katika muktadha uleule wa control-flow. Utekelezaji halisi lazima uhifadhi stack na registers zinazotarajiwa, na usiendelee tena kutoka kwenye instruction ileile iliyosababisha fault, la sivyo fault itatokea tena.<sup>[[7]](#references)</sup>

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

Utaratibu huohuo unaweza kushughulikia `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) iliyowekwa kimakusudi na kuelekeza upya utekelezaji. **Usiongeze `Rip` bila kufikiri ili “kuruka breakpoint”:** anwani iliyohifadhiwa na marekebisho yanayohitajika hutegemea trap, usimbaji wa maagizo na tabia ya debugger. Linganisha `ExceptionRecord->ExceptionAddress` na instruction pointer iliyohifadhiwa, kisha disassemble baiti kabla ya kuchagua mahali pa kuendelea.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) ni mfano tofauti wa hardware-breakpoint unaobadilisha hali ya kurudi ya syscall ya loader.

## Uundaji wa kurasa unaochochewa na hitilafu

VEH inaweza kubadilisha page fault kuwa **lazy loader**, badala ya kuruka tu. Hifadhi eneo la image la faragha lenye kurasa ambazo hazijawekwa kwenye commit, au tumia kurasa zilizomapped zenye guard pale inapowezekana. Kabla ya kuendesha image, orodhesha maeneo ya relocation na IAT thunks kulingana na ukurasa zinakoelekezwa. Hitilafu ikitokea ndani ya eneo hilo, handler huweka ukurasa uliofikiwa kwenye commit au kuufanya uweze kuandikwa, kunakili baiti za sehemu yake, kutumia relocations na imports za ukurasa huo, kuweka protection yake ya mwisho, kisha kurudisha `EXCEPTION_CONTINUE_EXECUTION`. Agizo la awali hujaribiwa tena; **usisogeze `Rip`** kama unavyofanya kwenye handler ya kuruka fault. Kurasa ambazo hazijafikiwa hazihitaji kuwa na payload kwenye memory.<sup>[[11]](#references)</sup>

Kwa access violation, `ExceptionRecord->ExceptionAddress` hubainisha **agizo** lililosababisha hitilafu, ilhali `ExceptionInformation[1]` hubainisha anwani iliyofikiwa.<sup>[[10]](#references)</sup> Kagua exception code, idadi ya vigezo na masafa ya anwani iliyofikiwa kabla ya kuunda ukurasa; vinginevyo, fault isiyohusiana inaweza kudhaniwa kimakosa kuwa ombi la loader.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` husababisha `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) inapofikiwa kwa mara ya kwanza, na Windows huondoa kiotomatiki biti ya guard; kwa hiyo, kuiwasha tena ni hatua tofauti, si hook ya kudumu.<sup>[[12]](#references)</sup> Hakikisha VEH na metadata yoyote inayohitaji zinapatikana wakati wa dispatch.<sup>[[11]](#references)</sup> Kwenye x64, huenda data ya unwind ikahitaji kupatikana kabla ya fault ya kwanza; loader iliyotajwa huunda kurasa zote mapema kabla ya kuita `DllMain` ili kuepuka race conditions za uanzishaji.<sup>[[11]](#references)</sup> Safisha instruction cache baada ya kuandika code na kabla ya kuitekeleza.<sup>[[13]](#references)</sup>

Ili kufuatilia mtiririko huu wakati wa reversing, weka breakpoint kwenye ukiukaji wa guard-page na access violation za first-chance, kagua exception record, kisha peleka tukio kwa handler ya programu kwa kutumia `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Tumia `!vprot` kwenye anwani iliyofikiwa ili kukagua protection ya ukurasa wake ya sasa.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Baada ya handler kuunda page kwenye memory, hifadhi bytes zake na uzilinganishe na file image.<sup>[[11]](#references)</sup> `!vprot` inayoendeshwa baada ya fault haiwezi kuthibitisha kuwa page ilikuwa guarded hapo awali, kwa sababu hali ya guard hutumika mara moja tu.<sup>[[11]](#references)[[12]](#references)</sup> Baada ya kujua range husika ya image, weka exception filters au handler breakpoints kwa mipaka finyu zaidi ili kuepuka faults zisizohusiana.<sup>[[16]](#references)</sup> Tazama [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) kwa usanidi wa filter.<sup>[[16]](#references)</sup>

## Trap Flag kama kizuizi kinachotegemea debugger

Bit `0x100` katika `EFLAGS`/`RFLAGS` ni Trap Flag (TF). Kuiweka husababisha mpaka wa instruction unaofuata kuibua `STATUS_SINGLE_STEP` (`0x80000004`). Tawi la VEH au SEH linaweza kutofautisha tukio la single-step lililowasilishwa kwa application na lile lililotumiwa na debugger, lakini huu ni **utaratibu wa kukisia unaodhibitiwa na sera ya debugger kuhusu exceptions**, si uthibitisho wa kuaminika kwamba debugger ipo.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Ikiwa handler inataka hatua moja tu, futa `0x100` katika `EFlags` ya context iliyorejeshwa kabla ya kuendelea. Pia tofautisha hatua zinazoendeshwa na TF na matukio ya hardware-breakpoint kwa kukagua anwani iliyochochea tukio na hali ya debug; yote mawili yanaweza kuonekana kama `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Kwa mipangilio ya first-/second-chance ya `sxe`, `sxd`, na `sxi` katika WinDbg, angalia [Uendeshaji wa kiotomatiki wa exceptions katika WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Kushughulikia Exceptions katika Debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Kushughulikia Exceptions kwa Vectored](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Kushughulikia exceptions za x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Kutumia Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembly Instructions](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Usanifu wa x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Kupakia image kunakoendeshwa na hitilafu](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Kuunda Guard Pages](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Kuonyesha Rekodi ya Exception)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - Vichujio vya exceptions vya sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Kuendelea huku Exception Haijashughulikiwa)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
