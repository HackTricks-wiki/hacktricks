# Windows kontrolni tok zasnovan na izuzecima i anti-debugging

{{#include ../banners/hacktricks-training.md}}

Zaštićeni Windows program može da koristi namerni izuzetak kao grananje: instrukcija koja izaziva grešku samo je ulazna tačka u handler koji bira sledeću adresu korisničkog koda. Time se skrivaju grane od linearne disasemblacije, a sledeći korak prepušta se dispečovanju izuzetaka.<sup>[[1]](#references)</sup>

## Dispečovanje je važno

Debugger priključen procesu prima izuzetak **first-chance** pre handlera aplikacije. Ako ga prosledi kao neobrađen, Windows pretražuje handlere procesa; izuzetak za koji ne postoji handler vraća se debuggeru kao **last-chance**. Zato debugger koji obradi breakpoint ili single-step događaj može da promeni to da li će se handler programa izvršiti.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registruje VEH za ceo proces na početku vectored liste. Pokreće se pre frame-based SEH-a, ali kasnija registracija sa najvišim prioritetom može da postavi drugi handler ispred njega. Vraćanje vrednosti `EXCEPTION_CONTINUE_SEARCH` prepušta izuzetak drugim handlerima; `EXCEPTION_CONTINUE_EXECUTION` nastavlja izvršavanje iz sačuvanog `CONTEXT`-a, uključujući sve izmene registara koje je handler napravio.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klasični x86 SEH koristi registracije povezane preko steka, koje `!exchain` može da pregleda. Nativni x64 koristi unose `RUNTIME_FUNCTION` u `.pdata`, sa unwind podacima u `.xdata`, a ne taj x86 lanac. Nemojte primenjivati [x86 SEH workflow za prepisivanje](../binary-exploitation/stack-overflow/windows-seh-overflow.md) na nativni x64 proces.<sup>[[5]](#references)[[6]](#references)</sup>

## Pretvorite grešku u granu kontrolnog toka

Na primer, delilac jednak nuli može namerno da izazove `EXCEPTION_INT_DIVIDE_BY_ZERO`, umesto da predstavlja grešku u programu. Handler mora da prepozna izuzetak i adresu greške, a zatim da postavi `ContextRecord->Rip` (ili `Eip` na x86) na važeću adresu nastavka pre nego što vrati `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Jezgro handler-a ispod pretpostavlja da su `fault_site` i `continuation` poznate adrese u istom kontekstu kontrolnog toka. Prava implementacija mora da sačuva očekivani stek i registre i ne sme da nastavi izvršavanje od iste instrukcije koja je izazvala grešku, jer će u suprotnom ponovo doći do greške.<sup>[[7]](#references)</sup>

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

Isti mehanizam može da obradi namerni `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) i preusmeri izvršavanje. **Nemojte** naslepo da uvećavate `Rip` da biste „preskočili prekidnu tačku“: sačuvana adresa i potrebno pomeranje zavise od zamke, kodiranja instrukcije i ponašanja debagera. Uporedite `ExceptionRecord->ExceptionAddress` sa sačuvanim pokazivačem na instrukciju i disasemblirajte bajtove pre nego što izaberete nastavak.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) je zaseban primer hardverske prekidne tačke koja menja povratno stanje sistemskog poziva loader-a.

## Materijalizacija stranica usled greške

VEH može da pretvori page fault u **lazy loader**, a ne samo u skok. Rezervišite privatni opseg slike sa stranicama koje nisu commit-ovane ili, gde je podržano, koristite mapirane stranice sa zaštitom. Pre pokretanja slike, indeksirajte lokacije relokacija i IAT thunk-ove prema odredišnoj stranici. Pri grešci unutar tog opsega, rukovalac commit-uje pogođenu stranicu ili joj omogućava upis, kopira bajtove njene sekcije, primenjuje relokacije i importe za tu stranicu, postavlja njenu konačnu zaštitu i vraća `EXCEPTION_CONTINUE_EXECUTION`. Izvorna instrukcija se ponovo izvršava; **nemojte** pomerati `Rip` kao kod rukovaoca koji preskače grešku. Stranice koje nikada nisu dodirnute ne moraju da sadrže payload u memoriji.<sup>[[11]](#references)</sup>

Kod access violation-a, `ExceptionRecord->ExceptionAddress` označava **instrukciju** koja je izazvala grešku, dok `ExceptionInformation[1]` označava adresu kojoj se pristupalo.<sup>[[10]](#references)</sup> Proverite kôd izuzetka, broj parametara i opseg adresa kojima se pristupalo pre materijalizacije stranice; u suprotnom, nepovezana greška može biti pogrešno protumačena kao zahtev loader-a.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` pri prvom pristupu izaziva `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`), a Windows automatski uklanja bit zaštite, pa je ponovno postavljanje zaštite poseban korak, a ne neprekidna kuka.<sup>[[12]](#references)</sup> Obezbedite da VEH i svi metapodaci koji su mu potrebni budu dostupni tokom obrade.<sup>[[11]](#references)</sup> Na x64, unwind podaci možda moraju biti dostupni pre prve greške; loader naveden u izvoru unapred materijalizuje stranice pre pozivanja `DllMain` da bi izbegao trke tokom inicijalizacije.<sup>[[11]](#references)</sup> Ispraznite keš instrukcija nakon upisivanja koda, a pre njegovog izvršavanja.<sup>[[13]](#references)</sup>

Da biste rekonstruisali ovaj tok tokom reverznog inženjerstva, postavite prekid na first-chance guard-page violations i access violations, pregledajte zapis izuzetka, a zatim prosledite događaj rukovaocu aplikacije pomoću `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Upotrebite `!vprot` nad adresom kojoj se pristupalo da biste pregledali trenutnu zaštitu njene stranice.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Nakon što rukovalac materijalizuje stranicu, izbacite njene bajtove i uporedite ih sa slikom datoteke.<sup>[[11]](#references)</sup> Naknadni `!vprot` ne može da dokaže da je stranica prethodno bila zaštićena, jer je stanje zaštite jednokratno.<sup>[[11]](#references)[[12]](#references)</sup> Sužavajte filtere izuzetaka ili tačke prekida rukovaoca kada saznate relevantni opseg slike kako biste izbegli nepovezane greške.<sup>[[16]](#references)</sup> Pogledajte [automatizaciju izuzetaka u WinDbg-u](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) za podešavanje filtera.<sup>[[16]](#references)</sup>

## Trap Flag kao mehanizam kontrole zavisan od debuggera

Bit `0x100` u `EFLAGS`/`RFLAGS` je Trap Flag (TF). Njegovo postavljanje izaziva `STATUS_SINGLE_STEP` (`0x80000004`) na sledećoj granici instrukcije. Grana VEH ili SEH može da razlikuje događaj single-step koji je prosleđen aplikaciji od onog koji je obradio debugger, ali to je **heuristika kojom upravlja pravilo za izuzetke u debuggeru**, a ne pouzdan dokaz da debugger postoji.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Ako handler želi samo jedan korak, obrišite `0x100` u polju `EFlags` konteksta koji se nastavlja, pa nastavite. Takođe razlikujte korake pokrenute pomoću TF-a od događaja hardverskih breakpointova proverom adrese okidača i stanja za otklanjanje grešaka; oba se mogu pojaviti kao `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Za WinDbg `sxe`, `sxd` i `sxi` postavke za first-/second-chance izuzetke pogledajte [automatizaciju izuzetaka u WinDbg-u](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Izuzeci](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Obrada izuzetaka u debugger-u](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Obrada vektorskih izuzetaka](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Obrada izuzetaka x64 arhitekture](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Korišćenje obrađivača vektorskih izuzetaka](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembler instrukcije](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 arhitektura](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Učitavanje slike pokrenuto greškom](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Kreiranje zaštitnih stranica](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Prikaz zapisa izuzetka)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - sx filteri izuzetaka](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Nastavak nakon neobrađenog izuzetka)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
