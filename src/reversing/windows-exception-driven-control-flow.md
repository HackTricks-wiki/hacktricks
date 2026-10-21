# Kontrolni tok zasnovan na Windows izuzecima i anti-debugging

{{#include ../banners/hacktricks-training.md}}

Zaštićeni Windows program može da koristi namerni izuzetak kao grananje: instrukcija koja izaziva grešku samo je ulazna tačka za handler koji bira sledeću adresu korisničkog koda. Time se skrivaju grane od linearne disasemblacije, a sledeći korak premešta u obradu izuzetaka.<sup>[[1]](#references)</sup>

## Obrada izuzetaka je važna

Debugger priključen procesu prima izuzetak **prve šanse** pre handlera aplikacije. Ako ga prosledi kao neobrađen, Windows pretražuje handlere procesa; izuzetak za koji ne postoji handler vraća se debuggeru kao izuzetak **poslednje šanse**. Zato debugger koji obradi događaj breakpointa ili pojedinačnog koraka može da promeni to da li će se pokrenuti handler programa.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registruje VEH za ceo proces na početku liste vectored handlera. Pokreće se pre SEH-a zasnovanog na steku, ali kasnija registracija sa najvišim prioritetom može da postavi drugi handler ispred njega. Vraćanje vrednosti `EXCEPTION_CONTINUE_SEARCH` prepušta izuzetak drugim handlerima; `EXCEPTION_CONTINUE_EXECUTION` nastavlja izvršavanje iz sačuvanog `CONTEXT`-a, uključujući sve izmene registara koje je handler izvršio.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klasični x86 SEH koristi registracije povezane u steku, koje `!exchain` može da pregleda. Nativni x64 koristi stavke `RUNTIME_FUNCTION` u `.pdata` sa unwind podacima u `.xdata`, a ne taj x86 lanac. Nemojte primenjivati [x86 SEH workflow za prepisivanje](../binary-exploitation/stack-overflow/windows-seh-overflow.md) na nativni x64 proces.<sup>[[5]](#references)[[6]](#references)</sup>

## Pretvaranje greške u granu kontrolnog toka

Na primer, deljenje nulom može namerno da izazove `EXCEPTION_INT_DIVIDE_BY_ZERO`, umesto da predstavlja grešku u programu. Handler mora da prepozna izuzetak i adresu instrukcije koja ga je izazvala, a zatim da postavi `ContextRecord->Rip` (ili `Eip` na x86) na važeću adresu za nastavak pre nego što vrati `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Jezgro rukovaoca ispod pretpostavlja da su `fault_site` i `continuation` poznate adrese u istom kontekstu toka izvršavanja. Stvarna implementacija mora da sačuva očekivani stek i registre, i ne sme da nastavi izvršavanje od iste instrukcije koja je izazvala grešku, jer će se greška ponoviti.<sup>[[7]](#references)</sup>

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

Isti mehanizam može da obradi namerni `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) i preusmeri izvršavanje. **Nemojte** naslepo uvećavati `Rip` da biste „preskočili breakpoint“: sačuvana adresa i potrebno pomeranje zavise od trap-a, kodiranja instrukcije i ponašanja debugger-a. Uporedite `ExceptionRecord->ExceptionAddress` sa sačuvanim instruction pointer-om i disasemblirajte bajtove pre nego što izaberete nastavak.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) je zaseban primer hardware-breakpoint-a koji menja povratno stanje loader syscall-a.

## Trap Flag kao kapija zavisna od debugger-a

Bit `0x100` u `EFLAGS`/`RFLAGS` je Trap Flag (TF). Njegovo postavljanje izaziva `STATUS_SINGLE_STEP` (`0x80000004`) na granici sledeće instrukcije. Grana u VEH-u ili SEH-u može da razlikuje single-step događaj prosleđen aplikaciji od onog koji je obradio debugger, ali to je **heuristika kontrolisana pravilima obrade izuzetaka u debugger-u**, a ne pouzdan dokaz da debugger postoji.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Ako handler želi samo jedan korak, obrišite `0x100` u polju `EFlags` konteksta koji se nastavlja pre nego što nastavite. Takođe razlikujte korake pokrenute pomoću TF-a od događaja hardverskih breakpoint-a tako što ćete proveriti adresu koja je izazvala događaj i stanje za debugging; oba mogu da se pojave kao `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Za podešavanja za prvi i drugi prolaz u WinDbg komandama `sxe`, `sxd` i `sxi`, pogledajte [automatizaciju izuzetaka u WinDbg-u](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Izuzeci](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Obrada izuzetaka u debuggeru](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Obrada vektorskih izuzetaka](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Obrada izuzetaka na x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Korišćenje vektorskog handlera za izuzetke](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembler instrukcije](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Arhitektura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
