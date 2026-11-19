# Windows Process Injection putem naziva niti i niti koje čekaju

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) prenosi bajtove u pokrenut proces bez `WriteProcessMemory`; Waiting Thread Hijacking (WTH) izvršava ih na postojećoj niti bez `SetThreadContext` i bez kreiranja udaljene niti.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Ovo su **primitivi za process injection, a ne ranjivosti za eskalaciju privilegija**: injector i dalje mora da ima pristup ciljnom procesu i niti. API-ji za opis niti zahtevaju Windows 10 verziju 1607 ili noviju.<sup>[[1]](#references)[[3]](#references)</sup> Pogledajte [Antivirus (AV) Bypass](av-bypass.md) za druge pristupe injection-u i izbegavanju detekcije.

## Thread Name-Calling: kopiranje payload-a na strani cilja

`NtSetInformationThread(ThreadNameInformation)` kopira prosleđeni `UNICODE_STRING` u prostor za skladištenje naziva niti. Poziv funkcije `GetThreadDescription` **unutar ciljnog procesa** zatim kreira heap kopiju tog naziva u korisničkom režimu. Time se prenos payload-a razdvaja od završnog kopiranja u memoriju: injector može da pročita vraćeni heap **pointer**, dok APC koji izvršava `RtlMoveMemory` unutar ciljnog procesa kopira bajtove na njihovo odredište.<sup>[[1]](#references)</sup> Originalna tehnika podržava i specijalne user APC-je; implementacija WhisperHijack umesto toga koristi običan `NtQueueApcThread` na niti koja čeka.<sup>[[1]](#references)[[3]](#references)</sup>

Za svaki blok od najviše `0xFFFE` bajtova, PoC koristi sledeći redosled. Duplirani auto-reset event signalizira završetak tek nakon što ciljni proces popuni privremeni slot; injector čeka taj signal pre nego što pročita pointer. Event potvrđuje APC koji dobavlja heap pointer, a ne naredni APC za kopiranje. PoC budi istu nit nakon što zakaže kopiranje i oslanja se na redosled APC-jeva, umesto na drugi signal za završetak.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Scratch adresa mora biti upisiva u ciljnom procesu i poznata injector-u bez prethodnog upisa na nju. Originalni PoC koristi `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack nudi i `PEB.PostProcessInitRoutine`, a podrazumevano koristi `TEB.TlsSlots[63]` (pronađen pomoću `NtQueryInformationThread(ThreadBasicInformation)`). Nije **garantovano** da je TLS slot neiskorišćen u svakom ciljnom procesu; prepisivanje aktivnog slota može da pokvari tu nit. U `Main.c` omogućite tačno jednu opciju. Provere pri kompajliranju odbacuju nedostajuće ili konfliktne PEB/TEB izbore.<sup>[[4]](#references)</sup>

Uobičajeni poziv funkcije `RtlInitUnicodeString` zaustavio bi se na ugrađenom širokom null znaku. Da bi se prenosili binarni podaci, inicijalizujte dužinu `UNICODE_STRING` pomoću bafera za dopunu iste veličine, koji ne sadrži null znakove, zamenite bajtove u njegovom polju `Buffer` stvarnim segmentom, a zatim ga prosledite funkciji `NtSetInformationThread`. Ovaj prenos zasnovan na dužini razlikuje se od direktnog prosleđivanja shellcode-a funkciji `SetThreadDescription` kao stringa sa završnim znakom.<sup>[[1]](#references)[[3]](#references)</sup>

## WTH: povratak iz čekanja u redu

Nabrojte niti pomoću `NtQuerySystemInformation(SystemProcessInformation)` i potražite one kod kojih je `ThreadState == Waiting` i `WaitReason == WrQueue`. Nit blokirana u syscall omotaču kao što je `NtWaitForWorkViaWorkerFactory` ima sačuvanu povratnu adresu pozivaoca na `[Rsp]`. Zamenom tog mesta na steku preusmerava se `ret` omotača na stub, bez menjanja `Rip` pomoću `SetThreadContext`. Stub mora da sačuva zastavice i registre, da **pozove** payload koji se vraća, da obnovi stanje, a zatim da skoči preko sačuvane originalne povratne adrese.<sup>[[2]](#references)[[3]](#references)</sup>

U x64 PoC-u, stub ima 8-bajtni slot za sačuvanu povratnu adresu na `+0x00`, instrukcije na `+0x08`, a payload na `+0x45`. U slot steka upisuje se `allocation_base + 0x08`, a ne adresa data slota. Sam `WrQueue` **nije dokaz** da se čeka na worker-factory; originalno istraživanje takođe navodi `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` kao putanju čekanja u redu. Pre nego što se oslonite na ovaj raspored, proverite stvarni stek čekanja/poziva i da je `[Rsp]` očekivani slot povratne adrese.<sup>[[2]](#references)[[3]](#references)</sup>

## Kombinovanje TNC-a i WTH-a bez upisa između procesa

WhisperHijack demonstrira kombinovani tok rada nad postojećim nativnim x64 procesom. Njegov Writer bira potencijalni proces/nit, dok Flipper child nasleđuje handle-ove potrebne za završnu predaju. Handle procesa zahteva `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **a ne** `PROCESS_VM_WRITE`; ipak, trenutni PoC otvara nit sa `THREAD_ALL_ACCESS`. Provere pristupa i dalje se primenjuju, kao i ublažavanja rizika procesa.<sup>[[3]](#references)[[4]](#references)</sup>

Kombinovani PoC koristi sledeći redosled; APC-ovi za kopiranje memorije izvršavaju se u ciljnom procesu, a ne preko handle-a sa pravima za udaljeni upis.<sup>[[4]](#references)</sup>

1. Rezervišite slobodne blokove poravnate na 64 KB u ciljnom procesu, a zatim potvrdite njihove stranice od 4 KB kao `PAGE_READWRITE`. PoC ispituje fiksne adrese kandidata pomoću `NtQueryVirtualMemory`; te adrese su implementacioni izbori, a ne zahtev TNC-a ili WTH-a.
2. Sastavite `[0x45-bajtni WTH stub][povratni x64 payload][8-bajtni pokazivač na ulaznu tačku stuba]`, gde je poslednji pokazivač `allocation_base + 0x08`. Isporučite ovaj bafer pomoću TNC petlje za segmente.
3. U Flipper-u pribavite `Rsp` niti koja čeka pomoću `NtGetContextThread(CONTEXT_CONTROL)`. Zakažite APC funkcije `RtlMoveMemory` u ciljnom procesu, da biste kopirali originalnu 8-bajtnu vrednost sa `[Rsp]` u data slot stuba.
4. Pomoću `NtProtectVirtualMemory` promenite region u izvršiv. Ovaj PoC bira `PAGE_EXECUTE_READWRITE` zato što se njegov polimorfni payload sam dekodira; WTH sam po sebi ne zahteva payload koji menja sopstveni kod.
5. Zakažite još jedan APC funkcije `RtlMoveMemory` u ciljnom procesu da biste kopirali **unapred postavljeni pokazivač na završni deo** u `[Rsp]`, a zatim pozovite `NtAlertThread`. FIFO redosled APC-ova čuva originalnu povratnu adresu pre nego što je zameni; povratak omotača ulazi u stub i, nakon povratka payloada, nastavlja izvršavanje originalnog pozivaoca.

Odsustvo funkcije `NtWriteVirtualMemory` **ne** znači da nema upisa u ciljni proces: funkcije `GetThreadDescription` i `RtlMoveMemory` obavljaju ih unutar ciljnog procesa.<sup>[[1]](#references)[[3]](#references)</sup> Isporuka običnog user APC-a takođe zavisi od toga da li izabrana nit obrađuje svoj APC red; snimak stanja `WrQueue` i poziv funkcije za alert ne garantuju opšte ni trenutno izvršavanje.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Primer izbegava kreiranje udaljene niti, njeno suspendovanje i direktnu zamenu konteksta, ali je i dalje uočljiv kroz APC-ove i promenu zaštite.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Pozivanje imena niti (Thread Name-Calling)](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Otimanje niti u čekanju (Waiting Thread Hijacking)](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC i README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – Implementacija WhisperHijack Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
