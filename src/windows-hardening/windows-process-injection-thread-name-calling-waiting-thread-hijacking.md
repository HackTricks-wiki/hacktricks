# Windows Process Injection via Thread Names and Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) dra grepe oor na ’n lopende proses sonder `WriteProcessMemory`; Waiting Thread Hijacking (WTH) voer dit op ’n bestaande thread uit sonder `SetThreadContext` of om ’n afgeleë thread te skep.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Dit is **process-injection-primitiewe, nie kwesbaarhede vir voorregte-eskalasie nie**: die injector benodig steeds toegang tot die teikenproses en -thread. Die thread-beskrywing-API’s vereis Windows 10 version 1607 of later.<sup>[[1]](#references)[[3]](#references)</sup> Sien [Antivirus (AV) Bypass](av-bypass.md) vir ander injection- en ontduikingsbenaderings.

## Thread Name-Calling: payload-kopiëring aan die teikenkant

`NtSetInformationThread(ThreadNameInformation)` kopieer ’n verskafde `UNICODE_STRING` na die thread-naamberging. Deur `GetThreadDescription` **binne die teiken** aan te roep, word dan ’n user-mode heap-kopie van daardie naam geskep. Dit skei payload-oordrag van die finale geheuekopie: die injector kan die teruggekeerde heap-**wyser** lees, terwyl ’n APC wat `RtlMoveMemory` binne die teiken uitvoer, die grepe na hul bestemming kopieer.<sup>[[1]](#references)</sup> Die oorspronklike tegniek ondersteun ook spesiale user APC’s; die WhisperHijack-implementering gebruik eerder gewone `NtQueueApcThread` op ’n wagtende thread.<sup>[[1]](#references)[[3]](#references)</sup>

Vir elke stuk van hoogstens `0xFFFE` grepe gebruik die PoC hierdie volgorde. ’n Gedupliseerde auto-reset-gebeurtenis dui voltooiing aan eers nadat die teiken die tydelike gleuf gevul het; die injector wag vir daardie sein voordat die wyser gelees word. Die gebeurtenis bevestig die heap-wyser-APC, nie die daaropvolgende kopieer-APC nie. Die PoC maak dieselfde thread wakker nadat die kopieer-APC in die tou geplaas is en maak op APC-volgorde staat, eerder as op ’n tweede voltooiingsein.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Die scratch-adres moet skryfbaar in die teiken wees en aan die injector bekend wees sonder dat dit eers geskryf hoef te word. Die oorspronklike PoC gebruik `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack bied ook `PEB.PostProcessInitRoutine` en gebruik by verstek `TEB.TlsSlots[63]` (opgespoor met `NtQueryInformationThread(ThreadBasicInformation)`). Die TLS-slot is **nie gewaarborg ongebruik te wees** in elke teiken nie; die oorskryf van ’n aktiewe slot kan daardie thread breek. Aktiveer presies een opsie in `Main.c`. Die compile-time-kontroles verwerp ontbrekende of botsende PEB/TEB-keuses.<sup>[[4]](#references)</sup>

’n Gewone `RtlInitUnicodeString`-aanroep sal by ’n ingebedde wye nul stop. Om binêre data oor te dra, inisialiseer die `UNICODE_STRING`-lengte met ’n ewe groot, nie-nul-opvulbuffer, vervang dan sy `Buffer`-grepe met die werklike chunk en gee dit daarna aan `NtSetInformationThread` deur. Hierdie lengtegebaseerde oordrag verskil van die direkte deurgee van die shellcode aan `SetThreadDescription` as ’n nulbeëindigde string.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: terugkeer vanaf ’n tou-wag

Enumerateer threads met `NtQuerySystemInformation(SystemProcessInformation)` en soek na `ThreadState == Waiting` met `WaitReason == WrQueue`. ’n Thread wat in ’n syscall-wrapper soos `NtWaitForWorkViaWorkerFactory` geblokkeer is, het ’n gestoorde caller-terugkeeradres by `[Rsp]`. Deur daardie stack-gleuf te vervang, word die wrapper se `ret` na ’n stub herlei sonder om `Rip` via `SetThreadContext` te verander. Die stub moet vlae en registers stoor, ’n payload **aanroep** wat terugkeer, die toestand herstel en dan deur die gestoorde oorspronklike terugkeeradres spring.<sup>[[2]](#references)[[3]](#references)</sup>

In die x64 PoC het die stub ’n 8-greep gestoorde-terugkeer-gleuf by `+0x00`, instruksies by `+0x08` en die payload by `+0x45`. Die stack-gleuf kry `allocation_base + 0x08`, nie die adres van die data-gleuf nie. `WrQueue` alleen is **nie bewys** van ’n worker-factory-wag nie: die oorspronklike navorsing identifiseer ook `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` as ’n tou-wag-pad. Gaan die werklike wag-/aanroepstack na, en bevestig dat `[Rsp]` die bedoelde terugkeer-gleuf is voordat jy op hierdie uitleg staatmaak.<sup>[[2]](#references)[[3]](#references)</sup>

## Kombineer TNC en WTH sonder skryfbewerkings oor prosesse heen

WhisperHijack demonstreer die gekombineerde werkvloei teen ’n bestaande native x64-proses. Sy Writer kies ’n kandidaatproses/-thread, terwyl ’n Flipper-child die handvatsels erf wat vir die finale oorhandiging nodig is. Die proseshandvatsel versoek `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **nie** `PROCESS_VM_WRITE` nie; die huidige PoC maak nietemin die thread met `THREAD_ALL_ACCESS` oop. Toegangsbeheer en prosesversagtings is steeds van toepassing.<sup>[[3]](#references)[[4]](#references)</sup>

Die gekombineerde PoC gebruik die volgende volgorde; die geheuekopie-APC’s word in die teiken uitgevoer, nie deur ’n handvatsel met afgeleë-skryfregte nie.<sup>[[4]](#references)</sup>

1. Reserveer 64-KB-belynde vrye blokke in die teiken, en commit dan hul 4-KB-bladsye as `PAGE_READWRITE`. Die PoC toets vaste kandidaatadresse met `NtQueryVirtualMemory`; hierdie adresse is implementasiekeuses, nie ’n vereiste van TNC of WTH nie.
2. Stel `[0x45-byte WTH stub][returning x64 payload][8-byte stub-entry pointer]` saam, waar die finale pointer `allocation_base + 0x08` is. Lewer hierdie buffer met die TNC-chunk-lus af.
3. Kry in die Flipper die wagthread se `Rsp` met `NtGetContextThread(CONTEXT_CONTROL)`. Plaas ’n `RtlMoveMemory`-APC in die teiken om die oorspronklike 8-greep-waarde by `[Rsp]` na die stub se data-gleuf te kopieer.
4. Verander die opgevoerde streek na uitvoerbaar met `NtProtectVirtualMemory`. Hierdie PoC kies `PAGE_EXECUTE_READWRITE` omdat sy polimorfiese payload homself dekodeer; WTH vereis nie op sigself ’n selfmodifiserende payload nie.
5. Plaas nog ’n `RtlMoveMemory`-APC in die teiken om die **vooraf opgevoerde stert-pointer** na `[Rsp]` te kopieer, en roep dan `NtAlertThread` aan. FIFO-APC-volgorde stoor die oorspronklike terugkeeradres voordat dit vervang word; die wrapper se terugkeer betree die stub en hervat, nadat die payload terugkeer, die oorspronklike caller.

Die afwesigheid van `NtWriteVirtualMemory` beteken **nie** dat daar geen skryfbewerkings in die teiken is nie: `GetThreadDescription` en `RtlMoveMemory` voer dit binne die teiken uit.<sup>[[1]](#references)[[3]](#references)</sup> Gewone user-APC-aflewering hang ook daarvan af dat die gekose thread sy APC-tou verwerk; ’n `WrQueue`-momentopname en ’n alert waarborg nie onmiddellike uitvoering in die algemeen nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Die voorbeeld vermy die skep van afgeleë threads, opskorting en direkte konteksvervanging, maar bly waarneembaar deur sy APC’s en beskermingsoorgang.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC en README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – WhisperHijack Main.c-implementering](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
