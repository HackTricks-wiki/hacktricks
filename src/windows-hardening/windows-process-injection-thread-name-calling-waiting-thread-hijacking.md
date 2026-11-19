# Windows Process Injection kupitia Thread Names na Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) huhamisha bytes hadi kwenye process inayoendesha bila kutumia `WriteProcessMemory`; Waiting Thread Hijacking (WTH) huzitekeleza kwenye thread iliyopo bila kutumia `SetThreadContext` au kuunda remote thread.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Hizi ni **process-injection primitives, si udhaifu wa privilege-escalation**: injector bado inahitaji ufikiaji wa process na thread lengwa. APIs za maelezo ya thread zinahitaji Windows 10 version 1607 au matoleo ya baadaye.<sup>[[1]](#references)[[3]](#references)</sup> Tazama [Antivirus (AV) Bypass](av-bypass.md) kwa mbinu nyingine za injection na evasion.

## Thread Name-Calling: kunakili payload upande wa target

`NtSetInformationThread(ThreadNameInformation)` hunakili `UNICODE_STRING` iliyotolewa kwenye hifadhi ya jina la thread. Kuita `GetThreadDescription` **ndani ya target** kisha huunda nakala ya jina kwenye user-mode heap. Hii hutenganisha uhamishaji wa payload na unakili wa mwisho wa memory: injector inaweza kusoma **pointer** ya heap inayorejeshwa, huku APC inayoendesha `RtlMoveMemory` ndani ya target ikinakili bytes hadi kwenye eneo lengwa.<sup>[[1]](#references)</sup> Mbinu ya awali pia hutumia special user APCs; utekelezaji wa WhisperHijack badala yake hutumia `NtQueueApcThread` ya kawaida kwenye thread inayosubiri.<sup>[[1]](#references)[[3]](#references)</sup>

Kwa kila chunk yenye ukubwa usiozidi `0xFFFE` bytes, PoC hutumia mpangilio huu. Event ya auto-reset iliyorudiwa huashiria kukamilika baada tu ya target kujaza nafasi ya scratch; injector husubiri ishara hiyo kabla ya kusoma pointer. Event hii huthibitisha kupokelewa kwa heap-pointer APC, si APC ya kunakili inayofuata. PoC huamsha thread hiyohiyo baada ya kupanga APC ya kunakili, na hutegemea mpangilio wa APC badala ya ishara ya pili ya kukamilika.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Anwani ya scratch lazima iwe writable katika target na ijulikane kwa injector bila kuiandikia kwanza. PoC ya awali hutumia `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack pia hutoa `PEB.PostProcessInitRoutine` na kwa chaguo-msingi hutumia `TEB.TlsSlots[63]` (inayopatikana kwa `NtQueryInformationThread(ThreadBasicInformation)`). Hakuna **uhakikisho** kwamba TLS slot haitumiki katika kila target; kubadilisha slot inayotumika kunaweza kuharibu thread hiyo. Wezesha chaguo moja tu katika `Main.c`. Ukaguzi wa wakati wa compile hukataa uteuzi wa PEB/TEB unaokosekana au unaokinzana.<sup>[[4]](#references)</sup>

`RtlInitUnicodeString` ya kawaida husimama inapokutana na null ya wide iliyo ndani ya data. Ili kubeba data ya binary, anzisha urefu wa `UNICODE_STRING` kwa kutumia buffer ya padding isiyo na null yenye ukubwa sawa, badilisha byte za `Buffer` yake ziwe chunk halisi, kisha ipitishe kwa `NtSetInformationThread`. Uhamisho huu unaotegemea urefu ni tofauti na kupitisha shellcode moja kwa moja kwa `SetThreadDescription` kama string iliyokamilishwa.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: kurudi kutoka kwenye kusubiri kwa queue

Orodhesha threads kwa `NtQuerySystemInformation(SystemProcessInformation)` na utafute `ThreadState == Waiting` pamoja na `WaitReason == WrQueue`. Thread iliyozuiwa kwenye syscall wrapper kama `NtWaitForWorkViaWorkerFactory` huwa na anwani ya kurudi ya caller iliyohifadhiwa kwenye `[Rsp]`. Kubadilisha nafasi hiyo ya stack huelekeza `ret` ya wrapper kwenye stub bila kubadilisha `Rip` kupitia `SetThreadContext`. Stub lazima ihifadhi flags na registers, **iite** payload inayorudi, irejeshe hali ya awali, kisha iruke kupitia anwani ya awali ya kurudi iliyohifadhiwa.<sup>[[2]](#references)[[3]](#references)</sup>

Katika PoC ya x64, stub ina nafasi ya kuhifadhi anwani ya kurudi ya baiti 8 kwenye `+0x00`, maelekezo kwenye `+0x08`, na payload kwenye `+0x45`. Nafasi ya stack hupokea `allocation_base + 0x08`, si anwani ya data slot. `WrQueue` pekee **haithibitishi** kusubiri kwa worker-factory: utafiti wa awali pia unabainisha `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` kama njia ya kusubiri queue. Kagua wait/call stack halisi na uhakikishe kwamba `[Rsp]` ndiyo nafasi iliyokusudiwa ya kurudi kabla ya kutegemea mpangilio huu.<sup>[[2]](#references)[[3]](#references)</sup>

## Kuunganisha TNC na WTH bila kuandika kwenye mchakato mwingine

WhisperHijack huonyesha mtiririko wa kazi uliounganishwa dhidi ya mchakato wa x64 native uliopo. Writer huchagua mchakato/thread mgombea, huku child ya Flipper ikirithi handles zinazohitajika kwa makabidhiano ya mwisho. Handle ya mchakato huomba `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **si** `PROCESS_VM_WRITE`; hata hivyo, PoC ya sasa hufungua thread kwa `THREAD_ALL_ACCESS`. Ukaguzi wa access na process mitigations bado hutumika.<sup>[[3]](#references)[[4]](#references)</sup>

PoC iliyounganishwa hutumia mfuatano huu; memory copy APCs hutekelezwa ndani ya target badala ya kupitia handle yenye haki za remote-write.<sup>[[4]](#references)</sup>

1. Hifadhi blocks huru zilizopangiliwa kwa mipaka ya 64-KB katika target, kisha commit kurasa zake za 4-KB kama `PAGE_READWRITE`. PoC hukagua anwani maalum za wagombea kwa `NtQueryVirtualMemory`; anwani hizi ni chaguo za utekelezaji, si sharti la TNC au WTH.
2. Kusanya `[0x45-byte WTH stub][returning x64 payload][8-byte stub-entry pointer]`, ambapo pointer ya mwisho ni `allocation_base + 0x08`. Peleka buffer hii kwa kutumia mzunguko wa TNC chunk.
3. Katika Flipper, pata `Rsp` ya thread inayosubiri kwa `NtGetContextThread(CONTEXT_CONTROL)`. Weka kwenye queue APC ya `RtlMoveMemory` itakayotekelezwa ndani ya target ili kunakili thamani ya awali ya baiti 8 kwenye `[Rsp]` hadi data slot ya stub.
4. Badilisha eneo lililoandaliwa liwe executable kwa `NtProtectVirtualMemory`. PoC hii huchagua `PAGE_EXECUTE_READWRITE` kwa sababu payload yake ya polymorphic hujidecode yenyewe; WTH yenyewe haihitaji payload inayojirekebisha.
5. Weka kwenye queue APC nyingine ya `RtlMoveMemory` itakayotekelezwa ndani ya target ili kunakili **pointer ya tail iliyoandaliwa mapema** hadi `[Rsp]`, kisha uite `NtAlertThread`. Mpangilio wa FIFO wa APC huhifadhi anwani ya awali ya kurudi kabla ya kuibadilisha; wrapper inaporudi, huingia kwenye stub na, baada ya payload kurudi, huendelea na caller wa awali.

Kutokuwepo kwa `NtWriteVirtualMemory` **hakumaanishi** kwamba hakuna maandishi yanayofanyika kwenye target: `GetThreadDescription` na `RtlMoveMemory` huyafanya ndani ya target.<sup>[[1]](#references)[[3]](#references)</sup> Uwasilishaji wa kawaida wa user APC pia hutegemea thread iliyochaguliwa kushughulikia APC queue yake; snapshot ya `WrQueue` na alert si dhamana ya jumla ya utekelezaji wa mara moja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Mfano huu huepuka kuunda remote-thread, kusimamisha thread na kubadilisha context moja kwa moja, lakini bado unaweza kuonekana kupitia APCs zake na mabadiliko ya protection.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Utekaji wa Waiting Thread](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC na README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – Utekelezaji wa WhisperHijack Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
