# Windows Process Injection via Thread Names and Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC), `WriteProcessMemory` का उपयोग किए बिना, किसी running process में bytes transfer करता है; Waiting Thread Hijacking (WTH), `SetThreadContext` का उपयोग किए बिना या remote thread बनाए बिना, उन्हें किसी existing thread पर चलाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> ये **process-injection primitives हैं, privilege-escalation vulnerabilities नहीं**: injector को अब भी target process और thread तक access चाहिए। Thread-description APIs के लिए Windows 10 version 1607 या बाद का version आवश्यक है।<sup>[[1]](#references)[[3]](#references)</sup> अन्य injection और evasion approaches के लिए [Antivirus (AV) Bypass](av-bypass.md) देखें।

## Thread Name-Calling: target-side payload copying

`NtSetInformationThread(ThreadNameInformation)` दिए गए `UNICODE_STRING` को thread-name storage में copy करता है। फिर **target के अंदर** `GetThreadDescription` कॉल करने से उस name की user-mode heap copy बनती है। इससे payload transfer और आखिरी memory copy अलग हो जाते हैं: injector लौटाए गए heap **pointer** को पढ़ सकता है, जबकि target के अंदर चल रहा APC `RtlMoveMemory` का उपयोग करके bytes को उनकी destination पर copy करता है।<sup>[[1]](#references)</sup> मूल technique special user APCs को भी support करती है; इसके बजाय WhisperHijack implementation waiting thread पर सामान्य `NtQueueApcThread` का उपयोग करता है।<sup>[[1]](#references)[[3]](#references)</sup>

अधिकतम `0xFFFE` bytes के हर chunk के लिए PoC यह क्रम अपनाता है। एक duplicated auto-reset event, target द्वारा scratch slot भरने के बाद ही completion signal करता है; injector pointer पढ़ने से पहले उस signal का इंतज़ार करता है। यह event heap-pointer APC की पुष्टि करता है, इसके बाद वाले copy APC की नहीं। Copy queue करने के बाद PoC उसी thread को alert करता है और दूसरे completion signal के बजाय APC ordering पर निर्भर करता है।<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Scratch address target में writable होना चाहिए और उसे पहले लिखे बिना injector को ज्ञात होना चाहिए। मूल PoC `PEB.SpareUlongs` का उपयोग करता है।<sup>[[1]](#references)</sup> WhisperHijack `PEB.PostProcessInitRoutine` का विकल्प भी देता है और default रूप से `TEB.TlsSlots[63]` का उपयोग करता है (जिसे `NtQueryInformationThread(ThreadBasicInformation)` से खोजा जाता है)। हर target में TLS slot के unused होने की **गारंटी नहीं** है; किसी live slot को overwrite करने से वह thread खराब हो सकता है। `Main.c` में ठीक एक विकल्प enable करें। Compile-time checks, PEB/TEB selections के न होने या उनमें टकराव होने पर उसे अस्वीकार करते हैं।<sup>[[4]](#references)</sup>

सामान्य `RtlInitUnicodeString` call, बीच में आने वाले wide null पर रुक जाती है। Binary data भेजने के लिए, समान आकार के non-null padding buffer का उपयोग करके `UNICODE_STRING` की length initialize करें, उसके `Buffer` bytes को वास्तविक chunk से बदलें, फिर उसे `NtSetInformationThread` को pass करें। यह length-based transfer, shellcode को terminated string के रूप में सीधे `SetThreadDescription` को pass करने से अलग है।<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: queue wait से लौटना

`NtQuerySystemInformation(SystemProcessInformation)` से threads enumerate करें और `ThreadState == Waiting` तथा `WaitReason == WrQueue` खोजें। `NtWaitForWorkViaWorkerFactory` जैसे syscall wrapper में blocked thread का saved caller return address `[Rsp]` पर होता है। उस stack slot को बदलने से, `SetThreadContext` के ज़रिए `Rip` बदले बिना, wrapper का `ret` एक stub पर redirect हो जाता है। Stub को flags और registers save करने चाहिए, लौटने वाले payload को **call** करना चाहिए, state restore करनी चाहिए, फिर saved original return address पर jump करना चाहिए।<sup>[[2]](#references)[[3]](#references)</sup>

x64 PoC में, stub में `+0x00` पर 8-byte saved-return slot, `+0x08` पर instructions और `+0x45` पर payload होता है। Stack slot में `allocation_base + 0x08` रखा जाता है, data slot का address नहीं। केवल `WrQueue` होना **worker-factory wait का प्रमाण नहीं** है: मूल research `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` को भी queue-wait path के रूप में पहचानता है। इस layout पर निर्भर होने से पहले वास्तविक wait/call stack और यह जाँचें कि `[Rsp]` अपेक्षित return slot है।<sup>[[2]](#references)[[3]](#references)</sup>

## Cross-process writes के बिना TNC और WTH को मिलाना

WhisperHijack एक मौजूदा native x64 process के विरुद्ध संयुक्त workflow दिखाता है। इसका Writer एक candidate process/thread चुनता है, जबकि Flipper child को अंतिम hand-off के लिए ज़रूरी handles विरासत में मिलते हैं। Process handle में `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE` माँगा जाता है, **`PROCESS_VM_WRITE` नहीं**; फिर भी, मौजूदा PoC thread को `THREAD_ALL_ACCESS` के साथ खोलता है। Access checks और process mitigations फिर भी लागू होते हैं।<sup>[[3]](#references)[[4]](#references)</sup>

संयुक्त PoC यह क्रम अपनाता है; memory copy APCs, remote-write rights वाले handle के ज़रिए नहीं, बल्कि target के भीतर execute होते हैं।<sup>[[4]](#references)</sup>

1. Target में 64-KB-aligned free blocks reserve करें, फिर उनके 4-KB pages को `PAGE_READWRITE` के रूप में commit करें। PoC `NtQueryVirtualMemory` से निश्चित candidate addresses की जाँच करता है; ये addresses implementation के विकल्प हैं, TNC या WTH की आवश्यकता नहीं।
2. `[0x45-byte WTH stub][returning x64 payload][8-byte stub-entry pointer]` assemble करें, जहाँ अंतिम pointer `allocation_base + 0x08` हो। इस buffer को TNC chunk loop से भेजें।
3. Flipper में, `NtGetContextThread(CONTEXT_CONTROL)` से waiting thread का `Rsp` प्राप्त करें। `[Rsp]` पर मौजूद मूल 8-byte value को stub के data slot में copy करने के लिए, target के भीतर `RtlMoveMemory` APC queue करें।
4. `NtProtectVirtualMemory` से staged region को executable बनाएँ। यह PoC `PAGE_EXECUTE_READWRITE` चुनता है क्योंकि इसका polymorphic payload स्वयं को decode करता है; WTH के लिए self-modifying payload आवश्यक नहीं है।
5. **पहले से staged tail pointer** को `[Rsp]` में copy करने के लिए target के भीतर एक और `RtlMoveMemory` APC queue करें, फिर `NtAlertThread` call करें। FIFO APC ordering, original return को बदलने से पहले save करती है; wrapper का return stub में प्रवेश करता है और payload लौटने के बाद original caller पर वापस जाता है।

`NtWriteVirtualMemory` का न होना यह **नहीं** दर्शाता कि target में कोई writes नहीं होतीं: `GetThreadDescription` और `RtlMoveMemory` उन्हें target के भीतर करते हैं।<sup>[[1]](#references)[[3]](#references)</sup> सामान्य user APC delivery भी चुने गए thread द्वारा अपनी APC queue को process करने पर निर्भर करती है; `WrQueue` snapshot और alert से तत्काल execution की सामान्य गारंटी नहीं मिलती।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> यह उदाहरण remote-thread creation, suspension और direct context replacement से बचता है, लेकिन इसके APCs और protection transition से इसका पता लगाया जा सकता है।<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC और README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – WhisperHijack Main.c कार्यान्वयन](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
