# Thread Names ve Waiting Threads üzerinden Windows Process Injection

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC), `WriteProcessMemory` kullanmadan çalışan bir sürece bayt aktarır; Waiting Thread Hijacking (WTH) ise `SetThreadContext` kullanmadan veya uzak bir thread oluşturmadan bu baytları mevcut bir thread üzerinde çalıştırır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Bunlar **process-injection ilkelleridir, privilege-escalation güvenlik açıkları değildir**: injector'ın hedef süreç ve thread'e erişimi yine de gerekir. Thread-description API'leri Windows 10 version 1607 veya sonraki sürümleri gerektirir.<sup>[[1]](#references)[[3]](#references)</sup> Diğer injection ve evasion yaklaşımları için [Antivirus (AV) Bypass](av-bypass.md) bölümüne bakın.

## Thread Name-Calling: hedef tarafında payload kopyalama

`NtSetInformationThread(ThreadNameInformation)`, sağlanan `UNICODE_STRING` değerini thread adı depolama alanına kopyalar. **Hedefin içinde** `GetThreadDescription` çağrılması, bu adın user-mode heap üzerinde bir kopyasını oluşturur. Böylece payload aktarımı, son bellek kopyalama işleminden ayrılır: injector döndürülen heap **pointer**'ını okuyabilir; hedefin içinde çalışan bir APC ise `RtlMoveMemory`'yi kullanarak baytları hedeflerine kopyalar.<sup>[[1]](#references)</sup> Orijinal teknik special user APC'leri de destekler; WhisperHijack uygulaması ise bekleyen bir thread üzerinde normal `NtQueueApcThread` kullanır.<sup>[[1]](#references)[[3]](#references)</sup>

PoC, en fazla `0xFFFE` baytlık her parça için bu sıralamayı kullanır. Çoğaltılmış bir auto-reset event, yalnızca hedef scratch slot'u doldurduktan sonra tamamlanma sinyali verir; injector pointer'ı okumadan önce bu sinyali bekler. Event, heap-pointer APC'sini onaylar; sonraki kopyalama APC'sini değil. PoC, kopyalama APC'sini sıraya aldıktan sonra aynı thread'i alert durumuna getirir ve ikinci bir tamamlanma sinyali yerine APC sıralamasına güvenir.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Scratch adresi hedefte yazılabilir olmalı ve önce yazma işlemi yapılmadan injector tarafından bilinmelidir. Özgün PoC, `PEB.SpareUlongs` kullanır.<sup>[[1]](#references)</sup> WhisperHijack ayrıca `PEB.PostProcessInitRoutine` seçeneğini sunar ve varsayılan olarak `TEB.TlsSlots[63]` kullanır (`NtQueryInformationThread(ThreadBasicInformation)` ile bulunur). TLS slotunun her hedefte kullanılmadığı **garanti değildir**; etkin bir slotun üzerine yazmak ilgili thread'i bozabilir. `Main.c` içinde tam olarak bir seçeneği etkinleştirin. Derleme zamanı denetimleri, PEB/TEB seçimlerinin eksik veya çakışmalı olmasını reddeder.<sup>[[4]](#references)</sup>

Normal bir `RtlInitUnicodeString` çağrısı, gömülü bir geniş karakterli null değerinde durur. İkili veri taşımak için `UNICODE_STRING` uzunluğunu aynı boyutta, null olmayan bir padding buffer kullanarak başlatın, `Buffer` baytlarını gerçek chunk ile değiştirin ve ardından `NtSetInformationThread`'e aktarın. Bu uzunluk tabanlı aktarım, shellcode'un sonlandırılmış bir string olarak doğrudan `SetThreadDescription`'a geçirilmesinden farklıdır.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: queue beklemesinden dönüş

Thread'leri `NtQuerySystemInformation(SystemProcessInformation)` ile sıralayın ve `ThreadState == Waiting` ile `WaitReason == WrQueue` koşullarını arayın. `NtWaitForWorkViaWorkerFactory` gibi bir syscall wrapper içinde bekleyen thread'in kaydedilmiş çağıran dönüş adresi `[Rsp]` konumundadır. Bu stack slotunu değiştirmek, `SetThreadContext` ile `Rip` değerini değiştirmeden wrapper'ın `ret` komutunu bir stub'a yönlendirir. Stub; bayrakları ve register'ları kaydetmeli, dönen bir payload'ı **çağırmalı**, durumu geri yüklemeli ve ardından kaydedilmiş özgün dönüş adresine atlamalıdır.<sup>[[2]](#references)[[3]](#references)</sup>

x64 PoC'de stub, `+0x00` konumunda 8 baytlık bir kaydedilmiş dönüş slotuna, `+0x08` konumunda talimatlara ve `+0x45` konumunda payload'a sahiptir. Stack slotuna veri slotu adresi değil, `allocation_base + 0x08` yazılır. Tek başına `WrQueue`, worker-factory beklemesinin kanıtı **değildir**: özgün araştırma, `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` işlevlerini de bir queue-wait yolu olarak tanımlar. Bu düzene güvenmeden önce gerçek bekleme/çağrı stack'ini ve `[Rsp]` değerinin hedeflenen dönüş slotu olduğunu doğrulayın.<sup>[[2]](#references)[[3]](#references)</sup>

## TNC ve WTH'yi süreçler arası yazma olmadan birleştirme

WhisperHijack, birleşik iş akışını mevcut bir native x64 sürecine karşı gösterir. Writer, aday bir süreç/thread seçerken Flipper alt süreci, son hand-off için gereken handle'ları devralır. Süreç handle'ı `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE` haklarını ister; `PROCESS_VM_WRITE` **istemez**. Buna rağmen mevcut PoC, thread'i `THREAD_ALL_ACCESS` ile açar. Erişim denetimleri ve süreç mitigation'ları yine geçerlidir.<sup>[[3]](#references)[[4]](#references)</sup>

Birleşik PoC şu sırayı kullanır; bellek kopyalama APC'leri, uzaktan yazma haklarına sahip bir handle üzerinden değil, hedefin içinde çalışır.<sup>[[4]](#references)</sup>

1. Hedefte 64-KB hizalı boş bloklar ayırın, ardından 4-KB sayfalarını `PAGE_READWRITE` olarak commit edin. PoC, `NtQueryVirtualMemory` ile sabit aday adreslerini yoklar; bu adresler TNC veya WTH gereksinimi değil, uygulama tercihleridir.
2. `[0x45-byte WTH stub][returning x64 payload][8-byte stub-entry pointer]` düzenini oluşturun; son pointer `allocation_base + 0x08` değeridir. Bu buffer'ı TNC chunk döngüsüyle gönderin.
3. Flipper içinde, `NtGetContextThread(CONTEXT_CONTROL)` ile bekleyen thread'in `Rsp` değerini alın. `[Rsp]` konumundaki özgün 8 baytlık değeri stub'ın veri slotuna kopyalamak için hedef içinde bir `RtlMoveMemory` APC'si kuyruğa alın.
4. `NtProtectVirtualMemory` ile hazırlanan bölgeyi yürütülebilir duruma getirin. Bu PoC, polimorfik payload'ı kendi kendini çözdüğü için `PAGE_EXECUTE_READWRITE` seçer; WTH'nin kendisi, kendini değiştiren bir payload gerektirmez.
5. **Önceden hazırlanan tail pointer'ı** `[Rsp]` konumuna kopyalamak için hedef içinde başka bir `RtlMoveMemory` APC'si kuyruğa alın, ardından `NtAlertThread` çağırın. FIFO APC sıralaması, özgün dönüş adresini değiştirmeden önce kaydeder; wrapper'ın dönüşü stub'a girer ve payload döndükten sonra özgün çağırana devam eder.

`NtWriteVirtualMemory` kullanılmaması, hedefte hiç yazma olmadığı **anlamına gelmez**: `GetThreadDescription` ve `RtlMoveMemory` bu yazmaları hedefin içinde gerçekleştirir.<sup>[[1]](#references)[[3]](#references)</sup> Normal kullanıcı APC'lerinin iletilmesi de seçilen thread'in APC kuyruğunu işlemesine bağlıdır; `WrQueue` anlık görüntüsü ve bir alert, yürütmenin hemen gerçekleşeceğini genel olarak garanti etmez.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Örnek, uzaktan thread oluşturma, askıya alma ve doğrudan context değiştirme işlemlerinden kaçınır; ancak APC'leri ve koruma geçişi gözlemlenebilir olmaya devam eder.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Bekleyen Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC ve README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – WhisperHijack Main.c uygulaması](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
