# Windows Process Injection via Thread Names and Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) передає байти в запущений процес без `WriteProcessMemory`; Waiting Thread Hijacking (WTH) запускає їх на наявному thread без `SetThreadContext` і без створення remote thread.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Це **примітиви process injection, а не вразливості для підвищення привілеїв**: injector усе ще потребує доступу до цільового процесу й thread. API опису thread вимагають Windows 10 версії 1607 або новішої.<sup>[[1]](#references)[[3]](#references)</sup> Інші підходи до injection та ухилення див. у [Antivirus (AV) Bypass](av-bypass.md).

## Thread Name-Calling: копіювання payload на стороні цільового процесу

`NtSetInformationThread(ThreadNameInformation)` копіює переданий `UNICODE_STRING` у сховище імені thread. Виклик `GetThreadDescription` **усередині цільового процесу** створює user-mode heap-копію цього імені. Так передавання payload відокремлюється від фінального копіювання в пам’ять: injector може прочитати повернений heap **pointer**, а APC, що виконує `RtlMoveMemory` усередині цільового процесу, копіює байти до місця призначення.<sup>[[1]](#references)</sup> Початкова техніка також підтримує special user APC; реалізація WhisperHijack натомість використовує звичайний `NtQueueApcThread` на thread, що очікує.<sup>[[1]](#references)[[3]](#references)</sup>

Для кожного chunk розміром не більше `0xFFFE` байтів PoC використовує такий порядок дій. Дубльований auto-reset event сигналізує про завершення лише після того, як цільовий процес заповнив scratch slot; injector очікує на цей сигнал перед зчитуванням pointer. Event підтверджує APC, що отримує heap pointer, а не наступний APC копіювання. Після постановки APC копіювання в чергу PoC переводить той самий thread у стан alertable і покладається на порядок виконання APC, а не на другий сигнал завершення.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Scratch-адреса має бути доступною для запису в цільовому процесі, а інжектор має знати її, не записуючи туди попередньо дані. В оригінальному PoC використовується `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack також пропонує `PEB.PostProcessInitRoutine` і за замовчуванням використовує `TEB.TlsSlots[63]` (знаходиться за допомогою `NtQueryInformationThread(ThreadBasicInformation)`). TLS-слот **не гарантовано буде вільним** у кожному цільовому процесі; перезапис активного слота може порушити роботу цього потоку. Увімкніть рівно одну опцію в `Main.c`. Перевірки під час компіляції відхиляють випадки, коли вибір PEB/TEB відсутній або суперечливий.<sup>[[4]](#references)</sup>

Звичайний виклик `RtlInitUnicodeString` зупинився б на вбудованому широкому нульовому символі. Щоб передати двійкові дані, ініціалізуйте довжину `UNICODE_STRING`, використавши буфер заповнення такого самого розміру без нульових символів, замініть байти його `Buffer` на фактичний фрагмент, а потім передайте його в `NtSetInformationThread`. Це передавання на основі довжини відрізняється від прямого передавання shellcode у `SetThreadDescription` як рядка з термінальним нульовим символом.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: повернення з очікування черги

Перелічіть потоки за допомогою `NtQuerySystemInformation(SystemProcessInformation)` і знайдіть потоки з `ThreadState == Waiting` та `WaitReason == WrQueue`. Потік, заблокований у syscall-обгортці, як-от `NtWaitForWorkViaWorkerFactory`, зберігає адресу повернення викликувача за адресою `[Rsp]`. Заміна цього слота стека спрямовує `ret` обгортки на stub, не змінюючи `Rip` через `SetThreadContext`. Stub має зберегти прапорці та регістри, **викликати** payload, який повертається, відновити стан, а потім перейти за збереженою початковою адресою повернення.<sup>[[2]](#references)[[3]](#references)</sup>

У x64 PoC stub має 8-байтовий слот для збереженої адреси повернення за зміщенням `+0x00`, інструкції за `+0x08`, а payload — за `+0x45`. У слот стека записується `allocation_base + 0x08`, а не адреса слота даних. Самого `WrQueue` **недостатньо, щоб підтвердити** очікування через worker factory: в оригінальному дослідженні також визначено `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` як шлях очікування черги. Перш ніж покладатися на цей макет, перевірте фактичний стек очікування/викликів і переконайтеся, що `[Rsp]` — це потрібний слот повернення.<sup>[[2]](#references)[[3]](#references)</sup>

## Поєднання TNC і WTH без запису між процесами

WhisperHijack демонструє комбінований робочий процес наявного нативного x64-процесу. Його Writer вибирає кандидатний процес/потік, а дочірній процес Flipper успадковує дескриптори, потрібні для фінального передавання керування. Дескриптор процесу запитує `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **але не** `PROCESS_VM_WRITE`; попри це, поточний PoC відкриває потік із `THREAD_ALL_ACCESS`. Перевірки доступу й пом’якшення загроз у процесі все одно застосовуються.<sup>[[3]](#references)[[4]](#references)</sup>

Комбінований PoC використовує таку послідовність; APC копіювання пам’яті виконуються в цільовому процесі, а не через дескриптор із правами віддаленого запису.<sup>[[4]](#references)</sup>

1. Зарезервуйте в цільовому процесі вільні блоки, вирівняні за 64 КБ, а потім зафіксуйте їхні сторінки по 4 КБ як `PAGE_READWRITE`. PoC перевіряє фіксовані кандидатні адреси за допомогою `NtQueryVirtualMemory`; ці адреси є вибором реалізації, а не вимогою TNC чи WTH.
2. Сформуйте `[0x45-байтовий WTH stub][x64 payload, що повертається][8-байтовий вказівник на точку входу stub]`, де останній вказівник дорівнює `allocation_base + 0x08`. Передайте цей буфер циклом фрагментів TNC.
3. У Flipper отримайте `Rsp` потоку, що очікує, за допомогою `NtGetContextThread(CONTEXT_CONTROL)`. Поставте в чергу APC з викликом `RtlMoveMemory` у цільовому процесі, щоб скопіювати початкове 8-байтове значення за адресою `[Rsp]` у слот даних stub.
4. Зробіть підготовлену область виконуваною за допомогою `NtProtectVirtualMemory`. Цей PoC вибирає `PAGE_EXECUTE_READWRITE`, оскільки його polymorphic payload сам себе декодує; WTH не потребує payload, що сам себе змінює.
5. Поставте в чергу ще один APC з викликом `RtlMoveMemory` у цільовому процесі, щоб скопіювати **попередньо підготовлений вказівник на хвіст** у `[Rsp]`, а потім викличте `NtAlertThread`. FIFO-порядок APC спершу зберігає початкову адресу повернення, а вже потім замінює її; повернення обгортки переходить до stub, а після повернення payload відновлюється виконання початкового викликувача.

Відсутність `NtWriteVirtualMemory` **не означає**, що запису в цільовий процес не відбувається: `GetThreadDescription` і `RtlMoveMemory` виконують його всередині цільового процесу.<sup>[[1]](#references)[[3]](#references)</sup> Доставка звичайного user APC також залежить від того, чи обробляє вибраний потік свою чергу APC; знімок `WrQueue` і сигнал не гарантують негайного виконання в усіх випадках.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> У прикладі не створюється віддалений потік, не призупиняється потік і не відбувається пряма заміна контексту, але його APC і зміна захисту пам’яті все одно можна виявити.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – PoC і README WhisperHijack](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – реалізація WhisperHijack у Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
