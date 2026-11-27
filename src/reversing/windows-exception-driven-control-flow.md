# Керування потоком виконання через винятки у Windows та anti-debugging

{{#include ../banners/hacktricks-training.md}}

Захищена програма для Windows може використовувати навмисно згенерований виняток як розгалуження: інструкція, що спричиняє помилку, — це лише точка входу до обробника, який вибирає наступну адресу користувацького коду. Це приховує ребра потоку керування від лінійної дизасембляції та переносить визначення наступного кроку до диспетчеризації винятків.<sup>[[1]](#references)</sup>

## Має значення диспетчеризація

Налагоджувач, під’єднаний до процесу, отримує виняток **першого шансу** до обробників програми. Якщо він передає подію як необроблену, Windows шукає обробники процесу; виняток, для якого немає обробника, повертається до налагоджувача як виняток **останнього шансу**. Тому налагоджувач, який перехоплює подію точки зупинки або покрокового виконання, може змінити те, чи запуститься обробник програми.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` реєструє загальнопроцесний VEH на початку списку векторизованих обробників. Він виконується до SEH, прив’язаного до кадру стека, але пізніша реєстрація з вищим пріоритетом може перемістити інший обробник перед ним. Повернення `EXCEPTION_CONTINUE_SEARCH` передає виняток іншим обробникам; `EXCEPTION_CONTINUE_EXECUTION` відновлює виконання зі збереженого `CONTEXT`, зокрема з урахуванням змін регістрів, внесених обробником.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Класичний x86 SEH використовує прив’язані до стека реєстрації, які можна переглянути командою `!exchain`. У нативному x64 використовуються записи `RUNTIME_FUNCTION` у `.pdata` з даними для розкручування стека в `.xdata`, а не цей ланцюжок x86. Не застосовуйте [процедуру перезапису x86 SEH](../binary-exploitation/stack-overflow/windows-seh-overflow.md) до нативного процесу x64.<sup>[[5]](#references)[[6]](#references)</sup>

## Перетворення помилки на ребро потоку керування

Наприклад, ділення на нуль може навмисно викликати `EXCEPTION_INT_DIVIDE_BY_ZERO`, а не бути ознакою помилки. Обробник має розпізнати виняток і адресу помилки, а потім встановити `ContextRecord->Rip` (або `Eip` у x86) на коректну адресу продовження, перш ніж повернути `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Наведене нижче ядро обробника передбачає, що `fault_site` і `continuation` — відомі адреси в одному контексті керування потоком. Реальна реалізація має зберегти очікуваний стек і регістри та не повинна відновлювати виконання з тієї самої інструкції, що спричинила помилку, інакше помилка виникне знову.<sup>[[7]](#references)</sup>

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

Той самий механізм може перехопити навмисний `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) і перенаправити виконання. **Не** збільшуйте `Rip` навмання, щоб «пропустити breakpoint»: збережена адреса й необхідне коригування залежать від пастки, кодування інструкції та поведінки debugger. Перш ніж вибирати адресу продовження, порівняйте `ExceptionRecord->ExceptionAddress` зі збереженим покажчиком інструкцій і дизасемблюйте байти.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) — це окремий приклад із hardware breakpoint, який змінює стан повернення із syscall завантажувача.

## Матеріалізація сторінок через помилки

VEH може перетворити помилку сторінки на **lazy loader**, а не просто на перехід. Зарезервуйте приватний діапазон образу, залишивши сторінки незакоміченими, або використовуйте guard pages у відображених сторінках, якщо це підтримується. До запуску образу проіндексуйте місця релокації та IAT thunks за цільовою сторінкою. У разі помилки в цьому діапазоні обробник комітить сторінку, до якої звернулися, або надає їй права на запис, копіює байти її секції, застосовує релокації та імпорти цієї сторінки, встановлює для неї остаточний захист і повертає `EXCEPTION_CONTINUE_EXECUTION`. Початкова інструкція виконується повторно; **не** просувайте `Rip`, як це робиться в обробнику, що пропускає інструкцію після помилки. Сторінки, до яких не зверталися, не обов’язково мають містити payload у пам’яті.<sup>[[11]](#references)</sup>

Для порушення доступу `ExceptionRecord->ExceptionAddress` вказує на **інструкцію**, під час виконання якої сталася помилка, а `ExceptionInformation[1]` — на адресу, до якої зверталися.<sup>[[10]](#references)</sup> Перш ніж матеріалізувати сторінку, перевірте код винятку, кількість параметрів і діапазон адреси, до якої зверталися; інакше сторонню помилку можна помилково сприйняти як запит від завантажувача.<sup>[[10]](#references)[[11]](#references)</sup> Під час першого доступу `PAGE_GUARD` викликає `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`), а Windows автоматично скидає біт guard, тому повторне встановлення цього біта — окремий крок, а не безперервний hook.<sup>[[12]](#references)</sup> Забезпечте доступність VEH і потрібних йому метаданих під час обробки подій.<sup>[[11]](#references)</sup> На x64 дані для unwind можуть знадобитися ще до першої помилки; у згаданому завантажувачі сторінки матеріалізуються заздалегідь, до виклику `DllMain`, щоб уникнути race conditions під час ініціалізації.<sup>[[11]](#references)</sup> Після запису коду й до його виконання очистьте кеш інструкцій.<sup>[[13]](#references)</sup>

Щоб відновити цей потік під час reverse engineering, установіть зупинку на first-chance guard-page violations і access violations, перевірте запис винятку, а потім передайте подію обробнику програми за допомогою `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Використайте `!vprot` для адреси, до якої зверталися, щоб перевірити поточний захист її сторінки.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Після того як обробник завантажить сторінку, збережіть її байти та порівняйте їх із образом файлу.<sup>[[11]](#references)</sup> Перевірка `!vprot` після винятку не доводить, що до цього сторінка була захищеною, оскільки статус guard діє лише один раз.<sup>[[11]](#references)[[12]](#references)</sup> Коли потрібний діапазон образу стане відомим, звузьте фільтри винятків або точки зупинки обробника, щоб уникнути сторонніх винятків.<sup>[[16]](#references)</sup> Налаштування фільтрів див. у розділі [автоматизація винятків у WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).<sup>[[16]](#references)</sup>

## Trap Flag як залежний від налагоджувача шлюз

Біт `0x100` у `EFLAGS`/`RFLAGS` — це Trap Flag (TF). Його встановлення спричиняє виняток `STATUS_SINGLE_STEP` (`0x80000004`) на межі наступної інструкції. Гілка VEH або SEH може розрізнити подію покрокового виконання, передану програмі, та подію, оброблену налагоджувачем, але це **евристика, що залежить від політики обробки винятків налагоджувача**, а не надійний доказ його наявності.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Якщо handler потрібен лише один крок, очистіть `0x100` у `EFlags` відновленого контексту перед продовженням. Також відрізняйте кроки, зумовлені TF, від подій апаратних точок зупинки, перевіряючи адресу, що спричинила подію, і стан налагодження; обидва типи можуть з’являтися як `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Щодо налаштувань першого й другого шансу `sxe`, `sxd` і `sxi` у WinDbg див. [Автоматизація винятків у WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research — Anti-Debug: винятки](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn — обробка винятків налагоджувачем](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn — AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn — обробка векторизованих винятків](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn — обробка винятків x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn — !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn — використання обробника векторизованих винятків](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research — Anti-Debug: інструкції асемблера](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn — архітектура x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn — EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon — завантаження образу на основі помилок](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn — створення сторінок захисту](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn — VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn — .exr (відображення запису винятку)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn — !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn — фільтри винятків sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn — gn (продовжити з необробленим винятком)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
