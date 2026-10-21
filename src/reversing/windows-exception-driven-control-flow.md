# Керування потоком виконання через винятки Windows та антиdebugging

{{#include ../banners/hacktricks-training.md}}

Захищена програма Windows може використовувати навмисно спричинений виняток для розгалуження: інструкція, що спричиняє помилку, лише передає керування обробнику, який вибирає наступну адресу коду користувача. Це приховує переходи від лінійної дизасембляції та переносить вибір наступного кроку до диспетчеризації винятків.<sup>[[1]](#references)</sup>

## Важлива диспетчеризація

Налагоджувач, підключений до процесу, отримує виняток **first-chance** до того, як його отримають обробники програми. Якщо налагоджувач позначає подію як необроблену, Windows шукає обробники процесу; якщо обробника немає, виняток повертається до налагоджувача як **last-chance**. Тож налагоджувач, який обробляє подію breakpoint або single-step, може змінити те, чи запуститься обробник програми.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` реєструє process-wide VEH на початку списку vectored handlers. Він запускається до frame-based SEH, але пізніша реєстрація з найвищим пріоритетом може перемістити інший обробник перед ним. Повернення `EXCEPTION_CONTINUE_SEARCH` передає виняток іншим обробникам; `EXCEPTION_CONTINUE_EXECUTION` відновлює виконання зі збереженого `CONTEXT`, включно зі змінами регістрів, внесеними обробником.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Класичний x86 SEH використовує пов’язані зі стеком реєстрації, які можна переглянути командою `!exchain`. Native x64 використовує записи `RUNTIME_FUNCTION` у `.pdata` з unwind-даними в `.xdata`, а не цей ланцюжок x86. Не застосовуйте [робочий процес перезапису x86 SEH](../binary-exploitation/stack-overflow/windows-seh-overflow.md) до процесу native x64.<sup>[[5]](#references)[[6]](#references)</sup>

## Перетворення помилки на перехід керування

Наприклад, ділення на нуль може навмисно спричинити `EXCEPTION_INT_DIVIDE_BY_ZERO`, а не бути помилкою. Обробник має розпізнати виняток і адресу помилки, а потім задати для `ContextRecord->Rip` (або `Eip` на x86) коректну адресу продовження, перш ніж повернути `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Наведене нижче ядро обробника передбачає, що `fault_site` і `continuation` — відомі адреси в одному контексті керування потоком. Реальна реалізація має зберігати очікувані значення стека й регістрів і не повинна відновлювати виконання з тієї самої інструкції, що спричинила помилку, інакше помилка виникне знову.<sup>[[7]](#references)</sup>

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

Той самий механізм може перехопити навмисний `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) і перенаправити виконання. **Не** збільшуйте `Rip` навмання, щоб «пропустити точку зупинки»: збережена адреса та необхідна корекція залежать від пастки, кодування інструкції й поведінки debugger. Перш ніж вибрати адресу продовження, порівняйте `ExceptionRecord->ExceptionAddress` зі збереженим покажчиком інструкцій і дизасемблюйте байти.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) — це окремий приклад з апаратною точкою зупинки, який змінює стан повернення системного виклику loader.

## Trap Flag як залежний від debugger шлюз

Біт `0x100` в `EFLAGS`/`RFLAGS` — це Trap Flag (TF). Його встановлення спричиняє виникнення `STATUS_SINGLE_STEP` (`0x80000004`) на межі наступної інструкції. Гілка VEH або SEH може розрізнити подію single-step, передану застосунку, і подію, перехоплену debugger, але це **евристика, залежна від політики обробки винятків у debugger, а не надійний доказ його наявності**.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Якщо handler потрібен лише один крок, очистіть `0x100` у полі `EFlags` відновленого контексту, перш ніж продовжити. Також відрізняйте кроки, спричинені TF, від подій апаратних breakpoint, перевіряючи адресу, що викликала подію, і стан налагодження; обидва випадки можуть мати тип `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Докладніше про налаштування `sxe`, `sxd` і `sxi` для першого та другого шансу у WinDbg див. у [Автоматизація обробки винятків у WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Винятки](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Обробка винятків у налагоджувачі](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Обробка векторизованих винятків](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Обробка винятків x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Використання обробника векторизованих винятків](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Інструкції асемблера](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Архітектура x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
