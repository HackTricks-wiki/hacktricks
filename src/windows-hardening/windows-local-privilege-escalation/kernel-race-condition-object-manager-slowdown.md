# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Чому важливо розширювати вікно race condition

Багато Windows kernel LPE дотримуються класичного шаблону `check_state(); NtOpenX("name"); privileged_action();`. На сучасному обладнанні холодний `NtOpenEvent`/`NtOpenSection` розв'язує коротке ім'я приблизно за 2 мкс, залишаючи майже нуль часу, щоб змінити перевірений стан до виконання захищеної дії. Навмисно змушуючи пошук у Object Manager Namespace (OMNS) на кроці 2 тривати десятки мікросекунд, attacker отримує достатньо часу, щоб стабільно вигравати інакше ненадійні race condition без необхідності виконувати тисячі спроб.<sup>[[1]](#references)</sup>

## Внутрішня будова пошуку Object Manager у двох словах

* **Структура OMNS** – Імена на кшталт `\BaseNamedObjects\Foo` розв'язуються каталог за каталогом. Для кожного компонента kernel має знайти/відкрити *Object Directory* і порівняти Unicode-рядки. На цьому шляху можуть переходитися symbolic links (наприклад, літери дисків).
* **Обмеження UNICODE_STRING** – Шляхи OM зберігаються в `UNICODE_STRING`, поле `Length` якого має 16-бітне значення. Абсолютне обмеження становить 65 535 байтів (32 767 UTF-16 codepoints). З префіксами на кшталт `\BaseNamedObjects\` attacker все ще контролює приблизно 32 000 символів.
* **Передумови для attacker** – Будь-який user може створювати objects у writable directories, таких як `\BaseNamedObjects`. Коли vulnerable code використовує ім'я всередині такого каталогу або переходить за symbolic link, що веде туди, attacker контролює performance пошуку без спеціальних privileges.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

Вартість розв'язання компонента приблизно лінійно залежить від його довжини, оскільки kernel має виконати Unicode-порівняння з кожним entry у батьківському каталозі. Створення event з іменем завдовжки 32 kB одразу збільшує latency `NtOpenEvent` приблизно з 2 мкс до 35 мкс у Windows 11 24H2 (тестова платформа Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Практичні примітки*

- Досягти ліміту довжини можна за допомогою будь-якого іменованого kernel object (events, sections, semaphores…).
- Symbolic links або reparse points можуть спрямовувати коротке ім'я “victim” на цей гігантський компонент, тому slowdown застосовується прозоро.
- Оскільки все розташовано в namespace, доступних для запису користувачем, payload працює зі стандартним user integrity level.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Глибоко рекурсивні каталоги

Агресивніший варіант створює ланцюжок із тисяч каталогів (`\BaseNamedObjects\A\A\...\X`). Кожен перехід запускає логіку розв'язання каталогів (перевірки ACL, пошук у hash-таблицях, підрахунок reference), тому затримка на рівень вища, ніж під час порівняння одного рядка. Приблизно 16 000 рівнів (обмеження те саме — розмір `UNICODE_STRING`) дають емпіричні показники, що перевищують бар'єр у 35 µs, досягнутий за допомогою довгих одиничних компонентів.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Поради:

* Чергуйте символ для кожного рівня (`A/B/C/...`), якщо батьківський каталог починає відхиляти дублікати.
* Зберігайте масив handle, щоб після експлуатації можна було коректно видалити ланцюжок і не забруднювати namespace.<sup>[[1]](#references)</sup>

## Примітив уповільнення №3 – Shadow directories, hash collisions & symlink reparses (хвилини замість мікросекунд)

Object directories підтримують **shadow directories** (fallback lookups) і хеш-таблиці записів із bucket-структурою. Зловживайте обома механізмами, а також 64-компонентним лімітом symbolic-link reparse, щоб збільшити уповільнення, не перевищуючи довжину `UNICODE_STRING`:

1. Створіть два каталоги під `\BaseNamedObjects`, наприклад `A` (shadow) і `A\A` (target). Створіть другий, використовуючи перший як shadow directory (`NtCreateDirectoryObjectEx`), щоб відсутні lookup-и в `A` переходили до `A\A`.
2. Заповніть кожен каталог тисячами **colliding names**, які потрапляють до одного hash bucket (наприклад, змінюючи кінцеві цифри, зберігаючи те саме значення `RtlHashUnicodeString`). Тепер lookup-и деградують до лінійного сканування O(n) всередині одного каталогу.
3. Побудуйте ланцюжок приблизно з 63 **object manager symbolic links**, які повторно виконують reparse у довгий суфікс `A\A\…`, витрачаючи reparse budget. Кожен reparse починає parsing згори, множачи вартість collision-пошуку.
4. Lookup фінального компонента (`...\\0`) тепер займає **хвилини** у Windows 11, коли в кожному каталозі присутні 16 000 collisions, забезпечуючи практично гарантований виграш у race для одноразових kernel LPE.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Чому це важливо*: уповільнення тривалістю в кілька хвилин перетворює одноразові race-based LPEs на детерміновані exploits.<sup>[[1]](#references)</sup>

### Нотатки щодо повторного тестування у 2025 році та готові інструменти

- James Forshaw повторно опублікував техніку з оновленими таймінгами для Windows 11 24H2 (ARM64). Базові відкриття залишаються на рівні ~2 µs; компонент розміром 32 kB збільшує цей показник приблизно до ~35 µs, а shadow-dir + collision + ланцюжки з 63 reparse усе ще досягають ~3 хвилин, що підтверджує: primitives зберігаються в актуальних збірках. Вихідний код і perf harness доступні в оновленій публікації Project Zero.<sup>[[1]](#references)</sup>
- Налаштування можна автоматизувати за допомогою публічного пакета `symboliclink-testing-tools`: `CreateObjectDirectory.exe` створює пару shadow/target, а `NativeSymlink.exe` у циклі генерує ланцюжок із 63 переходів. Це усуває потребу в написанні власних обгорток `NtCreate*` і забезпечує узгоджені ACL.<sup>[[2]](#references)</sup>

## Вимірювання вашого race window

Вбудуйте простий harness у свій exploit, щоб виміряти, наскільки великим стає window на апаратному забезпеченні жертви. Наведений нижче фрагмент відкриває цільовий object `iterations` разів і повертає середню вартість одного відкриття за допомогою `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Результати безпосередньо впливають на вашу стратегію orchestration race (наприклад, кількість необхідних worker threads, інтервали sleep і те, наскільки рано потрібно змінити shared state).

## Процес exploitation

1. **Знайдіть вразливий open** – Відстежуйте kernel path (за допомогою symbols, ETW, hypervisor tracing або reverse engineering), доки не знайдете виклик `NtOpen*`/`ObOpenObjectByName`, який обробляє ім’я, контрольоване attacker, або symbolic link у user-writable directory.
2. **Замініть це ім’я на повільний шлях**
- Створіть довгий компонент або ланцюжок директорій у `\BaseNamedObjects` (або іншому writable OM root).
- Створіть symbolic link, щоб ім’я, якого очікує kernel, тепер розгорталося в повільний шлях. Ви можете спрямувати directory lookup вразливого driver до своєї структури, не змінюючи оригінальний target.
3. **Запустіть race**
- Thread A (victim) виконує вразливий код і блокується всередині повільного lookup.
- Thread B (attacker) змінює guarded state (наприклад, замінює file handle, переписує symbolic link або перемикає object security), поки Thread A зайнятий.
- Коли Thread A продовжує виконання та виконує privileged action, він бачить застарілий state і виконує operation, контрольовану attacker.
4. **Виконайте cleanup** – Видаліть ланцюжок директорій і symbolic links, щоб не залишати підозрілих артефактів і не порушувати роботу легітимних IPC users.<sup>[[1]](#references)</sup>

## Операційні міркування

- **Комбінуйте primitives** – Ви можете використовувати довге ім’я *на кожному рівні* directory chain, щоб отримати ще більшу latency, доки не буде вичерпано розмір `UNICODE_STRING`.
- **One-shot bugs** – Розширене вікно (від десятків мікросекунд до хвилин) робить “single trigger” bugs реалістичними в поєднанні з CPU affinity pinning або hypervisor-assisted preemption.
- **Побічні ефекти** – Slowdown впливає лише на malicious path, тому загальна продуктивність системи залишається незмінною; defenders рідко це помітять, якщо не відстежують namespace growth.
- **Cleanup** – Зберігайте handles до кожної створеної directory/object, щоб після цього викликати `NtMakeTemporaryObject`/`NtClose`. Інакше необмежені directory chains можуть зберігатися після перезавантаження.
- **File-system races** – Якщо вразливий path зрештою проходить через NTFS, ви можете встановити Oplock (наприклад, `SetOpLock.exe` з того самого toolkit) на backing file, поки працює OM slowdown, заморозивши consumer ще на кілька мілісекунд без зміни OM graph.<sup>[[2]](#references)</sup>

## Захисні примітки

- Kernel code, який покладається на named objects, повинен повторно перевіряти security-sensitive state *після* open або отримувати reference до перевірки (усуваючи TOCTOU gap).
- Встановлюйте upper bounds для глибини/довжини OM path перед dereferencing user-controlled names. Відхилення надто довгих імен змушує attackers знову працювати у вікні мікросекунд.
- Інструментуйте namespace growth object manager (ETW `Microsoft-Windows-Kernel-Object`), щоб виявляти підозрілі ланцюжки з тисяч компонентів у `\BaseNamedObjects`.

## References

- [1] [Project Zero – Техніки Windows Exploitation: Перемога в Race Conditions за допомогою Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
