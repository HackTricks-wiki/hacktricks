# Використання умов гонки в kernel через повільні шляхи Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Чому важливо розширити вікно гонки

Багато Windows kernel LPE слідують класичній схемі `check_state(); NtOpenX("name"); privileged_action();`. На сучасному обладнанні холодний виклик `NtOpenEvent`/`NtOpenSection` для розв'язання короткого імені займає приблизно ~2 µs, залишаючи майже ніякого часу, щоб змінити перевірений стан до виконання захищеної дії. Навмисно змусивши пошук в Object Manager Namespace (OMNS) на кроці 2 тривати десятки мікросекунд, атакувальник отримує достатньо часу, щоб стабільно вигравати інакше нестабільні гонки без потреби в тисячах спроб.

## Внутрішня робота пошуку Object Manager — коротко

* **OMNS structure** – Імена, такі як `\BaseNamedObjects\Foo`, розв'язуються каталог за каталогом. Кожен компонент змушує ядро знаходити/відкривати *Object Directory* та порівнювати Unicode рядки. Можуть бути пройдені символічні посилання (наприклад, літери дисків) по шляху.
* **UNICODE_STRING limit** – Шляхи OM містяться в `UNICODE_STRING`, поле `Length` якого є 16-бітним значенням. Абсолютний ліміт — 65 535 байт (32 767 кодових позицій UTF-16). З префіксами на кшталт `\BaseNamedObjects\` атакувальник усе ще контролює ≈32 000 символів.
* **Attacker prerequisites** – Будь-який користувач може створювати об'єкти в підкаталогах, доступних для запису, таких як `\BaseNamedObjects`. Коли вразливий код використовує ім'я всередині них або переходить по символічному посиланню, що веде туди, атакувальник контролює швидкодію пошуку без спеціальних привілеїв.

## Примітив уповільнення №1 — один максимальний компонент

Вартість розв'язання компонента приблизно лінійно залежить від його довжини, оскільки ядро має виконати порівняння Unicode з кожним записом у батьківському каталозі. Створення event з іменем довжиною 32 kB одразу збільшує затримку виклику `NtOpenEvent` з ~2 µs до ~35 µs на Windows 11 24H2 (тестова платформа Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Практичні нотатки*

- Ви можете досягти ліміту довжини, використовуючи будь-який іменований kernel object (events, sections, semaphores…).
- Symbolic links або reparse points можуть скеровувати коротке “victim” ім'я на цей гігантський компонент, тож уповільнення застосовується прозоро.
- Оскільки все знаходиться в user-writable namespaces, payload працює з рівня стандартної user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Більш агресивний варіант виділяє ланцюг із тисяч каталогів (`\BaseNamedObjects\A\A\...\X`). Кожен крок запускає логіку розв'язання директорій (ACL checks, hash lookups, reference counting), тому затримка на рівень більша, ніж при порівнянні одного рядка. При ~16 000 рівнях (обмежених тим самим `UNICODE_STRING` розміром), емпіричні таймінги перевищують бар'єр у 35 µs, досягнутий довгими одиночними компонентами.
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
Tips:

* Чергуйте символ на кожному рівні (`A/B/C/...`), якщо батьківська директорія починає відхиляти дублікати.
* Тримайте масив дескрипторів, щоб мати змогу чисто видалити ланцюжок після експлуатації та не забруднювати простір імен.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (хвилини замість мікросекунд)

Object directories підтримують **shadow directories** (fallback lookups) та бакетовані хеш-таблиці для записів. Зловживання обома плюс 64-компонентний symbolic-link reparse limit дозволяє помножити уповільнення, не перевищуючи довжину `UNICODE_STRING`:

1. Створіть дві директорії під `\BaseNamedObjects`, напр., `A` (shadow) і `A\A` (target). Створіть другу, використавши першу як shadow directory (`NtCreateDirectoryObjectEx`), щоб відсутні пошукові запити в `A` переходили до `A\A`.
2. Заповніть кожну директорію тисячами **colliding names**, які потрапляють у той самий хеш-бакет (наприклад, змінюючи кінцеві цифри, зберігаючи той самий результат `RtlHashUnicodeString`). Пошук тепер деградує до O(n) лінійного сканування всередині однієї директорії.
3. Побудуйте ланцюжок приблизно з 63 **object manager symbolic links**, які повторно repars-ять у довгий суфікс `A\A\…`, витрачаючи reparse budget. Кожне перепарсування перезапускає розбір зверху, множачи вартість колізій.
4. Lookup останнього компоненту (`...\\0`) тепер займає **хвилини** на Windows 11, коли в кожній директорії є по 16 000 колізій, що надає практично гарантований виграш у гонці для one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Чому це важливо*: Затримка тривалістю кілька хвилин перетворює one-shot race-based LPEs на детерміновані експлойти.

## Вимірювання вашого race-вікна

Вбудуйте невеликий harness у свій експлойт, щоб виміряти, наскільки велике вікно стає на обладнанні жертви. Наведений нижче фрагмент відкриває цільовий об'єкт `iterations` разів і повертає середню вартість одного відкриття за допомогою `QueryPerformanceCounter`.
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
Результати безпосередньо впливають на вашу стратегію оркестрації гонки (наприклад, кількість робочих потоків, інтервали затримки, наскільки рано потрібно змінити спільний стан).

## Exploitation workflow

1. **Locate the vulnerable open** – Простежте шлях у ядрі (через symbols, ETW, hypervisor tracing або reversing), поки не знайдете виклик `NtOpen*`/`ObOpenObjectByName`, який обходить ім'я, контрольоване атакуючим, або symbolic link у директорії з правами запису для користувача.
2. **Replace that name with a slow path**
- Створіть довгий компонент або ланцюжок директорій під `\BaseNamedObjects` (або іншим коренем OM з правами запису).
- Створіть символьне посилання так, щоб ім'я, якого очікує ядро, тепер відображалося на повільний шлях. Ви можете спрямувати пошук директорії вразливого драйвера на вашу структуру, не торкаючись оригінальної цілі.
3. **Trigger the race**
- Потік A (жертва) виконує вразливий код і блокується всередині повільного пошуку.
- Потік B (атакуючий) змінює захищений стан (наприклад, міняє file handle, переписує символьне посилання, переключає object security), поки Потік A зайнятий.
- Коли Потік A відновлюється і виконує привілейовану дію, він бачить застарілий стан і виконує операцію, керовану атакуючим.
4. **Clean up** – Видаліть ланцюжок директорій і символьні посилання, щоб уникнути залишення підозрілих артефактів або порушення роботи легітимних користувачів IPC.

## Operational considerations

- **Combine primitives** – Ви можете використовувати довге ім'я на кожному рівні в ланцюжку директорій для ще більшої затримки, поки не вичерпаєте розмір `UNICODE_STRING`.
- **One-shot bugs** – Розширене вікно (від десятків мікросекунд до хвилин) робить «single trigger» баги реалістичними у поєднанні з CPU affinity pinning або hypervisor-assisted preemption.
- **Side effects** – Усповільнення впливає лише на шкідливий шлях, тому загальна продуктивність системи залишається неушкодженою; захисники рідко помітять це, якщо не відстежують зростання простору імен.
- **Cleanup** – Зберігайте дескриптори для кожної створеної директорії/об’єкта, щоб потім викликати `NtMakeTemporaryObject`/`NtClose`. Інакше необмежені ланцюжки директорій можуть зберігатися після перезавантаження.

## Defensive notes

- Код ядра, який покладається на іменовані об'єкти, повинен повторно перевіряти критичний для безпеки стан *після* open, або взяти reference перед перевіркою (закриваючи діру TOCTOU).
- Встановлюйте верхні межі на глибину/довжину шляху OM перед розіменуванням user-controlled імен. Відхилення надто довгих імен змушує атакуючих повернутися до мікросекундного вікна.
- Інструментуйте зростання простору імен object manager (ETW `Microsoft-Windows-Kernel-Object`), щоб виявляти підозрілі ланцюжки з тисяч компонентів під `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
