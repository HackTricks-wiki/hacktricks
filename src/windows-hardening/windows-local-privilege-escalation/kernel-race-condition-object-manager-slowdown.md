# Експлуатація race condition ядра через повільні шляхи Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Чому важливо розширити вікно гонки

Багато Windows kernel LPE слідують класичному шаблону `check_state(); NtOpenX("name"); privileged_action();`. На сучасному обладнанні холодний `NtOpenEvent`/`NtOpenSection` вирішує коротке ім'я приблизно за ~2 µs, залишаючи майже ніякого часу, щоб змінити перевірений стан до того, як відбудеться захищена дія. Навмисно змусивши пошук Object Manager Namespace (OMNS) у кроці 2 займати десятки мікросекунд, атакуючий отримує достатньо часу, щоб послідовно вигравати інакше нестабільні гонки без потреби в тисячах спроб.

## Внутрішня робота пошуку Object Manager — коротко

* **OMNS structure** – Імена, такі як `\BaseNamedObjects\Foo`, розв'язуються директорія за директорією. Кожен компонент змушує ядро знаходити/відкривати *Object Directory* і виконувати порівняння Unicode-рядків. Можуть також бути пройдені символічні посилання (наприклад, букви дисків).
* **UNICODE_STRING limit** – OM шляхи переноситься всередині `UNICODE_STRING`, у якого `Length` є 16-бітним значенням. Абсолютний ліміт — 65 535 байтів (32 767 UTF-16 кодових точок). З префіксами на кшталт `\BaseNamedObjects\` атакуючий все ще контролює ≈32 000 символів.
* **Attacker prerequisites** – Будь-який користувач може створювати об'єкти всередині записуваних директорій, таких як `\BaseNamedObjects`. Коли вразливий код використовує ім'я всередині або слідує за символічним посиланням, яке веде туди, атакуючий контролює продуктивність пошуку без особливих привілеїв.

## Slowdown primitive #1 – Single maximal component

Вартість розв'язування компонента приблизно лінійно залежить від його довжини, оскільки ядро має виконати Unicode-порівняння з кожним записом у батьківській директорії. Створення event з іменем довжиною 32 kB одразу збільшує затримку `NtOpenEvent` з ~2 µs до ~35 µs на Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Практичні нотатки*

- Ви можете досягти обмеження довжини, використовуючи будь-який іменований kernel object (events, sections, semaphores…).
- Symbolic links or reparse points можуть вказувати коротке “victim” ім'я на цей гігантський компонент, тож the slowdown застосовується прозоро.
- Через те, що все знаходиться в user-writable namespaces, payload працює з рівня стандартного user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Більш агресивний варіант виділяє ланцюжок з тисяч каталогів (`\BaseNamedObjects\A\A\...\X`). Кожен перехід запускає логіку розв'язання директорій (ACL checks, hash lookups, reference counting), тому затримка на рівень вища, ніж при порівнянні одного рядка. При ~16 000 рівнях (обмежених тим же `UNICODE_STRING` розміром) емпіричні заміри перевищують межу в 35 µs, досягнуту довгими одиночними компонентами.
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

* Чергуйте символ на кожному рівні (`A/B/C/...`), якщо батьківський каталог починає відхиляти дублікати.
* Тримайте handle array, щоб можна було чисто видалити ланцюжок після exploitation і не засмічувати простір імен.

## Вимірювання вашого race window

Вбудуйте невеликий тестовий механізм всередину свого exploit, щоб виміряти, наскільки велике стає вікно на апаратному забезпеченні жертви. Фрагмент нижче відкриває цільовий об'єкт `iterations` разів і повертає середню вартість одного відкриття за допомогою `QueryPerformanceCounter`.
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
Результати прямо впливають на вашу стратегію оркестрації гонки (наприклад, кількість робочих потоків, інтервали сну, наскільки рано потрібно змінити спільний стан).

## Робочий процес експлуатації

1. **Locate the vulnerable open** – Прослідкуйте шлях у kernel (через symbols, ETW, hypervisor tracing або reversing), поки не знайдете виклик `NtOpen*`/`ObOpenObjectByName`, який обходить ім'я, контрольоване атакувальником, або символічне посилання в директорії з правами запису для користувача.
2. **Replace that name with a slow path**
- Створіть довгий компонент або ланцюжок директорій під `\BaseNamedObjects` (або іншою записуваною OM root).
- Створіть символічне посилання так, щоб ім'я, яке очікує kernel, тепер резолвилось у повільний шлях. Ви можете спрямувати пошук директорії в уразливому драйвері на вашу структуру, не чіпаючи оригінальну ціль.
3. **Trigger the race**
- Thread A (victim) виконує уразливий код і блокується всередині повільного пошуку.
- Thread B (attacker) змінює захищений стан (наприклад, замінює файловий дескриптор, перезаписує символічне посилання, перемикає налаштування безпеки об'єкта), поки Thread A зайнятий.
- Коли Thread A відновлюється і виконує привілейовану дію, він бачить застарілий стан і виконує операцію під контролем атакувальника.
4. **Clean up** – Видаліть ланцюжок директорій і символічні посилання, щоб не залишати підозрілих артефактів або не ламати легітимних користувачів IPC.

## Операційні зауваження

- **Combine primitives** – Ви можете використовувати довге ім'я на *кожному рівні* в ланцюжку директорій для ще більшої затримки, поки не вичерпаєте розмір `UNICODE_STRING`.
- **One-shot bugs** – Розширене вікно (десятки мікросекунд) робить «single trigger» баги реалістичними в поєднанні з закріпленням CPU affinity або витісненням за допомогою гіпервізора.
- **Side effects** – Сповільнення впливає лише на шкідливий шлях, тож загальна продуктивність системи залишається незмінною; захисники рідко помітять його, якщо не відстежують зростання простору імен.
- **Cleanup** – Тримайте дескриптори до кожної створеної директорії/об'єкта, щоб потім викликати `NtMakeTemporaryObject`/`NtClose`. Інакше необмежені ланцюжки директорій можуть зберігатися після перезавантаження.

## Захисні зауваження

- Kernel-код, який покладається на named objects, повинен повторно перевіряти стан, критичний для безпеки, *після* open, або брати референс перед перевіркою (закриваючи TOCTOU-прогалину).
- Застосовуйте верхні межі для глибини/довжини OM-пути перед роздереференсуванням імен, контрольованих користувачем. Відхилення надто довгих імен змушує атакуючих повертатися в мікросекундне вікно.
- Інструментуйте зростання простору імен object manager (ETW `Microsoft-Windows-Kernel-Object`), щоб виявляти підозрілі ланцюжки з тисячами компонентів під `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
