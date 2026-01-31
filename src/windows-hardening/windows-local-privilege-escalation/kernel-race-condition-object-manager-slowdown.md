# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Чому розширення вікна гонки має значення

Багато Windows kernel LPEs дотримуються класичного шаблону `check_state(); NtOpenX("name"); privileged_action();`. На сучасному обладнанні холодний виклик `NtOpenEvent`/`NtOpenSection` вирішує коротке ім'я приблизно за ~2 µs, залишаючи майже ніякого часу, щоб змінити перевірений стан до виконання захищеної дії. Навмисне затягування пошуку в Object Manager Namespace (OMNS) на кроку 2 до десятків мікросекунд дає зловмиснику достатньо часу, щоб стабільно вигравати інакше ненадійні гонки без потреби в тисячах спроб.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Імена, такі як `\BaseNamedObjects\Foo`, розв'язуються каталог за каталогом. Кожний компонент змушує kernel знайти/відкрити *Object Directory* і виконати порівняння Unicode strings. Symbolic links (наприклад, літери дисків) можуть бути пройдені по шляху.
* **UNICODE_STRING limit** – OM paths передаються всередині `UNICODE_STRING`, чиє поле `Length` є 16‑бітовим значенням. Абсолютний ліміт — 65 535 байт (32 767 UTF-16 codepoints). З префіксами на кшталт `\BaseNamedObjects\` атакауючий все ще контролює ≈32 000 символів.
* **Attacker prerequisites** – Будь‑який користувач може створювати об'єкти під записуваними каталогами, такими як `\BaseNamedObjects`. Коли вразливий код використовує ім'я всередині або слідує symbolic link, що потрапляє туди, зловмисник контролює продуктивність пошуку без спеціальних привілеїв.

## Slowdown primitive #1 – Single maximal component

Вартість розв'язання компонента приблизно лінійно залежить від його довжини, оскільки kernel має виконати Unicode‑порівняння з кожним записом у батьківському каталозі. Створення event з ім'ям довжиною 32 kB одразу збільшує latency `NtOpenEvent` з ~2 µs до ~35 µs на Windows 11 24H2 (тестова платформа Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Практичні нотатки*

- Ви можете досягти обмеження довжини, використовуючи будь-який named kernel object (events, sections, semaphores…).
- Symbolic links або reparse points можуть вказувати коротке “victim” ім'я на цей гігантський компонент, тож уповільнення застосовується прозоро.
- Оскільки все розміщено в user-writable namespaces, payload працює з рівня standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Більш агресивний варіант виділяє ланцюг з тисяч директорій (`\BaseNamedObjects\A\A\...\X`). Кожен крок викликає логіку розв'язання директорій (ACL checks, hash lookups, reference counting), тому затримка на рівень вища, ніж при одному string compare. При ~16 000 рівнях (обмежено тією ж `UNICODE_STRING` розміром), емпіричні заміри перевищують бар'єр 35 µs, досягнутий довгими одиночними компонентами.
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

* Alternate the character per level (`A/B/C/...`) if the parent directory starts rejecting duplicates.
* Keep a handle array so you can delete the chain cleanly after exploitation to avoid polluting the namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (хвилини замість мікросекунд)

Директорії об'єктів підтримують **shadow directories** (fallback lookups) та хеш-таблиці, розбиті на бакети для записів. Зловживайте обома разом із 64-component symbolic-link reparse limit, щоб примножити уповільнення, не перевищуючи довжини `UNICODE_STRING`:

1. Create two directories under `\BaseNamedObjects`, e.g. `A` (shadow) and `A\A` (target). Create the second using the first as the shadow directory (`NtCreateDirectoryObjectEx`), so missing lookups in `A` fall through to `A\A`.
2. Fill each directory with thousands of **colliding names** that land in the same hash bucket (e.g., varying trailing digits while keeping the same `RtlHashUnicodeString` value). Lookups now degrade to O(n) linear scans inside a single directory.
3. Build a chain of ~63 **object manager symbolic links** that repeatedly reparse into the long `A\A\…` suffix, consuming the reparse budget. Each reparse restarts parsing from the top, multiplying the collision cost.
4. Lookup of the final component (`...\\0`) now takes **minutes** on Windows 11 when 16 000 collisions are present per directory, providing a practically guaranteed race win for one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Чому це важливо*: Хвилинне уповільнення перетворює one-shot race-based LPEs на детерміновані exploits.

## Вимірювання вашого race window

Вбудуйте короткий тестовий код у свій exploit, щоб виміряти, наскільки великим стає вікно на апаратному забезпеченні жертви. Фрагмент нижче відкриває цільовий об'єкт `iterations` разів і повертає середню вартість на одне відкриття, використовуючи `QueryPerformanceCounter`.
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
Результати безпосередньо враховуються у вашій race orchestration strategy (наприклад, кількість worker threads, необхідні sleep intervals, як рано потрібно flip the shared state).

## Потік експлуатації

1. **Locate the vulnerable open** – Прослідкуйте шлях у kernel (через symbols, ETW, hypervisor tracing або reversing), доки не знайдете виклик `NtOpen*`/`ObOpenObjectByName`, який обходить ім'я, контрольоване атакуючим, або символічне посилання в директорії, доступній для запису користувачем.
2. **Replace that name with a slow path**
- Створіть довгий компонент або ланцюжок директорій під `\BaseNamedObjects` (або іншим записуваним OM root).
- Створіть символічне посилання так, щоб ім'я, яке очікує kernel, тепер резолвилось на повільний шлях. Ви можете спрямувати пошук директорій вразливого драйвера на вашу структуру, не торкаючись початкової цілі.
3. **Trigger the race**
- Thread A (victim) виконує вразливий код і блокується всередині повільного пошуку.
- Thread B (attacker) flips the guarded state (наприклад, swaps a file handle, rewrites a symbolic link, toggles object security) поки Thread A зайнятий.
- Коли Thread A відновлюється і виконує привілейовану дію, вона бачить застарілий стан і виконує операцію під контролем атакуючого.
4. **Clean up** – Видаліть ланцюжок директорій і символічні посилання, щоб не залишати підозрілих артефактів або не порушити роботу легітимних користувачів IPC.

## Операційні міркування

- **Combine primitives** – Ви можете використовувати довге ім'я *на кожному рівні* ланцюжка директорій для ще більшої затримки, поки не вичерпаєте розмір `UNICODE_STRING`.
- **One-shot bugs** – Розширене вікно (від десятків мікросекунд до хвилин) робить «single trigger» баги реалістичними при поєднанні з CPU affinity pinning або hypervisor-assisted preemption.
- **Side effects** – Уповільнення впливає лише на шкідливий шлях, тому загальна продуктивність системи залишається незмінною; захисники рідко помітять це, якщо тільки не відстежують namespace growth.
- **Cleanup** – Зберігайте дескриптори (handles) для кожної створеної директорії/об'єкта, щоб пізніше викликати `NtMakeTemporaryObject`/`NtClose`. Інакше незаконтрольовані ланцюжки директорій можуть зберігатися після перезавантаження.

## Нотатки щодо захисту

- Код ядра, який покладається на named objects, повинен повторно перевіряти стан, критичний для безпеки, *після* open, або отримати reference перед перевіркою (закриваючи вікно TOCTOU).
- Встановлюйте верхні обмеження на глибину/довжину OM path перед дереференсуванням імен, контрольованих користувачем. Відхилення надто довгих імен примушує атакуючих повертатися в мікросекундне вікно.
- Інструментуйте зростання простору імен object manager (ETW `Microsoft-Windows-Kernel-Object`), щоб виявляти підозрілі ланцюжки з тисяч компонентів під `\BaseNamedObjects`.

## Посилання

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
