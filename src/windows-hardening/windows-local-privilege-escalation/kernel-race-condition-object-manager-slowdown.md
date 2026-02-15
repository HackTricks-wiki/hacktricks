# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Чому розширення вікна гонки має значення

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. На сучасному обладнанні холодний `NtOpenEvent`/`NtOpenSection` вирішує коротке ім'я приблизно за ~2 µs, залишаючи майже ніякого часу, щоб змінити перевірений стан перед виконанням захищеної дії. Навмисно змусивши Object Manager Namespace (OMNS) lookup у кроці 2 займати десятки мікросекунд, атакуючий отримує достатньо часу, щоб послідовно вигравати інакше ненадійні гонки без потреби в тисячах спроб.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Імена на кшталт `\BaseNamedObjects\Foo` розв'язуються директорія за директорією. Кожен компонент змушує kernel знаходити/відкривати *Object Directory* і порівнювати Unicode strings. По дорозі можуть проходитися symbolic links (наприклад, букви дисків).
* **UNICODE_STRING limit** – OM шляхи переносяться всередині `UNICODE_STRING`, чиє поле `Length` має 16-бітне значення. Абсолютний ліміт — 65 535 байт (32 767 UTF-16 кодових точок). З префіксами на кшталт `\BaseNamedObjects\` атакуючий все ще контролює ≈32 000 символів.
* **Attacker prerequisites** – Будь-який користувач може створювати об'єкти під записуваними директоріями, такими як `\BaseNamedObjects`. Коли вразливий код використовує ім'я всередині або слідує symbolic link, що веде туди, атакуючий контролює продуктивність lookup без спеціальних привілеїв.

## Slowdown primitive #1 – Single maximal component

Вартість розв'язування одного компонента приблизно лінійно залежить від його довжини, оскільки kernel повинен виконати Unicode comparison проти кожного запису в батьківській директорії. Створення event з іменем довжиною 32 kB відразу збільшує latency `NtOpenEvent` з ~2 µs до ~35 µs на Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Практичні нотатки*

- Ви можете досягти ліміту довжини, використовуючи будь-який named kernel object (events, sections, semaphores…).
- Symbolic links або reparse points можуть спрямувати коротке «victim» ім'я на цей гігантський компонент, тож уповільнення застосовується прозоро.
- Оскільки все розміщено в user-writable namespaces, payload працює з рівня standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Більш агресивний варіант виділяє ланцюжок із тисяч директорій (`\BaseNamedObjects\A\A\...\X`). Кожен крок запускає directory resolution logic (ACL checks, hash lookups, reference counting), тому затримка на рівень вища, ніж при порівнянні одного рядка. При ~16 000 рівнях (обмежених тим же `UNICODE_STRING`), емпіричні вимірювання перевищують бар'єр 35 µs, досягнутий довгими одиночними компонентами.
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

* Чергуйте символ на кожному рівні (`A/B/C/...`), якщо батьківська директорія починає відкидати дублікати.
* Тримайте handle array, щоб після експлуатації коректно видалити ланцюжок і не засмічувати namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (хвилини замість мікросекунд)

Директорії об'єктів підтримують **shadow directories** (fallback lookups) та bucketed hash tables для записів. Зловживайте обома і додайте 64-компонентне symbolic-link reparse limit, щоб множити уповільнення без перевищення довжини `UNICODE_STRING`:

1. Створіть дві директорії під `\BaseNamedObjects`, наприклад `A` (shadow) і `A\A` (target). Другу створіть, використовуючи першу як shadow directory (`NtCreateDirectoryObjectEx`), щоб відсутні пошуки в `A` переходили до `A\A`.
2. Заповніть кожну директорію тисячами **colliding names**, що потрапляють у ту саму хеш-кошик (наприклад, варіюючи кінцеві цифри, зберігаючи те саме значення `RtlHashUnicodeString`). Пошуки тепер деградують до O(n) лінійного сканування всередині однієї директорії.
3. Побудуйте ланцюжок з ~63 **object manager symbolic links**, які багаторазово reparse у довгий суфікс `A\A\…`, витрачаючи reparse budget. Кожний reparse перезапускає розбір зверху, множачи вартість колізій.
4. Пошук останнього компонента (`...\\0`) тепер займає **хвилини** у Windows 11, коли в кожній директорії присутні 16 000 колізій, що практично гарантує виграш у race для one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Чому це важливо*: Хвилинне уповільнення перетворює one-shot race-based LPEs на детерміністичні експлойти.

### 2025 примітки повторного тестування та готові інструменти

- James Forshaw повторно опублікував техніку з оновленими таймінгами для Windows 11 24H2 (ARM64). Базовий час відкриття залишається ~2 µs; компонент 32 kB підвищує його до ~35 µs, а shadow-dir + collision + 63-reparse chains все ще досягають ~3 minutes, що підтверджує, що primitives переживають поточні збірки. Вихідний код і perf harness знаходяться в оновленому пості Project Zero.
- Ви можете скриптувати налаштування, використовуючи публічний бандл `symboliclink-testing-tools`: `CreateObjectDirectory.exe` для створення пари shadow/target та `NativeSymlink.exe` у циклі для емісії 63-hop chain. Це уникає ручних обгорток `NtCreate*` і зберігає ACLs послідовними.

## Вимірювання вашого race window

Вбудуйте швидкий harness у свій exploit, щоб виміряти, наскільки велике вікно на обладнанні жертви. Наведений нижче фрагмент відкриває target object `iterations` разів і повертає середню вартість одного відкриття, використовуючи `QueryPerformanceCounter`.
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
Результати безпосередньо feed-ять у вашу стратегію оркестрації race (наприклад, кількість worker threads, інтервали очікування, як рано потрібно flip-нути спільний стан).

## Робочий процес експлуатації

1. **Знайдіть вразливий open** – Прослідкуйте kernel path (через symbols, ETW, hypervisor tracing або reversing), доки не знайдете виклик `NtOpen*`/`ObOpenObjectByName`, який обходить ім'я, контрольоване атакуючим, або symbolic link у директорії з правом запису для користувача.
2. **Замініть це ім'я на повільний шлях**
- Створіть довгий компонент або ланцюжок директорій під `\BaseNamedObjects` (або іншим коренем OM з правами запису).
- Створіть symbolic link так, щоб ім'я, яке очікує kernel, тепер резолвилося в повільний шлях. Ви можете спрямувати directory lookup вразливого драйвера на вашу структуру, не торкаючись оригінальної цілі.
3. **Спровокуйте race**
- Thread A (жертва) виконує вразливий код і блокується всередині повільного lookup.
- Thread B (атакуючий) flip-ає guarded state (наприклад, міняє file handle, перезаписує symbolic link, переключає object security), поки Thread A зайнятий.
- Коли Thread A відновлює роботу і виконує привілейовану дію, воно спостерігає застарілий стан і виконує операцію, контрольовану атакуючим.
4. **Очищення** – Видаліть ланцюжок директорій і symbolic links, щоб не залишати підозрілих артефактів або не порушувати легітимних користувачів IPC.

## Операційні міркування

- **Комбінуйте примітиви** – Ви можете використовувати довге ім'я *на кожному рівні* ланцюжка директорій для ще більшої латентності до вичерпання розміру `UNICODE_STRING`.
- **One-shot bugs** – Розширене вікно (від десятків мікросекунд до хвилин) робить «single trigger» баги реалістичними в поєднанні з прив'язкою CPU affinity або препреемпцією за допомогою hypervisor.
- **Побічні ефекти** – Уповільнення впливає лише на зловмисний шлях, тому загальна продуктивність системи залишається незмінною; захисники рідко помітять це, якщо не моніторять зростання namespace.
- **Очищення** – Тримайте handles на кожну директорію/об'єкт, який ви створили, щоб потім викликати `NtMakeTemporaryObject`/`NtClose`. Інакше необмежені ланцюжки директорій можуть зберігатися після перезавантаження.
- **File-system races** – Якщо вразливий шлях врешті-решт резолвиться через NTFS, ви можете поставити Oplock (наприклад, `SetOpLock.exe` з того ж набору інструментів) на backing file, поки працює OM slowdown, заморожуючи consumer ще на додаткові мілісекунди без зміни графа OM.

## Захисні нотатки

- Код ядра, що покладається на named objects, має повторно валідовувати стан, чутливий до безпеки, *після* open, або брати reference перед перевіркою (закриваючи TOCTOU-прогалину).
- Встановлюйте верхні межі глибини/довжини шляху OM перед dereferencing імен, контрольованих користувачем. Відхилення надто довгих імен змушує атакувальників повертатися в мікросекундне вікно.
- Інструментуйте зростання namespace object manager (ETW `Microsoft-Windows-Kernel-Object`) для виявлення підозрілих ланцюжків з тисяч компонентів під `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
