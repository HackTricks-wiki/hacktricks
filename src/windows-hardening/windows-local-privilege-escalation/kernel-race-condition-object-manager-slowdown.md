# Експлуатація Race Condition у kernel через Slow Paths Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Чому важливо розтягувати race window

Багато Windows kernel LPE відповідають класичному шаблону `check_state(); NtOpenX("name"); privileged_action();`. На сучасному hardware холодний `NtOpenEvent`/`NtOpenSection` розв’язує коротке ім’я приблизно за ~2 µs, залишаючи майже нуль часу, щоб змінити перевірений стан до виконання secure action. Навмисно змушуючи пошук в Object Manager Namespace (OMNS) на кроці 2 тривати десятки мікросекунд, attacker отримує достатньо часу, щоб стабільно вигравати інакше нестабільні race без необхідності виконувати тисячі спроб.<sup>[[1]](#references)</sup>

## Внутрішня будова пошуку Object Manager у двох словах

* **Структура OMNS** – Імена на кшталт `\BaseNamedObjects\Foo` розв’язуються directory за directory. Кожен компонент змушує kernel знайти/відкрити *Object Directory* і порівняти Unicode strings. На цьому шляху можуть проходитися symbolic links (наприклад, drive letters).
* **Обмеження UNICODE_STRING** – OM paths зберігаються в `UNICODE_STRING`, поле `Length` якого має 16-бітне значення. Абсолютний ліміт становить 65 535 bytes (32 767 UTF-16 codepoints). З префіксами на кшталт `\BaseNamedObjects\` attacker усе ще контролює приблизно 32 000 characters.
* **Передумови для attacker** – Будь-який user може створювати objects у writable directories, таких як `\BaseNamedObjects`. Коли vulnerable code використовує ім’я всередині такої directory або переходить за symbolic link, який веде туди, attacker контролює performance lookup без special privileges.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Один maximal component

Вартість розв’язання component приблизно лінійно залежить від його довжини, оскільки kernel має виконати Unicode comparison з кожним entry у parent directory. Створення event з іменем довжиною 32 kB одразу збільшує latency `NtOpenEvent` приблизно з ~2 µs до ~35 µs у Windows 11 24H2 (testbed Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Практичні нотатки*

- Досягти обмеження довжини можна за допомогою будь-якого іменованого kernel object (events, sections, semaphores…).
- Symbolic links або reparse points можуть вказувати коротке ім’я «victim» на цей гігантський компонент, тому slowdown застосовується прозоро.
- Оскільки все розміщено в namespace, доступних для запису користувачем, payload працює зі стандартним user integrity level.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Глибоко рекурсивні директорії

Агресивніший варіант виділяє ланцюжок із тисяч директорій (`\BaseNamedObjects\A\A\...\X`). Кожен перехід запускає логіку пошуку директорій (перевірки ACL, пошук у hash-таблицях, підрахунок reference), тому затримка на кожному рівні вища, ніж під час одного порівняння рядків. Приблизно на 16 000 рівнях (обмежених тим самим розміром `UNICODE_STRING`) емпіричні вимірювання перевищують бар’єр у 35 µs, досягнутий за допомогою довгих окремих компонентів.
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

* Чергуйте символи для кожного рівня (`A/B/C/...`), якщо батьківський каталог починає відхиляти дублікати.
* Зберігайте масив дескрипторів, щоб після exploitation коректно видалити весь ланцюжок і не забруднювати namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (хвилини замість мікросекунд)

Object directories підтримують **shadow directories** (fallback lookups) і хеш-таблиці з bucket'ами для записів. Використайте обидва механізми разом із лімітом у 64 компоненти для symbolic-link reparse, щоб збільшити slowdown, не перевищуючи довжину `UNICODE_STRING`:

1. Створіть два каталоги під `\BaseNamedObjects`, наприклад `A` (shadow) і `A\A` (target). Створіть другий, використавши перший як shadow directory (`NtCreateDirectoryObjectEx`), щоб відсутні lookup'и в `A` переходили до `A\A`.
2. Заповніть кожен каталог тисячами **colliding names**, які потрапляють до одного hash bucket (наприклад, змінюючи кінцеві цифри, але зберігаючи те саме значення `RtlHashUnicodeString`). Тепер lookup'и деградують до лінійного сканування O(n) всередині одного каталогу.
3. Побудуйте ланцюжок приблизно з 63 **object manager symbolic links**, які повторно виконують reparse до довгого суфікса `A\A\…`, витрачаючи reparse budget. Кожен reparse починає parsing згори, множачи вартість collision.
4. Lookup фінального компонента (`...\\0`) тепер триває **хвилини** у Windows 11, коли в кожному каталозі присутні 16 000 collisions, забезпечуючи практично гарантовану перемогу в race для одноразових kernel LPE.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Чому це важливо*: Уповільнення на кілька хвилин перетворює одноразові race-based LPE на детерміновані експлойти.<sup>[[1]](#references)</sup>

### Нотатки повторного тестування у 2025 році та готові інструменти

- James Forshaw повторно опублікував техніку з оновленими значеннями часу для Windows 11 24H2 (ARM64). Базове відкриття все ще займає приблизно 2 µs; компонент розміром 32 kB збільшує цей показник приблизно до 35 µs, а shadow-dir + collision + ланцюжки з 63 reparse усе ще дають змогу досягти приблизно 3 хвилин, підтверджуючи, що примітиви працюють і в поточних збірках. Вихідний код і perf harness доступні в оновленій публікації Project Zero.<sup>[[1]](#references)</sup>
- Налаштування можна автоматизувати за допомогою загальнодоступного пакета `symboliclink-testing-tools`: `CreateObjectDirectory.exe` створює пару shadow/target, а `NativeSymlink.exe` у циклі генерує ланцюжок із 63 переходів. Це усуває потребу вручну писати обгортки `NtCreate*` і забезпечує узгоджені ACL.<sup>[[2]](#references)</sup>

## Вимірювання вашого race window

Вбудуйте швидкий harness у свій експлойт, щоб виміряти, наскільки великим стає вікно на апаратному забезпеченні жертви. Наведений нижче фрагмент `iterations` разів відкриває цільовий об’єкт і повертає середню вартість одного відкриття за допомогою `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Результати безпосередньо впливають на вашу стратегію orchestration перегонів (наприклад, на кількість потрібних worker threads, інтервали sleep і те, наскільки рано потрібно змінити спільний стан).

## Workflow експлуатації

1. **Знайдіть вразливе відкриття** – простежте шлях у kernel (за допомогою symbols, ETW, hypervisor tracing або reverse engineering), доки не знайдете виклик `NtOpen*`/`ObOpenObjectByName`, який обходить ім’я під контролем attacker або symbolic link у каталозі, доступному для запису користувачем.
2. **Замініть це ім’я на slow path**
- Створіть довгий component або ланцюжок каталогів у `\BaseNamedObjects` (або іншому доступному для запису OM root).
- Створіть symbolic link, щоб ім’я, яке очікує kernel, тепер розгорталося в slow path. Ви можете спрямувати пошук каталогу вразливого driver до своєї структури, не змінюючи початковий target.
3. **Запустіть race**
- Thread A (victim) виконує вразливий код і блокується всередині slow lookup.
- Thread B (attacker) змінює захищений стан (наприклад, замінює file handle, переписує symbolic link або перемикає object security), поки Thread A зайнятий.
- Коли Thread A продовжує роботу та виконує privileged action, він бачить застарілий стан і виконує operation під контролем attacker.
4. **Виконайте очищення** – видаліть ланцюжок каталогів і symbolic links, щоб не залишати підозрілих артефактів і не порушувати роботу легітимних IPC-користувачів.<sup>[[1]](#references)</sup>

## Практичний ланцюжок: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), опублікований як bypass для RoguePlanet (CVE-2026-50656), демонструє ширший exploitation pattern: змусити privileged scanner класифікувати одне представлення логічного файлу, а потім змінити і його bytes, і namespace resolution до того, як remediation скористається ним. PoC поєднує Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, захоплення CLFS-generated-name і local administrative-share link, щоб перетворити очищення Defender на запис захищеної DLL.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Замініть вміст через Cloud Files hydration

Зареєструйте каталог, доступний для запису attacker, як Cloud Files sync root, підключіть callback `CF_CALLBACK_TYPE_FETCH_DATA` і створіть placeholder, оголошений розмір якого відповідає детермінованому detection trigger, наприклад EICAR ZIP. Перший fetch повертає trigger і перемикає стан callback; наступні fetch повертають payload. Після того як scanner класифікує перше представлення, отримайте transfer key і перезапустіть hydration із metadata розміром payload, а потім примусово доведіть hydration до EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
Межа безпеки не працює, якщо scan, verdict і remediation посилаються лише на pathname або placeholder identity: жоден із них не гарантує, що подальша hydration поверне bytes, які було inspected.<sup>[[4]](#references)</sup>

### 2. Перемкнути invariant path через shadow-directory fallback

Створіть цільову директорію Object Manager і другу директорію за допомогою `NtCreateDirectoryObjectEx`, передавши handle цільової директорії як її shadow/fallback directory. Додайте однойменний запис `WD_SCAN` в обидва шари resolution: видимий запис вказує на звичайну робочу директорію, тоді як fallback-запис вказує на `\CLFS\??\<working-directory>`. Передайте Defender лише наведену нижче invariant path; видалення видимого посилання, поки операція активна, змусить той самий string перейти до CLFS-backed entry.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Це відрізняється від використання shadow directories лише для сповільнення пошуку: attacker змінює **значення** раніше прийнятого шляху, не змінюючи його рядок.<sup>[[4]](#references)</sup>

### 3. Перехопіть згенероване ім’я та встановіть посилання, специфічне для filename

Відстежуйте робочий каталог за допомогою `ReadDirectoryChangesW`. Після першого `FILE_ACTION_ADDED` видаліть видиме посилання `WD_SCAN`, щоб активувати fallback lookup. Перехопіть друге згенероване filename, відкрийте пов’язаний із CLFS файл і заблокуйте діапазон `0..MAXLONGLONG` за допомогою `LockFileEx`. Поки privileged operation призупинена, замініть `WD_SCAN` у видимому каталозі на справжній каталог Object Manager і створіть дочірнє symbolic link з ім’ям, отриманим із перехопленого filename (PoC видаляє його останні чотири символи). Спрямуйте його до захищеного призначення через local SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Непривілейований процес не може самостійно записати цей об’єкт призначення, але контекст SYSTEM у Defender може пройти через адміністративну loopback-шару. Поєднання спостереження за згенерованими іменами з Object Manager link, специфічним для імені файлу, усуває необхідність заздалегідь передбачати артефакт remediation.<sup>[[4]](#references)</sup>

### 4. Стабілізація race під час очищення та запуск привілейованого loader

Перед скануванням PoC зберігає коректний PE (`ntdll.dll`) у NTFS alternate data stream `:stream` заповнювача. Після того як redirection створює захищений базовий файл, він відкриває `phoneinfo.dll:stream` з execute-доступом і підтримує активним mapping `PAGE_EXECUTE_READ | SEC_IMAGE`, поки cleanup продовжується; активні file/section objects обмежують видалення або заміну під час фінального race. Тепер перезапущена hydration повертає payload DLL замість EICAR, тому захищений базовий файл містить код, контрольований attacker.<sup>[[4]](#references)</sup>

Потім захищений запис перетворюється на виконання від імені SYSTEM шляхом розміщення створеного `Report.wer` у `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` і виклику `\Microsoft\Windows\Windows Error Reporting\QueueReporting` через Task Scheduler COM API. У цьому ланцюжку привілейована обробка WER завантажує розміщений `C:\Windows\System32\phoneinfo.dll`; підключення до named pipe використовується як сигнал виконання payload.<sup>[[4]](#references)</sup>

### Поворотні точки для виявлення

Корисні кореляції є специфічнішими за будь-яке окреме тимчасове ім’я та охоплюють усі переходи між namespace у цьому ланцюжку:<sup>[[4]](#references)</sup>

- Щойно зареєстрований Cloud Files provider, після якого на тому самому placeholder виявляється EICAR і виконується `CF_OPERATION_TYPE_RESTART_HYDRATION`.
- Шляхи Object Manager, що містять `WD_TARGET_*`, `WD_SHADOW_*` або `WD_SCAN`, особливо шлях сканування нижче `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Створення файлу CLFS, після якого встановлюється ексклюзивне блокування всього файлу та виконується loopback-доступ до `\\127.0.0.1\C$\Windows\System32\*.dll` із привілейованого security process.
- Створення DLL у System32 разом із NTFS ADS, після чого виконується mapping потоку через `SEC_IMAGE`.
- Створений attacker запис у WER queue, після якого відбувається нетиповий ручний запуск `\Microsoft\Windows\Windows Error Reporting\QueueReporting` і завантаження образу розміщеної DLL.

## Операційні міркування

- **Поєднання primitive** – Можна використовувати довге ім’я *на кожному рівні* ланцюжка каталогів, щоб ще більше збільшити latency, доки не буде вичерпано розмір `UNICODE_STRING`.
- **One-shot bugs** – Розширене вікно (від десятків мікросекунд до хвилин) робить “single trigger” bugs реалістичними в поєднанні з фіксацією CPU affinity або preemption за допомогою hypervisor.
- **Побічні ефекти** – Уповільнення впливає лише на malicious path, тому загальна продуктивність системи не змінюється; defenders рідко це помітять, якщо не відстежують зростання namespace.
- **Очищення** – Зберігайте handles до кожного створеного каталогу/object, щоб після цього викликати `NtMakeTemporaryObject`/`NtClose`. В іншому разі необмежені ланцюжки каталогів можуть зберігатися після перезавантажень.
- **File-system races** – Якщо вразливий path зрештою проходить через NTFS, можна встановити Oplock (наприклад, `SetOpLock.exe` з того самого toolkit) на backing file, поки працює OM slowdown, заморозивши consumer ще на кілька мілісекунд без зміни OM graph.<sup>[[2]](#references)</sup>

## Захисні примітки

- Kernel code, що покладається на named objects, має повторно перевіряти security-sensitive state *після* open або отримувати reference до перевірки (усуваючи TOCTOU gap).
- Встановлюйте верхні межі для depth/length шляхів OM перед dereference імен, контрольованих користувачем. Відхилення надто довгих імен змушує attackers повернутися до microsecond window.
- Інструментуйте зростання namespace Object Manager (ETW `Microsoft-Windows-Kernel-Object`), щоб виявляти підозрілі ланцюжки з тисяч компонентів у `\BaseNamedObjects`.

## References

- [1] [Project Zero – Методи експлуатації Windows: перемога в race conditions під час пошуку шляхів](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
