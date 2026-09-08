# Експлуатація Kernel Race Condition через повільні шляхи Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Чому важливо розтягувати вікно race

Багато Windows kernel LPE дотримуються класичного шаблону `check_state(); NtOpenX("name"); privileged_action();`. На сучасному обладнанні холодний `NtOpenEvent`/`NtOpenSection` знаходить коротке ім'я приблизно за 2 µs, майже не залишаючи часу, щоб змінити перевірений стан до виконання захищеної дії. Навмисно змушуючи пошук у Object Manager Namespace (OMNS) на кроці 2 тривати десятки мікросекунд, attacker отримує достатньо часу, щоб стабільно вигравати інакше ненадійні race без потреби в тисячах спроб.<sup>[[1]](#references)</sup>

## Внутрішня будова пошуку Object Manager у двох словах

* **Структура OMNS** – Імена на кшталт `\BaseNamedObjects\Foo` обробляються каталог за каталогом. Для кожного компонента kernel має знайти/відкрити *Object Directory* і порівняти Unicode-рядки. На цьому шляху можуть проходитися symbolic links (наприклад, літери дисків).
* **Обмеження UNICODE_STRING** – Шляхи OM зберігаються в `UNICODE_STRING`, чиє поле `Length` має 16-бітове значення. Абсолютний ліміт становить 65 535 байтів (32 767 кодових точок UTF-16). З префіксами на кшталт `\BaseNamedObjects\` attacker усе ще контролює приблизно 32 000 символів.
* **Передумови для attacker** – Будь-який user може створювати objects у writable directories, таких як `\BaseNamedObjects`. Коли vulnerable code використовує ім'я всередині такого каталогу або переходить за symbolic link, який веде туди, attacker контролює продуктивність пошуку без спеціальних привілеїв.<sup>[[1]](#references)</sup>

## Примітив уповільнення №1 – Один максимальний компонент

Вартість обробки компонента приблизно лінійно залежить від його довжини, оскільки kernel має виконати Unicode comparison з кожним записом у батьківському каталозі. Створення event з іменем довжиною 32 kB одразу збільшує затримку `NtOpenEvent` приблизно з 2 µs до 35 µs у Windows 11 24H2 (тестова платформа Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Практичні примітки*

- Досягти обмеження довжини можна за допомогою будь-якого іменованого kernel object (events, sections, semaphores…).
- Symbolic links або reparse points можуть вказувати коротке ім’я “victim” на цей гігантський компонент, тому slowdown застосовується прозоро.
- Оскільки все міститься в user-writable namespaces, payload працює зі стандартним user integrity level.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Глибоко вкладені каталоги

Агресивніший варіант створює ланцюжок із тисяч каталогів (`\BaseNamedObjects\A\A\...\X`). Кожен перехід запускає логіку розв’язання каталогів (перевірки ACL, пошук у hash-таблицях, підрахунок reference), тому затримка на рівень вища, ніж у разі одного порівняння рядків. Приблизно на 16 000 рівнях (обмеження визначається тим самим розміром `UNICODE_STRING`) емпіричні вимірювання перевищують бар’єр у 35 µs, досягнутий довгими одиничними компонентами.
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
* Зберігайте масив handle, щоб після експлуатації можна було коректно видалити ланцюжок і не забруднювати namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (хвилини замість мікросекунд)

Каталоги Object Manager підтримують **shadow directories** (резервні пошуки) та хеш-таблиці з bucket для записів. Зловживайте обома механізмами, а також лімітом у 64 повторних обробки symbolic link, щоб багаторазово збільшити затримку, не перевищуючи довжину `UNICODE_STRING`:

1. Створіть два каталоги під `\BaseNamedObjects`, наприклад `A` (shadow) і `A\A` (target). Створіть другий, використавши перший як shadow directory (`NtCreateDirectoryObjectEx`), щоб пошуки відсутніх об’єктів у `A` переходили до `A\A`.
2. Заповніть кожен каталог тисячами **імен із колізіями**, які потрапляють в один і той самий hash bucket (наприклад, змінюючи кінцеві цифри, зберігаючи те саме значення `RtlHashUnicodeString`). Тепер пошуки деградують до лінійного сканування O(n) в одному каталозі.
3. Побудуйте ланцюжок приблизно з 63 **symbolic links Object Manager**, які повторно виконують reparse у довгий суфікс `A\A\…`, використовуючи бюджет reparse. Кожен reparse запускає розбір шляху спочатку, багаторазово збільшуючи вартість обробки колізій.
4. Пошук фінального компонента (`...\\0`) тепер триває **хвилини** у Windows 11, коли в кожному каталозі присутні 16 000 колізій, що забезпечує практично гарантовану перемогу в race для одноразових kernel LPE.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Чому це важливо*: Уповільнення тривалістю в кілька хвилин перетворює одноразові race-based LPE на детерміновані exploits.<sup>[[1]](#references)</sup>

### Нотатки повторного тестування за 2025 рік і готові інструменти

- James Forshaw повторно опублікував техніку з оновленими таймінгами для Windows 11 24H2 (ARM64). Базове відкриття все ще займає приблизно 2 µs; компонент розміром 32 kB збільшує цей показник приблизно до 35 µs, а shadow-dir + collision + ланцюжки з 63 reparse усе ще досягають приблизно 3 хвилин, підтверджуючи, що primitives працюють і в актуальних збірках. Вихідний код і perf harness доступні в оновленому дописі Project Zero.<sup>[[1]](#references)</sup>
- Налаштування можна автоматизувати за допомогою загальнодоступного комплекту `symboliclink-testing-tools`: `CreateObjectDirectory.exe` створює пару shadow/target, а `NativeSymlink.exe` у циклі генерує ланцюжок із 63 переходів. Це усуває потребу писати власні обгортки `NtCreate*` і забезпечує узгоджені ACL.<sup>[[2]](#references)</sup>

## Вимірювання вашого race window

Вбудуйте швидкий harness у свій exploit, щоб виміряти, наскільки великим стає window на апаратному забезпеченні жертви. Наведений нижче фрагмент відкриває цільовий об’єкт `iterations` разів і повертає середню вартість одного відкриття за допомогою `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Результати безпосередньо визначають вашу стратегію оркестрації race (наприклад, необхідну кількість worker threads, інтервали sleep і те, наскільки рано потрібно змінити спільний стан).

## Процес експлуатації

1. **Знайдіть вразливий open** – простежте шлях у kernel (за допомогою symbols, ETW, hypervisor tracing або reversing), доки не знайдете виклик `NtOpen*`/`ObOpenObjectByName`, який проходить через ім’я, контрольоване атакувальником, або symbolic link у каталозі, доступному для запису користувачу.
2. **Замініть це ім’я на повільний шлях**
- Створіть довгий компонент або ланцюжок каталогів під `\BaseNamedObjects` (або в іншому доступному для запису корені OM).
- Створіть symbolic link, щоб ім’я, якого очікує kernel, тепер розв’язувалося в повільний шлях. Ви можете спрямувати пошук каталогу вразливого driver до своєї структури, не змінюючи початковий target.
3. **Запустіть race**
- Thread A (victim) виконує вразливий код і блокується всередині повільного пошуку.
- Thread B (attacker) змінює захищений стан (наприклад, замінює file handle, переписує symbolic link або перемикає security object), поки Thread A зайнятий.
- Коли Thread A продовжує виконання та виконує privileged action, він бачить застарілий стан і виконує операцію, контрольовану атакувальником.
4. **Очистіть сліди** – видаліть ланцюжок каталогів і symbolic links, щоб не залишати підозрілих артефактів і не порушувати роботу легітимних IPC-користувачів.<sup>[[1]](#references)</sup>

## Практичний ланцюжок: змінювані Cloud Files placeholders + перемикання шляхів Object Manager

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), опублікований як bypass для RoguePlanet (CVE-2026-50656), демонструє ширший шаблон експлуатації: змусити privileged scanner класифікувати одне представлення логічного файлу, а потім змінити і його bytes, і namespace resolution до того, як remediation використає цей файл. PoC поєднує Cloud Files hydration TOCTOU, fallback до shadow-directory Object Manager, захоплення CLFS-generated-name і link до local administrative-share, щоб перетворити очищення Defender на запис захищеної DLL.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Підміна вмісту через Cloud Files hydration

Зареєструйте каталог, доступний для запису атакувальнику, як Cloud Files sync root, підключіть callback `CF_CALLBACK_TYPE_FETCH_DATA` і створіть placeholder, оголошений розмір якого відповідає детермінованому detection trigger, наприклад EICAR ZIP. Перший fetch повертає trigger і змінює стан callback; наступні fetch повертають payload. Після того як scanner класифікує перше представлення, отримайте transfer key і перезапустіть hydration із metadata розміром payload, а потім примусово доведіть hydration до EOF.<sup>[[4]](#references)</sup>
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
Межа безпеки не працює, якщо scan, verdict і remediation посилаються лише на pathname або placeholder identity: жоден із них не гарантує, що подальша hydration поверне байти, які було перевірено.<sup>[[4]](#references)</sup>

### 2. Перемикання invariant path через shadow-directory fallback

Створіть цільовий каталог Object Manager і другий каталог за допомогою `NtCreateDirectoryObjectEx`, передавши handle цільового каталогу як його shadow/fallback directory. Розмістіть однойменний запис `WD_SCAN` в обох шарах resolution: видимий запис вказує на звичайний робочий каталог, тоді як fallback-запис вказує на `\CLFS\??\<working-directory>`. Передайте Defender лише наведений нижче invariant path; видалення видимого link під час активної операції змусить той самий рядок перейти до CLFS-backed entry.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Це відрізняється від використання тіньових каталогів лише для уповільнення пошуку: attacker змінює **значення** раніше прийнятого шляху, не змінюючи його рядок.<sup>[[4]](#references)</sup>

### 3. Перехоплення згенерованого імені та встановлення посилання, специфічного для filename

Відстежуйте робочий каталог за допомогою `ReadDirectoryChangesW`. Після першого `FILE_ACTION_ADDED` видаліть видиме посилання `WD_SCAN`, щоб активувати fallback lookup. Перехопіть друге згенероване filename, відкрийте цей CLFS-related файл і заблокуйте діапазон `0..MAXLONGLONG` за допомогою `LockFileEx`. Поки privileged operation призупинена, замініть `WD_SCAN` у видимому каталозі на справжній каталог Object Manager і створіть дочірнє symbolic link з іменем, отриманим із перехопленого filename (PoC видаляє його останні чотири символи). Спрямуйте його до protected destination через локальний SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Непривілейований процес не може сам записати до цього призначення, але контекст SYSTEM у Defender може пройти через loopback administrative share. Поєднання спостереження за згенерованими іменами з filename-specific Object Manager link усуває необхідність заздалегідь передбачати artifact remediation.<sup>[[4]](#references)</sup>

### 4. Стабілізація cleanup race і запуск privileged loader

Перед скануванням PoC зберігає коректний PE (`ntdll.dll`) у placeholder's `:stream` NTFS alternate data stream. Після того як redirection створює protected base file, він відкриває `phoneinfo.dll:stream` з execute access і підтримує mapping `PAGE_EXECUTE_READ | SEC_IMAGE` активним, поки cleanup продовжується; активні file/section objects обмежують видалення або заміну під час фінальної race. Перезапущена hydration тепер повертає payload DLL замість EICAR, тому protected base file містить code, контрольований attacker.<sup>[[4]](#references)</sup>

Потім protected write перетворюється на SYSTEM execution шляхом розміщення створеного `Report.wer` у `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` і виклику `\Microsoft\Windows\Windows Error Reporting\QueueReporting` через Task Scheduler COM API. У цьому ланцюжку privileged WER processing завантажує розміщений `C:\Windows\System32\phoneinfo.dll`; підключення до named pipe використовується як сигнал виконання payload.<sup>[[4]](#references)</sup>

### Detection pivots

Корисні кореляції є специфічнішими за будь-яке окреме тимчасове ім’я та охоплюють усі переходи між namespace у ланцюжку:<sup>[[4]](#references)</sup>

- Щойно зареєстрований Cloud Files provider, після якого відбувається EICAR detection і `CF_OPERATION_TYPE_RESTART_HYDRATION` для того самого placeholder.
- Object Manager paths, що містять `WD_TARGET_*`, `WD_SHADOW_*` або `WD_SCAN`, особливо scan path нижче `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Створення CLFS file, після якого відбуваються exclusive whole-file lock і loopback access до `\\127.0.0.1\C$\Windows\System32\*.dll` із privileged security process.
- Створення System32 DLL разом із NTFS ADS, після якого відбувається `SEC_IMAGE` mapping stream.
- Створений attacker WER queue entry, після якого відбуваються незвичний manual run `\Microsoft\Windows\Windows Error Reporting\QueueReporting` і image load розміщеної DLL.

## Застосований ланцюжок: перемикання mount-point під контролем oplock проти privileged remediation

Повторно використовуваний LPE pattern виникає, коли privileged scanner перевіряє file, контрольований attacker, а пізніше виконує remediation, повторно відкриваючи **pathname**, замість продовження роботи через validated handles. FalconFlank є публічним прикладом, націленим на workflow видалення Office macro у CrowdStrike Falcon; repository стверджує, що тестування виконувалося на Windows 11 25H2 і Windows Server 2025 з увімкненою відповідною policy, але не публікує CVE, affected-build range, vendor advisory або patch status, тому product-specific claim слід вважати неперевіреним і залежним від build.<sup>[[5]](#references)[[6]](#references)</sup>

### Структура race

1. Створіть writable tree, у якому кінцеве relative name є корисним у передбаченому destination. У прикладі використовується `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, але спочатку в `bcrypt.dll` записується OLE macro document, а не PE DLL. Content-based detection запускає remediation, зберігаючи basename, контрольований attacker, для подальшого side-load.<sup>[[5]](#references)</sup>
2. Відкрийте directories із broad sharing і `FILE_OPEN_REPARSE_POINT`, потім запросіть asynchronous RH oplock на trigger через `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` і `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Дочекайтеся overlapped event і використайте його completion як сигнал для перемикання path. RH oplock-break notification є advisory, а не доказом того, що кожна conflicting operation заблокована, тому exploitability усе ще залежить від точної open/remediation sequence жертви.<sup>[[5]](#references)[[7]](#references)</sup>
3. Після break видаліть leaf directory через `FileDispositionInformationEx` (information class 64), використовуючи delete та POSIX-semantics flags, закрийте його handle і застосуйте `IO_REPARSE_TAG_MOUNT_POINT` до тепер порожнього parent через `FSCTL_SET_REPARSE_POINT_EX`. Mount point перенаправляє незмінний suffix у protected tree, наприклад `\\SystemRoot\\System32\\WindowsPowerShell`; встановлення reparse point завершується помилкою, якщо directory не порожній, що пояснює попередній крок видалення.<sup>[[5]](#references)[[8]](#references)</sup>
4. Відновіть privileged workflow. Якщо він знову розв’язує string, не доводячи, що directory chain і final object є тими самими, які були раніше перевірені, той самий logical pathname тепер веде до protected directory, вибраної attacker. У прикладі успіх перевіряється повторним відкриттям `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` для read/write з original process; це відокремлює confused-deputy write primitive від подальшої code-execution stage.<sup>[[5]](#references)</sup>
5. Замініть отриманий file на справжню DLL і активуйте privileged loader. PoC використовує `CreateTransaction` + `CreateFileTransacted`, обрізає file, відображає replacement розміром DLL, копіює PE і виконує commit; TxF прив’язує file handle та подальші handle-based operations до transaction, але це post-race replacement mechanism, а не джерело порушення privilege boundary.<sup>[[5]](#references)[[9]](#references)</sup>
6. Нарешті, запустіть наявну privileged scheduled task, executable якої перевіряє розміщене adjacent filename. FalconFlank викликає `\\Microsoft\\Windows\\Application Experience\\MareBackup`, очікує підключення DLL до `\\??\\pipe\\FALCONFLANK`, а потім видаляє розміщений file. Не припускайте конкретний resulting token лише на підставі task name — перевірте launched process, module path, integrity level і token на тестованому build.<sup>[[5]](#references)</sup>

Отже, ключове питання аудиту полягає не в тому, «чи перевіряє service original input path?», а в тому, «чи кожна privileged mutation залишається прив’язаною до тих самих opened file і directory objects, які були validated?». Утримання handles між check і use, відкриття child objects відносно trusted directory handle, відхилення unexpected reparse tags і повторна перевірка file identity перед mutation усувають цей клас pathname-substitution bug.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection і PoC triage

High-signal detection корелює namespace transition із privileged consumer: OLE header під DLL basename у GUID-named temporary tree, oplock break, POSIX-style removal leaf directory, створення mount point, що вказує на protected Windows directory, а також створення або зміна того самого basename нижче цього destination. Для публічного прикладу додайте `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, manual execution `MareBackup` і named pipe `FALCONFLANK` як вужчі pivots; жоден із них не є достатнім окремо.<sup>[[5]](#references)</sup>

Під час відтворення PoC врахуйте три reliability defects у опублікованому source: він викликає `FlushFileBuffers` із pointer на embedded byte-array замість file handle, перевіряє застарілий `HRESULT` після `GetFolder`, `GetTask` і `Run`, а також використовує unbounded retry/wait loops для directory deletion, reparse creation, oplock event і pipe connection.<sup>[[5]](#references)</sup>

## Операційні міркування

- **Поєднання primitives** – Можна використовувати довге ім’я *на кожному рівні* directory chain для ще більшої затримки, доки не буде вичерпано розмір `UNICODE_STRING`.
- **One-shot bugs** – Розширене вікно (від десятків мікросекунд до хвилин) робить “single trigger” bugs реалістичними в поєднанні з CPU affinity pinning або hypervisor-assisted preemption.
- **Побічні ефекти** – Slowdown впливає лише на malicious path, тому загальна продуктивність системи не змінюється; defenders рідко це помітять, якщо не моніторять namespace growth.
- **Cleanup** – Утримуйте handles до кожного directory/object, який створюєте, щоб потім викликати `NtMakeTemporaryObject`/`NtClose`. Інакше unbounded directory chains можуть зберігатися після перезавантаження.
- **File-system races** – Якщо vulnerable path зрештою проходить через NTFS, можна встановити Oplock (наприклад, `SetOpLock.exe` з того самого toolkit) на backing file, поки працює OM slowdown, заморозивши consumer ще на кілька мілісекунд без зміни OM graph.<sup>[[2]](#references)</sup>

## Захисні примітки

- Kernel code, який покладається на named objects, має повторно перевіряти security-sensitive state *після* open або отримувати reference до перевірки (закриваючи TOCTOU gap).
- Встановлюйте upper bounds для OM path depth/length перед dereferencing user-controlled names. Відхилення надто довгих імен змушує attackers повернутися до microsecond window.
- Інструментуйте namespace growth Object Manager (ETW `Microsoft-Windows-Kernel-Object`), щоб виявляти підозрілі ланцюжки з тисяч компонентів під `\BaseNamedObjects`.

## References

- [1] [Project Zero – Методи експлуатації Windows: перемога в race conditions під час пошуку paths](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Як використовувати Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
